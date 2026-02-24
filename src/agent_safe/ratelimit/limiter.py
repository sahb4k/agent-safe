"""Per-caller rate limiting and circuit breaking.

Provides sliding-window rate limiting and automatic circuit breaking
for callers that trigger too many DENY decisions.  All state is in-memory
and thread-safe via a single lock.

Usage::

    config = RateLimitConfig(max_requests=50, window_seconds=60)
    limiter = RateLimiter(config)

    # Before policy evaluation:
    reason = limiter.check_rate_limit("agent-01")
    if reason is not None:
        # Return DENY with reason
        ...

    # After policy evaluation, if DENY:
    limiter.record_deny("agent-01")
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from pydantic import BaseModel, Field


class RateLimitError(Exception):
    """Raised when rate limiter encounters a configuration error."""


class RateLimitConfig(BaseModel):
    """Configuration for per-caller rate limiting and circuit breaking."""

    max_requests: int = Field(100, ge=1)
    """Maximum requests per window per caller."""

    window_seconds: float = Field(60.0, gt=0)
    """Sliding window duration in seconds."""

    circuit_breaker_threshold: int = Field(0, ge=0)
    """Number of DENY decisions in a window that triggers circuit breaker.
    0 means circuit breaker is disabled."""

    circuit_breaker_window_seconds: float = Field(60.0, gt=0)
    """Window for counting DENY decisions."""

    circuit_breaker_cooldown_seconds: float = Field(300.0, gt=0)
    """How long the circuit breaker stays open (blocks all requests)."""


class RateLimiter:
    """Per-caller rate limiter with circuit breaker.

    Thread-safe via a lock on all state mutations, following the same
    pattern as AuditLogger._lock and TicketValidator._lock.
    """

    def __init__(
        self,
        config: RateLimitConfig,
        _clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._clock = _clock or time.monotonic
        self._lock = threading.Lock()
        self._request_log: dict[str, deque[float]] = {}
        self._deny_log: dict[str, deque[float]] = {}
        self._circuit_open_since: dict[str, float] = {}

    @property
    def config(self) -> RateLimitConfig:
        """The rate limit configuration."""
        return self._config

    def check_rate_limit(self, caller_id: str) -> str | None:
        """Check if a caller is rate-limited or circuit-broken.

        Returns None if the request is allowed to proceed.
        Returns a reason string if the request should be denied.

        Records the request timestamp in the sliding window.
        """
        now = self._clock()

        with self._lock:
            # 1. Check circuit breaker first
            if self._config.circuit_breaker_threshold > 0:
                if caller_id in self._circuit_open_since:
                    opened_at = self._circuit_open_since[caller_id]
                    elapsed = now - opened_at
                    if elapsed < self._config.circuit_breaker_cooldown_seconds:
                        remaining = self._config.circuit_breaker_cooldown_seconds - elapsed
                        return (
                            f"Circuit breaker open for caller '{caller_id}': "
                            f"too many denied requests. "
                            f"Auto-resumes in {remaining:.0f}s."
                        )
                    # Cooldown expired -> close circuit
                    del self._circuit_open_since[caller_id]
                    self._deny_log.pop(caller_id, None)

            # 2. Check rate limit
            if caller_id not in self._request_log:
                self._request_log[caller_id] = deque()

            req_log = self._request_log[caller_id]
            self._prune_deque(req_log, self._config.window_seconds, now)

            if len(req_log) >= self._config.max_requests:
                return (
                    f"Rate limit exceeded for caller '{caller_id}': "
                    f"{self._config.max_requests} requests per "
                    f"{self._config.window_seconds:.0f}s window."
                )

            # 3. Record this request
            req_log.append(now)

        return None

    def record_deny(self, caller_id: str) -> None:
        """Record a DENY decision for circuit breaker tracking.

        If the number of denies in the window exceeds the threshold,
        opens the circuit breaker for this caller.
        """
        if self._config.circuit_breaker_threshold <= 0:
            return

        now = self._clock()

        with self._lock:
            if caller_id not in self._deny_log:
                self._deny_log[caller_id] = deque()

            deny_log = self._deny_log[caller_id]
            self._prune_deque(deny_log, self._config.circuit_breaker_window_seconds, now)
            deny_log.append(now)

            if len(deny_log) >= self._config.circuit_breaker_threshold:
                self._circuit_open_since[caller_id] = now

    @staticmethod
    def _prune_deque(d: deque[float], window: float, now: float) -> None:
        """Remove entries older than the window from the left of the deque."""
        cutoff = now - window
        while d and d[0] < cutoff:
            d.popleft()
