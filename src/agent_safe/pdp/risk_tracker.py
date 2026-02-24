"""Cumulative risk scoring — per-caller session-level risk tracking.

Tracks risk scores per caller within a sliding time window and provides
escalation signals when cumulative risk exceeds configurable thresholds.
This addresses Threat T7 (privilege escalation via action chaining).

Operates as a post-policy layer: the PDP evaluates policy first, then
the risk tracker can escalate decisions (ALLOW → REQUIRE_APPROVAL,
REQUIRE_APPROVAL → DENY) based on accumulated risk.

Usage::

    config = CumulativeRiskConfig(escalation_threshold=30, deny_threshold=75)
    tracker = CumulativeRiskTracker(config)

    # After policy evaluation, for non-DENY decisions:
    result = tracker.record_and_evaluate("agent-01", RiskClass.HIGH)
    escalation = tracker.should_escalate(result.cumulative_score)
    # escalation is None, "escalate", or "deny"
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from typing import NamedTuple

from pydantic import BaseModel, Field

from agent_safe.models import RiskClass


class _RiskEntry(NamedTuple):
    """Internal entry tracking a single risk event."""

    timestamp: float
    score: int


class CumulativeRiskConfig(BaseModel):
    """Configuration for cumulative risk scoring."""

    window_seconds: float = Field(3600.0, gt=0)
    """Sliding window duration in seconds (default 1 hour)."""

    risk_scores: dict[str, int] = Field(
        default_factory=lambda: {
            "low": 1,
            "medium": 5,
            "high": 15,
            "critical": 50,
        }
    )
    """Numeric risk score per RiskClass value."""

    escalation_threshold: int = Field(30, ge=1)
    """Cumulative score at which ALLOW decisions are escalated to REQUIRE_APPROVAL."""

    deny_threshold: int = Field(75, ge=1)
    """Cumulative score at which all non-DENY decisions are escalated to DENY."""


class CumulativeRiskResult(BaseModel):
    """Result of a cumulative risk evaluation."""

    cumulative_score: int
    cumulative_risk_class: RiskClass
    window_seconds: float
    entry_count: int
    escalated: bool = False
    escalated_from: str | None = None


class CumulativeRiskTracker:
    """Per-caller cumulative risk tracker with sliding window.

    Thread-safe via a lock on all state mutations, following the same
    pattern as RateLimiter and TicketValidator.
    """

    def __init__(
        self,
        config: CumulativeRiskConfig,
        _clock: Callable[[], float] | None = None,
    ) -> None:
        self._config = config
        self._clock = _clock or time.monotonic
        self._lock = threading.Lock()
        self._history: dict[str, deque[_RiskEntry]] = {}

    @property
    def config(self) -> CumulativeRiskConfig:
        """The cumulative risk configuration."""
        return self._config

    def record_and_evaluate(
        self,
        caller_id: str,
        effective_risk: RiskClass,
    ) -> CumulativeRiskResult:
        """Record an action's risk and return cumulative assessment.

        Called AFTER policy evaluation for non-DENY decisions. Records
        the risk score and returns the cumulative state including
        whether escalation is needed.
        """
        score = self._config.risk_scores.get(effective_risk.value, 0)
        now = self._clock()

        with self._lock:
            if caller_id not in self._history:
                self._history[caller_id] = deque()

            history = self._history[caller_id]
            self._prune_deque(history, now)
            history.append(_RiskEntry(timestamp=now, score=score))
            cumulative = sum(e.score for e in history)
            count = len(history)

        return CumulativeRiskResult(
            cumulative_score=cumulative,
            cumulative_risk_class=self._score_to_risk_class(cumulative),
            window_seconds=self._config.window_seconds,
            entry_count=count,
        )

    def get_cumulative_score(self, caller_id: str) -> int:
        """Get current cumulative score without recording."""
        now = self._clock()
        with self._lock:
            if caller_id not in self._history:
                return 0
            history = self._history[caller_id]
            self._prune_deque(history, now)
            return sum(e.score for e in history)

    def should_escalate(self, cumulative_score: int) -> str | None:
        """Determine escalation action based on cumulative score.

        Returns:
            ``"deny"`` if score >= deny_threshold,
            ``"escalate"`` if score >= escalation_threshold,
            ``None`` if no escalation needed.
        """
        if cumulative_score >= self._config.deny_threshold:
            return "deny"
        if cumulative_score >= self._config.escalation_threshold:
            return "escalate"
        return None

    def _score_to_risk_class(self, score: int) -> RiskClass:
        """Map numeric cumulative score to a RiskClass for display."""
        if score >= self._config.deny_threshold:
            return RiskClass.CRITICAL
        if score >= self._config.escalation_threshold:
            return RiskClass.HIGH
        if score >= self._config.escalation_threshold // 2:
            return RiskClass.MEDIUM
        return RiskClass.LOW

    def _prune_deque(self, d: deque[_RiskEntry], now: float) -> None:
        """Remove entries older than the window from the left."""
        cutoff = now - self._config.window_seconds
        while d and d[0].timestamp < cutoff:
            d.popleft()
