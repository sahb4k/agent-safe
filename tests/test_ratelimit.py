"""Tests for per-caller rate limiting and circuit breaking.

Covers:
- RateLimitConfig validation
- Sliding window rate limiting
- Circuit breaker state machine
- Thread safety
- PDP integration
- SDK integration (end-to-end)
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_safe import AgentSafe
from agent_safe.models import DecisionResult
from agent_safe.ratelimit.limiter import RateLimitConfig, RateLimiter

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"


# --- Mock clock for deterministic tests ---


class MockClock:
    """A controllable clock for testing time-dependent behavior."""

    def __init__(self, start: float = 1000.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


# --- RateLimitConfig ---


class TestRateLimitConfig:
    def test_default_values(self):
        cfg = RateLimitConfig()
        assert cfg.max_requests == 100
        assert cfg.window_seconds == 60.0
        assert cfg.circuit_breaker_threshold == 0
        assert cfg.circuit_breaker_cooldown_seconds == 300.0

    def test_custom_values(self):
        cfg = RateLimitConfig(
            max_requests=10, window_seconds=30,
            circuit_breaker_threshold=5,
            circuit_breaker_window_seconds=120,
            circuit_breaker_cooldown_seconds=600,
        )
        assert cfg.max_requests == 10
        assert cfg.window_seconds == 30
        assert cfg.circuit_breaker_threshold == 5

    def test_invalid_max_requests_zero(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(max_requests=0)

    def test_invalid_negative_window(self):
        with pytest.raises(ValidationError):
            RateLimitConfig(window_seconds=-1)

    def test_dict_conversion(self):
        cfg = RateLimitConfig(**{"max_requests": 50, "window_seconds": 30})
        assert cfg.max_requests == 50
        assert cfg.window_seconds == 30


# --- Rate Limiting ---


class TestRateLimiting:
    def test_under_limit_allows(self):
        clock = MockClock()
        limiter = RateLimiter(RateLimitConfig(max_requests=5), _clock=clock)
        for _ in range(5):
            assert limiter.check_rate_limit("agent-01") is None

    def test_at_limit_denies(self):
        clock = MockClock()
        limiter = RateLimiter(RateLimitConfig(max_requests=3), _clock=clock)
        for _ in range(3):
            assert limiter.check_rate_limit("agent-01") is None
        reason = limiter.check_rate_limit("agent-01")
        assert reason is not None
        assert "Rate limit exceeded" in reason
        assert "agent-01" in reason

    def test_reason_string_contains_details(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(max_requests=2, window_seconds=60), _clock=clock,
        )
        limiter.check_rate_limit("a")
        limiter.check_rate_limit("a")
        reason = limiter.check_rate_limit("a")
        assert "2 requests per 60s" in reason

    def test_window_slides(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(max_requests=2, window_seconds=10), _clock=clock,
        )
        assert limiter.check_rate_limit("a") is None  # 1
        assert limiter.check_rate_limit("a") is None  # 2
        assert limiter.check_rate_limit("a") is not None  # blocked

        # Advance past window
        clock.advance(11)
        assert limiter.check_rate_limit("a") is None  # allowed again

    def test_different_callers_independent(self):
        clock = MockClock()
        limiter = RateLimiter(RateLimitConfig(max_requests=2), _clock=clock)
        limiter.check_rate_limit("a")
        limiter.check_rate_limit("a")
        # caller "a" is at limit
        assert limiter.check_rate_limit("a") is not None
        # caller "b" is unaffected
        assert limiter.check_rate_limit("b") is None

    def test_anonymous_caller_tracked(self):
        clock = MockClock()
        limiter = RateLimiter(RateLimitConfig(max_requests=1), _clock=clock)
        assert limiter.check_rate_limit("anonymous") is None
        assert limiter.check_rate_limit("anonymous") is not None


# --- Circuit Breaker ---


class TestCircuitBreaker:
    def test_disabled_by_default(self):
        clock = MockClock()
        limiter = RateLimiter(RateLimitConfig(), _clock=clock)
        # Record many denies — should never trip CB
        for _ in range(1000):
            limiter.record_deny("a")
        assert limiter.check_rate_limit("a") is None

    def test_opens_after_threshold_denies(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(
                max_requests=1000,
                circuit_breaker_threshold=3,
                circuit_breaker_window_seconds=60,
                circuit_breaker_cooldown_seconds=300,
            ),
            _clock=clock,
        )
        limiter.record_deny("a")
        limiter.record_deny("a")
        # Not yet tripped
        assert limiter.check_rate_limit("a") is None

        limiter.record_deny("a")  # 3rd deny -> trips
        reason = limiter.check_rate_limit("a")
        assert reason is not None
        assert "Circuit breaker open" in reason

    def test_open_circuit_denies_all(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(
                max_requests=1000,
                circuit_breaker_threshold=1,
                circuit_breaker_cooldown_seconds=60,
            ),
            _clock=clock,
        )
        limiter.record_deny("a")
        for _ in range(10):
            reason = limiter.check_rate_limit("a")
            assert reason is not None
            assert "Circuit breaker" in reason

    def test_reason_string_contains_cooldown(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(
                max_requests=1000,
                circuit_breaker_threshold=1,
                circuit_breaker_cooldown_seconds=120,
            ),
            _clock=clock,
        )
        limiter.record_deny("a")
        reason = limiter.check_rate_limit("a")
        assert "120s" in reason

    def test_closes_after_cooldown(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(
                max_requests=1000,
                circuit_breaker_threshold=1,
                circuit_breaker_cooldown_seconds=60,
            ),
            _clock=clock,
        )
        limiter.record_deny("a")
        assert limiter.check_rate_limit("a") is not None  # CB open

        clock.advance(61)
        assert limiter.check_rate_limit("a") is None  # CB closed

    def test_deny_window_slides(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(
                max_requests=1000,
                circuit_breaker_threshold=3,
                circuit_breaker_window_seconds=10,
                circuit_breaker_cooldown_seconds=60,
            ),
            _clock=clock,
        )
        limiter.record_deny("a")
        limiter.record_deny("a")
        clock.advance(11)  # first two denies expire
        limiter.record_deny("a")
        # Only 1 deny in window, threshold is 3 — CB stays closed
        assert limiter.check_rate_limit("a") is None

    def test_different_callers_independent(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(
                max_requests=1000,
                circuit_breaker_threshold=1,
                circuit_breaker_cooldown_seconds=60,
            ),
            _clock=clock,
        )
        limiter.record_deny("a")
        assert limiter.check_rate_limit("a") is not None  # CB open for "a"
        assert limiter.check_rate_limit("b") is None  # "b" is fine

    def test_reopen_after_close(self):
        clock = MockClock()
        limiter = RateLimiter(
            RateLimitConfig(
                max_requests=1000,
                circuit_breaker_threshold=1,
                circuit_breaker_cooldown_seconds=10,
            ),
            _clock=clock,
        )
        limiter.record_deny("a")
        assert limiter.check_rate_limit("a") is not None  # open

        clock.advance(11)
        assert limiter.check_rate_limit("a") is None  # closed

        limiter.record_deny("a")  # misbehave again
        assert limiter.check_rate_limit("a") is not None  # re-opened


# --- Thread Safety ---


class TestThreadSafety:
    def test_concurrent_requests_respect_limit(self):
        limiter = RateLimiter(RateLimitConfig(max_requests=10, window_seconds=60))
        results: list[str | None] = []
        lock = threading.Lock()

        def make_requests():
            for _ in range(5):
                r = limiter.check_rate_limit("agent-01")
                with lock:
                    results.append(r)

        threads = [threading.Thread(target=make_requests) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # 20 total requests, limit is 10
        allowed = sum(1 for r in results if r is None)
        denied = sum(1 for r in results if r is not None)
        assert allowed == 10
        assert denied == 10


# --- PDP Integration ---


class TestPDPIntegration:
    def _safe(
        self, tmp_path: Path, rate_limit: dict | None = None,
    ) -> AgentSafe:
        return AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            rate_limit=rate_limit,
        )

    def test_rate_limited_returns_deny(self, tmp_path: Path):
        safe = self._safe(tmp_path, rate_limit={"max_requests": 2})
        # First two: ALLOW
        for _ in range(2):
            d = safe.check(
                action="restart-deployment", target="dev/test-app",
                caller="agent-01",
                params={"namespace": "dev", "deployment": "app"},
            )
            assert d.result == DecisionResult.ALLOW

        # Third: DENY (rate limited)
        d = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert d.result == DecisionResult.DENY
        assert "Rate limit exceeded" in d.reason

    def test_rate_limited_decision_has_audit_id(self, tmp_path: Path):
        safe = self._safe(tmp_path, rate_limit={"max_requests": 1})
        safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        d = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        assert d.audit_id.startswith("evt-")

    def test_rate_limited_decision_logged(self, tmp_path: Path):
        safe = self._safe(tmp_path, rate_limit={"max_requests": 1})
        safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        events = safe.audit.read_events()
        assert len(events) == 2
        assert events[1].decision == DecisionResult.DENY
        assert "Rate limit" in events[1].reason

    def test_no_rate_limiter_backward_compat(self, tmp_path: Path):
        safe = self._safe(tmp_path, rate_limit=None)
        for _ in range(20):
            d = safe.check(
                action="restart-deployment", target="dev/test-app",
                caller="agent-01",
                params={"namespace": "dev", "deployment": "app"},
            )
            assert d.result == DecisionResult.ALLOW

    def test_rate_limit_no_ticket_on_deny(self, tmp_path: Path):
        """Rate-limited DENY should not have an execution ticket."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            signing_key="test-key",
            rate_limit={"max_requests": 1},
        )
        d1 = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        assert d1.result == DecisionResult.ALLOW
        assert d1.ticket is not None

        d2 = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        assert d2.result == DecisionResult.DENY
        assert d2.ticket is None


# --- SDK Integration ---


class TestSDKIntegration:
    def test_rate_limit_config_object(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            rate_limit=RateLimitConfig(max_requests=5),
        )
        d = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        assert d.result == DecisionResult.ALLOW

    def test_rate_limit_dict(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            rate_limit={"max_requests": 5},
        )
        d = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="a", params={"namespace": "dev", "deployment": "app"},
        )
        assert d.result == DecisionResult.ALLOW

    def test_rate_limit_none_default(self):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        # No rate limiter = no limit
        for _ in range(50):
            d = safe.check(
                action="restart-deployment", target="dev/test-app",
                caller="a", params={"namespace": "dev", "deployment": "app"},
            )
            assert d.result == DecisionResult.ALLOW

    def test_check_plan_rate_limited(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            rate_limit={"max_requests": 2},
        )
        plan = [
            {"action": "restart-deployment", "target": "dev/test-app",
             "caller": "a", "params": {"namespace": "dev", "deployment": "app"}},
            {"action": "get-pod-logs", "target": "dev/test-app",
             "caller": "a", "params": {"namespace": "dev", "pod": "test-pod"}},
            {"action": "restart-deployment", "target": "dev/test-app",
             "caller": "a", "params": {"namespace": "dev", "deployment": "app"}},
        ]
        decisions = safe.check_plan(plan)
        # First 2 allowed, 3rd rate-limited
        assert decisions[0].result == DecisionResult.ALLOW
        assert decisions[1].result == DecisionResult.ALLOW
        assert decisions[2].result == DecisionResult.DENY
        assert "Rate limit" in decisions[2].reason

    def test_circuit_breaker_end_to_end(self, tmp_path: Path):
        """Agent triggers denies with unknown actions, then gets circuit broken."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            rate_limit={
                "max_requests": 1000,
                "circuit_breaker_threshold": 3,
                "circuit_breaker_window_seconds": 60,
                "circuit_breaker_cooldown_seconds": 300,
            },
        )
        # 3 unknown actions -> 3 DENY -> CB trips
        for _ in range(3):
            d = safe.check(action="nonexistent-action", caller="bad-agent")
            assert d.result == DecisionResult.DENY

        # Next request: circuit broken (even valid action)
        d = safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="bad-agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert d.result == DecisionResult.DENY
        assert "Circuit breaker" in d.reason
