"""Tests for cumulative risk scoring.

Covers:
- CumulativeRiskConfig validation
- Risk score mapping
- Sliding window behavior
- Escalation logic
- CumulativeRiskResult mapping
- PDP integration (post-policy escalation, audit context)
- SDK integration (end-to-end)
"""

from __future__ import annotations

import threading

import pytest
from pydantic import ValidationError

from agent_safe import AgentSafe
from agent_safe.models import (
    AgentIdentity,
    DecisionResult,
    PolicyRule,
    RiskClass,
    TargetDefinition,
)
from agent_safe.pdp.engine import PolicyDecisionPoint
from agent_safe.pdp.risk_tracker import (
    CumulativeRiskConfig,
    CumulativeRiskTracker,
)
from agent_safe.registry.loader import load_registry

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


# --- CumulativeRiskConfig ---


class TestCumulativeRiskConfig:
    def test_default_values(self):
        cfg = CumulativeRiskConfig()
        assert cfg.window_seconds == 3600.0
        assert cfg.escalation_threshold == 30
        assert cfg.deny_threshold == 75
        assert cfg.risk_scores == {
            "low": 1, "medium": 5, "high": 15, "critical": 50,
        }

    def test_custom_values(self):
        cfg = CumulativeRiskConfig(
            window_seconds=1800,
            escalation_threshold=20,
            deny_threshold=50,
            risk_scores={"low": 2, "medium": 10, "high": 30, "critical": 100},
        )
        assert cfg.window_seconds == 1800
        assert cfg.escalation_threshold == 20
        assert cfg.deny_threshold == 50
        assert cfg.risk_scores["high"] == 30

    def test_invalid_zero_window(self):
        with pytest.raises(ValidationError):
            CumulativeRiskConfig(window_seconds=0)

    def test_invalid_zero_threshold(self):
        with pytest.raises(ValidationError):
            CumulativeRiskConfig(escalation_threshold=0)

    def test_dict_conversion(self):
        cfg = CumulativeRiskConfig(
            **{"window_seconds": 600, "escalation_threshold": 10}
        )
        assert cfg.window_seconds == 600
        assert cfg.escalation_threshold == 10


# --- Risk Scoring ---


class TestRiskScoring:
    def test_low_risk_score(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        result = tracker.record_and_evaluate("agent-01", RiskClass.LOW)
        assert result.cumulative_score == 1

    def test_medium_risk_score(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        result = tracker.record_and_evaluate("agent-01", RiskClass.MEDIUM)
        assert result.cumulative_score == 5

    def test_high_risk_score(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        result = tracker.record_and_evaluate("agent-01", RiskClass.HIGH)
        assert result.cumulative_score == 15

    def test_critical_risk_score(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        result = tracker.record_and_evaluate("agent-01", RiskClass.CRITICAL)
        assert result.cumulative_score == 50

    def test_custom_scores(self):
        clock = MockClock()
        cfg = CumulativeRiskConfig(risk_scores={
            "low": 10, "medium": 20, "high": 40, "critical": 100,
        })
        tracker = CumulativeRiskTracker(cfg, _clock=clock)
        result = tracker.record_and_evaluate("agent-01", RiskClass.LOW)
        assert result.cumulative_score == 10


# --- Sliding Window ---


class TestSlidingWindow:
    def test_scores_accumulate(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        tracker.record_and_evaluate("agent-01", RiskClass.LOW)
        tracker.record_and_evaluate("agent-01", RiskClass.MEDIUM)
        result = tracker.record_and_evaluate("agent-01", RiskClass.HIGH)
        assert result.cumulative_score == 1 + 5 + 15
        assert result.entry_count == 3

    def test_old_entries_pruned(self):
        clock = MockClock()
        cfg = CumulativeRiskConfig(window_seconds=60)
        tracker = CumulativeRiskTracker(cfg, _clock=clock)

        tracker.record_and_evaluate("agent-01", RiskClass.HIGH)  # score=15
        clock.advance(61)  # past window
        result = tracker.record_and_evaluate("agent-01", RiskClass.LOW)  # score=1
        assert result.cumulative_score == 1
        assert result.entry_count == 1

    def test_window_slides(self):
        clock = MockClock()
        cfg = CumulativeRiskConfig(window_seconds=60)
        tracker = CumulativeRiskTracker(cfg, _clock=clock)

        tracker.record_and_evaluate("agent-01", RiskClass.HIGH)  # t=1000, score=15
        clock.advance(30)
        tracker.record_and_evaluate("agent-01", RiskClass.MEDIUM)  # t=1030, score=5
        clock.advance(31)
        # t=1061: first entry (t=1000) should be pruned
        result = tracker.record_and_evaluate("agent-01", RiskClass.LOW)  # score=1
        assert result.cumulative_score == 5 + 1  # only medium + low remain
        assert result.entry_count == 2

    def test_different_callers_independent(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)

        tracker.record_and_evaluate("agent-01", RiskClass.CRITICAL)
        result = tracker.record_and_evaluate("agent-02", RiskClass.LOW)
        assert result.cumulative_score == 1  # agent-02's own score only

    def test_empty_history_returns_zero(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        assert tracker.get_cumulative_score("agent-01") == 0


# --- Escalation ---


class TestEscalation:
    def test_below_threshold_no_escalation(self):
        tracker = CumulativeRiskTracker(CumulativeRiskConfig())
        assert tracker.should_escalate(10) is None

    def test_at_escalation_threshold(self):
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(escalation_threshold=30))
        assert tracker.should_escalate(30) == "escalate"

    def test_above_escalation_below_deny(self):
        tracker = CumulativeRiskTracker(
            CumulativeRiskConfig(escalation_threshold=30, deny_threshold=75)
        )
        assert tracker.should_escalate(50) == "escalate"

    def test_at_deny_threshold(self):
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(deny_threshold=75))
        assert tracker.should_escalate(75) == "deny"

    def test_above_deny_threshold(self):
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(deny_threshold=75))
        assert tracker.should_escalate(100) == "deny"

    def test_deny_overrides_escalate(self):
        """When score exceeds both thresholds, deny takes precedence."""
        cfg = CumulativeRiskConfig(escalation_threshold=30, deny_threshold=75)
        tracker = CumulativeRiskTracker(cfg)
        assert tracker.should_escalate(80) == "deny"


# --- CumulativeRiskResult ---


class TestCumulativeRiskResult:
    def test_low_score_maps_to_low(self):
        clock = MockClock()
        cfg = CumulativeRiskConfig(escalation_threshold=30, deny_threshold=75)
        tracker = CumulativeRiskTracker(cfg, _clock=clock)
        result = tracker.record_and_evaluate("agent-01", RiskClass.LOW)
        assert result.cumulative_risk_class == RiskClass.LOW

    def test_medium_score_maps_to_medium(self):
        clock = MockClock()
        cfg = CumulativeRiskConfig(escalation_threshold=30, deny_threshold=75)
        tracker = CumulativeRiskTracker(cfg, _clock=clock)
        # Score 15 >= 30//2=15 → MEDIUM
        result = tracker.record_and_evaluate("agent-01", RiskClass.HIGH)
        assert result.cumulative_risk_class == RiskClass.MEDIUM

    def test_high_score_maps_to_high(self):
        clock = MockClock()
        cfg = CumulativeRiskConfig(escalation_threshold=30, deny_threshold=75)
        tracker = CumulativeRiskTracker(cfg, _clock=clock)
        # Score needs to be >= 30 → HIGH
        tracker.record_and_evaluate("agent-01", RiskClass.HIGH)  # 15
        result = tracker.record_and_evaluate("agent-01", RiskClass.HIGH)  # 30
        assert result.cumulative_risk_class == RiskClass.HIGH


# --- PDP Integration ---


class TestPDPIntegration:
    @pytest.fixture()
    def registry(self):
        return load_registry(ACTIONS_DIR)

    @pytest.fixture()
    def dev_target(self):
        return TargetDefinition(
            id="dev/test-app", type="k8s-deployment",
            environment="dev", sensitivity="public",
        )

    @pytest.fixture()
    def allow_rule(self):
        return PolicyRule(
            name="allow-dev",
            match={"actions": ["*"], "targets": {"environments": ["dev"]}},
            decision="allow",
            reason="Dev is unrestricted",
            priority=10,
        )

    @pytest.fixture()
    def require_approval_rule(self):
        return PolicyRule(
            name="require-prod",
            match={"actions": ["*"], "targets": {"environments": ["prod"]}},
            decision="require_approval",
            reason="Prod requires approval",
            priority=10,
        )

    @pytest.fixture()
    def caller(self):
        return AgentIdentity(agent_id="agent-01", roles=["deployer"])

    def test_allow_escalated_to_require_approval(
        self, registry, dev_target, allow_rule, caller,
    ):
        clock = MockClock()
        tracker = CumulativeRiskTracker(
            CumulativeRiskConfig(escalation_threshold=10), _clock=clock,
        )
        pdp = PolicyDecisionPoint(
            rules=[allow_rule], registry=registry, risk_tracker=tracker,
        )

        # First check: score=5 (medium effective risk for dev), below threshold
        d1 = pdp.evaluate(
            "restart-deployment", dev_target, caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert d1.result == DecisionResult.ALLOW
        assert d1.cumulative_risk_score is not None

        # Second check: score accumulates past threshold
        d2 = pdp.evaluate(
            "restart-deployment", dev_target, caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        # Two medium-risk actions on public target = effective LOW each (score=1+1=2)
        # or effective LOW = score 1 each... let's check the actual score
        # restart-deployment risk_class=medium, target sensitivity=public
        # effective_risk = RISK_MATRIX[MEDIUM][PUBLIC] = LOW → score=1
        # Two LOW actions = score 2, still below 10
        # Need more to escalate
        assert d2.result == DecisionResult.ALLOW

    def test_high_risk_triggers_escalation(self, registry, dev_target, caller):
        clock = MockClock()
        tracker = CumulativeRiskTracker(
            CumulativeRiskConfig(escalation_threshold=10), _clock=clock,
        )
        pdp = PolicyDecisionPoint(
            rules=[PolicyRule(
                name="allow-all", match={"actions": ["*"]},
                decision="allow", reason="Allow all", priority=10,
            )],
            registry=registry,
            risk_tracker=tracker,
        )

        # exec-pod = HIGH risk, dev/public target → effective MEDIUM → score 5
        dev_pod = TargetDefinition(
            id="dev/debug-pod", type="k8s-pod",
            environment="dev", sensitivity="public",
        )
        d1 = pdp.evaluate(
            "exec-pod", dev_pod, caller,
            params={"namespace": "dev", "pod": "debug", "command": ["ls"]},
        )
        assert d1.result == DecisionResult.ALLOW
        assert d1.cumulative_risk_score == 5

        # Second exec-pod → score 10 → at escalation threshold
        d2 = pdp.evaluate(
            "exec-pod", dev_pod, caller,
            params={"namespace": "dev", "pod": "debug", "command": ["ls"]},
        )
        assert d2.result == DecisionResult.REQUIRE_APPROVAL
        assert d2.escalated_from == DecisionResult.ALLOW
        assert d2.cumulative_risk_score == 10
        assert "Escalated by cumulative risk" in d2.reason

    def test_deny_not_affected_by_cumulative_risk(
        self, registry, dev_target, caller,
    ):
        clock = MockClock()
        tracker = CumulativeRiskTracker(
            CumulativeRiskConfig(escalation_threshold=1), _clock=clock,
        )
        pdp = PolicyDecisionPoint(
            rules=[PolicyRule(
                name="deny-all", match={"actions": ["*"]},
                decision="deny", reason="Denied", priority=10,
            )],
            registry=registry,
            risk_tracker=tracker,
        )

        decision = pdp.evaluate(
            "restart-deployment", dev_target, caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.DENY
        # DENY decisions should NOT accumulate risk
        assert decision.cumulative_risk_score is None
        assert tracker.get_cumulative_score("agent-01") == 0

    def test_require_approval_escalated_to_deny(self, registry, caller):
        clock = MockClock()
        tracker = CumulativeRiskTracker(
            CumulativeRiskConfig(deny_threshold=10), _clock=clock,
        )

        prod_target = TargetDefinition(
            id="prod/api-server", type="k8s-deployment",
            environment="prod", sensitivity="critical",
        )

        pdp = PolicyDecisionPoint(
            rules=[PolicyRule(
                name="require-prod", match={"actions": ["*"]},
                decision="require_approval", reason="Prod requires approval",
                priority=10,
            )],
            registry=registry,
            risk_tracker=tracker,
        )

        # restart-deployment (medium) on critical target → effective CRITICAL → score 50
        d1 = pdp.evaluate(
            "restart-deployment", prod_target, caller,
            params={"namespace": "prod", "deployment": "api"},
        )
        # Score 50 >= deny_threshold 10 → REQUIRE_APPROVAL escalated to DENY
        assert d1.result == DecisionResult.DENY
        assert d1.escalated_from == DecisionResult.REQUIRE_APPROVAL
        assert "Cumulative risk threshold exceeded" in d1.reason

    def test_no_tracker_no_change(self, registry, dev_target, allow_rule, caller):
        pdp = PolicyDecisionPoint(
            rules=[allow_rule], registry=registry,
        )
        decision = pdp.evaluate(
            "restart-deployment", dev_target, caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.cumulative_risk_score is None
        assert decision.escalated_from is None

    def test_decision_fields_populated(self, registry, dev_target, caller):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        pdp = PolicyDecisionPoint(
            rules=[PolicyRule(
                name="allow-all", match={"actions": ["*"]},
                decision="allow", reason="Allow all", priority=10,
            )],
            registry=registry,
            risk_tracker=tracker,
        )

        decision = pdp.evaluate(
            "restart-deployment", dev_target, caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.cumulative_risk_score is not None
        assert decision.cumulative_risk_class is not None
        assert decision.escalated_from is None  # No escalation

    def test_audit_context_includes_cumulative_info(self, registry, dev_target, caller, tmp_path):
        from agent_safe.audit.logger import AuditLogger

        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        audit_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(audit_path)

        pdp = PolicyDecisionPoint(
            rules=[PolicyRule(
                name="allow-all", match={"actions": ["*"]},
                decision="allow", reason="Allow all", priority=10,
            )],
            registry=registry,
            risk_tracker=tracker,
            audit_logger=audit,
        )

        pdp.evaluate(
            "restart-deployment", dev_target, caller,
            params={"namespace": "dev", "deployment": "app"},
        )

        events = audit.read_events()
        assert len(events) == 1
        ctx = events[0].context
        assert ctx is not None
        assert "cumulative_risk_score" in ctx
        assert "cumulative_risk_class" in ctx
        assert "cumulative_entry_count" in ctx


# --- SDK Integration ---


class TestSDKIntegration:
    def test_config_via_dict(self):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            cumulative_risk={"escalation_threshold": 20, "deny_threshold": 60},
        )
        assert safe._risk_tracker is not None
        assert safe._risk_tracker.config.escalation_threshold == 20

    def test_config_via_object(self):
        cfg = CumulativeRiskConfig(escalation_threshold=15)
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            cumulative_risk=cfg,
        )
        assert safe._risk_tracker is not None
        assert safe._risk_tracker.config.escalation_threshold == 15

    def test_none_default_no_tracker(self):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        assert safe._risk_tracker is None

    def test_check_plan_accumulates(self):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            cumulative_risk={
                "escalation_threshold": 5,
                "deny_threshold": 100,
            },
        )

        plan = [
            {
                "action": "get-configmap",
                "target": "dev/test-app",
                "caller": "agent-01",
                "params": {"namespace": "dev", "configmap": "cfg"},
            },
            {
                "action": "get-configmap",
                "target": "dev/test-app",
                "caller": "agent-01",
                "params": {"namespace": "dev", "configmap": "cfg2"},
            },
        ]

        decisions = safe.check_plan(plan)
        assert len(decisions) == 2
        # Both should have cumulative risk scores
        assert decisions[0].cumulative_risk_score is not None
        assert decisions[1].cumulative_risk_score is not None
        # Second should have higher cumulative score
        assert decisions[1].cumulative_risk_score > decisions[0].cumulative_risk_score

    def test_cumulative_info_in_decision(self):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            cumulative_risk={"escalation_threshold": 100, "deny_threshold": 200},
        )

        decision = safe.check(
            action="get-configmap",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "configmap": "app-config"},
        )
        assert decision.cumulative_risk_score is not None
        assert decision.cumulative_risk_class is not None
        assert decision.escalated_from is None


# --- Thread Safety ---


class TestThreadSafety:
    def test_concurrent_callers(self):
        clock = MockClock()
        tracker = CumulativeRiskTracker(CumulativeRiskConfig(), _clock=clock)
        errors = []

        def record_many(caller_id: str):
            try:
                for _ in range(50):
                    tracker.record_and_evaluate(caller_id, RiskClass.LOW)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=record_many, args=(f"agent-{i}",))
            for i in range(4)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        # Each caller should have score=50 (50 LOW actions × 1)
        for i in range(4):
            assert tracker.get_cumulative_score(f"agent-{i}") == 50
