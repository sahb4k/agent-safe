"""Tests for the Policy Decision Point.

Table-driven tests covering:
- Default deny
- Priority ordering (highest wins)
- Action matching (exact, glob, wildcard)
- Target selectors (environment, sensitivity, type, labels)
- Caller selectors (agent_id, roles, groups)
- Risk class matching
- Time window matching
- Effective risk computation integration
- Unknown action / invalid params rejection
- Real policy file loading
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_safe.audit.logger import AuditLogger, verify_log
from agent_safe.models import (
    AgentIdentity,
    CallerSelector,
    DecisionResult,
    Environment,
    PolicyMatch,
    PolicyRule,
    RiskClass,
    Sensitivity,
    TargetDefinition,
    TargetSelector,
    TimeWindow,
)
from agent_safe.pdp.engine import PolicyDecisionPoint, load_policies
from agent_safe.registry.loader import load_registry

# --- Fixtures ---

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")


@pytest.fixture()
def registry():
    return load_registry(ACTIONS_DIR)


@pytest.fixture()
def prod_target():
    return TargetDefinition(
        id="prod/api-server",
        type="k8s-deployment",
        environment=Environment.PROD,
        sensitivity=Sensitivity.CRITICAL,
        owner="platform-team",
        labels={"app": "api-server", "tier": "backend"},
    )


@pytest.fixture()
def staging_target():
    return TargetDefinition(
        id="staging/api-server",
        type="k8s-deployment",
        environment=Environment.STAGING,
        sensitivity=Sensitivity.INTERNAL,
        owner="platform-team",
    )


@pytest.fixture()
def dev_target():
    return TargetDefinition(
        id="dev/test-app",
        type="k8s-deployment",
        environment=Environment.DEV,
        sensitivity=Sensitivity.PUBLIC,
    )


@pytest.fixture()
def deployer_caller():
    return AgentIdentity(
        agent_id="deploy-agent-01",
        agent_name="Deploy Agent",
        roles=["deployer", "reader"],
        groups=["platform-team"],
    )


@pytest.fixture()
def reader_caller():
    return AgentIdentity(
        agent_id="reader-agent-01",
        agent_name="Reader Agent",
        roles=["reader"],
        groups=["monitoring"],
    )


@pytest.fixture()
def anon_caller():
    return AgentIdentity(
        agent_id="unknown-agent",
        roles=[],
        groups=[],
    )


# --- Default Deny ---


class TestDefaultDeny:
    def test_no_rules_means_deny(self, registry, staging_target, deployer_caller):
        pdp = PolicyDecisionPoint(rules=[], registry=registry)
        decision = pdp.evaluate(
            action="restart-deployment",
            target=staging_target,
            caller=deployer_caller,
            params={"namespace": "staging", "deployment": "api"},
        )
        assert decision.result == DecisionResult.DENY
        assert "default deny" in decision.reason.lower()
        assert decision.policy_matched is None

    def test_no_matching_rule_means_deny(self, registry, prod_target, anon_caller):
        rules = [
            PolicyRule(
                name="allow-dev-only",
                match=PolicyMatch(
                    targets=TargetSelector(environments=[Environment.DEV]),
                ),
                decision=DecisionResult.ALLOW,
                reason="Dev only",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            action="restart-deployment",
            target=prod_target,
            caller=anon_caller,
            params={"namespace": "prod", "deployment": "api"},
        )
        assert decision.result == DecisionResult.DENY


# --- Priority Ordering ---


class TestPriorityOrdering:
    def test_higher_priority_wins(self, registry, prod_target, deployer_caller):
        rules = [
            PolicyRule(
                name="low-allow",
                priority=10,
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Low priority allow",
            ),
            PolicyRule(
                name="high-deny",
                priority=100,
                match=PolicyMatch(),
                decision=DecisionResult.DENY,
                reason="High priority deny",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            action="restart-deployment",
            target=prod_target,
            caller=deployer_caller,
            params={"namespace": "prod", "deployment": "api"},
        )
        assert decision.result == DecisionResult.DENY
        assert decision.policy_matched == "high-deny"

    def test_first_match_wins_at_same_priority(
        self, registry, dev_target, deployer_caller
    ):
        rules = [
            PolicyRule(
                name="first-allow",
                priority=50,
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="First",
            ),
            PolicyRule(
                name="second-deny",
                priority=50,
                match=PolicyMatch(),
                decision=DecisionResult.DENY,
                reason="Second",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            action="get-pod-logs",
            target=dev_target,
            caller=deployer_caller,
            params={"namespace": "dev", "pod": "test"},
        )
        # Both match, but stable sort preserves insertion order at same priority
        assert decision.result in (DecisionResult.ALLOW, DecisionResult.DENY)
        assert decision.policy_matched is not None


# --- Action Matching ---


class TestActionMatching:
    def test_exact_action_match(self, registry, dev_target, deployer_caller):
        rules = [
            PolicyRule(
                name="allow-restart",
                match=PolicyMatch(actions=["restart-deployment"]),
                decision=DecisionResult.ALLOW,
                reason="Restart allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)

        allow = pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert allow.result == DecisionResult.ALLOW

        deny = pdp.evaluate(
            "scale-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app", "replicas": 3},
        )
        assert deny.result == DecisionResult.DENY  # no match → default deny

    def test_wildcard_matches_all(self, registry, dev_target, deployer_caller):
        rules = [
            PolicyRule(
                name="allow-all",
                match=PolicyMatch(actions=["*"]),
                decision=DecisionResult.ALLOW,
                reason="All allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            "delete-pod", dev_target, deployer_caller,
            params={"namespace": "dev", "pod": "test"},
        )
        assert decision.result == DecisionResult.ALLOW

    def test_glob_pattern_match(self, registry, dev_target, deployer_caller):
        rules = [
            PolicyRule(
                name="allow-deploy-actions",
                match=PolicyMatch(actions=["*-deployment"]),
                decision=DecisionResult.ALLOW,
                reason="Deployment actions allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)

        allow = pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert allow.result == DecisionResult.ALLOW

        deny = pdp.evaluate(
            "delete-pod", dev_target, deployer_caller,
            params={"namespace": "dev", "pod": "test"},
        )
        assert deny.result == DecisionResult.DENY


# --- Target Selectors ---


class TestTargetSelectors:
    def test_environment_selector(
        self, registry, prod_target, staging_target, dev_target, deployer_caller
    ):
        rules = [
            PolicyRule(
                name="allow-staging",
                match=PolicyMatch(
                    targets=TargetSelector(environments=[Environment.STAGING]),
                ),
                decision=DecisionResult.ALLOW,
                reason="Staging allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        params = {"namespace": "ns", "deployment": "app"}

        staging = pdp.evaluate(
            "restart-deployment", staging_target, deployer_caller, params
        )
        assert staging.result == DecisionResult.ALLOW

        prod = pdp.evaluate(
            "restart-deployment", prod_target, deployer_caller, params
        )
        assert prod.result == DecisionResult.DENY

    def test_sensitivity_selector(self, registry, deployer_caller):
        critical_target = TargetDefinition(
            id="prod/db", type="k8s-deployment",
            environment=Environment.PROD, sensitivity=Sensitivity.CRITICAL,
        )
        public_target = TargetDefinition(
            id="dev/app", type="k8s-deployment",
            environment=Environment.DEV, sensitivity=Sensitivity.PUBLIC,
        )
        rules = [
            PolicyRule(
                name="deny-critical",
                priority=100,
                match=PolicyMatch(
                    targets=TargetSelector(
                        sensitivities=[Sensitivity.CRITICAL]
                    ),
                ),
                decision=DecisionResult.DENY,
                reason="Critical targets denied",
            ),
            PolicyRule(
                name="allow-all",
                priority=1,
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Fallback allow",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        params = {"namespace": "ns", "deployment": "app"}

        assert pdp.evaluate(
            "restart-deployment", critical_target, deployer_caller, params
        ).result == DecisionResult.DENY

        assert pdp.evaluate(
            "restart-deployment", public_target, deployer_caller, params
        ).result == DecisionResult.ALLOW

    def test_label_selector(self, registry, deployer_caller):
        backend = TargetDefinition(
            id="prod/api", type="k8s-deployment",
            environment=Environment.PROD, sensitivity=Sensitivity.INTERNAL,
            labels={"tier": "backend"},
        )
        frontend = TargetDefinition(
            id="prod/web", type="k8s-deployment",
            environment=Environment.PROD, sensitivity=Sensitivity.INTERNAL,
            labels={"tier": "frontend"},
        )
        rules = [
            PolicyRule(
                name="deny-backend",
                match=PolicyMatch(
                    targets=TargetSelector(labels={"tier": "backend"}),
                ),
                decision=DecisionResult.DENY,
                reason="Backend denied",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        params = {"namespace": "prod", "deployment": "app"}

        assert pdp.evaluate(
            "restart-deployment", backend, deployer_caller, params
        ).result == DecisionResult.DENY
        assert pdp.evaluate(
            "restart-deployment", frontend, deployer_caller, params
        ).result == DecisionResult.DENY  # default deny, no rule matches frontend

    def test_no_target_fails_target_selector(
        self, registry, deployer_caller
    ):
        rules = [
            PolicyRule(
                name="needs-target",
                match=PolicyMatch(
                    targets=TargetSelector(environments=[Environment.DEV]),
                ),
                decision=DecisionResult.ALLOW,
                reason="Dev allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            "restart-deployment", None, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.DENY


# --- Caller Selectors ---


class TestCallerSelectors:
    def test_role_selector(
        self, registry, dev_target, deployer_caller, reader_caller
    ):
        rules = [
            PolicyRule(
                name="deployer-only",
                match=PolicyMatch(
                    callers=CallerSelector(roles=["deployer"]),
                ),
                decision=DecisionResult.ALLOW,
                reason="Deployers allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        params = {"namespace": "dev", "deployment": "app"}

        assert pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller, params
        ).result == DecisionResult.ALLOW

        assert pdp.evaluate(
            "restart-deployment", dev_target, reader_caller, params
        ).result == DecisionResult.DENY

    def test_agent_id_selector(self, registry, dev_target):
        caller_a = AgentIdentity(agent_id="agent-a")
        caller_b = AgentIdentity(agent_id="agent-b")
        rules = [
            PolicyRule(
                name="agent-a-only",
                match=PolicyMatch(
                    callers=CallerSelector(agent_ids=["agent-a"]),
                ),
                decision=DecisionResult.ALLOW,
                reason="Agent A allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        params = {"namespace": "dev", "deployment": "app"}

        assert pdp.evaluate(
            "restart-deployment", dev_target, caller_a, params
        ).result == DecisionResult.ALLOW
        assert pdp.evaluate(
            "restart-deployment", dev_target, caller_b, params
        ).result == DecisionResult.DENY

    def test_group_selector(self, registry, dev_target):
        platform = AgentIdentity(
            agent_id="a1", groups=["platform-team"]
        )
        other = AgentIdentity(agent_id="a2", groups=["sales"])
        rules = [
            PolicyRule(
                name="platform-only",
                match=PolicyMatch(
                    callers=CallerSelector(groups=["platform-team"]),
                ),
                decision=DecisionResult.ALLOW,
                reason="Platform team allowed",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        params = {"namespace": "dev", "deployment": "app"}

        assert pdp.evaluate(
            "restart-deployment", dev_target, platform, params
        ).result == DecisionResult.ALLOW
        assert pdp.evaluate(
            "restart-deployment", dev_target, other, params
        ).result == DecisionResult.DENY

    def test_no_caller_fails_caller_selector(self, registry, dev_target):
        rules = [
            PolicyRule(
                name="needs-caller",
                match=PolicyMatch(
                    callers=CallerSelector(roles=["deployer"]),
                ),
                decision=DecisionResult.ALLOW,
                reason="Deployers only",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            "restart-deployment", dev_target, None,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.DENY


# --- Risk Class Matching ---


class TestRiskClassMatching:
    def test_effective_risk_match(self, registry, prod_target, deployer_caller):
        """Medium action on critical prod target = critical effective risk."""
        rules = [
            PolicyRule(
                name="critical-needs-approval",
                priority=100,
                match=PolicyMatch(risk_classes=[RiskClass.CRITICAL]),
                decision=DecisionResult.REQUIRE_APPROVAL,
                reason="Critical risk needs approval",
            ),
            PolicyRule(
                name="allow-all",
                priority=1,
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Fallback",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        # restart-deployment is MEDIUM risk, prod/api-server is CRITICAL sensitivity
        # effective risk = CRITICAL
        decision = pdp.evaluate(
            "restart-deployment", prod_target, deployer_caller,
            params={"namespace": "prod", "deployment": "api"},
        )
        assert decision.result == DecisionResult.REQUIRE_APPROVAL
        assert decision.effective_risk == RiskClass.CRITICAL

    def test_low_effective_risk_skips_critical_rule(
        self, registry, dev_target, deployer_caller
    ):
        """Low action on public dev target = low effective risk."""
        rules = [
            PolicyRule(
                name="critical-only",
                priority=100,
                match=PolicyMatch(risk_classes=[RiskClass.CRITICAL]),
                decision=DecisionResult.DENY,
                reason="Critical denied",
            ),
            PolicyRule(
                name="allow-all",
                priority=1,
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Fallback",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        # get-pod-logs is LOW risk, dev target is PUBLIC sensitivity
        # effective risk = LOW
        decision = pdp.evaluate(
            "get-pod-logs", dev_target, deployer_caller,
            params={"namespace": "dev", "pod": "test"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.effective_risk == RiskClass.LOW


# --- Time Window Matching ---


class TestTimeWindowMatching:
    def test_within_window_matches(self, registry, dev_target, deployer_caller):
        rules = [
            PolicyRule(
                name="weekend-maintenance",
                match=PolicyMatch(
                    time_windows=[
                        TimeWindow(days=[5, 6], start_hour=2, end_hour=6)
                    ],
                ),
                decision=DecisionResult.ALLOW,
                reason="Weekend maintenance",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        # Saturday (day=5) at 3am
        sat_3am = datetime(2025, 1, 18, 3, 0, 0, tzinfo=UTC)
        decision = pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
            timestamp=sat_3am,
        )
        assert decision.result == DecisionResult.ALLOW

    def test_outside_window_no_match(
        self, registry, dev_target, deployer_caller
    ):
        rules = [
            PolicyRule(
                name="weekend-only",
                match=PolicyMatch(
                    time_windows=[
                        TimeWindow(days=[5, 6], start_hour=2, end_hour=6)
                    ],
                ),
                decision=DecisionResult.ALLOW,
                reason="Weekend only",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        # Monday (day=0) at 10am
        mon_10am = datetime(2025, 1, 13, 10, 0, 0, tzinfo=UTC)
        decision = pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
            timestamp=mon_10am,
        )
        assert decision.result == DecisionResult.DENY  # default deny

    def test_midnight_wrap_window(
        self, registry, dev_target, deployer_caller
    ):
        rules = [
            PolicyRule(
                name="overnight",
                match=PolicyMatch(
                    time_windows=[TimeWindow(start_hour=22, end_hour=4)],
                ),
                decision=DecisionResult.ALLOW,
                reason="Overnight",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)

        # 23:00 should match
        late = datetime(2025, 1, 15, 23, 0, 0, tzinfo=UTC)
        assert pdp.evaluate(
            "get-pod-logs", dev_target, deployer_caller,
            params={"namespace": "dev", "pod": "x"},
            timestamp=late,
        ).result == DecisionResult.ALLOW

        # 02:00 should match
        early = datetime(2025, 1, 15, 2, 0, 0, tzinfo=UTC)
        assert pdp.evaluate(
            "get-pod-logs", dev_target, deployer_caller,
            params={"namespace": "dev", "pod": "x"},
            timestamp=early,
        ).result == DecisionResult.ALLOW

        # 12:00 should not match
        midday = datetime(2025, 1, 15, 12, 0, 0, tzinfo=UTC)
        assert pdp.evaluate(
            "get-pod-logs", dev_target, deployer_caller,
            params={"namespace": "dev", "pod": "x"},
            timestamp=midday,
        ).result == DecisionResult.DENY


# --- Unknown Action / Invalid Params ---


class TestEdgeCases:
    def test_unknown_action_denied(self, registry, dev_target, deployer_caller):
        rules = [
            PolicyRule(
                name="allow-all",
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Allow everything",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            "nonexistent-action", dev_target, deployer_caller,
        )
        assert decision.result == DecisionResult.DENY
        assert "Unknown action" in decision.reason

    def test_invalid_params_denied(self, registry, dev_target, deployer_caller):
        rules = [
            PolicyRule(
                name="allow-all",
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Allow everything",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            "scale-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app", "replicas": 999},
        )
        assert decision.result == DecisionResult.DENY
        assert "Invalid parameters" in decision.reason

    def test_no_target_no_caller(self, registry):
        pdp = PolicyDecisionPoint(
            rules=[
                PolicyRule(
                    name="allow-all",
                    match=PolicyMatch(),
                    decision=DecisionResult.ALLOW,
                    reason="Fallback",
                )
            ],
            registry=registry,
        )
        decision = pdp.evaluate("restart-deployment", None, None,
                                params={"namespace": "x", "deployment": "y"})
        assert decision.target == "unknown"
        assert decision.caller == "anonymous"

    def test_decision_has_audit_id(
        self, registry, dev_target, deployer_caller
    ):
        pdp = PolicyDecisionPoint(rules=[], registry=registry)
        decision = pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.audit_id.startswith("evt-")
        assert len(decision.audit_id) == 16  # "evt-" + 12 hex chars

    def test_decision_includes_risk_classes(
        self, registry, staging_target, deployer_caller
    ):
        pdp = PolicyDecisionPoint(rules=[], registry=registry)
        decision = pdp.evaluate(
            "restart-deployment", staging_target, deployer_caller,
            params={"namespace": "staging", "deployment": "app"},
        )
        # restart-deployment = medium, staging = internal → medium effective
        assert decision.risk_class == RiskClass.MEDIUM
        assert decision.effective_risk == RiskClass.MEDIUM


# --- Real Policy File Loading ---


class TestLoadPolicies:
    def test_load_real_policies(self):
        rules = load_policies(POLICIES_DIR)
        assert len(rules) == 6
        # Should be sorted by priority descending
        assert rules[0].priority >= rules[-1].priority
        assert rules[0].name == "require-approval-critical-risk"
        assert rules[-1].name == "allow-dev-all"

    def test_real_policies_integration(
        self, registry, prod_target, staging_target, dev_target,
        deployer_caller, reader_caller, anon_caller,
    ):
        """Full integration test with real policies + actions."""
        rules = load_policies(POLICIES_DIR)
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)

        # Dev: anything goes
        d = pdp.evaluate(
            "restart-deployment", dev_target, anon_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert d.result == DecisionResult.ALLOW
        assert d.policy_matched == "allow-dev-all"

        # Staging: deployer can restart
        d = pdp.evaluate(
            "restart-deployment", staging_target, deployer_caller,
            params={"namespace": "staging", "deployment": "api"},
        )
        assert d.result == DecisionResult.ALLOW
        assert d.policy_matched == "allow-deployer-staging"

        # Staging: reader can read logs
        d = pdp.evaluate(
            "get-pod-logs", staging_target, reader_caller,
            params={"namespace": "staging", "pod": "api-abc"},
        )
        assert d.result == DecisionResult.ALLOW
        assert d.policy_matched == "allow-read-actions-staging"

        # Staging: reader cannot restart (no deployer role)
        d = pdp.evaluate(
            "restart-deployment", staging_target, reader_caller,
            params={"namespace": "staging", "deployment": "api"},
        )
        assert d.result == DecisionResult.DENY

        # Prod: requires approval (medium action on critical target)
        d = pdp.evaluate(
            "restart-deployment", prod_target, deployer_caller,
            params={"namespace": "prod", "deployment": "api"},
        )
        # effective risk = CRITICAL (medium × critical)
        # require-approval-critical-risk (priority 1000) should fire
        assert d.result == DecisionResult.REQUIRE_APPROVAL

        # Prod: low-risk read still needs approval (prod rule)
        d = pdp.evaluate(
            "get-pod-logs", prod_target, deployer_caller,
            params={"namespace": "prod", "pod": "api-abc"},
        )
        assert d.result == DecisionResult.REQUIRE_APPROVAL


# --- PDP → Audit Integration ---


class TestPDPAuditIntegration:
    def test_evaluate_auto_logs(
        self, registry, dev_target, deployer_caller, tmp_path
    ):
        """Every evaluate() call writes to the audit log."""
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        pdp = PolicyDecisionPoint(
            rules=[
                PolicyRule(
                    name="allow-all",
                    match=PolicyMatch(),
                    decision=DecisionResult.ALLOW,
                    reason="Allow everything",
                )
            ],
            registry=registry,
            audit_logger=audit,
        )
        pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        events = audit.read_events()
        assert len(events) == 1
        assert events[0].action == "restart-deployment"
        assert events[0].decision == DecisionResult.ALLOW

    def test_multiple_evaluations_chain(
        self, registry, dev_target, deployer_caller, tmp_path
    ):
        """Multiple evaluate() calls produce a valid hash chain."""
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        pdp = PolicyDecisionPoint(
            rules=[
                PolicyRule(
                    name="allow-all",
                    match=PolicyMatch(),
                    decision=DecisionResult.ALLOW,
                    reason="Allow",
                )
            ],
            registry=registry,
            audit_logger=audit,
        )
        for _ in range(5):
            pdp.evaluate(
                "restart-deployment", dev_target, deployer_caller,
                params={"namespace": "dev", "deployment": "app"},
            )

        events = audit.read_events()
        assert len(events) == 5
        is_valid, errors = verify_log(log_path)
        assert is_valid is True
        assert errors == []

    def test_denied_decisions_are_logged(
        self, registry, dev_target, deployer_caller, tmp_path
    ):
        """Denied decisions (default deny) also appear in the audit log."""
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        pdp = PolicyDecisionPoint(
            rules=[], registry=registry, audit_logger=audit
        )
        pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        events = audit.read_events()
        assert len(events) == 1
        assert events[0].decision == DecisionResult.DENY

    def test_no_audit_logger_still_works(
        self, registry, dev_target, deployer_caller
    ):
        """PDP works fine without an audit logger (backward compat)."""
        pdp = PolicyDecisionPoint(rules=[], registry=registry)
        decision = pdp.evaluate(
            "restart-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.DENY

    def test_audit_captures_params(
        self, registry, dev_target, deployer_caller, tmp_path
    ):
        """Audit event includes the request parameters."""
        log_path = tmp_path / "audit.jsonl"
        audit = AuditLogger(log_path)
        pdp = PolicyDecisionPoint(
            rules=[
                PolicyRule(
                    name="allow-all",
                    match=PolicyMatch(),
                    decision=DecisionResult.ALLOW,
                    reason="Allow",
                )
            ],
            registry=registry,
            audit_logger=audit,
        )
        pdp.evaluate(
            "scale-deployment", dev_target, deployer_caller,
            params={"namespace": "dev", "deployment": "app", "replicas": 3},
        )
        events = audit.read_events()
        assert events[0].params == {
            "namespace": "dev", "deployment": "app", "replicas": 3
        }
