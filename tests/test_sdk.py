"""Tests for the AgentSafe SDK (public API)."""

from pathlib import Path

import pytest

from agent_safe import AgentSafe
from agent_safe.models import AgentIdentity, DecisionResult, RiskClass

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"


@pytest.fixture()
def safe(tmp_path: Path) -> AgentSafe:
    return AgentSafe(
        registry=ACTIONS_DIR,
        policies=POLICIES_DIR,
        inventory=INVENTORY_FILE,
        audit_log=tmp_path / "audit.jsonl",
    )


@pytest.fixture()
def safe_with_identity(tmp_path: Path) -> AgentSafe:
    return AgentSafe(
        registry=ACTIONS_DIR,
        policies=POLICIES_DIR,
        inventory=INVENTORY_FILE,
        audit_log=tmp_path / "audit.jsonl",
        signing_key="test-secret-key-for-sdk-tests",
    )


# --- Initialization ---


class TestInit:
    def test_creates_successfully(self, safe: AgentSafe):
        assert safe.registry is not None
        assert len(safe.list_actions()) > 0

    def test_without_inventory(self, tmp_path: Path):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        # Should work — inventory is optional
        decision = s.check(
            action="restart-deployment",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result in (
            DecisionResult.ALLOW, DecisionResult.DENY,
            DecisionResult.REQUIRE_APPROVAL,
        )

    def test_without_audit_log(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        assert s.audit is None

    def test_with_audit_log(self, tmp_path: Path):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            audit_log=tmp_path / "audit.jsonl",
        )
        assert s.audit is not None

    def test_with_identity(self, safe_with_identity: AgentSafe):
        assert safe_with_identity.identity is not None


# --- check() ---


class TestCheck:
    def test_dev_target_allowed(self, safe: AgentSafe):
        """Dev targets should be allowed by the allow-dev-all rule."""
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="any-agent",
            params={"namespace": "dev", "deployment": "test-app"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.policy_matched == "allow-dev-all"

    def test_prod_target_requires_approval(self, safe: AgentSafe):
        """Prod critical targets require approval."""
        decision = safe.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        assert decision.result == DecisionResult.REQUIRE_APPROVAL

    def test_unknown_action_denied(self, safe: AgentSafe):
        decision = safe.check(action="nuke-everything")
        assert decision.result == DecisionResult.DENY
        assert "Unknown action" in decision.reason

    def test_no_target_no_caller(self, safe: AgentSafe):
        decision = safe.check(
            action="restart-deployment",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.target == "unknown"
        assert decision.caller == "anonymous"

    def test_string_caller_becomes_agent_id(self, safe: AgentSafe):
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="my-agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.caller == "my-agent"

    def test_agent_identity_caller(self, safe: AgentSafe):
        identity = AgentIdentity(
            agent_id="deploy-agent-01",
            roles=["deployer"],
            groups=["platform-team"],
        )
        decision = safe.check(
            action="restart-deployment",
            target="staging/api-server",
            caller=identity,
            params={"namespace": "staging", "deployment": "api"},
        )
        assert decision.caller == "deploy-agent-01"
        assert decision.result == DecisionResult.ALLOW

    def test_jwt_caller(self, safe_with_identity: AgentSafe):
        """A valid JWT token is resolved to agent identity."""
        token = safe_with_identity.identity.create_token(
            agent_id="deploy-agent-01",
            roles=["deployer"],
            groups=["platform-team"],
        )
        decision = safe_with_identity.check(
            action="restart-deployment",
            target="staging/api-server",
            caller=token,
            params={"namespace": "staging", "deployment": "api"},
        )
        assert decision.caller == "deploy-agent-01"
        assert decision.result == DecisionResult.ALLOW

    def test_invalid_params_denied(self, safe: AgentSafe):
        decision = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            caller="any-agent",
            params={"namespace": "dev", "deployment": "app", "replicas": 999},
        )
        assert decision.result == DecisionResult.DENY
        assert "Invalid parameters" in decision.reason

    def test_decision_has_audit_id(self, safe: AgentSafe):
        decision = safe.check(
            action="get-pod-logs",
            target="dev/test-app",
            caller="reader",
            params={"namespace": "dev", "pod": "test"},
        )
        assert decision.audit_id.startswith("evt-")

    def test_decision_has_risk_classes(self, safe: AgentSafe):
        decision = safe.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        assert decision.risk_class == RiskClass.MEDIUM
        assert decision.effective_risk == RiskClass.CRITICAL

    def test_unknown_target_still_works(self, safe: AgentSafe):
        """A target not in inventory resolves to None (no target context)."""
        decision = safe.check(
            action="restart-deployment",
            target="nonexistent/target",
            caller="any-agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        # No target resolved, so target_id = "unknown"
        assert decision.target == "unknown"


# --- check_plan() ---


class TestCheckPlan:
    def test_batch_check(self, safe: AgentSafe):
        steps = [
            {
                "action": "get-pod-logs",
                "target": "dev/test-app",
                "caller": "reader",
                "params": {"namespace": "dev", "pod": "test"},
            },
            {
                "action": "restart-deployment",
                "target": "dev/test-app",
                "caller": "deployer",
                "params": {"namespace": "dev", "deployment": "app"},
            },
            {
                "action": "restart-deployment",
                "target": "prod/api-server",
                "caller": "deployer",
                "params": {"namespace": "prod", "deployment": "api-server"},
            },
        ]
        decisions = safe.check_plan(steps)
        assert len(decisions) == 3
        # Dev: allowed
        assert decisions[0].result == DecisionResult.ALLOW
        assert decisions[1].result == DecisionResult.ALLOW
        # Prod: requires approval
        assert decisions[2].result == DecisionResult.REQUIRE_APPROVAL

    def test_empty_plan(self, safe: AgentSafe):
        assert safe.check_plan([]) == []


# --- Audit integration ---


class TestAuditIntegration:
    def test_check_writes_audit(self, safe: AgentSafe):
        safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="any-agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        events = safe.audit.read_events()
        assert len(events) == 1
        assert events[0].action == "restart-deployment"

    def test_verify_audit_valid(self, safe: AgentSafe):
        for _ in range(3):
            safe.check(
                action="get-pod-logs",
                target="dev/test-app",
                caller="reader",
                params={"namespace": "dev", "pod": "x"},
            )
        is_valid, errors = safe.verify_audit()
        assert is_valid is True
        assert errors == []

    def test_verify_audit_no_logger(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        is_valid, errors = s.verify_audit()
        assert is_valid is True
        assert errors == []


# --- list_actions ---


class TestListActions:
    def test_lists_all_actions(self, safe: AgentSafe):
        actions = safe.list_actions()
        assert len(actions) >= 5
        assert "restart-deployment" in actions
        assert "scale-deployment" in actions
        assert "delete-pod" in actions
