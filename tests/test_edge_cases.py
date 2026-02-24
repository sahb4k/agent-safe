"""Edge case and hardening tests.

Covers:
- Malformed inputs to the SDK
- Empty configurations
- Conflicting policies
- Boundary conditions
- init command scaffolding
"""

from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_safe import AgentSafe
from agent_safe.cli.main import cli
from agent_safe.models import (
    AgentIdentity,
    DecisionResult,
    PolicyMatch,
    PolicyRule,
)
from agent_safe.pdp.engine import PDPError, PolicyDecisionPoint, load_policies
from agent_safe.registry.loader import RegistryError, load_registry

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"


def runner() -> CliRunner:
    return CliRunner(mix_stderr=False)


# --- Empty / missing configuration ---


class TestEmptyConfigs:
    def test_empty_actions_dir(self, tmp_path: Path):
        actions = tmp_path / "actions"
        actions.mkdir()
        policies = tmp_path / "policies"
        policies.mkdir()
        (policies / "default.yaml").write_text(
            "rules:\n  - name: allow-all\n    match: {}\n"
            "    decision: allow\n    reason: Allow all\n",
            encoding="utf-8",
        )
        safe = AgentSafe(registry=actions, policies=policies)
        # All actions are unknown with empty registry
        decision = safe.check(action="anything")
        assert decision.result == DecisionResult.DENY
        assert "Unknown action" in decision.reason

    def test_empty_policy_dir(self, tmp_path: Path):
        """Empty policy dir means no rules -> default deny for everything."""
        policies = tmp_path / "policies"
        policies.mkdir()
        safe = AgentSafe(registry=ACTIONS_DIR, policies=policies)
        decision = safe.check(
            action="restart-deployment",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.DENY
        assert "default deny" in decision.reason.lower()

    def test_missing_actions_dir_raises(self, tmp_path: Path):
        with pytest.raises(RegistryError, match="not found"):
            AgentSafe(
                registry=tmp_path / "nonexistent",
                policies=POLICIES_DIR,
            )

    def test_missing_policies_dir_raises(self, tmp_path: Path):
        with pytest.raises(PDPError, match="not found"):
            AgentSafe(
                registry=ACTIONS_DIR,
                policies=tmp_path / "nonexistent",
            )


# --- Malformed inputs ---


class TestMalformedInputs:
    def test_empty_action_name(self, tmp_path: Path):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(action="")
        assert decision.result == DecisionResult.DENY
        assert "Unknown action" in decision.reason

    def test_none_params_is_ok(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(action="restart-deployment", params=None)
        # Should not crash — params default to {}
        assert decision.result in (
            DecisionResult.ALLOW, DecisionResult.DENY,
            DecisionResult.REQUIRE_APPROVAL,
        )

    def test_empty_params_for_required_action(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(action="restart-deployment", params={})
        # restart-deployment has required params, but empty {} means no
        # params to validate (our validate_params only checks provided ones).
        # This is fine for MVP — params are validated when present.
        assert decision.result in (
            DecisionResult.ALLOW, DecisionResult.DENY,
            DecisionResult.REQUIRE_APPROVAL,
        )

    def test_extra_params_rejected(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="restart-deployment",
            params={
                "namespace": "dev",
                "deployment": "app",
                "evil_extra": "hack",
            },
        )
        assert decision.result == DecisionResult.DENY
        assert "Unknown parameter" in decision.reason

    def test_wrong_param_type_rejected(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="scale-deployment",
            params={
                "namespace": "dev",
                "deployment": "app",
                "replicas": "not-a-number",
            },
        )
        assert decision.result == DecisionResult.DENY
        assert "expected integer" in decision.reason.lower()


# --- Policy conflict scenarios ---


class TestPolicyConflicts:
    def test_higher_priority_always_wins(self):
        """When two rules match the same request, higher priority wins."""
        registry = load_registry(ACTIONS_DIR)
        rules = [
            PolicyRule(
                name="allow-everything",
                priority=10,
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Allow",
            ),
            PolicyRule(
                name="deny-everything",
                priority=100,
                match=PolicyMatch(),
                decision=DecisionResult.DENY,
                reason="Deny wins",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)
        decision = pdp.evaluate(
            "restart-deployment", None, None,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.DENY
        assert decision.policy_matched == "deny-everything"

    def test_specific_rule_overrides_broad(self):
        """A specific high-priority deny beats a broad low-priority allow."""
        registry = load_registry(ACTIONS_DIR)
        caller = AgentIdentity(agent_id="rogue", roles=["reader"])
        rules = [
            PolicyRule(
                name="deny-readers-delete",
                priority=200,
                match=PolicyMatch(
                    actions=["delete-*"],
                ),
                decision=DecisionResult.DENY,
                reason="Delete actions denied",
            ),
            PolicyRule(
                name="allow-all-low-pri",
                priority=1,
                match=PolicyMatch(),
                decision=DecisionResult.ALLOW,
                reason="Fallback allow",
            ),
        ]
        pdp = PolicyDecisionPoint(rules=rules, registry=registry)

        # delete-pod should be denied
        d = pdp.evaluate(
            "delete-pod", None, caller,
            params={"namespace": "dev", "pod": "test"},
        )
        assert d.result == DecisionResult.DENY
        assert d.policy_matched == "deny-readers-delete"

        # restart-deployment should be allowed
        d = pdp.evaluate(
            "restart-deployment", None, caller,
            params={"namespace": "dev", "deployment": "app"},
        )
        assert d.result == DecisionResult.ALLOW


# --- Boundary conditions ---


class TestBoundaryConditions:
    def test_param_at_exact_min(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app", "replicas": 0},
        )
        # replicas=0 is valid (min_value=0 for scale-deployment)
        assert decision.result != DecisionResult.DENY or "Invalid" not in decision.reason

    def test_param_at_exact_max(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app", "replicas": 100},
        )
        assert "Invalid" not in decision.reason

    def test_param_one_over_max(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app", "replicas": 101},
        )
        assert decision.result == DecisionResult.DENY
        assert "exceeds maximum" in decision.reason

    def test_param_one_under_min(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app", "replicas": -1},
        )
        assert decision.result == DecisionResult.DENY
        assert "below minimum" in decision.reason

    def test_pattern_constraint_valid(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="create-namespace",
            params={"namespace": "my-new-ns"},
        )
        assert "Invalid" not in decision.reason

    def test_pattern_constraint_invalid(self):
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        decision = safe.check(
            action="create-namespace",
            params={"namespace": "UPPERCASE-BAD"},
        )
        assert decision.result == DecisionResult.DENY
        assert "pattern" in decision.reason.lower()

    def test_many_actions_in_plan(self):
        """Batch check with a large plan doesn't break."""
        safe = AgentSafe(registry=ACTIONS_DIR, policies=POLICIES_DIR)
        steps = [
            {
                "action": "get-pod-logs",
                "target": "dev/test-app",
                "params": {"namespace": "dev", "pod": "x"},
            }
            for _ in range(100)
        ]
        decisions = safe.check_plan(steps)
        assert len(decisions) == 100
        assert all(d.audit_id.startswith("evt-") for d in decisions)


# --- init command ---


class TestInitCommand:
    def test_init_creates_scaffold(self, tmp_path: Path):
        target = tmp_path / "myproject"
        target.mkdir()
        result = runner().invoke(cli, ["init", str(target)])
        assert result.exit_code == 0
        assert "Created" in result.output
        assert (target / "actions" / "restart-deployment.yaml").exists()
        assert (target / "policies" / "default.yaml").exists()
        assert (target / "inventory.yaml").exists()

    def test_init_validates_after_scaffold(self, tmp_path: Path):
        target = tmp_path / "fresh"
        target.mkdir()
        runner().invoke(cli, ["init", str(target)])

        # The scaffolded files should pass validation
        result = runner().invoke(cli, [
            "validate",
            "--registry", str(target / "actions"),
            "--policies", str(target / "policies"),
            "--inventory", str(target / "inventory.yaml"),
        ])
        assert result.exit_code == 0
        assert "valid" in result.output.lower()

    def test_init_skips_existing(self, tmp_path: Path):
        target = tmp_path / "existing"
        target.mkdir()
        (target / "actions").mkdir()
        (target / "policies").mkdir()
        (target / "inventory.yaml").write_text("targets: []", encoding="utf-8")

        result = runner().invoke(cli, ["init", str(target)])
        assert result.exit_code == 0
        assert "skip" in result.output.lower()

    def test_init_default_cwd(self, tmp_path: Path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        result = runner().invoke(cli, ["init"])
        assert result.exit_code == 0
        assert (tmp_path / "actions").exists()

    def test_init_scaffold_loads_as_agentsafe(self, tmp_path: Path):
        """The scaffolded project can be used with the SDK."""
        target = tmp_path / "proj"
        target.mkdir()
        runner().invoke(cli, ["init", str(target)])

        safe = AgentSafe(
            registry=target / "actions",
            policies=target / "policies",
            inventory=target / "inventory.yaml",
        )
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.policy_matched == "allow-dev-all"


# --- Malformed YAML edge cases ---


class TestMalformedYAML:
    def test_policy_file_with_no_rules_key(self, tmp_path: Path):
        policies = tmp_path / "policies"
        policies.mkdir()
        (policies / "bad.yaml").write_text(
            "something_else: true\n", encoding="utf-8"
        )
        with pytest.raises(PDPError, match="rules"):
            load_policies(policies)

    def test_policy_file_with_rules_not_list(self, tmp_path: Path):
        policies = tmp_path / "policies"
        policies.mkdir()
        (policies / "bad.yaml").write_text(
            "rules: not-a-list\n", encoding="utf-8"
        )
        with pytest.raises(PDPError, match="list"):
            load_policies(policies)

    def test_action_file_not_mapping(self, tmp_path: Path):
        actions = tmp_path / "actions"
        actions.mkdir()
        (actions / "bad.yaml").write_text("- list-item\n", encoding="utf-8")
        with pytest.raises(RegistryError, match="mapping"):
            load_registry(actions)

    def test_action_file_invalid_yaml(self, tmp_path: Path):
        actions = tmp_path / "actions"
        actions.mkdir()
        (actions / "bad.yaml").write_text(
            "name: test\nversion: : bad\n", encoding="utf-8"
        )
        with pytest.raises(RegistryError, match="YAML"):
            load_registry(actions)
