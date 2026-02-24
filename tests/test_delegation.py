"""Tests for multi-agent delegation."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_safe.cli.main import cli
from agent_safe.identity.manager import (
    DelegationError,
    IdentityManager,
)
from agent_safe.models import (
    AgentIdentity,
    CallerSelector,
    DelegationLink,
    DelegationResult,
)
from agent_safe.sdk.client import AgentSafe, AgentSafeError

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"
SIGNING_KEY = "test-delegation-key"


def _mgr() -> IdentityManager:
    return IdentityManager(SIGNING_KEY)


def _parent_token(
    roles: list[str] | None = None,
    groups: list[str] | None = None,
    ttl: timedelta | None = None,
) -> str:
    return _mgr().create_token(
        agent_id="orchestrator-01",
        agent_name="Orchestrator",
        roles=roles or ["deployer", "reader"],
        groups=groups or ["infra-team"],
        ttl=ttl or timedelta(hours=1),
    )


# --- DelegationLink ---


class TestDelegationLink:
    def test_construction(self):
        link = DelegationLink(
            agent_id="agent-a",
            agent_name="Agent A",
            roles=["deployer"],
            groups=["team-1"],
            delegated_at=datetime.now(tz=UTC),
        )
        assert link.agent_id == "agent-a"
        assert link.roles == ["deployer"]

    def test_minimal(self):
        link = DelegationLink(
            agent_id="agent-b",
            delegated_at=datetime.now(tz=UTC),
        )
        assert link.agent_name == ""
        assert link.roles == []
        assert link.groups == []


# --- Delegation Models ---


class TestDelegationModels:
    def test_agent_identity_with_delegation(self):
        link = DelegationLink(
            agent_id="parent-01",
            delegated_at=datetime.now(tz=UTC),
        )
        identity = AgentIdentity(
            agent_id="child-01",
            delegation_chain=[link],
            delegated_roles=["deployer"],
            delegation_depth=1,
        )
        assert identity.delegation_depth == 1
        assert len(identity.delegation_chain) == 1
        assert identity.delegated_roles == ["deployer"]

    def test_agent_identity_without_delegation_backward_compat(self):
        identity = AgentIdentity(agent_id="plain-agent")
        assert identity.delegation_chain == []
        assert identity.delegated_roles == []
        assert identity.delegation_depth == 0

    def test_delegation_result_success(self):
        result = DelegationResult(
            success=True,
            token="jwt-token",
            parent_agent_id="parent-01",
            child_agent_id="child-01",
            delegation_depth=1,
        )
        assert result.success is True
        assert result.token == "jwt-token"

    def test_delegation_result_failure(self):
        result = DelegationResult(
            success=False,
            error="Depth exceeded",
            child_agent_id="child-01",
        )
        assert result.success is False
        assert "Depth" in result.error


# --- CallerSelector delegation fields ---


class TestCallerSelectorDelegation:
    def test_defaults_are_none(self):
        sel = CallerSelector()
        assert sel.delegated_from is None
        assert sel.max_delegation_depth is None
        assert sel.require_delegation is None

    def test_delegated_from_matches(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(delegated_from=["orchestrator-01"])
        caller = AgentIdentity(
            agent_id="worker-01",
            delegation_chain=[
                DelegationLink(
                    agent_id="orchestrator-01",
                    delegated_at=datetime.now(tz=UTC),
                ),
            ],
            delegation_depth=1,
        )
        assert _caller_matches(sel, caller) is True

    def test_delegated_from_no_match(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(delegated_from=["other-agent"])
        caller = AgentIdentity(
            agent_id="worker-01",
            delegation_chain=[
                DelegationLink(
                    agent_id="orchestrator-01",
                    delegated_at=datetime.now(tz=UTC),
                ),
            ],
            delegation_depth=1,
        )
        assert _caller_matches(sel, caller) is False

    def test_max_delegation_depth_matches(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(max_delegation_depth=2)
        caller = AgentIdentity(agent_id="w", delegation_depth=1)
        assert _caller_matches(sel, caller) is True

    def test_max_delegation_depth_exceeded(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(max_delegation_depth=1)
        caller = AgentIdentity(agent_id="w", delegation_depth=2)
        assert _caller_matches(sel, caller) is False

    def test_require_delegation_true_matches_delegated(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(require_delegation=True)
        caller = AgentIdentity(agent_id="w", delegation_depth=1)
        assert _caller_matches(sel, caller) is True

    def test_require_delegation_true_rejects_direct(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(require_delegation=True)
        caller = AgentIdentity(agent_id="w", delegation_depth=0)
        assert _caller_matches(sel, caller) is False

    def test_require_delegation_false_matches_direct(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(require_delegation=False)
        caller = AgentIdentity(agent_id="w", delegation_depth=0)
        assert _caller_matches(sel, caller) is True

    def test_require_delegation_false_rejects_delegated(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(require_delegation=False)
        caller = AgentIdentity(agent_id="w", delegation_depth=1)
        assert _caller_matches(sel, caller) is False

    def test_require_delegation_none_matches_both(self):
        from agent_safe.pdp.engine import _caller_matches

        sel = CallerSelector(require_delegation=None)
        direct = AgentIdentity(agent_id="d", delegation_depth=0)
        delegated = AgentIdentity(agent_id="w", delegation_depth=1)
        assert _caller_matches(sel, direct) is True
        assert _caller_matches(sel, delegated) is True


# --- create_delegation_token ---


class TestCreateDelegationToken:
    def test_simple_delegation(self):
        mgr = _mgr()
        parent = _parent_token()
        child_token = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        identity = mgr.validate_token(child_token)
        assert identity.agent_id == "worker-01"
        assert identity.delegation_depth == 1
        assert len(identity.delegation_chain) == 1
        assert identity.delegation_chain[0].agent_id == "orchestrator-01"
        assert identity.delegated_roles == ["deployer"]

    def test_delegation_chain_grows(self):
        mgr = _mgr()
        parent = _parent_token()
        child1 = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        child2 = mgr.create_delegation_token(
            parent_token=child1,
            child_agent_id="worker-02",
            child_roles=["deployer"],
        )
        identity = mgr.validate_token(child2)
        assert identity.delegation_depth == 2
        assert len(identity.delegation_chain) == 2
        assert identity.delegation_chain[0].agent_id == "orchestrator-01"
        assert identity.delegation_chain[1].agent_id == "worker-01"

    def test_multi_hop_delegation(self):
        mgr = _mgr()
        token = _parent_token()
        for i in range(3):
            token = mgr.create_delegation_token(
                parent_token=token,
                child_agent_id=f"worker-{i}",
                child_roles=["deployer"],
            )
        identity = mgr.validate_token(token)
        assert identity.delegation_depth == 3
        assert len(identity.delegation_chain) == 3

    def test_depth_limit_enforced(self):
        mgr = _mgr()
        token = _parent_token()
        token = mgr.create_delegation_token(
            parent_token=token,
            child_agent_id="w1",
            child_roles=["deployer"],
            max_depth=2,
        )
        token = mgr.create_delegation_token(
            parent_token=token,
            child_agent_id="w2",
            child_roles=["deployer"],
            max_depth=2,
        )
        with pytest.raises(DelegationError, match="exceeds max depth"):
            mgr.create_delegation_token(
                parent_token=token,
                child_agent_id="w3",
                child_roles=["deployer"],
                max_depth=2,
            )

    def test_role_scope_narrowing(self):
        mgr = _mgr()
        parent = _parent_token(roles=["deployer", "reader", "admin"])
        child_token = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="w1",
            child_roles=["deployer"],
        )
        identity = mgr.validate_token(child_token)
        assert identity.roles == ["deployer"]
        assert identity.delegated_roles == ["deployer"]

    def test_role_escalation_rejected(self):
        mgr = _mgr()
        parent = _parent_token(roles=["reader"])
        with pytest.raises(DelegationError, match="not held by parent"):
            mgr.create_delegation_token(
                parent_token=parent,
                child_agent_id="w1",
                child_roles=["admin"],
            )

    def test_group_scope_narrowing(self):
        mgr = _mgr()
        parent = _parent_token(groups=["infra-team", "dev-team"])
        child_token = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="w1",
            child_groups=["infra-team"],
        )
        identity = mgr.validate_token(child_token)
        assert identity.groups == ["infra-team"]

    def test_group_escalation_rejected(self):
        mgr = _mgr()
        parent = _parent_token(groups=["dev-team"])
        with pytest.raises(DelegationError, match="not held by parent"):
            mgr.create_delegation_token(
                parent_token=parent,
                child_agent_id="w1",
                child_groups=["admin-team"],
            )

    def test_ttl_capped_at_parent_remaining(self):
        mgr = _mgr()
        parent = _parent_token(ttl=timedelta(minutes=5))
        child_token = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="w1",
            ttl=timedelta(hours=1),  # Requested more than parent has
        )
        identity = mgr.validate_token(child_token)
        remaining = identity.expires_at - datetime.now(tz=UTC)
        # Should be capped at ~5 minutes, not 1 hour
        assert remaining < timedelta(minutes=6)

    def test_invalid_parent_token_rejected(self):
        mgr = _mgr()
        with pytest.raises(DelegationError, match="Invalid parent token"):
            mgr.create_delegation_token(
                parent_token="garbage",
                child_agent_id="w1",
            )

    def test_no_roles_delegation(self):
        mgr = _mgr()
        parent = _parent_token()
        child_token = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="w1",
        )
        identity = mgr.validate_token(child_token)
        assert identity.roles == []
        assert identity.delegated_roles == []


# --- Delegation PDP ---


class TestDelegationPDP:
    def test_delegated_caller_check(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            signing_key=SIGNING_KEY,
            audit_log=tmp_path / "audit.jsonl",
        )
        parent = _parent_token()
        result = safe.delegate(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        assert result.success is True

        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller=result.token,
        )
        # dev environment is allowed by default policy
        assert decision.result.value in ("allow", "deny", "require_approval")

    def test_non_delegated_caller_unaffected(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            signing_key=SIGNING_KEY,
            audit_log=tmp_path / "audit.jsonl",
        )
        parent = _parent_token()
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller=parent,
        )
        # Should work fine with non-delegated token
        assert decision.result is not None

    def test_delegation_chain_in_audit_context(self, tmp_path: Path):
        audit_file = tmp_path / "audit.jsonl"
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            signing_key=SIGNING_KEY,
            audit_log=audit_file,
        )
        parent = _parent_token()
        result = safe.delegate(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller=result.token,
        )
        # Read audit log and check context
        lines = audit_file.read_text().strip().split("\n")
        last_event = json.loads(lines[-1])
        assert last_event["context"] is not None
        assert last_event["context"]["delegation_depth"] == 1
        assert last_event["context"]["original_caller"] == "orchestrator-01"

    def test_direct_caller_no_delegation_context(self, tmp_path: Path):
        audit_file = tmp_path / "audit.jsonl"
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            signing_key=SIGNING_KEY,
            audit_log=audit_file,
        )
        parent = _parent_token()
        safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller=parent,
        )
        lines = audit_file.read_text().strip().split("\n")
        last_event = json.loads(lines[-1])
        assert last_event.get("context") is None


# --- Delegation SDK ---


class TestDelegationSDK:
    def test_delegate_creates_token(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            signing_key=SIGNING_KEY,
        )
        parent = _parent_token()
        result = safe.delegate(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        assert result.success is True
        assert result.token is not None
        assert result.parent_agent_id == "orchestrator-01"
        assert result.child_agent_id == "worker-01"
        assert result.delegation_depth == 1
        assert result.child_identity is not None
        assert result.child_identity.delegation_depth == 1

    def test_delegate_without_identity_raises(self):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        with pytest.raises(AgentSafeError, match="not configured"):
            safe.delegate(
                parent_token="any",
                child_agent_id="worker-01",
            )

    def test_delegate_scope_narrowing_error(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            signing_key=SIGNING_KEY,
        )
        parent = _parent_token(roles=["reader"])
        result = safe.delegate(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["admin"],
        )
        assert result.success is False
        assert "not held by parent" in result.error

    def test_verify_delegation(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            signing_key=SIGNING_KEY,
        )
        parent = _parent_token()
        result = safe.delegate(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        identity = safe.verify_delegation(result.token)
        assert identity is not None
        assert identity.agent_id == "worker-01"
        assert identity.delegation_depth == 1

    def test_verify_delegation_invalid_token(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            signing_key=SIGNING_KEY,
        )
        identity = safe.verify_delegation("garbage-token")
        assert identity is None

    def test_verify_delegation_without_identity_raises(self):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        with pytest.raises(AgentSafeError, match="not configured"):
            safe.verify_delegation("any-token")


# --- Delegation CLI ---


class TestDelegationCLI:
    def test_delegation_create(self):
        parent = _parent_token()
        result = CliRunner(mix_stderr=False).invoke(cli, [
            "delegation", "create", parent,
            "--child-id", "worker-01",
            "--roles", "deployer",
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 0
        assert "OK" in result.output
        assert "worker-01" in result.output

    def test_delegation_create_json_output(self):
        parent = _parent_token()
        result = CliRunner(mix_stderr=False).invoke(cli, [
            "delegation", "create", parent,
            "--child-id", "worker-01",
            "--roles", "deployer",
            "--signing-key", SIGNING_KEY,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["child_agent_id"] == "worker-01"
        assert data["delegation_depth"] == 1
        assert len(data["delegation_chain"]) == 1

    def test_delegation_verify(self):
        mgr = _mgr()
        parent = _parent_token()
        child = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        result = CliRunner(mix_stderr=False).invoke(cli, [
            "delegation", "verify", child,
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 0
        assert "DELEGATED" in result.output
        assert "worker-01" in result.output
        assert "orchestrator-01" in result.output

    def test_delegation_verify_invalid_token(self):
        result = CliRunner(mix_stderr=False).invoke(cli, [
            "delegation", "verify", "garbage",
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_delegation_verify_json_output(self):
        mgr = _mgr()
        parent = _parent_token()
        child = mgr.create_delegation_token(
            parent_token=parent,
            child_agent_id="worker-01",
            child_roles=["deployer"],
        )
        result = CliRunner(mix_stderr=False).invoke(cli, [
            "delegation", "verify", child,
            "--signing-key", SIGNING_KEY,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["agent_id"] == "worker-01"
        assert data["delegation_depth"] == 1

    def test_delegation_verify_direct_token(self):
        parent = _parent_token()
        result = CliRunner(mix_stderr=False).invoke(cli, [
            "delegation", "verify", parent,
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 0
        assert "DIRECT" in result.output
