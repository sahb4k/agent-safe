"""Tests for credential gating integration in the AgentSafe SDK."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_safe import AgentSafe, AgentSafeError
from agent_safe.credentials.env_vault import EnvVarVault
from agent_safe.models import DecisionResult

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"


@pytest.fixture()
def safe_with_vault(tmp_path: Path) -> AgentSafe:
    """AgentSafe with credential vault + signing key (for tickets)."""
    return AgentSafe(
        registry=ACTIONS_DIR,
        policies=POLICIES_DIR,
        inventory=INVENTORY_FILE,
        audit_log=tmp_path / "audit.jsonl",
        signing_key="test-credential-key",
        credential_vault=EnvVarVault(
            credentials={"kubernetes": {"token": "test-k8s-token"}},
        ),
    )


# --- Constructor ---


class TestConstructor:
    def test_with_vault_instance(self, tmp_path: Path):
        vault = EnvVarVault(credentials={"kubernetes": {"token": "x"}})
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            credential_vault=vault,
        )
        assert s.credential_resolver is not None

    def test_with_vault_dict(self, tmp_path: Path):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            credential_vault={
                "type": "env",
                "credentials": {"kubernetes": {"token": "x"}},
            },
        )
        assert s.credential_resolver is not None

    def test_without_vault(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        assert s.credential_resolver is None


# --- resolve_credentials ---


class TestResolveCredentials:
    def test_full_flow(self, safe_with_vault: AgentSafe):
        """check() → ALLOW with ticket → resolve_credentials()."""
        decision = safe_with_vault.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="any-agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.ticket is not None

        result = safe_with_vault.resolve_credentials(decision.ticket)
        assert result.success is True
        assert result.credential is not None
        assert result.credential.type == "kubernetes"
        assert result.credential.payload == {"token": "test-k8s-token"}

    def test_action_without_credentials_block(
        self, safe_with_vault: AgentSafe,
    ):
        """Actions without credentials return success=False."""
        decision = safe_with_vault.check(
            action="cordon-node",
            target="dev/test-app",
            caller="any-agent",
            params={"node": "worker-1"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.ticket is not None

        result = safe_with_vault.resolve_credentials(decision.ticket)
        assert result.success is False
        assert "does not declare" in result.error

    def test_without_vault_raises(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        with pytest.raises(AgentSafeError, match="not configured"):
            from datetime import UTC, datetime, timedelta

            from agent_safe.models import ExecutionTicket

            ticket = ExecutionTicket(
                token="x",
                action="restart-deployment",
                target="dev/test-app",
                caller="agent",
                audit_id="evt-x",
                nonce="n1",
                issued_at=datetime.now(tz=UTC),
                expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
            )
            s.resolve_credentials(ticket)


# --- revoke_credential ---


class TestRevokeCredential:
    def test_revoke(self, safe_with_vault: AgentSafe):
        decision = safe_with_vault.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="any-agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        result = safe_with_vault.resolve_credentials(decision.ticket)
        assert result.success is True

        # Should not raise
        safe_with_vault.revoke_credential(result.credential)

    def test_revoke_without_vault_raises(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        with pytest.raises(AgentSafeError, match="not configured"):
            from datetime import UTC, datetime

            from agent_safe.models import Credential, CredentialScope

            cred = Credential(
                credential_id="cred-x",
                type="kubernetes",
                payload={},
                expires_at=datetime.now(tz=UTC),
                scope=CredentialScope(type="kubernetes"),
                ticket_nonce="n1",
            )
            s.revoke_credential(cred)
