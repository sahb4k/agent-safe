"""Tests for the CredentialVault protocol and EnvVarVault backend."""

from datetime import UTC, datetime, timedelta

import pytest

from agent_safe.credentials.env_vault import EnvVarVault
from agent_safe.credentials.vault import (
    CredentialVault,
    CredentialVaultError,
    build_vault,
)
from agent_safe.models import CredentialScope, ExecutionTicket


def _make_ticket(**overrides) -> ExecutionTicket:
    """Helper to create a test ExecutionTicket."""
    now = datetime.now(tz=UTC)
    defaults = {
        "token": "test-jwt-token",
        "action": "restart-deployment",
        "target": "prod/api-server",
        "caller": "deploy-agent-01",
        "params": {"namespace": "prod", "deployment": "api-server"},
        "audit_id": "evt-test000001",
        "nonce": "testnonce123",
        "issued_at": now,
        "expires_at": now + timedelta(minutes=5),
    }
    defaults.update(overrides)
    return ExecutionTicket(**defaults)


def _make_scope(**overrides) -> CredentialScope:
    defaults = {
        "type": "kubernetes",
        "fields": {"verbs": ["get", "patch"], "resources": ["deployments"]},
        "ttl": 300,
    }
    defaults.update(overrides)
    return CredentialScope(**defaults)


# --- Protocol ---


class TestProtocol:
    def test_env_var_vault_satisfies_protocol(self):
        vault = EnvVarVault(credentials={"kubernetes": {"token": "x"}})
        assert isinstance(vault, CredentialVault)


# --- EnvVarVault with static mapping ---


class TestEnvVarVaultStatic:
    def test_get_credential_from_static(self):
        vault = EnvVarVault(
            credentials={"kubernetes": {"token": "k8s-test-token"}},
        )
        cred = vault.get_credential(_make_scope(), _make_ticket())
        assert cred.credential_id.startswith("cred-")
        assert cred.type == "kubernetes"
        assert cred.payload == {"token": "k8s-test-token"}
        assert cred.ticket_nonce == "testnonce123"

    def test_get_credential_missing_type_raises(self):
        vault = EnvVarVault(credentials={"kubernetes": {"token": "x"}})
        scope = _make_scope(type="aws-iam")
        with pytest.raises(CredentialVaultError, match="aws-iam"):
            vault.get_credential(scope, _make_ticket())

    def test_multiple_types(self):
        vault = EnvVarVault(
            credentials={
                "kubernetes": {"token": "k8s"},
                "aws-iam": {"access_key": "AK", "secret_key": "SK"},
            },
        )
        k8s = vault.get_credential(_make_scope(type="kubernetes"), _make_ticket())
        aws = vault.get_credential(
            _make_scope(type="aws-iam"), _make_ticket(nonce="n2"),
        )
        assert k8s.type == "kubernetes"
        assert aws.type == "aws-iam"
        assert aws.payload["access_key"] == "AK"

    def test_respects_ttl(self):
        vault = EnvVarVault(credentials={"kubernetes": {"token": "x"}})
        cred = vault.get_credential(_make_scope(ttl=60), _make_ticket(), ttl=60)
        delta = cred.expires_at - datetime.now(tz=UTC)
        assert timedelta(seconds=50) < delta < timedelta(seconds=70)


# --- EnvVarVault with environment variables ---


class TestEnvVarVaultEnv:
    def test_reads_env_var(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AGENT_SAFE_CRED_KUBERNETES", "env-k8s-token")
        vault = EnvVarVault()
        cred = vault.get_credential(_make_scope(), _make_ticket())
        assert cred.payload == {"token": "env-k8s-token"}

    def test_custom_prefix(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("MY_CRED_KUBERNETES", "my-token")
        vault = EnvVarVault(env_prefix="MY_CRED_")
        cred = vault.get_credential(_make_scope(), _make_ticket())
        assert cred.payload == {"token": "my-token"}

    def test_static_mapping_takes_priority(
        self, monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setenv("AGENT_SAFE_CRED_KUBERNETES", "env-token")
        vault = EnvVarVault(
            credentials={"kubernetes": {"token": "static-token"}},
        )
        cred = vault.get_credential(_make_scope(), _make_ticket())
        assert cred.payload == {"token": "static-token"}

    def test_no_env_var_raises(self):
        vault = EnvVarVault()
        with pytest.raises(CredentialVaultError, match="AGENT_SAFE_CRED_KUBERNETES"):
            vault.get_credential(_make_scope(), _make_ticket())


# --- Revocation ---


class TestEnvVarVaultRevoke:
    def test_revoke_reduces_count(self):
        vault = EnvVarVault(credentials={"kubernetes": {"token": "x"}})
        cred = vault.get_credential(_make_scope(), _make_ticket())
        assert vault.issued_count == 1
        vault.revoke(cred.credential_id)
        assert vault.issued_count == 0

    def test_revoke_unknown_is_noop(self):
        vault = EnvVarVault(credentials={"kubernetes": {"token": "x"}})
        vault.revoke("cred-nonexistent")  # no error
        assert vault.issued_count == 0


# --- build_vault ---


class TestBuildVault:
    def test_default_type_is_env(self):
        vault = build_vault(
            {"credentials": {"kubernetes": {"token": "x"}}},
        )
        assert isinstance(vault, EnvVarVault)

    def test_explicit_env_type(self):
        vault = build_vault(
            {"type": "env", "credentials": {"kubernetes": {"token": "x"}}},
        )
        assert isinstance(vault, EnvVarVault)

    def test_unknown_type_raises(self):
        with pytest.raises(CredentialVaultError, match="Unknown vault type"):
            build_vault({"type": "hashicorp"})

    def test_custom_env_prefix(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("CUSTOM_KUBERNETES", "tok")
        vault = build_vault({"type": "env", "env_prefix": "CUSTOM_"})
        cred = vault.get_credential(_make_scope(), _make_ticket())
        assert cred.payload == {"token": "tok"}
