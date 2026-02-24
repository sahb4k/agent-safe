"""Tests for the CredentialResolver and template resolution."""

from __future__ import annotations

import warnings
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent_safe.credentials.env_vault import EnvVarVault
from agent_safe.credentials.resolver import (
    CredentialResolver,
    ResolverWarning,
    resolve_scope_templates,
)
from agent_safe.models import CredentialScope, ExecutionTicket
from agent_safe.registry.loader import load_registry

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")


def _make_ticket(**overrides) -> ExecutionTicket:
    now = datetime.now(tz=UTC)
    defaults = {
        "token": "test-jwt-token",
        "action": "restart-deployment",
        "target": "prod/api-server",
        "caller": "deploy-agent-01",
        "params": {"namespace": "production", "deployment": "api-server"},
        "audit_id": "evt-test000001",
        "nonce": "testnonce123",
        "issued_at": now,
        "expires_at": now + timedelta(minutes=5),
    }
    defaults.update(overrides)
    return ExecutionTicket(**defaults)


@pytest.fixture()
def vault() -> EnvVarVault:
    return EnvVarVault(
        credentials={"kubernetes": {"token": "test-k8s-token"}},
    )


@pytest.fixture()
def resolver(vault: EnvVarVault) -> CredentialResolver:
    registry = load_registry(ACTIONS_DIR)
    return CredentialResolver(registry=registry, vault=vault)


# --- Template resolution ---


class TestTemplateResolution:
    def test_simple_param(self):
        scope = CredentialScope(
            type="kubernetes",
            fields={"namespaces": ["{{ params.namespace }}"]},
        )
        result = resolve_scope_templates(
            scope, {"namespace": "production"},
        )
        assert result.fields["namespaces"] == ["production"]

    def test_multiple_params(self):
        scope = CredentialScope(
            type="kubernetes",
            fields={
                "namespaces": ["{{ params.namespace }}"],
                "names": ["{{ params.deployment }}"],
            },
        )
        result = resolve_scope_templates(
            scope, {"namespace": "prod", "deployment": "api"},
        )
        assert result.fields["namespaces"] == ["prod"]
        assert result.fields["names"] == ["api"]

    def test_missing_param_left_unresolved(self):
        scope = CredentialScope(
            type="kubernetes",
            fields={"namespaces": ["{{ params.missing }}"]},
        )
        result = resolve_scope_templates(scope, {})
        assert result.fields["namespaces"] == ["{{ params.missing }}"]

    def test_no_templates_passthrough(self):
        scope = CredentialScope(
            type="kubernetes",
            fields={"verbs": ["get", "patch"], "static": "value"},
        )
        result = resolve_scope_templates(scope, {"namespace": "prod"})
        assert result.fields["verbs"] == ["get", "patch"]
        assert result.fields["static"] == "value"

    def test_whitespace_in_template(self):
        scope = CredentialScope(
            type="kubernetes",
            fields={"ns": ["{{  params.namespace  }}"]},
        )
        result = resolve_scope_templates(scope, {"namespace": "prod"})
        assert result.fields["ns"] == ["prod"]

    def test_nested_dict(self):
        scope = CredentialScope(
            type="custom",
            fields={"nested": {"key": "{{ params.val }}"}},
        )
        result = resolve_scope_templates(scope, {"val": "resolved"})
        assert result.fields["nested"]["key"] == "resolved"

    def test_non_string_passthrough(self):
        scope = CredentialScope(
            type="custom",
            fields={"count": 42, "flag": True},
        )
        result = resolve_scope_templates(scope, {})
        assert result.fields["count"] == 42
        assert result.fields["flag"] is True

    def test_preserves_ttl_and_type(self):
        scope = CredentialScope(type="ssh", fields={}, ttl=120)
        result = resolve_scope_templates(scope, {})
        assert result.type == "ssh"
        assert result.ttl == 120


# --- CredentialResolver.resolve ---


class TestResolve:
    def test_resolve_success(self, resolver: CredentialResolver):
        ticket = _make_ticket()
        result = resolver.resolve(ticket)
        assert result.success is True
        assert result.credential is not None
        assert result.credential.type == "kubernetes"
        assert result.credential.payload == {"token": "test-k8s-token"}
        assert result.action == "restart-deployment"
        assert result.ticket_nonce == "testnonce123"

    def test_resolve_unknown_action(self, resolver: CredentialResolver):
        ticket = _make_ticket(action="nonexistent-action")
        result = resolver.resolve(ticket)
        assert result.success is False
        assert "not found" in result.error

    def test_resolve_action_without_credentials(
        self, resolver: CredentialResolver,
    ):
        # cordon-node has no credentials block
        ticket = _make_ticket(
            action="cordon-node",
            params={"node": "worker-1"},
        )
        result = resolver.resolve(ticket)
        assert result.success is False
        assert "does not declare" in result.error

    def test_resolve_vault_error(self):
        registry = load_registry(ACTIONS_DIR)
        vault = EnvVarVault()  # no credentials configured
        resolver = CredentialResolver(registry=registry, vault=vault)

        ticket = _make_ticket()
        result = resolver.resolve(ticket)
        assert result.success is False
        assert "Vault error" in result.error

    def test_resolve_templates_params(self, resolver: CredentialResolver):
        """Templates in the credentials scope are resolved from ticket params."""
        ticket = _make_ticket(
            params={"namespace": "my-ns", "deployment": "my-deploy"},
        )
        result = resolver.resolve(ticket)
        assert result.success is True
        # The scope fields should have been resolved
        scope = result.credential.scope
        assert "my-ns" in scope.fields["namespaces"]


# --- CredentialResolver.revoke ---


class TestRevoke:
    def test_revoke_success(self, resolver: CredentialResolver, vault: EnvVarVault):
        ticket = _make_ticket()
        result = resolver.resolve(ticket)
        assert vault.issued_count == 1

        resolver.revoke(result.credential)
        assert vault.issued_count == 0

    def test_revoke_failure_warns(self):
        registry = load_registry(ACTIONS_DIR)
        mock_vault = MagicMock()
        mock_vault.revoke.side_effect = Exception("revoke failed")
        resolver = CredentialResolver(registry=registry, vault=mock_vault)

        # Create a fake credential
        from agent_safe.models import Credential

        cred = Credential(
            credential_id="cred-fake",
            type="kubernetes",
            payload={},
            expires_at=datetime.now(tz=UTC),
            scope=CredentialScope(type="kubernetes"),
            ticket_nonce="n1",
        )

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            resolver.revoke(cred)

        assert len(w) == 1
        assert issubclass(w[0].category, ResolverWarning)
        assert "revoke failed" in str(w[0].message)
