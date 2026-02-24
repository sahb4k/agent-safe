"""Tests for the credential-related Pydantic models."""

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from agent_safe.models import (
    ActionDefinition,
    Credential,
    CredentialResult,
    CredentialScope,
    RiskClass,
)

# --- CredentialScope ---


class TestCredentialScope:
    def test_default_ttl(self):
        scope = CredentialScope(type="kubernetes")
        assert scope.ttl == 300
        assert scope.fields == {}

    def test_custom_fields_and_ttl(self):
        scope = CredentialScope(
            type="kubernetes",
            fields={"verbs": ["get", "patch"], "resources": ["deployments"]},
            ttl=120,
        )
        assert scope.type == "kubernetes"
        assert scope.fields["verbs"] == ["get", "patch"]
        assert scope.ttl == 120

    def test_ttl_minimum_enforced(self):
        with pytest.raises(ValidationError):
            CredentialScope(type="kubernetes", ttl=0)

    def test_arbitrary_type(self):
        scope = CredentialScope(type="custom-vault", fields={"key": "val"})
        assert scope.type == "custom-vault"


# --- Credential ---


class TestCredential:
    def test_construction(self):
        scope = CredentialScope(type="kubernetes")
        cred = Credential(
            credential_id="cred-abc123",
            type="kubernetes",
            payload={"token": "k8s-token"},
            expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
            scope=scope,
            ticket_nonce="nonce-xyz",
        )
        assert cred.credential_id == "cred-abc123"
        assert cred.payload["token"] == "k8s-token"
        assert cred.ticket_nonce == "nonce-xyz"

    def test_empty_payload(self):
        scope = CredentialScope(type="ssh")
        cred = Credential(
            credential_id="cred-001",
            type="ssh",
            expires_at=datetime.now(tz=UTC),
            scope=scope,
            ticket_nonce="n1",
        )
        assert cred.payload == {}


# --- CredentialResult ---


class TestCredentialResult:
    def test_success(self):
        scope = CredentialScope(type="kubernetes")
        cred = Credential(
            credential_id="cred-001",
            type="kubernetes",
            payload={"token": "x"},
            expires_at=datetime.now(tz=UTC),
            scope=scope,
            ticket_nonce="n1",
        )
        result = CredentialResult(
            success=True,
            credential=cred,
            action="restart-deployment",
            target="prod/api",
            ticket_nonce="n1",
        )
        assert result.success is True
        assert result.credential is not None

    def test_failure(self):
        result = CredentialResult(
            success=False,
            error="Vault unreachable",
            action="restart-deployment",
        )
        assert result.success is False
        assert result.credential is None
        assert "Vault" in result.error


# --- ActionDefinition backward compat ---


class TestActionDefinitionCredentials:
    def test_no_credentials_field(self):
        """Actions without credentials continue to work."""
        action = ActionDefinition(
            name="test-action",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
        )
        assert action.credentials is None

    def test_with_credentials(self):
        action = ActionDefinition(
            name="test-action",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            credentials=CredentialScope(
                type="kubernetes",
                fields={"verbs": ["get"]},
                ttl=120,
            ),
        )
        assert action.credentials is not None
        assert action.credentials.type == "kubernetes"
        assert action.credentials.ttl == 120
