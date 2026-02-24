"""Tests for the agent identity manager (JWT)."""

from datetime import timedelta

import pytest

from agent_safe.identity.manager import IdentityError, IdentityManager


@pytest.fixture()
def manager() -> IdentityManager:
    return IdentityManager(signing_key="test-secret-key-for-unit-tests", issuer="agent-safe")


class TestIdentityManager:
    def test_create_and_validate_token(self, manager: IdentityManager):
        token = manager.create_token(
            agent_id="deploy-agent-01",
            agent_name="Deploy Agent",
            roles=["deployer", "reader"],
            groups=["platform-team"],
        )
        assert isinstance(token, str)
        assert len(token) > 0

        identity = manager.validate_token(token)
        assert identity.agent_id == "deploy-agent-01"
        assert identity.agent_name == "Deploy Agent"
        assert identity.roles == ["deployer", "reader"]
        assert identity.groups == ["platform-team"]
        assert identity.issued_at is not None
        assert identity.expires_at is not None

    def test_minimal_token(self, manager: IdentityManager):
        token = manager.create_token(agent_id="minimal-agent")
        identity = manager.validate_token(token)
        assert identity.agent_id == "minimal-agent"
        assert identity.agent_name == ""
        assert identity.roles == []
        assert identity.groups == []

    def test_custom_ttl(self, manager: IdentityManager):
        token = manager.create_token(
            agent_id="short-lived",
            ttl=timedelta(minutes=5),
        )
        identity = manager.validate_token(token)
        delta = identity.expires_at - identity.issued_at
        assert delta == timedelta(minutes=5)

    def test_expired_token_rejected(self, manager: IdentityManager):
        token = manager.create_token(
            agent_id="expired-agent",
            ttl=timedelta(seconds=-1),
        )
        with pytest.raises(IdentityError, match="expired"):
            manager.validate_token(token)

    def test_wrong_key_rejected(self, manager: IdentityManager):
        token = manager.create_token(agent_id="some-agent")
        other_manager = IdentityManager(signing_key="different-key")
        with pytest.raises(IdentityError, match="Invalid token"):
            other_manager.validate_token(token)

    def test_wrong_issuer_rejected(self):
        manager_a = IdentityManager(signing_key="shared-key", issuer="issuer-a")
        manager_b = IdentityManager(signing_key="shared-key", issuer="issuer-b")
        token = manager_a.create_token(agent_id="agent-x")
        with pytest.raises(IdentityError, match="Invalid token"):
            manager_b.validate_token(token)

    def test_tampered_token_rejected(self, manager: IdentityManager):
        token = manager.create_token(agent_id="agent-y")
        # Flip a character in the payload section
        parts = token.split(".")
        payload = parts[1]
        tampered = payload[:-1] + ("A" if payload[-1] != "A" else "B")
        tampered_token = f"{parts[0]}.{tampered}.{parts[2]}"
        with pytest.raises(IdentityError, match="Invalid token"):
            manager.validate_token(tampered_token)

    def test_garbage_token_rejected(self, manager: IdentityManager):
        with pytest.raises(IdentityError, match="Invalid token"):
            manager.validate_token("not.a.valid.jwt")

    def test_empty_token_rejected(self, manager: IdentityManager):
        with pytest.raises(IdentityError, match="Invalid token"):
            manager.validate_token("")

    def test_validate_or_none_success(self, manager: IdentityManager):
        token = manager.create_token(agent_id="valid-agent")
        identity = manager.validate_token_or_none(token)
        assert identity is not None
        assert identity.agent_id == "valid-agent"

    def test_validate_or_none_failure(self, manager: IdentityManager):
        assert manager.validate_token_or_none("garbage") is None

    def test_validate_or_none_expired(self, manager: IdentityManager):
        token = manager.create_token(agent_id="expired", ttl=timedelta(seconds=-1))
        assert manager.validate_token_or_none(token) is None

    def test_empty_signing_key_rejected(self):
        with pytest.raises(IdentityError, match="Signing key must not be empty"):
            IdentityManager(signing_key="")

    def test_multiple_agents_different_tokens(self, manager: IdentityManager):
        token_a = manager.create_token(agent_id="agent-a", roles=["admin"])
        token_b = manager.create_token(agent_id="agent-b", roles=["reader"])
        assert token_a != token_b

        id_a = manager.validate_token(token_a)
        id_b = manager.validate_token(token_b)
        assert id_a.agent_id == "agent-a"
        assert id_b.agent_id == "agent-b"
        assert id_a.roles == ["admin"]
        assert id_b.roles == ["reader"]

    def test_default_issuer(self):
        mgr = IdentityManager(signing_key="key")
        token = mgr.create_token(agent_id="test")
        identity = mgr.validate_token(token)
        assert identity.agent_id == "test"
