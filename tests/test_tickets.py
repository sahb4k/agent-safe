"""Tests for the execution ticket system.

Covers:
- TicketIssuer (issuance, JWT content, TTL, nonce uniqueness)
- TicketValidator (validation, replay, expiry, mismatches, cross-token)
- PDP integration (tickets on ALLOW, no tickets on DENY/REQUIRE_APPROVAL)
- SDK integration (end-to-end check with signing_key)
- CLI integration (check --signing-key, ticket verify)
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import jwt as pyjwt
import pytest
from click.testing import CliRunner

from agent_safe import AgentSafe
from agent_safe.cli.main import cli
from agent_safe.identity.manager import IdentityManager
from agent_safe.models import (
    Decision,
    DecisionResult,
    ExecutionTicket,
    RiskClass,
    TicketValidationResult,
)
from agent_safe.tickets.issuer import TicketIssuer, TicketIssuerError
from agent_safe.tickets.validator import TicketValidator, TicketValidatorError

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")

SIGNING_KEY = "test-secret-key-for-ticket-tests"


# --- TicketIssuer ---


class TestTicketIssuer:
    def test_issue_creates_valid_jwt(self):
        issuer = TicketIssuer(SIGNING_KEY)
        ticket = issuer.issue(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            audit_id="evt-abc123",
            params={"namespace": "dev", "deployment": "app"},
        )

        assert isinstance(ticket, ExecutionTicket)
        assert ticket.action == "restart-deployment"
        assert ticket.target == "dev/test-app"
        assert ticket.caller == "agent-01"
        assert ticket.audit_id == "evt-abc123"
        assert ticket.params == {"namespace": "dev", "deployment": "app"}
        assert len(ticket.nonce) == 32  # uuid4().hex
        assert ticket.token  # non-empty JWT string

        # Decode and verify JWT payload
        payload = pyjwt.decode(ticket.token, SIGNING_KEY, algorithms=["HS256"])
        assert payload["type"] == "execution-ticket"
        assert payload["action"] == "restart-deployment"
        assert payload["target"] == "dev/test-app"
        assert payload["caller"] == "agent-01"
        assert payload["audit_id"] == "evt-abc123"
        assert payload["nonce"] == ticket.nonce

    def test_issue_has_unique_nonces(self):
        issuer = TicketIssuer(SIGNING_KEY)
        t1 = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
        )
        t2 = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-2",
        )
        assert t1.nonce != t2.nonce

    def test_issue_default_ttl(self):
        issuer = TicketIssuer(SIGNING_KEY)
        ticket = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
        )
        delta = ticket.expires_at - ticket.issued_at
        assert abs(delta.total_seconds() - 300) < 2  # ~5 minutes

    def test_issue_custom_ttl(self):
        issuer = TicketIssuer(SIGNING_KEY, ttl=timedelta(minutes=10))
        ticket = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
        )
        delta = ticket.expires_at - ticket.issued_at
        assert abs(delta.total_seconds() - 600) < 2  # ~10 minutes

    def test_issue_per_call_ttl_override(self):
        issuer = TicketIssuer(SIGNING_KEY, ttl=timedelta(minutes=5))
        ticket = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
            ttl=timedelta(seconds=30),
        )
        delta = ticket.expires_at - ticket.issued_at
        assert abs(delta.total_seconds() - 30) < 2

    def test_issue_includes_params(self):
        issuer = TicketIssuer(SIGNING_KEY)
        params = {"replicas": 3, "namespace": "prod"}
        ticket = issuer.issue(
            action="scale-deployment", target="prod/api",
            caller="a", audit_id="evt-1", params=params,
        )
        assert ticket.params == params

        # Also in JWT
        payload = pyjwt.decode(ticket.token, SIGNING_KEY, algorithms=["HS256"])
        assert payload["params"] == params

    def test_issue_empty_params_default(self):
        issuer = TicketIssuer(SIGNING_KEY)
        ticket = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
        )
        assert ticket.params == {}

    def test_issue_type_claim(self):
        issuer = TicketIssuer(SIGNING_KEY)
        ticket = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
        )
        payload = pyjwt.decode(ticket.token, SIGNING_KEY, algorithms=["HS256"])
        assert payload["type"] == "execution-ticket"

    def test_issue_custom_issuer(self):
        issuer = TicketIssuer(SIGNING_KEY, issuer="my-org")
        ticket = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
        )
        payload = pyjwt.decode(
            ticket.token, SIGNING_KEY, algorithms=["HS256"],
            options={"verify_iss": False},
        )
        assert payload["iss"] == "my-org"

    def test_empty_signing_key_rejected(self):
        with pytest.raises(TicketIssuerError, match="empty"):
            TicketIssuer("")


# --- TicketValidator ---


class TestTicketValidator:
    def _issue(self, **kwargs) -> ExecutionTicket:
        issuer = TicketIssuer(SIGNING_KEY)
        defaults = {
            "action": "restart-deployment",
            "target": "dev/test-app",
            "caller": "agent-01",
            "audit_id": "evt-abc123",
        }
        defaults.update(kwargs)
        return issuer.issue(**defaults)

    def test_valid_ticket_accepted(self):
        ticket = self._issue()
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(ticket.token)
        assert result.valid
        assert result.reason == "Ticket is valid"
        assert result.ticket is not None
        assert result.ticket.action == "restart-deployment"
        assert result.ticket.nonce == ticket.nonce

    def test_expired_ticket_rejected(self):
        issuer = TicketIssuer(SIGNING_KEY)
        ticket = issuer.issue(
            action="restart-deployment", target="dev/test",
            caller="a", audit_id="evt-1",
            ttl=timedelta(seconds=-1),  # already expired
        )
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(ticket.token)
        assert not result.valid
        assert "expired" in result.reason.lower()

    def test_wrong_signing_key_rejected(self):
        ticket = self._issue()
        validator = TicketValidator("wrong-key")
        result = validator.validate(ticket.token)
        assert not result.valid
        assert "Invalid ticket" in result.reason

    def test_wrong_issuer_rejected(self):
        ticket = self._issue()
        validator = TicketValidator(SIGNING_KEY, issuer="other-org")
        result = validator.validate(ticket.token)
        assert not result.valid
        assert "issuer" in result.reason.lower()

    def test_tampered_token_rejected(self):
        ticket = self._issue()
        # Flip a character in the payload portion (middle of JWT)
        parts = ticket.token.split(".")
        payload_chars = list(parts[1])
        payload_chars[5] = "X" if payload_chars[5] != "X" else "Y"
        parts[1] = "".join(payload_chars)
        tampered = ".".join(parts)

        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(tampered)
        assert not result.valid

    def test_action_mismatch_rejected(self):
        ticket = self._issue(action="restart-deployment")
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(
            ticket.token, expected_action="scale-deployment",
        )
        assert not result.valid
        assert "Action mismatch" in result.reason

    def test_target_mismatch_rejected(self):
        ticket = self._issue(target="dev/test-app")
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(
            ticket.token, expected_target="prod/api-server",
        )
        assert not result.valid
        assert "Target mismatch" in result.reason

    def test_replay_rejected(self):
        ticket = self._issue()
        validator = TicketValidator(SIGNING_KEY)
        r1 = validator.validate(ticket.token)
        assert r1.valid

        r2 = validator.validate(ticket.token)
        assert not r2.valid
        assert "replay" in r2.reason.lower()

    def test_nonce_count_tracks_usage(self):
        validator = TicketValidator(SIGNING_KEY)
        assert validator.used_nonce_count == 0

        ticket = self._issue()
        validator.validate(ticket.token)
        assert validator.used_nonce_count == 1

    def test_identity_jwt_rejected_as_ticket(self):
        """An identity JWT (from IdentityManager) must not pass as a ticket."""
        mgr = IdentityManager(SIGNING_KEY, issuer="agent-safe")
        identity_token = mgr.create_token(agent_id="agent-01")

        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(identity_token)
        assert not result.valid
        # Should fail because of missing 'type' claim or wrong type
        reason = result.reason.lower()
        assert "not an execution ticket" in reason or "invalid ticket" in reason

    def test_garbage_token_rejected(self):
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate("not.a.jwt.at.all")
        assert not result.valid

    def test_empty_token_rejected(self):
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate("")
        assert not result.valid

    def test_no_expected_action_accepts_any(self):
        ticket = self._issue(action="restart-deployment")
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(ticket.token, expected_action=None)
        assert result.valid

    def test_no_expected_target_accepts_any(self):
        ticket = self._issue(target="dev/test-app")
        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(ticket.token, expected_target=None)
        assert result.valid

    def test_empty_signing_key_rejected(self):
        with pytest.raises(TicketValidatorError, match="empty"):
            TicketValidator("")


# --- Model tests ---


class TestExecutionTicketModel:
    def test_construction(self):
        from datetime import UTC, datetime

        now = datetime.now(tz=UTC)
        ticket = ExecutionTicket(
            token="jwt.token.here",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev"},
            audit_id="evt-123",
            nonce="abc123",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        assert ticket.action == "restart-deployment"
        assert ticket.params == {"namespace": "dev"}

    def test_decision_with_ticket(self):
        from datetime import UTC, datetime

        now = datetime.now(tz=UTC)
        ticket = ExecutionTicket(
            token="jwt.token.here",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            audit_id="evt-123",
            nonce="abc123",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="Allowed",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            audit_id="evt-123",
            ticket=ticket,
        )
        assert decision.ticket is not None
        assert decision.ticket.nonce == "abc123"

    def test_decision_without_ticket(self):
        decision = Decision(
            result=DecisionResult.DENY,
            reason="Denied",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            audit_id="evt-123",
        )
        assert decision.ticket is None

    def test_decision_to_dict_includes_ticket(self):
        from datetime import UTC, datetime

        now = datetime.now(tz=UTC)
        ticket = ExecutionTicket(
            token="jwt.token.here",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            audit_id="evt-123",
            nonce="abc123",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )
        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="Allowed",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            audit_id="evt-123",
            ticket=ticket,
        )
        d = decision.to_dict()
        assert d["ticket"] is not None
        assert d["ticket"]["nonce"] == "abc123"

    def test_decision_to_dict_ticket_null_when_absent(self):
        decision = Decision(
            result=DecisionResult.DENY,
            reason="Denied",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
            audit_id="evt-123",
        )
        d = decision.to_dict()
        assert d["ticket"] is None

    def test_ticket_validation_result_valid(self):
        result = TicketValidationResult(
            valid=True, reason="OK",
            ticket=ExecutionTicket(
                token="t", action="a", target="t", caller="c",
                audit_id="e", nonce="n",
                issued_at="2024-01-01T00:00:00Z",
                expires_at="2024-01-01T00:05:00Z",
            ),
        )
        assert result.valid
        assert result.ticket is not None

    def test_ticket_validation_result_invalid(self):
        result = TicketValidationResult(valid=False, reason="bad")
        assert not result.valid
        assert result.ticket is None


# --- PDP integration ---


class TestPDPTicketIntegration:
    def _safe(self, tmp_path: Path, signing_key: str | None = None) -> AgentSafe:
        return AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            signing_key=signing_key,
        )

    def test_allow_decision_has_ticket(self, tmp_path: Path):
        safe = self._safe(tmp_path, signing_key=SIGNING_KEY)
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.ticket is not None
        assert decision.ticket.action == "restart-deployment"
        assert decision.ticket.target == "dev/test-app"
        assert decision.ticket.audit_id == decision.audit_id

    def test_deny_decision_has_no_ticket(self, tmp_path: Path):
        safe = self._safe(tmp_path, signing_key=SIGNING_KEY)
        decision = safe.check(
            action="nonexistent-action",
            target="dev/test-app",
        )
        assert decision.result == DecisionResult.DENY
        assert decision.ticket is None

    def test_require_approval_has_no_ticket(self, tmp_path: Path):
        safe = self._safe(tmp_path, signing_key=SIGNING_KEY)
        decision = safe.check(
            action="restart-deployment",
            target="prod/api-server",
            params={"namespace": "prod", "deployment": "api"},
        )
        assert decision.result == DecisionResult.REQUIRE_APPROVAL
        assert decision.ticket is None

    def test_no_signing_key_means_no_ticket(self, tmp_path: Path):
        safe = self._safe(tmp_path, signing_key=None)
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.ticket is None

    def test_ticket_is_validated_by_validator(self, tmp_path: Path):
        """End-to-end: PDP issues ticket, validator accepts it."""
        safe = self._safe(tmp_path, signing_key=SIGNING_KEY)
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.ticket is not None

        validator = TicketValidator(SIGNING_KEY)
        result = validator.validate(
            decision.ticket.token,
            expected_action="restart-deployment",
            expected_target="dev/test-app",
        )
        assert result.valid

    def test_check_plan_has_tickets(self, tmp_path: Path):
        safe = self._safe(tmp_path, signing_key=SIGNING_KEY)
        plan = [
            {"action": "restart-deployment", "target": "dev/test-app",
             "params": {"namespace": "dev", "deployment": "app"}},
            {"action": "restart-deployment", "target": "prod/api-server",
             "params": {"namespace": "prod", "deployment": "api"}},
        ]
        decisions = safe.check_plan(plan)
        # First: dev → ALLOW with ticket
        assert decisions[0].result == DecisionResult.ALLOW
        assert decisions[0].ticket is not None
        # Second: prod → REQUIRE_APPROVAL, no ticket
        assert decisions[1].result == DecisionResult.REQUIRE_APPROVAL
        assert decisions[1].ticket is None


# --- CLI integration ---


def _runner() -> CliRunner:
    return CliRunner()


class TestCheckCommandTickets:
    def test_check_with_signing_key_shows_ticket(self, tmp_path: Path):
        result = _runner().invoke(cli, [
            "check", "restart-deployment",
            "--target", "dev/test-app",
            "--params", '{"namespace": "dev", "deployment": "app"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 0
        assert "ALLOW" in result.output
        assert "ticket:" in result.output
        assert "nonce:" in result.output
        assert "expires:" in result.output

    def test_check_deny_no_ticket_shown(self, tmp_path: Path):
        result = _runner().invoke(cli, [
            "check", "nonexistent-action",
            "--target", "dev/test-app",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 0
        assert "DENY" in result.output
        assert "ticket:" not in result.output

    def test_check_json_includes_ticket(self, tmp_path: Path):
        result = _runner().invoke(cli, [
            "check", "restart-deployment",
            "--target", "dev/test-app",
            "--params", '{"namespace": "dev", "deployment": "app"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--signing-key", SIGNING_KEY,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["result"] == "allow"
        assert data["ticket"] is not None
        assert "token" in data["ticket"]
        assert "nonce" in data["ticket"]


class TestTicketVerifyCommand:
    def _get_ticket_token(self, tmp_path: Path) -> str:
        """Issue a ticket via API and extract the token."""
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            signing_key=SIGNING_KEY,
        )
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.ticket is not None
        return decision.ticket.token

    def test_verify_valid_ticket(self, tmp_path: Path):
        token = self._get_ticket_token(tmp_path)
        result = _runner().invoke(cli, [
            "ticket", "verify", token,
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 0
        assert "VALID" in result.output
        assert "restart-deployment" in result.output

    def test_verify_with_action_match(self, tmp_path: Path):
        token = self._get_ticket_token(tmp_path)
        result = _runner().invoke(cli, [
            "ticket", "verify", token,
            "--signing-key", SIGNING_KEY,
            "--action", "restart-deployment",
        ])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_with_action_mismatch(self, tmp_path: Path):
        token = self._get_ticket_token(tmp_path)
        result = _runner().invoke(cli, [
            "ticket", "verify", token,
            "--signing-key", SIGNING_KEY,
            "--action", "scale-deployment",
        ])
        assert result.exit_code == 1
        assert "INVALID" in result.output
        assert "Action mismatch" in result.output

    def test_verify_wrong_key(self, tmp_path: Path):
        token = self._get_ticket_token(tmp_path)
        result = _runner().invoke(cli, [
            "ticket", "verify", token,
            "--signing-key", "wrong-key",
        ])
        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_verify_garbage_token(self):
        result = _runner().invoke(cli, [
            "ticket", "verify", "garbage.token.here",
            "--signing-key", SIGNING_KEY,
        ])
        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_verify_json_output(self, tmp_path: Path):
        token = self._get_ticket_token(tmp_path)
        result = _runner().invoke(cli, [
            "ticket", "verify", token,
            "--signing-key", SIGNING_KEY,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["valid"] is True
        assert data["ticket"]["action"] == "restart-deployment"

    def test_verify_replay_detected(self, tmp_path: Path):
        """Ticket verify command uses a fresh validator each call,
        so replay detection is per-validator-instance, not per-CLI-call.
        This tests the validator directly for replay."""
        token = self._get_ticket_token(tmp_path)
        validator = TicketValidator(SIGNING_KEY)
        r1 = validator.validate(token)
        assert r1.valid
        r2 = validator.validate(token)
        assert not r2.valid
        assert "replay" in r2.reason.lower()
