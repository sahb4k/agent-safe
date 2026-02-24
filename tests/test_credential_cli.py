"""Tests for the credential CLI commands."""

import json
from pathlib import Path

from click.testing import CliRunner

from agent_safe import AgentSafe
from agent_safe.cli.main import cli

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"
SIGNING_KEY = "test-credential-cli-key"


def runner() -> CliRunner:
    return CliRunner(mix_stderr=False)


def _get_ticket_token(tmp_path: Path) -> str:
    """Helper: get a valid ticket token for restart-deployment on dev."""
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
        caller="any-agent",
        params={"namespace": "dev", "deployment": "app"},
    )
    assert decision.ticket is not None
    return decision.ticket.token


# --- credential resolve ---


class TestCredentialResolve:
    def test_resolve_success(self, tmp_path: Path):
        token = _get_ticket_token(tmp_path)
        result = runner().invoke(cli, [
            "credential", "resolve", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--vault-cred", "kubernetes=test-k8s-token",
        ])
        assert result.exit_code == 0
        assert "OK" in result.output
        assert "credential_id:" in result.output

    def test_resolve_json_output(self, tmp_path: Path):
        token = _get_ticket_token(tmp_path)
        result = runner().invoke(cli, [
            "credential", "resolve", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--vault-cred", "kubernetes=test-k8s-token",
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["success"] is True
        assert data["credential"]["type"] == "kubernetes"

    def test_resolve_invalid_ticket(self):
        result = runner().invoke(cli, [
            "credential", "resolve", "garbage-token",
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert result.exit_code == 1
        assert "INVALID TICKET" in result.output

    def test_resolve_no_vault_cred(self, tmp_path: Path):
        token = _get_ticket_token(tmp_path)
        result = runner().invoke(cli, [
            "credential", "resolve", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert result.exit_code == 1
        assert "FAILED" in result.output


# --- credential test-vault ---


class TestCredentialTestVault:
    def test_vault_ok(self):
        result = runner().invoke(cli, [
            "credential", "test-vault",
            "--vault-cred", "kubernetes=test-token",
            "--cred-type", "kubernetes",
        ])
        assert result.exit_code == 0
        assert "OK" in result.output
        assert "revoke:" in result.output

    def test_vault_no_cred_fails(self):
        result = runner().invoke(cli, [
            "credential", "test-vault",
            "--cred-type", "kubernetes",
        ])
        assert result.exit_code == 1
        assert "FAILED" in result.output
