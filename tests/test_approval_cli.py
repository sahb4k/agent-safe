"""Tests for the approval CLI commands."""

import json
from pathlib import Path

from click.testing import CliRunner

from agent_safe import AgentSafe
from agent_safe.cli.main import cli

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")


def runner() -> CliRunner:
    return CliRunner()


def _create_pending_request(tmp_path: Path) -> tuple[AgentSafe, str]:
    """Helper: create an AgentSafe with a pending approval request.

    Returns (safe, request_id).
    """
    safe = AgentSafe(
        registry=ACTIONS_DIR,
        policies=POLICIES_DIR,
        inventory=INVENTORY_FILE,
        audit_log=tmp_path / "audit.jsonl",
        approval_store=tmp_path / "approvals.jsonl",
    )
    decision = safe.check(
        action="restart-deployment",
        target="prod/api-server",
        caller="deploy-agent-01",
        params={"namespace": "prod", "deployment": "api-server"},
    )
    return safe, decision.request_id


# --- check command with --approval-store ---


class TestCheckWithApprovalStore:
    def test_check_shows_request_id(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "check", "restart-deployment",
            "--target", "prod/api-server",
            "--caller", "deploy-agent-01",
            "--params", '{"namespace": "prod", "deployment": "api-server"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--approval-store", str(tmp_path / "approvals.jsonl"),
        ])
        assert result.exit_code == 0
        assert "REQUIRE_APPROVAL" in result.output
        assert "request:" in result.output
        assert "apr-" in result.output
        assert "agent-safe approval approve" in result.output

    def test_check_json_includes_request_id(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "check", "restart-deployment",
            "--target", "prod/api-server",
            "--caller", "deploy-agent-01",
            "--params", '{"namespace": "prod", "deployment": "api-server"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--approval-store", str(tmp_path / "approvals.jsonl"),
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["request_id"] is not None
        assert data["request_id"].startswith("apr-")


# --- approval list ---


class TestApprovalList:
    def test_list_pending(self, tmp_path: Path):
        _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "list",
            "--store", str(tmp_path / "approvals.jsonl"),
        ])
        assert result.exit_code == 0
        assert "restart-deployment" in result.output
        assert "pending request(s)" in result.output

    def test_list_pending_json(self, tmp_path: Path):
        _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "list",
            "--store", str(tmp_path / "approvals.jsonl"),
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["action"] == "restart-deployment"

    def test_list_no_store(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "approval", "list",
            "--store", str(tmp_path / "nonexistent.jsonl"),
        ])
        assert result.exit_code == 0
        assert "No approval store found" in result.output

    def test_list_empty(self, tmp_path: Path):
        # Create empty store file
        (tmp_path / "approvals.jsonl").touch()
        result = runner().invoke(cli, [
            "approval", "list",
            "--store", str(tmp_path / "approvals.jsonl"),
        ])
        assert result.exit_code == 0
        assert "No pending" in result.output


# --- approval show ---


class TestApprovalShow:
    def test_show_request(self, tmp_path: Path):
        _, request_id = _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "show", request_id,
            "--store", str(tmp_path / "approvals.jsonl"),
        ])
        assert result.exit_code == 0
        assert "PENDING" in result.output
        assert "restart-deployment" in result.output

    def test_show_json(self, tmp_path: Path):
        _, request_id = _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "show", request_id,
            "--store", str(tmp_path / "approvals.jsonl"),
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["request_id"] == request_id
        assert data["status"] == "pending"

    def test_show_not_found(self, tmp_path: Path):
        _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "show", "apr-nonexistent",
            "--store", str(tmp_path / "approvals.jsonl"),
        ])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_show_missing_store(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "approval", "show", "apr-fake",
            "--store", str(tmp_path / "missing.jsonl"),
        ])
        assert result.exit_code == 1


# --- approval approve ---


class TestApprovalApprove:
    def test_approve_request(self, tmp_path: Path):
        _, request_id = _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "approve", request_id,
            "--by", "admin",
            "--reason", "Ship it",
            "--store", str(tmp_path / "approvals.jsonl"),
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--audit-log", str(tmp_path / "audit.jsonl"),
        ])
        assert result.exit_code == 0
        assert "ALLOW" in result.output
        assert request_id in result.output

    def test_approve_with_signing_key_shows_ticket(self, tmp_path: Path):
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            approval_store=tmp_path / "approvals.jsonl",
            signing_key="test-key",
        )
        decision = safe.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )

        result = runner().invoke(cli, [
            "approval", "approve", decision.request_id,
            "--by", "admin",
            "--store", str(tmp_path / "approvals.jsonl"),
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--signing-key", "test-key",
        ])
        assert result.exit_code == 0
        assert "ALLOW" in result.output
        assert "ticket:" in result.output


# --- approval deny ---


class TestApprovalDeny:
    def test_deny_request(self, tmp_path: Path):
        _, request_id = _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "deny", request_id,
            "--by", "reviewer",
            "--reason", "Not now",
            "--store", str(tmp_path / "approvals.jsonl"),
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--audit-log", str(tmp_path / "audit.jsonl"),
        ])
        assert result.exit_code == 0
        assert "DENY" in result.output
        assert request_id in result.output

    def test_deny_nonexistent_request(self, tmp_path: Path):
        _create_pending_request(tmp_path)

        result = runner().invoke(cli, [
            "approval", "deny", "apr-nonexistent",
            "--store", str(tmp_path / "approvals.jsonl"),
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--audit-log", str(tmp_path / "audit.jsonl"),
        ])
        assert result.exit_code == 1
        assert "ERROR" in result.output
