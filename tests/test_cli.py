"""Tests for the agent-safe CLI."""

import json
from pathlib import Path

from click.testing import CliRunner

from agent_safe.cli.main import cli

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"


def runner() -> CliRunner:
    return CliRunner(mix_stderr=False)


# --- check command ---


class TestCheckCommand:
    def test_check_dev_allow(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "check", "restart-deployment",
            "--target", "dev/test-app",
            "--caller", "any-agent",
            "--params", '{"namespace": "dev", "deployment": "app"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
        ])
        assert result.exit_code == 0
        assert "ALLOW" in result.output

    def test_check_prod_require_approval(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "check", "restart-deployment",
            "--target", "prod/api-server",
            "--caller", "deploy-agent-01",
            "--params", '{"namespace": "prod", "deployment": "api-server"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
        ])
        assert result.exit_code == 0
        assert "REQUIRE_APPROVAL" in result.output

    def test_check_unknown_action(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "check", "nuke-everything",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--audit-log", str(tmp_path / "audit.jsonl"),
        ])
        assert result.exit_code == 0
        assert "DENY" in result.output

    def test_check_json_output(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "check", "restart-deployment",
            "--target", "dev/test-app",
            "--caller", "any-agent",
            "--params", '{"namespace": "dev", "deployment": "app"}',
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", str(tmp_path / "audit.jsonl"),
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["result"] == "allow"
        assert "audit_id" in data

    def test_check_invalid_params_json(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "check", "restart-deployment",
            "--params", "{not valid json}",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--audit-log", str(tmp_path / "audit.jsonl"),
        ])
        assert result.exit_code == 1
        assert "invalid JSON" in result.stderr


# --- list-actions command ---


class TestListActionsCommand:
    def test_list_actions(self):
        result = runner().invoke(cli, [
            "list-actions",
            "--registry", ACTIONS_DIR,
        ])
        assert result.exit_code == 0
        assert "restart-deployment" in result.output
        assert "action(s) registered" in result.output

    def test_list_actions_json(self):
        result = runner().invoke(cli, [
            "list-actions",
            "--registry", ACTIONS_DIR,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) >= 5
        names = [a["name"] for a in data]
        assert "restart-deployment" in names

    def test_list_actions_filter_tag(self):
        result = runner().invoke(cli, [
            "list-actions",
            "--registry", ACTIONS_DIR,
            "--tag", "kubernetes",
        ])
        assert result.exit_code == 0
        assert "restart-deployment" in result.output

    def test_list_actions_filter_risk(self):
        result = runner().invoke(cli, [
            "list-actions",
            "--registry", ACTIONS_DIR,
            "--risk", "low",
        ])
        assert result.exit_code == 0
        assert "get-pod-logs" in result.output


# --- validate command ---


class TestValidateCommand:
    def test_validate_all(self):
        result = runner().invoke(cli, [
            "validate",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
        ])
        assert result.exit_code == 0
        assert "OK" in result.output
        assert "valid" in result.output.lower()

    def test_validate_bad_registry(self, tmp_path: Path):
        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        bad_file = bad_dir / "bad.yaml"
        bad_file.write_text("not: a: valid: action", encoding="utf-8")
        result = runner().invoke(cli, [
            "validate", "--registry", str(bad_dir),
        ])
        assert result.exit_code == 1
        assert "FAIL" in result.output


# --- audit verify command ---


class TestAuditVerifyCommand:
    def test_verify_valid_log(self, tmp_path: Path):
        from agent_safe import AgentSafe

        log_path = tmp_path / "audit.jsonl"
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            audit_log=log_path,
        )
        safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        result = runner().invoke(cli, ["audit", "verify", str(log_path)])
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_verify_tampered_log(self, tmp_path: Path):
        from agent_safe import AgentSafe

        log_path = tmp_path / "audit.jsonl"
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            audit_log=log_path,
        )
        safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        safe.check(
            action="get-pod-logs",
            target="dev/test-app",
            caller="agent",
            params={"namespace": "dev", "pod": "x"},
        )
        # Tamper
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["reason"] = "TAMPERED"
        lines[0] = json.dumps(entry, sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = runner().invoke(cli, ["audit", "verify", str(log_path)])
        assert result.exit_code == 1
        assert "INVALID" in result.output

    def test_verify_missing_log(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "audit", "verify", str(tmp_path / "missing.jsonl"),
        ])
        assert result.exit_code == 1


# --- audit show command ---


class TestAuditShowCommand:
    def test_show_events(self, tmp_path: Path):
        from agent_safe import AgentSafe

        log_path = tmp_path / "audit.jsonl"
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            audit_log=log_path,
        )
        safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        result = runner().invoke(cli, ["audit", "show", str(log_path)])
        assert result.exit_code == 0
        assert "restart-deployment" in result.output
        assert "event(s) shown" in result.output

    def test_show_json(self, tmp_path: Path):
        from agent_safe import AgentSafe

        log_path = tmp_path / "audit.jsonl"
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            audit_log=log_path,
        )
        safe.check(
            action="get-pod-logs",
            target="dev/test-app",
            caller="agent",
            params={"namespace": "dev", "pod": "x"},
        )
        result = runner().invoke(cli, [
            "audit", "show", str(log_path), "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert len(data) == 1

    def test_show_missing_log(self, tmp_path: Path):
        result = runner().invoke(cli, [
            "audit", "show", str(tmp_path / "missing.jsonl"),
        ])
        assert result.exit_code == 1
