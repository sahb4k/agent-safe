"""Tests for runner CLI commands (v0.8.0)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from agent_safe.cli.main import cli
from agent_safe.tickets.issuer import TicketIssuer

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
SIGNING_KEY = "test-cli-runner-key-32chars-min!!"


def _issue_token(
    action: str = "restart-deployment",
    target: str = "dev/test-app",
    caller: str = "agent-01",
) -> str:
    issuer = TicketIssuer(signing_key=SIGNING_KEY)
    ticket = issuer.issue(
        action=action,
        target=target,
        caller=caller,
        audit_id="evt-cli-test",
        params={"namespace": "dev", "deployment": "test-app"},
    )
    return ticket.token


class TestRunnerExecuteCLI:
    def test_execute_dry_run_default(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert result.exit_code == 0
        assert "SKIPPED" in result.output

    def test_execute_invalid_token(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "runner", "execute", "bad-token",
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert result.exit_code == 1
        assert "ERROR" in result.output

    def test_execute_json_output(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "skipped"
        assert data["action"] == "restart-deployment"

    def test_execute_shows_executor_type(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert "dry-run" in result.output

    def test_execute_subprocess_unmapped_action(self) -> None:
        runner = CliRunner()
        token = _issue_token(action="exec-pod")
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--executor", "subprocess",
        ])
        # exec-pod is in registry but unmapped in SubprocessExecutor
        # So it will fail at executor level
        assert result.exit_code == 1


class TestRunnerDryRunCLI:
    def test_dry_run_valid_token(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "dry-run", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert result.exit_code == 0
        assert "DRY-RUN" in result.output

    def test_dry_run_invalid_token(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "runner", "dry-run", "bad-token",
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert result.exit_code == 1
        assert "ERROR" in result.output

    def test_dry_run_json_output(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "dry-run", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "skipped"

    def test_dry_run_shows_action_info(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "dry-run", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
        ])
        assert "restart-deployment" in result.output
        assert "dev/test-app" in result.output


class TestRunnerExecutorOptionsCLI:
    def test_executor_k8s_option_accepted(self) -> None:
        """CLI accepts --executor k8s (will fail at k8s import, but option is valid)."""
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--executor", "k8s",
        ])
        # May succeed or fail depending on kubernetes package,
        # but should NOT fail with "invalid choice"
        assert "Invalid value" not in (result.output or "")

    def test_executor_aws_option_accepted(self) -> None:
        """CLI accepts --executor aws (will fail at boto3 import, but option is valid)."""
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--executor", "aws",
        ])
        assert "Invalid value" not in (result.output or "")

    def test_aws_region_option(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--executor", "dry-run",
            "--aws-region", "us-west-2",
        ])
        # aws-region is ignored for dry-run but should not error
        assert result.exit_code == 0

    def test_aws_profile_option(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--executor", "dry-run",
            "--aws-profile", "staging",
        ])
        assert result.exit_code == 0

    def test_in_cluster_option(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--executor", "dry-run",
            "--in-cluster",
        ])
        assert result.exit_code == 0

    def test_invalid_executor_rejected(self) -> None:
        runner = CliRunner()
        token = _issue_token()
        result = runner.invoke(cli, [
            "runner", "execute", token,
            "--signing-key", SIGNING_KEY,
            "--registry", ACTIONS_DIR,
            "--executor", "invalid-executor",
        ])
        assert result.exit_code != 0
