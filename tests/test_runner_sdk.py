"""Tests for SDK execute() integration (v0.8.0)."""

from __future__ import annotations

import tempfile
from unittest.mock import MagicMock

import pytest

from agent_safe.models import ExecutionResult, ExecutionStatus
from agent_safe.sdk.client import AgentSafe, AgentSafeError

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"
SIGNING_KEY = "test-sdk-runner-key-32chars-min!!"


class TestSDKExecute:
    def test_execute_default_dry_run(self) -> None:
        """Default executor is DryRunExecutor."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=tmp.name,
                signing_key=SIGNING_KEY,
            )
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                params={"namespace": "dev", "deployment": "test-app"},
            )
            assert decision.ticket is not None

            result = safe.execute(decision.ticket.token)
            assert result.status == ExecutionStatus.SKIPPED
            assert result.action == "restart-deployment"
            assert result.executor_type == "dry-run"

    def test_execute_with_custom_executor(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=tmp.name,
                signing_key=SIGNING_KEY,
            )
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                params={"namespace": "dev", "deployment": "test-app"},
            )

            mock_executor = MagicMock()
            mock_executor.run_prechecks.return_value = []
            mock_executor.get_state.return_value = {}
            mock_executor.execute.return_value = ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                audit_id=decision.audit_id,
                output="done",
            )

            result = safe.execute(decision.ticket.token, executor=mock_executor)
            assert result.status == ExecutionStatus.SUCCESS
            mock_executor.execute.assert_called_once()

    def test_execute_without_signing_key_raises(self) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        with pytest.raises(AgentSafeError, match="Signing key"):
            safe.execute("some-token")

    def test_execute_invalid_token(self) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            signing_key=SIGNING_KEY,
        )
        result = safe.execute("garbage-token")
        assert result.status == ExecutionStatus.ERROR

    def test_execute_audits_result(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=tmp.name,
                signing_key=SIGNING_KEY,
            )
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                params={"namespace": "dev", "deployment": "test-app"},
            )
            safe.execute(decision.ticket.token)

            events = safe.audit.read_events()
            execution_events = [e for e in events if e.event_type == "execution"]
            assert len(execution_events) == 1

    def test_end_to_end_check_then_execute(self) -> None:
        """Full flow: check → get ticket → execute."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=tmp.name,
                signing_key=SIGNING_KEY,
            )
            # 1. Policy check
            decision = safe.check(
                action="scale-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                params={
                    "namespace": "dev",
                    "deployment": "test-app",
                    "replicas": 3,
                },
            )
            assert decision.result.value == "allow"
            assert decision.ticket is not None

            # 2. Execute with dry-run
            result = safe.execute(decision.ticket.token)
            assert result.status == ExecutionStatus.SKIPPED
            assert result.audit_id == decision.audit_id

    def test_execute_with_timeout(self) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            signing_key=SIGNING_KEY,
        )
        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="deploy-bot",
            params={"namespace": "dev", "deployment": "test-app"},
        )
        result = safe.execute(decision.ticket.token, timeout=60.0)
        assert result.status == ExecutionStatus.SKIPPED

    def test_execute_with_vault(self) -> None:
        """Execute with credential vault configured."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=tmp.name,
                signing_key=SIGNING_KEY,
                credential_vault={
                    "type": "env",
                    "credentials": {"kubernetes": {"token": "test-token"}},
                },
            )
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                params={"namespace": "dev", "deployment": "test-app"},
            )
            # Should not error — DryRunExecutor ignores credentials
            result = safe.execute(decision.ticket.token)
            assert result.status == ExecutionStatus.SKIPPED

    def test_execute_with_mock_k8s_executor(self) -> None:
        """SDK execute() with a mock K8sExecutor."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=tmp.name,
                signing_key=SIGNING_KEY,
            )
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                params={"namespace": "dev", "deployment": "test-app"},
            )

            mock_executor = MagicMock()
            mock_executor.run_prechecks.return_value = []
            mock_executor.get_state.return_value = {}
            mock_executor.execute.return_value = ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                audit_id=decision.audit_id,
                output="restarted via k8s client",
                executor_type="k8s",
            )

            result = safe.execute(decision.ticket.token, executor=mock_executor)
            assert result.status == ExecutionStatus.SUCCESS
            assert result.executor_type == "k8s"

    def test_execute_with_mock_aws_executor(self) -> None:
        """SDK execute() with a mock AwsExecutor."""
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=tmp.name,
                signing_key=SIGNING_KEY,
            )
            # Use a dev target that gets ALLOW, then pass a mock AWS executor
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                params={"namespace": "dev", "deployment": "test-app"},
            )
            assert decision.ticket is not None

            mock_executor = MagicMock()
            mock_executor.run_prechecks.return_value = []
            mock_executor.get_state.return_value = {}
            mock_executor.execute.return_value = ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-bot",
                audit_id=decision.audit_id,
                output="instance stopping",
                executor_type="aws",
            )

            result = safe.execute(decision.ticket.token, executor=mock_executor)
            assert result.status == ExecutionStatus.SUCCESS
            assert result.executor_type == "aws"
