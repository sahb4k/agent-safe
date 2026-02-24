"""Tests for SubprocessExecutor and kubectl command mapping (v0.8.0).

All subprocess.run calls are mocked — no actual kubectl execution.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from agent_safe.models import (
    ExecutionStatus,
    Precheck,
)
from agent_safe.runner.subprocess_executor import (
    KUBECTL_COMMANDS,
    SubprocessExecutor,
    build_kubectl_args,
)

# --- KubectlTemplate Mapping Tests ---


class TestKubectlTemplateMapping:
    def test_restart_deployment_mapped(self) -> None:
        assert "restart-deployment" in KUBECTL_COMMANDS
        t = KUBECTL_COMMANDS["restart-deployment"]
        assert t.verb == "rollout restart"

    def test_scale_deployment_mapped(self) -> None:
        t = KUBECTL_COMMANDS["scale-deployment"]
        assert t.verb == "scale"
        assert "--replicas={replicas}" in t.extra_args

    def test_delete_pod_mapped(self) -> None:
        t = KUBECTL_COMMANDS["delete-pod"]
        assert t.verb == "delete"
        assert t.resource == "pod/{pod}"

    def test_cordon_node_mapped(self) -> None:
        t = KUBECTL_COMMANDS["cordon-node"]
        assert t.verb == "cordon"

    def test_uncordon_node_mapped(self) -> None:
        t = KUBECTL_COMMANDS["uncordon-node"]
        assert t.verb == "uncordon"

    def test_drain_node_mapped(self) -> None:
        t = KUBECTL_COMMANDS["drain-node"]
        assert "--ignore-daemonsets" in t.extra_args

    def test_rollout_undo_mapped(self) -> None:
        t = KUBECTL_COMMANDS["rollout-undo"]
        assert t.verb == "rollout undo"

    def test_get_pod_logs_mapped(self) -> None:
        t = KUBECTL_COMMANDS["get-pod-logs"]
        assert t.verb == "logs"

    def test_update_image_mapped(self) -> None:
        t = KUBECTL_COMMANDS["update-image"]
        assert t.verb == "set image"

    def test_build_kubectl_args_restart(self) -> None:
        t = KUBECTL_COMMANDS["restart-deployment"]
        args = build_kubectl_args(
            t,
            {"namespace": "prod", "deployment": "api"},
            kubectl_path="kubectl",
        )
        assert args == [
            "kubectl", "rollout", "restart",
            "deployment/api", "-n", "prod",
        ]

    def test_build_kubectl_args_scale(self) -> None:
        t = KUBECTL_COMMANDS["scale-deployment"]
        args = build_kubectl_args(
            t,
            {"namespace": "dev", "deployment": "web", "replicas": 5},
        )
        assert "deployment/web" in args
        assert "--replicas=5" in args
        assert "-n" in args

    def test_build_kubectl_args_with_kubeconfig(self) -> None:
        t = KUBECTL_COMMANDS["restart-deployment"]
        args = build_kubectl_args(
            t,
            {"namespace": "prod", "deployment": "api"},
            kubeconfig="/tmp/kc.yaml",
        )
        assert "--kubeconfig" in args
        assert "/tmp/kc.yaml" in args

    def test_build_kubectl_args_with_context(self) -> None:
        t = KUBECTL_COMMANDS["restart-deployment"]
        args = build_kubectl_args(
            t,
            {"namespace": "prod", "deployment": "api"},
            context="my-cluster",
        )
        assert "--context" in args
        assert "my-cluster" in args


# --- SubprocessExecutor Execute Tests ---


class TestSubprocessExecutorExecute:
    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_execute_success(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="deployment.apps/api restarted\n",
            stderr="",
        )
        executor = SubprocessExecutor()
        result = executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert "restarted" in result.output
        assert result.executor_type == "subprocess"

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_execute_failure(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="",
            stderr="Error: deployment not found",
        )
        executor = SubprocessExecutor()
        result = executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status == ExecutionStatus.FAILURE
        assert "not found" in result.error

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_execute_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="kubectl", timeout=30)
        executor = SubprocessExecutor()
        result = executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            timeout=30,
        )
        assert result.status == ExecutionStatus.TIMEOUT
        assert "timed out" in result.error.lower()

    def test_execute_unmapped_action(self) -> None:
        executor = SubprocessExecutor()
        result = executor.execute(
            action="exec-pod",
            target="dev/pod",
            params={},
        )
        assert result.status == ExecutionStatus.ERROR
        assert "No kubectl mapping" in result.error

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_execute_with_custom_kubectl_path(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok", stderr="",
        )
        executor = SubprocessExecutor(kubectl_path="/usr/local/bin/kubectl")
        executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        call_args = mock_run.call_args[0][0]
        assert call_args[0] == "/usr/local/bin/kubectl"

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_execute_with_context(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="ok", stderr="",
        )
        executor = SubprocessExecutor(context="my-cluster")
        executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        call_args = mock_run.call_args[0][0]
        assert "--context" in call_args
        assert "my-cluster" in call_args

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_execute_captures_stdout(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="  deployment scaled  \n",
            stderr="",
        )
        executor = SubprocessExecutor()
        result = executor.execute(
            action="scale-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api", "replicas": 3},
        )
        assert result.output == "deployment scaled"

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_success_has_no_error(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="ok",
            stderr="some warning",
        )
        executor = SubprocessExecutor()
        result = executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert result.error is None


# --- SubprocessExecutor get_state Tests ---


class TestSubprocessExecutorState:
    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_get_state_parses_json(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout='{"spec":{"replicas":3}}',
            stderr="",
        )
        executor = SubprocessExecutor()
        state = executor.get_state(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert state == {"spec": {"replicas": 3}}

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_get_state_missing_resource(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="",
            stderr="not found",
        )
        executor = SubprocessExecutor()
        state = executor.get_state(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert state == {}

    def test_get_state_unmapped_action(self) -> None:
        executor = SubprocessExecutor()
        state = executor.get_state("exec-pod", "target", {})
        assert state == {}

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_get_state_non_json_output(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="NAME   READY\napi    1/1",
            stderr="",
        )
        executor = SubprocessExecutor()
        state = executor.get_state(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert "raw" in state

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_get_state_timeout(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="kubectl", timeout=30)
        executor = SubprocessExecutor()
        state = executor.get_state(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert state == {}


# --- SubprocessExecutor Prechecks Tests ---


class TestSubprocessExecutorPrechecks:
    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_prechecks_pass_when_state_exists(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout='{"spec":{}}',
            stderr="",
        )
        executor = SubprocessExecutor()
        results = executor.run_prechecks(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            prechecks=[Precheck(name="check-exists", description="Verify")],
        )
        assert len(results) == 1
        assert results[0].passed is True

    @patch("agent_safe.runner.subprocess_executor.subprocess.run")
    def test_prechecks_fail_when_state_empty(self, mock_run: MagicMock) -> None:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1,
            stdout="",
            stderr="not found",
        )
        executor = SubprocessExecutor()
        results = executor.run_prechecks(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            prechecks=[Precheck(name="check-exists", description="Verify")],
        )
        assert len(results) == 1
        assert results[0].passed is False

    def test_prechecks_empty_list(self) -> None:
        executor = SubprocessExecutor()
        results = executor.run_prechecks(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            prechecks=[],
        )
        assert results == []
