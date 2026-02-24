"""Integration tests for SubprocessExecutor against a Kind cluster.

Requires: Kind cluster 'agent-safe-test' + kubectl in PATH.
Run: pytest tests/integration/test_subprocess_executor.py -m integration -v
"""

from __future__ import annotations

import subprocess as sp
import time

import pytest

from agent_safe.models import ExecutionStatus
from tests.integration.conftest import skip_no_kind

pytestmark = [pytest.mark.integration, pytest.mark.kind, skip_no_kind]

NS = "agent-safe-inttest"
DEPLOY = "test-nginx"


def _get_running_pod_name(kubeconfig: str) -> str:
    """Get the name of a Running (non-terminating) pod from the test deployment."""
    for _ in range(15):
        result = sp.run(
            [
                "kubectl", "--kubeconfig", kubeconfig,
                "--context", "kind-agent-safe-test",
                "get", "pods", "-n", NS,
                "-l", "app=test-nginx",
                "--field-selector", "status.phase=Running",
                "-o", "jsonpath={.items[0].metadata.name}",
            ],
            capture_output=True, text=True, timeout=10,
        )
        name = result.stdout.strip()
        if name:
            return name
        time.sleep(2)
    raise AssertionError("No Running pod found after waiting")


class TestSubprocessScale:
    def test_scale_and_get_state(self, subprocess_executor):
        result = subprocess_executor.execute(
            action="scale-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY, "replicas": 3},
        )
        assert result.status == ExecutionStatus.SUCCESS

        state = subprocess_executor.get_state(
            action="scale-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY},
        )
        assert isinstance(state, dict)
        assert state.get("spec", {}).get("replicas") == 3

        # Restore
        subprocess_executor.execute(
            action="scale-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY, "replicas": 2},
        )


class TestSubprocessRestart:
    def test_restart_deployment(self, subprocess_executor):
        result = subprocess_executor.execute(
            action="restart-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY},
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestSubprocessLogs:
    def test_get_pod_logs(self, subprocess_executor, kind_kubeconfig):
        pod_name = _get_running_pod_name(kind_kubeconfig)
        result = subprocess_executor.execute(
            action="get-pod-logs",
            target=f"{NS}/{pod_name}",
            params={"namespace": NS, "pod": pod_name},
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestSubprocessDeletePod:
    def test_delete_pod(self, subprocess_executor, kind_kubeconfig):
        pod_name = _get_running_pod_name(kind_kubeconfig)
        result = subprocess_executor.execute(
            action="delete-pod",
            target=f"{NS}/{pod_name}",
            params={"namespace": NS, "pod": pod_name},
        )
        assert result.status == ExecutionStatus.SUCCESS
        time.sleep(5)


class TestSubprocessErrors:
    def test_nonexistent_deployment_fails(self, subprocess_executor):
        result = subprocess_executor.execute(
            action="restart-deployment",
            target=f"{NS}/no-such-deploy",
            params={"namespace": NS, "deployment": "no-such-deploy"},
        )
        assert result.status == ExecutionStatus.FAILURE

    def test_get_state_returns_dict(self, subprocess_executor):
        state = subprocess_executor.get_state(
            action="scale-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY},
        )
        assert isinstance(state, dict)
        assert "metadata" in state
