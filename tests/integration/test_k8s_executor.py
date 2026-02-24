"""Integration tests for K8sExecutor against a Kind cluster.

Requires: Kind cluster 'agent-safe-test' with bootstrapped resources.
Run: pytest tests/integration/test_k8s_executor.py -m integration -v
"""

from __future__ import annotations

import time

import pytest

from agent_safe.models import ExecutionStatus, Precheck
from tests.integration.conftest import skip_no_kind

pytestmark = [pytest.mark.integration, pytest.mark.kind, skip_no_kind]

NS = "agent-safe-inttest"
DEPLOY = "test-nginx"


class TestK8sScale:
    """Scale deployment up, verify state, scale back."""

    def test_scale_up(self, k8s_executor, k8s_credential):
        result = k8s_executor.execute(
            action="scale-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY, "replicas": 3},
            credential=k8s_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS

        state = k8s_executor.get_state(
            action="scale-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY},
            credential=k8s_credential,
        )
        assert state.get("spec", {}).get("replicas") == 3

    def test_scale_restore(self, k8s_executor, k8s_credential):
        result = k8s_executor.execute(
            action="scale-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY, "replicas": 2},
            credential=k8s_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestK8sRestart:
    def test_restart_deployment(self, k8s_executor, k8s_credential):
        result = k8s_executor.execute(
            action="restart-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY},
            credential=k8s_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestK8sLogs:
    def test_get_pod_logs(self, k8s_executor, k8s_credential, kind_kubeconfig):
        from kubernetes import client, config

        config.load_kube_config(config_file=kind_kubeconfig, context="kind-agent-safe-test")
        v1 = client.CoreV1Api()

        # Wait for a Running pod (previous restart may still be rolling)
        pod_name = None
        for _ in range(15):
            pods = v1.list_namespaced_pod(NS, label_selector="app=test-nginx")
            for p in pods.items:
                if p.status.phase == "Running" and p.metadata.deletion_timestamp is None:
                    pod_name = p.metadata.name
                    break
            if pod_name:
                break
            time.sleep(2)
        assert pod_name, "No Running pod found after waiting"

        result = k8s_executor.execute(
            action="get-pod-logs",
            target=f"{NS}/{pod_name}",
            params={"namespace": NS, "pod": pod_name},
            credential=k8s_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestK8sDeletePod:
    def test_delete_pod_recreated(self, k8s_executor, k8s_credential, kind_kubeconfig):
        from kubernetes import client, config

        config.load_kube_config(config_file=kind_kubeconfig, context="kind-agent-safe-test")
        v1 = client.CoreV1Api()
        pods = v1.list_namespaced_pod(NS, label_selector="app=test-nginx")
        pod_name = pods.items[0].metadata.name

        result = k8s_executor.execute(
            action="delete-pod",
            target=f"{NS}/{pod_name}",
            params={"namespace": NS, "pod": pod_name},
            credential=k8s_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS

        # Wait for replacement pod
        time.sleep(5)
        pods_after = v1.list_namespaced_pod(NS, label_selector="app=test-nginx")
        assert len(pods_after.items) >= 2


class TestK8sStateCapture:
    def test_get_state_deployment(self, k8s_executor, k8s_credential):
        state = k8s_executor.get_state(
            action="restart-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY},
            credential=k8s_credential,
        )
        assert isinstance(state, dict)
        assert "spec" in state
        assert "metadata" in state

    def test_get_state_configmap(self, k8s_executor, k8s_credential):
        state = k8s_executor.get_state(
            action="get-configmap",
            target=f"{NS}/test-config",
            params={"namespace": NS, "configmap": "test-config"},
            credential=k8s_credential,
        )
        assert state.get("data", {}).get("app.mode") == "testing"

    def test_get_state_nonexistent(self, k8s_executor, k8s_credential):
        state = k8s_executor.get_state(
            action="restart-deployment",
            target=f"{NS}/no-such-deploy",
            params={"namespace": NS, "deployment": "no-such-deploy"},
            credential=k8s_credential,
        )
        assert state == {}


class TestK8sPrechecks:
    def test_prechecks_pass(self, k8s_executor, k8s_credential):
        results = k8s_executor.run_prechecks(
            action="restart-deployment",
            target=f"{NS}/{DEPLOY}",
            params={"namespace": NS, "deployment": DEPLOY},
            prechecks=[Precheck(name="deploy-exists", description="Check deployment exists")],
            credential=k8s_credential,
        )
        assert len(results) == 1
        assert results[0].passed is True

    def test_prechecks_fail(self, k8s_executor, k8s_credential):
        results = k8s_executor.run_prechecks(
            action="restart-deployment",
            target=f"{NS}/no-such-deploy",
            params={"namespace": NS, "deployment": "no-such-deploy"},
            prechecks=[Precheck(name="deploy-exists", description="Check")],
            credential=k8s_credential,
        )
        assert len(results) == 1
        assert results[0].passed is False
