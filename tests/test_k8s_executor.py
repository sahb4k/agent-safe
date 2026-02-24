"""Tests for K8sExecutor (v0.9.0).

All kubernetes client calls are mocked — no real cluster needed.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from agent_safe.models import Credential, CredentialScope, ExecutionStatus, Precheck
from agent_safe.runner.k8s_executor import K8S_ACTION_MAP, K8sActionMapping, K8sExecutor

# --- Helpers ---


@contextmanager
def _mock_kubernetes_modules():
    """Context manager that injects mock kubernetes into sys.modules.

    This allows `from kubernetes import client, config` to work without
    the actual kubernetes package installed.
    """
    mock_k8s = MagicMock()
    mock_client = mock_k8s.client
    mock_config = mock_k8s.config
    mock_client.Configuration.return_value = MagicMock()
    mock_client.ApiClient.return_value = MagicMock()
    mock_exceptions = MagicMock()
    mock_client.exceptions = mock_exceptions

    modules = {
        "kubernetes": mock_k8s,
        "kubernetes.client": mock_client,
        "kubernetes.config": mock_config,
        "kubernetes.client.exceptions": mock_exceptions,
    }
    with patch.dict(sys.modules, modules):
        yield mock_client, mock_config


def _make_credential(
    payload: dict[str, Any] | None = None,
) -> Credential:
    return Credential(
        credential_id="cred-test",
        type="kubernetes",
        payload=payload or {"token": "test-token"},
        expires_at=datetime.now(tz=UTC),
        scope=CredentialScope(type="kubernetes", fields={}),
        ticket_nonce="nonce-test",
    )


# --- K8sActionMapping Tests ---


class TestK8sActionMapping:
    def test_restart_deployment_mapped(self) -> None:
        assert "restart-deployment" in K8S_ACTION_MAP
        m = K8S_ACTION_MAP["restart-deployment"]
        assert m.api_class == "AppsV1Api"
        assert m.execute_method == "patch_namespaced_deployment"

    def test_scale_deployment_mapped(self) -> None:
        m = K8S_ACTION_MAP["scale-deployment"]
        assert m.api_class == "AppsV1Api"
        assert m.body_builder == "_build_scale_body"

    def test_delete_pod_mapped(self) -> None:
        m = K8S_ACTION_MAP["delete-pod"]
        assert m.api_class == "CoreV1Api"
        assert m.execute_method == "delete_namespaced_pod"

    def test_cordon_node_mapped(self) -> None:
        m = K8S_ACTION_MAP["cordon-node"]
        assert m.namespaced is False
        assert m.body_builder == "_build_cordon_body"

    def test_uncordon_node_mapped(self) -> None:
        m = K8S_ACTION_MAP["uncordon-node"]
        assert m.body_builder == "_build_uncordon_body"

    def test_drain_node_mapped(self) -> None:
        m = K8S_ACTION_MAP["drain-node"]
        assert m.execute_method == "_execute_drain"

    def test_rollout_undo_mapped(self) -> None:
        m = K8S_ACTION_MAP["rollout-undo"]
        assert m.body_builder == "_build_rollback_body"

    def test_get_pod_logs_mapped(self) -> None:
        m = K8S_ACTION_MAP["get-pod-logs"]
        assert m.execute_method == "read_namespaced_pod_log"

    def test_update_image_mapped(self) -> None:
        m = K8S_ACTION_MAP["update-image"]
        assert m.body_builder == "_build_image_patch"

    def test_all_18_actions_mapped(self) -> None:
        assert len(K8S_ACTION_MAP) == 18
        for name, mapping in K8S_ACTION_MAP.items():
            assert isinstance(mapping, K8sActionMapping), f"{name} is not K8sActionMapping"
            assert mapping.api_class, f"{name} missing api_class"
            assert mapping.state_method, f"{name} missing state_method"


# --- K8sExecutor Execute Tests ---


class TestK8sExecutorExecute:
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_success(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "api"
        mock_api.patch_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert result.executor_type == "k8s"

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_api_exception(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        # Simulate ApiException
        mock_api = MagicMock()
        exc = type("ApiException", (Exception,), {"status": 404, "reason": "Not Found"})()
        # We need to mock the import of ApiException
        mock_api.patch_namespaced_deployment.side_effect = exc
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        # Since the exception won't be an ApiException (different class),
        # it will be caught by the general Exception handler
        result = executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status in (ExecutionStatus.FAILURE, ExecutionStatus.ERROR)
        assert result.error is not None

    def test_execute_unmapped_action(self) -> None:
        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="exec-pod",
            target="dev/pod",
            params={},
        )
        assert result.status == ExecutionStatus.ERROR
        assert "No K8s API mapping" in result.error

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_scale_deployment(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "web"
        mock_api.patch_namespaced_deployment_scale.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="scale-deployment",
            target="dev/web",
            params={"namespace": "dev", "deployment": "web", "replicas": 5},
        )
        assert result.status == ExecutionStatus.SUCCESS
        mock_api.patch_namespaced_deployment_scale.assert_called_once()

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_delete_pod(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_api.delete_namespaced_pod.return_value = MagicMock()
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="delete-pod",
            target="dev/mypod",
            params={"namespace": "dev", "pod": "mypod"},
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_cordon_node(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "node-1"
        mock_api.patch_node.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="cordon-node",
            target="prod/node-1",
            params={"node": "node-1"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        call_kwargs = mock_api.patch_node.call_args
        assert call_kwargs[1]["body"]["spec"]["unschedulable"] is True

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_get_pod_logs(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_api.read_namespaced_pod_log.return_value = "line1\nline2\n"
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="get-pod-logs",
            target="dev/mypod",
            params={"namespace": "dev", "pod": "mypod"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert "line1" in result.output

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_update_image(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "app"
        mock_api.patch_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="update-image",
            target="dev/app",
            params={
                "namespace": "dev",
                "deployment": "app",
                "container": "web",
                "image": "nginx:1.25",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS
        call_kwargs = mock_api.patch_namespaced_deployment.call_args
        body = call_kwargs[1]["body"]
        assert body["spec"]["template"]["spec"]["containers"][0]["image"] == "nginx:1.25"

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_general_error(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_api.patch_namespaced_deployment.side_effect = ConnectionError("timeout")
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status == ExecutionStatus.ERROR
        assert "timeout" in result.error

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_rollout_status_readonly(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "api"
        mock_api.read_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="rollout-status",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_create_namespace(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "new-ns"
        mock_api.create_namespace.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        # Mock kubernetes.client for V1Namespace
        with patch("agent_safe.runner.k8s_executor.K8sExecutor._build_namespace_body") as mock_body:
            mock_body.return_value = {"metadata": {"name": "new-ns"}}

            executor = K8sExecutor.__new__(K8sExecutor)
            executor._kubeconfig = None
            executor._context = None
            executor._in_cluster = False

            result = executor.execute(
                action="create-namespace",
                target="prod/new-ns",
                params={"namespace": "new-ns"},
            )
            assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_delete_namespace(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_api.delete_namespace.return_value = MagicMock()
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="delete-namespace",
            target="prod/old-ns",
            params={"namespace": "old-ns"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        mock_api.delete_namespace.assert_called_once()

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_rollout_undo(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "api"
        mock_api.patch_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="rollout-undo",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_get_secret(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "db-creds"
        mock_api.read_namespaced_secret.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="get-secret",
            target="dev/db-creds",
            params={"namespace": "dev", "secret": "db-creds"},
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_update_configmap(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "app-config"
        mock_api.patch_namespaced_config_map.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="update-configmap",
            target="dev/app-config",
            params={"namespace": "dev", "configmap": "app-config", "data": {"key": "val"}},
        )
        assert result.status == ExecutionStatus.SUCCESS
        mock_api.patch_namespaced_config_map.assert_called_once()

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_update_hpa_limits(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "web-hpa"
        mock_api.patch_namespaced_horizontal_pod_autoscaler.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="update-hpa-limits",
            target="dev/web-hpa",
            params={
                "namespace": "dev",
                "hpa": "web-hpa",
                "patch_json": '{"spec":{"maxReplicas":20}}',
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_apply_network_policy(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "deny-all"
        mock_api.create_namespaced_network_policy.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="apply-network-policy",
            target="dev/deny-all",
            params={"namespace": "dev", "policy": '{"kind":"NetworkPolicy"}'},
        )
        assert result.status == ExecutionStatus.SUCCESS
        mock_api.create_namespaced_network_policy.assert_called_once()

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_execute_scale_hpa(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.metadata.name = "web-hpa"
        mock_api.patch_namespaced_horizontal_pod_autoscaler.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="scale-hpa",
            target="dev/web-hpa",
            params={"namespace": "dev", "hpa": "web-hpa", "min_replicas": 2, "max_replicas": 10},
        )
        assert result.status == ExecutionStatus.SUCCESS


# --- K8sExecutor State Tests ---


class TestK8sExecutorState:
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_get_state_success(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"spec": {"replicas": 3}}
        mock_api.read_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        state = executor.get_state(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert state == {"spec": {"replicas": 3}}

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_get_state_not_found(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_api.read_namespaced_deployment.side_effect = Exception("Not found")
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        state = executor.get_state(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert state == {}

    def test_get_state_unmapped_action(self) -> None:
        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        state = executor.get_state("exec-pod", "dev/pod", {})
        assert state == {}

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_get_state_dict_result(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        # Object without to_dict returns a plain dict
        mock_api.read_namespaced_deployment.return_value = {"kind": "Deployment"}
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        state = executor.get_state(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
        )
        assert state == {"kind": "Deployment"}

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_get_state_node(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"spec": {"unschedulable": False}}
        mock_api.read_node.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        state = executor.get_state(
            action="cordon-node",
            target="prod/node-1",
            params={"node": "node-1"},
        )
        assert state["spec"]["unschedulable"] is False

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_get_state_configmap(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"data": {"key": "value"}}
        mock_api.read_namespaced_config_map.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        state = executor.get_state(
            action="get-configmap",
            target="dev/myconfig",
            params={"namespace": "dev", "configmap": "myconfig"},
        )
        assert state["data"]["key"] == "value"

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_get_state_hpa(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "spec": {"minReplicas": 1, "maxReplicas": 10},
        }
        mock_api.read_namespaced_horizontal_pod_autoscaler.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        state = executor.get_state(
            action="scale-hpa",
            target="dev/web-hpa",
            params={"namespace": "dev", "hpa": "web-hpa"},
        )
        assert state["spec"]["maxReplicas"] == 10


# --- K8sExecutor Prechecks Tests ---


class TestK8sExecutorPrechecks:
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_prechecks_pass_when_state_exists(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"spec": {}}
        mock_api.read_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        results = executor.run_prechecks(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            prechecks=[Precheck(name="check-exists", description="Verify")],
        )
        assert len(results) == 1
        assert results[0].passed is True

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_prechecks_fail_when_state_empty(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_api.read_namespaced_deployment.side_effect = Exception("Not found")
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        results = executor.run_prechecks(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            prechecks=[Precheck(name="check-exists", description="Verify")],
        )
        assert len(results) == 1
        assert results[0].passed is False

    def test_prechecks_empty_list(self) -> None:
        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        results = executor.run_prechecks(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            prechecks=[],
        )
        assert results == []

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_prechecks_multiple(
        self, mock_get_api: MagicMock, mock_get_client: MagicMock,
    ) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"spec": {"replicas": 3}}
        mock_api.read_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api
        mock_get_client.return_value = MagicMock()

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        results = executor.run_prechecks(
            action="restart-deployment",
            target="dev/api",
            params={"namespace": "dev", "deployment": "api"},
            prechecks=[
                Precheck(name="check-1", description="Check 1"),
                Precheck(name="check-2", description="Check 2"),
            ],
        )
        assert len(results) == 2
        assert all(r.passed for r in results)


# --- K8sExecutor Credentials Tests ---


class TestK8sExecutorCredentials:
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    def test_credential_with_token(self, mock_get_api: MagicMock) -> None:
        mock_api = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"spec": {}}
        mock_api.read_namespaced_deployment.return_value = mock_result
        mock_get_api.return_value = mock_api

        with _mock_kubernetes_modules() as (mock_client, _mock_config):
            executor = K8sExecutor.__new__(K8sExecutor)
            executor._kubeconfig = None
            executor._context = None
            executor._in_cluster = False

            cred = _make_credential({"token": "bearer-xyz", "host": "https://k8s.local"})
            state = executor.get_state(
                action="restart-deployment",
                target="dev/api",
                params={"namespace": "dev", "deployment": "api"},
                credential=cred,
            )
            # Should not raise
            assert isinstance(state, dict)

    def test_credential_with_kubeconfig_path(self) -> None:
        with _mock_kubernetes_modules() as (_mock_client, mock_config):
            executor = K8sExecutor.__new__(K8sExecutor)
            executor._kubeconfig = None
            executor._context = "my-ctx"
            executor._in_cluster = False

            cred = _make_credential({"kubeconfig": "/tmp/kc.yaml"})
            executor._get_api_client(cred)
            mock_config.load_kube_config.assert_called_once_with(
                config_file="/tmp/kc.yaml",
                context="my-ctx",
            )

    def test_constructor_in_cluster(self) -> None:
        with _mock_kubernetes_modules() as (_mock_client, mock_config):
            executor = K8sExecutor.__new__(K8sExecutor)
            executor._kubeconfig = None
            executor._context = None
            executor._in_cluster = True

            executor._get_api_client(None)
            mock_config.load_incluster_config.assert_called_once()

    def test_constructor_kubeconfig(self) -> None:
        with _mock_kubernetes_modules() as (_mock_client, mock_config):
            executor = K8sExecutor.__new__(K8sExecutor)
            executor._kubeconfig = "/home/.kube/config"
            executor._context = "staging"
            executor._in_cluster = False

            executor._get_api_client(None)
            mock_config.load_kube_config.assert_called_once_with(
                config_file="/home/.kube/config",
                context="staging",
            )

    def test_credential_in_cluster_payload(self) -> None:
        with _mock_kubernetes_modules() as (_mock_client, mock_config):
            executor = K8sExecutor.__new__(K8sExecutor)
            executor._kubeconfig = None
            executor._context = None
            executor._in_cluster = False

            cred = _make_credential({"in_cluster": True})
            executor._get_api_client(cred)
            mock_config.load_incluster_config.assert_called_once()


# --- K8sExecutor Protocol Tests ---


class TestK8sExecutorProtocol:
    def test_satisfies_executor_protocol(self) -> None:
        # K8sExecutor has execute, get_state, run_prechecks
        assert hasattr(K8sExecutor, "execute")
        assert hasattr(K8sExecutor, "get_state")
        assert hasattr(K8sExecutor, "run_prechecks")

    def test_executor_type_is_k8s(self) -> None:
        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="exec-pod",
            target="dev/pod",
            params={},
        )
        assert result.executor_type == "k8s"


# --- K8sExecutor Body Builder Tests ---


class TestK8sBodyBuilders:
    def _executor(self) -> K8sExecutor:
        e = K8sExecutor.__new__(K8sExecutor)
        e._kubeconfig = None
        e._context = None
        e._in_cluster = False
        return e

    def test_build_restart_body(self) -> None:
        body = self._executor()._build_restart_body({})
        assert "agent-safe/restartedAt" in body["spec"]["template"]["metadata"]["annotations"]

    def test_build_scale_body(self) -> None:
        body = self._executor()._build_scale_body({"replicas": 5})
        assert body["spec"]["replicas"] == 5

    def test_build_cordon_body(self) -> None:
        body = self._executor()._build_cordon_body({})
        assert body["spec"]["unschedulable"] is True

    def test_build_uncordon_body(self) -> None:
        body = self._executor()._build_uncordon_body({})
        assert body["spec"]["unschedulable"] is False

    def test_build_image_patch(self) -> None:
        body = self._executor()._build_image_patch({
            "container": "web",
            "image": "nginx:1.25",
        })
        containers = body["spec"]["template"]["spec"]["containers"]
        assert containers[0]["name"] == "web"
        assert containers[0]["image"] == "nginx:1.25"

    def test_build_configmap_patch(self) -> None:
        body = self._executor()._build_configmap_patch({"data": {"k": "v"}})
        assert body["data"]["k"] == "v"

    def test_build_configmap_patch_json_string(self) -> None:
        body = self._executor()._build_configmap_patch({"data": '{"k":"v"}'})
        assert body["data"]["k"] == "v"

    def test_build_hpa_scale_body(self) -> None:
        body = self._executor()._build_hpa_scale_body({
            "min_replicas": 2,
            "max_replicas": 10,
        })
        assert body["spec"]["minReplicas"] == 2
        assert body["spec"]["maxReplicas"] == 10

    def test_build_hpa_patch_json_string(self) -> None:
        body = self._executor()._build_hpa_patch({"patch_json": '{"spec":{"maxReplicas":20}}'})
        assert body["spec"]["maxReplicas"] == 20

    def test_build_rollback_body_with_revision(self) -> None:
        body = self._executor()._build_rollback_body({"revision": 3})
        assert body["metadata"]["annotations"]["deployment.kubernetes.io/revision"] == "3"

    def test_build_rollback_body_without_revision(self) -> None:
        body = self._executor()._build_rollback_body({})
        assert "agent-safe/rollbackAt" in body["spec"]["template"]["metadata"]["annotations"]


# --- K8sExecutor Drain Tests ---


class TestK8sExecutorDrain:
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._build_eviction_body")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    def test_drain_node_success(
        self, mock_get_client: MagicMock, mock_get_api: MagicMock,
        mock_build_eviction: MagicMock,
    ) -> None:
        mock_core = MagicMock()
        mock_get_api.return_value = mock_core
        mock_get_client.return_value = MagicMock()
        mock_build_eviction.return_value = MagicMock()

        # Mock list_pod_for_all_namespaces
        mock_pod = MagicMock()
        mock_pod.metadata.name = "pod-1"
        mock_pod.metadata.namespace = "default"
        mock_pod.metadata.owner_references = []
        mock_core.list_pod_for_all_namespaces.return_value = MagicMock(items=[mock_pod])

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="drain-node",
            target="prod/node-1",
            params={"node": "node-1"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert "drained" in result.output
        assert "1 pods evicted" in result.output

    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_instance")
    @patch("agent_safe.runner.k8s_executor.K8sExecutor._get_api_client")
    def test_drain_skips_daemonset_pods(
        self, mock_get_client: MagicMock, mock_get_api: MagicMock,
    ) -> None:
        mock_core = MagicMock()
        mock_get_api.return_value = mock_core
        mock_get_client.return_value = MagicMock()

        # Mock DaemonSet pod
        mock_ds_ref = MagicMock()
        mock_ds_ref.kind = "DaemonSet"
        mock_pod = MagicMock()
        mock_pod.metadata.name = "ds-pod"
        mock_pod.metadata.namespace = "kube-system"
        mock_pod.metadata.owner_references = [mock_ds_ref]
        mock_core.list_pod_for_all_namespaces.return_value = MagicMock(items=[mock_pod])

        executor = K8sExecutor.__new__(K8sExecutor)
        executor._kubeconfig = None
        executor._context = None
        executor._in_cluster = False

        result = executor.execute(
            action="drain-node",
            target="prod/node-1",
            params={"node": "node-1"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert "0 pods evicted" in result.output
