"""K8sExecutor — executes actions via the kubernetes Python client.

Uses the official ``kubernetes`` Python client library instead of kubectl
subprocess calls.  Supports kubeconfig file, in-cluster config, or
bearer token from credential payload.

Requires: ``pip install agent-safe[k8s]``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from agent_safe.models import (
    Credential,
    ExecutionResult,
    ExecutionStatus,
    Precheck,
    PreCheckResult,
)


def _check_kubernetes_available() -> None:
    """Raise ImportError with helpful message if kubernetes is not installed."""
    try:
        import kubernetes  # noqa: F401
    except ImportError:
        raise ImportError(
            "The 'kubernetes' package is required for K8sExecutor. "
            "Install it with: pip install agent-safe[k8s]"
        ) from None


@dataclass
class K8sActionMapping:
    """Maps an action name to a kubernetes client API call."""

    api_class: str
    execute_method: str
    state_method: str
    namespaced: bool = True
    param_map: dict[str, str] = field(default_factory=dict)
    body_builder: str = ""


K8S_ACTION_MAP: dict[str, K8sActionMapping] = {
    "restart-deployment": K8sActionMapping(
        api_class="AppsV1Api",
        execute_method="patch_namespaced_deployment",
        state_method="read_namespaced_deployment",
        param_map={"deployment": "name", "namespace": "namespace"},
        body_builder="_build_restart_body",
    ),
    "scale-deployment": K8sActionMapping(
        api_class="AppsV1Api",
        execute_method="patch_namespaced_deployment_scale",
        state_method="read_namespaced_deployment",
        param_map={"deployment": "name", "namespace": "namespace"},
        body_builder="_build_scale_body",
    ),
    "delete-pod": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="delete_namespaced_pod",
        state_method="read_namespaced_pod",
        param_map={"pod": "name", "namespace": "namespace"},
    ),
    "delete-namespace": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="delete_namespace",
        state_method="read_namespace",
        namespaced=False,
        param_map={"namespace": "name"},
    ),
    "create-namespace": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="create_namespace",
        state_method="read_namespace",
        namespaced=False,
        param_map={"namespace": "name"},
        body_builder="_build_namespace_body",
    ),
    "cordon-node": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="patch_node",
        state_method="read_node",
        namespaced=False,
        param_map={"node": "name"},
        body_builder="_build_cordon_body",
    ),
    "uncordon-node": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="patch_node",
        state_method="read_node",
        namespaced=False,
        param_map={"node": "name"},
        body_builder="_build_uncordon_body",
    ),
    "drain-node": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="_execute_drain",
        state_method="read_node",
        namespaced=False,
        param_map={"node": "name"},
    ),
    "rollout-undo": K8sActionMapping(
        api_class="AppsV1Api",
        execute_method="patch_namespaced_deployment",
        state_method="read_namespaced_deployment",
        param_map={"deployment": "name", "namespace": "namespace"},
        body_builder="_build_rollback_body",
    ),
    "rollout-status": K8sActionMapping(
        api_class="AppsV1Api",
        execute_method="read_namespaced_deployment",
        state_method="read_namespaced_deployment",
        param_map={"deployment": "name", "namespace": "namespace"},
    ),
    "get-pod-logs": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="read_namespaced_pod_log",
        state_method="read_namespaced_pod",
        param_map={"pod": "name", "namespace": "namespace"},
    ),
    "get-configmap": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="read_namespaced_config_map",
        state_method="read_namespaced_config_map",
        param_map={"configmap": "name", "namespace": "namespace"},
    ),
    "get-secret": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="read_namespaced_secret",
        state_method="read_namespaced_secret",
        param_map={"secret": "name", "namespace": "namespace"},
    ),
    "update-configmap": K8sActionMapping(
        api_class="CoreV1Api",
        execute_method="patch_namespaced_config_map",
        state_method="read_namespaced_config_map",
        param_map={"configmap": "name", "namespace": "namespace"},
        body_builder="_build_configmap_patch",
    ),
    "update-image": K8sActionMapping(
        api_class="AppsV1Api",
        execute_method="patch_namespaced_deployment",
        state_method="read_namespaced_deployment",
        param_map={"deployment": "name", "namespace": "namespace"},
        body_builder="_build_image_patch",
    ),
    "scale-hpa": K8sActionMapping(
        api_class="AutoscalingV1Api",
        execute_method="patch_namespaced_horizontal_pod_autoscaler",
        state_method="read_namespaced_horizontal_pod_autoscaler",
        param_map={"hpa": "name", "namespace": "namespace"},
        body_builder="_build_hpa_scale_body",
    ),
    "update-hpa-limits": K8sActionMapping(
        api_class="AutoscalingV1Api",
        execute_method="patch_namespaced_horizontal_pod_autoscaler",
        state_method="read_namespaced_horizontal_pod_autoscaler",
        param_map={"hpa": "name", "namespace": "namespace"},
        body_builder="_build_hpa_patch",
    ),
    "apply-network-policy": K8sActionMapping(
        api_class="NetworkingV1Api",
        execute_method="create_namespaced_network_policy",
        state_method="read_namespaced_network_policy",
        param_map={"policy": "name", "namespace": "namespace"},
        body_builder="_build_network_policy_body",
    ),
}


class K8sExecutor:
    """Executor that uses the kubernetes Python client.

    Requires: ``pip install agent-safe[k8s]``

    Credential handling:
    - If ``credential.payload`` has ``"kubeconfig"``, loads that kubeconfig
    - If ``credential.payload`` has ``"token"``, uses bearer token auth
    - If ``credential.payload`` has ``"in_cluster": True``, uses in-cluster config
    - Otherwise falls back to constructor arguments or default kubeconfig
    """

    def __init__(
        self,
        kubeconfig: str | None = None,
        context: str | None = None,
        in_cluster: bool = False,
    ) -> None:
        _check_kubernetes_available()
        self._kubeconfig = kubeconfig
        self._context = context
        self._in_cluster = in_cluster

    def execute(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
        timeout: float | None = None,
    ) -> ExecutionResult:
        mapping = K8S_ACTION_MAP.get(action)
        if mapping is None:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=action,
                target=target,
                caller="",
                audit_id="",
                error=f"No K8s API mapping for action: {action}",
                executor_type="k8s",
            )

        # Special case: drain-node is multi-step
        if action == "drain-node":
            return self._execute_drain(params, action, target, credential)

        try:
            api_client = self._get_api_client(credential)
            api = self._get_api_instance(mapping.api_class, api_client)
            method = getattr(api, mapping.execute_method)

            kwargs = self._build_kwargs(mapping, params)
            if mapping.body_builder:
                body = getattr(self, mapping.body_builder)(params)
                kwargs["body"] = body

            result = method(**kwargs)
            output = self._summarize(result, action)

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                action=action,
                target=target,
                caller="",
                audit_id="",
                output=output,
                executed_at=datetime.now(tz=UTC),
                executor_type="k8s",
            )
        except Exception as exc:
            # Detect kubernetes ApiException by class name to avoid import
            if type(exc).__name__ == "ApiException":
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    action=action,
                    target=target,
                    caller="",
                    audit_id="",
                    error=f"K8s API error ({exc.status}): {exc.reason}",
                    executed_at=datetime.now(tz=UTC),
                    executor_type="k8s",
                )
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=action,
                target=target,
                caller="",
                audit_id="",
                error=f"K8s executor error: {exc}",
                executed_at=datetime.now(tz=UTC),
                executor_type="k8s",
            )

    def get_state(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
    ) -> dict[str, Any]:
        mapping = K8S_ACTION_MAP.get(action)
        if mapping is None:
            return {}

        try:
            api_client = self._get_api_client(credential)
            api = self._get_api_instance(mapping.api_class, api_client)
            method = getattr(api, mapping.state_method)

            kwargs = self._build_state_kwargs(mapping, params)
            result = method(**kwargs)
            return self._to_dict(result)
        except Exception:
            return {}

    def run_prechecks(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        prechecks: list[Precheck],
        credential: Credential | None = None,
    ) -> list[PreCheckResult]:
        results: list[PreCheckResult] = []
        for pc in prechecks:
            state = self.get_state(action, target, params, credential)
            passed = bool(state)
            results.append(PreCheckResult(
                name=pc.name,
                passed=passed,
                message="" if passed else f"Resource state unavailable for {pc.name}",
            ))
        return results

    # --- Private: client setup ---

    def _get_api_client(self, credential: Credential | None = None) -> Any:
        """Build a kubernetes ApiClient from credential or constructor config."""
        from kubernetes import client, config

        if credential is not None:
            payload = credential.payload
            if "kubeconfig" in payload:
                config.load_kube_config(
                    config_file=payload["kubeconfig"],
                    context=self._context,
                )
                return client.ApiClient()
            if "token" in payload:
                configuration = client.Configuration()
                configuration.api_key["authorization"] = payload["token"]
                configuration.api_key_prefix["authorization"] = "Bearer"
                if "host" in payload:
                    configuration.host = payload["host"]
                if payload.get("verify_ssl") is False:
                    configuration.verify_ssl = False
                return client.ApiClient(configuration)
            if payload.get("in_cluster"):
                config.load_incluster_config()
                return client.ApiClient()

        if self._in_cluster:
            config.load_incluster_config()
        else:
            kwargs: dict[str, Any] = {}
            if self._kubeconfig:
                kwargs["config_file"] = self._kubeconfig
            if self._context:
                kwargs["context"] = self._context
            config.load_kube_config(**kwargs)
        return client.ApiClient()

    def _get_api_instance(self, api_class_name: str, api_client: Any) -> Any:
        """Instantiate the appropriate API class."""
        from kubernetes import client

        api_cls = getattr(client, api_class_name)
        return api_cls(api_client)

    # --- Private: argument building ---

    def _build_kwargs(
        self, mapping: K8sActionMapping, params: dict[str, Any],
    ) -> dict[str, Any]:
        """Build API call kwargs from param_map."""
        kwargs: dict[str, Any] = {}
        for action_param, api_kwarg in mapping.param_map.items():
            if action_param in params:
                kwargs[api_kwarg] = params[action_param]
        return kwargs

    def _build_state_kwargs(
        self, mapping: K8sActionMapping, params: dict[str, Any],
    ) -> dict[str, Any]:
        """Build state retrieval kwargs (same as execute kwargs minus body)."""
        return self._build_kwargs(mapping, params)

    # --- Private: body builders ---

    def _build_restart_body(self, params: dict[str, Any]) -> dict:
        return {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "agent-safe/restartedAt": datetime.now(tz=UTC).isoformat()
                        }
                    }
                }
            }
        }

    def _build_scale_body(self, params: dict[str, Any]) -> dict:
        return {"spec": {"replicas": int(params["replicas"])}}

    def _build_namespace_body(self, params: dict[str, Any]) -> Any:
        from kubernetes import client

        return client.V1Namespace(
            metadata=client.V1ObjectMeta(name=params["namespace"]),
        )

    def _build_cordon_body(self, params: dict[str, Any]) -> dict:
        return {"spec": {"unschedulable": True}}

    def _build_uncordon_body(self, params: dict[str, Any]) -> dict:
        return {"spec": {"unschedulable": False}}

    def _build_rollback_body(self, params: dict[str, Any]) -> dict:
        revision = params.get("revision")
        if revision:
            return {
                "metadata": {
                    "annotations": {
                        "deployment.kubernetes.io/revision": str(revision)
                    }
                }
            }
        return {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "agent-safe/rollbackAt": datetime.now(tz=UTC).isoformat()
                        }
                    }
                }
            }
        }

    def _build_configmap_patch(self, params: dict[str, Any]) -> dict:
        data = params.get("data", {})
        if isinstance(data, str):
            data = json.loads(data)
        return {"data": data}

    def _build_image_patch(self, params: dict[str, Any]) -> dict:
        container = params["container"]
        image = params["image"]
        return {
            "spec": {
                "template": {
                    "spec": {
                        "containers": [{"name": container, "image": image}]
                    }
                }
            }
        }

    def _build_hpa_scale_body(self, params: dict[str, Any]) -> dict:
        body: dict[str, Any] = {"spec": {}}
        if "min_replicas" in params:
            body["spec"]["minReplicas"] = int(params["min_replicas"])
        if "max_replicas" in params:
            body["spec"]["maxReplicas"] = int(params["max_replicas"])
        return body

    def _build_hpa_patch(self, params: dict[str, Any]) -> dict:
        patch_json = params.get("patch_json", "{}")
        if isinstance(patch_json, str):
            return json.loads(patch_json)
        return patch_json

    def _build_network_policy_body(self, params: dict[str, Any]) -> dict:
        policy = params.get("policy", "{}")
        if isinstance(policy, str):
            return json.loads(policy)
        return policy

    def _build_eviction_body(self, name: str, namespace: str) -> Any:
        """Build a V1Eviction body for pod eviction."""
        from kubernetes import client

        return client.V1Eviction(
            metadata=client.V1ObjectMeta(name=name, namespace=namespace),
        )

    # --- Private: drain (multi-step) ---

    def _execute_drain(
        self,
        params: dict[str, Any],
        action: str,
        target: str,
        credential: Credential | None,
    ) -> ExecutionResult:
        """Drain a node: cordon, then evict all non-DaemonSet pods."""
        try:
            api_client = self._get_api_client(credential)
            core = self._get_api_instance("CoreV1Api", api_client)
            node_name = params["node"]

            # Step 1: Cordon the node
            core.patch_node(name=node_name, body={"spec": {"unschedulable": True}})

            # Step 2: List pods on the node
            pods = core.list_pod_for_all_namespaces(
                field_selector=f"spec.nodeName={node_name}",
            )

            # Step 3: Evict non-DaemonSet pods
            evicted = 0
            for pod in pods.items:
                owner_refs = pod.metadata.owner_references or []
                is_daemonset = any(ref.kind == "DaemonSet" for ref in owner_refs)
                if is_daemonset:
                    continue

                eviction_body = self._build_eviction_body(
                    pod.metadata.name, pod.metadata.namespace,
                )
                try:
                    core.create_namespaced_pod_eviction(
                        name=pod.metadata.name,
                        namespace=pod.metadata.namespace,
                        body=eviction_body,
                    )
                    evicted += 1
                except Exception:
                    pass  # Best-effort eviction

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                action=action,
                target=target,
                caller="",
                audit_id="",
                output=f"Node {node_name} drained ({evicted} pods evicted)",
                executed_at=datetime.now(tz=UTC),
                executor_type="k8s",
            )
        except Exception as exc:
            if type(exc).__name__ == "ApiException":
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    action=action,
                    target=target,
                    caller="",
                    audit_id="",
                    error=f"K8s API error ({exc.status}): {exc.reason}",
                    executed_at=datetime.now(tz=UTC),
                    executor_type="k8s",
                )
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=action,
                target=target,
                caller="",
                audit_id="",
                error=f"Drain error: {exc}",
                executed_at=datetime.now(tz=UTC),
                executor_type="k8s",
            )

    # --- Private: helpers ---

    def _to_dict(self, k8s_object: Any) -> dict[str, Any]:
        """Convert a kubernetes client object to a plain dict."""
        if hasattr(k8s_object, "to_dict"):
            return k8s_object.to_dict()
        if isinstance(k8s_object, dict):
            return k8s_object
        return {}

    def _summarize(self, result: Any, action: str) -> str:
        """Produce a human-readable summary of the API result."""
        if isinstance(result, str):
            return result.strip()
        if hasattr(result, "metadata") and hasattr(result.metadata, "name"):
            return f"{action}: {result.metadata.name}"
        return f"{action} completed"
