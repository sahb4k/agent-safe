"""SubprocessExecutor — runs kubectl commands via subprocess.

Maps action names to kubectl command templates and executes them
via ``subprocess.run``.  Credential payloads containing a
``kubeconfig`` key are written to a temp file and passed via the
``KUBECONFIG`` environment variable.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
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


@dataclass
class KubectlTemplate:
    """Maps an action to a kubectl command."""

    verb: str
    resource: str
    namespace_param: str = ""
    extra_args: list[str] = field(default_factory=list)
    get_resource: str = ""
    get_output: str = "json"


KUBECTL_COMMANDS: dict[str, KubectlTemplate] = {
    "restart-deployment": KubectlTemplate(
        verb="rollout restart",
        resource="deployment/{deployment}",
        namespace_param="namespace",
        get_resource="deployment/{deployment}",
    ),
    "scale-deployment": KubectlTemplate(
        verb="scale",
        resource="deployment/{deployment}",
        namespace_param="namespace",
        extra_args=["--replicas={replicas}"],
        get_resource="deployment/{deployment}",
    ),
    "delete-pod": KubectlTemplate(
        verb="delete",
        resource="pod/{pod}",
        namespace_param="namespace",
    ),
    "delete-namespace": KubectlTemplate(
        verb="delete",
        resource="namespace/{namespace}",
    ),
    "create-namespace": KubectlTemplate(
        verb="create",
        resource="namespace/{namespace}",
    ),
    "cordon-node": KubectlTemplate(
        verb="cordon",
        resource="{node}",
        get_resource="node/{node}",
    ),
    "uncordon-node": KubectlTemplate(
        verb="uncordon",
        resource="{node}",
        get_resource="node/{node}",
    ),
    "drain-node": KubectlTemplate(
        verb="drain",
        resource="{node}",
        extra_args=["--ignore-daemonsets", "--delete-emptydir-data"],
        get_resource="node/{node}",
    ),
    "rollout-undo": KubectlTemplate(
        verb="rollout undo",
        resource="deployment/{deployment}",
        namespace_param="namespace",
        get_resource="deployment/{deployment}",
    ),
    "rollout-status": KubectlTemplate(
        verb="rollout status",
        resource="deployment/{deployment}",
        namespace_param="namespace",
        get_resource="deployment/{deployment}",
    ),
    "get-pod-logs": KubectlTemplate(
        verb="logs",
        resource="{pod}",
        namespace_param="namespace",
    ),
    "get-configmap": KubectlTemplate(
        verb="get",
        resource="configmap/{configmap}",
        namespace_param="namespace",
        get_resource="configmap/{configmap}",
    ),
    "get-secret": KubectlTemplate(
        verb="get",
        resource="secret/{secret}",
        namespace_param="namespace",
        get_resource="secret/{secret}",
    ),
    "update-image": KubectlTemplate(
        verb="set image",
        resource="deployment/{deployment}",
        namespace_param="namespace",
        extra_args=["{container}={image}"],
        get_resource="deployment/{deployment}",
    ),
    "scale-hpa": KubectlTemplate(
        verb="patch",
        resource="hpa/{hpa}",
        namespace_param="namespace",
        extra_args=[
            "--type=merge",
            '-p={{"spec":{{"minReplicas":{min_replicas},"maxReplicas":{max_replicas}}}}}',
        ],
        get_resource="hpa/{hpa}",
    ),
    "update-hpa-limits": KubectlTemplate(
        verb="patch",
        resource="hpa/{hpa}",
        namespace_param="namespace",
        extra_args=["--type=merge", "-p={patch_json}"],
        get_resource="hpa/{hpa}",
    ),
    "apply-network-policy": KubectlTemplate(
        verb="apply",
        resource="-f {policy_file}",
        namespace_param="namespace",
    ),
}


def build_kubectl_args(
    template: KubectlTemplate,
    params: dict[str, Any],
    kubectl_path: str = "kubectl",
    kubeconfig: str | None = None,
    context: str | None = None,
) -> list[str]:
    """Build a kubectl command line from a template and params."""
    args: list[str] = [kubectl_path]

    if kubeconfig:
        args.extend(["--kubeconfig", kubeconfig])
    if context:
        args.extend(["--context", context])

    # Verb may be multi-word (e.g., "rollout restart")
    args.extend(template.verb.split())

    # Resource with param substitution
    resource = template.resource.format(**params)
    args.extend(resource.split())

    # Namespace
    if template.namespace_param and template.namespace_param in params:
        args.extend(["-n", str(params[template.namespace_param])])

    # Extra args
    for arg in template.extra_args:
        args.append(arg.format(**params))

    return args


class SubprocessExecutor:
    """Executor that runs kubectl commands via subprocess.

    Maps action names to kubectl command templates. Actions without
    a mapping raise an error.
    """

    def __init__(
        self,
        kubectl_path: str = "kubectl",
        kubeconfig: str | None = None,
        context: str | None = None,
    ) -> None:
        self._kubectl_path = kubectl_path
        self._kubeconfig = kubeconfig
        self._context = context

    def execute(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
        timeout: float | None = None,
    ) -> ExecutionResult:
        template = KUBECTL_COMMANDS.get(action)
        if template is None:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=action,
                target=target,
                caller="",
                audit_id="",
                error=f"No kubectl mapping for action: {action}",
                executor_type="subprocess",
            )

        kubeconfig = self._resolve_kubeconfig(credential)
        args = build_kubectl_args(
            template, params,
            kubectl_path=self._kubectl_path,
            kubeconfig=kubeconfig,
            context=self._context,
        )

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self._build_env(kubeconfig),
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                status=ExecutionStatus.TIMEOUT,
                action=action,
                target=target,
                caller="",
                audit_id="",
                error=f"Command timed out after {timeout}s",
                executed_at=datetime.now(tz=UTC),
                executor_type="subprocess",
            )

        status = ExecutionStatus.SUCCESS if result.returncode == 0 else ExecutionStatus.FAILURE
        return ExecutionResult(
            status=status,
            action=action,
            target=target,
            caller="",
            audit_id="",
            output=result.stdout.strip(),
            error=result.stderr.strip() if result.returncode != 0 else None,
            executed_at=datetime.now(tz=UTC),
            executor_type="subprocess",
        )

    def get_state(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
    ) -> dict[str, Any]:
        template = KUBECTL_COMMANDS.get(action)
        if template is None or not template.get_resource:
            return {}

        resource = template.get_resource.format(**params)
        kubeconfig = self._resolve_kubeconfig(credential)

        args = [self._kubectl_path]
        if kubeconfig:
            args.extend(["--kubeconfig", kubeconfig])
        if self._context:
            args.extend(["--context", self._context])

        args.extend(["get", resource, "-o", template.get_output])

        if template.namespace_param and template.namespace_param in params:
            args.extend(["-n", str(params[template.namespace_param])])

        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, OSError):
            return {}

        if result.returncode != 0:
            return {}

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {"raw": result.stdout.strip()}

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
            # Default: check resource exists via get_state
            state = self.get_state(action, target, params, credential)
            passed = bool(state)
            results.append(PreCheckResult(
                name=pc.name,
                passed=passed,
                message="" if passed else f"Resource state unavailable for {pc.name}",
            ))
        return results

    def _resolve_kubeconfig(self, credential: Credential | None) -> str | None:
        """Get kubeconfig path from credential payload or constructor."""
        if credential is not None and "kubeconfig" in credential.payload:
            kc = credential.payload["kubeconfig"]
            if isinstance(kc, str) and os.path.exists(kc):
                return kc
            # Write to temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".kubeconfig", delete=False,
            ) as tmp:
                content = kc if isinstance(kc, str) else json.dumps(kc)
                tmp.write(content)
                return tmp.name
        return self._kubeconfig

    def _build_env(self, kubeconfig: str | None) -> dict[str, str] | None:
        """Build environment with KUBECONFIG if needed."""
        if kubeconfig is None:
            return None
        env = os.environ.copy()
        env["KUBECONFIG"] = kubeconfig
        return env
