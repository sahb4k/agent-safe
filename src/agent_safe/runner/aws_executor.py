"""AwsExecutor — executes actions via boto3.

Uses the AWS boto3 SDK to execute governed actions against AWS resources.
Supports credential payload (access key, secret, session token) or
falls back to boto3's default credential chain.

Requires: ``pip install agent-safe[aws]``
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


def _check_boto3_available() -> None:
    """Raise ImportError with helpful message if boto3 is not installed."""
    try:
        import boto3  # noqa: F401
    except ImportError:
        raise ImportError(
            "The 'boto3' package is required for AwsExecutor. "
            "Install it with: pip install agent-safe[aws]"
        ) from None


@dataclass
class AwsActionMapping:
    """Maps an action name to a boto3 API call."""

    service: str
    execute_method: str
    state_method: str
    param_map: dict[str, str] = field(default_factory=dict)
    request_builder: str = ""
    state_extractor: str = ""


AWS_ACTION_MAP: dict[str, AwsActionMapping] = {
    "ec2-stop-instance": AwsActionMapping(
        service="ec2",
        execute_method="stop_instances",
        state_method="describe_instances",
        request_builder="_build_ec2_instance_request",
        state_extractor="_extract_ec2_instance_state",
    ),
    "ec2-start-instance": AwsActionMapping(
        service="ec2",
        execute_method="start_instances",
        state_method="describe_instances",
        request_builder="_build_ec2_instance_request",
        state_extractor="_extract_ec2_instance_state",
    ),
    "ec2-reboot-instance": AwsActionMapping(
        service="ec2",
        execute_method="reboot_instances",
        state_method="describe_instances",
        request_builder="_build_ec2_instance_request",
        state_extractor="_extract_ec2_instance_state",
    ),
    "ec2-terminate-instance": AwsActionMapping(
        service="ec2",
        execute_method="terminate_instances",
        state_method="describe_instances",
        request_builder="_build_ec2_instance_request",
        state_extractor="_extract_ec2_instance_state",
    ),
    "ecs-update-service": AwsActionMapping(
        service="ecs",
        execute_method="update_service",
        state_method="describe_services",
        request_builder="_build_ecs_update_service_request",
        state_extractor="_extract_ecs_service_state",
    ),
    "ecs-stop-task": AwsActionMapping(
        service="ecs",
        execute_method="stop_task",
        state_method="describe_tasks",
        request_builder="_build_ecs_stop_task_request",
        state_extractor="_extract_ecs_task_state",
    ),
    "ecs-scale-service": AwsActionMapping(
        service="ecs",
        execute_method="update_service",
        state_method="describe_services",
        request_builder="_build_ecs_scale_service_request",
        state_extractor="_extract_ecs_service_state",
    ),
    "lambda-update-function-config": AwsActionMapping(
        service="lambda",
        execute_method="update_function_configuration",
        state_method="get_function_configuration",
        request_builder="_build_lambda_update_config_request",
        state_extractor="_extract_direct",
    ),
    "lambda-invoke-function": AwsActionMapping(
        service="lambda",
        execute_method="invoke",
        state_method="get_function",
        request_builder="_build_lambda_invoke_request",
        state_extractor="_extract_direct",
    ),
    "s3-delete-object": AwsActionMapping(
        service="s3",
        execute_method="delete_object",
        state_method="head_object",
        request_builder="_build_s3_object_request",
        state_extractor="_extract_direct",
    ),
    "s3-put-bucket-policy": AwsActionMapping(
        service="s3",
        execute_method="put_bucket_policy",
        state_method="get_bucket_policy",
        request_builder="_build_s3_put_policy_request",
        state_extractor="_extract_direct",
    ),
    "iam-attach-role-policy": AwsActionMapping(
        service="iam",
        execute_method="attach_role_policy",
        state_method="list_attached_role_policies",
        request_builder="_build_iam_attach_request",
        state_extractor="_extract_iam_policies",
    ),
    "iam-detach-role-policy": AwsActionMapping(
        service="iam",
        execute_method="detach_role_policy",
        state_method="list_attached_role_policies",
        request_builder="_build_iam_detach_request",
        state_extractor="_extract_iam_policies",
    ),
}


class AwsExecutor:
    """Executor that uses boto3 to call AWS APIs.

    Requires: ``pip install agent-safe[aws]``

    Credential handling:
    - If ``credential.payload`` has ``"access_key_id"`` and ``"secret_access_key"``,
      uses explicit credentials (optionally with ``"session_token"``)
    - If ``credential.payload`` has ``"profile_name"``, uses that AWS profile
    - Otherwise falls back to boto3's default credential chain
    """

    def __init__(
        self,
        region: str | None = None,
        profile: str | None = None,
        endpoint_url: str | None = None,
    ) -> None:
        _check_boto3_available()
        self._region = region
        self._profile = profile
        self._endpoint_url = endpoint_url

    def execute(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
        timeout: float | None = None,
    ) -> ExecutionResult:
        mapping = AWS_ACTION_MAP.get(action)
        if mapping is None:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=action,
                target=target,
                caller="",
                audit_id="",
                error=f"No AWS API mapping for action: {action}",
                executor_type="aws",
            )

        try:
            client = self._get_client(
                mapping.service, credential, params.get("region"),
            )
            method = getattr(client, mapping.execute_method)

            if mapping.request_builder:
                kwargs = getattr(self, mapping.request_builder)(params)
            else:
                kwargs = {}

            response = method(**kwargs)
            output = self._summarize_response(response, action)

            return ExecutionResult(
                status=ExecutionStatus.SUCCESS,
                action=action,
                target=target,
                caller="",
                audit_id="",
                output=output,
                executed_at=datetime.now(tz=UTC),
                executor_type="aws",
            )
        except Exception as exc:
            error_msg = str(exc)
            # Detect boto3 ClientError for proper failure status
            exc_type = type(exc).__name__
            if exc_type == "ClientError":
                return ExecutionResult(
                    status=ExecutionStatus.FAILURE,
                    action=action,
                    target=target,
                    caller="",
                    audit_id="",
                    error=f"AWS API error: {error_msg}",
                    executed_at=datetime.now(tz=UTC),
                    executor_type="aws",
                )
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=action,
                target=target,
                caller="",
                audit_id="",
                error=f"AWS executor error: {error_msg}",
                executed_at=datetime.now(tz=UTC),
                executor_type="aws",
            )

    def get_state(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
    ) -> dict[str, Any]:
        mapping = AWS_ACTION_MAP.get(action)
        if mapping is None:
            return {}

        try:
            client = self._get_client(
                mapping.service, credential, params.get("region"),
            )
            method = getattr(client, mapping.state_method)
            kwargs = self._build_state_kwargs(mapping, params)
            response = method(**kwargs)

            if mapping.state_extractor:
                return getattr(self, mapping.state_extractor)(response)
            return self._serialize_response(response)
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

    # --- Private: session/client setup ---

    def _get_boto3_session(
        self,
        credential: Credential | None = None,
        region: str | None = None,
    ) -> Any:
        """Build a boto3 Session from credential or constructor config."""
        import boto3

        kwargs: dict[str, Any] = {}

        if region or self._region:
            kwargs["region_name"] = region or self._region

        if credential is not None:
            payload = credential.payload
            if "access_key_id" in payload:
                kwargs["aws_access_key_id"] = payload["access_key_id"]
                kwargs["aws_secret_access_key"] = payload["secret_access_key"]
                if "session_token" in payload:
                    kwargs["aws_session_token"] = payload["session_token"]
                return boto3.Session(**kwargs)
            if "profile_name" in payload:
                kwargs["profile_name"] = payload["profile_name"]
                return boto3.Session(**kwargs)

        if self._profile:
            kwargs["profile_name"] = self._profile

        return boto3.Session(**kwargs)

    def _get_client(
        self,
        service: str,
        credential: Credential | None = None,
        region: str | None = None,
    ) -> Any:
        """Get a boto3 service client."""
        session = self._get_boto3_session(credential, region)
        kwargs: dict[str, Any] = {}
        if self._endpoint_url:
            kwargs["endpoint_url"] = self._endpoint_url
        return session.client(service, **kwargs)

    # --- Private: request builders ---

    def _build_ec2_instance_request(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"InstanceIds": [params["instance_id"]]}

    def _build_ecs_update_service_request(
        self, params: dict[str, Any],
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "cluster": params["cluster"],
            "service": params["service"],
        }
        if "desired_count" in params and params["desired_count"] is not None:
            kwargs["desiredCount"] = int(params["desired_count"])
        if params.get("force_new_deployment"):
            kwargs["forceNewDeployment"] = True
        return kwargs

    def _build_ecs_stop_task_request(self, params: dict[str, Any]) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "cluster": params["cluster"],
            "task": params["task"],
        }
        if "reason" in params and params["reason"]:
            kwargs["reason"] = params["reason"]
        return kwargs

    def _build_ecs_scale_service_request(
        self, params: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "cluster": params["cluster"],
            "service": params["service"],
            "desiredCount": int(params["desired_count"]),
        }

    def _build_lambda_update_config_request(
        self, params: dict[str, Any],
    ) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"FunctionName": params["function_name"]}
        if "memory_size" in params and params["memory_size"] is not None:
            kwargs["MemorySize"] = int(params["memory_size"])
        if "timeout" in params and params["timeout"] is not None:
            kwargs["Timeout"] = int(params["timeout"])
        if "environment_variables" in params and params["environment_variables"]:
            env_vars = params["environment_variables"]
            if isinstance(env_vars, str):
                env_vars = json.loads(env_vars)
            kwargs["Environment"] = {"Variables": env_vars}
        return kwargs

    def _build_lambda_invoke_request(self, params: dict[str, Any]) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"FunctionName": params["function_name"]}
        if "payload" in params and params["payload"]:
            kwargs["Payload"] = params["payload"]
        return kwargs

    def _build_s3_object_request(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"Bucket": params["bucket"], "Key": params["key"]}

    def _build_s3_put_policy_request(self, params: dict[str, Any]) -> dict[str, Any]:
        return {"Bucket": params["bucket"], "Policy": params["policy"]}

    def _build_iam_attach_request(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "RoleName": params["role_name"],
            "PolicyArn": params["policy_arn"],
        }

    def _build_iam_detach_request(self, params: dict[str, Any]) -> dict[str, Any]:
        return {
            "RoleName": params["role_name"],
            "PolicyArn": params["policy_arn"],
        }

    # --- Private: state kwargs builders ---

    def _build_state_kwargs(
        self, mapping: AwsActionMapping, params: dict[str, Any],
    ) -> dict[str, Any]:
        """Build kwargs for the state retrieval method."""
        service = mapping.service

        if service == "ec2":
            return {"InstanceIds": [params["instance_id"]]}
        if service == "ecs":
            if "task" in params:
                return {"cluster": params["cluster"], "tasks": [params["task"]]}
            return {"cluster": params["cluster"], "services": [params["service"]]}
        if service == "lambda":
            return {"FunctionName": params["function_name"]}
        if service == "s3":
            if mapping.state_method == "head_object":
                return {"Bucket": params["bucket"], "Key": params["key"]}
            return {"Bucket": params["bucket"]}
        if service == "iam":
            return {"RoleName": params["role_name"]}

        return {}

    # --- Private: state extractors ---

    def _extract_ec2_instance_state(self, response: dict) -> dict[str, Any]:
        try:
            instance = response["Reservations"][0]["Instances"][0]
            return self._serialize_response(instance)
        except (KeyError, IndexError):
            return {}

    def _extract_ecs_service_state(self, response: dict) -> dict[str, Any]:
        try:
            service = response["services"][0]
            return self._serialize_response(service)
        except (KeyError, IndexError):
            return {}

    def _extract_ecs_task_state(self, response: dict) -> dict[str, Any]:
        try:
            task = response["tasks"][0]
            return self._serialize_response(task)
        except (KeyError, IndexError):
            return {}

    def _extract_direct(self, response: dict) -> dict[str, Any]:
        return self._serialize_response(response)

    def _extract_iam_policies(self, response: dict) -> dict[str, Any]:
        try:
            policies = response["AttachedPolicies"]
            return {"attached_policies": policies}
        except KeyError:
            return {}

    # --- Private: serialization ---

    def _serialize_response(self, response: Any) -> dict[str, Any]:
        """Convert a boto3 response to a JSON-serializable dict."""
        if isinstance(response, dict):
            result: dict[str, Any] = {}
            for key, value in response.items():
                if key == "ResponseMetadata":
                    continue
                result[key] = self._serialize_value(value)
            return result
        return {}

    def _serialize_value(self, value: Any) -> Any:
        """Recursively serialize a value, converting datetimes to ISO strings."""
        if isinstance(value, datetime):
            return value.isoformat()
        if hasattr(value, "isoformat"):
            return value.isoformat()
        if isinstance(value, dict):
            return {k: self._serialize_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._serialize_value(v) for v in value]
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    def _summarize_response(self, response: Any, action: str) -> str:
        """Produce a human-readable summary of the API response."""
        if isinstance(response, dict):
            response = {
                k: v for k, v in response.items() if k != "ResponseMetadata"
            }
            try:
                return json.dumps(response, default=str, indent=None)[:500]
            except (TypeError, ValueError):
                pass
        return f"{action} completed"
