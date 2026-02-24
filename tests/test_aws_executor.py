"""Tests for AwsExecutor (v0.9.0).

All boto3 calls are mocked — no real AWS account needed.
"""

from __future__ import annotations

import sys
from contextlib import contextmanager
from datetime import UTC, datetime
from typing import Any
from unittest.mock import MagicMock, patch

from agent_safe.models import Credential, CredentialScope, ExecutionStatus, Precheck
from agent_safe.runner.aws_executor import AWS_ACTION_MAP, AwsActionMapping, AwsExecutor

# --- Helpers ---


@contextmanager
def _mock_boto3_modules():
    """Context manager that injects mock boto3 into sys.modules."""
    mock_boto3 = MagicMock()
    mock_session = MagicMock()
    mock_boto3.Session.return_value = mock_session

    modules = {
        "boto3": mock_boto3,
        "botocore": MagicMock(),
        "botocore.exceptions": MagicMock(),
    }
    with patch.dict(sys.modules, modules):
        yield mock_boto3


def _make_credential(
    payload: dict[str, Any] | None = None,
) -> Credential:
    return Credential(
        credential_id="cred-aws-test",
        type="aws",
        payload=payload or {
            "access_key_id": "AKIATEST",
            "secret_access_key": "secret123",
        },
        expires_at=datetime.now(tz=UTC),
        scope=CredentialScope(type="aws", fields={}),
        ticket_nonce="nonce-aws",
    )


def _mock_executor() -> AwsExecutor:
    """Create an AwsExecutor without triggering boto3 import check."""
    executor = AwsExecutor.__new__(AwsExecutor)
    executor._region = "us-east-1"
    executor._profile = None
    return executor


# --- AwsActionMapping Tests ---


class TestAwsActionMapping:
    def test_ec2_stop_instance_mapped(self) -> None:
        assert "ec2-stop-instance" in AWS_ACTION_MAP
        m = AWS_ACTION_MAP["ec2-stop-instance"]
        assert m.service == "ec2"
        assert m.execute_method == "stop_instances"

    def test_ec2_start_instance_mapped(self) -> None:
        m = AWS_ACTION_MAP["ec2-start-instance"]
        assert m.execute_method == "start_instances"

    def test_ec2_terminate_instance_mapped(self) -> None:
        m = AWS_ACTION_MAP["ec2-terminate-instance"]
        assert m.execute_method == "terminate_instances"

    def test_ecs_update_service_mapped(self) -> None:
        m = AWS_ACTION_MAP["ecs-update-service"]
        assert m.service == "ecs"
        assert m.execute_method == "update_service"

    def test_lambda_update_config_mapped(self) -> None:
        m = AWS_ACTION_MAP["lambda-update-function-config"]
        assert m.service == "lambda"

    def test_s3_delete_object_mapped(self) -> None:
        m = AWS_ACTION_MAP["s3-delete-object"]
        assert m.service == "s3"
        assert m.execute_method == "delete_object"

    def test_iam_attach_role_policy_mapped(self) -> None:
        m = AWS_ACTION_MAP["iam-attach-role-policy"]
        assert m.service == "iam"

    def test_all_12_actions_mapped(self) -> None:
        assert len(AWS_ACTION_MAP) == 12
        for name, mapping in AWS_ACTION_MAP.items():
            assert isinstance(mapping, AwsActionMapping), f"{name} is not AwsActionMapping"
            assert mapping.service, f"{name} missing service"
            assert mapping.execute_method, f"{name} missing execute_method"
            assert mapping.state_method, f"{name} missing state_method"


# --- AwsExecutor Execute Tests ---


class TestAwsExecutorExecute:
    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_ec2_stop_success(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.stop_instances.return_value = {
            "StoppingInstances": [
                {"InstanceId": "i-123", "CurrentState": {"Name": "stopping"}},
            ],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert result.executor_type == "aws"

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_ec2_start_success(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.start_instances.return_value = {
            "StartingInstances": [
                {"InstanceId": "i-123", "CurrentState": {"Name": "pending"}},
            ],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ec2-start-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_ecs_update_service(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.update_service.return_value = {
            "service": {"serviceName": "worker", "desiredCount": 5},
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ecs-update-service",
            target="staging/worker-service",
            params={
                "cluster": "staging",
                "service": "worker",
                "desired_count": 5,
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_ecs_stop_task(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.stop_task.return_value = {"task": {"taskArn": "arn:..."}}
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ecs-stop-task",
            target="staging/task",
            params={
                "cluster": "staging",
                "task": "task-123",
                "reason": "testing",
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_lambda_update_config(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.update_function_configuration.return_value = {
            "FunctionName": "my-func",
            "MemorySize": 512,
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="lambda-update-function-config",
            target="prod/my-func",
            params={
                "function_name": "my-func",
                "memory_size": 512,
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_lambda_invoke(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.invoke.return_value = {
            "StatusCode": 200,
            "Payload": b'{"result": "ok"}',
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="lambda-invoke-function",
            target="prod/my-func",
            params={
                "function_name": "my-func",
                "payload": '{"key": "value"}',
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_s3_delete_object(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.delete_object.return_value = {"DeleteMarker": True}
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="s3-delete-object",
            target="prod/audit-bucket",
            params={
                "bucket": "my-bucket",
                "key": "path/to/file.txt",
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_s3_put_bucket_policy(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.put_bucket_policy.return_value = {}
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="s3-put-bucket-policy",
            target="prod/audit-bucket",
            params={
                "bucket": "my-bucket",
                "policy": '{"Statement":[]}',
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_iam_attach_role_policy(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.attach_role_policy.return_value = {}
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="iam-attach-role-policy",
            target="prod/my-role",
            params={
                "role_name": "my-role",
                "policy_arn": "arn:aws:iam::123:policy/MyPolicy",
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_client_error(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        # Create a fake ClientError
        error_cls = type("ClientError", (Exception,), {})
        mock_client.stop_instances.side_effect = error_cls("Not authorized")
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        assert result.status == ExecutionStatus.FAILURE
        assert "Not authorized" in result.error

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_general_error(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.stop_instances.side_effect = ConnectionError("timeout")
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        assert result.status == ExecutionStatus.ERROR
        assert "timeout" in result.error

    def test_execute_unmapped_action(self) -> None:
        executor = _mock_executor()
        result = executor.execute(
            action="rds-reboot-instance",
            target="prod/db",
            params={},
        )
        assert result.status == ExecutionStatus.ERROR
        assert "No AWS API mapping" in result.error

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_ecs_scale_service(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.update_service.return_value = {
            "service": {"serviceName": "api", "desiredCount": 3},
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ecs-scale-service",
            target="staging/api",
            params={
                "cluster": "staging",
                "service": "api",
                "desired_count": 3,
                "region": "us-east-1",
            },
        )
        assert result.status == ExecutionStatus.SUCCESS

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_execute_ec2_reboot(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.reboot_instances.return_value = {}
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        result = executor.execute(
            action="ec2-reboot-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        assert result.status == ExecutionStatus.SUCCESS


# --- AwsExecutor State Tests ---


class TestAwsExecutorState:
    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_ec2_instance(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-123",
                    "State": {"Name": "running"},
                    "InstanceType": "t3.medium",
                }],
            }],
            "ResponseMetadata": {"RequestId": "abc"},
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        assert state["InstanceId"] == "i-123"
        assert state["State"]["Name"] == "running"

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_ecs_service(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_services.return_value = {
            "services": [{
                "serviceName": "worker",
                "desiredCount": 3,
                "runningCount": 3,
            }],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="ecs-update-service",
            target="staging/worker",
            params={"cluster": "staging", "service": "worker", "region": "us-east-1"},
        )
        assert state["serviceName"] == "worker"
        assert state["desiredCount"] == 3

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_ecs_task(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_tasks.return_value = {
            "tasks": [{"taskArn": "arn:...", "lastStatus": "RUNNING"}],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="ecs-stop-task",
            target="staging/task",
            params={"cluster": "staging", "task": "task-123", "region": "us-east-1"},
        )
        assert state["lastStatus"] == "RUNNING"

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_lambda_function(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_function_configuration.return_value = {
            "FunctionName": "my-func",
            "MemorySize": 256,
            "Timeout": 30,
            "Runtime": "python3.12",
            "ResponseMetadata": {},
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="lambda-update-function-config",
            target="prod/my-func",
            params={"function_name": "my-func", "region": "us-east-1"},
        )
        assert state["MemorySize"] == 256

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_s3_head_object(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.head_object.return_value = {
            "ContentLength": 1024,
            "ContentType": "text/plain",
            "ResponseMetadata": {},
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="s3-delete-object",
            target="prod/bucket",
            params={"bucket": "my-bucket", "key": "file.txt", "region": "us-east-1"},
        )
        assert state["ContentLength"] == 1024

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_iam_policies(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {"PolicyName": "ReadOnly", "PolicyArn": "arn:aws:iam::123:policy/ReadOnly"},
            ],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="iam-attach-role-policy",
            target="prod/my-role",
            params={"role_name": "my-role", "region": "us-east-1"},
        )
        assert len(state["attached_policies"]) == 1

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_error_returns_empty(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_instances.side_effect = Exception("Access denied")
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        assert state == {}

    def test_get_state_unmapped_action(self) -> None:
        executor = _mock_executor()
        state = executor.get_state("rds-reboot", "prod/db", {})
        assert state == {}

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_serializes_datetime(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {
            "Reservations": [{
                "Instances": [{
                    "InstanceId": "i-123",
                    "LaunchTime": datetime(2024, 1, 15, 12, 0, tzinfo=UTC),
                }],
            }],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
        )
        # datetime should be serialized to ISO string
        assert isinstance(state["LaunchTime"], str)
        assert "2024-01-15" in state["LaunchTime"]

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_get_state_s3_bucket_policy(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_bucket_policy.return_value = {
            "Policy": '{"Statement":[]}',
            "ResponseMetadata": {},
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        state = executor.get_state(
            action="s3-put-bucket-policy",
            target="prod/bucket",
            params={"bucket": "my-bucket", "region": "us-east-1"},
        )
        assert "Policy" in state


# --- AwsExecutor Prechecks Tests ---


class TestAwsExecutorPrechecks:
    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_prechecks_pass_when_state_exists(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-123"}]}],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        results = executor.run_prechecks(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
            prechecks=[Precheck(name="instance-exists", description="Verify")],
        )
        assert len(results) == 1
        assert results[0].passed is True

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_prechecks_fail_when_state_empty(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_instances.side_effect = Exception("Not found")
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        results = executor.run_prechecks(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
            prechecks=[Precheck(name="instance-exists", description="Verify")],
        )
        assert len(results) == 1
        assert results[0].passed is False

    def test_prechecks_empty_list(self) -> None:
        executor = _mock_executor()
        results = executor.run_prechecks(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
            prechecks=[],
        )
        assert results == []

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_prechecks_multiple(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-123"}]}],
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        results = executor.run_prechecks(
            action="ec2-stop-instance",
            target="prod/api-instance",
            params={"instance_id": "i-123", "region": "us-east-1"},
            prechecks=[
                Precheck(name="check-1", description="C1"),
                Precheck(name="check-2", description="C2"),
            ],
        )
        assert len(results) == 2
        assert all(r.passed for r in results)

    @patch("agent_safe.runner.aws_executor.AwsExecutor._get_client")
    def test_prechecks_lambda(self, mock_get_client: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_function_configuration.return_value = {
            "FunctionName": "my-func",
            "Runtime": "python3.12",
        }
        mock_get_client.return_value = mock_client

        executor = _mock_executor()
        results = executor.run_prechecks(
            action="lambda-update-function-config",
            target="prod/my-func",
            params={"function_name": "my-func", "region": "us-east-1"},
            prechecks=[Precheck(name="function-exists", description="Verify")],
        )
        assert results[0].passed is True


# --- AwsExecutor Credentials Tests ---


class TestAwsExecutorCredentials:
    def test_credential_with_access_key(self) -> None:
        with _mock_boto3_modules() as mock_boto3:
            mock_session = MagicMock()
            mock_session.client.return_value = MagicMock()
            mock_boto3.Session.return_value = mock_session

            executor = _mock_executor()
            cred = _make_credential({
                "access_key_id": "AKIA123",
                "secret_access_key": "secret",
            })
            executor._get_boto3_session(cred, "us-east-1")
            mock_boto3.Session.assert_called_once_with(
                region_name="us-east-1",
                aws_access_key_id="AKIA123",
                aws_secret_access_key="secret",
            )

    def test_credential_with_session_token(self) -> None:
        with _mock_boto3_modules() as mock_boto3:
            mock_boto3.Session.return_value = MagicMock()

            executor = _mock_executor()
            cred = _make_credential({
                "access_key_id": "AKIA123",
                "secret_access_key": "secret",
                "session_token": "FwoGZ...",
            })
            executor._get_boto3_session(cred, "us-east-1")
            call_kwargs = mock_boto3.Session.call_args[1]
            assert call_kwargs["aws_session_token"] == "FwoGZ..."

    def test_credential_with_profile(self) -> None:
        with _mock_boto3_modules() as mock_boto3:
            mock_boto3.Session.return_value = MagicMock()

            executor = _mock_executor()
            cred = _make_credential({"profile_name": "staging"})
            executor._get_boto3_session(cred, "us-west-2")
            call_kwargs = mock_boto3.Session.call_args[1]
            assert call_kwargs["profile_name"] == "staging"
            assert call_kwargs["region_name"] == "us-west-2"

    def test_no_credential_uses_defaults(self) -> None:
        with _mock_boto3_modules() as mock_boto3:
            mock_boto3.Session.return_value = MagicMock()

            executor = _mock_executor()
            executor._profile = "default-profile"
            executor._get_boto3_session(None, None)
            call_kwargs = mock_boto3.Session.call_args[1]
            assert call_kwargs["profile_name"] == "default-profile"
            assert call_kwargs["region_name"] == "us-east-1"

    def test_region_from_params_overrides_constructor(self) -> None:
        with _mock_boto3_modules() as mock_boto3:
            mock_boto3.Session.return_value = MagicMock()

            executor = _mock_executor()
            executor._region = "us-east-1"
            executor._get_boto3_session(None, "eu-west-1")
            call_kwargs = mock_boto3.Session.call_args[1]
            assert call_kwargs["region_name"] == "eu-west-1"

    def test_no_credential_no_profile(self) -> None:
        with _mock_boto3_modules() as mock_boto3:
            mock_boto3.Session.return_value = MagicMock()

            executor = _mock_executor()
            executor._profile = None
            executor._region = "ap-southeast-1"
            executor._get_boto3_session(None, None)
            call_kwargs = mock_boto3.Session.call_args[1]
            assert call_kwargs["region_name"] == "ap-southeast-1"
            assert "profile_name" not in call_kwargs

    def test_credential_priority_over_constructor(self) -> None:
        """Credential payload takes priority over constructor profile."""
        with _mock_boto3_modules() as mock_boto3:
            mock_boto3.Session.return_value = MagicMock()

            executor = _mock_executor()
            executor._profile = "default-profile"
            cred = _make_credential({
                "access_key_id": "AKIA_CRED",
                "secret_access_key": "secret_cred",
            })
            executor._get_boto3_session(cred, "us-east-1")
            call_kwargs = mock_boto3.Session.call_args[1]
            assert call_kwargs["aws_access_key_id"] == "AKIA_CRED"
            assert "profile_name" not in call_kwargs


# --- AwsExecutor Protocol Tests ---


class TestAwsExecutorProtocol:
    def test_satisfies_executor_protocol(self) -> None:
        assert hasattr(AwsExecutor, "execute")
        assert hasattr(AwsExecutor, "get_state")
        assert hasattr(AwsExecutor, "run_prechecks")

    def test_executor_type_is_aws(self) -> None:
        executor = _mock_executor()
        result = executor.execute(
            action="rds-reboot",
            target="prod/db",
            params={},
        )
        assert result.executor_type == "aws"


# --- AwsExecutor Serialization Tests ---


class TestAwsSerialize:
    def test_serialize_strips_response_metadata(self) -> None:
        executor = _mock_executor()
        result = executor._serialize_response({
            "InstanceId": "i-123",
            "ResponseMetadata": {"RequestId": "abc"},
        })
        assert "InstanceId" in result
        assert "ResponseMetadata" not in result

    def test_serialize_datetime(self) -> None:
        executor = _mock_executor()
        result = executor._serialize_value(datetime(2024, 6, 15, 12, 0, tzinfo=UTC))
        assert isinstance(result, str)
        assert "2024-06-15" in result

    def test_serialize_bytes(self) -> None:
        executor = _mock_executor()
        result = executor._serialize_value(b"hello")
        assert result == "hello"

    def test_serialize_nested(self) -> None:
        executor = _mock_executor()
        result = executor._serialize_response({
            "Items": [{"Time": datetime(2024, 1, 1, tzinfo=UTC)}],
            "ResponseMetadata": {},
        })
        assert isinstance(result["Items"][0]["Time"], str)
