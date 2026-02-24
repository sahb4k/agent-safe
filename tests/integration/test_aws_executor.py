"""Integration tests for AwsExecutor against LocalStack.

Requires: LocalStack running on localhost:4566.
Run: pytest tests/integration/test_aws_executor.py -m integration -v
"""

from __future__ import annotations

import contextlib
import json

import pytest

from agent_safe.models import ExecutionStatus
from tests.integration.conftest import skip_no_localstack

pytestmark = [pytest.mark.integration, pytest.mark.localstack, skip_no_localstack]


class TestAwsS3:
    """S3 operations against LocalStack."""

    def test_put_and_delete_object(
        self, aws_executor, aws_credential, localstack_s3_bucket, localstack_endpoint,
    ):
        from tests.integration.conftest import _boto3_client

        s3 = _boto3_client("s3", localstack_endpoint)
        s3.put_object(
            Bucket=localstack_s3_bucket, Key="test/file.txt", Body=b"hello integration",
        )

        # State should show the object
        state = aws_executor.get_state(
            action="s3-delete-object",
            target="inttest/bucket",
            params={"bucket": localstack_s3_bucket, "key": "test/file.txt", "region": "us-east-1"},
            credential=aws_credential,
        )
        assert state.get("ContentLength", 0) > 0

        # Delete via executor
        result = aws_executor.execute(
            action="s3-delete-object",
            target="inttest/bucket",
            params={"bucket": localstack_s3_bucket, "key": "test/file.txt", "region": "us-east-1"},
            credential=aws_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS

        # Object should be gone
        state_after = aws_executor.get_state(
            action="s3-delete-object",
            target="inttest/bucket",
            params={"bucket": localstack_s3_bucket, "key": "test/file.txt", "region": "us-east-1"},
            credential=aws_credential,
        )
        assert state_after == {}

    def test_put_bucket_policy(
        self, aws_executor, aws_credential, localstack_s3_bucket,
    ):
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{localstack_s3_bucket}/*",
            }],
        })
        result = aws_executor.execute(
            action="s3-put-bucket-policy",
            target="inttest/bucket",
            params={
                "bucket": localstack_s3_bucket,
                "policy": policy,
                "region": "us-east-1",
            },
            credential=aws_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestAwsIAM:
    """IAM attach/detach role policy against LocalStack."""

    def test_attach_and_detach_policy(
        self, aws_executor, aws_credential, localstack_iam_role,
    ):
        policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"

        # Attach
        result = aws_executor.execute(
            action="iam-attach-role-policy",
            target=f"inttest/{localstack_iam_role}",
            params={
                "role_name": localstack_iam_role,
                "policy_arn": policy_arn,
                "region": "us-east-1",
            },
            credential=aws_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS

        # Verify attached
        state = aws_executor.get_state(
            action="iam-attach-role-policy",
            target=f"inttest/{localstack_iam_role}",
            params={"role_name": localstack_iam_role, "region": "us-east-1"},
            credential=aws_credential,
        )
        arns = [p["PolicyArn"] for p in state.get("attached_policies", [])]
        assert policy_arn in arns

        # Detach
        result = aws_executor.execute(
            action="iam-detach-role-policy",
            target=f"inttest/{localstack_iam_role}",
            params={
                "role_name": localstack_iam_role,
                "policy_arn": policy_arn,
                "region": "us-east-1",
            },
            credential=aws_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestAwsEC2:
    """EC2 stop/start against LocalStack."""

    @pytest.fixture(autouse=True)
    def _create_instance(self, localstack_endpoint):
        from tests.integration.conftest import _boto3_client

        ec2 = _boto3_client("ec2", localstack_endpoint)
        response = ec2.run_instances(
            ImageId="ami-12345678", InstanceType="t2.micro",
            MinCount=1, MaxCount=1,
        )
        self.instance_id = response["Instances"][0]["InstanceId"]
        yield
        with contextlib.suppress(Exception):
            ec2.terminate_instances(InstanceIds=[self.instance_id])

    def test_stop_instance(self, aws_executor, aws_credential):
        state = aws_executor.get_state(
            action="ec2-stop-instance",
            target="inttest/ec2",
            params={"instance_id": self.instance_id, "region": "us-east-1"},
            credential=aws_credential,
        )
        assert state.get("InstanceId") == self.instance_id

        result = aws_executor.execute(
            action="ec2-stop-instance",
            target="inttest/ec2",
            params={"instance_id": self.instance_id, "region": "us-east-1"},
            credential=aws_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS

    def test_start_instance(self, aws_executor, aws_credential):
        # Stop first, then start
        aws_executor.execute(
            action="ec2-stop-instance",
            target="inttest/ec2",
            params={"instance_id": self.instance_id, "region": "us-east-1"},
            credential=aws_credential,
        )
        result = aws_executor.execute(
            action="ec2-start-instance",
            target="inttest/ec2",
            params={"instance_id": self.instance_id, "region": "us-east-1"},
            credential=aws_credential,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestAwsErrors:
    def test_nonexistent_instance_fails(self, aws_executor, aws_credential):
        result = aws_executor.execute(
            action="ec2-stop-instance",
            target="inttest/ec2",
            params={"instance_id": "i-nonexistent000000", "region": "us-east-1"},
            credential=aws_credential,
        )
        assert result.status in (ExecutionStatus.FAILURE, ExecutionStatus.ERROR)

    def test_unmapped_action_errors(self, aws_executor, aws_credential):
        result = aws_executor.execute(
            action="rds-reboot-cluster",
            target="inttest/rds",
            params={},
            credential=aws_credential,
        )
        assert result.status == ExecutionStatus.ERROR
