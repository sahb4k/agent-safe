"""Integration test fixtures and infrastructure detection.

Run with:  pytest tests/integration/ -m integration -v
Requires:  Kind cluster 'agent-safe-test' and/or LocalStack on :4566.
Tests skip automatically if infrastructure is not available.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import tempfile
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import pytest

from agent_safe.models import Credential, CredentialScope

# ---------------------------------------------------------------------------
# Infrastructure detection (evaluated once at import time)
# ---------------------------------------------------------------------------

LOCALSTACK_ENDPOINT = "http://localhost:4566"
KIND_CLUSTER_NAME = "agent-safe-test"
KIND_CONTEXT = f"kind-{KIND_CLUSTER_NAME}"
TEST_NAMESPACE = "agent-safe-inttest"


def _is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, ConnectionRefusedError, TimeoutError):
        return False


def _is_kind_running() -> bool:
    kubectl = shutil.which("kubectl")
    if kubectl is None:
        return False
    try:
        result = subprocess.run(
            [kubectl, "cluster-info", "--context", KIND_CONTEXT],
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _is_localstack_running() -> bool:
    return _is_port_open("localhost", 4566)


KIND_AVAILABLE = _is_kind_running()
LOCALSTACK_AVAILABLE = _is_localstack_running()

skip_no_kind = pytest.mark.skipif(
    not KIND_AVAILABLE,
    reason=f"Kind cluster '{KIND_CLUSTER_NAME}' not running. Run: bash infra/setup.sh",
)

skip_no_localstack = pytest.mark.skipif(
    not LOCALSTACK_AVAILABLE,
    reason="LocalStack not running on localhost:4566. Run: bash infra/setup.sh",
)


# ---------------------------------------------------------------------------
# Kind / Kubernetes fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def kind_kubeconfig() -> Generator[str, None, None]:
    """Export Kind kubeconfig to a temp file. Cleaned up after session."""
    kind_bin = shutil.which("kind")
    if kind_bin is None:
        pytest.skip("kind binary not found in PATH")

    try:
        result = subprocess.run(
            [kind_bin, "get", "kubeconfig", "--name", KIND_CLUSTER_NAME],
            capture_output=True, text=True, timeout=10,
        )
    except (subprocess.TimeoutExpired, OSError):
        pytest.skip("Failed to get Kind kubeconfig")

    if result.returncode != 0:
        pytest.skip(f"Failed to get Kind kubeconfig: {result.stderr.strip()}")

    fd, path = tempfile.mkstemp(suffix=".kubeconfig")
    with os.fdopen(fd, "w") as f:
        f.write(result.stdout)

    yield path

    with contextlib.suppress(OSError):
        os.unlink(path)


@pytest.fixture(scope="session")
def k8s_executor(kind_kubeconfig: str):
    """K8sExecutor wired to the Kind cluster."""
    from agent_safe.runner.k8s_executor import K8sExecutor
    return K8sExecutor(kubeconfig=kind_kubeconfig, context=KIND_CONTEXT)


@pytest.fixture(scope="session")
def subprocess_executor(kind_kubeconfig: str):
    """SubprocessExecutor wired to the Kind cluster."""
    from agent_safe.runner.subprocess_executor import SubprocessExecutor
    return SubprocessExecutor(kubeconfig=kind_kubeconfig, context=KIND_CONTEXT)


@pytest.fixture(scope="session")
def k8s_credential(kind_kubeconfig: str) -> Credential:
    """Credential pointing to the Kind kubeconfig file."""
    return Credential(
        credential_id="cred-kind-inttest",
        type="kubernetes",
        payload={"kubeconfig": kind_kubeconfig},
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        scope=CredentialScope(type="kubernetes", fields={}),
        ticket_nonce="nonce-inttest",
    )


@pytest.fixture(scope="session")
def k8s_test_namespace() -> str:
    return TEST_NAMESPACE


# ---------------------------------------------------------------------------
# LocalStack / AWS fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def localstack_endpoint() -> str:
    return LOCALSTACK_ENDPOINT


@pytest.fixture(scope="session")
def aws_executor(localstack_endpoint: str):
    """AwsExecutor wired to LocalStack."""
    from agent_safe.runner.aws_executor import AwsExecutor
    return AwsExecutor(region="us-east-1", endpoint_url=localstack_endpoint)


@pytest.fixture(scope="session")
def aws_credential() -> Credential:
    """Dummy credential for LocalStack."""
    return Credential(
        credential_id="cred-localstack-inttest",
        type="aws",
        payload={
            "access_key_id": "test",
            "secret_access_key": "test",
        },
        expires_at=datetime(2099, 1, 1, tzinfo=UTC),
        scope=CredentialScope(type="aws", fields={}),
        ticket_nonce="nonce-inttest",
    )


def _boto3_client(service: str, endpoint: str) -> Any:
    """Create a raw boto3 client for test setup/teardown."""
    import boto3
    return boto3.client(
        service,
        endpoint_url=endpoint,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


@pytest.fixture(scope="module")
def localstack_s3_bucket(localstack_endpoint: str) -> Generator[str, None, None]:
    """Create an S3 bucket in LocalStack; clean up after."""
    bucket_name = "agent-safe-inttest"
    s3 = _boto3_client("s3", localstack_endpoint)
    with contextlib.suppress(Exception):
        s3.create_bucket(Bucket=bucket_name)
    yield bucket_name
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except Exception:
        pass


@pytest.fixture(scope="module")
def localstack_iam_role(localstack_endpoint: str) -> Generator[str, None, None]:
    """Create an IAM role in LocalStack; clean up after."""
    role_name = "agent-safe-inttest-role"
    iam = _boto3_client("iam", localstack_endpoint)
    trust_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    with contextlib.suppress(Exception):
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
    yield role_name
    try:
        policies = iam.list_attached_role_policies(RoleName=role_name).get(
            "AttachedPolicies", []
        )
        for p in policies:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
        iam.delete_role(RoleName=role_name)
    except Exception:
        pass
