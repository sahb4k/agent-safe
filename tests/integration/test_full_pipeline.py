"""Full pipeline integration test: check -> ticket -> execute (real) -> audit.

Exercises the entire agent-safe lifecycle against real Kind infrastructure.
Requires: Kind cluster 'agent-safe-test' with bootstrapped resources.
Run: pytest tests/integration/test_full_pipeline.py -m integration -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_safe.models import DecisionResult, ExecutionStatus
from tests.integration.conftest import skip_no_kind

pytestmark = [pytest.mark.integration, pytest.mark.kind, skip_no_kind]

NS = "agent-safe-inttest"
DEPLOY = "test-nginx"
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def safe(kind_kubeconfig, tmp_path):
    """Create a fully wired AgentSafe instance for integration testing."""
    from agent_safe.credentials.env_vault import EnvVarVault
    from agent_safe.sdk.client import AgentSafe

    vault = EnvVarVault(credentials={
        "kubernetes": {"kubeconfig": kind_kubeconfig},
    })
    return AgentSafe(
        registry=str(PROJECT_ROOT / "actions"),
        policies=str(PROJECT_ROOT / "policies"),
        inventory=str(PROJECT_ROOT / "inventory.yaml"),
        audit_log=str(tmp_path / "audit.jsonl"),
        signing_key="integration-test-key-32chars!!!!",
        credential_vault=vault,
    )


class TestPipelineScale:
    """E2E: check -> ticket -> execute scale-deployment with K8sExecutor."""

    def test_scale_via_pipeline(self, safe, kind_kubeconfig):
        from agent_safe.runner.k8s_executor import K8sExecutor

        token = safe.identity.create_token(
            agent_id="inttest-agent",
            agent_name="Integration Test Agent",
            roles=["deployer"],
            groups=["platform-team"],
        )

        decision = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            caller=token,
            params={"namespace": NS, "deployment": DEPLOY, "replicas": 3},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.ticket is not None

        executor = K8sExecutor(kubeconfig=kind_kubeconfig, context="kind-agent-safe-test")
        result = safe.execute(
            ticket_token=decision.ticket.token,
            executor=executor,
        )
        assert result.status == ExecutionStatus.SUCCESS

        # Cleanup: scale back
        decision2 = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            caller=token,
            params={"namespace": NS, "deployment": DEPLOY, "replicas": 2},
        )
        safe.execute(ticket_token=decision2.ticket.token, executor=executor)


class TestPipelineRestart:
    def test_restart_via_pipeline(self, safe, kind_kubeconfig):
        from agent_safe.runner.k8s_executor import K8sExecutor

        token = safe.identity.create_token(
            agent_id="inttest-agent",
            agent_name="Integration Test Agent",
            roles=["deployer"],
            groups=["platform-team"],
        )

        decision = safe.check(
            action="restart-deployment",
            target="dev/test-app",
            caller=token,
            params={"namespace": NS, "deployment": DEPLOY},
        )
        assert decision.result == DecisionResult.ALLOW

        executor = K8sExecutor(kubeconfig=kind_kubeconfig, context="kind-agent-safe-test")
        result = safe.execute(
            ticket_token=decision.ticket.token,
            executor=executor,
        )
        assert result.status == ExecutionStatus.SUCCESS


class TestPipelineAudit:
    def test_audit_integrity_after_execution(self, safe, kind_kubeconfig):
        from agent_safe.runner.k8s_executor import K8sExecutor

        token = safe.identity.create_token(
            agent_id="audit-test-agent",
            agent_name="Audit Test Agent",
            roles=["deployer"],
            groups=["platform-team"],
        )

        decision = safe.check(
            action="scale-deployment",
            target="dev/test-app",
            caller=token,
            params={"namespace": NS, "deployment": DEPLOY, "replicas": 2},
        )

        executor = K8sExecutor(kubeconfig=kind_kubeconfig, context="kind-agent-safe-test")
        safe.execute(ticket_token=decision.ticket.token, executor=executor)

        is_valid, errors = safe.verify_audit()
        assert is_valid, f"Audit log integrity failed: {errors}"


class TestPolicyDenial:
    def test_prod_requires_approval(self, safe):
        token = safe.identity.create_token(
            agent_id="inttest-agent",
            agent_name="Integration Test Agent",
            roles=["deployer"],
            groups=["platform-team"],
        )

        decision = safe.check(
            action="restart-deployment",
            target="prod/api-server",
            caller=token,
            params={"namespace": "production", "deployment": "api-server"},
        )
        assert decision.result in (DecisionResult.REQUIRE_APPROVAL, DecisionResult.DENY)
        assert decision.ticket is None
