"""Tests for approval workflow integration in the AgentSafe SDK."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent_safe import AgentSafe, AgentSafeError
from agent_safe.models import ApprovalStatus, DecisionResult

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")


@pytest.fixture()
def safe_with_approval(tmp_path: Path) -> AgentSafe:
    """AgentSafe with approval store enabled."""
    return AgentSafe(
        registry=ACTIONS_DIR,
        policies=POLICIES_DIR,
        inventory=INVENTORY_FILE,
        audit_log=tmp_path / "audit.jsonl",
        approval_store=tmp_path / "approvals.jsonl",
    )


@pytest.fixture()
def safe_with_signing(tmp_path: Path) -> AgentSafe:
    """AgentSafe with approval store + signing key (tickets)."""
    return AgentSafe(
        registry=ACTIONS_DIR,
        policies=POLICIES_DIR,
        inventory=INVENTORY_FILE,
        audit_log=tmp_path / "audit.jsonl",
        approval_store=tmp_path / "approvals.jsonl",
        signing_key="test-approval-key",
    )


# --- Constructor validation ---


class TestConstructor:
    def test_approval_notifiers_without_store_raises(self, tmp_path: Path):
        with pytest.raises(AgentSafeError, match="approval_notifiers requires"):
            AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                approval_notifiers={"webhook_url": "https://example.com"},
            )

    def test_approval_store_accepts_path(self, tmp_path: Path):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            approval_store=tmp_path / "approvals.jsonl",
        )
        assert s.approval_store is not None

    def test_approval_ttl_int_seconds(self, tmp_path: Path):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            approval_store=tmp_path / "approvals.jsonl",
            approval_ttl=300,
        )
        assert s.approval_store is not None

    def test_approval_ttl_timedelta(self, tmp_path: Path):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            approval_store=tmp_path / "approvals.jsonl",
            approval_ttl=timedelta(minutes=10),
        )
        assert s.approval_store is not None


# --- check() with approval store ---


class TestCheckWithApproval:
    def test_require_approval_creates_request(
        self, safe_with_approval: AgentSafe,
    ):
        """check() on a prod target should create an approval request."""
        decision = safe_with_approval.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        assert decision.result == DecisionResult.REQUIRE_APPROVAL
        assert decision.request_id is not None
        assert decision.request_id.startswith("apr-")

    def test_allow_decision_no_request(
        self, safe_with_approval: AgentSafe,
    ):
        """ALLOW decisions should not create approval requests."""
        decision = safe_with_approval.check(
            action="restart-deployment",
            target="dev/test-app",
            caller="any-agent",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert decision.result == DecisionResult.ALLOW
        assert decision.request_id is None

    def test_request_stored_and_retrievable(
        self, safe_with_approval: AgentSafe,
    ):
        decision = safe_with_approval.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        req = safe_with_approval.get_approval_status(decision.request_id)
        assert req is not None
        assert req.status == ApprovalStatus.PENDING
        assert req.action == "restart-deployment"
        assert req.params == {"namespace": "prod", "deployment": "api-server"}


# --- resolve_approval ---


class TestResolveApproval:
    def test_approve_returns_allow(self, safe_with_approval: AgentSafe):
        decision = safe_with_approval.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        resolved = safe_with_approval.resolve_approval(
            request_id=decision.request_id,
            action="approve",
            resolved_by="admin",
            reason="LGTM",
        )
        assert resolved.result == DecisionResult.ALLOW
        assert "admin" in resolved.reason

    def test_deny_returns_deny(self, safe_with_approval: AgentSafe):
        decision = safe_with_approval.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        resolved = safe_with_approval.resolve_approval(
            request_id=decision.request_id,
            action="deny",
            resolved_by="reviewer",
        )
        assert resolved.result == DecisionResult.DENY

    def test_approve_issues_ticket_with_signing_key(
        self, safe_with_signing: AgentSafe,
    ):
        decision = safe_with_signing.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        resolved = safe_with_signing.resolve_approval(
            request_id=decision.request_id,
            action="approve",
            resolved_by="admin",
        )
        assert resolved.result == DecisionResult.ALLOW
        assert resolved.ticket is not None
        assert resolved.ticket.action == "restart-deployment"

    def test_resolve_logs_audit_event(self, safe_with_approval: AgentSafe):
        decision = safe_with_approval.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        safe_with_approval.resolve_approval(
            request_id=decision.request_id,
            action="approve",
            resolved_by="admin",
        )
        events = safe_with_approval.audit.read_events()
        # Should have at least 2 events: the check + the resolution
        assert len(events) >= 2
        resolution = events[-1]
        assert resolution.context is not None
        assert resolution.context["type"] == "approval_resolution"
        assert resolution.context["resolved_by"] == "admin"

    def test_resolve_without_store_raises(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        with pytest.raises(AgentSafeError, match="not configured"):
            s.resolve_approval("apr-fake", action="approve")


# --- list_pending_approvals ---


class TestListPending:
    def test_lists_pending(self, safe_with_approval: AgentSafe):
        safe_with_approval.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        pending = safe_with_approval.list_pending_approvals()
        assert len(pending) == 1
        assert pending[0].action == "restart-deployment"

    def test_empty_without_store(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        assert s.list_pending_approvals() == []


# --- get_approval_status ---


class TestGetApprovalStatus:
    def test_returns_none_without_store(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        assert s.get_approval_status("apr-fake") is None


# --- wait_for_approval ---


class TestWaitForApproval:
    def test_wait_without_store_raises(self):
        s = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        with pytest.raises(AgentSafeError, match="not configured"):
            s.wait_for_approval("apr-fake")

    def test_wait_not_found_raises(self, safe_with_approval: AgentSafe):
        with pytest.raises(AgentSafeError, match="not found"):
            safe_with_approval.wait_for_approval(
                "apr-nonexistent", timeout=0.1, poll_interval=0.05,
            )

    def test_wait_timeout_returns_deny(self, safe_with_approval: AgentSafe):
        decision = safe_with_approval.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        result = safe_with_approval.wait_for_approval(
            decision.request_id, timeout=0.1, poll_interval=0.05,
        )
        assert result.result == DecisionResult.DENY
        assert "timed out" in result.reason


# --- Notifier dispatch on check() ---


class TestNotifierDispatch:
    def test_notifiers_called_on_require_approval(self, tmp_path: Path):
        mock_notifier = MagicMock()
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            approval_store=tmp_path / "approvals.jsonl",
            approval_notifiers=[mock_notifier],
        )
        safe.check(
            action="restart-deployment",
            target="prod/api-server",
            caller="deploy-agent-01",
            params={"namespace": "prod", "deployment": "api-server"},
        )
        mock_notifier.notify.assert_called_once()
        req = mock_notifier.notify.call_args[0][0]
        assert req.action == "restart-deployment"
