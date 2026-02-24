"""Tests for the approval request store."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from agent_safe.approval.store import (
    ApprovalStore,
    ApprovalStoreError,
    FileApprovalStore,
)
from agent_safe.models import (
    ApprovalStatus,
    Decision,
    DecisionResult,
    RiskClass,
)


def _make_decision(**overrides) -> Decision:
    """Helper to create a REQUIRE_APPROVAL decision for tests."""
    defaults = {
        "result": DecisionResult.REQUIRE_APPROVAL,
        "reason": "Requires approval",
        "action": "restart-deployment",
        "target": "prod/api-server",
        "caller": "deploy-agent-01",
        "risk_class": RiskClass.MEDIUM,
        "effective_risk": RiskClass.CRITICAL,
        "policy_matched": "require-approval-prod",
        "audit_id": "evt-test000001",
    }
    defaults.update(overrides)
    return Decision(**defaults)


# --- FileApprovalStore ---


class TestFileApprovalStoreCreate:
    def test_create_returns_pending_request(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        decision = _make_decision()
        req = store.create(decision, params={"namespace": "prod"})

        assert req.request_id.startswith("apr-")
        assert req.status == ApprovalStatus.PENDING
        assert req.action == "restart-deployment"
        assert req.target == "prod/api-server"
        assert req.caller == "deploy-agent-01"
        assert req.params == {"namespace": "prod"}
        assert req.risk_class == RiskClass.MEDIUM
        assert req.effective_risk == RiskClass.CRITICAL

    def test_create_persists_to_file(self, tmp_path: Path):
        path = tmp_path / "approvals.jsonl"
        store = FileApprovalStore(path)
        store.create(_make_decision())

        lines = path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["status"] == "pending"

    def test_create_multiple_requests(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        r1 = store.create(_make_decision(audit_id="evt-001"))
        r2 = store.create(_make_decision(audit_id="evt-002"))

        assert r1.request_id != r2.request_id
        assert len(store.list_pending()) == 2

    def test_create_with_custom_ttl(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        req = store.create(
            _make_decision(), ttl=timedelta(minutes=5),
        )
        # expires_at should be ~5 minutes from created_at
        delta = req.expires_at - req.created_at
        assert timedelta(minutes=4) < delta < timedelta(minutes=6)

    def test_create_default_ttl(self, tmp_path: Path):
        store = FileApprovalStore(
            tmp_path / "approvals.jsonl", ttl=timedelta(minutes=30),
        )
        req = store.create(_make_decision())
        delta = req.expires_at - req.created_at
        assert timedelta(minutes=29) < delta < timedelta(minutes=31)


class TestFileApprovalStoreGet:
    def test_get_existing(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        req = store.create(_make_decision())
        fetched = store.get(req.request_id)

        assert fetched is not None
        assert fetched.request_id == req.request_id
        assert fetched.status == ApprovalStatus.PENDING

    def test_get_missing_returns_none(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        assert store.get("apr-nonexistent") is None

    def test_get_auto_expires(self, tmp_path: Path):
        store = FileApprovalStore(
            tmp_path / "approvals.jsonl",
            ttl=timedelta(seconds=0),  # instant expiry
        )
        req = store.create(_make_decision())

        import time
        time.sleep(0.05)  # ensure past expiry

        fetched = store.get(req.request_id)
        assert fetched is not None
        assert fetched.status == ApprovalStatus.EXPIRED


class TestFileApprovalStoreResolve:
    def test_approve(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        req = store.create(_make_decision())

        resolved = store.resolve(
            req.request_id,
            ApprovalStatus.APPROVED,
            resolved_by="admin",
            reason="Looks good",
        )
        assert resolved.status == ApprovalStatus.APPROVED
        assert resolved.resolved_by == "admin"
        assert resolved.resolution_reason == "Looks good"
        assert resolved.resolved_at is not None

    def test_deny(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        req = store.create(_make_decision())

        resolved = store.resolve(
            req.request_id,
            ApprovalStatus.DENIED,
            resolved_by="reviewer",
        )
        assert resolved.status == ApprovalStatus.DENIED

    def test_resolve_persists(self, tmp_path: Path):
        path = tmp_path / "approvals.jsonl"
        store = FileApprovalStore(path)
        req = store.create(_make_decision())
        store.resolve(req.request_id, ApprovalStatus.APPROVED, resolved_by="x")

        # Re-read from a fresh store
        store2 = FileApprovalStore(path)
        fetched = store2.get(req.request_id)
        assert fetched is not None
        assert fetched.status == ApprovalStatus.APPROVED

    def test_resolve_already_resolved_raises(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        req = store.create(_make_decision())
        store.resolve(req.request_id, ApprovalStatus.APPROVED, resolved_by="x")

        with pytest.raises(ApprovalStoreError, match="already"):
            store.resolve(
                req.request_id, ApprovalStatus.DENIED, resolved_by="y",
            )

    def test_resolve_expired_raises(self, tmp_path: Path):
        store = FileApprovalStore(
            tmp_path / "approvals.jsonl",
            ttl=timedelta(seconds=0),
        )
        req = store.create(_make_decision())

        import time
        time.sleep(0.05)

        with pytest.raises(ApprovalStoreError, match="already"):
            store.resolve(
                req.request_id, ApprovalStatus.APPROVED, resolved_by="x",
            )

    def test_resolve_not_found_raises(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        with pytest.raises(ApprovalStoreError, match="not found"):
            store.resolve(
                "apr-nonexistent", ApprovalStatus.APPROVED, resolved_by="x",
            )

    def test_resolve_invalid_status_raises(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        req = store.create(_make_decision())

        with pytest.raises(ApprovalStoreError, match="must be"):
            store.resolve(req.request_id, ApprovalStatus.PENDING)


class TestFileApprovalStoreListPending:
    def test_list_pending_filters_resolved(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        r1 = store.create(_make_decision(audit_id="evt-001"))
        r2 = store.create(_make_decision(audit_id="evt-002"))
        store.resolve(r1.request_id, ApprovalStatus.APPROVED, resolved_by="x")

        pending = store.list_pending()
        assert len(pending) == 1
        assert pending[0].request_id == r2.request_id

    def test_list_pending_auto_expires(self, tmp_path: Path):
        store = FileApprovalStore(
            tmp_path / "approvals.jsonl",
            ttl=timedelta(seconds=0),
        )
        store.create(_make_decision())

        import time
        time.sleep(0.05)

        assert store.list_pending() == []

    def test_list_pending_empty_store(self, tmp_path: Path):
        store = FileApprovalStore(tmp_path / "approvals.jsonl")
        assert store.list_pending() == []


class TestProtocol:
    def test_file_store_satisfies_protocol(self):
        assert isinstance(
            FileApprovalStore(Path("/tmp/test")), ApprovalStore,
        )
