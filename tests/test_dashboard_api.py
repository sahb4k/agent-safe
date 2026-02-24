"""Tests for dashboard API endpoints (v0.10.0).

Uses FastAPI TestClient to test all routers end-to-end.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from dashboard.backend.app import create_app  # noqa: E402
from dashboard.backend.config import DashboardConfig  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")


def _make_event(
    event_id: str = "evt-1",
    action: str = "restart-deployment",
    target: str = "dev/test",
    caller: str = "agent-01",
    decision: str = "allow",
    risk_class: str = "low",
    event_type: str = "decision",
    timestamp: str | None = None,
) -> dict:
    ts = timestamp or "2025-01-15T10:00:00+00:00"
    return {
        "event_id": event_id,
        "timestamp": ts,
        "prev_hash": "genesis",
        "entry_hash": "abc123",
        "event_type": event_type,
        "action": action,
        "target": target,
        "caller": caller,
        "decision": decision,
        "reason": "test matched",
        "risk_class": risk_class,
        "effective_risk": risk_class,
    }


def _write_audit_log(events: list[dict]) -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
    ) as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
        return f.name


def _make_client(events: list[dict] | None = None) -> TestClient:
    log_path = _write_audit_log(events or [])
    config = DashboardConfig(
        actions_dir=ACTIONS_DIR,
        policies_dir=POLICIES_DIR,
        inventory_file=INVENTORY_FILE,
        audit_log=log_path,
    )
    app = create_app(config)
    return TestClient(app)


# --- Health ---


class TestHealthEndpoint:
    def test_health_ok(self) -> None:
        client = _make_client()
        resp = client.get("/api/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["version"] == "0.10.0"

    def test_health_has_counts(self) -> None:
        client = _make_client([_make_event()])
        resp = client.get("/api/health")
        data = resp.json()
        assert data["audit_events"] == 1
        assert data["actions"] >= 33
        assert data["policies"] >= 1


# --- Audit Events ---


class TestAuditEventsEndpoint:
    def test_list_events_empty(self) -> None:
        client = _make_client([])
        resp = client.get("/api/audit/events")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_list_events_returns_items(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(3)]
        client = _make_client(events)
        resp = client.get("/api/audit/events")
        data = resp.json()
        assert data["total"] == 3
        assert len(data["items"]) == 3

    def test_list_events_pagination(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(10)]
        client = _make_client(events)
        resp = client.get("/api/audit/events?page=1&page_size=5")
        data = resp.json()
        assert data["total"] == 10
        assert len(data["items"]) == 5
        assert data["page"] == 1

    def test_list_events_page_2(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(8)]
        client = _make_client(events)
        resp = client.get("/api/audit/events?page=2&page_size=5")
        data = resp.json()
        assert len(data["items"]) == 3
        assert data["page"] == 2

    def test_list_events_filter_event_type(self) -> None:
        events = [
            _make_event(event_id="evt-1", event_type="decision"),
            _make_event(event_id="evt-2", event_type="state_capture"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/events?event_type=state_capture")
        data = resp.json()
        assert data["total"] == 1

    def test_list_events_filter_action(self) -> None:
        events = [
            _make_event(event_id="evt-1", action="restart-deployment"),
            _make_event(event_id="evt-2", action="scale-deployment"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/events?action=scale-deployment")
        data = resp.json()
        assert data["total"] == 1

    def test_list_events_filter_risk_class(self) -> None:
        events = [
            _make_event(event_id="evt-1", risk_class="low"),
            _make_event(event_id="evt-2", risk_class="critical"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/events?risk_class=critical")
        data = resp.json()
        assert data["total"] == 1

    def test_list_events_filter_decision(self) -> None:
        events = [
            _make_event(event_id="evt-1", decision="allow"),
            _make_event(event_id="evt-2", decision="deny"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/events?decision=deny")
        data = resp.json()
        assert data["total"] == 1

    def test_list_events_filter_target(self) -> None:
        events = [
            _make_event(event_id="evt-1", target="dev/app"),
            _make_event(event_id="evt-2", target="prod/api"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/events?target=prod/api")
        data = resp.json()
        assert data["total"] == 1


class TestAuditStatsEndpoint:
    def test_stats_empty(self) -> None:
        client = _make_client([])
        resp = client.get("/api/audit/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_events"] == 0

    def test_stats_with_data(self) -> None:
        events = [
            _make_event(event_id="evt-1", decision="allow"),
            _make_event(event_id="evt-2", decision="deny"),
            _make_event(event_id="evt-3", decision="allow"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/stats")
        data = resp.json()
        assert data["total_events"] == 3
        assert data["by_decision"]["allow"] == 2
        assert data["by_decision"]["deny"] == 1


class TestAuditTimelineEndpoint:
    def test_timeline_empty(self) -> None:
        client = _make_client([])
        resp = client.get("/api/audit/timeline")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_timeline_with_data(self) -> None:
        events = [
            _make_event(event_id="evt-1", timestamp="2025-01-15T10:15:00+00:00"),
            _make_event(event_id="evt-2", timestamp="2025-01-15T10:45:00+00:00"),
            _make_event(event_id="evt-3", timestamp="2025-01-15T11:15:00+00:00"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/timeline?bucket_hours=1")
        data = resp.json()
        assert len(data) == 2

    def test_timeline_bucket_size(self) -> None:
        events = [
            _make_event(event_id="evt-1", timestamp="2025-01-15T10:00:00+00:00"),
            _make_event(event_id="evt-2", timestamp="2025-01-15T13:00:00+00:00"),
        ]
        client = _make_client(events)
        resp = client.get("/api/audit/timeline?bucket_hours=6")
        data = resp.json()
        assert len(data) == 2  # 06:00 and 12:00 buckets


# --- Actions ---


class TestActionsEndpoints:
    def test_list_actions(self) -> None:
        client = _make_client()
        resp = client.get("/api/actions/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 33

    def test_list_actions_filter_tag(self) -> None:
        client = _make_client()
        resp = client.get("/api/actions/?tag=aws")
        data = resp.json()
        assert len(data) == 13

    def test_list_actions_filter_risk(self) -> None:
        client = _make_client()
        resp = client.get("/api/actions/?risk=critical")
        data = resp.json()
        assert len(data) >= 1
        for a in data:
            assert a["risk_class"] == "critical"

    def test_get_action_found(self) -> None:
        client = _make_client()
        resp = client.get("/api/actions/restart-deployment")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "restart-deployment"
        assert "parameters" in data

    def test_get_action_not_found(self) -> None:
        client = _make_client()
        resp = client.get("/api/actions/nonexistent")
        assert resp.status_code == 404

    def test_get_action_detail_fields(self) -> None:
        client = _make_client()
        resp = client.get("/api/actions/scale-deployment")
        data = resp.json()
        assert data["name"] == "scale-deployment"
        assert "parameters" in data
        assert "risk_class" in data
        assert "tags" in data
        assert "target_types" in data

    def test_get_aws_action(self) -> None:
        client = _make_client()
        resp = client.get("/api/actions/ec2-stop-instance")
        data = resp.json()
        assert data["name"] == "ec2-stop-instance"
        assert data["credentials"] is not None


# --- Policies ---


class TestPoliciesEndpoints:
    def test_list_policies(self) -> None:
        client = _make_client()
        resp = client.get("/api/policies/")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1

    def test_policy_fields(self) -> None:
        client = _make_client()
        resp = client.get("/api/policies/")
        data = resp.json()
        for p in data:
            assert "name" in p
            assert "priority" in p
            assert "decision" in p

    def test_match_analysis(self) -> None:
        client = _make_client()
        resp = client.get("/api/policies/match-analysis")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 1
        for item in data:
            assert "rule_name" in item
            assert "matching_target_count" in item


# --- Activity ---


class TestActivityEndpoints:
    def test_feed_empty(self) -> None:
        client = _make_client([])
        resp = client.get("/api/activity/feed")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_feed_with_data(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(5)]
        client = _make_client(events)
        resp = client.get("/api/activity/feed?limit=3")
        data = resp.json()
        assert len(data) == 3

    def test_feed_item_fields(self) -> None:
        client = _make_client([_make_event()])
        resp = client.get("/api/activity/feed")
        data = resp.json()
        assert len(data) == 1
        item = data[0]
        assert "event_id" in item
        assert "timestamp" in item
        assert "action" in item
        assert "decision" in item

    def test_recent_decisions_empty(self) -> None:
        client = _make_client([])
        resp = client.get("/api/activity/recent-decisions")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_recent_decisions_filters_non_decisions(self) -> None:
        events = [
            _make_event(event_id="evt-1", event_type="decision"),
            _make_event(event_id="evt-2", event_type="state_capture"),
        ]
        client = _make_client(events)
        resp = client.get("/api/activity/recent-decisions")
        data = resp.json()
        assert len(data) == 1
        assert data[0]["event_type"] == "decision"


# --- App Factory ---


class TestAppFactory:
    def test_create_app_default_config(self) -> None:
        config = DashboardConfig(
            actions_dir=ACTIONS_DIR,
            policies_dir=POLICIES_DIR,
            inventory_file=INVENTORY_FILE,
        )
        app = create_app(config)
        assert app is not None
        assert app.title == "Agent-Safe Dashboard"

    def test_create_app_dev_mode(self) -> None:
        log_path = _write_audit_log([])
        config = DashboardConfig(
            actions_dir=ACTIONS_DIR,
            policies_dir=POLICIES_DIR,
            inventory_file=INVENTORY_FILE,
            audit_log=log_path,
            dev_mode=True,
        )
        app = create_app(config)
        # CORS middleware should be present
        assert app is not None
