"""Tests for dashboard backend services (v0.10.0)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
from dashboard.backend.config import DashboardConfig
from dashboard.backend.services.action_service import ActionService
from dashboard.backend.services.activity_service import ActivityService
from dashboard.backend.services.audit_service import AuditService
from dashboard.backend.services.policy_service import PolicyService

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
        "reason": "test rule matched",
        "risk_class": risk_class,
        "effective_risk": risk_class,
    }


def _write_audit_log(events: list[dict]) -> str:
    """Write events to a temp JSONL file, return the path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
    ) as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
        return f.name


# --- Config Tests ---


class TestDashboardConfig:
    def test_defaults(self) -> None:
        cfg = DashboardConfig()
        assert cfg.host == "127.0.0.1"
        assert cfg.port == 8420
        assert cfg.dev_mode is False

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AGENT_SAFE_DASHBOARD_PORT", "9999")
        monkeypatch.setenv("AGENT_SAFE_DASHBOARD_DEV_MODE", "true")
        cfg = DashboardConfig.from_env()
        assert cfg.port == 9999
        assert cfg.dev_mode is True

    def test_from_env_no_vars(self) -> None:
        cfg = DashboardConfig.from_env()
        assert cfg.port == 8420


# --- AuditService Tests ---


class TestAuditService:
    def _make_service(self, events: list[dict]) -> AuditService:
        log_path = _write_audit_log(events)
        cfg = DashboardConfig(audit_log=log_path)
        return AuditService(cfg)

    def test_get_events_empty(self) -> None:
        svc = self._make_service([])
        result = svc.get_events()
        assert result.total == 0
        assert result.items == []

    def test_get_events_returns_items(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(3)]
        svc = self._make_service(events)
        result = svc.get_events()
        assert result.total == 3
        assert len(result.items) == 3

    def test_get_events_pagination(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(10)]
        svc = self._make_service(events)
        result = svc.get_events(page=1, page_size=3)
        assert result.total == 10
        assert len(result.items) == 3
        assert result.page == 1
        assert result.page_size == 3

    def test_get_events_page_2(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(5)]
        svc = self._make_service(events)
        p1 = svc.get_events(page=1, page_size=3)
        p2 = svc.get_events(page=2, page_size=3)
        assert len(p1.items) == 3
        assert len(p2.items) == 2

    def test_get_events_filter_by_event_type(self) -> None:
        events = [
            _make_event(event_id="evt-1", event_type="decision"),
            _make_event(event_id="evt-2", event_type="state_capture"),
            _make_event(event_id="evt-3", event_type="decision"),
        ]
        svc = self._make_service(events)
        result = svc.get_events(event_type="state_capture")
        assert result.total == 1

    def test_get_events_filter_by_action(self) -> None:
        events = [
            _make_event(event_id="evt-1", action="restart-deployment"),
            _make_event(event_id="evt-2", action="scale-deployment"),
        ]
        svc = self._make_service(events)
        result = svc.get_events(action="scale-deployment")
        assert result.total == 1

    def test_get_events_filter_by_risk_class(self) -> None:
        events = [
            _make_event(event_id="evt-1", risk_class="low"),
            _make_event(event_id="evt-2", risk_class="critical"),
        ]
        svc = self._make_service(events)
        result = svc.get_events(risk_class="critical")
        assert result.total == 1

    def test_get_events_filter_by_decision(self) -> None:
        events = [
            _make_event(event_id="evt-1", decision="allow"),
            _make_event(event_id="evt-2", decision="deny"),
        ]
        svc = self._make_service(events)
        result = svc.get_events(decision="deny")
        assert result.total == 1

    def test_get_events_filter_by_target(self) -> None:
        events = [
            _make_event(event_id="evt-1", target="dev/app"),
            _make_event(event_id="evt-2", target="prod/api"),
        ]
        svc = self._make_service(events)
        result = svc.get_events(target="prod/api")
        assert result.total == 1

    def test_get_events_sorted_newest_first(self) -> None:
        events = [
            _make_event(event_id="evt-1", timestamp="2025-01-15T08:00:00+00:00"),
            _make_event(event_id="evt-2", timestamp="2025-01-15T12:00:00+00:00"),
        ]
        svc = self._make_service(events)
        result = svc.get_events()
        assert result.items[0]["event_id"] == "evt-2"

    def test_get_stats(self) -> None:
        events = [
            _make_event(event_id="evt-1", decision="allow", risk_class="low"),
            _make_event(event_id="evt-2", decision="deny", risk_class="high"),
            _make_event(event_id="evt-3", decision="allow", risk_class="low"),
        ]
        svc = self._make_service(events)
        stats = svc.get_stats()
        assert stats.total_events == 3
        assert stats.by_decision["allow"] == 2
        assert stats.by_decision["deny"] == 1
        assert stats.by_risk_class["low"] == 2
        assert stats.by_risk_class["high"] == 1

    def test_get_stats_empty(self) -> None:
        svc = self._make_service([])
        stats = svc.get_stats()
        assert stats.total_events == 0
        assert stats.by_decision == {}

    def test_get_timeline(self) -> None:
        events = [
            _make_event(event_id="evt-1", timestamp="2025-01-15T10:15:00+00:00"),
            _make_event(event_id="evt-2", timestamp="2025-01-15T10:45:00+00:00"),
            _make_event(event_id="evt-3", timestamp="2025-01-15T11:15:00+00:00"),
        ]
        svc = self._make_service(events)
        timeline = svc.get_timeline(bucket_hours=1)
        assert len(timeline) == 2  # 10:00 and 11:00 buckets
        assert timeline[0].count == 2
        assert timeline[1].count == 1

    def test_get_timeline_empty(self) -> None:
        svc = self._make_service([])
        assert svc.get_timeline() == []

    def test_event_count(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(5)]
        svc = self._make_service(events)
        assert svc.event_count() == 5

    def test_cache_invalidation(self) -> None:
        events = [_make_event()]
        svc = self._make_service(events)
        assert svc.event_count() == 1
        svc.invalidate_cache()
        # Still returns same after reload
        assert svc.event_count() == 1


# --- ActionService Tests ---


class TestActionService:
    def _make_service(self) -> ActionService:
        cfg = DashboardConfig(actions_dir=ACTIONS_DIR)
        return ActionService(cfg)

    def test_list_actions(self) -> None:
        svc = self._make_service()
        actions = svc.list_actions()
        assert len(actions) >= 33  # 20 K8s + 13 AWS
        assert all(a.name for a in actions)

    def test_list_actions_filter_by_tag(self) -> None:
        svc = self._make_service()
        aws_actions = svc.list_actions(tag="aws")
        assert len(aws_actions) == 13
        for a in aws_actions:
            assert "aws" in a.tags

    def test_list_actions_filter_by_risk(self) -> None:
        svc = self._make_service()
        critical = svc.list_actions(risk="critical")
        assert len(critical) >= 1
        for a in critical:
            assert a.risk_class == "critical"

    def test_get_action_found(self) -> None:
        svc = self._make_service()
        detail = svc.get_action("restart-deployment")
        assert detail is not None
        assert detail.name == "restart-deployment"
        assert detail.risk_class == "medium"
        assert len(detail.parameters) >= 1

    def test_get_action_not_found(self) -> None:
        svc = self._make_service()
        assert svc.get_action("nonexistent-action") is None

    def test_get_action_has_parameters(self) -> None:
        svc = self._make_service()
        detail = svc.get_action("scale-deployment")
        assert detail is not None
        param_names = [p.name for p in detail.parameters]
        assert "replicas" in param_names

    def test_get_action_with_credentials(self) -> None:
        svc = self._make_service()
        detail = svc.get_action("ec2-stop-instance")
        assert detail is not None
        assert detail.credentials is not None
        assert detail.credentials["type"] == "aws"

    def test_get_action_reversible(self) -> None:
        svc = self._make_service()
        detail = svc.get_action("ec2-stop-instance")
        assert detail is not None
        assert detail.reversible is True
        assert detail.rollback_action == "ec2-start-instance"

    def test_action_count(self) -> None:
        svc = self._make_service()
        assert svc.action_count() >= 33

    def test_list_actions_sorted_by_name(self) -> None:
        svc = self._make_service()
        actions = svc.list_actions()
        names = [a.name for a in actions]
        assert names == sorted(names)

    def test_cache_invalidation(self) -> None:
        svc = self._make_service()
        count1 = svc.action_count()
        svc.invalidate_cache()
        count2 = svc.action_count()
        assert count1 == count2


# --- PolicyService Tests ---


class TestPolicyService:
    def _make_service(self) -> PolicyService:
        cfg = DashboardConfig(
            policies_dir=POLICIES_DIR,
            inventory_file=INVENTORY_FILE,
        )
        return PolicyService(cfg)

    def test_list_policies(self) -> None:
        svc = self._make_service()
        rules = svc.list_policies()
        assert len(rules) >= 1
        assert all(r.name for r in rules)

    def test_policies_sorted_by_priority(self) -> None:
        svc = self._make_service()
        rules = svc.list_policies()
        # load_policies returns highest priority first
        priorities = [r.priority for r in rules]
        assert priorities == sorted(priorities, reverse=True)

    def test_policy_has_decision(self) -> None:
        svc = self._make_service()
        rules = svc.list_policies()
        valid = {"allow", "deny", "require_approval"}
        for r in rules:
            assert r.decision in valid

    def test_match_analysis(self) -> None:
        svc = self._make_service()
        analysis = svc.get_match_analysis()
        assert len(analysis) >= 1
        for item in analysis:
            assert item.matching_target_count >= 0

    def test_match_analysis_no_inventory(self) -> None:
        cfg = DashboardConfig(
            policies_dir=POLICIES_DIR,
            inventory_file="/nonexistent/inventory.yaml",
        )
        svc = PolicyService(cfg)
        analysis = svc.get_match_analysis()
        for item in analysis:
            assert item.matching_target_count == 0

    def test_policy_count(self) -> None:
        svc = self._make_service()
        assert svc.policy_count() >= 1


# --- ActivityService Tests ---


class TestActivityService:
    def _make_service(self, events: list[dict]) -> ActivityService:
        log_path = _write_audit_log(events)
        cfg = DashboardConfig(audit_log=log_path)
        audit_svc = AuditService(cfg)
        return ActivityService(audit_svc)

    def test_get_feed_empty(self) -> None:
        svc = self._make_service([])
        feed = svc.get_feed()
        assert feed == []

    def test_get_feed_returns_items(self) -> None:
        events = [_make_event(event_id=f"evt-{i}") for i in range(5)]
        svc = self._make_service(events)
        feed = svc.get_feed(limit=3)
        assert len(feed) == 3

    def test_get_feed_newest_first(self) -> None:
        events = [
            _make_event(event_id="evt-old", timestamp="2025-01-15T08:00:00+00:00"),
            _make_event(event_id="evt-new", timestamp="2025-01-15T12:00:00+00:00"),
        ]
        svc = self._make_service(events)
        feed = svc.get_feed()
        assert feed[0].event_id == "evt-new"

    def test_get_recent_decisions(self) -> None:
        events = [
            _make_event(event_id="evt-1", event_type="decision"),
            _make_event(event_id="evt-2", event_type="state_capture"),
            _make_event(event_id="evt-3", event_type="decision"),
        ]
        svc = self._make_service(events)
        decisions = svc.get_recent_decisions()
        assert len(decisions) == 2
        for d in decisions:
            assert d.event_type == "decision"

    def test_get_recent_decisions_limit(self) -> None:
        events = [
            _make_event(event_id=f"evt-{i}", event_type="decision")
            for i in range(20)
        ]
        svc = self._make_service(events)
        decisions = svc.get_recent_decisions(limit=5)
        assert len(decisions) == 5
