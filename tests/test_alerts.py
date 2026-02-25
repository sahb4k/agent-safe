"""Tests for alert rules, alert engine, and alert API endpoints."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from dashboard.backend.alerts.engine import AlertEngine  # noqa: E402
from dashboard.backend.alerts.models import (  # noqa: E402
    AlertChannels,
    AlertConditions,
    AlertRuleCreateRequest,
    AlertRuleUpdateRequest,
)
from dashboard.backend.alerts.service import AlertService  # noqa: E402
from dashboard.backend.app import create_app  # noqa: E402
from dashboard.backend.config import DashboardConfig  # noqa: E402
from dashboard.backend.db.connection import Database  # noqa: E402
from dashboard.backend.db.migrations import run_migrations  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")
SIGNING_KEY = "alert-test-key-" + "z" * 49


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    d = Database(str(tmp_path / "test.db"))
    run_migrations(d)
    return d


@pytest.fixture()
def alert_svc(db: Database) -> AlertService:
    return AlertService(db)


@pytest.fixture()
def engine(alert_svc: AlertService, db: Database) -> AlertEngine:
    return AlertEngine(alert_svc, db)


def _make_channels(**kwargs) -> AlertChannels:
    return AlertChannels(
        webhook_url=kwargs.get("webhook_url", "https://example.com/hook"),
        **{k: v for k, v in kwargs.items() if k != "webhook_url"},
    )


def _make_create_request(
    name: str = "test-rule",
    **kwargs,
) -> AlertRuleCreateRequest:
    return AlertRuleCreateRequest(
        name=name,
        description=kwargs.pop("description", "test"),
        conditions=kwargs.pop(
            "conditions",
            AlertConditions(risk_classes=["critical"]),
        ),
        channels=kwargs.pop("channels", _make_channels()),
        **kwargs,
    )


# ------------------------------------------------------------------
# AlertService — Rule CRUD
# ------------------------------------------------------------------


class TestAlertServiceCRUD:
    def test_create_rule(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(_make_create_request())
        assert rule.rule_id.startswith("alr-")
        assert rule.name == "test-rule"
        assert rule.is_active is True

    def test_create_duplicate_name_raises(self, alert_svc: AlertService) -> None:
        alert_svc.create_rule(_make_create_request("dup"))
        with pytest.raises(ValueError, match="already exists"):
            alert_svc.create_rule(_make_create_request("dup"))

    def test_create_invalid_threshold_raises(self, alert_svc: AlertService) -> None:
        with pytest.raises(ValueError, match="Threshold"):
            alert_svc.create_rule(_make_create_request(threshold=0))

    def test_create_invalid_window_raises(self, alert_svc: AlertService) -> None:
        with pytest.raises(ValueError, match="Window"):
            alert_svc.create_rule(_make_create_request(window_seconds=-1))

    def test_list_rules(self, alert_svc: AlertService) -> None:
        alert_svc.create_rule(_make_create_request("a"))
        alert_svc.create_rule(_make_create_request("b"))
        rules = alert_svc.list_rules()
        assert len(rules) == 2

    def test_list_rules_excludes_inactive(self, alert_svc: AlertService) -> None:
        alert_svc.create_rule(_make_create_request("active"))
        alert_svc.create_rule(_make_create_request("deleted"))
        alert_svc.delete_rule(alert_svc.list_rules()[-1].rule_id)
        rules = alert_svc.list_rules()
        assert len(rules) == 1
        assert rules[0].name == "active"

    def test_list_rules_includes_inactive(self, alert_svc: AlertService) -> None:
        alert_svc.create_rule(_make_create_request("a"))
        alert_svc.create_rule(_make_create_request("b"))
        alert_svc.delete_rule(alert_svc.list_rules()[0].rule_id)
        rules = alert_svc.list_rules(include_inactive=True)
        assert len(rules) == 2

    def test_get_rule(self, alert_svc: AlertService) -> None:
        created = alert_svc.create_rule(_make_create_request())
        found = alert_svc.get_rule(created.rule_id)
        assert found is not None
        assert found.name == "test-rule"

    def test_get_rule_not_found(self, alert_svc: AlertService) -> None:
        assert alert_svc.get_rule("nonexistent") is None

    def test_update_rule_name(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(_make_create_request())
        updated = alert_svc.update_rule(
            rule.rule_id,
            AlertRuleUpdateRequest(name="renamed"),
        )
        assert updated is not None
        assert updated.name == "renamed"

    def test_update_rule_conditions(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(_make_create_request())
        updated = alert_svc.update_rule(
            rule.rule_id,
            AlertRuleUpdateRequest(
                conditions=AlertConditions(decisions=["deny"]),
            ),
        )
        assert updated is not None
        assert updated.conditions.decisions == ["deny"]

    def test_update_rule_toggle_active(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(_make_create_request())
        updated = alert_svc.update_rule(
            rule.rule_id,
            AlertRuleUpdateRequest(is_active=False),
        )
        assert updated is not None
        assert updated.is_active is False

    def test_update_rule_duplicate_name_raises(self, alert_svc: AlertService) -> None:
        alert_svc.create_rule(_make_create_request("a"))
        rule_b = alert_svc.create_rule(_make_create_request("b"))
        with pytest.raises(ValueError, match="already exists"):
            alert_svc.update_rule(
                rule_b.rule_id,
                AlertRuleUpdateRequest(name="a"),
            )

    def test_update_nonexistent_returns_none(self, alert_svc: AlertService) -> None:
        result = alert_svc.update_rule(
            "missing", AlertRuleUpdateRequest(name="x"),
        )
        assert result is None

    def test_delete_rule(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(_make_create_request())
        assert alert_svc.delete_rule(rule.rule_id) is True
        # Should be soft-deleted (inactive)
        found = alert_svc.get_rule(rule.rule_id)
        assert found is not None
        assert found.is_active is False

    def test_delete_nonexistent(self, alert_svc: AlertService) -> None:
        assert alert_svc.delete_rule("missing") is False

    def test_rule_with_cluster_ids(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(
            _make_create_request(cluster_ids=["cl-1", "cl-2"]),
        )
        assert rule.cluster_ids == ["cl-1", "cl-2"]

    def test_rule_with_threshold(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(
            _make_create_request(threshold=5, window_seconds=600),
        )
        assert rule.threshold == 5
        assert rule.window_seconds == 600


# ------------------------------------------------------------------
# AlertService — History
# ------------------------------------------------------------------


class TestAlertServiceHistory:
    def test_record_and_list_history(self, alert_svc: AlertService) -> None:
        alert_svc.create_rule(_make_create_request("rule-1"))
        rule = alert_svc.list_rules()[0]

        row_id = alert_svc.record_alert(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            cluster_id="cluster-1",
            trigger_event_ids=["evt-1", "evt-2"],
            conditions=rule.conditions,
            notification_status="sent",
        )
        assert row_id > 0

        history = alert_svc.list_history()
        assert len(history) == 1
        assert history[0].rule_name == "rule-1"
        assert history[0].trigger_event_ids == ["evt-1", "evt-2"]
        assert history[0].notification_status == "sent"

    def test_list_history_filter_by_rule(self, alert_svc: AlertService) -> None:
        r1 = alert_svc.create_rule(_make_create_request("rule-a"))
        r2 = alert_svc.create_rule(_make_create_request("rule-b"))

        alert_svc.record_alert(r1.rule_id, "rule-a", "cl-1", [], r1.conditions, "sent")
        alert_svc.record_alert(r2.rule_id, "rule-b", "cl-1", [], r2.conditions, "sent")

        history = alert_svc.list_history(rule_id=r1.rule_id)
        assert len(history) == 1
        assert history[0].rule_name == "rule-a"

    def test_list_history_filter_by_cluster(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(_make_create_request())

        alert_svc.record_alert(rule.rule_id, rule.name, "cl-1", [], rule.conditions, "sent")
        alert_svc.record_alert(rule.rule_id, rule.name, "cl-2", [], rule.conditions, "sent")

        history = alert_svc.list_history(cluster_id="cl-2")
        assert len(history) == 1
        assert history[0].cluster_id == "cl-2"

    def test_history_with_error(self, alert_svc: AlertService) -> None:
        rule = alert_svc.create_rule(_make_create_request())
        alert_svc.record_alert(
            rule.rule_id, rule.name, "cl-1", [],
            rule.conditions, "failed", notification_error="timeout",
        )
        history = alert_svc.list_history()
        assert history[0].notification_status == "failed"
        assert history[0].notification_error == "timeout"


# ------------------------------------------------------------------
# AlertEngine — Event Matching
# ------------------------------------------------------------------


class TestAlertEngineMatching:
    def test_match_risk_class(self) -> None:
        conds = AlertConditions(risk_classes=["critical", "high"])
        assert AlertEngine._event_matches({"risk_class": "critical"}, conds) is True
        assert AlertEngine._event_matches({"risk_class": "low"}, conds) is False

    def test_match_decision(self) -> None:
        conds = AlertConditions(decisions=["deny"])
        assert AlertEngine._event_matches({"decision": "deny"}, conds) is True
        assert AlertEngine._event_matches({"decision": "allow"}, conds) is False

    def test_match_event_type(self) -> None:
        conds = AlertConditions(event_types=["action_denied"])
        assert AlertEngine._event_matches({"event_type": "action_denied"}, conds) is True
        assert AlertEngine._event_matches({"event_type": "action_executed"}, conds) is False

    def test_match_action_pattern(self) -> None:
        conds = AlertConditions(action_patterns=["deploy.*", "db.drop_*"])
        assert AlertEngine._event_matches({"action": "deploy.prod"}, conds) is True
        assert AlertEngine._event_matches({"action": "db.drop_table"}, conds) is True
        assert AlertEngine._event_matches({"action": "restart.service"}, conds) is False

    def test_match_empty_conditions(self) -> None:
        conds = AlertConditions()
        assert AlertEngine._event_matches({"action": "anything"}, conds) is True

    def test_match_combined_conditions(self) -> None:
        conds = AlertConditions(
            risk_classes=["critical"],
            decisions=["deny"],
        )
        assert AlertEngine._event_matches(
            {"risk_class": "critical", "decision": "deny"}, conds,
        ) is True
        assert AlertEngine._event_matches(
            {"risk_class": "critical", "decision": "allow"}, conds,
        ) is False


# ------------------------------------------------------------------
# AlertEngine — Evaluate Batch
# ------------------------------------------------------------------


class TestAlertEngineEvaluate:
    def test_evaluate_fires_on_match(
        self, alert_svc: AlertService, engine: AlertEngine,
    ) -> None:
        alert_svc.create_rule(_make_create_request(
            conditions=AlertConditions(risk_classes=["critical"]),
        ))

        events = [
            {"event_id": "evt-1", "risk_class": "critical", "decision": "deny"},
        ]

        with patch.object(engine, "_send_notifications"):
            engine.evaluate_batch("cluster-1", events)

        history = alert_svc.list_history()
        assert len(history) == 1
        assert history[0].cluster_id == "cluster-1"

    def test_evaluate_no_match(
        self, alert_svc: AlertService, engine: AlertEngine,
    ) -> None:
        alert_svc.create_rule(_make_create_request(
            conditions=AlertConditions(risk_classes=["critical"]),
        ))

        events = [
            {"event_id": "evt-1", "risk_class": "low", "decision": "allow"},
        ]

        engine.evaluate_batch("cluster-1", events)
        assert len(alert_svc.list_history()) == 0

    def test_evaluate_respects_cluster_scope(
        self, alert_svc: AlertService, engine: AlertEngine,
    ) -> None:
        alert_svc.create_rule(_make_create_request(
            conditions=AlertConditions(risk_classes=["critical"]),
            cluster_ids=["cluster-a"],
        ))

        events = [{"event_id": "evt-1", "risk_class": "critical"}]

        with patch.object(engine, "_send_notifications"):
            engine.evaluate_batch("cluster-b", events)  # wrong cluster

        assert len(alert_svc.list_history()) == 0

    def test_evaluate_respects_cooldown(
        self, alert_svc: AlertService, engine: AlertEngine,
    ) -> None:
        alert_svc.create_rule(_make_create_request(
            conditions=AlertConditions(risk_classes=["critical"]),
            cooldown_seconds=3600,
        ))

        events = [{"event_id": "evt-1", "risk_class": "critical"}]

        with patch.object(engine, "_send_notifications"):
            engine.evaluate_batch("cluster-1", events)
            engine.evaluate_batch("cluster-1", events)  # should be in cooldown

        assert len(alert_svc.list_history()) == 1  # Only one fired

    def test_evaluate_catches_exceptions(
        self, alert_svc: AlertService, engine: AlertEngine,
    ) -> None:
        """evaluate_batch should swallow exceptions, not crash."""
        alert_svc.create_rule(_make_create_request(
            conditions=AlertConditions(risk_classes=["critical"]),
        ))

        events = [{"event_id": "evt-1", "risk_class": "critical"}]

        with patch.object(engine, "_evaluate", side_effect=RuntimeError("boom")):
            engine.evaluate_batch("cluster-1", events)  # should not raise


# ------------------------------------------------------------------
# AlertEngine — Notifications
# ------------------------------------------------------------------


class TestAlertEngineNotifications:
    def test_notification_failure_recorded(
        self, alert_svc: AlertService, engine: AlertEngine,
    ) -> None:
        alert_svc.create_rule(_make_create_request(
            conditions=AlertConditions(risk_classes=["critical"]),
            cooldown_seconds=0,
        ))

        events = [{"event_id": "evt-1", "risk_class": "critical"}]

        with patch.object(
            engine, "_send_notifications", side_effect=Exception("timeout"),
        ):
            engine.evaluate_batch("cluster-1", events)

        history = alert_svc.list_history()
        assert len(history) == 1
        assert history[0].notification_status == "failed"
        assert "timeout" in (history[0].notification_error or "")


# ------------------------------------------------------------------
# Alert API Endpoints
# ------------------------------------------------------------------


def _write_audit_log() -> str:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
    ) as f:
        return f.name


def _make_team_client() -> TestClient:
    config = DashboardConfig(
        actions_dir=ACTIONS_DIR,
        policies_dir=POLICIES_DIR,
        inventory_file=INVENTORY_FILE,
        audit_log=_write_audit_log(),
        tier="team",
        signing_key=SIGNING_KEY,
        admin_username="admin",
        admin_password="adminpass",
        db_path=tempfile.mktemp(suffix=".db"),
    )
    app = create_app(config)
    return TestClient(app)


def _admin_headers(client: TestClient) -> dict:
    resp = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "adminpass"},
    )
    return {"Authorization": f"Bearer {resp.json()['token']}"}


class TestAlertAPI:
    def test_list_rules_empty(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/alerts/rules", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_rule(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.post(
            "/api/alerts/rules",
            json={
                "name": "critical-deny",
                "description": "Alert on critical denies",
                "conditions": {"risk_classes": ["critical"], "decisions": ["deny"]},
                "channels": {"webhook_url": "https://example.com/hook"},
            },
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "critical-deny"
        assert data["rule_id"].startswith("alr-")

    def test_create_duplicate_rule(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        body = {
            "name": "dup",
            "channels": {"webhook_url": "https://example.com/hook"},
        }
        client.post("/api/alerts/rules", json=body, headers=headers)
        resp = client.post("/api/alerts/rules", json=body, headers=headers)
        assert resp.status_code == 409

    def test_get_rule(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create_resp = client.post(
            "/api/alerts/rules",
            json={
                "name": "test",
                "channels": {"webhook_url": "https://example.com/hook"},
            },
            headers=headers,
        )
        rule_id = create_resp.json()["rule_id"]
        resp = client.get(f"/api/alerts/rules/{rule_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "test"

    def test_get_rule_not_found(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/alerts/rules/nonexistent", headers=headers)
        assert resp.status_code == 404

    def test_update_rule(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create_resp = client.post(
            "/api/alerts/rules",
            json={
                "name": "orig",
                "channels": {"webhook_url": "https://example.com/hook"},
            },
            headers=headers,
        )
        rule_id = create_resp.json()["rule_id"]
        resp = client.put(
            f"/api/alerts/rules/{rule_id}",
            json={"name": "updated"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "updated"

    def test_delete_rule(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create_resp = client.post(
            "/api/alerts/rules",
            json={
                "name": "to-delete",
                "channels": {"webhook_url": "https://example.com/hook"},
            },
            headers=headers,
        )
        rule_id = create_resp.json()["rule_id"]
        resp = client.delete(f"/api/alerts/rules/{rule_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_list_history_empty(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/alerts/history", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == []

    def test_alerts_require_auth(self) -> None:
        client = _make_team_client()
        resp = client.get("/api/alerts/rules")
        assert resp.status_code == 401


# ------------------------------------------------------------------
# Tier Gating
# ------------------------------------------------------------------


class TestAlertTierGating:
    def test_team_tier_has_alerts(self) -> None:
        from dashboard.backend.auth.tier import has_feature
        assert has_feature("team", "alerts") is True

    def test_enterprise_tier_has_alerts(self) -> None:
        from dashboard.backend.auth.tier import has_feature
        assert has_feature("enterprise", "alerts") is True

    def test_free_tier_no_alerts(self) -> None:
        from dashboard.backend.auth.tier import has_feature
        assert has_feature("free", "alerts") is False
