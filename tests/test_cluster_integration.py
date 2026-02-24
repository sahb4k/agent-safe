"""Integration tests for the multi-cluster pipeline.

Tests the full flow: AuditLogger → DashboardShipper → ingest endpoint → query back.
These verify that serialization, auth, and data integrity work end-to-end.
"""

from __future__ import annotations

import tempfile
import warnings
from datetime import UTC, datetime
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from dashboard.backend.app import create_app  # noqa: E402
from dashboard.backend.config import DashboardConfig  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from agent_safe.audit.logger import AuditLogger, ShipperWarning  # noqa: E402
from agent_safe.models import (  # noqa: E402
    AuditEvent,
    Decision,
    DecisionResult,
    RiskClass,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")

SIGNING_KEY = "integration-test-key-" + "y" * 44


def _make_dashboard() -> tuple[TestClient, DashboardConfig]:
    """Create a team-tier dashboard TestClient with full cluster support."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
    ) as f:
        log_path = f.name

    config = DashboardConfig(
        actions_dir=ACTIONS_DIR,
        policies_dir=POLICIES_DIR,
        inventory_file=INVENTORY_FILE,
        audit_log=log_path,
        tier="team",
        signing_key=SIGNING_KEY,
        admin_username="admin",
        admin_password="adminpass",
        db_path=tempfile.mktemp(suffix=".db"),
    )
    app = create_app(config)
    return TestClient(app), config


def _admin_headers(client: TestClient) -> dict:
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    return {"Authorization": f"Bearer {login.json()['token']}"}


def _register_cluster(client: TestClient, headers: dict, name: str) -> tuple[str, str]:
    """Register a cluster, return (cluster_id, api_key)."""
    resp = client.post(
        "/api/clusters/", json={"name": name}, headers=headers
    )
    assert resp.status_code == 201
    data = resp.json()
    return data["cluster"]["cluster_id"], data["api_key"]


def _make_decision(
    action: str = "restart-deployment",
    target: str = "dev/test-app",
    caller: str = "agent-01",
    result: DecisionResult = DecisionResult.ALLOW,
    risk: RiskClass = RiskClass.LOW,
    policy: str = "allow-dev-all",
) -> Decision:
    return Decision(
        result=result,
        reason=f"Matched {policy}",
        action=action,
        target=target,
        caller=caller,
        risk_class=risk,
        effective_risk=risk,
        policy_matched=policy,
        audit_id=f"evt-{action}-{target}",
    )


# ------------------------------------------------------------------
# Serialization Round-Trip
# ------------------------------------------------------------------


class TestSerializationRoundTrip:
    """Verify that AuditEvent → DashboardShipper JSON → ingest → DB
    preserves all fields correctly."""

    def test_full_event_fields_preserved(self) -> None:
        """Create a fully-populated AuditEvent, serialize exactly as
        DashboardShipper does, POST to ingest, then query back and
        verify every field matches."""
        client, _config = _make_dashboard()
        headers = _admin_headers(client)
        cluster_id, api_key = _register_cluster(client, headers, "roundtrip-cluster")

        # Create a real AuditEvent with ALL fields populated
        event = AuditEvent(
            event_id="evt-roundtrip-001",
            timestamp=datetime(2025, 6, 15, 14, 30, 0, tzinfo=UTC),
            prev_hash="abc123",
            entry_hash="def456",
            event_type="decision",
            action="scale-deployment",
            target="prod/api-gateway",
            caller="deploy-agent-07",
            params={"replicas": 5, "strategy": "rolling"},
            decision=DecisionResult.DENY,
            reason="Production scaling requires approval",
            policy_matched="deny-prod-scaling",
            risk_class=RiskClass.HIGH,
            effective_risk=RiskClass.CRITICAL,
            correlation_id="corr-xyz-789",
            ticket_id="tkt-999",
            context={"environment": "production", "region": "us-east-1"},
        )

        # Serialize EXACTLY as DashboardShipper does
        body = {"events": [event.model_dump(mode="json")]}

        resp = client.post(
            "/api/clusters/ingest",
            json=body,
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        assert resp.json()["accepted"] == 1

        # Query it back
        events_resp = client.get(
            f"/api/clusters/{cluster_id}/events", headers=headers
        )
        assert events_resp.status_code == 200
        items = events_resp.json()["items"]
        assert len(items) == 1

        stored = items[0]
        assert stored["event_id"] == "evt-roundtrip-001"
        assert stored["action"] == "scale-deployment"
        assert stored["target"] == "prod/api-gateway"
        assert stored["caller"] == "deploy-agent-07"
        assert stored["decision"] == "deny"
        assert stored["reason"] == "Production scaling requires approval"
        assert stored["risk_class"] == "high"
        assert stored["effective_risk"] == "critical"
        assert stored["policy_matched"] == "deny-prod-scaling"
        assert stored["correlation_id"] == "corr-xyz-789"
        assert stored["event_type"] == "decision"
        assert stored["cluster_id"] == cluster_id

    def test_minimal_event_fields(self) -> None:
        """An event with only required fields should ingest and query back."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cluster_id, api_key = _register_cluster(client, headers, "minimal-cluster")

        body = {
            "events": [{
                "event_id": "evt-minimal-1",
                "timestamp": "2025-01-01T00:00:00+00:00",
                "action": "test-action",
                "target": "test/target",
                "caller": "agent",
                "decision": "allow",
                "risk_class": "low",
                "effective_risk": "low",
            }]
        }
        resp = client.post(
            "/api/clusters/ingest",
            json=body,
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        assert resp.json()["accepted"] == 1

    def test_state_capture_event_type(self) -> None:
        """Non-decision event types should be stored correctly."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cluster_id, api_key = _register_cluster(client, headers, "state-capture-cluster")

        body = {
            "events": [{
                "event_id": "evt-state-1",
                "timestamp": "2025-01-15T10:00:00+00:00",
                "event_type": "state_capture",
                "action": "restart-deployment",
                "target": "dev/app",
                "caller": "agent-01",
                "decision": "allow",
                "risk_class": "low",
                "effective_risk": "low",
            }]
        }
        resp = client.post(
            "/api/clusters/ingest",
            json=body,
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.json()["accepted"] == 1

        events_resp = client.get(
            f"/api/clusters/{cluster_id}/events",
            params={"event_type": "state_capture"},
            headers=headers,
        )
        assert events_resp.json()["total"] == 1
        assert events_resp.json()["items"][0]["event_type"] == "state_capture"


# ------------------------------------------------------------------
# AuditLogger → DashboardShipper → Ingest Pipeline
# ------------------------------------------------------------------


class _TestClientShipper:
    """A shipper that routes to a TestClient instead of making real HTTP calls.

    This simulates what DashboardShipper does but uses TestClient as
    the transport, enabling end-to-end testing without a real server.
    """

    def __init__(self, client: TestClient, api_key: str) -> None:
        self._client = client
        self._api_key = api_key

    def ship(self, event: AuditEvent) -> None:
        envelope = {
            "events": [event.model_dump(mode="json")],
        }
        resp = self._client.post(
            "/api/clusters/ingest",
            json=envelope,
            headers={"Authorization": f"Bearer {self._api_key}"},
        )
        if resp.status_code != 200:
            raise ConnectionError(f"Ingest failed: {resp.status_code} {resp.text}")


class TestAuditLoggerPipeline:
    """Test the full pipeline: AuditLogger.log_decision() → shipper → ingest → DB."""

    def test_log_decision_ships_to_dashboard(self, tmp_path: Path) -> None:
        """A logged decision should appear in both the local JSONL and the dashboard DB."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cluster_id, api_key = _register_cluster(client, headers, "logger-pipeline")

        shipper = _TestClientShipper(client, api_key)
        logger = AuditLogger(tmp_path / "audit.jsonl", shippers=[shipper])

        decision = _make_decision(
            action="restart-deployment",
            target="prod/web-server",
            caller="deploy-agent-03",
            result=DecisionResult.DENY,
            risk=RiskClass.HIGH,
        )
        event = logger.log_decision(decision, params={"force": True})

        # 1. Event should be in local JSONL
        local_events = logger.read_events()
        assert len(local_events) == 1
        assert local_events[0].event_id == event.event_id

        # 2. Event should be in dashboard DB
        resp = client.get(f"/api/clusters/{cluster_id}/events", headers=headers)
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["event_id"] == event.event_id
        assert items[0]["action"] == "restart-deployment"
        assert items[0]["target"] == "prod/web-server"
        assert items[0]["decision"] == "deny"
        assert items[0]["risk_class"] == "high"

    def test_multiple_decisions_ship_sequentially(self, tmp_path: Path) -> None:
        """Multiple logged decisions should all arrive in the dashboard."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cluster_id, api_key = _register_cluster(client, headers, "multi-decision")

        shipper = _TestClientShipper(client, api_key)
        logger = AuditLogger(tmp_path / "audit.jsonl", shippers=[shipper])

        actions = ["restart-deployment", "scale-deployment", "rollback-deployment"]
        for action in actions:
            decision = _make_decision(action=action)
            logger.log_decision(decision)

        resp = client.get(f"/api/clusters/{cluster_id}/events", headers=headers)
        assert resp.json()["total"] == 3
        stored_actions = {item["action"] for item in resp.json()["items"]}
        assert stored_actions == set(actions)

    def test_hash_chain_fields_dont_break_ingestion(self, tmp_path: Path) -> None:
        """AuditLogger adds prev_hash and entry_hash. These should
        pass through ingestion without errors."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cluster_id, api_key = _register_cluster(client, headers, "hashchain")

        shipper = _TestClientShipper(client, api_key)
        logger = AuditLogger(tmp_path / "audit.jsonl", shippers=[shipper])

        d1 = _make_decision(action="action-1", target="dev/app1")
        d2 = _make_decision(action="action-2", target="dev/app2")
        e1 = logger.log_decision(d1)
        e2 = logger.log_decision(d2)

        # Verify hash chain is valid locally
        assert e1.prev_hash != ""
        assert e2.prev_hash == e1.entry_hash

        # Both should be in dashboard
        resp = client.get(f"/api/clusters/{cluster_id}/events", headers=headers)
        assert resp.json()["total"] == 2


# ------------------------------------------------------------------
# Multi-Cluster Aggregation
# ------------------------------------------------------------------


class TestMultiClusterAggregation:
    """Test querying events across multiple registered clusters."""

    def _setup_clusters(self) -> tuple[TestClient, dict, list[tuple[str, str]]]:
        """Register 3 clusters with different events."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        clusters = []
        for name in ["prod-east", "prod-west", "staging"]:
            cid, key = _register_cluster(client, headers, name)
            clusters.append((cid, key))
        return client, headers, clusters

    def _ingest(self, client: TestClient, api_key: str, events: list[dict]) -> None:
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": events},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200

    def test_aggregated_view_shows_all_clusters(self) -> None:
        client, headers, clusters = self._setup_clusters()

        # Ingest different events to each cluster
        self._ingest(client, clusters[0][1], [
            {"event_id": "east-1", "timestamp": "2025-01-15T10:00:00+00:00",
             "action": "deploy", "target": "prod/api", "caller": "agent-01",
             "decision": "allow", "risk_class": "low", "effective_risk": "low"},
        ])
        self._ingest(client, clusters[1][1], [
            {"event_id": "west-1", "timestamp": "2025-01-15T11:00:00+00:00",
             "action": "scale", "target": "prod/web", "caller": "agent-02",
             "decision": "deny", "risk_class": "high", "effective_risk": "high"},
        ])
        self._ingest(client, clusters[2][1], [
            {"event_id": "stg-1", "timestamp": "2025-01-15T12:00:00+00:00",
             "action": "restart", "target": "staging/db", "caller": "agent-03",
             "decision": "allow", "risk_class": "medium", "effective_risk": "medium"},
        ])

        # Aggregated view should show all 3
        resp = client.get("/api/clusters/events", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 3

    def test_per_cluster_filtering(self) -> None:
        client, headers, clusters = self._setup_clusters()

        self._ingest(client, clusters[0][1], [
            {"event_id": f"east-{i}", "timestamp": "2025-01-15T10:00:00+00:00",
             "action": "deploy", "target": "prod/api", "caller": "agent-01",
             "decision": "allow", "risk_class": "low", "effective_risk": "low"}
            for i in range(5)
        ])
        self._ingest(client, clusters[1][1], [
            {"event_id": f"west-{i}", "timestamp": "2025-01-15T10:00:00+00:00",
             "action": "deploy", "target": "prod/api", "caller": "agent-01",
             "decision": "allow", "risk_class": "low", "effective_risk": "low"}
            for i in range(3)
        ])

        # Per-cluster query should only show that cluster's events
        resp_east = client.get(
            f"/api/clusters/{clusters[0][0]}/events", headers=headers
        )
        assert resp_east.json()["total"] == 5

        resp_west = client.get(
            f"/api/clusters/{clusters[1][0]}/events", headers=headers
        )
        assert resp_west.json()["total"] == 3

        # Aggregated shows all
        resp_all = client.get("/api/clusters/events", headers=headers)
        assert resp_all.json()["total"] == 8

    def test_aggregated_stats(self) -> None:
        client, headers, clusters = self._setup_clusters()

        self._ingest(client, clusters[0][1], [
            {"event_id": "e1", "timestamp": "2025-01-15T10:00:00+00:00",
             "action": "deploy", "target": "prod/api", "caller": "a",
             "decision": "allow", "risk_class": "low", "effective_risk": "low"},
        ])
        self._ingest(client, clusters[1][1], [
            {"event_id": "e2", "timestamp": "2025-01-15T10:00:00+00:00",
             "action": "scale", "target": "prod/web", "caller": "b",
             "decision": "deny", "risk_class": "high", "effective_risk": "high"},
        ])

        # Aggregated stats
        resp = client.get("/api/clusters/stats", headers=headers)
        assert resp.status_code == 200
        stats = resp.json()
        assert stats["total_events"] == 2
        assert stats["by_decision"]["allow"] == 1
        assert stats["by_decision"]["deny"] == 1

        # Per-cluster stats
        resp_east = client.get(
            f"/api/clusters/{clusters[0][0]}/stats", headers=headers
        )
        assert resp_east.json()["total_events"] == 1
        assert resp_east.json()["by_decision"]["allow"] == 1

    def test_cluster_event_count_in_listing(self) -> None:
        """Cluster listing should show correct event_count per cluster."""
        client, headers, clusters = self._setup_clusters()

        self._ingest(client, clusters[0][1], [
            {"event_id": f"e{i}", "timestamp": "2025-01-15T10:00:00+00:00",
             "action": "deploy", "target": "t", "caller": "a",
             "decision": "allow", "risk_class": "low", "effective_risk": "low"}
            for i in range(7)
        ])

        resp = client.get("/api/clusters/", headers=headers)
        cluster_list = resp.json()
        east = next(c for c in cluster_list if c["name"] == "prod-east")
        assert east["event_count"] == 7
        west = next(c for c in cluster_list if c["name"] == "prod-west")
        assert west["event_count"] == 0


# ------------------------------------------------------------------
# Auth Edge Cases
# ------------------------------------------------------------------


class TestAuthEdgeCases:
    def test_deactivated_cluster_rejects_ingest(self) -> None:
        """After deactivating a cluster, its API key should be rejected."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cluster_id, api_key = _register_cluster(client, headers, "to-deactivate")

        # Ingest works initially
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [{"event_id": "e1", "timestamp": "2025-01-01T00:00:00Z",
                              "action": "a", "target": "t", "caller": "c",
                              "decision": "allow", "risk_class": "low",
                              "effective_risk": "low"}]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200

        # Deactivate
        client.delete(f"/api/clusters/{cluster_id}", headers=headers)

        # Now ingest should be rejected
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [{"event_id": "e2", "timestamp": "2025-01-01T00:00:00Z",
                              "action": "a", "target": "t", "caller": "c",
                              "decision": "allow", "risk_class": "low",
                              "effective_risk": "low"}]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 401

    def test_wrong_api_key_rejected(self) -> None:
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        _register_cluster(client, headers, "wrong-key-cluster")

        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [{"event_id": "e1", "timestamp": "2025-01-01T00:00:00Z",
                              "action": "a", "target": "t", "caller": "c",
                              "decision": "allow", "risk_class": "low",
                              "effective_risk": "low"}]},
            headers={"Authorization": "Bearer ask_totally_fake_key_1234567890"},
        )
        assert resp.status_code == 401

    def test_jwt_session_token_not_accepted_for_ingest(self) -> None:
        """The ingest endpoint should only accept API keys, not JWT sessions."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        _register_cluster(client, headers, "jwt-test-cluster")

        # Try using the admin JWT token for ingest
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [{"event_id": "e1", "timestamp": "2025-01-01T00:00:00Z",
                              "action": "a", "target": "t", "caller": "c",
                              "decision": "allow", "risk_class": "low",
                              "effective_risk": "low"}]},
            headers=headers,  # This is a JWT, not an API key
        )
        assert resp.status_code == 401

    def test_cluster_a_key_cannot_ingest_to_cluster_b(self) -> None:
        """Each cluster's API key should only record events under that cluster."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cid_a, key_a = _register_cluster(client, headers, "cluster-a")
        cid_b, key_b = _register_cluster(client, headers, "cluster-b")

        # Ingest with key_a
        client.post(
            "/api/clusters/ingest",
            json={"events": [{"event_id": "from-a", "timestamp": "2025-01-01T00:00:00Z",
                              "action": "deploy", "target": "t", "caller": "c",
                              "decision": "allow", "risk_class": "low",
                              "effective_risk": "low"}]},
            headers={"Authorization": f"Bearer {key_a}"},
        )

        # Events should be under cluster A, not B
        resp_a = client.get(f"/api/clusters/{cid_a}/events", headers=headers)
        assert resp_a.json()["total"] == 1

        resp_b = client.get(f"/api/clusters/{cid_b}/events", headers=headers)
        assert resp_b.json()["total"] == 0


# ------------------------------------------------------------------
# Event Deduplication
# ------------------------------------------------------------------


class TestEventDeduplication:
    def test_duplicate_event_ids_across_clusters_allowed(self) -> None:
        """Same event_id in different clusters should both be stored."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        cid_a, key_a = _register_cluster(client, headers, "dedup-a")
        cid_b, key_b = _register_cluster(client, headers, "dedup-b")

        event = {"event_id": "same-id", "timestamp": "2025-01-01T00:00:00Z",
                 "action": "deploy", "target": "t", "caller": "c",
                 "decision": "allow", "risk_class": "low", "effective_risk": "low"}

        resp_a = client.post(
            "/api/clusters/ingest", json={"events": [event]},
            headers={"Authorization": f"Bearer {key_a}"},
        )
        assert resp_a.json()["accepted"] == 1

        resp_b = client.post(
            "/api/clusters/ingest", json={"events": [event]},
            headers={"Authorization": f"Bearer {key_b}"},
        )
        assert resp_b.json()["accepted"] == 1

        # Both should be stored
        resp_all = client.get("/api/clusters/events", headers=headers)
        assert resp_all.json()["total"] == 2

    def test_duplicate_within_same_cluster_rejected(self) -> None:
        """Re-sending the same event_id to the same cluster should be a duplicate."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        _cid, api_key = _register_cluster(client, headers, "dedup-same")

        event = {"event_id": "dup-1", "timestamp": "2025-01-01T00:00:00Z",
                 "action": "deploy", "target": "t", "caller": "c",
                 "decision": "allow", "risk_class": "low", "effective_risk": "low"}

        r1 = client.post(
            "/api/clusters/ingest", json={"events": [event]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert r1.json()["accepted"] == 1

        r2 = client.post(
            "/api/clusters/ingest", json={"events": [event]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert r2.json()["accepted"] == 0
        assert r2.json()["duplicates"] == 1

    def test_batch_with_mixed_new_and_duplicate(self) -> None:
        """A batch containing both new and duplicate events should partially succeed."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        _cid, api_key = _register_cluster(client, headers, "mixed-batch")

        # First batch
        client.post(
            "/api/clusters/ingest",
            json={"events": [
                {"event_id": "existing-1", "timestamp": "2025-01-01T00:00:00Z",
                 "action": "a", "target": "t", "caller": "c",
                 "decision": "allow", "risk_class": "low", "effective_risk": "low"},
            ]},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Second batch: 1 duplicate + 2 new
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [
                {"event_id": "existing-1", "timestamp": "2025-01-01T00:00:00Z",
                 "action": "a", "target": "t", "caller": "c",
                 "decision": "allow", "risk_class": "low", "effective_risk": "low"},
                {"event_id": "new-1", "timestamp": "2025-01-01T00:00:00Z",
                 "action": "a", "target": "t", "caller": "c",
                 "decision": "allow", "risk_class": "low", "effective_risk": "low"},
                {"event_id": "new-2", "timestamp": "2025-01-01T00:00:00Z",
                 "action": "a", "target": "t", "caller": "c",
                 "decision": "allow", "risk_class": "low", "effective_risk": "low"},
            ]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.json()["accepted"] == 2
        assert resp.json()["duplicates"] == 1


# ------------------------------------------------------------------
# Shipper Error Handling
# ------------------------------------------------------------------


class TestShipperErrorHandling:
    def test_broken_ingest_doesnt_block_local_logging(self, tmp_path: Path) -> None:
        """If the dashboard is unreachable, local logging should still work
        and a warning should be emitted."""
        client, _ = _make_dashboard()

        class _BrokenShipper:
            def ship(self, event: AuditEvent) -> None:
                raise ConnectionError("Dashboard unreachable")

        logger = AuditLogger(tmp_path / "audit.jsonl", shippers=[_BrokenShipper()])

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            decision = _make_decision()
            event = logger.log_decision(decision)

        # Local log should still have the event
        local_events = logger.read_events()
        assert len(local_events) == 1
        assert local_events[0].event_id == event.event_id

        # Warning should have been emitted
        shipper_warnings = [x for x in w if issubclass(x.category, ShipperWarning)]
        assert len(shipper_warnings) == 1
        assert "Dashboard unreachable" in str(shipper_warnings[0].message)

    def test_ingest_endpoint_rejects_malformed_events(self) -> None:
        """Events missing required fields should be counted as errors."""
        client, _ = _make_dashboard()
        headers = _admin_headers(client)
        _cid, api_key = _register_cluster(client, headers, "malformed-test")

        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [
                {},  # No event_id
                {"event_id": ""},  # Empty event_id
                {"event_id": "good-1", "timestamp": "2025-01-01T00:00:00Z",
                 "action": "a", "target": "t", "caller": "c",
                 "decision": "allow", "risk_class": "low", "effective_risk": "low"},
            ]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        data = resp.json()
        assert data["accepted"] == 1
        assert data["errors"] == 2
