"""Tests for multi-cluster registration, event ingestion, and aggregation."""

from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from dashboard.backend.app import create_app  # noqa: E402
from dashboard.backend.clusters.service import ClusterService  # noqa: E402
from dashboard.backend.config import DashboardConfig  # noqa: E402
from dashboard.backend.db.connection import Database  # noqa: E402
from dashboard.backend.db.migrations import get_schema_version, run_migrations  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")

SIGNING_KEY = "cluster-test-key-" + "x" * 48


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    d = Database(str(tmp_path / "test.db"))
    run_migrations(d)
    return d


@pytest.fixture()
def cluster_svc(db: Database) -> ClusterService:
    return ClusterService(db)


def _make_event(
    event_id: str = "evt-1",
    action: str = "restart-deployment",
    target: str = "dev/test",
    caller: str = "agent-01",
    decision: str = "allow",
    risk_class: str = "low",
    event_type: str = "decision",
    timestamp: str = "2025-01-15T10:00:00+00:00",
) -> dict:
    return {
        "event_id": event_id,
        "timestamp": timestamp,
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


def _make_team_client() -> TestClient:
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
    return TestClient(app)


def _admin_headers(client: TestClient) -> dict:
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    token = login.json()["token"]
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------------------
# Migration
# ------------------------------------------------------------------


class TestMigrationV2:
    def test_migration_creates_clusters_table(self, db: Database) -> None:
        rows = db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='clusters'"
        )
        assert len(rows) == 1

    def test_migration_creates_cluster_events_table(self, db: Database) -> None:
        rows = db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cluster_events'"
        )
        assert len(rows) == 1

    def test_schema_version_is_3(self, db: Database) -> None:
        assert get_schema_version(db) == 3

    def test_migration_idempotent(self, db: Database) -> None:
        run_migrations(db)
        run_migrations(db)
        assert get_schema_version(db) == 3


# ------------------------------------------------------------------
# Cluster Registration
# ------------------------------------------------------------------


class TestClusterRegistration:
    def test_register_cluster(self, cluster_svc: ClusterService) -> None:
        result = cluster_svc.register_cluster("prod-east", description="US East prod")
        assert result.cluster.name == "prod-east"
        assert result.cluster.description == "US East prod"
        assert result.cluster.is_active is True
        assert result.cluster.cluster_id.startswith("clu-")
        assert result.api_key.startswith("ask_")

    def test_register_duplicate_raises(self, cluster_svc: ClusterService) -> None:
        cluster_svc.register_cluster("prod-east")
        with pytest.raises(ValueError, match="already exists"):
            cluster_svc.register_cluster("prod-east")

    def test_api_key_prefix_stored(self, cluster_svc: ClusterService) -> None:
        result = cluster_svc.register_cluster("test-cluster")
        assert result.cluster.api_key_prefix == result.api_key[:12]

    def test_api_key_hash_stored(self, cluster_svc: ClusterService, db: Database) -> None:
        result = cluster_svc.register_cluster("hash-test")
        expected_hash = hashlib.sha256(result.api_key.encode()).hexdigest()
        row = db.fetchone(
            "SELECT api_key_hash FROM clusters WHERE cluster_id = ?",
            (result.cluster.cluster_id,),
        )
        assert row is not None
        assert row["api_key_hash"] == expected_hash


# ------------------------------------------------------------------
# Cluster Listing
# ------------------------------------------------------------------


class TestClusterListing:
    def test_list_empty(self, cluster_svc: ClusterService) -> None:
        assert cluster_svc.list_clusters() == []

    def test_list_clusters(self, cluster_svc: ClusterService) -> None:
        cluster_svc.register_cluster("cluster-a")
        cluster_svc.register_cluster("cluster-b")
        clusters = cluster_svc.list_clusters()
        assert len(clusters) == 2

    def test_get_cluster(self, cluster_svc: ClusterService) -> None:
        result = cluster_svc.register_cluster("my-cluster")
        found = cluster_svc.get_cluster(result.cluster.cluster_id)
        assert found is not None
        assert found.name == "my-cluster"

    def test_get_missing_cluster(self, cluster_svc: ClusterService) -> None:
        assert cluster_svc.get_cluster("nonexistent") is None

    def test_deactivate_cluster(self, cluster_svc: ClusterService) -> None:
        result = cluster_svc.register_cluster("doomed-cluster")
        assert cluster_svc.deactivate_cluster(result.cluster.cluster_id) is True
        found = cluster_svc.get_cluster(result.cluster.cluster_id)
        assert found is not None
        assert found.is_active is False

    def test_deactivate_nonexistent(self, cluster_svc: ClusterService) -> None:
        assert cluster_svc.deactivate_cluster("nonexistent") is False


# ------------------------------------------------------------------
# API Key Validation
# ------------------------------------------------------------------


class TestAPIKeyValidation:
    def test_valid_key(self, cluster_svc: ClusterService) -> None:
        result = cluster_svc.register_cluster("key-test")
        cluster_id = cluster_svc.validate_api_key(result.api_key)
        assert cluster_id == result.cluster.cluster_id

    def test_invalid_key(self, cluster_svc: ClusterService) -> None:
        assert cluster_svc.validate_api_key("fake-key-12345") is None

    def test_deactivated_key(self, cluster_svc: ClusterService) -> None:
        result = cluster_svc.register_cluster("deactivated")
        cluster_svc.deactivate_cluster(result.cluster.cluster_id)
        assert cluster_svc.validate_api_key(result.api_key) is None


# ------------------------------------------------------------------
# Event Ingestion
# ------------------------------------------------------------------


class TestEventIngestion:
    def test_ingest_single_event(self, cluster_svc: ClusterService) -> None:
        reg = cluster_svc.register_cluster("ingest-test")
        events = [_make_event(event_id="evt-1")]
        resp = cluster_svc.ingest_events(reg.cluster.cluster_id, events)
        assert resp.accepted == 1
        assert resp.duplicates == 0
        assert resp.errors == 0

    def test_ingest_multiple_events(self, cluster_svc: ClusterService) -> None:
        reg = cluster_svc.register_cluster("multi-ingest")
        events = [
            _make_event(event_id="evt-1"),
            _make_event(event_id="evt-2"),
            _make_event(event_id="evt-3"),
        ]
        resp = cluster_svc.ingest_events(reg.cluster.cluster_id, events)
        assert resp.accepted == 3

    def test_ingest_duplicate_detected(self, cluster_svc: ClusterService) -> None:
        reg = cluster_svc.register_cluster("dup-test")
        events = [_make_event(event_id="evt-1")]
        cluster_svc.ingest_events(reg.cluster.cluster_id, events)
        resp = cluster_svc.ingest_events(reg.cluster.cluster_id, events)
        assert resp.accepted == 0
        assert resp.duplicates == 1

    def test_ingest_missing_event_id(self, cluster_svc: ClusterService) -> None:
        reg = cluster_svc.register_cluster("no-id-test")
        events = [{"action": "test", "target": "test"}]
        resp = cluster_svc.ingest_events(reg.cluster.cluster_id, events)
        assert resp.errors == 1
        assert resp.accepted == 0

    def test_ingest_updates_last_seen(self, cluster_svc: ClusterService) -> None:
        reg = cluster_svc.register_cluster("last-seen-test")
        assert reg.cluster.last_seen is None
        cluster_svc.ingest_events(
            reg.cluster.cluster_id, [_make_event(event_id="evt-1")]
        )
        found = cluster_svc.get_cluster(reg.cluster.cluster_id)
        assert found is not None
        assert found.last_seen is not None

    def test_event_count_after_ingest(self, cluster_svc: ClusterService) -> None:
        reg = cluster_svc.register_cluster("count-test")
        cluster_svc.ingest_events(
            reg.cluster.cluster_id,
            [_make_event(event_id=f"evt-{i}") for i in range(5)],
        )
        assert cluster_svc.event_count(reg.cluster.cluster_id) == 5
        # Also reflected in cluster info
        found = cluster_svc.get_cluster(reg.cluster.cluster_id)
        assert found is not None
        assert found.event_count == 5


# ------------------------------------------------------------------
# Event Queries
# ------------------------------------------------------------------


class TestEventQueries:
    def _seed_events(self, cluster_svc: ClusterService) -> str:
        reg = cluster_svc.register_cluster("query-test")
        events = [
            _make_event(event_id="evt-1", decision="allow", risk_class="low"),
            _make_event(event_id="evt-2", decision="deny", risk_class="high"),
            _make_event(event_id="evt-3", decision="allow", risk_class="critical"),
            _make_event(event_id="evt-4", decision="deny", risk_class="low", action="scale-down"),
        ]
        cluster_svc.ingest_events(reg.cluster.cluster_id, events)
        return reg.cluster.cluster_id

    def test_get_all_events(self, cluster_svc: ClusterService) -> None:
        cid = self._seed_events(cluster_svc)
        result = cluster_svc.get_cluster_events(cluster_id=cid)
        assert result.total == 4
        assert len(result.items) == 4

    def test_filter_by_decision(self, cluster_svc: ClusterService) -> None:
        cid = self._seed_events(cluster_svc)
        result = cluster_svc.get_cluster_events(cluster_id=cid, decision="deny")
        assert result.total == 2

    def test_filter_by_risk_class(self, cluster_svc: ClusterService) -> None:
        cid = self._seed_events(cluster_svc)
        result = cluster_svc.get_cluster_events(cluster_id=cid, risk_class="low")
        assert result.total == 2

    def test_filter_by_action(self, cluster_svc: ClusterService) -> None:
        cid = self._seed_events(cluster_svc)
        result = cluster_svc.get_cluster_events(cluster_id=cid, action="scale-down")
        assert result.total == 1

    def test_pagination(self, cluster_svc: ClusterService) -> None:
        cid = self._seed_events(cluster_svc)
        result = cluster_svc.get_cluster_events(cluster_id=cid, page=1, page_size=2)
        assert result.total == 4
        assert len(result.items) == 2
        assert result.page == 1

    def test_aggregated_events_all_clusters(self, cluster_svc: ClusterService) -> None:
        reg1 = cluster_svc.register_cluster("cluster-a")
        reg2 = cluster_svc.register_cluster("cluster-b")
        cluster_svc.ingest_events(
            reg1.cluster.cluster_id, [_make_event(event_id="a-1")]
        )
        cluster_svc.ingest_events(
            reg2.cluster.cluster_id, [_make_event(event_id="b-1")]
        )
        result = cluster_svc.get_cluster_events(cluster_id=None)
        assert result.total == 2


# ------------------------------------------------------------------
# Cluster Stats
# ------------------------------------------------------------------


class TestClusterStats:
    def test_stats_for_cluster(self, cluster_svc: ClusterService) -> None:
        reg = cluster_svc.register_cluster("stats-test")
        events = [
            _make_event(event_id="evt-1", decision="allow", risk_class="low"),
            _make_event(event_id="evt-2", decision="deny", risk_class="high"),
        ]
        cluster_svc.ingest_events(reg.cluster.cluster_id, events)
        stats = cluster_svc.get_cluster_stats(reg.cluster.cluster_id)
        assert stats.total_events == 2
        assert stats.by_decision["allow"] == 1
        assert stats.by_decision["deny"] == 1

    def test_stats_aggregated(self, cluster_svc: ClusterService) -> None:
        reg1 = cluster_svc.register_cluster("stat-a")
        reg2 = cluster_svc.register_cluster("stat-b")
        cluster_svc.ingest_events(
            reg1.cluster.cluster_id, [_make_event(event_id="a-1")]
        )
        cluster_svc.ingest_events(
            reg2.cluster.cluster_id, [_make_event(event_id="b-1")]
        )
        stats = cluster_svc.get_cluster_stats()
        assert stats.total_events == 2

    def test_empty_stats(self, cluster_svc: ClusterService) -> None:
        stats = cluster_svc.get_cluster_stats()
        assert stats.total_events == 0


# ------------------------------------------------------------------
# API Endpoints
# ------------------------------------------------------------------


class TestClusterAPI:
    def test_register_cluster_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.post(
            "/api/clusters/",
            json={"name": "prod-east", "description": "Production US East"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["cluster"]["name"] == "prod-east"
        assert "api_key" in data
        assert data["api_key"].startswith("ask_")

    def test_list_clusters_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        client.post(
            "/api/clusters/",
            json={"name": "cluster-a"},
            headers=headers,
        )
        resp = client.get("/api/clusters/", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_register_duplicate_cluster(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        client.post("/api/clusters/", json={"name": "same"}, headers=headers)
        resp = client.post("/api/clusters/", json={"name": "same"}, headers=headers)
        assert resp.status_code == 409

    def test_get_cluster_by_id(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create = client.post(
            "/api/clusters/", json={"name": "detail-test"}, headers=headers
        )
        cluster_id = create.json()["cluster"]["cluster_id"]
        resp = client.get(f"/api/clusters/{cluster_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "detail-test"

    def test_deactivate_cluster_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create = client.post(
            "/api/clusters/", json={"name": "to-delete"}, headers=headers
        )
        cluster_id = create.json()["cluster"]["cluster_id"]
        resp = client.delete(f"/api/clusters/{cluster_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

    def test_cluster_not_found(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/clusters/nonexistent", headers=headers)
        assert resp.status_code == 404


# ------------------------------------------------------------------
# Ingest API
# ------------------------------------------------------------------


class TestIngestAPI:
    def test_ingest_with_api_key(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        # Register cluster
        create = client.post(
            "/api/clusters/", json={"name": "ingest-api"}, headers=headers
        )
        api_key = create.json()["api_key"]

        # Ingest with API key
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [_make_event(event_id="api-evt-1")]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["accepted"] == 1

    def test_ingest_without_key(self) -> None:
        client = _make_team_client()
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [_make_event()]},
        )
        assert resp.status_code == 401

    def test_ingest_with_invalid_key(self) -> None:
        client = _make_team_client()
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [_make_event()]},
            headers={"Authorization": "Bearer fake-key"},
        )
        assert resp.status_code == 401

    def test_ingest_deactivated_key(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create = client.post(
            "/api/clusters/", json={"name": "deactivated"}, headers=headers
        )
        api_key = create.json()["api_key"]
        cluster_id = create.json()["cluster"]["cluster_id"]
        # Deactivate
        client.delete(f"/api/clusters/{cluster_id}", headers=headers)
        # Try ingest
        resp = client.post(
            "/api/clusters/ingest",
            json={"events": [_make_event()]},
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 401

    def test_events_visible_after_ingest(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create = client.post(
            "/api/clusters/", json={"name": "visible-test"}, headers=headers
        )
        api_key = create.json()["api_key"]
        cluster_id = create.json()["cluster"]["cluster_id"]

        # Ingest events
        client.post(
            "/api/clusters/ingest",
            json={"events": [
                _make_event(event_id="vis-1"),
                _make_event(event_id="vis-2"),
            ]},
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Query cluster events
        resp = client.get(f"/api/clusters/{cluster_id}/events", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["total"] == 2


# ------------------------------------------------------------------
# Cluster Events Endpoint
# ------------------------------------------------------------------


class TestClusterEventsAPI:
    def test_aggregated_events(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/clusters/events", headers=headers)
        assert resp.status_code == 200
        assert "items" in resp.json()

    def test_cluster_stats(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/clusters/stats", headers=headers)
        assert resp.status_code == 200
        assert "total_events" in resp.json()


# ------------------------------------------------------------------
# Free Tier Gating
# ------------------------------------------------------------------


class TestFreeTierGating:
    def test_free_tier_no_cluster_endpoints(self) -> None:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
        ) as f:
            log_path = f.name

        config = DashboardConfig(
            actions_dir=ACTIONS_DIR,
            policies_dir=POLICIES_DIR,
            inventory_file=INVENTORY_FILE,
            audit_log=log_path,
            tier="free",
        )
        app = create_app(config)
        client = TestClient(app)
        resp = client.get("/api/clusters/")
        assert resp.status_code in (404, 405)
