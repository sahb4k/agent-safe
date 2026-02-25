"""Tests for managed policy CRUD, publishing, bundle sync, and API endpoints."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from dashboard.backend.app import create_app  # noqa: E402
from dashboard.backend.config import DashboardConfig  # noqa: E402
from dashboard.backend.db.connection import Database  # noqa: E402
from dashboard.backend.db.migrations import get_schema_version, run_migrations  # noqa: E402
from dashboard.backend.managed_policies.models import (  # noqa: E402
    ManagedPolicyCreateRequest,
    ManagedPolicyUpdateRequest,
    MatchCallers,
    MatchConditions,
    MatchTargets,
)
from dashboard.backend.managed_policies.service import ManagedPolicyService  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")

SIGNING_KEY = "managed-policy-test-key-" + "z" * 40


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    d = Database(str(tmp_path / "test.db"))
    run_migrations(d)
    return d


@pytest.fixture()
def svc(db: Database) -> ManagedPolicyService:
    return ManagedPolicyService(db)


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
    return TestClient(create_app(config))


def _admin_headers(client: TestClient) -> dict:
    login = client.post(
        "/api/auth/login", json={"username": "admin", "password": "adminpass"}
    )
    token = login.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def _make_free_client() -> TestClient:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
    ) as f:
        log_path = f.name

    config = DashboardConfig(
        actions_dir=ACTIONS_DIR,
        policies_dir=POLICIES_DIR,
        inventory_file=INVENTORY_FILE,
        audit_log=log_path,
    )
    return TestClient(create_app(config))


# ------------------------------------------------------------------
# Migration Tests
# ------------------------------------------------------------------


class TestMigrationV3:
    def test_schema_version_is_3(self, db: Database) -> None:
        assert get_schema_version(db) == 3

    def test_managed_policies_table_exists(self, db: Database) -> None:
        row = db.fetchone(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='managed_policies'"
        )
        assert row is not None

    def test_policy_revisions_table_exists(self, db: Database) -> None:
        row = db.fetchone(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='policy_revisions'"
        )
        assert row is not None

    def test_cluster_policy_status_table_exists(self, db: Database) -> None:
        row = db.fetchone(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='cluster_policy_status'"
        )
        assert row is not None


# ------------------------------------------------------------------
# Service CRUD Tests
# ------------------------------------------------------------------


class TestPolicyCRUD:
    def test_create_policy(self, svc: ManagedPolicyService) -> None:
        req = ManagedPolicyCreateRequest(
            name="deny-prod-delete",
            description="Block deletions in prod",
            priority=900,
            decision="deny",
            reason="Production is protected",
            match=MatchConditions(
                actions=["delete-*"],
                targets=MatchTargets(environments=["prod"]),
            ),
        )
        result = svc.create_policy(req, created_by="admin")
        assert result.policy_id.startswith("pol-")
        assert result.name == "deny-prod-delete"
        assert result.priority == 900
        assert result.decision == "deny"
        assert result.is_active is True
        assert result.match.actions == ["delete-*"]
        assert result.match.targets.environments == ["prod"]

    def test_create_duplicate_name_raises(self, svc: ManagedPolicyService) -> None:
        req = ManagedPolicyCreateRequest(
            name="unique-rule", decision="allow", reason="test",
        )
        svc.create_policy(req)
        with pytest.raises(ValueError, match="already exists"):
            svc.create_policy(req)

    def test_create_invalid_decision_raises(self, svc: ManagedPolicyService) -> None:
        req = ManagedPolicyCreateRequest(
            name="bad-decision", decision="maybe", reason="test",
        )
        with pytest.raises(ValueError, match="Invalid decision"):
            svc.create_policy(req)

    def test_list_policies_active_only(self, svc: ManagedPolicyService) -> None:
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r1", priority=100, decision="allow", reason="test",
        ))
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r2", priority=200, decision="deny", reason="test",
        ))
        result = svc.list_policies()
        assert len(result) == 2
        # Sorted by priority descending
        assert result[0].name == "r2"
        assert result[1].name == "r1"

    def test_list_policies_includes_inactive(self, svc: ManagedPolicyService) -> None:
        p = svc.create_policy(ManagedPolicyCreateRequest(
            name="to-delete", decision="allow", reason="test",
        ))
        svc.delete_policy(p.policy_id)
        assert len(svc.list_policies(include_inactive=False)) == 0
        assert len(svc.list_policies(include_inactive=True)) == 1

    def test_get_policy(self, svc: ManagedPolicyService) -> None:
        p = svc.create_policy(ManagedPolicyCreateRequest(
            name="get-me", decision="allow", reason="test",
        ))
        result = svc.get_policy(p.policy_id)
        assert result is not None
        assert result.name == "get-me"

    def test_get_policy_not_found(self, svc: ManagedPolicyService) -> None:
        assert svc.get_policy("pol-nonexistent") is None

    def test_update_policy(self, svc: ManagedPolicyService) -> None:
        p = svc.create_policy(ManagedPolicyCreateRequest(
            name="original", priority=10, decision="allow", reason="v1",
        ))
        updated = svc.update_policy(
            p.policy_id,
            ManagedPolicyUpdateRequest(priority=500, reason="v2"),
        )
        assert updated is not None
        assert updated.priority == 500
        assert updated.reason == "v2"
        assert updated.name == "original"  # Unchanged

    def test_update_policy_match(self, svc: ManagedPolicyService) -> None:
        p = svc.create_policy(ManagedPolicyCreateRequest(
            name="update-match", decision="allow", reason="test",
        ))
        updated = svc.update_policy(
            p.policy_id,
            ManagedPolicyUpdateRequest(
                match=MatchConditions(
                    actions=["get-*"],
                    callers=MatchCallers(roles=["viewer"]),
                ),
            ),
        )
        assert updated is not None
        assert updated.match.actions == ["get-*"]
        assert updated.match.callers.roles == ["viewer"]

    def test_update_nonexistent_returns_none(self, svc: ManagedPolicyService) -> None:
        result = svc.update_policy(
            "pol-ghost",
            ManagedPolicyUpdateRequest(priority=999),
        )
        assert result is None

    def test_delete_policy_soft_delete(self, svc: ManagedPolicyService) -> None:
        p = svc.create_policy(ManagedPolicyCreateRequest(
            name="to-remove", decision="allow", reason="test",
        ))
        assert svc.delete_policy(p.policy_id) is True
        # Still accessible but inactive
        result = svc.get_policy(p.policy_id)
        assert result is not None
        assert result.is_active is False

    def test_delete_nonexistent_returns_false(self, svc: ManagedPolicyService) -> None:
        assert svc.delete_policy("pol-nope") is False


# ------------------------------------------------------------------
# Publishing Tests
# ------------------------------------------------------------------


class TestPublishing:
    def test_publish_creates_revision(self, svc: ManagedPolicyService) -> None:
        svc.create_policy(ManagedPolicyCreateRequest(
            name="rule-a", priority=100, decision="allow", reason="allowed",
        ))
        svc.create_policy(ManagedPolicyCreateRequest(
            name="rule-b", priority=200, decision="deny", reason="denied",
        ))
        result = svc.publish(published_by="admin", notes="first publish")
        assert result.revision.revision_id == 1
        assert result.revision.rule_count == 2
        assert result.revision.published_by == "admin"
        assert result.revision.notes == "first publish"
        assert len(result.bundle_preview) == 2

    def test_publish_excludes_inactive(self, svc: ManagedPolicyService) -> None:
        svc.create_policy(ManagedPolicyCreateRequest(
            name="active-rule", decision="allow", reason="yes",
        ))
        inactive = svc.create_policy(ManagedPolicyCreateRequest(
            name="deleted-rule", decision="deny", reason="no",
        ))
        svc.delete_policy(inactive.policy_id)
        result = svc.publish()
        assert result.revision.rule_count == 1
        assert result.bundle_preview[0]["name"] == "active-rule"

    def test_publish_empty_is_allowed(self, svc: ManagedPolicyService) -> None:
        result = svc.publish()
        assert result.revision.rule_count == 0
        assert result.bundle_preview == []

    def test_multiple_revisions(self, svc: ManagedPolicyService) -> None:
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r1", decision="allow", reason="v1",
        ))
        svc.publish(notes="rev 1")
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r2", decision="deny", reason="v2",
        ))
        svc.publish(notes="rev 2")
        revisions = svc.list_revisions()
        assert len(revisions) == 2
        assert revisions[0].revision_id == 2  # Newest first
        assert revisions[0].rule_count == 2
        assert revisions[1].revision_id == 1
        assert revisions[1].rule_count == 1

    def test_get_latest_revision(self, svc: ManagedPolicyService) -> None:
        assert svc.get_latest_revision() is None
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r", decision="allow", reason="test",
        ))
        svc.publish(notes="latest")
        latest = svc.get_latest_revision()
        assert latest is not None
        assert latest.notes == "latest"

    def test_bundle_entry_format(self, svc: ManagedPolicyService) -> None:
        """Published bundle entries must match PolicyRule YAML schema."""
        svc.create_policy(ManagedPolicyCreateRequest(
            name="complex-rule",
            description="A complex rule",
            priority=500,
            decision="require_approval",
            reason="Needs review",
            match=MatchConditions(
                actions=["restart-*", "scale-*"],
                targets=MatchTargets(environments=["prod"], sensitivities=["critical"]),
                callers=MatchCallers(roles=["deployer"]),
                risk_classes=["high", "critical"],
            ),
        ))
        result = svc.publish()
        entry = result.bundle_preview[0]
        assert entry["name"] == "complex-rule"
        assert entry["priority"] == 500
        assert entry["decision"] == "require_approval"
        assert entry["match"]["actions"] == ["restart-*", "scale-*"]
        assert entry["match"]["targets"]["environments"] == ["prod"]
        assert entry["match"]["callers"]["roles"] == ["deployer"]
        assert entry["match"]["risk_classes"] == ["high", "critical"]


# ------------------------------------------------------------------
# Bundle Sync Tests
# ------------------------------------------------------------------


class TestBundleSync:
    def test_get_bundle_latest(self, svc: ManagedPolicyService) -> None:
        svc.create_policy(ManagedPolicyCreateRequest(
            name="synced-rule", priority=100, decision="allow", reason="ok",
        ))
        svc.publish()
        bundle = svc.get_bundle()
        assert bundle is not None
        assert bundle.revision_id == 1
        assert len(bundle.rules) == 1
        assert bundle.rules[0]["name"] == "synced-rule"

    def test_get_bundle_specific_revision(self, svc: ManagedPolicyService) -> None:
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r1", decision="allow", reason="v1",
        ))
        svc.publish()
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r2", decision="deny", reason="v2",
        ))
        svc.publish()
        bundle_v1 = svc.get_bundle(revision_id=1)
        assert bundle_v1 is not None
        assert len(bundle_v1.rules) == 1
        bundle_v2 = svc.get_bundle(revision_id=2)
        assert bundle_v2 is not None
        assert len(bundle_v2.rules) == 2

    def test_get_bundle_no_revisions(self, svc: ManagedPolicyService) -> None:
        assert svc.get_bundle() is None

    def test_record_cluster_sync(self, db: Database, svc: ManagedPolicyService) -> None:
        """Sync status should be recorded and retrievable."""
        # Need a cluster first
        from dashboard.backend.clusters.service import ClusterService

        cluster_svc = ClusterService(db)
        cluster = cluster_svc.register_cluster("sync-test")

        svc.create_policy(ManagedPolicyCreateRequest(
            name="r1", decision="allow", reason="test",
        ))
        svc.publish()

        svc.record_cluster_sync(cluster.cluster.cluster_id, 1)
        status = svc.get_sync_status()
        assert len(status) == 1
        assert status[0].cluster_name == "sync-test"
        assert status[0].revision_id == 1
        assert status[0].is_current is True

    def test_sync_status_behind(self, db: Database, svc: ManagedPolicyService) -> None:
        """Cluster should show 'behind' when not on latest revision."""
        from dashboard.backend.clusters.service import ClusterService

        cluster_svc = ClusterService(db)
        cluster = cluster_svc.register_cluster("behind-test")

        svc.create_policy(ManagedPolicyCreateRequest(
            name="r1", decision="allow", reason="test",
        ))
        svc.publish()
        svc.record_cluster_sync(cluster.cluster.cluster_id, 1)

        # Publish a second revision
        svc.create_policy(ManagedPolicyCreateRequest(
            name="r2", decision="deny", reason="test",
        ))
        svc.publish()

        status = svc.get_sync_status()
        assert len(status) == 1
        assert status[0].revision_id == 1
        assert status[0].is_current is False  # Behind

    def test_sync_status_never_synced(self, db: Database, svc: ManagedPolicyService) -> None:
        """Cluster that never synced should show null revision."""
        from dashboard.backend.clusters.service import ClusterService

        cluster_svc = ClusterService(db)
        cluster_svc.register_cluster("no-sync")

        status = svc.get_sync_status()
        assert len(status) == 1
        assert status[0].revision_id is None
        assert status[0].is_current is False


# ------------------------------------------------------------------
# API Tests — Managed Policy CRUD
# ------------------------------------------------------------------


class TestManagedPolicyAPI:
    def test_create_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.post(
            "/api/policies/managed",
            json={
                "name": "api-rule",
                "priority": 100,
                "decision": "allow",
                "reason": "API created",
                "match": {"actions": ["get-*"]},
            },
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "api-rule"
        assert data["policy_id"].startswith("pol-")

    def test_list_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        client.post(
            "/api/policies/managed",
            json={"name": "rule-1", "decision": "allow", "reason": "r1"},
            headers=headers,
        )
        resp = client.get("/api/policies/managed", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 1

    def test_get_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create_resp = client.post(
            "/api/policies/managed",
            json={"name": "single", "decision": "deny", "reason": "blocked"},
            headers=headers,
        )
        pid = create_resp.json()["policy_id"]
        resp = client.get(f"/api/policies/managed/{pid}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["name"] == "single"

    def test_get_not_found(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/policies/managed/pol-nope", headers=headers)
        assert resp.status_code == 404

    def test_update_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create_resp = client.post(
            "/api/policies/managed",
            json={"name": "update-me", "priority": 10, "decision": "allow", "reason": "v1"},
            headers=headers,
        )
        pid = create_resp.json()["policy_id"]
        resp = client.put(
            f"/api/policies/managed/{pid}",
            json={"priority": 500, "reason": "v2"},
            headers=headers,
        )
        assert resp.status_code == 200
        assert resp.json()["priority"] == 500
        assert resp.json()["reason"] == "v2"

    def test_delete_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        create_resp = client.post(
            "/api/policies/managed",
            json={"name": "delete-me", "decision": "deny", "reason": "bye"},
            headers=headers,
        )
        pid = create_resp.json()["policy_id"]
        resp = client.delete(f"/api/policies/managed/{pid}", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == {"ok": True}

    def test_duplicate_name_returns_409(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        client.post(
            "/api/policies/managed",
            json={"name": "dupe", "decision": "allow", "reason": "first"},
            headers=headers,
        )
        resp = client.post(
            "/api/policies/managed",
            json={"name": "dupe", "decision": "deny", "reason": "second"},
            headers=headers,
        )
        assert resp.status_code == 409


# ------------------------------------------------------------------
# API Tests — Publishing & Revisions
# ------------------------------------------------------------------


class TestPublishAPI:
    def test_publish_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        client.post(
            "/api/policies/managed",
            json={"name": "pub-rule", "decision": "allow", "reason": "publish test"},
            headers=headers,
        )
        resp = client.post(
            "/api/policies/publish",
            json={"notes": "first release"},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["revision"]["rule_count"] == 1
        assert data["revision"]["notes"] == "first release"

    def test_list_revisions_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        client.post(
            "/api/policies/managed",
            json={"name": "r1", "decision": "allow", "reason": "test"},
            headers=headers,
        )
        client.post("/api/policies/publish", json={}, headers=headers)
        client.post("/api/policies/publish", json={"notes": "v2"}, headers=headers)

        resp = client.get("/api/policies/revisions", headers=headers)
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_latest_revision_via_api(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        client.post(
            "/api/policies/managed",
            json={"name": "r1", "decision": "allow", "reason": "test"},
            headers=headers,
        )
        client.post("/api/policies/publish", json={"notes": "latest"}, headers=headers)

        resp = client.get("/api/policies/revisions/latest", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["notes"] == "latest"

    def test_latest_revision_404_when_none(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/policies/revisions/latest", headers=headers)
        assert resp.status_code == 404


# ------------------------------------------------------------------
# API Tests — Policy Bundle Pull
# ------------------------------------------------------------------


class TestBundlePullAPI:
    def test_pull_bundle_with_api_key(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)

        # Register cluster
        cluster_resp = client.post(
            "/api/clusters/",
            json={"name": "sync-cluster"},
            headers=headers,
        )
        api_key = cluster_resp.json()["api_key"]

        # Create and publish policy
        client.post(
            "/api/policies/managed",
            json={"name": "synced-rule", "priority": 100, "decision": "allow", "reason": "ok"},
            headers=headers,
        )
        client.post("/api/policies/publish", json={}, headers=headers)

        # Pull bundle
        resp = client.get(
            "/api/clusters/policy-bundle",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["revision_id"] == 1
        assert len(data["rules"]) == 1
        assert data["rules"][0]["name"] == "synced-rule"

    def test_pull_bundle_no_key_returns_401(self) -> None:
        client = _make_team_client()
        resp = client.get("/api/clusters/policy-bundle")
        assert resp.status_code == 401

    def test_pull_bundle_invalid_key_returns_401(self) -> None:
        client = _make_team_client()
        resp = client.get(
            "/api/clusters/policy-bundle",
            headers={"Authorization": "Bearer bad-key"},
        )
        assert resp.status_code == 401

    def test_pull_bundle_no_revisions_returns_404(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        cluster_resp = client.post(
            "/api/clusters/",
            json={"name": "no-rev-cluster"},
            headers=headers,
        )
        api_key = cluster_resp.json()["api_key"]
        resp = client.get(
            "/api/clusters/policy-bundle",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 404

    def test_pull_records_sync_status(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)

        cluster_resp = client.post(
            "/api/clusters/",
            json={"name": "track-sync"},
            headers=headers,
        )
        api_key = cluster_resp.json()["api_key"]

        client.post(
            "/api/policies/managed",
            json={"name": "r1", "decision": "allow", "reason": "test"},
            headers=headers,
        )
        client.post("/api/policies/publish", json={}, headers=headers)

        # Pull bundle
        client.get(
            "/api/clusters/policy-bundle",
            headers={"Authorization": f"Bearer {api_key}"},
        )

        # Check sync status
        resp = client.get("/api/policies/sync-status", headers=headers)
        assert resp.status_code == 200
        status = resp.json()
        assert len(status) == 1
        assert status[0]["cluster_name"] == "track-sync"
        assert status[0]["revision_id"] == 1
        assert status[0]["is_current"] is True


# ------------------------------------------------------------------
# Tier Gating Tests
# ------------------------------------------------------------------


class TestTierGating:
    def test_free_tier_managed_returns_403(self) -> None:
        client = _make_free_client()
        resp = client.get("/api/policies/managed")
        assert resp.status_code == 403

    def test_free_tier_publish_returns_403(self) -> None:
        client = _make_free_client()
        resp = client.post("/api/policies/publish", json={})
        assert resp.status_code == 403

    def test_free_tier_file_based_still_works(self) -> None:
        client = _make_free_client()
        resp = client.get("/api/policies/")
        assert resp.status_code == 200


# ------------------------------------------------------------------
# File-Based Policies Unchanged
# ------------------------------------------------------------------


class TestFilePoliciesUnchanged:
    def test_file_based_list_still_works(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/policies/", headers=headers)
        assert resp.status_code == 200
        policies = resp.json()
        assert len(policies) > 0  # default.yaml has rules

    def test_match_analysis_still_works(self) -> None:
        client = _make_team_client()
        headers = _admin_headers(client)
        resp = client.get("/api/policies/match-analysis", headers=headers)
        assert resp.status_code == 200
