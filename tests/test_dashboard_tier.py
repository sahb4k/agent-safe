"""Tests for tier gating and feature flags."""

from __future__ import annotations

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

SIGNING_KEY = "tier-test-key-" + "x" * 50


def _make_client(tier: str = "free", admin_password: str = "") -> TestClient:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
    ) as f:
        log_path = f.name

    config = DashboardConfig(
        actions_dir=ACTIONS_DIR,
        policies_dir=POLICIES_DIR,
        inventory_file=INVENTORY_FILE,
        audit_log=log_path,
        tier=tier,
        signing_key=SIGNING_KEY if tier != "free" else "",
        admin_username="admin",
        admin_password=admin_password,
        db_path=tempfile.mktemp(suffix=".db"),
    )
    app = create_app(config)
    return TestClient(app)


class TestFreeTier:
    def test_free_tier_no_auth_required(self) -> None:
        client = _make_client("free")
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_free_tier_audit_works(self) -> None:
        client = _make_client("free")
        resp = client.get("/api/audit/events")
        assert resp.status_code == 200

    def test_free_tier_no_auth_endpoints(self) -> None:
        client = _make_client("free")
        resp = client.post("/api/auth/login", json={"username": "a", "password": "b"})
        assert resp.status_code in (404, 405)  # Auth router not mounted

    def test_free_tier_no_reports_endpoint(self) -> None:
        client = _make_client("free")
        resp = client.post(
            "/api/reports/generate",
            json={"report_type": "soc2", "start_date": "2025-01-01", "end_date": "2025-01-31"},
        )
        assert resp.status_code in (404, 405)  # Reports router not mounted

    def test_free_tier_no_users_endpoint(self) -> None:
        client = _make_client("free")
        resp = client.get("/api/users/")
        assert resp.status_code == 404  # Users router not mounted


class TestTeamTier:
    def test_team_tier_has_auth(self) -> None:
        client = _make_client("team", admin_password="pass123")
        resp = client.post(
            "/api/auth/login", json={"username": "admin", "password": "pass123"}
        )
        assert resp.status_code == 200
        assert "token" in resp.json()

    def test_team_tier_has_reports(self) -> None:
        client = _make_client("team", admin_password="pass123")
        login = client.post(
            "/api/auth/login", json={"username": "admin", "password": "pass123"}
        )
        token = login.json()["token"]
        resp = client.post(
            "/api/reports/generate",
            json={"report_type": "soc2", "start_date": "2025-01-01", "end_date": "2025-01-31"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["report_type"] == "soc2"

    def test_team_tier_has_users(self) -> None:
        client = _make_client("team", admin_password="pass123")
        login = client.post(
            "/api/auth/login", json={"username": "admin", "password": "pass123"}
        )
        token = login.json()["token"]
        resp = client.get("/api/users/", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200


class TestBootstrapAdmin:
    def test_admin_created_on_startup(self) -> None:
        client = _make_client("team", admin_password="bootstrap123")
        resp = client.post(
            "/api/auth/login", json={"username": "admin", "password": "bootstrap123"}
        )
        assert resp.status_code == 200

    def test_no_admin_without_password(self) -> None:
        client = _make_client("team", admin_password="")
        # No admin user bootstrapped, so login should fail
        # But signing_key is set, so auth router is mounted
        resp = client.post(
            "/api/auth/login", json={"username": "admin", "password": "anything"}
        )
        assert resp.status_code == 401
