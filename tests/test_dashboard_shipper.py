"""Tests for the DashboardShipper audit shipper."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest

from agent_safe.audit.dashboard_shipper import DashboardShipper
from agent_safe.audit.shipper import AuditShipper, build_shippers
from agent_safe.models import AuditEvent, DecisionResult, RiskClass


@pytest.fixture()
def sample_event() -> AuditEvent:
    return AuditEvent(
        event_id="evt-test-001",
        timestamp=datetime(2025, 1, 15, 10, 0, 0, tzinfo=UTC),
        prev_hash="genesis",
        entry_hash="abc123",
        event_type="decision",
        action="restart-deployment",
        target="dev/test-app",
        caller="agent-01",
        decision=DecisionResult.ALLOW,
        reason="Dev allow-all",
        risk_class=RiskClass.LOW,
        effective_risk=RiskClass.LOW,
    )


class TestDashboardShipperProtocol:
    def test_satisfies_audit_shipper_protocol(self) -> None:
        shipper = DashboardShipper(
            dashboard_url="https://dashboard.example.com",
            api_key="ask_test123",
        )
        assert isinstance(shipper, AuditShipper)

    def test_url_construction(self) -> None:
        shipper = DashboardShipper(
            dashboard_url="https://dashboard.example.com",
            api_key="test",
        )
        assert shipper._url == "https://dashboard.example.com/api/clusters/ingest"

    def test_url_construction_trailing_slash(self) -> None:
        shipper = DashboardShipper(
            dashboard_url="https://dashboard.example.com/",
            api_key="test",
        )
        assert shipper._url == "https://dashboard.example.com/api/clusters/ingest"


class TestDashboardShipperShip:
    @patch("agent_safe.audit.dashboard_shipper.urllib.request.urlopen")
    def test_posts_event_json(
        self, mock_urlopen: MagicMock, sample_event: AuditEvent
    ) -> None:
        shipper = DashboardShipper(
            dashboard_url="https://dashboard.example.com",
            api_key="ask_mykey123",
        )
        shipper.ship(sample_event)

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://dashboard.example.com/api/clusters/ingest"
        assert req.method == "POST"

        body = json.loads(req.data.decode("utf-8"))
        assert "events" in body
        assert len(body["events"]) == 1
        assert body["events"][0]["event_id"] == "evt-test-001"
        assert body["events"][0]["action"] == "restart-deployment"
        assert "shipped_at" in body

    @patch("agent_safe.audit.dashboard_shipper.urllib.request.urlopen")
    def test_sends_auth_header(
        self, mock_urlopen: MagicMock, sample_event: AuditEvent
    ) -> None:
        shipper = DashboardShipper(
            dashboard_url="https://example.com",
            api_key="ask_secret_key_12345",
        )
        shipper.ship(sample_event)

        req = mock_urlopen.call_args[0][0]
        assert req.headers["Authorization"] == "Bearer ask_secret_key_12345"
        assert req.headers["Content-type"] == "application/json"

    @patch("agent_safe.audit.dashboard_shipper.urllib.request.urlopen")
    def test_timeout_passed(
        self, mock_urlopen: MagicMock, sample_event: AuditEvent
    ) -> None:
        shipper = DashboardShipper(
            dashboard_url="https://example.com",
            api_key="test",
            timeout=5.0,
        )
        shipper.ship(sample_event)

        assert mock_urlopen.call_args[1]["timeout"] == 5.0

    @patch("agent_safe.audit.dashboard_shipper.urllib.request.urlopen")
    def test_network_error_raises(
        self, mock_urlopen: MagicMock, sample_event: AuditEvent
    ) -> None:
        mock_urlopen.side_effect = ConnectionError("network down")
        shipper = DashboardShipper(
            dashboard_url="https://example.com",
            api_key="test",
        )
        with pytest.raises(ConnectionError):
            shipper.ship(sample_event)


class TestBuildShippersIntegration:
    def test_build_dashboard_shipper(self) -> None:
        shippers = build_shippers({
            "dashboard_url": "https://dashboard.example.com",
            "dashboard_api_key": "ask_test123",
        })
        assert len(shippers) == 1
        assert isinstance(shippers[0], DashboardShipper)

    def test_build_dashboard_shipper_with_timeout(self) -> None:
        shippers = build_shippers({
            "dashboard_url": "https://dashboard.example.com",
            "dashboard_api_key": "ask_test123",
            "dashboard_timeout": 30.0,
        })
        assert len(shippers) == 1
        assert shippers[0]._timeout == 30.0

    def test_no_dashboard_shipper_without_url(self) -> None:
        shippers = build_shippers({})
        assert len(shippers) == 0

    def test_dashboard_shipper_alongside_others(self) -> None:
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            shippers = build_shippers({
                "filesystem_path": f.name,
                "dashboard_url": "https://dashboard.example.com",
                "dashboard_api_key": "ask_test",
            })
        assert len(shippers) == 2
