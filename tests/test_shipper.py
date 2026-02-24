"""Tests for external audit log shipping.

Covers:
- FilesystemShipper
- WebhookShipper
- S3Shipper
- AuditLogger integration with shippers
- build_shippers factory
- SDK integration
- CLI audit ship command
"""

from __future__ import annotations

import json
import warnings
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_safe import AgentSafe
from agent_safe.audit.logger import AuditLogger, ShipperWarning
from agent_safe.audit.shipper import (
    AuditShipper,
    FilesystemShipper,
    S3Shipper,
    WebhookShipper,
    build_shippers,
)
from agent_safe.models import AuditEvent, DecisionResult, RiskClass

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"


@pytest.fixture()
def sample_event() -> AuditEvent:
    return AuditEvent(
        event_id="evt-test-001",
        timestamp=datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC),
        prev_hash="0" * 64,
        entry_hash="a" * 64,
        action="restart-deployment",
        target="dev/test-app",
        caller="agent-01",
        params={"namespace": "dev", "deployment": "app"},
        decision=DecisionResult.ALLOW,
        reason="Dev allow-all",
        risk_class=RiskClass.MEDIUM,
        effective_risk=RiskClass.LOW,
        policy_matched="allow-dev-all",
    )


# --- FilesystemShipper ---


class TestFilesystemShipper:
    def test_writes_json_line(self, tmp_path: Path, sample_event: AuditEvent):
        dest = tmp_path / "shipped.jsonl"
        shipper = FilesystemShipper(dest)
        shipper.ship(sample_event)

        lines = dest.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["event_id"] == "evt-test-001"
        assert data["action"] == "restart-deployment"

    def test_appends_multiple_events(
        self, tmp_path: Path, sample_event: AuditEvent,
    ):
        dest = tmp_path / "shipped.jsonl"
        shipper = FilesystemShipper(dest)
        shipper.ship(sample_event)
        shipper.ship(sample_event)

        lines = dest.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_creates_file_on_first_ship(
        self, tmp_path: Path, sample_event: AuditEvent,
    ):
        dest = tmp_path / "new_dir" / "shipped.jsonl"
        dest.parent.mkdir(parents=True)
        shipper = FilesystemShipper(dest)
        shipper.ship(sample_event)
        assert dest.exists()

    def test_satisfies_protocol(self):
        assert isinstance(FilesystemShipper("/tmp/test.jsonl"), AuditShipper)


# --- WebhookShipper ---


class TestWebhookShipper:
    @patch("agent_safe.audit.shipper.urllib.request.urlopen")
    def test_posts_json(self, mock_urlopen: MagicMock, sample_event: AuditEvent):
        shipper = WebhookShipper("https://example.com/audit")
        shipper.ship(sample_event)

        mock_urlopen.assert_called_once()
        req = mock_urlopen.call_args[0][0]
        assert req.full_url == "https://example.com/audit"
        assert req.method == "POST"
        assert req.get_header("Content-type") == "application/json"

        body = json.loads(req.data.decode("utf-8"))
        assert "event" in body
        assert "shipped_at" in body
        assert body["event"]["event_id"] == "evt-test-001"

    @patch("agent_safe.audit.shipper.urllib.request.urlopen")
    def test_custom_headers(
        self, mock_urlopen: MagicMock, sample_event: AuditEvent,
    ):
        shipper = WebhookShipper(
            "https://example.com/audit",
            headers={"Authorization": "Bearer token123"},
        )
        shipper.ship(sample_event)

        req = mock_urlopen.call_args[0][0]
        assert req.get_header("Authorization") == "Bearer token123"

    @patch("agent_safe.audit.shipper.urllib.request.urlopen")
    def test_timeout_passed(
        self, mock_urlopen: MagicMock, sample_event: AuditEvent,
    ):
        shipper = WebhookShipper("https://example.com/audit", timeout=5.0)
        shipper.ship(sample_event)

        assert mock_urlopen.call_args[1]["timeout"] == 5.0

    def test_satisfies_protocol(self):
        assert isinstance(
            WebhookShipper("https://example.com"), AuditShipper,
        )


# --- S3Shipper ---


class TestS3Shipper:
    def test_uploads_with_correct_key(self, sample_event: AuditEvent):
        mock_client = MagicMock()
        shipper = S3Shipper(bucket="my-bucket", prefix="logs/", client=mock_client)
        shipper.ship(sample_event)

        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "my-bucket"
        assert call_kwargs["Key"] == "logs/2025-06-15/evt-test-001.json"
        assert call_kwargs["ContentType"] == "application/json"

        body = json.loads(call_kwargs["Body"].decode("utf-8"))
        assert body["event_id"] == "evt-test-001"

    def test_default_prefix(self, sample_event: AuditEvent):
        mock_client = MagicMock()
        shipper = S3Shipper(bucket="b", client=mock_client)
        shipper.ship(sample_event)

        key = mock_client.put_object.call_args[1]["Key"]
        assert key.startswith("audit-logs/")

    def test_missing_boto3_raises_import_error(self):
        with patch.dict("sys.modules", {"boto3": None}), pytest.raises(
            ImportError, match="boto3",
        ):
            S3Shipper(bucket="test-bucket")

    def test_satisfies_protocol(self):
        mock_client = MagicMock()
        assert isinstance(
            S3Shipper(bucket="b", client=mock_client), AuditShipper,
        )


# --- AuditLogger Integration ---


class TestAuditLoggerShipperIntegration:
    def test_shipper_called_after_write(self, tmp_path: Path):
        mock_shipper = MagicMock(spec=["ship"])
        logger = AuditLogger(tmp_path / "audit.jsonl", shippers=[mock_shipper])

        from agent_safe.models import Decision

        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="test",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
        )
        logger.log_decision(decision)

        mock_shipper.ship.assert_called_once()
        shipped_event = mock_shipper.ship.call_args[0][0]
        assert isinstance(shipped_event, AuditEvent)
        assert shipped_event.event_id == "evt-test"

    def test_broken_shipper_warns_but_writes_locally(self, tmp_path: Path):
        broken_shipper = MagicMock(spec=["ship"])
        broken_shipper.ship.side_effect = ConnectionError("network down")

        log_path = tmp_path / "audit.jsonl"
        logger = AuditLogger(log_path, shippers=[broken_shipper])

        from agent_safe.models import Decision

        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="test",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
        )

        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            logger.log_decision(decision)

        # Local write succeeded
        assert log_path.exists()
        events = logger.read_events()
        assert len(events) == 1

        # Warning emitted
        assert len(w) == 1
        assert issubclass(w[0].category, ShipperWarning)
        assert "MagicMock" in str(w[0].message)

    def test_multiple_shippers_all_called(self, tmp_path: Path):
        shipper_a = MagicMock(spec=["ship"])
        shipper_b = MagicMock(spec=["ship"])
        logger = AuditLogger(
            tmp_path / "audit.jsonl", shippers=[shipper_a, shipper_b],
        )

        from agent_safe.models import Decision

        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="test",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
        )
        logger.log_decision(decision)

        shipper_a.ship.assert_called_once()
        shipper_b.ship.assert_called_once()

    def test_no_shippers_backward_compat(self, tmp_path: Path):
        logger = AuditLogger(tmp_path / "audit.jsonl")

        from agent_safe.models import Decision

        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="test",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
        )
        event = logger.log_decision(decision)
        assert event.event_id == "evt-test"


# --- Custom Shipper Protocol ---


class TestCustomShipper:
    def test_custom_class_satisfies_protocol(self):
        class MyShipper:
            def ship(self, event: AuditEvent) -> None:
                pass

        assert isinstance(MyShipper(), AuditShipper)

    def test_custom_shipper_works_with_logger(self, tmp_path: Path):
        shipped: list[AuditEvent] = []

        class CollectorShipper:
            def ship(self, event: AuditEvent) -> None:
                shipped.append(event)

        logger = AuditLogger(
            tmp_path / "audit.jsonl", shippers=[CollectorShipper()],
        )

        from agent_safe.models import Decision

        decision = Decision(
            result=DecisionResult.ALLOW,
            reason="test",
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            risk_class=RiskClass.MEDIUM,
            effective_risk=RiskClass.LOW,
            audit_id="evt-test",
        )
        logger.log_decision(decision)

        assert len(shipped) == 1
        assert shipped[0].event_id == "evt-test"


# --- build_shippers factory ---


class TestBuildShippers:
    def test_filesystem_only(self, tmp_path: Path):
        shippers = build_shippers({"filesystem_path": str(tmp_path / "out.jsonl")})
        assert len(shippers) == 1
        assert isinstance(shippers[0], FilesystemShipper)

    def test_webhook_only(self):
        shippers = build_shippers({"webhook_url": "https://example.com/hook"})
        assert len(shippers) == 1
        assert isinstance(shippers[0], WebhookShipper)

    def test_s3_with_mock_client(self):
        with patch("agent_safe.audit.shipper.S3Shipper") as mock_cls:
            mock_cls.return_value = MagicMock()
            shippers = build_shippers({"s3_bucket": "my-bucket"})
            assert len(shippers) == 1

    def test_multiple_backends(self, tmp_path: Path):
        with patch("agent_safe.audit.shipper.S3Shipper") as mock_s3:
            mock_s3.return_value = MagicMock()
            shippers = build_shippers({
                "filesystem_path": str(tmp_path / "out.jsonl"),
                "webhook_url": "https://example.com/hook",
                "s3_bucket": "my-bucket",
            })
            assert len(shippers) == 3

    def test_empty_config(self):
        shippers = build_shippers({})
        assert len(shippers) == 0

    def test_webhook_custom_timeout(self):
        shippers = build_shippers({
            "webhook_url": "https://example.com",
            "webhook_timeout": 5.0,
        })
        assert len(shippers) == 1
        assert isinstance(shippers[0], WebhookShipper)


# --- SDK Integration ---


class TestSDKShipperIntegration:
    def test_shippers_as_list(self, tmp_path: Path):
        shipped: list[AuditEvent] = []

        class Collector:
            def ship(self, event: AuditEvent) -> None:
                shipped.append(event)

        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            audit_shippers=[Collector()],
        )
        safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert len(shipped) == 1

    def test_shippers_as_dict(self, tmp_path: Path):
        dest = tmp_path / "shipped.jsonl"
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path / "audit.jsonl",
            audit_shippers={"filesystem_path": str(dest)},
        )
        safe.check(
            action="restart-deployment", target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "app"},
        )
        assert dest.exists()
        lines = dest.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1

    def test_shippers_without_audit_log_raises(self):
        from agent_safe.sdk.client import AgentSafeError

        with pytest.raises(AgentSafeError, match="audit_log"):
            AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_shippers=[MagicMock(spec=["ship"])],
            )


# --- CLI audit ship ---


class TestAuditShipCommand:
    def _generate_log(self, log_path: Path, count: int = 1) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=log_path,
        )
        for _ in range(count):
            safe.check(
                action="restart-deployment", target="dev/test-app",
                caller="agent-01",
                params={"namespace": "dev", "deployment": "app"},
            )

    def test_ship_to_filesystem(self, tmp_path: Path):
        from click.testing import CliRunner

        from agent_safe.cli.main import cli

        log_path = tmp_path / "audit.jsonl"
        self._generate_log(log_path, count=3)

        dest = tmp_path / "shipped.jsonl"
        result = CliRunner(mix_stderr=False).invoke(cli, [
            "audit", "ship", str(log_path),
            "--backend", "filesystem",
            "--path", str(dest),
        ])
        assert result.exit_code == 0
        assert "Shipped 3 event(s)" in result.output
        assert dest.exists()

        lines = dest.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 3

    def test_ship_missing_log(self, tmp_path: Path):
        from click.testing import CliRunner

        from agent_safe.cli.main import cli

        result = CliRunner(mix_stderr=False).invoke(cli, [
            "audit", "ship", str(tmp_path / "missing.jsonl"),
            "--backend", "filesystem",
            "--path", str(tmp_path / "dest.jsonl"),
        ])
        assert result.exit_code == 1

    def test_ship_empty_log(self, tmp_path: Path):
        from click.testing import CliRunner

        from agent_safe.cli.main import cli

        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("", encoding="utf-8")

        result = CliRunner(mix_stderr=False).invoke(cli, [
            "audit", "ship", str(log_path),
            "--backend", "filesystem",
            "--path", str(tmp_path / "dest.jsonl"),
        ])
        assert result.exit_code == 0
        assert "No events" in result.output

    def test_ship_missing_required_option(self, tmp_path: Path):
        from click.testing import CliRunner

        from agent_safe.cli.main import cli

        log_path = tmp_path / "audit.jsonl"
        log_path.write_text("", encoding="utf-8")

        result = CliRunner(mix_stderr=False).invoke(cli, [
            "audit", "ship", str(log_path),
            "--backend", "webhook",
            # Missing --url
        ])
        assert result.exit_code == 1
