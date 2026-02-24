"""Tests for compliance report generation."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from dashboard.backend.config import DashboardConfig  # noqa: E402
from dashboard.backend.reports.service import ReportService  # noqa: E402
from dashboard.backend.services.audit_service import AuditService  # noqa: E402

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


def _make_report_service(events: list[dict]) -> ReportService:
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8",
    ) as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
        log_path = f.name

    config = DashboardConfig(
        actions_dir=ACTIONS_DIR,
        policies_dir=POLICIES_DIR,
        inventory_file=INVENTORY_FILE,
        audit_log=log_path,
    )
    audit_svc = AuditService(config)
    return ReportService(audit_svc)


class TestSOC2Report:
    def test_generate_soc2(self) -> None:
        events = [
            _make_event(event_id="evt-1", decision="allow", risk_class="low"),
            _make_event(event_id="evt-2", decision="deny", risk_class="high"),
            _make_event(event_id="evt-3", decision="require_approval", risk_class="critical"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")

        assert report.report_type == "soc2"
        assert report.period["start"] == "2025-01-01"
        assert report.period["end"] == "2025-01-31"
        assert report.summary.total_decisions == 3
        assert report.summary.allowed == 1
        assert report.summary.denied == 1
        assert report.summary.approvals_required == 1

    def test_soc2_sections_present(self) -> None:
        events = [_make_event()]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")

        section_titles = [s.title for s in report.sections]
        assert any("Access Control" in t for t in section_titles)
        assert any("Change Management" in t for t in section_titles)
        assert any("Risk Assessment" in t for t in section_titles)
        assert any("Audit Trail" in t for t in section_titles)
        assert any("Incident Response" in t for t in section_titles)

    def test_soc2_denial_rate(self) -> None:
        events = [
            _make_event(event_id="evt-1", decision="allow"),
            _make_event(event_id="evt-2", decision="deny"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")
        assert report.summary.denial_rate == 0.5

    def test_soc2_empty_period(self) -> None:
        events = [
            _make_event(event_id="evt-1", timestamp="2025-03-15T10:00:00+00:00"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")
        assert report.summary.total_decisions == 0
        assert report.summary.denial_rate == 0.0


class TestISO27001Report:
    def test_generate_iso27001(self) -> None:
        events = [
            _make_event(event_id="evt-1", decision="allow"),
            _make_event(event_id="evt-2", decision="deny"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("iso27001", "2025-01-01", "2025-01-31")

        assert report.report_type == "iso27001"
        assert report.summary.total_decisions == 2

    def test_iso27001_sections_present(self) -> None:
        events = [_make_event()]
        svc = _make_report_service(events)
        report = svc.generate("iso27001", "2025-01-01", "2025-01-31")

        section_titles = [s.title for s in report.sections]
        assert any("Security Events" in t for t in section_titles)
        assert any("Access Management" in t for t in section_titles)
        assert any("Change Control" in t for t in section_titles)
        assert any("Monitoring" in t for t in section_titles)


class TestReportSummary:
    def test_unique_agents(self) -> None:
        events = [
            _make_event(event_id="evt-1", caller="agent-01"),
            _make_event(event_id="evt-2", caller="agent-02"),
            _make_event(event_id="evt-3", caller="agent-01"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")
        assert report.summary.unique_agents == 2

    def test_unique_targets(self) -> None:
        events = [
            _make_event(event_id="evt-1", target="dev/app1"),
            _make_event(event_id="evt-2", target="prod/app2"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")
        assert report.summary.unique_targets == 2

    def test_high_risk_count(self) -> None:
        events = [
            _make_event(event_id="evt-1", risk_class="low"),
            _make_event(event_id="evt-2", risk_class="high"),
            _make_event(event_id="evt-3", risk_class="critical"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")
        assert report.summary.high_risk_actions == 2


class TestReportEdgeCases:
    def test_unknown_report_type(self) -> None:
        svc = _make_report_service([])
        with pytest.raises(ValueError, match="Unknown report type"):
            svc.generate("pci-dss", "2025-01-01", "2025-01-31")

    def test_no_events(self) -> None:
        svc = _make_report_service([])
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")
        assert report.summary.total_decisions == 0
        assert report.summary.denial_rate == 0.0

    def test_state_capture_events_not_counted_as_decisions(self) -> None:
        events = [
            _make_event(event_id="evt-1", event_type="decision"),
            _make_event(event_id="evt-2", event_type="state_capture"),
        ]
        svc = _make_report_service(events)
        report = svc.generate("soc2", "2025-01-01", "2025-01-31")
        assert report.summary.total_decisions == 1
