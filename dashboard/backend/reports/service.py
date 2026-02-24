"""Compliance report generation from audit data."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from agent_safe.models import AuditEvent
from dashboard.backend.reports.models import (
    ComplianceReportResponse,
    ReportSection,
    ReportSummary,
)
from dashboard.backend.services.audit_service import AuditService


class ReportService:
    """Generates SOC2 and ISO 27001 compliance reports from audit data."""

    def __init__(self, audit_svc: AuditService) -> None:
        self._audit_svc = audit_svc

    def generate(
        self,
        report_type: str,
        start_date: str,
        end_date: str,
    ) -> ComplianceReportResponse:
        """Generate a compliance report for the given period."""
        events = self._filter_events(start_date, end_date)
        summary = self._build_summary(events)

        if report_type == "soc2":
            sections = self._soc2_sections(events, summary)
        elif report_type == "iso27001":
            sections = self._iso27001_sections(events, summary)
        else:
            raise ValueError(f"Unknown report type: {report_type}")

        return ComplianceReportResponse(
            report_type=report_type,
            generated_at=datetime.now(UTC),
            period={"start": start_date, "end": end_date},
            summary=summary,
            sections=sections,
        )

    def _filter_events(self, start_date: str, end_date: str) -> list[AuditEvent]:
        """Get all audit events in the date range."""
        all_events = self._audit_svc._load_events()
        start_dt = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
        end_dt = datetime.fromisoformat(f"{end_date}T23:59:59").replace(tzinfo=UTC)
        return [
            e
            for e in all_events
            if start_dt <= e.timestamp <= end_dt
        ]

    def _build_summary(self, events: list[AuditEvent]) -> ReportSummary:
        decisions = [e for e in events if e.event_type == "decision"]
        allowed = sum(1 for d in decisions if d.decision.value == "allow")
        denied = sum(1 for d in decisions if d.decision.value == "deny")
        approvals = sum(1 for d in decisions if d.decision.value == "require_approval")
        unique_agents = len({d.caller for d in decisions})
        unique_targets = len({d.target for d in decisions})
        high_risk = sum(
            1 for d in decisions if d.risk_class.value in ("high", "critical")
        )
        total = len(decisions)

        # Verify audit chain integrity
        chain_valid = True
        try:
            logger = self._audit_svc._logger
            valid, _errors = logger.verify_log()
            chain_valid = valid
        except Exception:
            chain_valid = False

        return ReportSummary(
            total_decisions=total,
            allowed=allowed,
            denied=denied,
            approvals_required=approvals,
            unique_agents=unique_agents,
            unique_targets=unique_targets,
            high_risk_actions=high_risk,
            denial_rate=round(denied / total, 4) if total > 0 else 0.0,
            audit_chain_valid=chain_valid,
        )

    def _soc2_sections(
        self,
        events: list[AuditEvent],
        summary: ReportSummary,
    ) -> list[ReportSection]:
        decisions = [e for e in events if e.event_type == "decision"]
        return [
            self._access_control_section(decisions),
            self._change_management_section(decisions),
            self._risk_assessment_section(decisions),
            self._audit_trail_section(summary),
            self._incident_response_section(decisions),
        ]

    def _iso27001_sections(
        self,
        events: list[AuditEvent],
        summary: ReportSummary,
    ) -> list[ReportSection]:
        decisions = [e for e in events if e.event_type == "decision"]
        return [
            self._security_events_section(decisions),
            self._access_management_section(decisions),
            self._change_control_section(events),
            self._monitoring_section(decisions, summary),
        ]

    # --- SOC2 Sections ---

    def _access_control_section(self, decisions: list[AuditEvent]) -> ReportSection:
        agents: dict[str, dict[str, Any]] = {}
        for d in decisions:
            if d.caller not in agents:
                agents[d.caller] = {
                    "agent": d.caller,
                    "total_actions": 0,
                    "allowed": 0,
                    "denied": 0,
                    "targets_accessed": set(),
                }
            agents[d.caller]["total_actions"] += 1
            agents[d.caller][d.decision.value] = (
                agents[d.caller].get(d.decision.value, 0) + 1
            )
            agents[d.caller]["targets_accessed"].add(d.target)

        items = []
        for info in agents.values():
            items.append({
                "agent": info["agent"],
                "total_actions": info["total_actions"],
                "allowed": info.get("allow", 0),
                "denied": info.get("deny", 0),
                "unique_targets": len(info["targets_accessed"]),
            })

        return ReportSection(
            title="CC6.1 — Access Control Evidence",
            description=(
                "All agent identities that requested actions during the report period, "
                "with decision outcomes and target scope."
            ),
            items=sorted(items, key=lambda x: x["total_actions"], reverse=True),
        )

    def _change_management_section(self, decisions: list[AuditEvent]) -> ReportSection:
        actions: Counter[str] = Counter()
        for d in decisions:
            actions[d.action] += 1

        items = [
            {"action": action, "count": count}
            for action, count in actions.most_common()
        ]

        return ReportSection(
            title="CC8.1 — Change Management",
            description=(
                "All infrastructure actions requested during the report period, "
                "including those that required approval or were denied by policy."
            ),
            items=items,
        )

    def _risk_assessment_section(self, decisions: list[AuditEvent]) -> ReportSection:
        risk_dist: Counter[str] = Counter()
        for d in decisions:
            risk_dist[d.effective_risk.value] += 1

        items = [
            {"risk_class": risk, "count": count}
            for risk, count in risk_dist.most_common()
        ]

        return ReportSection(
            title="CC3.2 — Risk Assessment",
            description=(
                "Distribution of actions by effective risk class "
                "(action risk x target sensitivity)."
            ),
            items=items,
        )

    def _audit_trail_section(self, summary: ReportSummary) -> ReportSection:
        return ReportSection(
            title="CC7.2 — Audit Trail Integrity",
            description=(
                "Verification of the hash-chained audit log. Each entry contains a "
                "SHA-256 hash linking to the previous entry, creating a tamper-evident chain."
            ),
            items=[
                {
                    "check": "Hash-chain integrity",
                    "result": "PASS" if summary.audit_chain_valid else "FAIL",
                    "total_events": summary.total_decisions,
                },
            ],
        )

    def _incident_response_section(self, decisions: list[AuditEvent]) -> ReportSection:
        denials = [
            {
                "timestamp": d.timestamp.isoformat(),
                "action": d.action,
                "target": d.target,
                "caller": d.caller,
                "risk_class": d.effective_risk.value,
                "reason": d.reason,
            }
            for d in decisions
            if d.decision.value == "deny"
            and d.effective_risk.value in ("high", "critical")
        ]

        return ReportSection(
            title="CC7.4 — Incident Response",
            description=(
                "High-risk and critical actions that were denied by policy. "
                "These represent potential security incidents or policy violations."
            ),
            items=denials[:100],  # Cap at 100 entries
        )

    # --- ISO 27001 Sections ---

    def _security_events_section(self, decisions: list[AuditEvent]) -> ReportSection:
        items = [
            {
                "timestamp": d.timestamp.isoformat(),
                "action": d.action,
                "target": d.target,
                "caller": d.caller,
                "decision": d.decision.value,
                "risk_class": d.risk_class.value,
                "effective_risk": d.effective_risk.value,
            }
            for d in decisions[-200:]  # Most recent 200
        ]

        return ReportSection(
            title="A.12.4 — Information Security Events",
            description=(
                "All policy decisions with risk classification. "
                "Shows the governance layer's evaluation of each agent request."
            ),
            items=items,
        )

    def _access_management_section(self, decisions: list[AuditEvent]) -> ReportSection:
        caller_summary: dict[str, dict[str, int]] = {}
        for d in decisions:
            if d.caller not in caller_summary:
                caller_summary[d.caller] = {"allow": 0, "deny": 0, "require_approval": 0}
            caller_summary[d.caller][d.decision.value] = (
                caller_summary[d.caller].get(d.decision.value, 0) + 1
            )

        items = [
            {"agent": caller, **counts}
            for caller, counts in sorted(caller_summary.items())
        ]

        return ReportSection(
            title="A.9.2 — Access Management",
            description=(
                "Agent identity access patterns showing decision distribution per agent."
            ),
            items=items,
        )

    def _change_control_section(self, events: list[AuditEvent]) -> ReportSection:
        state_captures = [e for e in events if e.event_type == "state_capture"]
        approvals = [
            e for e in events
            if e.event_type == "decision" and e.decision.value == "require_approval"
        ]

        items: list[dict[str, Any]] = [
            {
                "metric": "State captures recorded",
                "count": len(state_captures),
            },
            {
                "metric": "Actions requiring approval",
                "count": len(approvals),
            },
        ]

        return ReportSection(
            title="A.12.1 — Change Control",
            description=(
                "Evidence of change control processes including approval workflows "
                "and before/after state capture."
            ),
            items=items,
        )

    def _monitoring_section(
        self,
        decisions: list[AuditEvent],
        summary: ReportSummary,
    ) -> ReportSection:
        # Group by day
        daily: Counter[str] = Counter()
        for d in decisions:
            day = d.timestamp.strftime("%Y-%m-%d")
            daily[day] += 1

        items = [
            {"date": day, "decisions": count}
            for day, count in sorted(daily.items())
        ]

        return ReportSection(
            title="A.12.4 — Monitoring & Review",
            description=(
                "Daily decision volume showing governance activity patterns. "
                f"Audit chain integrity: {'PASS' if summary.audit_chain_valid else 'FAIL'}."
            ),
            items=items,
        )
