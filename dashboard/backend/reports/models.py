"""Compliance report data models."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class ComplianceReportRequest(BaseModel):
    """Request to generate a compliance report."""

    report_type: str  # "soc2" | "iso27001"
    start_date: str  # ISO date YYYY-MM-DD
    end_date: str  # ISO date YYYY-MM-DD


class ReportSummary(BaseModel):
    """High-level summary of the report period."""

    total_decisions: int
    allowed: int
    denied: int
    approvals_required: int
    unique_agents: int
    unique_targets: int
    high_risk_actions: int
    denial_rate: float
    audit_chain_valid: bool


class ReportSection(BaseModel):
    """A section of a compliance report."""

    title: str
    description: str
    items: list[dict[str, Any]]


class ComplianceReportResponse(BaseModel):
    """Complete compliance report."""

    report_type: str
    generated_at: datetime
    period: dict[str, str]
    summary: ReportSummary
    sections: list[ReportSection]
