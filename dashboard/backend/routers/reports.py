"""Compliance report API endpoints (paid tier)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from dashboard.backend.auth.dependencies import require_auth
from dashboard.backend.auth.models import SessionClaims
from dashboard.backend.reports.models import ComplianceReportRequest, ComplianceReportResponse
from dashboard.backend.reports.service import ReportService

router = APIRouter(prefix="/api/reports", tags=["reports"])

_service: ReportService | None = None


def init_router(service: ReportService) -> None:
    global _service  # noqa: PLW0603
    _service = service


def _svc() -> ReportService:
    assert _service is not None, "ReportService not initialized"
    return _service


@router.post("/generate", response_model=ComplianceReportResponse)
def generate_report(
    body: ComplianceReportRequest,
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> ComplianceReportResponse:
    if body.report_type not in ("soc2", "iso27001"):
        raise HTTPException(
            status_code=400,
            detail=f"Unknown report type: {body.report_type}. Use 'soc2' or 'iso27001'.",
        )
    try:
        return _svc().generate(body.report_type, body.start_date, body.end_date)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
