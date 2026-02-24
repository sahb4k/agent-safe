"""Audit event API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from dashboard.backend.schemas import AuditStatsResponse, PaginatedResponse, TimelineBucket
from dashboard.backend.services.audit_service import AuditService

router = APIRouter(prefix="/api/audit", tags=["audit"])

# Service is injected by the app factory via router.state
_service: AuditService | None = None


def init_router(service: AuditService) -> None:
    global _service  # noqa: PLW0603
    _service = service


def _svc() -> AuditService:
    assert _service is not None, "AuditService not initialized"
    return _service


@router.get("/events", response_model=PaginatedResponse)
def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    event_type: str | None = None,
    action: str | None = None,
    target: str | None = None,
    risk_class: str | None = None,
    decision: str | None = None,
    start_date: str | None = None,
    end_date: str | None = None,
) -> PaginatedResponse:
    return _svc().get_events(
        page=page,
        page_size=page_size,
        event_type=event_type,
        action=action,
        target=target,
        risk_class=risk_class,
        decision=decision,
        start_date=start_date,
        end_date=end_date,
    )


@router.get("/stats", response_model=AuditStatsResponse)
def get_stats() -> AuditStatsResponse:
    return _svc().get_stats()


@router.get("/timeline", response_model=list[TimelineBucket])
def get_timeline(
    bucket_hours: int = Query(1, ge=1, le=24),
) -> list[TimelineBucket]:
    return _svc().get_timeline(bucket_hours=bucket_hours)
