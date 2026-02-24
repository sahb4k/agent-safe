"""Activity feed API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Query

from dashboard.backend.schemas import ActivityFeedItem
from dashboard.backend.services.activity_service import ActivityService

router = APIRouter(prefix="/api/activity", tags=["activity"])

_service: ActivityService | None = None


def init_router(service: ActivityService) -> None:
    global _service  # noqa: PLW0603
    _service = service


def _svc() -> ActivityService:
    assert _service is not None, "ActivityService not initialized"
    return _service


@router.get("/feed", response_model=list[ActivityFeedItem])
def get_feed(
    limit: int = Query(50, ge=1, le=200),
) -> list[ActivityFeedItem]:
    return _svc().get_feed(limit=limit)


@router.get("/recent-decisions", response_model=list[ActivityFeedItem])
def get_recent_decisions(
    limit: int = Query(10, ge=1, le=50),
) -> list[ActivityFeedItem]:
    return _svc().get_recent_decisions(limit=limit)
