"""Action registry API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from dashboard.backend.schemas import ActionDetailResponse, ActionSummary
from dashboard.backend.services.action_service import ActionService

router = APIRouter(prefix="/api/actions", tags=["actions"])

_service: ActionService | None = None


def init_router(service: ActionService) -> None:
    global _service  # noqa: PLW0603
    _service = service


def _svc() -> ActionService:
    assert _service is not None, "ActionService not initialized"
    return _service


@router.get("/", response_model=list[ActionSummary])
def list_actions(
    tag: str | None = None,
    risk: str | None = None,
) -> list[ActionSummary]:
    return _svc().list_actions(tag=tag, risk=risk)


@router.get("/{name}", response_model=ActionDetailResponse)
def get_action(name: str) -> ActionDetailResponse:
    result = _svc().get_action(name)
    if result is None:
        raise HTTPException(status_code=404, detail=f"Action '{name}' not found")
    return result
