"""Alert rule management and alert history API."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from dashboard.backend.alerts.models import (
    AlertHistoryItem,
    AlertRuleCreateRequest,
    AlertRuleInfo,
    AlertRuleUpdateRequest,
)
from dashboard.backend.alerts.service import AlertService
from dashboard.backend.auth.dependencies import require_admin, require_auth
from dashboard.backend.auth.models import SessionClaims
from dashboard.backend.auth.tier import has_feature

router = APIRouter(prefix="/api/alerts", tags=["alerts"])

_service: AlertService | None = None
_tier: str = "free"


def init_router(service: AlertService, tier: str) -> None:
    global _service, _tier  # noqa: PLW0603
    _service = service
    _tier = tier


def _svc() -> AlertService:
    assert _service is not None, "AlertService not initialized"
    return _service


def _check_feature() -> None:
    if not has_feature(_tier, "alerts"):
        raise HTTPException(
            status_code=403, detail="Alert rules require a paid tier",
        )


# ------------------------------------------------------------------
# Rule CRUD
# ------------------------------------------------------------------


@router.get("/rules", response_model=list[AlertRuleInfo])
def list_rules(
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> list[AlertRuleInfo]:
    _check_feature()
    return _svc().list_rules()


@router.post("/rules", response_model=AlertRuleInfo, status_code=201)
def create_rule(
    body: AlertRuleCreateRequest,
    user: Annotated[SessionClaims, Depends(require_admin)],
) -> AlertRuleInfo:
    _check_feature()
    try:
        return _svc().create_rule(body, created_by=user.sub)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e


@router.get("/rules/{rule_id}", response_model=AlertRuleInfo)
def get_rule(
    rule_id: str,
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> AlertRuleInfo:
    _check_feature()
    rule = _svc().get_rule(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return rule


@router.put("/rules/{rule_id}", response_model=AlertRuleInfo)
def update_rule(
    rule_id: str,
    body: AlertRuleUpdateRequest,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> AlertRuleInfo:
    _check_feature()
    try:
        result = _svc().update_rule(rule_id, body)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    if result is None:
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return result


@router.delete("/rules/{rule_id}")
def delete_rule(
    rule_id: str,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> dict:
    _check_feature()
    if not _svc().delete_rule(rule_id):
        raise HTTPException(status_code=404, detail="Alert rule not found")
    return {"ok": True}


# ------------------------------------------------------------------
# History
# ------------------------------------------------------------------


@router.get("/history", response_model=list[AlertHistoryItem])
def list_history(
    _user: Annotated[SessionClaims, Depends(require_auth)],
    limit: int = Query(50, ge=1, le=200),
    rule_id: str | None = None,
    cluster_id: str | None = None,
) -> list[AlertHistoryItem]:
    _check_feature()
    return _svc().list_history(
        limit=limit, rule_id=rule_id, cluster_id=cluster_id,
    )
