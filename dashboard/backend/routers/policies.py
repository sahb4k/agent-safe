"""Policy rule API endpoints (file-based read-only + managed CRUD)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from dashboard.backend.auth.dependencies import (
    SessionClaims,
    require_admin,
    require_auth,
    require_editor_or_above,
)
from dashboard.backend.auth.tier import has_feature
from dashboard.backend.managed_policies.models import (
    ClusterSyncStatus,
    ManagedPolicyCreateRequest,
    ManagedPolicyInfo,
    ManagedPolicyUpdateRequest,
    PolicyRevisionInfo,
    PublishRequest,
    PublishResponse,
)
from dashboard.backend.managed_policies.service import ManagedPolicyService
from dashboard.backend.schemas import PolicyMatchAnalysis, PolicyRuleResponse
from dashboard.backend.services.policy_service import PolicyService

router = APIRouter(prefix="/api/policies", tags=["policies"])

_service: PolicyService | None = None
_managed_service: ManagedPolicyService | None = None
_tier: str = "free"


def init_router(
    service: PolicyService,
    managed_service: ManagedPolicyService | None = None,
    tier: str = "free",
) -> None:
    global _service, _managed_service, _tier  # noqa: PLW0603
    _service = service
    _managed_service = managed_service
    _tier = tier


def _svc() -> PolicyService:
    assert _service is not None, "PolicyService not initialized"
    return _service


def _managed_svc() -> ManagedPolicyService:
    assert _managed_service is not None, "ManagedPolicyService not initialized"
    return _managed_service


def _check_feature() -> None:
    if not has_feature(_tier, "policies"):
        raise HTTPException(status_code=403, detail="Policy management requires a paid tier")


# ------------------------------------------------------------------
# File-based policies (read-only, no auth required) — unchanged
# ------------------------------------------------------------------


@router.get("/", response_model=list[PolicyRuleResponse])
def list_policies() -> list[PolicyRuleResponse]:
    return _svc().list_policies()


@router.get("/match-analysis", response_model=list[PolicyMatchAnalysis])
def get_match_analysis() -> list[PolicyMatchAnalysis]:
    return _svc().get_match_analysis()


# ------------------------------------------------------------------
# Managed policies (CRUD, paid tier, auth required)
# ------------------------------------------------------------------


@router.get("/managed", response_model=list[ManagedPolicyInfo])
def list_managed_policies(
    _user: Annotated[SessionClaims, Depends(require_auth)],
    include_inactive: bool = False,
) -> list[ManagedPolicyInfo]:
    _check_feature()
    return _managed_svc().list_policies(include_inactive=include_inactive)


@router.post("/managed", response_model=ManagedPolicyInfo, status_code=201)
def create_managed_policy(
    body: ManagedPolicyCreateRequest,
    user: Annotated[SessionClaims, Depends(require_editor_or_above)],
) -> ManagedPolicyInfo:
    _check_feature()
    try:
        return _managed_svc().create_policy(body, created_by=user.username)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e


@router.get("/managed/{policy_id}", response_model=ManagedPolicyInfo)
def get_managed_policy(
    policy_id: str,
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> ManagedPolicyInfo:
    _check_feature()
    policy = _managed_svc().get_policy(policy_id)
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.put("/managed/{policy_id}", response_model=ManagedPolicyInfo)
def update_managed_policy(
    policy_id: str,
    body: ManagedPolicyUpdateRequest,
    _user: Annotated[SessionClaims, Depends(require_editor_or_above)],
) -> ManagedPolicyInfo:
    _check_feature()
    try:
        policy = _managed_svc().update_policy(policy_id, body)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if policy is None:
        raise HTTPException(status_code=404, detail="Policy not found")
    return policy


@router.delete("/managed/{policy_id}")
def delete_managed_policy(
    policy_id: str,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> dict[str, bool]:
    _check_feature()
    if not _managed_svc().delete_policy(policy_id):
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"ok": True}


# ------------------------------------------------------------------
# Publishing & Revisions
# ------------------------------------------------------------------


@router.post("/publish", response_model=PublishResponse)
def publish_policies(
    body: PublishRequest,
    user: Annotated[SessionClaims, Depends(require_admin)],
) -> PublishResponse:
    _check_feature()
    return _managed_svc().publish(published_by=user.username, notes=body.notes)


@router.get("/revisions", response_model=list[PolicyRevisionInfo])
def list_revisions(
    _user: Annotated[SessionClaims, Depends(require_auth)],
    limit: int = 20,
) -> list[PolicyRevisionInfo]:
    _check_feature()
    return _managed_svc().list_revisions(limit=limit)


@router.get("/revisions/latest", response_model=PolicyRevisionInfo)
def get_latest_revision(
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> PolicyRevisionInfo:
    _check_feature()
    rev = _managed_svc().get_latest_revision()
    if rev is None:
        raise HTTPException(status_code=404, detail="No revisions published yet")
    return rev


# ------------------------------------------------------------------
# Cluster Sync Status
# ------------------------------------------------------------------


@router.get("/sync-status", response_model=list[ClusterSyncStatus])
def get_sync_status(
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> list[ClusterSyncStatus]:
    _check_feature()
    return _managed_svc().get_sync_status()
