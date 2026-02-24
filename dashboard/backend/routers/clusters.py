"""Cluster management, event ingestion, and aggregated audit views."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from dashboard.backend.auth.dependencies import require_admin, require_auth
from dashboard.backend.auth.models import SessionClaims
from dashboard.backend.auth.tier import has_feature
from dashboard.backend.clusters.models import (
    ClusterCreateRequest,
    ClusterCreateResponse,
    ClusterInfo,
    IngestRequest,
    IngestResponse,
)
from dashboard.backend.clusters.service import ClusterService
from dashboard.backend.schemas import AuditStatsResponse, PaginatedResponse

router = APIRouter(prefix="/api/clusters", tags=["clusters"])

_service: ClusterService | None = None
_tier: str = "free"


def init_router(service: ClusterService, tier: str) -> None:
    global _service, _tier  # noqa: PLW0603
    _service = service
    _tier = tier


def _svc() -> ClusterService:
    assert _service is not None, "ClusterService not initialized"
    return _service


def _check_feature() -> None:
    if not has_feature(_tier, "clusters"):
        raise HTTPException(status_code=403, detail="Cluster management requires a paid tier")


def _extract_bearer_token(request: Request) -> str | None:
    """Extract a Bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header[7:]


# ------------------------------------------------------------------
# Cluster CRUD (admin, paid tier)
# ------------------------------------------------------------------


@router.post("/", response_model=ClusterCreateResponse, status_code=201)
def register_cluster(
    body: ClusterCreateRequest,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> ClusterCreateResponse:
    _check_feature()
    try:
        return _svc().register_cluster(name=body.name, description=body.description)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e


@router.get("/", response_model=list[ClusterInfo])
def list_clusters(
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> list[ClusterInfo]:
    _check_feature()
    return _svc().list_clusters()


@router.get("/events", response_model=PaginatedResponse)
def list_all_cluster_events(
    _user: Annotated[SessionClaims, Depends(require_auth)],
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
    """Aggregated events from all clusters."""
    _check_feature()
    return _svc().get_cluster_events(
        cluster_id=None,
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
def get_all_cluster_stats(
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> AuditStatsResponse:
    """Aggregated stats from all clusters."""
    _check_feature()
    return _svc().get_cluster_stats()


@router.get("/{cluster_id}", response_model=ClusterInfo)
def get_cluster(
    cluster_id: str,
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> ClusterInfo:
    _check_feature()
    cluster = _svc().get_cluster(cluster_id)
    if cluster is None:
        raise HTTPException(status_code=404, detail="Cluster not found")
    return cluster


@router.delete("/{cluster_id}")
def deactivate_cluster(
    cluster_id: str,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> dict:
    _check_feature()
    if not _svc().deactivate_cluster(cluster_id):
        raise HTTPException(status_code=404, detail="Cluster not found")
    return {"ok": True}


@router.get("/{cluster_id}/events", response_model=PaginatedResponse)
def list_cluster_events(
    cluster_id: str,
    _user: Annotated[SessionClaims, Depends(require_auth)],
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
    _check_feature()
    return _svc().get_cluster_events(
        cluster_id=cluster_id,
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


@router.get("/{cluster_id}/stats", response_model=AuditStatsResponse)
def get_cluster_stats(
    cluster_id: str,
    _user: Annotated[SessionClaims, Depends(require_auth)],
) -> AuditStatsResponse:
    _check_feature()
    return _svc().get_cluster_stats(cluster_id=cluster_id)


# ------------------------------------------------------------------
# Event Ingestion (API key auth, NOT JWT)
# ------------------------------------------------------------------


@router.post("/ingest", response_model=IngestResponse)
def ingest_events(
    request: Request,
    body: IngestRequest,
) -> IngestResponse:
    """Receive audit events from a remote sidecar.

    Authentication is via API key (Bearer token), not JWT session.
    """
    api_key = _extract_bearer_token(request)
    if not api_key:
        raise HTTPException(status_code=401, detail="API key required")
    cluster_id = _svc().validate_api_key(api_key)
    if not cluster_id:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return _svc().ingest_events(cluster_id, body.events)
