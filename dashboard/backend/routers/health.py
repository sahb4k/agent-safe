"""Health check endpoint."""

from __future__ import annotations

from fastapi import APIRouter

from dashboard.backend.schemas import HealthResponse
from dashboard.backend.services.action_service import ActionService
from dashboard.backend.services.audit_service import AuditService
from dashboard.backend.services.policy_service import PolicyService

router = APIRouter(tags=["health"])

_audit: AuditService | None = None
_actions: ActionService | None = None
_policies: PolicyService | None = None
_version: str = "0.10.0"


def init_router(
    audit: AuditService,
    actions: ActionService,
    policies: PolicyService,
    version: str = "0.10.0",
) -> None:
    global _audit, _actions, _policies, _version  # noqa: PLW0603
    _audit = audit
    _actions = actions
    _policies = policies
    _version = version


@router.get("/api/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    return HealthResponse(
        version=_version,
        audit_events=_audit.event_count() if _audit else 0,
        actions=_actions.action_count() if _actions else 0,
        policies=_policies.policy_count() if _policies else 0,
    )
