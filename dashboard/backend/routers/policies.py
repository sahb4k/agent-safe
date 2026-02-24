"""Policy rule API endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from dashboard.backend.schemas import PolicyMatchAnalysis, PolicyRuleResponse
from dashboard.backend.services.policy_service import PolicyService

router = APIRouter(prefix="/api/policies", tags=["policies"])

_service: PolicyService | None = None


def init_router(service: PolicyService) -> None:
    global _service  # noqa: PLW0603
    _service = service


def _svc() -> PolicyService:
    assert _service is not None, "PolicyService not initialized"
    return _service


@router.get("/", response_model=list[PolicyRuleResponse])
def list_policies() -> list[PolicyRuleResponse]:
    return _svc().list_policies()


@router.get("/match-analysis", response_model=list[PolicyMatchAnalysis])
def get_match_analysis() -> list[PolicyMatchAnalysis]:
    return _svc().get_match_analysis()
