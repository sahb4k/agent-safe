"""Authentication API endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from dashboard.backend.auth.dependencies import require_auth
from dashboard.backend.auth.models import LoginRequest, LoginResponse, SessionClaims, UserInfo
from dashboard.backend.auth.service import AuthService

router = APIRouter(prefix="/api/auth", tags=["auth"])

_service: AuthService | None = None


def init_router(service: AuthService) -> None:
    global _service  # noqa: PLW0603
    _service = service


def _svc() -> AuthService:
    assert _service is not None, "AuthService not initialized"
    return _service


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest) -> LoginResponse:
    result = _svc().login(body.username, body.password)
    if result is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return result


@router.post("/logout")
def logout() -> dict:
    # Stateless JWT — logout is client-side token removal.
    return {"ok": True}


@router.get("/me", response_model=UserInfo)
def me(user: Annotated[SessionClaims, Depends(require_auth)]) -> UserInfo:
    return UserInfo(
        user_id=user.sub,
        username=user.username,
        display_name=user.username,
        role=user.role,
    )


@router.get("/tier")
def tier_info() -> dict:
    """Return the current tier (public, used by frontend to decide UI)."""
    from dashboard.backend.auth.dependencies import _tier

    return {"tier": _tier}
