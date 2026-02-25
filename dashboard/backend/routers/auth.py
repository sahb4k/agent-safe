"""Authentication API endpoints."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from dashboard.backend.auth.dependencies import require_auth
from dashboard.backend.auth.models import LoginRequest, LoginResponse, SessionClaims, UserInfo
from dashboard.backend.auth.service import AuthService

router = APIRouter(prefix="/api/auth", tags=["auth"])

_service: AuthService | None = None
_password_auth_enabled: bool = True
_sso_enabled: bool = False


def init_router(
    service: AuthService,
    password_auth_enabled: bool = True,
    sso_enabled: bool = False,
) -> None:
    global _service, _password_auth_enabled, _sso_enabled  # noqa: PLW0603
    _service = service
    _password_auth_enabled = password_auth_enabled
    _sso_enabled = sso_enabled


def _svc() -> AuthService:
    assert _service is not None, "AuthService not initialized"
    return _service


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest) -> LoginResponse:
    if not _password_auth_enabled:
        raise HTTPException(
            status_code=403, detail="Password authentication is disabled",
        )
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
    """Return the current tier and auth config (public, used by frontend)."""
    from dashboard.backend.auth.dependencies import _tier

    return {
        "tier": _tier,
        "sso_enabled": _sso_enabled,
        "password_auth_enabled": _password_auth_enabled,
    }
