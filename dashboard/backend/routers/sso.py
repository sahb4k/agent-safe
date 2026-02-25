"""SSO/OIDC authentication endpoints (enterprise tier)."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, Request

from dashboard.backend.auth.models import LoginResponse, SSOConfigInfo
from dashboard.backend.auth.sso_service import SSOService
from dashboard.backend.auth.tier import has_feature

router = APIRouter(prefix="/api/auth/sso", tags=["sso"])

_service: SSOService | None = None
_tier: str = "free"
_password_auth_enabled: bool = True


def init_router(
    service: SSOService,
    tier: str,
    password_auth_enabled: bool = True,
) -> None:
    global _service, _tier, _password_auth_enabled  # noqa: PLW0603
    _service = service
    _tier = tier
    _password_auth_enabled = password_auth_enabled


def _svc() -> SSOService:
    assert _service is not None, "SSOService not initialized"
    return _service


def _check_feature() -> None:
    if not has_feature(_tier, "sso"):
        raise HTTPException(
            status_code=403, detail="SSO requires enterprise tier",
        )


@router.get("/config", response_model=SSOConfigInfo)
def sso_config() -> SSOConfigInfo:
    """Public SSO configuration for the login page."""
    if not has_feature(_tier, "sso") or _service is None:
        return SSOConfigInfo(
            oidc_enabled=False,
            password_auth_enabled=_password_auth_enabled,
        )
    return SSOConfigInfo(
        oidc_enabled=True,
        password_auth_enabled=_password_auth_enabled,
        provider_name=_svc().get_provider_name(),
    )


@router.get("/authorize")
def authorize(
    request: Request,
    redirect_to: str = Query("/", description="Where to redirect after login"),
) -> dict:
    """Returns the OIDC authorization URL for the frontend to redirect to."""
    _check_feature()
    redirect_uri = str(request.base_url).rstrip("/") + "/api/auth/sso/callback"
    url = _svc().create_authorize_url(redirect_uri, redirect_to)
    return {"authorize_url": url}


@router.get("/callback")
def callback_redirect(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
) -> dict:
    """Handle OIDC provider redirect (browser GET).

    Returns the token directly — frontend SSOCallbackPage will POST
    to /api/auth/sso/token instead for the standard SPA flow.
    This endpoint exists as a fallback.
    """
    _check_feature()
    redirect_uri = str(request.base_url).rstrip("/") + "/api/auth/sso/callback"
    try:
        result = _svc().handle_callback(code, state, redirect_uri)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "token": result.token,
        "user": result.user.model_dump(),
        "expires_in": result.expires_in,
    }


@router.post("/token", response_model=LoginResponse)
def exchange_token(
    request: Request,
    code: str = Query(...),
    state: str = Query(...),
) -> LoginResponse:
    """Exchange authorization code + state for a JWT session token.

    Called by the frontend SSOCallbackPage after OIDC redirect.
    """
    _check_feature()
    redirect_uri = str(request.base_url).rstrip("/") + "/api/auth/sso/callback"
    try:
        return _svc().handle_callback(code, state, redirect_uri)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
