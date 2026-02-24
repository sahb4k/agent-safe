"""FastAPI dependencies for authentication and authorization."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from dashboard.backend.auth.models import DashboardRole, SessionClaims
from dashboard.backend.auth.service import AuthService

# Module-level service reference, set by app factory.
_auth_service: AuthService | None = None
_tier: str = "free"


def init_auth(service: AuthService, tier: str) -> None:
    """Called by the app factory to inject the auth service."""
    global _auth_service, _tier  # noqa: PLW0603
    _auth_service = service
    _tier = tier


def _get_auth_service() -> AuthService:
    assert _auth_service is not None, "AuthService not initialized"
    return _auth_service


def optional_auth(request: Request) -> SessionClaims | None:
    """Return user claims if present, None otherwise.

    In free tier, always returns None (no auth required).
    In paid tiers, extracts and validates the Bearer token.
    """
    if _tier == "free":
        return None

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]
    svc = _get_auth_service()
    return svc.validate_session(token)


def require_auth(
    user: Annotated[SessionClaims | None, Depends(optional_auth)],
) -> SessionClaims:
    """Require a valid session. Returns 401 if missing/invalid.

    In free tier, this is a no-op (returns a synthetic viewer session).
    """
    if _tier == "free":
        return SessionClaims(
            sub="free-user",
            username="free",
            role="admin",
            type="dashboard-session",
            iat=0,
            exp=0,
        )
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def require_admin(
    user: Annotated[SessionClaims, Depends(require_auth)],
) -> SessionClaims:
    """Require admin role."""
    if _tier != "free" and user.role != DashboardRole.ADMIN.value:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


def require_editor_or_above(
    user: Annotated[SessionClaims, Depends(require_auth)],
) -> SessionClaims:
    """Require editor or admin role."""
    allowed = {DashboardRole.ADMIN.value, DashboardRole.EDITOR.value}
    if _tier != "free" and user.role not in allowed:
        raise HTTPException(status_code=403, detail="Editor access required")
    return user
