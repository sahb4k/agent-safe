"""User management API endpoints (admin only, paid tier)."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from dashboard.backend.auth.dependencies import require_admin
from dashboard.backend.auth.models import (
    PasswordResetRequest,
    SessionClaims,
    UserCreateRequest,
    UserInfo,
    UserUpdateRequest,
)
from dashboard.backend.auth.service import AuthService
from dashboard.backend.auth.tier import has_feature

router = APIRouter(prefix="/api/users", tags=["users"])

_service: AuthService | None = None
_tier: str = "free"


def init_router(service: AuthService, tier: str) -> None:
    global _service, _tier  # noqa: PLW0603
    _service = service
    _tier = tier


def _svc() -> AuthService:
    assert _service is not None, "AuthService not initialized"
    return _service


def _check_feature() -> None:
    if not has_feature(_tier, "users"):
        raise HTTPException(status_code=403, detail="User management requires a paid tier")


@router.get("/", response_model=list[UserInfo])
def list_users(
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> list[UserInfo]:
    _check_feature()
    users = _svc().list_users()
    return [
        UserInfo(
            user_id=u.user_id,
            username=u.username,
            display_name=u.display_name,
            role=u.role.value,
        )
        for u in users
    ]


@router.post("/", response_model=UserInfo, status_code=201)
def create_user(
    body: UserCreateRequest,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> UserInfo:
    _check_feature()
    try:
        user = _svc().create_user(
            username=body.username,
            password=body.password,
            role=body.role,
            display_name=body.display_name,
            email=body.email,
        )
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e
    return UserInfo(
        user_id=user.user_id,
        username=user.username,
        display_name=user.display_name,
        role=user.role.value,
    )


@router.put("/{user_id}", response_model=UserInfo)
def update_user(
    user_id: str,
    body: UserUpdateRequest,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> UserInfo:
    _check_feature()
    try:
        user = _svc().update_user(
            user_id,
            display_name=body.display_name,
            email=body.email,
            role=body.role,
            is_active=body.is_active,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return UserInfo(
        user_id=user.user_id,
        username=user.username,
        display_name=user.display_name,
        role=user.role.value,
    )


@router.delete("/{user_id}")
def delete_user(
    user_id: str,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> dict:
    _check_feature()
    if not _svc().deactivate_user(user_id):
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}


@router.post("/{user_id}/reset-password")
def reset_password(
    user_id: str,
    body: PasswordResetRequest,
    _user: Annotated[SessionClaims, Depends(require_admin)],
) -> dict:
    _check_feature()
    if not _svc().reset_password(user_id, body.new_password):
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True}
