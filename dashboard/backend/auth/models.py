"""Authentication and user data models."""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class DashboardRole(enum.StrEnum):
    ADMIN = "admin"
    EDITOR = "editor"
    VIEWER = "viewer"


class DashboardUser(BaseModel):
    """A dashboard user stored in SQLite."""

    user_id: str
    username: str
    display_name: str = ""
    email: str = ""
    role: DashboardRole = DashboardRole.VIEWER
    is_active: bool = True
    created_at: datetime
    last_login: datetime | None = None
    auth_provider: str = "local"
    external_id: str | None = None


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    user: UserInfo
    expires_in: int


class UserInfo(BaseModel):
    user_id: str
    username: str
    display_name: str
    role: str


class UserCreateRequest(BaseModel):
    username: str
    password: str
    display_name: str = ""
    email: str = ""
    role: str = "viewer"


class UserUpdateRequest(BaseModel):
    display_name: str | None = None
    email: str | None = None
    role: str | None = None
    is_active: bool | None = None


class PasswordResetRequest(BaseModel):
    new_password: str


class SSOConfigInfo(BaseModel):
    """Public SSO configuration info for the login page (no secrets)."""

    oidc_enabled: bool
    password_auth_enabled: bool
    provider_name: str = ""


class SessionClaims(BaseModel):
    """JWT payload for dashboard sessions."""

    sub: str
    username: str
    role: str
    type: str = "dashboard-session"
    iat: int
    exp: int

    def to_jwt_payload(self) -> dict[str, Any]:
        return self.model_dump()
