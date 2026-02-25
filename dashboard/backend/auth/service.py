"""Authentication service: user CRUD, password hashing, JWT sessions."""

from __future__ import annotations

import hashlib
import os
import time
import uuid
from datetime import UTC, datetime

import jwt

from dashboard.backend.auth.models import (
    DashboardRole,
    DashboardUser,
    LoginResponse,
    SessionClaims,
    UserInfo,
)
from dashboard.backend.db.connection import Database

# PBKDF2 parameters
_HASH_ITERATIONS = 260_000
_HASH_ALGO = "sha256"
_SALT_BYTES = 32

# Session defaults
SESSION_TTL_SECONDS = 8 * 3600  # 8 hours


def _hash_password(password: str, salt: str) -> str:
    """Hash a password with PBKDF2-SHA256."""
    dk = hashlib.pbkdf2_hmac(
        _HASH_ALGO,
        password.encode("utf-8"),
        bytes.fromhex(salt),
        _HASH_ITERATIONS,
    )
    return dk.hex()


def _generate_salt() -> str:
    return os.urandom(_SALT_BYTES).hex()


class AuthService:
    """Manages users, passwords, and JWT sessions."""

    def __init__(self, db: Database, signing_key: str) -> None:
        self._db = db
        self._signing_key = signing_key

    # --- User CRUD ---

    def create_user(
        self,
        username: str,
        password: str,
        role: str = "viewer",
        display_name: str = "",
        email: str = "",
    ) -> DashboardUser:
        """Create a new user. Raises ValueError if username is taken."""
        existing = self._db.fetchone(
            "SELECT user_id FROM users WHERE username = ?", (username,)
        )
        if existing:
            raise ValueError(f"Username '{username}' already exists")

        if role not in [r.value for r in DashboardRole]:
            raise ValueError(f"Invalid role: {role}")

        user_id = f"usr-{uuid.uuid4().hex[:12]}"
        salt = _generate_salt()
        password_hash = _hash_password(password, salt)
        now = datetime.now(UTC).isoformat()

        self._db.write(
            """INSERT INTO users
               (user_id, username, display_name, email, password_hash, salt, role, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, username, display_name, email, password_hash, salt, role, now),
        )

        return DashboardUser(
            user_id=user_id,
            username=username,
            display_name=display_name,
            email=email,
            role=DashboardRole(role),
            is_active=True,
            created_at=datetime.fromisoformat(now),
        )

    def get_user(self, user_id: str) -> DashboardUser | None:
        row = self._db.fetchone("SELECT * FROM users WHERE user_id = ?", (user_id,))
        return self._row_to_user(row) if row else None

    def get_user_by_username(self, username: str) -> DashboardUser | None:
        row = self._db.fetchone("SELECT * FROM users WHERE username = ?", (username,))
        return self._row_to_user(row) if row else None

    def list_users(self) -> list[DashboardUser]:
        rows = self._db.fetchall("SELECT * FROM users ORDER BY created_at")
        return [self._row_to_user(r) for r in rows]

    def update_user(
        self,
        user_id: str,
        *,
        display_name: str | None = None,
        email: str | None = None,
        role: str | None = None,
        is_active: bool | None = None,
    ) -> DashboardUser | None:
        user = self.get_user(user_id)
        if user is None:
            return None

        updates: list[str] = []
        params: list[str | int] = []

        if display_name is not None:
            updates.append("display_name = ?")
            params.append(display_name)
        if email is not None:
            updates.append("email = ?")
            params.append(email)
        if role is not None:
            if role not in [r.value for r in DashboardRole]:
                raise ValueError(f"Invalid role: {role}")
            updates.append("role = ?")
            params.append(role)
        if is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if is_active else 0)

        if updates:
            params.append(user_id)
            self._db.write(
                f"UPDATE users SET {', '.join(updates)} WHERE user_id = ?",
                tuple(params),
            )

        return self.get_user(user_id)

    def deactivate_user(self, user_id: str) -> bool:
        result = self.update_user(user_id, is_active=False)
        return result is not None

    def reset_password(self, user_id: str, new_password: str) -> bool:
        user = self.get_user(user_id)
        if user is None:
            return False
        salt = _generate_salt()
        password_hash = _hash_password(new_password, salt)
        self._db.write(
            "UPDATE users SET password_hash = ?, salt = ? WHERE user_id = ?",
            (password_hash, salt, user_id),
        )
        return True

    def user_count(self) -> int:
        row = self._db.fetchone("SELECT COUNT(*) as cnt FROM users")
        return int(row["cnt"]) if row else 0

    # --- Authentication ---

    def verify_password(self, username: str, password: str) -> DashboardUser | None:
        """Verify credentials. Returns user if valid, None if invalid."""
        row = self._db.fetchone(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,),
        )
        if row is None:
            return None

        computed = _hash_password(password, row["salt"])
        if computed != row["password_hash"]:
            return None

        # Update last_login
        now = datetime.now(UTC).isoformat()
        self._db.write(
            "UPDATE users SET last_login = ? WHERE user_id = ?",
            (now, row["user_id"]),
        )

        return self._row_to_user(row)

    def login(self, username: str, password: str) -> LoginResponse | None:
        """Verify credentials and create a session token."""
        user = self.verify_password(username, password)
        if user is None:
            return None

        token = self._create_session_token(user)
        return LoginResponse(
            token=token,
            user=UserInfo(
                user_id=user.user_id,
                username=user.username,
                display_name=user.display_name,
                role=user.role.value,
            ),
            expires_in=SESSION_TTL_SECONDS,
        )

    # --- Sessions ---

    def _create_session_token(self, user: DashboardUser) -> str:
        now = int(time.time())
        claims = SessionClaims(
            sub=user.user_id,
            username=user.username,
            role=user.role.value,
            type="dashboard-session",
            iat=now,
            exp=now + SESSION_TTL_SECONDS,
        )
        return jwt.encode(claims.to_jwt_payload(), self._signing_key, algorithm="HS256")

    def validate_session(self, token: str) -> SessionClaims | None:
        """Validate a JWT session token. Returns claims or None."""
        try:
            payload = jwt.decode(token, self._signing_key, algorithms=["HS256"])
            if payload.get("type") != "dashboard-session":
                return None
            return SessionClaims(**payload)
        except jwt.PyJWTError:
            return None

    # --- SSO User Methods ---

    def create_sso_user(
        self,
        external_id: str,
        username: str,
        display_name: str = "",
        email: str = "",
        role: str = "viewer",
    ) -> DashboardUser:
        """Create a user provisioned via SSO (no password)."""
        if role not in [r.value for r in DashboardRole]:
            raise ValueError(f"Invalid role: {role}")

        user_id = f"usr-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC).isoformat()

        self._db.write(
            """INSERT INTO users
               (user_id, username, display_name, email,
                password_hash, salt, role, created_at,
                auth_provider, external_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id, username, display_name, email,
                "", "", role, now,
                "oidc", external_id,
            ),
        )

        return DashboardUser(
            user_id=user_id,
            username=username,
            display_name=display_name,
            email=email,
            role=DashboardRole(role),
            is_active=True,
            created_at=datetime.fromisoformat(now),
            auth_provider="oidc",
            external_id=external_id,
        )

    def get_user_by_external_id(self, external_id: str) -> DashboardUser | None:
        """Find a user by their SSO external ID."""
        row = self._db.fetchone(
            "SELECT * FROM users WHERE external_id = ? AND auth_provider = 'oidc'",
            (external_id,),
        )
        return self._row_to_user(row) if row else None

    # --- Helpers ---

    @staticmethod
    def _row_to_user(row: dict | None) -> DashboardUser | None:
        if row is None:
            return None
        keys = row.keys()
        auth_provider = row["auth_provider"] if "auth_provider" in keys else "local"
        external_id = row["external_id"] if "external_id" in keys else None
        return DashboardUser(
            user_id=row["user_id"],
            username=row["username"],
            display_name=row["display_name"],
            email=row["email"],
            role=DashboardRole(row["role"]),
            is_active=bool(row["is_active"]),
            created_at=datetime.fromisoformat(row["created_at"]),
            last_login=(
                datetime.fromisoformat(row["last_login"]) if row["last_login"] else None
            ),
            auth_provider=auth_provider,
            external_id=external_id,
        )
