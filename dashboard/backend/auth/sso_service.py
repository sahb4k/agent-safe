"""OIDC Single Sign-On service (stdlib-only, no authlib)."""

from __future__ import annotations

import base64
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime, timedelta
from typing import Any

from dashboard.backend.auth.models import DashboardUser, LoginResponse, UserInfo
from dashboard.backend.auth.service import SESSION_TTL_SECONDS, AuthService
from dashboard.backend.db.connection import Database

logger = logging.getLogger(__name__)

_STATE_TTL_SECONDS = 600  # 10 minutes


class OIDCDiscovery:
    """Cached OIDC provider discovery document."""

    def __init__(self) -> None:
        self._config: dict[str, Any] | None = None
        self._fetched_at: float = 0
        self._cache_ttl: float = 3600  # 1 hour

    def fetch(self, provider_url: str) -> dict[str, Any]:
        """Fetch and cache the .well-known/openid-configuration."""
        now = time.time()
        if self._config and (now - self._fetched_at) < self._cache_ttl:
            return self._config

        discovery_url = (
            provider_url.rstrip("/") + "/.well-known/openid-configuration"
        )
        req = urllib.request.Request(
            discovery_url, headers={"Accept": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            self._config = json.loads(resp.read().decode("utf-8"))
        self._fetched_at = now
        return self._config  # type: ignore[return-value]

    @property
    def authorization_endpoint(self) -> str:
        assert self._config, "Discovery not fetched"
        return self._config["authorization_endpoint"]

    @property
    def token_endpoint(self) -> str:
        assert self._config, "Discovery not fetched"
        return self._config["token_endpoint"]

    @property
    def userinfo_endpoint(self) -> str:
        assert self._config, "Discovery not fetched"
        return self._config.get("userinfo_endpoint", "")

    @property
    def issuer(self) -> str:
        assert self._config, "Discovery not fetched"
        return self._config["issuer"]


class SSOService:
    """Manages OIDC authorization code flow and user provisioning."""

    def __init__(
        self,
        db: Database,
        auth_service: AuthService,
        provider_url: str,
        client_id: str,
        client_secret: str,
        default_role: str = "viewer",
        scopes: str = "openid email profile",
    ) -> None:
        self._db = db
        self._auth = auth_service
        self._provider_url = provider_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._default_role = default_role
        self._scopes = scopes
        self._discovery = OIDCDiscovery()

    # ------------------------------------------------------------------
    # Authorization Flow
    # ------------------------------------------------------------------

    def create_authorize_url(
        self, redirect_uri: str, redirect_to: str = "/",
    ) -> str:
        """Generate OIDC authorization URL with state and nonce."""
        self._cleanup_expired_states()

        config = self._discovery.fetch(self._provider_url)
        state = os.urandom(32).hex()
        nonce = os.urandom(32).hex()
        self._save_state(state, nonce, redirect_to)

        params = {
            "client_id": self._client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": self._scopes,
            "state": state,
            "nonce": nonce,
        }
        return config["authorization_endpoint"] + "?" + urllib.parse.urlencode(params)

    def handle_callback(
        self, code: str, state: str, redirect_uri: str,
    ) -> LoginResponse:
        """Exchange auth code for tokens, provision user, return JWT session."""
        nonce, _redirect_to = self._consume_state(state)

        # Exchange code for tokens
        token_response = self._exchange_code(code, redirect_uri)

        id_token = token_response.get("id_token", "")
        if not id_token:
            raise ValueError("No id_token in token response")

        claims = _decode_id_token_payload(id_token)

        # Validate nonce
        if claims.get("nonce") != nonce:
            raise ValueError("Nonce mismatch — possible replay attack")

        # Validate issuer and audience
        expected_issuer = self._discovery.issuer
        if claims.get("iss") != expected_issuer:
            raise ValueError(
                f"Issuer mismatch: expected {expected_issuer}, "
                f"got {claims.get('iss')}"
            )
        aud = claims.get("aud")
        if isinstance(aud, list):
            if self._client_id not in aud:
                raise ValueError("Audience mismatch")
        elif aud != self._client_id:
            raise ValueError("Audience mismatch")

        # Provision or update user
        user = self._provision_or_update_user(claims)

        # Issue JWT session token (same as password login)
        token = self._auth._create_session_token(user)  # noqa: SLF001
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

    def get_provider_name(self) -> str:
        """Return a display name derived from the provider URL."""
        try:
            parsed = urllib.parse.urlparse(self._provider_url)
            return parsed.hostname or self._provider_url
        except Exception:
            return self._provider_url

    # ------------------------------------------------------------------
    # Token Exchange
    # ------------------------------------------------------------------

    def _exchange_code(
        self, code: str, redirect_uri: str,
    ) -> dict[str, Any]:
        """POST to token_endpoint, return token response JSON."""
        config = self._discovery.fetch(self._provider_url)
        data = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }).encode("utf-8")

        req = urllib.request.Request(
            config["token_endpoint"],
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise ValueError(
                f"Token exchange failed (HTTP {e.code}): {body}"
            ) from e

    # ------------------------------------------------------------------
    # User Provisioning
    # ------------------------------------------------------------------

    def _provision_or_update_user(
        self, claims: dict[str, Any],
    ) -> DashboardUser:
        """Find existing user by external_id or create a new one."""
        sub = claims.get("sub", "")
        if not sub:
            raise ValueError("Missing 'sub' claim in ID token")

        email = claims.get("email", "")
        name = claims.get("name", "")

        # 1. Lookup by external_id
        existing = self._auth.get_user_by_external_id(sub)
        if existing:
            # Update last_login
            now = datetime.now(UTC).isoformat()
            self._db.write(
                "UPDATE users SET last_login = ? WHERE user_id = ?",
                (now, existing.user_id),
            )
            return existing

        # 2. Create new user
        username = self._derive_username(email, name)
        return self._auth.create_sso_user(
            external_id=sub,
            username=username,
            display_name=name or username,
            email=email,
            role=self._default_role,
        )

    def _derive_username(self, email: str, name: str) -> str:
        """Derive a unique username from email or name."""
        base = email.split("@")[0] if email else name.lower().replace(" ", ".")
        if not base:
            base = "sso-user"

        # Check for collisions
        candidate = base
        suffix = 0
        while self._auth.get_user_by_username(candidate) is not None:
            suffix += 1
            candidate = f"{base}-{suffix}"
        return candidate

    # ------------------------------------------------------------------
    # State Management (CSRF)
    # ------------------------------------------------------------------

    def _save_state(
        self, state: str, nonce: str, redirect_to: str,
    ) -> None:
        now = datetime.now(tz=UTC)
        expires = now + timedelta(seconds=_STATE_TTL_SECONDS)
        self._db.write(
            """INSERT INTO oidc_auth_states
               (state, nonce, redirect_to, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?)""",
            (state, nonce, redirect_to, now.isoformat(), expires.isoformat()),
        )

    def _consume_state(self, state: str) -> tuple[str, str]:
        """Retrieve and delete state. Returns (nonce, redirect_to).

        Raises ValueError if state is invalid or expired.
        """
        row = self._db.fetchone(
            "SELECT * FROM oidc_auth_states WHERE state = ?", (state,),
        )
        if row is None:
            raise ValueError("Invalid or expired state parameter")

        # Delete (single use)
        self._db.write(
            "DELETE FROM oidc_auth_states WHERE state = ?", (state,),
        )

        # Check expiry
        expires = datetime.fromisoformat(row["expires_at"])
        if datetime.now(tz=UTC) > expires:
            raise ValueError("State parameter has expired")

        return row["nonce"], row["redirect_to"]

    def _cleanup_expired_states(self) -> None:
        """Delete expired state entries."""
        now = datetime.now(tz=UTC).isoformat()
        self._db.write(
            "DELETE FROM oidc_auth_states WHERE expires_at < ?", (now,),
        )


def _decode_id_token_payload(id_token: str) -> dict[str, Any]:
    """Decode the payload of a JWT without signature verification.

    Safe because the token was received directly from the token endpoint
    over TLS (per OIDC Core spec section 3.1.3.7).
    """
    parts = id_token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid ID token format")

    payload_b64 = parts[1]
    # Add padding for base64
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)
