"""Agent identity manager.

Creates and validates JWT tokens for agent identity.
Each agent gets a signed token containing its ID, roles, and groups.
The PDP uses these claims for caller-based policy matching.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from agent_safe.models import AgentIdentity

# Default token lifetime
DEFAULT_TOKEN_TTL = timedelta(hours=1)

# JWT algorithm — HMAC-SHA256 for MVP (shared secret between agent and PDP).
# Move to asymmetric (RS256/ES256) for cross-trust-boundary enforcement later.
_ALGORITHM = "HS256"


class IdentityError(Exception):
    """Raised when token creation or validation fails."""


class IdentityManager:
    """Creates and validates agent identity tokens (JWTs).

    The signing key must be shared between the token issuer and the PDP.
    For MVP this is a symmetric HMAC key. In production, consider rotating
    keys and using asymmetric signing.
    """

    def __init__(self, signing_key: str, issuer: str = "agent-safe") -> None:
        if not signing_key:
            raise IdentityError("Signing key must not be empty")
        self._signing_key = signing_key
        self._issuer = issuer

    def create_token(
        self,
        agent_id: str,
        agent_name: str = "",
        roles: list[str] | None = None,
        groups: list[str] | None = None,
        ttl: timedelta | None = None,
    ) -> str:
        """Create a signed JWT for an agent.

        Returns the encoded token string.
        """
        now = datetime.now(tz=UTC)
        ttl = ttl if ttl is not None else DEFAULT_TOKEN_TTL

        payload = {
            "agent_id": agent_id,
            "agent_name": agent_name,
            "roles": roles or [],
            "groups": groups or [],
            "iss": self._issuer,
            "iat": now,
            "exp": now + ttl,
        }

        return jwt.encode(payload, self._signing_key, algorithm=_ALGORITHM)

    def validate_token(self, token: str) -> AgentIdentity:
        """Validate a JWT and return the agent identity.

        Raises:
            IdentityError: If the token is expired, malformed, or has an
                invalid signature.
        """
        try:
            payload = jwt.decode(
                token,
                self._signing_key,
                algorithms=[_ALGORITHM],
                issuer=self._issuer,
                options={"require": ["agent_id", "iss", "iat", "exp"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise IdentityError("Token has expired") from e
        except jwt.InvalidIssuerError as e:
            raise IdentityError(f"Invalid token issuer: {e}") from e
        except jwt.InvalidTokenError as e:
            raise IdentityError(f"Invalid token: {e}") from e

        return AgentIdentity(
            agent_id=payload["agent_id"],
            agent_name=payload.get("agent_name", ""),
            roles=payload.get("roles", []),
            groups=payload.get("groups", []),
            issued_at=datetime.fromtimestamp(payload["iat"], tz=UTC),
            expires_at=datetime.fromtimestamp(payload["exp"], tz=UTC),
        )

    def validate_token_or_none(self, token: str) -> AgentIdentity | None:
        """Validate a JWT, returning None instead of raising on failure."""
        try:
            return self.validate_token(token)
        except IdentityError:
            return None
