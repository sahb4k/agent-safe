"""Agent identity manager.

Creates and validates JWT tokens for agent identity.
Each agent gets a signed token containing its ID, roles, and groups.
The PDP uses these claims for caller-based policy matching.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import jwt

from agent_safe.models import AgentIdentity, DelegationLink

# Default token lifetime
DEFAULT_TOKEN_TTL = timedelta(hours=1)

# JWT algorithm — HMAC-SHA256 for MVP (shared secret between agent and PDP).
# Move to asymmetric (RS256/ES256) for cross-trust-boundary enforcement later.
_ALGORITHM = "HS256"


class IdentityError(Exception):
    """Raised when token creation or validation fails."""


class DelegationError(IdentityError):
    """Raised when delegation token creation or validation fails."""


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

    def create_delegation_token(
        self,
        parent_token: str,
        child_agent_id: str,
        child_agent_name: str = "",
        child_roles: list[str] | None = None,
        child_groups: list[str] | None = None,
        ttl: timedelta | None = None,
        max_depth: int = 5,
    ) -> str:
        """Create a delegation token carrying the parent's delegation chain.

        The child token carries the parent's identity as a DelegationLink
        appended to the delegation_chain. The child's roles are the
        intersection of the requested roles and the parent's effective roles
        (scope narrowing).

        Raises:
            DelegationError: If parent token is invalid, depth exceeded,
                or requested roles/groups are not a subset of parent's.
        """
        # Validate parent token
        try:
            parent = self.validate_token(parent_token)
        except IdentityError as exc:
            raise DelegationError(f"Invalid parent token: {exc}") from exc

        # Check depth limit
        new_depth = parent.delegation_depth + 1
        if new_depth > max_depth:
            raise DelegationError(
                f"Delegation depth {new_depth} exceeds max depth {max_depth}"
            )

        # Compute parent's effective roles/groups
        parent_effective_roles = set(parent.roles)
        parent_effective_groups = set(parent.groups)

        # Validate scope narrowing — child roles must be subset of parent's
        child_roles = child_roles or []
        child_groups = child_groups or []

        if child_roles and not set(child_roles).issubset(parent_effective_roles):
            extra = set(child_roles) - parent_effective_roles
            raise DelegationError(
                f"Cannot delegate roles not held by parent: {sorted(extra)}"
            )

        if child_groups and not set(child_groups).issubset(parent_effective_groups):
            extra = set(child_groups) - parent_effective_groups
            raise DelegationError(
                f"Cannot delegate groups not held by parent: {sorted(extra)}"
            )

        # Build delegation chain — append parent as a link
        now = datetime.now(tz=UTC)
        parent_link = DelegationLink(
            agent_id=parent.agent_id,
            agent_name=parent.agent_name,
            roles=list(parent.roles),
            groups=list(parent.groups),
            delegated_at=now,
        )
        chain = list(parent.delegation_chain) + [parent_link]

        # Compute TTL — child must not outlive parent
        if parent.expires_at is not None:
            parent_remaining = parent.expires_at - now
            if parent_remaining.total_seconds() <= 0:
                raise DelegationError("Parent token has expired")
            ttl = min(ttl, parent_remaining) if ttl is not None else parent_remaining
        elif ttl is None:
            ttl = DEFAULT_TOKEN_TTL

        # Build JWT payload
        payload = {
            "agent_id": child_agent_id,
            "agent_name": child_agent_name,
            "roles": child_roles,
            "groups": child_groups,
            "iss": self._issuer,
            "iat": now,
            "exp": now + ttl,
            "delegation_chain": [
                link.model_dump(mode="json") for link in chain
            ],
            "delegated_roles": child_roles,
            "delegation_depth": new_depth,
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
            delegation_chain=[
                DelegationLink(**link)
                for link in payload.get("delegation_chain", [])
            ],
            delegated_roles=payload.get("delegated_roles", []),
            delegation_depth=payload.get("delegation_depth", 0),
        )

    def validate_token_or_none(self, token: str) -> AgentIdentity | None:
        """Validate a JWT, returning None instead of raising on failure."""
        try:
            return self.validate_token(token)
        except IdentityError:
            return None
