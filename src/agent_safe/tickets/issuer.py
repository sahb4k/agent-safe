"""Execution ticket issuer.

Generates signed, time-limited, single-use JWT tickets when the PDP
returns ALLOW.  Each ticket encodes the approved action, target, params,
caller, audit_id, and a unique nonce.

The ticket is a standard JWT signed with HMAC-SHA256, using the same
PyJWT dependency and pattern as the identity manager.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from agent_safe.models import ExecutionTicket

_ALGORITHM = "HS256"
DEFAULT_TICKET_TTL = timedelta(minutes=5)


class TicketIssuerError(Exception):
    """Raised when ticket issuance fails."""


class TicketIssuer:
    """Issues signed execution tickets for ALLOW decisions.

    The signing key should be the same key shared with ticket validators.
    For MVP this is a symmetric HMAC key, consistent with the identity
    manager pattern.
    """

    def __init__(
        self,
        signing_key: str,
        issuer: str = "agent-safe",
        ttl: timedelta | None = None,
    ) -> None:
        if not signing_key:
            raise TicketIssuerError("Signing key must not be empty")
        self._signing_key = signing_key
        self._issuer = issuer
        self._ttl = ttl if ttl is not None else DEFAULT_TICKET_TTL

    def issue(
        self,
        action: str,
        target: str,
        caller: str,
        audit_id: str,
        params: dict[str, Any] | None = None,
        ttl: timedelta | None = None,
    ) -> ExecutionTicket:
        """Issue a signed execution ticket.

        Args:
            action: The approved action name.
            target: The approved target identifier.
            caller: The caller that was approved.
            audit_id: The audit event ID from the decision.
            params: The approved action parameters.
            ttl: Override the default TTL for this ticket.

        Returns:
            An ExecutionTicket with the signed JWT token.
        """
        now = datetime.now(tz=UTC)
        effective_ttl = ttl if ttl is not None else self._ttl
        expires_at = now + effective_ttl
        nonce = uuid.uuid4().hex
        params = params or {}

        payload = {
            "type": "execution-ticket",
            "action": action,
            "target": target,
            "caller": caller,
            "params": params,
            "audit_id": audit_id,
            "nonce": nonce,
            "iss": self._issuer,
            "iat": now,
            "exp": expires_at,
        }

        token = jwt.encode(payload, self._signing_key, algorithm=_ALGORITHM)

        return ExecutionTicket(
            token=token,
            action=action,
            target=target,
            caller=caller,
            params=params,
            audit_id=audit_id,
            nonce=nonce,
            issued_at=now,
            expires_at=expires_at,
        )
