"""Execution ticket validator.

Standalone validator that executors use to verify tickets before executing.
Validates signature, expiry, action/target match, and single-use nonce.

The validator tracks used nonces in memory with TTL-based cleanup to prevent
replay attacks while keeping the implementation lightweight.  For distributed
executors, replace the nonce store with Redis/DB in production.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta

import jwt

from agent_safe.models import ExecutionTicket, TicketValidationResult

_ALGORITHM = "HS256"

# How long to keep expired nonces before cleanup.
# Must be >= the maximum possible ticket TTL to prevent replay.
_NONCE_RETENTION = timedelta(minutes=30)


class TicketValidatorError(Exception):
    """Raised when the validator encounters a configuration error."""


class TicketValidator:
    """Validates signed execution tickets.

    Designed to work standalone — does not need the full AgentSafe
    instance.  An executor only needs the signing key and this validator.
    """

    def __init__(
        self,
        signing_key: str,
        issuer: str = "agent-safe",
    ) -> None:
        if not signing_key:
            raise TicketValidatorError("Signing key must not be empty")
        self._signing_key = signing_key
        self._issuer = issuer
        self._used_nonces: dict[str, datetime] = {}  # nonce -> expiry time
        self._lock = threading.Lock()

    def validate(
        self,
        token: str,
        expected_action: str | None = None,
        expected_target: str | None = None,
    ) -> TicketValidationResult:
        """Validate a ticket token.

        Args:
            token: The JWT token string from an ExecutionTicket.
            expected_action: If provided, the ticket's action must match.
            expected_target: If provided, the ticket's target must match.

        Returns:
            A TicketValidationResult with valid=True/False and reason.
        """
        # Step 1: Decode and verify JWT signature + expiry
        try:
            payload = jwt.decode(
                token,
                self._signing_key,
                algorithms=[_ALGORITHM],
                issuer=self._issuer,
                options={
                    "require": [
                        "type", "action", "target", "caller",
                        "audit_id", "nonce", "iss", "iat", "exp",
                    ],
                },
            )
        except jwt.ExpiredSignatureError:
            return TicketValidationResult(
                valid=False, reason="Ticket has expired",
            )
        except jwt.InvalidIssuerError:
            return TicketValidationResult(
                valid=False, reason="Invalid ticket issuer",
            )
        except jwt.InvalidTokenError as e:
            return TicketValidationResult(
                valid=False, reason=f"Invalid ticket: {e}",
            )

        # Step 2: Verify this is an execution ticket (not an identity JWT)
        if payload.get("type") != "execution-ticket":
            return TicketValidationResult(
                valid=False, reason="Token is not an execution ticket",
            )

        # Step 3: Check action match
        if expected_action is not None and payload["action"] != expected_action:
            return TicketValidationResult(
                valid=False,
                reason=(
                    f"Action mismatch: ticket is for '{payload['action']}', "
                    f"expected '{expected_action}'"
                ),
            )

        # Step 4: Check target match
        if expected_target is not None and payload["target"] != expected_target:
            return TicketValidationResult(
                valid=False,
                reason=(
                    f"Target mismatch: ticket is for '{payload['target']}', "
                    f"expected '{expected_target}'"
                ),
            )

        # Step 5: Check nonce (single-use)
        nonce = payload["nonce"]
        with self._lock:
            self._cleanup_expired_nonces()
            if nonce in self._used_nonces:
                return TicketValidationResult(
                    valid=False,
                    reason="Ticket has already been used (replay detected)",
                )
            # Mark nonce as used
            expires_at = datetime.fromtimestamp(payload["exp"], tz=UTC)
            self._used_nonces[nonce] = expires_at

        # Build the ExecutionTicket object for the caller
        ticket = ExecutionTicket(
            token=token,
            action=payload["action"],
            target=payload["target"],
            caller=payload["caller"],
            params=payload.get("params", {}),
            audit_id=payload["audit_id"],
            nonce=nonce,
            issued_at=datetime.fromtimestamp(payload["iat"], tz=UTC),
            expires_at=expires_at,
        )

        return TicketValidationResult(
            valid=True,
            reason="Ticket is valid",
            ticket=ticket,
        )

    def _cleanup_expired_nonces(self) -> None:
        """Remove nonces whose tickets have expired + retention period.

        Called under lock from validate().  Keeps memory bounded.
        """
        now = datetime.now(tz=UTC)
        expired = [
            nonce
            for nonce, exp_time in self._used_nonces.items()
            if now > exp_time + _NONCE_RETENTION
        ]
        for nonce in expired:
            del self._used_nonces[nonce]

    @property
    def used_nonce_count(self) -> int:
        """Number of nonces currently tracked (for testing/monitoring)."""
        return len(self._used_nonces)
