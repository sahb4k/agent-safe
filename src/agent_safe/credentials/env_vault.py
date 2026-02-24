"""Environment variable credential vault — for development and testing.

Reads credentials from environment variables or a static dict.
Does NOT provide real scoping or short-lived credentials — it simply
returns the configured value. Use for local development, CI, and tests.

For production, implement the CredentialVault protocol with a real
vault backend (HashiCorp Vault, AWS Secrets Manager, etc.).
"""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from agent_safe.credentials.vault import CredentialVaultError
from agent_safe.models import Credential, CredentialScope, ExecutionTicket


class EnvVarVault:
    """Credential vault backed by environment variables or a static mapping.

    Lookup strategy:
    1. If a static mapping is provided at init, look up ``scope.type``.
    2. Otherwise, read from env var ``AGENT_SAFE_CRED_{TYPE}``.
    3. The payload is returned as ``{"token": <value>}``.

    This backend always "succeeds" if the env var / mapping exists.
    It does not enforce scoping — all credentials are full-access.
    Revocation is a no-op.
    """

    def __init__(
        self,
        credentials: dict[str, dict[str, Any]] | None = None,
        env_prefix: str = "AGENT_SAFE_CRED_",
    ) -> None:
        self._credentials = credentials or {}
        self._env_prefix = env_prefix
        self._issued: dict[str, datetime] = {}

    def get_credential(
        self,
        scope: CredentialScope,
        ticket: ExecutionTicket,
        ttl: int = 300,
    ) -> Credential:
        """Retrieve a credential for the given scope."""
        payload = self._resolve_payload(scope.type)
        if payload is None:
            env_var = (
                f"{self._env_prefix}"
                f"{scope.type.upper().replace('-', '_')}"
            )
            raise CredentialVaultError(
                f"No credential configured for type '{scope.type}'. "
                f"Set {env_var} or pass credentials={{'{scope.type}': {{...}}}} "
                f"to EnvVarVault()."
            )

        credential_id = f"cred-{uuid.uuid4().hex[:12]}"
        expires_at = datetime.now(tz=UTC) + timedelta(seconds=ttl)
        self._issued[credential_id] = expires_at

        return Credential(
            credential_id=credential_id,
            type=scope.type,
            payload=payload,
            expires_at=expires_at,
            scope=scope,
            ticket_nonce=ticket.nonce,
        )

    def revoke(self, credential_id: str) -> None:
        """No-op revocation for the env var vault."""
        self._issued.pop(credential_id, None)

    def _resolve_payload(self, cred_type: str) -> dict[str, Any] | None:
        """Look up credential payload from static mapping or env vars."""
        if cred_type in self._credentials:
            return self._credentials[cred_type]

        env_var = f"{self._env_prefix}{cred_type.upper().replace('-', '_')}"
        value = os.environ.get(env_var)
        if value is not None:
            return {"token": value}

        return None

    @property
    def issued_count(self) -> int:
        """Number of credentials currently tracked (for testing)."""
        return len(self._issued)
