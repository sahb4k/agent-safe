"""Credential vault protocol and error types.

Defines the interface that all vault backends must satisfy.
Built-in backends: EnvVarVault (development/testing).
Real backends (HashiCorp Vault, AWS Secrets Manager, K8s) are
planned for future phases and will require external dependencies.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from agent_safe.models import Credential, CredentialScope, ExecutionTicket


class CredentialVaultError(Exception):
    """Raised when a vault backend cannot issue or revoke a credential."""


@runtime_checkable
class CredentialVault(Protocol):
    """Protocol for credential vault backends.

    Any object with ``get_credential()`` and ``revoke()`` methods
    satisfies this protocol.
    """

    def get_credential(
        self,
        scope: CredentialScope,
        ticket: ExecutionTicket,
        ttl: int = 300,
    ) -> Credential:
        """Retrieve a scoped, time-limited credential.

        Args:
            scope: The credential scope from the action definition,
                with param templates already resolved.
            ticket: The validated execution ticket (for audit correlation).
            ttl: Maximum credential lifetime in seconds.

        Returns:
            A Credential with the access payload and expiry.

        Raises:
            CredentialVaultError: If the vault cannot issue a credential.
        """
        ...

    def revoke(self, credential_id: str) -> None:
        """Revoke a previously issued credential (best-effort).

        Args:
            credential_id: The credential_id from a Credential.

        Raises:
            CredentialVaultError: If revocation fails.
        """
        ...


def build_vault(config: dict[str, Any]) -> CredentialVault:
    """Build a vault instance from a configuration dict.

    Supported keys:
    - type: ``"env"`` (default) — uses EnvVarVault
    - credentials: dict mapping credential types to payload dicts
    - env_prefix: environment variable prefix (default ``"AGENT_SAFE_CRED_"``)

    Future types: ``"hashicorp"``, ``"aws"``, ``"kubernetes"``.
    """
    from agent_safe.credentials.env_vault import EnvVarVault

    vault_type = config.get("type", "env")

    if vault_type == "env":
        return EnvVarVault(
            credentials=config.get("credentials"),
            env_prefix=config.get("env_prefix", "AGENT_SAFE_CRED_"),
        )

    raise CredentialVaultError(
        f"Unknown vault type: {vault_type}. "
        f"Available: 'env'. Future: 'hashicorp', 'aws', 'kubernetes'."
    )
