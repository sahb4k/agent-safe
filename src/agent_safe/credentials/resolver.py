"""Credential resolver — fetches scoped credentials for validated tickets.

The resolver:
1. Takes a validated ticket and the action registry
2. Reads the action's credential scope from its definition
3. Templates parameter references (``{{ params.xyz }}``)
4. Calls the vault to get a scoped, short-lived credential
5. Returns a CredentialResult

The resolver does NOT validate tickets — that remains the job of
TicketValidator. The resolver assumes the ticket has already been
validated.
"""

from __future__ import annotations

import re
import warnings
from typing import Any

from agent_safe.credentials.vault import CredentialVault, CredentialVaultError
from agent_safe.models import (
    Credential,
    CredentialResult,
    CredentialScope,
    ExecutionTicket,
)
from agent_safe.registry.loader import ActionRegistry


class CredentialResolverError(Exception):
    """Raised for resolver configuration or resolution errors."""


class ResolverWarning(UserWarning):
    """Emitted when credential revocation fails (non-fatal)."""


class CredentialResolver:
    """Resolves credentials for validated execution tickets.

    Stateless — all context comes from the ticket, registry, and vault.
    """

    def __init__(
        self,
        registry: ActionRegistry,
        vault: CredentialVault,
    ) -> None:
        self._registry = registry
        self._vault = vault

    def resolve(
        self,
        ticket: ExecutionTicket,
    ) -> CredentialResult:
        """Resolve credentials for a validated ticket.

        Args:
            ticket: A validated ExecutionTicket (caller is responsible
                for validating with TicketValidator first).

        Returns:
            CredentialResult with success=True and a Credential,
            or success=False and an error message.
        """
        action_def = self._registry.get(ticket.action)
        if action_def is None:
            return CredentialResult(
                success=False,
                error=f"Action not found in registry: {ticket.action}",
                action=ticket.action,
                target=ticket.target,
                ticket_nonce=ticket.nonce,
            )

        if action_def.credentials is None:
            return CredentialResult(
                success=False,
                error=(
                    f"Action '{ticket.action}' does not declare a "
                    f"credentials block"
                ),
                action=ticket.action,
                target=ticket.target,
                ticket_nonce=ticket.nonce,
            )

        resolved_scope = resolve_scope_templates(
            action_def.credentials, ticket.params,
        )

        try:
            credential = self._vault.get_credential(
                scope=resolved_scope,
                ticket=ticket,
                ttl=resolved_scope.ttl,
            )
        except CredentialVaultError as exc:
            return CredentialResult(
                success=False,
                error=f"Vault error: {exc}",
                action=ticket.action,
                target=ticket.target,
                ticket_nonce=ticket.nonce,
            )

        return CredentialResult(
            success=True,
            credential=credential,
            action=ticket.action,
            target=ticket.target,
            ticket_nonce=ticket.nonce,
        )

    def revoke(self, credential: Credential) -> None:
        """Best-effort revocation. Warns on failure, never raises."""
        try:
            self._vault.revoke(credential.credential_id)
        except Exception as exc:
            warnings.warn(
                f"Credential revocation failed for "
                f"{credential.credential_id}: {exc}",
                ResolverWarning,
                stacklevel=2,
            )


# --- Template resolution ---

_PARAM_PATTERN = re.compile(r"\{\{\s*params\.(\w+)\s*\}\}")


def resolve_scope_templates(
    scope: CredentialScope,
    params: dict[str, Any],
) -> CredentialScope:
    """Replace ``{{ params.xyz }}`` references in scope fields.

    Returns a new CredentialScope with resolved values.
    Templates that reference missing params are left unresolved.
    """
    resolved_fields = _resolve_dict(scope.fields, params)
    return CredentialScope(
        type=scope.type,
        fields=resolved_fields,
        ttl=scope.ttl,
    )


def _resolve_dict(
    data: dict[str, Any],
    params: dict[str, Any],
) -> dict[str, Any]:
    """Recursively resolve templates in a dict."""
    return {key: _resolve_value(value, params) for key, value in data.items()}


def _resolve_value(value: Any, params: dict[str, Any]) -> Any:
    """Resolve a single value: strings are templated, lists/dicts recurse."""
    if isinstance(value, str):
        return _PARAM_PATTERN.sub(
            lambda m: str(params.get(m.group(1), m.group(0))),
            value,
        )
    if isinstance(value, list):
        return [_resolve_value(item, params) for item in value]
    if isinstance(value, dict):
        return _resolve_dict(value, params)
    return value
