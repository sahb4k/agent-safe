"""Agent-Safe: A governance and policy enforcement layer for AI agents."""

__version__ = "0.1.0"

from agent_safe.credentials.env_vault import EnvVarVault
from agent_safe.credentials.resolver import CredentialResolver
from agent_safe.credentials.vault import CredentialVault, CredentialVaultError
from agent_safe.models import (
    ApprovalRequest,
    ApprovalStatus,
    Credential,
    CredentialResult,
    CredentialScope,
    ExecutionTicket,
    TicketValidationResult,
)
from agent_safe.sdk.client import AgentSafe, AgentSafeError
from agent_safe.tickets.validator import TicketValidator

__all__ = [
    "AgentSafe",
    "AgentSafeError",
    "ApprovalRequest",
    "ApprovalStatus",
    "Credential",
    "CredentialResolver",
    "CredentialResult",
    "CredentialScope",
    "CredentialVault",
    "CredentialVaultError",
    "EnvVarVault",
    "ExecutionTicket",
    "TicketValidationResult",
    "TicketValidator",
    "__version__",
]
