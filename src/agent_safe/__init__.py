"""Agent-Safe: A governance and policy enforcement layer for AI agents."""

__version__ = "0.7.0"

from agent_safe.credentials.env_vault import EnvVarVault
from agent_safe.credentials.resolver import CredentialResolver
from agent_safe.credentials.vault import CredentialVault, CredentialVaultError
from agent_safe.models import (
    ApprovalRequest,
    ApprovalStatus,
    Credential,
    CredentialResult,
    CredentialScope,
    DelegationLink,
    DelegationResult,
    ExecutionTicket,
    RollbackPlan,
    StateCapture,
    StateFieldSpec,
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
    "DelegationLink",
    "DelegationResult",
    "EnvVarVault",
    "ExecutionTicket",
    "RollbackPlan",
    "StateCapture",
    "StateFieldSpec",
    "TicketValidationResult",
    "TicketValidator",
    "__version__",
]
