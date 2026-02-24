"""Agent-Safe: A governance and policy enforcement layer for AI agents."""

__version__ = "0.8.0"

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
    ExecutionResult,
    ExecutionStatus,
    ExecutionTicket,
    PreCheckResult,
    RollbackPlan,
    StateCapture,
    StateFieldSpec,
    TicketValidationResult,
)
from agent_safe.runner.executor import DryRunExecutor, Executor
from agent_safe.runner.runner import Runner, RunnerError
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
    "DryRunExecutor",
    "EnvVarVault",
    "ExecutionResult",
    "ExecutionStatus",
    "ExecutionTicket",
    "Executor",
    "PreCheckResult",
    "RollbackPlan",
    "Runner",
    "RunnerError",
    "StateCapture",
    "StateFieldSpec",
    "TicketValidationResult",
    "TicketValidator",
    "__version__",
]
