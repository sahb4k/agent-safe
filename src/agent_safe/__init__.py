"""Agent-Safe: A governance and policy enforcement layer for AI agents."""

__version__ = "0.13.0"

# Optional executor imports (don't crash if optional deps are missing)
import contextlib

from agent_safe.config import AgentSafeConfig, find_config, generate_signing_key, load_config
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
from agent_safe.runner.subprocess_executor import SubprocessExecutor
from agent_safe.sdk.client import AgentSafe, AgentSafeError
from agent_safe.tickets.validator import TicketValidator

with contextlib.suppress(ImportError):
    from agent_safe.runner.k8s_executor import K8sExecutor

with contextlib.suppress(ImportError):
    from agent_safe.runner.aws_executor import AwsExecutor

__all__ = [
    "AgentSafe",
    "AgentSafeConfig",
    "AgentSafeError",
    "ApprovalRequest",
    "ApprovalStatus",
    "AwsExecutor",
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
    "find_config",
    "generate_signing_key",
    "K8sExecutor",
    "load_config",
    "PreCheckResult",
    "RollbackPlan",
    "Runner",
    "RunnerError",
    "StateCapture",
    "StateFieldSpec",
    "SubprocessExecutor",
    "TicketValidationResult",
    "TicketValidator",
    "__version__",
]
