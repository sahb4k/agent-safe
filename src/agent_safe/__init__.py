"""Agent-Safe: A governance and policy enforcement layer for AI agents."""

__version__ = "0.1.0"

from agent_safe.sdk.client import AgentSafe, AgentSafeError

__all__ = ["AgentSafe", "AgentSafeError", "__version__"]
