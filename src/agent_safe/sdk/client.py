"""AgentSafe SDK — the single public entry point.

Wires together every internal component (registry, policies, inventory,
identity, PDP, audit) behind one class with one method: ``check()``.

Usage::

    from agent_safe import AgentSafe

    safe = AgentSafe(
        registry="./actions/",
        policies="./policies/",
        inventory="./inventory.yaml",
    )
    decision = safe.check(
        action="restart-deployment",
        target="prod/api-server",
        caller="deploy-agent-01",
        params={"namespace": "production", "deployment": "api-server"},
    )
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

from agent_safe.audit.logger import AuditLogger
from agent_safe.identity.manager import IdentityManager
from agent_safe.inventory.loader import Inventory, load_inventory
from agent_safe.models import AgentIdentity, Decision
from agent_safe.pdp.engine import PolicyDecisionPoint, load_policies
from agent_safe.registry.loader import ActionRegistry, load_registry


class AgentSafeError(Exception):
    """Raised for configuration or initialization errors."""


class AgentSafe:
    """Public API for Agent-Safe.

    Loads all configuration from disk, wires internal components, and
    exposes ``check()`` for policy evaluation + audit logging.
    """

    def __init__(
        self,
        registry: str | Path,
        policies: str | Path,
        inventory: str | Path | None = None,
        audit_log: str | Path | None = None,
        signing_key: str | None = None,
        issuer: str = "agent-safe",
    ) -> None:
        """Initialize AgentSafe.

        Args:
            registry: Path to the actions YAML directory.
            policies: Path to the policies YAML directory.
            inventory: Path to the inventory YAML file (optional).
            audit_log: Path to the audit log file (optional, enables logging).
            signing_key: HMAC key for JWT identity (optional).
            issuer: JWT issuer name (default "agent-safe").
        """
        self._registry: ActionRegistry = load_registry(registry)
        self._rules = load_policies(policies)

        self._inventory: Inventory | None = None
        if inventory is not None:
            self._inventory = load_inventory(inventory)

        self._audit: AuditLogger | None = None
        if audit_log is not None:
            self._audit = AuditLogger(Path(audit_log))

        self._identity: IdentityManager | None = None
        if signing_key is not None:
            self._identity = IdentityManager(signing_key, issuer=issuer)

        self._pdp = PolicyDecisionPoint(
            rules=self._rules,
            registry=self._registry,
            audit_logger=self._audit,
        )

    @property
    def registry(self) -> ActionRegistry:
        """The loaded action registry."""
        return self._registry

    @property
    def audit(self) -> AuditLogger | None:
        """The audit logger, if configured."""
        return self._audit

    @property
    def identity(self) -> IdentityManager | None:
        """The identity manager, if configured."""
        return self._identity

    def check(
        self,
        action: str,
        target: str | None = None,
        caller: str | AgentIdentity | None = None,
        params: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
        correlation_id: str | None = None,
    ) -> Decision:
        """Evaluate a policy decision for an action request.

        This is the primary API. It resolves the target from inventory,
        resolves the caller identity, evaluates the PDP, and auto-logs
        the decision to the audit trail.

        Args:
            action: The action name (must exist in the registry).
            target: Target identifier (looked up in inventory) or None.
            caller: Agent ID string, AgentIdentity object, or JWT token.
                If a string that isn't a valid agent_id in the identity
                system, it's treated as a bare agent_id (anonymous-style).
            params: Action parameters (validated against the action schema).
            timestamp: Override the request time (defaults to now).
            correlation_id: Optional tracing ID for log correlation.

        Returns:
            A Decision with result, reason, risk class, and audit ID.
        """
        # Resolve target from inventory
        target_def = None
        if target is not None and self._inventory is not None:
            target_def = self._inventory.get(target)

        # Resolve caller identity
        caller_identity = _resolve_caller(caller, self._identity)

        return self._pdp.evaluate(
            action=action,
            target=target_def,
            caller=caller_identity,
            params=params,
            timestamp=timestamp,
        )

    def check_plan(
        self,
        steps: list[dict[str, Any]],
        timestamp: datetime | None = None,
    ) -> list[Decision]:
        """Evaluate a batch of actions (an agent plan).

        Each step is a dict with keys: ``action``, ``target`` (optional),
        ``caller`` (optional), ``params`` (optional).

        Returns a list of Decisions, one per step, in order.
        """
        decisions: list[Decision] = []
        for step in steps:
            decision = self.check(
                action=step["action"],
                target=step.get("target"),
                caller=step.get("caller"),
                params=step.get("params"),
                timestamp=timestamp,
            )
            decisions.append(decision)
        return decisions

    def list_actions(self) -> list[str]:
        """Return sorted list of registered action names."""
        return self._registry.list_actions()

    def verify_audit(self) -> tuple[bool, list[str]]:
        """Verify the audit log chain integrity.

        Returns (is_valid, list_of_errors).
        If no audit log is configured, returns (True, []).
        """
        if self._audit is None:
            return True, []
        from agent_safe.audit.logger import verify_log

        return verify_log(self._audit.path)


def _resolve_caller(
    caller: str | AgentIdentity | None,
    identity_mgr: IdentityManager | None,
) -> AgentIdentity | None:
    """Resolve a caller argument into an AgentIdentity or None."""
    if caller is None:
        return None

    if isinstance(caller, AgentIdentity):
        return caller

    # caller is a string — try JWT validation first, fall back to bare ID
    if identity_mgr is not None:
        resolved = identity_mgr.validate_token_or_none(caller)
        if resolved is not None:
            return resolved

    # Bare agent ID string
    return AgentIdentity(agent_id=caller)
