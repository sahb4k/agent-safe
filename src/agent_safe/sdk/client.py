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

import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from agent_safe.approval.notifier import (
    ApprovalNotifier,
    build_notifiers,
    dispatch_notifications,
)
from agent_safe.approval.store import FileApprovalStore
from agent_safe.audit.logger import AuditLogger
from agent_safe.audit.shipper import AuditShipper, build_shippers
from agent_safe.credentials.resolver import CredentialResolver
from agent_safe.credentials.vault import CredentialVault, build_vault
from agent_safe.identity.manager import DelegationError, IdentityManager
from agent_safe.inventory.loader import Inventory, load_inventory
from agent_safe.models import (
    AgentIdentity,
    ApprovalRequest,
    ApprovalStatus,
    Credential,
    CredentialResult,
    Decision,
    DecisionResult,
    DelegationResult,
    ExecutionTicket,
    RiskClass,
)
from agent_safe.pdp.engine import PolicyDecisionPoint, load_policies
from agent_safe.pdp.risk_tracker import CumulativeRiskConfig, CumulativeRiskTracker
from agent_safe.ratelimit.limiter import RateLimitConfig, RateLimiter
from agent_safe.registry.loader import ActionRegistry, load_registry
from agent_safe.tickets.issuer import TicketIssuer


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
        rate_limit: RateLimitConfig | dict | None = None,
        audit_shippers: list[AuditShipper] | dict | None = None,
        approval_store: str | Path | None = None,
        approval_ttl: timedelta | int | None = None,
        approval_notifiers: list[ApprovalNotifier] | dict | None = None,
        credential_vault: CredentialVault | dict | None = None,
        cumulative_risk: CumulativeRiskConfig | dict | None = None,
    ) -> None:
        """Initialize AgentSafe.

        Args:
            registry: Path to the actions YAML directory.
            policies: Path to the policies YAML directory.
            inventory: Path to the inventory YAML file (optional).
            audit_log: Path to the audit log file (optional, enables logging).
            signing_key: HMAC key for JWT identity and execution tickets (optional).
            issuer: JWT issuer name (default "agent-safe").
            rate_limit: Per-caller rate limit config (optional).
            audit_shippers: External audit log shippers (optional).
                Pass a list of AuditShipper instances, or a dict to
                auto-build shippers via ``build_shippers()``.
                Requires ``audit_log`` to be set.
            approval_store: Path to the approval store JSONL file (optional).
            approval_ttl: Approval request TTL — timedelta or int seconds
                (default 1 hour).
            approval_notifiers: Approval notifiers (optional).
                Pass a list of ApprovalNotifier instances, or a dict to
                auto-build via ``build_notifiers()``.
                Requires ``approval_store`` to be set.
            credential_vault: Credential vault for JIT credential scoping
                (optional). Pass a CredentialVault instance, or a dict
                to auto-build via ``build_vault()``.
            cumulative_risk: Cumulative risk scoring config (optional).
                Pass a CumulativeRiskConfig instance, or a dict with
                keys: window_seconds, risk_scores, escalation_threshold,
                deny_threshold.
        """
        self._registry: ActionRegistry = load_registry(registry)
        self._rules = load_policies(policies)

        self._inventory: Inventory | None = None
        if inventory is not None:
            self._inventory = load_inventory(inventory)

        # Resolve shippers
        shippers: list[AuditShipper] | None = None
        if audit_shippers is not None:
            if audit_log is None:
                raise AgentSafeError(
                    "audit_shippers requires audit_log to be set"
                )
            if isinstance(audit_shippers, dict):
                shippers = build_shippers(audit_shippers)
            else:
                shippers = audit_shippers

        self._audit: AuditLogger | None = None
        if audit_log is not None:
            self._audit = AuditLogger(Path(audit_log), shippers=shippers)

        self._identity: IdentityManager | None = None
        if signing_key is not None:
            self._identity = IdentityManager(signing_key, issuer=issuer)

        self._ticket_issuer: TicketIssuer | None = None
        if signing_key is not None:
            self._ticket_issuer = TicketIssuer(signing_key, issuer=issuer)

        self._rate_limiter: RateLimiter | None = None
        if rate_limit is not None:
            if isinstance(rate_limit, dict):
                rate_limit = RateLimitConfig(**rate_limit)
            self._rate_limiter = RateLimiter(rate_limit)

        self._risk_tracker: CumulativeRiskTracker | None = None
        if cumulative_risk is not None:
            if isinstance(cumulative_risk, dict):
                cumulative_risk = CumulativeRiskConfig(**cumulative_risk)
            self._risk_tracker = CumulativeRiskTracker(cumulative_risk)

        # Approval store
        self._approval_store: FileApprovalStore | None = None
        if approval_store is not None:
            ttl = None
            if isinstance(approval_ttl, int):
                ttl = timedelta(seconds=approval_ttl)
            elif isinstance(approval_ttl, timedelta):
                ttl = approval_ttl
            self._approval_store = FileApprovalStore(
                Path(approval_store), ttl=ttl,
            )

        # Approval notifiers
        self._approval_notifiers: list[ApprovalNotifier] = []
        if approval_notifiers is not None:
            if approval_store is None:
                raise AgentSafeError(
                    "approval_notifiers requires approval_store to be set",
                )
            if isinstance(approval_notifiers, dict):
                self._approval_notifiers = build_notifiers(approval_notifiers)
            else:
                self._approval_notifiers = approval_notifiers

        # Credential vault
        self._credential_resolver: CredentialResolver | None = None
        if credential_vault is not None:
            if isinstance(credential_vault, dict):
                vault = build_vault(credential_vault)
            else:
                vault = credential_vault
            self._credential_resolver = CredentialResolver(
                registry=self._registry,
                vault=vault,
            )

        self._pdp = PolicyDecisionPoint(
            rules=self._rules,
            registry=self._registry,
            audit_logger=self._audit,
            ticket_issuer=self._ticket_issuer,
            rate_limiter=self._rate_limiter,
            risk_tracker=self._risk_tracker,
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
        ticket_id: str | None = None,
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

        decision = self._pdp.evaluate(
            action=action,
            target=target_def,
            caller=caller_identity,
            params=params,
            timestamp=timestamp,
            ticket_id=ticket_id,
        )

        # Create approval request for REQUIRE_APPROVAL decisions
        if (
            self._approval_store is not None
            and decision.result == DecisionResult.REQUIRE_APPROVAL
        ):
            approval_request = self._approval_store.create(
                decision, params=params,
            )
            decision = decision.model_copy(
                update={"request_id": approval_request.request_id},
            )
            if self._approval_notifiers:
                dispatch_notifications(
                    self._approval_notifiers, approval_request,
                )

        return decision

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
                ticket_id=step.get("ticket_id"),
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

    @property
    def credential_resolver(self) -> CredentialResolver | None:
        """The credential resolver, if configured."""
        return self._credential_resolver

    def resolve_credentials(
        self,
        ticket: ExecutionTicket,
    ) -> CredentialResult:
        """Resolve scoped credentials for a validated execution ticket.

        Call after ``check()`` returns ALLOW with a ticket. The resolver
        looks up the action's credential scope, templates parameter
        references, and fetches a scoped credential from the vault.

        Args:
            ticket: The ExecutionTicket from a successful check() decision.

        Returns:
            CredentialResult with the credential or an error message.

        Raises:
            AgentSafeError: If no credential vault is configured.
        """
        if self._credential_resolver is None:
            raise AgentSafeError(
                "Credential vault is not configured. "
                "Pass credential_vault= to AgentSafe()."
            )
        return self._credential_resolver.resolve(ticket)

    def revoke_credential(self, credential: Credential) -> None:
        """Best-effort revocation of a previously issued credential.

        Args:
            credential: The Credential from resolve_credentials().

        Raises:
            AgentSafeError: If no credential vault is configured.
        """
        if self._credential_resolver is None:
            raise AgentSafeError("Credential vault is not configured.")
        self._credential_resolver.revoke(credential)

    def delegate(
        self,
        parent_token: str,
        child_agent_id: str,
        child_agent_name: str = "",
        child_roles: list[str] | None = None,
        child_groups: list[str] | None = None,
        ttl: int | None = None,
        max_depth: int = 5,
    ) -> DelegationResult:
        """Create a delegation token for a sub-agent.

        The parent agent delegates authority to a child agent. The child
        receives a JWT carrying the delegation chain and a subset of
        the parent's roles (scope narrowing).

        Args:
            parent_token: JWT of the delegating (parent) agent.
            child_agent_id: Agent ID for the child agent.
            child_agent_name: Display name for the child agent.
            child_roles: Roles to grant (must be subset of parent's).
            child_groups: Groups to grant (must be subset of parent's).
            ttl: Token lifetime in seconds. Capped at parent's remaining TTL.
            max_depth: Maximum delegation chain depth (default 5).

        Returns:
            DelegationResult with success/error and the child token.

        Raises:
            AgentSafeError: If identity manager is not configured.
        """
        if self._identity is None:
            raise AgentSafeError(
                "Identity manager is not configured. "
                "Pass signing_key= to AgentSafe()."
            )

        ttl_delta = timedelta(seconds=ttl) if ttl is not None else None

        try:
            token = self._identity.create_delegation_token(
                parent_token=parent_token,
                child_agent_id=child_agent_id,
                child_agent_name=child_agent_name,
                child_roles=child_roles,
                child_groups=child_groups,
                ttl=ttl_delta,
                max_depth=max_depth,
            )
        except DelegationError as exc:
            return DelegationResult(
                success=False,
                error=str(exc),
                parent_agent_id="",
                child_agent_id=child_agent_id,
            )

        child_identity = self._identity.validate_token(token)
        parent_identity = self._identity.validate_token(parent_token)

        return DelegationResult(
            success=True,
            token=token,
            child_identity=child_identity,
            parent_agent_id=parent_identity.agent_id,
            child_agent_id=child_agent_id,
            delegation_depth=child_identity.delegation_depth,
        )

    def verify_delegation(self, token: str) -> AgentIdentity | None:
        """Verify a delegation token and return the full identity with chain.

        Returns None if the token is invalid or expired.

        Raises:
            AgentSafeError: If identity manager is not configured.
        """
        if self._identity is None:
            raise AgentSafeError(
                "Identity manager is not configured. "
                "Pass signing_key= to AgentSafe()."
            )
        return self._identity.validate_token_or_none(token)

    @property
    def approval_store(self) -> FileApprovalStore | None:
        """The approval store, if configured."""
        return self._approval_store

    def get_approval_status(
        self, request_id: str,
    ) -> ApprovalRequest | None:
        """Check the status of an approval request.

        Returns the ApprovalRequest with current status, or None if not found.
        """
        if self._approval_store is None:
            return None
        return self._approval_store.get(request_id)

    def wait_for_approval(
        self,
        request_id: str,
        timeout: float = 60.0,
        poll_interval: float = 2.0,
    ) -> Decision:
        """Block until an approval request is resolved or times out.

        Args:
            request_id: The approval request ID from check().
            timeout: Maximum wait in seconds (default 60).
            poll_interval: Time between polls in seconds (default 2).

        Returns:
            A Decision with result=ALLOW (+ ticket) or result=DENY.
        """
        import time

        if self._approval_store is None:
            raise AgentSafeError("Approval store is not configured")

        deadline = time.monotonic() + timeout
        request: ApprovalRequest | None = None

        while time.monotonic() < deadline:
            request = self._approval_store.get(request_id)
            if request is None:
                raise AgentSafeError(
                    f"Approval request not found: {request_id}",
                )

            if request.status == ApprovalStatus.APPROVED:
                return self._build_approval_decision(
                    request, DecisionResult.ALLOW,
                )
            if request.status in (
                ApprovalStatus.DENIED, ApprovalStatus.EXPIRED,
            ):
                return self._build_approval_decision(
                    request, DecisionResult.DENY,
                )

            time.sleep(poll_interval)

        # Timeout — treat as deny
        return Decision(
            result=DecisionResult.DENY,
            reason=f"Approval request {request_id} timed out",
            action=request.action if request else "unknown",
            target=request.target if request else "unknown",
            caller=request.caller if request else "unknown",
            risk_class=request.risk_class if request else RiskClass.CRITICAL,
            effective_risk=(
                request.effective_risk if request else RiskClass.CRITICAL
            ),
            audit_id=request.audit_id if request else f"evt-{uuid.uuid4().hex[:12]}",
            request_id=request_id,
        )

    def resolve_approval(
        self,
        request_id: str,
        action: str,
        resolved_by: str = "unknown",
        reason: str | None = None,
    ) -> Decision:
        """Resolve a pending approval request.

        Args:
            request_id: The approval request ID.
            action: "approve" or "deny".
            resolved_by: Who resolved the request.
            reason: Optional reason for the resolution.

        Returns:
            A Decision with result=ALLOW (+ ticket) or result=DENY.
        """
        if self._approval_store is None:
            raise AgentSafeError("Approval store is not configured")

        status = (
            ApprovalStatus.APPROVED if action == "approve"
            else ApprovalStatus.DENIED
        )

        request = self._approval_store.resolve(
            request_id=request_id,
            status=status,
            resolved_by=resolved_by,
            reason=reason,
        )

        result = (
            DecisionResult.ALLOW if status == ApprovalStatus.APPROVED
            else DecisionResult.DENY
        )
        decision = self._build_approval_decision(request, result)

        # Audit the resolution
        if self._audit is not None:
            self._audit.log_raw(
                event_id=f"evt-{uuid.uuid4().hex[:12]}",
                action=request.action,
                target=request.target,
                caller=request.caller,
                decision=result,
                reason=(
                    f"Approval {action}d by {resolved_by}"
                    + (f": {reason}" if reason else "")
                ),
                risk_class=request.risk_class,
                effective_risk=request.effective_risk,
                policy_matched=request.policy_matched,
                context={
                    "type": "approval_resolution",
                    "request_id": request_id,
                    "original_audit_id": request.audit_id,
                    "resolved_by": resolved_by,
                    "resolution": action,
                },
            )

        return decision

    def list_pending_approvals(self) -> list[ApprovalRequest]:
        """List all pending approval requests."""
        if self._approval_store is None:
            return []
        return self._approval_store.list_pending()

    def _build_approval_decision(
        self,
        request: ApprovalRequest,
        result: DecisionResult,
    ) -> Decision:
        """Build a Decision from a resolved approval request."""
        if result == DecisionResult.ALLOW:
            reason = f"Approved by {request.resolved_by}"
        elif request.status == ApprovalStatus.EXPIRED:
            reason = f"Request {request.request_id} expired"
        else:
            reason = f"Denied by {request.resolved_by or 'system'}"

        decision = Decision(
            result=result,
            reason=reason,
            action=request.action,
            target=request.target,
            caller=request.caller,
            risk_class=request.risk_class,
            effective_risk=request.effective_risk,
            policy_matched=request.policy_matched,
            audit_id=request.audit_id,
            request_id=request.request_id,
        )

        # Issue execution ticket for approved decisions
        if self._ticket_issuer is not None and result == DecisionResult.ALLOW:
            ticket = self._ticket_issuer.issue(
                action=request.action,
                target=request.target,
                caller=request.caller,
                audit_id=request.audit_id,
                params=request.params,
            )
            decision = decision.model_copy(update={"ticket": ticket})

        return decision


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
