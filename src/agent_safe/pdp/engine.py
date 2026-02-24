"""Policy Decision Point — the core evaluation engine.

Takes an action request (action, target, caller, params, timestamp)
and returns ALLOW / DENY / REQUIRE_APPROVAL with a reason and audit ID.

Evaluation:
1. Validate action exists in registry
2. Validate params against action schema
3. Resolve target from inventory
4. Compute effective risk (action risk × target sensitivity)
5. Match policies (highest priority first, first match wins)
6. Default: DENY if no rule matches
"""

from __future__ import annotations

import fnmatch
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_safe.audit.logger import AuditLogger
from agent_safe.models import (
    AgentIdentity,
    Decision,
    DecisionResult,
    PolicyMatch,
    PolicyRule,
    RiskClass,
    TargetDefinition,
    compute_effective_risk,
)
from agent_safe.ratelimit.limiter import RateLimiter
from agent_safe.registry.loader import ActionRegistry
from agent_safe.tickets.issuer import TicketIssuer


class PDPError(Exception):
    """Raised when the PDP encounters a configuration or loading error."""


def load_policies(policies_dir: str | Path) -> list[PolicyRule]:
    """Load policy rules from all YAML files in a directory.

    Each file must have a top-level 'rules' key containing a list of rules.
    Rules from all files are merged and sorted by priority (highest first).
    """
    policies_dir = Path(policies_dir)
    if not policies_dir.is_dir():
        raise PDPError(f"Policies directory not found: {policies_dir}")

    rules: list[PolicyRule] = []
    yaml_files = sorted(
        list(policies_dir.glob("*.yaml")) + list(policies_dir.glob("*.yml"))
    )

    for path in yaml_files:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            raise PDPError(f"Invalid YAML in {path}: {e}") from e

        if not isinstance(raw, dict) or "rules" not in raw:
            raise PDPError(f"Policy file must have a 'rules' key: {path}")

        raw_rules: Any = raw["rules"]
        if not isinstance(raw_rules, list):
            raise PDPError(f"'rules' must be a list: {path}")

        for i, entry in enumerate(raw_rules):
            try:
                rules.append(PolicyRule(**entry))
            except (ValidationError, TypeError) as e:
                raise PDPError(
                    f"Invalid rule at index {i} in {path}: {e}"
                ) from e

    # Sort by priority descending — highest priority evaluated first
    rules.sort(key=lambda r: r.priority, reverse=True)
    return rules


class PolicyDecisionPoint:
    """Stateless policy evaluator.

    All context comes from the request + registry + inventory + policies.
    No state is held between calls.
    """

    def __init__(
        self,
        rules: list[PolicyRule],
        registry: ActionRegistry,
        audit_logger: AuditLogger | None = None,
        ticket_issuer: TicketIssuer | None = None,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        self._rules = sorted(rules, key=lambda r: r.priority, reverse=True)
        self._registry = registry
        self._audit = audit_logger
        self._ticket_issuer = ticket_issuer
        self._rate_limiter = rate_limiter

    @property
    def rules(self) -> list[PolicyRule]:
        return list(self._rules)

    def evaluate(
        self,
        action: str,
        target: TargetDefinition | None,
        caller: AgentIdentity | None,
        params: dict[str, Any] | None = None,
        timestamp: datetime | None = None,
    ) -> Decision:
        """Evaluate a policy decision for an action request.

        Args:
            action: The action name being requested.
            target: The resolved target (from inventory). None if unknown.
            caller: The agent identity (from JWT). None if anonymous.
            params: The action parameters.
            timestamp: When the request was made. Defaults to now.

        Returns:
            A Decision with result, reason, and audit metadata.
        """
        timestamp = timestamp or datetime.now(tz=UTC)
        params = params or {}
        audit_id = f"evt-{uuid.uuid4().hex[:12]}"

        # Resolve action from registry
        action_def = self._registry.get(action)
        action_risk = action_def.risk_class if action_def else RiskClass.CRITICAL

        # Compute effective risk
        if target is not None:
            effective_risk = compute_effective_risk(action_risk, target.sensitivity)
        else:
            # Unknown target = assume worst-case sensitivity
            effective_risk = compute_effective_risk(action_risk, "critical")

        caller_id = caller.agent_id if caller else "anonymous"

        # Validate params if action is known
        param_errors: list[str] = []
        if action_def is not None and params:
            param_errors = self._registry.validate_params(action, params)

        target_id = target.id if target else "unknown"

        # Rate limit check (before policy evaluation)
        if self._rate_limiter is not None:
            deny_reason = self._rate_limiter.check_rate_limit(caller_id)
            if deny_reason is not None:
                decision = Decision(
                    result=DecisionResult.DENY,
                    reason=deny_reason,
                    action=action,
                    target=target_id,
                    caller=caller_id,
                    risk_class=action_risk,
                    effective_risk=effective_risk,
                    policy_matched=None,
                    audit_id=audit_id,
                )
                if self._audit is not None:
                    self._audit.log_decision(
                        decision, params=params, timestamp=timestamp
                    )
                return decision

        decision: Decision | None = None

        # If action is unknown, deny immediately
        if action_def is None:
            decision = Decision(
                result=DecisionResult.DENY,
                reason=f"Unknown action: {action}",
                action=action,
                target=target_id,
                caller=caller_id,
                risk_class=action_risk,
                effective_risk=effective_risk,
                policy_matched=None,
                audit_id=audit_id,
            )

        # If params are invalid, deny
        if decision is None and param_errors:
            decision = Decision(
                result=DecisionResult.DENY,
                reason=f"Invalid parameters: {'; '.join(param_errors)}",
                action=action,
                target=target_id,
                caller=caller_id,
                risk_class=action_risk,
                effective_risk=effective_risk,
                policy_matched=None,
                audit_id=audit_id,
            )

        # Evaluate rules — first match wins
        if decision is None:
            for rule in self._rules:
                if _rule_matches(
                    rule.match, action, target, caller, effective_risk, timestamp
                ):
                    decision = Decision(
                        result=rule.decision,
                        reason=rule.reason,
                        action=action,
                        target=target_id,
                        caller=caller_id,
                        risk_class=action_risk,
                        effective_risk=effective_risk,
                        policy_matched=rule.name,
                        audit_id=audit_id,
                    )
                    break

        # Default deny
        if decision is None:
            decision = Decision(
                result=DecisionResult.DENY,
                reason="No matching policy (default deny)",
                action=action,
                target=target_id,
                caller=caller_id,
                risk_class=action_risk,
                effective_risk=effective_risk,
                policy_matched=None,
                audit_id=audit_id,
            )

        # Record DENY for circuit breaker tracking
        if self._rate_limiter is not None and decision.result == DecisionResult.DENY:
            self._rate_limiter.record_deny(caller_id)

        # Auto-log to audit trail
        if self._audit is not None:
            self._audit.log_decision(
                decision, params=params, timestamp=timestamp
            )

        # Issue execution ticket for ALLOW decisions
        if (
            self._ticket_issuer is not None
            and decision.result == DecisionResult.ALLOW
        ):
            ticket = self._ticket_issuer.issue(
                action=decision.action,
                target=decision.target,
                caller=decision.caller,
                audit_id=decision.audit_id,
                params=params,
            )
            decision = decision.model_copy(update={"ticket": ticket})

        return decision


def _rule_matches(
    match: PolicyMatch,
    action: str,
    target: TargetDefinition | None,
    caller: AgentIdentity | None,
    effective_risk: RiskClass,
    timestamp: datetime,
) -> bool:
    """Check if a policy rule's match conditions apply to this request.

    All specified conditions must be true (AND logic).
    Within a condition's list, any value can match (OR logic).
    """
    if not _actions_match(match.actions, action):
        return False

    if match.targets is not None and not _target_matches(match.targets, target):
        return False

    if match.callers is not None and not _caller_matches(match.callers, caller):
        return False

    if match.risk_classes is not None and effective_risk not in match.risk_classes:
        return False

    return not (match.time_windows is not None and not _time_matches(match.time_windows, timestamp))


def _actions_match(patterns: list[str], action: str) -> bool:
    """Check if the action name matches any of the patterns (glob/fnmatch)."""
    return any(fnmatch.fnmatch(action, p) for p in patterns)


def _target_matches(selector: Any, target: TargetDefinition | None) -> bool:
    """Check if a target matches the selector. No target = no match."""
    if target is None:
        return False

    if selector.environments is not None and target.environment not in selector.environments:
        return False

    if selector.sensitivities is not None and target.sensitivity not in selector.sensitivities:
        return False

    if selector.types is not None and target.type not in selector.types:
        return False

    if selector.labels is not None:
        for key, value in selector.labels.items():
            if target.labels.get(key) != value:
                return False

    return True


def _caller_matches(selector: Any, caller: AgentIdentity | None) -> bool:
    """Check if a caller matches the selector. No caller = no match."""
    if caller is None:
        return False

    if selector.agent_ids is not None and caller.agent_id not in selector.agent_ids:
        return False

    if selector.roles is not None and not any(r in caller.roles for r in selector.roles):
        return False

    if selector.groups is not None:
        if not any(g in caller.groups for g in selector.groups):
            return False

    return True


def _time_matches(windows: list[Any], timestamp: datetime) -> bool:
    """Check if the timestamp falls within any of the time windows."""
    for window in windows:
        day_ok = window.days is None or timestamp.weekday() in window.days
        if window.start_hour <= window.end_hour:
            hour_ok = window.start_hour <= timestamp.hour <= window.end_hour
        else:
            # Wraps midnight (e.g., 22-06)
            hour_ok = timestamp.hour >= window.start_hour or timestamp.hour <= window.end_hour
        if day_ok and hour_ok:
            return True
    return False
