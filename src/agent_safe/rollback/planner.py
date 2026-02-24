"""Rollback planner — generates RollbackPlan from state capture + registry.

Given an original decision's audit event and its state capture, the planner
resolves rollback parameters via declarative YAML mappings (``rollback_params``)
and returns a structured ``RollbackPlan`` that describes how to reverse the
action. The planner never executes anything.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from agent_safe.models import (
    AuditEvent,
    RollbackPlan,
    StateCapture,
)
from agent_safe.registry.loader import ActionRegistry


class RollbackError(Exception):
    """Raised when a rollback plan cannot be generated."""


def _resolve_source(
    source: str,
    original_params: dict[str, Any],
    before_state: dict[str, Any],
) -> tuple[Any | None, str | None]:
    """Resolve a dot-path source to a value.

    Returns ``(value, None)`` on success or ``(None, warning)`` on failure.
    """
    parts = source.split(".", 1)
    if len(parts) != 2:
        return None, f"Invalid source path: {source!r} (expected 'namespace.field')"

    namespace, field = parts
    if namespace == "params":
        if field in original_params:
            return original_params[field], None
        return None, f"Source {source!r} not found in original params"
    if namespace == "before_state":
        if field in before_state:
            return before_state[field], None
        return None, f"Source {source!r} not found in before_state"
    return None, f"Unknown source namespace: {namespace!r}"


class RollbackPlanner:
    """Generates a :class:`RollbackPlan` from state capture and registry data.

    Usage::

        planner = RollbackPlanner(registry)
        plan = planner.generate(state_capture, original_event)
    """

    def __init__(self, registry: ActionRegistry) -> None:
        self._registry = registry

    def generate(
        self,
        state_capture: StateCapture,
        original_event: AuditEvent,
    ) -> RollbackPlan:
        """Generate a rollback plan for an executed action.

        Args:
            state_capture: The before/after state capture for the action.
            original_event: The audit event for the original decision.

        Returns:
            A :class:`RollbackPlan` describing the compensating action.

        Raises:
            RollbackError: If the action is not reversible, has no rollback
                action, or the rollback action is not in the registry.
        """
        action_def = self._registry.get(original_event.action)
        if action_def is None:
            raise RollbackError(
                f"Action {original_event.action!r} not found in registry"
            )

        if not action_def.reversible:
            raise RollbackError(
                f"Action {original_event.action!r} is not reversible"
            )

        if action_def.rollback_action is None:
            raise RollbackError(
                f"Action {original_event.action!r} has no rollback_action defined"
            )

        rollback_action_name = action_def.rollback_action
        rollback_action_def = self._registry.get(rollback_action_name)
        if rollback_action_def is None:
            raise RollbackError(
                f"Rollback action {rollback_action_name!r} not found in registry"
            )

        warnings: list[str] = []
        original_params = original_event.params or {}
        before_state = state_capture.before_state

        if action_def.rollback_params:
            # Declarative mapping from YAML
            rollback_params = self._resolve_declared(
                action_def.rollback_params,
                original_params,
                before_state,
                warnings,
            )
        else:
            # Convention-based fallback
            rollback_params = self._resolve_convention(
                action_def.name,
                rollback_action_name,
                rollback_action_def,
                original_params,
                before_state,
                warnings,
            )

        return RollbackPlan(
            original_audit_id=original_event.event_id,
            original_action=original_event.action,
            original_target=original_event.target,
            original_caller=original_event.caller,
            original_params=original_params,
            rollback_action=rollback_action_name,
            rollback_params=rollback_params,
            rollback_target=original_event.target,
            rollback_caller=original_event.caller,
            before_state=before_state,
            generated_at=datetime.now(tz=UTC),
            warnings=warnings,
        )

    def _resolve_declared(
        self,
        mapping: dict[str, Any],
        original_params: dict[str, Any],
        before_state: dict[str, Any],
        warnings: list[str],
    ) -> dict[str, Any]:
        """Resolve rollback params from declared rollback_params mapping."""
        result: dict[str, Any] = {}
        for param_name, source_obj in mapping.items():
            source_str = source_obj.source
            value, warning = _resolve_source(
                source_str, original_params, before_state,
            )
            if warning is not None:
                warnings.append(warning)
            else:
                result[param_name] = value
        return result

    def _resolve_convention(
        self,
        action_name: str,
        rollback_action_name: str,
        rollback_action_def: Any,
        original_params: dict[str, Any],
        before_state: dict[str, Any],
        warnings: list[str],
    ) -> dict[str, Any]:
        """Resolve rollback params using convention-based mapping."""
        warnings.append(
            "Using convention-based parameter mapping "
            "(no rollback_params declared)"
        )

        if action_name == rollback_action_name:
            # Self-reversible: copy all original params, override from
            # before_state where param names match state keys.
            result = dict(original_params)
            for key, value in before_state.items():
                if key in result:
                    result[key] = value
            return result

        # Paired rollback: copy params whose names appear in the
        # rollback action's parameter list.
        rollback_param_names = {
            p.name for p in rollback_action_def.parameters
        }
        result: dict[str, Any] = {}
        for name, value in original_params.items():
            if name in rollback_param_names:
                result[name] = value
        return result
