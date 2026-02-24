"""Runner — orchestrates governed action execution.

The Runner validates an execution ticket, resolves credentials, captures
state, delegates to an Executor, audits the result, and revokes
credentials.  It is the enforcement point between the PDP decision
and the actual side effect.
"""

from __future__ import annotations

import contextlib
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from agent_safe.models import (
    Credential,
    ExecutionResult,
    ExecutionStatus,
)
from agent_safe.runner.executor import DryRunExecutor, Executor
from agent_safe.tickets.validator import TicketValidator

if TYPE_CHECKING:
    from agent_safe.audit.logger import AuditLogger
    from agent_safe.credentials.resolver import CredentialResolver
    from agent_safe.registry.loader import ActionRegistry


class RunnerError(Exception):
    """Raised for runner configuration or lifecycle errors."""


class Runner:
    """Orchestrates governed action execution.

    Lifecycle:
      1. Validate execution ticket
      2. Look up action definition
      3. Resolve credentials (if vault configured)
      4. Run prechecks (advisory)
      5. Capture before-state
      6. Execute action
      7. Capture after-state
      8. Log execution event
      9. Revoke credentials
     10. Return ExecutionResult
    """

    def __init__(
        self,
        executor: Executor,
        ticket_validator: TicketValidator,
        registry: ActionRegistry,
        credential_resolver: CredentialResolver | None = None,
        audit_logger: AuditLogger | None = None,
        default_timeout: float = 300.0,
    ) -> None:
        self._executor = executor
        self._validator = ticket_validator
        self._registry = registry
        self._credential_resolver = credential_resolver
        self._audit = audit_logger
        self._default_timeout = default_timeout

    def run(self, ticket_token: str) -> ExecutionResult:
        """Validate ticket and execute the action.

        Returns an ExecutionResult with the outcome. Never raises for
        expected failures (invalid ticket, executor error, timeout) —
        those are captured in the result's status and error fields.
        """
        # Step 1: Validate ticket
        validation = self._validator.validate(ticket_token)
        if not validation.valid:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action="unknown",
                target="unknown",
                caller="unknown",
                audit_id="",
                error=f"Ticket validation failed: {validation.reason}",
            )

        ticket = validation.ticket
        assert ticket is not None

        # Step 2: Look up action
        action_def = self._registry.get(ticket.action)
        if action_def is None:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=ticket.action,
                target=ticket.target,
                caller=ticket.caller,
                audit_id=ticket.audit_id,
                ticket_nonce=ticket.nonce,
                error=f"Action not found in registry: {ticket.action}",
            )

        # Step 3: Resolve credentials
        credential: Credential | None = None
        if (
            self._credential_resolver is not None
            and action_def.credentials is not None
        ):
            cred_result = self._credential_resolver.resolve(ticket)
            if not cred_result.success:
                return ExecutionResult(
                    status=ExecutionStatus.ERROR,
                    action=ticket.action,
                    target=ticket.target,
                    caller=ticket.caller,
                    audit_id=ticket.audit_id,
                    ticket_nonce=ticket.nonce,
                    error=f"Credential resolution failed: {cred_result.error}",
                )
            credential = cred_result.credential

        try:
            return self._execute_with_credential(
                ticket_token, ticket, action_def, credential,
            )
        finally:
            # Step 9: Revoke credential (always, even on error)
            if credential is not None and self._credential_resolver is not None:
                self._credential_resolver.revoke(credential)

    def _execute_with_credential(
        self,
        ticket_token: str,
        ticket: Any,
        action_def: Any,
        credential: Credential | None,
    ) -> ExecutionResult:
        """Execute with credential, called inside try/finally for revocation."""
        params = ticket.params or {}
        timeout = self._default_timeout

        # Step 4: Run prechecks (advisory)
        precheck_results = self._executor.run_prechecks(
            action=ticket.action,
            target=ticket.target,
            params=params,
            prechecks=action_def.prechecks,
            credential=credential,
        )

        # Step 5: Capture before-state
        before_state: dict[str, Any] = {}
        with contextlib.suppress(Exception):
            before_state = self._executor.get_state(
                action=ticket.action,
                target=ticket.target,
                params=params,
                credential=credential,
            )

        # Step 6: Execute
        start = time.monotonic()
        try:
            result = self._executor.execute(
                action=ticket.action,
                target=ticket.target,
                params=params,
                credential=credential,
                timeout=timeout,
            )
        except Exception as exc:
            elapsed = (time.monotonic() - start) * 1000
            result = ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=ticket.action,
                target=ticket.target,
                caller=ticket.caller,
                audit_id=ticket.audit_id,
                ticket_nonce=ticket.nonce,
                error=f"Executor error: {exc}",
                duration_ms=elapsed,
                executed_at=datetime.now(tz=UTC),
                executor_type=type(self._executor).__name__,
            )

        elapsed = (time.monotonic() - start) * 1000

        # Patch result with runner-level context
        result = result.model_copy(update={
            "caller": ticket.caller,
            "audit_id": ticket.audit_id,
            "ticket_nonce": ticket.nonce,
            "duration_ms": result.duration_ms or elapsed,
            "precheck_results": precheck_results,
            "before_state": before_state,
            "executor_type": result.executor_type or type(self._executor).__name__,
        })

        # Step 7: Capture after-state
        after_state: dict[str, Any] = {}
        if result.status in (ExecutionStatus.SUCCESS, ExecutionStatus.SKIPPED):
            with contextlib.suppress(Exception):
                after_state = self._executor.get_state(
                    action=ticket.action,
                    target=ticket.target,
                    params=params,
                    credential=credential,
                )

        result = result.model_copy(update={"after_state": after_state})

        # Step 8: Audit
        if self._audit is not None:
            self._audit.log_execution(result)

        return result

    def dry_run(self, ticket_token: str) -> ExecutionResult:
        """Validate ticket and show what would happen (no execution).

        Still validates the ticket and looks up the action, but does
        not execute, capture state, or resolve credentials.
        """
        # Step 1: Validate ticket
        validation = self._validator.validate(ticket_token)
        if not validation.valid:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action="unknown",
                target="unknown",
                caller="unknown",
                audit_id="",
                error=f"Ticket validation failed: {validation.reason}",
            )

        ticket = validation.ticket
        assert ticket is not None

        # Step 2: Look up action
        action_def = self._registry.get(ticket.action)
        if action_def is None:
            return ExecutionResult(
                status=ExecutionStatus.ERROR,
                action=ticket.action,
                target=ticket.target,
                caller=ticket.caller,
                audit_id=ticket.audit_id,
                ticket_nonce=ticket.nonce,
                error=f"Action not found in registry: {ticket.action}",
            )

        # Step 4: Run prechecks (advisory, using DryRunExecutor)
        dry = DryRunExecutor()
        precheck_results = dry.run_prechecks(
            action=ticket.action,
            target=ticket.target,
            params=ticket.params or {},
            prechecks=action_def.prechecks,
        )

        has_creds = action_def.credentials is not None
        cred_msg = " (credentials required)" if has_creds else ""

        return ExecutionResult(
            status=ExecutionStatus.SKIPPED,
            action=ticket.action,
            target=ticket.target,
            caller=ticket.caller,
            audit_id=ticket.audit_id,
            ticket_nonce=ticket.nonce,
            output=(
                f"[dry-run] Would execute {ticket.action} on "
                f"{ticket.target}{cred_msg}"
            ),
            precheck_results=precheck_results,
            executed_at=datetime.now(tz=UTC),
            executor_type="dry-run",
        )
