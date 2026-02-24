"""Executor protocol and built-in DryRunExecutor.

The Executor protocol defines the interface for action backends.
Any object with ``execute()``, ``get_state()``, and ``run_prechecks()``
methods satisfies the protocol — no inheritance required.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from agent_safe.models import (
    Credential,
    ExecutionResult,
    ExecutionStatus,
    Precheck,
    PreCheckResult,
)


@runtime_checkable
class Executor(Protocol):
    """Protocol for action executors.

    Any object with ``execute()``, ``get_state()``, and ``run_prechecks()``
    methods satisfies this protocol.
    """

    def execute(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
        timeout: float | None = None,
    ) -> ExecutionResult:
        """Execute an action and return the result."""
        ...

    def get_state(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
    ) -> dict[str, Any]:
        """Capture current state of the target resource."""
        ...

    def run_prechecks(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        prechecks: list[Precheck],
        credential: Credential | None = None,
    ) -> list[PreCheckResult]:
        """Run advisory prechecks before execution."""
        ...


class DryRunExecutor:
    """Executor that simulates execution without side effects.

    Useful for testing, CI/CD dry-runs, and SDK integration tests.
    All prechecks pass, state is empty, execution returns SKIPPED.
    """

    def execute(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
        timeout: float | None = None,
    ) -> ExecutionResult:
        return ExecutionResult(
            status=ExecutionStatus.SKIPPED,
            action=action,
            target=target,
            caller="",
            audit_id="",
            output=f"[dry-run] Would execute {action} on {target}",
            executed_at=datetime.now(tz=UTC),
            executor_type="dry-run",
        )

    def get_state(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        credential: Credential | None = None,
    ) -> dict[str, Any]:
        return {}

    def run_prechecks(
        self,
        action: str,
        target: str,
        params: dict[str, Any],
        prechecks: list[Precheck],
        credential: Credential | None = None,
    ) -> list[PreCheckResult]:
        return [
            PreCheckResult(name=pc.name, passed=True, message="[dry-run] skipped")
            for pc in prechecks
        ]
