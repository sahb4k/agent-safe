"""Tests for the Runner/Executor framework (v0.8.0).

Covers:
- ExecutionStatus, PreCheckResult, ExecutionResult models
- Executor protocol and DryRunExecutor
- Runner lifecycle, validation, errors, and dry_run
"""

from __future__ import annotations

import tempfile
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

from agent_safe.audit.logger import AuditLogger
from agent_safe.credentials.resolver import CredentialResolver
from agent_safe.models import (
    ActionDefinition,
    Credential,
    CredentialResult,
    CredentialScope,
    ExecutionResult,
    ExecutionStatus,
    Precheck,
    PreCheckResult,
    RiskClass,
)
from agent_safe.registry.loader import ActionRegistry
from agent_safe.runner.executor import DryRunExecutor, Executor
from agent_safe.runner.runner import Runner
from agent_safe.tickets.issuer import TicketIssuer
from agent_safe.tickets.validator import TicketValidator

SIGNING_KEY = "test-runner-key-32chars-minimum!!"


def _make_action(
    name: str = "restart-deployment",
    risk_class: RiskClass = RiskClass.MEDIUM,
    prechecks: list[Precheck] | None = None,
    credentials: CredentialScope | None = None,
) -> ActionDefinition:
    return ActionDefinition(
        name=name,
        version="1.0.0",
        description=f"Test action {name}",
        risk_class=risk_class,
        target_types=["k8s-deployment"],
        prechecks=prechecks or [],
        credentials=credentials,
    )


def _make_registry(*actions: ActionDefinition) -> ActionRegistry:
    registry = ActionRegistry()
    for action in actions:
        registry.register(action)
    return registry


def _issue_ticket(
    action: str = "restart-deployment",
    target: str = "dev/test-app",
    caller: str = "agent-01",
    params: dict[str, Any] | None = None,
) -> str:
    issuer = TicketIssuer(signing_key=SIGNING_KEY)
    ticket = issuer.issue(
        action=action,
        target=target,
        caller=caller,
        audit_id="evt-test123",
        params=params or {"namespace": "dev", "deployment": "app"},
    )
    return ticket.token


# --- ExecutionStatus Model Tests ---


class TestExecutionStatusModel:
    def test_enum_values(self) -> None:
        assert ExecutionStatus.SUCCESS == "success"
        assert ExecutionStatus.FAILURE == "failure"
        assert ExecutionStatus.TIMEOUT == "timeout"
        assert ExecutionStatus.SKIPPED == "skipped"
        assert ExecutionStatus.ERROR == "error"

    def test_from_string(self) -> None:
        assert ExecutionStatus("success") == ExecutionStatus.SUCCESS

    def test_serialization(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            action="test",
            target="test",
            caller="test",
            audit_id="evt-test",
        )
        data = result.model_dump(mode="json")
        assert data["status"] == "success"


# --- PreCheckResult Model Tests ---


class TestPreCheckResultModel:
    def test_construction(self) -> None:
        pc = PreCheckResult(name="check-exists", passed=True)
        assert pc.name == "check-exists"
        assert pc.passed is True
        assert pc.message == ""
        assert pc.advisory is True

    def test_with_message(self) -> None:
        pc = PreCheckResult(name="check-exists", passed=False, message="Not found")
        assert pc.passed is False
        assert pc.message == "Not found"

    def test_serialization(self) -> None:
        pc = PreCheckResult(name="check", passed=True, advisory=False)
        data = pc.model_dump(mode="json")
        assert data["advisory"] is False


# --- ExecutionResult Model Tests ---


class TestExecutionResultModel:
    def test_minimal_construction(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            action="restart-deployment",
            target="dev/test",
            caller="agent-01",
            audit_id="evt-123",
        )
        assert result.status == ExecutionStatus.SUCCESS
        assert result.output == ""
        assert result.error is None
        assert result.precheck_results == []
        assert result.before_state == {}

    def test_full_construction(self) -> None:
        now = datetime.now(tz=UTC)
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            action="restart-deployment",
            target="dev/test",
            caller="agent-01",
            audit_id="evt-123",
            ticket_nonce="abc123",
            output="deployment restarted",
            duration_ms=150.5,
            precheck_results=[PreCheckResult(name="check", passed=True)],
            before_state={"replicas": 2},
            after_state={"replicas": 2},
            executed_at=now,
            executor_type="subprocess",
        )
        assert result.ticket_nonce == "abc123"
        assert result.duration_ms == 150.5
        assert len(result.precheck_results) == 1

    def test_failure_result(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.FAILURE,
            action="test",
            target="test",
            caller="test",
            audit_id="evt-test",
            error="command failed",
        )
        assert result.status == ExecutionStatus.FAILURE
        assert result.error == "command failed"

    def test_timeout_result(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.TIMEOUT,
            action="test",
            target="test",
            caller="test",
            audit_id="evt-test",
            error="timed out",
        )
        assert result.status == ExecutionStatus.TIMEOUT

    def test_serialization_roundtrip(self) -> None:
        result = ExecutionResult(
            status=ExecutionStatus.SKIPPED,
            action="test",
            target="test",
            caller="test",
            audit_id="evt-test",
            output="dry-run",
            executor_type="dry-run",
        )
        data = result.model_dump(mode="json")
        restored = ExecutionResult(**data)
        assert restored.status == ExecutionStatus.SKIPPED
        assert restored.executor_type == "dry-run"


# --- Executor Protocol Tests ---


class TestExecutorProtocol:
    def test_dry_run_satisfies_protocol(self) -> None:
        executor = DryRunExecutor()
        assert isinstance(executor, Executor)

    def test_protocol_is_runtime_checkable(self) -> None:
        assert isinstance(DryRunExecutor(), Executor)

    def test_non_executor_fails(self) -> None:
        assert not isinstance("not an executor", Executor)


# --- DryRunExecutor Tests ---


class TestDryRunExecutor:
    def test_execute_returns_skipped(self) -> None:
        executor = DryRunExecutor()
        result = executor.execute(
            action="restart-deployment",
            target="dev/test",
            params={"namespace": "dev"},
        )
        assert result.status == ExecutionStatus.SKIPPED
        assert "dry-run" in result.output
        assert result.executor_type == "dry-run"

    def test_get_state_returns_empty(self) -> None:
        executor = DryRunExecutor()
        state = executor.get_state("test", "target", {})
        assert state == {}

    def test_run_prechecks_all_pass(self) -> None:
        executor = DryRunExecutor()
        prechecks = [
            Precheck(name="check-1", description="First check"),
            Precheck(name="check-2", description="Second check"),
        ]
        results = executor.run_prechecks("test", "target", {}, prechecks)
        assert len(results) == 2
        assert all(r.passed for r in results)

    def test_run_prechecks_empty(self) -> None:
        executor = DryRunExecutor()
        results = executor.run_prechecks("test", "target", {}, [])
        assert results == []

    def test_execute_with_credential(self) -> None:
        executor = DryRunExecutor()
        cred = Credential(
            credential_id="cred-1",
            type="kubernetes",
            payload={"token": "abc"},
            expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
            scope=CredentialScope(type="kubernetes"),
            ticket_nonce="nonce-1",
        )
        result = executor.execute("test", "target", {}, credential=cred)
        assert result.status == ExecutionStatus.SKIPPED


# --- Runner Validation Tests ---


class TestRunnerValidation:
    def setup_method(self) -> None:
        self.action = _make_action()
        self.registry = _make_registry(self.action)
        self.validator = TicketValidator(signing_key=SIGNING_KEY)
        self.executor = DryRunExecutor()

    def test_invalid_ticket_returns_error(self) -> None:
        runner = Runner(
            executor=self.executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        result = runner.run("garbage-token")
        assert result.status == ExecutionStatus.ERROR
        assert "Ticket validation failed" in result.error

    def test_expired_ticket_returns_error(self) -> None:
        issuer = TicketIssuer(signing_key=SIGNING_KEY, ttl=timedelta(seconds=-1))
        ticket = issuer.issue(
            action="restart-deployment",
            target="dev/test",
            caller="agent-01",
            audit_id="evt-test",
        )
        runner = Runner(
            executor=self.executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        result = runner.run(ticket.token)
        assert result.status == ExecutionStatus.ERROR
        assert "expired" in result.error.lower()

    def test_replay_ticket_returns_error(self) -> None:
        token = _issue_ticket()
        runner = Runner(
            executor=self.executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        # First use succeeds
        result1 = runner.run(token)
        assert result1.status == ExecutionStatus.SKIPPED

        # Second use is replay
        result2 = runner.run(token)
        assert result2.status == ExecutionStatus.ERROR
        assert "replay" in result2.error.lower()

    def test_unknown_action_returns_error(self) -> None:
        token = _issue_ticket(action="nonexistent-action")
        runner = Runner(
            executor=self.executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        result = runner.run(token)
        assert result.status == ExecutionStatus.ERROR
        assert "not found" in result.error.lower()

    def test_empty_token_returns_error(self) -> None:
        runner = Runner(
            executor=self.executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        result = runner.run("")
        assert result.status == ExecutionStatus.ERROR

    def test_wrong_key_returns_error(self) -> None:
        token = _issue_ticket()
        wrong_validator = TicketValidator(signing_key="wrong-key-32chars-minimum!!!!!!")
        runner = Runner(
            executor=self.executor,
            ticket_validator=wrong_validator,
            registry=self.registry,
        )
        result = runner.run(token)
        assert result.status == ExecutionStatus.ERROR


# --- Runner Lifecycle Tests ---


class TestRunnerLifecycle:
    def setup_method(self) -> None:
        self.action = _make_action(
            prechecks=[Precheck(name="check-exists", description="Verify exists")],
        )
        self.registry = _make_registry(self.action)
        self.validator = TicketValidator(signing_key=SIGNING_KEY)

    def test_full_lifecycle_with_dry_run_executor(self) -> None:
        executor = DryRunExecutor()
        runner = Runner(
            executor=executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.SKIPPED
        assert result.caller == "agent-01"
        assert result.audit_id == "evt-test123"
        assert result.ticket_nonce != ""
        assert result.duration_ms is not None
        assert len(result.precheck_results) == 1
        assert result.precheck_results[0].passed is True

    def test_lifecycle_with_audit(self) -> None:
        executor = DryRunExecutor()
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            audit = AuditLogger(tmp.name)
            runner = Runner(
                executor=executor,
                ticket_validator=self.validator,
                registry=self.registry,
                audit_logger=audit,
            )
            token = _issue_ticket()
            result = runner.run(token)
            assert result.status == ExecutionStatus.SKIPPED

            events = audit.read_events()
            execution_events = [e for e in events if e.event_type == "execution"]
            assert len(execution_events) == 1
            assert execution_events[0].action == "restart-deployment"

    def test_lifecycle_with_credentials(self) -> None:
        action_with_creds = _make_action(
            credentials=CredentialScope(type="kubernetes", fields={"token": "test"}),
        )
        registry = _make_registry(action_with_creds)

        mock_resolver = MagicMock(spec=CredentialResolver)
        mock_cred = Credential(
            credential_id="cred-test",
            type="kubernetes",
            payload={"token": "abc"},
            expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
            scope=CredentialScope(type="kubernetes"),
            ticket_nonce="nonce",
        )
        mock_resolver.resolve.return_value = CredentialResult(
            success=True, credential=mock_cred,
            action="restart-deployment", target="dev/test-app",
            ticket_nonce="nonce",
        )

        executor = DryRunExecutor()
        runner = Runner(
            executor=executor,
            ticket_validator=self.validator,
            registry=registry,
            credential_resolver=mock_resolver,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.SKIPPED
        mock_resolver.resolve.assert_called_once()
        mock_resolver.revoke.assert_called_once_with(mock_cred)

    def test_credential_revoked_on_executor_error(self) -> None:
        action_with_creds = _make_action(
            credentials=CredentialScope(type="kubernetes"),
        )
        registry = _make_registry(action_with_creds)

        mock_resolver = MagicMock(spec=CredentialResolver)
        mock_cred = Credential(
            credential_id="cred-test",
            type="kubernetes",
            payload={},
            expires_at=datetime.now(tz=UTC) + timedelta(minutes=5),
            scope=CredentialScope(type="kubernetes"),
            ticket_nonce="nonce",
        )
        mock_resolver.resolve.return_value = CredentialResult(
            success=True, credential=mock_cred,
            action="restart-deployment", target="dev/test-app",
            ticket_nonce="nonce",
        )

        # Executor that raises
        mock_executor = MagicMock()
        mock_executor.run_prechecks.return_value = []
        mock_executor.get_state.return_value = {}
        mock_executor.execute.side_effect = RuntimeError("boom")

        runner = Runner(
            executor=mock_executor,
            ticket_validator=self.validator,
            registry=registry,
            credential_resolver=mock_resolver,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.ERROR
        assert "boom" in result.error
        # Credential must still be revoked
        mock_resolver.revoke.assert_called_once_with(mock_cred)

    def test_no_credential_action_works(self) -> None:
        """Actions without credential scope skip credential resolution."""
        action_no_creds = _make_action(credentials=None)
        registry = _make_registry(action_no_creds)

        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=registry,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.SKIPPED

    def test_no_audit_logger_works(self) -> None:
        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=self.registry,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.SKIPPED

    def test_before_after_state_captured(self) -> None:
        mock_executor = MagicMock()
        mock_executor.run_prechecks.return_value = []
        mock_executor.get_state.side_effect = [
            {"replicas": 2},  # before
            {"replicas": 5},  # after
        ]
        mock_executor.execute.return_value = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            action="restart-deployment",
            target="dev/test-app",
            caller="",
            audit_id="",
            output="done",
        )

        runner = Runner(
            executor=mock_executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.SUCCESS
        assert result.before_state == {"replicas": 2}
        assert result.after_state == {"replicas": 5}

    def test_executor_type_propagated(self) -> None:
        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=self.registry,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.executor_type == "dry-run"

    def test_prechecks_included_in_result(self) -> None:
        action = _make_action(prechecks=[
            Precheck(name="pc-1", description="Check 1"),
            Precheck(name="pc-2", description="Check 2"),
        ])
        registry = _make_registry(action)

        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=registry,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert len(result.precheck_results) == 2

    def test_state_capture_failure_non_fatal(self) -> None:
        mock_executor = MagicMock()
        mock_executor.run_prechecks.return_value = []
        mock_executor.get_state.side_effect = RuntimeError("state error")
        mock_executor.execute.return_value = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            action="restart-deployment",
            target="dev/test-app",
            caller="",
            audit_id="",
        )

        runner = Runner(
            executor=mock_executor,
            ticket_validator=self.validator,
            registry=self.registry,
        )
        token = _issue_ticket()
        result = runner.run(token)
        # State capture failure is non-fatal
        assert result.status == ExecutionStatus.SUCCESS
        assert result.before_state == {}


# --- Runner Error Tests ---


class TestRunnerErrors:
    def setup_method(self) -> None:
        self.action = _make_action(
            credentials=CredentialScope(type="kubernetes"),
        )
        self.registry = _make_registry(self.action)
        self.validator = TicketValidator(signing_key=SIGNING_KEY)

    def test_credential_resolution_failure(self) -> None:
        mock_resolver = MagicMock(spec=CredentialResolver)
        mock_resolver.resolve.return_value = CredentialResult(
            success=False, error="Vault unreachable",
            action="restart-deployment", target="dev/test-app",
            ticket_nonce="nonce",
        )

        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=self.registry,
            credential_resolver=mock_resolver,
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.ERROR
        assert "Vault unreachable" in result.error

    def test_executor_raises_exception(self) -> None:
        mock_executor = MagicMock()
        mock_executor.run_prechecks.return_value = []
        mock_executor.get_state.return_value = {}
        mock_executor.execute.side_effect = RuntimeError("kaboom")

        runner = Runner(
            executor=mock_executor,
            ticket_validator=self.validator,
            registry=_make_registry(_make_action()),
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.ERROR
        assert "kaboom" in result.error

    def test_executor_returns_failure(self) -> None:
        mock_executor = MagicMock()
        mock_executor.run_prechecks.return_value = []
        mock_executor.get_state.return_value = {}
        mock_executor.execute.return_value = ExecutionResult(
            status=ExecutionStatus.FAILURE,
            action="restart-deployment",
            target="dev/test-app",
            caller="",
            audit_id="",
            error="kubectl exit code 1",
        )

        runner = Runner(
            executor=mock_executor,
            ticket_validator=self.validator,
            registry=_make_registry(_make_action()),
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.FAILURE
        assert result.error == "kubectl exit code 1"

    def test_executor_returns_timeout(self) -> None:
        mock_executor = MagicMock()
        mock_executor.run_prechecks.return_value = []
        mock_executor.get_state.return_value = {}
        mock_executor.execute.return_value = ExecutionResult(
            status=ExecutionStatus.TIMEOUT,
            action="restart-deployment",
            target="dev/test-app",
            caller="",
            audit_id="",
            error="timed out",
        )

        runner = Runner(
            executor=mock_executor,
            ticket_validator=self.validator,
            registry=_make_registry(_make_action()),
        )
        token = _issue_ticket()
        result = runner.run(token)
        assert result.status == ExecutionStatus.TIMEOUT

    def test_no_credential_resolver_with_cred_action_skips(self) -> None:
        """No credential_resolver configured but action has credentials -> skip creds."""
        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=self.registry,
            credential_resolver=None,
        )
        token = _issue_ticket()
        result = runner.run(token)
        # No resolver → skip credential resolution, still execute
        assert result.status == ExecutionStatus.SKIPPED


# --- Runner dry_run Tests ---


class TestRunnerDryRun:
    def setup_method(self) -> None:
        self.action = _make_action(
            prechecks=[Precheck(name="deploy-exists", description="Check")],
        )
        self.registry = _make_registry(self.action)
        self.validator = TicketValidator(signing_key=SIGNING_KEY)

    def test_dry_run_returns_skipped(self) -> None:
        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=self.registry,
        )
        token = _issue_ticket()
        result = runner.dry_run(token)
        assert result.status == ExecutionStatus.SKIPPED
        assert "dry-run" in result.output.lower()

    def test_dry_run_validates_ticket(self) -> None:
        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=self.registry,
        )
        result = runner.dry_run("bad-token")
        assert result.status == ExecutionStatus.ERROR

    def test_dry_run_includes_prechecks(self) -> None:
        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=self.registry,
        )
        token = _issue_ticket()
        result = runner.dry_run(token)
        assert len(result.precheck_results) == 1
        assert result.precheck_results[0].name == "deploy-exists"

    def test_dry_run_shows_cred_requirement(self) -> None:
        action = _make_action(
            credentials=CredentialScope(type="kubernetes"),
        )
        registry = _make_registry(action)
        runner = Runner(
            executor=DryRunExecutor(),
            ticket_validator=self.validator,
            registry=registry,
        )
        token = _issue_ticket()
        result = runner.dry_run(token)
        assert "credentials required" in result.output.lower()
