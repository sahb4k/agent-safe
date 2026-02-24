"""Tests for the hash-chained audit log."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agent_safe.audit.logger import GENESIS_HASH, AuditLogger, verify_log
from agent_safe.models import Decision, DecisionResult, RiskClass


@pytest.fixture()
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"


@pytest.fixture()
def sample_decision() -> Decision:
    return Decision(
        result=DecisionResult.ALLOW,
        reason="Dev allow-all",
        action="restart-deployment",
        target="dev/test-app",
        caller="deploy-agent-01",
        risk_class=RiskClass.MEDIUM,
        effective_risk=RiskClass.LOW,
        policy_matched="allow-dev-all",
        audit_id="evt-abc123def456",
    )


@pytest.fixture()
def deny_decision() -> Decision:
    return Decision(
        result=DecisionResult.DENY,
        reason="No matching policy (default deny)",
        action="delete-namespace",
        target="prod/payments",
        caller="unknown-agent",
        risk_class=RiskClass.CRITICAL,
        effective_risk=RiskClass.CRITICAL,
        policy_matched=None,
        audit_id="evt-def456789abc",
    )


# --- Basic Writing ---


class TestAuditLogWriter:
    def test_log_creates_file(self, log_path: Path, sample_decision: Decision):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        assert log_path.exists()

    def test_first_entry_uses_genesis_hash(
        self, log_path: Path, sample_decision: Decision
    ):
        logger = AuditLogger(log_path)
        event = logger.log_decision(sample_decision)
        assert event.prev_hash == GENESIS_HASH
        assert event.entry_hash != ""
        assert len(event.entry_hash) == 64

    def test_second_entry_chains_to_first(
        self, log_path: Path, sample_decision: Decision, deny_decision: Decision
    ):
        logger = AuditLogger(log_path)
        first = logger.log_decision(sample_decision)
        second = logger.log_decision(deny_decision)
        assert second.prev_hash == first.entry_hash
        assert second.entry_hash != first.entry_hash

    def test_event_fields_persisted(
        self, log_path: Path, sample_decision: Decision
    ):
        logger = AuditLogger(log_path)
        event = logger.log_decision(
            sample_decision,
            params={"namespace": "dev", "deployment": "app"},
            correlation_id="req-xyz",
            context={"source": "test"},
        )
        assert event.event_id == "evt-abc123def456"
        assert event.action == "restart-deployment"
        assert event.target == "dev/test-app"
        assert event.caller == "deploy-agent-01"
        assert event.decision == DecisionResult.ALLOW
        assert event.params == {"namespace": "dev", "deployment": "app"}
        assert event.correlation_id == "req-xyz"
        assert event.context == {"source": "test"}

    def test_log_is_json_lines(
        self, log_path: Path, sample_decision: Decision, deny_decision: Decision
    ):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        logger.log_decision(deny_decision)

        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            data = json.loads(line)
            assert "event_id" in data
            assert "entry_hash" in data

    def test_append_only(
        self, log_path: Path, sample_decision: Decision
    ):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        size1 = log_path.stat().st_size

        logger.log_decision(sample_decision)
        size2 = log_path.stat().st_size
        assert size2 > size1

    def test_custom_timestamp(self, log_path: Path, sample_decision: Decision):
        logger = AuditLogger(log_path)
        ts = datetime(2025, 6, 15, 12, 0, 0, tzinfo=UTC)
        event = logger.log_decision(sample_decision, timestamp=ts)
        assert event.timestamp == ts


# --- Reading ---


class TestAuditLogReader:
    def test_read_events(
        self, log_path: Path, sample_decision: Decision, deny_decision: Decision
    ):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        logger.log_decision(deny_decision)

        events = logger.read_events()
        assert len(events) == 2
        assert events[0].decision == DecisionResult.ALLOW
        assert events[1].decision == DecisionResult.DENY

    def test_read_empty_log(self, log_path: Path):
        logger = AuditLogger(log_path)
        assert logger.read_events() == []

    def test_read_nonexistent_log(self, tmp_path: Path):
        logger = AuditLogger(tmp_path / "missing.jsonl")
        assert logger.read_events() == []


# --- Chain Verification ---


class TestVerifyLog:
    def test_valid_chain(
        self, log_path: Path, sample_decision: Decision, deny_decision: Decision
    ):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        logger.log_decision(deny_decision)
        logger.log_decision(sample_decision)

        is_valid, errors = verify_log(log_path)
        assert is_valid is True
        assert errors == []

    def test_empty_log_is_valid(self, log_path: Path):
        is_valid, errors = verify_log(log_path)
        assert is_valid is True

    def test_nonexistent_log_is_valid(self, tmp_path: Path):
        is_valid, errors = verify_log(tmp_path / "missing.jsonl")
        assert is_valid is True

    def test_tampered_entry_detected(
        self, log_path: Path, sample_decision: Decision
    ):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        logger.log_decision(sample_decision)

        # Tamper with the first entry
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        entry = json.loads(lines[0])
        entry["reason"] = "TAMPERED"
        lines[0] = json.dumps(entry, sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        is_valid, errors = verify_log(log_path)
        assert is_valid is False
        assert len(errors) >= 1
        assert any("hash mismatch" in e for e in errors)

    def test_deleted_entry_detected(
        self, log_path: Path, sample_decision: Decision, deny_decision: Decision
    ):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        logger.log_decision(deny_decision)
        logger.log_decision(sample_decision)

        # Delete the middle entry
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        del lines[1]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        is_valid, errors = verify_log(log_path)
        assert is_valid is False
        assert any("chain broken" in e for e in errors)

    def test_reordered_entries_detected(
        self, log_path: Path, sample_decision: Decision, deny_decision: Decision
    ):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)
        logger.log_decision(deny_decision)

        # Swap the entries
        lines = log_path.read_text(encoding="utf-8").strip().split("\n")
        lines[0], lines[1] = lines[1], lines[0]
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        is_valid, errors = verify_log(log_path)
        assert is_valid is False

    def test_single_entry_valid(self, log_path: Path, sample_decision: Decision):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)

        is_valid, errors = verify_log(log_path)
        assert is_valid is True

    def test_corrupt_json_detected(self, log_path: Path, sample_decision: Decision):
        logger = AuditLogger(log_path)
        logger.log_decision(sample_decision)

        # Corrupt the file
        with log_path.open("a", encoding="utf-8") as f:
            f.write("{{not valid json}}\n")

        is_valid, errors = verify_log(log_path)
        assert is_valid is False
        assert any("invalid JSON" in e for e in errors)


# --- Resumption ---


class TestLogResumption:
    def test_new_logger_continues_chain(
        self, log_path: Path, sample_decision: Decision, deny_decision: Decision
    ):
        """A new AuditLogger instance picks up where the last left off."""
        logger1 = AuditLogger(log_path)
        first = logger1.log_decision(sample_decision)

        # Create a new logger instance (simulates process restart)
        logger2 = AuditLogger(log_path)
        second = logger2.log_decision(deny_decision)

        assert second.prev_hash == first.entry_hash

        # Full chain should verify
        is_valid, errors = verify_log(log_path)
        assert is_valid is True
        assert errors == []

    def test_resume_with_multiple_entries(
        self, log_path: Path, sample_decision: Decision
    ):
        logger1 = AuditLogger(log_path)
        logger1.log_decision(sample_decision)
        logger1.log_decision(sample_decision)
        last = logger1.log_decision(sample_decision)

        logger2 = AuditLogger(log_path)
        assert logger2.prev_hash == last.entry_hash


# --- Raw Logging ---


class TestRawLogging:
    def test_log_raw_event(self, log_path: Path):
        logger = AuditLogger(log_path)
        event = logger.log_raw(
            event_id="evt-manual-001",
            action="custom-action",
            target="custom/target",
            caller="manual-caller",
            decision=DecisionResult.DENY,
            reason="Manual denial",
            risk_class=RiskClass.HIGH,
            effective_risk=RiskClass.HIGH,
            params={"key": "value"},
        )
        assert event.event_id == "evt-manual-001"
        assert event.action == "custom-action"

        is_valid, _ = verify_log(log_path)
        assert is_valid is True
