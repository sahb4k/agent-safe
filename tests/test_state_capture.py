"""Tests for before/after state capture (v0.6.0).

Covers:
- StateFieldSpec model
- StateCapture model
- AuditEvent.event_type field
- ActionDefinition.state_fields
- compute_state_diff utility
- AuditLogger.log_state_capture() and get_state_captures()
- SDK record_before_state(), record_after_state(), record_state(), get_state_capture()
- CLI audit show-state, audit state-coverage, --event-type filter
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from click.testing import CliRunner

from agent_safe.audit.differ import compute_state_diff
from agent_safe.audit.logger import AuditLogger
from agent_safe.cli.main import cli
from agent_safe.models import (
    ActionDefinition,
    AuditEvent,
    DecisionResult,
    PolicyMatch,
    PolicyRule,
    RiskClass,
    StateCapture,
    StateFieldSpec,
)
from agent_safe.registry.loader import load_registry
from agent_safe.sdk.client import AgentSafe, AgentSafeError

# --- Test constants ---

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

ACTIONS_DIR = str(_PROJECT_ROOT / "actions")
POLICIES_DIR = str(_PROJECT_ROOT / "policies")
INVENTORY_FILE = str(_PROJECT_ROOT / "inventory.yaml")

NOW = datetime(2026, 2, 24, 12, 0, 0, tzinfo=UTC)


def _make_rule(
    name: str,
    decision: DecisionResult,
    reason: str = "test",
    priority: int = 100,
    actions: list[str] | None = None,
) -> PolicyRule:
    """Helper to create a PolicyRule."""
    match_kwargs: dict[str, Any] = {}
    if actions is not None:
        match_kwargs["actions"] = actions
    return PolicyRule(
        name=name,
        priority=priority,
        match=PolicyMatch(**match_kwargs),
        decision=decision,
        reason=reason,
    )


# ============================================================
# StateFieldSpec model tests
# ============================================================


class TestStateFieldSpec:
    """Test the StateFieldSpec model."""

    def test_construction_minimal(self) -> None:
        spec = StateFieldSpec(name="replicas")
        assert spec.name == "replicas"
        assert spec.description == ""
        assert spec.type == "any"
        assert spec.required is False

    def test_construction_full(self) -> None:
        spec = StateFieldSpec(
            name="replicas",
            description="Current replica count",
            type="integer",
            required=True,
        )
        assert spec.name == "replicas"
        assert spec.description == "Current replica count"
        assert spec.type == "integer"
        assert spec.required is True

    def test_serialization(self) -> None:
        spec = StateFieldSpec(name="data", type="object", required=True)
        data = spec.model_dump()
        assert data["name"] == "data"
        assert data["type"] == "object"
        assert data["required"] is True

    def test_from_dict(self) -> None:
        spec = StateFieldSpec(**{"name": "generation", "type": "integer"})
        assert spec.name == "generation"
        assert spec.type == "integer"


# ============================================================
# StateCapture model tests
# ============================================================


class TestStateCaptureModel:
    """Test the StateCapture model."""

    def test_construction_minimal(self) -> None:
        capture = StateCapture(
            audit_id="evt-abc123",
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            captured_at=NOW,
        )
        assert capture.audit_id == "evt-abc123"
        assert capture.before_state == {}
        assert capture.after_state == {}
        assert capture.diff == {}
        assert capture.capture_duration_ms is None
        assert capture.state_fields_declared == []
        assert capture.state_fields_captured == []

    def test_construction_full(self) -> None:
        capture = StateCapture(
            audit_id="evt-abc123",
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            before_state={"replicas": 2},
            after_state={"replicas": 5},
            diff={
                "changed": {"replicas": {"old": 2, "new": 5}},
                "added": {}, "removed": {}, "unchanged": [],
            },
            captured_at=NOW,
            capture_duration_ms=150.5,
            state_fields_declared=["replicas", "available_replicas"],
            state_fields_captured=["replicas"],
        )
        assert capture.before_state == {"replicas": 2}
        assert capture.after_state == {"replicas": 5}
        assert capture.capture_duration_ms == 150.5
        assert len(capture.state_fields_declared) == 2

    def test_serialization(self) -> None:
        capture = StateCapture(
            audit_id="evt-123",
            action="test",
            target="t",
            caller="c",
            before_state={"a": 1},
            after_state={"a": 2},
            captured_at=NOW,
        )
        data = capture.model_dump(mode="json")
        assert data["audit_id"] == "evt-123"
        assert data["before_state"] == {"a": 1}
        assert data["after_state"] == {"a": 2}

    def test_from_dict(self) -> None:
        data = {
            "audit_id": "evt-x",
            "action": "test",
            "target": "t",
            "caller": "c",
            "captured_at": NOW.isoformat(),
        }
        capture = StateCapture(**data)
        assert capture.audit_id == "evt-x"

    def test_empty_states(self) -> None:
        capture = StateCapture(
            audit_id="evt-empty",
            action="test",
            target="t",
            caller="c",
            before_state={},
            after_state={},
            captured_at=NOW,
        )
        assert capture.before_state == {}
        assert capture.after_state == {}


# ============================================================
# AuditEvent.event_type tests
# ============================================================


class TestAuditEventType:
    """Test the event_type field on AuditEvent."""

    def test_default_is_decision(self) -> None:
        event = AuditEvent(
            event_id="evt-1",
            timestamp=NOW,
            prev_hash="0" * 64,
            action="test",
            target="t",
            caller="c",
            decision=DecisionResult.ALLOW,
            reason="test",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
        )
        assert event.event_type == "decision"

    def test_state_capture_type(self) -> None:
        event = AuditEvent(
            event_id="evt-2",
            timestamp=NOW,
            prev_hash="0" * 64,
            event_type="state_capture",
            action="test",
            target="t",
            caller="c",
            decision=DecisionResult.ALLOW,
            reason="state capture",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
        )
        assert event.event_type == "state_capture"

    def test_backward_compat_missing_event_type(self) -> None:
        """Old events without event_type should default to 'decision'."""
        data = {
            "event_id": "evt-old",
            "timestamp": NOW.isoformat(),
            "prev_hash": "0" * 64,
            "entry_hash": "",
            "action": "test",
            "target": "t",
            "caller": "c",
            "decision": "allow",
            "reason": "test",
            "risk_class": "low",
            "effective_risk": "low",
        }
        event = AuditEvent(**data)
        assert event.event_type == "decision"

    def test_event_type_in_serialization(self) -> None:
        event = AuditEvent(
            event_id="evt-3",
            timestamp=NOW,
            prev_hash="0" * 64,
            event_type="state_capture",
            action="test",
            target="t",
            caller="c",
            decision=DecisionResult.ALLOW,
            reason="test",
            risk_class=RiskClass.LOW,
            effective_risk=RiskClass.LOW,
        )
        data = event.model_dump(mode="json")
        assert data["event_type"] == "state_capture"


# ============================================================
# ActionDefinition.state_fields tests
# ============================================================


class TestActionDefinitionStateFields:
    """Test the state_fields field on ActionDefinition."""

    def test_default_empty_list(self) -> None:
        action = ActionDefinition(
            name="test-action",
            version="1.0.0",
            description="test",
            risk_class=RiskClass.LOW,
            target_types=["k8s-deployment"],
        )
        assert action.state_fields == []

    def test_with_state_fields(self) -> None:
        action = ActionDefinition(
            name="test-action",
            version="1.0.0",
            description="test",
            risk_class=RiskClass.LOW,
            target_types=["k8s-deployment"],
            state_fields=[
                StateFieldSpec(name="replicas", type="integer", required=True),
                StateFieldSpec(name="ready", type="integer"),
            ],
        )
        assert len(action.state_fields) == 2
        assert action.state_fields[0].name == "replicas"
        assert action.state_fields[0].required is True
        assert action.state_fields[1].name == "ready"

    def test_yaml_loading_with_state_fields(self) -> None:
        """Verify the real action YAML files with state_fields load correctly."""
        registry = load_registry(ACTIONS_DIR)
        action = registry.get("scale-deployment")
        assert action is not None
        assert len(action.state_fields) > 0
        field_names = [sf.name for sf in action.state_fields]
        assert "replicas" in field_names

    def test_yaml_loading_without_state_fields(self) -> None:
        """Actions without state_fields should load with empty list."""
        registry = load_registry(ACTIONS_DIR)
        action = registry.get("delete-pod")
        assert action is not None
        assert action.state_fields == []


# ============================================================
# compute_state_diff tests
# ============================================================


class TestComputeStateDiff:
    """Test the compute_state_diff utility."""

    def test_both_empty(self) -> None:
        diff = compute_state_diff({}, {})
        assert diff == {"added": {}, "removed": {}, "changed": {}, "unchanged": []}

    def test_identical(self) -> None:
        state = {"a": 1, "b": 2}
        diff = compute_state_diff(state, state)
        assert diff["added"] == {}
        assert diff["removed"] == {}
        assert diff["changed"] == {}
        assert sorted(diff["unchanged"]) == ["a", "b"]

    def test_added_keys(self) -> None:
        diff = compute_state_diff({}, {"a": 1, "b": 2})
        assert diff["added"] == {"a": 1, "b": 2}
        assert diff["removed"] == {}
        assert diff["changed"] == {}

    def test_removed_keys(self) -> None:
        diff = compute_state_diff({"a": 1, "b": 2}, {})
        assert diff["removed"] == {"a": 1, "b": 2}
        assert diff["added"] == {}
        assert diff["changed"] == {}

    def test_changed_keys(self) -> None:
        diff = compute_state_diff({"a": 1}, {"a": 2})
        assert diff["changed"] == {"a": {"old": 1, "new": 2}}
        assert diff["unchanged"] == []

    def test_mixed(self) -> None:
        before = {"a": 1, "b": 2, "c": 3}
        after = {"a": 1, "b": 5, "d": 4}
        diff = compute_state_diff(before, after)
        assert diff["unchanged"] == ["a"]
        assert diff["changed"] == {"b": {"old": 2, "new": 5}}
        assert diff["removed"] == {"c": 3}
        assert diff["added"] == {"d": 4}

    def test_nested_values(self) -> None:
        before = {"config": {"key": "old"}}
        after = {"config": {"key": "new"}}
        diff = compute_state_diff(before, after)
        assert diff["changed"]["config"]["old"] == {"key": "old"}
        assert diff["changed"]["config"]["new"] == {"key": "new"}

    def test_none_values(self) -> None:
        diff = compute_state_diff({"a": None}, {"a": 1})
        assert diff["changed"] == {"a": {"old": None, "new": 1}}

    def test_type_change(self) -> None:
        diff = compute_state_diff({"a": "1"}, {"a": 1})
        assert diff["changed"] == {"a": {"old": "1", "new": 1}}

    def test_empty_before(self) -> None:
        diff = compute_state_diff({}, {"x": 10})
        assert diff["added"] == {"x": 10}
        assert diff["unchanged"] == []

    def test_empty_after(self) -> None:
        diff = compute_state_diff({"x": 10}, {})
        assert diff["removed"] == {"x": 10}
        assert diff["unchanged"] == []

    def test_sorted_keys(self) -> None:
        diff = compute_state_diff({}, {"z": 1, "a": 2, "m": 3})
        assert list(diff["added"].keys()) == ["a", "m", "z"]

    def test_large_diff(self) -> None:
        before = {f"key{i}": i for i in range(10)}
        after = {f"key{i}": i * 2 for i in range(5, 15)}
        diff = compute_state_diff(before, after)
        assert len(diff["removed"]) == 5  # key0-key4
        assert len(diff["added"]) == 5  # key10-key14
        assert len(diff["changed"]) == 5  # key5-key9


# ============================================================
# AuditLogger state capture tests
# ============================================================


class TestLogStateCapture:
    """Test AuditLogger.log_state_capture()."""

    def test_writes_event(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            capture = StateCapture(
                audit_id="evt-orig",
                action="scale-deployment",
                target="dev/test-app",
                caller="agent-01",
                before_state={"replicas": 2},
                after_state={"replicas": 5},
                diff={
                    "changed": {"replicas": {"old": 2, "new": 5}},
                    "added": {}, "removed": {}, "unchanged": [],
                },
                captured_at=NOW,
                capture_duration_ms=100.0,
            )
            event = logger.log_state_capture(capture)
            assert event.event_type == "state_capture"
            assert event.correlation_id == "evt-orig"
            assert event.action == "scale-deployment"
        finally:
            path.unlink(missing_ok=True)

    def test_hash_chain_maintained(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)

            # Write a decision event first
            from agent_safe.models import Decision
            decision = Decision(
                result=DecisionResult.ALLOW,
                reason="test",
                action="test",
                target="t",
                caller="c",
                risk_class=RiskClass.LOW,
                effective_risk=RiskClass.LOW,
                audit_id="evt-dec",
            )
            logger.log_decision(decision)

            # Write a state capture
            capture = StateCapture(
                audit_id="evt-dec",
                action="test",
                target="t",
                caller="c",
                before_state={"a": 1},
                after_state={"a": 2},
                captured_at=NOW,
            )
            logger.log_state_capture(capture)

            # Verify chain
            from agent_safe.audit.logger import verify_log
            is_valid, errors = verify_log(path)
            assert is_valid, f"Chain broken: {errors}"
        finally:
            path.unlink(missing_ok=True)

    def test_context_contains_state_data(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            capture = StateCapture(
                audit_id="evt-orig",
                action="test",
                target="t",
                caller="c",
                before_state={"x": 1},
                after_state={"x": 2},
                diff={
                    "changed": {"x": {"old": 1, "new": 2}},
                    "added": {}, "removed": {}, "unchanged": [],
                },
                captured_at=NOW,
                state_fields_declared=["x"],
                state_fields_captured=["x"],
            )
            event = logger.log_state_capture(capture)
            ctx = event.context
            assert ctx is not None
            assert ctx["type"] == "state_capture"
            assert ctx["original_audit_id"] == "evt-orig"
            assert ctx["before_state"] == {"x": 1}
            assert ctx["after_state"] == {"x": 2}
            assert ctx["diff"]["changed"]["x"] == {"old": 1, "new": 2}
            assert ctx["state_fields_declared"] == ["x"]
            assert ctx["state_fields_captured"] == ["x"]
        finally:
            path.unlink(missing_ok=True)

    def test_event_id_generated(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            capture = StateCapture(
                audit_id="evt-orig",
                action="test",
                target="t",
                caller="c",
                captured_at=NOW,
            )
            event = logger.log_state_capture(capture)
            assert event.event_id.startswith("evt-")
            assert event.event_id != "evt-orig"  # gets its own event_id
        finally:
            path.unlink(missing_ok=True)

    def test_decision_fields_set(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            capture = StateCapture(
                audit_id="evt-orig",
                action="test",
                target="t",
                caller="c",
                captured_at=NOW,
            )
            event = logger.log_state_capture(capture)
            assert event.decision == DecisionResult.ALLOW
            assert event.risk_class == RiskClass.LOW
            assert event.effective_risk == RiskClass.LOW
        finally:
            path.unlink(missing_ok=True)

    def test_shippers_called(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            shipped: list[AuditEvent] = []

            class FakeShipper:
                def ship(self, event: AuditEvent) -> None:
                    shipped.append(event)

            logger = AuditLogger(path, shippers=[FakeShipper()])  # type: ignore[list-item]
            capture = StateCapture(
                audit_id="evt-orig",
                action="test",
                target="t",
                caller="c",
                captured_at=NOW,
            )
            logger.log_state_capture(capture)
            assert len(shipped) == 1
            assert shipped[0].event_type == "state_capture"
        finally:
            path.unlink(missing_ok=True)


class TestGetStateCaptures:
    """Test AuditLogger.get_state_captures()."""

    def test_returns_matching(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            capture = StateCapture(
                audit_id="evt-target",
                action="test",
                target="t",
                caller="c",
                captured_at=NOW,
            )
            logger.log_state_capture(capture)

            results = logger.get_state_captures("evt-target")
            assert len(results) == 1
            assert results[0].event_type == "state_capture"
            assert results[0].context["original_audit_id"] == "evt-target"
        finally:
            path.unlink(missing_ok=True)

    def test_returns_empty_for_no_match(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            capture = StateCapture(
                audit_id="evt-other",
                action="test",
                target="t",
                caller="c",
                captured_at=NOW,
            )
            logger.log_state_capture(capture)

            results = logger.get_state_captures("evt-nomatch")
            assert results == []
        finally:
            path.unlink(missing_ok=True)

    def test_returns_empty_for_empty_log(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            results = logger.get_state_captures("evt-anything")
            assert results == []
        finally:
            path.unlink(missing_ok=True)

    def test_ignores_decision_events(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            # Log a decision event
            from agent_safe.models import Decision
            decision = Decision(
                result=DecisionResult.ALLOW,
                reason="test",
                action="test",
                target="t",
                caller="c",
                risk_class=RiskClass.LOW,
                effective_risk=RiskClass.LOW,
                audit_id="evt-dec",
            )
            logger.log_decision(decision)

            results = logger.get_state_captures("evt-dec")
            assert results == []
        finally:
            path.unlink(missing_ok=True)

    def test_multiple_captures_for_same_audit_id(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = Path(f.name)
        try:
            logger = AuditLogger(path)
            for i in range(3):
                capture = StateCapture(
                    audit_id="evt-multi",
                    action="test",
                    target="t",
                    caller="c",
                    before_state={"v": i},
                    after_state={"v": i + 1},
                    captured_at=NOW,
                )
                logger.log_state_capture(capture)

            results = logger.get_state_captures("evt-multi")
            assert len(results) == 3
        finally:
            path.unlink(missing_ok=True)


# ============================================================
# SDK record_before_state() tests
# ============================================================


class TestRecordBeforeState:
    """Test AgentSafe.record_before_state()."""

    def test_stores_state(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-abc", {"replicas": 2})
            assert "evt-abc" in safe._pending_state
            assert safe._pending_state["evt-abc"]["before_state"] == {"replicas": 2}
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_raises_without_audit(self) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        try:
            safe.record_before_state("evt-abc", {"replicas": 2})
            raise AssertionError("Should have raised")
        except AgentSafeError as e:
            assert "Audit log is not configured" in str(e)

    def test_multiple_audit_ids(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-1", {"a": 1})
            safe.record_before_state("evt-2", {"b": 2})
            assert len(safe._pending_state) == 2
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_overwrites_existing(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-1", {"a": 1})
            safe.record_before_state("evt-1", {"a": 99})
            assert safe._pending_state["evt-1"]["before_state"] == {"a": 99}
        finally:
            Path(audit_path).unlink(missing_ok=True)


# ============================================================
# SDK record_after_state() tests
# ============================================================


class TestRecordAfterState:
    """Test AgentSafe.record_after_state()."""

    def test_writes_event(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-abc", {"replicas": 2})
            capture = safe.record_after_state(
                "evt-abc", {"replicas": 5},
                action="scale-deployment", target="dev/test-app", caller="agent-01",
            )
            assert capture.audit_id == "evt-abc"
            assert capture.before_state == {"replicas": 2}
            assert capture.after_state == {"replicas": 5}
            assert capture.action == "scale-deployment"
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_raises_without_before(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            try:
                safe.record_after_state("evt-missing", {"replicas": 5})
                raise AssertionError("Should have raised")
            except AgentSafeError as e:
                assert "No before-state recorded" in str(e)
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_raises_without_audit(self) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        try:
            safe.record_after_state("evt-abc", {"replicas": 5})
            raise AssertionError("Should have raised")
        except AgentSafeError as e:
            assert "Audit log is not configured" in str(e)

    def test_diff_computed(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-diff", {"replicas": 2, "ready": 2})
            capture = safe.record_after_state(
                "evt-diff", {"replicas": 5, "ready": 2},
                action="scale-deployment",
            )
            assert capture.diff["changed"] == {"replicas": {"old": 2, "new": 5}}
            assert "ready" in capture.diff["unchanged"]
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_duration_computed(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-dur", {"a": 1})
            capture = safe.record_after_state("evt-dur", {"a": 2})
            assert capture.capture_duration_ms is not None
            assert capture.capture_duration_ms >= 0
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_state_fields_declared(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-sf", {"replicas": 2})
            capture = safe.record_after_state(
                "evt-sf", {"replicas": 5},
                action="scale-deployment",
            )
            assert "replicas" in capture.state_fields_declared
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_state_fields_captured(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-fc", {"replicas": 2, "ready": 2})
            capture = safe.record_after_state(
                "evt-fc", {"replicas": 5, "available": 3},
            )
            assert sorted(capture.state_fields_captured) == ["available", "ready", "replicas"]
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_pops_pending_state(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-pop", {"a": 1})
            safe.record_after_state("evt-pop", {"a": 2})
            assert "evt-pop" not in safe._pending_state
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_defaults_for_optional_fields(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-def", {"a": 1})
            capture = safe.record_after_state("evt-def", {"a": 2})
            assert capture.action == "unknown"
            assert capture.target == "unknown"
            assert capture.caller == "unknown"
        finally:
            Path(audit_path).unlink(missing_ok=True)


# ============================================================
# SDK record_state() tests
# ============================================================


class TestRecordState:
    """Test AgentSafe.record_state() convenience method."""

    def test_writes_event(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            capture = safe.record_state(
                "evt-conv",
                before={"replicas": 2},
                after={"replicas": 5},
                action="scale-deployment",
                target="dev/test-app",
                caller="agent-01",
            )
            assert capture.audit_id == "evt-conv"
            assert capture.before_state == {"replicas": 2}
            assert capture.after_state == {"replicas": 5}
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_returns_state_capture(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            result = safe.record_state("evt-ret", {"a": 1}, {"a": 2})
            assert isinstance(result, StateCapture)
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_diff_computed(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            capture = safe.record_state("evt-d", {"x": 1}, {"x": 2, "y": 3})
            assert capture.diff["changed"] == {"x": {"old": 1, "new": 2}}
            assert capture.diff["added"] == {"y": 3}
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_cleans_pending(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_state("evt-clean", {"a": 1}, {"a": 2})
            assert "evt-clean" not in safe._pending_state
        finally:
            Path(audit_path).unlink(missing_ok=True)


# ============================================================
# SDK get_state_capture() tests
# ============================================================


class TestGetStateCapture:
    """Test AgentSafe.get_state_capture()."""

    def test_retrieves_capture(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_state(
                "evt-get",
                before={"replicas": 2},
                after={"replicas": 5},
                action="scale-deployment",
                target="dev/test-app",
                caller="agent-01",
            )
            capture = safe.get_state_capture("evt-get")
            assert capture is not None
            assert capture.audit_id == "evt-get"
            assert capture.before_state == {"replicas": 2}
            assert capture.after_state == {"replicas": 5}
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_returns_none_when_not_found(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            capture = safe.get_state_capture("evt-nonexistent")
            assert capture is None
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_returns_none_without_audit(self) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
        )
        assert safe.get_state_capture("evt-any") is None

    def test_reconstructs_all_fields(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_state(
                "evt-full",
                before={"a": 1, "b": 2},
                after={"a": 3, "c": 4},
                action="test-action",
                target="dev/app",
                caller="agent-x",
            )
            capture = safe.get_state_capture("evt-full")
            assert capture is not None
            assert capture.action == "test-action"
            assert capture.target == "dev/app"
            assert capture.caller == "agent-x"
            assert capture.diff["changed"]["a"] == {"old": 1, "new": 3}
        finally:
            Path(audit_path).unlink(missing_ok=True)


# ============================================================
# End-to-end: check() → record_state() flow
# ============================================================


class TestStateCaptureEndToEnd:
    """Test the full check() → state capture flow."""

    def test_check_then_record(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )

            if decision.result == DecisionResult.ALLOW:
                capture = safe.record_state(
                    decision.audit_id,
                    before={"generation": 5, "available_replicas": 3},
                    after={"generation": 6, "available_replicas": 3},
                    action="restart-deployment",
                    target="dev/test-app",
                    caller="deploy-agent",
                )
                assert capture.audit_id == decision.audit_id
                assert capture.diff["changed"]["generation"] == {"old": 5, "new": 6}
                assert "available_replicas" in capture.diff["unchanged"]

                # Verify in audit log
                events = safe.audit.read_events()
                state_events = [e for e in events if e.event_type == "state_capture"]
                assert len(state_events) == 1
                assert state_events[0].correlation_id == decision.audit_id
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_audit_chain_valid_after_state_capture(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            decision = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(
                decision.audit_id,
                before={"gen": 1},
                after={"gen": 2},
                action="restart-deployment",
            )

            is_valid, errors = safe.verify_audit()
            assert is_valid, f"Chain broken: {errors}"
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_state_fields_from_action_yaml(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            safe.record_before_state("evt-yaml", {"replicas": 2})
            capture = safe.record_after_state(
                "evt-yaml",
                {"replicas": 5},
                action="scale-deployment",
            )
            # scale-deployment has state_fields declared
            assert "replicas" in capture.state_fields_declared
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_get_state_capture_after_record(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_state(
                "evt-roundtrip",
                before={"x": 10},
                after={"x": 20},
                action="test",
                target="t",
                caller="c",
            )
            retrieved = safe.get_state_capture("evt-roundtrip")
            assert retrieved is not None
            assert retrieved.before_state == {"x": 10}
            assert retrieved.after_state == {"x": 20}
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_multiple_decisions_with_state(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            # Two decisions, each with state
            d1 = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d1.audit_id, {"gen": 1}, {"gen": 2}, action="restart-deployment")

            d2 = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d2.audit_id, {"gen": 2}, {"gen": 3}, action="restart-deployment")

            c1 = safe.get_state_capture(d1.audit_id)
            c2 = safe.get_state_capture(d2.audit_id)
            assert c1 is not None
            assert c2 is not None
            assert c1.before_state["gen"] == 1
            assert c2.before_state["gen"] == 2
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_no_state_for_denied_actions(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            # Unknown action → DENY
            decision = safe.check(
                action="nonexistent-action",
                target="dev/test-app",
                caller="agent",
            )
            assert decision.result == DecisionResult.DENY
            # No state capture for denied actions
            capture = safe.get_state_capture(decision.audit_id)
            assert capture is None
        finally:
            Path(audit_path).unlink(missing_ok=True)


# ============================================================
# CLI audit show-state tests
# ============================================================


class TestAuditShowState:
    """Test the CLI audit show-state command."""

    def test_shows_state(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_state(
                "evt-cli",
                before={"replicas": 2},
                after={"replicas": 5},
                action="scale-deployment",
                target="dev/app",
                caller="agent-01",
            )

            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "show-state", "evt-cli",
                "--log-file", audit_path,
            ])
            assert result.exit_code == 0
            assert "evt-cli" in result.output
            assert "scale-deployment" in result.output
            assert "replicas" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_json_output(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_state(
                "evt-json",
                before={"a": 1},
                after={"a": 2},
                action="test",
                target="t",
                caller="c",
            )

            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "show-state", "evt-json",
                "--log-file", audit_path,
                "--json-output",
            ])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["audit_id"] == "evt-json"
            assert data["before_state"] == {"a": 1}
            assert data["after_state"] == {"a": 2}
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_not_found(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            # Empty log
            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "show-state", "evt-missing",
                "--log-file", audit_path,
            ])
            assert result.exit_code == 1
            assert "No state capture found" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_shows_changes(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            safe.record_state(
                "evt-ch",
                before={"replicas": 2},
                after={"replicas": 5},
                action="scale-deployment",
            )

            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "show-state", "evt-ch",
                "--log-file", audit_path,
            ])
            assert result.exit_code == 0
            assert "Changes" in result.output
            assert "replicas" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)


# ============================================================
# CLI audit state-coverage tests
# ============================================================


class TestAuditStateCoverage:
    """Test the CLI audit state-coverage command."""

    def test_coverage_report(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            # Two decisions, one with state capture
            d1 = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d1.audit_id, {"g": 1}, {"g": 2}, action="restart-deployment")

            safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            # No state for d2

            runner = CliRunner()
            result = runner.invoke(cli, ["audit", "state-coverage", audit_path])
            assert result.exit_code == 0
            assert "1/2" in result.output or "50.0%" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_json_output(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                audit_log=audit_path,
            )
            d1 = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d1.audit_id, {"a": 1}, {"a": 2})

            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "state-coverage", audit_path,
                "--json-output",
            ])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["total_decisions"] == 1
            assert data["with_state_capture"] == 1
            assert data["coverage_percent"] == 100.0
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_empty_log(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            runner = CliRunner()
            result = runner.invoke(cli, ["audit", "state-coverage", audit_path])
            assert result.exit_code == 0
            assert "0/0" in result.output or "0.0%" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)


# ============================================================
# CLI audit show --event-type filter tests
# ============================================================


class TestAuditShowEventTypeFilter:
    """Test the --event-type filter on audit show."""

    def test_filter_decision(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            d = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d.audit_id, {"a": 1}, {"a": 2}, action="restart-deployment")

            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "show", audit_path,
                "--event-type", "decision",
            ])
            assert result.exit_code == 0
            assert "1 event(s) shown" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_filter_state_capture(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            d = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d.audit_id, {"a": 1}, {"a": 2}, action="restart-deployment")

            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "show", audit_path,
                "--event-type", "state_capture",
            ])
            assert result.exit_code == 0
            assert "STATE_CAPTURE" in result.output
            assert "1 event(s) shown" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_no_filter_shows_all(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            d = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d.audit_id, {"a": 1}, {"a": 2}, action="restart-deployment")

            runner = CliRunner()
            result = runner.invoke(cli, ["audit", "show", audit_path])
            assert result.exit_code == 0
            assert "2 event(s) shown" in result.output
        finally:
            Path(audit_path).unlink(missing_ok=True)

    def test_json_output_with_filter(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            audit_path = f.name
        try:
            safe = AgentSafe(
                registry=ACTIONS_DIR,
                policies=POLICIES_DIR,
                inventory=INVENTORY_FILE,
                audit_log=audit_path,
            )
            d = safe.check(
                action="restart-deployment",
                target="dev/test-app",
                caller="deploy-agent",
                params={"namespace": "dev", "deployment": "app"},
            )
            safe.record_state(d.audit_id, {"a": 1}, {"a": 2}, action="restart-deployment")

            runner = CliRunner()
            result = runner.invoke(cli, [
                "audit", "show", audit_path,
                "--event-type", "state_capture",
                "--json-output",
            ])
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert len(data) == 1
            assert data[0]["event_type"] == "state_capture"
        finally:
            Path(audit_path).unlink(missing_ok=True)
