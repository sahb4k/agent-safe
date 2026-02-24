"""Tests for rollback pairing (v0.7.0).

Covers:
- RollbackParamSource model
- RollbackPlan model
- ActionDefinition.rollback_params
- _resolve_source() helper
- RollbackPlanner (self-reversible, paired, convention, errors, warnings)
- SDK generate_rollback(), check_rollback()
- End-to-end rollback flow
- CLI rollback show, rollback check
"""

from __future__ import annotations

import json
import tempfile
from datetime import UTC, datetime
from typing import Any

from click.testing import CliRunner

from agent_safe.cli.main import cli
from agent_safe.models import (
    ActionDefinition,
    AuditEvent,
    DecisionResult,
    PolicyMatch,
    PolicyRule,
    RiskClass,
    RollbackPlan,
    StateCapture,
)
from agent_safe.registry.loader import ActionRegistry, load_registry
from agent_safe.rollback.planner import (
    RollbackError,
    RollbackPlanner,
    _resolve_source,
)
from agent_safe.sdk.client import AgentSafe, AgentSafeError

# --- Test constants ---

ACTIONS_DIR = "e:/Docs/Projects/agent-safe/actions"
POLICIES_DIR = "e:/Docs/Projects/agent-safe/policies"
INVENTORY_FILE = "e:/Docs/Projects/agent-safe/inventory.yaml"

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


def _make_registry(*actions: ActionDefinition) -> ActionRegistry:
    """Build an ActionRegistry from a list of ActionDefinitions."""
    registry = ActionRegistry()
    for action in actions:
        registry.register(action)
    return registry


def _make_audit_event(
    event_id: str = "evt-abc123",
    action: str = "scale-deployment",
    target: str = "dev/test-app",
    caller: str = "agent-01",
    params: dict[str, Any] | None = None,
) -> AuditEvent:
    """Helper to create a decision AuditEvent."""
    return AuditEvent(
        event_id=event_id,
        timestamp=NOW,
        prev_hash="0" * 64,
        entry_hash="a" * 64,
        event_type="decision",
        action=action,
        target=target,
        caller=caller,
        params=params or {
            "namespace": "dev",
            "deployment": "api",
            "replicas": 5,
        },
        decision=DecisionResult.ALLOW,
        reason="Allowed by test",
        risk_class=RiskClass.MEDIUM,
        effective_risk=RiskClass.MEDIUM,
    )


def _make_state_capture(
    audit_id: str = "evt-abc123",
    action: str = "scale-deployment",
    before_state: dict[str, Any] | None = None,
    after_state: dict[str, Any] | None = None,
) -> StateCapture:
    """Helper to create a StateCapture."""
    return StateCapture(
        audit_id=audit_id,
        action=action,
        target="dev/test-app",
        caller="agent-01",
        before_state=(
            {"replicas": 2} if before_state is None else before_state
        ),
        after_state=(
            {"replicas": 5} if after_state is None else after_state
        ),
        diff={"changed": {"replicas": {"old": 2, "new": 5}}},
        captured_at=NOW,
    )


# ============================================================
# RollbackParamSource model tests
# ============================================================


class TestRollbackParamSource:
    """Test the RollbackParamSource model."""

    def test_construction(self) -> None:
        from agent_safe.models import RollbackParamSource

        source = RollbackParamSource(source="params.namespace")
        assert source.source == "params.namespace"

    def test_before_state_source(self) -> None:
        from agent_safe.models import RollbackParamSource

        source = RollbackParamSource(source="before_state.replicas")
        assert source.source == "before_state.replicas"

    def test_serialization(self) -> None:
        from agent_safe.models import RollbackParamSource

        source = RollbackParamSource(source="params.namespace")
        data = source.model_dump()
        assert data == {"source": "params.namespace"}

    def test_from_dict(self) -> None:
        from agent_safe.models import RollbackParamSource

        source = RollbackParamSource.model_validate(
            {"source": "before_state.replicas"},
        )
        assert source.source == "before_state.replicas"


# ============================================================
# RollbackPlan model tests
# ============================================================


class TestRollbackPlan:
    """Test the RollbackPlan model."""

    def test_construction_minimal(self) -> None:
        plan = RollbackPlan(
            original_audit_id="evt-abc123",
            original_action="scale-deployment",
            original_target="dev/test-app",
            original_caller="agent-01",
            rollback_action="scale-deployment",
            rollback_target="dev/test-app",
            rollback_caller="agent-01",
            generated_at=NOW,
        )
        assert plan.original_audit_id == "evt-abc123"
        assert plan.rollback_action == "scale-deployment"
        assert plan.rollback_params == {}
        assert plan.warnings == []

    def test_construction_full(self) -> None:
        plan = RollbackPlan(
            original_audit_id="evt-abc123",
            original_action="scale-deployment",
            original_target="dev/test-app",
            original_caller="agent-01",
            original_params={"namespace": "dev", "deployment": "api",
                             "replicas": 5},
            rollback_action="scale-deployment",
            rollback_params={"namespace": "dev", "deployment": "api",
                             "replicas": 2},
            rollback_target="dev/test-app",
            rollback_caller="agent-01",
            before_state={"replicas": 2},
            generated_at=NOW,
            warnings=["test warning"],
        )
        assert plan.rollback_params["replicas"] == 2
        assert plan.before_state["replicas"] == 2
        assert len(plan.warnings) == 1

    def test_serialization(self) -> None:
        plan = RollbackPlan(
            original_audit_id="evt-abc123",
            original_action="scale-deployment",
            original_target="dev/test-app",
            original_caller="agent-01",
            rollback_action="scale-deployment",
            rollback_target="dev/test-app",
            rollback_caller="agent-01",
            generated_at=NOW,
        )
        data = plan.model_dump(mode="json")
        assert data["original_audit_id"] == "evt-abc123"
        assert isinstance(data["generated_at"], str)

    def test_from_dict(self) -> None:
        plan = RollbackPlan.model_validate({
            "original_audit_id": "evt-abc123",
            "original_action": "scale-deployment",
            "original_target": "dev/test-app",
            "original_caller": "agent-01",
            "rollback_action": "scale-deployment",
            "rollback_target": "dev/test-app",
            "rollback_caller": "agent-01",
            "generated_at": NOW.isoformat(),
        })
        assert plan.original_action == "scale-deployment"

    def test_warnings_list(self) -> None:
        plan = RollbackPlan(
            original_audit_id="evt-abc123",
            original_action="scale-deployment",
            original_target="dev/test-app",
            original_caller="agent-01",
            rollback_action="scale-deployment",
            rollback_target="dev/test-app",
            rollback_caller="agent-01",
            generated_at=NOW,
            warnings=["warning 1", "warning 2"],
        )
        assert len(plan.warnings) == 2
        assert "warning 1" in plan.warnings

    def test_default_empty_collections(self) -> None:
        plan = RollbackPlan(
            original_audit_id="evt-abc123",
            original_action="scale-deployment",
            original_target="dev/test-app",
            original_caller="agent-01",
            rollback_action="scale-deployment",
            rollback_target="dev/test-app",
            rollback_caller="agent-01",
            generated_at=NOW,
        )
        assert plan.original_params == {}
        assert plan.rollback_params == {}
        assert plan.before_state == {}
        assert plan.warnings == []


# ============================================================
# ActionDefinition.rollback_params tests
# ============================================================


class TestActionDefinitionRollbackParams:
    """Test rollback_params field on ActionDefinition."""

    def test_default_empty(self) -> None:
        action = ActionDefinition(
            name="test-action",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
        )
        assert action.rollback_params == {}

    def test_with_rollback_params(self) -> None:
        from agent_safe.models import RollbackParamSource

        action = ActionDefinition(
            name="test-action",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="test-action",
            rollback_params={
                "namespace": RollbackParamSource(source="params.namespace"),
                "replicas": RollbackParamSource(
                    source="before_state.replicas",
                ),
            },
        )
        assert len(action.rollback_params) == 2
        assert action.rollback_params["replicas"].source == (
            "before_state.replicas"
        )

    def test_yaml_loading_has_rollback_params(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        action = registry.get("scale-deployment")
        assert action is not None
        assert len(action.rollback_params) > 0
        assert "replicas" in action.rollback_params
        assert action.rollback_params["replicas"].source == (
            "before_state.replicas"
        )

    def test_yaml_loading_backward_compat(self) -> None:
        """Actions without rollback_params still load fine."""
        registry = load_registry(ACTIONS_DIR)
        action = registry.get("restart-deployment")
        assert action is not None
        assert action.rollback_params == {}

    def test_yaml_loading_cordon_node(self) -> None:
        registry = load_registry(ACTIONS_DIR)
        action = registry.get("cordon-node")
        assert action is not None
        assert "node" in action.rollback_params
        assert action.rollback_params["node"].source == "params.node"


# ============================================================
# _resolve_source tests
# ============================================================


class TestResolveSource:
    """Test the _resolve_source helper."""

    def test_params_found(self) -> None:
        value, warning = _resolve_source(
            "params.namespace", {"namespace": "dev"}, {},
        )
        assert value == "dev"
        assert warning is None

    def test_before_state_found(self) -> None:
        value, warning = _resolve_source(
            "before_state.replicas", {}, {"replicas": 3},
        )
        assert value == 3
        assert warning is None

    def test_params_missing(self) -> None:
        value, warning = _resolve_source(
            "params.missing", {"namespace": "dev"}, {},
        )
        assert value is None
        assert warning is not None
        assert "not found" in warning

    def test_before_state_missing(self) -> None:
        value, warning = _resolve_source(
            "before_state.missing", {}, {"replicas": 3},
        )
        assert value is None
        assert warning is not None
        assert "not found" in warning

    def test_invalid_path_no_dot(self) -> None:
        value, warning = _resolve_source("invalid", {}, {})
        assert value is None
        assert "Invalid source path" in warning

    def test_unknown_namespace(self) -> None:
        value, warning = _resolve_source("unknown.field", {}, {})
        assert value is None
        assert "Unknown source namespace" in warning

    def test_params_with_complex_value(self) -> None:
        value, warning = _resolve_source(
            "params.data",
            {"data": {"key": "val"}},
            {},
        )
        assert value == {"key": "val"}
        assert warning is None

    def test_before_state_with_zero(self) -> None:
        value, warning = _resolve_source(
            "before_state.replicas", {}, {"replicas": 0},
        )
        assert value == 0
        assert warning is None

    def test_before_state_with_none_value(self) -> None:
        value, warning = _resolve_source(
            "before_state.field", {}, {"field": None},
        )
        assert value is None
        assert warning is None

    def test_params_with_empty_string(self) -> None:
        value, warning = _resolve_source(
            "params.ns", {"ns": ""}, {},
        )
        assert value == ""
        assert warning is None


# ============================================================
# RollbackPlanner — self-reversible actions
# ============================================================


class TestRollbackPlannerSelfReversible:
    """Test RollbackPlanner with self-reversible actions."""

    def setup_method(self) -> None:
        self.registry = load_registry(ACTIONS_DIR)
        self.planner = RollbackPlanner(self.registry)

    def test_scale_deployment_happy_path(self) -> None:
        event = _make_audit_event()
        capture = _make_state_capture()
        plan = self.planner.generate(capture, event)

        assert plan.rollback_action == "scale-deployment"
        assert plan.rollback_params["replicas"] == 2
        assert plan.rollback_params["namespace"] == "dev"
        assert plan.rollback_params["deployment"] == "api"
        assert plan.original_audit_id == "evt-abc123"

    def test_scale_deployment_before_state_used(self) -> None:
        event = _make_audit_event()
        capture = _make_state_capture(before_state={"replicas": 10})
        plan = self.planner.generate(capture, event)
        assert plan.rollback_params["replicas"] == 10

    def test_scale_deployment_target_preserved(self) -> None:
        event = _make_audit_event(target="prod/web-app")
        capture = _make_state_capture()
        plan = self.planner.generate(capture, event)
        assert plan.rollback_target == "prod/web-app"

    def test_scale_deployment_caller_preserved(self) -> None:
        event = _make_audit_event(caller="deploy-bot")
        capture = _make_state_capture()
        plan = self.planner.generate(capture, event)
        assert plan.rollback_caller == "deploy-bot"

    def test_scale_deployment_missing_state_field(self) -> None:
        """Missing before_state.replicas produces a warning."""
        event = _make_audit_event()
        capture = _make_state_capture(before_state={})
        plan = self.planner.generate(capture, event)
        assert "replicas" not in plan.rollback_params
        assert any("not found" in w for w in plan.warnings)

    def test_scale_hpa_happy_path(self) -> None:
        event = _make_audit_event(
            action="scale-hpa",
            params={
                "namespace": "dev", "hpa": "web-hpa",
                "min_replicas": 5, "max_replicas": 20,
            },
        )
        capture = _make_state_capture(
            action="scale-hpa",
            before_state={"min_replicas": 2, "max_replicas": 10},
        )
        plan = self.planner.generate(capture, event)
        assert plan.rollback_action == "scale-hpa"
        assert plan.rollback_params["min_replicas"] == 2
        assert plan.rollback_params["max_replicas"] == 10

    def test_update_configmap_happy_path(self) -> None:
        event = _make_audit_event(
            action="update-configmap",
            params={
                "namespace": "dev", "configmap": "app-config",
                "key": "log_level", "value": "debug",
            },
        )
        capture = _make_state_capture(
            action="update-configmap",
            before_state={"previous_value": "info"},
        )
        plan = self.planner.generate(capture, event)
        assert plan.rollback_action == "update-configmap"
        assert plan.rollback_params["value"] == "info"
        assert plan.rollback_params["key"] == "log_level"

    def test_update_hpa_limits_happy_path(self) -> None:
        event = _make_audit_event(
            action="update-hpa-limits",
            params={
                "namespace": "dev", "hpa": "web-hpa",
                "target_cpu_percent": 80,
            },
        )
        capture = _make_state_capture(
            action="update-hpa-limits",
            before_state={
                "target_cpu_percent": 70,
                "target_memory_percent": 85,
            },
        )
        plan = self.planner.generate(capture, event)
        assert plan.rollback_action == "update-hpa-limits"
        assert plan.rollback_params["target_cpu_percent"] == 70
        assert plan.rollback_params["target_memory_percent"] == 85

    def test_original_params_in_plan(self) -> None:
        event = _make_audit_event()
        capture = _make_state_capture()
        plan = self.planner.generate(capture, event)
        assert plan.original_params["replicas"] == 5
        assert plan.original_params["namespace"] == "dev"

    def test_before_state_in_plan(self) -> None:
        event = _make_audit_event()
        capture = _make_state_capture(before_state={"replicas": 3})
        plan = self.planner.generate(capture, event)
        assert plan.before_state["replicas"] == 3


# ============================================================
# RollbackPlanner — paired rollback actions
# ============================================================


class TestRollbackPlannerPairedRollback:
    """Test RollbackPlanner with paired rollback actions."""

    def setup_method(self) -> None:
        self.registry = load_registry(ACTIONS_DIR)
        self.planner = RollbackPlanner(self.registry)

    def test_cordon_to_uncordon(self) -> None:
        event = _make_audit_event(
            action="cordon-node",
            params={"node": "worker-01"},
        )
        capture = _make_state_capture(
            action="cordon-node",
            before_state={"schedulable": True},
        )
        plan = self.planner.generate(capture, event)
        assert plan.rollback_action == "uncordon-node"
        assert plan.rollback_params["node"] == "worker-01"

    def test_update_image_to_rollout_undo(self) -> None:
        event = _make_audit_event(
            action="update-image",
            params={
                "namespace": "prod", "deployment": "web",
                "container": "app", "image": "nginx:1.25",
            },
        )
        capture = _make_state_capture(
            action="update-image",
            before_state={"current_image": "nginx:1.24"},
        )
        plan = self.planner.generate(capture, event)
        assert plan.rollback_action == "rollout-undo"
        assert plan.rollback_params["namespace"] == "prod"
        assert plan.rollback_params["deployment"] == "web"

    def test_create_namespace_to_delete(self) -> None:
        event = _make_audit_event(
            action="create-namespace",
            params={"namespace": "staging"},
        )
        capture = _make_state_capture(
            action="create-namespace",
            before_state={},
        )
        plan = self.planner.generate(capture, event)
        assert plan.rollback_action == "delete-namespace"
        assert plan.rollback_params["namespace"] == "staging"

    def test_paired_rollback_preserves_target(self) -> None:
        event = _make_audit_event(
            action="cordon-node",
            target="cluster/worker-01",
            params={"node": "worker-01"},
        )
        capture = _make_state_capture(
            action="cordon-node",
            before_state={"schedulable": True},
        )
        plan = self.planner.generate(capture, event)
        assert plan.rollback_target == "cluster/worker-01"

    def test_paired_rollback_different_action_name(self) -> None:
        event = _make_audit_event(
            action="cordon-node",
            params={"node": "node-1"},
        )
        capture = _make_state_capture(
            action="cordon-node",
            before_state={"schedulable": True},
        )
        plan = self.planner.generate(capture, event)
        assert plan.original_action == "cordon-node"
        assert plan.rollback_action == "uncordon-node"
        assert plan.rollback_action != plan.original_action

    def test_update_image_no_revision(self) -> None:
        """rollout-undo doesn't get revision — defaults to previous."""
        event = _make_audit_event(
            action="update-image",
            params={
                "namespace": "dev", "deployment": "api",
                "container": "main", "image": "app:v2",
            },
        )
        capture = _make_state_capture(
            action="update-image",
            before_state={"current_image": "app:v1"},
        )
        plan = self.planner.generate(capture, event)
        assert "revision" not in plan.rollback_params

    def test_cordon_node_only_node_param(self) -> None:
        """uncordon-node only needs the node param."""
        event = _make_audit_event(
            action="cordon-node",
            params={"node": "worker-05"},
        )
        capture = _make_state_capture(
            action="cordon-node",
            before_state={"schedulable": True},
        )
        plan = self.planner.generate(capture, event)
        assert list(plan.rollback_params.keys()) == ["node"]

    def test_create_namespace_only_namespace_param(self) -> None:
        event = _make_audit_event(
            action="create-namespace",
            params={"namespace": "test-ns"},
        )
        capture = _make_state_capture(
            action="create-namespace",
            before_state={},
        )
        plan = self.planner.generate(capture, event)
        assert list(plan.rollback_params.keys()) == ["namespace"]


# ============================================================
# RollbackPlanner — error cases
# ============================================================


class TestRollbackPlannerErrors:
    """Test RollbackPlanner error handling."""

    def setup_method(self) -> None:
        self.registry = load_registry(ACTIONS_DIR)
        self.planner = RollbackPlanner(self.registry)

    def test_unknown_action(self) -> None:
        event = _make_audit_event(action="nonexistent-action")
        capture = _make_state_capture(action="nonexistent-action")
        try:
            self.planner.generate(capture, event)
            raise AssertionError("Should have raised RollbackError")
        except RollbackError as e:
            assert "not found in registry" in str(e)

    def test_not_reversible(self) -> None:
        event = _make_audit_event(
            action="restart-deployment",
            params={"namespace": "dev", "deployment": "api"},
        )
        capture = _make_state_capture(action="restart-deployment")
        try:
            self.planner.generate(capture, event)
            raise AssertionError("Should have raised RollbackError")
        except RollbackError as e:
            assert "not reversible" in str(e)

    def test_delete_pod_not_reversible(self) -> None:
        event = _make_audit_event(
            action="delete-pod",
            params={"namespace": "dev", "pod": "web-abc123"},
        )
        capture = _make_state_capture(action="delete-pod")
        try:
            self.planner.generate(capture, event)
            raise AssertionError("Should have raised RollbackError")
        except RollbackError as e:
            assert "not reversible" in str(e)

    def test_drain_node_not_reversible(self) -> None:
        event = _make_audit_event(
            action="drain-node",
            params={"node": "worker-01"},
        )
        capture = _make_state_capture(action="drain-node")
        try:
            self.planner.generate(capture, event)
            raise AssertionError("Should have raised RollbackError")
        except RollbackError as e:
            assert "not reversible" in str(e)

    def test_no_rollback_action(self) -> None:
        """Action with reversible=True but no rollback_action."""
        action_def = ActionDefinition(
            name="custom-action",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action=None,
        )
        registry = _make_registry(action_def)
        planner = RollbackPlanner(registry)
        event = _make_audit_event(action="custom-action")
        capture = _make_state_capture(action="custom-action")
        try:
            planner.generate(capture, event)
            raise AssertionError("Should have raised RollbackError")
        except RollbackError as e:
            assert "no rollback_action" in str(e)

    def test_rollback_action_not_in_registry(self) -> None:
        """rollback_action points to action not in registry."""
        action_def = ActionDefinition(
            name="custom-action",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="nonexistent-rollback",
        )
        registry = _make_registry(action_def)
        planner = RollbackPlanner(registry)
        event = _make_audit_event(action="custom-action")
        capture = _make_state_capture(action="custom-action")
        try:
            planner.generate(capture, event)
            raise AssertionError("Should have raised RollbackError")
        except RollbackError as e:
            assert "not found in registry" in str(e)

    def test_error_is_exception(self) -> None:
        assert issubclass(RollbackError, Exception)

    def test_error_message_includes_action_name(self) -> None:
        event = _make_audit_event(action="restart-deployment",
                                  params={"namespace": "x",
                                          "deployment": "y"})
        capture = _make_state_capture(action="restart-deployment")
        try:
            self.planner.generate(capture, event)
            raise AssertionError("Should have raised")
        except RollbackError as e:
            assert "restart-deployment" in str(e)


# ============================================================
# RollbackPlanner — convention-based fallback
# ============================================================


class TestRollbackPlannerConvention:
    """Test convention-based param mapping when rollback_params is empty."""

    def test_self_reversible_convention(self) -> None:
        """Self-reversible copies params, overrides from before_state."""
        action_def = ActionDefinition(
            name="my-scale",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="my-scale",
            parameters=[
                {"name": "ns", "type": "string", "required": True,
                 "description": "namespace"},
                {"name": "replicas", "type": "integer", "required": True,
                 "description": "count"},
            ],
        )
        registry = _make_registry(action_def)
        planner = RollbackPlanner(registry)

        event = _make_audit_event(
            action="my-scale",
            params={"ns": "dev", "replicas": 5},
        )
        capture = _make_state_capture(
            action="my-scale",
            before_state={"replicas": 2},
        )
        plan = planner.generate(capture, event)
        assert plan.rollback_params["ns"] == "dev"
        assert plan.rollback_params["replicas"] == 2

    def test_paired_convention(self) -> None:
        """Paired rollback copies matching param names."""
        action_a = ActionDefinition(
            name="action-a",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="action-b",
            parameters=[
                {"name": "node", "type": "string", "required": True,
                 "description": "node"},
                {"name": "extra", "type": "string", "required": False,
                 "description": "extra"},
            ],
        )
        action_b = ActionDefinition(
            name="action-b",
            version="1.0.0",
            description="Rollback",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            parameters=[
                {"name": "node", "type": "string", "required": True,
                 "description": "node"},
            ],
        )
        registry = _make_registry(action_a, action_b)
        planner = RollbackPlanner(registry)

        event = _make_audit_event(
            action="action-a",
            params={"node": "w1", "extra": "val"},
        )
        capture = _make_state_capture(action="action-a")
        plan = planner.generate(capture, event)
        assert plan.rollback_params == {"node": "w1"}

    def test_convention_adds_warning(self) -> None:
        """Convention mode always adds a warning."""
        action_def = ActionDefinition(
            name="simple",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="simple",
        )
        registry = _make_registry(action_def)
        planner = RollbackPlanner(registry)

        event = _make_audit_event(action="simple", params={})
        capture = _make_state_capture(action="simple", before_state={})
        plan = planner.generate(capture, event)
        assert any("convention" in w.lower() for w in plan.warnings)

    def test_convention_self_reversible_no_override_without_match(
        self,
    ) -> None:
        """Only override params that exist in before_state."""
        action_def = ActionDefinition(
            name="my-action",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="my-action",
        )
        registry = _make_registry(action_def)
        planner = RollbackPlanner(registry)

        event = _make_audit_event(
            action="my-action",
            params={"ns": "dev", "count": 5},
        )
        capture = _make_state_capture(
            action="my-action",
            before_state={"other_key": "val"},
        )
        plan = planner.generate(capture, event)
        assert plan.rollback_params["ns"] == "dev"
        assert plan.rollback_params["count"] == 5

    def test_convention_paired_no_match(self) -> None:
        """Paired with no matching params produces empty rollback_params."""
        action_a = ActionDefinition(
            name="action-x",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="action-y",
            parameters=[
                {"name": "foo", "type": "string", "required": True,
                 "description": "foo"},
            ],
        )
        action_b = ActionDefinition(
            name="action-y",
            version="1.0.0",
            description="Rollback",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            parameters=[
                {"name": "bar", "type": "string", "required": True,
                 "description": "bar"},
            ],
        )
        registry = _make_registry(action_a, action_b)
        planner = RollbackPlanner(registry)

        event = _make_audit_event(
            action="action-x", params={"foo": "val"},
        )
        capture = _make_state_capture(action="action-x")
        plan = planner.generate(capture, event)
        assert plan.rollback_params == {}

    def test_convention_self_reversible_overrides_all_matching(self) -> None:
        """All matching before_state keys override original params."""
        action_def = ActionDefinition(
            name="multi",
            version="1.0.0",
            description="Test",
            risk_class=RiskClass.LOW,
            target_types=["test"],
            reversible=True,
            rollback_action="multi",
        )
        registry = _make_registry(action_def)
        planner = RollbackPlanner(registry)

        event = _make_audit_event(
            action="multi",
            params={"a": 1, "b": 2, "c": 3},
        )
        capture = _make_state_capture(
            action="multi",
            before_state={"a": 10, "b": 20},
        )
        plan = planner.generate(capture, event)
        assert plan.rollback_params["a"] == 10
        assert plan.rollback_params["b"] == 20
        assert plan.rollback_params["c"] == 3


# ============================================================
# RollbackPlanner — warnings
# ============================================================


class TestRollbackPlannerWarnings:
    """Test warning generation in rollback plans."""

    def setup_method(self) -> None:
        self.registry = load_registry(ACTIONS_DIR)
        self.planner = RollbackPlanner(self.registry)

    def test_missing_before_state_field_warns(self) -> None:
        event = _make_audit_event()
        capture = _make_state_capture(before_state={})
        plan = self.planner.generate(capture, event)
        assert len(plan.warnings) > 0

    def test_partial_before_state_warns(self) -> None:
        """Some fields present, some missing."""
        event = _make_audit_event(
            action="scale-hpa",
            params={
                "namespace": "dev", "hpa": "web",
                "min_replicas": 5, "max_replicas": 20,
            },
        )
        capture = _make_state_capture(
            action="scale-hpa",
            before_state={"min_replicas": 2},
        )
        plan = self.planner.generate(capture, event)
        assert "min_replicas" in plan.rollback_params
        assert "max_replicas" not in plan.rollback_params
        assert any("max_replicas" in w for w in plan.warnings)

    def test_no_warnings_when_all_resolved(self) -> None:
        event = _make_audit_event()
        capture = _make_state_capture(before_state={"replicas": 2})
        plan = self.planner.generate(capture, event)
        assert len(plan.warnings) == 0

    def test_multiple_missing_fields_multiple_warnings(self) -> None:
        event = _make_audit_event(
            action="scale-hpa",
            params={
                "namespace": "dev", "hpa": "web",
                "min_replicas": 5, "max_replicas": 20,
            },
        )
        capture = _make_state_capture(
            action="scale-hpa",
            before_state={},
        )
        plan = self.planner.generate(capture, event)
        state_warnings = [
            w for w in plan.warnings if "not found" in w
        ]
        assert len(state_warnings) == 2

    def test_generated_at_is_set(self) -> None:
        event = _make_audit_event()
        capture = _make_state_capture()
        plan = self.planner.generate(capture, event)
        assert plan.generated_at is not None


# ============================================================
# SDK generate_rollback()
# ============================================================


class TestGenerateRollbackSDK:
    """Test AgentSafe.generate_rollback()."""

    def _make_safe(self, audit_log_path: str) -> AgentSafe:
        return AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=audit_log_path,
        )

    def test_happy_path(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2},
            after={"replicas": 5},
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        plan = safe.generate_rollback(decision.audit_id)
        assert plan.rollback_action == "scale-deployment"
        assert plan.rollback_params["replicas"] == 2

    def test_no_audit_configured(self) -> None:
        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
        )
        try:
            safe.generate_rollback("evt-nonexistent")
            raise AssertionError("Should have raised")
        except AgentSafeError as e:
            assert "not configured" in str(e)

    def test_no_decision_found(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        try:
            safe.generate_rollback("evt-nonexistent")
            raise AssertionError("Should have raised")
        except AgentSafeError as e:
            assert "No decision event" in str(e)

    def test_no_state_capture(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        try:
            safe.generate_rollback(decision.audit_id)
            raise AssertionError("Should have raised")
        except AgentSafeError as e:
            assert "No state capture" in str(e)

    def test_not_reversible_action(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        decision = safe.check(
            "restart-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "api"},
        )
        safe.record_state(
            decision.audit_id,
            before={"generation": 1},
            after={"generation": 2},
            action="restart-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        try:
            safe.generate_rollback(decision.audit_id)
            raise AssertionError("Should have raised")
        except AgentSafeError as e:
            assert "not reversible" in str(e)

    def test_returns_rollback_plan_type(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2},
            after={"replicas": 5},
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        plan = safe.generate_rollback(decision.audit_id)
        assert isinstance(plan, RollbackPlan)

    def test_plan_has_original_params(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2},
            after={"replicas": 5},
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        plan = safe.generate_rollback(decision.audit_id)
        assert plan.original_params["replicas"] == 5

    def test_plan_has_before_state(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2},
            after={"replicas": 5},
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        plan = safe.generate_rollback(decision.audit_id)
        assert plan.before_state["replicas"] == 2


# ============================================================
# SDK check_rollback()
# ============================================================


class TestCheckRollbackSDK:
    """Test AgentSafe.check_rollback()."""

    def _make_safe(self, audit_log_path: str) -> AgentSafe:
        return AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=audit_log_path,
        )

    def _setup_decision_and_state(
        self, safe: AgentSafe,
    ) -> str:
        """Create a decision + state capture, return audit_id."""
        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2},
            after={"replicas": 5},
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        return decision.audit_id

    def test_happy_path_allow(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        decision = safe.check_rollback(audit_id)
        assert decision.action == "scale-deployment"

    def test_rollback_decision_has_action(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        decision = safe.check_rollback(audit_id)
        assert decision.action == "scale-deployment"
        assert decision.audit_id != audit_id

    def test_custom_caller(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        decision = safe.check_rollback(audit_id, caller="rollback-bot")
        assert decision.caller == "rollback-bot"

    def test_default_caller_from_original(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        decision = safe.check_rollback(audit_id)
        assert decision.caller == "agent-01"

    def test_rollback_creates_audit_event(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        safe.check_rollback(audit_id)

        # Verify a new decision event was logged
        events = safe.audit.read_events()
        decision_events = [
            e for e in events if e.event_type == "decision"
        ]
        assert len(decision_events) >= 2

    def test_rollback_returns_decision_type(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        from agent_safe.models import Decision

        decision = safe.check_rollback(audit_id)
        assert isinstance(decision, Decision)

    def test_rollback_has_risk_class(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        decision = safe.check_rollback(audit_id)
        assert decision.risk_class is not None

    def test_rollback_target_matches_original(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)
        audit_id = self._setup_decision_and_state(safe)
        decision = safe.check_rollback(audit_id)
        assert decision.target == "dev/test-app"


# ============================================================
# End-to-end rollback flow
# ============================================================


class TestRollbackEndToEnd:
    """Full check → record_state → generate_rollback → check_rollback."""

    def _make_safe(self, audit_log_path: str) -> AgentSafe:
        return AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=audit_log_path,
        )

    def test_full_scale_deployment_flow(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)

        # 1. Original action
        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        assert decision.result == DecisionResult.ALLOW

        # 2. Record state
        capture = safe.record_state(
            decision.audit_id,
            before={"replicas": 2},
            after={"replicas": 5},
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        assert capture.diff["changed"]["replicas"]["old"] == 2

        # 3. Generate rollback plan
        plan = safe.generate_rollback(decision.audit_id)
        assert plan.rollback_action == "scale-deployment"
        assert plan.rollback_params["replicas"] == 2

        # 4. Check rollback through PDP
        rb_decision = safe.check_rollback(decision.audit_id)
        assert rb_decision.action == "scale-deployment"

    def test_paired_rollback_flow(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)

        decision = safe.check(
            "cordon-node",
            target="dev/worker-01",
            caller="ops-agent",
            params={"node": "worker-01"},
        )

        safe.record_state(
            decision.audit_id,
            before={"schedulable": True},
            after={"schedulable": False},
            action="cordon-node",
            target="dev/worker-01",
            caller="ops-agent",
        )

        plan = safe.generate_rollback(decision.audit_id)
        assert plan.rollback_action == "uncordon-node"
        assert plan.rollback_params["node"] == "worker-01"

    def test_audit_chain_valid_after_rollback(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)

        decision = safe.check(
            "scale-deployment",
            target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2},
            after={"replicas": 5},
            action="scale-deployment",
            target="dev/test-app",
            caller="agent-01",
        )
        safe.check_rollback(decision.audit_id)

        # Verify audit chain is intact
        ok, errors = safe.verify_audit()
        assert ok is True
        assert errors == []

    def test_multiple_rollbacks_same_action(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)

        # First action
        d1 = safe.check(
            "scale-deployment", target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            d1.audit_id,
            before={"replicas": 2}, after={"replicas": 5},
            action="scale-deployment", target="dev/test-app",
            caller="agent-01",
        )

        # Second action
        d2 = safe.check(
            "scale-deployment", target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 10,
            },
        )
        safe.record_state(
            d2.audit_id,
            before={"replicas": 5}, after={"replicas": 10},
            action="scale-deployment", target="dev/test-app",
            caller="agent-01",
        )

        # Rollback second action → replicas=5
        plan2 = safe.generate_rollback(d2.audit_id)
        assert plan2.rollback_params["replicas"] == 5

        # Rollback first action → replicas=2
        plan1 = safe.generate_rollback(d1.audit_id)
        assert plan1.rollback_params["replicas"] == 2

    def test_generate_and_check_different_audit_ids(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)

        decision = safe.check(
            "scale-deployment", target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2}, after={"replicas": 5},
            action="scale-deployment", target="dev/test-app",
            caller="agent-01",
        )

        safe.generate_rollback(decision.audit_id)
        rb_decision = safe.check_rollback(decision.audit_id)

        # Original and rollback have different audit IDs
        assert decision.audit_id != rb_decision.audit_id

    def test_rollback_plan_before_state_matches_capture(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as f:
            audit_path = f.name

        safe = self._make_safe(audit_path)

        decision = safe.check(
            "scale-deployment", target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2, "available_replicas": 2},
            after={"replicas": 5, "available_replicas": 3},
            action="scale-deployment", target="dev/test-app",
            caller="agent-01",
        )

        plan = safe.generate_rollback(decision.audit_id)
        assert plan.before_state["replicas"] == 2
        assert plan.before_state["available_replicas"] == 2


# ============================================================
# CLI rollback show
# ============================================================


class TestRollbackCLIShow:
    """Test the rollback show CLI command."""

    def _setup_audit(self) -> tuple[str, str]:
        """Create an audit log with a decision + state capture."""
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as tmp:
            audit_path = tmp.name

        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=audit_path,
        )
        decision = safe.check(
            "scale-deployment", target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2}, after={"replicas": 5},
            action="scale-deployment", target="dev/test-app",
            caller="agent-01",
        )
        return audit_path, decision.audit_id

    def test_show_happy_path(self) -> None:
        audit_path, audit_id = self._setup_audit()
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "show", audit_id,
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", audit_path,
        ])
        assert result.exit_code == 0
        assert "Rollback Plan" in result.output
        assert "scale-deployment" in result.output

    def test_show_json(self) -> None:
        audit_path, audit_id = self._setup_audit()
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "show", audit_id,
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", audit_path,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["rollback_action"] == "scale-deployment"
        assert data["rollback_params"]["replicas"] == 2

    def test_show_not_found(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as tmp:
            tmp_path = tmp.name
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "show", "evt-nonexistent",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", tmp_path,
        ])
        assert result.exit_code != 0
        assert "ERROR" in result.output

    def test_show_not_reversible(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as tmp:
            tmp_path = tmp.name

        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path,
        )
        decision = safe.check(
            "restart-deployment", target="dev/test-app",
            caller="agent-01",
            params={"namespace": "dev", "deployment": "api"},
        )
        safe.record_state(
            decision.audit_id,
            before={"generation": 1}, after={"generation": 2},
            action="restart-deployment", target="dev/test-app",
            caller="agent-01",
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "show", decision.audit_id,
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", tmp_path,
        ])
        assert result.exit_code != 0
        assert "not reversible" in result.output

    def test_show_displays_warnings(self) -> None:
        """When before_state is missing a field, warnings appear."""
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as tmp:
            tmp_path = tmp.name

        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=tmp_path,
        )
        decision = safe.check(
            "scale-deployment", target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        # Record state without required 'replicas' field
        safe.record_state(
            decision.audit_id,
            before={}, after={"replicas": 5},
            action="scale-deployment", target="dev/test-app",
            caller="agent-01",
        )

        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "show", decision.audit_id,
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", tmp_path,
        ])
        assert result.exit_code == 0
        assert "warning:" in result.output


# ============================================================
# CLI rollback check
# ============================================================


class TestRollbackCLICheck:
    """Test the rollback check CLI command."""

    def _setup_audit(self) -> tuple[str, str]:
        """Create an audit log with a decision + state capture."""
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as tmp:
            audit_path = tmp.name

        safe = AgentSafe(
            registry=ACTIONS_DIR,
            policies=POLICIES_DIR,
            inventory=INVENTORY_FILE,
            audit_log=audit_path,
        )
        decision = safe.check(
            "scale-deployment", target="dev/test-app",
            caller="agent-01",
            params={
                "namespace": "dev", "deployment": "api", "replicas": 5,
            },
        )
        safe.record_state(
            decision.audit_id,
            before={"replicas": 2}, after={"replicas": 5},
            action="scale-deployment", target="dev/test-app",
            caller="agent-01",
        )
        return audit_path, decision.audit_id

    def test_check_happy_path(self) -> None:
        audit_path, audit_id = self._setup_audit()
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "check", audit_id,
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", audit_path,
        ])
        assert result.exit_code == 0
        assert "scale-deployment" in result.output

    def test_check_json(self) -> None:
        audit_path, audit_id = self._setup_audit()
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "check", audit_id,
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", audit_path,
            "--json-output",
        ])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "plan" in data
        assert "decision" in data
        assert data["plan"]["rollback_action"] == "scale-deployment"

    def test_check_not_found(self) -> None:
        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", delete=False,
        ) as tmp:
            tmp_path = tmp.name
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "check", "evt-nonexistent",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", tmp_path,
        ])
        assert result.exit_code != 0

    def test_check_with_caller_override(self) -> None:
        audit_path, audit_id = self._setup_audit()
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "check", audit_id,
            "--caller", "rollback-bot",
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", audit_path,
        ])
        assert result.exit_code == 0

    def test_check_shows_decision_result(self) -> None:
        audit_path, audit_id = self._setup_audit()
        runner = CliRunner()
        result = runner.invoke(cli, [
            "rollback", "check", audit_id,
            "--registry", ACTIONS_DIR,
            "--policies", POLICIES_DIR,
            "--inventory", INVENTORY_FILE,
            "--audit-log", audit_path,
        ])
        assert result.exit_code == 0
        assert "action:" in result.output
        assert "risk:" in result.output
        assert "audit:" in result.output
