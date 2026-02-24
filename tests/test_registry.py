"""Tests for the Action Registry."""

from pathlib import Path

import pytest
import yaml

from agent_safe.models import ActionDefinition, RiskClass
from agent_safe.registry.loader import (
    ActionRegistry,
    RegistryError,
    load_action_file,
    load_registry,
)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# --- Fixtures ---


@pytest.fixture()
def empty_registry() -> ActionRegistry:
    return ActionRegistry()


@pytest.fixture()
def sample_action() -> ActionDefinition:
    return ActionDefinition(
        name="restart-deployment",
        version="1.0.0",
        description="Restart a deployment",
        parameters=[
            {"name": "namespace", "type": "string", "required": True},
            {"name": "deployment", "type": "string", "required": True},
        ],
        risk_class=RiskClass.MEDIUM,
        target_types=["k8s-deployment"],
        tags=["kubernetes", "restart"],
    )


@pytest.fixture()
def scale_action() -> ActionDefinition:
    return ActionDefinition(
        name="scale-deployment",
        version="1.0.0",
        description="Scale a deployment",
        parameters=[
            {"name": "namespace", "type": "string", "required": True, "description": "NS"},
            {"name": "deployment", "type": "string", "required": True, "description": "Deploy"},
            {
                "name": "replicas",
                "type": "integer",
                "required": True,
                "description": "Count",
                "constraints": {"min_value": 0, "max_value": 100},
            },
        ],
        risk_class=RiskClass.MEDIUM,
        target_types=["k8s-deployment"],
        tags=["kubernetes", "scaling"],
    )


# --- ActionRegistry Unit Tests ---


class TestActionRegistry:
    def test_register_and_get(
        self, empty_registry: ActionRegistry, sample_action: ActionDefinition
    ):
        empty_registry.register(sample_action, file_hash="abc123")
        assert len(empty_registry) == 1
        assert empty_registry.get("restart-deployment") is not None
        assert empty_registry.get("restart-deployment").version == "1.0.0"

    def test_get_missing_returns_none(self, empty_registry: ActionRegistry):
        assert empty_registry.get("nonexistent") is None

    def test_get_or_raise_missing(self, empty_registry: ActionRegistry):
        with pytest.raises(RegistryError, match="Action not found"):
            empty_registry.get_or_raise("nonexistent")

    def test_duplicate_name_rejected(
        self, empty_registry: ActionRegistry, sample_action: ActionDefinition
    ):
        empty_registry.register(sample_action)
        with pytest.raises(RegistryError, match="Duplicate action name"):
            empty_registry.register(sample_action)

    def test_list_actions_sorted(
        self,
        empty_registry: ActionRegistry,
        sample_action: ActionDefinition,
        scale_action: ActionDefinition,
    ):
        empty_registry.register(scale_action)
        empty_registry.register(sample_action)
        assert empty_registry.list_actions() == ["restart-deployment", "scale-deployment"]

    def test_list_by_tag(
        self,
        empty_registry: ActionRegistry,
        sample_action: ActionDefinition,
        scale_action: ActionDefinition,
    ):
        empty_registry.register(sample_action)
        empty_registry.register(scale_action)
        k8s_actions = empty_registry.list_by_tag("kubernetes")
        assert len(k8s_actions) == 2
        scaling = empty_registry.list_by_tag("scaling")
        assert len(scaling) == 1
        assert scaling[0].name == "scale-deployment"

    def test_list_by_tag_no_match(
        self, empty_registry: ActionRegistry, sample_action: ActionDefinition
    ):
        empty_registry.register(sample_action)
        assert empty_registry.list_by_tag("nonexistent") == []

    def test_list_by_risk(self, empty_registry: ActionRegistry, sample_action: ActionDefinition):
        empty_registry.register(sample_action)
        assert len(empty_registry.list_by_risk("medium")) == 1
        assert len(empty_registry.list_by_risk("critical")) == 0

    def test_versioned_name(self, empty_registry: ActionRegistry, sample_action: ActionDefinition):
        empty_registry.register(sample_action)
        assert empty_registry.versioned_name("restart-deployment") == "restart-deployment@1.0.0"

    def test_versioned_name_missing(self, empty_registry: ActionRegistry):
        assert empty_registry.versioned_name("nonexistent") is None

    def test_file_hashes(self, empty_registry: ActionRegistry, sample_action: ActionDefinition):
        empty_registry.register(sample_action, file_hash="sha256abc")
        assert empty_registry.file_hashes == {"restart-deployment": "sha256abc"}

    def test_actions_property(
        self,
        empty_registry: ActionRegistry,
        sample_action: ActionDefinition,
        scale_action: ActionDefinition,
    ):
        empty_registry.register(sample_action)
        empty_registry.register(scale_action)
        actions = empty_registry.actions
        assert len(actions) == 2
        names = {a.name for a in actions}
        assert names == {"restart-deployment", "scale-deployment"}


# --- Parameter Validation Tests ---


class TestValidateParams:
    def test_valid_params(self, empty_registry: ActionRegistry, sample_action: ActionDefinition):
        empty_registry.register(sample_action)
        errors = empty_registry.validate_params(
            "restart-deployment",
            {"namespace": "production", "deployment": "api-server"},
        )
        assert errors == []

    def test_missing_required_param(
        self, empty_registry: ActionRegistry, sample_action: ActionDefinition
    ):
        empty_registry.register(sample_action)
        errors = empty_registry.validate_params(
            "restart-deployment",
            {"namespace": "production"},
        )
        assert len(errors) == 1
        assert "Missing required parameter: deployment" in errors[0]

    def test_unknown_param(self, empty_registry: ActionRegistry, sample_action: ActionDefinition):
        empty_registry.register(sample_action)
        errors = empty_registry.validate_params(
            "restart-deployment",
            {"namespace": "prod", "deployment": "api", "extra_field": "bad"},
        )
        assert any("Unknown parameter: extra_field" in e for e in errors)

    def test_wrong_type_string_expected(
        self, empty_registry: ActionRegistry, sample_action: ActionDefinition
    ):
        empty_registry.register(sample_action)
        errors = empty_registry.validate_params(
            "restart-deployment",
            {"namespace": 123, "deployment": "api"},
        )
        assert any("expected string" in e for e in errors)

    def test_wrong_type_integer_expected(
        self, empty_registry: ActionRegistry, scale_action: ActionDefinition
    ):
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": "five"},
        )
        assert any("expected integer" in e for e in errors)

    def test_boolean_not_integer(
        self, empty_registry: ActionRegistry, scale_action: ActionDefinition
    ):
        """Booleans should not be accepted as integers."""
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": True},
        )
        assert any("expected integer" in e for e in errors)

    def test_constraint_min_value(
        self, empty_registry: ActionRegistry, scale_action: ActionDefinition
    ):
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": -1},
        )
        assert any("below minimum" in e for e in errors)

    def test_constraint_max_value(
        self, empty_registry: ActionRegistry, scale_action: ActionDefinition
    ):
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": 200},
        )
        assert any("exceeds maximum" in e for e in errors)

    def test_constraint_within_range(
        self, empty_registry: ActionRegistry, scale_action: ActionDefinition
    ):
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": 50},
        )
        assert errors == []

    def test_constraint_boundary_min(
        self, empty_registry: ActionRegistry, scale_action: ActionDefinition
    ):
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": 0},
        )
        assert errors == []

    def test_constraint_boundary_max(
        self, empty_registry: ActionRegistry, scale_action: ActionDefinition
    ):
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": 100},
        )
        assert errors == []

    def test_unknown_action(self, empty_registry: ActionRegistry):
        errors = empty_registry.validate_params("nonexistent", {"foo": "bar"})
        assert any("Unknown action" in e for e in errors)

    def test_constraint_pattern(self, empty_registry: ActionRegistry):
        action = ActionDefinition(
            name="create-namespace",
            version="1.0.0",
            description="Create a namespace",
            parameters=[
                {
                    "name": "namespace",
                    "type": "string",
                    "required": True,
                    "description": "NS name",
                    "constraints": {"pattern": r"^[a-z][a-z0-9-]{0,62}$"},
                },
            ],
            risk_class=RiskClass.HIGH,
            target_types=["k8s-namespace"],
        )
        empty_registry.register(action)

        assert empty_registry.validate_params("create-namespace", {"namespace": "my-ns"}) == []
        errors = empty_registry.validate_params("create-namespace", {"namespace": "INVALID!"})
        assert any("does not match pattern" in e for e in errors)

    def test_constraint_enum(self, empty_registry: ActionRegistry):
        action = ActionDefinition(
            name="update-strategy",
            version="1.0.0",
            description="Update deployment strategy",
            parameters=[
                {
                    "name": "strategy",
                    "type": "string",
                    "required": True,
                    "description": "Strategy type",
                    "constraints": {"enum": ["RollingUpdate", "Recreate"]},
                },
            ],
            risk_class=RiskClass.MEDIUM,
            target_types=["k8s-deployment"],
        )
        empty_registry.register(action)

        result = empty_registry.validate_params("update-strategy", {"strategy": "RollingUpdate"})
        assert result == []
        errors = empty_registry.validate_params("update-strategy", {"strategy": "BlueGreen"})
        assert any("not in allowed values" in e for e in errors)

    def test_constraint_string_length(self, empty_registry: ActionRegistry):
        action = ActionDefinition(
            name="set-label",
            version="1.0.0",
            description="Set a label",
            parameters=[
                {
                    "name": "value",
                    "type": "string",
                    "required": True,
                    "description": "Label value",
                    "constraints": {"min_length": 1, "max_length": 63},
                },
            ],
            risk_class=RiskClass.LOW,
            target_types=["k8s-deployment"],
        )
        empty_registry.register(action)

        assert empty_registry.validate_params("set-label", {"value": "ok"}) == []
        errors = empty_registry.validate_params("set-label", {"value": ""})
        assert any("below minimum" in e for e in errors)
        errors = empty_registry.validate_params("set-label", {"value": "x" * 100})
        assert any("exceeds maximum" in e for e in errors)

    def test_multiple_errors(self, empty_registry: ActionRegistry, scale_action: ActionDefinition):
        empty_registry.register(scale_action)
        errors = empty_registry.validate_params(
            "scale-deployment",
            {"replicas": "not-a-number", "unknown": True},
        )
        # Missing namespace, missing deployment, wrong type replicas, unknown param
        assert len(errors) >= 3


# --- File Loading Tests ---


class TestLoadActionFile:
    def test_load_valid_file(self, tmp_path: Path):
        content = {
            "name": "test-action",
            "version": "1.0.0",
            "description": "A test action",
            "risk_class": "low",
            "target_types": ["k8s-pod"],
        }
        f = tmp_path / "test-action.yaml"
        f.write_text(yaml.dump(content), encoding="utf-8")

        action, file_hash = load_action_file(f)
        assert action.name == "test-action"
        assert action.risk_class == RiskClass.LOW
        assert len(file_hash) == 64  # SHA-256 hex

    def test_file_not_found(self):
        with pytest.raises(RegistryError, match="not found"):
            load_action_file(Path("/nonexistent/action.yaml"))

    def test_invalid_yaml(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("{{not valid yaml", encoding="utf-8")
        with pytest.raises(RegistryError, match="Invalid YAML"):
            load_action_file(f)

    def test_not_a_mapping(self, tmp_path: Path):
        f = tmp_path / "list.yaml"
        f.write_text(yaml.dump(["a", "b"]), encoding="utf-8")
        with pytest.raises(RegistryError, match="YAML mapping"):
            load_action_file(f)

    def test_invalid_schema(self, tmp_path: Path):
        content = {
            "name": "BadName",
            "version": "1.0.0",
            "risk_class": "low",
            "target_types": ["x"],
        }
        f = tmp_path / "bad-schema.yaml"
        f.write_text(yaml.dump(content), encoding="utf-8")
        with pytest.raises(RegistryError, match="Invalid action definition"):
            load_action_file(f)

    def test_hash_changes_with_content(self, tmp_path: Path):
        content = {
            "name": "hash-test",
            "version": "1.0.0",
            "description": "v1",
            "risk_class": "low",
            "target_types": ["k8s-pod"],
        }
        f = tmp_path / "hash-test.yaml"
        f.write_text(yaml.dump(content), encoding="utf-8")
        _, hash1 = load_action_file(f)

        content["description"] = "v2"
        f.write_text(yaml.dump(content), encoding="utf-8")
        _, hash2 = load_action_file(f)

        assert hash1 != hash2


class TestLoadRegistry:
    def test_load_real_actions_dir(self):
        """Load the actual project actions/ directory."""
        registry = load_registry(str(_PROJECT_ROOT / "actions"))
        assert len(registry) == 33  # 20 K8s + 13 AWS
        assert registry.get("restart-deployment") is not None
        assert registry.get("scale-deployment") is not None
        assert registry.get("delete-pod") is not None
        assert registry.get("cordon-node") is not None
        assert registry.get("get-pod-logs") is not None
        assert registry.get("drain-node") is not None
        assert registry.get("exec-pod") is not None
        assert registry.get("delete-namespace") is not None

    def test_load_real_actions_integrity(self):
        """Verify that all shipped action files produce valid hashes."""
        registry = load_registry(str(_PROJECT_ROOT / "actions"))
        hashes = registry.file_hashes
        assert len(hashes) == 33  # 20 K8s + 13 AWS
        for name, h in hashes.items():
            assert len(h) == 64, f"Bad hash for {name}"

    def test_load_empty_dir(self, tmp_path: Path):
        registry = load_registry(tmp_path)
        assert len(registry) == 0

    def test_dir_not_found(self):
        with pytest.raises(RegistryError, match="not found"):
            load_registry("/nonexistent/dir")

    def test_duplicate_action_across_files(self, tmp_path: Path):
        content = {
            "name": "same-action",
            "version": "1.0.0",
            "description": "First",
            "risk_class": "low",
            "target_types": ["k8s-pod"],
        }
        (tmp_path / "a.yaml").write_text(yaml.dump(content), encoding="utf-8")
        content["description"] = "Second"
        (tmp_path / "b.yaml").write_text(yaml.dump(content), encoding="utf-8")

        with pytest.raises(RegistryError, match="Duplicate action name"):
            load_registry(tmp_path)

    def test_loads_both_yaml_and_yml(self, tmp_path: Path):
        base = {"version": "1.0.0", "description": "Test"}
        a = {**base, "name": "action-a", "risk_class": "low", "target_types": ["x"]}
        b = {**base, "name": "action-b", "risk_class": "high", "target_types": ["y"]}
        (tmp_path / "a.yaml").write_text(yaml.dump(a), encoding="utf-8")
        (tmp_path / "b.yml").write_text(yaml.dump(b), encoding="utf-8")

        registry = load_registry(tmp_path)
        assert len(registry) == 2

    def test_ignores_non_yaml_files(self, tmp_path: Path):
        a = {
            "name": "only-action",
            "version": "1.0.0",
            "description": "A",
            "risk_class": "low",
            "target_types": ["x"],
        }
        (tmp_path / "action.yaml").write_text(yaml.dump(a), encoding="utf-8")
        (tmp_path / "readme.txt").write_text("ignore me", encoding="utf-8")
        (tmp_path / "notes.md").write_text("ignore me too", encoding="utf-8")

        registry = load_registry(tmp_path)
        assert len(registry) == 1

    def test_validate_params_on_loaded_actions(self):
        """End-to-end: load real actions and validate params."""
        registry = load_registry(str(_PROJECT_ROOT / "actions"))

        # Valid restart
        errors = registry.validate_params(
            "restart-deployment",
            {"namespace": "production", "deployment": "api-server"},
        )
        assert errors == []

        # Valid scale
        errors = registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": 3},
        )
        assert errors == []

        # Invalid scale — replicas out of range
        errors = registry.validate_params(
            "scale-deployment",
            {"namespace": "prod", "deployment": "api", "replicas": 999},
        )
        assert any("exceeds maximum" in e for e in errors)

        # Invalid — missing required params
        errors = registry.validate_params("delete-pod", {})
        assert len(errors) >= 2  # namespace and pod are required
