"""Tests for the target inventory loader."""

from pathlib import Path

import pytest
import yaml

from agent_safe.inventory.loader import Inventory, InventoryError, load_inventory
from agent_safe.models import Environment, Sensitivity, TargetDefinition


@pytest.fixture()
def sample_targets() -> list[TargetDefinition]:
    return [
        TargetDefinition(
            id="prod/api-server",
            type="k8s-deployment",
            environment=Environment.PROD,
            sensitivity=Sensitivity.CRITICAL,
            owner="platform-team",
            labels={"app": "api-server"},
        ),
        TargetDefinition(
            id="staging/api-server",
            type="k8s-deployment",
            environment=Environment.STAGING,
            sensitivity=Sensitivity.INTERNAL,
            owner="platform-team",
        ),
        TargetDefinition(
            id="dev/test-app",
            type="k8s-deployment",
            environment=Environment.DEV,
            sensitivity=Sensitivity.PUBLIC,
        ),
        TargetDefinition(
            id="prod/worker-node-01",
            type="k8s-node",
            environment=Environment.PROD,
            sensitivity=Sensitivity.CRITICAL,
            owner="infra-team",
        ),
    ]


class TestInventory:
    def test_create_from_targets(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        assert len(inv) == 4

    def test_get_existing_target(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        target = inv.get("prod/api-server")
        assert target is not None
        assert target.environment == Environment.PROD
        assert target.sensitivity == Sensitivity.CRITICAL

    def test_get_missing_target_returns_none(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        assert inv.get("nonexistent/target") is None

    def test_get_or_raise_existing(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        target = inv.get_or_raise("prod/api-server")
        assert target.id == "prod/api-server"

    def test_get_or_raise_missing(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        with pytest.raises(InventoryError, match="Target not found"):
            inv.get_or_raise("nonexistent/target")

    def test_duplicate_id_rejected(self):
        targets = [
            TargetDefinition(
                id="dup/target",
                type="k8s-deployment",
                environment=Environment.DEV,
                sensitivity=Sensitivity.PUBLIC,
            ),
            TargetDefinition(
                id="dup/target",
                type="k8s-deployment",
                environment=Environment.DEV,
                sensitivity=Sensitivity.PUBLIC,
            ),
        ]
        with pytest.raises(InventoryError, match="Duplicate target ID"):
            Inventory(targets)

    def test_list_by_environment(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        prod = inv.list_by_environment("prod")
        assert len(prod) == 2
        assert all(t.environment == Environment.PROD for t in prod)

    def test_list_by_environment_empty(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        assert inv.list_by_environment("nonexistent") == []

    def test_list_by_type(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        nodes = inv.list_by_type("k8s-node")
        assert len(nodes) == 1
        assert nodes[0].id == "prod/worker-node-01"

    def test_targets_property_returns_copy(self, sample_targets: list[TargetDefinition]):
        inv = Inventory(sample_targets)
        targets = inv.targets
        assert len(targets) == 4
        # Modifying the returned list does not affect the inventory
        targets.clear()
        assert len(inv) == 4

    def test_empty_inventory(self):
        inv = Inventory([])
        assert len(inv) == 0
        assert inv.get("anything") is None


class TestLoadInventory:
    def test_load_valid_file(self, tmp_path: Path):
        content = {
            "targets": [
                {
                    "id": "prod/api",
                    "type": "k8s-deployment",
                    "environment": "prod",
                    "sensitivity": "critical",
                    "owner": "team-a",
                },
                {
                    "id": "dev/app",
                    "type": "k8s-deployment",
                    "environment": "dev",
                    "sensitivity": "public",
                },
            ]
        }
        f = tmp_path / "inventory.yaml"
        f.write_text(yaml.dump(content), encoding="utf-8")

        inv = load_inventory(f)
        assert len(inv) == 2
        assert inv.get("prod/api").sensitivity == Sensitivity.CRITICAL

    def test_load_real_inventory_file(self):
        """Load the actual project inventory.yaml to verify it's valid."""
        inv = load_inventory(Path("e:/Docs/Projects/agent-safe/inventory.yaml"))
        assert len(inv) == 12
        assert inv.get("prod/api-server") is not None
        assert inv.get("dev/debug-pod") is not None

    def test_file_not_found(self):
        with pytest.raises(InventoryError, match="not found"):
            load_inventory("/nonexistent/path.yaml")

    def test_invalid_yaml(self, tmp_path: Path):
        f = tmp_path / "bad.yaml"
        f.write_text("{{invalid yaml: [", encoding="utf-8")
        with pytest.raises(InventoryError, match="Invalid YAML"):
            load_inventory(f)

    def test_missing_targets_key(self, tmp_path: Path):
        f = tmp_path / "no_targets.yaml"
        f.write_text(yaml.dump({"stuff": []}), encoding="utf-8")
        with pytest.raises(InventoryError, match="top-level 'targets' key"):
            load_inventory(f)

    def test_targets_not_a_list(self, tmp_path: Path):
        f = tmp_path / "bad_targets.yaml"
        f.write_text(yaml.dump({"targets": "not-a-list"}), encoding="utf-8")
        with pytest.raises(InventoryError, match="must be a list"):
            load_inventory(f)

    def test_invalid_target_entry(self, tmp_path: Path):
        content = {
            "targets": [
                {
                    "id": "test",
                    "type": "k8s-deployment",
                    "environment": "invalid-env",
                    "sensitivity": "public",
                }
            ]
        }
        f = tmp_path / "bad_entry.yaml"
        f.write_text(yaml.dump(content), encoding="utf-8")
        with pytest.raises(InventoryError, match="Invalid target at index 0"):
            load_inventory(f)

    def test_duplicate_id_in_file(self, tmp_path: Path):
        content = {
            "targets": [
                {
                    "id": "same/id",
                    "type": "k8s-deployment",
                    "environment": "dev",
                    "sensitivity": "public",
                },
                {
                    "id": "same/id",
                    "type": "k8s-pod",
                    "environment": "dev",
                    "sensitivity": "public",
                },
            ]
        }
        f = tmp_path / "dup.yaml"
        f.write_text(yaml.dump(content), encoding="utf-8")
        with pytest.raises(InventoryError, match="Duplicate target ID"):
            load_inventory(f)

    def test_empty_targets_list(self, tmp_path: Path):
        f = tmp_path / "empty.yaml"
        f.write_text(yaml.dump({"targets": []}), encoding="utf-8")
        inv = load_inventory(f)
        assert len(inv) == 0

    def test_accepts_string_path(self, tmp_path: Path):
        content = {
            "targets": [
                {
                    "id": "dev/x",
                    "type": "k8s-deployment",
                    "environment": "dev",
                    "sensitivity": "public",
                }
            ]
        }
        f = tmp_path / "inv.yaml"
        f.write_text(yaml.dump(content), encoding="utf-8")
        inv = load_inventory(str(f))
        assert len(inv) == 1
