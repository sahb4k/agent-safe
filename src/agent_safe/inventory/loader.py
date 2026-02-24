"""Target inventory loader.

Loads and validates target definitions from a YAML file.
Provides lookup by target ID for the PDP.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_safe.models import TargetDefinition


class InventoryError(Exception):
    """Raised when the inventory file is invalid or cannot be loaded."""


class Inventory:
    """In-memory target inventory loaded from YAML.

    Provides O(1) lookup by target ID and filtering by properties.
    """

    def __init__(self, targets: list[TargetDefinition]) -> None:
        self._targets: dict[str, TargetDefinition] = {}
        for target in targets:
            if target.id in self._targets:
                raise InventoryError(f"Duplicate target ID: {target.id}")
            self._targets[target.id] = target

    @property
    def targets(self) -> list[TargetDefinition]:
        return list(self._targets.values())

    def __len__(self) -> int:
        return len(self._targets)

    def get(self, target_id: str) -> TargetDefinition | None:
        """Look up a target by its ID. Returns None if not found."""
        return self._targets.get(target_id)

    def get_or_raise(self, target_id: str) -> TargetDefinition:
        """Look up a target by ID. Raises InventoryError if not found."""
        target = self._targets.get(target_id)
        if target is None:
            raise InventoryError(f"Target not found: {target_id}")
        return target

    def list_by_environment(self, environment: str) -> list[TargetDefinition]:
        """Return all targets in a given environment."""
        return [t for t in self._targets.values() if t.environment == environment]

    def list_by_type(self, target_type: str) -> list[TargetDefinition]:
        """Return all targets of a given type."""
        return [t for t in self._targets.values() if t.type == target_type]


def load_inventory(path: str | Path) -> Inventory:
    """Load and validate a target inventory from a YAML file.

    The YAML file must have a top-level 'targets' key containing a list
    of target definitions.

    Raises:
        InventoryError: If the file cannot be read, parsed, or validated.
    """
    path = Path(path)
    if not path.exists():
        raise InventoryError(f"Inventory file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise InventoryError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(raw, dict) or "targets" not in raw:
        raise InventoryError(f"Inventory file must have a top-level 'targets' key: {path}")

    raw_targets: Any = raw["targets"]
    if not isinstance(raw_targets, list):
        raise InventoryError(f"'targets' must be a list: {path}")

    targets: list[TargetDefinition] = []
    for i, entry in enumerate(raw_targets):
        try:
            targets.append(TargetDefinition(**entry))
        except (ValidationError, TypeError) as e:
            raise InventoryError(f"Invalid target at index {i} in {path}: {e}") from e

    return Inventory(targets)
