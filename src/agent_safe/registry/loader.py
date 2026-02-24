"""Action Registry — loads, validates, and serves action definitions.

The registry is the versioned catalogue of actions that agents can request.
Each action is defined in a YAML file and validated against the ActionDefinition
schema on load. The registry provides lookup, listing, parameter validation,
and integrity checking (SHA-256 per file).
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agent_safe.models import ActionDefinition, ParamType


class RegistryError(Exception):
    """Raised when the registry cannot load or validate actions."""


class ActionRegistry:
    """In-memory registry of action definitions loaded from YAML files.

    Actions are keyed by name. The registry enforces uniqueness — loading
    two files with the same action name is an error.
    """

    def __init__(self) -> None:
        self._actions: dict[str, ActionDefinition] = {}
        self._file_hashes: dict[str, str] = {}  # filename -> sha256

    @property
    def actions(self) -> list[ActionDefinition]:
        return list(self._actions.values())

    @property
    def file_hashes(self) -> dict[str, str]:
        """SHA-256 hashes of loaded action files, keyed by filename."""
        return dict(self._file_hashes)

    def __len__(self) -> int:
        return len(self._actions)

    def get(self, name: str) -> ActionDefinition | None:
        """Look up an action by name. Returns None if not found."""
        return self._actions.get(name)

    def get_or_raise(self, name: str) -> ActionDefinition:
        """Look up an action by name. Raises RegistryError if not found."""
        action = self._actions.get(name)
        if action is None:
            raise RegistryError(f"Action not found: {name}")
        return action

    def list_actions(self) -> list[str]:
        """Return sorted list of registered action names."""
        return sorted(self._actions.keys())

    def list_by_tag(self, tag: str) -> list[ActionDefinition]:
        """Return actions that have the given tag."""
        return [a for a in self._actions.values() if tag in a.tags]

    def list_by_risk(self, risk_class: str) -> list[ActionDefinition]:
        """Return actions with the given risk class."""
        return [a for a in self._actions.values() if a.risk_class == risk_class]

    def versioned_name(self, name: str) -> str | None:
        """Return 'name@version' for a registered action, or None."""
        action = self._actions.get(name)
        if action is None:
            return None
        return f"{action.name}@{action.version}"

    def register(self, action: ActionDefinition, file_hash: str = "") -> None:
        """Register a single action definition.

        Raises RegistryError if an action with the same name already exists.
        """
        if action.name in self._actions:
            existing = self._actions[action.name]
            raise RegistryError(
                f"Duplicate action name '{action.name}': "
                f"already registered as {existing.name}@{existing.version}"
            )
        self._actions[action.name] = action
        if file_hash:
            self._file_hashes[action.name] = file_hash

    def validate_params(self, action_name: str, params: dict[str, Any]) -> list[str]:
        """Validate parameters against an action's parameter schema.

        Returns a list of error messages. Empty list means valid.
        """
        action = self._actions.get(action_name)
        if action is None:
            return [f"Unknown action: {action_name}"]

        errors: list[str] = []

        # Check required params are present
        for param_def in action.parameters:
            if param_def.required and param_def.name not in params:
                errors.append(f"Missing required parameter: {param_def.name}")

        # Check for unknown params
        known_names = {p.name for p in action.parameters}
        for key in params:
            if key not in known_names:
                errors.append(f"Unknown parameter: {key}")

        # Validate each provided param
        for param_def in action.parameters:
            if param_def.name not in params:
                continue
            value = params[param_def.name]
            param_errors = _validate_single_param(param_def.name, value, param_def)
            errors.extend(param_errors)

        return errors


def _validate_single_param(name: str, value: Any, param_def: Any) -> list[str]:
    """Validate a single parameter value against its definition."""
    errors: list[str] = []

    # Type checking
    type_valid = _check_type(value, param_def.type)
    if not type_valid:
        actual = type(value).__name__
        errors.append(f"Parameter '{name}': expected {param_def.type.value}, got {actual}")
        return errors  # Skip constraint checks if type is wrong

    # Constraint checking
    if param_def.constraints is None:
        return errors

    c = param_def.constraints

    if c.min_value is not None and isinstance(value, (int, float)) and value < c.min_value:
        errors.append(f"Parameter '{name}': value {value} is below minimum {c.min_value}")

    if c.max_value is not None and isinstance(value, (int, float)) and value > c.max_value:
        errors.append(f"Parameter '{name}': value {value} exceeds maximum {c.max_value}")

    if c.min_length is not None and isinstance(value, str) and len(value) < c.min_length:
        errors.append(f"Parameter '{name}': length {len(value)} is below minimum {c.min_length}")

    if c.max_length is not None and isinstance(value, str) and len(value) > c.max_length:
        errors.append(f"Parameter '{name}': length {len(value)} exceeds maximum {c.max_length}")

    if c.pattern is not None and isinstance(value, str) and not re.fullmatch(c.pattern, value):
        errors.append(f"Parameter '{name}': value does not match pattern '{c.pattern}'")

    if c.enum is not None and str(value) not in c.enum:
        errors.append(f"Parameter '{name}': value '{value}' not in allowed values {c.enum}")

    return errors


def _check_type(value: Any, expected: ParamType) -> bool:
    """Check if a value matches the expected parameter type."""
    match expected:
        case ParamType.STRING:
            return isinstance(value, str)
        case ParamType.INTEGER:
            return isinstance(value, int) and not isinstance(value, bool)
        case ParamType.NUMBER:
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        case ParamType.BOOLEAN:
            return isinstance(value, bool)
        case ParamType.ARRAY:
            return isinstance(value, list)
    return False


def _compute_file_hash(path: Path) -> str:
    """Compute SHA-256 hash of a file's contents."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_action_file(path: Path) -> tuple[ActionDefinition, str]:
    """Load and validate a single action YAML file.

    Returns (ActionDefinition, sha256_hash).
    Raises RegistryError on any failure.
    """
    if not path.exists():
        raise RegistryError(f"Action file not found: {path}")

    file_hash = _compute_file_hash(path)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise RegistryError(f"Invalid YAML in {path}: {e}") from e

    if not isinstance(raw, dict):
        raise RegistryError(f"Action file must contain a YAML mapping: {path}")

    try:
        action = ActionDefinition(**raw)
    except ValidationError as e:
        raise RegistryError(f"Invalid action definition in {path}: {e}") from e

    return action, file_hash


def load_registry(actions_dir: str | Path) -> ActionRegistry:
    """Load all YAML action files from a directory into a registry.

    Scans for *.yaml and *.yml files. Each file must contain exactly
    one action definition.

    Raises RegistryError if the directory doesn't exist, any file is
    invalid, or duplicate action names are found.
    """
    actions_dir = Path(actions_dir)
    if not actions_dir.is_dir():
        raise RegistryError(f"Actions directory not found: {actions_dir}")

    registry = ActionRegistry()
    yaml_files = sorted(list(actions_dir.glob("*.yaml")) + list(actions_dir.glob("*.yml")))

    if not yaml_files:
        return registry

    for path in yaml_files:
        action, file_hash = load_action_file(path)
        try:
            registry.register(action, file_hash)
        except RegistryError as e:
            raise RegistryError(f"Error loading {path}: {e}") from e

    return registry
