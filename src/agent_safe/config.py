"""Config file loading and auto-discovery for Agent-Safe.

Searches for ``agent-safe.yaml`` in the current directory and parent
directories, parses it, and resolves all relative paths against the
config file's location.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

CONFIG_FILENAME = "agent-safe.yaml"


@dataclass(frozen=True)
class AgentSafeConfig:
    """Parsed Agent-Safe project configuration."""

    config_path: Path | None = None
    registry: str | None = None
    policies: str | None = None
    inventory: str | None = None
    audit_log: str | None = None
    signing_key: str | None = None
    issuer: str = "agent-safe"
    rate_limit: dict[str, Any] | None = None
    cumulative_risk: dict[str, Any] | None = None


def find_config(start: Path | None = None) -> Path | None:
    """Walk from *start* (default ``cwd()``) up to the filesystem root.

    Returns the first ``agent-safe.yaml`` found, or ``None``.
    """
    current = (start or Path.cwd()).resolve()
    while True:
        candidate = current / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        parent = current.parent
        if parent == current:
            return None
        current = parent


def load_config(
    path: str | Path | None = None,
    *,
    auto_discover: bool = True,
) -> AgentSafeConfig:
    """Load an Agent-Safe config file.

    Resolution order:

    1. Explicit *path* (error if it doesn't exist).
    2. Auto-discover by walking parent directories.
    3. Return an empty ``AgentSafeConfig`` (all defaults).
    """
    config_path: Path | None = None

    if path is not None:
        config_path = Path(path).resolve()
        if not config_path.is_file():
            msg = f"Config file not found: {config_path}"
            raise FileNotFoundError(msg)
    elif auto_discover:
        config_path = find_config()

    if config_path is None:
        return AgentSafeConfig()

    return _parse_config(config_path)


def _parse_config(config_path: Path) -> AgentSafeConfig:
    """Read and parse a YAML config file, resolving relative paths."""
    text = config_path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}

    if not isinstance(data, dict):
        msg = f"Expected a YAML mapping in {config_path}, got {type(data).__name__}"
        raise ValueError(msg)

    base = config_path.parent

    def _resolve(key: str) -> str | None:
        val = data.get(key)
        if val is None:
            return None
        return str((base / val).resolve())

    return AgentSafeConfig(
        config_path=config_path,
        registry=_resolve("registry"),
        policies=_resolve("policies"),
        inventory=_resolve("inventory"),
        audit_log=_resolve("audit_log"),
        signing_key=data.get("signing_key"),
        issuer=data.get("issuer", "agent-safe"),
        rate_limit=data.get("rate_limit"),
        cumulative_risk=data.get("cumulative_risk"),
    )


def generate_signing_key() -> str:
    """Generate a 256-bit hex signing key (64 hex characters)."""
    return secrets.token_hex(32)
