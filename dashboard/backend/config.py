"""Dashboard configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_PREFIX = "AGENT_SAFE_DASHBOARD_"


@dataclass
class DashboardConfig:
    """Settings for the governance dashboard.

    All fields can be overridden via environment variables prefixed with
    ``AGENT_SAFE_DASHBOARD_`` (e.g., ``AGENT_SAFE_DASHBOARD_PORT=9000``).
    """

    host: str = "127.0.0.1"
    port: int = 8420
    actions_dir: str = "./actions"
    policies_dir: str = "./policies"
    inventory_file: str = "./inventory.yaml"
    audit_log: str = "./audit.jsonl"
    dev_mode: bool = False

    @classmethod
    def from_env(cls) -> DashboardConfig:
        """Create config from environment variables."""
        kwargs: dict[str, str | int | bool] = {}
        for fld in cls.__dataclass_fields__:
            env_key = f"{ENV_PREFIX}{fld.upper()}"
            val = os.environ.get(env_key)
            if val is None:
                continue
            fld_type = cls.__dataclass_fields__[fld].type
            if fld_type == "int":
                kwargs[fld] = int(val)
            elif fld_type == "bool":
                kwargs[fld] = val.lower() in ("1", "true", "yes")
            else:
                kwargs[fld] = val
        return cls(**kwargs)
