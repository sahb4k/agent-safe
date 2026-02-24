"""Action registry data access for the dashboard."""

from __future__ import annotations

import time

from agent_safe.registry.loader import ActionRegistry, load_registry
from dashboard.backend.config import DashboardConfig
from dashboard.backend.schemas import (
    ActionDetailResponse,
    ActionSummary,
    ParameterDetail,
)


class ActionService:
    """Reads action definitions from the YAML registry."""

    def __init__(self, config: DashboardConfig) -> None:
        self._config = config
        self._cache: ActionRegistry | None = None
        self._cache_ts: float = 0.0
        self._cache_ttl: float = 30.0  # actions change rarely

    def _load_registry(self) -> ActionRegistry:
        now = time.monotonic()
        if self._cache is not None and (now - self._cache_ts) < self._cache_ttl:
            return self._cache
        self._cache = load_registry(self._config.actions_dir)
        self._cache_ts = now
        return self._cache

    def invalidate_cache(self) -> None:
        self._cache = None

    def list_actions(
        self,
        tag: str | None = None,
        risk: str | None = None,
    ) -> list[ActionSummary]:
        registry = self._load_registry()
        actions = registry.actions

        if tag:
            actions = [a for a in actions if tag in a.tags]
        if risk:
            actions = [a for a in actions if a.risk_class.value == risk]

        return [
            ActionSummary(
                name=a.name,
                description=a.description,
                risk_class=a.risk_class.value,
                tags=a.tags,
                reversible=a.reversible,
                target_types=a.target_types,
            )
            for a in sorted(actions, key=lambda a: a.name)
        ]

    def get_action(self, name: str) -> ActionDetailResponse | None:
        registry = self._load_registry()
        action = registry.get(name)
        if action is None:
            return None

        return ActionDetailResponse(
            name=action.name,
            version=action.version,
            description=action.description,
            risk_class=action.risk_class.value,
            tags=action.tags,
            target_types=action.target_types,
            reversible=action.reversible,
            rollback_action=action.rollback_action,
            parameters=[
                ParameterDetail(
                    name=p.name,
                    type=p.type.value,
                    required=p.required,
                    description=p.description,
                    default=p.default,
                )
                for p in action.parameters
            ],
            prechecks=[
                {"name": pc.name, "description": pc.description}
                for pc in action.prechecks
            ],
            credentials=(
                action.credentials.model_dump(mode="json")
                if action.credentials
                else None
            ),
            state_fields=[
                sf.model_dump(mode="json") for sf in action.state_fields
            ],
        )

    def action_count(self) -> int:
        return len(self._load_registry())
