"""Policy rule data access and match analysis."""

from __future__ import annotations

import time
from pathlib import Path

from agent_safe.inventory.loader import Inventory, load_inventory
from agent_safe.models import PolicyRule
from agent_safe.pdp.engine import load_policies
from dashboard.backend.config import DashboardConfig
from dashboard.backend.schemas import PolicyMatchAnalysis, PolicyRuleResponse


class PolicyService:
    """Reads policy rules and performs match analysis against inventory."""

    def __init__(self, config: DashboardConfig) -> None:
        self._config = config
        self._rules_cache: list[PolicyRule] | None = None
        self._inventory_cache: Inventory | None = None
        self._cache_ts: float = 0.0
        self._cache_ttl: float = 30.0

    def _load(self) -> tuple[list[PolicyRule], Inventory | None]:
        now = time.monotonic()
        if self._rules_cache is not None and (now - self._cache_ts) < self._cache_ttl:
            return self._rules_cache, self._inventory_cache

        self._rules_cache = load_policies(self._config.policies_dir)
        if Path(self._config.inventory_file).exists():
            self._inventory_cache = load_inventory(self._config.inventory_file)
        else:
            self._inventory_cache = None
        self._cache_ts = now
        return self._rules_cache, self._inventory_cache

    def invalidate_cache(self) -> None:
        self._rules_cache = None
        self._inventory_cache = None

    def list_policies(self) -> list[PolicyRuleResponse]:
        rules, _ = self._load()
        return [
            PolicyRuleResponse(
                name=r.name,
                description=r.description,
                priority=r.priority,
                decision=r.decision.value,
                reason=r.reason,
                match_actions=r.match.actions,
                match_environments=(
                    [e.value for e in r.match.targets.environments]
                    if r.match.targets and r.match.targets.environments
                    else None
                ),
                match_sensitivities=(
                    [s.value for s in r.match.targets.sensitivities]
                    if r.match.targets and r.match.targets.sensitivities
                    else None
                ),
                match_risk_classes=(
                    [rc.value for rc in r.match.risk_classes]
                    if r.match.risk_classes
                    else None
                ),
            )
            for r in rules
        ]

    def get_match_analysis(self) -> list[PolicyMatchAnalysis]:
        rules, inventory = self._load()
        if inventory is None:
            return [
                PolicyMatchAnalysis(
                    rule_name=r.name,
                    priority=r.priority,
                    decision=r.decision.value,
                    matching_target_count=0,
                    matching_targets=[],
                )
                for r in rules
            ]

        results: list[PolicyMatchAnalysis] = []
        targets = inventory.targets

        for rule in rules:
            matching: list[str] = []
            for t in targets:
                if self._rule_matches_target(rule, t):
                    matching.append(t.id)
            results.append(
                PolicyMatchAnalysis(
                    rule_name=rule.name,
                    priority=rule.priority,
                    decision=rule.decision.value,
                    matching_target_count=len(matching),
                    matching_targets=matching,
                )
            )

        return results

    @staticmethod
    def _rule_matches_target(rule: PolicyRule, target: object) -> bool:
        """Check if a rule's target selector matches an inventory target."""
        sel = rule.match.targets
        if sel is None:
            return True  # No target constraints → matches all

        if sel.environments and target.environment not in sel.environments:  # type: ignore[union-attr]
            return False
        if sel.sensitivities and target.sensitivity not in sel.sensitivities:  # type: ignore[union-attr]
            return False
        if sel.types and target.type not in sel.types:  # type: ignore[union-attr]
            return False
        if sel.labels:
            for k, v in sel.labels.items():
                if target.labels.get(k) != v:  # type: ignore[union-attr]
                    return False
        return True

    def policy_count(self) -> int:
        rules, _ = self._load()
        return len(rules)
