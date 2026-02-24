"""Audit event data access and aggregation."""

from __future__ import annotations

import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from agent_safe.audit.logger import AuditLogger
from agent_safe.models import AuditEvent
from dashboard.backend.config import DashboardConfig
from dashboard.backend.schemas import (
    AuditEventResponse,
    AuditStatsResponse,
    PaginatedResponse,
    TimelineBucket,
)


class AuditService:
    """Reads and aggregates audit events from the JSONL log."""

    def __init__(self, config: DashboardConfig) -> None:
        self._config = config
        self._logger = AuditLogger(log_path=config.audit_log)
        self._cache: list[AuditEvent] | None = None
        self._cache_ts: float = 0.0
        self._cache_ttl: float = 5.0

    def _load_events(self) -> list[AuditEvent]:
        now = time.monotonic()
        if self._cache is not None and (now - self._cache_ts) < self._cache_ttl:
            return self._cache
        self._cache = self._logger.read_events()
        self._cache_ts = now
        return self._cache

    def invalidate_cache(self) -> None:
        self._cache = None

    def get_events(
        self,
        page: int = 1,
        page_size: int = 25,
        event_type: str | None = None,
        action: str | None = None,
        target: str | None = None,
        risk_class: str | None = None,
        decision: str | None = None,
        start_date: str | None = None,
        end_date: str | None = None,
    ) -> PaginatedResponse:
        events = self._load_events()

        # Apply filters
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        if action:
            events = [e for e in events if e.action == action]
        if target:
            events = [e for e in events if e.target == target]
        if risk_class:
            events = [e for e in events if e.risk_class.value == risk_class]
        if decision:
            events = [e for e in events if e.decision.value == decision]
        if start_date:
            start_dt = datetime.fromisoformat(start_date).replace(tzinfo=UTC)
            events = [e for e in events if e.timestamp >= start_dt]
        if end_date:
            end_dt = datetime.fromisoformat(end_date).replace(tzinfo=UTC)
            events = [e for e in events if e.timestamp <= end_dt]

        total = len(events)
        # Newest first
        events = sorted(events, key=lambda e: e.timestamp, reverse=True)
        start = (page - 1) * page_size
        end = start + page_size
        page_events = events[start:end]

        items = [
            AuditEventResponse(
                event_id=e.event_id,
                timestamp=e.timestamp,
                event_type=e.event_type,
                action=e.action,
                target=e.target,
                caller=e.caller,
                decision=e.decision.value,
                reason=e.reason,
                risk_class=e.risk_class.value,
                effective_risk=e.effective_risk.value,
                policy_matched=e.policy_matched,
                correlation_id=e.correlation_id,
                ticket_id=e.ticket_id,
                params=e.params,
                context=e.context,
            )
            for e in page_events
        ]

        return PaginatedResponse(
            items=[i.model_dump(mode="json") for i in items],
            total=total,
            page=page,
            page_size=page_size,
        )

    def get_stats(self) -> AuditStatsResponse:
        events = self._load_events()
        by_decision: Counter[str] = Counter()
        by_risk: Counter[str] = Counter()
        by_type: Counter[str] = Counter()

        for e in events:
            by_decision[e.decision.value] += 1
            by_risk[e.risk_class.value] += 1
            by_type[e.event_type] += 1

        return AuditStatsResponse(
            total_events=len(events),
            by_decision=dict(by_decision),
            by_risk_class=dict(by_risk),
            by_event_type=dict(by_type),
        )

    def get_timeline(self, bucket_hours: int = 1) -> list[TimelineBucket]:
        events = self._load_events()
        if not events:
            return []

        buckets: dict[str, dict[str, Any]] = {}
        for e in events:
            # Round down to bucket boundary
            ts = e.timestamp.replace(minute=0, second=0, microsecond=0)
            if bucket_hours > 1:
                ts = ts.replace(hour=(ts.hour // bucket_hours) * bucket_hours)
            key = ts.isoformat()

            if key not in buckets:
                buckets[key] = {
                    "timestamp": key,
                    "count": 0,
                    "allow": 0,
                    "deny": 0,
                    "require_approval": 0,
                }
            buckets[key]["count"] += 1
            decision_val = e.decision.value
            if decision_val in buckets[key]:
                buckets[key][decision_val] += 1

        sorted_keys = sorted(buckets.keys())
        return [TimelineBucket(**buckets[k]) for k in sorted_keys]

    def event_count(self) -> int:
        return len(self._load_events())
