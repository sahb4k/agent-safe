"""Activity feed — recent audit events for real-time display."""

from __future__ import annotations

from dashboard.backend.schemas import ActivityFeedItem
from dashboard.backend.services.audit_service import AuditService


class ActivityService:
    """Provides a tail-view of recent audit events."""

    def __init__(self, audit_service: AuditService) -> None:
        self._audit = audit_service

    def get_feed(self, limit: int = 50) -> list[ActivityFeedItem]:
        events = self._audit._load_events()
        # Sort newest first
        events = sorted(events, key=lambda e: e.timestamp, reverse=True)[:limit]

        return [
            ActivityFeedItem(
                event_id=e.event_id,
                timestamp=e.timestamp,
                event_type=e.event_type,
                action=e.action,
                target=e.target,
                caller=e.caller,
                decision=e.decision.value,
                risk_class=e.risk_class.value,
            )
            for e in events
        ]

    def get_recent_decisions(self, limit: int = 10) -> list[ActivityFeedItem]:
        events = self._audit._load_events()
        decisions = [e for e in events if e.event_type == "decision"]
        decisions = sorted(decisions, key=lambda e: e.timestamp, reverse=True)[:limit]

        return [
            ActivityFeedItem(
                event_id=e.event_id,
                timestamp=e.timestamp,
                event_type=e.event_type,
                action=e.action,
                target=e.target,
                caller=e.caller,
                decision=e.decision.value,
                risk_class=e.risk_class.value,
            )
            for e in decisions
        ]
