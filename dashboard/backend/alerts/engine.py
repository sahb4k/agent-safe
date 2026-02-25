"""Alert evaluation engine — matches ingested events against active rules."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from fnmatch import fnmatch
from typing import Any

from dashboard.backend.alerts.models import AlertChannels, AlertConditions, AlertRuleInfo
from dashboard.backend.alerts.service import AlertService
from dashboard.backend.db.connection import Database

logger = logging.getLogger(__name__)


class AlertEngine:
    """Evaluate ingested events against active alert rules and fire notifications."""

    def __init__(self, alert_service: AlertService, db: Database) -> None:
        self._alert_svc = alert_service
        self._db = db
        self._cooldowns: dict[str, str] = {}  # rule_id -> last fired ISO

    def evaluate_batch(
        self, cluster_id: str, events: list[dict[str, Any]],
    ) -> None:
        """Evaluate a batch of newly ingested events against all active rules.

        Called as a fire-and-forget background task after ingest_events().
        Errors are logged and swallowed — never crashes the background worker.
        """
        try:
            self._evaluate(cluster_id, events)
        except Exception:
            logger.exception("Alert evaluation failed for cluster %s", cluster_id)

    def _evaluate(
        self, cluster_id: str, events: list[dict[str, Any]],
    ) -> None:
        rules = self._alert_svc.list_rules(include_inactive=False)
        if not rules:
            return

        for rule in rules:
            # Skip rules scoped to other clusters
            if rule.cluster_ids is not None and cluster_id not in rule.cluster_ids:
                continue

            # Skip if in cooldown
            if self._is_in_cooldown(rule.rule_id, rule.cooldown_seconds):
                continue

            # Find matching events from this batch
            matching_ids = [
                e.get("event_id", "")
                for e in events
                if self._event_matches(e, rule.conditions)
            ]
            if not matching_ids:
                continue

            # Threshold check
            if rule.threshold > 1 and rule.window_seconds > 0:
                if not self._threshold_met(cluster_id, rule):
                    continue

            self._fire_alert(rule, cluster_id, matching_ids)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    @staticmethod
    def _event_matches(
        event: dict[str, Any], conditions: AlertConditions,
    ) -> bool:
        """Check if a single event matches the rule's conditions."""
        if conditions.risk_classes:
            if event.get("risk_class") not in conditions.risk_classes:
                return False
        if conditions.decisions:
            if event.get("decision") not in conditions.decisions:
                return False
        if conditions.event_types:
            if event.get("event_type") not in conditions.event_types:
                return False
        if conditions.action_patterns:
            action = event.get("action", "")
            if not any(fnmatch(action, p) for p in conditions.action_patterns):
                return False
        return True

    # ------------------------------------------------------------------
    # Threshold
    # ------------------------------------------------------------------

    def _threshold_met(self, cluster_id: str, rule: AlertRuleInfo) -> bool:
        """Count matching events in the time window from the DB."""
        cutoff = (
            datetime.now(tz=UTC) - timedelta(seconds=rule.window_seconds)
        ).isoformat()

        where_parts = ["cluster_id = ?", "timestamp >= ?"]
        params: list[object] = [cluster_id, cutoff]

        conds = rule.conditions
        if conds.risk_classes:
            placeholders = ",".join("?" * len(conds.risk_classes))
            where_parts.append(f"risk_class IN ({placeholders})")
            params.extend(conds.risk_classes)
        if conds.decisions:
            placeholders = ",".join("?" * len(conds.decisions))
            where_parts.append(f"decision IN ({placeholders})")
            params.extend(conds.decisions)
        if conds.event_types:
            placeholders = ",".join("?" * len(conds.event_types))
            where_parts.append(f"event_type IN ({placeholders})")
            params.extend(conds.event_types)

        where = " AND ".join(where_parts)
        row = self._db.fetchone(
            f"SELECT COUNT(*) AS cnt FROM cluster_events WHERE {where}",
            tuple(params),
        )
        count = int(row["cnt"]) if row else 0
        return count >= rule.threshold

    # ------------------------------------------------------------------
    # Cooldown
    # ------------------------------------------------------------------

    def _is_in_cooldown(self, rule_id: str, cooldown_seconds: int) -> bool:
        if cooldown_seconds <= 0:
            return False

        # In-memory cache (fast path)
        last_fired = self._cooldowns.get(rule_id)
        if last_fired:
            elapsed = (
                datetime.now(tz=UTC) - datetime.fromisoformat(last_fired)
            ).total_seconds()
            if elapsed < cooldown_seconds:
                return True

        # DB fallback (survives restart)
        cutoff = (
            datetime.now(tz=UTC) - timedelta(seconds=cooldown_seconds)
        ).isoformat()
        row = self._db.fetchone(
            "SELECT id FROM alert_history "
            "WHERE rule_id = ? AND fired_at >= ? LIMIT 1",
            (rule_id, cutoff),
        )
        return row is not None

    # ------------------------------------------------------------------
    # Fire
    # ------------------------------------------------------------------

    def _fire_alert(
        self,
        rule: AlertRuleInfo,
        cluster_id: str,
        event_ids: list[str],
    ) -> None:
        now = datetime.now(tz=UTC).isoformat()
        self._cooldowns[rule.rule_id] = now

        payload = {
            "type": "alert",
            "rule_id": rule.rule_id,
            "rule_name": rule.name,
            "cluster_id": cluster_id,
            "fired_at": now,
            "trigger_event_ids": event_ids,
            "conditions": rule.conditions.model_dump(),
        }

        status = "sent"
        error = None

        try:
            self._send_notifications(rule.channels, payload)
        except Exception as exc:
            status = "failed"
            error = str(exc)
            logger.warning(
                "Alert notification failed for rule %s: %s",
                rule.name, error,
            )

        self._alert_svc.record_alert(
            rule_id=rule.rule_id,
            rule_name=rule.name,
            cluster_id=cluster_id,
            trigger_event_ids=event_ids,
            conditions=rule.conditions,
            notification_status=status,
            notification_error=error,
        )

    @staticmethod
    def _send_notifications(
        channels: AlertChannels, payload: dict[str, Any],
    ) -> None:
        """Send to all configured channels. Uses stdlib urllib.request."""
        if channels.webhook_url:
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
            headers: dict[str, str] = {"Content-Type": "application/json"}
            if channels.webhook_headers:
                headers.update(channels.webhook_headers)
            req = urllib.request.Request(
                channels.webhook_url, data=body, headers=headers, method="POST",
            )
            urllib.request.urlopen(req, timeout=10)  # noqa: S310

        if channels.slack_webhook_url:
            text = (
                f":rotating_light: *Alert: {payload['rule_name']}*\n"
                f"*Cluster:* `{payload['cluster_id']}`\n"
                f"*Fired at:* {payload['fired_at']}\n"
                f"*Matching events:* {len(payload['trigger_event_ids'])}\n"
                f"*Conditions:* {json.dumps(payload['conditions'])}"
            )
            slack_data: dict[str, Any] = {"text": text}
            if channels.slack_channel:
                slack_data["channel"] = channels.slack_channel
            body = json.dumps(slack_data).encode("utf-8")
            req = urllib.request.Request(
                channels.slack_webhook_url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)  # noqa: S310
