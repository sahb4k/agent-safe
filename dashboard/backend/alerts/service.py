"""Alert rule CRUD and alert history persistence."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime

from dashboard.backend.alerts.models import (
    AlertChannels,
    AlertConditions,
    AlertHistoryItem,
    AlertRuleCreateRequest,
    AlertRuleInfo,
    AlertRuleUpdateRequest,
)
from dashboard.backend.db.connection import Database


class AlertService:
    """Manages alert rules (CRUD) and alert history queries."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Rule CRUD
    # ------------------------------------------------------------------

    def create_rule(
        self,
        req: AlertRuleCreateRequest,
        created_by: str = "",
    ) -> AlertRuleInfo:
        """Create a new alert rule."""
        existing = self._db.fetchone(
            "SELECT rule_id FROM alert_rules WHERE name = ?", (req.name,)
        )
        if existing:
            raise ValueError(f"Alert rule '{req.name}' already exists")

        if req.threshold < 1:
            raise ValueError("Threshold must be at least 1")
        if req.window_seconds < 0:
            raise ValueError("Window seconds must be non-negative")

        rule_id = f"alr-{secrets.token_hex(12)}"
        now = datetime.now(tz=UTC).isoformat()

        self._db.write(
            """INSERT INTO alert_rules
               (rule_id, name, description, conditions_json, cluster_ids_json,
                threshold, window_seconds, channels_json, cooldown_seconds,
                created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule_id,
                req.name,
                req.description,
                req.conditions.model_dump_json(),
                json.dumps(req.cluster_ids) if req.cluster_ids is not None else None,
                req.threshold,
                req.window_seconds,
                req.channels.model_dump_json(),
                req.cooldown_seconds,
                created_by,
                now,
                now,
            ),
        )

        return self.get_rule(rule_id)  # type: ignore[return-value]

    def list_rules(
        self, include_inactive: bool = False,
    ) -> list[AlertRuleInfo]:
        """List all alert rules, sorted by name."""
        if include_inactive:
            rows = self._db.fetchall(
                "SELECT * FROM alert_rules ORDER BY name"
            )
        else:
            rows = self._db.fetchall(
                "SELECT * FROM alert_rules WHERE is_active = 1 ORDER BY name"
            )
        return [self._row_to_rule(r) for r in rows]

    def get_rule(self, rule_id: str) -> AlertRuleInfo | None:
        """Get a single alert rule by ID."""
        row = self._db.fetchone(
            "SELECT * FROM alert_rules WHERE rule_id = ?", (rule_id,)
        )
        return self._row_to_rule(row) if row else None

    def update_rule(
        self,
        rule_id: str,
        req: AlertRuleUpdateRequest,
    ) -> AlertRuleInfo | None:
        """Update an alert rule. Returns None if not found."""
        existing = self.get_rule(rule_id)
        if existing is None:
            return None

        updates: list[str] = []
        params: list[object] = []

        if req.name is not None:
            dup = self._db.fetchone(
                "SELECT rule_id FROM alert_rules WHERE name = ? AND rule_id != ?",
                (req.name, rule_id),
            )
            if dup:
                raise ValueError(f"Alert rule '{req.name}' already exists")
            updates.append("name = ?")
            params.append(req.name)

        if req.description is not None:
            updates.append("description = ?")
            params.append(req.description)

        if req.conditions is not None:
            updates.append("conditions_json = ?")
            params.append(req.conditions.model_dump_json())

        if req.cluster_ids is not None:
            updates.append("cluster_ids_json = ?")
            params.append(json.dumps(req.cluster_ids))

        if req.threshold is not None:
            if req.threshold < 1:
                raise ValueError("Threshold must be at least 1")
            updates.append("threshold = ?")
            params.append(req.threshold)

        if req.window_seconds is not None:
            if req.window_seconds < 0:
                raise ValueError("Window seconds must be non-negative")
            updates.append("window_seconds = ?")
            params.append(req.window_seconds)

        if req.channels is not None:
            updates.append("channels_json = ?")
            params.append(req.channels.model_dump_json())

        if req.cooldown_seconds is not None:
            updates.append("cooldown_seconds = ?")
            params.append(req.cooldown_seconds)

        if req.is_active is not None:
            updates.append("is_active = ?")
            params.append(1 if req.is_active else 0)

        if updates:
            updates.append("updated_at = ?")
            params.append(datetime.now(tz=UTC).isoformat())
            params.append(rule_id)
            self._db.write(
                f"UPDATE alert_rules SET {', '.join(updates)} WHERE rule_id = ?",
                tuple(params),
            )

        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        """Soft-delete an alert rule (set is_active = 0)."""
        existing = self.get_rule(rule_id)
        if existing is None:
            return False
        self._db.write(
            "UPDATE alert_rules SET is_active = 0, updated_at = ? WHERE rule_id = ?",
            (datetime.now(tz=UTC).isoformat(), rule_id),
        )
        return True

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def list_history(
        self,
        limit: int = 50,
        rule_id: str | None = None,
        cluster_id: str | None = None,
    ) -> list[AlertHistoryItem]:
        """List alert history, newest first."""
        conditions = []
        params: list[object] = []

        if rule_id is not None:
            conditions.append("rule_id = ?")
            params.append(rule_id)
        if cluster_id is not None:
            conditions.append("cluster_id = ?")
            params.append(cluster_id)

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        params.append(limit)

        rows = self._db.fetchall(
            f"SELECT * FROM alert_history{where} ORDER BY fired_at DESC LIMIT ?",
            tuple(params),
        )
        return [self._row_to_history(r) for r in rows]

    def record_alert(
        self,
        rule_id: str,
        rule_name: str,
        cluster_id: str,
        trigger_event_ids: list[str],
        conditions: AlertConditions,
        notification_status: str,
        notification_error: str | None = None,
    ) -> int:
        """Record a fired alert in history. Returns the row id."""
        now = datetime.now(tz=UTC).isoformat()
        self._db.write(
            """INSERT INTO alert_history
               (rule_id, rule_name, cluster_id, fired_at,
                trigger_event_ids, conditions_snapshot,
                notification_status, notification_error)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                rule_id,
                rule_name,
                cluster_id,
                now,
                json.dumps(trigger_event_ids),
                conditions.model_dump_json(),
                notification_status,
                notification_error,
            ),
        )
        row = self._db.fetchone("SELECT last_insert_rowid() as id")
        return int(row["id"]) if row else 0

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_rule(row: dict) -> AlertRuleInfo:
        cluster_ids = None
        if row["cluster_ids_json"] is not None:
            cluster_ids = json.loads(row["cluster_ids_json"])

        return AlertRuleInfo(
            rule_id=row["rule_id"],
            name=row["name"],
            description=row["description"],
            is_active=bool(row["is_active"]),
            conditions=AlertConditions(**json.loads(row["conditions_json"])),
            cluster_ids=cluster_ids,
            threshold=row["threshold"],
            window_seconds=row["window_seconds"],
            channels=AlertChannels(**json.loads(row["channels_json"])),
            cooldown_seconds=row["cooldown_seconds"],
            created_by=row["created_by"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )

    @staticmethod
    def _row_to_history(row: dict) -> AlertHistoryItem:
        return AlertHistoryItem(
            id=row["id"],
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            cluster_id=row["cluster_id"],
            fired_at=datetime.fromisoformat(row["fired_at"]),
            trigger_event_ids=json.loads(row["trigger_event_ids"]),
            conditions_snapshot=AlertConditions(
                **json.loads(row["conditions_snapshot"])
            ),
            notification_status=row["notification_status"],
            notification_error=row["notification_error"],
        )
