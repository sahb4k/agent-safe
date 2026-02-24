"""Cluster registration, API key management, and event aggregation."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import UTC, datetime
from typing import Any

from dashboard.backend.clusters.models import (
    ClusterCreateResponse,
    ClusterInfo,
    IngestResponse,
)
from dashboard.backend.db.connection import Database
from dashboard.backend.schemas import AuditStatsResponse, PaginatedResponse


class ClusterService:
    """Manages cluster registration, API keys, and aggregated audit events."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Cluster CRUD
    # ------------------------------------------------------------------

    def register_cluster(
        self,
        name: str,
        description: str = "",
    ) -> ClusterCreateResponse:
        """Register a new cluster and return the one-time API key."""
        existing = self._db.fetchone(
            "SELECT cluster_id FROM clusters WHERE name = ?", (name,)
        )
        if existing is not None:
            raise ValueError(f"Cluster '{name}' already exists")

        cluster_id = f"clu-{secrets.token_hex(12)}"
        api_key = f"ask_{secrets.token_hex(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        api_key_prefix = api_key[:12]
        now = datetime.now(tz=UTC).isoformat()

        self._db.write(
            """INSERT INTO clusters
               (cluster_id, name, description, api_key_hash, api_key_prefix,
                is_active, created_at)
               VALUES (?, ?, ?, ?, ?, 1, ?)""",
            (cluster_id, name, description, api_key_hash, api_key_prefix, now),
        )

        cluster = ClusterInfo(
            cluster_id=cluster_id,
            name=name,
            description=description,
            api_key_prefix=api_key_prefix,
            is_active=True,
            created_at=datetime.now(tz=UTC),
            event_count=0,
        )
        return ClusterCreateResponse(cluster=cluster, api_key=api_key)

    def list_clusters(self) -> list[ClusterInfo]:
        """List all registered clusters with event counts."""
        rows = self._db.fetchall(
            """SELECT c.*, COUNT(ce.id) AS event_count
               FROM clusters c
               LEFT JOIN cluster_events ce ON c.cluster_id = ce.cluster_id
               GROUP BY c.cluster_id
               ORDER BY c.created_at DESC"""
        )
        return [self._row_to_cluster(r) for r in rows]

    def get_cluster(self, cluster_id: str) -> ClusterInfo | None:
        """Get a single cluster by ID."""
        row = self._db.fetchone(
            """SELECT c.*, COUNT(ce.id) AS event_count
               FROM clusters c
               LEFT JOIN cluster_events ce ON c.cluster_id = ce.cluster_id
               WHERE c.cluster_id = ?
               GROUP BY c.cluster_id""",
            (cluster_id,),
        )
        if row is None:
            return None
        return self._row_to_cluster(row)

    def deactivate_cluster(self, cluster_id: str) -> bool:
        """Deactivate a cluster (revoke API key)."""
        cursor = self._db.write(
            "UPDATE clusters SET is_active = 0 WHERE cluster_id = ?",
            (cluster_id,),
        )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # API Key Validation
    # ------------------------------------------------------------------

    def validate_api_key(self, api_key: str) -> str | None:
        """Validate an API key. Returns cluster_id if valid, None otherwise."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        row = self._db.fetchone(
            "SELECT cluster_id FROM clusters WHERE api_key_hash = ? AND is_active = 1",
            (key_hash,),
        )
        return row["cluster_id"] if row else None

    # ------------------------------------------------------------------
    # Event Ingestion
    # ------------------------------------------------------------------

    def ingest_events(
        self, cluster_id: str, events: list[dict[str, Any]]
    ) -> IngestResponse:
        """Ingest a batch of audit events from a remote cluster."""
        now = datetime.now(tz=UTC).isoformat()
        accepted = 0
        duplicates = 0
        errors = 0

        # Update last_seen
        self._db.write(
            "UPDATE clusters SET last_seen = ? WHERE cluster_id = ?",
            (now, cluster_id),
        )

        for event in events:
            try:
                event_id = event.get("event_id", "")
                if not event_id:
                    errors += 1
                    continue

                # Check for duplicate first (avoids relying on exception parsing)
                existing = self._db.fetchone(
                    "SELECT id FROM cluster_events WHERE cluster_id = ? AND event_id = ?",
                    (cluster_id, event_id),
                )
                if existing is not None:
                    duplicates += 1
                    continue

                self._db.write(
                    """INSERT INTO cluster_events
                       (cluster_id, event_id, timestamp, event_type, action,
                        target, caller, decision, reason, risk_class,
                        effective_risk, policy_matched, correlation_id,
                        ticket_id, params, context, ingested_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        cluster_id,
                        event_id,
                        event.get("timestamp", now),
                        event.get("event_type", "decision"),
                        event.get("action", ""),
                        event.get("target", ""),
                        event.get("caller", ""),
                        event.get("decision", ""),
                        event.get("reason", ""),
                        event.get("risk_class", "low"),
                        event.get("effective_risk", "low"),
                        event.get("policy_matched"),
                        event.get("correlation_id"),
                        event.get("ticket_id"),
                        json.dumps(event.get("params", {})),
                        json.dumps(event.get("context")) if event.get("context") else None,
                        now,
                    ),
                )
                accepted += 1
            except Exception:
                errors += 1

        return IngestResponse(accepted=accepted, duplicates=duplicates, errors=errors)

    # ------------------------------------------------------------------
    # Event Queries
    # ------------------------------------------------------------------

    def get_cluster_events(
        self,
        cluster_id: str | None = None,
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
        """Query cluster events with filtering and pagination."""
        conditions: list[str] = []
        params: list[Any] = []

        if cluster_id is not None:
            conditions.append("cluster_id = ?")
            params.append(cluster_id)
        if event_type is not None:
            conditions.append("event_type = ?")
            params.append(event_type)
        if action is not None:
            conditions.append("action = ?")
            params.append(action)
        if target is not None:
            conditions.append("target = ?")
            params.append(target)
        if risk_class is not None:
            conditions.append("risk_class = ?")
            params.append(risk_class)
        if decision is not None:
            conditions.append("decision = ?")
            params.append(decision)
        if start_date is not None:
            conditions.append("timestamp >= ?")
            params.append(start_date)
        if end_date is not None:
            conditions.append("timestamp <= ?")
            params.append(end_date)

        where = ""
        if conditions:
            where = "WHERE " + " AND ".join(conditions)

        # Count
        count_row = self._db.fetchone(
            f"SELECT COUNT(*) AS cnt FROM cluster_events {where}",  # noqa: S608
            tuple(params),
        )
        total = count_row["cnt"] if count_row else 0

        # Paginate
        offset = (page - 1) * page_size
        rows = self._db.fetchall(
            f"SELECT * FROM cluster_events {where} ORDER BY timestamp DESC LIMIT ? OFFSET ?",  # noqa: S608
            (*params, page_size, offset),
        )

        items = [self._row_to_event(r) for r in rows]
        return PaginatedResponse(
            items=items, total=total, page=page, page_size=page_size
        )

    def get_cluster_stats(self, cluster_id: str | None = None) -> AuditStatsResponse:
        """Aggregate stats for cluster events."""
        condition = ""
        params: tuple[Any, ...] = ()
        if cluster_id is not None:
            condition = "WHERE cluster_id = ?"
            params = (cluster_id,)

        rows = self._db.fetchall(
            f"SELECT decision, risk_class, event_type FROM cluster_events {condition}",  # noqa: S608
            params,
        )

        by_decision: dict[str, int] = {}
        by_risk: dict[str, int] = {}
        by_type: dict[str, int] = {}

        for r in rows:
            d = r["decision"]
            by_decision[d] = by_decision.get(d, 0) + 1
            rk = r["risk_class"]
            by_risk[rk] = by_risk.get(rk, 0) + 1
            et = r["event_type"]
            by_type[et] = by_type.get(et, 0) + 1

        return AuditStatsResponse(
            total_events=len(rows),
            by_decision=by_decision,
            by_risk_class=by_risk,
            by_event_type=by_type,
        )

    def event_count(self, cluster_id: str | None = None) -> int:
        """Total event count, optionally filtered by cluster."""
        if cluster_id is not None:
            row = self._db.fetchone(
                "SELECT COUNT(*) AS cnt FROM cluster_events WHERE cluster_id = ?",
                (cluster_id,),
            )
        else:
            row = self._db.fetchone("SELECT COUNT(*) AS cnt FROM cluster_events")
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_cluster(row: Any) -> ClusterInfo:
        return ClusterInfo(
            cluster_id=row["cluster_id"],
            name=row["name"],
            description=row["description"],
            api_key_prefix=row["api_key_prefix"],
            is_active=bool(row["is_active"]),
            created_at=row["created_at"],
            last_seen=row["last_seen"],
            event_count=row["event_count"],
        )

    @staticmethod
    def _row_to_event(row: Any) -> dict[str, Any]:
        return {
            "event_id": row["event_id"],
            "cluster_id": row["cluster_id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "action": row["action"],
            "target": row["target"],
            "caller": row["caller"],
            "decision": row["decision"],
            "reason": row["reason"],
            "risk_class": row["risk_class"],
            "effective_risk": row["effective_risk"],
            "policy_matched": row["policy_matched"],
            "correlation_id": row["correlation_id"],
            "ticket_id": row["ticket_id"],
            "params": json.loads(row["params"]) if row["params"] else {},
            "context": json.loads(row["context"]) if row["context"] else None,
            "ingested_at": row["ingested_at"],
        }
