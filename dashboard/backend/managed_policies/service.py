"""Managed policy CRUD, revision publishing, and bundle sync."""

from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime
from typing import Any

from dashboard.backend.db.connection import Database
from dashboard.backend.managed_policies.models import (
    ClusterSyncStatus,
    ManagedPolicyCreateRequest,
    ManagedPolicyInfo,
    ManagedPolicyUpdateRequest,
    MatchConditions,
    PolicyBundleResponse,
    PolicyRevisionInfo,
    PublishResponse,
)

_VALID_DECISIONS = {"allow", "deny", "require_approval"}


class ManagedPolicyService:
    """CRUD for dashboard-managed policy rules, publishing, and bundle sync."""

    def __init__(self, db: Database) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Policy CRUD
    # ------------------------------------------------------------------

    def create_policy(
        self,
        req: ManagedPolicyCreateRequest,
        created_by: str = "",
    ) -> ManagedPolicyInfo:
        """Create a new managed policy rule."""
        if req.decision not in _VALID_DECISIONS:
            raise ValueError(
                f"Invalid decision '{req.decision}', must be one of: "
                f"{', '.join(sorted(_VALID_DECISIONS))}"
            )

        existing = self._db.fetchone(
            "SELECT policy_id FROM managed_policies WHERE name = ?", (req.name,)
        )
        if existing is not None:
            raise ValueError(f"Policy '{req.name}' already exists")

        policy_id = f"pol-{secrets.token_hex(12)}"
        now = datetime.now(tz=UTC).isoformat()
        match_json = req.match.model_dump_json()

        self._db.write(
            """INSERT INTO managed_policies
               (policy_id, name, description, priority, decision, reason,
                match_json, is_active, created_by, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)""",
            (
                policy_id, req.name, req.description, req.priority,
                req.decision, req.reason, match_json, created_by, now, now,
            ),
        )

        return ManagedPolicyInfo(
            policy_id=policy_id,
            name=req.name,
            description=req.description,
            priority=req.priority,
            decision=req.decision,
            reason=req.reason,
            match=req.match,
            is_active=True,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )

    def list_policies(
        self, include_inactive: bool = False,
    ) -> list[ManagedPolicyInfo]:
        """List managed policies, ordered by priority descending."""
        if include_inactive:
            rows = self._db.fetchall(
                "SELECT * FROM managed_policies ORDER BY priority DESC"
            )
        else:
            rows = self._db.fetchall(
                "SELECT * FROM managed_policies WHERE is_active = 1 ORDER BY priority DESC"
            )
        return [self._row_to_policy(r) for r in rows]

    def get_policy(self, policy_id: str) -> ManagedPolicyInfo | None:
        """Get a single managed policy by ID."""
        row = self._db.fetchone(
            "SELECT * FROM managed_policies WHERE policy_id = ?",
            (policy_id,),
        )
        if row is None:
            return None
        return self._row_to_policy(row)

    def update_policy(
        self,
        policy_id: str,
        req: ManagedPolicyUpdateRequest,
    ) -> ManagedPolicyInfo | None:
        """Update a managed policy. Only non-None fields are changed."""
        existing = self._db.fetchone(
            "SELECT * FROM managed_policies WHERE policy_id = ?",
            (policy_id,),
        )
        if existing is None:
            return None

        updates: list[str] = []
        values: list[Any] = []

        if req.name is not None:
            updates.append("name = ?")
            values.append(req.name)
        if req.description is not None:
            updates.append("description = ?")
            values.append(req.description)
        if req.priority is not None:
            updates.append("priority = ?")
            values.append(req.priority)
        if req.decision is not None:
            if req.decision not in _VALID_DECISIONS:
                raise ValueError(
                    f"Invalid decision '{req.decision}', "
                    f"must be one of: {', '.join(sorted(_VALID_DECISIONS))}"
                )
            updates.append("decision = ?")
            values.append(req.decision)
        if req.reason is not None:
            updates.append("reason = ?")
            values.append(req.reason)
        if req.match is not None:
            updates.append("match_json = ?")
            values.append(req.match.model_dump_json())
        if req.is_active is not None:
            updates.append("is_active = ?")
            values.append(1 if req.is_active else 0)

        if not updates:
            return self._row_to_policy(existing)

        now = datetime.now(tz=UTC).isoformat()
        updates.append("updated_at = ?")
        values.append(now)
        values.append(policy_id)

        set_clause = ", ".join(updates)
        self._db.write(
            f"UPDATE managed_policies SET {set_clause} WHERE policy_id = ?",  # noqa: S608
            tuple(values),
        )

        return self.get_policy(policy_id)

    def delete_policy(self, policy_id: str) -> bool:
        """Soft-delete a managed policy (set is_active = 0)."""
        now = datetime.now(tz=UTC).isoformat()
        cursor = self._db.write(
            "UPDATE managed_policies SET is_active = 0, updated_at = ? WHERE policy_id = ?",
            (now, policy_id),
        )
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Publishing
    # ------------------------------------------------------------------

    def publish(
        self,
        published_by: str = "",
        notes: str = "",
    ) -> PublishResponse:
        """Snapshot all active managed policies into a new immutable revision."""
        policies = self.list_policies(include_inactive=False)
        bundle = [self._policy_to_bundle_entry(p) for p in policies]
        bundle_json = json.dumps(bundle, sort_keys=True)
        now = datetime.now(tz=UTC).isoformat()

        self._db.write(
            """INSERT INTO policy_revisions
               (bundle_json, rule_count, published_by, published_at, notes)
               VALUES (?, ?, ?, ?, ?)""",
            (bundle_json, len(bundle), published_by, now, notes),
        )

        # Fetch the inserted row to get the auto-incremented revision_id
        row = self._db.fetchone(
            "SELECT * FROM policy_revisions ORDER BY revision_id DESC LIMIT 1"
        )

        revision = PolicyRevisionInfo(
            revision_id=row["revision_id"],
            rule_count=row["rule_count"],
            published_by=row["published_by"],
            published_at=row["published_at"],
            notes=row["notes"],
        )
        return PublishResponse(revision=revision, bundle_preview=bundle)

    def list_revisions(self, limit: int = 20) -> list[PolicyRevisionInfo]:
        """List recent revisions, newest first."""
        rows = self._db.fetchall(
            "SELECT * FROM policy_revisions ORDER BY revision_id DESC LIMIT ?",
            (limit,),
        )
        return [
            PolicyRevisionInfo(
                revision_id=r["revision_id"],
                rule_count=r["rule_count"],
                published_by=r["published_by"],
                published_at=r["published_at"],
                notes=r["notes"],
            )
            for r in rows
        ]

    def get_latest_revision(self) -> PolicyRevisionInfo | None:
        """Get the most recent revision, or None if no revisions exist."""
        row = self._db.fetchone(
            "SELECT * FROM policy_revisions ORDER BY revision_id DESC LIMIT 1"
        )
        if row is None:
            return None
        return PolicyRevisionInfo(
            revision_id=row["revision_id"],
            rule_count=row["rule_count"],
            published_by=row["published_by"],
            published_at=row["published_at"],
            notes=row["notes"],
        )

    # ------------------------------------------------------------------
    # Bundle Sync
    # ------------------------------------------------------------------

    def get_bundle(
        self, revision_id: int | None = None,
    ) -> PolicyBundleResponse | None:
        """Get a policy bundle for a specific (or latest) revision."""
        if revision_id is not None:
            row = self._db.fetchone(
                "SELECT * FROM policy_revisions WHERE revision_id = ?",
                (revision_id,),
            )
        else:
            row = self._db.fetchone(
                "SELECT * FROM policy_revisions ORDER BY revision_id DESC LIMIT 1"
            )
        if row is None:
            return None

        rules = json.loads(row["bundle_json"])
        return PolicyBundleResponse(
            revision_id=row["revision_id"],
            published_at=row["published_at"],
            rules=rules,
        )

    def record_cluster_sync(
        self, cluster_id: str, revision_id: int,
    ) -> None:
        """Record that a cluster has synced to a specific revision (upsert)."""
        now = datetime.now(tz=UTC).isoformat()
        self._db.write(
            """INSERT INTO cluster_policy_status (cluster_id, revision_id, synced_at)
               VALUES (?, ?, ?)
               ON CONFLICT(cluster_id) DO UPDATE SET
                   revision_id = excluded.revision_id,
                   synced_at = excluded.synced_at""",
            (cluster_id, revision_id, now),
        )

    def get_sync_status(self) -> list[ClusterSyncStatus]:
        """Get policy sync status for all active clusters."""
        latest = self.get_latest_revision()
        latest_id = latest.revision_id if latest else None

        rows = self._db.fetchall(
            """SELECT c.cluster_id, c.name,
                      cps.revision_id, cps.synced_at
               FROM clusters c
               LEFT JOIN cluster_policy_status cps ON c.cluster_id = cps.cluster_id
               WHERE c.is_active = 1
               ORDER BY c.name"""
        )

        return [
            ClusterSyncStatus(
                cluster_id=r["cluster_id"],
                cluster_name=r["name"],
                revision_id=r["revision_id"],
                synced_at=r["synced_at"],
                is_current=r["revision_id"] == latest_id
                if r["revision_id"] is not None
                else False,
            )
            for r in rows
        ]

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_policy(row: Any) -> ManagedPolicyInfo:
        match_data = json.loads(row["match_json"]) if row["match_json"] else {}
        return ManagedPolicyInfo(
            policy_id=row["policy_id"],
            name=row["name"],
            description=row["description"],
            priority=row["priority"],
            decision=row["decision"],
            reason=row["reason"],
            match=MatchConditions(**match_data),
            is_active=bool(row["is_active"]),
            created_by=row["created_by"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    @staticmethod
    def _policy_to_bundle_entry(policy: ManagedPolicyInfo) -> dict[str, Any]:
        """Convert a managed policy to a PolicyRule-compatible dict for YAML."""
        entry: dict[str, Any] = {
            "name": policy.name,
            "description": policy.description,
            "priority": policy.priority,
            "decision": policy.decision,
            "reason": policy.reason,
            "match": {},
        }

        match = policy.match
        match_dict: dict[str, Any] = {}

        if match.actions != ["*"]:
            match_dict["actions"] = match.actions

        if match.targets is not None:
            targets: dict[str, Any] = {}
            if match.targets.environments:
                targets["environments"] = match.targets.environments
            if match.targets.sensitivities:
                targets["sensitivities"] = match.targets.sensitivities
            if match.targets.types:
                targets["types"] = match.targets.types
            if match.targets.labels:
                targets["labels"] = match.targets.labels
            if targets:
                match_dict["targets"] = targets

        if match.callers is not None:
            callers: dict[str, Any] = {}
            if match.callers.agent_ids:
                callers["agent_ids"] = match.callers.agent_ids
            if match.callers.roles:
                callers["roles"] = match.callers.roles
            if match.callers.groups:
                callers["groups"] = match.callers.groups
            if callers:
                match_dict["callers"] = callers

        if match.risk_classes:
            match_dict["risk_classes"] = match.risk_classes

        if match.require_ticket is not None:
            match_dict["require_ticket"] = match.require_ticket

        entry["match"] = match_dict
        return entry
