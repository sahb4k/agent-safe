"""Version-tracked SQLite schema migrations."""

from __future__ import annotations

from dashboard.backend.db.connection import Database

MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        );
        INSERT INTO schema_version (version) VALUES (0);

        CREATE TABLE IF NOT EXISTS users (
            user_id       TEXT PRIMARY KEY,
            username      TEXT UNIQUE NOT NULL,
            display_name  TEXT NOT NULL DEFAULT '',
            email         TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            salt          TEXT NOT NULL,
            role          TEXT NOT NULL DEFAULT 'viewer',
            is_active     INTEGER NOT NULL DEFAULT 1,
            created_at    TEXT NOT NULL,
            last_login    TEXT
        );
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS clusters (
            cluster_id     TEXT PRIMARY KEY,
            name           TEXT UNIQUE NOT NULL,
            description    TEXT NOT NULL DEFAULT '',
            api_key_hash   TEXT NOT NULL,
            api_key_prefix TEXT NOT NULL,
            is_active      INTEGER NOT NULL DEFAULT 1,
            created_at     TEXT NOT NULL,
            last_seen      TEXT
        );

        CREATE TABLE IF NOT EXISTS cluster_events (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            cluster_id     TEXT NOT NULL REFERENCES clusters(cluster_id),
            event_id       TEXT NOT NULL,
            timestamp      TEXT NOT NULL,
            event_type     TEXT NOT NULL DEFAULT 'decision',
            action         TEXT NOT NULL,
            target         TEXT NOT NULL,
            caller         TEXT NOT NULL,
            decision       TEXT NOT NULL,
            reason         TEXT NOT NULL DEFAULT '',
            risk_class     TEXT NOT NULL DEFAULT 'low',
            effective_risk TEXT NOT NULL DEFAULT 'low',
            policy_matched TEXT,
            correlation_id TEXT,
            ticket_id      TEXT,
            params         TEXT NOT NULL DEFAULT '{}',
            context        TEXT,
            ingested_at    TEXT NOT NULL,
            UNIQUE(cluster_id, event_id)
        );

        CREATE INDEX IF NOT EXISTS idx_cluster_events_cluster
            ON cluster_events(cluster_id);
        CREATE INDEX IF NOT EXISTS idx_cluster_events_timestamp
            ON cluster_events(timestamp);
        """,
    ),
]


def get_schema_version(db: Database) -> int:
    """Return the current schema version, or 0 if uninitialized."""
    try:
        row = db.fetchone("SELECT version FROM schema_version")
        return int(row["version"]) if row else 0
    except Exception:
        return 0


def run_migrations(db: Database) -> int:
    """Apply pending migrations. Returns the final schema version."""
    current = get_schema_version(db)

    for version, sql in MIGRATIONS:
        if version <= current:
            continue
        db.write_script(sql)
        db.write("UPDATE schema_version SET version = ?", (version,))

    return get_schema_version(db)
