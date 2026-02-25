"""Tests for SQLite database layer and migrations."""

from __future__ import annotations

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi", reason="fastapi not installed")

from dashboard.backend.db.connection import Database  # noqa: E402
from dashboard.backend.db.migrations import get_schema_version, run_migrations  # noqa: E402


@pytest.fixture()
def db_path(tmp_path: Path) -> str:
    return str(tmp_path / "test.db")


@pytest.fixture()
def db(db_path: str) -> Database:
    return Database(db_path)


class TestDatabase:
    def test_create_database(self, db: Database) -> None:
        db.write("CREATE TABLE test (id INTEGER PRIMARY KEY, name TEXT)")
        db.write("INSERT INTO test (name) VALUES (?)", ("hello",))
        row = db.fetchone("SELECT * FROM test WHERE id = 1")
        assert row is not None
        assert row["name"] == "hello"

    def test_fetchall(self, db: Database) -> None:
        db.write("CREATE TABLE items (id INTEGER PRIMARY KEY, val TEXT)")
        db.write("INSERT INTO items (val) VALUES (?)", ("a",))
        db.write("INSERT INTO items (val) VALUES (?)", ("b",))
        rows = db.fetchall("SELECT * FROM items ORDER BY val")
        assert len(rows) == 2
        assert rows[0]["val"] == "a"

    def test_fetchone_missing(self, db: Database) -> None:
        db.write("CREATE TABLE empty_table (id INTEGER PRIMARY KEY)")
        row = db.fetchone("SELECT * FROM empty_table WHERE id = 1")
        assert row is None

    def test_wal_mode(self, db: Database) -> None:
        row = db.fetchone("PRAGMA journal_mode")
        assert row[0] == "wal"

    def test_foreign_keys_enabled(self, db: Database) -> None:
        row = db.fetchone("PRAGMA foreign_keys")
        assert row[0] == 1

    def test_write_script(self, db: Database) -> None:
        db.write_script("""
            CREATE TABLE t1 (id INTEGER PRIMARY KEY);
            CREATE TABLE t2 (id INTEGER PRIMARY KEY);
        """)
        # Both tables should exist
        db.write("INSERT INTO t1 (id) VALUES (1)")
        db.write("INSERT INTO t2 (id) VALUES (1)")


class TestMigrations:
    def test_initial_schema_version(self, db: Database) -> None:
        assert get_schema_version(db) == 0

    def test_run_migrations(self, db: Database) -> None:
        version = run_migrations(db)
        assert version == 4

    def test_migrations_idempotent(self, db: Database) -> None:
        run_migrations(db)
        run_migrations(db)
        assert get_schema_version(db) == 4

    def test_users_table_created(self, db: Database) -> None:
        run_migrations(db)
        rows = db.fetchall("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        assert len(rows) == 1

    def test_schema_version_table_created(self, db: Database) -> None:
        run_migrations(db)
        rows = db.fetchall(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        )
        assert len(rows) == 1
