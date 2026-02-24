"""SQLite connection factory with WAL mode and foreign keys."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path


class Database:
    """Thread-safe SQLite connection manager.

    Uses WAL mode for concurrent readers and a threading lock for writes.
    Each thread gets its own connection via thread-local storage.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = str(db_path)
        self._local = threading.local()
        self._write_lock = threading.Lock()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        return self._get_conn().execute(sql, params)

    def executemany(self, sql: str, params_seq: list[tuple]) -> sqlite3.Cursor:
        return self._get_conn().executemany(sql, params_seq)

    def fetchone(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        return self._get_conn().execute(sql, params).fetchone()

    def fetchall(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        return self._get_conn().execute(sql, params).fetchall()

    def write(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """Execute a write operation with thread safety."""
        with self._write_lock:
            cursor = self._get_conn().execute(sql, params)
            self._get_conn().commit()
            return cursor

    def write_many(self, sql: str, params_seq: list[tuple]) -> None:
        """Execute multiple write operations atomically."""
        with self._write_lock:
            conn = self._get_conn()
            conn.executemany(sql, params_seq)
            conn.commit()

    def write_script(self, sql: str) -> None:
        """Execute a multi-statement SQL script."""
        with self._write_lock:
            conn = self._get_conn()
            conn.executescript(sql)

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
