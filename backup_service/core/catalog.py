"""SQLite State Catalog for Non-Destructive Delta File Tracking.

Maintains file signatures (size, mtime, SHA-256) across runs to detect
ADDED, UPDATED, and DELETED files with zero data loss.
"""

import sqlite3
import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager


class FileChangeType(str, Enum):
    ADDED = "ADDED"
    UPDATED = "UPDATED"
    DELETED = "DELETED"
    UNCHANGED = "UNCHANGED"


@dataclass
class CatalogEntry:
    client_id: str
    source_id: str
    rel_path: str
    size: int
    mtime: float
    sha256: str
    first_seen_at: str
    last_updated_at: str
    is_deleted: bool
    last_deleted_at: Optional[str] = None


class StateCatalog:
    """ACID-compliant SQLite state catalog for differential backup tracking."""

    def __init__(self, db_path: str):
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Context manager yielding connection and strictly closing on exit."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for high performance and concurrency
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Create tables and indexes if they do not exist."""
        with self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS file_catalog (
                    client_id TEXT NOT NULL,
                    source_id TEXT NOT NULL,
                    rel_path TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    mtime REAL NOT NULL,
                    sha256 TEXT NOT NULL,
                    first_seen_at TEXT NOT NULL,
                    last_updated_at TEXT NOT NULL,
                    is_deleted INTEGER NOT NULL DEFAULT 0,
                    last_deleted_at TEXT,
                    PRIMARY KEY (client_id, source_id, rel_path)
                );

                CREATE INDEX IF NOT EXISTS idx_file_lookup 
                ON file_catalog (client_id, source_id, is_deleted);

                CREATE TABLE IF NOT EXISTS backup_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT NOT NULL,
                    run_date TEXT NOT NULL,
                    run_timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    files_added INTEGER NOT NULL DEFAULT 0,
                    files_updated INTEGER NOT NULL DEFAULT 0,
                    files_deleted INTEGER NOT NULL DEFAULT 0,
                    dbs_dumped INTEGER NOT NULL DEFAULT 0,
                    total_incremental_bytes INTEGER NOT NULL DEFAULT 0,
                    duration_seconds REAL NOT NULL DEFAULT 0.0,
                    error_message TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_runs_client 
                ON backup_runs (client_id, run_date);
            """)

    def get_active_files(self, client_id: str, source_id: str) -> Dict[str, CatalogEntry]:
        """Fetch all currently active (non-deleted) files for a given client and source."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT client_id, source_id, rel_path, size, mtime, sha256, 
                       first_seen_at, last_updated_at, is_deleted, last_deleted_at
                FROM file_catalog
                WHERE client_id = ? AND source_id = ? AND is_deleted = 0
                """,
                (client_id, source_id)
            )
            entries = {}
            for row in cur.fetchall():
                entries[row["rel_path"]] = CatalogEntry(
                    client_id=row["client_id"],
                    source_id=row["source_id"],
                    rel_path=row["rel_path"],
                    size=row["size"],
                    mtime=row["mtime"],
                    sha256=row["sha256"],
                    first_seen_at=row["first_seen_at"],
                    last_updated_at=row["last_updated_at"],
                    is_deleted=bool(row["is_deleted"]),
                    last_deleted_at=row["last_deleted_at"]
                )
            return entries

    def get_all_known_files(self, client_id: str, source_id: str) -> Dict[str, CatalogEntry]:
        """Fetch all known files (including marked deleted) for this client & source."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT client_id, source_id, rel_path, size, mtime, sha256, 
                       first_seen_at, last_updated_at, is_deleted, last_deleted_at
                FROM file_catalog
                WHERE client_id = ? AND source_id = ?
                """,
                (client_id, source_id)
            )
            entries = {}
            for row in cur.fetchall():
                entries[row["rel_path"]] = CatalogEntry(
                    client_id=row["client_id"],
                    source_id=row["source_id"],
                    rel_path=row["rel_path"],
                    size=row["size"],
                    mtime=row["mtime"],
                    sha256=row["sha256"],
                    first_seen_at=row["first_seen_at"],
                    last_updated_at=row["last_updated_at"],
                    is_deleted=bool(row["is_deleted"]),
                    last_deleted_at=row["last_deleted_at"]
                )
            return entries

    def record_file_addition_or_update(
        self,
        client_id: str,
        source_id: str,
        rel_path: str,
        size: int,
        mtime: float,
        sha256: str
    ):
        """Insert or update a file record. If previously marked deleted, revives it."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO file_catalog (
                    client_id, source_id, rel_path, size, mtime, sha256, 
                    first_seen_at, last_updated_at, is_deleted, last_deleted_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, NULL)
                ON CONFLICT(client_id, source_id, rel_path) DO UPDATE SET
                    size = excluded.size,
                    mtime = excluded.mtime,
                    sha256 = excluded.sha256,
                    last_updated_at = excluded.last_updated_at,
                    is_deleted = 0,
                    last_deleted_at = NULL
                """,
                (client_id, source_id, rel_path, size, mtime, sha256, now_iso, now_iso)
            )

    def mark_file_deleted(self, client_id: str, source_id: str, rel_path: str):
        """Mark a file as deleted from source (never deletes physical backup)."""
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                UPDATE file_catalog
                SET is_deleted = 1, last_deleted_at = ?
                WHERE client_id = ? AND source_id = ? AND rel_path = ?
                """,
                (now_iso, client_id, source_id, rel_path)
            )

    def record_run(
        self,
        client_id: str,
        run_date: str,
        run_timestamp: str,
        status: str,
        files_added: int,
        files_updated: int,
        files_deleted: int,
        dbs_dumped: int,
        total_incremental_bytes: int,
        duration_seconds: float,
        error_message: Optional[str] = None
    ):
        """Record the execution outcome of a backup run."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO backup_runs (
                    client_id, run_date, run_timestamp, status,
                    files_added, files_updated, files_deleted, dbs_dumped,
                    total_incremental_bytes, duration_seconds, error_message
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id, run_date, run_timestamp, status,
                    files_added, files_updated, files_deleted, dbs_dumped,
                    total_incremental_bytes, duration_seconds, error_message
                )
            )

    def get_run_history(self, client_id: str, limit: int = 15) -> List[Dict]:
        """Retrieve recent backup runs for a client."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT id, client_id, run_date, run_timestamp, status,
                       files_added, files_updated, files_deleted, dbs_dumped,
                       total_incremental_bytes, duration_seconds, error_message
                FROM backup_runs
                WHERE client_id = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (client_id, limit)
            )
            return [dict(row) for row in cur.fetchall()]
