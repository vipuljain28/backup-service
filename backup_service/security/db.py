"""Relational Metadata Database Manager & Repository."""

import sqlite3
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from contextlib import contextmanager

from backup_service.security.auth import hash_password, Role


class DatabaseManager:
    """SQLite Database Manager for Application State, Configurations, and Inventory."""

    def __init__(self, db_path: str = "./metadata.sqlite"):
        self.db_path = Path(db_path).resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def connection(self):
        """Context manager yielding SQLite connection with WAL mode and strict closing."""
        conn = sqlite3.connect(str(self.db_path), timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self):
        with self.connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'operator',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS storage_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    provider_type TEXT NOT NULL, -- 'gdrive', 'onedrive', 'local', 's3_terabox'
                    encrypted_credentials TEXT NOT NULL,
                    is_default INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS clients (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT UNIQUE NOT NULL,
                    display_name TEXT NOT NULL,
                    retention_days INTEGER NOT NULL DEFAULT 10,
                    storage_config_id INTEGER REFERENCES storage_configs(id) ON DELETE SET NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS server_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    mode TEXT NOT NULL DEFAULT 'local', -- 'local' or 'ssh'
                    host TEXT,
                    port INTEGER DEFAULT 22,
                    username TEXT,
                    auth_type TEXT, -- 'password', 'key_file', 'key_text'
                    encrypted_secret TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS database_targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
                    server_id INTEGER REFERENCES server_connections(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    engine TEXT NOT NULL DEFAULT 'mysql', -- 'mysql', 'mariadb', 'postgres'
                    host TEXT DEFAULT '127.0.0.1',
                    port INTEGER DEFAULT 3306,
                    username TEXT DEFAULT 'root',
                    encrypted_password TEXT,
                    db_name TEXT NOT NULL,
                    ssl_enabled INTEGER NOT NULL DEFAULT 0,
                    ssl_options TEXT, -- JSON
                    dump_options TEXT, -- JSON array
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS folder_sources (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
                    server_id INTEGER REFERENCES server_connections(id) ON DELETE CASCADE,
                    source_slug TEXT NOT NULL,
                    absolute_path TEXT NOT NULL,
                    exclude_patterns TEXT, -- JSON array
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS backup_schedules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    cron_expression TEXT NOT NULL, -- e.g. '0 2 * * *'
                    is_enabled INTEGER NOT NULL DEFAULT 1,
                    last_run_at TEXT,
                    next_run_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS backup_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
                    trigger_type TEXT NOT NULL, -- 'manual' or 'scheduled'
                    status TEXT NOT NULL, -- 'running', 'success', 'failed', 'partial'
                    run_date TEXT NOT NULL,
                    run_timestamp TEXT NOT NULL,
                    files_added INTEGER DEFAULT 0,
                    files_updated INTEGER DEFAULT 0,
                    files_deleted INTEGER DEFAULT 0,
                    dbs_dumped INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    duration_seconds REAL DEFAULT 0.0,
                    manifest_json TEXT,
                    error_message TEXT,
                    is_dry_run INTEGER DEFAULT 0,
                    execution_logs TEXT,
                    storage_location TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS restore_jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_job_id INTEGER REFERENCES backup_jobs(id) ON DELETE SET NULL,
                    client_id INTEGER REFERENCES clients(id) ON DELETE CASCADE,
                    target_server_id INTEGER REFERENCES server_connections(id) ON DELETE SET NULL,
                    target_path TEXT,
                    target_db_name TEXT,
                    restore_scope TEXT NOT NULL DEFAULT 'all', -- 'all', 'files_only', 'db_only'
                    status TEXT NOT NULL DEFAULT 'pending', -- 'pending', 'running', 'success', 'failed'
                    execution_logs TEXT,
                    created_at TEXT NOT NULL,
                    completed_at TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    ip_address TEXT,
                    action TEXT NOT NULL,
                    resource_type TEXT,
                    resource_id TEXT,
                    status TEXT NOT NULL,
                    details_json TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_logs(created_at);
                CREATE INDEX IF NOT EXISTS idx_jobs_client ON backup_jobs(client_id, run_date);
            """)

            # Safe auto-migration for legacy schema instances
            try:
                conn.execute("ALTER TABLE backup_jobs ADD COLUMN is_dry_run INTEGER DEFAULT 0")
            except Exception:
                pass

            try:
                conn.execute("ALTER TABLE backup_jobs ADD COLUMN execution_logs TEXT")
            except Exception:
                pass

            try:
                conn.execute("ALTER TABLE backup_jobs ADD COLUMN storage_location TEXT")
            except Exception:
                pass

            # Seed default admin user if no users exist
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM users")
            if cur.fetchone()["cnt"] == 0:
                now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
                initial_pass_hash = hash_password("admin@STAR2026!")
                conn.execute(
                    """
                    INSERT INTO users (username, email, password_hash, role, is_active, must_change_password, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("admin", "admin@starcalibration.local", initial_pass_hash, Role.ADMIN, 1, 1, now_iso, now_iso)
                )

    # --------------------------------------------------------------------------
    # Users API
    # --------------------------------------------------------------------------
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT id, username, email, role, is_active, created_at, updated_at FROM users ORDER BY id ASC")
            return [dict(row) for row in cur.fetchall()]

    def create_user(self, username: str, email: str, password_hash: str, role: str) -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO users (username, email, password_hash, role, is_active, must_change_password, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, 0, ?, ?)
                """,
                (username, email, password_hash, role, now_iso, now_iso)
            )
            return cur.lastrowid

    # --------------------------------------------------------------------------
    # Storage Configs API
    # --------------------------------------------------------------------------
    def list_storage_configs(self) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT id, name, provider_type, is_default, created_at FROM storage_configs ORDER BY id ASC")
            return [dict(row) for row in cur.fetchall()]

    def get_storage_config(self, config_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT * FROM storage_configs WHERE id = ?", (config_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def save_storage_config(self, name: str, provider_type: str, encrypted_credentials: str, is_default: bool = False) -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            if is_default:
                conn.execute("UPDATE storage_configs SET is_default = 0")
            cur = conn.execute(
                """
                INSERT INTO storage_configs (name, provider_type, encrypted_credentials, is_default, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (name, provider_type, encrypted_credentials, int(is_default), now_iso, now_iso)
            )
            return cur.lastrowid

    # --------------------------------------------------------------------------
    # Clients & Nested Resources API
    # --------------------------------------------------------------------------
    def list_clients(self) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                """
                SELECT c.*, s.name AS storage_name, s.provider_type AS storage_provider
                FROM clients c
                LEFT JOIN storage_configs s ON c.storage_config_id = s.id
                ORDER BY c.id ASC
                """
            )
            clients = [dict(row) for row in cur.fetchall()]
            for c in clients:
                cid = c["id"]
                c["servers"] = [dict(r) for r in conn.execute("SELECT * FROM server_connections WHERE client_id = ? ORDER BY id ASC", (cid,)).fetchall()]
                c["databases"] = [dict(r) for r in conn.execute(
                    """
                    SELECT d.*, s.name AS server_name, s.mode AS server_mode, s.host AS server_host
                    FROM database_targets d
                    LEFT JOIN server_connections s ON d.server_id = s.id
                    WHERE d.client_id = ?
                    ORDER BY d.id ASC
                    """, (cid,)).fetchall()]
                c["folders"] = [dict(r) for r in conn.execute(
                    """
                    SELECT f.*, s.name AS server_name, s.mode AS server_mode, s.host AS server_host
                    FROM folder_sources f
                    LEFT JOIN server_connections s ON f.server_id = s.id
                    WHERE f.client_id = ?
                    ORDER BY f.id ASC
                    """, (cid,)).fetchall()]
                c["schedules"] = [dict(r) for r in conn.execute("SELECT * FROM backup_schedules WHERE client_id = ? ORDER BY id ASC", (cid,)).fetchall()]
            return clients

    def get_client(self, client_id_num: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT * FROM clients WHERE id = ?", (client_id_num,))
            row = cur.fetchone()
            if not row:
                return None
            client_dict = dict(row)
            # Attach children
            client_dict["servers"] = [dict(r) for r in conn.execute("SELECT * FROM server_connections WHERE client_id = ?", (client_id_num,)).fetchall()]
            client_dict["databases"] = [dict(r) for r in conn.execute(
                """
                SELECT d.*, s.name AS server_name, s.mode AS server_mode, s.host AS server_host
                FROM database_targets d
                LEFT JOIN server_connections s ON d.server_id = s.id
                WHERE d.client_id = ?
                ORDER BY d.id ASC
                """, (client_id_num,)).fetchall()]
            client_dict["folders"] = [dict(r) for r in conn.execute(
                """
                SELECT f.*, s.name AS server_name, s.mode AS server_mode, s.host AS server_host
                FROM folder_sources f
                LEFT JOIN server_connections s ON f.server_id = s.id
                WHERE f.client_id = ?
                ORDER BY f.id ASC
                """, (client_id_num,)).fetchall()]
            client_dict["schedules"] = [dict(r) for r in conn.execute("SELECT * FROM backup_schedules WHERE client_id = ?", (client_id_num,)).fetchall()]
            return client_dict

    def create_client(self, client_id: str, display_name: str, retention_days: int = 10, storage_config_id: Optional[int] = None) -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO clients (client_id, display_name, retention_days, storage_config_id, is_active, created_at, updated_at)
                VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (client_id, display_name, retention_days, storage_config_id, now_iso, now_iso)
            )
            return cur.lastrowid

    def add_server_connection(self, client_id: int, name: str, mode: str, host: str, port: int, username: str, auth_type: str, encrypted_secret: str) -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO server_connections (client_id, name, mode, host, port, username, auth_type, encrypted_secret, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (client_id, name, mode, host, port, username, auth_type, encrypted_secret, now_iso)
            )
            return cur.lastrowid

    def add_database_target(self, client_id: int, server_id: int, name: str, engine: str, host: str, port: int, username: str, encrypted_password: str, db_name: str, ssl_enabled: bool, dump_options: str = "[]") -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO database_targets (client_id, server_id, name, engine, host, port, username, encrypted_password, db_name, ssl_enabled, dump_options, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (client_id, server_id, name, engine, host, port, username, encrypted_password, db_name, int(ssl_enabled), dump_options, now_iso)
            )
            return cur.lastrowid

    def add_folder_source(self, client_id: int, server_id: int, source_slug: str, absolute_path: str, exclude_patterns: str = "[]") -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO folder_sources (client_id, server_id, source_slug, absolute_path, exclude_patterns, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (client_id, server_id, source_slug, absolute_path, exclude_patterns, now_iso)
            )
            return cur.lastrowid

    def get_database_target(self, db_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT d.*, s.name AS server_name, s.mode AS server_mode, s.host AS server_host,
                       s.port AS server_port, s.username AS server_username, s.auth_type AS server_auth_type,
                       s.encrypted_secret AS server_encrypted_secret
                FROM database_targets d
                LEFT JOIN server_connections s ON d.server_id = s.id
                WHERE d.id = ?
                """, (db_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_database_target(self, db_id: int, client_id: int, server_id: int, name: str, engine: str, host: str, port: int, username: str, encrypted_password: Optional[str], db_name: str, ssl_enabled: bool) -> bool:
        with self.connection() as conn:
            if encrypted_password is not None and encrypted_password != "":
                conn.execute(
                    """
                    UPDATE database_targets SET
                        server_id = ?, name = ?, engine = ?, host = ?, port = ?,
                        username = ?, encrypted_password = ?, db_name = ?, ssl_enabled = ?
                    WHERE id = ? AND client_id = ?
                    """,
                    (server_id, name, engine, host, port, username, encrypted_password, db_name, int(ssl_enabled), db_id, client_id)
                )
            else:
                conn.execute(
                    """
                    UPDATE database_targets SET
                        server_id = ?, name = ?, engine = ?, host = ?, port = ?,
                        username = ?, db_name = ?, ssl_enabled = ?
                    WHERE id = ? AND client_id = ?
                    """,
                    (server_id, name, engine, host, port, username, db_name, int(ssl_enabled), db_id, client_id)
                )
            return True

    def get_folder_source(self, folder_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            row = conn.execute(
                """
                SELECT f.*, s.name AS server_name, s.mode AS server_mode, s.host AS server_host,
                       s.port AS server_port, s.username AS server_username, s.auth_type AS server_auth_type,
                       s.encrypted_secret AS server_encrypted_secret
                FROM folder_sources f
                LEFT JOIN server_connections s ON f.server_id = s.id
                WHERE f.id = ?
                """, (folder_id,)
            ).fetchone()
            return dict(row) if row else None

    def update_folder_source(self, folder_id: int, client_id: int, server_id: int, source_slug: str, absolute_path: str, exclude_patterns: str = "[]") -> bool:
        with self.connection() as conn:
            conn.execute(
                """
                UPDATE folder_sources SET
                    server_id = ?, source_slug = ?, absolute_path = ?, exclude_patterns = ?
                WHERE id = ? AND client_id = ?
                """,
                (server_id, source_slug, absolute_path, exclude_patterns, folder_id, client_id)
            )
            return True

    # --------------------------------------------------------------------------
    # Jobs & Restores API
    # --------------------------------------------------------------------------
    def record_backup_job(
        self,
        client_id: int,
        trigger_type: str,
        status: str,
        run_date: str,
        run_timestamp: str,
        files_added: int = 0,
        files_updated: int = 0,
        files_deleted: int = 0,
        dbs_dumped: int = 0,
        total_bytes: int = 0,
        duration_seconds: float = 0.0,
        manifest_json: str = "{}",
        error_message: str = None,
        is_dry_run: int = 0,
        execution_logs: str = "",
        storage_location: str = ""
    ) -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO backup_jobs (
                    client_id, trigger_type, status, run_date, run_timestamp,
                    files_added, files_updated, files_deleted, dbs_dumped,
                    total_bytes, duration_seconds, manifest_json, error_message,
                    is_dry_run, execution_logs, storage_location, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id, trigger_type, status, run_date, run_timestamp,
                    files_added, files_updated, files_deleted, dbs_dumped,
                    total_bytes, duration_seconds, manifest_json, error_message,
                    is_dry_run, execution_logs, storage_location, now_iso
                )
            )
            return cur.lastrowid

    def update_backup_job_logs(self, job_id: int, logs: str):
        with self.connection() as conn:
            conn.execute("UPDATE backup_jobs SET execution_logs = ? WHERE id = ?", (logs, job_id))

    def get_backup_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                """
                SELECT j.*, c.client_id AS client_slug, c.display_name AS client_name
                FROM backup_jobs j
                JOIN clients c ON j.client_id = c.id
                WHERE j.id = ?
                """,
                (job_id,)
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def list_backup_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                """
                SELECT j.*, c.client_id AS client_slug, c.display_name AS client_name
                FROM backup_jobs j
                JOIN clients c ON j.client_id = c.id
                ORDER BY j.id DESC LIMIT ?
                """,
                (limit,)
            )
            return [dict(row) for row in cur.fetchall()]

    def record_restore_job(self, backup_job_id: int, client_id: int, target_server_id: Optional[int], target_path: str, target_db_name: str, restore_scope: str = "all") -> int:
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO restore_jobs (
                    backup_job_id, client_id, target_server_id, target_path,
                    target_db_name, restore_scope, status, execution_logs, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, 'running', '', ?)
                """,
                (backup_job_id, client_id, target_server_id, target_path, target_db_name, restore_scope, now_iso)
            )
            return cur.lastrowid

    def update_restore_job(self, job_id: int, status: str, logs: str):
        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
        with self.connection() as conn:
            conn.execute(
                "UPDATE restore_jobs SET status = ?, execution_logs = ?, completed_at = ? WHERE id = ?",
                (status, logs, now_iso, job_id)
            )

    def list_all_servers(self) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                """
                SELECT s.*, c.display_name AS client_name, c.client_id AS client_slug
                FROM server_connections s
                LEFT JOIN clients c ON s.client_id = c.id
                ORDER BY s.id DESC
                """
            )
            return [dict(row) for row in cur.fetchall()]

    def get_server(self, server_id: int) -> Optional[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute("SELECT * FROM server_connections WHERE id = ?", (server_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def list_restore_jobs(self, limit: int = 30) -> List[Dict[str, Any]]:
        with self.connection() as conn:
            cur = conn.execute(
                """
                SELECT r.*, c.display_name AS client_name,
                       s.name AS target_server_name, s.host AS target_server_host, s.mode AS target_server_mode
                FROM restore_jobs r
                JOIN clients c ON r.client_id = c.id
                LEFT JOIN server_connections s ON r.target_server_id = s.id
                ORDER BY r.id DESC LIMIT ?
                """,
                (limit,)
            )
            return [dict(row) for row in cur.fetchall()]
