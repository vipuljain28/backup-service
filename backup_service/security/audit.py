"""Security Audit Logging Subsystem."""

import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any


class AuditLogger:
    """Immutable audit trail writer."""

    def __init__(self, db_manager):
        self.db = db_manager

    def log(
        self,
        action: str,
        user_id: Optional[int] = None,
        username: Optional[str] = "system",
        ip_address: Optional[str] = "127.0.0.1",
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        status: str = "SUCCESS",
        details: Optional[Dict[str, Any]] = None
    ):
        """Append an immutable audit entry."""
        now_iso = datetime.now(timezone.utc).isoformat()
        details_str = json.dumps(details or {}, separators=(",", ":"))

        with self.db.connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_logs (
                    user_id, username, ip_address, action, resource_type,
                    resource_id, status, details_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id, username, ip_address, action, resource_type,
                    resource_id, status, details_str, now_iso
                )
            )
