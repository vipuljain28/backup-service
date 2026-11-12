"""Backup Manifest Generator.

Generates comprehensive audit manifests (TXT and JSON) documenting:
- Added files
- Updated files
- Deleted files (highlighting non-destructive retention in backup master)
- Database full dumps
- Execution metadata and metrics
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, field


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable representation."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(num_bytes) < 1024.0:
            return f"{num_bytes:3.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


@dataclass
class FileChangeItem:
    source_id: str
    rel_path: str
    action: str  # ADDED, UPDATED, DELETED
    size: int
    old_size: int = 0
    sha256: str = ""


@dataclass
class DatabaseDumpItem:
    name: str
    engine: str
    db_name: str
    output_filename: str
    size_bytes: int


@dataclass
class ManifestReport:
    client_id: str
    client_display_name: str
    execution_date: str  # YYYY-MM-DD
    execution_timestamp: str
    connection_mode: str
    retention_days: int
    duration_seconds: float = 0.0
    databases: List[DatabaseDumpItem] = field(default_factory=list)
    changes: List[FileChangeItem] = field(default_factory=list)

    @property
    def added_count(self) -> int:
        return sum(1 for c in self.changes if c.action == "ADDED")

    @property
    def updated_count(self) -> int:
        return sum(1 for c in self.changes if c.action == "UPDATED")

    @property
    def deleted_count(self) -> int:
        return sum(1 for c in self.changes if c.action == "DELETED")

    @property
    def total_incremental_bytes(self) -> int:
        file_bytes = sum(c.size for c in self.changes if c.action in ("ADDED", "UPDATED"))
        db_bytes = sum(d.size_bytes for d in self.databases)
        return file_bytes + db_bytes

    def generate_txt(self) -> str:
        """Generate human-readable manifest text content."""
        lines = []
        lines.append("=" * 80)
        lines.append("ENTERPRISE BACKUP EXECUTION MANIFEST")
        lines.append(f"Client Identifier : {self.client_id} ({self.client_display_name})")
        lines.append(f"Execution Date    : {self.execution_date}")
        lines.append(f"Execution Time    : {self.execution_timestamp} UTC")
        lines.append(f"Connection Mode   : {self.connection_mode.upper()}")
        lines.append(f"Retention Policy  : {self.retention_days} Days (Incremental & Databases)")
        lines.append(f"Execution Time    : {self.duration_seconds:.2f} seconds")
        lines.append("=" * 80)
        lines.append("")
        lines.append("[SUMMARY METRICS]")
        lines.append(f"  * Total Files Added         : {self.added_count}")
        lines.append(f"  * Total Files Updated       : {self.updated_count}")
        lines.append(f"  * Total Files Deleted (Src) : {self.deleted_count} (PRESERVED IN MASTER BACKUP)")
        lines.append(f"  * Database Dumps Performed  : {len(self.databases)}")
        lines.append(f"  * Total Incremental Volume  : {format_bytes(self.total_incremental_bytes)}")
        lines.append("")
        lines.append("[DATABASE FULL BACKUPS]")
        if self.databases:
            for db in self.databases:
                size_str = format_bytes(db.size_bytes)
                lines.append(f"  + [{db.engine.upper()}] {db.name} (DB: {db.db_name}) -> {db.output_filename} ({size_str})")
        else:
            lines.append("  (No databases configured for this client)")
        lines.append("")

        lines.append("[FILE AUDIT LOG - DELTA CHANGES]")
        lines.append("NOTE: Deletions on source NEVER delete files from Google Drive backup master.")
        lines.append("-" * 80)

        if not self.changes:
            lines.append("  (No file changes detected since last backup)")
        else:
            for item in self.changes:
                size_str = format_bytes(item.size)
                prefix = f"[{item.source_id}] {item.rel_path}"
                if item.action == "ADDED":
                    lines.append(f"  + [ADDED]              {prefix} ({size_str})")
                elif item.action == "UPDATED":
                    old_str = format_bytes(item.old_size)
                    lines.append(f"  * [UPDATED]            {prefix} ({old_str} -> {size_str})")
                elif item.action == "DELETED":
                    lines.append(f"  - [DELETED IN SOURCE]  {prefix} ({size_str}) [RETAINED IN BACKUP MASTER]")

        lines.append("-" * 80)
        lines.append("=" * 80)
        lines.append("END OF MANIFEST")
        lines.append("=" * 80)
        return "\n".join(lines) + "\n"

    def generate_json(self) -> Dict[str, Any]:
        """Generate structured JSON representation."""
        return {
            "client_id": self.client_id,
            "client_display_name": self.client_display_name,
            "execution_date": self.execution_date,
            "execution_timestamp": self.execution_timestamp,
            "connection_mode": self.connection_mode,
            "retention_days": self.retention_days,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "files_added": self.added_count,
                "files_updated": self.updated_count,
                "files_deleted": self.deleted_count,
                "databases_dumped": len(self.databases),
                "total_incremental_bytes": self.total_incremental_bytes,
            },
            "databases": [
                {
                    "name": db.name,
                    "engine": db.engine,
                    "db_name": db.db_name,
                    "output_filename": db.output_filename,
                    "size_bytes": db.size_bytes,
                }
                for db in self.databases
            ],
            "file_changes": [
                {
                    "source_id": c.source_id,
                    "rel_path": c.rel_path,
                    "action": c.action,
                    "size": c.size,
                    "old_size": c.old_size,
                    "sha256": c.sha256,
                }
                for c in self.changes
            ],
        }

    def write_to_directory(self, target_dir: Path):
        """Write manifest.txt and manifest.json into the target directory."""
        target_dir = Path(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        txt_path = target_dir / "manifest.txt"
        json_path = target_dir / "manifest.json"

        txt_path.write_text(self.generate_txt(), encoding="utf-8")
        json_path.write_text(json.dumps(self.generate_json(), indent=2), encoding="utf-8")
