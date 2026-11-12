"""Unit tests for Manifest Generation."""

import tempfile
from pathlib import Path
from backup_service.core.manifest import (
    ManifestReport, FileChangeItem, DatabaseDumpItem
)


def test_manifest_formatting():
    manifest = ManifestReport(
        client_id="client_test",
        client_display_name="Test Enterprise Client",
        execution_date="2026-11-12",
        execution_timestamp="2026-11-12 10:00:00",
        connection_mode="local",
        retention_days=10,
        duration_seconds=2.45
    )

    manifest.databases.append(DatabaseDumpItem(
        name="primary_db",
        engine="mysql",
        db_name="starcalibration",
        output_filename="primary_db_2026-11-12.sql.gz",
        size_bytes=1048576  # 1 MB
    ))

    manifest.changes.append(FileChangeItem(
        source_id="uploads",
        rel_path="certs/cert_101.pdf",
        action="ADDED",
        size=512000,
        sha256="abc123"
    ))

    manifest.changes.append(FileChangeItem(
        source_id="uploads",
        rel_path="configs/settings.json",
        action="UPDATED",
        size=4096,
        old_size=2048,
        sha256="def456"
    ))

    manifest.changes.append(FileChangeItem(
        source_id="uploads",
        rel_path="old/deprecated.csv",
        action="DELETED",
        size=8192,
        sha256="ghi789"
    ))

    txt = manifest.generate_txt()
    assert "ENTERPRISE BACKUP EXECUTION MANIFEST" in txt
    assert "Total Files Added         : 1" in txt
    assert "Total Files Updated       : 1" in txt
    assert "Total Files Deleted (Src) : 1 (PRESERVED IN MASTER BACKUP)" in txt
    assert "+ [ADDED]" in txt
    assert "* [UPDATED]" in txt
    assert "- [DELETED IN SOURCE]" in txt
    assert "[RETAINED IN BACKUP MASTER]" in txt

    with tempfile.TemporaryDirectory() as tmp_dir:
        out_path = Path(tmp_dir)
        manifest.write_to_directory(out_path)
        assert (out_path / "manifest.txt").exists()
        assert (out_path / "manifest.json").exists()
