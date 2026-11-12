"""Unit tests for SQLite State Catalog."""

import tempfile
from pathlib import Path
from backup_service.core.catalog import StateCatalog, FileChangeType


def test_catalog_lifecycle():
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_path = Path(tmp_dir) / "catalog.sqlite"
        catalog = StateCatalog(str(db_path))

        client_id = "test_client"
        source_id = "docs"

        # 1. Initially no active files
        active = catalog.get_active_files(client_id, source_id)
        assert len(active) == 0

        # 2. Add files
        catalog.record_file_addition_or_update(
            client_id=client_id,
            source_id=source_id,
            rel_path="readme.txt",
            size=100,
            mtime=123456.0,
            sha256="hash_1"
        )
        catalog.record_file_addition_or_update(
            client_id=client_id,
            source_id=source_id,
            rel_path="guide.pdf",
            size=2048,
            mtime=123457.0,
            sha256="hash_2"
        )

        active = catalog.get_active_files(client_id, source_id)
        assert len(active) == 2
        assert active["readme.txt"].sha256 == "hash_1"
        assert active["guide.pdf"].size == 2048

        # 3. Update a file
        catalog.record_file_addition_or_update(
            client_id=client_id,
            source_id=source_id,
            rel_path="readme.txt",
            size=120,
            mtime=123460.0,
            sha256="hash_1_updated"
        )
        active = catalog.get_active_files(client_id, source_id)
        assert active["readme.txt"].size == 120
        assert active["readme.txt"].sha256 == "hash_1_updated"

        # 4. Mark a file as deleted (Soft delete for non-destructive retention)
        catalog.mark_file_deleted(client_id, source_id, "guide.pdf")
        active = catalog.get_active_files(client_id, source_id)
        assert len(active) == 1
        assert "guide.pdf" not in active

        all_known = catalog.get_all_known_files(client_id, source_id)
        assert len(all_known) == 2
        assert all_known["guide.pdf"].is_deleted is True

        # 5. Revive deleted file if it reappears
        catalog.record_file_addition_or_update(
            client_id=client_id,
            source_id=source_id,
            rel_path="guide.pdf",
            size=2048,
            mtime=123500.0,
            sha256="hash_2_revived"
        )
        active = catalog.get_active_files(client_id, source_id)
        assert len(active) == 2
        assert active["guide.pdf"].is_deleted is False

        # 6. Test run history recording
        catalog.record_run(
            client_id=client_id,
            run_date="2026-11-12",
            run_timestamp="2026-11-12 10:00:00",
            status="SUCCESS",
            files_added=2,
            files_updated=1,
            files_deleted=1,
            dbs_dumped=1,
            total_incremental_bytes=50000,
            duration_seconds=1.25
        )
        history = catalog.get_run_history(client_id)
        assert len(history) == 1
        assert history[0]["status"] == "SUCCESS"
        assert history[0]["files_added"] == 2
