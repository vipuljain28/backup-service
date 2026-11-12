"""End-to-end integration test of the Backup Service."""

import os
import tempfile
import time
from pathlib import Path
from backup_service.config.settings import (
    AppConfig, ClientConfig, FileSourceConfig
)
from backup_service.core.orchestrator import BackupOrchestrator


def test_full_backup_cycle_and_non_destructive_sync():
    with tempfile.TemporaryDirectory() as tmp_root:
        base_dir = Path(tmp_root)
        source_dir = base_dir / "client_source_data"
        source_dir.mkdir(parents=True, exist_ok=True)

        backup_storage_dir = base_dir / "cloud_storage"
        staging_dir = base_dir / "temp_staging"
        catalog_path = base_dir / "catalog.sqlite"

        # Create initial files in source
        file1 = source_dir / "document.pdf"
        file1.write_text("Original document content", encoding="utf-8")

        file2 = source_dir / "notes.txt"
        file2.write_text("Daily notes content", encoding="utf-8")

        nested_dir = source_dir / "subfolder"
        nested_dir.mkdir()
        file3 = nested_dir / "data.csv"
        file3.write_text("id,val\n1,100", encoding="utf-8")

        # Build AppConfig
        client_cfg = ClientConfig(
            client_id="test_tenant",
            display_name="Test Tenant Lab",
            connection_mode="local",
            retention_days=10,
            file_sources=[
                FileSourceConfig(id="primary_files", path=str(source_dir))
            ],
            databases=[]
        )

        app_cfg = AppConfig(
            storage_provider="local",
            local_storage_root=str(backup_storage_dir),
            staging_dir=str(staging_dir),
            catalog_db_path=str(catalog_path),
            clients=[client_cfg]
        )

        orchestrator = BackupOrchestrator(app_cfg)

        # ----------------------------------------------------------------------
        # RUN 1: Baseline / Starter run
        # ----------------------------------------------------------------------
        report1 = orchestrator.run_backup_for_client(client_cfg)
        assert report1.added_count == 3
        assert report1.updated_count == 0
        assert report1.deleted_count == 0

        # Verify Master folder has all 3 files
        master_files = backup_storage_dir / "test_tenant" / "master" / "files" / "primary_files"
        assert (master_files / "document.pdf").exists()
        assert (master_files / "notes.txt").exists()
        assert (master_files / "subfolder" / "data.csv").exists()

        # Verify Incremental folder for today has all 3 files + manifest
        today_str = report1.execution_date
        inc_files = backup_storage_dir / "test_tenant" / "incremental" / today_str / "files" / "primary_files"
        assert (inc_files / "document.pdf").exists()
        assert (inc_files / "notes.txt").exists()

        inc_manifest = backup_storage_dir / "test_tenant" / "incremental" / today_str / "manifest.txt"
        assert inc_manifest.exists()
        manifest_text = inc_manifest.read_text(encoding="utf-8")
        assert "+ [ADDED]" in manifest_text

        # ----------------------------------------------------------------------
        # RUN 2: No modifications (Idempotency test)
        # ----------------------------------------------------------------------
        report2 = orchestrator.run_backup_for_client(client_cfg)
        assert report2.added_count == 0
        assert report2.updated_count == 0
        assert report2.deleted_count == 0

        # ----------------------------------------------------------------------
        # RUN 3: Modifications, Additions, and Deletions
        # ----------------------------------------------------------------------
        time.sleep(1.1)  # Ensure mtime timestamp progresses

        # 1. Update notes.txt
        file2.write_text("Daily notes content UPDATED with new data", encoding="utf-8")

        # 2. Add new file
        file4 = source_dir / "new_report.docx"
        file4.write_text("Quarterly audit report", encoding="utf-8")

        # 3. Delete document.pdf from source
        file1.unlink()

        report3 = orchestrator.run_backup_for_client(client_cfg)
        assert report3.added_count == 1      # new_report.docx
        assert report3.updated_count == 1    # notes.txt
        assert report3.deleted_count == 1    # document.pdf

        # CRITICAL TEST: Verify document.pdf is STILL PRESERVED in master!
        # (Requirement: "backup will not delte file it creates a txt for all the updated added and deleted file so it will add and updte file but do not delete it from bacup")
        assert (master_files / "document.pdf").exists(), "Deleted file MUST NOT be deleted from master backup!"
        assert (master_files / "notes.txt").read_text(encoding="utf-8") == "Daily notes content UPDATED with new data"
        assert (master_files / "new_report.docx").exists()

        # Check latest manifest
        latest_manifest_text = inc_manifest.read_text(encoding="utf-8")
        assert "- [DELETED IN SOURCE]" in latest_manifest_text
        assert "[RETAINED IN BACKUP MASTER]" in latest_manifest_text
        assert "* [UPDATED]" in latest_manifest_text
        assert "+ [ADDED]" in latest_manifest_text
