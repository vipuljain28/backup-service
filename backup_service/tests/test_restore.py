"""Unit tests for Disaster Recovery & Reconnection Engine."""

import tempfile
from pathlib import Path
from backup_service.storage.local_storage import LocalStorageProvider
from backup_service.security.db import DatabaseManager
from backup_service.core.reconnect import ArchiveReconnector
from backup_service.core.restore import RestorationEngine


def test_archive_reconnection_and_restore():
    with tempfile.TemporaryDirectory() as storage_root, tempfile.TemporaryDirectory() as db_root:
        storage = LocalStorageProvider(storage_root)
        db_path = Path(db_root) / "metadata.sqlite"
        db = DatabaseManager(str(db_path))

        # Save a valid storage config to satisfy foreign key constraints
        cfg_id = db.save_storage_config(
            name="Test Local Storage",
            provider_type="local",
            encrypted_credentials="v1:test:test:test",
            is_default=True
        )

        # 1. Simulate existing cloud storage structure
        # {storage_root}/client_phoenix/master/files/
        # {storage_root}/client_phoenix/incremental/2026-11-10/
        storage.ensure_directory_path(["client_phoenix", "master", "files"])
        storage.ensure_directory_path(["client_phoenix", "incremental", "2026-11-10"])

        # 2. Reconnect
        reconnector = ArchiveReconnector(storage, db)
        report = reconnector.scan_and_reconnect(storage_config_id=cfg_id)

        assert report["discovered_clients"] == 1
        assert report["imported_snapshots"] == 1

        # Verify client is now present in DB
        clients = db.list_clients()
        client_ids = [c["client_id"] for c in clients]
        assert "client_phoenix" in client_ids

        # 3. Test Restoration Engine
        restore_engine = RestorationEngine(storage, staging_dir=str(Path(db_root) / "temp_restore"))
        result = restore_engine.execute_restore(
            client_id="client_phoenix",
            snapshot_date="2026-11-10",
            target_mode="local",
            target_file_directory=str(Path(db_root) / "restored_phoenix"),
            restore_scope="files_only"
        )
        assert result["status"] == "SUCCESS"
