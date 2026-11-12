"""Unit tests for Retention Management."""

import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from backup_service.storage.local_storage import LocalStorageProvider
from backup_service.core.retention import RetentionManager


def test_retention_sliding_window():
    with tempfile.TemporaryDirectory() as tmp_dir:
        storage = LocalStorageProvider(tmp_dir)
        retention = RetentionManager(storage)
        client_id = "test_client"

        today = datetime.now(timezone.utc).date()
        date_today_str = today.strftime("%Y-%m-%d")
        date_5d_str = (today - timedelta(days=5)).strftime("%Y-%m-%d")
        date_11d_str = (today - timedelta(days=11)).strftime("%Y-%m-%d")
        date_20d_str = (today - timedelta(days=20)).strftime("%Y-%m-%d")

        # Create folders
        storage.ensure_directory_path([client_id, "incremental", date_today_str])
        storage.ensure_directory_path([client_id, "incremental", date_5d_str])
        storage.ensure_directory_path([client_id, "incremental", date_11d_str])
        storage.ensure_directory_path([client_id, "incremental", date_20d_str])
        # Create master folder (MUST NEVER BE PURGED)
        storage.ensure_directory_path([client_id, "master", "files"])

        # Enforce 10-day retention
        purged = retention.enforce_client_retention(client_id, retention_days=10, dry_run=False)

        purged_names = {p["name"] for p in purged if p["status"] == "PURGED"}
        assert date_11d_str in purged_names
        assert date_20d_str in purged_names
        assert date_5d_str not in purged_names
        assert date_today_str not in purged_names

        # Verify filesystem state
        inc_root = Path(tmp_dir) / client_id / "incremental"
        assert (inc_root / date_today_str).exists()
        assert (inc_root / date_5d_str).exists()
        assert not (inc_root / date_11d_str).exists()
        assert not (inc_root / date_20d_str).exists()

        # Master folder MUST exist
        assert (Path(tmp_dir) / client_id / "master" / "files").exists()
