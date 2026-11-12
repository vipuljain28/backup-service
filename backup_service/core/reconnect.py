"""Existing Backup Archive Discovery & Reconnection Engine.

Allows a fresh software installation to scan a remote or local storage folder,
auto-discover all historical client archives, and reconstitute the disaster
recovery inventory with zero manual re-entry.
"""

import re
import json
import logging
from typing import Dict, Any, List
from backup_service.storage.base import StorageProvider
from backup_service.security.db import DatabaseManager

logger = logging.getLogger("backup_service.reconnect")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}")


class ArchiveReconnector:
    """Discovers and imports existing backup structures into local inventory."""

    def __init__(self, storage: StorageProvider, db: DatabaseManager):
        self.storage = storage
        self.db = db

    def scan_and_reconnect(self, storage_config_id: int) -> Dict[str, Any]:
        """Scan storage root, detect client folders, and populate local catalog."""
        logger.info("Starting storage scan to reconnect existing backup archives...")
        report = {
            "discovered_clients": 0,
            "imported_snapshots": 0,
            "details": []
        }

        # Step 1: List root directory children
        root_folder_id = self.storage.ensure_directory_path([])
        subdirs = self.storage.list_subdirectories(root_folder_id)

        if not subdirs:
            logger.info("No subdirectories found in storage root.")
            return report

        existing_clients = {c["client_id"]: c["id"] for c in self.db.list_clients()}

        for item in subdirs:
            client_candidate = item["name"]
            client_id = client_candidate.strip()

            # Ignore non-client folders
            if client_id.startswith(".") or client_id in ("temp", "staging", "logs"):
                continue

            # Verify client candidate has 'incremental' or 'master'
            child_folders = self.storage.list_subdirectories(item["id"])
            child_names = {c["name"]: c["id"] for c in child_folders}

            if "incremental" not in child_names and "master" not in child_names:
                continue

            logger.info("Discovered existing client archive folder: '%s'", client_id)

            # Ensure client exists in database
            if client_id not in existing_clients:
                display_name = client_id.replace("_", " ").title()
                db_client_id = self.db.create_client(
                    client_id=client_id,
                    display_name=display_name,
                    retention_days=10,
                    storage_config_id=storage_config_id
                )
                existing_clients[client_id] = db_client_id
                report["discovered_clients"] += 1
            else:
                db_client_id = existing_clients[client_id]

            client_snapshots = 0
            # Inspect incremental folder for date snapshots
            if "incremental" in child_names:
                inc_folder_id = child_names["incremental"]
                date_folders = self.storage.list_subdirectories(inc_folder_id)

                for df in date_folders:
                    d_name = df["name"]
                    if not DATE_PATTERN.match(d_name):
                        continue

                    # Record historical snapshot in backup_jobs if not already recorded
                    self.db.record_backup_job(
                        client_id=db_client_id,
                        trigger_type="imported",
                        status="success",
                        run_date=d_name[:10],
                        run_timestamp=f"{d_name[:10]} 00:00:00",
                        files_added=0,
                        files_updated=0,
                        files_deleted=0,
                        dbs_dumped=1,
                        total_bytes=0,
                        duration_seconds=0.0,
                        manifest_json=json.dumps({"imported_from": d_name})
                    )
                    client_snapshots += 1
                    report["imported_snapshots"] += 1

            report["details"].append({
                "client_id": client_id,
                "snapshots_imported": client_snapshots
            })

        logger.info(
            "Archive reconnection complete. Discovered %d clients and %d historical snapshots.",
            report["discovered_clients"], report["imported_snapshots"]
        )
        return report
