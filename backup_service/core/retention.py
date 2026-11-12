"""Retention Policy Engine.

Enforces sliding-window retention (default: 10 days) across date-wise
incremental folders in Google Drive / Storage, purging expired snapshots
and their enclosed database full dumps while strictly preserving the master archive.
"""

import re
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from backup_service.storage.base import StorageProvider

logger = logging.getLogger("backup_service.retention")

DATE_FOLDER_REGEX = re.compile(r"^(\d{4}-\d{2}-\d{2})(?:[T_](\d{2}-?\d{2}-?\d{2}))?$")


class RetentionManager:
    """Manages pruning of expired incremental and database backups."""

    def __init__(self, storage: StorageProvider):
        self.storage = storage

    def enforce_client_retention(
        self,
        client_id: str,
        retention_days: int = 10,
        dry_run: bool = False
    ) -> List[Dict[str, Any]]:
        """Evaluate and purge incremental date folders older than retention_days.
        
        Returns a list of purged folder details.
        """
        logger.info(
            "Evaluating retention policy for client '%s' (Window: %d days)...",
            client_id, retention_days
        )

        # 1. Resolve incremental root directory ID for client
        try:
            inc_folder_id = self.storage.ensure_directory_path([client_id, "incremental"])
        except Exception as exc:
            logger.error("Could not access incremental folder for client '%s': %s", client_id, exc)
            return []

        # 2. List all subdirectories inside incremental/
        subdirs = self.storage.list_subdirectories(inc_folder_id)
        if not subdirs:
            logger.info("No incremental folders found for client '%s'.", client_id)
            return []

        today = datetime.now(timezone.utc).date()
        cutoff_date = today - timedelta(days=retention_days)
        logger.info("Retention cutoff date: %s (Folders strictly older than this will be purged)", cutoff_date)

        purged_records = []

        for folder in subdirs:
            folder_name = folder["name"]
            folder_id = folder["id"]

            match = DATE_FOLDER_REGEX.match(folder_name)
            if not match:
                logger.debug("Skipping non-date folder in incremental: '%s'", folder_name)
                continue

            folder_date_str = match.group(1)
            try:
                folder_date = datetime.strptime(folder_date_str, "%Y-%m-%d").date()
            except ValueError:
                logger.warning("Invalid date format in folder name: '%s'", folder_name)
                continue

            age_days = (today - folder_date).days

            if folder_date < cutoff_date:
                logger.info(
                    "Expired snapshot detected: '%s' (Age: %d days > %d days cutoff)",
                    folder_name, age_days, retention_days
                )

                if dry_run:
                    logger.info("[DRY RUN] Would purge expired remote folder: %s", folder_name)
                    purged_records.append({
                        "name": folder_name,
                        "id": folder_id,
                        "age_days": age_days,
                        "status": "DRY_RUN_PURGED"
                    })
                else:
                    success = self.storage.delete_directory(folder_id)
                    if success:
                        logger.info("Successfully purged expired folder: %s", folder_name)
                        purged_records.append({
                            "name": folder_name,
                            "id": folder_id,
                            "age_days": age_days,
                            "status": "PURGED"
                        })
                    else:
                        logger.error("Failed to purge expired folder: %s", folder_name)
                        purged_records.append({
                            "name": folder_name,
                            "id": folder_id,
                            "age_days": age_days,
                            "status": "FAILED"
                        })
            else:
                logger.debug("Folder '%s' retained (Age: %d days <= %d days)", folder_name, age_days, retention_days)

        logger.info(
            "Retention enforcement completed for client '%s'. Total purged: %d",
            client_id, len([r for r in purged_records if r.get("status") in ("PURGED", "DRY_RUN_PURGED")])
        )
        return purged_records
