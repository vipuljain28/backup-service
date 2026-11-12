"""Central Backup Orchestrator.

Coordinates database extraction, file delta scanning, non-destructive staging,
Google Drive synchronization, and retention policy enforcement.
"""

import os
import time
import shutil
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any

from backup_service.config.settings import AppConfig, ClientConfig
from backup_service.core.catalog import StateCatalog
from backup_service.core.manifest import (
    ManifestReport, FileChangeItem, DatabaseDumpItem
)
from backup_service.core.retention import RetentionManager
from backup_service.drivers import get_source_driver
from backup_service.storage import get_storage_provider

logger = logging.getLogger("backup_service.orchestrator")


def calculate_sha256(file_path: Path) -> str:
    """Compute SHA-256 checksum in 64KB chunks."""
    h = hashlib.sha256()
    with open(str(file_path), "rb") as f:
        while chunk := f.read(64 * 1024):
            h.update(chunk)
    return h.hexdigest()


class BackupOrchestrator:
    """Enterprise backup orchestrator managing multi-tenant lifecycle."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.catalog = StateCatalog(config.catalog_db_path)
        self.storage = get_storage_provider(config)
        self.retention = RetentionManager(self.storage)

    def verify_all_connections(self) -> Dict[str, Any]:
        """Verify storage backend and connectivity for all configured clients."""
        report = {
            "storage_provider": self.config.storage_provider,
            "storage_connected": False,
            "clients": {}
        }

        logger.info("Testing storage connection for provider '%s'...", self.config.storage_provider)
        report["storage_connected"] = self.storage.verify_connection()

        for client in self.config.clients:
            logger.info("Testing connectivity for client '%s' (%s)...", client.client_id, client.connection_mode)
            driver = get_source_driver(client)
            try:
                ok = driver.test_connection()
                report["clients"][client.client_id] = {
                    "mode": client.connection_mode,
                    "connected": ok,
                    "databases": len(client.databases),
                    "file_sources": len(client.file_sources),
                }
            except Exception as exc:
                logger.error("Connection failed for client '%s': %s", client.client_id, exc)
                report["clients"][client.client_id] = {
                    "mode": client.connection_mode,
                    "connected": False,
                    "error": str(exc)
                }
            finally:
                driver.close()

        return report

    def run_backup_for_client(
        self,
        client: ClientConfig,
        dry_run: bool = False
    ) -> ManifestReport:
        """Execute complete backup cycle for a single client."""
        start_time = time.time()
        now_utc = datetime.now(timezone.utc)
        run_date = now_utc.strftime("%Y-%m-%d")
        run_time_str = now_utc.strftime("%H%M%S")
        timestamp_full = now_utc.strftime("%Y-%m-%d %H:%M:%S")

        logger.info(
            "=== Starting Backup: %s (%s) [Mode: %s, Retention: %d days] ===",
            client.display_name, client.client_id, client.connection_mode, client.retention_days
        )

        staging_root = Path(self.config.staging_dir).resolve() / f"{client.client_id}_{run_date}_{run_time_str}"
        staging_inc_dir = staging_root / "incremental"
        staging_inc_db_dir = staging_inc_dir / "database"
        staging_inc_files_dir = staging_inc_dir / "files"
        staging_master_files_dir = staging_root / "master" / "files"

        manifest = ManifestReport(
            client_id=client.client_id,
            client_display_name=client.display_name,
            execution_date=run_date,
            execution_timestamp=timestamp_full,
            connection_mode=client.connection_mode,
            retention_days=client.retention_days
        )

        driver = get_source_driver(client)

        try:
            logger.info("Connecting to source host (%s)...", client.connection_mode.upper())
            if not driver.test_connection():
                raise ConnectionError(f"Failed to establish connection to source host ({client.connection_mode.upper()})")

            # ------------------------------------------------------------------
            # Phase 1: Database Full Dumps & Verification
            # ------------------------------------------------------------------
            if client.databases:
                logger.info("Phase 1: Validating & dumping %d database(s)...", len(client.databases))
                for db in client.databases:
                    db_filename = f"{db.name}_{run_date}_{run_time_str}.sql.gz"
                    local_dump_target = staging_inc_db_dir / db_filename

                    if dry_run:
                        logger.info("[DRY RUN] Verifying credentials & connectivity to database '%s' (DB: %s)...", db.name, db.db_name)
                        driver.verify_database_access(db)
                        manifest.databases.append(DatabaseDumpItem(
                            name=db.name,
                            engine=db.engine,
                            db_name=db.db_name,
                            output_filename=db_filename,
                            size_bytes=0
                        ))
                    else:
                        size_bytes = driver.dump_database(db, local_dump_target)
                        manifest.databases.append(DatabaseDumpItem(
                            name=db.name,
                            engine=db.engine,
                            db_name=db.db_name,
                            output_filename=db_filename,
                            size_bytes=size_bytes
                        ))

            # ------------------------------------------------------------------
            # Phase 2: File Delta Scanning & Non-Destructive Ingestion
            # ------------------------------------------------------------------
            logger.info("Phase 2: Scanning %d configured file source path(s)...", len(client.file_sources))
            pending_catalog_updates = []
            pending_catalog_deletions = []

            for source in client.file_sources:
                logger.info("Scanning source '%s' at: %s", source.id, source.path)
                active_files = self.catalog.get_active_files(client.client_id, source.id)
                seen_rel_paths = set()
                pending_fetch_tasks = []

                for file_info in driver.scan_source_files(source.id, source.path, source.exclude_patterns):
                    rel_p = file_info.rel_path
                    seen_rel_paths.add(rel_p)

                    staged_inc_file = staging_inc_files_dir / source.id / rel_p
                    staged_master_file = staging_master_files_dir / source.id / rel_p

                    existing_entry = active_files.get(rel_p)

                    if existing_entry is None:
                        # Case A: Brand New File (ADDED)
                        if dry_run:
                            manifest.changes.append(FileChangeItem(
                                source_id=source.id,
                                rel_path=rel_p,
                                action="ADDED",
                                size=file_info.size
                            ))
                        else:
                            pending_fetch_tasks.append((file_info, staged_inc_file, staged_master_file, "ADDED", None))

                    else:
                        # Case B: Existing File - Check for modification
                        mtime_changed = abs(file_info.mtime - existing_entry.mtime) > 1.0
                        size_changed = file_info.size != existing_entry.size

                        if mtime_changed or size_changed:
                            if dry_run:
                                manifest.changes.append(FileChangeItem(
                                    source_id=source.id,
                                    rel_path=rel_p,
                                    action="UPDATED",
                                    size=file_info.size,
                                    old_size=existing_entry.size
                                ))
                            else:
                                pending_fetch_tasks.append((file_info, staged_inc_file, staged_master_file, "UPDATED", existing_entry))

                # Parallel file downloads via ThreadPoolExecutor workers
                if not dry_run and pending_fetch_tasks:
                    logger.info(
                        "Parallel downloading %d file(s) for source '%s' across 8 concurrent workers...",
                        len(pending_fetch_tasks), source.id
                    )

                    def _progress_cb(done, total, last_file):
                        logger.info("Download Progress: %d/%d files completed (latest: %s)", done, total, last_file)

                    download_batches = [(item[0], item[1]) for item in pending_fetch_tasks]
                    driver.fetch_files_batch(download_batches, max_workers=8, progress_callback=_progress_cb)

                    # Ingest and hash fetched files
                    for file_info, staged_inc_file, staged_master_file, action, existing_entry in pending_fetch_tasks:
                        if not staged_inc_file.exists():
                            logger.warning("File expected at %s but not found after fetch", staged_inc_file)
                            continue

                        file_hash = calculate_sha256(staged_inc_file)

                        if action == "ADDED":
                            staged_master_file.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(str(staged_inc_file), str(staged_master_file))

                            pending_catalog_updates.append({
                                "client_id": client.client_id,
                                "source_id": source.id,
                                "rel_path": file_info.rel_path,
                                "size": file_info.size,
                                "mtime": file_info.mtime,
                                "sha256": file_hash
                            })
                            manifest.changes.append(FileChangeItem(
                                source_id=source.id,
                                rel_path=file_info.rel_path,
                                action="ADDED",
                                size=file_info.size,
                                sha256=file_hash
                            ))
                        elif action == "UPDATED":
                            if file_hash != existing_entry.sha256:
                                staged_master_file.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copy2(str(staged_inc_file), str(staged_master_file))

                                pending_catalog_updates.append({
                                    "client_id": client.client_id,
                                    "source_id": source.id,
                                    "rel_path": file_info.rel_path,
                                    "size": file_info.size,
                                    "mtime": file_info.mtime,
                                    "sha256": file_hash
                                })
                                manifest.changes.append(FileChangeItem(
                                    source_id=source.id,
                                    rel_path=file_info.rel_path,
                                    action="UPDATED",
                                    size=file_info.size,
                                    old_size=existing_entry.size,
                                    sha256=file_hash
                                ))
                            else:
                                if staged_inc_file.exists():
                                    staged_inc_file.unlink()
                                pending_catalog_updates.append({
                                    "client_id": client.client_id,
                                    "source_id": source.id,
                                    "rel_path": file_info.rel_path,
                                    "size": file_info.size,
                                    "mtime": file_info.mtime,
                                    "sha256": file_hash
                                })

                # Case C: Check for files deleted from source
                # NON-DESTRUCTIVE: Never deleted from master!
                for rel_p, entry in active_files.items():
                    if rel_p not in seen_rel_paths:
                        logger.info(
                            "File removed on source: [%s] %s. Flagging in audit manifest; "
                            "preserving safely in backup master.",
                            source.id, rel_p
                        )
                        if not dry_run:
                            pending_catalog_deletions.append((client.client_id, source.id, rel_p))

                        manifest.changes.append(FileChangeItem(
                            source_id=source.id,
                            rel_path=rel_p,
                            action="DELETED",
                            size=entry.size,
                            sha256=entry.sha256
                        ))

            # ------------------------------------------------------------------
            # Phase 3: Manifest Generation
            # ------------------------------------------------------------------
            manifest.duration_seconds = time.time() - start_time
            if not dry_run:
                manifest.write_to_directory(staging_inc_dir)

            # ------------------------------------------------------------------
            # Phase 4: Cloud Upload to Google Drive (Uniform Hierarchy)
            # ------------------------------------------------------------------
            if not dry_run:
                logger.info("Phase 4: Syncing payload to storage under uniform client hierarchy...")
                # 4a. Sync Incremental Date Folder
                # Destination: {client_id}/incremental/{run_date}/
                inc_remote_folder_id = self.storage.ensure_directory_path(
                    [client.client_id, "incremental", run_date]
                )

                # Upload database dumps
                if staging_inc_db_dir.exists():
                    db_remote_id = self.storage.ensure_directory_path(
                        [client.client_id, "incremental", run_date, "database"]
                    )
                    for dump_file in staging_inc_db_dir.iterdir():
                        if dump_file.is_file():
                            self.storage.upload_file(dump_file, db_remote_id, dump_file.name)

                # Upload incremental changed/added files
                if staging_inc_files_dir.exists():
                    for root_d, _, files in os.walk(str(staging_inc_files_dir)):
                        for f in files:
                            full_f = Path(root_d) / f
                            rel_dir = os.path.relpath(root_d, str(staging_inc_files_dir)).replace("\\", "/")
                            path_parts = [client.client_id, "incremental", run_date, "files"]
                            if rel_dir != ".":
                                path_parts.extend(rel_dir.split("/"))

                            target_folder_id = self.storage.ensure_directory_path(path_parts)
                            self.storage.upload_file(full_f, target_folder_id, f)

                # Upload manifest files
                manifest_txt = staging_inc_dir / "manifest.txt"
                if manifest_txt.exists():
                    self.storage.upload_file(manifest_txt, inc_remote_folder_id, "manifest.txt")
                manifest_json = staging_inc_dir / "manifest.json"
                if manifest_json.exists():
                    self.storage.upload_file(manifest_json, inc_remote_folder_id, "manifest.json")

                # 4b. Sync Master Files (Current latest snapshot, never deleting removed files)
                # Destination: {client_id}/master/files/...
                if staging_master_files_dir.exists():
                    logger.info("Syncing new/updated files to master baseline folder...")
                    for root_d, _, files in os.walk(str(staging_master_files_dir)):
                        for f in files:
                            full_f = Path(root_d) / f
                            rel_dir = os.path.relpath(root_d, str(staging_master_files_dir)).replace("\\", "/")
                            path_parts = [client.client_id, "master", "files"]
                            if rel_dir != ".":
                                path_parts.extend(rel_dir.split("/"))

                            target_folder_id = self.storage.ensure_directory_path(path_parts)
                            self.storage.upload_file(full_f, target_folder_id, f, overwrite=True)

                # 4c. Atomically Commit Verified Catalog State (Only after confirmed storage upload)
                if pending_catalog_updates or pending_catalog_deletions:
                    logger.info(
                        "Atomically committing snapshot catalog state (%d file updates, %d deletions)...",
                        len(pending_catalog_updates), len(pending_catalog_deletions)
                    )
                    self.catalog.record_batch_updates(pending_catalog_updates, pending_catalog_deletions)

            # ------------------------------------------------------------------
            # Phase 5: Retention Policy Enforcement (10-day sliding window)
            # ------------------------------------------------------------------
            logger.info("Phase 5: Enforcing %d-day retention policy...", client.retention_days)
            self.retention.enforce_client_retention(
                client_id=client.client_id,
                retention_days=client.retention_days,
                dry_run=dry_run
            )

            # ------------------------------------------------------------------
            # Phase 6: Catalog Audit & Metrics Logging
            # ------------------------------------------------------------------
            manifest.duration_seconds = time.time() - start_time
            if not dry_run:
                self.catalog.record_run(
                    client_id=client.client_id,
                    run_date=run_date,
                    run_timestamp=timestamp_full,
                    status="SUCCESS",
                    files_added=manifest.added_count,
                    files_updated=manifest.updated_count,
                    files_deleted=manifest.deleted_count,
                    dbs_dumped=len(manifest.databases),
                    total_incremental_bytes=manifest.total_incremental_bytes,
                    duration_seconds=manifest.duration_seconds
                )

            logger.info(
                "=== Completed Backup for '%s' in %.2f seconds (Added: %d, Updated: %d, Deleted (preserved): %d, DBs: %d) ===",
                client.client_id, manifest.duration_seconds,
                manifest.added_count, manifest.updated_count, manifest.deleted_count,
                len(manifest.databases)
            )
            return manifest

        except Exception as exc:
            duration = time.time() - start_time
            logger.error("Backup failed for client '%s': %s", client.client_id, exc, exc_info=True)
            if not dry_run:
                self.catalog.record_run(
                    client_id=client.client_id,
                    run_date=run_date,
                    run_timestamp=timestamp_full,
                    status="FAILED",
                    files_added=manifest.added_count,
                    files_updated=manifest.updated_count,
                    files_deleted=manifest.deleted_count,
                    dbs_dumped=len(manifest.databases),
                    total_incremental_bytes=manifest.total_incremental_bytes,
                    duration_seconds=duration,
                    error_message=str(exc)
                )
            raise

        finally:
            driver.close()
            # Clean up local staging area
            if staging_root.exists():
                shutil.rmtree(str(staging_root), ignore_errors=True)

    def run_all(self, client_id_filter: Optional[str] = None, dry_run: bool = False) -> List[ManifestReport]:
        """Execute backup cycle for all configured clients or a specific client."""
        results = []
        for client in self.config.clients:
            if client_id_filter and client.client_id != client_id_filter:
                continue
            report = self.run_backup_for_client(client, dry_run=dry_run)
            results.append(report)
        return results
