"""Local Source Driver for executing directly on Linux or localhost."""

import os
import gzip
import shutil
import fnmatch
import logging
import subprocess
from pathlib import Path
from typing import Generator, List
from backup_service.drivers.base import SourceDriver, SourceFileInfo
from backup_service.config.settings import DatabaseConfig

logger = logging.getLogger("backup_service.driver.local")


class LocalDriver(SourceDriver):
    """Driver executing against local filesystem and database instances."""

    def test_connection(self) -> bool:
        """Localhost is inherently connected."""
        return True

    def scan_source_files(
        self,
        source_id: str,
        base_path: str,
        exclude_patterns: List[str]
    ) -> Generator[SourceFileInfo, None, None]:
        """Walk local directory and yield file descriptors."""
        root = Path(base_path).resolve()
        if not root.is_dir():
            logger.warning("Configured path does not exist or is not a directory: %s", base_path)
            return

        for current_dir, dirnames, filenames in os.walk(str(root)):
            # Normalize relative directory path
            rel_dir = os.path.relpath(current_dir, str(root))
            if rel_dir == ".":
                rel_dir = ""

            # Prune excluded directories in-place for performance
            dirnames[:] = [
                d for d in dirnames
                if not any(fnmatch.fnmatch(os.path.join(rel_dir, d).replace("\\", "/"), pat) for pat in exclude_patterns)
            ]

            for fname in filenames:
                rel_file_path = os.path.join(rel_dir, fname).replace("\\", "/")
                # Check exclusions
                if any(fnmatch.fnmatch(rel_file_path, pat) or fnmatch.fnmatch(fname, pat) for pat in exclude_patterns):
                    continue

                full_path = Path(current_dir) / fname
                try:
                    stat = full_path.stat()
                    yield SourceFileInfo(
                        source_id=source_id,
                        rel_path=rel_file_path,
                        abs_path_or_remote=str(full_path),
                        size=stat.st_size,
                        mtime=stat.st_mtime
                    )
                except (OSError, PermissionError) as exc:
                    logger.warning("Skipping unreadable file %s: %s", full_path, exc)

    def fetch_file(self, file_info: SourceFileInfo, local_dest: Path) -> Path:
        """Copy local file to destination."""
        local_dest = Path(local_dest)
        local_dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file_info.abs_path_or_remote, str(local_dest))
        return local_dest

    def dump_database(
        self,
        db_config: DatabaseConfig,
        local_output_path: Path
    ) -> int:
        """Stream compressed database dump directly to local_output_path."""
        local_output_path = Path(local_output_path)
        local_output_path.parent.mkdir(parents=True, exist_ok=True)

        env = os.environ.copy()
        if db_config.engine in ("mysql", "mariadb"):
            cmd = [
                "mysqldump",
                f"-h{db_config.host}",
                f"-P{db_config.port}",
                f"-u{db_config.user}",
            ]
            if db_config.password:
                env["MYSQL_PWD"] = db_config.password

            cmd.extend(db_config.dump_options)
            cmd.append(db_config.db_name)

        elif db_config.engine == "postgres":
            cmd = [
                "pg_dump",
                f"-h", db_config.host,
                f"-p", str(db_config.port),
                f"-U", db_config.user,
                "-F", "p",  # Plain SQL text format to be gzipped
            ]
            if db_config.password:
                env["PGPASSWORD"] = db_config.password

            cmd.extend(db_config.dump_options)
            cmd.append(db_config.db_name)
        else:
            raise ValueError(f"Unsupported database engine: {db_config.engine}")

        logger.info("Executing database dump for '%s' (DB: %s)", db_config.name, db_config.db_name)

        try:
            # Stream directly to gzip compressed file to conserve disk space and I/O
            with gzip.open(str(local_output_path), "wb", compresslevel=6) as gz_out:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env
                )
                while True:
                    chunk = process.stdout.read(64 * 1024)
                    if not chunk:
                        break
                    gz_out.write(chunk)

                stderr_bytes = process.stderr.read()
                ret_code = process.wait()

                if ret_code != 0:
                    err_msg = stderr_bytes.decode("utf-8", errors="replace")
                    raise RuntimeError(f"Database dump failed with exit code {ret_code}: {err_msg}")

            file_size = local_output_path.stat().st_size
            logger.info("Database dump successful: %s (%d bytes)", local_output_path.name, file_size)
            return file_size

        except FileNotFoundError as err:
            logger.error("Dump binary not found on system path: %s", err)
            raise RuntimeError(
                f"Binary for '{db_config.engine}' dump was not found on PATH. "
                "Ensure mysqldump or pg_dump is installed."
            ) from err
