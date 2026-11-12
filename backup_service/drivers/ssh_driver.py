"""SSH Remote Source Driver using Paramiko.

Connects to a remote Linux server from localhost to perform:
- Non-invasive remote database dumps streamed via SSH stdout directly into local gzip
- Remote file directory differential scanning (Python-assisted or pure SFTP fallback)
- SFTP file extraction for changed/added assets
"""

import os
import json
import shlex
import logging
from pathlib import Path
from typing import Generator, List, Optional
import fnmatch
from backup_service.drivers.base import SourceDriver, SourceFileInfo
from backup_service.config.settings import SSHConfig, DatabaseConfig

logger = logging.getLogger("backup_service.driver.ssh")


class SSHDriver(SourceDriver):
    """Driver executing against a remote host over SSH/SFTP."""

    def __init__(self, ssh_config: SSHConfig):
        self.config = ssh_config
        self._client = None
        self._sftp = None

    def _get_client(self):
        """Establish or return active Paramiko SSHClient."""
        if self._client is not None:
            return self._client

        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": self.config.host,
            "port": self.config.port,
            "username": self.config.user,
            "timeout": self.config.timeout_seconds,
        }

        if self.config.key_path:
            expanded_key = os.path.expanduser(self.config.key_path)
            connect_kwargs["key_filename"] = expanded_key
            if self.config.key_passphrase:
                connect_kwargs["passphrase"] = self.config.key_passphrase

        if self.config.password:
            connect_kwargs["password"] = self.config.password

        logger.info("Connecting via SSH to %s@%s:%d...", self.config.user, self.config.host, self.config.port)
        client.connect(**connect_kwargs)
        self._client = client
        return self._client

    def _get_sftp(self):
        """Establish or return active SFTP client."""
        if self._sftp is not None:
            return self._sftp
        client = self._get_client()
        self._sftp = client.open_sftp()
        return self._sftp

    def test_connection(self) -> bool:
        """Verify SSH connection and command execution."""
        try:
            client = self._get_client()
            stdin, stdout, stderr = client.exec_command("echo '__SSH_OK__'")
            output = stdout.read().decode("utf-8").strip()
            return output == "__SSH_OK__"
        except Exception as exc:
            logger.error("SSH connection test failed to %s: %s", self.config.host, exc)
            return False

    def scan_source_files(
        self,
        source_id: str,
        base_path: str,
        exclude_patterns: List[str]
    ) -> Generator[SourceFileInfo, None, None]:
        """Scan remote directory over SSH."""
        client = self._get_client()
        
        # Try high-speed remote Python inspection first
        remote_scanner_script = (
            f"python3 -c \""
            f"import os, json; root = '{base_path}'; out = [];\n"
            f"for d, _, files in os.walk(root):\n"
            f"    for f in files:\n"
            f"        p = os.path.join(d, f)\n"
            f"        try:\n"
            f"            s = os.stat(p)\n"
            f"            out.append((os.path.relpath(p, root), s.st_size, s.st_mtime))\n"
            f"        except Exception: pass\n"
            f"print(json.dumps(out))\n"
            f"\" 2>/dev/null"
        )

        stdin, stdout, stderr = client.exec_command(remote_scanner_script)
        raw_output = stdout.read().decode("utf-8").strip()

        if raw_output and raw_output.startswith("["):
            try:
                entries = json.loads(raw_output)
                for rel_path, size, mtime in entries:
                    norm_path = rel_path.replace("\\", "/")
                    if any(fnmatch.fnmatch(norm_path, pat) for pat in exclude_patterns):
                        continue
                    remote_full = os.path.join(base_path, rel_path).replace("\\", "/")
                    yield SourceFileInfo(
                        source_id=source_id,
                        rel_path=norm_path,
                        abs_path_or_remote=remote_full,
                        size=size,
                        mtime=mtime
                    )
                return
            except json.JSONDecodeError:
                pass

        # Fallback to SFTP recursive walk if remote python was unavailable
        logger.debug("Falling back to SFTP tree traversal for %s", base_path)
        sftp = self._get_sftp()

        def _walk_sftp(remote_dir: str, rel_prefix: str = ""):
            try:
                for attr in sftp.listdir_attr(remote_dir):
                    item_name = attr.filename
                    rel_item = os.path.join(rel_prefix, item_name).replace("\\", "/")

                    if any(fnmatch.fnmatch(rel_item, pat) or fnmatch.fnmatch(item_name, pat) for pat in exclude_patterns):
                        continue

                    remote_path = f"{remote_dir}/{item_name}"
                    import stat
                    if stat.S_ISDIR(attr.st_mode):
                        yield from _walk_sftp(remote_path, rel_item)
                    elif stat.S_ISREG(attr.st_mode):
                        yield SourceFileInfo(
                            source_id=source_id,
                            rel_path=rel_item,
                            abs_path_or_remote=remote_path,
                            size=attr.st_size or 0,
                            mtime=float(attr.st_mtime or 0.0)
                        )
            except IOError as err:
                logger.warning("SFTP walk error on %s: %s", remote_dir, err)

        yield from _walk_sftp(base_path)

    def fetch_file(self, file_info: SourceFileInfo, local_dest: Path) -> Path:
        """Download remote file via SFTP into local destination."""
        local_dest = Path(local_dest)
        local_dest.parent.mkdir(parents=True, exist_ok=True)
        sftp = self._get_sftp()
        sftp.get(file_info.abs_path_or_remote, str(local_dest))
        return local_dest

    def verify_database_access(self, db_config: DatabaseConfig) -> None:
        """Verify database connectivity and credentials without dumping data."""
        client = self._get_client()
        if db_config.engine in ("mysql", "mariadb"):
            pwd_clause = f"--password={shlex.quote(db_config.password)}" if db_config.password else ""
            test_cmd = (
                f"mysql -h {shlex.quote(str(db_config.host))} -P {db_config.port} -u {shlex.quote(db_config.user)} "
                f"{pwd_clause} {shlex.quote(db_config.db_name)} -e 'SELECT 1;' 2>&1"
            )
            stdin, stdout, stderr = client.exec_command(test_cmd, timeout=10)
            output = stdout.read().decode("utf-8", errors="ignore").strip()
            exit_code = stdout.channel.recv_exit_status()
            fatal_keywords = ["ERROR ", "Access denied", "Can't connect", "Unknown database"]
            if exit_code != 0 or any(k in output for k in fatal_keywords):
                raise RuntimeError(
                    f"Database connection failed for '{db_config.db_name}' on remote host: {output}"
                )
            logger.info("[DRY RUN] Verified MySQL database access for '%s' (DB: %s)", db_config.name, db_config.db_name)
        elif db_config.engine == "postgres":
            pwd_env = f"PGPASSWORD={shlex.quote(db_config.password)} " if db_config.password else ""
            test_cmd = (
                f"{pwd_env}psql -h {shlex.quote(str(db_config.host))} -p {db_config.port} -U {shlex.quote(db_config.user)} "
                f"-d {shlex.quote(db_config.db_name)} -c 'SELECT 1;' 2>&1"
            )
            stdin, stdout, stderr = client.exec_command(test_cmd, timeout=10)
            output = stdout.read().decode("utf-8", errors="ignore").strip()
            exit_code = stdout.channel.recv_exit_status()
            if exit_code != 0 or "FATAL:" in output:
                raise RuntimeError(
                    f"PostgreSQL connection failed for '{db_config.db_name}' on remote host: {output}"
                )
            logger.info("[DRY RUN] Verified PostgreSQL database access for '%s' (DB: %s)", db_config.name, db_config.db_name)

    def dump_database(
        self,
        db_config: DatabaseConfig,
        local_output_path: Path
    ) -> int:
        """Stream compressed database dump over SSH stdout directly into local file.
        
        Zero disk space overhead on the remote server!
        """
        local_output_path = Path(local_output_path)
        local_output_path.parent.mkdir(parents=True, exist_ok=True)
        client = self._get_client()

        if db_config.engine in ("mysql", "mariadb"):
            pwd_clause = f"--password={shlex.quote(db_config.password)}" if db_config.password else ""
            opts = " ".join(db_config.dump_options)
            inner_cmd = (
                f"mysqldump -h {shlex.quote(str(db_config.host))} -P {db_config.port} -u {shlex.quote(db_config.user)} "
                f"{pwd_clause} {opts} {shlex.quote(db_config.db_name)} | gzip -c"
            )
            remote_cmd = f"bash -c {shlex.quote('set -o pipefail; ' + inner_cmd)}"
        elif db_config.engine == "postgres":
            pwd_env = f"PGPASSWORD={shlex.quote(db_config.password)} " if db_config.password else ""
            opts = " ".join(db_config.dump_options)
            inner_cmd = (
                f"{pwd_env}pg_dump -h {shlex.quote(str(db_config.host))} -p {db_config.port} -U {shlex.quote(db_config.user)} "
                f"{opts} {shlex.quote(db_config.db_name)} | gzip -c"
            )
            remote_cmd = f"bash -c {shlex.quote('set -o pipefail; ' + inner_cmd)}"
        else:
            raise ValueError(f"Unsupported database engine: {db_config.engine}")

        logger.info(
            "Executing remote DB dump over SSH for '%s' (DB: %s)",
            db_config.name, db_config.db_name
        )

        stdin, stdout, stderr = client.exec_command(remote_cmd)

        # Stream directly into local destination file
        total_bytes = 0
        with open(str(local_output_path), "wb") as f_out:
            while True:
                chunk = stdout.read(64 * 1024)
                if not chunk:
                    break
                f_out.write(chunk)
                total_bytes += len(chunk)

        err_output = stderr.read().decode("utf-8", errors="ignore").strip()
        exit_status = stdout.channel.recv_exit_status()

        fatal_keywords = ["Got error:", "Access denied", "Can't connect", "Unknown database", "ERROR "]
        has_fatal_error = any(k in err_output for k in fatal_keywords)

        if exit_status != 0 or has_fatal_error or total_bytes <= 40:
            if local_output_path.exists():
                local_output_path.unlink()
            err_msg = err_output or f"mysqldump exited with status {exit_status} and generated 0 database bytes."
            raise RuntimeError(
                f"Remote database dump failed for '{db_config.db_name}': {err_msg}"
            )

        logger.info(
            "Remote DB dump streamed successfully: %s (%d bytes)",
            local_output_path.name, total_bytes
        )
        return total_bytes

    def close(self):
        """Close SFTP and SSH connections."""
        if self._sftp:
            try:
                self._sftp.close()
            except Exception:
                pass
            self._sftp = None

        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
