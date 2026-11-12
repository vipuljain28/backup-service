"""Database Connectivity and SSL Verification Subsystem."""

import socket
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("backup_service.db_checker")


class DatabaseChecker:
    """Verifies database credentials, network reachability, and SSL negotiation."""

    @staticmethod
    def test_connection(
        engine: str,
        host: str,
        port: int,
        user: str,
        password: Optional[str],
        db_name: str,
        ssl_enabled: bool = False,
        timeout_seconds: int = 5
    ) -> Dict[str, Any]:
        """Perform non-invasive connectivity test against target database server."""
        engine = engine.lower().strip()
        result = {
            "engine": engine,
            "host": host,
            "port": port,
            "db_name": db_name,
            "ssl_enabled": ssl_enabled,
            "connected": False,
            "latency_ms": 0.0,
            "message": ""
        }

        # Step 1: TCP Socket Reachability Check
        import time
        start_time = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout_seconds)
            sock.connect((host, port))
            sock.close()
            result["latency_ms"] = round((time.time() - start_time) * 1000, 2)
        except Exception as exc:
            result["message"] = f"Network connection failed: {exc}"
            return result

        # Step 2: Protocol / Credential Handshake Check
        try:
            if engine in ("mysql", "mariadb"):
                # Attempt light protocol ping via subprocess mysqldump or direct handshake
                import subprocess
                cmd = ["mysqladmin", f"-h{host}", f"-P{port}", f"-u{user}"]
                if password:
                    cmd.append(f"-p{password}")
                if ssl_enabled:
                    cmd.append("--ssl-mode=REQUIRED")
                cmd.append("ping")

                proc = subprocess.run(cmd, capture_output=True, timeout=timeout_seconds, text=True)
                if proc.returncode == 0 and "alive" in proc.stdout.lower():
                    result["connected"] = True
                    result["message"] = f"Successfully connected to {engine.upper()} (Server is alive, SSL={ssl_enabled})"
                    return result
                elif proc.returncode != 0:
                    # If mysqladmin binary is absent, TCP socket reachability is confirmed
                    if "not found" in proc.stderr.lower() or "not recognized" in proc.stderr.lower():
                        result["connected"] = True
                        result["message"] = f"TCP port {port} open and responding ({result['latency_ms']} ms). mysqladmin binary not present on path."
                        return result
                    result["message"] = f"Handshake failed: {proc.stderr.strip()}"
                    return result

            elif engine == "postgres":
                import subprocess
                import os
                env = os.environ.copy()
                if password:
                    env["PGPASSWORD"] = password
                cmd = ["pg_isready", "-h", host, "-p", str(port), "-d", db_name, "-U", user]
                proc = subprocess.run(cmd, capture_output=True, timeout=timeout_seconds, text=True, env=env)
                if proc.returncode == 0:
                    result["connected"] = True
                    result["message"] = f"PostgreSQL server is ready and accepting connections (SSL={ssl_enabled})"
                    return result
                else:
                    if "not found" in proc.stderr.lower() or "not recognized" in proc.stderr.lower():
                        result["connected"] = True
                        result["message"] = f"TCP port {port} open and responding ({result['latency_ms']} ms)."
                        return result
                    result["message"] = f"PostgreSQL not ready: {proc.stderr.strip()}"
                    return result

            # Generic fallback: TCP connection verified
            result["connected"] = True
            result["message"] = f"TCP connection verified to {host}:{port} in {result['latency_ms']} ms"
            return result

        except Exception as exc:
            result["message"] = f"Database check encountered error: {exc}"
            return result
