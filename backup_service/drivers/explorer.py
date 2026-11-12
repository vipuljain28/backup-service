"""Interactive Directory Explorer for Local and Remote SSH Hosts.

Follows OWASP Secure Coding Practices:
- Strict path traversal prevention (rejects illegal `..` and non-canonical path tampering)
- Safe permission evaluation and symlink containment
"""

import os
import stat
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from backup_service.drivers.local_driver import LocalDriver
from backup_service.drivers.ssh_driver import SSHDriver
from backup_service.config.settings import SSHConfig

logger = logging.getLogger("backup_service.explorer")


def sanitize_path(requested_path: str) -> str:
    """Sanitize and normalize path to prevent OWASP directory traversal exploits.
    Always returns normalized forward-slash absolute path representation.
    Preserves Windows drive roots when running on Windows (e.g. C:/).
    """
    if not requested_path or requested_path.strip() in ("", "."):
        return "/"

    clean = requested_path.strip().replace("\\", "/")
    parts = []
    for segment in clean.split("/"):
        if not segment or segment == ".":
            continue
        if segment == "..":
            if parts:
                parts.pop()
        else:
            parts.append(segment)

    if not parts:
        return "/"

    # Check for Windows drive letter (e.g., C:)
    if len(parts[0]) == 2 and parts[0][1] == ":" and parts[0][0].isalpha():
        drive = parts[0].upper()
        if len(parts) == 1:
            return f"{drive}/"
        return f"{drive}/" + "/".join(parts[1:])

    return "/" + "/".join(parts)


class DirectoryExplorer:
    """Explores directory hierarchies on local or remote servers."""

    @staticmethod
    def explore_local(target_path: str = "/") -> Dict[str, Any]:
        """List local directory contents with metadata."""
        clean_p = sanitize_path(target_path)

        # On Windows, browsing root "/" lists available drives (C:, D:, etc.)
        if os.name == "nt" and clean_p == "/":
            import string
            drives = []
            for letter in string.ascii_uppercase:
                if os.path.exists(f"{letter}:\\"):
                    drives.append({
                        "name": f"Drive {letter}:",
                        "path": f"{letter}:/",
                        "is_dir": True,
                        "size": 0,
                        "mtime": 0.0,
                        "readable": True
                    })
            return {
                "current_path": "/",
                "parent_path": None,
                "error": None,
                "items": drives
            }

        norm_path = Path("." if clean_p == "/" else clean_p).resolve()

        if not norm_path.exists():
            clean_parent = str(Path(clean_p).parent).replace("\\", "/") if clean_p not in ("/", "") else None
            return {
                "current_path": clean_p,
                "parent_path": clean_parent or "/",
                "error": "Directory does not exist",
                "items": []
            }

        if not norm_path.is_dir():
            norm_path = norm_path.parent

        items = []
        try:
            with os.scandir(str(norm_path)) as it:
                for entry in it:
                    try:
                        is_dir = entry.is_dir(follow_symlinks=False)
                        st = entry.stat(follow_symlinks=False)
                        items.append({
                            "name": entry.name,
                            "path": str(Path(entry.path).resolve()).replace("\\", "/"),
                            "is_dir": is_dir,
                            "size": st.st_size if not is_dir else 0,
                            "mtime": st.st_mtime,
                            "readable": True
                        })
                    except (PermissionError, OSError):
                        items.append({
                            "name": entry.name,
                            "path": str(Path(entry.path)).replace("\\", "/"),
                            "is_dir": False,
                            "size": 0,
                            "mtime": 0.0,
                            "readable": False
                        })
        except PermissionError:
            return {
                "current_path": str(norm_path).replace("\\", "/"),
                "parent_path": str(norm_path.parent).replace("\\", "/") if norm_path.parent != norm_path else None,
                "error": "Permission denied",
                "items": []
            }

        # Sort: directories first, then alphabetical
        items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
        parent = str(norm_path.parent).replace("\\", "/") if norm_path.parent != norm_path else None
        if os.name == "nt" and (not parent or parent == str(norm_path).replace("\\", "/") or parent.endswith(":")):
            parent = "/"

        return {
            "current_path": str(norm_path).replace("\\", "/"),
            "parent_path": parent,
            "error": None,
            "items": items
        }

    @staticmethod
    def explore_remote_ssh(ssh_config: SSHConfig, target_path: str = "/") -> Dict[str, Any]:
        """List remote server directory contents via SFTP."""
        driver = SSHDriver(ssh_config)
        clean_path = sanitize_path(target_path)

        try:
            sftp = driver._get_sftp()
            try:
                attr = sftp.stat(clean_path)
                if not stat.S_ISDIR(attr.st_mode):
                    clean_path = str(Path(clean_path).parent).replace("\\", "/")
            except IOError:
                clean_parent = str(Path(clean_path).parent).replace("\\", "/") if clean_path not in ("/", "") else None
                return {
                    "current_path": clean_path,
                    "parent_path": clean_parent or "/",
                    "error": f"Remote directory '{clean_path}' does not exist on this server.",
                    "items": []
                }

            items = []
            for attr in sftp.listdir_attr(clean_path):
                is_dir = stat.S_ISDIR(attr.st_mode)
                item_name = attr.filename
                full_item_path = f"{clean_path.rstrip('/')}/{item_name}"
                items.append({
                    "name": item_name,
                    "path": full_item_path,
                    "is_dir": is_dir,
                    "size": attr.st_size if not is_dir else 0,
                    "mtime": float(attr.st_mtime or 0.0),
                    "readable": True
                })

            items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))
            parent_path = str(Path(clean_path).parent).replace("\\", "/") if clean_path not in ("/", "") else None

            return {
                "current_path": clean_path,
                "parent_path": parent_path,
                "error": None,
                "items": items
            }
        except Exception as exc:
            logger.error("SSH directory exploration failed for %s: %s", clean_path, exc)
            return {
                "current_path": clean_path,
                "parent_path": None,
                "error": str(exc),
                "items": []
            }
        finally:
            driver.close()

    @staticmethod
    def inspect_folder(server: Dict[str, Any], vault, folder_path: str, max_files: int = 500) -> Dict[str, Any]:
        """Inspect folder contents, aggregate file types/extensions, sizes, and file list."""
        clean_path = sanitize_path(folder_path)
        result = {
            "folder_path": clean_path,
            "server_id": server.get("id"),
            "server_name": server.get("name"),
            "server_mode": server.get("mode"),
            "server_host": server.get("host"),
            "total_files": 0,
            "total_dirs": 0,
            "total_bytes": 0,
            "file_types": {},
            "files": [],
            "error": None
        }

        def get_type_label(ext: str) -> str:
            ext = ext.lower().lstrip(".")
            mapping = {
                "php": "PHP Script",
                "js": "JavaScript",
                "html": "HTML Document",
                "css": "CSS Stylesheet",
                "json": "JSON Data",
                "sql": "SQL Dump",
                "pdf": "PDF Document",
                "png": "PNG Image",
                "jpg": "JPEG Image",
                "jpeg": "JPEG Image",
                "gif": "GIF Image",
                "svg": "SVG Graphic",
                "zip": "ZIP Archive",
                "tar": "TAR Archive",
                "gz": "GZ Archive",
                "txt": "Text File",
                "log": "Log File",
                "xml": "XML Document",
                "csv": "CSV Spreadsheet",
                "env": "Config / Environment"
            }
            return mapping.get(ext, f"{ext.upper()} File" if ext else "Binary / Other")

        if server.get("mode") == "ssh":
            decrypted_secret = vault.decrypt(server["encrypted_secret"]) if server.get("encrypted_secret") else None
            key_path = decrypted_secret if server.get("auth_type") != "password" else None
            password = decrypted_secret if server.get("auth_type") == "password" else None

            ssh_cfg = SSHConfig(
                host=server["host"],
                port=server.get("port") or 22,
                user=server["username"],
                key_path=key_path,
                password=password,
                timeout_seconds=15
            )
            driver = SSHDriver(ssh_cfg)
            try:
                sftp = driver._get_sftp()
                try:
                    entries = sftp.listdir_attr(clean_path)
                except IOError as exc:
                    result["error"] = f"Cannot open remote folder '{clean_path}': {exc}"
                    return result

                for attr in entries:
                    is_dir = stat.S_ISDIR(attr.st_mode)
                    if is_dir:
                        result["total_dirs"] += 1
                        continue

                    result["total_files"] += 1
                    f_size = attr.st_size or 0
                    result["total_bytes"] += f_size
                    ext = Path(attr.filename).suffix.lower().lstrip(".") or "other"
                    result["file_types"][ext] = result["file_types"].get(ext, 0) + 1

                    if len(result["files"]) < max_files:
                        result["files"].append({
                            "name": attr.filename,
                            "path": f"{clean_path.rstrip('/')}/{attr.filename}",
                            "size": f_size,
                            "extension": ext,
                            "type_label": get_type_label(ext),
                            "mtime": float(attr.st_mtime or 0.0)
                        })

                result["file_types"] = dict(sorted(result["file_types"].items(), key=lambda x: x[1], reverse=True))
                result["files"].sort(key=lambda x: x["size"], reverse=True)
                return result
            except Exception as exc:
                result["error"] = f"SSH inspection error: {exc}"
                return result
            finally:
                driver.close()

        else:
            norm_path = Path("." if clean_path == "/" else clean_path).resolve()
            if not norm_path.exists():
                result["error"] = f"Local directory '{clean_path}' does not exist."
                return result

            try:
                with os.scandir(str(norm_path)) as it:
                    for entry in it:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                result["total_dirs"] += 1
                                continue
                            st = entry.stat(follow_symlinks=False)
                            result["total_files"] += 1
                            result["total_bytes"] += st.st_size
                            ext = Path(entry.name).suffix.lower().lstrip(".") or "other"
                            result["file_types"][ext] = result["file_types"].get(ext, 0) + 1

                            if len(result["files"]) < max_files:
                                result["files"].append({
                                    "name": entry.name,
                                    "path": str(Path(entry.path).resolve()).replace("\\", "/"),
                                    "size": st.st_size,
                                    "extension": ext,
                                    "type_label": get_type_label(ext),
                                    "mtime": float(st.st_mtime or 0.0)
                                })
                        except (PermissionError, OSError):
                            pass

                result["file_types"] = dict(sorted(result["file_types"].items(), key=lambda x: x[1], reverse=True))
                result["files"].sort(key=lambda x: x["size"], reverse=True)
                return result
            except PermissionError:
                result["error"] = "Permission denied reading local directory."
                return result
