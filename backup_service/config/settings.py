"""Configuration schema and validation models for the Backup Service."""

import os
import re
from typing import List, Optional, Literal
from pathlib import Path
from pydantic import BaseModel, Field, field_validator
import yaml

ENV_VAR_PATTERN = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-(.*?))?\}")


def expand_env_vars(text: str) -> str:
    """Expand environment variables in configuration string.
    Supports syntax: ${VAR} and ${VAR:-default_value}.
    """
    def _replace(match):
        var_name = match.group(1)
        default_val = match.group(2) if match.group(2) is not None else ""
        return os.environ.get(var_name, default_val)
    return ENV_VAR_PATTERN.sub(_replace, text)


class DatabaseConfig(BaseModel):
    """Database connection and dump configuration."""
    name: str = Field(..., description="Unique logical identifier for this database")
    engine: Literal["mysql", "mariadb", "postgres"] = Field("mysql", description="Database engine type")
    host: str = Field("127.0.0.1", description="Database host")
    port: int = Field(3306, description="Database port")
    user: str = Field("root", description="Database username")
    password: Optional[str] = Field(None, description="Database password (supports env expansion)")
    db_name: str = Field(..., description="Target database name to dump")
    dump_options: List[str] = Field(
        default_factory=lambda: ["--single-transaction", "--quick", "--routines", "--triggers"],
        description="Extra arguments passed to dump binary"
    )

    @field_validator("port", mode="before")
    @classmethod
    def set_default_port(cls, v, info):
        if v:
            return int(v)
        engine = info.data.get("engine", "mysql")
        return 5432 if engine == "postgres" else 3306

    @field_validator("db_name")
    @classmethod
    def validate_db_name(cls, v: str):
        if not re.match(r"^[a-zA-Z0-9_\-]+$", v):
            raise ValueError(f"Invalid database name '{v}': must only contain letters, numbers, underscores, and dashes.")
        return v

    @field_validator("dump_options")
    @classmethod
    def validate_dump_options(cls, v: List[str]):
        for opt in v:
            if not re.match(r"^--?[a-zA-Z0-9_\-=]+$", opt.strip()):
                raise ValueError(f"Invalid dump option '{opt}': prohibited command argument.")
        return v


class FileSourceConfig(BaseModel):
    """Configuration for directory paths to be backed up."""
    id: str = Field(..., description="Unique slug for this directory (e.g., uploads, documents)")
    path: str = Field(..., description="Absolute path on source server")
    exclude_patterns: List[str] = Field(
        default_factory=lambda: ["*.tmp", "*.log", ".git/*", "node_modules/*", ".cache/*"],
        description="Glob patterns to exclude from backup"
    )


class SSHConfig(BaseModel):
    """SSH connection configuration for remote server mode."""
    host: str = Field(..., description="Remote server hostname or IP")
    port: int = Field(22, description="SSH port")
    user: str = Field(..., description="SSH login username")
    key_path: Optional[str] = Field(None, description="Path to private SSH key file")
    key_passphrase: Optional[str] = Field(None, description="Passphrase for private key")
    password: Optional[str] = Field(None, description="SSH password (key authentication preferred)")
    timeout_seconds: int = Field(30, description="SSH connection timeout in seconds")


class ClientConfig(BaseModel):
    """Tenant/Client configuration containing all databases and file sources."""
    client_id: str = Field(..., description="URL/Path safe client identifier (e.g., client_a)")
    display_name: str = Field(..., description="Friendly human-readable client name")
    connection_mode: Literal["local", "ssh"] = Field("local", description="Whether to run locally or over SSH")
    ssh: Optional[SSHConfig] = Field(None, description="SSH settings if connection_mode is ssh")
    databases: List[DatabaseConfig] = Field(default_factory=list, description="Databases belonging to this client")
    file_sources: List[FileSourceConfig] = Field(default_factory=list, description="File folders to back up")
    retention_days: int = Field(10, ge=1, description="Sliding window retention days for incremental and DB backups")

    @field_validator("ssh")
    @classmethod
    def validate_ssh_when_mode_is_ssh(cls, v, info):
        if info.data.get("connection_mode") == "ssh" and not v:
            raise ValueError("ssh configuration must be provided when connection_mode is 'ssh'")
        return v


class GoogleDriveConfig(BaseModel):
    """Google Drive cloud storage credentials and target settings."""
    auth_mode: Literal["service_account", "oauth_user"] = Field(
        "service_account",
        description="Authentication method: service_account (headless) or oauth_user"
    )
    service_account_file: Optional[str] = Field(
        None, description="Path to Google Service Account JSON key"
    )
    oauth_client_file: Optional[str] = Field(
        None, description="Path to OAuth2 client_secret.json"
    )
    oauth_token_file: Optional[str] = Field(
        "token.json", description="Path to store saved OAuth2 user tokens"
    )
    root_folder_name: str = Field(
        "Backups_Enterprise", description="Name of the root backup folder in Google Drive"
    )
    root_folder_id: Optional[str] = Field(
        None, description="Explicit Google Drive folder ID to use as root (overrides root_folder_name)"
    )
    shared_drive_id: Optional[str] = Field(
        None, description="Optional Google Shared Drive (Team Drive) ID"
    )


class AppConfig(BaseModel):
    """Root configuration for the Backup Service."""
    storage_provider: Literal["gdrive", "local"] = Field(
        "gdrive", description="Storage backend ('gdrive' for cloud or 'local' for local testing/NAS)"
    )
    local_storage_root: str = Field(
        "./local_cloud_backup", description="Target directory when storage_provider is local"
    )
    gdrive: GoogleDriveConfig = Field(default_factory=GoogleDriveConfig)
    staging_dir: str = Field(
        "./temp_staging", description="Temporary staging area for assembling payloads"
    )
    catalog_db_path: str = Field(
        "./backup_catalog.sqlite", description="Path to SQLite catalog database tracking state"
    )
    retention_days_default: int = Field(10, description="Default retention days if not overridden per client")
    clients: List[ClientConfig] = Field(..., min_length=1, description="List of configured clients")

    @classmethod
    def from_yaml_file(cls, file_path: str) -> "AppConfig":
        """Load and validate AppConfig from a YAML file with env var expansion."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")

        raw_content = path.read_text(encoding="utf-8")
        expanded_content = expand_env_vars(raw_content)
        parsed_yaml = yaml.safe_load(expanded_content)

        if not isinstance(parsed_yaml, dict):
            raise ValueError(f"Invalid YAML content in {path}: expected dictionary root")

        return cls(**parsed_yaml)
