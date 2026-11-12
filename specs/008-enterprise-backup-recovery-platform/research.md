# Research & Architectural Decisions: 008-enterprise-backup-recovery-platform

## 1. Web Application Framework & Architecture

- **Decision**: Python 3 (FastAPI) backend with Jinja2 + Modern Responsive UI (Tailwind CSS + Vanilla JS / Alpine.js).
- **Rationale**:
  - Direct native compatibility with the existing Python backup engine (`google-api-python-client`, `paramiko`, `sqlite3`, `pydantic`).
  - Zero cross-language serialization friction: The API server can directly trigger orchestrator runs and stream background jobs.
  - High performance: ASGI asynchronous non-blocking I/O allows streaming logs and long-running backup operations without blocking the web UI.
  - Turnkey deployment: Single unified service (`uvicorn` / `gunicorn`) requiring only standard Python dependencies.
- **Alternatives Considered**:
  - *Node.js / Express backend*: Would require bridging or executing Python CLI as a subprocess for every operation, adding IPC latency, subprocess management complexity, and double dependency trees.
  - *PHP monolithic web interface*: Legacy PHP in `startcalibration` lacks asynchronous job streaming and native multi-cloud SDKs for Google Drive and OneDrive.

---

## 2. Cryptographic Security & Credential Vault

- **Decision**: Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM (via Python `cryptography` library) with PBKDF2-HMAC-SHA256 key derivation.
- **Rationale**:
  - Passwords and SSH private keys must never be stored in plaintext.
  - AES-256-GCM ensures both confidentiality and integrity (detects tampering/bit-flipping).
  - An application master key is derived from an environment variable (`BACKUP_MASTER_KEY` / `SECRET_KEY`) with fallback to a secured local master key file (`.vault_key` with 0600 permissions).
- **Alternatives Considered**:
  - *Plain Base64 encoding*: Insecure, fails basic compliance.
  - *HashiCorp Vault*: Excellent for hyperscale, but excessive operational overhead for a self-hosted single-node or hybrid backup appliance.

---

## 3. Storage Provider Architecture & Extensibility

- **Decision**: Abstract `StorageProvider` interface with provider implementations:
  1. `GoogleDriveProvider`: Google Drive API v3 (Service Account JSON & OAuth2).
  2. `OneDriveProvider`: Microsoft Graph API (`/me/drive/root` & app permissions).
  3. `LocalStorageProvider`: Local filesystem and mounted NAS storage.
  4. `S3TeraBoxProvider`: S3-compatible cloud API (supports MinIO, AWS S3, Wasabi, Backblaze B2, and TeraBox S3 endpoints).
- **Rationale**:
  - Decouples business logic and orchestration from specific cloud APIs.
  - Guarantees uniform client directory hierarchy across all providers.
  - Enables effortless addition of future storage targets.

---

## 4. Disaster Recovery & Restoration Engine

- **Decision**: Two-phase point-in-time restoration engine with dry-run verification:
  - **Phase 1: Manifest & Target Validation**: Verifies destination server connectivity, checks target filesystem permissions, and confirms database connection parameters with SSL.
  - **Phase 2: Execution & Streaming**:
    - For Files: Downloads snapshot archives or copies files to destination (preserving relative folder structure).
    - For Databases: Streams `.sql.gz` through decompression into `mysql` or `psql` command either locally or via SSH stdin pipe.
  - **Archive Discovery / Reconnection**: A crawler module that accepts a storage provider and root folder, scans for `{client_id}/master/` and `{client_id}/incremental/`, parses `manifest.json` files, and automatically populates the local metadata catalog.
- **Rationale**:
  - Full point-in-time recovery to original or *new* servers fulfills enterprise Disaster Recovery (RTO / RPO) standards.
  - Reconnection allows a completely fresh installation to immediately recognize and restore from past backups.

---

## 5. Job Scheduling & Concurrency Control

- **Decision**: Background scheduler (`APScheduler` / Asyncio background loop) with transactional job locking.
- **Rationale**:
  - Lightweight, embedded, requires no external Redis/RabbitMQ broker for standalone installations, yet fully capable of executing Cron expressions (`0 2 * * *`) and interval jobs.
  - State locks prevent concurrent backup jobs for the same client.
