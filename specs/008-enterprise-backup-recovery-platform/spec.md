# Feature Specification: 008-enterprise-backup-recovery-platform

**Feature Branch**: `008-enterprise-backup-recovery-platform`  
**Created**: 2026-11-12  
**Status**: Approved  
**Input**: User description: "Create a secure web application to manage the backups and follow all security standards and enterprise level admin and code like installation guide, options to connect Google Drive, OneDrive, Local, TeraBox/S3, option to connect server or run self, schedule backup, create client, add folders with directory browser, add DB using password, username, host, SSL options, non-destructive delta sync, 10-day retention, recovery at new location, connect new installation with existing backups, permission management, CI/CD, update through GitHub, unit testing and test reports."

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Enterprise Authentication, RBAC & Security Vault (Priority: P1)

As a System Administrator, I want to securely log in to an administrative web console protected by Role-Based Access Control (RBAC), multi-factor readiness, and audit logging, so that credentials for databases and SSH servers are encrypted at rest with zero data leakage.

**Why this priority**: Foundational security gate. An enterprise backup platform must protect sensitive infrastructure credentials (database passwords, SSH private keys) and enforce least privilege.

**Independent Test**: Can be tested by creating roles (`Admin`, `Operator`, `Auditor`), authenticating, verifying token lifecycles, and ensuring an unauthorized user cannot view decrypted secrets or perform restricted actions.

**Acceptance Scenarios**:
1. **Given** an unauthenticated visitor, **When** they request any management endpoint, **Then** the system rejects the request with HTTP 401 and redirects to the secure login interface.
2. **Given** an authenticated user with `Auditor` role, **When** they attempt to trigger a backup or edit client credentials, **Then** the system blocks the mutation with HTTP 403 Forbidden and logs an authorization failure.
3. **Given** an administrator saving a database password or private SSH key, **When** the entity is stored, **Then** the secret is encrypted with AES-256-GCM before writing to the database, and audit logs record the configuration change.

---

### User Story 2 - Multi-Cloud & Hybrid Storage Provider Hub (Priority: P1)

As a Backup Administrator, I want to configure and verify multiple storage destinations including Google Drive (Service Account / OAuth), Microsoft OneDrive (Microsoft Graph), Local Storage / NAS, and S3-compatible / TeraBox storage, so that backups can be stored securely across hybrid cloud infrastructures.

**Why this priority**: The core value proposition is reliable data durability across major cloud providers with uniform remote folder hierarchies.

**Independent Test**: Can be tested by configuring credentials for each storage type, running the "Test Connection" diagnostic action, and verifying folder creation and token refreshes.

**Acceptance Scenarios**:
1. **Given** valid Google Cloud Service Account credentials, **When** the administrator validates the connection, **Then** the system verifies read/write access to Google Drive API v3 and caches the root directory identifier.
2. **Given** Microsoft OneDrive credentials, **When** testing the connection, **Then** the system executes a token handshake against Microsoft Graph API and confirms storage availability.
3. **Given** a designated storage provider, **When** a client backup is routed to it, **Then** the provider creates a standardized directory structure (`{root}/{client_name}/master/` and `{root}/{client_name}/incremental/{date}/`).

---

### User Story 3 - Client, Server & Target Management with Directory Explorer (Priority: P1)

As an Operator, I want to define clients (tenants), configure server connection parameters (Localhost or SSH with key/password), explore remote file directories interactively in the browser, and specify databases with optional SSL encryption, so that backup targets can be configured without manual CLI typing.

**Why this priority**: Eliminates human error during configuration and provides seamless remote file exploration and multi-database targeting.

**Independent Test**: Can be tested by adding a client, testing SSH connectivity, fetching the remote directory tree via the Directory Browser API, and configuring database connections with SSL enabled/disabled.

**Acceptance Scenarios**:
1. **Given** a configured SSH server, **When** the operator opens the "Directory Browser" modal in the UI, **Then** the system streams the directory contents of the remote server, allowing path selection with one click.
2. **Given** a MySQL, MariaDB, or PostgreSQL database target, **When** the operator toggles SSL on and provides credentials, **Then** the system performs a connectivity test using parameterized health checks.
3. **Given** multiple folder paths and databases defined for a client, **When** saved, **Then** all relationships are persisted atomically with encrypted credential references.

---

### User Story 4 - Automated Scheduling, Non-Destructive Delta Sync & 10-Day Retention (Priority: P1)

As a System Administrator, I want automated background jobs that run according to configurable schedules, execute full database dumps, compute non-destructive file deltas, and enforce a 10-day sliding retention policy, so that current data is preserved in `master/` and historical snapshots are preserved in date-wise folders without data loss.

**Why this priority**: Delivers the core operational automated backup promise of the platform.

**Independent Test**: Can be tested by scheduling or manually triggering a backup run, verifying that added/modified files go to incremental + master, deleted files are preserved in master with audit manifest entries, and snapshots older than 10 days are purged.

**Acceptance Scenarios**:
1. **Given** an automated schedule (e.g. daily at 02:00 AM), **When** triggered, **Then** the backup service dumps all configured client databases into `.sql.gz` and copies delta files to `{client_id}/incremental/{YYYY-MM-DD}/`.
2. **Given** a file deleted on the source server, **When** the backup executes, **Then** the file is NOT deleted from Google Drive `master/files/`, and `manifest.txt` records `[DELETED IN SOURCE] (Preserved in backup master)`.
3. **Given** existing incremental date folders older than 10 days on Google Drive, **When** the retention cycle executes, **Then** expired date folders and their enclosed database backups are permanently purged while preserving the `master/` folder.

---

### User Story 5 - Disaster Recovery, Flexible Restore & Archive Reconnection (Priority: P2)

As a Disaster Recovery Engineer, I want to restore backups either to their original server or to an entirely new server/path/database, and connect a brand new software installation to existing cloud backup folders, so that full service recovery can be performed after infrastructure failure.

**Why this priority**: Essential for business continuity and disaster recovery scenarios.

**Independent Test**: Can be tested by executing a restoration flow to a staging directory, verifying database restoration, and running the "Import Existing Backups" scan against a pre-populated storage folder.

**Acceptance Scenarios**:
1. **Given** a historical backup snapshot, **When** an operator chooses "Restore to New Location" specifying Target Server B, `/opt/restored_data`, and Target DB `db_restored`, **Then** the system unpackages the files and imports the SQL dump into the new target with progress tracking.
2. **Given** a clean software installation with no local database, **When** the administrator provides the storage credentials and points to an existing Google Drive backup root folder, **Then** the system scans the directory, reconstructs the client inventory, parses existing `manifest.json` files, and makes historical snapshots immediately restorable.

---

### User Story 6 - Operations, Self-Update & GitHub CI/CD Diagnostics (Priority: P2)

As a DevOps Engineer, I want the platform to support seamless deployment (local server self-install or remote manager), automated GitHub-based version updates, and CI/CD test reports, so that the software remains maintainable and verifiable.

**Why this priority**: Ensures long-term operability, zero-friction maintenance, and cloud-native release quality.

**Independent Test**: Can be tested by running the system health/update check endpoint, verifying CI/CD pipeline execution, and checking automated test reporting.

**Acceptance Scenarios**:
1. **Given** a deployed instance, **When** checking for updates, **Then** the platform compares the local git commit/tag against the remote GitHub repository and displays release notes with an authenticated update trigger.
2. **Given** a pull request or release branch, **When** committed, **Then** GitHub Actions executes automated unit tests, produces coverage reports, and verifies installation scripts.

---

## Edge Cases

- **Network Flakiness during Cloud Uploads**: The system must utilize chunked resumable uploads with exponential backoff (HTTP 429/500/503 retry policy).
- **Target Remote Disk Full**: Database dumps over SSH must stream through stdout directly into local staging gzip without writing uncompressed `.sql` files to the remote server.
- **Concurrent Job Collisions**: Job execution locks (using distributed or SQLite transactional mutex) prevent concurrent runs for the same client.
- **Corrupted Source Files**: Permission errors or unreadable files on the source filesystem must be logged as warnings in the manifest without halting the entire backup run.
- **Restoration Target Overwrite Guard**: The restoration engine must require explicit confirmation (`overwrite_existing: true`) before modifying any existing database or file path.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST provide an administrative Web UI and REST API built with secure session/JWT authentication and Role-Based Access Control (Admin, Operator, Auditor).
- **FR-002**: System MUST store all sensitive credentials (database passwords, SSH private keys, cloud tokens) encrypted at rest using AES-256-GCM.
- **FR-003**: System MUST record immutable audit log entries for all configuration changes, backup triggers, restores, and user logins.
- **FR-004**: System MUST support multiple storage providers via a unified interface: Google Drive, Microsoft OneDrive, Local Storage/NAS, and S3-compatible/TeraBox.
- **FR-005**: System MUST provide interactive server directory browsing over both Local and SSH connections for folder selection.
- **FR-006**: System MUST support multiple databases per client across MySQL, MariaDB, and PostgreSQL with configurable SSL options.
- **FR-007**: System MUST support multiple file directory sources per client with glob pattern exclusions.
- **FR-008**: System MUST maintain a uniform Google Drive folder hierarchy for every client: `{client_id}/master/` and `{client_id}/incremental/{YYYY-MM-DD}/`.
- **FR-009**: System MUST perform non-destructive file delta synchronization, never deleting files from `master/` when removed on source, and generating an audit manifest (`manifest.txt` and `manifest.json`).
- **FR-010**: System MUST enforce a 10-day sliding window retention policy on incremental snapshots and database dumps, while strictly preserving `master/`.
- **FR-011**: System MUST provide automated backup scheduling via Cron syntax and on-demand manual triggers.
- **FR-012**: System MUST provide full disaster recovery restoration to original location or a custom new server/path/database.
- **FR-013**: System MUST provide an "Import Existing Backups" feature that scans an existing storage folder and reconstitutes client snapshots on a fresh installation.
- **FR-014**: System MUST include a self-update mechanism checking GitHub repository releases and supporting controlled updates.
- **FR-015**: System MUST include automated unit and integration tests with HTML/JUnit test report output.
- **FR-016**: System MUST provide full installation documentation, systemd service units, and Docker container deployment configurations.

### Key Entities

- **User**: Represents administrative operators with `username`, `password_hash`, `role` (Admin/Operator/Auditor), `is_active`, `created_at`.
- **StorageProviderConfig**: Credentials and parameters for cloud destinations (`type`: `gdrive`, `onedrive`, `local`, `s3_terabox`, `encrypted_credentials`, `is_default`).
- **Client**: Multi-tenant client definition (`client_id`, `display_name`, `retention_days`, `storage_provider_id`, `is_active`).
- **ServerConnection**: Host configuration (`mode`: `local` or `ssh`, `host`, `port`, `user`, `encrypted_key_or_password`).
- **DatabaseTarget**: Database to dump (`client_id`, `server_id`, `engine`: `mysql`/`mariadb`/`postgres`, `host`, `port`, `user`, `encrypted_password`, `db_name`, `ssl_enabled`).
- **FolderSource**: File path to back up (`client_id`, `server_id`, `source_slug`, `absolute_path`, `exclude_patterns`).
- **BackupJob**: Record of scheduled or manual runs (`client_id`, `schedule_id`, `run_date`, `status`, `duration_seconds`, `manifest_json`).
- **RestoreJob**: Record of disaster recovery operations (`backup_job_id`, `target_server_id`, `target_path`, `target_db`, `status`, `logs`).
- **AuditLog**: Security and compliance log (`user_id`, `ip_address`, `action`, `resource_type`, `resource_id`, `status`, `timestamp`).

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Administrators can set up a new client with databases, folders, and cloud storage in under 3 minutes via the Web UI.
- **SC-002**: Directory browsing queries respond in under 500ms for local filesystems and under 1.5s over standard SSH connections.
- **SC-003**: 100% of stored database passwords and private keys are encrypted at rest with zero plaintext leakage in database dumps or logs.
- **SC-004**: Database dumps over SSH produce zero disk overhead on the target remote server by streaming through compressed SSH stdout.
- **SC-005**: Incremental backups for 10,000 files complete scan and delta identification in under 5 seconds.
- **SC-006**: Automated test suite achieves >85% test pass coverage with zero regressions across core security and storage routines.

---

## Assumptions

- Target servers support SSH (OpenSSH) and standard database dump binaries (`mysqldump`, `pg_dump`).
- For Google Drive integration, users have access to Google Cloud Console to create a Service Account or OAuth credentials.
- The web application backend runs on Python 3.9+ with an embedded or external relational database (SQLite for turnkey deployments, PostgreSQL/MySQL for large enterprise clusters).
