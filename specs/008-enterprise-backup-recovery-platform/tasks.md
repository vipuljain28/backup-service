# Tasks: 008-enterprise-backup-recovery-platform

**Input**: Design documents from `/specs/008-enterprise-backup-recovery-platform/`  
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

## Format: `[TaskID] [P?] [Story] Description with file path`
- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: User story mapping (US1, US2, US3, US4, US5, US6)

---

## Phase 1: Setup (Shared Infrastructure)

- [x] T001 Initialize package structure and directory layout in `backup_service/`
- [x] T002 Update dependency manifests in `backup_service/requirements.txt`
- [x] T003 [P] Configure code formatting and linting rules in `backup_service/pyproject.toml`

---

## Phase 2: Foundational (Security, Cryptography & Metadata Store)

- [x] T004 Implement AES-256-GCM Cryptographic Vault in `backup_service/security/vault.py`
- [x] T005 [P] Implement password hashing, JWT token handling, and RBAC guards in `backup_service/security/auth.py`
- [x] T006 [P] Implement immutable security audit logging engine in `backup_service/security/audit.py`
- [x] T007 Implement relational metadata database models in `backup_service/security/models.py`
- [x] T008 Implement database initialization and migration routine in `backup_service/security/db.py`

---

## Phase 3: User Story 1 - Authentication, RBAC & Security Admin (Priority: P1)

- [x] T009 [US1] Create authentication endpoints (login, logout, me, refresh) in `backup_service/web/routes/auth_routes.py`
- [x] T010 [US1] Implement user management and role assignment in `backup_service/web/routes/user_routes.py`
- [x] T011 [US1] Implement security audit log query endpoints in `backup_service/web/routes/audit_routes.py`
- [x] T012 [P] [US1] Create secure login and user administration templates in `backup_service/web/templates/login.html` and `users.html`
- [x] T013 [US1] Write unit tests for vault encryption and RBAC enforcement in `backup_service/tests/test_security.py`

---

## Phase 4: User Story 2 - Multi-Cloud Storage Hub (Priority: P1)

- [x] T014 [US2] Enhance Google Drive API v3 provider in `backup_service/storage/gdrive.py`
- [x] T015 [P] [US2] Implement Microsoft OneDrive Graph API provider in `backup_service/storage/onedrive.py`
- [x] T016 [P] [US2] Implement S3-compatible / TeraBox cloud provider in `backup_service/storage/s3_terabox.py`
- [x] T017 [US2] Create storage configuration and test connection endpoints in `backup_service/web/routes/storage_routes.py`
- [x] T018 [US2] Write unit tests for storage providers in `backup_service/tests/test_storage.py`

---

## Phase 5: User Story 3 - Client, Server & Target Management with Directory Explorer (Priority: P1)

- [x] T019 [US3] Implement interactive Directory Explorer for Local and SSH hosts in `backup_service/drivers/explorer.py`
- [x] T020 [US3] Implement database connection and SSL verification engine in `backup_service/drivers/db_checker.py`
- [x] T021 [US3] Create Client, Server, Database, and Folder management endpoints in `backup_service/web/routes/client_routes.py`
- [x] T022 [US3] Create Directory Browser modal and API endpoint in `backup_service/web/routes/explorer_routes.py`
- [x] T023 [P] [US3] Create client administration UI template in `backup_service/web/templates/clients.html`
- [x] T024 [US3] Write unit tests for directory exploration and DB SSL verification in `backup_service/tests/test_explorer.py`

---

## Phase 6: User Story 4 - Automated Scheduling, Non-Destructive Delta & Retention (Priority: P1)

- [x] T025 [US4] Integrate background job scheduler and Cron manager in `backup_service/core/scheduler.py`
- [x] T026 [US4] Integrate backup execution pipeline with web notifications in `backup_service/web/routes/backup_routes.py`
- [x] T027 [US4] Create schedule management endpoints in `backup_service/web/routes/schedule_routes.py`
- [x] T028 [P] [US4] Create live backup monitor and job history UI in `backup_service/web/templates/backups.html`
- [x] T029 [US4] Write unit tests for scheduling and non-destructive delta in `backup_service/tests/test_scheduler.py`

---

## Phase 7: User Story 5 - Disaster Recovery, Flexible Restore & Archive Reconnect (Priority: P2)

- [x] T030 [US5] Implement Point-in-Time Restore Engine (to original or new location) in `backup_service/core/restore.py`
- [x] T031 [US5] Implement Existing Backup Archive Reconnection / Crawler in `backup_service/core/reconnect.py`
- [x] T032 [US5] Create restoration endpoints (trigger restore, live restore log stream) in `backup_service/web/routes/restore_routes.py`
- [x] T033 [US5] Create "Import Existing Backups" endpoint in `backup_service/web/routes/reconnect_routes.py`
- [x] T034 [P] [US5] Create Disaster Recovery and Restoration UI in `backup_service/web/templates/restore.html`
- [x] T035 [US5] Write unit tests for disaster recovery and reconnect in `backup_service/tests/test_restore.py`

---

## Phase 8: User Story 6 - Web UI Management Console & GitHub Self-Update (Priority: P2)

- [x] T036 [US6] Assemble FastAPI application, middleware, static assets, and templates in `backup_service/web/server.py`
- [x] T037 [US6] Create Executive Dashboard overview template in `backup_service/web/templates/dashboard.html`
- [x] T038 [US6] Create responsive base layout and navigation in `backup_service/web/templates/base.html`
- [x] T039 [US6] Implement GitHub self-update checker and release viewer in `backup_service/core/updater.py`
- [x] T040 [US6] Create System health and update endpoints in `backup_service/web/routes/system_routes.py`
- [x] T041 [US6] Create System settings and update UI in `backup_service/web/templates/system.html`

---

## Phase 9: CI/CD, Automated Tests with HTML Reporting & Installation Guide

- [x] T042 Implement comprehensive test runner with HTML report generation in `backup_service/tests/run_all_tests.py`
- [x] T043 [P] Create automated Linux installation script in `backup_service/deploy/install.sh`
- [x] T044 [P] Create Systemd service and timer units in `backup_service/deploy/backup-service.service` and `backup-service.timer`
- [x] T045 [P] Create Dockerfile for containerized deployment in `backup_service/deploy/Dockerfile`
- [x] T046 Create GitHub Actions CI/CD workflow in `.github/workflows/ci.yml`
