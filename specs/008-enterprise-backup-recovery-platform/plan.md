# Implementation Plan: 008-enterprise-backup-recovery-platform

**Branch**: `008-enterprise-backup-recovery-platform` | **Date**: 2026-11-12 | **Spec**: [spec.md](file:///g:/projects/star/specs/008-enterprise-backup-recovery-platform/spec.md)

**Input**: Feature specification from `/specs/008-enterprise-backup-recovery-platform/spec.md`

## Summary

Build an enterprise-grade, secure Web Application & Management Platform for Backup & Disaster Recovery. Features include multi-tenant client administration, multi-cloud storage (Google Drive, OneDrive, Local/NAS, S3/TeraBox), remote server SSH connection management, interactive directory browsing, database dumps with SSL options, non-destructive delta file tracking, 10-day sliding retention, flexible restoration to new locations, existing backup archive reconnection, RBAC security with AES-256-GCM vault, automated unit testing with report generation, and GitHub-based self-update capabilities.

---

## Technical Context

**Language/Version**: Python 3.9+ (Python 3.13 validated)  
**Primary Dependencies**: FastAPI / Starlette, Uvicorn, Jinja2, Pydantic v2, PyYAML, `google-api-python-client`, `google-auth`, `paramiko`, `cryptography` (AES-256-GCM), `requests`  
**Storage**: SQLite with WAL mode (`metadata.sqlite` and `catalog.sqlite`) with support for external PostgreSQL/MySQL; Google Drive API v3, Microsoft Graph API, Local/NAS, S3/TeraBox  
**Testing**: Python standard test harness with HTML test report generator; CI/CD via GitHub Actions  
**Target Platform**: Linux Server (Ubuntu, Debian, RHEL, CentOS), macOS, Windows Server; Docker container support  
**Project Type**: Secure Web Service & Automated Backup Daemon  
**Performance Goals**: File delta scan of 10,000 files in <5s; Streaming remote DB dumps over SSH with 0 remote disk overhead; Sub-second web UI interactions  
**Constraints**: Zero plaintext credential storage (AES-256-GCM encryption at rest); Zero data loss (deletions on source never delete files in backup master); Strict 10-day retention on incremental snapshots  
**Scale/Scope**: 100+ clients, 1,000+ databases, millions of files, multi-terabyte cloud backups  

---

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- [x] **Principle I (Scope Isolation)**: All new code is cleanly encapsulated in `backup_service/` and `specs/008-enterprise-backup-recovery-platform/`. Forbidden directories (`lims_frontend`, `logs`, `log-analyzer`) are completely untouched.
- [x] **Principle VI (Cyber Security & Zero-Trust)**: Enforces role-based authorization (Admin, Operator, Auditor), AES-256-GCM encryption for all passwords and SSH keys, secure session cookies/JWT, and immutable audit logging. Zero backdoors or bypass flags.
- [x] **Principle VII (Object-Level Authorization)**: Every entity operation (clients, servers, databases, backups, restores) is validated server-side against authenticated user tenancy.
- [x] **Principle IX (SOLID & Clean Layering)**: Strict separation of Presentation (Web UI/API), Application (Orchestrator, Retention, Restore, Schedulers), Domain (Models, Schemas, Vault), and Infrastructure (Drivers, Storage Providers).

---

## Project Structure

```text
backup_service/
├── cli.py                     # CLI entrypoint (run, verify, prune, history, init)
├── requirements.txt           # Python dependencies
├── README.md                  # Comprehensive architectural guide & deployment manual
├── config/
│   ├── settings.py            # Pydantic configuration models & env interpolation
│   └── config.example.yaml    # Annotated multi-client configuration template
├── core/
│   ├── catalog.py             # SQLite state catalog for delta tracking
│   ├── manifest.py            # Audit manifest generator (TXT & JSON)
│   ├── retention.py           # 10-day sliding-window retention engine
│   ├── orchestrator.py        # Central backup orchestrator
│   └── restore.py             # Disaster recovery & point-in-time restore engine
├── security/
│   ├── vault.py               # AES-256-GCM encryption/decryption for credentials
│   ├── auth.py                # Password hashing, JWT token handling, RBAC permissions
│   └── audit.py               # Immutable audit logging engine
├── drivers/
│   ├── base.py                # Abstract SourceDriver interface
│   ├── local_driver.py        # Localhost execution & DB dump
│   ├── ssh_driver.py          # SSH/SFTP driver with stdout streaming
│   └── explorer.py            # Remote & Local interactive directory explorer
├── storage/
│   ├── base.py                # Abstract StorageProvider interface
│   ├── gdrive.py              # Google Drive API v3 provider
│   ├── onedrive.py            # Microsoft OneDrive Graph API provider
│   ├── s3_terabox.py          # S3-compatible / TeraBox cloud provider
│   └── local_storage.py       # Local filesystem & NAS provider
├── web/
│   ├── server.py              # FastAPI web server entrypoint & router assembly
│   ├── routes/                # Modular API & UI endpoints
│   │   ├── auth_routes.py     # Authentication, sessions, user management
│   │   ├── client_routes.py   # Client tenants, servers, databases, folders
│   │   ├── storage_routes.py  # Storage destination configuration & testing
│   │   ├── backup_routes.py   # Job execution, schedules, live monitoring
│   │   ├── restore_routes.py  # Disaster recovery, restore to new server, import existing
│   │   └── system_routes.py   # Health, diagnostics, GitHub self-update
│   ├── static/                # CSS, JavaScript, icons
│   └── templates/             # Jinja2 HTML responsive dashboard views
├── deploy/
│   ├── install.sh             # Linux production automated installation script
│   ├── backup-service.service # Systemd service unit
│   ├── backup-service.timer   # Systemd scheduled timer unit
│   └── Dockerfile             # Containerized deployment specification
├── tests/
│   ├── run_all_tests.py       # Test runner producing HTML & console reports
│   ├── test_security.py       # Vault & RBAC unit tests
│   ├── test_explorer.py       # Directory browser unit tests
│   ├── test_restore.py        # Disaster recovery & reconnect tests
│   ├── test_storage.py        # Multi-cloud provider tests
│   └── test_end_to_end.py     # Full integration tests
└── .github/
    └── workflows/
        └── ci.yml             # GitHub Actions CI/CD pipeline
```
