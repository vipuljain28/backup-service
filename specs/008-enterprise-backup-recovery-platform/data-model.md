# Data Model: 008-enterprise-backup-recovery-platform

## Entity-Relationship Diagram

```mermaid
erDiagram
    User ||--o{ AuditLog : creates
    Client ||--o{ ServerConnection : owns
    Client ||--o{ DatabaseTarget : owns
    Client ||--o{ FolderSource : owns
    Client ||--o{ BackupSchedule : has
    Client ||--o{ BackupJob : executes
    StorageConfig ||--o{ Client : stores_for
    ServerConnection ||--o{ DatabaseTarget : hosts
    ServerConnection ||--o{ FolderSource : hosts
    BackupJob ||--o{ RestoreJob : restores_from
    ServerConnection ||--o{ RestoreJob : target_for

    User {
        int id PK
        string username UK
        string email
        string password_hash
        string role "admin | operator | auditor"
        bool is_active
        datetime created_at
    }

    StorageConfig {
        int id PK
        string name
        string provider_type "gdrive | onedrive | local | s3_terabox"
        text encrypted_credentials "AES-256-GCM"
        bool is_default
        datetime created_at
    }

    Client {
        int id PK
        string client_id UK
        string display_name
        int retention_days "Default 10"
        int storage_config_id FK
        bool is_active
        datetime created_at
    }

    ServerConnection {
        int id PK
        int client_id FK
        string name
        string mode "local | ssh"
        string host
        int port "Default 22"
        string username
        string auth_type "password | key_file | key_text"
        text encrypted_secret "AES-256-GCM"
        datetime created_at
    }

    DatabaseTarget {
        int id PK
        int client_id FK
        int server_id FK
        string name
        string engine "mysql | mariadb | postgres"
        string host
        int port
        string username
        text encrypted_password "AES-256-GCM"
        string db_name
        bool ssl_enabled
        string ssl_options "JSON"
        string dump_options "JSON"
        datetime created_at
    }

    FolderSource {
        int id PK
        int client_id FK
        int server_id FK
        string source_slug
        string absolute_path
        string exclude_patterns "JSON Array"
        datetime created_at
    }

    BackupSchedule {
        int id PK
        int client_id FK
        string name
        string cron_expression "e.g. 0 2 * * *"
        bool is_enabled
        datetime last_run_at
        datetime next_run_at
        datetime created_at
    }

    BackupJob {
        int id PK
        int client_id FK
        string trigger_type "manual | scheduled"
        string status "running | success | failed | partial"
        string run_date "YYYY-MM-DD"
        string run_timestamp
        int files_added
        int files_updated
        int files_deleted
        int dbs_dumped
        bigint total_bytes
        float duration_seconds
        text manifest_json
        text error_message
        datetime created_at
    }

    RestoreJob {
        int id PK
        int backup_job_id FK
        int client_id FK
        int target_server_id FK
        string target_path
        string target_db_name
        string restore_scope "all | files_only | db_only"
        string status "pending | running | success | failed"
        text execution_logs
        datetime created_at
        datetime completed_at
    }

    AuditLog {
        int id PK
        int user_id FK
        string username
        string ip_address
        string action
        string resource_type
        string resource_id
        text details_json
        datetime created_at
    }
```

---

## Field Constraints & Validation Rules

1. **User.role**: Must strictly be one of `['admin', 'operator', 'auditor']`.
2. **Client.client_id**: Lowercase alphanumeric slug `^[a-z0-9_-]{3,64}$`. Unique across system.
3. **Client.retention_days**: Integer $\ge 1$, default $10$.
4. **Encrypted Fields**: All fields marked `encrypted_*` are ciphertext blocks formatted as `v1:<salt_b64>:<nonce_b64>:<tag_b64>:<ciphertext_b64>`. Decryption happens only in memory upon driver initialization.
5. **DatabaseTarget.engine**: `['mysql', 'mariadb', 'postgres']`.
6. **ServerConnection.mode**: `['local', 'ssh']`. If `ssh`, `host` and `username` are required.
7. **AuditLog**: Write-only ledger. Records cannot be updated or deleted through the application API.
