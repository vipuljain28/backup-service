# Quickstart & Verification Guide: 008-enterprise-backup-recovery-platform

## 1. Prerequisites
- Python 3.9+ (Python 3.13 supported)
- Standard tools: OpenSSH client, `mysqldump` / `mariadb-dump` or `pg_dump`
- Web Browser (Chrome, Firefox, Edge, Safari)

---

## 2. Quick Installation & Launch

```bash
# 1. Install dependencies
pip install -r backup_service/requirements.txt

# 2. Start the Enterprise Management Web Server
python -m backup_service.web.server --port 8080 --host 0.0.0.0
```

Access the Web Management Console at: `http://localhost:8080`  
Default Initial Credentials:
- **Username**: `admin`
- **Password**: `admin@STAR2026!` *(Enforced password change on first login)*

---

## 3. End-to-End Operational Verification Scenarios

### Scenario A: Role-Based Access Control (RBAC)
1. Navigate to `/security`.
2. Create an operator account (`op_user`) and an auditor account (`auditor_user`).
3. Log in as `auditor_user` and attempt to trigger a backup or delete a client.
4. **Expected**: System blocks mutation with HTTP 403 Forbidden and records an audit log.

### Scenario B: Multi-Cloud Destination Setup
1. Navigate to `/storage`.
2. Click **Add Storage Destination**.
3. Choose **Google Drive**:
   - Upload `service_account.json` or specify OAuth credentials.
   - Set root folder name: `STAR_Enterprise_Backups`.
   - Click **Test Connection** -> Status returns `CONNECTED [OK]`.
4. Choose **Local / NAS** or **S3 / TeraBox**:
   - Provide credentials and click **Test Connection** -> Verified successfully.

### Scenario C: Server Connection & Interactive Directory Explorer
1. Navigate to `/servers` -> Click **Add Server Connection**.
2. Select **SSH Remote** mode:
   - Provide hostname (e.g. `192.168.1.100`), user, and upload SSH private key.
   - Click **Test Connection** -> Status returns `CONNECTED [OK]`.
3. In the Client configuration under **Folders to Back Up**:
   - Click **Browse Server**.
   - Navigate the interactive directory tree and select target directory (e.g. `/var/www/uploads`).
   - Click **Use Selected Path** -> Path automatically populates with zero typing.

### Scenario D: Database Configuration with SSL
1. In the Client configuration under **Databases**:
   - Select engine: `MySQL`.
   - Enter host, port (3306), username, password, and database name.
   - Toggle **SSL Enabled** (Optional: upload CA certificate).
   - Click **Test DB Connection** -> Verifies connection and SSL handshake.

### Scenario E: Backup Execution & Non-Destructive Delta Verification
1. Trigger backup manually or via schedule.
2. In the Live Job Monitor, watch progress bars for:
   - Full Database dump (compressed stream)
   - File differential scan
   - Google Drive chunked upload
3. Delete a file on the source directory and run the backup again:
   - Verify `manifest.txt` records: `[DELETED IN SOURCE] ... [RETAINED IN BACKUP MASTER]`.
   - Verify file is STILL preserved in Google Drive `master/files/`.

### Scenario F: Restore to a New Location (Disaster Recovery)
1. Navigate to `/restores` -> Click **New Restore Job**.
2. Select a backup snapshot from the inventory.
3. Select **Restore to New Location**:
   - Target Server: `DR_Backup_Server_02`
   - Target Directory: `/opt/restored_data`
   - Target Database: `star_dr_recovered`
4. Click **Start Restore**:
   - System unpackages files and streams SQL dump to the new target.

### Scenario G: Connect New Installation with Existing Backups
1. On a completely new installation:
2. Navigate to `/restores/import-existing`.
3. Select the Storage Provider (e.g. Google Drive) and enter existing root folder `STAR_Enterprise_Backups`.
4. Click **Scan & Import**:
   - The platform auto-discovers all client folders, reads `manifest.json` files, and reconstitutes the full disaster recovery catalog.

---

## 4. Automated Testing & Report Generation

Run all unit, integration, and security tests with HTML reporting:
```bash
python -m backup_service.tests.run_all_tests --html-report
```
Outputs report to `backup_service/tests/test_report.html`.
