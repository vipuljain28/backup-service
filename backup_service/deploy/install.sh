#!/usr/bin/env bash
# ==============================================================================
# Enterprise Backup & Recovery Management Platform Installation Script
# ==============================================================================
set -euo pipefail

INSTALL_DIR="/opt/lims_backup"
SERVICE_USER="limsbackup"

echo "======================================================================"
echo " LIMS BACKUP ENTERPRISE PLATFORM INSTALLATION"
echo "======================================================================"

# 1. Check Root Privileges
if [ "$EUID" -ne 0 ]; then
  echo "[!] Please run as root (sudo bash install.sh)"
  exit 1
fi

# 2. Install System Dependencies
echo "[+] Installing system prerequisites..."
if command -v apt-get &>/dev/null; then
  apt-get update -y
  apt-get install -y python3 python3-pip python3-venv git openssh-client default-mysql-client postgresql-client
elif command -v yum &>/dev/null; then
  yum install -y python3 python3-pip git openssh-clients mariadb postgresql
fi

# 3. Create Dedicated Service User
if ! id "$SERVICE_USER" &>/dev/null; then
  echo "[+] Creating dedicated system user '$SERVICE_USER'..."
  useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
fi

# 4. Create App Directory & Virtualenv
echo "[+] Setting up installation directory at $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
python3 -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip

# 5. Install Dependencies
echo "[+] Installing Python dependencies..."
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt

# 6. Setup Secure Permissions
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 700 "$INSTALL_DIR"

# 7. Install Systemd Services
echo "[+] Registering Systemd web service and scheduler timer..."
cp deploy/backup-service.service /etc/systemd/system/
cp deploy/backup-service.timer /etc/systemd/system/

systemctl daemon-reload
systemctl enable --now backup-service.service
systemctl enable --now backup-service.timer

echo "======================================================================"
echo "[SUCCESS] Installation Complete!"
echo " Web Console running on: http://<SERVER_IP>:8080"
echo " Initial Credentials   : admin / admin@LIMS2026!"
echo " Status Check          : systemctl status backup-service.service"
echo "======================================================================"
