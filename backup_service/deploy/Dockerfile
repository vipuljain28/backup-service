# ==============================================================================
# Enterprise Backup & Disaster Recovery Platform Docker Container
# ==============================================================================
FROM python:3.13-slim

WORKDIR /app

# Install system utilities: OpenSSH, MySQL & PostgreSQL dump binaries
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-client \
    default-mysql-client \
    postgresql-client \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . /app/backup_service

ENV PYTHONUNBUFFERED=1
ENV METADATA_DB_PATH=/data/metadata.sqlite

VOLUME ["/data", "/app/local_cloud_backup"]
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/v1/system/health || exit 1

CMD ["python", "-m", "backup_service.web.server", "--host", "0.0.0.0", "--port", "8080"]
