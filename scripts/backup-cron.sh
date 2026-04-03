#!/bin/sh
# Daily backup cron job — runs inside the backup container.
# Called by crond at 02:00 daily.
set -e

RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/backups/ai_gateway_${TIMESTAMP}.sql.gz"

echo "[$(date -Iseconds)] Starting daily backup..."

pg_dump --no-owner --no-acl | gzip > "${BACKUP_FILE}"

SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "[$(date -Iseconds)] Backup complete: ${BACKUP_FILE} (${SIZE})"

# Prune backups older than retention period
DELETED=0
find /backups -name "ai_gateway_*.sql.gz" -mtime +${RETENTION_DAYS} -print -delete | while read f; do
    DELETED=$((DELETED + 1))
    echo "[$(date -Iseconds)] Pruned: ${f}"
done

echo "[$(date -Iseconds)] Backup job finished. Retention: ${RETENTION_DAYS} days."
