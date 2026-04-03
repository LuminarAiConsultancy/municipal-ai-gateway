#!/bin/sh
# Restore PostgreSQL from a backup file.
#
# Usage:
#   ./scripts/restore.sh <backup-file.sql.gz>
#
# WARNING: This replaces all data in the database.
set -e

if [ -z "$1" ]; then
    echo "Usage: ./scripts/restore.sh <backup-file.sql.gz>"
    echo ""
    echo "Available backups:"
    ls -lh *.sql.gz 2>/dev/null || echo "  (none in current directory)"
    echo ""
    echo "Backups from the backup container are in the 'backups' Docker volume."
    echo "To list them: docker compose exec backup ls -lh /backups/"
    exit 1
fi

BACKUP_FILE="$1"

if [ ! -f "${BACKUP_FILE}" ]; then
    echo "Error: File not found: ${BACKUP_FILE}"
    exit 1
fi

DB_USER="${POSTGRES_USER:-gateway}"
DB_NAME="${POSTGRES_DB:-ai_gateway}"

echo "WARNING: This will replace ALL data in the '${DB_NAME}' database."
echo "Backup file: ${BACKUP_FILE}"
echo ""
printf "Type 'yes' to continue: "
read CONFIRM
if [ "${CONFIRM}" != "yes" ]; then
    echo "Restore cancelled."
    exit 0
fi

echo ""
echo "Stopping gateway to prevent writes..."
docker compose stop gateway

echo "Restoring from ${BACKUP_FILE}..."
gunzip -c "${BACKUP_FILE}" | docker compose exec -T db psql -U "${DB_USER}" -d "${DB_NAME}" --quiet

echo "Restarting gateway..."
docker compose start gateway

echo ""
echo "Restore complete. Verify with:"
echo "  curl -k https://localhost/health"
