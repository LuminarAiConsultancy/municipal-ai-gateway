#!/bin/sh
# On-demand PostgreSQL backup.
#
# Usage:
#   ./scripts/backup-now.sh
#
# Runs pg_dump against the running database container and saves a
# gzipped SQL file to the backups/ volume. The file is named with
# the current timestamp.
set -e

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="ai_gateway_${TIMESTAMP}.sql.gz"

echo "Creating backup..."
docker compose exec -T db pg_dump \
    -U "${POSTGRES_USER:-gateway}" \
    --no-owner --no-acl \
    "${POSTGRES_DB:-ai_gateway}" \
    | gzip > "${BACKUP_FILE}"

SIZE=$(du -h "${BACKUP_FILE}" | cut -f1)
echo "Backup saved: ${BACKUP_FILE} (${SIZE})"
echo ""
echo "To restore from this backup:"
echo "  ./scripts/restore.sh ${BACKUP_FILE}"
