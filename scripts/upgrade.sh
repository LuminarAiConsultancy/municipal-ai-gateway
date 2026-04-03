#!/bin/sh
# Upgrade the Canadian Municipal AI Gateway to the latest version.
#
# Usage:
#   ./scripts/upgrade.sh
#
# What this script does:
#   1. Creates a database backup
#   2. Pulls the latest code from git
#   3. Rebuilds and restarts containers
#   4. Runs a health check
#   5. If the health check fails, rolls back to the previous version
#
# Requirements:
#   - Git
#   - Docker Compose
#   - The gateway must already be running
set -e

HEALTH_URL="${HEALTH_URL:-https://localhost/health}"
HEALTH_RETRIES=12
HEALTH_INTERVAL=5

echo "===== Canadian Municipal AI Gateway Upgrade ====="
echo ""

# Step 1: Record current commit for rollback
PREVIOUS_COMMIT=$(git rev-parse HEAD)
echo "Current version: ${PREVIOUS_COMMIT}"

# Step 2: Backup the database
echo ""
echo "[1/5] Backing up database..."
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="pre_upgrade_${TIMESTAMP}.sql.gz"
docker compose exec -T db pg_dump \
    -U "${POSTGRES_USER:-gateway}" \
    --no-owner --no-acl \
    "${POSTGRES_DB:-ai_gateway}" \
    | gzip > "${BACKUP_FILE}"
echo "       Backup saved: ${BACKUP_FILE}"

# Step 3: Pull latest code
echo ""
echo "[2/5] Pulling latest code..."
git pull --ff-only origin main
NEW_COMMIT=$(git rev-parse HEAD)
echo "       Updated to: ${NEW_COMMIT}"

if [ "${PREVIOUS_COMMIT}" = "${NEW_COMMIT}" ]; then
    echo ""
    echo "Already up to date. Nothing to do."
    rm -f "${BACKUP_FILE}"
    exit 0
fi

# Step 4: Rebuild and restart
echo ""
echo "[3/5] Rebuilding containers..."
docker compose build --quiet

echo ""
echo "[4/5] Restarting services..."
docker compose up -d

# Step 5: Health check
echo ""
echo "[5/5] Waiting for health check..."
HEALTHY=false
for i in $(seq 1 ${HEALTH_RETRIES}); do
    sleep ${HEALTH_INTERVAL}
    if curl -sf -k "${HEALTH_URL}" > /dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    echo "       Attempt ${i}/${HEALTH_RETRIES} — not healthy yet..."
done

if [ "${HEALTHY}" = "true" ]; then
    echo ""
    echo "===== Upgrade successful ====="
    echo "Version: ${NEW_COMMIT}"
    echo "Backup:  ${BACKUP_FILE} (safe to delete after verification)"
    exit 0
fi

# Rollback
echo ""
echo "HEALTH CHECK FAILED — rolling back to ${PREVIOUS_COMMIT}"
echo ""

git checkout "${PREVIOUS_COMMIT}"
docker compose build --quiet
docker compose up -d

# Wait for rollback health
ROLLBACK_HEALTHY=false
for i in $(seq 1 ${HEALTH_RETRIES}); do
    sleep ${HEALTH_INTERVAL}
    if curl -sf -k "${HEALTH_URL}" > /dev/null 2>&1; then
        ROLLBACK_HEALTHY=true
        break
    fi
done

if [ "${ROLLBACK_HEALTHY}" = "true" ]; then
    echo "Rollback successful. Gateway is running on previous version."
    echo "Backup file preserved: ${BACKUP_FILE}"
    echo ""
    echo "Investigate the failed upgrade before retrying."
    exit 1
else
    echo "CRITICAL: Rollback also failed. Manual intervention required."
    echo "Database backup: ${BACKUP_FILE}"
    echo "Previous commit: ${PREVIOUS_COMMIT}"
    exit 2
fi
