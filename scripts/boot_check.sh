#!/bin/bash
#
# HVYM Tunnler Boot Health Check
#
# This script runs on every boot via systemd (hvym-tunnler-boot.service)
# to verify the server identity is intact before starting the main service.
#
# Exit codes:
#   0 - All checks passed
#   1 - Critical error (missing .env when marker exists)
#

set -euo pipefail

# Configuration
MARKER_DIR="/var/lib/hvym-tunnler"
MARKER_FILE="${MARKER_DIR}/.initialized"
HVYM_HOME="/home/hvym"
TUNNLER_DIR="${HVYM_HOME}/hvym_tunnler"
ENV_FILE="${TUNNLER_DIR}/.env"
LOG_TAG="hvym-tunnler-boot"

# Logging helper
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
    logger -t "$LOG_TAG" "$1" 2>/dev/null || true
}

log "Boot check starting..."

# Check 1: Has initialization ever completed?
if [[ ! -f "$MARKER_FILE" ]]; then
    log "WARNING: Server not initialized (marker file missing)"
    log "         Run the initialization script or cloud-init"
    log "         Marker expected at: $MARKER_FILE"
    # Don't block boot - just warn
    exit 0
fi

log "Initialization marker found"

# Check 2: Is the .env file present?
if [[ ! -f "$ENV_FILE" ]]; then
    log "CRITICAL: .env file missing but initialization marker exists!"
    log "          Server identity has been lost."
    log "          Expected at: $ENV_FILE"
    log ""
    log "          Recovery options:"
    log "          1. Restore .env from backup"
    log "          2. Delete $MARKER_FILE and reinitialize"
    log "             (WARNING: All clients will need reconfiguration)"
    log ""
    # This is a critical error - exit with error code
    exit 1
fi

log ".env file present"

# Check 3: Does .env contain required variables?
if ! grep -q "TUNNLER_SERVER_ADDRESS=" "$ENV_FILE"; then
    log "CRITICAL: .env file exists but missing TUNNLER_SERVER_ADDRESS"
    exit 1
fi

if ! grep -q "TUNNLER_SERVER_SECRET=" "$ENV_FILE"; then
    log "CRITICAL: .env file exists but missing TUNNLER_SERVER_SECRET"
    exit 1
fi

log "Server identity variables present"

# Check 4: Verify QR code and metadata exist (regenerate if missing)
STATIC_DIR="${TUNNLER_DIR}/static"
DATA_DIR="${TUNNLER_DIR}/data"
QR_FILE="${STATIC_DIR}/server_identity_qr.png"
META_FILE="${DATA_DIR}/server_identity.json"

if [[ ! -f "$QR_FILE" ]] || [[ ! -f "$META_FILE" ]]; then
    log "WARNING: QR code or metadata missing, regenerating..."

    # Extract domain from .env
    DOMAIN=$(grep "TUNNLER_DOMAIN=" "$ENV_FILE" | cut -d= -f2 || echo "tunnel.heavymeta.art")

    # Run setup_identity.py to regenerate (won't overwrite .env without --force)
    if [[ -f "${TUNNLER_DIR}/venv/bin/python" ]]; then
        sudo -u hvym "${TUNNLER_DIR}/venv/bin/python" \
            "${TUNNLER_DIR}/scripts/setup_identity.py" \
            --domain "$DOMAIN" || log "WARNING: Failed to regenerate QR/metadata"
    fi
fi

# Check 5: Log server address for reference
SERVER_ADDR=$(grep "TUNNLER_SERVER_ADDRESS=" "$ENV_FILE" | cut -d= -f2)
log "Server identity intact: ${SERVER_ADDR:0:10}...${SERVER_ADDR: -10}"

# Check 6: Verify marker file contents (informational)
if [[ -f "$MARKER_FILE" ]]; then
    INIT_DATE=$(grep -o '"initialized_at"[[:space:]]*:[[:space:]]*"[^"]*"' "$MARKER_FILE" 2>/dev/null | cut -d'"' -f4 || echo "unknown")
    log "Initialized on: $INIT_DATE"
fi

log "Boot check completed successfully"
exit 0
