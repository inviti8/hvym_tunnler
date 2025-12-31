#!/bin/bash

# OpenZiti Configuration
ZITI_VERSION="0.32.4"
ZITI_USER="ziti"
ZITI_HOME="/opt/ziti"
ZITI_BIN_DIR="${ZITI_HOME}/bin"
ZITI_CTRL_PORT="6262"
ZITI_CTRL_EDGE_PORT="1280"
ZITI_EDGE_ROUTER_PORT="3022"
ZITI_EDGE_ROUTER_TRANSPORT_PORT="10080"

# Network Configuration
PUBLIC_IP=$(curl -s ifconfig.me || echo "YOUR_PUBLIC_IP")
DOMAIN_NAME="your-domain.com"  # Change this to your domain

# Database Configuration
ZITI_DB_PATH="${ZITI_HOME}/db/ziti.db"

# Service Configuration
ZITI_SERVICES=("tunnel-service")
ZITI_ADMIN_USERNAME="admin"
ZITI_ADMIN_PASSWORD=$(openssl rand -base64 24 | tr -d '=+/' | head -c 32)

# Output colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Export variables for subscripts
export ZITI_VERSION ZITI_USER ZITI_HOME ZITI_BIN_DIR ZITI_CTRL_PORT ZITI_CTRL_EDGE_PORT

echo -e "${GREEN}Configuration loaded successfully${NC}"

# Create directories if they don't exist
mkdir -p "${ZITI_HOME}/configs"
chown -R ${ZITI_USER}:${ZITI_USER} "${ZITI_HOME}"
