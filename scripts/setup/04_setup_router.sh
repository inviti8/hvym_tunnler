#!/bin/bash

# Exit on error and print each command
set -ex

# Source the configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR%/*}/config.sh"

# Create router configuration
cat > "${ZITI_HOME}/configs/router.yaml" << ROUTER_CONFIG
v: 3

name: edge-router
listeners:
  - binding: edge
    address: tcp:0.0.0.0:${ZITI_EDGE_ROUTER_PORT}
    options:
      advertise: ${DOMAIN_NAME}:${ZITI_EDGE_ROUTER_PORT}
  - binding: link
    address: tls:0.0.0.0:${ZITI_EDGE_ROUTER_TRANSPORT_PORT}
    options:
      advertise: ${DOMAIN_NAME}:${ZITI_EDGE_ROUTER_TRANSPORT_PORT}
ROUTER_CONFIG

# Create systemd service for router
cat > /etc/systemd/system/ziti-router.service << SERVICE
[Unit]
Description=OpenZiti Router
After=network.target ziti-controller.service
Requires=ziti-controller.service

[Service]
User=${ZITI_USER}
WorkingDirectory=${ZITI_HOME}
ExecStart=${ZITI_BIN_DIR}/ziti-router run ${ZITI_HOME}/configs/router.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICE

# Set permissions
chown -R "${ZITI_USER}:${ZITI_USER}" "${ZITI_HOME}"

# Enable and start the router
systemctl daemon-reload
systemctl enable ziti-router
systemctl start ziti-router

echo "✅ OpenZiti router setup completed successfully"
