#!/bin/bash

# Exit on error and print each command
set -ex

# Source the configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR%/*}/config.sh"

# Create controller configuration
cat > "${ZITI_HOME}/configs/controller.yaml" << CONTROLLER_CONFIG
v: 3

db: ${ZITI_DB_PATH}

web:
  - name: edge-client
    bindPoints:
      - interface: edge-client
        address: 0.0.0.0:${ZITI_CTRL_EDGE_PORT}
        protocol: tcp
    options:
      _trace: true
      idleTimeout: 5000
      readTimeout: 20000
      writeTimeout: 10000

edge:
  api:
    sessionTimeout: 30m
    address: 0.0.0.0:1282
    port: 1282
  enrollment:
    signingCert:
      cert: ${ZITI_HOME}/pki/ca.pem
      key: ${ZITI_HOME}/pki/ca.key
    edgeIdentity:
      duration: 5m
    edgeRouter:
      duration: 5m
CONTROLLER_CONFIG

# Create systemd service for controller
cat > /etc/systemd/system/ziti-controller.service << SERVICE
[Unit]
Description=OpenZiti Controller
After=network.target

[Service]
User=${ZITI_USER}
WorkingDirectory=${ZITI_HOME}
ExecStart=${ZITI_BIN_DIR}/ziti-controller run ${ZITI_HOME}/configs/controller.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SERVICE

# Create PKI directory
mkdir -p "${ZITI_HOME}/pki"

# Generate CA certificate
if [ ! -f "${ZITI_HOME}/pki/ca.key" ]; then
    openssl genrsa -out "${ZITI_HOME}/pki/ca.key" 4096
    openssl req -new -x509 -days 3650 -key "${ZITI_HOME}/pki/ca.key" -out "${ZITI_HOME}/pki/ca.pem" \
        -subj "/CN=OpenZiti CA/OU=OpenZiti/O=OpenZiti/L=Remote/ST=Remote/C=US"
fi

# Set permissions
chown -R "${ZITI_USER}:${ZITI_USER}" "${ZITI_HOME}"

# Initialize the controller
if [ ! -f "${ZITI_DB_PATH}" ]; then
    sudo -u "${ZITI_USER}" ziti-controller edge init "${ZITI_HOME}/configs/controller.yaml" \
        -u "${ZITI_ADMIN_USERNAME}" \
        -p "${ZITI_ADMIN_PASSWORD}" \
        --admin-username "${ZITI_ADMIN_USERNAME}" \
        --admin-password "${ZITI_ADMIN_PASSWORD}"
fi

# Enable and start the controller
systemctl daemon-reload
systemctl enable ziti-controller
systemctl start ziti-controller

echo "✅ OpenZiti controller initialized successfully"
echo "Admin username: ${ZITI_ADMIN_USERNAME}"
echo "Admin password: ${ZITI_ADMIN_PASSWORD}"
echo "Please save these credentials in a secure location!"
