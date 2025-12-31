#!/bin/bash

# Exit on error and print each command
set -ex

# Source the configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR%/*}/config.sh"

# Login to the controller
export ZITI_PWD=${ZITI_ADMIN_PASSWORD}
ziti edge login "${DOMAIN_NAME}:${ZITI_CTRL_EDGE_PORT}" -u "${ZITI_ADMIN_USERNAME}" -p "${ZITI_ADMIN_PASSWORD}" -y

# Create edge router policy
ziti edge create edge-router-policy edge-router-policy-default \
    --edge-router-roles \"#default\" \
    --identity-roles \"#all\"

# Create service edge router policy
ziti edge create service-edge-router-policy service-edge-router-policy-default \
    --edge-router-roles \"#default\" \
    --service-roles \"#all\"

# Create service policies
ziti edge create service-policy service-policy-default Dial \
    --service-roles \"#all\" \
    --identity-roles \"#all\"

ziti edge create service-policy service-policy-bind Bind \
    --service-roles \"#all\" \
    --identity-roles \"#all\"

# Create tunnel service
ziti edge create config tunnel-config \
    protocol tcp \
    address localhost:80

ziti edge create service tunnel-service \
    --configs tunnel-config \
    --role-attributes tunnel-service

# Create client configuration
mkdir -p "${ZITI_HOME}/client-configs"

# Create client identity
CLIENT_ID="tunnel-client-$(date +%s)"
ziti edge create identity device "${CLIENT_ID}" -o "${ZITI_HOME}/client-configs/${CLIENT_ID}.jwt" -a "tunnel-clients"

# Create client config
cat > "${ZITI_HOME}/client-configs/tunnel-config.json" << CLIENT_CONFIG
{
  "ztAPI": "https://${DOMAIN_NAME}:${ZITI_CTRL_EDGE_PORT}",
  "identity": "${ZITI_HOME}/client-configs/${CLIENT_ID}.json",
  "tunnels": [
    {
      "name": "webapp",
      "address": "localhost:3000",
      "protocol": "tcp",
      "service": "tunnel-service"
    }
  ]
}
CLIENT_CONFIG

# Set permissions
chown -R "${ZITI_USER}:${ZITI_USER}" "${ZITI_HOME}"

echo "✅ Tunnel service setup completed successfully"
echo "Client configuration files are available in: ${ZITI_HOME}/client-configs/"
