#!/bin/bash

# Exit on error and print each command
set -ex

# Source the configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

# Check if client name is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <client-name> [local-port] [service-name]"
    exit 1
fi

CLIENT_NAME="$1"
LOCAL_PORT="${2:-3000}"
SERVICE_NAME="${3:-tunnel-service}"

# Login to the controller
export ZITI_PWD=${ZITI_ADMIN_PASSWORD}
ziti edge login "${DOMAIN_NAME}:${ZITI_CTRL_EDGE_PORT}" -u "${ZITI_ADMIN_USERNAME}" -p "${ZITI_ADMIN_PASSWORD}" -y

# Create client identity
ziti edge create identity device "${CLIENT_NAME}" -o "${ZITI_HOME}/client-configs/${CLIENT_NAME}.jwt" -a "tunnel-clients"

# Enroll the identity
ziti edge enroll "${ZITI_HOME}/client-configs/${CLIENT_NAME}.jwt" -o "${ZITI_HOME}/client-configs/${CLIENT_NAME}.json"

# Create client config
cat > "${ZITI_HOME}/client-configs/${CLIENT_NAME}-config.json" << CLIENT_CONFIG
{
  "ztAPI": "https://${DOMAIN_NAME}:${ZITI_CTRL_EDGE_PORT}",
  "identity": "${ZITI_HOME}/client-configs/${CLIENT_NAME}.json",
  "tunnels": [
    {
      "name": "webapp",
      "address": "localhost:${LOCAL_PORT}",
      "protocol": "tcp",
      "service": "${SERVICE_NAME}"
    }
  ]
}
CLIENT_CONFIG

# Create start script
cat > "${ZITI_HOME}/client-configs/start-${CLIENT_NAME}.sh" << 'START_SCRIPT'
#!/bin/bash
${ZITI_BIN_DIR}/ziti-tunnel run -c "${ZITI_HOME}/client-configs/${CLIENT_NAME}-config.json"
START_SCRIPT

chmod +x "${ZITI_HOME}/client-configs/start-${CLIENT_NAME}.sh"

echo "✅ Client configuration generated successfully"
echo "Client config: ${ZITI_HOME}/client-configs/${CLIENT_NAME}-config.json"
echo "Start script: ${ZITI_HOME}/client-configs/start-${CLIENT_NAME}.sh"
echo "To start the tunnel: ${ZITI_HOME}/client-configs/start-${CLIENT_NAME}.sh"
