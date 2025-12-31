#!/bin/bash

# Exit on error and print each command
set -ex

# Source the configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR%/*}/config.sh"

# Download and install OpenZiti
echo "Installing OpenZiti version ${ZITI_VERSION}..."
ZITI_ARCHIVE="ziti-${ZITI_VERSION}-linux-amd64.tar.gz"
ZITI_DOWNLOAD_URL="https://github.com/openziti/ziti/releases/download/v${ZITI_VERSION}/${ZITI_ARCHIVE}"

# Download and extract OpenZiti
cd /tmp
curl -L -o "${ZITI_ARCHIVE}" "${ZITI_DOWNLOAD_URL}"
tar xzf "${ZITI_ARCHIVE}"

# Install binaries
install -m 755 "ziti" "${ZITI_BIN_DIR}/"
install -m 755 "ziti-controller" "${ZITI_BIN_DIR}/"
install -m 755 "ziti-router" "${ZITI_BIN_DIR}/"
install -m 755 "ziti-tunnel" "${ZITI_BIN_DIR}/"

# Create symlinks
ln -sf "${ZITI_BIN_DIR}/ziti" /usr/local/bin/ziti
ln -sf "${ZITI_BIN_DIR}/ziti-controller" /usr/local/bin/ziti-controller
ln -sf "${ZITI_BIN_DIR}/ziti-router" /usr/local/bin/ziti-router
ln -sf "${ZITI_BIN_DIR}/ziti-tunnel" /usr/local/bin/ziti-tunnel

# Set ownership
chown -R "${ZITI_USER}:${ZITI_USER}" "${ZITI_HOME}"

# Clean up
rm -f "/tmp/${ZITI_ARCHIVE}" "/tmp/ziti" "/tmp/ziti-controller" "/tmp/ziti-router" "/tmp/ziti-tunnel"

echo "✅ OpenZiti installed successfully"
