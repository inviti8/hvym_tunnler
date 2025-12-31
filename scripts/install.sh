#!/bin/bash

# Exit on error and print each command
set -ex

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root"
  exit 1
fi

# Source the configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/config.sh"

# Run setup scripts
for script in "${SCRIPT_DIR}/setup/"*.sh; do
  if [ -f "$script" ]; then
    echo "Running $(basename "$script")..."
    bash "$script"
  fi
done

echo "✅ Installation completed successfully!"
echo "Next steps:"
echo "1. Configure your domain in config.sh"
echo "2. Run 'sudo ./scripts/configure.sh' to configure OpenZiti"
