#!/bin/bash
#
# HVYM Tunnler - VPS Startup Script
#
# Universal startup script that works on any VPS provider:
#   - Oracle Cloud (via cloud-init or manual)
#   - DigitalOcean, Linode, Vultr, Hetzner
#   - Container-based VPS (OpenVZ, LXC)
#   - Any Ubuntu/Debian server
#
# Usage:
#   curl -O https://raw.githubusercontent.com/inviti8/hvym_tunnler/master/scripts/vps_startup.sh
#   chmod +x vps_startup.sh
#   sudo ./vps_startup.sh
#
# Or via cloud-init: paste into "user data" / "startup script" field
#
# Logs: /var/log/hvym-startup.log
#

set -uo pipefail  # Note: removed -e to handle errors gracefully

#=============================================================================
# CONFIGURATION - Modify these variables for your deployment
#=============================================================================

# Domain for tunnel endpoints (e.g., tunnel.yourdomain.com)
DOMAIN="tunnel.hvym.link"

# Git repository URL
REPO_URL="https://github.com/inviti8/hvym_tunnler.git"

# Git branch to deploy
REPO_BRANCH="master"

# Linux user to run the service
HVYM_USER="hvym"

# Allowed tunnel services (comma-separated)
ALLOWED_SERVICES="pintheon,ipfs"

# Log level (DEBUG, INFO, WARNING, ERROR)
LOG_LEVEL="INFO"

#=============================================================================
# END CONFIGURATION - Do not modify below unless you know what you're doing
#=============================================================================

# Derived paths
HVYM_HOME="/home/${HVYM_USER}"
TUNNLER_DIR="${HVYM_HOME}/hvym_tunnler"
VENV_DIR="${TUNNLER_DIR}/venv"
MARKER_DIR="/var/lib/hvym-tunnler"
MARKER_FILE="${MARKER_DIR}/.initialized"
LOG_FILE="/var/log/hvym-startup.log"

# Redirect all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

echo ""
echo "============================================================"
echo "HVYM Tunnler Startup Script"
echo "Started: $(date)"
echo "============================================================"
echo ""

#-----------------------------------------------------------------------------
# Check if this is a restart (marker file exists)
#-----------------------------------------------------------------------------

if [[ -f "$MARKER_FILE" ]]; then
    echo "=== RESTART DETECTED ==="
    echo "Marker file exists: $MARKER_FILE"
    echo "Skipping initialization (already completed)"
    echo ""
    echo "Ensuring services are running..."

    # Just ensure services are running
    systemctl is-active --quiet redis-server || systemctl start redis-server
    systemctl is-active --quiet hvym-tunnler || systemctl start hvym-tunnler
    systemctl is-active --quiet nginx || systemctl start nginx

    echo "Services verified."
    echo ""
    echo "Restart complete: $(date)"
    exit 0
fi

echo "=== FIRST BOOT - FULL INITIALIZATION ==="
echo ""

#-----------------------------------------------------------------------------
# Phase 1: System Setup
#-----------------------------------------------------------------------------

echo "--- Phase 1: System Setup ---"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Detect package manager
if command -v apt &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
else
    echo "ERROR: No supported package manager found (apt/dnf/yum)"
    exit 1
fi

echo "Detected package manager: $PKG_MANAGER"

if [[ "$PKG_MANAGER" == "apt" ]]; then
    echo "Updating package lists..."
    apt update

    echo "Upgrading existing packages..."
    apt upgrade -y

    # Determine Python version available
    PYTHON_PKG="python3"
    PYTHON_VENV_PKG="python3-venv"
    if apt-cache show python3.11 &>/dev/null; then
        PYTHON_PKG="python3.11"
        PYTHON_VENV_PKG="python3.11-venv"
    elif apt-cache show python3.10 &>/dev/null; then
        PYTHON_PKG="python3.10"
        PYTHON_VENV_PKG="python3.10-venv"
    fi

    echo "Installing required packages (Python: $PYTHON_PKG)..."
    apt install -y \
        "$PYTHON_PKG" \
        "$PYTHON_VENV_PKG" \
        python3-pip \
        nginx \
        certbot \
        python3-certbot-nginx \
        git \
        curl \
        redis-server \
        ufw \
        jq || {
            echo "WARNING: Some packages failed to install, continuing..."
        }

elif [[ "$PKG_MANAGER" == "dnf" ]] || [[ "$PKG_MANAGER" == "yum" ]]; then
    echo "Updating packages..."
    $PKG_MANAGER update -y

    echo "Installing required packages..."
    $PKG_MANAGER install -y \
        python3 \
        python3-pip \
        nginx \
        certbot \
        python3-certbot-nginx \
        git \
        curl \
        redis \
        firewalld \
        jq || {
            echo "WARNING: Some packages failed to install, continuing..."
        }
fi

# Find the Python executable
PYTHON_BIN=""
for py in python3.11 python3.10 python3; do
    if command -v "$py" &> /dev/null; then
        PYTHON_BIN="$py"
        break
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    echo "ERROR: No Python 3 found"
    exit 1
fi

echo "Using Python: $PYTHON_BIN ($($PYTHON_BIN --version))"
echo "Package installation complete."
echo ""

#-----------------------------------------------------------------------------
# Phase 2: Firewall Configuration
#-----------------------------------------------------------------------------

echo "--- Phase 2: Firewall Configuration ---"
echo ""

# Detect if running in a container (OpenVZ, LXC, Docker)
# Containers typically can't modify kernel/firewall settings
detect_container() {
    # Check for container indicators
    if [[ -f /proc/1/environ ]] && grep -qa 'container=' /proc/1/environ 2>/dev/null; then
        return 0  # Is container
    fi
    if [[ -f /run/systemd/container ]]; then
        return 0  # Is container
    fi
    if grep -qa 'docker\|lxc\|openvz' /proc/1/cgroup 2>/dev/null; then
        return 0  # Is container
    fi
    if [[ ! -w /proc/sys/net/ipv4/ip_forward ]] 2>/dev/null; then
        return 0  # Can't write to sysctl = likely container
    fi
    return 1  # Not a container
}

if detect_container; then
    echo "Container-based VPS detected (OpenVZ/LXC/Docker)"
    echo "Skipping UFW configuration - use provider's firewall instead"
    echo ""
    echo "IMPORTANT: Configure firewall in your VPS provider's dashboard:"
    echo "  - Allow TCP port 22 (SSH)"
    echo "  - Allow TCP port 80 (HTTP)"
    echo "  - Allow TCP port 443 (HTTPS)"
    echo ""
elif ! command -v ufw &> /dev/null; then
    echo "UFW not available, skipping firewall configuration"
    echo "Ensure ports 22, 80, 443 are open via your provider's firewall"
    echo ""
else
    # Full VM - configure UFW
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "Firewall already active, checking rules..."
    else
        echo "Configuring firewall..."
        ufw allow 22/tcp comment "SSH" || true
        ufw allow 80/tcp comment "HTTP" || true
        ufw allow 443/tcp comment "HTTPS" || true
        if ufw --force enable; then
            echo "UFW enabled successfully"
        else
            echo "WARNING: UFW failed to enable - configure firewall manually"
        fi
    fi
    ufw status verbose 2>/dev/null || echo "Could not get UFW status"
fi
echo ""

#-----------------------------------------------------------------------------
# Phase 3: User Setup
#-----------------------------------------------------------------------------

echo "--- Phase 3: User Setup ---"
echo ""

# Check if user exists
if id "$HVYM_USER" &>/dev/null; then
    echo "User '$HVYM_USER' already exists"
else
    echo "Creating user '$HVYM_USER'..."
    useradd -m -s /bin/bash "$HVYM_USER"
    echo "User created."
fi

echo ""

#-----------------------------------------------------------------------------
# Phase 4: Repository Setup
#-----------------------------------------------------------------------------

echo "--- Phase 4: Repository Setup ---"
echo ""

if [[ -d "$TUNNLER_DIR" ]]; then
    echo "Repository already exists at $TUNNLER_DIR"
    echo "Pulling latest changes..."
    cd "$TUNNLER_DIR"
    sudo -u "$HVYM_USER" git fetch origin
    sudo -u "$HVYM_USER" git checkout "$REPO_BRANCH"
    sudo -u "$HVYM_USER" git pull origin "$REPO_BRANCH"
else
    echo "Cloning repository..."
    sudo -u "$HVYM_USER" git clone -b "$REPO_BRANCH" "$REPO_URL" "$TUNNLER_DIR"
fi

echo "Repository ready."
echo ""

#-----------------------------------------------------------------------------
# Phase 5: Python Environment Setup
#-----------------------------------------------------------------------------

echo "--- Phase 5: Python Environment Setup ---"
echo ""

# Re-detect Python if not set (in case script is run in parts)
if [[ -z "${PYTHON_BIN:-}" ]]; then
    for py in python3.11 python3.10 python3; do
        if command -v "$py" &> /dev/null; then
            PYTHON_BIN="$py"
            break
        fi
    done
fi

echo "Using Python: $PYTHON_BIN"

if [[ -f "${VENV_DIR}/bin/python" ]]; then
    echo "Virtual environment already exists"
else
    echo "Creating Python virtual environment..."
    sudo -u "$HVYM_USER" "$PYTHON_BIN" -m venv "$VENV_DIR" || {
        echo "ERROR: Failed to create virtual environment"
        echo "Trying with --without-pip flag..."
        sudo -u "$HVYM_USER" "$PYTHON_BIN" -m venv --without-pip "$VENV_DIR"
        # Bootstrap pip manually
        curl -sS https://bootstrap.pypa.io/get-pip.py | sudo -u "$HVYM_USER" "${VENV_DIR}/bin/python"
    }
fi

echo "Installing Python dependencies..."
sudo -u "$HVYM_USER" "${VENV_DIR}/bin/pip" install --upgrade pip || true
sudo -u "$HVYM_USER" "${VENV_DIR}/bin/pip" install -r "${TUNNLER_DIR}/requirements.txt" || {
    echo "ERROR: Failed to install requirements"
    exit 1
}

# Install QR code dependencies for setup script
sudo -u "$HVYM_USER" "${VENV_DIR}/bin/pip" install "qrcode[pil]" Pillow || {
    echo "WARNING: Failed to install QR code dependencies"
}

echo "Python environment ready."
echo ""

#-----------------------------------------------------------------------------
# Phase 6: Identity Generation
#-----------------------------------------------------------------------------

echo "--- Phase 6: Identity Generation ---"
echo ""

if [[ -f "${TUNNLER_DIR}/.env" ]]; then
    echo "Server identity already exists (.env file found)"
    echo "Skipping identity generation to preserve existing keys."
else
    echo "Generating server identity..."
    sudo -u "$HVYM_USER" "${VENV_DIR}/bin/python" \
        "${TUNNLER_DIR}/scripts/setup_identity.py" \
        --domain "$DOMAIN" \
        --services "$ALLOWED_SERVICES" \
        --log-level "$LOG_LEVEL"
fi

# Display server address
if [[ -f "${TUNNLER_DIR}/.env" ]]; then
    SERVER_ADDR=$(grep "TUNNLER_SERVER_ADDRESS=" "${TUNNLER_DIR}/.env" | cut -d= -f2)
    echo ""
    echo "Server Stellar Address: $SERVER_ADDR"
fi

echo ""

#-----------------------------------------------------------------------------
# Phase 7: Systemd Services
#-----------------------------------------------------------------------------

echo "--- Phase 7: Systemd Services ---"
echo ""

# Main application service
echo "Installing hvym-tunnler.service..."
cat > /etc/systemd/system/hvym-tunnler.service << EOF
[Unit]
Description=HVYM Tunnler Service
After=network.target redis-server.service hvym-tunnler-boot.service
Requires=hvym-tunnler-boot.service

[Service]
Type=simple
User=${HVYM_USER}
WorkingDirectory=${TUNNLER_DIR}
Environment="PATH=${VENV_DIR}/bin"
EnvironmentFile=${TUNNLER_DIR}/.env
ExecStart=${VENV_DIR}/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Boot check service
echo "Installing hvym-tunnler-boot.service..."
cat > /etc/systemd/system/hvym-tunnler-boot.service << EOF
[Unit]
Description=HVYM Tunnler Boot Health Check
After=network.target
Before=hvym-tunnler.service

[Service]
Type=oneshot
ExecStart=/bin/bash ${TUNNLER_DIR}/scripts/boot_check.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Make boot_check.sh executable
chmod +x "${TUNNLER_DIR}/scripts/boot_check.sh"

# Reload systemd
systemctl daemon-reload

# Enable services
systemctl enable redis-server
systemctl enable hvym-tunnler-boot
systemctl enable hvym-tunnler

echo "Systemd services installed and enabled."
echo ""

#-----------------------------------------------------------------------------
# Phase 8: Nginx Configuration
#-----------------------------------------------------------------------------

echo "--- Phase 8: Nginx Configuration ---"
echo ""

echo "Installing nginx configuration..."
cat > /etc/nginx/sites-available/hvym-tunnler << EOF
upstream tunnler {
    server 127.0.0.1:8000;
    keepalive 32;
}

# HTTP server (for initial setup and certbot)
server {
    listen 80;
    server_name ${DOMAIN} *.${DOMAIN};

    # Certbot challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # API and WebSocket (before SSL is configured)
    location /connect {
        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }

    location / {
        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}

# Note: HTTPS configuration will be added by certbot after SSL setup
# Run: sudo certbot --nginx -d ${DOMAIN} -d "*.${DOMAIN}"
EOF

# Enable site
ln -sf /etc/nginx/sites-available/hvym-tunnler /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and reload nginx
nginx -t
systemctl reload nginx

echo "Nginx configured."
echo ""

#-----------------------------------------------------------------------------
# Phase 9: Start Services
#-----------------------------------------------------------------------------

echo "--- Phase 9: Start Services ---"
echo ""

echo "Starting Redis..."
systemctl start redis-server

echo "Starting HVYM Tunnler..."
systemctl start hvym-tunnler

# Wait a moment for service to start
sleep 3

# Check service status
echo ""
echo "Service status:"
systemctl is-active hvym-tunnler && echo "  hvym-tunnler: RUNNING" || echo "  hvym-tunnler: FAILED"
systemctl is-active redis-server && echo "  redis-server: RUNNING" || echo "  redis-server: FAILED"
systemctl is-active nginx && echo "  nginx: RUNNING" || echo "  nginx: FAILED"

echo ""

#-----------------------------------------------------------------------------
# Phase 10: Create Marker File
#-----------------------------------------------------------------------------

echo "--- Phase 10: Finalization ---"
echo ""

# Create marker directory and file
mkdir -p "$MARKER_DIR"

# Get server address for marker
SERVER_ADDR=$(grep "TUNNLER_SERVER_ADDRESS=" "${TUNNLER_DIR}/.env" | cut -d= -f2 || echo "unknown")

cat > "$MARKER_FILE" << EOF
{
    "initialized_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "server_address": "${SERVER_ADDR}",
    "domain": "${DOMAIN}",
    "version": "1.0.0",
    "repo_url": "${REPO_URL}",
    "repo_branch": "${REPO_BRANCH}"
}
EOF

echo "Initialization marker created: $MARKER_FILE"
echo ""

#-----------------------------------------------------------------------------
# Summary
#-----------------------------------------------------------------------------

echo "============================================================"
echo "HVYM Tunnler Initialization Complete!"
echo "============================================================"
echo ""
echo "Server Stellar Address:"
echo "  $SERVER_ADDR"
echo ""
echo "Endpoints (HTTP - configure SSL for production):"
echo "  Health:   http://${DOMAIN}/health"
echo "  Info:     http://${DOMAIN}/info"
echo "  Identity: http://${DOMAIN}/server-identity"
echo "  QR Code:  http://${DOMAIN}/server-identity/qr"
echo ""
echo "Next Steps:"
echo "  1. Configure DNS:"
echo "     A    ${DOMAIN}      → $(curl -s ifconfig.me || echo 'YOUR_IP')"
echo "     A    *.${DOMAIN}    → $(curl -s ifconfig.me || echo 'YOUR_IP')"
echo ""
echo "  2. Install SSL certificate (after DNS propagates):"
echo "     sudo certbot --nginx -d ${DOMAIN} -d \"*.${DOMAIN}\""
echo ""
echo "  3. Test the server:"
echo "     curl http://${DOMAIN}/health"
echo ""
echo "Logs:"
echo "  Startup:  /var/log/hvym-startup.log"
echo "  Service:  journalctl -u hvym-tunnler -f"
echo ""
echo "Completed: $(date)"
echo "============================================================"
