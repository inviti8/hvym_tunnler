#!/bin/bash

# Exit on error and print each command
set -ex

# Update package lists
echo "Updating package lists..."
apt-get update -y

# Install required dependencies
echo "Installing required packages..."
DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \
    software-properties-common \
    jq \
    unzip \
    net-tools \
    iptables-persistent \
    fail2ban \
    ufw \
    ntp \
    htop \
    netcat \
    tcpdump \
    dnsutils \
    python3-pip

# Install Docker
echo "Installing Docker..."
# Remove old versions
apt-get remove -y docker docker-engine docker.io containerd runc || true

# Set up Docker repository
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io

# Install Docker Compose
DOCKER_COMPOSE_VERSION="v2.15.1"
DOCKER_COMPOSE_URL="https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)"
curl -L "${DOCKER_COMPOSE_URL}" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Create ziti user if it doesn't exist
if ! id -u ${ZITI_USER} >/dev/null 2>&1; then
    useradd -m -d ${ZITI_HOME} -s /bin/bash ${ZITI_USER}
    usermod -aG docker ${ZITI_USER}
else
    usermod -aG docker ${ZITI_USER} || true
fi

# Create necessary directories
mkdir -p ${ZITI_HOME}/bin
mkdir -p ${ZITI_HOME}/db
mkdir -p ${ZITI_HOME}/configs
chown -R ${ZITI_USER}:${ZITI_USER} ${ZITI_HOME}
chmod 755 ${ZITI_HOME}

# Enable and start services
systemctl enable docker
systemctl start docker
systemctl enable fail2ban
systemctl start fail2ban

# Configure firewall
echo "Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow ${ZITI_CTRL_PORT}/tcp
ufw allow ${ZITI_CTRL_EDGE_PORT}/tcp
ufw allow ${ZITI_EDGE_ROUTER_PORT}/tcp
ufw allow ${ZITI_EDGE_ROUTER_TRANSPORT_PORT}/tcp
ufw --force enable

# Disable IPv6 if not needed
if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" != "1" ]; then
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
fi

echo "✅ Dependencies installed successfully"
