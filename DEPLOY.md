# HVYM Tunnler Deployment Guide

Complete instructions for deploying and testing HVYM Tunnler on a VPS.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [VPS Setup](#vps-setup)
3. [Domain & DNS Configuration](#domain--dns-configuration)
4. [SSL Certificates](#ssl-certificates)
5. [Server Deployment](#server-deployment)
6. [Configuration](#configuration)
7. [Testing the Server](#testing-the-server)
8. [Client Testing](#client-testing)
9. [Production Checklist](#production-checklist)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### VPS Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 vCPU | 2 vCPU |
| RAM | 1 GB | 2 GB |
| Storage | 20 GB SSD | 40 GB SSD |
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Network | Public IPv4 | Public IPv4 + IPv6 |

### Required Software

- Python 3.10+
- Docker & Docker Compose (optional but recommended)
- nginx (for reverse proxy)
- certbot (for SSL)
- git

### Domain Requirements

- A domain you control (e.g., `heavymeta.art`)
- Ability to create wildcard DNS records
- Access to DNS management

---

## VPS Setup

### 1. Initial Server Setup

```bash
# Connect to your VPS
ssh root@your-vps-ip

# Update system
apt update && apt upgrade -y

# Install required packages
apt install -y \
    python3.11 \
    python3.11-venv \
    python3-pip \
    nginx \
    certbot \
    python3-certbot-nginx \
    git \
    curl \
    redis-server

# Create non-root user (recommended)
adduser hvym
usermod -aG sudo hvym

# Switch to new user
su - hvym
```

### 2. Install Docker (Optional but Recommended)

```bash
# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install docker-compose-plugin

# Logout and login again for group changes
exit
ssh hvym@your-vps-ip

# Verify installation
docker --version
docker compose version
```

### 3. Configure Firewall

```bash
# Allow SSH
sudo ufw allow 22/tcp

# Allow HTTP and HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw enable

# Verify
sudo ufw status
```

---

## Domain & DNS Configuration

### 1. DNS Records

Add these DNS records to your domain (replace `your-vps-ip` with actual IP):

| Type | Name | Value | TTL |
|------|------|-------|-----|
| A | `tunnel` | `your-vps-ip` | 300 |
| A | `*.tunnel` | `your-vps-ip` | 300 |

**Example for `heavymeta.art`:**

```
tunnel.heavymeta.art      A    203.0.113.50
*.tunnel.heavymeta.art    A    203.0.113.50
```

### 2. Verify DNS Propagation

```bash
# Check main domain
dig tunnel.heavymeta.art +short

# Check wildcard (use any subdomain)
dig test.tunnel.heavymeta.art +short
dig GABCDEF.tunnel.heavymeta.art +short

# Both should return your VPS IP
```

**Note:** DNS propagation can take up to 48 hours, but usually completes within 15-30 minutes.

---

## SSL Certificates

### Option A: Let's Encrypt with Certbot (Recommended)

```bash
# Stop nginx temporarily
sudo systemctl stop nginx

# Get wildcard certificate (requires DNS challenge)
sudo certbot certonly \
    --manual \
    --preferred-challenges dns \
    -d tunnel.heavymeta.art \
    -d "*.tunnel.heavymeta.art"
```

When prompted, add the TXT record to your DNS:

```
_acme-challenge.tunnel.heavymeta.art    TXT    <provided-value>
```

Wait for DNS propagation, then press Enter to continue.

Certificates will be saved to:
- `/etc/letsencrypt/live/tunnel.heavymeta.art/fullchain.pem`
- `/etc/letsencrypt/live/tunnel.heavymeta.art/privkey.pem`

### Option B: Certbot with Cloudflare DNS Plugin

If using Cloudflare for DNS:

```bash
# Install Cloudflare plugin
sudo apt install python3-certbot-dns-cloudflare

# Create credentials file
sudo mkdir -p /etc/letsencrypt
sudo nano /etc/letsencrypt/cloudflare.ini
```

Add to cloudflare.ini:
```ini
dns_cloudflare_api_token = your-cloudflare-api-token
```

```bash
# Secure the file
sudo chmod 600 /etc/letsencrypt/cloudflare.ini

# Get certificate
sudo certbot certonly \
    --dns-cloudflare \
    --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini \
    -d tunnel.heavymeta.art \
    -d "*.tunnel.heavymeta.art"
```

### Set Up Auto-Renewal

```bash
# Test renewal
sudo certbot renew --dry-run

# Certbot auto-renewal is typically set up automatically
# Verify with:
sudo systemctl status certbot.timer
```

---

## Server Deployment

### Option A: Docker Deployment (Recommended)

#### 1. Clone Repository

```bash
cd ~
git clone https://github.com/your-org/hvym_tunnler.git
cd hvym_tunnler
```

#### 2. Generate Server Keypair

```bash
# Generate Stellar keypair for server identity
python3 -c "
from stellar_sdk import Keypair
k = Keypair.random()
print(f'TUNNLER_SERVER_ADDRESS={k.public_key}')
print(f'TUNNLER_SERVER_SECRET={k.secret}')
" | tee server_keys.txt
```

**IMPORTANT:** Save `server_keys.txt` securely and delete it after copying to `.env`

#### 3. Create Environment File

```bash
cp .env.example .env
nano .env
```

Edit `.env`:
```bash
# Paste the values from server_keys.txt
TUNNLER_SERVER_ADDRESS=GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
TUNNLER_SERVER_SECRET=SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Network
TUNNLER_DOMAIN=tunnel.heavymeta.art

# Redis (docker internal)
TUNNLER_REDIS_URL=redis://redis:6379

# Logging
TUNNLER_LOG_LEVEL=INFO
```

#### 4. Create SSL Certificate Directory

```bash
mkdir -p certs
sudo cp /etc/letsencrypt/live/tunnel.heavymeta.art/fullchain.pem certs/
sudo cp /etc/letsencrypt/live/tunnel.heavymeta.art/privkey.pem certs/
sudo chown -R $USER:$USER certs/
chmod 600 certs/*.pem
```

#### 5. Update nginx.conf for SSL

```bash
nano nginx.conf
```

Update the nginx.conf to enable SSL:

```nginx
events {
    worker_connections 1024;
}

http {
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent"';
    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    upstream tunnler {
        server tunnler:8000;
        keepalive 32;
    }

    # SSL configuration
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    # Main server for API and WebSocket
    server {
        listen 443 ssl;
        server_name tunnel.heavymeta.art;

        location /connect {
            proxy_pass http://tunnler;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_read_timeout 86400;
            proxy_send_timeout 86400;
        }

        location / {
            proxy_pass http://tunnler;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }

    # Wildcard server for tunnel endpoints
    server {
        listen 443 ssl;
        server_name *.tunnel.heavymeta.art;

        location / {
            set $stellar_address "";
            if ($host ~* ^([^.]+)\.tunnel\.heavymeta\.art$) {
                set $stellar_address $1;
            }

            proxy_pass http://tunnler/proxy$request_uri;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Stellar-Address $stellar_address;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }

    # HTTP redirect to HTTPS
    server {
        listen 80;
        server_name tunnel.heavymeta.art *.tunnel.heavymeta.art;
        return 301 https://$host$request_uri;
    }
}
```

#### 6. Start Services

```bash
# Build and start
docker compose up -d --build

# Check status
docker compose ps

# View logs
docker compose logs -f tunnler
```

#### 7. Verify Deployment

```bash
# Health check
curl https://tunnel.heavymeta.art/health

# Should return:
# {"status":"healthy","service":"hvym_tunnler","server_address":"GXXX..."}

# Server info
curl https://tunnel.heavymeta.art/info
```

---

### Option B: Manual Deployment (Without Docker)

#### 1. Clone and Setup

```bash
cd ~
git clone https://github.com/your-org/hvym_tunnler.git
cd hvym_tunnler

# Create virtual environment
python3.11 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install hvym_stellar from local or PyPI
pip install -e /path/to/hvym_stellar
# OR
pip install hvym_stellar
```

#### 2. Create Environment File

```bash
cp .env.example .env
nano .env
# Add server keypair and configuration (same as Docker option)
```

#### 3. Configure systemd Service

```bash
sudo nano /etc/systemd/system/hvym-tunnler.service
```

```ini
[Unit]
Description=HVYM Tunnler Service
After=network.target redis-server.service

[Service]
Type=simple
User=hvym
WorkingDirectory=/home/hvym/hvym_tunnler
Environment="PATH=/home/hvym/hvym_tunnler/venv/bin"
EnvironmentFile=/home/hvym/hvym_tunnler/.env
ExecStart=/home/hvym/hvym_tunnler/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable hvym-tunnler
sudo systemctl start hvym-tunnler

# Check status
sudo systemctl status hvym-tunnler
```

#### 4. Configure nginx

```bash
sudo nano /etc/nginx/sites-available/hvym-tunnler
```

```nginx
upstream tunnler {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 443 ssl;
    server_name tunnel.heavymeta.art;

    ssl_certificate /etc/letsencrypt/live/tunnel.heavymeta.art/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tunnel.heavymeta.art/privkey.pem;

    location /connect {
        proxy_pass http://tunnler;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }

    location / {
        proxy_pass http://tunnler;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

server {
    listen 443 ssl;
    server_name *.tunnel.heavymeta.art;

    ssl_certificate /etc/letsencrypt/live/tunnel.heavymeta.art/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/tunnel.heavymeta.art/privkey.pem;

    location / {
        set $stellar_address "";
        if ($host ~* ^([^.]+)\.tunnel\.heavymeta\.art$) {
            set $stellar_address $1;
        }

        proxy_pass http://tunnler/proxy$request_uri;
        proxy_set_header Host $host;
        proxy_set_header X-Stellar-Address $stellar_address;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

server {
    listen 80;
    server_name tunnel.heavymeta.art *.tunnel.heavymeta.art;
    return 301 https://$host$request_uri;
}
```

```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/hvym-tunnler /etc/nginx/sites-enabled/

# Test config
sudo nginx -t

# Reload nginx
sudo systemctl reload nginx
```

---

## Configuration

### Server Configuration Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TUNNLER_SERVER_ADDRESS` | Yes | - | Server's Stellar public key (G...) |
| `TUNNLER_SERVER_SECRET` | Yes | - | Server's Stellar secret key (S...) |
| `TUNNLER_DOMAIN` | No | tunnel.heavymeta.art | Domain for endpoints |
| `TUNNLER_HOST` | No | 0.0.0.0 | Listen host |
| `TUNNLER_PORT` | No | 8000 | Listen port |
| `TUNNLER_REDIS_URL` | No | redis://localhost:6379 | Redis connection URL |
| `TUNNLER_LOG_LEVEL` | No | INFO | Logging level |
| `TUNNLER_JWT_CLOCK_SKEW` | No | 60 | JWT clock skew tolerance (seconds) |
| `TUNNLER_ALLOWED_SERVICES` | No | ["pintheon", "ipfs"] | Allowed service names |
| `TUNNLER_CHALLENGE_TTL` | No | 30 | Challenge validity in seconds |
| `TUNNLER_RATE_LIMIT_WINDOW` | No | 60 | Rate limit window in seconds |
| `TUNNLER_RATE_LIMIT_MAX_ATTEMPTS` | No | 10 | Max auth attempts per window |
| `TUNNLER_RATE_LIMIT_BLOCK_DURATION` | No | 300 | Block duration after exceeding limit |

### Security Features

HVYM Tunnler implements several security measures:

1. **Challenge-Response Authentication**: Each connection receives a unique server-generated challenge that must be signed and included in the JWT. This prevents token replay attacks.

2. **IP Binding**: Challenges are bound to the connecting IP address, preventing man-in-the-middle token capture and reuse.

3. **Rate Limiting**: Excessive failed authentication attempts trigger temporary IP blocks to prevent brute force attacks.

4. **Token Expiration**: JWTs have configurable expiration times (default: 1 hour).

5. **Audience Verification**: JWTs must be addressed to the correct server Stellar address.

### Client Configuration

Clients need to know the server's Stellar address to create properly addressed JWTs.

Create a client config file or distribute via API:

```json
{
  "server_url": "wss://tunnel.heavymeta.art/connect",
  "server_address": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  "services": ["pintheon"]
}
```

---

## Testing the Server

### 1. Basic Health Check

```bash
# From your local machine
curl https://tunnel.heavymeta.art/health
```

Expected response:
```json
{
  "status": "healthy",
  "service": "hvym_tunnler",
  "server_address": "GXXX..."
}
```

### 2. Server Info Endpoint

```bash
curl https://tunnel.heavymeta.art/info
```

Expected response:
```json
{
  "server_address": "GXXX...",
  "websocket_url": "wss://tunnel.heavymeta.art/connect",
  "services": ["pintheon", "ipfs"],
  "version": "1.0.0"
}
```

### 3. Test Challenge-Response Authentication

Create a test script on your local machine:

```python
#!/usr/bin/env python3
"""Test HVYM Tunnler challenge-response authentication."""

import asyncio
import json
import websockets
from stellar_sdk import Keypair
from hvym_stellar import Stellar25519KeyPair, StellarJWTToken

# Server configuration (get from /info endpoint)
SERVER_URL = "wss://tunnel.heavymeta.art/connect"
SERVER_ADDRESS = "GXXX..."  # Replace with actual server address

async def test_connection():
    # Create client keypair
    client_keypair = Keypair.random()
    client_kp = Stellar25519KeyPair(client_keypair)

    print(f"Client address: {client_keypair.public_key}")

    try:
        # Connect without auth header (challenge-response flow)
        async with websockets.connect(
            SERVER_URL,
            ping_interval=30
        ) as ws:
            print("Connected! Waiting for challenge...")

            # Step 1: Receive challenge from server
            challenge_msg = await asyncio.wait_for(ws.recv(), timeout=10)
            challenge_data = json.loads(challenge_msg)

            if challenge_data.get('type') != 'auth_challenge':
                print(f"✗ Expected auth_challenge, got: {challenge_data}")
                return

            challenge_id = challenge_data.get('challenge_id')
            challenge_value = challenge_data.get('challenge')
            server_addr = challenge_data.get('server_address', SERVER_ADDRESS)

            print(f"✓ Received challenge: {challenge_id[:16]}...")

            # Step 2: Create JWT with challenge bound
            token = StellarJWTToken(
                keypair=client_kp,
                audience=server_addr,
                services=["pintheon"],
                expires_in=3600,
                claims={"challenge": challenge_value}
            )
            jwt = token.to_jwt()
            print(f"✓ JWT created with challenge binding")

            # Step 3: Send auth response
            await ws.send(json.dumps({
                "type": "auth_response",
                "challenge_id": challenge_id,
                "jwt": jwt
            }))
            print("  Sent auth response...")

            # Step 4: Receive auth result
            response = await asyncio.wait_for(ws.recv(), timeout=10)
            data = json.loads(response)

            print(f"Response type: {data.get('type')}")

            if data.get('type') == 'auth_ok':
                print(f"✓ Authentication successful!")
                print(f"  Endpoint: {data.get('endpoint')}")
                print(f"  Services: {data.get('services')}")

                # Keep connection for a moment
                await asyncio.sleep(2)
                print("✓ Connection stable")
            elif data.get('type') == 'auth_failed':
                print(f"✗ Authentication failed: {data.get('error')}")
            else:
                print(f"✗ Unexpected response: {data}")

    except websockets.exceptions.InvalidStatusCode as e:
        print(f"✗ Connection rejected: {e}")
    except Exception as e:
        print(f"✗ Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
```

Run the test:
```bash
pip install websockets hvym_stellar stellar-sdk
python test_connection.py
```

### 4. Test WebSocket Connection with wscat

```bash
# Install wscat
npm install -g wscat

# Note: wscat doesn't support custom headers easily
# Use the Python script above for proper JWT testing
```

### 5. Check Server Logs

```bash
# Docker
docker compose logs -f tunnler

# Systemd
sudo journalctl -u hvym-tunnler -f
```

---

## Client Testing

### 1. Test with Standalone Client

Create `test_client.py`:

```python
#!/usr/bin/env python3
"""Standalone tunnel client test."""

import asyncio
import logging
from stellar_sdk import Keypair

# Setup logging
logging.basicConfig(level=logging.INFO)

# Import from hvym_stellar and tunnel client
from hvym_stellar import Stellar25519KeyPair
from tunnel_client import HVYMTunnelClient, TunnelConfig, TunnelState

# Configuration
SERVER_URL = "wss://tunnel.heavymeta.art/connect"
SERVER_ADDRESS = "GXXX..."  # Replace with server address

async def main():
    # Create client wallet
    keypair = Keypair.random()
    wallet = Stellar25519KeyPair(keypair)

    print(f"Client Stellar Address: {keypair.public_key}")

    # Configure tunnel
    config = TunnelConfig(
        server_url=SERVER_URL,
        server_address=SERVER_ADDRESS,
        services=["pintheon"],
        local_pintheon_port=9998
    )

    # Create client
    client = HVYMTunnelClient(wallet, config)

    # Set callbacks
    def on_connected(endpoint):
        print(f"✓ Connected! Endpoint: {endpoint.url}")
        print(f"  You can now access local services via: {endpoint.url}")

    def on_disconnected():
        print("Disconnected")

    def on_error(msg):
        print(f"Error: {msg}")

    def on_state_changed(state):
        print(f"State: {state.value}")

    client.on_connected = on_connected
    client.on_disconnected = on_disconnected
    client.on_error = on_error
    client.on_state_changed = on_state_changed

    # Bind local port
    client.bind_port("pintheon", 9998)

    # Connect (runs until disconnected)
    print("Connecting to tunnel server...")
    try:
        await client.connect()
    except KeyboardInterrupt:
        print("\nDisconnecting...")
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
```

### 2. Test with Metavinci

In Metavinci, configure the tunnel:

```python
# In metavinci.py, after initializing tunnel_config_store:

# Set server configuration
self.tunnel_config_store.server_url = "wss://tunnel.heavymeta.art/connect"
self.tunnel_config_store.server_address = "GXXX..."  # Server's address

# Start tunnel (requires active Stellar wallet)
self.tunnel_manager.start_tunnel()
```

### 3. End-to-End Test

1. Start Pintheon locally (port 9998)
2. Connect tunnel client
3. Access `https://YOUR_STELLAR_ADDRESS.tunnel.heavymeta.art/`
4. Should proxy to your local Pintheon

```bash
# Test the tunnel endpoint (replace with your client's Stellar address)
curl https://GABCDEF....tunnel.heavymeta.art/api/status
```

---

## Production Checklist

### Security

- [ ] Server keypair generated and stored securely
- [ ] `.env` file has restricted permissions (`chmod 600`)
- [ ] SSL certificates installed and auto-renewing
- [ ] Firewall configured (only 80, 443, 22 open)
- [ ] Redis not exposed externally (bind to 127.0.0.1)
- [ ] Log files don't contain secrets
- [ ] Rate limiting tuned for expected load
- [ ] Challenge TTL appropriate (30s default is good)
- [ ] Monitor `/api/stats` for blocked IPs

### Reliability

- [ ] Service auto-starts on boot
- [ ] Health checks configured
- [ ] Log rotation configured
- [ ] Monitoring/alerting set up

### Performance

- [ ] nginx keepalive configured
- [ ] Redis persistence enabled
- [ ] Appropriate resource limits set

### Backup

- [ ] Server keypair backed up securely
- [ ] Configuration files backed up
- [ ] SSL certificate renewal tested

---

## Troubleshooting

### Connection Refused

```bash
# Check if service is running
docker compose ps
# OR
sudo systemctl status hvym-tunnler

# Check logs
docker compose logs tunnler
# OR
sudo journalctl -u hvym-tunnler
```

### SSL Certificate Errors

```bash
# Check certificate
openssl s_client -connect tunnel.heavymeta.art:443 -servername tunnel.heavymeta.art

# Check expiry
echo | openssl s_client -connect tunnel.heavymeta.art:443 2>/dev/null | openssl x509 -noout -dates
```

### JWT Verification Failed

1. Check client and server clocks are synchronized
2. Verify server address in JWT matches server's actual address
3. Check JWT hasn't expired
4. Verify client keypair is valid
5. Ensure challenge is included in JWT claims

```python
# Debug JWT
from hvym_stellar import StellarJWTTokenVerifier

verifier = StellarJWTTokenVerifier(jwt_string)
print(verifier.inspect())
print(f"Expired: {verifier.is_expired()}")
```

### Challenge Verification Failed

Common causes:
- **"Challenge expired"**: Client took >30s to respond. Check network latency.
- **"Challenge IP mismatch"**: Client's IP changed between challenge and response (proxy/NAT issue).
- **"Invalid challenge response"**: Client didn't include the challenge in JWT claims.

```bash
# Check current rate limit status
curl https://tunnel.heavymeta.art/api/stats
```

### Rate Limited

If you see "Too many requests" errors:

```bash
# Check how many IPs are blocked
curl https://tunnel.heavymeta.art/api/stats | jq '.security.rate_limited_ips'

# Wait for block to expire (default 5 minutes)
# Or adjust TUNNLER_RATE_LIMIT_BLOCK_DURATION
```

### WebSocket Connection Drops

```bash
# Check nginx timeout settings
grep timeout /etc/nginx/nginx.conf

# Increase timeouts if needed:
# proxy_read_timeout 86400;
# proxy_send_timeout 86400;
```

### Redis Connection Failed

```bash
# Check Redis is running
sudo systemctl status redis

# Test connection
redis-cli ping
```

### DNS Issues

```bash
# Check DNS resolution
dig tunnel.heavymeta.art
dig test.tunnel.heavymeta.art

# Check from different DNS servers
dig @8.8.8.8 tunnel.heavymeta.art
dig @1.1.1.1 tunnel.heavymeta.art
```

### View Active Tunnels

```bash
# API endpoint
curl https://tunnel.heavymeta.art/api/tunnels

# Or check Redis directly
redis-cli keys "hvym_tunnel:*"
```

---

## Maintenance

### Update Server

```bash
cd ~/hvym_tunnler
git pull

# Docker
docker compose down
docker compose up -d --build

# Systemd
sudo systemctl restart hvym-tunnler
```

### Rotate Server Keypair

1. Generate new keypair
2. Update `.env` with new keys
3. Restart server
4. Update all clients with new server address
5. Securely delete old keys

### Certificate Renewal

Certbot should auto-renew. If manual renewal needed:

```bash
sudo certbot renew

# Then restart nginx
sudo systemctl reload nginx

# If using Docker, copy new certs
sudo cp /etc/letsencrypt/live/tunnel.heavymeta.art/*.pem ~/hvym_tunnler/certs/
docker compose restart nginx
```

---

## Support

- GitHub Issues: https://github.com/your-org/hvym_tunnler/issues
- Documentation: See `/docs` folder
- Logs: Check server logs for detailed error messages
