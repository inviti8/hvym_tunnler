# HVYM Tunnler - Automated Startup Script Plan

This document outlines the implementation plan for an Oracle Cloud VM startup script that fully automates hvym_tunnler deployment.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Oracle VM Boot Sequence                       │
├─────────────────────────────────────────────────────────────────┤
│  1. Startup script detects: INIT or RESTART?                    │
│  2. If INIT (first boot):                                        │
│     - Install system packages                                    │
│     - Create user, clone repo                                    │
│     - Generate Stellar keypair + QR code                         │
│     - Configure systemd + nginx                                  │
│     - Mark initialization complete                               │
│  3. If RESTART (subsequent boot):                                │
│     - Skip all setup steps                                       │
│     - Ensure services are running                                │
│  4. API endpoint serves QR code at /server-identity              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Initialization vs Restart Detection

**Critical Requirement:** The startup script must distinguish between first boot and subsequent restarts to avoid:
- Regenerating the Stellar keypair (would break all client configurations)
- Reinstalling packages unnecessarily
- Overwriting customized configurations

### Detection Strategy

Use a **marker file** to track initialization state:

```
/var/lib/hvym-tunnler/.initialized
```

| File State | Meaning | Action |
|------------|---------|--------|
| Does not exist | First boot (INIT) | Run full setup |
| Exists | Restart | Skip setup, ensure services running |

### Boot Flow Diagram

```
                    ┌─────────────────┐
                    │   VM Boot       │
                    └────────┬────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │ Check /var/lib/hvym-tunnler/ │
              │      .initialized            │
              └──────────────┬───────────────┘
                             │
              ┌──────────────┴──────────────┐
              │                             │
              ▼                             ▼
      ┌───────────────┐            ┌───────────────┐
      │ File Missing  │            │ File Exists   │
      │ (FIRST BOOT)  │            │ (RESTART)     │
      └───────┬───────┘            └───────┬───────┘
              │                             │
              ▼                             ▼
    ┌─────────────────────┐      ┌─────────────────────┐
    │ Full Initialization │      │ Quick Start         │
    │ - Install packages  │      │ - Verify services   │
    │ - Create user       │      │ - Start if stopped  │
    │ - Clone repo        │      │ - Log restart       │
    │ - Generate keypair  │      └─────────────────────┘
    │ - Setup services    │
    │ - Create marker     │
    └─────────────────────┘
```

### Marker File Contents

The marker file stores metadata about the initialization:

```json
{
  "initialized_at": "2026-02-03T12:00:00Z",
  "server_address": "GXXX...",
  "domain": "tunnel.heavymeta.art",
  "version": "1.0.0",
  "packages_installed": true,
  "services_configured": true
}
```

This allows:
- Verification that setup completed successfully
- Quick reference to server identity without reading .env
- Version tracking for future upgrade scripts

### Idempotency Rules

Each setup step must be idempotent (safe to run multiple times):

| Step | Idempotency Check |
|------|-------------------|
| Install packages | `dpkg -l \| grep package` or let apt handle it |
| Create user | `id hvym` - skip if exists |
| Clone repo | Check if `/home/hvym/hvym_tunnler` exists |
| Generate keypair | **NEVER regenerate** - check `.env` exists |
| Setup venv | Check if `venv/bin/python` exists |
| Systemd service | Compare file hash, only update if changed |
| Nginx config | Compare file hash, only update if changed |
| Firewall rules | `ufw status` - skip if already configured |

### Script Pseudocode

```bash
#!/bin/bash
MARKER_DIR="/var/lib/hvym-tunnler"
MARKER_FILE="${MARKER_DIR}/.initialized"

# Detect boot type
if [[ -f "$MARKER_FILE" ]]; then
    echo "=== RESTART DETECTED ==="
    echo "Marker file exists: $MARKER_FILE"

    # Just ensure services are running
    systemctl is-active --quiet redis-server || systemctl start redis-server
    systemctl is-active --quiet hvym-tunnler || systemctl start hvym-tunnler
    systemctl is-active --quiet nginx || systemctl start nginx

    echo "Services verified. Restart complete."
    exit 0
fi

echo "=== FIRST BOOT - INITIALIZATION ==="

# ... full setup steps ...

# Mark initialization complete (ONLY after everything succeeds)
mkdir -p "$MARKER_DIR"
cat > "$MARKER_FILE" << EOF
{
  "initialized_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "server_address": "$(grep TUNNLER_SERVER_ADDRESS /home/hvym/hvym_tunnler/.env | cut -d= -f2)",
  "domain": "${DOMAIN}",
  "version": "1.0.0"
}
EOF

echo "=== INITIALIZATION COMPLETE ==="
```

### Edge Cases

| Scenario | Detection | Handling |
|----------|-----------|----------|
| Partial init (crashed mid-setup) | Marker missing | Re-run full init (idempotent steps) |
| .env exists but no marker | Check .env | Preserve .env, create marker |
| Marker exists but services broken | Service check fails | Attempt repair, log error |
| Manual reinstall requested | Admin deletes marker | Full init runs again |
| Keypair accidentally deleted | .env missing | **CRITICAL** - alert, don't auto-regenerate |

### Recovery Mode

For the critical case where `.env` is deleted but marker exists:

```bash
if [[ -f "$MARKER_FILE" ]] && [[ ! -f "/home/hvym/hvym_tunnler/.env" ]]; then
    echo "CRITICAL: Server identity (.env) missing but marker exists!"
    echo "This requires manual intervention to avoid breaking clients."
    echo ""
    echo "Options:"
    echo "1. Restore .env from backup"
    echo "2. Delete $MARKER_FILE to force new identity generation"
    echo "   (WARNING: All existing clients will need reconfiguration)"
    exit 1
fi
```

---

## Cloud-Init vs Systemd: Script Execution Model

**Important:** Oracle cloud-init scripts only run **once** on first boot by default.

For our use case, we need **two scripts**:

| Script | Trigger | Purpose |
|--------|---------|---------|
| `oracle_startup.sh` | Cloud-init (first boot only) | Full initialization |
| `hvym-tunnler-boot.service` | Systemd (every boot) | Health check & service recovery |

### Recommended Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         FIRST BOOT                               │
├─────────────────────────────────────────────────────────────────┤
│  cloud-init → oracle_startup.sh                                  │
│    ├── Install packages                                          │
│    ├── Create user, clone repo                                   │
│    ├── Generate keypair                                          │
│    ├── Install hvym-tunnler.service (main app)                  │
│    ├── Install hvym-tunnler-boot.service (boot checker)         │
│    └── Create marker file                                        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       EVERY BOOT                                 │
├─────────────────────────────────────────────────────────────────┤
│  systemd → hvym-tunnler-boot.service (Type=oneshot)             │
│    ├── Check marker file exists                                  │
│    ├── Verify .env exists (CRITICAL check)                       │
│    ├── Ensure redis, nginx running                               │
│    └── Log boot event                                            │
│                                                                   │
│  systemd → hvym-tunnler.service (main app, auto-start)          │
│    └── uvicorn app.main:app                                      │
└─────────────────────────────────────────────────────────────────┘
```

### hvym-tunnler-boot.service

```ini
[Unit]
Description=HVYM Tunnler Boot Health Check
After=network.target
Before=hvym-tunnler.service

[Service]
Type=oneshot
ExecStart=/home/hvym/hvym_tunnler/scripts/boot_check.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

### boot_check.sh

```bash
#!/bin/bash
# Quick boot-time health check

MARKER="/var/lib/hvym-tunnler/.initialized"
ENV_FILE="/home/hvym/hvym_tunnler/.env"

if [[ ! -f "$MARKER" ]]; then
    echo "WARNING: Server not initialized. Run oracle_startup.sh"
    exit 0  # Don't block boot
fi

if [[ ! -f "$ENV_FILE" ]]; then
    echo "CRITICAL: .env file missing! Server identity lost."
    echo "Restore from backup or delete $MARKER to reinitialize."
    # Could send alert here (email, webhook, etc.)
    exit 1
fi

echo "Boot check passed. Server identity intact."
exit 0
```

This approach ensures:
1. Cloud-init does heavy lifting only once
2. Every boot verifies critical files
3. Main service has proper dependencies

---

## Components

### 1. Shell Startup Script (`scripts/oracle_startup.sh`)

**Purpose:** Run by Oracle cloud-init on first boot to bootstrap the entire system.

**Tasks to automate from DEPLOY.md:**

| Step | DEPLOY.md Section | Automation |
|------|-------------------|------------|
| System update | VPS Setup §1 | `apt update && apt upgrade -y` |
| Install packages | VPS Setup §1 | Python 3.11, nginx, certbot, redis, git, docker |
| Create user | VPS Setup §1 | Create `hvym` user with sudo |
| Configure firewall | VPS Setup §3 | UFW rules for 22, 80, 443 |
| Clone repository | Server Deployment §1 | `git clone` to `/home/hvym/hvym_tunnler` |
| Run setup script | NEW | Execute `scripts/setup_identity.py` |
| Create systemd service | Server Deployment Option B §3 | Install hvym-tunnler.service |
| Configure nginx | Server Deployment Option B §4 | Install nginx config |
| Start services | Server Deployment §6 | Enable and start all services |

**Script outline:**

```bash
#!/bin/bash
# Oracle VM Startup Script for HVYM Tunnler
# Run via: Oracle Cloud > Compute > Instance > Cloud-init script

set -euo pipefail
exec > >(tee /var/log/hvym-startup.log) 2>&1

HVYM_USER="hvym"
HVYM_HOME="/home/${HVYM_USER}"
REPO_URL="https://github.com/inviti8/hvym_tunnler.git"
DOMAIN="${TUNNLER_DOMAIN:-tunnel.heavymeta.art}"

# --- Phase 1: System Setup ---
# --- Phase 2: User & Repository ---
# --- Phase 3: Identity Generation ---
# --- Phase 4: Service Configuration ---
# --- Phase 5: Start Services ---
```

### 2. Python Setup Script (`scripts/setup_identity.py`)

**Purpose:** Generate server identity (Stellar keypair) and create QR code.

**Dependencies:**
```
stellar-sdk>=10.0.0
qrcode[pil]>=7.4
Pillow>=10.0.0
```

**Functionality:**

```python
#!/usr/bin/env python3
"""
HVYM Tunnler Identity Setup Script

Generates:
1. Stellar Ed25519 keypair for server identity
2. .env file with TUNNLER_SERVER_ADDRESS and TUNNLER_SERVER_SECRET
3. QR code PNG of public key for easy client configuration
4. JSON metadata file for API consumption
"""

from stellar_sdk import Keypair
import qrcode
from pathlib import Path
import json
from datetime import datetime, timezone

class IdentitySetup:
    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.data_path = base_path / "data"
        self.static_path = base_path / "static"

    def generate_keypair(self) -> Keypair:
        """Generate new random Stellar keypair."""
        return Keypair.random()

    def save_env_file(self, keypair: Keypair, domain: str):
        """Write .env file with server credentials."""
        env_content = f"""# HVYM Tunnler Server Configuration
# Generated: {datetime.now(timezone.utc).isoformat()}
# WARNING: Keep TUNNLER_SERVER_SECRET secure!

TUNNLER_SERVER_ADDRESS={keypair.public_key}
TUNNLER_SERVER_SECRET={keypair.secret}
TUNNLER_DOMAIN={domain}
TUNNLER_REDIS_URL=redis://localhost:6379
TUNNLER_LOG_LEVEL=INFO
"""
        env_path = self.base_path / ".env"
        env_path.write_text(env_content)
        env_path.chmod(0o600)  # Restrict permissions

    def generate_qr_code(self, public_key: str) -> Path:
        """Generate QR code image for public key."""
        self.static_path.mkdir(parents=True, exist_ok=True)

        # Create QR with Stellar address
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(public_key)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        qr_path = self.static_path / "server_identity_qr.png"
        img.save(qr_path)

        return qr_path

    def save_metadata(self, keypair: Keypair, domain: str):
        """Save server metadata JSON for API."""
        self.data_path.mkdir(parents=True, exist_ok=True)

        metadata = {
            "server_address": keypair.public_key,
            "domain": domain,
            "websocket_url": f"wss://{domain}/connect",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "qr_code_path": "/server-identity/qr"
        }

        meta_path = self.data_path / "server_identity.json"
        meta_path.write_text(json.dumps(metadata, indent=2))

    def run(self, domain: str) -> dict:
        """Execute full identity setup."""
        keypair = self.generate_keypair()

        self.save_env_file(keypair, domain)
        qr_path = self.generate_qr_code(keypair.public_key)
        self.save_metadata(keypair, domain)

        return {
            "public_key": keypair.public_key,
            "qr_path": str(qr_path),
            "env_path": str(self.base_path / ".env")
        }
```

**Output files:**
| File | Purpose | Permissions |
|------|---------|-------------|
| `.env` | Server credentials | 600 (owner only) |
| `static/server_identity_qr.png` | QR code image | 644 (world readable) |
| `data/server_identity.json` | Metadata for API | 644 |

### 3. API Endpoint (`app/api/identity.py`)

**Purpose:** Serve the server's public identity (QR code and metadata) on a public URL.

**Endpoints:**

| Endpoint | Method | Response | Purpose |
|----------|--------|----------|---------|
| `/server-identity` | GET | JSON | Server metadata + public key |
| `/server-identity/qr` | GET | image/png | QR code image |
| `/server-identity/qr.svg` | GET | image/svg+xml | QR code as SVG (optional) |

**Implementation:**

```python
"""
Server Identity API - Public endpoints for server discovery.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from pathlib import Path
import json

router = APIRouter(prefix="/server-identity", tags=["identity"])

# Paths relative to app root
BASE_PATH = Path(__file__).parent.parent.parent
STATIC_PATH = BASE_PATH / "static"
DATA_PATH = BASE_PATH / "data"

@router.get("")
async def get_server_identity():
    """
    Get server identity metadata.

    Returns the server's Stellar public address and connection info.
    This endpoint is public and requires no authentication.

    Use this to configure tunnel clients.
    """
    meta_path = DATA_PATH / "server_identity.json"

    if not meta_path.exists():
        raise HTTPException(
            status_code=503,
            detail="Server identity not configured. Run setup_identity.py first."
        )

    metadata = json.loads(meta_path.read_text())
    return JSONResponse(content=metadata)


@router.get("/qr")
async def get_identity_qr_code():
    """
    Get QR code image of server's Stellar public address.

    Scan this QR code with a Stellar wallet or client app
    to get the server's address for connection configuration.

    Returns: PNG image (image/png)
    """
    qr_path = STATIC_PATH / "server_identity_qr.png"

    if not qr_path.exists():
        raise HTTPException(
            status_code=503,
            detail="QR code not generated. Run setup_identity.py first."
        )

    return FileResponse(
        qr_path,
        media_type="image/png",
        filename="hvym_tunnler_server.png",
        headers={
            "Cache-Control": "public, max-age=86400"  # Cache for 24h
        }
    )


@router.get("/qr.svg")
async def get_identity_qr_svg():
    """
    Get QR code as SVG (scalable vector graphics).

    Returns: SVG image (image/svg+xml)
    """
    svg_path = STATIC_PATH / "server_identity_qr.svg"

    if not svg_path.exists():
        raise HTTPException(
            status_code=503,
            detail="SVG QR code not generated."
        )

    return FileResponse(
        svg_path,
        media_type="image/svg+xml",
        filename="hvym_tunnler_server.svg"
    )
```

**Integration with main.py:**

```python
# In app/main.py, add:
from app.api.identity import router as identity_router

app.include_router(identity_router)
```

---

## File Structure

```
hvym_tunnler/
├── scripts/
│   ├── oracle_startup.sh      # NEW: Cloud-init startup script
│   ├── setup_identity.py      # NEW: Identity generation script
│   └── install_certs.sh       # Optional: SSL cert helper
├── app/
│   ├── api/
│   │   ├── routes.py          # Existing routes
│   │   └── identity.py        # NEW: Identity API endpoint
│   └── main.py                # Add identity router
├── static/                    # NEW: Static files directory
│   └── server_identity_qr.png # Generated QR code
├── data/                      # NEW: Runtime data directory
│   └── server_identity.json   # Generated metadata
├── .env                       # Generated by setup script
└── docs/
    └── START_SCRIPT.md        # This document
```

---

## Detailed Implementation Plan

### Phase 1: Create setup_identity.py

```
Location: scripts/setup_identity.py
Dependencies: stellar-sdk, qrcode[pil], Pillow
```

**Features:**
1. Generate cryptographically secure Stellar keypair
2. Write `.env` file with proper permissions (0600)
3. Generate QR code in multiple formats (PNG required, SVG optional)
4. Create JSON metadata for API consumption
5. Idempotency check - don't overwrite existing identity unless forced
6. Command-line interface with options:
   - `--domain` - Override default domain
   - `--force` - Overwrite existing identity
   - `--output-dir` - Custom output directory

**CLI Usage:**
```bash
python scripts/setup_identity.py --domain tunnel.heavymeta.art
python scripts/setup_identity.py --force  # Regenerate
```

### Phase 2: Create identity.py API

```
Location: app/api/identity.py
```

**Endpoints:**
- `GET /server-identity` → JSON metadata
- `GET /server-identity/qr` → PNG image

**Security considerations:**
- Public endpoints (no auth required) - intentional for discovery
- Only exposes PUBLIC key, never secret
- Rate limiting inherited from main app

### Phase 3: Create oracle_startup.sh

```
Location: scripts/oracle_startup.sh
```

**Script sections:**

#### 3.1 System Setup
```bash
# Update packages
apt update && apt upgrade -y

# Install dependencies
apt install -y \
    python3.11 \
    python3.11-venv \
    python3-pip \
    nginx \
    certbot \
    python3-certbot-nginx \
    git \
    curl \
    redis-server \
    ufw
```

#### 3.2 Firewall
```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
```

#### 3.3 User & Repository
```bash
# Create user
useradd -m -s /bin/bash hvym
usermod -aG sudo hvym

# Clone repo
sudo -u hvym git clone ${REPO_URL} /home/hvym/hvym_tunnler

# Setup Python environment
sudo -u hvym python3.11 -m venv /home/hvym/hvym_tunnler/venv
sudo -u hvym /home/hvym/hvym_tunnler/venv/bin/pip install -r /home/hvym/hvym_tunnler/requirements.txt
sudo -u hvym /home/hvym/hvym_tunnler/venv/bin/pip install qrcode[pil] Pillow
```

#### 3.4 Identity Generation
```bash
# Run setup script
sudo -u hvym /home/hvym/hvym_tunnler/venv/bin/python \
    /home/hvym/hvym_tunnler/scripts/setup_identity.py \
    --domain "${DOMAIN}"

# Verify
cat /home/hvym/hvym_tunnler/data/server_identity.json
```

#### 3.5 Systemd Service
```bash
cat > /etc/systemd/system/hvym-tunnler.service << 'EOF'
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
EOF

systemctl daemon-reload
systemctl enable hvym-tunnler
```

#### 3.6 Nginx Configuration
```bash
cat > /etc/nginx/sites-available/hvym-tunnler << 'EOF'
upstream tunnler {
    server 127.0.0.1:8000;
    keepalive 32;
}

server {
    listen 80;
    server_name ${DOMAIN} *.${DOMAIN};

    # For certbot challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Redirect to HTTPS (after certs installed)
    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS config added after certbot runs
EOF

ln -sf /etc/nginx/sites-available/hvym-tunnler /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx
```

#### 3.7 SSL (Manual step - requires DNS)
```bash
# SSL requires wildcard cert with DNS challenge
# This must be done manually after DNS is configured:
#
# certbot certonly \
#     --manual \
#     --preferred-challenges dns \
#     -d ${DOMAIN} \
#     -d "*.${DOMAIN}"
#
# Then run: scripts/install_certs.sh
```

#### 3.8 Start Services
```bash
systemctl start redis-server
systemctl start hvym-tunnler
systemctl status hvym-tunnler

# Output server identity for user
echo "========================================="
echo "HVYM Tunnler Setup Complete!"
echo "========================================="
cat /home/hvym/hvym_tunnler/data/server_identity.json
echo ""
echo "QR Code available at: http://YOUR_IP/server-identity/qr"
echo "(after SSL: https://${DOMAIN}/server-identity/qr)"
echo "========================================="
```

---

## Security Considerations

### Secret Key Protection

| Item | Protection |
|------|------------|
| `.env` file | chmod 600, owned by hvym user |
| `TUNNLER_SERVER_SECRET` | Never logged, never in API responses |
| Memory | Secret only loaded at startup |

### Public Exposure

| Item | Visibility |
|------|------------|
| `TUNNLER_SERVER_ADDRESS` | Intentionally public |
| QR code | Public (contains only public key) |
| `/server-identity` endpoint | Public, no auth |

### Startup Script Security

- Script runs as root during cloud-init
- Creates restricted user `hvym` for runtime
- Service runs as `hvym`, not root
- Firewall enabled by default

---

## Testing Plan

### Local Testing

```bash
# Test setup_identity.py
cd hvym_tunnler
python scripts/setup_identity.py --domain localhost

# Verify outputs
cat .env
ls -la static/
cat data/server_identity.json

# Test API endpoint
uvicorn app.main:app --reload
curl http://localhost:8000/server-identity
curl http://localhost:8000/server-identity/qr -o test_qr.png
```

### Oracle Cloud Testing

1. Create Oracle Always Free VM (Ubuntu 22.04)
2. Paste `oracle_startup.sh` into Cloud-init script field
3. Launch instance
4. SSH in and check:
   ```bash
   tail -f /var/log/hvym-startup.log
   systemctl status hvym-tunnler
   curl http://localhost:8000/health
   curl http://localhost:8000/server-identity
   ```
5. Access from browser: `http://VM_PUBLIC_IP/server-identity/qr`

---

## Environment Variables

The startup script accepts these environment variables (set in Oracle cloud-init):

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNLER_DOMAIN` | tunnel.heavymeta.art | Domain for SSL and endpoints |
| `REPO_URL` | (github url) | Repository to clone |
| `REPO_BRANCH` | master | Branch to checkout |

**Example cloud-init with custom domain:**
```yaml
#cloud-config
runcmd:
  - export TUNNLER_DOMAIN="mytunnel.example.com"
  - curl -sSL https://raw.githubusercontent.com/.../oracle_startup.sh | bash
```

---

## Post-Setup Manual Steps

After the startup script completes, these steps require manual intervention:

### 1. Configure DNS (Required)
```
A    tunnel.yourdomain.com      → VM_PUBLIC_IP
A    *.tunnel.yourdomain.com    → VM_PUBLIC_IP
```

### 2. Install SSL Certificates (Required for production)
```bash
sudo certbot certonly \
    --manual \
    --preferred-challenges dns \
    -d tunnel.yourdomain.com \
    -d "*.tunnel.yourdomain.com"

# Add TXT record when prompted, then:
sudo scripts/install_certs.sh
sudo systemctl restart nginx
```

### 3. Verify Deployment
```bash
# Health check
curl https://tunnel.yourdomain.com/health

# Get server identity
curl https://tunnel.yourdomain.com/server-identity

# View QR code in browser
# https://tunnel.yourdomain.com/server-identity/qr
```

---

## Implementation Checklist

- [x] Create `scripts/setup_identity.py`
  - [x] Keypair generation
  - [x] .env file creation with secure permissions
  - [x] QR code generation (PNG)
  - [x] Metadata JSON generation
  - [x] CLI argument parsing
  - [x] Idempotency (don't overwrite unless --force)
  - [x] Return existing identity info if already configured

- [x] Create `app/api/identity.py`
  - [x] GET /server-identity endpoint
  - [x] GET /server-identity/qr endpoint
  - [x] GET /server-identity/address endpoint (bonus)
  - [x] Proper error handling (503 if not configured)
  - [x] Cache headers for QR image

- [x] Update `app/main.py`
  - [x] Import and include identity router

- [x] Create `scripts/oracle_startup.sh` (cloud-init, runs once)
  - [x] **Configurable variables at top of file**
  - [x] System package installation
  - [x] User creation
  - [x] Firewall configuration
  - [x] Repository clone
  - [x] Python venv setup
  - [x] Run setup_identity.py
  - [x] Install hvym-tunnler.service (main app)
  - [x] Install hvym-tunnler-boot.service (boot checker)
  - [x] Nginx configuration
  - [x] Service startup
  - [x] Create marker file at `/var/lib/hvym-tunnler/.initialized`
  - [x] Output summary with server address

- [x] Create `scripts/boot_check.sh` (runs every boot via systemd)
  - [x] Verify marker file exists
  - [x] **Critical: Check .env exists, alert if missing**
  - [x] Log boot event
  - [x] Non-blocking (don't prevent boot on warning)
  - [x] Regenerate QR/metadata if missing

- [x] Create `hvym-tunnler-boot.service` (embedded in oracle_startup.sh)
  - [x] Type=oneshot, runs before main service
  - [x] Executes boot_check.sh
  - [x] RemainAfterExit=yes

- [x] Update `requirements.txt`
  - [x] Add qrcode[pil]
  - [x] Add Pillow

- [x] Create directories
  - [x] `static/` (for QR images) with .gitkeep
  - [x] `data/` (for runtime metadata) with .gitkeep
  - [ ] Add to .gitignore

- [ ] Testing
  - [ ] Local test of setup_identity.py
  - [ ] Local test of /server-identity endpoints
  - [ ] Oracle Cloud VM test - first boot (INIT)
  - [ ] Oracle Cloud VM test - reboot (RESTART)
  - [ ] Oracle Cloud VM test - partial init recovery
  - [ ] Test critical error when .env missing on restart

---

## Appendix: Full oracle_startup.sh Template

See `scripts/oracle_startup.sh` for the complete implementation.
