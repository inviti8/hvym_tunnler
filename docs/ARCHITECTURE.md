# HVYM Tunnler Architecture

## Overview

HVYM Tunnler is a self-hosted tunneling service built on OpenZiti, designed to replace the third-party Pinggy dependency currently used across the Heavymeta network. This document outlines the current implementation state and integration points with the broader ecosystem.

---

## Current Pinggy Dependency

### Usage in Heavymeta CLI & Metavinci Desktop

The Heavymeta network currently relies on **Pinggy** (v0.2.2) for exposing local services to the internet.

**Locations:**
- `heavymeta-cli-dev/hvym.py`
- `metavinci/metavinci.py`

**How Pinggy is Used:**

```bash
pinggy -p 443 -R0:localhost:{port} -L4300:localhost:4300 \
       -o StrictHostKeyChecking=no \
       -o ServerAliveInterval=30 \
       -t {pinggy_token}@{tier}.pinggy.io \
       x:https x:localServerTls:localhost x:passpreflight
```

**CLI Commands:**
| Command | Description |
|---------|-------------|
| `pinggy-set-token` | Configure Pinggy authentication token |
| `pinggy-token` | Retrieve current token |
| `pinggy-set-tier` | Set Pinggy tier (free/paid) |
| `pinggy-tier` | Get current tier |

**Download Sources:**
- Windows: `s3.ap-south-1.amazonaws.com/public.pinggy.binaries/cli/v0.2.2/windows/{arch}/pinggy.exe`
- macOS: `s3.ap-south-1.amazonaws.com/public.pinggy.binaries/cli/v0.2.2/darwin/{arch}/pinggy`
- Linux: `s3.ap-south-1.amazonaws.com/public.pinggy.binaries/cli/v0.2.2/linux/{arch}/pinggy`

### Pintheon Gateway System

Pintheon does not use Pinggy directly. Instead, it implements a **gateway abstraction layer**:

- Users provide their own domain/gateway URL during node setup
- The `url_host` variable stores the public gateway URL
- Nginx reverse proxy handles routing to IPFS gateway (port 8082) and Flask app
- Admin can update gateway dynamically via `/update_gateway` endpoint
- Domain is published to Stellar blockchain as `home_domain`

---

## HVYM Tunnler Implementation

### Technology Stack

| Component | Technology |
|-----------|------------|
| Network Layer | OpenZiti (Zero-Trust Networking) |
| API Server | FastAPI (Python) |
| Database | PostgreSQL 14 |
| Container Runtime | Docker & Docker Compose |
| SDK | openziti-sdk-python |

### System Components

```
┌─────────────────────────────────────────────────────────────────┐
│                      HVYM Tunnler Service                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────┐ │
│  │  FastAPI Server │    │  OpenZiti       │    │  PostgreSQL │ │
│  │  (Port 8000)    │◄──►│  Controller     │◄──►│  Database   │ │
│  │                 │    │  (Port 1280)    │    │             │ │
│  │  REST API for   │    │                 │    │  Tunnel &   │ │
│  │  tunnel mgmt    │    │  Policy & Auth  │    │  Config     │ │
│  └─────────────────┘    └────────┬────────┘    └─────────────┘ │
│                                  │                              │
│                         ┌────────▼────────┐                     │
│                         │  OpenZiti       │                     │
│                         │  Edge Router    │                     │
│                         │  (Port 3022)    │                     │
│                         │                 │                     │
│                         │  Client Conn.   │                     │
│                         └────────┬────────┘                     │
│                                  │                              │
└──────────────────────────────────┼──────────────────────────────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
              ┌─────▼─────┐ ┌─────▼─────┐ ┌─────▼─────┐
              │  Client   │ │  Client   │ │  Client   │
              │  Tunneler │ │  Tunneler │ │  Tunneler │
              │           │ │           │ │           │
              │ Pintheon  │ │ Metavinci │ │   Other   │
              │   Node    │ │  Desktop  │ │  Service  │
              └───────────┘ └───────────┘ └───────────┘
```

### OpenZiti Components

1. **Controller** (Port 1280, 6262)
   - Central management plane
   - Handles authentication and authorization
   - Manages service policies and identities
   - Stores network configuration

2. **Edge Router** (Port 3022, 10080)
   - Handles client connections
   - Routes traffic between services
   - Provides edge binding for external access

3. **Tunneler Clients**
   - Run on end-user machines (Pintheon nodes, Metavinci desktops)
   - Connect to router via secure, outbound-only connections
   - No incoming ports required on client side

### API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/tunnels/` | Create new tunnel |
| `GET` | `/tunnels/` | List all active tunnels |
| `GET` | `/tunnels/{service_id}` | Get tunnel details |
| `DELETE` | `/tunnels/{service_id}` | Close/delete tunnel |
| `GET` | `/health` | Health check |

### Directory Structure

```
hvym_tunnler/
├── app/
│   ├── main.py              # FastAPI application
│   └── services/
│       └── ziti_service.py  # OpenZiti service management
├── scripts/
│   ├── config.sh            # Configuration variables
│   ├── install.sh           # Main installation script
│   ├── generate_client_config.sh
│   └── setup/
│       ├── 01_install_dependencies.sh
│       ├── 02_install_openziti.sh
│       ├── 03_init_controller.sh
│       ├── 04_setup_router.sh
│       └── 05_setup_tunnel_service.sh
├── docker-compose.dev.yml   # Development environment
├── requirements.txt         # Python dependencies
├── SETUP.md                 # Setup guide
└── TUNNEL_SERVICE.md        # OpenZiti service guide
```

### Configuration

**Default Ports:**
| Port | Service |
|------|---------|
| 1280 | OpenZiti Edge API |
| 3022 | Edge Router |
| 6262 | Fabric API |
| 8000 | Management API |
| 10080 | Transport |

**Environment Variables:**
- OpenZiti version: `0.32.4`
- Installation path: `/opt/ziti`
- Database: `tunneldb` (PostgreSQL)

---

## Pinggy vs HVYM Tunnler Comparison

| Aspect | Pinggy (Current) | HVYM Tunnler (Target) |
|--------|------------------|----------------------|
| **Hosting** | Third-party SaaS | Self-hosted |
| **Security Model** | Token-based | Zero-trust + JWT + Certificates |
| **Infrastructure** | Shared cloud | Dedicated containers |
| **Cost** | Per-tier subscription | Infrastructure only |
| **Customization** | Limited | Full control |
| **Dependencies** | External service | Internal service |
| **Incoming Ports** | Required | Not required (outbound only) |

---

## Integration Points

### Metavinci Desktop / Heavymeta CLI

**Current (Pinggy):**
1. User configures Pinggy token via `pinggy-set-token`
2. CLI spawns Pinggy process in terminal
3. Pinggy connects to `{tier}.pinggy.io`
4. External URL provided for accessing local services

**Target (HVYM Tunnler):**
1. User enrolls with HVYM Tunnler controller
2. CLI spawns `ziti-tunnel` with enrolled identity
3. Tunneler connects to HVYM Tunnler edge router
4. Service exposed through HVYM network

### Pintheon Nodes

**Current:**
- Gateway URL manually configured by user
- No automatic tunneling provided
- User must arrange their own DNS/domain

**Target:**
- Automatic tunnel creation via HVYM Tunnler API
- `url_host` populated with HVYM-provided endpoint
- Seamless integration with Stellar home_domain

---

## Development Status

**Implemented:**
- FastAPI REST API for tunnel management
- OpenZiti service integration (ziti_service.py)
- Docker Compose development environment
- Installation scripts for production deployment
- Client configuration generation

**Pending:**
- Integration with Heavymeta CLI
- Integration with Metavinci Desktop
- Integration with Pintheon gateway system
- Production deployment infrastructure
- Monitoring and logging pipeline
- High availability configuration

---

## Security Considerations

1. **Zero-Trust Model**: No implicit trust; all connections authenticated
2. **Certificate-Based Auth**: Device identities use JWT enrollment + certificates
3. **No Incoming Ports**: Clients connect outbound only
4. **Policy-Based Access**: Fine-grained service and edge router policies
5. **Isolated Networks**: Docker bridge network isolation
6. **Firewall Rules**: Only required ports exposed (via UFW)

---

## Next Steps

1. **Complete API Implementation**: Add authentication, rate limiting, and user management
2. **Build Client SDK**: Python/Node.js SDK for CLI and desktop integration
3. **Replace Pinggy Calls**: Update `hvym.py` and `metavinci.py` to use HVYM Tunnler
4. **Pintheon Integration**: Auto-configure gateway URL from tunnel endpoint
5. **Deploy Production Infrastructure**: Set up hosted controller and routers
6. **Documentation**: User guides for node operators and developers
