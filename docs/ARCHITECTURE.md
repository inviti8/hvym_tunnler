# HVYM Tunnler Architecture

## Overview

HVYM Tunnler is a WebSocket-based tunneling service that provides secure, Stellar-authenticated tunnels for the Heavymeta network. It enables Metavinci Desktop and Pintheon nodes to expose local services to the internet without opening incoming ports.

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| API Server | FastAPI (Python) |
| Transport | WebSocket |
| Authentication | Stellar Ed25519 JWT (via hvym_stellar) |
| Session Storage | Redis (with in-memory fallback) |
| Crypto | hvym_stellar 0.22.0 |

---

## System Architecture

```
                                    Internet
                                        │
                                        ▼
                              ┌─────────────────┐
                              │   Nginx/Caddy   │
                              │   (TLS + Proxy) │
                              └────────┬────────┘
                                       │
         ┌─────────────────────────────┼─────────────────────────────┐
         │                  HVYM Tunnler Server                       │
         │                                                            │
         │  ┌──────────────┐    ┌──────────────┐    ┌─────────────┐  │
         │  │   FastAPI    │    │   Session    │    │   Redis     │  │
         │  │   + Routes   │◄──►│   Manager    │◄──►│   Registry  │  │
         │  │  (Port 8000) │    │              │    │             │  │
         │  └──────┬───────┘    └──────────────┘    └─────────────┘  │
         │         │                                                  │
         │         │ WebSocket (/connect)                             │
         │         │                                                  │
         │  ┌──────▼───────┐    ┌──────────────┐    ┌─────────────┐  │
         │  │  Connection  │    │   Challenge  │    │    JWT      │  │
         │  │   Manager    │◄──►│   Manager    │◄──►│   Verifier  │  │
         │  │              │    │              │    │ (hvym_stellar)│ │
         │  └──────────────┘    └──────────────┘    └─────────────┘  │
         │                                                            │
         └─────────────────────────────┼──────────────────────────────┘
                                       │
                   ┌───────────────────┼───────────────────┐
                   │                   │                   │
            ┌──────▼──────┐     ┌──────▼──────┐     ┌──────▼──────┐
            │  Metavinci  │     │  Pintheon   │     │   Other     │
            │   Desktop   │     │    Node     │     │   Client    │
            │             │     │             │     │             │
            │ localhost:X │     │ localhost:Y │     │ localhost:Z │
            └─────────────┘     └─────────────┘     └─────────────┘
```

---

## Core Components

### 1. FastAPI Application (`app/main.py`)

The main entry point that orchestrates all components:

- **Lifespan management**: Initializes and cleans up server components
- **WebSocket endpoint** (`/connect`): Handles tunnel connections
- **REST endpoints**: Health checks, server info, API routes
- **CORS middleware**: Allows cross-origin requests

### 2. Authentication (`app/auth/`)

#### JWT Verifier (`jwt_verifier.py`)

Wraps `hvym_stellar.StellarJWTTokenVerifier` for JWT verification:

```python
from hvym_stellar import StellarJWTTokenVerifier, StellarJWTSession

class StellarJWTVerifier:
    def verify(self, jwt_string: str) -> dict:
        verifier = StellarJWTTokenVerifier(jwt_string)
        return verifier.verify(
            expected_audience=self.server_address,
            expected_issuer="hvym_tunnler"
        )

    def derive_shared_key(self, client_address: str) -> bytes:
        session = StellarJWTSession(
            server_keypair=self._server_keypair,
            client_stellar_address=client_address
        )
        return session.derive_tunnel_key()
```

#### Challenge Manager (`challenge.py`)

Prevents replay attacks with server-generated challenges:

- **Unique challenges**: 32-byte random value per connection
- **IP binding**: Challenge tied to client IP
- **Expiration**: 30-second TTL (configurable)
- **Rate limiting**: 10 attempts per minute, 5-minute block on exceed
- **Single use**: Challenge invalidated after verification

#### Session Manager (`session.py`)

Tracks authenticated tunnel sessions:

- **TunnelSession**: Dataclass with address, services, expiration
- **Shared key**: Optional ECDH-derived key for encryption
- **Auto-cleanup**: Expired sessions removed automatically

### 3. Tunnel Management (`app/tunnel/`)

#### Connection Manager (`connection.py`)

Manages WebSocket tunnel connections:

- **Connection lifecycle**: Accept, authenticate, maintain, close
- **Stream multiplexing**: Multiple requests over single WebSocket
- **Request forwarding**: Routes HTTP requests to tunnel clients
- **Ping/pong keepalive**: 30-second heartbeat interval
- **Graceful shutdown**: Clean disconnect on server stop

### 4. Registry (`app/registry/`)

#### Tunnel Registry (`store.py`)

Persistent storage for active tunnels:

- **Redis backend**: For production multi-instance deployment
- **In-memory fallback**: For development/single-instance
- **TTL-based expiry**: Auto-cleanup of expired tunnels
- **Active set tracking**: Fast lookup of all active tunnels

### 5. API Routes (`app/api/routes.py`)

REST endpoints for tunnel management:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/info` | GET | Server configuration |
| `/proxy/{path}` | ANY | Forward request to tunnel |
| `/api/tunnels` | GET | List active tunnels |
| `/api/tunnel/{addr}` | GET | Get tunnel details |
| `/api/stats` | GET | Server statistics |

---

## Authentication Flow

### Challenge-Response Protocol

```
Client                                          Server
------                                          ------
    │                                               │
    │  1. WebSocket Connect                         │
    │─────────────────────────────────────────────>│
    │                                               │
    │  2. auth_challenge                            │
    │     {challenge_id, challenge, server_address} │
    │<─────────────────────────────────────────────│
    │                                               │
    │  3. Create JWT with challenge in claims       │
    │     Sign with Stellar Ed25519 key             │
    │                                               │
    │  4. auth_response                             │
    │     {jwt, challenge_id}                       │
    │─────────────────────────────────────────────>│
    │                                               │
    │                      5. Verify JWT signature  │
    │                      6. Verify challenge      │
    │                      7. Check services        │
    │                      8. Create session        │
    │                                               │
    │  9. auth_ok                                   │
    │     {endpoint, server_address, services}      │
    │<─────────────────────────────────────────────│
    │                                               │
    │  10. Tunnel established                       │
    │◄─────────────────────────────────────────────►│
```

### JWT Token Structure

Created by client using `hvym_stellar.StellarJWTToken`:

**Header:**
```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "GCLIENT..."
}
```

**Payload:**
```json
{
  "iss": "hvym_tunnler",
  "sub": "GCLIENT...",
  "aud": "GSERVER...",
  "iat": 1706745600,
  "exp": 1706749200,
  "challenge": "<server_challenge>",
  "services": ["pintheon", "ipfs"]
}
```

---

## WebSocket Protocol

### Message Types

#### Server → Client

| Type | Description |
|------|-------------|
| `auth_challenge` | Initial challenge |
| `auth_ok` | Authentication successful |
| `auth_failed` | Authentication failed |
| `ping` | Keepalive ping |
| `tunnel_request` | Forward HTTP request |
| `bind_ok` | Port bind confirmed |

#### Client → Server

| Type | Description |
|------|-------------|
| `auth_response` | JWT with challenge |
| `pong` | Keepalive response |
| `bind` | Request port binding |
| `tunnel_response` | HTTP response data |
| `stream_data` | Stream payload |
| `stream_close` | Close stream |

### Stream Multiplexing

Multiple HTTP requests share one WebSocket via stream IDs:

```json
// Server → Client
{
  "type": "tunnel_request",
  "stream_id": 1,
  "request": {
    "method": "GET",
    "path": "/api/data",
    "headers": {...},
    "body": ""
  }
}

// Client → Server
{
  "type": "tunnel_response",
  "stream_id": 1,
  "response": {
    "status_code": 200,
    "headers": {...},
    "body": "..."
  }
}
```

---

## End-to-End Encryption

### Overview

HVYM Tunnler supports **zero-knowledge tunneling** where the server cannot read tunnel traffic. This uses the ECDH shared key derived during authentication.

### Encryption Details

| Property | Value |
|----------|-------|
| Algorithm | XSalsa20-Poly1305 (NaCl SecretBox) |
| Key | 32-byte ECDH shared key |
| Nonce | 24-byte random per message |
| Authentication | Poly1305 MAC (16 bytes) |

### Negotiation Flow

```
Client                                          Server
------                                          ------
    │                                               │
    │  auth_ok                                      │
    │  {encryption_available: true, ...}           │
    │<─────────────────────────────────────────────│
    │                                               │
    │  enable_encryption                            │
    │  {}                                           │
    │─────────────────────────────────────────────>│
    │                                               │
    │  encryption_enabled                           │
    │  {mode: "XSalsa20-Poly1305"}                 │
    │<─────────────────────────────────────────────│
    │                                               │
    │  [All subsequent tunnel traffic encrypted]   │
    │◄─────────────────────────────────────────────►│
```

### Encrypted Message Format

```json
{
  "type": "tunnel_request_encrypted",
  "encrypted": true,
  "payload": "<base64(nonce || ciphertext)>"
}
```

The payload contains:
- 24-byte nonce
- Ciphertext (original JSON + 16-byte Poly1305 tag)

### Decrypted Inner Structure

```json
{
  "type": "tunnel_request",
  "stream_id": 1,
  "request": {
    "method": "POST",
    "path": "/api/wallet/sign",
    "headers": {"Authorization": "Bearer ..."},
    "body": "{\"tx\": \"sensitive...\"}"
  }
}
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Confidentiality** | Server cannot read tunnel content |
| **Integrity** | Tampering detected via Poly1305 |
| **Authenticity** | Only parties with shared key can encrypt/decrypt |
| **Forward Secrecy** | New key derived per session via ECDH |
| **Replay Protection** | Unique nonce per message |

### When to Enable

E2E encryption is recommended for:
- Wallet operations (signing, key management)
- Authentication tokens
- Personal data
- Any sensitive API calls

### Client Implementation

```python
from hvym_stellar import (
    Stellar25519KeyPair,
    StellarJWTToken,
    StellarJWTSession,
    StellarSecretBox  # Core encryption from hvym_stellar
)

# After receiving auth_ok with encryption_available=true
if auth_response["encryption_available"]:
    # Derive same shared key as server
    session = StellarJWTSession(
        server_keypair=client_keypair,  # Client's keypair
        client_stellar_address=server_address  # Server's address
    )

    # Create SecretBox directly from session
    box = session.create_secret_box()

    # Or use the lower-level approach:
    # shared_key = session.derive_tunnel_key()
    # box = StellarSecretBox(shared_key)

    # Request encryption
    await ws.send_json({"type": "enable_encryption"})
    # Wait for encryption_enabled response

    # Encrypt messages
    encrypted_payload = box.encrypt_json({
        "type": "tunnel_response",
        "stream_id": 1,
        "response": {"status_code": 200, "body": "..."}
    })
    await ws.send_json({
        "type": "tunnel_response_encrypted",
        "encrypted": True,
        "payload": encrypted_payload
    })
```

### Crypto Module Split

| Module | Location | Responsibility |
|--------|----------|----------------|
| `StellarSecretBox` | hvym_stellar | Core XSalsa20-Poly1305 encryption |
| `StellarJWTSession.create_secret_box()` | hvym_stellar | Convenience factory |
| `TunnelCrypto` | hvym_tunnler | Thin wrapper for tunnel-specific methods |
| `TunnelCryptoNegotiator` | hvym_tunnler | WebSocket message wrapping & negotiation |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `TUNNLER_SERVER_ADDRESS` | (required) | Server's Stellar public key |
| `TUNNLER_SERVER_SECRET` | (required) | Server's Stellar secret key |
| `TUNNLER_HOST` | `0.0.0.0` | Bind address |
| `TUNNLER_PORT` | `8000` | Bind port |
| `TUNNLER_DOMAIN` | `tunnel.heavymeta.art` | Base domain |
| `TUNNLER_REDIS_URL` | `redis://localhost:6379` | Redis connection |
| `TUNNLER_JWT_CLOCK_SKEW` | `60` | JWT clock tolerance (seconds) |
| `TUNNLER_SESSION_TIMEOUT` | `86400` | Session duration (24h) |
| `TUNNLER_CHALLENGE_TTL` | `30` | Challenge validity (seconds) |
| `TUNNLER_RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |
| `TUNNLER_RATE_LIMIT_MAX_ATTEMPTS` | `10` | Max attempts per window |
| `TUNNLER_RATE_LIMIT_BLOCK_DURATION` | `300` | Block duration (5 min) |
| `TUNNLER_ALLOWED_SERVICES` | `["pintheon","ipfs"]` | Allowed service names |
| `TUNNLER_LOG_LEVEL` | `INFO` | Logging level |
| `TUNNLER_DEBUG` | `false` | Debug mode |

### Example `.env`

```bash
TUNNLER_SERVER_ADDRESS=GSERVER...
TUNNLER_SERVER_SECRET=SSERVER...
TUNNLER_DOMAIN=tunnel.heavymeta.art
TUNNLER_REDIS_URL=redis://localhost:6379
TUNNLER_ALLOWED_SERVICES=["pintheon","ipfs"]
```

---

## Directory Structure

```
hvym_tunnler/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Settings management
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_verifier.py  # hvym_stellar JWT verification
│   │   ├── challenge.py     # Challenge-response manager
│   │   └── session.py       # Session management
│   ├── crypto/
│   │   ├── __init__.py
│   │   └── tunnel_crypto.py # E2E encryption (XSalsa20-Poly1305)
│   ├── tunnel/
│   │   ├── __init__.py
│   │   └── connection.py    # WebSocket connection manager
│   ├── registry/
│   │   ├── __init__.py
│   │   └── store.py         # Redis/memory tunnel registry
│   └── api/
│       ├── __init__.py
│       └── routes.py        # REST API endpoints
├── tests/
│   ├── __init__.py
│   ├── conftest.py          # Pytest fixtures
│   ├── test_server.py       # Server component tests
│   ├── test_challenge.py    # Challenge manager tests
│   └── test_crypto.py       # E2E encryption tests
├── docs/
│   ├── ARCHITECTURE.md      # This file
│   ├── HVYM_STELLAR_JWT.md  # JWT specification
│   └── SEAMLESS_TUNNELING.md
├── requirements.txt
├── pyproject.toml
└── .env.example
```

---

## Security Model

### 1. Stellar Ed25519 Authentication

- JWT signed with client's Stellar Ed25519 key
- Server verifies signature using public key from `sub` claim
- No shared secrets required for verification

### 2. Challenge-Response

- Prevents JWT replay attacks
- Challenge bound to client IP
- Single-use with 30-second TTL

### 3. Rate Limiting

- Per-IP rate limiting on auth attempts
- 10 attempts per 60-second window
- 5-minute block after exceeding limit
- Resets on successful authentication

### 4. Session Security

- ECDH shared key derivation for E2E encryption
- Session expiration from JWT `exp` claim
- Automatic session cleanup

### 5. Transport Security

- TLS termination at reverse proxy (nginx/caddy)
- WebSocket over HTTPS (wss://)

### 6. End-to-End Encryption (Zero-Knowledge)

- Optional XSalsa20-Poly1305 encryption for tunnel traffic
- Server routes encrypted blobs it cannot read
- 24-byte random nonce per message
- Poly1305 authentication tag detects tampering
- Key derived via ECDH (Curve25519) from Stellar keys

---

## Dependencies

```
# Core
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
websockets>=12.0
pydantic>=2.0
pydantic-settings>=2.0

# Stellar/Crypto
hvym_stellar>=0.22.0
stellar-sdk>=9.0.0
pynacl>=1.5.0

# Storage
redis>=5.0.0
```

---

## Integration Points

### Metavinci Desktop

1. Create JWT with `hvym_stellar.StellarJWTToken`
2. Connect to `wss://tunnel.heavymeta.art/connect`
3. Complete challenge-response authentication
4. Receive public endpoint URL
5. Forward local service traffic through tunnel

### Pintheon Nodes

1. Generate JWT for tunnel authentication
2. Establish persistent tunnel connection
3. Use assigned endpoint as `url_host`
4. Publish endpoint to Stellar blockchain as `home_domain`

---

## Deployment

### Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run with hot reload
python -m app.main
```

### Production

```bash
# Run with uvicorn
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4

# Or with gunicorn
gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name tunnel.heavymeta.art *.tunnel.heavymeta.art;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    # WebSocket tunnel endpoint
    location /connect {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 86400;
    }

    # Proxy requests to tunneled clients
    # Extract Stellar address from subdomain
    location / {
        set $stellar_address "";
        if ($host ~* "^([^.]+)\.tunnel\.heavymeta\.art$") {
            set $stellar_address $1;
        }

        proxy_pass http://127.0.0.1:8000/proxy$request_uri;
        proxy_set_header X-Stellar-Address $stellar_address;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

---

## References

- [hvym_stellar JWT Specification](./HVYM_STELLAR_JWT.md)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [RFC 8037 - EdDSA in JOSE](https://tools.ietf.org/html/rfc8037)
