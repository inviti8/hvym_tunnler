# HVYM Tunnler Service

This document provides a comprehensive guide to implementing and deploying the HVYM Tunnler server, which provides secure tunneling for the Heavymeta network using Stellar-based JWT authentication.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Server Implementation](#server-implementation)
5. [Authentication Layer](#authentication-layer)
6. [WebSocket Handler](#websocket-handler)
7. [Service Registry](#service-registry)
8. [Deployment](#deployment)
9. [Configuration](#configuration)
10. [Monitoring](#monitoring)
11. [Security Considerations](#security-considerations)
12. [Scaling](#scaling)
13. [Troubleshooting](#troubleshooting)

---

## Overview

HVYM Tunnler is a self-hosted tunneling service that replaces third-party dependencies like Pinggy. It provides:

- **Stellar JWT Authentication**: Clients authenticate using Ed25519-signed JWTs tied to their Stellar wallet
- **WebSocket Transport**: Firewall-friendly connections over wss://
- **YAMUX Multiplexing**: Multiple services over a single connection
- **Zero External Dependencies**: No third-party tunnel providers required
- **Soroban Integration** (Future): On-chain namespace registry and failover

### Key Differences from Traditional Tunneling

| Aspect | Traditional (Pinggy/ngrok) | HVYM Tunnler |
|--------|---------------------------|--------------|
| Authentication | Opaque token | Stellar Ed25519 JWT |
| Identity | Provider-assigned | Stellar address (verifiable) |
| Server Trust | Third-party | Self-hosted + Soroban contracts |
| Client | External binary | Native in Metavinci |
| Namespace | Provider-controlled | Soroban contracts (future) |

---

## Architecture

### System Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           HVYM Tunnler Server                               │
│                           (tunnel.heavymeta.art)                            │
│                           Stellar Address: GSERVER...                       │
│                                                                             │
│  ┌───────────────────┐  ┌───────────────────┐  ┌───────────────────────┐   │
│  │   Auth Service    │  │  WebSocket Server │  │   Service Registry    │   │
│  │                   │  │                   │  │                       │   │
│  │  - JWT Validation │  │  - Connection Mgr │  │  - Client → Tunnel    │   │
│  │  - Stellar Verify │  │  - YAMUX Mux      │  │  - Endpoint Mapping   │   │
│  │  - Session Create │  │  - Traffic Route  │  │  - Health Tracking    │   │
│  └─────────┬─────────┘  └─────────┬─────────┘  └───────────┬───────────┘   │
│            │                      │                        │               │
│            └──────────────────────┼────────────────────────┘               │
│                                   │                                        │
│  ┌────────────────────────────────┴────────────────────────────────────┐   │
│  │                        HTTP Reverse Proxy                            │   │
│  │                        (nginx / caddy)                               │   │
│  │                                                                      │   │
│  │  *.tunnel.heavymeta.art → Route by subdomain → Active tunnel        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐
              │  Client 1 │   │  Client 2 │   │  Client N │
              │  GABC...  │   │  GDEF...  │   │  GXYZ...  │
              │           │   │           │   │           │
              │ Metavinci │   │ Metavinci │   │ Metavinci │
              └───────────┘   └───────────┘   └───────────┘
```

### Request Flow

```
1. External Request
   https://GABCD....tunnel.heavymeta.art/api/data
                              │
                              ▼
2. Reverse Proxy (nginx)
   - Extract subdomain (Stellar address)
   - Find active tunnel for GABCD...
   - Forward to WebSocket connection
                              │
                              ▼
3. WebSocket Server
   - Lookup tunnel by Stellar address
   - Create YAMUX stream for request
   - Forward HTTP request over stream
                              │
                              ▼
4. Client (Metavinci)
   - Receive request on YAMUX stream
   - Forward to localhost:9998 (Pintheon)
   - Return response over stream
                              │
                              ▼
5. Response flows back
   - YAMUX stream → WebSocket → nginx → External client
```

---

## Prerequisites

### Server Requirements

- Linux server (Ubuntu 22.04 LTS recommended)
- Public IP address
- Domain with wildcard DNS: `*.tunnel.heavymeta.art`
- Python 3.11+
- Docker and Docker Compose (optional, for containerized deployment)

### Dependencies

```
# requirements.txt
fastapi>=0.109.0
uvicorn[standard]>=0.27.0
websockets>=12.0
pydantic>=2.0
hvym_stellar>=0.22.0      # With JWT support
stellar-sdk>=9.0.0
redis>=5.0.0              # For session/registry storage
pyyaml>=6.0
python-multipart>=0.0.6
httpx>=0.26.0             # For health checks
```

### Stellar Server Identity

Each tunnel server requires its own Stellar keypair:

```python
from stellar_sdk import Keypair

# Generate server keypair (do once, store securely)
server_keypair = Keypair.random()
print(f"Server Address: {server_keypair.public_key}")
print(f"Server Secret: {server_keypair.secret}")

# Store in environment or secrets manager
# TUNNLER_SERVER_SECRET=S...
# TUNNLER_SERVER_ADDRESS=G...
```

---

## Server Implementation

### Project Structure

```
hvym_tunnler/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI application
│   ├── config.py            # Configuration management
│   ├── auth/
│   │   ├── __init__.py
│   │   ├── jwt_verifier.py  # Stellar JWT verification
│   │   └── session.py       # Session management
│   ├── tunnel/
│   │   ├── __init__.py
│   │   ├── connection.py    # WebSocket connection handler
│   │   ├── multiplexer.py   # YAMUX multiplexing
│   │   └── proxy.py         # HTTP proxy logic
│   ├── registry/
│   │   ├── __init__.py
│   │   ├── store.py         # Tunnel registry
│   │   └── endpoint.py      # Endpoint management
│   └── api/
│       ├── __init__.py
│       └── routes.py        # REST API endpoints
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── config.yaml
```

### Main Application

**File: `app/main.py`**

```python
"""
HVYM Tunnler Server - Main Application

Provides WebSocket-based tunneling with Stellar JWT authentication.
"""

import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .config import Settings, get_settings
from .auth.jwt_verifier import StellarJWTVerifier
from .auth.session import SessionManager, TunnelSession
from .tunnel.connection import TunnelConnectionManager
from .registry.store import TunnelRegistry


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("hvym_tunnler")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    settings = get_settings()

    # Initialize components
    app.state.jwt_verifier = StellarJWTVerifier(
        server_address=settings.server_address,
        server_secret=settings.server_secret
    )
    app.state.session_manager = SessionManager()
    app.state.registry = TunnelRegistry(redis_url=settings.redis_url)
    app.state.connection_manager = TunnelConnectionManager(
        registry=app.state.registry,
        session_manager=app.state.session_manager
    )

    logger.info(f"HVYM Tunnler starting...")
    logger.info(f"Server address: {settings.server_address}")

    yield

    # Cleanup
    await app.state.connection_manager.shutdown()
    logger.info("HVYM Tunnler stopped")


# Create FastAPI app
app = FastAPI(
    title="HVYM Tunnler",
    description="Stellar-authenticated tunneling service for Heavymeta network",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "hvym_tunnler",
        "server_address": get_settings().server_address
    }


# Server info endpoint
@app.get("/info")
async def server_info(settings: Settings = Depends(get_settings)):
    """Get server information for client configuration."""
    return {
        "server_address": settings.server_address,
        "websocket_url": f"wss://{settings.domain}/connect",
        "services": ["pintheon", "ipfs"],
        "version": "1.0.0"
    }


# Active tunnels endpoint (for monitoring)
@app.get("/tunnels")
async def list_tunnels():
    """List active tunnels (admin only in production)."""
    registry: TunnelRegistry = app.state.registry
    tunnels = await registry.list_active()
    return {
        "count": len(tunnels),
        "tunnels": [
            {
                "stellar_address": t.stellar_address,
                "endpoint": t.endpoint_url,
                "connected_at": t.connected_at.isoformat(),
                "services": t.services
            }
            for t in tunnels
        ]
    }


# WebSocket tunnel endpoint
@app.websocket("/connect")
async def websocket_tunnel(websocket: WebSocket):
    """
    WebSocket endpoint for tunnel connections.

    Authentication via Authorization header with Stellar JWT.
    """
    jwt_verifier: StellarJWTVerifier = app.state.jwt_verifier
    connection_manager: TunnelConnectionManager = app.state.connection_manager

    # Extract JWT from headers
    auth_header = websocket.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        await websocket.close(code=4001, reason="Missing authorization")
        return

    jwt_token = auth_header[7:]  # Remove "Bearer " prefix

    # Verify JWT
    try:
        claims = jwt_verifier.verify(jwt_token)
    except Exception as e:
        logger.warning(f"JWT verification failed: {e}")
        await websocket.close(code=4002, reason=f"Authentication failed: {e}")
        return

    # Accept connection
    await websocket.accept()
    logger.info(f"Client connected: {claims['sub']}")

    # Create session
    session = TunnelSession(
        stellar_address=claims['sub'],
        services=claims.get('services', ['pintheon']),
        expires_at=claims.get('exp')
    )

    # Handle connection
    try:
        await connection_manager.handle_connection(websocket, session)
    except WebSocketDisconnect:
        logger.info(f"Client disconnected: {session.stellar_address}")
    except Exception as e:
        logger.error(f"Connection error for {session.stellar_address}: {e}")
    finally:
        await connection_manager.remove_connection(session.stellar_address)
```

---

## Authentication Layer

### JWT Verifier

**File: `app/auth/jwt_verifier.py`**

```python
"""
Stellar JWT Verification for HVYM Tunnler.

Verifies JWTs signed with Stellar Ed25519 keys.
"""

import json
import time
import base64
import logging
from typing import Dict, Any

from nacl.signing import VerifyKey
from stellar_sdk import Keypair

from hvym_stellar import Stellar25519KeyPair


logger = logging.getLogger("jwt_verifier")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def _stellar_address_to_pubkey(address: str) -> bytes:
    """Extract Ed25519 public key from Stellar address."""
    return Keypair.from_public_key(address).raw_public_key()


class StellarJWTVerifier:
    """
    Verifies Stellar-signed JWT tokens.

    Extracts the signer's public key from the `sub` claim (Stellar address)
    and verifies the Ed25519 signature.
    """

    def __init__(
        self,
        server_address: str,
        server_secret: str = None,
        clock_skew_seconds: int = 60
    ):
        """
        Initialize verifier.

        Args:
            server_address: This server's Stellar address (for audience validation)
            server_secret: Server's secret key (for deriving shared keys)
            clock_skew_seconds: Allowed clock skew for expiration
        """
        self.server_address = server_address
        self.clock_skew = clock_skew_seconds

        # Create server keypair for ECDH if secret provided
        if server_secret:
            self.server_keypair = Stellar25519KeyPair(
                Keypair.from_secret(server_secret)
            )
        else:
            self.server_keypair = None

    def verify(self, jwt_string: str) -> Dict[str, Any]:
        """
        Verify JWT and return claims.

        Args:
            jwt_string: The JWT string to verify

        Returns:
            Verified claims dictionary

        Raises:
            ValueError: If verification fails
        """
        # Parse JWT
        parts = jwt_string.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        header_b64, payload_b64, signature_b64 = parts

        # Decode components
        try:
            header = json.loads(_base64url_decode(header_b64))
            payload = json.loads(_base64url_decode(payload_b64))
            signature = _base64url_decode(signature_b64)
        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {e}")

        # Verify algorithm
        if header.get('alg') != 'EdDSA':
            raise ValueError(f"Unsupported algorithm: {header.get('alg')}")

        # Verify required claims
        for claim in ['iss', 'sub', 'aud', 'iat']:
            if claim not in payload:
                raise ValueError(f"Missing required claim: {claim}")

        # Verify issuer
        if payload['iss'] != 'hvym_tunnler':
            raise ValueError(f"Invalid issuer: {payload['iss']}")

        # Verify audience (must be this server)
        if payload['aud'] != self.server_address:
            raise ValueError(
                f"Audience mismatch: expected {self.server_address}, "
                f"got {payload['aud']}"
            )

        # Verify expiration
        if 'exp' in payload:
            current_time = int(time.time())
            if current_time > payload['exp'] + self.clock_skew:
                raise ValueError(f"Token expired at {payload['exp']}")

        # Extract public key from sub claim
        try:
            client_address = payload['sub']
            pubkey_bytes = _stellar_address_to_pubkey(client_address)
            verify_key = VerifyKey(pubkey_bytes)
        except Exception as e:
            raise ValueError(f"Invalid Stellar address in sub: {e}")

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        try:
            verify_key.verify(signing_input, signature)
        except Exception as e:
            raise ValueError(f"Signature verification failed: {e}")

        logger.info(f"JWT verified for: {client_address}")
        return payload

    def derive_shared_key(self, client_address: str) -> bytes:
        """
        Derive shared key with client for encrypted channel.

        Args:
            client_address: Client's Stellar address

        Returns:
            32-byte shared key
        """
        if not self.server_keypair:
            raise ValueError("Server keypair not configured")

        # Get client's public key
        client_pubkey = _stellar_address_to_pubkey(client_address)

        # Convert to X25519 for ECDH
        from nacl.signing import VerifyKey
        from nacl.public import Box

        verify_key = VerifyKey(client_pubkey)
        client_x25519 = verify_key.to_curve25519_public_key()

        # Compute shared secret
        box = Box(self.server_keypair.private_key(), client_x25519)
        return box.shared_key()
```

### Session Management

**File: `app/auth/session.py`**

```python
"""
Session management for tunnel connections.
"""

import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
import asyncio


@dataclass
class TunnelSession:
    """Represents an authenticated tunnel session."""
    stellar_address: str
    services: List[str]
    expires_at: Optional[int] = None
    connected_at: datetime = field(default_factory=datetime.utcnow)
    endpoint_url: str = ""
    shared_key: Optional[bytes] = None

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return int(time.time()) > self.expires_at

    def build_endpoint_url(self, domain: str) -> str:
        """Build public endpoint URL."""
        self.endpoint_url = f"https://{self.stellar_address}.{domain}"
        return self.endpoint_url


class SessionManager:
    """Manages active tunnel sessions."""

    def __init__(self):
        self._sessions: Dict[str, TunnelSession] = {}
        self._lock = asyncio.Lock()

    async def create_session(self, session: TunnelSession) -> TunnelSession:
        """Register a new session."""
        async with self._lock:
            self._sessions[session.stellar_address] = session
        return session

    async def get_session(self, stellar_address: str) -> Optional[TunnelSession]:
        """Get session by Stellar address."""
        return self._sessions.get(stellar_address)

    async def remove_session(self, stellar_address: str):
        """Remove a session."""
        async with self._lock:
            self._sessions.pop(stellar_address, None)

    async def list_sessions(self) -> List[TunnelSession]:
        """List all active sessions."""
        return list(self._sessions.values())

    async def cleanup_expired(self):
        """Remove expired sessions."""
        async with self._lock:
            expired = [
                addr for addr, session in self._sessions.items()
                if session.is_expired
            ]
            for addr in expired:
                del self._sessions[addr]
        return len(expired)
```

---

## WebSocket Handler

### Connection Manager

**File: `app/tunnel/connection.py`**

```python
"""
WebSocket connection management for tunnels.
"""

import json
import asyncio
import logging
from typing import Dict, Optional
from dataclasses import dataclass

from fastapi import WebSocket

from ..auth.session import TunnelSession, SessionManager
from ..registry.store import TunnelRegistry


logger = logging.getLogger("connection_manager")


@dataclass
class TunnelConnection:
    """Active tunnel connection."""
    websocket: WebSocket
    session: TunnelSession
    streams: Dict[int, asyncio.Queue]  # stream_id -> data queue


class TunnelConnectionManager:
    """
    Manages WebSocket connections for tunnels.

    Handles:
    - Connection lifecycle
    - Message routing
    - Stream multiplexing (YAMUX)
    - Health monitoring
    """

    def __init__(
        self,
        registry: TunnelRegistry,
        session_manager: SessionManager,
        domain: str = "tunnel.heavymeta.art"
    ):
        self.registry = registry
        self.session_manager = session_manager
        self.domain = domain
        self._connections: Dict[str, TunnelConnection] = {}
        self._lock = asyncio.Lock()

    async def handle_connection(
        self,
        websocket: WebSocket,
        session: TunnelSession
    ):
        """
        Handle a new tunnel connection.

        Args:
            websocket: The WebSocket connection
            session: Authenticated session
        """
        stellar_address = session.stellar_address

        # Build endpoint URL
        endpoint_url = session.build_endpoint_url(self.domain)

        # Create connection object
        connection = TunnelConnection(
            websocket=websocket,
            session=session,
            streams={}
        )

        # Register connection
        async with self._lock:
            # Close existing connection if any
            if stellar_address in self._connections:
                old_conn = self._connections[stellar_address]
                try:
                    await old_conn.websocket.close(
                        code=4003,
                        reason="New connection from same address"
                    )
                except:
                    pass

            self._connections[stellar_address] = connection

        # Register in registry
        await self.registry.register(session)

        # Register in session manager
        await self.session_manager.create_session(session)

        # Send auth confirmation
        await websocket.send_json({
            "type": "auth_ok",
            "endpoint": endpoint_url,
            "server_address": self.registry.server_address,
            "services": session.services
        })

        logger.info(f"Tunnel established: {stellar_address} -> {endpoint_url}")

        # Start message handling
        try:
            await self._message_loop(connection)
        finally:
            await self.remove_connection(stellar_address)

    async def _message_loop(self, connection: TunnelConnection):
        """Main message handling loop."""
        websocket = connection.websocket
        session = connection.session

        # Start ping task
        ping_task = asyncio.create_task(self._ping_loop(connection))

        try:
            async for message in websocket.iter_text():
                await self._handle_message(connection, message)
        finally:
            ping_task.cancel()

    async def _handle_message(self, connection: TunnelConnection, message: str):
        """Process incoming message from client."""
        try:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "pong":
                # Keepalive response
                pass

            elif msg_type == "bind":
                # Client binding a local port
                service = data.get("service")
                local_port = data.get("local_port")
                logger.info(
                    f"Bind request: {connection.session.stellar_address} "
                    f"{service} -> localhost:{local_port}"
                )
                await connection.websocket.send_json({
                    "type": "bind_ok",
                    "service": service
                })

            elif msg_type == "stream_data":
                # Data from client for a stream
                stream_id = data.get("stream_id")
                payload = data.get("payload")
                # Route to appropriate handler
                await self._handle_stream_data(connection, stream_id, payload)

            elif msg_type == "stream_close":
                # Client closing a stream
                stream_id = data.get("stream_id")
                if stream_id in connection.streams:
                    del connection.streams[stream_id]

            else:
                logger.debug(f"Unknown message type: {msg_type}")

        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from {connection.session.stellar_address}")

    async def _handle_stream_data(
        self,
        connection: TunnelConnection,
        stream_id: int,
        payload: str
    ):
        """Handle data from a stream."""
        # This will be expanded with full YAMUX implementation
        if stream_id in connection.streams:
            await connection.streams[stream_id].put(payload)

    async def _ping_loop(self, connection: TunnelConnection):
        """Send periodic pings to keep connection alive."""
        while True:
            try:
                await asyncio.sleep(30)
                await connection.websocket.send_json({"type": "ping"})
            except Exception:
                break

    async def remove_connection(self, stellar_address: str):
        """Remove a connection."""
        async with self._lock:
            if stellar_address in self._connections:
                del self._connections[stellar_address]

        await self.registry.unregister(stellar_address)
        await self.session_manager.remove_session(stellar_address)
        logger.info(f"Connection removed: {stellar_address}")

    async def get_connection(
        self,
        stellar_address: str
    ) -> Optional[TunnelConnection]:
        """Get connection by Stellar address."""
        return self._connections.get(stellar_address)

    async def forward_request(
        self,
        stellar_address: str,
        request_data: dict
    ) -> Optional[dict]:
        """
        Forward an HTTP request to a client tunnel.

        Args:
            stellar_address: Target client's address
            request_data: HTTP request data

        Returns:
            Response data or None if failed
        """
        connection = await self.get_connection(stellar_address)
        if not connection:
            return None

        # Create stream for this request
        stream_id = id(request_data)  # Simple stream ID
        response_queue = asyncio.Queue()
        connection.streams[stream_id] = response_queue

        try:
            # Send request to client
            await connection.websocket.send_json({
                "type": "tunnel_request",
                "stream_id": stream_id,
                "request": request_data
            })

            # Wait for response
            response = await asyncio.wait_for(
                response_queue.get(),
                timeout=30.0
            )
            return response

        except asyncio.TimeoutError:
            logger.warning(f"Request timeout for {stellar_address}")
            return None
        finally:
            connection.streams.pop(stream_id, None)

    async def shutdown(self):
        """Gracefully shutdown all connections."""
        async with self._lock:
            for addr, conn in self._connections.items():
                try:
                    await conn.websocket.close(
                        code=1001,
                        reason="Server shutting down"
                    )
                except:
                    pass
            self._connections.clear()
```

---

## Service Registry

### Registry Store

**File: `app/registry/store.py`**

```python
"""
Tunnel registry for tracking active tunnels.
"""

import json
import logging
from typing import List, Optional
from datetime import datetime

import redis.asyncio as redis

from ..auth.session import TunnelSession


logger = logging.getLogger("registry")


class TunnelRegistry:
    """
    Registry for active tunnel connections.

    Uses Redis for persistence and cross-instance coordination.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        server_address: str = "",
        key_prefix: str = "hvym_tunnel:"
    ):
        self.redis_url = redis_url
        self.server_address = server_address
        self.key_prefix = key_prefix
        self._redis: Optional[redis.Redis] = None

    async def _get_redis(self) -> redis.Redis:
        """Get Redis connection."""
        if self._redis is None:
            self._redis = await redis.from_url(self.redis_url)
        return self._redis

    def _key(self, stellar_address: str) -> str:
        """Build Redis key for a tunnel."""
        return f"{self.key_prefix}{stellar_address}"

    async def register(self, session: TunnelSession):
        """Register a tunnel in the registry."""
        r = await self._get_redis()

        data = {
            "stellar_address": session.stellar_address,
            "endpoint_url": session.endpoint_url,
            "services": session.services,
            "connected_at": session.connected_at.isoformat(),
            "expires_at": session.expires_at,
            "server_address": self.server_address
        }

        # Store with TTL if session has expiration
        ttl = None
        if session.expires_at:
            ttl = max(1, session.expires_at - int(datetime.utcnow().timestamp()))

        key = self._key(session.stellar_address)
        await r.set(key, json.dumps(data), ex=ttl)

        # Add to active set
        await r.sadd(f"{self.key_prefix}active", session.stellar_address)

        logger.info(f"Registered tunnel: {session.stellar_address}")

    async def unregister(self, stellar_address: str):
        """Remove a tunnel from the registry."""
        r = await self._get_redis()

        await r.delete(self._key(stellar_address))
        await r.srem(f"{self.key_prefix}active", stellar_address)

        logger.info(f"Unregistered tunnel: {stellar_address}")

    async def get(self, stellar_address: str) -> Optional[TunnelSession]:
        """Get tunnel info by Stellar address."""
        r = await self._get_redis()

        data = await r.get(self._key(stellar_address))
        if not data:
            return None

        info = json.loads(data)
        return TunnelSession(
            stellar_address=info["stellar_address"],
            endpoint_url=info["endpoint_url"],
            services=info["services"],
            connected_at=datetime.fromisoformat(info["connected_at"]),
            expires_at=info.get("expires_at")
        )

    async def list_active(self) -> List[TunnelSession]:
        """List all active tunnels."""
        r = await self._get_redis()

        addresses = await r.smembers(f"{self.key_prefix}active")
        tunnels = []

        for addr in addresses:
            if isinstance(addr, bytes):
                addr = addr.decode()
            session = await self.get(addr)
            if session:
                tunnels.append(session)

        return tunnels

    async def lookup_by_endpoint(
        self,
        subdomain: str
    ) -> Optional[TunnelSession]:
        """
        Look up tunnel by endpoint subdomain.

        The subdomain IS the Stellar address for default endpoints.
        """
        # For default endpoints, subdomain = Stellar address
        return await self.get(subdomain)

    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
```

---

## Deployment

### Docker Deployment

**File: `Dockerfile`**

```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app/ ./app/

# Environment
ENV PYTHONUNBUFFERED=1
ENV TUNNLER_HOST=0.0.0.0
ENV TUNNLER_PORT=8000

# Run
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

**File: `docker-compose.yml`**

```yaml
version: '3.8'

services:
  tunnler:
    build: .
    container_name: hvym-tunnler
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - TUNNLER_SERVER_ADDRESS=${TUNNLER_SERVER_ADDRESS}
      - TUNNLER_SERVER_SECRET=${TUNNLER_SERVER_SECRET}
      - TUNNLER_DOMAIN=tunnel.heavymeta.art
      - TUNNLER_REDIS_URL=redis://redis:6379
    depends_on:
      - redis
    networks:
      - tunnler-network

  redis:
    image: redis:7-alpine
    container_name: hvym-tunnler-redis
    restart: unless-stopped
    volumes:
      - redis-data:/data
    networks:
      - tunnler-network

  nginx:
    image: nginx:alpine
    container_name: hvym-tunnler-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - tunnler
    networks:
      - tunnler-network

networks:
  tunnler-network:
    driver: bridge

volumes:
  redis-data:
```

### Nginx Configuration

**File: `nginx.conf`**

```nginx
events {
    worker_connections 1024;
}

http {
    # Upstream for tunnler service
    upstream tunnler {
        server tunnler:8000;
    }

    # SSL configuration
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    # Main server for API and WebSocket connections
    server {
        listen 443 ssl;
        server_name tunnel.heavymeta.art;

        # WebSocket upgrade support
        location /connect {
            proxy_pass http://tunnler;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_read_timeout 86400;
        }

        # API endpoints
        location / {
            proxy_pass http://tunnler;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }

    # Wildcard server for tunnel endpoints
    server {
        listen 443 ssl;
        server_name *.tunnel.heavymeta.art;

        location / {
            # Extract Stellar address from subdomain
            set $stellar_address $host;
            if ($host ~* ^([^.]+)\.tunnel\.heavymeta\.art$) {
                set $stellar_address $1;
            }

            # Forward to tunnler with address header
            proxy_pass http://tunnler/proxy;
            proxy_set_header Host $host;
            proxy_set_header X-Stellar-Address $stellar_address;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
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

---

## Configuration

**File: `app/config.py`**

```python
"""
Configuration management for HVYM Tunnler.
"""

import os
from functools import lru_cache
from typing import List, Optional

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Server identity
    server_address: str = ""
    server_secret: str = ""

    # Network
    host: str = "0.0.0.0"
    port: int = 8000
    domain: str = "tunnel.heavymeta.art"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Authentication
    jwt_clock_skew: int = 60
    session_timeout: int = 86400  # 24 hours

    # Services
    allowed_services: List[str] = ["pintheon", "ipfs"]

    # Logging
    log_level: str = "INFO"

    class Config:
        env_prefix = "TUNNLER_"
        env_file = ".env"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
```

**File: `.env.example`**

```bash
# Server Identity (REQUIRED)
# Generate with: python -c "from stellar_sdk import Keypair; k=Keypair.random(); print(f'TUNNLER_SERVER_ADDRESS={k.public_key}\nTUNNLER_SERVER_SECRET={k.secret}')"
TUNNLER_SERVER_ADDRESS=GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
TUNNLER_SERVER_SECRET=SXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# Network
TUNNLER_HOST=0.0.0.0
TUNNLER_PORT=8000
TUNNLER_DOMAIN=tunnel.heavymeta.art

# Redis
TUNNLER_REDIS_URL=redis://localhost:6379

# Logging
TUNNLER_LOG_LEVEL=INFO
```

---

## Monitoring

### Health Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Basic health check |
| `/info` | GET | Server info for clients |
| `/tunnels` | GET | List active tunnels |

### Metrics to Track

- Active connections count
- Connection duration
- Bytes transferred per tunnel
- Authentication failures
- WebSocket errors

### Logging

```python
# Structured logging format
{
    "timestamp": "2024-01-15T10:30:00Z",
    "level": "INFO",
    "event": "tunnel_connected",
    "stellar_address": "GABC...",
    "endpoint": "https://GABC....tunnel.heavymeta.art",
    "services": ["pintheon"]
}
```

---

## Security Considerations

1. **Stellar JWT Verification**: All connections authenticated via Ed25519 signatures
2. **Audience Validation**: JWTs must specify this server's address
3. **TLS Required**: All connections over HTTPS/WSS
4. **No Plaintext Secrets**: Server secret stored in environment only
5. **Session Expiration**: Automatic cleanup of expired sessions
6. **Rate Limiting**: Consider adding rate limits per Stellar address
7. **Input Validation**: Validate all incoming messages

---

## Scaling

### Horizontal Scaling

```
                    ┌─────────────────┐
                    │   Load Balancer │
                    │   (HAProxy)     │
                    └────────┬────────┘
                             │
           ┌─────────────────┼─────────────────┐
           │                 │                 │
    ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
    │  Tunnler 1  │   │  Tunnler 2  │   │  Tunnler 3  │
    │  GSERVER1.. │   │  GSERVER2.. │   │  GSERVER3.. │
    └──────┬──────┘   └──────┬──────┘   └──────┬──────┘
           │                 │                 │
           └─────────────────┼─────────────────┘
                             │
                    ┌────────▼────────┐
                    │   Redis Cluster │
                    └─────────────────┘
```

### Considerations

1. **Sticky Sessions**: WebSocket connections must stay on same server
2. **Redis Cluster**: Shared registry across instances
3. **Geographic Distribution**: Deploy in multiple regions
4. **Soroban Registry** (Future): Decentralized server discovery

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| JWT verification fails | Clock skew | Increase `jwt_clock_skew` setting |
| Connection drops | Firewall timeout | Ensure ping/pong working |
| Endpoint not reachable | DNS not configured | Check wildcard DNS |
| Redis connection error | Wrong URL | Verify `redis_url` setting |

### Debug Mode

```bash
# Enable debug logging
TUNNLER_LOG_LEVEL=DEBUG uvicorn app.main:app --reload
```

---

## Future Enhancements

### Phase 5: Soroban Integration

- **TunnelRegistry Contract**: On-chain server registration
- **TunnelNamespace Contract**: Custom endpoint names
- **Failover Logic**: Automatic client reassignment
- **Health Reporting**: On-chain server status

See [SEAMLESS_TUNNELING.md](./docs/SEAMLESS_TUNNELING.md) for details.

---

## References

- [SEAMLESS_TUNNELING.md](./docs/SEAMLESS_TUNNELING.md) - Overall architecture
- [HVYM_STELLAR_JWT.md](./docs/HVYM_STELLAR_JWT.md) - JWT implementation
- [METAVINCI_TUNNELER.md](./docs/METAVINCI_TUNNELER.md) - Client implementation
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [WebSockets Library](https://websockets.readthedocs.io/)
- [Stellar SDK](https://stellar-sdk.readthedocs.io/)
