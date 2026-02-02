# Seamless Tunneling Design

## Vision

Replace the third-party Pinggy dependency with a native tunneling solution that:
1. Uses **Heavymeta's Stellar-based token system** for authentication
2. Embeds tunneling client code **directly in Metavinci**
3. Provides seamless, zero-configuration connectivity for Pintheon nodes
4. Leverages **Soroban smart contracts** as the source of truth for namespace resolution

---

## Design Decisions Summary

| Decision | Choice | Rationale |
|----------|--------|-----------|
| **Architecture** | OpenZiti + Stellar JWT Signer | Battle-tested tunneling, custom auth layer |
| **Client Location** | Embedded in Metavinci | No external dependencies, tight wallet integration |
| **Server Identity** | Each server has own Stellar address | Enables smart contract failsafe system |
| **Token System** | New `TUNNEL` token type in hvym_stellar | High-level integration with existing crypto |
| **Endpoint Naming** | Stellar address subdomain | Simple, verifiable; Soroban contracts for namespaces |

---

## OpenZiti + Stellar JWT Integration

### Why OpenZiti?

OpenZiti provides battle-tested infrastructure for:
- Zero-trust networking (no incoming ports on clients)
- Connection multiplexing and traffic routing
- Built-in reconnection and keepalive
- Edge router distribution for geographic performance

### Stellar JWT Signer Configuration

OpenZiti's **External JWT Signer** feature allows us to plug in Stellar-signed JWTs:

```yaml
# OpenZiti Controller Configuration
external-jwt-signers:
  - name: "hvym-stellar"
    issuer: "hvym_tunnler"
    audience: "tunnel.heavymeta.art"
    # Ed25519 public keys are extracted from Stellar addresses
    # Validation happens via custom auth plugin
    claimsProperty: "sub"  # Maps to Stellar address
    useExternalId: true
```

**Authentication Flow:**
1. Client creates JWT signed with Stellar Ed25519 key
2. OpenZiti validates signature against public key derived from `sub` claim (Stellar address)
3. Identity established, tunnel connection authorized

---

## HVYM Stellar Token System

### New Token Type: `TUNNEL`

Extend `hvym_stellar` with a dedicated tunnel token type for seamless integration:

```python
class TokenType(Enum):
    ACCESS = "ACCESS"    # Macaroon-based authorization
    SECRET = "SECRET"    # Encrypted data container
    DATA = "DATA"        # Biscuit-based file tokens
    TUNNEL = "TUNNEL"    # NEW: JWT for tunnel authentication
```

### TUNNEL Token Structure

```python
class StellarTunnelToken:
    """JWT token for HVYM Tunnler authentication."""

    def __init__(
        self,
        keypair: Stellar25519KeyPair,
        server_address: str,           # Target tunnel server's Stellar address
        services: List[str] = None,    # Requested services ["pintheon", "ipfs"]
        expires_in: int = 3600,        # Token lifetime in seconds
        caveats: dict = None           # Additional restrictions
    ):
        self.keypair = keypair
        self.server_address = server_address
        self.services = services or ["pintheon"]
        self.expires_in = expires_in
        self.caveats = caveats or {}

    def to_jwt(self) -> str:
        """Generate signed JWT."""
        header = {
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": self.keypair.stellar_address()  # Key ID = Stellar address
        }
        payload = {
            "iss": "hvym_tunnler",
            "sub": self.keypair.stellar_address(),
            "aud": self.server_address,            # Target server address
            "iat": int(time.time()),
            "exp": int(time.time()) + self.expires_in,
            "services": self.services,
            "caveats": self.caveats
        }
        return self._sign_jwt(header, payload)

    def _sign_jwt(self, header: dict, payload: dict) -> str:
        """Sign JWT with Stellar Ed25519 key."""
        header_b64 = base64url_encode(json.dumps(header))
        payload_b64 = base64url_encode(json.dumps(payload))
        message = f"{header_b64}.{payload_b64}".encode()

        # Sign with Ed25519 (Stellar's native signing)
        signature = self.keypair.signing_key().sign(message).signature
        signature_b64 = base64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"
```

### Token Verification (Server-Side)

```python
class StellarTunnelTokenVerifier:
    """Verify TUNNEL tokens on the server."""

    def __init__(self, server_keypair: Stellar25519KeyPair):
        self.server_keypair = server_keypair

    def verify(self, jwt: str) -> TunnelSession:
        """Verify JWT and establish tunnel session."""
        header, payload, signature = self._parse_jwt(jwt)

        # 1. Verify audience matches this server
        if payload["aud"] != self.server_keypair.stellar_address():
            raise AuthError("Token not intended for this server")

        # 2. Verify expiration
        if payload["exp"] < time.time():
            raise AuthError("Token expired")

        # 3. Extract client's public key from 'sub' claim
        client_address = payload["sub"]
        client_pubkey = stellar_address_to_ed25519_pubkey(client_address)

        # 4. Verify Ed25519 signature
        message = f"{header}.{payload}".encode()
        if not verify_ed25519_signature(client_pubkey, message, signature):
            raise AuthError("Invalid signature")

        # 5. Derive shared key for encrypted channel
        shared_key = self.server_keypair.derive_shared_key(client_pubkey)

        return TunnelSession(
            client_address=client_address,
            server_address=self.server_keypair.stellar_address(),
            services=payload["services"],
            shared_key=shared_key,
            expires_at=payload["exp"]
        )
```

---

## Server Identity & Smart Contract Failsafe

### Each Server Has Its Own Stellar Address

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    HVYM Tunnel Server Fleet                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐         │
│  │  Server US-EAST │  │  Server EU-WEST │  │  Server APAC    │         │
│  │                 │  │                 │  │                 │         │
│  │  Stellar Addr:  │  │  Stellar Addr:  │  │  Stellar Addr:  │         │
│  │  GSERVER1...    │  │  GSERVER2...    │  │  GSERVER3...    │         │
│  │                 │  │                 │  │                 │         │
│  │  Status: ACTIVE │  │  Status: ACTIVE │  │  Status: STANDBY│         │
│  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘         │
│           │                    │                    │                   │
│           └────────────────────┼────────────────────┘                   │
│                                │                                        │
│                    ┌───────────▼───────────┐                           │
│                    │   Soroban Contract    │                           │
│                    │   "TunnelRegistry"    │                           │
│                    │                       │                           │
│                    │  - Server addresses   │                           │
│                    │  - Health status      │                           │
│                    │  - Failover rules     │                           │
│                    │  - Client mappings    │                           │
│                    └───────────────────────┘                           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Smart Contract Failsafe System (Future Development)

**Purpose:** Decentralized server health monitoring and automatic failover.

```rust
// Soroban Contract: TunnelRegistry (conceptual)

#[contract]
pub struct TunnelRegistry;

#[contractimpl]
impl TunnelRegistry {
    /// Register a tunnel server
    pub fn register_server(
        env: Env,
        server_address: Address,
        region: Symbol,
        endpoint: String,
    ) -> Result<(), Error>;

    /// Server heartbeat - must be called periodically
    pub fn heartbeat(
        env: Env,
        server_address: Address,
        active_tunnels: u32,
        capacity: u32,
    ) -> Result<(), Error>;

    /// Get healthy servers for a region
    pub fn get_servers(
        env: Env,
        region: Symbol,
    ) -> Vec<ServerInfo>;

    /// Failover: reassign clients from failed server
    pub fn failover(
        env: Env,
        failed_server: Address,
        target_server: Address,
    ) -> Result<(), Error>;

    /// Client lookup: which server handles this client?
    pub fn get_client_server(
        env: Env,
        client_address: Address,
    ) -> Option<Address>;
}
```

**Benefits:**
- Decentralized health monitoring (no single point of failure)
- Transparent server status (publicly auditable on-chain)
- Automatic client reassignment during outages
- Cryptographic proof of server identity

**Note:** This is noted for future development. The initial implementation will use a simpler centralized registry, with the Soroban contract layer added later for resilience.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         HVYM Tunnler Service                            │
│                         (Stellar Address: GSERVER...)                   │
│                                                                         │
│  ┌──────────────────┐    ┌──────────────────┐    ┌──────────────────┐  │
│  │  Auth Service    │    │  OpenZiti        │    │  Service         │  │
│  │                  │    │  Controller      │    │  Registry        │  │
│  │  - TUNNEL Token  │◄──►│                  │◄──►│                  │  │
│  │    Verification  │    │  - Connection    │    │  - Stellar Addr  │  │
│  │  - Shared Key    │    │    Multiplexing  │    │    → Tunnel ID   │  │
│  │    Derivation    │    │  - Edge Routing  │    │  - Soroban Sync  │  │
│  └──────────────────┘    └──────────────────┘    └──────────────────┘  │
│           ▲                       ▲                       ▲             │
└───────────┼───────────────────────┼───────────────────────┼─────────────┘
            │                       │                       │
            │  TUNNEL Token (JWT)   │  Encrypted Tunnel     │  On-Chain
            │                       │                       │  Registry
            │                       │                       │
┌───────────┴───────────────────────┴───────────┐   ┌───────┴───────────┐
│              Metavinci Desktop                │   │  Soroban Contract │
│              (Stellar Address: GCLIENT...)    │   │  TunnelRegistry   │
│                                               │   │                   │
│  ┌─────────────┐  ┌─────────────┐  ┌───────┐ │   │  - Namespaces     │
│  │   Stellar   │  │   Tunnel    │  │ Local │ │   │  - Server Health  │
│  │   Wallet    │──│   Client    │──│ Svcs  │ │   │  - Client Mapping │
│  │             │  │  (Native)   │  │       │ │   │                   │
│  └─────────────┘  └─────────────┘  └───────┘ │   └───────────────────┘
│                                               │
└───────────────────────────────────────────────┘
```

---

## Endpoint Naming & Soroban Namespaces

### Default: Stellar Address Subdomain

Every tunnel gets a deterministic endpoint based on the client's Stellar address:

```
https://GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKL.tunnel.heavymeta.art
```

**Properties:**
- **Deterministic**: Same address always gets same subdomain
- **Verifiable**: Anyone can verify the address owns this endpoint
- **No Registration**: Works immediately, no setup required
- **Collision-Free**: Stellar addresses are globally unique

### Soroban Namespace System (Source of Truth)

The URL itself is not the source of truth - **Soroban contracts are**.

```rust
// Soroban Contract: TunnelNamespace (conceptual)

#[contract]
pub struct TunnelNamespace;

#[contractimpl]
impl TunnelNamespace {
    /// Register a custom namespace (e.g., "mynode")
    pub fn register(
        env: Env,
        owner: Address,           // Must sign transaction
        namespace: Symbol,        // "mynode"
        target: Address,          // Client's Stellar address
    ) -> Result<(), Error>;

    /// Resolve namespace to Stellar address
    pub fn resolve(
        env: Env,
        namespace: Symbol,
    ) -> Option<Address>;

    /// Transfer namespace ownership
    pub fn transfer(
        env: Env,
        namespace: Symbol,
        new_owner: Address,
    ) -> Result<(), Error>;

    /// List namespaces owned by address
    pub fn list_owned(
        env: Env,
        owner: Address,
    ) -> Vec<Symbol>;
}
```

**Resolution Flow:**

```
Client Request: https://mynode.tunnel.heavymeta.art
                           │
                           ▼
              ┌────────────────────────┐
              │  Tunnel Server         │
              │                        │
              │  1. Check Soroban:     │
              │     resolve("mynode")  │
              │     → GCLIENT123...    │
              │                        │
              │  2. Route to tunnel    │
              │     for GCLIENT123...  │
              └────────────────────────┘
```

**Benefits:**
- Custom vanity names without central registration
- Ownership proven cryptographically
- Transferable (can sell/gift namespaces)
- Auditable history on-chain
- Works even if tunnel server changes

---

## Metavinci Tunnel Client

### Embedded Client Implementation

```python
# metavinci/hvym_tunnel_client.py

from hvym_stellar import Stellar25519KeyPair, StellarTunnelToken
import asyncio
import websockets

class HVYMTunnelClient:
    """Native tunnel client embedded in Metavinci."""

    def __init__(self, wallet: Stellar25519KeyPair):
        self.wallet = wallet
        self.connection = None
        self.tunnel_endpoint = None
        self._reconnect_task = None

    async def connect(
        self,
        server_address: str,
        services: List[str] = None
    ) -> str:
        """
        Establish authenticated tunnel connection.

        Args:
            server_address: Tunnel server's Stellar address
            services: List of services to expose ["pintheon", "ipfs"]

        Returns:
            Public tunnel endpoint URL
        """
        # 1. Create TUNNEL token
        token = StellarTunnelToken(
            keypair=self.wallet,
            server_address=server_address,
            services=services or ["pintheon"],
            expires_in=3600
        )

        # 2. Connect to server
        server_url = await self._resolve_server_url(server_address)
        self.connection = await self._establish_connection(
            server_url,
            token.to_jwt()
        )

        # 3. Get assigned endpoint
        self.tunnel_endpoint = self._build_endpoint_url()

        # 4. Start keepalive
        self._reconnect_task = asyncio.create_task(self._keepalive_loop())

        return self.tunnel_endpoint

    async def expose_port(self, local_port: int, service_name: str):
        """Expose a local port through the tunnel."""
        await self.connection.send_json({
            "type": "bind",
            "service": service_name,
            "local_port": local_port
        })

    async def disconnect(self):
        """Close tunnel connection."""
        if self._reconnect_task:
            self._reconnect_task.cancel()
        if self.connection:
            await self.connection.close()

    def _build_endpoint_url(self) -> str:
        """Build public endpoint URL from Stellar address."""
        return f"https://{self.wallet.stellar_address()}.tunnel.heavymeta.art"

    async def _resolve_server_url(self, server_address: str) -> str:
        """Resolve server Stellar address to WebSocket URL."""
        # Future: Query Soroban TunnelRegistry contract
        # For now: Use known server mapping
        return f"wss://{server_address}.tunnel.heavymeta.art/connect"

    async def _establish_connection(self, url: str, jwt: str):
        """Establish WebSocket connection with JWT auth."""
        headers = {"Authorization": f"Bearer {jwt}"}
        return await websockets.connect(url, extra_headers=headers)

    async def _keepalive_loop(self):
        """Maintain connection with periodic pings."""
        while True:
            try:
                await asyncio.sleep(30)
                await self.connection.ping()
            except Exception as e:
                await self._handle_reconnect(e)

    async def _handle_reconnect(self, error):
        """Handle reconnection on connection loss."""
        # Exponential backoff reconnection logic
        pass
```

### Integration with Metavinci

```python
# metavinci/metavinci.py (modified)

from hvym_tunnel_client import HVYMTunnelClient

class Metavinci:
    def __init__(self):
        self.wallet = self._load_wallet()
        self.tunnel_client = HVYMTunnelClient(self.wallet)

    async def start_tunnel(self):
        """Replace Pinggy with native tunnel."""
        # Old: spawn_pinggy_process()
        # New:
        endpoint = await self.tunnel_client.connect(
            server_address=HVYM_TUNNEL_SERVER,
            services=["pintheon", "ipfs"]
        )

        # Expose Pintheon
        await self.tunnel_client.expose_port(9999, "pintheon")

        # Update Pintheon gateway
        self.pintheon.url_host = endpoint

        return endpoint
```

---

## Implementation Phases

### Phase 1: Token System
- [ ] Add `TokenType.TUNNEL` to hvym_stellar
- [ ] Implement `StellarTunnelToken` class
- [ ] Implement `StellarTunnelTokenVerifier` class
- [ ] Unit tests for token creation/verification

### Phase 2: Server Core
- [ ] Create tunnel server with Stellar auth
- [ ] Configure OpenZiti with External JWT Signer
- [ ] Implement service registry (in-memory first)
- [ ] WebSocket connection handler

### Phase 3: Client Integration
- [ ] Embed `HVYMTunnelClient` in Metavinci
- [ ] Replace Pinggy calls
- [ ] Add reconnection logic
- [ ] Update Pintheon gateway integration

### Phase 4: Infrastructure
- [ ] Deploy tunnel server(s)
- [ ] Set up wildcard DNS for `*.tunnel.heavymeta.art`
- [ ] Configure TLS certificates
- [ ] Monitoring and logging

### Phase 5: Soroban Contracts (Future)
- [ ] Deploy `TunnelRegistry` contract
- [ ] Deploy `TunnelNamespace` contract
- [ ] Integrate server health reporting
- [ ] Implement namespace resolution in server
- [ ] Add failover logic

---

## Security Considerations

1. **Stellar-Based Identity**: All auth tied to Ed25519 keypairs
2. **No Shared Secrets**: Asymmetric crypto only
3. **Per-Session Keys**: ECDH derives unique shared key per connection
4. **Audience Validation**: Tokens specify target server address
5. **Expiration**: Short-lived tokens (1 hour default)
6. **On-Chain Audit**: Server registrations visible on Soroban

---

## Technical Decisions: Transport & Multiplexing

Based on research into existing tunneling solutions (Pinggy, frp, chisel, ngrok):

### Industry Landscape

| Solution | Transport | Multiplexing | Notes |
|----------|-----------|--------------|-------|
| **Pinggy** | SSH | SSH channels | Uses `golang.org/x/crypto/ssh` |
| **chisel/sish** | SSH | SSH channels | Popular self-hosted |
| **frp** | TCP/QUIC/KCP | Custom TCP mux | Supports connection pooling |
| **go-http-tunnel** | HTTP/2 | HTTP/2 streams | Single muxed connection |
| **koding/tunnel** | TCP | YAMUX | Clean library approach |
| **rathole** | TCP | Noise Protocol | Rust, high performance |

### Recommended Approach: WebSocket + YAMUX

**Transport: WebSocket over TLS (wss://)**

Rationale:
- Works through corporate firewalls and HTTP proxies
- Browser-compatible (future web client possible)
- TLS provides encryption at transport layer
- Well-supported in Python (`websockets` library)

**Multiplexing: YAMUX**

Rationale:
- Battle-tested (used by Consul, Nomad, Boundary)
- Available in Python (`yamux` or port from Go)
- Lightweight stream multiplexing over single connection
- Supports backpressure and flow control

### Architecture Layers

```
┌─────────────────────────────────────────────────────┐
│  Application Layer                                  │
│  - Pintheon traffic                                 │
│  - IPFS gateway traffic                             │
│  - Multiple services on logical streams             │
├─────────────────────────────────────────────────────┤
│  Multiplexing Layer (YAMUX)                         │
│  - Stream 1: Pintheon (port 9999)                   │
│  - Stream 2: IPFS (port 8082)                       │
│  - Stream N: Additional services                    │
├─────────────────────────────────────────────────────┤
│  Transport Layer (WebSocket over TLS)               │
│  - Single persistent connection                     │
│  - Automatic reconnection                           │
│  - Works through firewalls                          │
├─────────────────────────────────────────────────────┤
│  Authentication Layer (Stellar JWT)                 │
│  - TUNNEL token in connection header                │
│  - ECDH shared key for additional encryption        │
│  - Session management                               │
└─────────────────────────────────────────────────────┘
```

### Why Not SSH?

While Pinggy uses SSH successfully, WebSocket offers advantages for our use case:
- **Simpler client embedding**: No SSH library dependency in Metavinci
- **Browser future**: Could build web-based tunnel client
- **Stellar integration**: JWT auth fits naturally in WebSocket headers
- **OpenZiti compatibility**: OpenZiti Edge SDK supports WebSocket transport

### Why Not QUIC?

QUIC has built-in multiplexing but:
- Requires UDP (often blocked by firewalls)
- More complex to implement
- Less mature Python support
- Can add later as optional transport

### Bandwidth & Geographic Routing (Future)

These questions remain open for Phase 5:
- **Bandwidth Quotas**: Could tie to Stellar transactions or implement separately
- **Geographic Routing**: Soroban contract could store server regions, client picks nearest

---

## Comparison: Pinggy vs HVYM Tunnler

| Aspect | Pinggy | HVYM Tunnler |
|--------|--------|--------------|
| Auth | Opaque token string | Stellar Ed25519 JWT |
| Identity | Unknown provider | Verifiable Stellar address |
| Client | External binary download | Native in Metavinci |
| Server Trust | Third-party | Own infrastructure + Soroban |
| Namespace | None | Soroban contracts |
| Failover | Provider-managed | Smart contract automated |
| Cost | Subscription tiers | Infrastructure only |

---

## References

- [hvym_stellar Documentation](../../../hvym_stellar/README.md)
- [hvym_stellar Crypto Spec](../../../hvym_stellar/CRYPTO_SPEC.md)
- [OpenZiti External JWT Signers](https://openziti.io/docs/learn/core-concepts/security/authentication/external-jwt-signers/)
- [Soroban Smart Contracts](https://soroban.stellar.org/docs)
