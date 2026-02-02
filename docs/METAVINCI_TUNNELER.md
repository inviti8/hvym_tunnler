# Metavinci Tunnel Client Implementation

## Overview

This document specifies the implementation of a native tunnel client embedded in Metavinci, replacing the third-party Pinggy dependency. The client uses Stellar-based JWT authentication and WebSocket transport with YAMUX multiplexing.

---

## Current Pinggy Implementation (To Replace)

### Existing Code Locations

| Component | File | Lines | Description |
|-----------|------|-------|-------------|
| `PintheonSetupWorker` | metavinci.py | 156-471 | Installs Pinggy binary |
| `_get_pinggy_path()` | metavinci.py | 3171-3180 | Get executable path |
| `_is_tunnel_open()` | metavinci.py | 3182-3188 | Check tunnel status via HTTP |
| `_open_tunnel_direct()` | metavinci.py | 3190-3243 | Launch tunnel in terminal |
| `_set_tunnel_token_direct()` | metavinci.py | 3245-3266 | Qt dialog for token |
| `_set_tunnel_tier_direct()` | metavinci.py | 3268-3289 | Qt dialog for tier |
| Instance variables | metavinci.py | 1559-1567 | `TUNNEL_TOKEN`, `PINGGY_TIER` |
| UI actions | metavinci.py | 1654-1664 | Tray menu actions |

### Current Pinggy Command

```bash
pinggy -p 443 -R0:localhost:{port} -L4300:localhost:4300 \
  -o StrictHostKeyChecking=no -o ServerAliveInterval=30 \
  -t {token}@{tier}.pinggy.io \
  x:https x:localServerTls:localhost x:passpreflight
```

### Problems with Current Approach

1. **External binary dependency** - Must download Pinggy from S3
2. **Terminal spawning** - Opens separate terminal window
3. **No process control** - Fire-and-forget, can't monitor status
4. **Opaque authentication** - Token is just a string, no identity verification
5. **Third-party dependency** - Relies on pinggy.io infrastructure

---

## New Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        Metavinci Application                            │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────────┐ │
│  │  Stellar Wallet │  │  HVYMTunnelClient│  │  Local Services        │ │
│  │                 │  │  (QThread)       │  │                        │ │
│  │  - Keypair mgmt │─►│  - JWT auth      │◄─┤  - Pintheon (:9998)    │ │
│  │  - Address      │  │  - WebSocket     │  │  - IPFS Gateway        │ │
│  │                 │  │  - YAMUX mux     │  │  - Other services      │ │
│  └─────────────────┘  │  - Reconnection  │  └─────────────────────────┘ │
│                       └────────┬────────┘                               │
│                                │                                        │
│  ┌─────────────────────────────┴─────────────────────────────────────┐ │
│  │                         Qt Signal/Slot                             │ │
│  │  connected_signal, disconnected_signal, error_signal,              │ │
│  │  endpoint_signal, status_signal                                    │ │
│  └────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ WebSocket (wss://)
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                        HVYM Tunnler Server                              │
│                        (tunnel.heavymeta.art)                           │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Authentication | Stellar JWT (hvym_stellar) | Identity verification |
| Transport | WebSocket over TLS | Firewall traversal |
| Multiplexing | YAMUX | Multiple streams over single connection |
| Application | PyQt5 QThread | Background tunnel management |

---

## Implementation

### 1. New Files to Create

```
metavinci/
├── metavinci.py              # Existing (modify)
├── wallet_manager.py         # Existing (no changes needed)
├── tunnel_client.py          # NEW: Core tunnel client
├── tunnel_worker.py          # NEW: QThread wrapper
└── tunnel_config.py          # NEW: Configuration management
```

### 2. Dependencies to Add

```python
# requirements.txt additions
websockets>=12.0          # WebSocket client
yamux>=0.1.0              # Stream multiplexing (or implement minimal version)
hvym_stellar>=0.22.0      # With new JWT support
```

### 3. Core Tunnel Client

**File: `metavinci/tunnel_client.py`**

```python
"""
HVYM Tunnel Client - Native tunnel implementation for Metavinci.

Replaces Pinggy with Stellar-authenticated WebSocket tunneling.
"""

import asyncio
import json
import logging
import time
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass
from enum import Enum

import websockets
from websockets.client import WebSocketClientProtocol

from hvym_stellar import Stellar25519KeyPair, StellarJWTToken
from stellar_sdk import Keypair


class TunnelState(Enum):
    """Tunnel connection states."""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    ERROR = "error"


@dataclass
class TunnelEndpoint:
    """Represents the public tunnel endpoint."""
    url: str                    # https://GADDR....tunnel.heavymeta.art
    stellar_address: str        # Client's Stellar address
    server_address: str         # Server's Stellar address
    services: List[str]         # Bound services


@dataclass
class TunnelConfig:
    """Tunnel configuration."""
    server_url: str = "wss://tunnel.heavymeta.art/connect"
    server_address: str = ""    # Server's Stellar address (for JWT audience)
    services: List[str] = None
    reconnect_delay: float = 1.0
    max_reconnect_delay: float = 60.0
    reconnect_multiplier: float = 2.0
    ping_interval: float = 30.0
    ping_timeout: float = 10.0
    jwt_lifetime: int = 3600    # 1 hour

    def __post_init__(self):
        if self.services is None:
            self.services = ["pintheon"]


class HVYMTunnelClient:
    """
    Native HVYM tunnel client.

    Establishes authenticated WebSocket connection to HVYM Tunnler server
    using Stellar JWT tokens for authentication.

    Example:
        wallet = Stellar25519KeyPair(Keypair.from_secret("S..."))
        client = HVYMTunnelClient(wallet)

        # Set callbacks
        client.on_connected = lambda ep: print(f"Connected: {ep.url}")
        client.on_disconnected = lambda: print("Disconnected")

        # Connect (blocking)
        await client.connect()

        # Or connect in background
        asyncio.create_task(client.connect())
    """

    def __init__(
        self,
        wallet: Stellar25519KeyPair,
        config: TunnelConfig = None
    ):
        """
        Initialize tunnel client.

        Args:
            wallet: Stellar25519KeyPair for authentication
            config: Optional tunnel configuration
        """
        self.wallet = wallet
        self.config = config or TunnelConfig()

        # Connection state
        self._state = TunnelState.DISCONNECTED
        self._websocket: Optional[WebSocketClientProtocol] = None
        self._endpoint: Optional[TunnelEndpoint] = None
        self._reconnect_delay = self.config.reconnect_delay

        # Control flags
        self._should_reconnect = True
        self._stop_requested = False

        # Bound local ports
        self._port_bindings: Dict[str, int] = {}  # service_name -> local_port

        # Callbacks
        self.on_state_changed: Optional[Callable[[TunnelState], None]] = None
        self.on_connected: Optional[Callable[[TunnelEndpoint], None]] = None
        self.on_disconnected: Optional[Callable[[], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        self.on_endpoint_ready: Optional[Callable[[str], None]] = None

        # Logger
        self._logger = logging.getLogger("HVYMTunnelClient")

    @property
    def state(self) -> TunnelState:
        """Get current tunnel state."""
        return self._state

    @property
    def endpoint(self) -> Optional[TunnelEndpoint]:
        """Get tunnel endpoint (if connected)."""
        return self._endpoint

    @property
    def stellar_address(self) -> str:
        """Get client's Stellar address."""
        return self.wallet.base_stellar_keypair().public_key

    @property
    def is_connected(self) -> bool:
        """Check if tunnel is connected."""
        return self._state == TunnelState.CONNECTED

    def _set_state(self, state: TunnelState):
        """Update state and notify callback."""
        old_state = self._state
        self._state = state
        self._logger.info(f"State changed: {old_state.value} -> {state.value}")
        if self.on_state_changed:
            self.on_state_changed(state)

    def _create_jwt(self) -> str:
        """Create Stellar-signed JWT for authentication."""
        token = StellarJWTToken(
            keypair=self.wallet,
            audience=self.config.server_address,
            services=self.config.services,
            expires_in=self.config.jwt_lifetime
        )
        return token.to_jwt()

    def _build_endpoint_url(self) -> str:
        """Build public endpoint URL from Stellar address."""
        return f"https://{self.stellar_address}.tunnel.heavymeta.art"

    async def connect(self):
        """
        Connect to tunnel server.

        This method runs the connection loop, handling reconnection
        automatically. Call disconnect() to stop.
        """
        self._stop_requested = False
        self._should_reconnect = True

        while not self._stop_requested:
            try:
                await self._connect_once()
            except Exception as e:
                self._logger.error(f"Connection error: {e}")
                self._set_state(TunnelState.ERROR)
                if self.on_error:
                    self.on_error(str(e))

            # Handle reconnection
            if self._should_reconnect and not self._stop_requested:
                self._set_state(TunnelState.RECONNECTING)
                self._logger.info(f"Reconnecting in {self._reconnect_delay}s...")
                await asyncio.sleep(self._reconnect_delay)

                # Exponential backoff
                self._reconnect_delay = min(
                    self._reconnect_delay * self.config.reconnect_multiplier,
                    self.config.max_reconnect_delay
                )
            else:
                break

        self._set_state(TunnelState.DISCONNECTED)
        if self.on_disconnected:
            self.on_disconnected()

    async def _connect_once(self):
        """Establish single connection attempt."""
        self._set_state(TunnelState.CONNECTING)

        # Create JWT for authentication
        jwt = self._create_jwt()

        # Connect with JWT in Authorization header
        headers = {"Authorization": f"Bearer {jwt}"}

        self._logger.info(f"Connecting to {self.config.server_url}")

        async with websockets.connect(
            self.config.server_url,
            extra_headers=headers,
            ping_interval=self.config.ping_interval,
            ping_timeout=self.config.ping_timeout,
            close_timeout=10
        ) as websocket:
            self._websocket = websocket
            self._set_state(TunnelState.AUTHENTICATING)

            # Wait for auth confirmation
            auth_response = await asyncio.wait_for(
                websocket.recv(),
                timeout=30
            )
            auth_data = json.loads(auth_response)

            if auth_data.get("type") != "auth_ok":
                raise Exception(f"Authentication failed: {auth_data.get('error', 'Unknown')}")

            # Build endpoint info
            self._endpoint = TunnelEndpoint(
                url=auth_data.get("endpoint", self._build_endpoint_url()),
                stellar_address=self.stellar_address,
                server_address=self.config.server_address,
                services=self.config.services
            )

            # Reset reconnect delay on successful connection
            self._reconnect_delay = self.config.reconnect_delay

            self._set_state(TunnelState.CONNECTED)
            self._logger.info(f"Connected! Endpoint: {self._endpoint.url}")

            if self.on_connected:
                self.on_connected(self._endpoint)
            if self.on_endpoint_ready:
                self.on_endpoint_ready(self._endpoint.url)

            # Bind configured services
            for service, port in self._port_bindings.items():
                await self._send_bind(service, port)

            # Main message loop
            await self._message_loop(websocket)

    async def _message_loop(self, websocket: WebSocketClientProtocol):
        """Handle incoming messages."""
        try:
            async for message in websocket:
                await self._handle_message(message)
        except websockets.ConnectionClosed as e:
            self._logger.info(f"Connection closed: {e.code} {e.reason}")
        except Exception as e:
            self._logger.error(f"Message loop error: {e}")
            raise

    async def _handle_message(self, message: str):
        """Process incoming message from server."""
        try:
            data = json.loads(message)
            msg_type = data.get("type")

            if msg_type == "ping":
                await self._websocket.send(json.dumps({"type": "pong"}))

            elif msg_type == "tunnel_data":
                # Forward data to local service
                await self._handle_tunnel_data(data)

            elif msg_type == "bind_ok":
                service = data.get("service")
                self._logger.info(f"Service bound: {service}")

            elif msg_type == "error":
                self._logger.error(f"Server error: {data.get('message')}")
                if self.on_error:
                    self.on_error(data.get("message", "Unknown server error"))

            else:
                self._logger.debug(f"Unknown message type: {msg_type}")

        except json.JSONDecodeError:
            self._logger.warning(f"Invalid JSON message: {message[:100]}")

    async def _handle_tunnel_data(self, data: dict):
        """Handle incoming tunnel data (forward to local service)."""
        # This will be expanded with YAMUX stream handling
        service = data.get("service")
        payload = data.get("payload")
        stream_id = data.get("stream_id")

        local_port = self._port_bindings.get(service)
        if not local_port:
            self._logger.warning(f"No binding for service: {service}")
            return

        # TODO: Forward to local port via YAMUX stream
        self._logger.debug(f"Tunnel data for {service} (stream {stream_id})")

    async def _send_bind(self, service: str, local_port: int):
        """Send bind request to server."""
        if not self._websocket:
            return

        message = {
            "type": "bind",
            "service": service,
            "local_port": local_port
        }
        await self._websocket.send(json.dumps(message))
        self._logger.info(f"Binding {service} -> localhost:{local_port}")

    def bind_port(self, service: str, local_port: int):
        """
        Bind a local port to a service name.

        Args:
            service: Service name (e.g., "pintheon")
            local_port: Local port to expose
        """
        self._port_bindings[service] = local_port

        # If already connected, send bind immediately
        if self.is_connected and self._websocket:
            asyncio.create_task(self._send_bind(service, local_port))

    def unbind_port(self, service: str):
        """Unbind a service."""
        if service in self._port_bindings:
            del self._port_bindings[service]

    async def disconnect(self):
        """Disconnect from tunnel server."""
        self._stop_requested = True
        self._should_reconnect = False

        if self._websocket:
            await self._websocket.close()
            self._websocket = None

        self._endpoint = None
        self._set_state(TunnelState.DISCONNECTED)

    def disconnect_sync(self):
        """Synchronous disconnect (for use from Qt thread)."""
        self._stop_requested = True
        self._should_reconnect = False

        if self._websocket:
            # Schedule close on event loop
            asyncio.get_event_loop().call_soon_threadsafe(
                lambda: asyncio.create_task(self._websocket.close())
            )
```

### 4. Qt Thread Worker

**File: `metavinci/tunnel_worker.py`**

```python
"""
Qt Thread wrapper for HVYM Tunnel Client.

Provides PyQt5 signals for tunnel events and runs the async
client in a background thread.
"""

import asyncio
import logging
from typing import Optional

from PyQt5.QtCore import QThread, pyqtSignal, QObject

from hvym_stellar import Stellar25519KeyPair
from stellar_sdk import Keypair

from .tunnel_client import HVYMTunnelClient, TunnelConfig, TunnelState, TunnelEndpoint


class TunnelWorker(QThread):
    """
    Background worker for tunnel connection.

    Signals:
        state_changed(str): Tunnel state changed
        connected(str): Connected with endpoint URL
        disconnected(): Connection lost
        error(str): Error occurred
        endpoint_ready(str): Public endpoint URL available

    Example:
        # In Metavinci class
        self.tunnel_worker = TunnelWorker(self.stellar_keypair)
        self.tunnel_worker.connected.connect(self._on_tunnel_connected)
        self.tunnel_worker.error.connect(self._on_tunnel_error)
        self.tunnel_worker.start()
    """

    # Signals
    state_changed = pyqtSignal(str)
    connected = pyqtSignal(str)      # endpoint URL
    disconnected = pyqtSignal()
    error = pyqtSignal(str)
    endpoint_ready = pyqtSignal(str)  # endpoint URL

    def __init__(
        self,
        wallet: Stellar25519KeyPair,
        config: TunnelConfig = None,
        parent: QObject = None
    ):
        """
        Initialize tunnel worker.

        Args:
            wallet: Stellar25519KeyPair for authentication
            config: Optional tunnel configuration
            parent: Qt parent object
        """
        super().__init__(parent)
        self.wallet = wallet
        self.config = config or TunnelConfig()
        self._client: Optional[HVYMTunnelClient] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._logger = logging.getLogger("TunnelWorker")

    @property
    def is_connected(self) -> bool:
        """Check if tunnel is connected."""
        return self._client and self._client.is_connected

    @property
    def endpoint_url(self) -> Optional[str]:
        """Get current endpoint URL."""
        if self._client and self._client.endpoint:
            return self._client.endpoint.url
        return None

    @property
    def stellar_address(self) -> str:
        """Get client's Stellar address."""
        return self.wallet.base_stellar_keypair().public_key

    def bind_port(self, service: str, local_port: int):
        """Bind a local port to a service."""
        if self._client:
            self._client.bind_port(service, local_port)

    def run(self):
        """Thread entry point - runs async event loop."""
        self._logger.info("Tunnel worker starting")

        # Create new event loop for this thread
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            # Create client
            self._client = HVYMTunnelClient(self.wallet, self.config)

            # Wire up callbacks to emit Qt signals
            self._client.on_state_changed = self._on_state_changed
            self._client.on_connected = self._on_connected
            self._client.on_disconnected = self._on_disconnected
            self._client.on_error = self._on_error
            self._client.on_endpoint_ready = self._on_endpoint_ready

            # Run connection loop
            self._loop.run_until_complete(self._client.connect())

        except Exception as e:
            self._logger.error(f"Tunnel worker error: {e}")
            self.error.emit(str(e))

        finally:
            self._loop.close()
            self._logger.info("Tunnel worker stopped")

    def stop(self):
        """Stop the tunnel connection."""
        if self._client:
            self._client.disconnect_sync()

        # Wait for thread to finish
        self.wait(5000)

    def _on_state_changed(self, state: TunnelState):
        """Handle state change from client."""
        self.state_changed.emit(state.value)

    def _on_connected(self, endpoint: TunnelEndpoint):
        """Handle connection from client."""
        self.connected.emit(endpoint.url)

    def _on_disconnected(self):
        """Handle disconnection from client."""
        self.disconnected.emit()

    def _on_error(self, message: str):
        """Handle error from client."""
        self.error.emit(message)

    def _on_endpoint_ready(self, url: str):
        """Handle endpoint ready from client."""
        self.endpoint_ready.emit(url)


class TunnelManager(QObject):
    """
    High-level tunnel manager for Metavinci.

    Manages tunnel lifecycle, configuration persistence,
    and integration with Pintheon.

    Example:
        self.tunnel_manager = TunnelManager(self)
        self.tunnel_manager.set_wallet(self.stellar_keypair)
        self.tunnel_manager.connected.connect(self._update_pintheon_gateway)
        self.tunnel_manager.start_tunnel()
    """

    # Signals (forwarded from worker)
    state_changed = pyqtSignal(str)
    connected = pyqtSignal(str)
    disconnected = pyqtSignal()
    error = pyqtSignal(str)

    def __init__(self, parent: QObject = None):
        super().__init__(parent)
        self._wallet: Optional[Stellar25519KeyPair] = None
        self._worker: Optional[TunnelWorker] = None
        self._config = TunnelConfig()
        self._logger = logging.getLogger("TunnelManager")

        # Default port bindings
        self._default_bindings = {
            "pintheon": 9998,
            # "ipfs": 8082,
        }

    def set_wallet(self, wallet: Stellar25519KeyPair):
        """Set the wallet for authentication."""
        self._wallet = wallet

    def set_server(self, server_url: str, server_address: str):
        """Configure tunnel server."""
        self._config.server_url = server_url
        self._config.server_address = server_address

    def set_services(self, services: list):
        """Set services to request."""
        self._config.services = services

    def add_port_binding(self, service: str, port: int):
        """Add a port binding."""
        self._default_bindings[service] = port

    @property
    def is_connected(self) -> bool:
        """Check if tunnel is connected."""
        return self._worker and self._worker.is_connected

    @property
    def endpoint_url(self) -> Optional[str]:
        """Get current endpoint URL."""
        if self._worker:
            return self._worker.endpoint_url
        return None

    def start_tunnel(self) -> bool:
        """
        Start the tunnel connection.

        Returns:
            True if tunnel started, False if missing wallet or already running
        """
        if not self._wallet:
            self._logger.error("Cannot start tunnel: no wallet configured")
            self.error.emit("No wallet configured for tunnel authentication")
            return False

        if self._worker and self._worker.isRunning():
            self._logger.warning("Tunnel already running")
            return False

        self._logger.info("Starting tunnel...")

        # Create worker
        self._worker = TunnelWorker(self._wallet, self._config, self)

        # Connect signals
        self._worker.state_changed.connect(self.state_changed.emit)
        self._worker.connected.connect(self._on_connected)
        self._worker.disconnected.connect(self.disconnected.emit)
        self._worker.error.connect(self.error.emit)

        # Add default port bindings
        for service, port in self._default_bindings.items():
            self._worker.bind_port(service, port)

        # Start worker thread
        self._worker.start()
        return True

    def stop_tunnel(self):
        """Stop the tunnel connection."""
        if self._worker:
            self._logger.info("Stopping tunnel...")
            self._worker.stop()
            self._worker = None

    def _on_connected(self, endpoint_url: str):
        """Handle connection."""
        self._logger.info(f"Tunnel connected: {endpoint_url}")
        self.connected.emit(endpoint_url)
```

### 5. Configuration Storage

**File: `metavinci/tunnel_config.py`**

```python
"""
Tunnel configuration persistence.

Stores tunnel settings in TinyDB alongside existing Metavinci config.
"""

from typing import Optional, Dict, Any
from tinydb import TinyDB, Query


class TunnelConfigStore:
    """
    Persistent storage for tunnel configuration.

    Integrates with Metavinci's existing TinyDB database.
    """

    def __init__(self, db: TinyDB):
        """
        Initialize config store.

        Args:
            db: TinyDB instance (from Metavinci)
        """
        self.db = db
        self.query = Query()
        self._ensure_table()

    def _ensure_table(self):
        """Ensure tunnel config exists in database."""
        existing = self.db.search(self.query.type == 'tunnel_config')
        if not existing:
            self.db.insert({
                'type': 'tunnel_config',
                'server_url': 'wss://tunnel.heavymeta.art/connect',
                'server_address': '',  # Will be set when server is deployed
                'auto_connect': False,
                'services': ['pintheon'],
                'port_bindings': {'pintheon': 9998}
            })

    def get_config(self) -> Dict[str, Any]:
        """Get tunnel configuration."""
        result = self.db.search(self.query.type == 'tunnel_config')
        if result:
            return result[0]
        return {}

    def set_config(self, **kwargs):
        """Update tunnel configuration."""
        self.db.update(kwargs, self.query.type == 'tunnel_config')

    @property
    def server_url(self) -> str:
        return self.get_config().get('server_url', '')

    @server_url.setter
    def server_url(self, value: str):
        self.set_config(server_url=value)

    @property
    def server_address(self) -> str:
        return self.get_config().get('server_address', '')

    @server_address.setter
    def server_address(self, value: str):
        self.set_config(server_address=value)

    @property
    def auto_connect(self) -> bool:
        return self.get_config().get('auto_connect', False)

    @auto_connect.setter
    def auto_connect(self, value: bool):
        self.set_config(auto_connect=value)

    @property
    def services(self) -> list:
        return self.get_config().get('services', ['pintheon'])

    @services.setter
    def services(self, value: list):
        self.set_config(services=value)

    @property
    def port_bindings(self) -> Dict[str, int]:
        return self.get_config().get('port_bindings', {'pintheon': 9998})

    def set_port_binding(self, service: str, port: int):
        bindings = self.port_bindings
        bindings[service] = port
        self.set_config(port_bindings=bindings)

    def get_last_endpoint(self) -> Optional[str]:
        """Get last known endpoint URL."""
        return self.get_config().get('last_endpoint')

    def set_last_endpoint(self, url: str):
        """Store last known endpoint URL."""
        self.set_config(last_endpoint=url)
```

---

## Integration with Metavinci

### 1. Modifications to `metavinci.py`

#### Add Imports (after line 82)

```python
# Tunnel client
from tunnel_worker import TunnelManager
from tunnel_config import TunnelConfigStore
```

#### Add Instance Variables (around line 1570)

```python
# Replace Pinggy variables
# OLD:
# self.TUNNEL_TOKEN = ''
# self.PINGGY_TIER = 'free'

# NEW:
self.tunnel_manager: Optional[TunnelManager] = None
self.tunnel_config_store: Optional[TunnelConfigStore] = None
```

#### Initialize Tunnel Manager (in `__init__`, after DB setup ~line 1554)

```python
# Initialize tunnel configuration
self.tunnel_config_store = TunnelConfigStore(self.DB)

# Initialize tunnel manager
self.tunnel_manager = TunnelManager(self)
self.tunnel_manager.connected.connect(self._on_tunnel_connected)
self.tunnel_manager.disconnected.connect(self._on_tunnel_disconnected)
self.tunnel_manager.error.connect(self._on_tunnel_error)
self.tunnel_manager.state_changed.connect(self._on_tunnel_state_changed)

# Configure from stored settings
config = self.tunnel_config_store.get_config()
self.tunnel_manager.set_server(
    config.get('server_url', ''),
    config.get('server_address', '')
)
for service, port in config.get('port_bindings', {}).items():
    self.tunnel_manager.add_port_binding(service, port)
```

#### Replace Pinggy Methods

**Replace `_open_tunnel_direct()` (lines 3190-3243):**

```python
def _open_tunnel(self):
    """Open HVYM tunnel connection."""
    # Get active wallet
    wallet_kp = self._get_active_stellar_keypair()
    if not wallet_kp:
        self._show_error_dialog(
            "No Wallet",
            "Please create or select a Stellar wallet before opening tunnel."
        )
        return

    # Set wallet and start tunnel
    self.tunnel_manager.set_wallet(wallet_kp)

    if self.tunnel_manager.start_tunnel():
        self._update_tunnel_ui_connecting()
    else:
        self._show_error_dialog(
            "Tunnel Error",
            "Failed to start tunnel. Check logs for details."
        )
```

**Replace `_is_tunnel_open()` (lines 3182-3188):**

```python
def _is_tunnel_open(self) -> bool:
    """Check if tunnel is connected."""
    return self.tunnel_manager and self.tunnel_manager.is_connected
```

**Add new callback methods:**

```python
def _on_tunnel_connected(self, endpoint_url: str):
    """Handle tunnel connection."""
    logging.info(f"Tunnel connected: {endpoint_url}")

    # Store endpoint
    self.tunnel_config_store.set_last_endpoint(endpoint_url)

    # Update Pintheon gateway URL
    self._update_pintheon_gateway(endpoint_url)

    # Update UI
    self._update_tunnel_ui_connected(endpoint_url)

    # Show notification
    self.tray_icon.showMessage(
        "HVYM Tunnel",
        f"Connected: {endpoint_url}",
        QSystemTrayIcon.Information,
        3000
    )

def _on_tunnel_disconnected(self):
    """Handle tunnel disconnection."""
    logging.info("Tunnel disconnected")
    self._update_tunnel_ui_disconnected()

def _on_tunnel_error(self, message: str):
    """Handle tunnel error."""
    logging.error(f"Tunnel error: {message}")
    self._show_error_dialog("Tunnel Error", message)
    self._update_tunnel_ui_disconnected()

def _on_tunnel_state_changed(self, state: str):
    """Handle tunnel state change."""
    logging.debug(f"Tunnel state: {state}")
    # Update status indicator if needed

def _update_pintheon_gateway(self, endpoint_url: str):
    """Update Pintheon with new gateway URL."""
    # This would call Pintheon's /update_gateway endpoint
    # or update the configuration directly
    try:
        import requests
        response = requests.post(
            f"https://127.0.0.1:9999/update_gateway",
            data={"gateway": endpoint_url},
            verify=False,
            timeout=5
        )
        if response.ok:
            logging.info(f"Pintheon gateway updated to: {endpoint_url}")
    except Exception as e:
        logging.warning(f"Failed to update Pintheon gateway: {e}")

def _get_active_stellar_keypair(self) -> Optional[Stellar25519KeyPair]:
    """Get the active Stellar wallet as Stellar25519KeyPair."""
    # This should integrate with existing wallet_manager
    # Return the currently selected wallet
    try:
        # Example - adjust based on actual wallet manager API
        from stellar_sdk import Keypair
        wallet = self.wallet_manager.get_active_wallet()
        if wallet:
            keypair = Keypair.from_secret(wallet.secret_key)
            return Stellar25519KeyPair(keypair)
    except Exception as e:
        logging.error(f"Failed to get wallet keypair: {e}")
    return None
```

#### Update UI Methods

**Replace `_set_tunnel_token_direct()` and `_set_tunnel_tier_direct()`:**

These are no longer needed - authentication uses the Stellar wallet.

**Update menu creation (around line 1817):**

```python
# OLD Pinggy menu:
# self.settings_menu.addAction(self.set_tunnel_token_action)
# self.settings_menu.addAction(self.set_tunnel_tier_action)

# NEW: No token/tier settings needed
# Tunnel uses Stellar wallet for authentication
```

**Update action visibility (around line 3661):**

```python
# OLD:
# self.open_tunnel_action.setVisible(
#     self.PINTHEON_ACTIVE and len(self.TUNNEL_TOKEN) >= 7
# )

# NEW:
self.open_tunnel_action.setVisible(
    self.PINTHEON_ACTIVE and self._get_active_stellar_keypair() is not None
)
```

#### Add UI Helper Methods

```python
def _update_tunnel_ui_connecting(self):
    """Update UI for connecting state."""
    self.open_tunnel_action.setText("Connecting...")
    self.open_tunnel_action.setEnabled(False)

def _update_tunnel_ui_connected(self, endpoint_url: str):
    """Update UI for connected state."""
    self.open_tunnel_action.setText("Disconnect Tunnel")
    self.open_tunnel_action.setEnabled(True)
    # Change action to disconnect
    try:
        self.open_tunnel_action.triggered.disconnect()
    except:
        pass
    self.open_tunnel_action.triggered.connect(self._close_tunnel)

def _update_tunnel_ui_disconnected(self):
    """Update UI for disconnected state."""
    self.open_tunnel_action.setText("Open Tunnel")
    self.open_tunnel_action.setEnabled(True)
    # Change action back to connect
    try:
        self.open_tunnel_action.triggered.disconnect()
    except:
        pass
    self.open_tunnel_action.triggered.connect(self._open_tunnel)

def _close_tunnel(self):
    """Close the tunnel connection."""
    if self.tunnel_manager:
        self.tunnel_manager.stop_tunnel()
```

### 2. Remove Pinggy-Related Code

The following can be removed or deprecated:

| Code | Lines | Action |
|------|-------|--------|
| `PintheonSetupWorker._install_pinggy()` | 392-426 | Remove |
| `PintheonSetupWorker._get_pinggy_paths()` | 190-203 | Remove |
| `PintheonSetupWorker._get_pinggy_download_url()` | 205-227 | Remove |
| `_get_pinggy_path()` | 3171-3180 | Remove |
| `_open_tunnel_direct()` | 3190-3243 | Replace |
| `_set_tunnel_token_direct()` | 3245-3266 | Remove |
| `_set_tunnel_tier_direct()` | 3268-3289 | Remove |
| `TUNNEL_TOKEN` variable | 1559 | Remove |
| `PINGGY_TIER` variable | 1567 | Remove |
| Pinggy menu actions | 1654-1664 | Simplify |

---

## Testing

### Unit Tests

```python
# tests/test_tunnel_client.py

import pytest
import asyncio
from unittest.mock import Mock, patch

from hvym_stellar import Stellar25519KeyPair
from stellar_sdk import Keypair

from metavinci.tunnel_client import HVYMTunnelClient, TunnelConfig, TunnelState


@pytest.fixture
def wallet():
    """Create test wallet."""
    return Stellar25519KeyPair(Keypair.random())


@pytest.fixture
def config():
    """Create test config."""
    return TunnelConfig(
        server_url="wss://test.example.com/connect",
        server_address=Keypair.random().public_key
    )


def test_client_creation(wallet, config):
    """Test client initialization."""
    client = HVYMTunnelClient(wallet, config)
    assert client.state == TunnelState.DISCONNECTED
    assert client.stellar_address == wallet.base_stellar_keypair().public_key


def test_jwt_creation(wallet, config):
    """Test JWT token creation."""
    client = HVYMTunnelClient(wallet, config)
    jwt = client._create_jwt()

    # JWT should have 3 parts
    parts = jwt.split('.')
    assert len(parts) == 3


def test_port_binding(wallet, config):
    """Test port binding."""
    client = HVYMTunnelClient(wallet, config)
    client.bind_port("pintheon", 9998)

    assert "pintheon" in client._port_bindings
    assert client._port_bindings["pintheon"] == 9998


@pytest.mark.asyncio
async def test_disconnect(wallet, config):
    """Test disconnect."""
    client = HVYMTunnelClient(wallet, config)
    await client.disconnect()

    assert client.state == TunnelState.DISCONNECTED
```

### Integration Tests

```python
# tests/test_tunnel_integration.py

import pytest
from PyQt5.QtCore import QCoreApplication
from PyQt5.QtTest import QSignalSpy

from hvym_stellar import Stellar25519KeyPair
from stellar_sdk import Keypair

from metavinci.tunnel_worker import TunnelWorker, TunnelManager


@pytest.fixture
def app():
    """Create Qt application."""
    return QCoreApplication([])


@pytest.fixture
def wallet():
    return Stellar25519KeyPair(Keypair.random())


def test_tunnel_manager_no_wallet(app):
    """Test starting tunnel without wallet."""
    manager = TunnelManager()
    result = manager.start_tunnel()
    assert result == False


def test_tunnel_manager_with_wallet(app, wallet):
    """Test tunnel manager initialization."""
    manager = TunnelManager()
    manager.set_wallet(wallet)

    assert manager._wallet == wallet
```

---

## Migration Checklist

### Phase 1: Add New Code
- [ ] Create `tunnel_client.py`
- [ ] Create `tunnel_worker.py`
- [ ] Create `tunnel_config.py`
- [ ] Add dependencies to requirements.txt
- [ ] Add hvym_stellar JWT support (see HVYM_STELLAR_JWT.md)

### Phase 2: Integrate with Metavinci
- [ ] Add imports to metavinci.py
- [ ] Initialize TunnelManager in `__init__`
- [ ] Add tunnel callback methods
- [ ] Update `_open_tunnel()` method
- [ ] Update `_is_tunnel_open()` method
- [ ] Update UI state management

### Phase 3: Remove Pinggy Code
- [ ] Remove Pinggy installation code from PintheonSetupWorker
- [ ] Remove `_get_pinggy_path()`
- [ ] Remove `_open_tunnel_direct()`
- [ ] Remove token/tier dialog methods
- [ ] Remove TUNNEL_TOKEN and PINGGY_TIER variables
- [ ] Simplify settings menu (no Pinggy options)

### Phase 4: Testing
- [ ] Unit tests for tunnel_client
- [ ] Unit tests for tunnel_worker
- [ ] Integration tests with Metavinci
- [ ] End-to-end test with actual server

---

## Security Considerations

1. **Wallet Integration**: Tunnel uses existing Stellar wallet - no separate token storage
2. **JWT Expiration**: Tokens expire after 1 hour, auto-renewed on reconnect
3. **No Plaintext Secrets**: Unlike Pinggy token, no secrets stored in database
4. **Audience Verification**: JWT contains server address, prevents token reuse
5. **TLS Required**: WebSocket connection requires wss:// (TLS)

---

## References

- [SEAMLESS_TUNNELING.md](./SEAMLESS_TUNNELING.md) - Overall architecture
- [HVYM_STELLAR_JWT.md](./HVYM_STELLAR_JWT.md) - JWT implementation
- [hvym_stellar CRYPTO_SPEC](../../../hvym_stellar/CRYPTO_SPEC.md) - Cryptographic spec
- [websockets library](https://websockets.readthedocs.io/)
- [PyQt5 QThread](https://doc.qt.io/qtforpython/PySide6/QtCore/QThread.html)
