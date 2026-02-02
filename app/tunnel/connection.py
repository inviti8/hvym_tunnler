"""
WebSocket connection management for tunnels with E2E encryption.
"""

import json
import asyncio
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

from fastapi import WebSocket
from nacl.exceptions import CryptoError

from ..auth.session import TunnelSession, SessionManager
from ..registry.store import TunnelRegistry
from ..crypto.tunnel_crypto import TunnelCryptoNegotiator

logger = logging.getLogger("hvym_tunnler.connection")


@dataclass
class TunnelConnection:
    """Active tunnel connection with optional E2E encryption."""
    websocket: WebSocket
    session: TunnelSession
    crypto: TunnelCryptoNegotiator = field(default_factory=TunnelCryptoNegotiator)
    streams: Dict[int, asyncio.Queue] = field(default_factory=dict)
    _next_stream_id: int = 1

    def get_next_stream_id(self) -> int:
        """Get next available stream ID."""
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        return stream_id


class TunnelConnectionManager:
    """
    Manages WebSocket connections for tunnels with E2E encryption.

    Handles:
    - Connection lifecycle
    - E2E encryption negotiation
    - Message routing (encrypted or plaintext)
    - Stream multiplexing
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
            session: Authenticated session (with optional shared_key)
        """
        stellar_address = session.stellar_address

        # Build endpoint URL
        endpoint_url = session.build_endpoint_url(self.domain)

        # Create crypto negotiator with shared key if available
        crypto = TunnelCryptoNegotiator(session.shared_key)

        # Create connection object
        connection = TunnelConnection(
            websocket=websocket,
            session=session,
            crypto=crypto
        )

        # Register connection
        async with self._lock:
            # Close existing connection if any
            if stellar_address in self._connections:
                old_conn = self._connections[stellar_address]
                logger.info(f"Closing existing connection for {stellar_address}")
                try:
                    await old_conn.websocket.close(
                        code=4003,
                        reason="New connection from same address"
                    )
                except Exception:
                    pass

            self._connections[stellar_address] = connection

        # Register in registry
        await self.registry.register(session)

        # Register in session manager
        await self.session_manager.create_session(session)

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
        except Exception as e:
            logger.debug(f"Message loop ended for {session.stellar_address}: {e}")
        finally:
            ping_task.cancel()
            try:
                await ping_task
            except asyncio.CancelledError:
                pass

    async def _handle_message(self, connection: TunnelConnection, message: str):
        """Process incoming message from client."""
        try:
            data = json.loads(message)

            # Handle encrypted messages
            if data.get("encrypted"):
                try:
                    data = connection.crypto.unwrap_incoming(data)
                except CryptoError as e:
                    logger.warning(
                        f"Decryption failed from {connection.session.stellar_address}: {e}"
                    )
                    return

            msg_type = data.get("type")

            if msg_type == "pong":
                # Keepalive response - acknowledged
                pass

            elif msg_type == "enable_encryption":
                # Client requesting E2E encryption
                if connection.crypto.enable_encryption():
                    await self._send_message(connection, {
                        "type": "encryption_enabled",
                        "mode": "XSalsa20-Poly1305"
                    })
                    logger.info(
                        f"E2E encryption enabled for {connection.session.stellar_address}"
                    )
                else:
                    await self._send_message(connection, {
                        "type": "encryption_unavailable",
                        "reason": "No shared key available"
                    })

            elif msg_type == "disable_encryption":
                # Client disabling E2E encryption
                connection.crypto.disable_encryption()
                await self._send_message(connection, {
                    "type": "encryption_disabled"
                })

            elif msg_type == "bind":
                # Client binding a local port
                service = data.get("service")
                local_port = data.get("local_port")
                logger.info(
                    f"Bind request: {connection.session.stellar_address} "
                    f"{service} -> localhost:{local_port}"
                )
                await self._send_message(connection, {
                    "type": "bind_ok",
                    "service": service,
                    "local_port": local_port
                })

            elif msg_type == "stream_data":
                # Data from client for a stream (response to tunnel_request)
                stream_id = data.get("stream_id")
                payload = data.get("payload")
                await self._handle_stream_data(connection, stream_id, payload)

            elif msg_type == "stream_close":
                # Client closing a stream
                stream_id = data.get("stream_id")
                if stream_id in connection.streams:
                    # Signal stream closure
                    await connection.streams[stream_id].put(None)
                    del connection.streams[stream_id]

            elif msg_type in ("tunnel_response", "tunnel_response_encrypted"):
                # Response to a forwarded request
                stream_id = data.get("stream_id")
                response = data.get("response")
                if stream_id in connection.streams:
                    await connection.streams[stream_id].put(response)

            else:
                logger.debug(f"Unknown message type: {msg_type}")

        except json.JSONDecodeError:
            logger.warning(
                f"Invalid JSON from {connection.session.stellar_address}"
            )
        except Exception as e:
            logger.error(
                f"Error handling message from {connection.session.stellar_address}: {e}"
            )

    async def _send_message(
        self,
        connection: TunnelConnection,
        message: dict,
        encrypt: bool = False
    ):
        """
        Send a message to the client.

        Args:
            connection: Target connection
            message: Message dict to send
            encrypt: Force encryption (if available)
        """
        if encrypt and connection.crypto.is_encrypted:
            msg_type = message.pop("type", "message")
            wrapped = connection.crypto.wrap_outgoing(msg_type, message)
            await connection.websocket.send_json(wrapped)
        else:
            await connection.websocket.send_json(message)

    async def _handle_stream_data(
        self,
        connection: TunnelConnection,
        stream_id: int,
        payload: Any
    ):
        """Handle data from a stream."""
        if stream_id in connection.streams:
            await connection.streams[stream_id].put(payload)

    async def _ping_loop(self, connection: TunnelConnection):
        """Send periodic pings to keep connection alive."""
        try:
            while True:
                await asyncio.sleep(30)
                try:
                    await connection.websocket.send_json({"type": "ping"})
                except Exception:
                    break
        except asyncio.CancelledError:
            pass

    async def remove_connection(self, stellar_address: str):
        """Remove a connection and clean up."""
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
        request_data: dict,
        timeout: float = 30.0
    ) -> Optional[dict]:
        """
        Forward an HTTP request to a client tunnel with E2E encryption.

        Args:
            stellar_address: Target client's address
            request_data: HTTP request data (method, path, headers, body)
            timeout: Request timeout in seconds

        Returns:
            Response data or None if failed
        """
        connection = await self.get_connection(stellar_address)
        if not connection:
            logger.warning(f"No connection found for {stellar_address}")
            return None

        # Create stream for this request
        stream_id = connection.get_next_stream_id()
        response_queue: asyncio.Queue = asyncio.Queue()
        connection.streams[stream_id] = response_queue

        try:
            # Build message (encrypted if E2E is enabled)
            if connection.crypto.is_encrypted:
                message = connection.crypto.wrap_tunnel_request(
                    stream_id=stream_id,
                    request_data=request_data
                )
                logger.debug(
                    f"Sending encrypted request to {stellar_address} "
                    f"(stream {stream_id})"
                )
            else:
                message = {
                    "type": "tunnel_request",
                    "stream_id": stream_id,
                    "request": request_data
                }

            # Send request to client
            await connection.websocket.send_json(message)

            # Wait for response
            response = await asyncio.wait_for(
                response_queue.get(),
                timeout=timeout
            )
            return response

        except asyncio.TimeoutError:
            logger.warning(f"Request timeout for {stellar_address}")
            return None
        except Exception as e:
            logger.error(f"Error forwarding request to {stellar_address}: {e}")
            return None
        finally:
            connection.streams.pop(stream_id, None)

    async def broadcast(self, message: dict, encrypt: bool = False):
        """Broadcast a message to all connected clients."""
        for addr, conn in self._connections.items():
            try:
                await self._send_message(conn, message.copy(), encrypt=encrypt)
            except Exception as e:
                logger.warning(f"Failed to broadcast to {addr}: {e}")

    async def shutdown(self):
        """Gracefully shutdown all connections."""
        logger.info("Shutting down connection manager...")
        async with self._lock:
            for addr, conn in self._connections.items():
                try:
                    await conn.websocket.close(
                        code=1001,
                        reason="Server shutting down"
                    )
                except Exception:
                    pass
            self._connections.clear()
        logger.info("All connections closed")

    @property
    def connection_count(self) -> int:
        """Get count of active connections."""
        return len(self._connections)

    @property
    def encrypted_connection_count(self) -> int:
        """Get count of connections with E2E encryption enabled."""
        return sum(
            1 for conn in self._connections.values()
            if conn.crypto.is_encrypted
        )

    async def list_connections(self) -> list:
        """List all active connections."""
        return [
            {
                "stellar_address": conn.session.stellar_address,
                "endpoint": conn.session.endpoint_url,
                "services": conn.session.services,
                "connected_at": conn.session.connected_at.isoformat(),
                "encrypted": conn.crypto.is_encrypted
            }
            for conn in self._connections.values()
        ]
