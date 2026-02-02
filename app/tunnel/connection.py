"""
WebSocket connection management for tunnels.
"""

import json
import asyncio
import logging
from typing import Dict, Optional, Any
from dataclasses import dataclass, field

from fastapi import WebSocket

from ..auth.session import TunnelSession, SessionManager
from ..registry.store import TunnelRegistry

logger = logging.getLogger("hvym_tunnler.connection")


@dataclass
class TunnelConnection:
    """Active tunnel connection."""
    websocket: WebSocket
    session: TunnelSession
    streams: Dict[int, asyncio.Queue] = field(default_factory=dict)
    _next_stream_id: int = 1

    def get_next_stream_id(self) -> int:
        """Get next available stream ID."""
        stream_id = self._next_stream_id
        self._next_stream_id += 1
        return stream_id


class TunnelConnectionManager:
    """
    Manages WebSocket connections for tunnels.

    Handles:
    - Connection lifecycle
    - Message routing
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
            session: Authenticated session
        """
        stellar_address = session.stellar_address

        # Build endpoint URL
        endpoint_url = session.build_endpoint_url(self.domain)

        # Create connection object
        connection = TunnelConnection(
            websocket=websocket,
            session=session
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
            msg_type = data.get("type")

            if msg_type == "pong":
                # Keepalive response - acknowledged
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

            elif msg_type == "tunnel_response":
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
        Forward an HTTP request to a client tunnel.

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
            # Send request to client
            await connection.websocket.send_json({
                "type": "tunnel_request",
                "stream_id": stream_id,
                "request": request_data
            })

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

    async def broadcast(self, message: dict):
        """Broadcast a message to all connected clients."""
        for addr, conn in self._connections.items():
            try:
                await conn.websocket.send_json(message)
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

    async def list_connections(self) -> list:
        """List all active connections."""
        return [
            {
                "stellar_address": conn.session.stellar_address,
                "endpoint": conn.session.endpoint_url,
                "services": conn.session.services,
                "connected_at": conn.session.connected_at.isoformat()
            }
            for conn in self._connections.values()
        ]
