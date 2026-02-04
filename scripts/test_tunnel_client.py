#!/usr/bin/env python3
"""
Test tunnel client - Demonstrates tunneling a local web server.

This script:
1. Starts a simple HTTP server on localhost
2. Connects to the HVYM Tunnler server
3. Authenticates using Stellar JWT
4. Forwards incoming tunnel requests to the local server

Usage:
    python scripts/test_tunnel_client.py --server wss://tunnel.hvym.link/connect

Requirements:
    pip install websockets aiohttp stellar-sdk hvym-stellar
"""

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
from threading import Thread
from dataclasses import dataclass
from typing import Optional

import aiohttp
import websockets
from stellar_sdk import Keypair

# Add parent directory to path for hvym_stellar import
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "hvym_stellar"))

try:
    from hvym_stellar import Stellar25519KeyPair, StellarJWTToken
except ImportError:
    print("Error: hvym_stellar not found. Install with: pip install hvym-stellar")
    print("Or ensure hvym_stellar is in your Python path")
    sys.exit(1)


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("test_tunnel_client")


# Simple HTML page for the test server
TEST_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>HVYM Tunnel Test</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
            display: flex;
            justify-content: center;
            align-items: center;
        }}
        .card {{
            background: white;
            border-radius: 16px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            text-align: center;
            max-width: 500px;
        }}
        h1 {{ color: #333; margin-bottom: 10px; }}
        p {{ color: #666; }}
        .success {{ color: #22c55e; font-weight: bold; }}
        .address {{
            background: #f5f5f5;
            padding: 10px;
            border-radius: 8px;
            font-family: monospace;
            font-size: 0.8em;
            word-break: break-all;
            margin-top: 20px;
        }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Tunnel Working!</h1>
        <p class="success">Your local server is now accessible via the tunnel.</p>
        <p>This page is being served from your local machine through the HVYM Tunnel.</p>
        <div class="address">
            Client Address: {client_address}
        </div>
    </div>
</body>
</html>
"""


@dataclass
class TunnelConfig:
    """Tunnel client configuration."""
    server_url: str = "wss://tunnel.hvym.link/connect"
    local_port: int = 8888
    services: list = None

    def __post_init__(self):
        if self.services is None:
            self.services = ["pintheon"]


class TestHTTPHandler(SimpleHTTPRequestHandler):
    """Simple HTTP handler that serves the test page."""

    client_address_str = "unknown"

    def do_GET(self):
        """Handle GET requests."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        html = TEST_HTML.format(client_address=self.client_address_str)
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        """Suppress default logging."""
        logger.debug(f"Local HTTP: {format % args}")


class TunnelClient:
    """
    Test tunnel client for HVYM Tunnler.

    Connects to the tunnel server, authenticates with Stellar JWT,
    and forwards requests to a local HTTP server.
    """

    def __init__(self, keypair: Stellar25519KeyPair, config: TunnelConfig):
        self.keypair = keypair
        self.config = config
        self.stellar_address = keypair.base_stellar_keypair().public_key
        self.websocket = None
        self.server_address = None
        self.endpoint_url = None
        self._running = False

    async def connect(self):
        """Connect to the tunnel server."""
        logger.info(f"Connecting to {self.config.server_url}")
        logger.info(f"Client Stellar Address: {self.stellar_address}")

        try:
            async with websockets.connect(
                self.config.server_url,
                ping_interval=30,
                ping_timeout=10,
                close_timeout=10
            ) as websocket:
                self.websocket = websocket

                # Wait for auth challenge
                challenge_msg = await asyncio.wait_for(
                    websocket.recv(),
                    timeout=30
                )
                challenge_data = json.loads(challenge_msg)

                if challenge_data.get("type") != "auth_challenge":
                    logger.error(f"Expected auth_challenge, got: {challenge_data}")
                    return

                logger.info("Received auth challenge")

                challenge_id = challenge_data["challenge_id"]
                challenge_value = challenge_data["challenge"]
                self.server_address = challenge_data["server_address"]

                # Create JWT with challenge
                jwt_token = StellarJWTToken(
                    keypair=self.keypair,
                    audience=self.server_address,
                    services=self.config.services,
                    expires_in=3600,
                    claims={"challenge": challenge_value}
                )
                jwt_string = jwt_token.to_jwt()

                # Send auth response
                await websocket.send(json.dumps({
                    "type": "auth_response",
                    "jwt": jwt_string,
                    "challenge_id": challenge_id
                }))

                logger.info("Sent auth response")

                # Wait for auth result
                auth_result = await asyncio.wait_for(
                    websocket.recv(),
                    timeout=30
                )
                auth_data = json.loads(auth_result)

                if auth_data.get("type") == "auth_failed":
                    logger.error(f"Authentication failed: {auth_data.get('error')}")
                    return

                if auth_data.get("type") != "auth_ok":
                    logger.error(f"Unexpected response: {auth_data}")
                    return

                self.endpoint_url = auth_data.get("endpoint")
                encryption_available = auth_data.get("encryption_available", False)

                logger.info("=" * 60)
                logger.info("TUNNEL CONNECTED!")
                logger.info("=" * 60)
                logger.info(f"Public URL: {self.endpoint_url}")
                logger.info(f"Local Port: {self.config.local_port}")
                logger.info(f"Encryption: {'Available' if encryption_available else 'Not available'}")
                logger.info("=" * 60)

                # Send bind request
                await websocket.send(json.dumps({
                    "type": "bind",
                    "service": self.config.services[0],
                    "local_port": self.config.local_port
                }))

                # Run message loop
                self._running = True
                await self._message_loop()

        except websockets.exceptions.ConnectionClosed as e:
            logger.info(f"Connection closed: {e}")
        except Exception as e:
            logger.error(f"Connection error: {e}")
            raise

    async def _message_loop(self):
        """Handle incoming messages from the tunnel server."""
        while self._running:
            try:
                message = await self.websocket.recv()
                data = json.loads(message)

                msg_type = data.get("type")

                if msg_type == "ping":
                    await self.websocket.send(json.dumps({"type": "pong"}))

                elif msg_type == "bind_ok":
                    logger.info(f"Bind confirmed: {data.get('service')} -> localhost:{data.get('local_port')}")

                elif msg_type == "tunnel_request":
                    # Forward request to local server
                    stream_id = data.get("stream_id")
                    request = data.get("request", {})

                    logger.info(f"Tunnel request [{stream_id}]: {request.get('method')} {request.get('path')}")

                    # Forward to local HTTP server
                    response = await self._forward_to_local(request)

                    # Send response back
                    await self.websocket.send(json.dumps({
                        "type": "tunnel_response",
                        "stream_id": stream_id,
                        "response": response
                    }))

                elif msg_type == "encryption_enabled":
                    logger.info("E2E encryption enabled")

                else:
                    logger.debug(f"Received message: {msg_type}")

            except websockets.exceptions.ConnectionClosed:
                logger.info("Connection closed")
                self._running = False
            except Exception as e:
                logger.error(f"Message handling error: {e}")

    async def _forward_to_local(self, request: dict) -> dict:
        """Forward a request to the local HTTP server."""
        method = request.get("method", "GET")
        path = request.get("path", "/")
        headers = request.get("headers", {})
        body = request.get("body")

        url = f"http://127.0.0.1:{self.config.local_port}{path}"

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(
                    method,
                    url,
                    headers=headers,
                    data=body,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    response_body = await resp.text()
                    return {
                        "status_code": resp.status,
                        "headers": dict(resp.headers),
                        "body": response_body
                    }
        except Exception as e:
            logger.error(f"Error forwarding to local: {e}")
            return {
                "status": 502,
                "headers": {"Content-Type": "text/plain"},
                "body": f"Error forwarding request: {e}"
            }

    def stop(self):
        """Stop the tunnel client."""
        self._running = False


def start_local_server(port: int, client_address: str) -> HTTPServer:
    """Start a local HTTP server in a background thread."""
    TestHTTPHandler.client_address_str = client_address
    server = HTTPServer(('127.0.0.1', port), TestHTTPHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    logger.info(f"Local HTTP server started on http://127.0.0.1:{port}")
    return server


async def main():
    parser = argparse.ArgumentParser(description="Test HVYM Tunnel Client")
    parser.add_argument(
        "--server",
        default="wss://tunnel.hvym.link/connect",
        help="Tunnel server WebSocket URL"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8888,
        help="Local port for the test HTTP server"
    )
    parser.add_argument(
        "--secret",
        help="Stellar secret key (if not provided, generates random keypair)"
    )
    parser.add_argument(
        "--service",
        default="pintheon",
        help="Service to bind"
    )
    args = parser.parse_args()

    # Create or load keypair
    if args.secret:
        stellar_kp = Keypair.from_secret(args.secret)
        logger.info("Using provided Stellar keypair")
    else:
        stellar_kp = Keypair.random()
        logger.info("Generated random Stellar keypair")
        logger.info(f"Secret: {stellar_kp.secret}")

    keypair = Stellar25519KeyPair(stellar_kp)
    client_address = stellar_kp.public_key

    # Start local HTTP server
    local_server = start_local_server(args.port, client_address)

    # Create tunnel config
    config = TunnelConfig(
        server_url=args.server,
        local_port=args.port,
        services=[args.service]
    )

    # Create and connect tunnel client
    client = TunnelClient(keypair, config)

    try:
        await client.connect()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
    finally:
        client.stop()
        local_server.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
