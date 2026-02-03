"""
HVYM Tunnler Server - Main Application

Provides WebSocket-based tunneling with Stellar JWT authentication.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends
from fastapi.middleware.cors import CORSMiddleware

from .config import Settings, get_settings
from .auth.jwt_verifier import StellarJWTVerifier
from .auth.session import SessionManager, TunnelSession
from .auth.challenge import ChallengeManager, ChallengeError, RateLimitError
from .tunnel.connection import TunnelConnectionManager
from .registry.store import TunnelRegistry
from .api.routes import router as api_router
from .api.identity import router as identity_router


# Configure logging
def setup_logging(level: str = "INFO"):
    """Configure application logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


logger = logging.getLogger("hvym_tunnler")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle management."""
    settings = get_settings()
    setup_logging(settings.log_level)

    logger.info("HVYM Tunnler starting...")
    logger.info(f"Server address: {settings.server_address or '(not configured)'}")
    logger.info(f"Domain: {settings.domain}")

    # Initialize components
    app.state.jwt_verifier = StellarJWTVerifier(
        server_address=settings.server_address,
        server_secret=settings.server_secret,
        clock_skew_seconds=settings.jwt_clock_skew
    )

    app.state.session_manager = SessionManager()

    app.state.challenge_manager = ChallengeManager(
        challenge_ttl=settings.challenge_ttl,
        rate_limit_window=settings.rate_limit_window,
        rate_limit_max_attempts=settings.rate_limit_max_attempts,
        rate_limit_block_duration=settings.rate_limit_block_duration
    )

    app.state.registry = TunnelRegistry(
        redis_url=settings.redis_url,
        server_address=settings.server_address
    )

    app.state.connection_manager = TunnelConnectionManager(
        registry=app.state.registry,
        session_manager=app.state.session_manager,
        domain=settings.domain
    )

    logger.info("HVYM Tunnler ready")

    yield

    # Cleanup
    logger.info("HVYM Tunnler shutting down...")
    await app.state.connection_manager.shutdown()
    await app.state.registry.close()
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

# Include API routes
app.include_router(api_router)
app.include_router(identity_router)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    settings = get_settings()
    return {
        "status": "healthy",
        "service": "hvym_tunnler",
        "server_address": settings.server_address or "(not configured)"
    }


# Server info endpoint
@app.get("/info")
async def server_info():
    """Get server information for client configuration."""
    settings = get_settings()
    return {
        "server_address": settings.server_address,
        "websocket_url": f"wss://{settings.domain}/connect",
        "services": settings.allowed_services,
        "version": "1.0.0"
    }


# WebSocket tunnel endpoint
@app.websocket("/connect")
async def websocket_tunnel(websocket: WebSocket):
    """
    WebSocket endpoint for tunnel connections.

    Uses challenge-response authentication:
    1. Server sends challenge
    2. Client responds with JWT containing challenge
    3. Server verifies JWT and challenge binding
    """
    import json
    import asyncio

    jwt_verifier: StellarJWTVerifier = app.state.jwt_verifier
    challenge_manager: ChallengeManager = app.state.challenge_manager
    connection_manager: TunnelConnectionManager = app.state.connection_manager
    settings = get_settings()

    # Get client IP for rate limiting and challenge binding
    client_ip = websocket.client.host if websocket.client else "unknown"

    # Check rate limit before accepting
    try:
        challenge_id, challenge_value = challenge_manager.create_challenge(client_ip)
    except RateLimitError as e:
        logger.warning(f"Rate limited connection from {client_ip}")
        await websocket.close(code=4029, reason="Too many requests")
        return

    # Accept connection to begin challenge-response
    await websocket.accept()

    # Send challenge
    await websocket.send_json({
        "type": "auth_challenge",
        "challenge_id": challenge_id,
        "challenge": challenge_value,
        "server_address": settings.server_address
    })

    logger.debug(f"Sent challenge to {client_ip}")

    # Wait for auth response
    try:
        auth_message = await asyncio.wait_for(
            websocket.receive_json(),
            timeout=30.0
        )
    except asyncio.TimeoutError:
        logger.warning(f"Auth timeout from {client_ip}")
        await websocket.close(code=4008, reason="Authentication timeout")
        return
    except Exception as e:
        logger.warning(f"Failed to receive auth response: {e}")
        await websocket.close(code=4000, reason="Invalid auth response")
        return

    # Validate auth response format
    if auth_message.get("type") != "auth_response":
        logger.warning(f"Invalid auth message type: {auth_message.get('type')}")
        await websocket.close(code=4001, reason="Expected auth_response")
        return

    jwt_token = auth_message.get("jwt")
    response_challenge_id = auth_message.get("challenge_id")

    if not jwt_token or not response_challenge_id:
        logger.warning("Missing jwt or challenge_id in auth_response")
        await websocket.close(code=4001, reason="Missing auth fields")
        return

    # Verify JWT
    try:
        claims = jwt_verifier.verify(jwt_token)
    except Exception as e:
        logger.warning(f"JWT verification failed: {e}")
        await websocket.send_json({
            "type": "auth_failed",
            "error": str(e)
        })
        await websocket.close(code=4002, reason=f"Authentication failed")
        return

    # Verify challenge binding in JWT
    jwt_challenge = claims.get("challenge")
    if not jwt_challenge or jwt_challenge != challenge_value:
        logger.warning(f"Challenge mismatch in JWT from {claims.get('sub', 'unknown')}")
        await websocket.send_json({
            "type": "auth_failed",
            "error": "Challenge mismatch"
        })
        await websocket.close(code=4002, reason="Challenge verification failed")
        return

    # Verify challenge with manager (handles IP binding, expiration, replay)
    try:
        challenge_manager.verify_challenge(
            challenge_id=response_challenge_id,
            challenge_response=challenge_value,
            client_ip=client_ip
        )
    except ChallengeError as e:
        logger.warning(f"Challenge verification failed: {e}")
        await websocket.send_json({
            "type": "auth_failed",
            "error": str(e)
        })
        await websocket.close(code=4002, reason="Challenge verification failed")
        return
    except RateLimitError as e:
        logger.warning(f"Rate limited during verification: {client_ip}")
        await websocket.send_json({
            "type": "auth_failed",
            "error": "Rate limited"
        })
        await websocket.close(code=4029, reason="Too many requests")
        return

    # Check services are allowed
    requested_services = claims.get('services', ['pintheon'])
    for service in requested_services:
        if service not in settings.allowed_services:
            logger.warning(f"Service not allowed: {service}")
            await websocket.send_json({
                "type": "auth_failed",
                "error": f"Service not allowed: {service}"
            })
            await websocket.close(code=4003, reason=f"Service not allowed")
            return

    logger.info(f"Client authenticated: {claims['sub']} from {client_ip}")

    # Create session
    session = TunnelSession(
        stellar_address=claims['sub'],
        services=requested_services,
        expires_at=claims.get('exp')
    )

    # Derive shared key if possible
    try:
        session.shared_key = jwt_verifier.derive_shared_key(claims['sub'])
    except Exception as e:
        logger.debug(f"Could not derive shared key: {e}")

    # Send auth success with E2E encryption capability
    endpoint_url = f"https://{claims['sub']}.{settings.domain}"
    await websocket.send_json({
        "type": "auth_ok",
        "endpoint": endpoint_url,
        "server_address": settings.server_address,
        "services": requested_services,
        "encryption_available": session.shared_key is not None,
        "encryption_mode": "XSalsa20-Poly1305" if session.shared_key else None
    })

    # Handle connection
    try:
        await connection_manager.handle_connection(websocket, session)
    except WebSocketDisconnect:
        logger.info(f"Client disconnected: {session.stellar_address}")
    except Exception as e:
        logger.error(f"Connection error for {session.stellar_address}: {e}")
    finally:
        await connection_manager.remove_connection(session.stellar_address)


# Development server entry point
if __name__ == "__main__":
    import uvicorn
    settings = get_settings()
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower()
    )
