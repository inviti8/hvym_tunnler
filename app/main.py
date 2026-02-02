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
from .tunnel.connection import TunnelConnectionManager
from .registry.store import TunnelRegistry
from .api.routes import router as api_router


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

    Authentication via Authorization header with Stellar JWT.
    """
    jwt_verifier: StellarJWTVerifier = app.state.jwt_verifier
    connection_manager: TunnelConnectionManager = app.state.connection_manager
    settings = get_settings()

    # Extract JWT from headers or query params
    auth_header = websocket.headers.get("authorization", "")
    jwt_token = None

    if auth_header.startswith("Bearer "):
        jwt_token = auth_header[7:]  # Remove "Bearer " prefix
    else:
        # Check query params (fallback for browsers)
        jwt_token = websocket.query_params.get("token")

    if not jwt_token:
        logger.warning("Connection attempt without authorization")
        await websocket.close(code=4001, reason="Missing authorization")
        return

    # Verify JWT
    try:
        claims = jwt_verifier.verify(jwt_token)
    except Exception as e:
        logger.warning(f"JWT verification failed: {e}")
        await websocket.close(code=4002, reason=f"Authentication failed: {e}")
        return

    # Check services are allowed
    requested_services = claims.get('services', ['pintheon'])
    for service in requested_services:
        if service not in settings.allowed_services:
            logger.warning(f"Service not allowed: {service}")
            await websocket.close(
                code=4003,
                reason=f"Service not allowed: {service}"
            )
            return

    # Accept connection
    await websocket.accept()
    logger.info(f"Client connected: {claims['sub']}")

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
