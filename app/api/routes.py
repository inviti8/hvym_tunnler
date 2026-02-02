"""
API routes for HVYM Tunnler.

Includes proxy endpoint for forwarding requests to tunneled clients.
"""

import logging
from typing import Optional

from fastapi import APIRouter, Request, Response, HTTPException
from fastapi.responses import JSONResponse

router = APIRouter()
logger = logging.getLogger("hvym_tunnler.api")


@router.api_route(
    "/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
)
async def proxy_request(request: Request, path: str):
    """
    Proxy requests to tunneled clients.

    The target client is identified by the X-Stellar-Address header
    set by nginx based on the subdomain.
    """
    # Get connection manager from app state
    connection_manager = request.app.state.connection_manager

    # Get stellar address from header (set by nginx)
    stellar_address = request.headers.get("X-Stellar-Address")

    if not stellar_address:
        raise HTTPException(
            status_code=400,
            detail="Missing X-Stellar-Address header"
        )

    # Build request data
    body = await request.body()
    request_data = {
        "method": request.method,
        "path": f"/{path}",
        "query_string": str(request.query_params),
        "headers": dict(request.headers),
        "body": body.decode("utf-8", errors="replace") if body else ""
    }

    # Forward to client
    response = await connection_manager.forward_request(
        stellar_address=stellar_address,
        request_data=request_data
    )

    if response is None:
        raise HTTPException(
            status_code=502,
            detail=f"Tunnel not available for {stellar_address}"
        )

    # Build response
    status_code = response.get("status_code", 200)
    headers = response.get("headers", {})
    body = response.get("body", "")

    # Remove hop-by-hop headers
    hop_headers = [
        "connection", "keep-alive", "proxy-authenticate",
        "proxy-authorization", "te", "trailers",
        "transfer-encoding", "upgrade"
    ]
    for h in hop_headers:
        headers.pop(h, None)
        headers.pop(h.title(), None)

    return Response(
        content=body.encode() if isinstance(body, str) else body,
        status_code=status_code,
        headers=headers
    )


@router.get("/api/tunnels")
async def list_tunnels(request: Request):
    """List all active tunnels."""
    registry = request.app.state.registry
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


@router.get("/api/tunnel/{stellar_address}")
async def get_tunnel(request: Request, stellar_address: str):
    """Get details of a specific tunnel."""
    registry = request.app.state.registry
    tunnel = await registry.get(stellar_address)

    if not tunnel:
        raise HTTPException(
            status_code=404,
            detail=f"Tunnel not found for {stellar_address}"
        )

    return {
        "stellar_address": tunnel.stellar_address,
        "endpoint": tunnel.endpoint_url,
        "connected_at": tunnel.connected_at.isoformat(),
        "services": tunnel.services,
        "expires_at": tunnel.expires_at,
        "is_expired": tunnel.is_expired
    }


@router.get("/api/stats")
async def get_stats(request: Request):
    """Get server statistics."""
    connection_manager = request.app.state.connection_manager
    registry = request.app.state.registry
    session_manager = request.app.state.session_manager

    return {
        "active_connections": connection_manager.connection_count,
        "registered_tunnels": await registry.count(),
        "active_sessions": session_manager.count
    }
