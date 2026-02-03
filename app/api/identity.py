"""
Server Identity API - Public endpoints for server discovery.

These endpoints allow clients to discover the server's Stellar address
and retrieve a QR code for easy configuration.

All endpoints are public and require no authentication.
"""

import json
import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, JSONResponse

logger = logging.getLogger("hvym_tunnler.identity")

router = APIRouter(prefix="/server-identity", tags=["identity"])

# Paths relative to app root
BASE_PATH = Path(__file__).parent.parent.parent
STATIC_PATH = BASE_PATH / "static"
DATA_PATH = BASE_PATH / "data"


def _get_identity_metadata() -> Optional[dict]:
    """Load identity metadata from file."""
    meta_path = DATA_PATH / "server_identity.json"

    if not meta_path.exists():
        return None

    try:
        return json.loads(meta_path.read_text())
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load identity metadata: {e}")
        return None


@router.get("")
async def get_server_identity():
    """
    Get server identity metadata.

    Returns the server's Stellar public address and connection info.
    This endpoint is public and requires no authentication.

    Use this to configure tunnel clients.

    Returns:
        JSON object containing:
        - server_address: Stellar public key (G...)
        - domain: Server domain
        - websocket_url: WebSocket connection URL
        - api_url: REST API base URL
        - qr_code_path: Path to QR code endpoint
    """
    metadata = _get_identity_metadata()

    if not metadata:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Server identity not configured",
                "message": "Run scripts/setup_identity.py to initialize the server",
                "code": "IDENTITY_NOT_CONFIGURED"
            }
        )

    return JSONResponse(content=metadata)


@router.get("/qr")
async def get_identity_qr_code():
    """
    Get QR code image of server's Stellar public address.

    Scan this QR code with a Stellar wallet or tunnel client app
    to get the server's address for connection configuration.

    The QR code contains only the public address (safe to share).

    Returns:
        PNG image (image/png)
    """
    qr_path = STATIC_PATH / "server_identity_qr.png"

    if not qr_path.exists():
        raise HTTPException(
            status_code=503,
            detail={
                "error": "QR code not generated",
                "message": "Run scripts/setup_identity.py to initialize the server",
                "code": "QR_NOT_GENERATED"
            }
        )

    return FileResponse(
        qr_path,
        media_type="image/png",
        filename="hvym_tunnler_server.png",
        headers={
            "Cache-Control": "public, max-age=86400",  # Cache for 24h
            "X-Content-Type-Options": "nosniff"
        }
    )


@router.get("/address")
async def get_server_address():
    """
    Get just the server's Stellar address.

    Convenience endpoint that returns only the address string.
    Useful for programmatic access without parsing full metadata.

    Returns:
        JSON object with single 'address' field
    """
    metadata = _get_identity_metadata()

    if not metadata or "server_address" not in metadata:
        raise HTTPException(
            status_code=503,
            detail={
                "error": "Server identity not configured",
                "code": "IDENTITY_NOT_CONFIGURED"
            }
        )

    return JSONResponse(content={
        "address": metadata["server_address"]
    })
