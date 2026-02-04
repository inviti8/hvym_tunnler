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
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

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
    Get QR code page with server's Stellar public address.

    Displays an HTML page with the QR code that can be scanned
    with a Stellar wallet or tunnel client app.

    The QR code contains only the public address (safe to share).

    Returns:
        HTML page with embedded QR code
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

    metadata = _get_identity_metadata()
    server_address = metadata.get("server_address", "Unknown") if metadata else "Unknown"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HVYM Tunnler - Server Identity</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .container {{
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 400px;
            width: 100%;
        }}
        h1 {{
            color: #1a1a2e;
            font-size: 1.5rem;
            margin-bottom: 8px;
        }}
        .subtitle {{
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 24px;
        }}
        .qr-container {{
            background: white;
            padding: 20px;
            border-radius: 12px;
            display: inline-block;
            margin-bottom: 24px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }}
        .qr-container img {{
            display: block;
            max-width: 256px;
            height: auto;
        }}
        .address {{
            background: #f5f5f5;
            border-radius: 8px;
            padding: 12px;
            font-family: 'Monaco', 'Menlo', monospace;
            font-size: 0.7rem;
            word-break: break-all;
            color: #333;
            margin-bottom: 16px;
        }}
        .download-link {{
            color: #4a90d9;
            text-decoration: none;
            font-size: 0.85rem;
        }}
        .download-link:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>HVYM Tunnler</h1>
        <p class="subtitle">Scan to connect</p>
        <div class="qr-container">
            <img src="/server-identity/qr.png" alt="Server Identity QR Code">
        </div>
        <div class="address">{server_address}</div>
        <a href="/server-identity/qr.png" download="hvym_tunnler_server.png" class="download-link">
            Download QR Code
        </a>
    </div>
</body>
</html>"""

    return HTMLResponse(content=html_content)


@router.get("/qr.png")
async def get_identity_qr_image():
    """
    Get raw QR code PNG image.

    Direct image endpoint for embedding or downloading.

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
        headers={
            "Cache-Control": "public, max-age=86400",
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
