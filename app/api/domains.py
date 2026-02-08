"""
REST API for custom domain management.
"""

import asyncio
import logging
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

logger = logging.getLogger("hvym_tunnler.api.domains")

router = APIRouter(prefix="/api/domains", tags=["domains"])

security = HTTPBearer()

# Valid domain pattern: allows subdomains of any depth
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)


# ── Auth dependency ──────────────────────────────────────────────────

async def get_current_stellar_address(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> str:
    """Extract and verify Stellar address from JWT Bearer token."""
    jwt_verifier = request.app.state.jwt_verifier
    try:
        claims = jwt_verifier.verify(credentials.credentials)
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    sub = claims.get("sub")
    if not sub:
        raise HTTPException(status_code=401, detail="Token missing sub claim")
    return sub


# ── Request / Response models ────────────────────────────────────────

class DomainRegisterRequest(BaseModel):
    domain: str
    method: str = "cname"


# ── Routes ───────────────────────────────────────────────────────────

@router.post("")
async def register_domain(
    body: DomainRegisterRequest,
    request: Request,
    stellar_address: str = Depends(get_current_stellar_address),
):
    """Register a new custom domain."""
    from ..domains.models import CustomDomain

    domain = body.domain.lower().strip()
    method = body.method.lower()

    # Validate domain format
    if not _DOMAIN_RE.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")

    # Block registering tunnel domain subdomains
    tunnel_domain = request.app.state.domain_verifier.tunnel_domain
    if domain.endswith(f".{tunnel_domain}") or domain == tunnel_domain:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot register subdomains of {tunnel_domain}",
        )

    if method not in ("cname", "txt"):
        raise HTTPException(
            status_code=400, detail="Method must be 'cname' or 'txt'"
        )

    domain_registry = request.app.state.domain_registry
    verifier = request.app.state.domain_verifier

    domain_entry = CustomDomain(
        domain=domain,
        stellar_address=stellar_address,
        verification_method=method,
    )

    try:
        await domain_registry.register(domain_entry)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))

    instructions = verifier.get_verification_instructions(
        domain, method, stellar_address, domain_entry.verification_token
    )

    return {
        **domain_entry.to_api_response(),
        "instructions": instructions,
    }


@router.get("")
async def list_domains(
    request: Request,
    stellar_address: str = Depends(get_current_stellar_address),
):
    """List all custom domains for the authenticated address."""
    domain_registry = request.app.state.domain_registry
    domains = await domain_registry.list_by_address(stellar_address)
    return {
        "count": len(domains),
        "domains": [d.to_api_response() for d in domains],
    }


@router.get("/{domain}")
async def get_domain(
    domain: str,
    request: Request,
    stellar_address: str = Depends(get_current_stellar_address),
):
    """Get details of a specific custom domain."""
    domain_registry = request.app.state.domain_registry
    entry = await domain_registry.get(domain.lower())

    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")

    if entry.stellar_address != stellar_address:
        raise HTTPException(status_code=403, detail="Not your domain")

    return entry.to_api_response()


@router.post("/{domain}/verify")
async def verify_domain(
    domain: str,
    request: Request,
    stellar_address: str = Depends(get_current_stellar_address),
):
    """Trigger DNS verification for a domain."""
    from datetime import datetime, timezone

    domain_registry = request.app.state.domain_registry
    verifier = request.app.state.domain_verifier
    ssl_provisioner = request.app.state.ssl_provisioner

    entry = await domain_registry.get(domain.lower())

    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")

    if entry.stellar_address != stellar_address:
        raise HTTPException(status_code=403, detail="Not your domain")

    if entry.status == "verified":
        return {
            "domain": entry.domain,
            "status": "verified",
            "message": "Domain is already verified",
        }

    # Run verification
    if entry.verification_method == "cname":
        success, message = await verifier.verify_cname(entry.domain)
    else:
        success, message = await verifier.verify_txt(
            entry.domain, entry.stellar_address, entry.verification_token
        )

    entry.last_checked_at = datetime.now(timezone.utc)

    if success:
        entry.status = "verified"
        entry.verified_at = datetime.now(timezone.utc)
        await domain_registry.update(entry)

        # Fire-and-forget SSL provisioning
        async def _provision_ssl():
            ok, msg = await ssl_provisioner.provision(entry.domain)
            if ok:
                entry.ssl_provisioned = True
                entry.ssl_expires_at = await ssl_provisioner.cert_expiry(
                    entry.domain
                )
                await domain_registry.update(entry)
            else:
                logger.error(
                    f"SSL provisioning failed for {entry.domain}: {msg}"
                )

        asyncio.create_task(_provision_ssl())

        return {
            "domain": entry.domain,
            "status": "verified",
            "message": message,
        }

    await domain_registry.update(entry)
    return {
        "domain": entry.domain,
        "status": entry.status,
        "message": message,
    }


@router.delete("/{domain}")
async def delete_domain(
    domain: str,
    request: Request,
    stellar_address: str = Depends(get_current_stellar_address),
):
    """Delete a custom domain mapping."""
    domain_registry = request.app.state.domain_registry
    ssl_provisioner = request.app.state.ssl_provisioner

    entry = await domain_registry.get(domain.lower())

    if not entry:
        raise HTTPException(status_code=404, detail="Domain not found")

    if entry.stellar_address != stellar_address:
        raise HTTPException(status_code=403, detail="Not your domain")

    await domain_registry.delete(domain.lower())

    # Background cert cleanup
    if entry.ssl_provisioned:
        async def _cleanup_cert():
            ok, msg = await ssl_provisioner.revoke(entry.domain)
            if not ok:
                logger.warning(f"Cert cleanup failed for {entry.domain}: {msg}")

        asyncio.create_task(_cleanup_cert())

    return {"deleted": True, "domain": domain.lower()}
