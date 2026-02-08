"""
Custom domain data model for HVYM Tunnler.
"""

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class CustomDomain:
    """Represents a custom domain mapping to a Stellar address."""

    domain: str
    stellar_address: str
    status: str = "pending_verification"
    verification_method: str = "cname"
    verification_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: Optional[datetime] = None
    last_checked_at: Optional[datetime] = None
    ssl_provisioned: bool = False
    ssl_expires_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "domain": self.domain,
            "stellar_address": self.stellar_address,
            "status": self.status,
            "verification_method": self.verification_method,
            "verification_token": self.verification_token,
            "created_at": self.created_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "last_checked_at": self.last_checked_at.isoformat() if self.last_checked_at else None,
            "ssl_provisioned": self.ssl_provisioned,
            "ssl_expires_at": self.ssl_expires_at.isoformat() if self.ssl_expires_at else None,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CustomDomain":
        """Create from dictionary."""
        return cls(
            domain=data["domain"],
            stellar_address=data["stellar_address"],
            status=data.get("status", "pending_verification"),
            verification_method=data.get("verification_method", "cname"),
            verification_token=data.get("verification_token", ""),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(timezone.utc),
            verified_at=datetime.fromisoformat(data["verified_at"]) if data.get("verified_at") else None,
            last_checked_at=datetime.fromisoformat(data["last_checked_at"]) if data.get("last_checked_at") else None,
            ssl_provisioned=data.get("ssl_provisioned", False),
            ssl_expires_at=datetime.fromisoformat(data["ssl_expires_at"]) if data.get("ssl_expires_at") else None,
        )

    def to_api_response(self) -> dict:
        """Convert to API response, hiding token when verified."""
        resp = {
            "domain": self.domain,
            "stellar_address": self.stellar_address,
            "status": self.status,
            "verification_method": self.verification_method,
            "created_at": self.created_at.isoformat(),
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "ssl_provisioned": self.ssl_provisioned,
            "ssl_expires_at": self.ssl_expires_at.isoformat() if self.ssl_expires_at else None,
        }
        if self.status == "pending_verification":
            resp["verification_token"] = self.verification_token
        return resp
