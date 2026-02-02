"""
Session management for tunnel connections.
"""

import time
import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger("hvym_tunnler.session")


@dataclass
class TunnelSession:
    """Represents an authenticated tunnel session."""
    stellar_address: str
    services: List[str]
    expires_at: Optional[int] = None
    connected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    endpoint_url: str = ""
    shared_key: Optional[bytes] = None

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        if self.expires_at is None:
            return False
        return int(time.time()) > self.expires_at

    @property
    def time_remaining(self) -> Optional[int]:
        """Get seconds until expiration, or None if no expiration."""
        if self.expires_at is None:
            return None
        remaining = self.expires_at - int(time.time())
        return max(0, remaining)

    def build_endpoint_url(self, domain: str) -> str:
        """Build public endpoint URL for this session."""
        self.endpoint_url = f"https://{self.stellar_address}.{domain}"
        return self.endpoint_url

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "stellar_address": self.stellar_address,
            "services": self.services,
            "expires_at": self.expires_at,
            "connected_at": self.connected_at.isoformat(),
            "endpoint_url": self.endpoint_url
        }


class SessionManager:
    """Manages active tunnel sessions."""

    def __init__(self):
        self._sessions: Dict[str, TunnelSession] = {}
        self._lock = asyncio.Lock()

    async def create_session(self, session: TunnelSession) -> TunnelSession:
        """Register a new session."""
        async with self._lock:
            # Close existing session if any
            if session.stellar_address in self._sessions:
                logger.info(
                    f"Replacing existing session for {session.stellar_address}"
                )
            self._sessions[session.stellar_address] = session
        logger.info(f"Session created for {session.stellar_address}")
        return session

    async def get_session(self, stellar_address: str) -> Optional[TunnelSession]:
        """Get session by Stellar address."""
        session = self._sessions.get(stellar_address)
        if session and session.is_expired:
            await self.remove_session(stellar_address)
            return None
        return session

    async def remove_session(self, stellar_address: str) -> bool:
        """Remove a session."""
        async with self._lock:
            if stellar_address in self._sessions:
                del self._sessions[stellar_address]
                logger.info(f"Session removed for {stellar_address}")
                return True
        return False

    async def list_sessions(self) -> List[TunnelSession]:
        """List all active sessions."""
        # Filter out expired sessions
        active = []
        expired = []
        for addr, session in self._sessions.items():
            if session.is_expired:
                expired.append(addr)
            else:
                active.append(session)

        # Clean up expired
        for addr in expired:
            await self.remove_session(addr)

        return active

    async def cleanup_expired(self) -> int:
        """Remove all expired sessions."""
        async with self._lock:
            expired = [
                addr for addr, session in self._sessions.items()
                if session.is_expired
            ]
            for addr in expired:
                del self._sessions[addr]
            if expired:
                logger.info(f"Cleaned up {len(expired)} expired sessions")
        return len(expired)

    @property
    def count(self) -> int:
        """Get count of active sessions."""
        return len(self._sessions)
