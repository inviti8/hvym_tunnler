"""
Tunnel registry for tracking active tunnels.
"""

import json
import logging
from typing import List, Optional
from datetime import datetime, timezone

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from ..auth.session import TunnelSession

logger = logging.getLogger("hvym_tunnler.registry")


class TunnelRegistry:
    """
    Registry for active tunnel connections.

    Uses Redis for persistence and cross-instance coordination.
    Falls back to in-memory storage if Redis is unavailable.
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        server_address: str = "",
        key_prefix: str = "hvym_tunnel:"
    ):
        self.redis_url = redis_url
        self.server_address = server_address
        self.key_prefix = key_prefix
        self._redis: Optional[redis.Redis] = None
        self._use_redis = REDIS_AVAILABLE
        # In-memory fallback
        self._memory_store: dict = {}

    async def _get_redis(self) -> Optional[redis.Redis]:
        """Get Redis connection."""
        if not self._use_redis:
            return None

        if self._redis is None:
            try:
                self._redis = await redis.from_url(
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True
                )
                # Test connection
                await self._redis.ping()
                logger.info("Connected to Redis")
            except Exception as e:
                logger.warning(f"Redis unavailable, using in-memory storage: {e}")
                self._use_redis = False
                return None

        return self._redis

    def _key(self, stellar_address: str) -> str:
        """Build Redis key for a tunnel."""
        return f"{self.key_prefix}{stellar_address}"

    async def register(self, session: TunnelSession):
        """Register a tunnel in the registry."""
        data = {
            "stellar_address": session.stellar_address,
            "endpoint_url": session.endpoint_url,
            "services": session.services,
            "connected_at": session.connected_at.isoformat(),
            "expires_at": session.expires_at,
            "server_address": self.server_address
        }

        r = await self._get_redis()
        if r:
            # Store with TTL if session has expiration
            ttl = None
            if session.expires_at:
                ttl = max(
                    1,
                    session.expires_at - int(datetime.now(timezone.utc).timestamp())
                )

            key = self._key(session.stellar_address)
            await r.set(key, json.dumps(data), ex=ttl)

            # Add to active set
            await r.sadd(f"{self.key_prefix}active", session.stellar_address)
        else:
            # In-memory fallback
            self._memory_store[session.stellar_address] = data

        logger.info(f"Registered tunnel: {session.stellar_address}")

    async def unregister(self, stellar_address: str):
        """Remove a tunnel from the registry."""
        r = await self._get_redis()
        if r:
            await r.delete(self._key(stellar_address))
            await r.srem(f"{self.key_prefix}active", stellar_address)
        else:
            self._memory_store.pop(stellar_address, None)

        logger.info(f"Unregistered tunnel: {stellar_address}")

    async def get(self, stellar_address: str) -> Optional[TunnelSession]:
        """Get tunnel info by Stellar address."""
        r = await self._get_redis()

        if r:
            data = await r.get(self._key(stellar_address))
            if not data:
                return None
            info = json.loads(data) if isinstance(data, str) else data
        else:
            info = self._memory_store.get(stellar_address)
            if not info:
                return None

        return TunnelSession(
            stellar_address=info["stellar_address"],
            endpoint_url=info.get("endpoint_url", ""),
            services=info.get("services", []),
            connected_at=datetime.fromisoformat(info["connected_at"]),
            expires_at=info.get("expires_at")
        )

    async def list_active(self) -> List[TunnelSession]:
        """List all active tunnels."""
        r = await self._get_redis()
        tunnels = []

        if r:
            addresses = await r.smembers(f"{self.key_prefix}active")

            for addr in addresses:
                session = await self.get(addr)
                if session:
                    tunnels.append(session)
        else:
            for addr in self._memory_store:
                session = await self.get(addr)
                if session:
                    tunnels.append(session)

        return tunnels

    async def lookup_by_endpoint(
        self,
        subdomain: str
    ) -> Optional[TunnelSession]:
        """
        Look up tunnel by endpoint subdomain.

        The subdomain IS the Stellar address for default endpoints.
        """
        # For default endpoints, subdomain = Stellar address
        return await self.get(subdomain)

    async def exists(self, stellar_address: str) -> bool:
        """Check if a tunnel exists for the given address."""
        r = await self._get_redis()
        if r:
            return await r.exists(self._key(stellar_address)) > 0
        return stellar_address in self._memory_store

    async def count(self) -> int:
        """Get count of active tunnels."""
        r = await self._get_redis()
        if r:
            return await r.scard(f"{self.key_prefix}active")
        return len(self._memory_store)

    async def close(self):
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Redis connection closed")
