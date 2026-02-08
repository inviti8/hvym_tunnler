"""
Domain registry for custom domain -> Stellar address mappings.
"""

import json
import logging
import time
from typing import Dict, List, Optional

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

from .models import CustomDomain

logger = logging.getLogger("hvym_tunnler.domains.registry")


class _CacheEntry:
    """TTL cache entry for domain lookups."""

    __slots__ = ("value", "expires_at")

    def __init__(self, value: Optional[CustomDomain], ttl: float):
        self.value = value
        self.expires_at = time.monotonic() + ttl


class DomainRegistry:
    """
    Registry for custom domain -> Stellar address mappings.

    Uses Redis for persistence with in-memory fallback,
    mirroring TunnelRegistry patterns.
    """

    POSITIVE_TTL = 60.0   # seconds to cache a found domain
    NEGATIVE_TTL = 10.0   # seconds to cache a miss

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        key_prefix: str = "hvym_tunnel:",
        max_domains_per_address: int = 5,
    ):
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self.max_domains_per_address = max_domains_per_address
        self._redis: Optional[redis.Redis] = None
        self._use_redis = REDIS_AVAILABLE
        # In-memory fallback
        self._memory_store: Dict[str, dict] = {}
        self._reverse_index: Dict[str, set] = {}
        # In-process lookup cache
        self._cache: Dict[str, _CacheEntry] = {}

    async def _get_redis(self) -> Optional[redis.Redis]:
        """Get Redis connection."""
        if not self._use_redis:
            return None

        if self._redis is None:
            try:
                self._redis = await redis.from_url(
                    self.redis_url,
                    encoding="utf-8",
                    decode_responses=True,
                )
                await self._redis.ping()
                logger.info("Domain registry connected to Redis")
            except Exception as e:
                logger.warning(
                    f"Redis unavailable for domain registry, using in-memory: {e}"
                )
                self._use_redis = False
                return None

        return self._redis

    def _domain_key(self, domain: str) -> str:
        return f"{self.key_prefix}domain:{domain}"

    def _address_key(self, stellar_address: str) -> str:
        return f"{self.key_prefix}domains:{stellar_address}"

    def _invalidate_cache(self, domain: str) -> None:
        self._cache.pop(domain, None)

    async def register(self, domain_entry: CustomDomain) -> CustomDomain:
        """
        Register a custom domain.

        Raises ValueError if domain already exists or address limit exceeded.
        """
        domain = domain_entry.domain.lower()
        addr = domain_entry.stellar_address

        # Check duplicate
        existing = await self.get(domain)
        if existing:
            raise ValueError(f"Domain {domain} is already registered")

        # Check per-address limit
        existing_domains = await self.list_by_address(addr)
        if len(existing_domains) >= self.max_domains_per_address:
            raise ValueError(
                f"Maximum of {self.max_domains_per_address} domains per address reached"
            )

        data = domain_entry.to_dict()
        r = await self._get_redis()
        if r:
            await r.set(self._domain_key(domain), json.dumps(data))
            await r.sadd(self._address_key(addr), domain)
        else:
            self._memory_store[domain] = data
            self._reverse_index.setdefault(addr, set()).add(domain)

        self._invalidate_cache(domain)
        logger.info(f"Registered domain: {domain} -> {addr}")
        return domain_entry

    async def get(self, domain: str) -> Optional[CustomDomain]:
        """Get domain entry by domain name."""
        domain = domain.lower()
        r = await self._get_redis()

        if r:
            data = await r.get(self._domain_key(domain))
            if not data:
                return None
            info = json.loads(data) if isinstance(data, str) else data
        else:
            info = self._memory_store.get(domain)
            if not info:
                return None

        return CustomDomain.from_dict(info)

    async def update(self, domain_entry: CustomDomain) -> CustomDomain:
        """Update an existing domain entry."""
        domain = domain_entry.domain.lower()
        data = domain_entry.to_dict()

        r = await self._get_redis()
        if r:
            await r.set(self._domain_key(domain), json.dumps(data))
        else:
            self._memory_store[domain] = data

        self._invalidate_cache(domain)
        logger.info(f"Updated domain: {domain}")
        return domain_entry

    async def delete(self, domain: str) -> bool:
        """Delete a domain entry."""
        domain = domain.lower()
        entry = await self.get(domain)
        if not entry:
            return False

        r = await self._get_redis()
        if r:
            await r.delete(self._domain_key(domain))
            await r.srem(self._address_key(entry.stellar_address), domain)
        else:
            self._memory_store.pop(domain, None)
            addr_set = self._reverse_index.get(entry.stellar_address)
            if addr_set:
                addr_set.discard(domain)

        self._invalidate_cache(domain)
        logger.info(f"Deleted domain: {domain}")
        return True

    async def list_by_address(self, stellar_address: str) -> List[CustomDomain]:
        """List all domains for a Stellar address."""
        r = await self._get_redis()
        domains: List[CustomDomain] = []

        if r:
            members = await r.smembers(self._address_key(stellar_address))
            for d in members:
                entry = await self.get(d)
                if entry:
                    domains.append(entry)
        else:
            for d in self._reverse_index.get(stellar_address, set()):
                entry = await self.get(d)
                if entry:
                    domains.append(entry)

        return domains

    async def lookup(self, domain: str) -> Optional[CustomDomain]:
        """
        Hot-path lookup: returns verified domain entry or None.

        Uses in-process TTL cache to avoid hitting Redis on every proxied request.
        Only returns domains with status == "verified".
        """
        domain = domain.lower()

        # Check cache
        cached = self._cache.get(domain)
        if cached and time.monotonic() < cached.expires_at:
            return cached.value

        entry = await self.get(domain)
        if entry and entry.status == "verified":
            self._cache[domain] = _CacheEntry(entry, self.POSITIVE_TTL)
            return entry

        # Cache the miss with shorter TTL
        self._cache[domain] = _CacheEntry(None, self.NEGATIVE_TTL)
        return None

    async def cleanup_expired_pending(self, expiry_hours: int = 72) -> int:
        """Remove pending domains older than expiry_hours."""
        from datetime import datetime, timezone, timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(hours=expiry_hours)
        removed = 0

        r = await self._get_redis()
        if r:
            # Scan for all domain keys
            cursor = 0
            pattern = f"{self.key_prefix}domain:*"
            while True:
                cursor, keys = await r.scan(cursor, match=pattern, count=100)
                for key in keys:
                    data = await r.get(key)
                    if not data:
                        continue
                    info = json.loads(data)
                    if (
                        info.get("status") == "pending_verification"
                        and datetime.fromisoformat(info["created_at"]) < cutoff
                    ):
                        domain = info["domain"]
                        await self.delete(domain)
                        removed += 1
                if cursor == 0:
                    break
        else:
            expired = []
            for domain, data in self._memory_store.items():
                if (
                    data.get("status") == "pending_verification"
                    and datetime.fromisoformat(data["created_at"]) < cutoff
                ):
                    expired.append(domain)
            for domain in expired:
                await self.delete(domain)
                removed += 1

        if removed:
            logger.info(f"Cleaned up {removed} expired pending domains")
        return removed

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None
            logger.info("Domain registry Redis connection closed")
