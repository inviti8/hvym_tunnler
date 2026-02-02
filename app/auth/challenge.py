"""
Challenge-Response Authentication for HVYM Tunnler.

Implements replay-resistant authentication using server-generated challenges.
"""

import os
import time
import secrets
import hashlib
import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("hvym_tunnler.challenge")


@dataclass
class PendingChallenge:
    """A pending authentication challenge."""
    challenge: str
    created_at: float
    client_ip: str


@dataclass
class RateLimitEntry:
    """Rate limiting state for an IP."""
    attempts: int = 0
    first_attempt: float = 0.0
    blocked_until: float = 0.0


class ChallengeManager:
    """
    Manages challenge-response authentication.

    Security features:
    - Unique challenge per connection attempt
    - Challenge expiration (prevents replay)
    - Rate limiting per IP
    - Challenge binding to client IP
    """

    def __init__(
        self,
        challenge_ttl: int = 30,           # Seconds before challenge expires
        rate_limit_window: int = 60,        # Rate limit window in seconds
        rate_limit_max_attempts: int = 10,  # Max attempts per window
        rate_limit_block_duration: int = 300  # Block duration after exceeding limit
    ):
        """
        Initialize challenge manager.

        Args:
            challenge_ttl: How long a challenge remains valid
            rate_limit_window: Time window for rate limiting
            rate_limit_max_attempts: Max auth attempts in window
            rate_limit_block_duration: How long to block after rate limit exceeded
        """
        self.challenge_ttl = challenge_ttl
        self.rate_limit_window = rate_limit_window
        self.rate_limit_max_attempts = rate_limit_max_attempts
        self.rate_limit_block_duration = rate_limit_block_duration

        # Active challenges: challenge_id -> PendingChallenge
        self._challenges: Dict[str, PendingChallenge] = {}

        # Rate limiting: client_ip -> RateLimitEntry
        self._rate_limits: Dict[str, RateLimitEntry] = defaultdict(RateLimitEntry)

        # Used challenges (prevent reuse): challenge_hash -> expiry_time
        self._used_challenges: Dict[str, float] = {}

    def create_challenge(self, client_ip: str) -> Tuple[str, str]:
        """
        Create a new authentication challenge.

        Args:
            client_ip: Client's IP address for binding

        Returns:
            Tuple of (challenge_id, challenge_value)

        Raises:
            RateLimitError: If client is rate limited
        """
        # Check rate limit
        if self._is_rate_limited(client_ip):
            raise RateLimitError(f"Rate limited: {client_ip}")

        # Generate challenge
        challenge_id = secrets.token_urlsafe(16)
        challenge_value = secrets.token_urlsafe(32)

        # Store pending challenge
        self._challenges[challenge_id] = PendingChallenge(
            challenge=challenge_value,
            created_at=time.time(),
            client_ip=client_ip
        )

        # Cleanup old challenges periodically
        self._cleanup_expired()

        logger.debug(f"Created challenge {challenge_id[:8]}... for {client_ip}")
        return challenge_id, challenge_value

    def verify_challenge(
        self,
        challenge_id: str,
        challenge_response: str,
        client_ip: str
    ) -> bool:
        """
        Verify a challenge response.

        Args:
            challenge_id: The challenge ID from create_challenge
            challenge_response: The challenge value signed/included by client
            client_ip: Client's current IP (must match creation IP)

        Returns:
            True if valid

        Raises:
            ChallengeError: If verification fails
            RateLimitError: If client is rate limited
        """
        # Record attempt for rate limiting
        self._record_attempt(client_ip)

        # Check rate limit
        if self._is_rate_limited(client_ip):
            raise RateLimitError(f"Rate limited: {client_ip}")

        # Find pending challenge
        pending = self._challenges.get(challenge_id)
        if not pending:
            logger.warning(f"Unknown challenge ID: {challenge_id[:8]}...")
            raise ChallengeError("Invalid or expired challenge")

        # Check expiration
        if time.time() > pending.created_at + self.challenge_ttl:
            del self._challenges[challenge_id]
            logger.warning(f"Expired challenge: {challenge_id[:8]}...")
            raise ChallengeError("Challenge expired")

        # Check IP binding
        if pending.client_ip != client_ip:
            logger.warning(
                f"IP mismatch for challenge {challenge_id[:8]}...: "
                f"expected {pending.client_ip}, got {client_ip}"
            )
            raise ChallengeError("Challenge IP mismatch")

        # Verify challenge value
        if not secrets.compare_digest(pending.challenge, challenge_response):
            logger.warning(f"Challenge value mismatch: {challenge_id[:8]}...")
            raise ChallengeError("Invalid challenge response")

        # Mark challenge as used (prevent replay)
        challenge_hash = hashlib.sha256(
            f"{challenge_id}:{challenge_response}".encode()
        ).hexdigest()
        self._used_challenges[challenge_hash] = time.time() + self.challenge_ttl

        # Remove pending challenge
        del self._challenges[challenge_id]

        # Reset rate limit on success
        if client_ip in self._rate_limits:
            del self._rate_limits[client_ip]

        logger.debug(f"Challenge verified: {challenge_id[:8]}...")
        return True

    def _is_rate_limited(self, client_ip: str) -> bool:
        """Check if client IP is rate limited."""
        entry = self._rate_limits.get(client_ip)
        if not entry:
            return False

        current_time = time.time()

        # Check if blocked
        if entry.blocked_until > current_time:
            return True

        # Check if window expired
        if current_time > entry.first_attempt + self.rate_limit_window:
            # Reset window
            entry.attempts = 0
            entry.first_attempt = 0
            entry.blocked_until = 0
            return False

        return False

    def _record_attempt(self, client_ip: str):
        """Record an authentication attempt."""
        entry = self._rate_limits[client_ip]
        current_time = time.time()

        # Start new window if needed
        if entry.first_attempt == 0 or current_time > entry.first_attempt + self.rate_limit_window:
            entry.first_attempt = current_time
            entry.attempts = 1
        else:
            entry.attempts += 1

        # Check if should block
        if entry.attempts > self.rate_limit_max_attempts:
            entry.blocked_until = current_time + self.rate_limit_block_duration
            logger.warning(f"Rate limit exceeded for {client_ip}, blocking for {self.rate_limit_block_duration}s")

    def _cleanup_expired(self):
        """Remove expired challenges and rate limit entries."""
        current_time = time.time()

        # Cleanup expired challenges
        expired_challenges = [
            cid for cid, c in self._challenges.items()
            if current_time > c.created_at + self.challenge_ttl
        ]
        for cid in expired_challenges:
            del self._challenges[cid]

        # Cleanup used challenges
        expired_used = [
            h for h, exp in self._used_challenges.items()
            if current_time > exp
        ]
        for h in expired_used:
            del self._used_challenges[h]

        # Cleanup old rate limit entries
        stale_ips = [
            ip for ip, entry in self._rate_limits.items()
            if current_time > entry.first_attempt + self.rate_limit_window * 2
            and entry.blocked_until < current_time
        ]
        for ip in stale_ips:
            del self._rate_limits[ip]

    def get_stats(self) -> Dict:
        """Get challenge manager statistics."""
        return {
            "pending_challenges": len(self._challenges),
            "used_challenges": len(self._used_challenges),
            "rate_limited_ips": sum(
                1 for e in self._rate_limits.values()
                if e.blocked_until > time.time()
            )
        }


class ChallengeError(Exception):
    """Challenge verification failed."""
    pass


class RateLimitError(Exception):
    """Rate limit exceeded."""
    pass
