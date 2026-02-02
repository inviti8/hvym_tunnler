"""
Tests for Challenge-Response Authentication.
"""

import time
import pytest

from app.auth.challenge import (
    ChallengeManager,
    ChallengeError,
    RateLimitError
)


class TestChallengeManager:
    """Test ChallengeManager functionality."""

    @pytest.fixture
    def manager(self):
        """Create test challenge manager."""
        return ChallengeManager(
            challenge_ttl=5,
            rate_limit_window=10,
            rate_limit_max_attempts=3,
            rate_limit_block_duration=5
        )

    def test_create_challenge(self, manager):
        """Test challenge creation."""
        challenge_id, challenge_value = manager.create_challenge("192.168.1.1")

        assert challenge_id is not None
        assert challenge_value is not None
        assert len(challenge_id) > 0
        assert len(challenge_value) > 0

    def test_verify_challenge_success(self, manager):
        """Test successful challenge verification."""
        client_ip = "192.168.1.1"
        challenge_id, challenge_value = manager.create_challenge(client_ip)

        # Verification should succeed
        result = manager.verify_challenge(
            challenge_id=challenge_id,
            challenge_response=challenge_value,
            client_ip=client_ip
        )

        assert result is True

    def test_verify_challenge_wrong_value(self, manager):
        """Test challenge verification with wrong value."""
        client_ip = "192.168.1.1"
        challenge_id, _ = manager.create_challenge(client_ip)

        with pytest.raises(ChallengeError, match="Invalid challenge response"):
            manager.verify_challenge(
                challenge_id=challenge_id,
                challenge_response="wrong_value",
                client_ip=client_ip
            )

    def test_verify_challenge_wrong_id(self, manager):
        """Test challenge verification with wrong ID."""
        client_ip = "192.168.1.1"
        _, challenge_value = manager.create_challenge(client_ip)

        with pytest.raises(ChallengeError, match="Invalid or expired"):
            manager.verify_challenge(
                challenge_id="wrong_id",
                challenge_response=challenge_value,
                client_ip=client_ip
            )

    def test_verify_challenge_ip_mismatch(self, manager):
        """Test challenge verification with IP mismatch."""
        challenge_id, challenge_value = manager.create_challenge("192.168.1.1")

        with pytest.raises(ChallengeError, match="IP mismatch"):
            manager.verify_challenge(
                challenge_id=challenge_id,
                challenge_response=challenge_value,
                client_ip="192.168.1.2"  # Different IP
            )

    def test_verify_challenge_expired(self, manager):
        """Test challenge verification after expiration."""
        client_ip = "192.168.1.1"

        # Create manager with very short TTL
        short_ttl_manager = ChallengeManager(challenge_ttl=1)
        challenge_id, challenge_value = short_ttl_manager.create_challenge(client_ip)

        # Wait for expiration
        time.sleep(1.5)

        with pytest.raises(ChallengeError, match="expired"):
            short_ttl_manager.verify_challenge(
                challenge_id=challenge_id,
                challenge_response=challenge_value,
                client_ip=client_ip
            )

    def test_challenge_cannot_be_reused(self, manager):
        """Test that challenges cannot be used twice."""
        client_ip = "192.168.1.1"
        challenge_id, challenge_value = manager.create_challenge(client_ip)

        # First verification should succeed
        manager.verify_challenge(
            challenge_id=challenge_id,
            challenge_response=challenge_value,
            client_ip=client_ip
        )

        # Create new challenge for second attempt
        challenge_id2, challenge_value2 = manager.create_challenge(client_ip)

        # Second verification with first challenge should fail
        with pytest.raises(ChallengeError, match="Invalid or expired"):
            manager.verify_challenge(
                challenge_id=challenge_id,  # Old challenge ID
                challenge_response=challenge_value,
                client_ip=client_ip
            )

    def test_rate_limiting(self, manager):
        """Test rate limiting kicks in after max attempts."""
        client_ip = "192.168.1.100"

        # Make attempts exceeding the limit (max_attempts=3, so 4 should trigger)
        for i in range(4):
            try:
                challenge_id, challenge_value = manager.create_challenge(client_ip)
                # Fail verification with wrong value
                manager.verify_challenge(
                    challenge_id=challenge_id,
                    challenge_response="wrong",
                    client_ip=client_ip
                )
            except (ChallengeError, RateLimitError):
                pass  # Expected

        # Next attempt should be rate limited
        with pytest.raises(RateLimitError):
            manager.create_challenge(client_ip)

    def test_rate_limit_different_ips(self, manager):
        """Test rate limiting is per-IP."""
        # Rate limit first IP
        for i in range(4):
            try:
                challenge_id, _ = manager.create_challenge("192.168.1.1")
                manager.verify_challenge(challenge_id, "wrong", "192.168.1.1")
            except (ChallengeError, RateLimitError):
                pass

        # Second IP should still work
        challenge_id, challenge_value = manager.create_challenge("192.168.1.2")
        assert challenge_id is not None

    def test_rate_limit_reset_on_success(self, manager):
        """Test rate limit resets after successful verification."""
        client_ip = "192.168.1.1"

        # Make some failed attempts
        for i in range(2):
            challenge_id, _ = manager.create_challenge(client_ip)
            try:
                manager.verify_challenge(challenge_id, "wrong", client_ip)
            except ChallengeError:
                pass

        # Successful verification
        challenge_id, challenge_value = manager.create_challenge(client_ip)
        manager.verify_challenge(challenge_id, challenge_value, client_ip)

        # Should be able to create more challenges
        challenge_id, _ = manager.create_challenge(client_ip)
        assert challenge_id is not None

    def test_get_stats(self, manager):
        """Test statistics retrieval."""
        # Create some challenges
        manager.create_challenge("192.168.1.1")
        manager.create_challenge("192.168.1.2")

        stats = manager.get_stats()

        assert "pending_challenges" in stats
        assert "used_challenges" in stats
        assert "rate_limited_ips" in stats
        assert stats["pending_challenges"] == 2

    def test_unique_challenges(self, manager):
        """Test that each challenge is unique."""
        challenges = set()

        for _ in range(100):
            _, challenge_value = manager.create_challenge("192.168.1.1")
            assert challenge_value not in challenges
            challenges.add(challenge_value)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
