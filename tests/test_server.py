"""
Tests for HVYM Tunnler Server.
"""

import os
import sys
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Set test environment variables before importing app modules
os.environ["TUNNLER_SERVER_ADDRESS"] = "GTEST1234567890123456789012345678901234567890123456"
os.environ["TUNNLER_SERVER_SECRET"] = "STEST1234567890123456789012345678901234567890123456"
os.environ["TUNNLER_DEBUG"] = "true"


class TestConfig:
    """Test configuration module."""

    def test_settings_loads(self):
        """Test settings load from environment."""
        from app.config import Settings

        settings = Settings()
        assert settings.host == "0.0.0.0"
        assert settings.port == 8000
        assert settings.domain == "tunnel.heavymeta.art"

    def test_settings_env_prefix(self):
        """Test settings use TUNNLER_ prefix."""
        from app.config import Settings

        os.environ["TUNNLER_LOG_LEVEL"] = "DEBUG"
        settings = Settings()
        assert settings.log_level == "DEBUG"


class TestSession:
    """Test session management."""

    def test_tunnel_session_creation(self):
        """Test TunnelSession creation."""
        from app.auth.session import TunnelSession

        session = TunnelSession(
            stellar_address="GABC123",
            services=["pintheon"]
        )
        assert session.stellar_address == "GABC123"
        assert session.services == ["pintheon"]
        assert not session.is_expired

    def test_session_expiration(self):
        """Test session expiration check."""
        import time
        from app.auth.session import TunnelSession

        # Non-expiring session
        session = TunnelSession(
            stellar_address="GABC123",
            services=["pintheon"],
            expires_at=None
        )
        assert not session.is_expired

        # Expired session
        expired_session = TunnelSession(
            stellar_address="GABC123",
            services=["pintheon"],
            expires_at=int(time.time()) - 100
        )
        assert expired_session.is_expired

        # Future expiration
        future_session = TunnelSession(
            stellar_address="GABC123",
            services=["pintheon"],
            expires_at=int(time.time()) + 3600
        )
        assert not future_session.is_expired

    def test_build_endpoint_url(self):
        """Test endpoint URL building."""
        from app.auth.session import TunnelSession

        session = TunnelSession(
            stellar_address="GABCDEF",
            services=["pintheon"]
        )
        url = session.build_endpoint_url("tunnel.heavymeta.art")
        assert url == "https://GABCDEF.tunnel.heavymeta.art"
        assert session.endpoint_url == url


class TestSessionManager:
    """Test SessionManager."""

    @pytest.mark.asyncio
    async def test_create_and_get_session(self):
        """Test creating and retrieving sessions."""
        from app.auth.session import SessionManager, TunnelSession

        manager = SessionManager()
        session = TunnelSession(
            stellar_address="GABC123",
            services=["pintheon"]
        )

        await manager.create_session(session)
        retrieved = await manager.get_session("GABC123")

        assert retrieved is not None
        assert retrieved.stellar_address == "GABC123"

    @pytest.mark.asyncio
    async def test_remove_session(self):
        """Test removing sessions."""
        from app.auth.session import SessionManager, TunnelSession

        manager = SessionManager()
        session = TunnelSession(
            stellar_address="GABC123",
            services=["pintheon"]
        )

        await manager.create_session(session)
        await manager.remove_session("GABC123")
        retrieved = await manager.get_session("GABC123")

        assert retrieved is None

    @pytest.mark.asyncio
    async def test_list_sessions(self):
        """Test listing sessions."""
        from app.auth.session import SessionManager, TunnelSession

        manager = SessionManager()

        session1 = TunnelSession(stellar_address="G1", services=["pintheon"])
        session2 = TunnelSession(stellar_address="G2", services=["ipfs"])

        await manager.create_session(session1)
        await manager.create_session(session2)

        sessions = await manager.list_sessions()
        assert len(sessions) == 2


class TestTunnelRegistry:
    """Test TunnelRegistry."""

    @pytest.mark.asyncio
    async def test_register_and_get(self):
        """Test registering and retrieving tunnels."""
        from app.registry.store import TunnelRegistry
        from app.auth.session import TunnelSession

        registry = TunnelRegistry(server_address="GSERVER123")

        session = TunnelSession(
            stellar_address="GCLIENT123",
            services=["pintheon"],
            endpoint_url="https://GCLIENT123.tunnel.heavymeta.art"
        )

        await registry.register(session)
        retrieved = await registry.get("GCLIENT123")

        assert retrieved is not None
        assert retrieved.stellar_address == "GCLIENT123"

    @pytest.mark.asyncio
    async def test_unregister(self):
        """Test unregistering tunnels."""
        from app.registry.store import TunnelRegistry
        from app.auth.session import TunnelSession

        registry = TunnelRegistry(server_address="GSERVER123")

        session = TunnelSession(
            stellar_address="GCLIENT123",
            services=["pintheon"]
        )

        await registry.register(session)
        await registry.unregister("GCLIENT123")
        retrieved = await registry.get("GCLIENT123")

        assert retrieved is None

    @pytest.mark.asyncio
    async def test_list_active(self):
        """Test listing active tunnels."""
        from app.registry.store import TunnelRegistry
        from app.auth.session import TunnelSession

        registry = TunnelRegistry(server_address="GSERVER123")

        session1 = TunnelSession(stellar_address="G1", services=["pintheon"])
        session2 = TunnelSession(stellar_address="G2", services=["ipfs"])

        await registry.register(session1)
        await registry.register(session2)

        active = await registry.list_active()
        assert len(active) == 2


class TestJWTVerifier:
    """Test Stellar JWT verification."""

    def test_invalid_jwt_format(self):
        """Test rejection of invalid JWT format."""
        from app.auth.jwt_verifier import StellarJWTVerifier

        verifier = StellarJWTVerifier(
            server_address="GSERVER123"
        )

        with pytest.raises(ValueError, match="Invalid JWT format"):
            verifier.verify("not-a-jwt")

        with pytest.raises(ValueError, match="Invalid JWT format"):
            verifier.verify("only.two.parts.here.invalid")

    def test_valid_jwt_verification(self):
        """Test verification of valid JWT from hvym_stellar."""
        # This test requires hvym_stellar to be installed
        try:
            from stellar_sdk import Keypair
            from hvym_stellar import Stellar25519KeyPair, StellarJWTToken
        except ImportError:
            pytest.skip("hvym_stellar not installed")

        from app.auth.jwt_verifier import StellarJWTVerifier

        # Create server and client keypairs
        server_kp = Keypair.random()
        client_stellar_kp = Keypair.random()
        client_kp = Stellar25519KeyPair(client_stellar_kp)

        # Create verifier
        verifier = StellarJWTVerifier(
            server_address=server_kp.public_key
        )

        # Create JWT
        token = StellarJWTToken(
            keypair=client_kp,
            audience=server_kp.public_key,
            services=["pintheon"],
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        # Verify
        claims = verifier.verify(jwt_string)
        assert claims['sub'] == client_stellar_kp.public_key
        assert claims['aud'] == server_kp.public_key
        assert claims['services'] == ["pintheon"]


class TestConnectionManager:
    """Test TunnelConnectionManager."""

    @pytest.mark.asyncio
    async def test_connection_count(self):
        """Test connection counting."""
        from app.tunnel.connection import TunnelConnectionManager
        from app.registry.store import TunnelRegistry
        from app.auth.session import SessionManager

        registry = TunnelRegistry(server_address="GSERVER")
        session_manager = SessionManager()
        manager = TunnelConnectionManager(
            registry=registry,
            session_manager=session_manager
        )

        assert manager.connection_count == 0

    @pytest.mark.asyncio
    async def test_shutdown(self):
        """Test graceful shutdown."""
        from app.tunnel.connection import TunnelConnectionManager
        from app.registry.store import TunnelRegistry
        from app.auth.session import SessionManager

        registry = TunnelRegistry(server_address="GSERVER")
        session_manager = SessionManager()
        manager = TunnelConnectionManager(
            registry=registry,
            session_manager=session_manager
        )

        # Should not raise
        await manager.shutdown()
        assert manager.connection_count == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
