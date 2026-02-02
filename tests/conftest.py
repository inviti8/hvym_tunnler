"""
Pytest configuration for HVYM Tunnler tests.
"""

import os
import sys
import pytest

# Add app directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Set test environment variables
os.environ["TUNNLER_SERVER_ADDRESS"] = "GTEST1234567890123456789012345678901234567890123456"
os.environ["TUNNLER_SERVER_SECRET"] = "STEST1234567890123456789012345678901234567890123456"
os.environ["TUNNLER_DEBUG"] = "true"
os.environ["TUNNLER_REDIS_URL"] = "redis://localhost:6379"


@pytest.fixture
def test_settings():
    """Provide test settings."""
    from app.config import Settings
    return Settings()


@pytest.fixture
def session_manager():
    """Provide a session manager."""
    from app.auth.session import SessionManager
    return SessionManager()


@pytest.fixture
def registry():
    """Provide a tunnel registry."""
    from app.registry.store import TunnelRegistry
    return TunnelRegistry(server_address="GTEST_SERVER")


@pytest.fixture
def connection_manager(registry, session_manager):
    """Provide a connection manager."""
    from app.tunnel.connection import TunnelConnectionManager
    return TunnelConnectionManager(
        registry=registry,
        session_manager=session_manager
    )
