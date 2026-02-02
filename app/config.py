"""
Configuration management for HVYM Tunnler.
"""

import os
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Server identity (REQUIRED)
    server_address: str = ""
    server_secret: str = ""

    # Network
    host: str = "0.0.0.0"
    port: int = 8000
    domain: str = "tunnel.heavymeta.art"

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Authentication
    jwt_clock_skew: int = 60  # seconds
    session_timeout: int = 86400  # 24 hours

    # Services
    allowed_services: List[str] = ["pintheon", "ipfs"]

    # Logging
    log_level: str = "INFO"

    # Debug mode
    debug: bool = False

    model_config = {
        "env_prefix": "TUNNLER_",
        "env_file": ".env",
        "extra": "ignore"
    }

    def validate_required(self) -> bool:
        """Validate that required settings are configured."""
        if not self.server_address:
            raise ValueError(
                "TUNNLER_SERVER_ADDRESS is required. "
                "Generate with: python -c \"from stellar_sdk import Keypair; "
                "k=Keypair.random(); print(k.public_key)\""
            )
        if not self.server_secret:
            raise ValueError(
                "TUNNLER_SERVER_SECRET is required. "
                "Generate with: python -c \"from stellar_sdk import Keypair; "
                "k=Keypair.random(); print(k.secret)\""
            )
        return True


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    settings = Settings()
    # In production, validate required fields
    if not settings.debug:
        try:
            settings.validate_required()
        except ValueError as e:
            import logging
            logging.warning(f"Configuration warning: {e}")
    return settings
