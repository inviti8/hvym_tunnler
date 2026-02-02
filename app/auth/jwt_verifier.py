"""
Stellar JWT Verification for HVYM Tunnler.

Uses hvym_stellar's StellarJWTTokenVerifier for JWT verification.
"""

import logging
from typing import Dict, Any, Optional

from stellar_sdk import Keypair

try:
    from hvym_stellar import (
        Stellar25519KeyPair,
        StellarJWTTokenVerifier,
        StellarJWTSession
    )
    HVYM_STELLAR_AVAILABLE = True
except ImportError:
    HVYM_STELLAR_AVAILABLE = False
    Stellar25519KeyPair = None
    StellarJWTTokenVerifier = None
    StellarJWTSession = None

logger = logging.getLogger("hvym_tunnler.jwt_verifier")


class StellarJWTVerifier:
    """
    Wrapper around hvym_stellar's JWT verification.

    Provides server-side JWT verification and shared key derivation
    using the hvym_stellar library.
    """

    def __init__(
        self,
        server_address: str,
        server_secret: str = None,
        clock_skew_seconds: int = 60
    ):
        """
        Initialize verifier.

        Args:
            server_address: This server's Stellar address (for audience validation)
            server_secret: Server's secret key (for deriving shared keys)
            clock_skew_seconds: Allowed clock skew for expiration
        """
        if not HVYM_STELLAR_AVAILABLE:
            raise ImportError(
                "hvym_stellar library required: pip install hvym_stellar"
            )

        self.server_address = server_address
        self.clock_skew = clock_skew_seconds
        self._server_keypair: Optional[Stellar25519KeyPair] = None

        # Create server keypair for ECDH if secret provided
        if server_secret:
            stellar_kp = Keypair.from_secret(server_secret)
            self._server_keypair = Stellar25519KeyPair(stellar_kp)

    def verify(self, jwt_string: str) -> Dict[str, Any]:
        """
        Verify JWT and return claims.

        Args:
            jwt_string: The JWT string to verify

        Returns:
            Verified claims dictionary

        Raises:
            ValueError: If verification fails
        """
        # Use hvym_stellar's verifier
        verifier = StellarJWTTokenVerifier(jwt_string)

        # Verify with audience check
        claims = verifier.verify(
            expected_audience=self.server_address,
            expected_issuer="hvym_tunnler"
        )

        logger.info(f"JWT verified for: {claims['sub']}")
        return claims

    def derive_shared_key(self, client_address: str) -> bytes:
        """
        Derive shared key with client for encrypted channel.

        Args:
            client_address: Client's Stellar address

        Returns:
            32-byte shared key
        """
        if not self._server_keypair:
            raise ValueError("Server keypair not configured")

        # Use hvym_stellar's session for key derivation
        session = StellarJWTSession(
            server_keypair=self._server_keypair,
            client_stellar_address=client_address
        )

        return session.derive_tunnel_key()
