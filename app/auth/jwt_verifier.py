"""
Stellar JWT Verification for HVYM Tunnler.

Verifies JWTs signed with Stellar Ed25519 keys.
"""

import json
import time
import base64
import logging
from typing import Dict, Any, Optional

from nacl.signing import VerifyKey
from nacl.public import Box
from stellar_sdk import Keypair

logger = logging.getLogger("hvym_tunnler.jwt_verifier")


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def _stellar_address_to_pubkey(address: str) -> bytes:
    """Extract Ed25519 public key from Stellar address."""
    return Keypair.from_public_key(address).raw_public_key()


class StellarJWTVerifier:
    """
    Verifies Stellar-signed JWT tokens.

    Extracts the signer's public key from the `sub` claim (Stellar address)
    and verifies the Ed25519 signature.
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
        self.server_address = server_address
        self.clock_skew = clock_skew_seconds
        self._server_keypair: Optional[Keypair] = None
        self._server_private_key = None

        # Create server keypair for ECDH if secret provided
        if server_secret:
            self._server_keypair = Keypair.from_secret(server_secret)
            # Convert to X25519 for ECDH
            from nacl.signing import SigningKey
            signing_key = SigningKey(self._server_keypair.raw_secret_key())
            self._server_private_key = signing_key.to_curve25519_private_key()

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
        # Parse JWT
        parts = jwt_string.split('.')
        if len(parts) != 3:
            raise ValueError("Invalid JWT format: expected 3 parts")

        header_b64, payload_b64, signature_b64 = parts

        # Decode components
        try:
            header = json.loads(_base64url_decode(header_b64))
            payload = json.loads(_base64url_decode(payload_b64))
            signature = _base64url_decode(signature_b64)
        except Exception as e:
            raise ValueError(f"Failed to decode JWT: {e}")

        # Verify algorithm
        if header.get('alg') != 'EdDSA':
            raise ValueError(f"Unsupported algorithm: {header.get('alg')}")

        # Verify required claims
        for claim in ['iss', 'sub', 'aud', 'iat']:
            if claim not in payload:
                raise ValueError(f"Missing required claim: {claim}")

        # Verify issuer
        if payload['iss'] != 'hvym_tunnler':
            raise ValueError(f"Invalid issuer: {payload['iss']}")

        # Verify audience (must be this server)
        if payload['aud'] != self.server_address:
            raise ValueError(
                f"Audience mismatch: expected {self.server_address}, "
                f"got {payload['aud']}"
            )

        # Verify expiration
        if 'exp' in payload:
            current_time = int(time.time())
            if current_time > payload['exp'] + self.clock_skew:
                raise ValueError(
                    f"Token expired at {payload['exp']} "
                    f"(current time: {current_time})"
                )

        # Extract public key from sub claim
        try:
            client_address = payload['sub']
            pubkey_bytes = _stellar_address_to_pubkey(client_address)
            verify_key = VerifyKey(pubkey_bytes)
        except Exception as e:
            raise ValueError(f"Invalid Stellar address in sub: {e}")

        # Verify signature
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')
        try:
            verify_key.verify(signing_input, signature)
        except Exception as e:
            raise ValueError(f"Signature verification failed: {e}")

        logger.info(f"JWT verified for: {client_address}")
        return payload

    def derive_shared_key(self, client_address: str) -> bytes:
        """
        Derive shared key with client for encrypted channel.

        Args:
            client_address: Client's Stellar address

        Returns:
            32-byte shared key
        """
        if not self._server_private_key:
            raise ValueError("Server keypair not configured")

        # Get client's public key and convert to X25519
        client_pubkey = _stellar_address_to_pubkey(client_address)
        verify_key = VerifyKey(client_pubkey)
        client_x25519 = verify_key.to_curve25519_public_key()

        # Compute shared secret
        box = Box(self._server_private_key, client_x25519)
        return box.shared_key()
