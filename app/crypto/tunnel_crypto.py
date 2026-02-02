"""
End-to-End Encryption for Tunnel Traffic.

Uses hvym_stellar.StellarSecretBox for the core encryption,
with WebSocket-specific message wrapping handled here.
"""

import logging
from typing import Optional

from nacl.exceptions import CryptoError

try:
    from hvym_stellar import StellarSecretBox
    HVYM_STELLAR_AVAILABLE = True
except ImportError:
    HVYM_STELLAR_AVAILABLE = False
    StellarSecretBox = None

logger = logging.getLogger("hvym_tunnler.crypto")

# Re-export for convenience
__all__ = ['TunnelCrypto', 'TunnelCryptoNegotiator', 'CryptoError']


class TunnelCrypto:
    """
    Tunnel encryption using hvym_stellar.StellarSecretBox.

    This is a thin wrapper that delegates to StellarSecretBox,
    providing tunnel-specific convenience methods.

    Example:
        crypto = TunnelCrypto(shared_key)
        encrypted = crypto.encrypt_message({"method": "POST", ...})
        decrypted = crypto.decrypt_message(encrypted)
    """

    def __init__(self, shared_key: bytes):
        """
        Initialize with ECDH-derived shared key.

        Args:
            shared_key: 32-byte key from StellarJWTSession.derive_tunnel_key()
        """
        if not HVYM_STELLAR_AVAILABLE:
            raise ImportError("hvym_stellar required for encryption")

        self._box = StellarSecretBox(shared_key)

    def encrypt_json(self, data: dict) -> str:
        """Encrypt JSON data to base64 string."""
        return self._box.encrypt_json(data)

    def decrypt_json(self, encrypted_b64: str) -> dict:
        """Decrypt base64 string to JSON data."""
        return self._box.decrypt_json(encrypted_b64)

    def encrypt_message(self, data: dict) -> dict:
        """
        Wrap data in an encrypted tunnel message.

        Args:
            data: The message payload to encrypt

        Returns:
            Dict with encrypted flag and payload
        """
        return {
            "encrypted": True,
            "payload": self.encrypt_json(data)
        }

    def decrypt_message(self, message: dict) -> dict:
        """
        Unwrap and decrypt a tunnel message.

        Args:
            message: Message dict with 'payload' field

        Returns:
            Decrypted payload dict
        """
        if not message.get("encrypted"):
            raise ValueError("Message is not encrypted")
        return self.decrypt_json(message["payload"])

    @property
    def key_id(self) -> str:
        """Get key identifier for logging."""
        return self._box.key_id


class TunnelCryptoNegotiator:
    """
    Handles E2E encryption negotiation and WebSocket message wrapping.

    Supports both encrypted and plaintext modes for backward compatibility.
    Uses hvym_stellar.StellarSecretBox for the actual encryption.

    Example:
        # Initialize with ECDH shared key
        negotiator = TunnelCryptoNegotiator(shared_key)

        # Enable after handshake
        negotiator.enable_encryption()

        # Wrap outgoing messages (auto-encrypts if enabled)
        message = negotiator.wrap_tunnel_request(stream_id, request_data)

        # Unwrap incoming messages (auto-decrypts if encrypted)
        data = negotiator.unwrap_incoming(received_message)
    """

    def __init__(self, shared_key: Optional[bytes] = None):
        """
        Initialize negotiator.

        Args:
            shared_key: Optional ECDH shared key. If None, encryption disabled.
        """
        self._crypto: Optional[TunnelCrypto] = None
        self._encryption_enabled = False

        if shared_key and HVYM_STELLAR_AVAILABLE:
            try:
                self._crypto = TunnelCrypto(shared_key)
                logger.debug(
                    f"E2E encryption available (key: {self._crypto.key_id}...)"
                )
            except Exception as e:
                logger.warning(f"Failed to initialize encryption: {e}")

    def enable_encryption(self) -> bool:
        """
        Enable encryption if available.

        Returns:
            True if encryption is now enabled
        """
        if self._crypto:
            self._encryption_enabled = True
            logger.info("E2E encryption enabled")
            return True
        return False

    def disable_encryption(self):
        """Disable encryption (fallback to plaintext)."""
        self._encryption_enabled = False
        logger.info("E2E encryption disabled")

    @property
    def is_encrypted(self) -> bool:
        """Check if encryption is currently active."""
        return self._encryption_enabled and self._crypto is not None

    @property
    def key_id(self) -> Optional[str]:
        """Get key identifier if available."""
        return self._crypto.key_id if self._crypto else None

    def wrap_outgoing(self, message_type: str, data: dict) -> dict:
        """
        Wrap an outgoing message, encrypting if enabled.

        Args:
            message_type: The message type (e.g., 'tunnel_request')
            data: The message payload

        Returns:
            Message dict ready for WebSocket send
        """
        if self.is_encrypted:
            # Encrypt the entire payload
            inner = {"type": message_type, **data}
            return {
                "type": f"{message_type}_encrypted",
                "encrypted": True,
                "payload": self._crypto.encrypt_json(inner)
            }
        else:
            return {"type": message_type, **data}

    def unwrap_incoming(self, message: dict) -> dict:
        """
        Unwrap an incoming message, decrypting if needed.

        Args:
            message: Received message dict

        Returns:
            Decrypted/unwrapped message with 'type' field
        """
        if message.get("encrypted") and self._crypto:
            try:
                decrypted = self._crypto.decrypt_json(message["payload"])
                return decrypted
            except CryptoError as e:
                logger.error(f"Decryption failed: {e}")
                raise
        return message

    def wrap_tunnel_request(
        self,
        stream_id: int,
        request_data: dict
    ) -> dict:
        """
        Wrap an HTTP request for tunneling.

        Args:
            stream_id: Stream identifier
            request_data: HTTP request (method, path, headers, body)

        Returns:
            Wrapped message for WebSocket
        """
        return self.wrap_outgoing("tunnel_request", {
            "stream_id": stream_id,
            "request": request_data
        })

    def wrap_tunnel_response(
        self,
        stream_id: int,
        response_data: dict
    ) -> dict:
        """
        Wrap an HTTP response for tunneling.

        Args:
            stream_id: Stream identifier
            response_data: HTTP response (status_code, headers, body)

        Returns:
            Wrapped message for WebSocket
        """
        return self.wrap_outgoing("tunnel_response", {
            "stream_id": stream_id,
            "response": response_data
        })
