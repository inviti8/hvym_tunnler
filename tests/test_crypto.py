"""
Tests for E2E tunnel encryption.

Tests both hvym_stellar.StellarSecretBox and hvym_tunnler's
WebSocket-specific TunnelCryptoNegotiator.
"""

import pytest
import os
from nacl.exceptions import CryptoError

from hvym_stellar import StellarSecretBox
from app.crypto.tunnel_crypto import TunnelCrypto, TunnelCryptoNegotiator


class TestStellarSecretBox:
    """Tests for hvym_stellar.StellarSecretBox (core encryption)."""

    @pytest.fixture
    def shared_key(self):
        """Generate a 32-byte shared key."""
        return os.urandom(32)

    @pytest.fixture
    def box(self, shared_key):
        """Create StellarSecretBox instance."""
        return StellarSecretBox(shared_key)

    def test_init_invalid_key_size(self):
        """Test initialization with wrong key size fails."""
        with pytest.raises(ValueError, match="Invalid key size"):
            StellarSecretBox(b"short_key")

    def test_encrypt_decrypt_bytes(self, box):
        """Test encrypting and decrypting raw bytes."""
        plaintext = b"Hello, World! This is a secret message."

        encrypted = box.encrypt(plaintext)
        assert encrypted != plaintext
        assert len(encrypted) > len(plaintext)  # nonce + tag overhead

        decrypted = box.decrypt(encrypted)
        assert decrypted == plaintext

    def test_encrypt_decrypt_json(self, box):
        """Test encrypting and decrypting JSON data."""
        data = {
            "method": "POST",
            "path": "/api/wallet/sign",
            "headers": {"Authorization": "Bearer secret_token"},
            "body": {"transaction": "sensitive_data"}
        }

        encrypted_b64 = box.encrypt_json(data)
        assert isinstance(encrypted_b64, str)

        decrypted = box.decrypt_json(encrypted_b64)
        assert decrypted == data

    def test_different_keys_fail(self):
        """Test decryption with different key fails."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)

        box1 = StellarSecretBox(key1)
        box2 = StellarSecretBox(key2)

        encrypted = box1.encrypt_json({"secret": "data"})

        with pytest.raises(CryptoError):
            box2.decrypt_json(encrypted)

    def test_tampered_ciphertext_fails(self, box):
        """Test tampered ciphertext is detected."""
        encrypted = box.encrypt(b"secret data")

        # Tamper with ciphertext (after nonce)
        tampered = encrypted[:24] + bytes([encrypted[24] ^ 0xFF]) + encrypted[25:]

        with pytest.raises(CryptoError):
            box.decrypt(tampered)

    def test_unique_ciphertexts(self, box):
        """Test each encryption produces unique output (random nonce)."""
        data = {"same": "data"}

        encrypted1 = box.encrypt_json(data)
        encrypted2 = box.encrypt_json(data)

        assert encrypted1 != encrypted2

    def test_key_id(self, box):
        """Test key ID is generated for logging."""
        assert len(box.key_id) > 0

    def test_repr(self, box):
        """Test string representation."""
        assert "StellarSecretBox" in repr(box)
        assert box.key_id in repr(box)


class TestTunnelCrypto:
    """Tests for TunnelCrypto wrapper."""

    @pytest.fixture
    def shared_key(self):
        return os.urandom(32)

    @pytest.fixture
    def crypto(self, shared_key):
        return TunnelCrypto(shared_key)

    def test_encrypt_message_wrapper(self, crypto):
        """Test message wrapper format."""
        data = {"key": "value"}

        wrapped = crypto.encrypt_message(data)
        assert wrapped["encrypted"] is True
        assert "payload" in wrapped

    def test_decrypt_message_wrapper(self, crypto):
        """Test unwrapping encrypted message."""
        data = {"key": "value", "nested": {"a": 1}}

        wrapped = crypto.encrypt_message(data)
        unwrapped = crypto.decrypt_message(wrapped)

        assert unwrapped == data

    def test_decrypt_unencrypted_message_fails(self, crypto):
        """Test decrypting non-encrypted message fails."""
        with pytest.raises(ValueError, match="not encrypted"):
            crypto.decrypt_message({"type": "plaintext"})

    def test_key_id(self, crypto):
        """Test key ID passthrough."""
        assert len(crypto.key_id) > 0


class TestTunnelCryptoNegotiator:
    """Tests for encryption negotiation."""

    @pytest.fixture
    def shared_key(self):
        return os.urandom(32)

    def test_init_without_key(self):
        """Test initialization without shared key."""
        negotiator = TunnelCryptoNegotiator(None)
        assert not negotiator.is_encrypted
        assert not negotiator.enable_encryption()

    def test_init_with_key(self, shared_key):
        """Test initialization with shared key."""
        negotiator = TunnelCryptoNegotiator(shared_key)
        assert not negotiator.is_encrypted  # Not enabled by default

    def test_enable_encryption(self, shared_key):
        """Test enabling encryption."""
        negotiator = TunnelCryptoNegotiator(shared_key)

        assert negotiator.enable_encryption()
        assert negotiator.is_encrypted

    def test_disable_encryption(self, shared_key):
        """Test disabling encryption."""
        negotiator = TunnelCryptoNegotiator(shared_key)
        negotiator.enable_encryption()

        negotiator.disable_encryption()
        assert not negotiator.is_encrypted

    def test_key_id(self, shared_key):
        """Test key ID property."""
        negotiator = TunnelCryptoNegotiator(shared_key)
        assert negotiator.key_id is not None

    def test_wrap_outgoing_plaintext(self, shared_key):
        """Test wrapping when encryption disabled."""
        negotiator = TunnelCryptoNegotiator(shared_key)

        message = negotiator.wrap_outgoing("tunnel_request", {
            "stream_id": 1,
            "request": {"method": "GET"}
        })

        assert message["type"] == "tunnel_request"
        assert "encrypted" not in message

    def test_wrap_outgoing_encrypted(self, shared_key):
        """Test wrapping when encryption enabled."""
        negotiator = TunnelCryptoNegotiator(shared_key)
        negotiator.enable_encryption()

        message = negotiator.wrap_outgoing("tunnel_request", {
            "stream_id": 1,
            "request": {"method": "GET"}
        })

        assert message["type"] == "tunnel_request_encrypted"
        assert message["encrypted"] is True
        assert "payload" in message

    def test_unwrap_incoming_plaintext(self, shared_key):
        """Test unwrapping plaintext message."""
        negotiator = TunnelCryptoNegotiator(shared_key)

        message = {"type": "tunnel_response", "data": "value"}
        unwrapped = negotiator.unwrap_incoming(message)

        assert unwrapped == message

    def test_unwrap_incoming_encrypted(self, shared_key):
        """Test unwrapping encrypted message."""
        negotiator = TunnelCryptoNegotiator(shared_key)
        negotiator.enable_encryption()

        # Wrap a message
        original = {"stream_id": 1, "response": {"status": 200}}
        wrapped = negotiator.wrap_outgoing("tunnel_response", original)

        # Unwrap it
        unwrapped = negotiator.unwrap_incoming(wrapped)

        assert unwrapped["type"] == "tunnel_response"
        assert unwrapped["stream_id"] == 1
        assert unwrapped["response"] == {"status": 200}

    def test_wrap_tunnel_request(self, shared_key):
        """Test tunnel request wrapper."""
        negotiator = TunnelCryptoNegotiator(shared_key)
        negotiator.enable_encryption()

        request_data = {
            "method": "POST",
            "path": "/api/data",
            "body": "secret"
        }

        wrapped = negotiator.wrap_tunnel_request(
            stream_id=42,
            request_data=request_data
        )

        assert wrapped["encrypted"] is True

        # Verify we can unwrap it
        unwrapped = negotiator.unwrap_incoming(wrapped)
        assert unwrapped["stream_id"] == 42
        assert unwrapped["request"] == request_data

    def test_wrap_tunnel_response(self, shared_key):
        """Test tunnel response wrapper."""
        negotiator = TunnelCryptoNegotiator(shared_key)
        negotiator.enable_encryption()

        response_data = {
            "status_code": 200,
            "headers": {"Content-Type": "application/json"},
            "body": '{"result": "sensitive"}'
        }

        wrapped = negotiator.wrap_tunnel_response(
            stream_id=42,
            response_data=response_data
        )

        assert wrapped["encrypted"] is True

        unwrapped = negotiator.unwrap_incoming(wrapped)
        assert unwrapped["stream_id"] == 42
        assert unwrapped["response"] == response_data


class TestStellarJWTSessionInheritance:
    """Tests for StellarJWTSession inheriting from StellarKeyBase."""

    def test_inherits_from_stellar_key_base(self):
        """Verify StellarJWTSession inherits from StellarKeyBase."""
        from hvym_stellar import StellarJWTSession, StellarKeyBase, Stellar25519KeyPair
        from stellar_sdk import Keypair

        assert issubclass(StellarJWTSession, StellarKeyBase)

    def test_inherited_shared_secret_methods(self):
        """Test that inherited methods from StellarKeyBase work."""
        from hvym_stellar import StellarJWTSession, Stellar25519KeyPair
        from stellar_sdk import Keypair

        server_kp = Stellar25519KeyPair(Keypair.random())
        client_kp = Stellar25519KeyPair(Keypair.random())
        client_address = client_kp.base_stellar_keypair().public_key

        session = StellarJWTSession(server_kp, client_address)

        # These methods are inherited from StellarKeyBase
        raw_secret = session.shared_secret()
        assert len(raw_secret) == 32

        hex_secret = session.shared_secret_as_hex()
        assert len(hex_secret) == 64  # 32 bytes = 64 hex chars

        hash_secret = session.hash_of_shared_secret()
        assert len(hash_secret) == 64

        asymmetric_secret = session.asymmetric_shared_secret()
        assert asymmetric_secret == raw_secret  # Same without salt

    def test_bidirectional_session_compatibility(self):
        """Test server and client sessions derive same shared secret."""
        from hvym_stellar import StellarJWTSession, Stellar25519KeyPair
        from stellar_sdk import Keypair

        server_kp = Stellar25519KeyPair(Keypair.random())
        client_kp = Stellar25519KeyPair(Keypair.random())

        server_address = server_kp.base_stellar_keypair().public_key
        client_address = client_kp.base_stellar_keypair().public_key

        # Server creates session with client's address
        server_session = StellarJWTSession(server_kp, client_address)

        # Client creates session with server's address
        client_session = StellarJWTSession(client_kp, server_address)

        # Both should derive the same shared secret (ECDH property)
        assert server_session.shared_secret() == client_session.shared_secret()
        assert server_session.derive_tunnel_key() == client_session.derive_tunnel_key()

    def test_create_secret_box_interop(self):
        """Test SecretBox created from session works bidirectionally."""
        from hvym_stellar import StellarJWTSession, Stellar25519KeyPair
        from stellar_sdk import Keypair

        server_kp = Stellar25519KeyPair(Keypair.random())
        client_kp = Stellar25519KeyPair(Keypair.random())

        server_address = server_kp.base_stellar_keypair().public_key
        client_address = client_kp.base_stellar_keypair().public_key

        server_session = StellarJWTSession(server_kp, client_address)
        client_session = StellarJWTSession(client_kp, server_address)

        server_box = server_session.create_secret_box()
        client_box = client_session.create_secret_box()

        # Server encrypts, client decrypts
        message = {"wallet": "secret_key_data"}
        encrypted = server_box.encrypt_json(message)
        decrypted = client_box.decrypt_json(encrypted)
        assert decrypted == message

        # Client encrypts, server decrypts
        response = {"status": "signed"}
        encrypted2 = client_box.encrypt_json(response)
        decrypted2 = server_box.decrypt_json(encrypted2)
        assert decrypted2 == response

    def test_session_properties(self):
        """Test session property accessors."""
        from hvym_stellar import StellarJWTSession, Stellar25519KeyPair
        from stellar_sdk import Keypair

        server_kp = Stellar25519KeyPair(Keypair.random())
        client_kp = Stellar25519KeyPair(Keypair.random())

        server_address = server_kp.base_stellar_keypair().public_key
        client_address = client_kp.base_stellar_keypair().public_key

        session = StellarJWTSession(server_kp, client_address)

        assert session.server_address == server_address
        assert session.client_address == client_address
        assert "StellarJWTSession" in repr(session)


class TestE2EScenario:
    """End-to-end encryption scenario tests."""

    def test_server_client_communication(self):
        """Test full server-client encrypted communication."""
        # Both sides derive same shared key (simulated ECDH)
        shared_key = os.urandom(32)

        server_crypto = TunnelCryptoNegotiator(shared_key)
        client_crypto = TunnelCryptoNegotiator(shared_key)

        # Both enable encryption
        server_crypto.enable_encryption()
        client_crypto.enable_encryption()

        # Server sends encrypted request
        request = {
            "method": "GET",
            "path": "/api/wallet/balance",
            "headers": {"Authorization": "Bearer token123"}
        }
        server_message = server_crypto.wrap_tunnel_request(1, request)

        # Client receives and decrypts
        client_received = client_crypto.unwrap_incoming(server_message)
        assert client_received["request"] == request

        # Client sends encrypted response
        response = {
            "status_code": 200,
            "body": '{"balance": "1000 XLM"}'
        }
        client_message = client_crypto.wrap_tunnel_response(1, response)

        # Server receives and decrypts
        server_received = server_crypto.unwrap_incoming(client_message)
        assert server_received["response"] == response

    def test_man_in_middle_cannot_read(self):
        """Test that MITM cannot decrypt traffic."""
        shared_key = os.urandom(32)
        attacker_key = os.urandom(32)

        legitimate = TunnelCryptoNegotiator(shared_key)
        attacker = TunnelCryptoNegotiator(attacker_key)

        legitimate.enable_encryption()
        attacker.enable_encryption()

        # Legitimate party encrypts sensitive data
        sensitive = {"secret": "wallet_private_key_xyz"}
        encrypted = legitimate.wrap_tunnel_request(1, sensitive)

        # Attacker intercepts but cannot decrypt
        with pytest.raises(CryptoError):
            attacker.unwrap_incoming(encrypted)

    def test_using_stellar_secret_box_directly(self):
        """Test direct usage of StellarSecretBox for interop."""
        shared_key = os.urandom(32)

        # Server uses StellarSecretBox directly
        server_box = StellarSecretBox(shared_key)

        # Client uses TunnelCrypto wrapper
        client_crypto = TunnelCrypto(shared_key)

        # Server encrypts
        data = {"secret": "value"}
        encrypted = server_box.encrypt_json(data)

        # Client decrypts via wrapper
        decrypted = client_crypto.decrypt_json(encrypted)
        assert decrypted == data

        # Vice versa
        data2 = {"response": "ok"}
        encrypted2 = client_crypto.encrypt_json(data2)
        decrypted2 = server_box.decrypt_json(encrypted2)
        assert decrypted2 == data2
