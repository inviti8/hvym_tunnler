# HVYM Stellar JWT Implementation Specification

## Overview

This document specifies the implementation of a new `TUNNEL` token type for `hvym_stellar`, enabling JWT-based authentication for the HVYM Tunnler service. Unlike existing token types (ACCESS/SECRET using Macaroons, DATA using Biscuits), TUNNEL tokens use standard JWTs signed with Stellar Ed25519 keys.

---

## Token Type Comparison

| Aspect | ACCESS/SECRET | DATA | TUNNEL (New) |
|--------|---------------|------|--------------|
| Backend | Macaroon | Biscuit | JWT |
| Signing | HMAC-SHA256 (shared key) | Ed25519 | Ed25519 |
| Key Requirement | Both parties needed | Shared keypair | Sender's keypair only |
| Verification | Requires receiver's key | Requires receiver's key | Public key from `sub` claim |
| Use Case | Access control, secrets | File storage | Service authentication |
| Standard | pymacaroons | biscuit-auth | RFC 7519 + EdDSA |

---

## High-Level Architecture

### Existing hvym_stellar Token Flow (Macaroons)

```
Sender                                          Receiver
------                                          --------
1. Compute shared_secret = ECDH(sender_priv, receiver_pub)
2. Derive signing_key = SHA256(domain || shared_secret)
3. Create Macaroon signed with HMAC(signing_key)
                    ──────────────────────────────────────►
                                                4. Compute shared_secret = ECDH(receiver_priv, sender_pub)
                                                5. Derive signing_key (same as sender)
                                                6. Verify HMAC signature
```

### New JWT Token Flow (TUNNEL)

```
Client (Metavinci)                              Server (Tunnler)
------------------                              ----------------
1. Create JWT payload with claims
2. Sign with Ed25519(client_private_key)
                    ──────────────────────────────────────►
                                                3. Extract client_address from `sub` claim
                                                4. Derive public key from Stellar address
                                                5. Verify Ed25519 signature
                                                6. Optionally: ECDH for channel encryption
```

**Key Difference**: JWT verification only requires the sender's public key (derivable from Stellar address), not a pre-shared secret.

---

## Implementation Details

### 1. TokenType Enum Extension

```python
# hvym_stellar/__init__.py

class TokenType(Enum):
    ACCESS = 1      # Macaroon-based authorization
    SECRET = 2      # Macaroon with encrypted secret
    # DATA = 3      # (Implicit - HVYMDataToken uses Biscuits)
    TUNNEL = 4      # JWT for tunnel authentication
```

### 2. Domain Separation

Add new domain constant for JWT operations:

```python
class DomainSeparation:
    """Constants for cryptographic domain separation."""
    VERSION = b"hvym_v1"

    # Existing domains
    TOKEN_SIGNING = VERSION + b":token:sign"
    TOKEN_SECRET = VERSION + b":token:secret"
    HYBRID_ENCRYPT = VERSION + b":hybrid:encrypt"
    ASYMMETRIC_ENCRYPT = VERSION + b":asymmetric:encrypt"
    DATA_FILE = VERSION + b":data:file"

    # NEW: JWT domain
    JWT_SIGNING = VERSION + b":jwt:sign"
```

### 3. JWT Utility Functions

```python
import json
import time
import base64
from typing import Dict, Any, Optional, Tuple
from nacl.signing import SigningKey, VerifyKey
from stellar_sdk import Keypair

def _base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url string (no padding)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def _base64url_decode(data: str) -> bytes:
    """Decode base64url string to bytes (handles missing padding)."""
    # Add padding if needed
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data.encode('utf-8'))


def _stellar_address_to_ed25519_pubkey(stellar_address: str) -> bytes:
    """
    Extract Ed25519 public key bytes from Stellar G... address.

    Args:
        stellar_address: Stellar public key (G... format)

    Returns:
        32-byte Ed25519 public key
    """
    keypair = Keypair.from_public_key(stellar_address)
    return keypair.raw_public_key()


def _ed25519_pubkey_to_stellar_address(pubkey_bytes: bytes) -> str:
    """
    Convert Ed25519 public key bytes to Stellar G... address.

    Args:
        pubkey_bytes: 32-byte Ed25519 public key

    Returns:
        Stellar public key (G... format)
    """
    # Stellar addresses are just Ed25519 pubkeys with a checksum
    # We can reconstruct using stellar_sdk
    return Keypair.from_raw_ed25519_public_key(pubkey_bytes).public_key
```

### 4. StellarJWTToken Class (Token Builder)

```python
class StellarJWTToken:
    """
    JWT token signed with Stellar Ed25519 key.

    Used for tunnel authentication where the recipient can verify
    the sender's identity using only the sender's Stellar public address.

    Unlike Macaroon-based tokens, JWT tokens do not require a pre-shared
    ECDH secret - verification uses the public key derived from the
    `sub` claim (Stellar address).

    Example:
        # Create token
        token = StellarJWTToken(
            keypair=sender_kp,
            audience="GSERVER...",
            services=["pintheon", "ipfs"],
            expires_in=3600
        )
        jwt_string = token.to_jwt()

        # Verify token (server side)
        verifier = StellarJWTTokenVerifier(jwt_string)
        if verifier.valid():
            session = verifier.get_claims()
    """

    # JWT algorithm identifier for Ed25519
    ALGORITHM = "EdDSA"

    # Default issuer
    DEFAULT_ISSUER = "hvym_tunnler"

    def __init__(
        self,
        keypair: 'Stellar25519KeyPair',
        audience: str,
        services: list = None,
        expires_in: int = 3600,
        issuer: str = None,
        claims: dict = None
    ):
        """
        Initialize a new JWT token.

        Args:
            keypair: The signer's Stellar25519KeyPair
            audience: Target recipient's Stellar address (aud claim)
            services: List of requested services (e.g., ["pintheon", "ipfs"])
            expires_in: Token lifetime in seconds (default: 1 hour)
            issuer: Token issuer (default: "hvym_tunnler")
            claims: Additional custom claims to include
        """
        self._keypair = keypair
        self._audience = audience
        self._services = services or ["pintheon"]
        self._expires_in = expires_in
        self._issuer = issuer or self.DEFAULT_ISSUER
        self._custom_claims = claims or {}

        # Timestamps
        self._iat = int(time.time())
        self._exp = self._iat + expires_in if expires_in else None

    @property
    def stellar_address(self) -> str:
        """Get the signer's Stellar address."""
        return self._keypair.base_stellar_keypair().public_key

    def _build_header(self) -> dict:
        """Build JWT header."""
        return {
            "alg": self.ALGORITHM,
            "typ": "JWT",
            "kid": self.stellar_address  # Key ID = Stellar address
        }

    def _build_payload(self) -> dict:
        """Build JWT payload with claims."""
        payload = {
            "iss": self._issuer,
            "sub": self.stellar_address,
            "aud": self._audience,
            "iat": self._iat,
            "services": self._services,
        }

        # Add expiration if set
        if self._exp is not None:
            payload["exp"] = self._exp

        # Add custom claims
        payload.update(self._custom_claims)

        return payload

    def to_jwt(self) -> str:
        """
        Generate the signed JWT string.

        Returns:
            JWT string in format: header.payload.signature
        """
        # Build header and payload
        header = self._build_header()
        payload = self._build_payload()

        # Encode to base64url
        header_b64 = _base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
        payload_b64 = _base64url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))

        # Create signing input
        signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

        # Sign with Ed25519
        signed = self._keypair.signing_key().sign(signing_input)
        signature = signed.signature  # 64 bytes

        # Encode signature
        signature_b64 = _base64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    def get_claims(self) -> dict:
        """Get the token claims (for debugging/inspection)."""
        return self._build_payload()

    def inspect(self) -> str:
        """Return human-readable token inspection."""
        header = self._build_header()
        payload = self._build_payload()
        return (
            f"=== JWT Header ===\n{json.dumps(header, indent=2)}\n\n"
            f"=== JWT Payload ===\n{json.dumps(payload, indent=2)}"
        )
```

### 5. StellarJWTTokenVerifier Class

```python
class StellarJWTTokenVerifier:
    """
    Verifier for Stellar-signed JWT tokens.

    Extracts the signer's public key from the `sub` claim (Stellar address)
    and verifies the Ed25519 signature.

    Example:
        verifier = StellarJWTTokenVerifier(jwt_string)

        # Check validity
        if verifier.valid():
            claims = verifier.get_claims()
            print(f"Authenticated: {claims['sub']}")

        # Or verify with audience check
        if verifier.valid(expected_audience="GSERVER..."):
            # Token is for this server
            pass
    """

    def __init__(
        self,
        jwt_string: str,
        max_age_seconds: int = None
    ):
        """
        Initialize the verifier.

        Args:
            jwt_string: The JWT string to verify
            max_age_seconds: Optional maximum token age (in addition to exp claim)
        """
        self._jwt_string = jwt_string
        self._max_age_seconds = max_age_seconds

        # Parse JWT
        self._header = None
        self._payload = None
        self._signature = None
        self._signing_input = None
        self._parse_error = None

        self._parse_jwt()

    def _parse_jwt(self):
        """Parse the JWT string into components."""
        try:
            parts = self._jwt_string.split('.')
            if len(parts) != 3:
                self._parse_error = "Invalid JWT format: expected 3 parts"
                return

            header_b64, payload_b64, signature_b64 = parts

            # Decode header and payload
            self._header = json.loads(_base64url_decode(header_b64))
            self._payload = json.loads(_base64url_decode(payload_b64))
            self._signature = _base64url_decode(signature_b64)
            self._signing_input = f"{header_b64}.{payload_b64}".encode('utf-8')

        except json.JSONDecodeError as e:
            self._parse_error = f"Invalid JSON in JWT: {e}"
        except Exception as e:
            self._parse_error = f"Failed to parse JWT: {e}"

    def valid(
        self,
        expected_audience: str = None,
        expected_issuer: str = None
    ) -> bool:
        """
        Check if the JWT is valid.

        Args:
            expected_audience: If provided, verify `aud` claim matches
            expected_issuer: If provided, verify `iss` claim matches

        Returns:
            True if token is valid, False otherwise
        """
        try:
            self.verify(expected_audience, expected_issuer)
            return True
        except Exception:
            return False

    def verify(
        self,
        expected_audience: str = None,
        expected_issuer: str = None
    ) -> dict:
        """
        Verify the JWT and return claims.

        Args:
            expected_audience: If provided, verify `aud` claim matches
            expected_issuer: If provided, verify `iss` claim matches

        Returns:
            The verified claims dictionary

        Raises:
            ValueError: If verification fails
        """
        # Check parse errors
        if self._parse_error:
            raise ValueError(self._parse_error)

        # Verify algorithm
        if self._header.get('alg') != 'EdDSA':
            raise ValueError(f"Unsupported algorithm: {self._header.get('alg')}")

        # Verify required claims
        required_claims = ['iss', 'sub', 'aud', 'iat']
        for claim in required_claims:
            if claim not in self._payload:
                raise ValueError(f"Missing required claim: {claim}")

        # Verify audience if specified
        if expected_audience and self._payload['aud'] != expected_audience:
            raise ValueError(
                f"Audience mismatch: expected {expected_audience}, "
                f"got {self._payload['aud']}"
            )

        # Verify issuer if specified
        if expected_issuer and self._payload['iss'] != expected_issuer:
            raise ValueError(
                f"Issuer mismatch: expected {expected_issuer}, "
                f"got {self._payload['iss']}"
            )

        # Verify expiration
        if 'exp' in self._payload:
            current_time = int(time.time())
            # Allow 60 second clock skew
            if current_time > self._payload['exp'] + 60:
                raise ValueError(
                    f"Token expired at {self._payload['exp']} "
                    f"(current time: {current_time})"
                )

        # Verify max age if specified
        if self._max_age_seconds is not None:
            current_time = int(time.time())
            token_age = current_time - self._payload['iat']
            if token_age > self._max_age_seconds + 60:  # 60s grace
                raise ValueError(
                    f"Token too old: {token_age}s > {self._max_age_seconds}s"
                )

        # Extract public key from sub claim (Stellar address)
        try:
            stellar_address = self._payload['sub']
            pubkey_bytes = _stellar_address_to_ed25519_pubkey(stellar_address)
            verify_key = VerifyKey(pubkey_bytes)
        except Exception as e:
            raise ValueError(f"Invalid Stellar address in sub claim: {e}")

        # Verify Ed25519 signature
        try:
            verify_key.verify(self._signing_input, self._signature)
        except Exception as e:
            raise ValueError(f"Signature verification failed: {e}")

        return self._payload

    def get_claims(self) -> dict:
        """
        Get the token claims without verification.

        WARNING: Always call valid() or verify() before trusting claims!
        """
        if self._parse_error:
            raise ValueError(self._parse_error)
        return self._payload.copy()

    def get_header(self) -> dict:
        """Get the token header."""
        if self._parse_error:
            raise ValueError(self._parse_error)
        return self._header.copy()

    def get_stellar_address(self) -> str:
        """Get the signer's Stellar address from sub claim."""
        return self._payload['sub']

    def get_services(self) -> list:
        """Get the requested services."""
        return self._payload.get('services', [])

    def is_expired(self) -> bool:
        """Check if the token has expired."""
        if 'exp' not in self._payload:
            return False
        return int(time.time()) > self._payload['exp']

    def inspect(self) -> str:
        """Return human-readable token inspection."""
        if self._parse_error:
            return f"Parse Error: {self._parse_error}"
        return (
            f"=== JWT Header ===\n{json.dumps(self._header, indent=2)}\n\n"
            f"=== JWT Payload ===\n{json.dumps(self._payload, indent=2)}\n\n"
            f"=== Signature ===\n{self._signature.hex()[:64]}..."
        )
```

### 6. Optional: ECDH Session Key Derivation

For establishing encrypted channels after JWT authentication:

```python
class StellarJWTSession:
    """
    Establishes an encrypted session after JWT authentication.

    After verifying a JWT, the server can derive a shared key with
    the client for encrypting the tunnel traffic.
    """

    def __init__(
        self,
        server_keypair: 'Stellar25519KeyPair',
        client_stellar_address: str
    ):
        """
        Initialize session with server keypair and client address.

        Args:
            server_keypair: Server's Stellar25519KeyPair
            client_stellar_address: Client's Stellar address (from JWT sub)
        """
        self._server_keypair = server_keypair
        self._client_address = client_stellar_address

        # Derive client's X25519 public key from Stellar address
        client_pubkey_bytes = _stellar_address_to_ed25519_pubkey(client_stellar_address)
        # Convert Ed25519 to X25519 for ECDH
        # Note: This uses the same conversion as Stellar25519KeyPair
        from nacl.signing import VerifyKey
        verify_key = VerifyKey(client_pubkey_bytes)
        self._client_x25519_pub = verify_key.to_curve25519_public_key()

    def derive_shared_key(self, domain: bytes = None) -> bytes:
        """
        Derive shared key for session encryption.

        Args:
            domain: Optional domain separation bytes

        Returns:
            32-byte shared key
        """
        from nacl.public import Box

        # Compute ECDH shared secret
        box = Box(
            self._server_keypair.private_key(),
            self._client_x25519_pub
        )
        shared_secret = box.shared_key()

        # Apply domain separation if provided
        if domain:
            hasher = hashlib.sha256()
            hasher.update(domain + shared_secret)
            return hasher.digest()

        return shared_secret

    def derive_tunnel_key(self) -> bytes:
        """Derive key specifically for tunnel encryption."""
        return self.derive_shared_key(DomainSeparation.JWT_SIGNING)
```

---

## JWT Wire Format

### Structure

```
┌─────────────────────────────────────────────────────────────────┐
│                         JWT Token                               │
├───────────────────┬───────────────────┬─────────────────────────┤
│  Header (base64url)│  Payload (base64url)│  Signature (base64url) │
│                   │                   │                         │
│  {"alg":"EdDSA",  │  {"iss":"hvym_..  │  [64 bytes Ed25519]     │
│   "typ":"JWT",    │   "sub":"GABC..", │                         │
│   "kid":"GABC.."} │   "aud":"GXYZ..", │                         │
│                   │   ...}            │                         │
└───────────────────┴───────────────────┴─────────────────────────┘
          │                   │                     │
          └─────────┬─────────┘                     │
                    │                               │
             signing_input = header.payload         │
                    │                               │
                    └───────────────────────────────┘
                              Ed25519_Sign(private_key, signing_input)
```

### Header Fields

| Field | Value | Description |
|-------|-------|-------------|
| `alg` | `"EdDSA"` | Ed25519 signature algorithm |
| `typ` | `"JWT"` | Token type |
| `kid` | `"G..."` | Key ID = Signer's Stellar address |

### Payload Claims

| Claim | Required | Description |
|-------|----------|-------------|
| `iss` | Yes | Issuer (e.g., "hvym_tunnler") |
| `sub` | Yes | Subject = Signer's Stellar address |
| `aud` | Yes | Audience = Target server's Stellar address |
| `iat` | Yes | Issued at (Unix timestamp) |
| `exp` | No | Expiration (Unix timestamp) |
| `services` | No | Requested services array |
| (custom) | No | Additional application claims |

### Example Token

**Header:**
```json
{
  "alg": "EdDSA",
  "typ": "JWT",
  "kid": "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKL"
}
```

**Payload:**
```json
{
  "iss": "hvym_tunnler",
  "sub": "GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKL",
  "aud": "GXYZ789012345678901234567890123456789012345678",
  "iat": 1706745600,
  "exp": 1706749200,
  "services": ["pintheon", "ipfs"]
}
```

---

## Integration with Existing Code

### Using Existing Stellar25519KeyPair

The JWT implementation uses the existing `Stellar25519KeyPair` class:

```python
from hvym_stellar import Stellar25519KeyPair, StellarJWTToken, StellarJWTTokenVerifier
from stellar_sdk import Keypair

# Create keypairs (same as other token types)
client_kp = Stellar25519KeyPair(Keypair.random())
server_kp = Stellar25519KeyPair(Keypair.random())

# Create JWT
token = StellarJWTToken(
    keypair=client_kp,
    audience=server_kp.base_stellar_keypair().public_key,
    services=["pintheon"],
    expires_in=3600
)
jwt_string = token.to_jwt()

# Verify JWT
verifier = StellarJWTTokenVerifier(jwt_string)
if verifier.valid(expected_audience=server_kp.base_stellar_keypair().public_key):
    print(f"Authenticated client: {verifier.get_stellar_address()}")
```

### Comparison with Existing Token Creation

```python
# ACCESS Token (Macaroon - requires receiver's public key for ECDH)
access_token = StellarSharedKeyTokenBuilder(
    senderKeyPair=client_kp,
    receiverPub=server_kp.public_key(),  # X25519 public key
    token_type=TokenType.ACCESS,
    expires_in=3600
)

# TUNNEL Token (JWT - only requires signer's keypair + audience address)
tunnel_token = StellarJWTToken(
    keypair=client_kp,
    audience=server_kp.base_stellar_keypair().public_key,  # Stellar address
    expires_in=3600
)
```

---

## Security Considerations

### 1. Signature Algorithm

- Uses Ed25519 (EdDSA) per RFC 8037
- 128-bit security level
- Same curve as Stellar's native signing

### 2. Key Binding

- `sub` claim contains signer's Stellar address
- `kid` header also contains the address (for key lookup)
- Public key derived from address, not provided separately
- Prevents key substitution attacks

### 3. Audience Verification

- `aud` claim MUST be verified by server
- Prevents token reuse across different servers
- Each tunnel server has unique Stellar address

### 4. Timestamp Validation

- `iat` (issued at) prevents pre-dated tokens
- `exp` (expiration) limits token lifetime
- 60-second clock skew tolerance
- Optional `max_age_seconds` for additional freshness check

### 5. No Shared Secret Required

- Unlike Macaroon tokens, JWT verification doesn't need ECDH
- Reduces complexity for one-way authentication
- Server can still derive shared key after verification (for channel encryption)

---

## Test Cases

```python
def test_jwt_creation():
    """Test basic JWT creation."""
    kp = Stellar25519KeyPair(Keypair.random())
    token = StellarJWTToken(
        keypair=kp,
        audience="GSERVERPUBKEY...",
        services=["pintheon"],
        expires_in=3600
    )
    jwt_string = token.to_jwt()

    # JWT should have 3 parts
    assert len(jwt_string.split('.')) == 3


def test_jwt_verification():
    """Test JWT verification."""
    kp = Stellar25519KeyPair(Keypair.random())
    server_addr = Keypair.random().public_key

    token = StellarJWTToken(
        keypair=kp,
        audience=server_addr,
        expires_in=3600
    )
    jwt_string = token.to_jwt()

    verifier = StellarJWTTokenVerifier(jwt_string)
    assert verifier.valid(expected_audience=server_addr)
    assert verifier.get_stellar_address() == kp.base_stellar_keypair().public_key


def test_jwt_expired():
    """Test expired JWT rejection."""
    kp = Stellar25519KeyPair(Keypair.random())

    # Create token that expires immediately
    token = StellarJWTToken(
        keypair=kp,
        audience="GSERVER...",
        expires_in=-100  # Already expired
    )
    jwt_string = token.to_jwt()

    verifier = StellarJWTTokenVerifier(jwt_string)
    assert not verifier.valid()
    assert verifier.is_expired()


def test_jwt_wrong_audience():
    """Test wrong audience rejection."""
    kp = Stellar25519KeyPair(Keypair.random())

    token = StellarJWTToken(
        keypair=kp,
        audience="GSERVER1...",
        expires_in=3600
    )
    jwt_string = token.to_jwt()

    verifier = StellarJWTTokenVerifier(jwt_string)
    assert not verifier.valid(expected_audience="GSERVER2...")


def test_jwt_tampered():
    """Test tampered JWT rejection."""
    kp = Stellar25519KeyPair(Keypair.random())

    token = StellarJWTToken(
        keypair=kp,
        audience="GSERVER...",
        expires_in=3600
    )
    jwt_string = token.to_jwt()

    # Tamper with payload
    parts = jwt_string.split('.')
    tampered = parts[0] + '.' + parts[1] + 'x' + '.' + parts[2]

    verifier = StellarJWTTokenVerifier(tampered)
    assert not verifier.valid()
```

---

## File Changes Summary

### hvym_stellar/\_\_init\_\_.py

1. Add `TUNNEL = 4` to `TokenType` enum
2. Add `JWT_SIGNING` to `DomainSeparation` class
3. Add utility functions: `_base64url_encode`, `_base64url_decode`, `_stellar_address_to_ed25519_pubkey`
4. Add `StellarJWTToken` class
5. Add `StellarJWTTokenVerifier` class
6. (Optional) Add `StellarJWTSession` class for post-auth ECDH

### New Exports

```python
__all__ = [
    # Existing exports...
    'StellarJWTToken',
    'StellarJWTTokenVerifier',
    'StellarJWTSession',  # Optional
]
```

---

## Dependencies

No new dependencies required. Uses:
- `nacl` (already required for Ed25519)
- `stellar_sdk` (already required for Keypair)
- `json`, `time`, `base64`, `hashlib` (stdlib)

---

## References

- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [RFC 8037 - CFRG ECDH and Signatures in JOSE](https://tools.ietf.org/html/rfc8037)
- [hvym_stellar CRYPTO_SPEC.md](../../../hvym_stellar/CRYPTO_SPEC.md)
- [Stellar Ed25519 Keys](https://developers.stellar.org/docs/learn/encyclopedia/security/signatures-multisig)
