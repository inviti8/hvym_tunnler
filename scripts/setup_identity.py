#!/usr/bin/env python3
"""
HVYM Tunnler Identity Setup Script

Generates:
1. Stellar Ed25519 keypair for server identity
2. .env file with TUNNLER_SERVER_ADDRESS and TUNNLER_SERVER_SECRET
3. QR code PNG of public key for easy client configuration
4. JSON metadata file for API consumption

Usage:
    python setup_identity.py --domain tunnel.heavymeta.art
    python setup_identity.py --domain tunnel.heavymeta.art --force  # Regenerate
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    from stellar_sdk import Keypair
except ImportError:
    print("ERROR: stellar-sdk not installed. Run: pip install stellar-sdk")
    sys.exit(1)

try:
    import qrcode
    from PIL import Image
except ImportError:
    print("ERROR: qrcode or Pillow not installed. Run: pip install qrcode[pil] Pillow")
    sys.exit(1)


class IdentitySetup:
    """Handles server identity generation and storage."""

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.data_path = base_path / "data"
        self.static_path = base_path / "static"
        self.env_path = base_path / ".env"

    def identity_exists(self) -> bool:
        """Check if identity has already been generated."""
        return self.env_path.exists()

    def load_existing_identity(self) -> dict:
        """Load existing identity from .env file."""
        if not self.env_path.exists():
            return {}

        identity = {}
        with open(self.env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    identity[key] = value

        return identity

    def generate_keypair(self) -> Keypair:
        """Generate new random Stellar keypair."""
        return Keypair.random()

    def save_env_file(
        self,
        keypair: Keypair,
        domain: str,
        allowed_services: str,
        log_level: str
    ):
        """Write .env file with server credentials."""
        # Convert comma-separated services to JSON array for pydantic-settings
        services_list = [s.strip() for s in allowed_services.split(",")]
        services_json = json.dumps(services_list)

        env_content = f"""# HVYM Tunnler Server Configuration
# Generated: {datetime.now(timezone.utc).isoformat()}
# WARNING: Keep TUNNLER_SERVER_SECRET secure! Back it up safely.

# Server Identity (Stellar Ed25519 Keypair)
TUNNLER_SERVER_ADDRESS={keypair.public_key}
TUNNLER_SERVER_SECRET={keypair.secret}

# Network Configuration
TUNNLER_DOMAIN={domain}
TUNNLER_HOST=0.0.0.0
TUNNLER_PORT=8000

# Redis (local)
TUNNLER_REDIS_URL=redis://localhost:6379

# Services (JSON array format required by pydantic-settings)
TUNNLER_ALLOWED_SERVICES={services_json}

# Logging
TUNNLER_LOG_LEVEL={log_level}

# Security Settings (defaults are good for production)
# TUNNLER_CHALLENGE_TTL=30
# TUNNLER_RATE_LIMIT_WINDOW=60
# TUNNLER_RATE_LIMIT_MAX_ATTEMPTS=10
# TUNNLER_RATE_LIMIT_BLOCK_DURATION=300
# TUNNLER_JWT_CLOCK_SKEW=60
"""
        self.env_path.write_text(env_content)
        # Restrict permissions (owner read/write only)
        os.chmod(self.env_path, 0o600)
        print(f"  Created: {self.env_path} (permissions: 600)")

    def generate_qr_code(self, public_key: str) -> Path:
        """Generate QR code image for public key."""
        self.static_path.mkdir(parents=True, exist_ok=True)

        # Create QR with Stellar address
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(public_key)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        qr_path = self.static_path / "server_identity_qr.png"
        img.save(qr_path)
        print(f"  Created: {qr_path}")

        return qr_path

    def save_metadata(self, public_key: str, domain: str):
        """Save server metadata JSON for API."""
        self.data_path.mkdir(parents=True, exist_ok=True)

        metadata = {
            "server_address": public_key,
            "domain": domain,
            "websocket_url": f"wss://{domain}/connect",
            "api_url": f"https://{domain}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "qr_code_path": "/server-identity/qr"
        }

        meta_path = self.data_path / "server_identity.json"
        meta_path.write_text(json.dumps(metadata, indent=2))
        print(f"  Created: {meta_path}")

        return metadata

    def run(
        self,
        domain: str,
        allowed_services: str = "pintheon,ipfs",
        log_level: str = "INFO",
        force: bool = False
    ) -> dict:
        """
        Execute full identity setup.

        Args:
            domain: Domain for tunnel endpoints
            allowed_services: Comma-separated list of allowed services
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR)
            force: If True, regenerate even if identity exists

        Returns:
            dict with public_key, qr_path, env_path
        """
        print(f"\n{'='*60}")
        print("HVYM Tunnler Identity Setup")
        print(f"{'='*60}\n")

        # Check for existing identity
        if self.identity_exists() and not force:
            existing = self.load_existing_identity()
            public_key = existing.get("TUNNLER_SERVER_ADDRESS", "")

            print("Existing identity found!")
            print(f"  Server Address: {public_key}")
            print(f"  .env file: {self.env_path}")
            print("\nTo regenerate, run with --force flag.")
            print("WARNING: Regenerating will break all existing client configurations!\n")

            # Ensure QR code and metadata exist for existing identity
            if public_key:
                existing_domain = existing.get("TUNNLER_DOMAIN", domain)
                if not (self.static_path / "server_identity_qr.png").exists():
                    print("Regenerating missing QR code...")
                    self.generate_qr_code(public_key)
                if not (self.data_path / "server_identity.json").exists():
                    print("Regenerating missing metadata...")
                    self.save_metadata(public_key, existing_domain)

            return {
                "public_key": public_key,
                "qr_path": str(self.static_path / "server_identity_qr.png"),
                "env_path": str(self.env_path),
                "already_existed": True
            }

        # Generate new identity
        if force and self.identity_exists():
            print("WARNING: Force flag set. Regenerating identity...")
            print("         All existing clients will need reconfiguration!\n")

        print("Generating new Stellar keypair...")
        keypair = self.generate_keypair()

        print(f"\n  Public Address: {keypair.public_key}")
        print(f"  (Secret key stored in .env - keep it safe!)\n")

        print("Creating configuration files...")
        self.save_env_file(keypair, domain, allowed_services, log_level)

        print("\nGenerating QR code...")
        qr_path = self.generate_qr_code(keypair.public_key)

        print("\nSaving metadata...")
        self.save_metadata(keypair.public_key, domain)

        print(f"\n{'='*60}")
        print("Setup Complete!")
        print(f"{'='*60}")
        print(f"\nServer Stellar Address:")
        print(f"  {keypair.public_key}")
        print(f"\nQR Code available at:")
        print(f"  https://{domain}/server-identity/qr")
        print(f"\nIMPORTANT: Back up your .env file securely!")
        print(f"           The secret key cannot be recovered if lost.\n")

        return {
            "public_key": keypair.public_key,
            "qr_path": str(qr_path),
            "env_path": str(self.env_path),
            "already_existed": False
        }


def main():
    parser = argparse.ArgumentParser(
        description="Generate HVYM Tunnler server identity"
    )
    parser.add_argument(
        "--domain",
        default="tunnel.heavymeta.art",
        help="Domain for tunnel endpoints (default: tunnel.heavymeta.art)"
    )
    parser.add_argument(
        "--services",
        default="pintheon,ipfs",
        help="Comma-separated allowed services (default: pintheon,ipfs)"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging level (default: INFO)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Force regeneration even if identity exists (DANGER: breaks clients)"
    )
    parser.add_argument(
        "--base-path",
        default=None,
        help="Base path for hvym_tunnler (default: script's parent directory)"
    )

    args = parser.parse_args()

    # Determine base path
    if args.base_path:
        base_path = Path(args.base_path)
    else:
        # Default: parent of scripts directory
        base_path = Path(__file__).parent.parent

    base_path = base_path.resolve()

    if not base_path.exists():
        print(f"ERROR: Base path does not exist: {base_path}")
        sys.exit(1)

    # Run setup
    setup = IdentitySetup(base_path)
    result = setup.run(
        domain=args.domain,
        allowed_services=args.services,
        log_level=args.log_level,
        force=args.force
    )

    # Exit code: 0 for new identity, 0 for existing (not an error)
    sys.exit(0)


if __name__ == "__main__":
    main()
