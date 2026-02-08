"""
SSL certificate provisioning via certbot for custom domains.
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("hvym_tunnler.domains.ssl")


class SSLProvisioner:
    """Provisions and manages SSL certificates via certbot."""

    def __init__(
        self,
        webroot: str = "/var/www/acme",
        certbot_bin: str = "certbot",
        email: Optional[str] = None,
        dry_run: bool = False,
        timeout: int = 120,
    ):
        self.webroot = webroot
        self.certbot_bin = certbot_bin
        self.email = email
        self.dry_run = dry_run
        self.timeout = timeout

    async def provision(self, domain: str) -> tuple[bool, str]:
        """
        Provision an SSL certificate for a domain via certbot HTTP-01.

        Returns (success, message).
        """
        domain = domain.lower().rstrip(".")
        cmd = [
            self.certbot_bin,
            "certonly",
            "--webroot",
            "-w", self.webroot,
            "-d", domain,
            "--non-interactive",
            "--agree-tos",
        ]

        if self.email:
            cmd.extend(["--email", self.email])
        else:
            cmd.append("--register-unsafely-without-email")

        if self.dry_run:
            cmd.append("--dry-run")

        logger.info(f"Provisioning SSL cert for {domain}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )

            if process.returncode == 0:
                logger.info(f"SSL cert provisioned for {domain}")
                return True, f"Certificate provisioned for {domain}"

            error_msg = stderr.decode().strip() or stdout.decode().strip()
            logger.error(f"Certbot failed for {domain}: {error_msg}")
            return False, f"Certbot failed: {error_msg}"

        except asyncio.TimeoutError:
            logger.error(f"Certbot timed out for {domain}")
            return False, f"Certbot timed out after {self.timeout}s"
        except FileNotFoundError:
            logger.error(f"Certbot binary not found: {self.certbot_bin}")
            return False, f"Certbot not found at {self.certbot_bin}"
        except Exception as e:
            logger.error(f"SSL provisioning error for {domain}: {e}")
            return False, f"SSL provisioning error: {e}"

    async def revoke(self, domain: str) -> tuple[bool, str]:
        """
        Delete certificate for a domain.

        Returns (success, message).
        """
        domain = domain.lower().rstrip(".")
        cmd = [
            self.certbot_bin,
            "delete",
            "--cert-name", domain,
            "--non-interactive",
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )

            if process.returncode == 0:
                logger.info(f"SSL cert deleted for {domain}")
                return True, f"Certificate deleted for {domain}"

            error_msg = stderr.decode().strip() or stdout.decode().strip()
            logger.warning(f"Certbot delete failed for {domain}: {error_msg}")
            return False, f"Certbot delete failed: {error_msg}"

        except asyncio.TimeoutError:
            return False, "Certbot timed out"
        except FileNotFoundError:
            return False, f"Certbot not found at {self.certbot_bin}"
        except Exception as e:
            return False, f"Cert deletion error: {e}"

    def cert_exists(self, domain: str) -> bool:
        """Check if a certificate exists for the domain."""
        domain = domain.lower().rstrip(".")
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        return os.path.exists(cert_path)

    async def cert_expiry(self, domain: str) -> Optional[datetime]:
        """Get certificate expiry date via openssl."""
        domain = domain.lower().rstrip(".")
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"

        if not os.path.exists(cert_path):
            return None

        try:
            process = await asyncio.create_subprocess_exec(
                "openssl", "x509", "-enddate", "-noout", "-in", cert_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                process.communicate(), timeout=30
            )

            if process.returncode != 0:
                return None

            # Output format: notAfter=Mon DD HH:MM:SS YYYY GMT
            line = stdout.decode().strip()
            date_str = line.split("=", 1)[1]
            from email.utils import parsedate_to_datetime
            return parsedate_to_datetime(date_str).replace(tzinfo=timezone.utc)

        except Exception as e:
            logger.debug(f"Failed to read cert expiry for {domain}: {e}")
            return None
