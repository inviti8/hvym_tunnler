"""
DNS verification for custom domains.
"""

import logging
import socket
from typing import List, Optional, Tuple

try:
    import dns.resolver
    import dns.name
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

logger = logging.getLogger("hvym_tunnler.domains.verification")


class DomainVerifier:
    """Verifies domain ownership via DNS records."""

    def __init__(self, tunnel_domain: str = "tunnel.heavymeta.art"):
        self.tunnel_domain = tunnel_domain.lower().rstrip(".")

    def _get_resolver(self) -> "dns.resolver.Resolver":
        resolver = dns.resolver.Resolver()
        resolver.timeout = 10
        resolver.lifetime = 10
        return resolver

    async def verify_cname(self, domain: str) -> Tuple[bool, str]:
        """
        Verify that domain has a CNAME pointing to the tunnel domain.

        Falls back to A record IP comparison if no CNAME is found.
        Returns (success, message).
        """
        if not DNS_AVAILABLE:
            return False, "dnspython not installed"

        domain = domain.lower().rstrip(".")
        resolver = self._get_resolver()

        # Check CNAME
        try:
            answers = resolver.resolve(domain, "CNAME")
            for rdata in answers:
                target = str(rdata.target).rstrip(".")
                if target.lower() == self.tunnel_domain:
                    return True, f"CNAME verified: {domain} -> {target}"
            # CNAME exists but points elsewhere
            targets = [str(r.target).rstrip(".") for r in answers]
            return False, (
                f"CNAME exists but points to {', '.join(targets)}, "
                f"expected {self.tunnel_domain}"
            )
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            return False, f"Domain {domain} does not exist (NXDOMAIN)"
        except Exception as e:
            logger.debug(f"CNAME lookup failed for {domain}: {e}")

        # Fallback: compare A record IPs
        try:
            domain_ips = self._resolve_a_records(domain, resolver)
            tunnel_ips = self._resolve_a_records(self.tunnel_domain, resolver)
            if domain_ips and tunnel_ips and domain_ips & tunnel_ips:
                return True, (
                    f"A record verified: {domain} resolves to same IP as "
                    f"{self.tunnel_domain}"
                )
            if not domain_ips:
                return False, f"No A records found for {domain}"
            return False, (
                f"{domain} resolves to {', '.join(domain_ips)}, "
                f"but {self.tunnel_domain} resolves to {', '.join(tunnel_ips)}"
            )
        except Exception as e:
            return False, f"DNS verification failed: {e}"

    def _resolve_a_records(
        self, domain: str, resolver: "dns.resolver.Resolver"
    ) -> set:
        """Resolve A records for a domain."""
        ips = set()
        try:
            answers = resolver.resolve(domain, "A")
            for rdata in answers:
                ips.add(str(rdata))
        except Exception:
            pass
        return ips

    async def verify_txt(
        self,
        domain: str,
        stellar_address: str,
        token: str,
    ) -> Tuple[bool, str]:
        """
        Verify TXT record at _hvym-verify.{domain}.

        Expected record: hvym-verify={stellar_address}:{token}
        """
        if not DNS_AVAILABLE:
            return False, "dnspython not installed"

        domain = domain.lower().rstrip(".")
        txt_domain = f"_hvym-verify.{domain}"
        expected = f"hvym-verify={stellar_address}:{token}"
        resolver = self._get_resolver()

        try:
            answers = resolver.resolve(txt_domain, "TXT")
            for rdata in answers:
                # TXT records may be split into multiple strings
                txt_value = "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in rdata.strings
                )
                if txt_value == expected:
                    return True, f"TXT record verified at {txt_domain}"
            # Records exist but none match
            found = [
                "".join(
                    s.decode() if isinstance(s, bytes) else s
                    for s in r.strings
                )
                for r in answers
            ]
            return False, (
                f"TXT records found at {txt_domain} but none match. "
                f"Found: {found}, expected: {expected}"
            )
        except dns.resolver.NoAnswer:
            return False, f"No TXT records found at {txt_domain}"
        except dns.resolver.NXDOMAIN:
            return False, f"{txt_domain} does not exist (NXDOMAIN)"
        except Exception as e:
            return False, f"TXT verification failed: {e}"

    def get_verification_instructions(
        self,
        domain: str,
        method: str,
        stellar_address: str,
        token: str,
    ) -> dict:
        """Return human-readable DNS instructions for domain verification."""
        domain = domain.lower().rstrip(".")

        if method == "cname":
            return {
                "method": "cname",
                "instructions": (
                    f"Add a CNAME record for {domain} pointing to "
                    f"{self.tunnel_domain}"
                ),
                "record_type": "CNAME",
                "record_name": domain,
                "record_value": self.tunnel_domain,
            }
        else:
            txt_value = f"hvym-verify={stellar_address}:{token}"
            return {
                "method": "txt",
                "instructions": (
                    f"Add a TXT record at _hvym-verify.{domain} with value: "
                    f"{txt_value}"
                ),
                "record_type": "TXT",
                "record_name": f"_hvym-verify.{domain}",
                "record_value": txt_value,
            }
