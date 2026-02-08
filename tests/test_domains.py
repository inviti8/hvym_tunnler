"""
Tests for custom domain support.
"""

import pytest
import asyncio
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app.domains.models import CustomDomain
from app.domains.registry import DomainRegistry
from app.domains.verification import DomainVerifier


# ── CustomDomain model tests ────────────────────────────────────────


class TestCustomDomainModel:
    def test_creation_defaults(self):
        domain = CustomDomain(
            domain="gallery.example.com",
            stellar_address="GABCDEF1234567890",
        )
        assert domain.domain == "gallery.example.com"
        assert domain.stellar_address == "GABCDEF1234567890"
        assert domain.status == "pending_verification"
        assert domain.verification_method == "cname"
        assert len(domain.verification_token) > 0
        assert domain.ssl_provisioned is False
        assert domain.verified_at is None
        assert domain.ssl_expires_at is None
        assert isinstance(domain.created_at, datetime)

    def test_serialization_roundtrip(self):
        domain = CustomDomain(
            domain="art.example.com",
            stellar_address="GXYZ9876543210",
            verification_method="txt",
        )
        data = domain.to_dict()
        restored = CustomDomain.from_dict(data)

        assert restored.domain == domain.domain
        assert restored.stellar_address == domain.stellar_address
        assert restored.status == domain.status
        assert restored.verification_method == domain.verification_method
        assert restored.verification_token == domain.verification_token
        assert restored.ssl_provisioned == domain.ssl_provisioned

    def test_serialization_with_dates(self):
        now = datetime.now(timezone.utc)
        domain = CustomDomain(
            domain="test.example.com",
            stellar_address="GTEST123",
            status="verified",
            verified_at=now,
            last_checked_at=now,
            ssl_provisioned=True,
            ssl_expires_at=now + timedelta(days=90),
        )
        data = domain.to_dict()
        restored = CustomDomain.from_dict(data)

        assert restored.verified_at is not None
        assert restored.last_checked_at is not None
        assert restored.ssl_provisioned is True
        assert restored.ssl_expires_at is not None

    def test_api_response_hides_token_when_verified(self):
        domain = CustomDomain(
            domain="gallery.example.com",
            stellar_address="GABCDEF",
            status="verified",
            verified_at=datetime.now(timezone.utc),
        )
        resp = domain.to_api_response()
        assert "verification_token" not in resp
        assert resp["status"] == "verified"

    def test_api_response_shows_token_when_pending(self):
        domain = CustomDomain(
            domain="gallery.example.com",
            stellar_address="GABCDEF",
        )
        resp = domain.to_api_response()
        assert "verification_token" in resp
        assert resp["status"] == "pending_verification"

    def test_unique_tokens(self):
        d1 = CustomDomain(domain="a.example.com", stellar_address="G1")
        d2 = CustomDomain(domain="b.example.com", stellar_address="G2")
        assert d1.verification_token != d2.verification_token


# ── DomainRegistry tests ────────────────────────────────────────────


class TestDomainRegistry:
    @pytest.fixture
    def domain_registry(self):
        """In-memory domain registry (no Redis)."""
        reg = DomainRegistry(max_domains_per_address=5)
        reg._use_redis = False
        return reg

    @pytest.mark.asyncio
    async def test_register_and_get(self, domain_registry):
        entry = CustomDomain(
            domain="gallery.example.com",
            stellar_address="GABCDEF",
        )
        await domain_registry.register(entry)
        result = await domain_registry.get("gallery.example.com")
        assert result is not None
        assert result.domain == "gallery.example.com"
        assert result.stellar_address == "GABCDEF"

    @pytest.mark.asyncio
    async def test_case_insensitive(self, domain_registry):
        entry = CustomDomain(
            domain="Gallery.Example.COM",
            stellar_address="GABCDEF",
        )
        await domain_registry.register(entry)
        result = await domain_registry.get("gallery.example.com")
        assert result is not None

    @pytest.mark.asyncio
    async def test_duplicate_rejection(self, domain_registry):
        entry = CustomDomain(
            domain="gallery.example.com",
            stellar_address="GABCDEF",
        )
        await domain_registry.register(entry)

        entry2 = CustomDomain(
            domain="gallery.example.com",
            stellar_address="GOTHER",
        )
        with pytest.raises(ValueError, match="already registered"):
            await domain_registry.register(entry2)

    @pytest.mark.asyncio
    async def test_per_address_limit(self, domain_registry):
        domain_registry.max_domains_per_address = 2

        for i in range(2):
            entry = CustomDomain(
                domain=f"d{i}.example.com",
                stellar_address="GABCDEF",
            )
            await domain_registry.register(entry)

        entry3 = CustomDomain(
            domain="d2.example.com",
            stellar_address="GABCDEF",
        )
        with pytest.raises(ValueError, match="Maximum"):
            await domain_registry.register(entry3)

    @pytest.mark.asyncio
    async def test_delete(self, domain_registry):
        entry = CustomDomain(
            domain="gallery.example.com",
            stellar_address="GABCDEF",
        )
        await domain_registry.register(entry)
        assert await domain_registry.delete("gallery.example.com") is True
        assert await domain_registry.get("gallery.example.com") is None
        assert await domain_registry.delete("gallery.example.com") is False

    @pytest.mark.asyncio
    async def test_list_by_address(self, domain_registry):
        for i in range(3):
            entry = CustomDomain(
                domain=f"d{i}.example.com",
                stellar_address="GABCDEF",
            )
            await domain_registry.register(entry)

        # Different address
        other = CustomDomain(
            domain="other.example.com",
            stellar_address="GOTHER",
        )
        await domain_registry.register(other)

        results = await domain_registry.list_by_address("GABCDEF")
        assert len(results) == 3

        results2 = await domain_registry.list_by_address("GOTHER")
        assert len(results2) == 1

    @pytest.mark.asyncio
    async def test_lookup_returns_only_verified(self, domain_registry):
        entry = CustomDomain(
            domain="pending.example.com",
            stellar_address="GABCDEF",
            status="pending_verification",
        )
        await domain_registry.register(entry)

        # lookup should reject pending domains
        result = await domain_registry.lookup("pending.example.com")
        assert result is None

        # Update to verified
        entry.status = "verified"
        await domain_registry.update(entry)

        # Now lookup should return it
        result = await domain_registry.lookup("pending.example.com")
        assert result is not None
        assert result.status == "verified"

    @pytest.mark.asyncio
    async def test_lookup_cache(self, domain_registry):
        entry = CustomDomain(
            domain="cached.example.com",
            stellar_address="GABCDEF",
            status="verified",
        )
        await domain_registry.register(entry)

        # First lookup populates cache
        r1 = await domain_registry.lookup("cached.example.com")
        assert r1 is not None

        # Delete from store; cache should still serve it
        domain_registry._memory_store.pop("cached.example.com", None)

        r2 = await domain_registry.lookup("cached.example.com")
        assert r2 is not None

    @pytest.mark.asyncio
    async def test_cleanup_expired_pending(self, domain_registry):
        old = CustomDomain(
            domain="old.example.com",
            stellar_address="GABCDEF",
            status="pending_verification",
            created_at=datetime.now(timezone.utc) - timedelta(hours=100),
        )
        recent = CustomDomain(
            domain="recent.example.com",
            stellar_address="GABCDEF",
            status="pending_verification",
        )
        verified = CustomDomain(
            domain="verified.example.com",
            stellar_address="GABCDEF",
            status="verified",
            created_at=datetime.now(timezone.utc) - timedelta(hours=100),
        )

        await domain_registry.register(old)
        await domain_registry.register(recent)
        await domain_registry.register(verified)

        removed = await domain_registry.cleanup_expired_pending(expiry_hours=72)
        assert removed == 1

        assert await domain_registry.get("old.example.com") is None
        assert await domain_registry.get("recent.example.com") is not None
        assert await domain_registry.get("verified.example.com") is not None

    @pytest.mark.asyncio
    async def test_update(self, domain_registry):
        entry = CustomDomain(
            domain="upd.example.com",
            stellar_address="GABCDEF",
        )
        await domain_registry.register(entry)

        entry.status = "verified"
        entry.verified_at = datetime.now(timezone.utc)
        await domain_registry.update(entry)

        result = await domain_registry.get("upd.example.com")
        assert result.status == "verified"
        assert result.verified_at is not None


# ── DomainVerifier tests ────────────────────────────────────────────


class TestDomainVerifier:
    def test_cname_instructions(self):
        verifier = DomainVerifier(tunnel_domain="tunnel.hvym.link")
        instructions = verifier.get_verification_instructions(
            domain="gallery.example.com",
            method="cname",
            stellar_address="GABCDEF",
            token="test_token",
        )
        assert instructions["method"] == "cname"
        assert instructions["record_type"] == "CNAME"
        assert instructions["record_value"] == "tunnel.hvym.link"
        assert "gallery.example.com" in instructions["instructions"]

    def test_txt_instructions(self):
        verifier = DomainVerifier(tunnel_domain="tunnel.hvym.link")
        instructions = verifier.get_verification_instructions(
            domain="gallery.example.com",
            method="txt",
            stellar_address="GABCDEF",
            token="test_token",
        )
        assert instructions["method"] == "txt"
        assert instructions["record_type"] == "TXT"
        assert instructions["record_name"] == "_hvym-verify.gallery.example.com"
        assert "GABCDEF:test_token" in instructions["record_value"]


class TestDomainVerifierDNS:
    """Tests requiring mocked DNS lookups."""

    @pytest.mark.asyncio
    async def test_verify_cname_success(self):
        verifier = DomainVerifier(tunnel_domain="tunnel.hvym.link")

        mock_rdata = MagicMock()
        mock_rdata.target = MagicMock()
        mock_rdata.target.__str__ = lambda _: "tunnel.hvym.link."

        mock_answers = [mock_rdata]

        with patch("app.domains.verification.DNS_AVAILABLE", True):
            with patch.object(
                verifier, "_get_resolver"
            ) as mock_resolver_factory:
                mock_resolver = MagicMock()
                mock_resolver.resolve.return_value = mock_answers
                mock_resolver_factory.return_value = mock_resolver

                success, msg = await verifier.verify_cname("gallery.example.com")
                assert success is True
                assert "CNAME verified" in msg

    @pytest.mark.asyncio
    async def test_verify_txt_success(self):
        verifier = DomainVerifier(tunnel_domain="tunnel.hvym.link")

        expected_value = "hvym-verify=GABCDEF:my_token"
        mock_rdata = MagicMock()
        mock_rdata.strings = [expected_value.encode()]

        mock_answers = [mock_rdata]

        with patch("app.domains.verification.DNS_AVAILABLE", True):
            with patch.object(
                verifier, "_get_resolver"
            ) as mock_resolver_factory:
                mock_resolver = MagicMock()
                mock_resolver.resolve.return_value = mock_answers
                mock_resolver_factory.return_value = mock_resolver

                success, msg = await verifier.verify_txt(
                    "gallery.example.com", "GABCDEF", "my_token"
                )
                assert success is True
                assert "TXT record verified" in msg

    @pytest.mark.asyncio
    async def test_verify_txt_wrong_token(self):
        verifier = DomainVerifier(tunnel_domain="tunnel.hvym.link")

        mock_rdata = MagicMock()
        mock_rdata.strings = [b"hvym-verify=GABCDEF:wrong_token"]

        mock_answers = [mock_rdata]

        with patch("app.domains.verification.DNS_AVAILABLE", True):
            with patch.object(
                verifier, "_get_resolver"
            ) as mock_resolver_factory:
                mock_resolver = MagicMock()
                mock_resolver.resolve.return_value = mock_answers
                mock_resolver_factory.return_value = mock_resolver

                success, msg = await verifier.verify_txt(
                    "gallery.example.com", "GABCDEF", "correct_token"
                )
                assert success is False
                assert "none match" in msg
