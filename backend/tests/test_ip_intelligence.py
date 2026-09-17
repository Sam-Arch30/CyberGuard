import pytest
import asyncio
from typing import Optional
from backend.schemas.ip_intelligence import IPIntelligence
from backend.services.ip_providers import BaseIPIntelligenceProvider, MockIPIntelligenceProvider
from backend.services.ip_cache import IPIntelligenceCache
from backend.services.ip_intelligence_service import IPIntelligenceService


class ErrorThrowingProvider(BaseIPIntelligenceProvider):
    async def lookup(self, ip: str) -> IPIntelligence:
        raise RuntimeError("Simulated upstream provider failure")


class RateLimitProvider(BaseIPIntelligenceProvider):
    async def lookup(self, ip: str) -> IPIntelligence:
        return IPIntelligence(
            ip=ip,
            scope="public",
            enrichment_available=False,
            error="Rate limit exceeded for IP intelligence provider"
        )


class MissingFieldsProvider(BaseIPIntelligenceProvider):
    async def lookup(self, ip: str) -> IPIntelligence:
        return IPIntelligence(
            ip=ip,
            scope="public",
            enrichment_available=True,
            country=None,
            city=None,
            asn="AS9999",
            infrastructure_type="Observed infrastructure location"
        )


class CountingProvider(BaseIPIntelligenceProvider):
    def __init__(self):
        self.call_count = 0

    async def lookup(self, ip: str) -> IPIntelligence:
        self.call_count += 1
        return IPIntelligence(
            ip=ip,
            scope="public",
            enrichment_available=True,
            country="Germany",
            country_code="DE",
            city="Frankfurt",
            asn="AS54321"
        )


@pytest.mark.anyio
async def test_valid_public_ip_lookup():
    mock_p = MockIPIntelligenceProvider()
    svc = IPIntelligenceService(provider=mock_p, cache=IPIntelligenceCache())
    res = await svc.get_ip_intelligence("185.220.101.5")

    assert res.ip == "185.220.101.5"
    assert res.scope == "public"
    assert res.enrichment_available is True
    assert res.country is not None
    assert res.asn is not None
    assert res.error is None


@pytest.mark.anyio
async def test_private_ip_bypasses_provider():
    counter_p = CountingProvider()
    svc = IPIntelligenceService(provider=counter_p, cache=IPIntelligenceCache())

    # Test RFC 1918 192.168.1.1 and 10.0.0.1 and loopback 127.0.0.1
    res = await svc.get_ip_intelligence("192.168.1.1")
    assert res.ip == "192.168.1.1"
    assert res.scope == "private"
    assert res.enrichment_available is False
    assert counter_p.call_count == 0  # Bypassed provider entirely!

    res2 = await svc.get_ip_intelligence("127.0.0.1")
    assert res2.scope == "private"
    assert res2.enrichment_available is False
    assert counter_p.call_count == 0


@pytest.mark.anyio
async def test_provider_error_graceful_fallback():
    err_p = ErrorThrowingProvider()
    svc = IPIntelligenceService(provider=err_p, cache=IPIntelligenceCache())
    res = await svc.get_ip_intelligence("203.0.113.50")

    assert res.ip == "203.0.113.50"
    assert res.enrichment_available is False
    assert res.error is not None
    assert "Simulated upstream provider failure" in res.error


@pytest.mark.anyio
async def test_rate_limit_handling():
    rate_p = RateLimitProvider()
    svc = IPIntelligenceService(provider=rate_p, cache=IPIntelligenceCache())
    res = await svc.get_ip_intelligence("198.51.100.22")

    assert res.enrichment_available is False
    assert res.error == "Rate limit exceeded for IP intelligence provider"


@pytest.mark.anyio
async def test_missing_fields_graceful_handling():
    missing_p = MissingFieldsProvider()
    svc = IPIntelligenceService(provider=missing_p, cache=IPIntelligenceCache())
    res = await svc.get_ip_intelligence("198.51.100.33")

    assert res.ip == "198.51.100.33"
    assert res.country is None
    assert res.city is None
    assert res.asn == "AS9999"
    assert res.enrichment_available is True


@pytest.mark.anyio
async def test_ipv6_lookup():
    mock_p = MockIPIntelligenceProvider()
    svc = IPIntelligenceService(provider=mock_p, cache=IPIntelligenceCache())
    res = await svc.get_ip_intelligence("2001:db8::1")

    assert res.ip == "2001:db8::1"
    assert res.scope == "public"
    assert res.enrichment_available is True


@pytest.mark.anyio
async def test_cache_hit_prevents_duplicate_provider_calls():
    counter_p = CountingProvider()
    cache = IPIntelligenceCache()
    svc = IPIntelligenceService(provider=counter_p, cache=cache)

    # First lookup (cache miss)
    res1 = await svc.get_ip_intelligence("203.0.113.99")
    assert counter_p.call_count == 1
    assert res1.country == "Germany"

    # Second lookup for same IP (cache hit)
    res2 = await svc.get_ip_intelligence("203.0.113.99")
    assert counter_p.call_count == 1  # Provider call count MUST stay 1!
    assert res2.country == "Germany"
