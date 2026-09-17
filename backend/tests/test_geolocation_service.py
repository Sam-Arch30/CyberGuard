"""
Unit and Integration Tests for MailTraceAI Geolocation & IP Intelligence Security.
Covers all 12 mandated test scenarios:
1. Valid API configuration
2. Missing API key
3. Invalid API key
4. Provider timeout
5. HTTP 429 / rate limit
6. Invalid IP
7. Private IP (RFC 1918)
8. Reserved / Loopback IP
9. Successful geolocation
10. Cached geolocation
11. Provider unavailable / network failure
12. Malformed provider response
+ Strict security validation ensuring credentials are never exposed in responses or logs.
"""
import pytest
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas.ip_intelligence import IPIntelligence, GeolocationResponse, GeolocationStatusResponse
from backend.config.geolocation_config import GeolocationConfig
from backend.services.ip_cache import IPIntelligenceCache
from backend.services.ip_providers import IPApiProvider, IPInfoProvider, MockIPIntelligenceProvider
from backend.services.geolocation_service import GeolocationService


# -----------------------------------------------------------------------------
# 1. Valid API Configuration
# -----------------------------------------------------------------------------
def test_valid_api_configuration():
    # Inject synthetic dummy test key (never a real secret)
    config = GeolocationConfig(provider="ipapi", api_key="dummy_valid_test_token_12345")
    assert config.is_configured is True
    assert config.provider == "ipapi"

    status = config.get_provider_status()
    assert status["status"] == "Configured"
    assert status["tier"] == "authenticated_pro"
    # STRICT SECURITY: Ensure key is not in status
    assert "dummy_valid_test_token_12345" not in str(status)


# -----------------------------------------------------------------------------
# 2. Missing API Key
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_missing_api_key():
    config = GeolocationConfig(provider="ipinfo", api_key="")
    assert config.is_configured is False
    status = config.get_provider_status()
    assert status["status"] == "Not Configured"

    # IPInfoProvider requires a key; when missing, returns safe clean error
    provider = IPInfoProvider(config=config, api_key=None, require_key=True)
    res = await provider.lookup("203.0.113.10")

    assert res.enrichment_available is False
    assert "The geolocation provider has not been configured" in (res.error or "")


# -----------------------------------------------------------------------------
# 3. Invalid API Key
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_invalid_api_key():
    config = GeolocationConfig(provider="ipapi", api_key="invalid_test_key")
    provider = IPApiProvider(config=config, api_key="invalid_test_key")

    mock_resp = MagicMock()
    mock_resp.status_code = 401

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await provider.lookup("203.0.113.15")

    assert res.enrichment_available is False
    assert "Invalid or unauthorized API key" in (res.error or "")
    # Ensure invalid key string itself is NOT leaked in the error
    assert "invalid_test_key" not in (res.error or "")


# -----------------------------------------------------------------------------
# 4. Provider Timeout
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_provider_timeout():
    config = GeolocationConfig(provider="ipapi", api_key="dummy_timeout_test_key")
    provider = IPApiProvider(config=config, api_key="dummy_timeout_test_key")

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.TimeoutException("Connection timed out")
        res = await provider.lookup("203.0.113.20")

    assert res.enrichment_available is False
    assert res.error == "Provider request timeout"


# -----------------------------------------------------------------------------
# 5. HTTP 429 / Rate Limit
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_rate_limit_exceeded():
    config = GeolocationConfig(provider="ipapi", api_key="dummy_key")
    provider = IPApiProvider(config=config, api_key="dummy_key")

    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await provider.lookup("203.0.113.25")

    assert res.enrichment_available is False
    assert "Rate limit exceeded" in (res.error or "")


# -----------------------------------------------------------------------------
# 6. Invalid IP
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_invalid_ip_formats():
    provider = IPApiProvider()
    invalid_ips = ["999.999.999.999", "not_an_ip", "http://malicious.com", "1.2.3.4.5", ""]

    for bad_ip in invalid_ips:
        res = await provider.lookup(bad_ip)
        assert res.enrichment_available is False
        assert "Invalid IP address format" in (res.error or "")


# -----------------------------------------------------------------------------
# 7. Private IP (RFC 1918)
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_private_ip_rfc1918():
    provider = IPApiProvider()
    private_ips = ["10.0.0.1", "192.168.1.254", "172.16.5.10", "172.31.255.255"]

    for priv_ip in private_ips:
        res = await provider.lookup(priv_ip)
        assert res.enrichment_available is False
        assert res.scope == "private"
        assert "Private/Reserved Address" in (res.error or "")


# -----------------------------------------------------------------------------
# 8. Reserved & Loopback IP
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_reserved_and_loopback_ip():
    provider = IPApiProvider()
    reserved_ips = ["127.0.0.1", "0.0.0.0", "169.254.169.254", "::1"]

    for r_ip in reserved_ips:
        res = await provider.lookup(r_ip)
        assert res.enrichment_available is False
        assert res.scope in ("private", "loopback", "reserved")
        assert "Private/Reserved Address" in (res.error or "")


# -----------------------------------------------------------------------------
# 9. Successful Geolocation
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_successful_geolocation():
    config = GeolocationConfig(provider="ipapi", api_key="dummy_pro_key")
    provider = IPApiProvider(config=config, api_key="dummy_pro_key")
    cache = IPIntelligenceCache()
    service = GeolocationService(config=config, provider=provider, cache=cache)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "regionName": "Hesse",
        "city": "Frankfurt",
        "lat": 50.1109,
        "lon": 8.6821,
        "timezone": "Europe/Berlin",
        "isp": "Test Cloud Provider",
        "org": "Test Cloud GmbH",
        "as": "AS20000 Test Network",
        "proxy": False,
        "hosting": True
    }

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        geo = await service.get_geolocation("203.0.113.55")

    assert geo.ip == "203.0.113.55"
    assert geo.country == "Germany"
    assert geo.country_code == "DE"
    assert geo.city == "Frankfurt"
    assert geo.latitude == 50.1109
    assert geo.longitude == 8.6821
    assert geo.asn == "AS20000"
    assert geo.cached is False
    assert geo.error is None
    # Forensic accuracy notice check
    assert "estimated location of observed network infrastructure" in geo.notice
    # Security: No credentials in response
    assert not hasattr(geo, "api_key")
    assert not hasattr(geo, "token")


# -----------------------------------------------------------------------------
# 10. Cached Geolocation
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_cached_geolocation():
    config = GeolocationConfig(provider="mock")
    cache = IPIntelligenceCache()
    service = GeolocationService(config=config, cache=cache)

    # 1st lookup -> external/mock, cached=False
    geo1 = await service.get_geolocation("203.0.113.88")
    assert geo1.cached is False

    # 2nd lookup -> retrieved from cache, cached=True
    geo2 = await service.get_geolocation("203.0.113.88")
    assert geo2.cached is True
    assert geo2.source == "backend_cache"
    assert geo2.city == geo1.city


# -----------------------------------------------------------------------------
# 11. Provider Unavailable / Network Failure
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_provider_unavailable():
    config = GeolocationConfig(provider="ipapi", api_key="dummy_key")
    provider = IPApiProvider(config=config, api_key="dummy_key")

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = httpx.ConnectError("Network unreachable")
        res = await provider.lookup("203.0.113.60")

    assert res.enrichment_available is False
    assert "Geolocation provider temporarily unavailable" in (res.error or "")


# -----------------------------------------------------------------------------
# 12. Malformed Provider Response
# -----------------------------------------------------------------------------
@pytest.mark.anyio
async def test_malformed_provider_response():
    config = GeolocationConfig(provider="ipapi", api_key="dummy_key")
    provider = IPApiProvider(config=config, api_key="dummy_key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.side_effect = ValueError("Invalid JSON stream")

    with patch.object(httpx.AsyncClient, "get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = mock_resp
        res = await provider.lookup("203.0.113.70")

    assert res.enrichment_available is False
    assert "Malformed response" in (res.error or "")


# -----------------------------------------------------------------------------
# 13. API Endpoint Security & Status Tests
# -----------------------------------------------------------------------------
def test_status_endpoint_never_leaks_secrets():
    client = TestClient(app)
    response = client.get("/api/intelligence/geolocation/status")
    assert response.status_code == 200
    data = response.json()

    assert "status" in data
    assert data["status"] in ("Configured", "Not Configured")
    assert "provider" in data

    # Verify no secret fields exist in JSON response
    assert "api_key" not in data
    assert "token" not in data
    assert "secret" not in data
    assert "authorization" not in data


def test_ip_geolocation_endpoint_sanitization():
    client = TestClient(app)
    response = client.get("/api/intelligence/ip/127.0.0.1/geolocation")
    assert response.status_code == 200
    data = response.json()

    assert data["ip"] == "127.0.0.1"
    assert "Private/Reserved Address" in (data["error"] or "")
    assert "notice" in data
    assert "estimated location of observed network infrastructure" in data["notice"]

    # Strict secret leak assertion
    for forbidden in ("api_key", "token", "password", "auth", "secret"):
        assert forbidden not in data
