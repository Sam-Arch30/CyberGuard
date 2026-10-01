import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient

from backend.main import app
from backend.schemas.domain_intelligence import DNSRecords, DomainRegistration, DomainIntelligence
from backend.services.dns_service import DNSService
from backend.services.rdap_service import RDAPService
from backend.services.domain_cache import DomainIntelligenceCache
from backend.services.domain_intelligence_service import DomainIntelligenceService

client = TestClient(app)


@pytest.fixture
def mock_services():
    mock_dns = MagicMock(spec=DNSService)
    mock_rdap = MagicMock(spec=RDAPService)
    cache = DomainIntelligenceCache()
    service = DomainIntelligenceService(
        dns_service=mock_dns,
        rdap_service=mock_rdap,
        cache=cache,
        new_domain_threshold_days=30
    )
    return service, mock_dns, mock_rdap, cache


@pytest.mark.anyio
async def test_valid_domain_dns_and_rdap(mock_services):
    """Test full enrichment of a valid domain with DNS and RDAP registration data."""
    service, mock_dns, mock_rdap, _ = mock_services

    mock_dns.resolve_records = AsyncMock(return_value=(
        DNSRecords(
            a=["93.184.216.34"],
            aaaa=["2606:2800:220:1:248:1893:25c8:1946"],
            mx=["10 mail.example.com"],
            ns=["a.iana-servers.net", "b.iana-servers.net"],
            txt=["v=spf1 -all"]
        ),
        True,
        "Active / Resolvable",
        None
    ))

    mock_rdap.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registrar="Example Registrar LLC",
        registration_date="2015-08-14T04:00:00Z",
        expiration_date="2028-08-13T04:00:00Z",
        nameservers=["a.iana-servers.net", "b.iana-servers.net"],
        status=["clientTransferProhibited"],
        registration_source="RDAP"
    ))

    intel = await service.lookup_domain("example.com")

    assert intel.domain == "example.com"
    assert intel.is_resolvable is True
    assert intel.status_message == "Active / Resolvable"
    assert intel.dns.a == ["93.184.216.34"]
    assert intel.dns.mx == ["10 mail.example.com"]
    assert intel.registration.registrar == "Example Registrar LLC"
    assert intel.domain_age_days is not None
    assert intel.domain_age_days > 365
    assert intel.newly_registered_domain is False


@pytest.mark.anyio
async def test_nxdomain_handling(mock_services):
    """Test handling of non-existent domain (NXDOMAIN) returning graceful unresolvable state."""
    service, mock_dns, mock_rdap, _ = mock_services

    mock_dns.resolve_records = AsyncMock(return_value=(
        DNSRecords(),
        False,
        "NXDOMAIN (Domain does not exist in DNS)",
        None
    ))

    mock_rdap.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registration_source="unavailable",
        status=["Domain not found in RDAP"]
    ))

    intel = await service.lookup_domain("nonexistent-threat-domain-xyz123.com")

    assert intel.is_resolvable is False
    assert "NXDOMAIN" in (intel.status_message or "")
    assert intel.dns.a == []
    assert intel.domain_age_days is None
    assert intel.newly_registered_domain is None


@pytest.mark.anyio
async def test_timeout_handling(mock_services):
    """Test graceful handling when DNS and RDAP queries encounter timeouts."""
    service, mock_dns, mock_rdap, _ = mock_services

    mock_dns.resolve_records = AsyncMock(return_value=(
        DNSRecords(),
        False,
        "DNS Resolution Timeout",
        None
    ))

    mock_rdap.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registration_source="unavailable",
        status=["RDAP connection timeout or network error"]
    ))

    intel = await service.lookup_domain("timeout-domain.org")

    assert intel.is_resolvable is False
    assert "Timeout" in (intel.status_message or "")
    assert intel.domain_age_days is None
    assert intel.registration.registration_source == "unavailable"


@pytest.mark.anyio
async def test_missing_rdap_data(mock_services):
    """Test domain with valid DNS but missing RDAP registration data does not invent domain age."""
    service, mock_dns, mock_rdap, _ = mock_services

    mock_dns.resolve_records = AsyncMock(return_value=(
        DNSRecords(a=["192.0.2.1"]),
        True,
        "Active / Resolvable",
        None
    ))

    mock_rdap.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registrar=None,
        registration_date=None,
        expiration_date=None,
        registration_source="unavailable",
        status=["RDAP data unavailable"]
    ))

    intel = await service.lookup_domain("private-corp.local")

    assert intel.is_resolvable is True
    assert intel.registration.registration_date is None
    # Crucial: Age must NOT be invented
    assert intel.domain_age_days is None
    assert intel.newly_registered_domain is None


@pytest.mark.anyio
async def test_idn_punycode_domain(mock_services):
    """Test Internationalized Domain Name (IDN) normalization and punycode generation."""
    service, mock_dns, mock_rdap, _ = mock_services

    mock_dns.resolve_records = AsyncMock(return_value=(
        DNSRecords(a=["192.0.2.5"]),
        True,
        "Active / Resolvable",
        "xn--mnchen-3ya.de"
    ))

    mock_rdap.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registrar="DENIC eG",
        registration_source="RDAP"
    ))

    intel = await service.lookup_domain("münchen.de")

    assert intel.domain == "münchen.de"
    assert intel.punycode == "xn--mnchen-3ya.de"
    assert intel.is_resolvable is True


@pytest.mark.anyio
async def test_multiple_mx_records_sorting():
    """Test DNSService sorting of multiple MX records by preference ascending."""
    dns_service = DNSService()

    # Create mock MX answers with out-of-order preferences
    mock_ans = [
        MagicMock(preference=20, exchange=MagicMock(to_text=lambda: "alt.mail.com.")),
        MagicMock(preference=5, exchange=MagicMock(to_text=lambda: "primary.mail.com.")),
        MagicMock(preference=10, exchange=MagicMock(to_text=lambda: "backup.mail.com.")),
    ]

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = mock_ans

    rtype, records, err = dns_service._query_record_sync(mock_resolver, "example.com", "MX")

    assert rtype == "MX"
    assert err is None
    assert len(records) == 3
    # Check ascending sort by priority
    assert records[0] == "5 primary.mail.com"
    assert records[1] == "10 backup.mail.com"
    assert records[2] == "20 alt.mail.com"


@pytest.mark.anyio
async def test_newly_registered_domain_flag(mock_services):
    """Test domain registered under 30 days receives newly_registered_domain = True as neutral indicator."""
    service, mock_dns, mock_rdap, _ = mock_services

    # Created 12 days ago
    recent_date = (datetime.now(timezone.utc) - timedelta(days=12)).strftime("%Y-%m-%dT%H:%M:%SZ")

    mock_dns.resolve_records = AsyncMock(return_value=(
        DNSRecords(a=["203.0.113.10"]),
        True,
        "Active / Resolvable",
        None
    ))

    mock_rdap.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registrar="FastReg Inc.",
        registration_date=recent_date,
        registration_source="RDAP"
    ))

    intel = await service.lookup_domain("brand-new-site.xyz")

    assert intel.domain_age_days == 12
    assert intel.newly_registered_domain is True


@pytest.mark.anyio
async def test_domain_intelligence_cache_hit(mock_services):
    """Test repeated lookups hit the thread-safe TTL cache without issuing redundant network queries."""
    service, mock_dns, mock_rdap, cache = mock_services

    mock_dns.resolve_records = AsyncMock(return_value=(
        DNSRecords(a=["1.2.3.4"]),
        True,
        "Active / Resolvable",
        None
    ))
    mock_rdap.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registrar="Cache Test Registrar",
        registration_source="RDAP"
    ))

    # First lookup (Cache Miss)
    intel1 = await service.lookup_domain("cached-domain.com")
    assert mock_dns.resolve_records.call_count == 1
    assert mock_rdap.lookup_domain.call_count == 1
    assert len(cache) == 1

    # Second lookup (Cache Hit)
    intel2 = await service.lookup_domain("cached-domain.com")
    assert mock_dns.resolve_records.call_count == 1
    assert mock_rdap.lookup_domain.call_count == 1
    assert intel2.domain == intel1.domain
    assert intel2.dns.a == ["1.2.3.4"]


def test_api_lookup_domain_endpoint():
    """Test GET /api/emails/lookup-domain/{domain} endpoint returns valid schema."""
    with patch("backend.api.routes.email.global_domain_service.lookup_domain") as mock_lookup:
        mock_lookup.return_value = DomainIntelligence(
            domain="api-test.com",
            dns=DNSRecords(a=["93.184.216.34"], mx=["10 mail.api-test.com"]),
            registration=DomainRegistration(
                registrar="Test Registrar",
                registration_date="2020-01-01T00:00:00Z",
                registration_source="RDAP"
            ),
            domain_age_days=1500,
            newly_registered_domain=False,
            is_resolvable=True,
            status_message="Active / Resolvable"
        )

        response = client.get("/api/emails/lookup-domain/api-test.com")
        assert response.status_code == 200
        data = response.json()

        assert data["domain"] == "api-test.com"
        assert data["dns"]["a"] == ["93.184.216.34"]
        assert data["registration"]["registrar"] == "Test Registrar"
        assert data["domain_age_days"] == 1500
        assert data["newly_registered_domain"] is False


def test_whois_service_parsing():
    """Test parsing of raw WHOIS output with registration date, expiration, and registrar."""
    from backend.services.whois_service import WHOISService

    whois_text = """
    Domain Name: EXAMPLE.COM
    Registry Domain ID: 2138514_DOMAIN_COM-VRSN
    Registrar WHOIS Server: whois.markmonitor.com
    Registrar: MarkMonitor Inc.
    Creation Date: 1997-09-15T04:00:00Z
    Registry Expiry Date: 2028-09-14T04:00:00Z
    Name Server: NS1.EXAMPLE.COM
    Name Server: NS2.EXAMPLE.COM
    Domain Status: clientDeleteProhibited
    """
    service = WHOISService()
    registrar, reg_date, exp_date, ns, statuses = service._parse_whois_response(whois_text)

    assert registrar == "MarkMonitor Inc."
    assert reg_date == "1997-09-15T04:00:00Z"
    assert exp_date == "2028-09-14T04:00:00Z"
    assert "ns1.example.com" in ns
    assert "ns2.example.com" in ns
    assert "clientDeleteProhibited" in statuses


@pytest.mark.anyio
async def test_rdap_subdomain_apex_resolution():
    """Test that a subdomain query falls back to apex domain when subdomain is not in RDAP."""
    from backend.services.rdap_service import RDAPService

    rdap_service = RDAPService()

    # Mock _query_single_rdap: return None for mail.company.com, return valid for company.com
    async def mock_query(client, target):
        if target == "mail.company.com":
            return None
        elif target == "company.com":
            return DomainRegistration(
                registrar="Apex Registrar Inc.",
                registration_date="2010-05-20T00:00:00Z",
                registration_source="RDAP"
            )
        return None

    rdap_service._query_single_rdap = mock_query
    res = await rdap_service.lookup_domain("mail.company.com")

    assert res.registration_source == "RDAP"
    assert res.registrar == "Apex Registrar Inc."
    assert res.registration_date == "2010-05-20T00:00:00Z"


@pytest.mark.anyio
async def test_rdap_whois_fallback():
    """Test fallback to WHOIS service when RDAP returns unavailable."""
    from backend.services.rdap_service import RDAPService
    from backend.services.whois_service import WHOISService

    mock_whois = MagicMock(spec=WHOISService)
    mock_whois.lookup_domain = AsyncMock(return_value=DomainRegistration(
        registrar="WHOIS Registrar Ltd.",
        registration_date="1998-01-01T00:00:00Z",
        registration_source="WHOIS"
    ))

    rdap_service = RDAPService(whois_service=mock_whois)
    rdap_service._query_single_rdap = AsyncMock(return_value=None)

    res = await rdap_service.lookup_domain("cc-tld-domain.ru")

    assert res.registration_source == "WHOIS"
    assert res.registrar == "WHOIS Registrar Ltd."
    assert res.registration_date == "1998-01-01T00:00:00Z"


def test_robust_date_formats():
    """Test _calculate_domain_age parsing dot-delimited, slash-delimited, and ISO dates."""
    service = DomainIntelligenceService()

    # ISO
    age1, new1 = service._calculate_domain_age("2020-01-01T00:00:00Z")
    assert age1 is not None and age1 > 1000
    assert new1 is False

    # Dot-separated (e.g. WHOIS 1997.09.23)
    age2, new2 = service._calculate_domain_age("1997.09.23")
    assert age2 is not None and age2 > 7000
    assert new2 is False

    # Date only (recent within 30 days)
    recent_date = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")
    age3, new3 = service._calculate_domain_age(recent_date)
    assert age3 is not None and age3 >= 0
    assert new3 is True  # Within 30 days

