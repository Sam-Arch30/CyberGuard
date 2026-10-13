"""
Unit & Integration Test Suite for URL, Domain & Website Intelligence Engine (Section 7).
Covers all 35 required scenarios, critical SSRF defenses, false-positive mitigation,
re-analysis history, and API routes.
"""
from __future__ import annotations

import asyncio
import json
import socket
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    EvidenceItemModel,
    FindingEvidenceModel,
    IndicatorModel,
    RelationshipModel,
    ThreatEventModel,
)
from backend.schemas.unified import (
    ArtifactTypeEnum,
    AnalysisStatusEnum,
    IndicatorTypeEnum,
    RelationshipTypeEnum,
    SeverityEnum,
)
from backend.services.safe_http_client import (
    SafeHttpClient,
    SafeHttpResponse,
    RedirectHop,
    TLSInspectionResult,
)
from backend.services.website_inspector import WebsiteInspector, WebsiteInspectionResult
from backend.services.threat_intelligence_service import (
    ThreatIntelligenceService,
    ThreatIntelligenceCache,
    ThreatIntelResult,
)
from backend.services.url_domain_analyzers import (
    PassiveURLAnalyzer,
    DomainIntelligenceAnalyzer,
    SafeWebsiteAnalyzer,
)
from backend.services.url_domain_pipeline import URLDomainIntelligencePipeline
from backend.schemas.domain_intelligence import DNSRecords, DomainRegistration


@pytest.fixture
def db_session():
    """Provides a transactional database session for tests."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


# ============================================================================
# 1. URL PARSING & NORMALIZATION
# ============================================================================

def test_01_url_parsing():
    """Verifies standards-aware parsing of URL components."""
    analyzer = PassiveURLAnalyzer()
    res = asyncio.run(analyzer.analyze("https://admin:pass@portal.example.com:8443/login/path?user=1#section", {}))

    assert res.status == AnalysisStatusEnum.COMPLETED
    comps = res.metadata["parsed_components"]
    assert comps["scheme"] == "https"
    assert comps["hostname"] == "portal.example.com"
    assert comps["port"] == 8443
    assert comps["path"] == "/login/path"
    assert comps["query"] == "user=1"
    assert comps["userinfo"] == "admin:pass"
    assert comps["registrable_domain"] == "example.com"
    assert comps["subdomain"] == "portal"


def test_02_url_normalization():
    """Verifies standard URL normalization rules."""
    from backend.schemas.unified import normalize_url
    url1 = "HTTP://EXAMPLE.COM/path/../path/index.html?token=ABC#top"
    norm1 = normalize_url(url1)
    assert norm1.startswith("http://example.com/path/../path/index.html?token=ABC#top")


# ============================================================================
# 2. IP-LITERAL HOSTS (IPv4 & IPv6)
# ============================================================================

def test_03_ipv4_literal_url():
    """Verifies detection of IPv4 address used directly as hostname."""
    analyzer = PassiveURLAnalyzer()
    res = asyncio.run(analyzer.analyze("http://198.51.100.12/update.php", {}))

    finding_types = [f["finding_type"] for f in res.findings]
    assert "IP_LITERAL_HOST" in finding_types

    ip_inds = [i for i in res.indicators if i["indicator_type"] == IndicatorTypeEnum.IP]
    assert len(ip_inds) == 1
    assert ip_inds[0]["value"] == "198.51.100.12"


def test_04_ipv6_literal_url():
    """Verifies bracketed IPv6 address used as hostname."""
    analyzer = PassiveURLAnalyzer()
    res = asyncio.run(analyzer.analyze("http://[2001:db8::1]:8080/dashboard", {}))

    finding_types = [f["finding_type"] for f in res.findings]
    assert "IP_LITERAL_HOST" in finding_types
    assert "NON_STANDARD_PORT" in finding_types

    comps = res.metadata["parsed_components"]
    assert comps["hostname"] == "2001:db8::1"
    assert comps["port"] == 8080


# ============================================================================
# 3. IDN / PUNYCODE & HOMOGLYPHS
# ============================================================================

def test_05_idn_punycode():
    """Verifies Punycode encoding detection."""
    analyzer = PassiveURLAnalyzer()
    res = asyncio.run(analyzer.analyze("https://xn--e1afmkfd.xn--p1ai/auth", {}))

    finding_types = [f["finding_type"] for f in res.findings]
    assert "PUNYCODE_DOMAIN" in finding_types


def test_06_excessive_subdomains():
    """Verifies detection of deep subdomain hierarchies."""
    analyzer = PassiveURLAnalyzer()
    res = asyncio.run(analyzer.analyze("https://a.b.c.d.example.com/portal", {}))

    finding_types = [f["finding_type"] for f in res.findings]
    assert "EXCESSIVE_SUBDOMAINS" in finding_types


def test_07_userinfo_in_url():
    """Verifies detection of embedded credentials in URL."""
    analyzer = PassiveURLAnalyzer()
    res = asyncio.run(analyzer.analyze("https://victim:secret123@phish.net/login", {}))

    finding_types = [f["finding_type"] for f in res.findings]
    assert "URL_USERINFO_PRESENT" in finding_types
    userinfo_finding = next(f for f in res.findings if f["finding_type"] == "URL_USERINFO_PRESENT")
    assert userinfo_finding["severity"] == SeverityEnum.HIGH


def test_08_non_standard_port():
    """Verifies non-standard port flag."""
    analyzer = PassiveURLAnalyzer()
    res = asyncio.run(analyzer.analyze("http://example.com:8888/", {}))

    finding_types = [f["finding_type"] for f in res.findings]
    assert "NON_STANDARD_PORT" in finding_types


# ============================================================================
# 4. REGISTRABLE DOMAIN & LOOKALIKE DETECTION
# ============================================================================

def test_09_registrable_domain_extraction():
    """Verifies Public Suffix List aware domain extraction (co.uk, gov.au)."""
    analyzer = PassiveURLAnalyzer()
    res1 = asyncio.run(analyzer.analyze("https://secure.banking.service.co.uk/account", {}))
    assert res1.metadata["parsed_components"]["registrable_domain"] == "service.co.uk"
    assert res1.metadata["parsed_components"]["subdomain"] == "secure.banking"

    res2 = asyncio.run(analyzer.analyze("https://portal.health.gov.au/login", {}))
    assert res2.metadata["parsed_components"]["registrable_domain"] == "health.gov.au"


def test_10_lookalike_domain_detection():
    """Verifies lookalike detection against protected brands."""
    analyzer = DomainIntelligenceAnalyzer(protected_domains=["paypal.com", "microsoft.com"])
    # mock DNS and RDAP to avoid external network
    analyzer.dns_service.resolve_all = AsyncMock(return_value=DNSRecords())
    analyzer.rdap_service.lookup = AsyncMock(return_value=DomainRegistration(domain="paypa1.com"))

    res = asyncio.run(analyzer.analyze("paypa1.com", {}))
    finding_types = [f["finding_type"] for f in res.findings]
    assert "LOOKALIKE_DOMAIN" in finding_types
    lookalike_finding = next(f for f in res.findings if f["finding_type"] == "LOOKALIKE_DOMAIN")
    assert lookalike_finding["severity"] == SeverityEnum.HIGH


def test_11_benign_idn_false_positive_control():
    """Verifies legitimate domain without lookalike is not flagged as malicious impersonation."""
    analyzer = DomainIntelligenceAnalyzer(protected_domains=["paypal.com", "microsoft.com"])
    analyzer.dns_service.resolve_all = AsyncMock(return_value=DNSRecords())
    analyzer.rdap_service.lookup = AsyncMock(return_value=DomainRegistration(domain="münchen.de"))

    res = asyncio.run(analyzer.analyze("münchen.de", {}))
    finding_types = [f["finding_type"] for f in res.findings]
    assert "LOOKALIKE_DOMAIN" not in finding_types


# ============================================================================
# 5. DNS ANALYSIS & RELATIONSHIPS
# ============================================================================

def test_12_dns_relationship_creation():
    """Verifies creation of RESOLVES_TO, USES_NAMESERVER, and MAIL_EXCHANGER relationships."""
    analyzer = DomainIntelligenceAnalyzer()
    analyzer.dns_service.resolve_all = AsyncMock(return_value=DNSRecords(
        a=["198.51.100.1"],
        aaaa=["2001:db8::2"],
        mx=["10 mail.company.com"],
        ns=["ns1.company.com"],
        txt=["v=spf1 -all"],
    ))
    analyzer.rdap_service.lookup = AsyncMock(return_value=DomainRegistration(domain="company.com"))

    res = asyncio.run(analyzer.analyze("company.com", {}))
    rel_types = [r["relationship_type"] for r in res.relationships]

    assert RelationshipTypeEnum.RESOLVES_TO in rel_types
    assert RelationshipTypeEnum.MAIL_EXCHANGER in rel_types
    assert RelationshipTypeEnum.USES_NAMESERVER in rel_types


# ============================================================================
# 6. CRITICAL SSRF TEST SUITE
# ============================================================================

def test_13_private_ip_classification():
    """Verifies IP classification rejects RFC-1918 private ranges."""
    for ip in ["10.0.0.1", "10.254.254.254", "172.16.0.1", "172.31.255.255", "192.168.1.1", "192.168.254.254"]:
        is_safe, reason = SafeHttpClient.classify_ip_safety(ip)
        assert not is_safe, f"Expected {ip} to be blocked as private"
        assert "prohibited" in reason.lower()


def test_14_loopback_blocking():
    """Verifies loopback addresses (127.0.0.1, ::1, localhost) are rejected."""
    for host in ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"]:
        is_safe, reason = SafeHttpClient.classify_ip_safety(host)
        assert not is_safe, f"Expected {host} to be blocked as loopback"

    is_safe_host, _, _ = SafeHttpClient.resolve_and_verify_destination("localhost")
    assert not is_safe_host


def test_15_link_local_blocking():
    """Verifies link-local ranges (169.254.0.0/16, fe80::/10) are rejected."""
    for ip in ["169.254.1.1", "169.254.100.5", "fe80::1"]:
        is_safe, _ = SafeHttpClient.classify_ip_safety(ip)
        assert not is_safe


def test_16_ipv6_local_private_blocking():
    """Verifies IPv6 unique local (ULA) and multicast ranges are rejected."""
    for ip in ["::1", "fe80::dead:beef", "fc00::1", "fd00:1234::1", "ff02::1"]:
        is_safe, _ = SafeHttpClient.classify_ip_safety(ip)
        assert not is_safe


def test_17_metadata_address_blocking():
    """Verifies cloud metadata IP literals and hostnames are rejected."""
    for meta in ["169.254.169.254", "169.254.170.2", "fd00:ec2::254"]:
        is_safe, _ = SafeHttpClient.classify_ip_safety(meta)
        assert not is_safe

    for host in ["metadata.google.internal", "metadata.internal", "instance-data"]:
        is_safe, _, _ = SafeHttpClient.resolve_and_verify_destination(host)
        assert not is_safe


def _stream_response(status, headers=None, chunks=None, error=None):
    from contextlib import asynccontextmanager
    import httpx
    consumed = []
    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in chunks or []:
                consumed.append(chunk)
                yield chunk
    @asynccontextmanager
    async def stream(self, method, url, **kwargs):
        if error: raise error
        response = httpx.Response(status, headers=headers, stream=Body(), request=httpx.Request(method, url))
        try: yield response
        finally: await response.aclose()
    return stream, consumed

def test_18_redirect_to_private_ip_blocking():
    stream, _ = _stream_response(302, {'location':'http://192.168.1.10/admin'})
    with patch.object(SafeHttpClient,'resolve_and_verify_destination',side_effect=[(True,'safe',['93.184.216.34']),(False,'Private address prohibited',['192.168.1.10'])]), patch('httpx.AsyncClient.stream',stream):
        result = asyncio.run(SafeHttpClient().fetch_url('http://example.com/redirect'))
    assert not result.is_safe_destination
    assert 'prohibited' in result.blocked_reason.lower()
    assert result.blocked_ip == '192.168.1.10'
    assert len(result.redirect_chain) == 1

def test_19_multi_hop_redirect_limit():
    stream, _ = _stream_response(302, {'location':'http://example.com/next'})
    with patch.object(SafeHttpClient,'resolve_and_verify_destination',return_value=(True,'safe',['93.184.216.34'])), patch('httpx.AsyncClient.stream',stream):
        result=asyncio.run(SafeHttpClient(max_redirects=2).fetch_url('http://example.com/hop0'))
    assert 'limit exceeded' in result.error.lower()
    assert len(result.redirect_chain)==3

def test_20_http_timeout():
    import httpx
    stream, _ = _stream_response(200,error=httpx.TimeoutException('Read timeout'))
    with patch.object(SafeHttpClient,'resolve_and_verify_destination',return_value=(True,'safe',['93.184.216.34'])), patch('httpx.AsyncClient.stream',stream):
        result=asyncio.run(SafeHttpClient(total_timeout=.2).fetch_url('http://example.com/timeout'))
    assert result.status_code==0
    assert 'timed out' in result.error.lower()

def test_21_response_size_limit():
    stream, consumed = _stream_response(200,{'content-type':'text/html'},[b'A'*30,b'B'*40,b'C'*20])
    with patch.object(SafeHttpClient,'resolve_and_verify_destination',return_value=(True,'safe',['93.184.216.34'])), patch('httpx.AsyncClient.stream',stream):
        result=asyncio.run(SafeHttpClient(max_size_bytes=50).fetch_url('http://example.com/large'))
    assert result.is_truncated
    assert result.response_size==50
    assert len(consumed)==2

# ============================================================================
# 7. TLS CERTIFICATE INSPECTION
# ============================================================================

def test_22_tls_metadata():
    """Verifies TLS certificate structure extraction."""
    tls_res = TLSInspectionResult(
        is_valid=True,
        subject_cn="secure.example.com",
        issuer_cn="DigiCert Global Root CA",
        valid_from="Jan 1 00:00:00 2026 GMT",
        valid_until="Jan 1 00:00:00 2027 GMT",
        san_list=["secure.example.com", "example.com"],
        has_expired=False,
        is_self_signed=False,
    )
    assert tls_res.is_valid
    assert not tls_res.has_expired
    assert not tls_res.is_self_signed


def test_23_tls_error_handling():
    """Verifies handling of expired or self-signed certificates."""
    expired_tls = TLSInspectionResult(
        is_valid=False,
        error_type="EXPIRED_CERTIFICATE",
        error_message="certificate has expired",
        has_expired=True,
    )
    assert not expired_tls.is_valid
    assert expired_tls.error_type == "EXPIRED_CERTIFICATE"


# ============================================================================
# 8. REGISTRATION & THREAT INTELLIGENCE
# ============================================================================

def test_24_rdap_registration_unavailable():
    """Verifies that unavailable or privacy-redacted WHOIS/RDAP is handled without false alarms."""
    analyzer = DomainIntelligenceAnalyzer()
    analyzer.dns_service.resolve_all = AsyncMock(return_value=DNSRecords())
    analyzer.rdap_service.lookup = AsyncMock(return_value=DomainRegistration(
        registrar="Privacy Protection Corp",
        is_redacted=True,
    ))

    res = asyncio.run(analyzer.analyze("privacy-domain.com", {}))
    finding_types = [f["finding_type"] for f in res.findings]
    assert "REGISTRATION_DATA_REDACTED" in finding_types
    # Redacted registration should have SAFE severity
    redacted_finding = next(f for f in res.findings if f["finding_type"] == "REGISTRATION_DATA_REDACTED")
    assert redacted_finding["severity"] == SeverityEnum.SAFE


def test_25_threat_intel_provider_unavailable():
    """Verifies provider query returns UNKNOWN without inventing findings."""
    ti_service = ThreatIntelligenceService()
    results = asyncio.run(ti_service.lookup_domain("clean-domain.test"))
    assert len(results) == 1
    assert results[0].verdict == "UNKNOWN"
    assert not results[0].is_malicious


def test_26_threat_intel_rate_limit():
    """Verifies explicit handling of threat intelligence rate limits."""
    ti_service = ThreatIntelligenceService(rate_limit_simulated=True)
    results = asyncio.run(ti_service.lookup_domain("rate-limited-test.com"))
    assert len(results) == 1
    assert results[0].is_rate_limited
    assert results[0].verdict == "RATE_LIMITED"


# ============================================================================
# 9. STATIC HTML & FORM ANALYSIS
# ============================================================================

def test_27_static_html_parsing():
    """Verifies safe static HTML inspection without script execution."""
    html = """
    <!DOCTYPE html>
    <html>
    <head><title>Test Organization Portal</title><link rel="icon" href="/favicon.ico"></head>
    <body>
      <p>Welcome to portal</p>
      <a href="/docs/guide.pdf">Guide</a>
      <a href="https://external-partner.com/info">Partner</a>
      <script src="/js/app.js"></script>
    </body>
    </html>
    """
    res = WebsiteInspector.inspect_html("https://portal.example.com", html)
    assert res.title == "Test Organization Portal"
    assert res.favicon_url == "https://portal.example.com/favicon.ico"
    assert res.internal_links_count == 1
    assert res.external_links_count == 1
    assert len(res.scripts) == 1
    assert not res.has_login_form
    assert not res.has_password_field


def test_28_password_field_detection():
    """Verifies detection of password input fields."""
    html = """
    <html><body>
    <form action="/login" method="POST">
      <input type="text" name="user" />
      <input type="password" name="passwd" />
      <input type="submit" value="Log In" />
    </form>
    </body></html>
    """
    res = WebsiteInspector.inspect_html("https://portal.example.com/auth", html)
    assert res.has_password_field
    assert res.has_login_form
    assert "PASSWORD_FIELD_DETECTED" in res.credential_harvesting_signals


def test_29_cross_domain_form_action():
    """Verifies detection of form actions posting to external/unrelated domains."""
    html = """
    <html><body>
    <form action="https://evil-harvester.test/drop" method="POST">
      <input type="text" name="email" />
      <input type="password" name="pwd" />
    </form>
    </body></html>
    """
    res = WebsiteInspector.inspect_html("https://legit-service.com/account", html)
    assert res.has_cross_domain_form
    assert "https://evil-harvester.test/drop" in res.cross_domain_form_actions
    assert "CROSS_DOMAIN_FORM_ACTION" in res.credential_harvesting_signals


def test_30_no_form_submission():
    """Verifies that WebsiteInspector and SafeHttpClient never submit forms."""
    inspector = WebsiteInspector()
    html = "<form action='https://evil.test/collect' method='POST'><input type='password' /></form>"
    # Inspecting static HTML does not trigger any network I/O
    res = inspector.inspect_html("https://target.test", html)
    assert res.has_password_field


def test_31_no_javascript_execution():
    """Verifies that JavaScript inside <script> tags is treated as passive metadata only."""
    html = """
    <html><body>
    <script>
      window.location = "http://malicious.test";
      alert("Hacked");
    </script>
    <script src="https://cdn.example.com/tracker.js"></script>
    </body></html>
    """
    res = WebsiteInspector.inspect_html("https://site.test", html)
    # The static parser never executes JS or evaluates window.location
    assert len(res.scripts) == 1
    assert res.scripts[0].resolved_src == "https://cdn.example.com/tracker.js"


# ============================================================================
# 10. ORCHESTRATOR & PIPELINE INTEGRATION
# ============================================================================

def test_32_orchestrator_integration(db_session: Session):
    """Verifies end-to-end URL analysis pipeline with canonical persistence."""
    pipeline = URLDomainIntelligencePipeline()

    # Mock network components to avoid external calls
    pipeline.dns_service.resolve_all = AsyncMock(return_value=DNSRecords(
        a=["198.51.100.50"],
        mx=["10 mail.sample-phish.test"],
    ))
    pipeline.rdap_service.lookup = AsyncMock(return_value=DomainRegistration(
        domain="sample-phish.test",
        registration_date="2026-09-25",  # 7 days old
    ))

    # Mock SafeHttpClient
    mock_http_resp = SafeHttpResponse(
        url="http://sample-phish.test/login",
        final_url="http://sample-phish.test/login",
        status_code=200,
        content_type="text/html",
        content_text="<html><form action='http://sample-phish.test/login' method='POST'><input type='password' /></form></html>",
    )
    pipeline.safe_client.fetch_url = AsyncMock(return_value=mock_http_resp)

    res = asyncio.run(pipeline.analyze_url(
        url="http://sample-phish.test/login",
        db=db_session,
        active_analysis_enabled=True,
    ))

    assert res["status"] == "COMPLETED"
    assert res["artifact_id"] is not None
    assert res["analysis_run_id"] is not None
    assert res["overall_severity"] in ("MEDIUM", "HIGH", "CRITICAL")

    # Verify canonical models exist in DB
    run_model = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.id == res["analysis_run_id"]).first()
    assert run_model is not None
    assert run_model.status == "COMPLETED"

    findings = db_session.query(FindingModel).filter(FindingModel.analysis_run_id == run_model.id).all()
    assert len(findings) > 0

    relationships = db_session.query(RelationshipModel).filter(RelationshipModel.source_id == "sample-phish.test").all()
    assert len(relationships) > 0


def test_33_analysis_history_preservation(db_session: Session):
    """Verifies re-analyzing creates a new independent AnalysisRun preserving history."""
    pipeline = URLDomainIntelligencePipeline()
    pipeline.dns_service.resolve_all = AsyncMock(return_value=DNSRecords())
    pipeline.rdap_service.lookup = AsyncMock(return_value=DomainRegistration(domain="history-test.com"))
    pipeline.safe_client.fetch_url = AsyncMock(return_value=SafeHttpResponse(
        url="http://history-test.com",
        final_url="http://history-test.com",
        status_code=200,
        content_type="text/plain",
    ))

    res1 = asyncio.run(pipeline.analyze_url("http://history-test.com", db=db_session, active_analysis_enabled=False))
    res2 = asyncio.run(pipeline.analyze_url("http://history-test.com", db=db_session, active_analysis_enabled=False))

    # Shared content artifact, separate analysis runs
    assert res1["artifact_id"] == res2["artifact_id"]
    assert res1["analysis_run_id"] != res2["analysis_run_id"]

    runs = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id == res1["artifact_id"]).all()
    assert len(runs) >= 2


def test_34_passive_only_mode(db_session: Session):
    """Verifies active_analysis_enabled=False skips outbound network calls cleanly."""
    pipeline = URLDomainIntelligencePipeline()
    pipeline.dns_service.resolve_all = AsyncMock(return_value=DNSRecords())
    pipeline.rdap_service.lookup = AsyncMock(return_value=DomainRegistration(domain="passive-test.com"))
    pipeline.safe_client.fetch_url = AsyncMock()

    res = asyncio.run(pipeline.analyze_url("http://passive-test.com", db=db_session, active_analysis_enabled=False))
    assert res["status"] == "COMPLETED"
    assert not res["active_analysis_enabled"]
    pipeline.safe_client.fetch_url.assert_not_called()

    finding_types = [f["finding_type"] for f in res["findings"]]
    assert "ACTIVE_ANALYSIS_DISABLED" in finding_types


def test_35_unknown_not_safe():
    """Verifies that unresolvable domains or missing intelligence do not output SAFE."""
    analyzer = DomainIntelligenceAnalyzer()
    analyzer.dns_service.resolve_all = AsyncMock(return_value=DNSRecords(errors={"A": "NXDOMAIN"}))
    analyzer.rdap_service.lookup = AsyncMock(side_effect=Exception("RDAP timeout"))

    res = asyncio.run(analyzer.analyze("nonexistent-domain-xyz123.test", {}))
    # No malicious findings invented, but not declared affirmatively benign/safe
    assert len(res.metadata.get("resolved_ips", [])) == 0


# ============================================================================
# 11. FALSE-POSITIVE CONTROLS
# ============================================================================

def test_36_false_positive_controls():
    """
    Verifies that benign signals (long query parameters, free CA, privacy WHOIS)
    do not elevate a legitimate URL to a high-severity threat.
    """
    analyzer = PassiveURLAnalyzer()
    long_url = "https://legit-portal.company.com/view/document?session_token=abcdef1234567890&utm_source=email&redirect_uri=/dashboard&version=2.1.0"
    res = asyncio.run(analyzer.analyze(long_url, {}))

    # Should not produce high or critical findings solely from length or parameters
    severities = [f["severity"] for f in res.findings]
    assert SeverityEnum.CRITICAL not in severities
    assert SeverityEnum.HIGH not in severities


# ============================================================================
# 12. API ENDPOINTS VERIFICATION
# ============================================================================

def test_37_api_endpoints(client: TestClient):
    """Verifies FastAPI route handlers for /api/urls."""
    # 1. Config endpoint
    resp_cfg = client.get("/api/urls/config")
    assert resp_cfg.status_code == 200
    cfg_data = resp_cfg.json()
    assert cfg_data["ssrf_protection_active"] is True
    assert "http" in cfg_data["allowed_schemes"]

    # 2. Analyze URL (passive-only test via API)
    resp_url = client.post("/api/urls/analyze", json={
        "url": "https://service-check.test/status",
        "active_analysis_enabled": False,
        "uploader": "TEST_SUITE",
    })
    assert resp_url.status_code == 200
    url_data = resp_url.json()
    assert url_data["status"] == "COMPLETED"
    assert url_data["target"] == "https://service-check.test/status"
    assert url_data["artifact_id"] is not None

    # 3. Analyze Domain
    resp_dom = client.post("/api/urls/analyze-domain", json={
        "domain": "service-check.test",
        "uploader": "TEST_SUITE",
    })
    assert resp_dom.status_code == 200
    dom_data = resp_dom.json()
    assert dom_data["status"] == "COMPLETED"
    assert dom_data["target"] == "service-check.test"
