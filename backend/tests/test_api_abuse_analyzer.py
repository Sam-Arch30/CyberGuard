"""
Comprehensive Test Suite for Section 11 — API Abuse Detection Engine.
Validates normalization, secret redaction, token fingerprinting, rate & burst analysis,
endpoint/resource enumeration, auth & authz failures, session anomalies,
data volume & scraping, composite abuse hypotheses, database persistence,
cross-module correlations (Sections 9 & 10), false-positive safety, and performance.
"""
import json
import time
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    ThreatEventModel,
    EntityModel,
    IndicatorModel,
)
from backend.schemas.unified import ArtifactTypeEnum, SeverityEnum
from backend.schemas.api_security import (
    HTTPMethodEnum,
    ClientTypeEnum,
    APIConfigResponse,
    NormalizedAPIEvent,
    AccountAPIBaselineProfile,
)
from backend.services.api_analyzers import (
    APISecretRedactor,
    EndpointNormalizer,
    MethodNormalizer,
    ClientClassifier,
    GenericJsonApiAdapter,
    GenericCsvApiAdapter,
    GatewayJsonApiAdapter,
    ApiAdapterRegistry,
    APIRateBurstEngine,
    APIEnumerationEngine,
    APIAuthFailureEngine,
    APIMethodPrivilegeEngine,
    APISessionAnomalyEngine,
    APIVolumeScrapingEngine,
    APIPatternAggregator,
)
from backend.services.api_pipeline import APISecurityPipeline, global_api_pipeline


@pytest.fixture
def db_session():
    """Provides an isolated database session."""
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    """FastAPI test client."""
    return TestClient(app)


# ============================================================================
# 1. NORMALIZATION & ADAPTER TESTS
# ============================================================================

def test_01_generic_json_normalization():
    adapter = GenericJsonApiAdapter()
    raw = {
        "id": "evt-001",
        "timestamp": "2026-10-02T12:00:00Z",
        "method": "POST",
        "endpoint": "/api/v1/users/1001",
        "status_code": 201,
        "source_ip": "198.51.100.22",
        "account_id": "alice",
        "session_id": "sess-abc-123",
        "response_bytes": 1024,
        "duration_ms": 45.2,
    }
    assert adapter.can_handle(raw) is True
    event = adapter.normalize(raw)

    assert event.id == "evt-001"
    assert event.method == HTTPMethodEnum.POST
    assert event.raw_method == "POST"
    assert event.route_template == "/api/v1/users/{id}"
    assert event.resource_type == "users"
    assert event.resource_id_hash is not None
    assert event.status_code == 201
    assert event.source_ip == "198.51.100.22"
    assert event.account_id == "alice"
    assert event.session_id == "sess-abc-123"
    assert event.response_bytes == 1024
    assert event.duration_ms == 45.2


def test_02_generic_csv_normalization():
    adapter = GenericCsvApiAdapter()
    row = {
        "timestamp": "2026-10-02 12:05:00",
        "method": "GET",
        "path": "/api/v1/products/550e8400-e29b-41d4-a716-446655440000",
        "status": "200",
        "ip": "203.0.113.5",
        "user": "bob",
        "bytes": "2048",
    }
    assert adapter.can_handle(row) is True
    event = adapter.normalize(row)

    assert event.provider == "generic_csv"
    assert event.method == HTTPMethodEnum.GET
    assert event.route_template == "/api/v1/products/{uuid}"
    assert event.status_code == 200
    assert event.source_ip == "203.0.113.5"
    assert event.account_id == "bob"
    assert event.response_bytes == 2048


def test_03_gateway_json_normalization():
    adapter = GatewayJsonApiAdapter()
    raw = {
        "client_ip": "192.0.2.77",
        "started_at": 1790942400000,
        "request": {
            "method": "DELETE",
            "uri": "/api/v1/documents/doc-archive-123",
            "size": 150,
            "headers": {
                "user-agent": "curl/7.88.1",
                "authorization": "Bearer super-secret-token-xyz",
            }
        },
        "response": {
            "status": 204,
            "size": 0,
        },
        "latencies": {
            "request": 12.5,
        },
        "service": {"name": "document-service"},
    }
    assert adapter.can_handle(raw) is True
    event = adapter.normalize(raw)

    assert event.provider == "gateway_json"
    assert event.method == HTTPMethodEnum.DELETE
    assert event.status_code == 204
    assert event.source_ip == "192.0.2.77"
    assert event.service == "document-service"
    assert event.token_fingerprint is not None
    assert event.token_fingerprint.startswith("tkfp_")
    # Verify raw secret is NEVER in event
    assert "super-secret-token-xyz" not in str(event.model_dump())


def test_04_timestamp_normalization():
    adapter = GenericJsonApiAdapter()

    # ISO format
    e1 = adapter.normalize({"endpoint": "/test", "method": "GET", "timestamp": "2026-10-02T10:15:30Z"})
    assert e1.timestamp.year == 2026 and e1.timestamp.hour == 10

    # Epoch milliseconds
    e2 = adapter.normalize({"endpoint": "/test", "method": "GET", "timestamp": 1790942400000})
    assert e2.timestamp.tzinfo is not None

    # Epoch seconds
    e3 = adapter.normalize({"endpoint": "/test", "method": "GET", "timestamp": 1790942400})
    assert e3.timestamp.tzinfo is not None


def test_05_method_normalization():
    assert MethodNormalizer.normalize("GET")[0] == HTTPMethodEnum.GET
    assert MethodNormalizer.normalize("post")[0] == HTTPMethodEnum.POST
    assert MethodNormalizer.normalize("PATCH")[0] == HTTPMethodEnum.PATCH
    assert MethodNormalizer.normalize("DELETE")[0] == HTTPMethodEnum.DELETE
    assert MethodNormalizer.normalize("CUSTOM_VERB")[0] == HTTPMethodEnum.OTHER
    assert MethodNormalizer.normalize("CUSTOM_VERB")[1] == "CUSTOM_VERB"


def test_06_route_normalization_conservative():
    # Numeric ID
    t1, res1, h1 = EndpointNormalizer.normalize_endpoint("/api/v1/users/1001")
    assert t1 == "/api/v1/users/{id}"
    assert res1 == "users"
    assert h1 is not None

    # UUID
    t2, res2, h2 = EndpointNormalizer.normalize_endpoint("/api/orders/550e8400-e29b-41d4-a716-446655440000")
    assert t2 == "/api/orders/{uuid}"
    assert res2 == "orders"

    # Hex Hash
    t3, res3, h3 = EndpointNormalizer.normalize_endpoint("/api/blobs/64b5f92a1c0d48f764b5f92a1c0d48f7")
    assert t3 == "/api/blobs/{hash}"

    # Date
    t4, res4, h4 = EndpointNormalizer.normalize_endpoint("/api/reports/2026-10-02")
    assert t4 == "/api/reports/{date}"

    # Static routes MUST be preserved and NOT converted to placeholders
    t5, res5, h5 = EndpointNormalizer.normalize_endpoint("/api/v1/users/me")
    assert t5 == "/api/v1/users/me"

    t6, res6, h6 = EndpointNormalizer.normalize_endpoint("/api/v1/export")
    assert t6 == "/api/v1/export"


# ============================================================================
# 2. PRIVACY & SECRET REDACTION TESTS
# ============================================================================

def test_07_query_secret_redaction():
    raw_uri = "/api/v1/search?q=cyberguard&token=secret_12345&api_key=my_key_999&limit=50"
    clean_uri, meta = APISecretRedactor.redact_url_path_and_query(raw_uri)

    assert "secret_12345" not in clean_uri
    assert "my_key_999" not in clean_uri
    assert "token=%5BREDACTED_BY_CYBERGUARD%5D" in clean_uri or "token=[REDACTED_BY_CYBERGUARD]" in clean_uri
    assert meta["q"] == "cyberguard"
    assert meta["limit"] == "50"
    assert meta["token"] == "[REDACTED_BY_CYBERGUARD]"
    assert meta["api_key"] == "[REDACTED_BY_CYBERGUARD]"


def test_08_header_and_dict_secret_redaction():
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer confidential_bearer_token",
        "Cookie": "session_id=confidential_session_secret",
        "X-API-Key": "secret_api_key_header",
        "User-Agent": "Mozilla/5.0",
    }
    redacted = APISecretRedactor.redact_dict(headers)

    assert "confidential_bearer_token" not in str(redacted)
    assert "confidential_session_secret" not in str(redacted)
    assert "secret_api_key_header" not in str(redacted)
    assert redacted["Authorization"] == "[REDACTED_BY_CYBERGUARD]"
    assert redacted["Cookie"] == "[REDACTED_BY_CYBERGUARD]"
    assert redacted["X-API-Key"] == "[REDACTED_BY_CYBERGUARD]"
    assert redacted["Content-Type"] == "application/json"


def test_09_token_fingerprinting():
    token_1 = "Bearer my-secret-jwt-token-alpha"
    token_2 = "my-secret-jwt-token-alpha"  # same token without bearer
    token_3 = "different-secret-token"

    fp1 = APISecretRedactor.fingerprint_token(token_1)
    fp2 = APISecretRedactor.fingerprint_token(token_2)
    fp3 = APISecretRedactor.fingerprint_token(token_3)

    assert fp1 is not None and fp1.startswith("tkfp_")
    # Bearer normalization produces identical fingerprint
    assert fp1 == fp2
    assert fp1 != fp3
    # Verify raw secret cannot be reversed
    assert "my-secret" not in fp1


# ============================================================================
# 3. RATE & BURST DETECTION TESTS
# ============================================================================

def test_10_high_request_rate_detection():
    config = APIConfigResponse(rate_threshold_human=10, rate_window_seconds=60)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id=f"evt-{i}",
            timestamp=base_time + timedelta(seconds=i * 2),  # 15 requests in 30 seconds
            source_ip="198.51.100.10",
            account_id="user_spammer",
            method=HTTPMethodEnum.GET,
            endpoint=f"/api/v1/items/{i}",
            route_template="/api/v1/items/{id}",
            status_code=200,
        )
        for i in range(15)
    ]

    findings = APIRateBurstEngine.analyze(events, config)
    rate_findings = [f for f in findings if f.finding_type == "HIGH_API_REQUEST_RATE"]

    assert len(rate_findings) >= 1
    rf = rate_findings[0]
    assert rf.rule_id == "API_RATE_001"
    assert rf.severity == SeverityEnum.MEDIUM
    assert rf.target_account == "user_spammer"
    assert any(e.key == "request_count_in_window" and int(e.value) >= 10 for e in rf.evidence_items)


def test_11_request_burst_detection():
    config = APIConfigResponse(burst_threshold=15, burst_window_seconds=10)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    # 20 requests in 5 seconds
    events = [
        NormalizedAPIEvent(
            id=f"burst-{i}",
            timestamp=base_time + timedelta(milliseconds=i * 250),
            source_ip="198.51.100.11",
            session_id="sess_bursty",
            method=HTTPMethodEnum.GET,
            endpoint=f"/api/v1/feed",
            status_code=200,
        )
        for i in range(20)
    ]

    findings = APIRateBurstEngine.analyze(events, config)
    burst_findings = [f for f in findings if f.finding_type == "API_REQUEST_BURST"]

    assert len(burst_findings) >= 1
    bf = burst_findings[0]
    assert bf.rule_id == "API_BURST_001"
    assert bf.severity == SeverityEnum.LOW
    assert bf.target_session == "sess_bursty"


# ============================================================================
# 4. ENUMERATION TESTS
# ============================================================================

def test_12_endpoint_enumeration():
    config = APIConfigResponse(endpoint_enum_distinct_threshold=5, endpoint_enum_window_seconds=120)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    routes = ["/api/v1/auth", "/api/v1/users", "/api/v1/orders", "/api/v1/billing", "/api/v1/admin", "/api/v1/tokens"]
    events = [
        NormalizedAPIEvent(
            id=f"enum-e-{i}",
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="198.51.100.12",
            account_id="scanner_bob",
            method=HTTPMethodEnum.GET,
            endpoint=routes[i],
            route_template=routes[i],
            status_code=200,
        )
        for i in range(len(routes))
    ]

    findings = APIEnumerationEngine.analyze(events, config)
    enum_findings = [f for f in findings if f.finding_type == "API_ENDPOINT_ENUMERATION_PATTERN"]

    assert len(enum_findings) >= 1
    ef = enum_findings[0]
    assert ef.rule_id == "API_ENUM_001"
    assert ef.severity == SeverityEnum.MEDIUM
    assert ef.target_account == "scanner_bob"


def test_13_resource_enumeration():
    config = APIConfigResponse(resource_enum_distinct_threshold=8, resource_enum_window_seconds=180)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    # Ingest traversal across /api/v1/records/1001, 1002, 1003...
    events = []
    for i in range(12):
        t, r_type, r_hash = EndpointNormalizer.normalize_endpoint(f"/api/v1/records/{1000 + i}")
        events.append(NormalizedAPIEvent(
            id=f"enum-r-{i}",
            timestamp=base_time + timedelta(seconds=i * 2),
            source_ip="198.51.100.13",
            session_id="sess_harvester",
            method=HTTPMethodEnum.GET,
            endpoint=f"/api/v1/records/{1000 + i}",
            route_template=t,
            resource_type=r_type,
            resource_id_hash=r_hash,
            status_code=200,
        ))

    findings = APIEnumerationEngine.analyze(events, config)
    res_findings = [f for f in findings if f.finding_type == "RESOURCE_ENUMERATION_PATTERN"]

    assert len(res_findings) >= 1
    rf = res_findings[0]
    assert rf.rule_id == "API_ENUM_002"
    assert rf.severity == SeverityEnum.HIGH
    assert rf.target_session == "sess_harvester"
    assert rf.target_endpoint == "/api/v1/records/{id}"


# ============================================================================
# 5. AUTH & AUTHORIZATION FAILURE TESTS
# ============================================================================

def test_14_repeated_authentication_failures():
    config = APIConfigResponse(auth_failure_threshold=5, auth_failure_window_seconds=300)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id=f"auth-fail-{i}",
            timestamp=base_time + timedelta(seconds=i * 10),
            source_ip="198.51.100.14",
            account_id="attacker",
            method=HTTPMethodEnum.POST,
            endpoint="/api/v1/auth/login",
            status_code=401,
            authentication_status="FAILURE",
        )
        for i in range(6)
    ]

    findings = APIAuthFailureEngine.analyze(events, config)
    auth_findings = [f for f in findings if f.finding_type == "REPEATED_API_AUTH_FAILURES"]

    assert len(auth_findings) >= 1
    af = auth_findings[0]
    assert af.rule_id == "API_AUTH_001"
    assert af.severity == SeverityEnum.MEDIUM


def test_15_repeated_authorization_failures():
    config = APIConfigResponse(authz_failure_threshold=4, authz_failure_window_seconds=300)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    endpoints = ["/api/v1/admin/secrets", "/api/v1/billing/cards", "/api/v1/users/export", "/api/v1/keys"]
    events = [
        NormalizedAPIEvent(
            id=f"authz-fail-{i}",
            timestamp=base_time + timedelta(seconds=i * 15),
            source_ip="198.51.100.15",
            session_id="sess_probing",
            account_id="insider_carol",
            method=HTTPMethodEnum.GET,
            endpoint=endpoints[i],
            route_template=endpoints[i],
            status_code=403,
            authorization_status="DENIED",
        )
        for i in range(4)
    ]

    findings = APIAuthFailureEngine.analyze(events, config)
    authz_findings = [f for f in findings if f.finding_type == "REPEATED_AUTHORIZATION_FAILURES"]

    assert len(authz_findings) >= 1
    azf = authz_findings[0]
    assert azf.rule_id == "API_AUTHZ_001"
    assert azf.severity == SeverityEnum.HIGH
    assert azf.target_session == "sess_probing"


def test_16_high_missing_endpoint_404_rate():
    config = APIConfigResponse(missing_endpoint_threshold=5, missing_endpoint_window_seconds=120)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id=f"404-{i}",
            timestamp=base_time + timedelta(seconds=i * 5),
            source_ip="198.51.100.16",
            method=HTTPMethodEnum.GET,
            endpoint=f"/api/v1/missing_path_{i}",
            status_code=404,
        )
        for i in range(7)
    ]

    findings = APIAuthFailureEngine.analyze(events, config)
    f404 = [f for f in findings if f.finding_type == "HIGH_MISSING_ENDPOINT_RATE"]

    assert len(f404) >= 1
    assert f404[0].rule_id == "API_404_001"
    assert f404[0].severity == SeverityEnum.LOW


# ============================================================================
# 6. METHOD & PRIVILEGE ANOMALY TESTS
# ============================================================================

def test_17_unusual_destructive_methods():
    config = APIConfigResponse()
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id=f"del-{i}",
            timestamp=base_time + timedelta(seconds=i * 2),
            source_ip="198.51.100.17",
            account_id="user_purger",
            method=HTTPMethodEnum.DELETE,
            raw_method="DELETE",
            endpoint=f"/api/v1/records/{i}",
            status_code=204,
        )
        for i in range(6)
    ]

    findings = APIMethodPrivilegeEngine.analyze(events, config)
    meth_findings = [f for f in findings if f.finding_type == "UNUSUAL_API_METHOD"]

    assert len(meth_findings) >= 1
    assert meth_findings[0].rule_id == "API_METH_001"


def test_18_privileged_operation_signal():
    config = APIConfigResponse(sensitive_routes=["/api/v1/admin", "/api/secrets"])
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id="priv-1",
            timestamp=base_time,
            source_ip="198.51.100.18",
            account_id="admin_user",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/admin/configuration",
            status_code=200,
        )
    ]

    findings = APIMethodPrivilegeEngine.analyze(events, config)
    priv_findings = [f for f in findings if f.finding_type == "PRIVILEGED_API_OPERATION"]

    assert len(priv_findings) >= 1
    assert priv_findings[0].rule_id == "API_PRIV_001"


# ============================================================================
# 7. SESSION & SOURCE ANOMALY TESTS
# ============================================================================

def test_19_rapid_session_source_change():
    config = APIConfigResponse(rapid_source_change_window_seconds=600)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id="sess-ip-1",
            timestamp=base_time,
            source_ip="198.51.100.1",  # Initial IP
            session_id="sess_hijacked",
            account_id="victim_alice",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/profile",
            status_code=200,
        ),
        NormalizedAPIEvent(
            id="sess-ip-2",
            timestamp=base_time + timedelta(seconds=60),
            source_ip="203.0.113.88",  # Different IP 60s later
            session_id="sess_hijacked",
            account_id="victim_alice",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/inbox",
            status_code=200,
        ),
    ]

    findings = APISessionAnomalyEngine.analyze(events, config)
    rapid_findings = [f for f in findings if f.finding_type == "RAPID_SESSION_SOURCE_CHANGE"]

    assert len(rapid_findings) >= 1
    rf = rapid_findings[0]
    assert rf.rule_id == "API_SESS_002"
    assert rf.severity == SeverityEnum.HIGH


def test_20_client_profile_change_in_session():
    config = APIConfigResponse()
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id="ua-1",
            timestamp=base_time,
            source_ip="198.51.100.20",
            session_id="sess_token_leak",
            account_id="alice",
            user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0",
            client_type=ClientTypeEnum.BROWSER,
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/data",
            status_code=200,
        ),
        NormalizedAPIEvent(
            id="ua-2",
            timestamp=base_time + timedelta(seconds=30),
            source_ip="198.51.100.20",
            session_id="sess_token_leak",
            account_id="alice",
            user_agent="python-requests/2.31.0",
            client_type=ClientTypeEnum.AUTOMATION,
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/data",
            status_code=200,
        ),
    ]

    findings = APISessionAnomalyEngine.analyze(events, config)
    client_findings = [f for f in findings if f.finding_type == "API_CLIENT_PROFILE_CHANGE"]

    assert len(client_findings) >= 1
    assert client_findings[0].rule_id == "API_CLIENT_001"


def test_21_new_endpoint_vs_insufficient_history():
    config = APIConfigResponse(min_history_events_baseline=5)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Profile with SUFFICIENT history (>= 5 events)
    mature_profile = AccountAPIBaselineProfile(
        account_id="mature_user",
        total_requests_observed=20,
        known_endpoints=["/api/v1/home", "/api/v1/profile"],
    )

    ev_mature = [
        NormalizedAPIEvent(
            id="new-ep-1",
            timestamp=base_time,
            source_ip="198.51.100.21",
            account_id="mature_user",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/financials/reports",
            route_template="/api/v1/financials/reports",
            status_code=200,
        )
    ]

    findings_mature = APISessionAnomalyEngine.analyze(
        ev_mature, config, account_profiles={"mature_user": mature_profile}
    )
    new_findings = [f for f in findings_mature if f.finding_type == "NEW_API_ENDPOINT"]
    assert len(new_findings) == 1
    assert new_findings[0].rule_id == "API_NEW_001"

    # 2. Profile with INSUFFICIENT history (< 5 events) -> Suppress false alarm!
    immature_profile = AccountAPIBaselineProfile(
        account_id="newbie_user",
        total_requests_observed=2,
        known_endpoints=["/api/v1/home"],
    )
    ev_immature = [
        NormalizedAPIEvent(
            id="new-ep-2",
            timestamp=base_time,
            source_ip="198.51.100.21",
            account_id="newbie_user",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/settings",
            route_template="/api/v1/settings",
            status_code=200,
        )
    ]
    findings_immature = APISessionAnomalyEngine.analyze(
        ev_immature, config, account_profiles={"newbie_user": immature_profile}
    )
    assert len([f for f in findings_immature if f.finding_type == "NEW_API_ENDPOINT"]) == 0


# ============================================================================
# 8. DATA VOLUME, EXFILTRATION & SCRAPING TESTS
# ============================================================================

def test_22_high_response_volume():
    config = APIConfigResponse(high_response_volume_bytes=5 * 1024 * 1024)  # 5 MB threshold
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id="vol-1",
            timestamp=base_time,
            source_ip="198.51.100.22",
            account_id="downloader_dan",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/backup.tar.gz",
            response_bytes=6 * 1024 * 1024,  # 6 MB
            status_code=200,
        )
    ]

    findings = APIVolumeScrapingEngine.analyze(events, config)
    vol_findings = [f for f in findings if f.finding_type == "HIGH_API_RESPONSE_VOLUME"]

    assert len(vol_findings) >= 1
    assert vol_findings[0].rule_id == "API_VOL_001"
    assert vol_findings[0].severity == SeverityEnum.MEDIUM


def test_23_bulk_export_activity():
    config = APIConfigResponse(bulk_export_min_bytes=1024 * 1024)  # 1 MB threshold
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedAPIEvent(
            id="exp-1",
            timestamp=base_time,
            source_ip="198.51.100.23",
            session_id="sess_exfil",
            account_id="alice",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/customer_data/export",
            response_bytes=2 * 1024 * 1024,  # 2 MB
            status_code=200,
        )
    ]

    findings = APIVolumeScrapingEngine.analyze(events, config)
    exp_findings = [f for f in findings if f.finding_type == "UNUSUAL_BULK_EXPORT_ACTIVITY"]

    assert len(exp_findings) >= 1
    assert exp_findings[0].rule_id == "API_EXP_001"
    assert exp_findings[0].severity == SeverityEnum.HIGH


def test_24_scraping_like_activity():
    config = APIConfigResponse(
        scraping_min_requests=10,
        scraping_min_resources=8,
        scraping_max_duration_seconds=60,
    )
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    # 12 distinct resources queried with GET in 24 seconds with 100% 200 OK
    events = [
        NormalizedAPIEvent(
            id=f"scrape-{i}",
            timestamp=base_time + timedelta(seconds=i * 2),
            source_ip="198.51.100.24",
            session_id="sess_scraper",
            method=HTTPMethodEnum.GET,
            endpoint=f"/api/v1/catalog/item/{i}",
            resource_type="catalog",
            resource_id_hash=f"hash-{i}",
            status_code=200,
        )
        for i in range(12)
    ]

    findings = APIVolumeScrapingEngine.analyze(events, config)
    scrape_findings = [f for f in findings if f.finding_type == "SCRAPING_LIKE_API_ACTIVITY"]

    assert len(scrape_findings) >= 1
    sf = scrape_findings[0]
    assert sf.rule_id == "API_SCRAPE_001"
    assert sf.severity == SeverityEnum.MEDIUM


def test_25_periodic_api_activity():
    config = APIConfigResponse(periodicity_min_observations=5, periodicity_max_cv=0.15)
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    # 5 events exactly 30 seconds apart (variance ~ 0, CV ~ 0)
    events = [
        NormalizedAPIEvent(
            id=f"period-{i}",
            timestamp=base_time + timedelta(seconds=i * 30),
            source_ip="198.51.100.25",
            account_id="sync_bot",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/healthcheck",
            status_code=200,
        )
        for i in range(5)
    ]

    findings = APIVolumeScrapingEngine.analyze(events, config)
    period_findings = [f for f in findings if f.finding_type == "PERIODIC_API_ACTIVITY"]

    assert len(period_findings) >= 1
    pf = period_findings[0]
    assert pf.rule_id == "API_PERIOD_001"
    assert pf.severity == SeverityEnum.LOW  # Informational, not alone malicious


# ============================================================================
# 9. COMPOSITE HYPOTHESIS & FULL PIPELINE TESTS
# ============================================================================

@pytest.mark.anyio
async def test_26_composite_api_abuse_suspected(db_session):
    """
    Scenario:
    Session S exhibits:
    1. Rapid session source change (Session anomaly)
    2. Traverses 15 resource IDs on /api/v1/records/{id} (Resource enumeration)
    3. Receives repeated 403 Forbidden on privileged endpoints (Authorization anomaly)
    4. Downloads large response payload from export endpoint (Data volume anomaly)
    Expected: API_ABUSE_SUSPECTED composite threat event!
    """
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events: List[Dict[str, Any]] = []

    # 1. Initial request from IP 1
    events.append({
        "timestamp": base_time.isoformat(),
        "source_ip": "198.51.100.30",
        "account_id": "alice_finance",
        "session_id": "sess_malicious_007",
        "method": "GET",
        "endpoint": "/api/v1/dashboard",
        "status_code": 200,
    })

    # 2. Rapid switch to IP 2 + Resource Enumeration
    for i in range(16):
        events.append({
            "timestamp": (base_time + timedelta(seconds=60 + i * 2)).isoformat(),
            "source_ip": "203.0.113.99",  # Switched IP
            "account_id": "alice_finance",
            "session_id": "sess_malicious_007",
            "method": "GET",
            "endpoint": f"/api/v1/records/{2000 + i}",
            "status_code": 200,
            "response_bytes": 1024,
        })

    # 3. Authorization Failures (403s on admin endpoints)
    for i in range(6):
        events.append({
            "timestamp": (base_time + timedelta(seconds=120 + i * 5)).isoformat(),
            "source_ip": "203.0.113.99",
            "account_id": "alice_finance",
            "session_id": "sess_malicious_007",
            "method": "GET",
            "endpoint": f"/api/v1/admin/secrets/{i}",
            "status_code": 403,
        })

    # 4. Large Bulk Export
    events.append({
        "timestamp": (base_time + timedelta(seconds=180)).isoformat(),
        "source_ip": "203.0.113.99",
        "account_id": "alice_finance",
        "session_id": "sess_malicious_007",
        "method": "GET",
        "endpoint": "/api/v1/customers/export",
        "status_code": 200,
        "response_bytes": 18 * 1024 * 1024,  # 18 MB
    })

    pipeline = APISecurityPipeline()
    res = await pipeline.analyze_events(raw_events=events, db=db_session)

    assert res.events_analyzed_count == len(events)
    assert res.api_abuse_suspected is True
    assert res.possible_exfiltration_detected is True
    assert res.overall_severity in (SeverityEnum.HIGH, SeverityEnum.CRITICAL)
    assert res.overall_risk_score >= 70.0

    finding_types = {f.finding_type for f in res.findings}
    assert "RESOURCE_ENUMERATION_PATTERN" in finding_types
    assert "REPEATED_AUTHORIZATION_FAILURES" in finding_types
    assert "RAPID_SESSION_SOURCE_CHANGE" in finding_types
    assert "HIGH_API_RESPONSE_VOLUME" in finding_types
    assert "API_ABUSE_SUSPECTED" in finding_types
    assert "POSSIBLE_API_DATA_EXFILTRATION" in finding_types


@pytest.mark.anyio
async def test_27_cross_module_correlation_with_section_9_ato(db_session):
    """
    Scenario:
    1. Create an upstream Section 9 ACCOUNT_TAKEOVER_SUSPECTED ThreatEvent for account 'dave_exec'.
    2. Ingest API requests for 'dave_exec'.
    3. Pipeline correlates and outputs CORRELATED_ACCOUNT_TAKEOVER_ACTIVITY!
    """
    # Seed prior Section 9 ThreatEvent
    te = ThreatEventModel(
        id=f"te-ato-{uuid.uuid4().hex[:8]}",
        event_type="ACCOUNT_TAKEOVER_SUSPECTED",
        severity="CRITICAL",
        summary="Account takeover suspected for dave_exec",
        metadata_json=json.dumps({"account_id": "dave_exec", "target_account": "dave_exec", "reason": "Rapid location change & new device"}),
    )
    db_session.add(te)
    db_session.commit()

    events = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "198.51.100.99",
            "account_id": "dave_exec",
            "method": "GET",
            "endpoint": "/api/v1/sensitive_report",
            "status_code": 200,
        }
    ]

    pipeline = APISecurityPipeline()
    res = await pipeline.analyze_events(raw_events=events, db=db_session)

    finding_types = {f.finding_type for f in res.findings}
    assert "CORRELATED_ACCOUNT_TAKEOVER_ACTIVITY" in finding_types


@pytest.mark.anyio
async def test_28_cross_module_correlation_with_section_10_network(db_session):
    """
    Scenario:
    1. Seed a Section 10 SUSPICIOUS_EXTERNAL_COMMUNICATION ThreatEvent from IP '203.0.113.77'.
    2. Ingest API telemetry from '203.0.113.77'.
    3. Pipeline correlates and flags CORRELATED_NETWORK_THREAT_ACTIVITY!
    """
    te_net = ThreatEventModel(
        id=f"te-net-{uuid.uuid4().hex[:8]}",
        event_type="SUSPICIOUS_EXTERNAL_COMMUNICATION",
        severity="HIGH",
        summary="Suspicious external communication detected",
        metadata_json=json.dumps({"source_ip": "203.0.113.77", "destination_ip": "203.0.113.77"}),
    )
    db_session.add(te_net)
    db_session.commit()

    events = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "203.0.113.77",
            "method": "GET",
            "endpoint": "/api/v1/ping",
            "status_code": 200,
        }
    ]

    pipeline = APISecurityPipeline()
    res = await pipeline.analyze_events(raw_events=events, db=db_session)

    finding_types = {f.finding_type for f in res.findings}
    assert "CORRELATED_NETWORK_THREAT_ACTIVITY" in finding_types


@pytest.mark.anyio
async def test_29_reanalysis_creates_new_run_without_destroying_history(db_session):
    """
    Verifies that reanalyzing an existing artifact creates a distinct AnalysisRunModel
    while preserving original historical analysis records.
    """
    pipeline = APISecurityPipeline()
    events = [
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "198.51.100.50",
            "account_id": "test_reanalysis_user",
            "method": "GET",
            "endpoint": "/api/v1/metrics",
            "status_code": 200,
        }
    ]

    # Initial Run
    res1 = await pipeline.analyze_events(raw_events=events, db=db_session)
    art_id = res1.artifact_id
    assert art_id is not None
    run_id_1 = res1.analysis_run_id

    # Re-analysis
    res2 = await pipeline.reanalyze_artifact(artifact_id=art_id, db=db_session)
    run_id_2 = res2.analysis_run_id

    assert run_id_1 != run_id_2

    # Query DB to ensure BOTH runs exist
    runs = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id == art_id).all()
    assert len(runs) >= 2


# ============================================================================
# 10. FALSE-POSITIVE SAFETY TESTS
# ============================================================================

def test_30_false_positive_safety_checks():
    """
    Validates that benign behaviors are NOT falsely declared as malicious:
    - Service account high traffic within threshold is NOT flagged
    - Single DELETE request is NOT flagged
    - Single 404 Not Found is NOT flagged
    - Single 403 Forbidden is NOT flagged
    """
    config = APIConfigResponse()
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Service account with 100 requests (threshold is 300) -> NO RATE ALERT
    svc_events = [
        NormalizedAPIEvent(
            id=f"svc-{i}",
            timestamp=base_time + timedelta(seconds=i),
            source_ip="10.0.1.50",
            account_id="svc_internal_sync",
            is_service_account=True,
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/status",
            status_code=200,
        )
        for i in range(100)
    ]
    findings_svc = APIRateBurstEngine.analyze(svc_events, config)
    assert len([f for f in findings_svc if f.finding_type == "HIGH_API_REQUEST_RATE"]) == 0

    # 2. Single DELETE request -> NO METHOD ALERT
    del_events = [
        NormalizedAPIEvent(
            id="del-single",
            timestamp=base_time,
            source_ip="10.0.1.51",
            account_id="regular_user",
            method=HTTPMethodEnum.DELETE,
            raw_method="DELETE",
            endpoint="/api/v1/item/42",
            status_code=204,
        )
    ]
    findings_del = APIMethodPrivilegeEngine.analyze(del_events, config)
    assert len([f for f in findings_del if f.finding_type == "UNUSUAL_API_METHOD"]) == 0

    # 3. Single 404 & single 403 -> NO REPEATED FAILURE ALERT
    isolated_errs = [
        NormalizedAPIEvent(
            id="err-404",
            timestamp=base_time,
            source_ip="10.0.1.52",
            account_id="typo_user",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/typo_path",
            status_code=404,
        ),
        NormalizedAPIEvent(
            id="err-403",
            timestamp=base_time + timedelta(seconds=5),
            source_ip="10.0.1.52",
            account_id="typo_user",
            method=HTTPMethodEnum.GET,
            endpoint="/api/v1/restricted",
            status_code=403,
        ),
    ]
    findings_errs = APIAuthFailureEngine.analyze(isolated_errs, config)
    assert len([f for f in findings_errs if f.finding_type in ("HIGH_MISSING_ENDPOINT_RATE", "REPEATED_AUTHORIZATION_FAILURES")]) == 0


# ============================================================================
# 11. API ROUTE & UPLOAD TESTS
# ============================================================================

def test_31_api_routes_config(client):
    res = client.get("/api/api-security/config")
    assert res.status_code == 200
    data = res.json()
    assert "rate_threshold_human" in data
    assert "supported_adapters" in data
    assert "generic_json" in data["supported_adapters"]


def test_32_api_routes_analyze_batch(client):
    payload = [
        {
            "timestamp": "2026-10-02T12:00:00Z",
            "source_ip": "198.51.100.90",
            "account_id": "test_batch_user",
            "method": "GET",
            "endpoint": "/api/v1/health",
            "status_code": 200,
        }
    ]
    res = client.post("/api/api-security/analyze-batch", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["events_analyzed_count"] == 1
    assert data["overall_severity"] == "SAFE"


def test_33_api_routes_upload_csv(client):
    csv_content = (
        "timestamp,method,path,status,ip,user,bytes\n"
        "2026-10-02 12:00:00,GET,/api/v1/items,200,198.51.100.91,csv_user,512\n"
        "2026-10-02 12:00:02,GET,/api/v1/items/101,200,198.51.100.91,csv_user,1024\n"
    )
    files = {"file": ("test_api.csv", csv_content.encode("utf-8"), "text/csv")}
    res = client.post("/api/api-security/upload-log", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["events_analyzed_count"] == 2


# ============================================================================
# 12. PERFORMANCE BENCHMARK TEST (SECTION 61)
# ============================================================================

def test_34_performance_benchmark():
    """
    Measures normalization and analytical throughput over 1,000 synthetic API events.
    """
    base_time = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    config = APIConfigResponse()
    adapter = GenericJsonApiAdapter()

    # Generate 1,000 synthetic events
    raw_events = [
        {
            "id": f"perf-{i}",
            "timestamp": (base_time + timedelta(milliseconds=i * 50)).isoformat(),
            "source_ip": f"198.51.100.{(i % 20) + 1}",
            "account_id": f"user_{(i % 10) + 1}",
            "session_id": f"sess_{(i % 10) + 1}",
            "method": "GET" if i % 10 != 0 else "POST",
            "endpoint": f"/api/v1/products/{1000 + (i % 50)}",
            "status_code": 200 if i % 15 != 0 else 403,
            "response_bytes": 1024 + (i * 10),
            "duration_ms": 10.0 + (i % 20),
            "user_agent": "Mozilla/5.0 Chrome/120.0" if i % 2 == 0 else "curl/7.88",
        }
        for i in range(1000)
    ]

    t0 = time.perf_counter()
    # 1. Normalization throughput
    norm_events = [adapter.normalize(e) for e in raw_events]
    t_norm = time.perf_counter() - t0

    # 2. Analytics throughput
    t1 = time.perf_counter()
    findings = []
    findings.extend(APIRateBurstEngine.analyze(norm_events, config))
    findings.extend(APIEnumerationEngine.analyze(norm_events, config))
    findings.extend(APIAuthFailureEngine.analyze(norm_events, config))
    findings.extend(APIMethodPrivilegeEngine.analyze(norm_events, config))
    findings.extend(APISessionAnomalyEngine.analyze(norm_events, config))
    findings.extend(APIVolumeScrapingEngine.analyze(norm_events, config))
    t_analysis = time.perf_counter() - t1

    total_time = t_norm + t_analysis
    events_per_sec = len(raw_events) / total_time if total_time > 0 else 0.0

    print(f"\n[BENCHMARK] 1,000 API Events Normalized in {t_norm:.3f}s")
    print(f"[BENCHMARK] Analyzed in {t_analysis:.3f}s (Total: {total_time:.3f}s)")
    print(f"[BENCHMARK] Throughput: {events_per_sec:.1f} events/sec. Findings generated: {len(findings)}")

    assert len(norm_events) == 1000
    assert total_time < 2.0  # Must comfortably process 1,000 events in < 2 seconds on modern CPU
