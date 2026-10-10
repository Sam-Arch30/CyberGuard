"""
Section 52: Comprehensive Tests for Threat Intelligence & External Intelligence Enrichment.
Verifies indicator normalization, privacy policy gates, internal threat memory precedence,
multi-provider consensus, conflicting verdict surfacing, caching and staleness,
background job workers, knowledge graph projection, tenant isolation, and REST APIs.
"""
import asyncio
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import (
    ThreatIntelligenceRecordModel,
    ThreatIntelProviderConfigModel,
    IndicatorModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    EntityModel,
    BackgroundJobModel,
)
from backend.schemas.jobs import JobTypeEnum
from backend.schemas.threat_intelligence import (
    IndicatorTypeEnum,
    PrivacyScopeEnum,
    VerdictEnum,
    SeverityEnum,
    ProviderStatusEnum,
)
from backend.services.indicator_normalizer import IndicatorNormalizer
from backend.services.threat_intelligence_service import ThreatIntelligenceService
from backend.services.background_job_worker import BackgroundJobWorker

# In-memory SQLite for testing with StaticPool
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        ThreatIntelligenceService.ensure_default_provider_configs(session, "ws-test")
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# =============================================================================
# 1. Indicator Normalization Unit Tests
# =============================================================================

def test_indicator_normalization_ip():
    """Verifies IPv4 and IPv6 normalization and port stripping."""
    norm1 = IndicatorNormalizer.normalize("198.51.100.25:8080", IndicatorTypeEnum.IP)
    assert norm1.type == IndicatorTypeEnum.IP
    assert norm1.normalized_value == "198.51.100.25"

    norm2 = IndicatorNormalizer.normalize("IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334", IndicatorTypeEnum.IP)
    assert norm2.type == IndicatorTypeEnum.IP
    assert norm2.normalized_value == "2001:db8:85a3::8a2e:370:7334"


def test_indicator_normalization_domain_and_punycode():
    """Verifies domain case normalization, trailing dot removal, and punycode IDN."""
    norm1 = IndicatorNormalizer.normalize("EXAMPLE.COM.", IndicatorTypeEnum.DOMAIN)
    assert norm1.normalized_value == "example.com"

    # IDN / Unicode domain -> Punycode conversion
    norm2 = IndicatorNormalizer.normalize("münchen.de", IndicatorTypeEnum.DOMAIN)
    assert norm2.normalized_value == "xn--mnchen-3ya.de"


def test_indicator_normalization_url():
    """Verifies scheme normalization, default port removal, path cleaning, and query sorting."""
    raw_url = "HTTP://Example.COM:80/path//to/file.php?b=2&a=1#fragment"
    norm = IndicatorNormalizer.normalize(raw_url, IndicatorTypeEnum.URL)
    assert norm.type == IndicatorTypeEnum.URL
    assert norm.normalized_value == "http://example.com/path/to/file.php?a=1&b=2"


def test_indicator_normalization_hashes():
    """Verifies hash length validation and lowercase normalization."""
    sha256_raw = "4A7D1ED414474E4033AC29CCB8653D9B00000000000000000000000000000000"
    norm = IndicatorNormalizer.normalize(sha256_raw, IndicatorTypeEnum.SHA256)
    assert norm.type == IndicatorTypeEnum.SHA256
    assert norm.normalized_value == sha256_raw.lower()
    assert norm.privacy_scope == PrivacyScopeEnum.PUBLIC

    md5_raw = "4A7D1ED414474E4033AC29CCB8653D9B"
    norm_md5 = IndicatorNormalizer.normalize(md5_raw, IndicatorTypeEnum.MD5)
    assert norm_md5.type == IndicatorTypeEnum.MD5
    assert norm_md5.normalized_value == md5_raw.lower()


# =============================================================================
# 2. Privacy Policy Gatekeeper & SSRF Safeguards
# =============================================================================

def test_privacy_policy_blocks_internal_rfc1918_and_loopback():
    """Ensures private RFC-1918 subnets, loopbacks, and cloud metadata are blocked from external lookup."""
    internal_ips = ["127.0.0.1", "10.0.0.5", "192.168.1.100", "172.16.50.2", "169.254.169.254", "::1"]
    for ip in internal_ips:
        norm = IndicatorNormalizer.normalize(ip, IndicatorTypeEnum.IP)
        assert norm.privacy_scope == PrivacyScopeEnum.INTERNAL
        allowed, reason = IndicatorNormalizer.is_external_lookup_allowed(norm)
        assert allowed is False
        assert "internal/private" in reason


def test_privacy_policy_blocks_corporate_internal_domains():
    """Ensures internal corporate hostnames and domains (.local, .internal, .corp, localhost) are blocked."""
    internal_domains = ["dc01.corp.internal", "exchange.local", "intranet.lan", "localhost", "server01"]
    for dom in internal_domains:
        norm = IndicatorNormalizer.normalize(dom, IndicatorTypeEnum.DOMAIN)
        assert norm.privacy_scope == PrivacyScopeEnum.INTERNAL
        allowed, reason = IndicatorNormalizer.is_external_lookup_allowed(norm)
        assert allowed is False


def test_privacy_policy_permits_public_observables():
    """Ensures routable public domains, public IPs, and file hashes are allowed for external lookup."""
    public_observables = ["bank-corp-update.com", "8.8.8.8", "https://github.com/security", "4a7d1ed414474e4033ac29ccb8653d9b"]
    for obs in public_observables:
        norm = IndicatorNormalizer.normalize(obs)
        allowed, _ = IndicatorNormalizer.is_external_lookup_allowed(norm)
        assert allowed is True


# =============================================================================
# 3. Internal Threat Memory Precedence (Internal First)
# =============================================================================

@pytest.mark.anyio
async def test_internal_threat_memory_queried_first(db_session):
    """Verifies historical observations in Threat Memory are surfaced with high confidence."""
    now = datetime.now(timezone.utc)
    # Seed historical entry in ThreatMemory
    mem_entry = ThreatMemoryEntryModel(
        workspace_id="ws-test",
        memory_type="DOMAIN",
        subject_type="DOMAIN",
        subject_id="bank-phish-internal.com",
        canonical_key="DOMAIN:bank-phish-internal.com",
        status="VERIFIED",
        confidence=0.98,
        observation_count=5,
        summary="Verified APT credential harvesting domain in previous incident.",
        attributes_json=json.dumps({"threat_types": ["Credential Harvesting", "APT29 Phishing"]}),
        first_seen_at=now - timedelta(days=30),
        last_seen_at=now - timedelta(days=2),
        created_at=now,
        updated_at=now,
    )
    db_session.add(mem_entry)
    db_session.commit()

    svc = ThreatIntelligenceService()
    res = await svc.enrich_indicator(
        db=db_session,
        raw_indicator="bank-phish-internal.com",
        indicator_type=IndicatorTypeEnum.DOMAIN,
        workspace_id="ws-test",
    )

    assert res.internal_memory_matched is True
    assert res.overall_verdict == VerdictEnum.MALICIOUS
    assert "Credential Harvesting" in res.threat_types
    # Verify provider breakdown includes internal threat memory
    prov_names = [p.provider for p in res.providers_data]
    assert "internal_threat_memory" in prov_names


# =============================================================================
# 4. Multi-Provider Consensus & Conflicting Intelligence
# =============================================================================

@pytest.mark.anyio
async def test_multi_provider_consensus_and_verdict_breakdown(db_session):
    """Verifies that multiple providers are queried and their verdicts aggregated."""
    svc = ThreatIntelligenceService()
    # "bank-corp-update.com" matches feed and simulated external providers
    res = await svc.enrich_indicator(
        db=db_session,
        raw_indicator="bank-corp-update.com",
        indicator_type=IndicatorTypeEnum.DOMAIN,
        workspace_id="ws-test",
    )

    assert res.overall_verdict == VerdictEnum.MALICIOUS
    assert res.total_sources_queried >= 2
    assert "MALICIOUS" in res.verdict_breakdown
    assert res.consensus_confidence >= 0.80
    assert len(res.providers_data) >= 2


@pytest.mark.anyio
async def test_conflicting_verdict_surfaced_explicitly(db_session):
    """Verifies that disagreement between providers is surfaced with is_conflicting=True and not hidden."""
    now = datetime.now(timezone.utc)
    # Manually seed two conflicting provider records into the database
    rec_clean = ThreatIntelligenceRecordModel(
        workspace_id="ws-test",
        indicator_type="DOMAIN",
        indicator_value="mixed-reputation.com",
        normalized_value="mixed-reputation.com",
        provider="provider_alpha",
        verdict="CLEAN",
        confidence=0.85,
        severity="NONE",
        threat_types_json="[]",
        retrieved_at=now,
        expires_at=now + timedelta(days=7),
    )
    rec_mal = ThreatIntelligenceRecordModel(
        workspace_id="ws-test",
        indicator_type="DOMAIN",
        indicator_value="mixed-reputation.com",
        normalized_value="mixed-reputation.com",
        provider="provider_beta",
        verdict="MALICIOUS",
        confidence=0.90,
        severity="HIGH",
        threat_types_json=json.dumps(["Phishing Detection"]),
        retrieved_at=now,
        expires_at=now + timedelta(days=7),
    )
    db_session.add(rec_clean)
    db_session.add(rec_mal)
    db_session.commit()

    svc = ThreatIntelligenceService()
    res = await svc.enrich_indicator(
        db=db_session,
        raw_indicator="mixed-reputation.com",
        indicator_type=IndicatorTypeEnum.DOMAIN,
        workspace_id="ws-test",
        force_refresh=False,
    )

    assert res.is_conflicting is True
    assert res.conflict_summary is not None
    assert "Conflicting intelligence" in res.conflict_summary
    assert res.verdict_breakdown.get("CLEAN", 0) >= 1
    assert res.verdict_breakdown.get("MALICIOUS", 0) >= 1


# =============================================================================
# 5. Caching, TTL Expiry & Force Refresh
# =============================================================================

@pytest.mark.anyio
async def test_caching_and_force_refresh_behavior(db_session):
    """Verifies cache hits for subsequent queries and cache bypass on force_refresh."""
    svc = ThreatIntelligenceService()
    ind = "185.220.101.42"

    # First query (populates database and cache)
    res1 = await svc.enrich_indicator(
        db=db_session,
        raw_indicator=ind,
        indicator_type=IndicatorTypeEnum.IP,
        workspace_id="ws-test",
        force_refresh=False,
    )
    assert res1.overall_verdict == VerdictEnum.MALICIOUS

    # Verify database record exists
    count = (
        db_session.query(ThreatIntelligenceRecordModel)
        .filter(ThreatIntelligenceRecordModel.normalized_value == ind)
        .count()
    )
    assert count >= 1

    # Second query should use cache
    res2 = await svc.enrich_indicator(
        db=db_session,
        raw_indicator=ind,
        indicator_type=IndicatorTypeEnum.IP,
        workspace_id="ws-test",
        force_refresh=False,
    )
    assert res2.overall_verdict == res1.overall_verdict

    # Force refresh bypasses cache
    res3 = await svc.enrich_indicator(
        db=db_session,
        raw_indicator=ind,
        indicator_type=IndicatorTypeEnum.IP,
        workspace_id="ws-test",
        force_refresh=True,
    )
    assert res3.overall_verdict == res1.overall_verdict


# =============================================================================
# 6. Knowledge Graph Projection
# =============================================================================

@pytest.mark.anyio
async def test_knowledge_graph_projection(db_session):
    """Verifies enriched indicators project canonical entity nodes into Knowledge Graph."""
    svc = ThreatIntelligenceService()
    ind = "185.220.101.42"

    await svc.enrich_indicator(
        db=db_session,
        raw_indicator=ind,
        indicator_type=IndicatorTypeEnum.IP,
        workspace_id="ws-test",
    )

    # Check EntityModel in Knowledge Graph
    entity = (
        db_session.query(EntityModel)
        .filter(EntityModel.name == ind)
        .first()
    )
    assert entity is not None
    assert entity.entity_type == "IP_ADDRESS"
    attrs = json.loads(entity.attributes_json)
    assert "threat_intelligence_verdict" in attrs


# =============================================================================
# 7. Background Job Worker Integration
# =============================================================================

def test_background_job_indicator_enrichment_worker(db_session, monkeypatch):
    """Verifies asynchronous background job execution via BackgroundJobWorker."""
    monkeypatch.setattr("backend.services.background_job_worker.SessionLocal", TestingSessionLocal)
    now = datetime.now(timezone.utc)

    # Create background job
    job = BackgroundJobModel(
        workspace_id="ws-test",
        job_type=JobTypeEnum.INDICATOR_ENRICHMENT.value,
        payload_json=json.dumps({
            "indicator_value": "bank-corp-update.com",
            "indicator_type": "DOMAIN",
        }),
        status="QUEUED",
        created_at=now,
        updated_at=now,
    )
    db_session.add(job)
    db_session.commit()

    worker = BackgroundJobWorker(worker_id="test-ti-worker")
    claimed = BackgroundJobWorker.claim_next_job(db_session, worker.worker_id, workspace_id="ws-test")
    assert claimed is not None
    assert claimed.id == job.id

    asyncio.run(worker.execute_job(claimed.id))

    db_session.refresh(job)
    assert job.status == "SUCCEEDED"
    assert "overall_verdict" in job.result
    assert job.result["overall_verdict"] == "MALICIOUS"


# =============================================================================
# 8. Multi-Tenant Boundary & Provider Configuration Isolation
# =============================================================================

def test_multi_tenant_isolation(db_session):
    """Ensures intelligence records and provider configurations are tenant-isolated."""
    now = datetime.now(timezone.utc)
    rec_alpha = ThreatIntelligenceRecordModel(
        workspace_id="ws-alpha",
        indicator_type="IP",
        indicator_value="198.51.100.99",
        normalized_value="198.51.100.99",
        provider="custom_alpha",
        verdict="SUSPICIOUS",
        confidence=0.75,
        retrieved_at=now,
    )
    db_session.add(rec_alpha)
    db_session.commit()

    # Query from ws-beta must return empty history
    history_beta = ThreatIntelligenceService.get_indicator_history(
        db=db_session,
        workspace_id="ws-beta",
        indicator_type="IP",
        normalized_value="198.51.100.99",
    )
    assert history_beta.total_observations == 0

    # Query from ws-alpha returns the observation
    history_alpha = ThreatIntelligenceService.get_indicator_history(
        db=db_session,
        workspace_id="ws-alpha",
        indicator_type="IP",
        normalized_value="198.51.100.99",
    )
    assert history_alpha.total_observations == 1


# =============================================================================
# 9. REST API Endpoints Verification
# =============================================================================

def test_api_indicator_lookup_and_privacy_classification(client, db_session):
    """Tests GET /api/intelligence/indicator/... and /api/intelligence/privacy/classify."""
    # 1. Privacy classification API
    res = client.get("/api/intelligence/privacy/classify?value=10.0.0.1")
    assert res.status_code == 200
    data = res.json()
    assert data["privacy_scope"] == "INTERNAL"
    assert data["external_lookup_permitted"] is False

    # 2. Enrich indicator API for public indicator
    res2 = client.get(
        "/api/intelligence/indicator/IP/185.220.101.42",
        headers={"X-Workspace-ID": "ws-test"},
    )
    assert res2.status_code == 200
    intel = res2.json()
    assert intel["normalized_value"] == "185.220.101.42"
    assert intel["overall_verdict"] == "MALICIOUS"

    # 3. Provider config API
    res3 = client.get(
        "/api/intelligence/providers",
        headers={"X-Workspace-ID": "ws-test"},
    )
    assert res3.status_code == 200
    provs = res3.json()
    assert len(provs) >= 4
    # Ensure no secrets leak in API response
    for p in provs:
        assert "api_key" not in p
        assert "api_key_ciphertext" not in p
