"""
Comprehensive Test Suite for Section 15:
Cross-Incident Pattern Detection & Campaign Correlation Engine.
Tests all scenarios (A, B, C, D, E), false-positive controls,
scoring explainability, transitive correlation boundaries, and analyst reviews.
"""
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
    IncidentModel,
    IncidentCorrelationModel,
    CampaignModel,
    CampaignIncidentModel,
    ThreatEventModel,
    AuditLogModel,
    EntityModel,
    RelationshipModel,
)
from backend.services.cross_incident_engine import (
    CrossIncidentCorrelationEngine,
    prevalence_tracker,
    ENGINE_VERSION,
    CONFIG_VERSION,
)
from backend.schemas.cross_incident import (
    IncidentCorrelationProfile,
    IndicatorSpecificity,
    CorrelationFeatureCategory,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

@pytest.fixture
def test_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def engine_service():
    return CrossIncidentCorrelationEngine()


# -----------------------------------------------------------------------------
# 1. Scenarios A, B, C, D, E
# -----------------------------------------------------------------------------

def test_scenario_a_strong_correlation(engine_service, test_db):
    """
    Scenario A:
    Incident A: email, attachment hash H1, domain D1, target identity Acme
    Incident B: email, attachment hash H1, domain D1, target identity Acme
    Expected: Strong correlation; no 'same attacker confirmed'.
    """
    h1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b800"
    d1 = "rare-c2-dropzone.test"
    t1 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)

    prof_a = IncidentCorrelationProfile(
        incident_id="INC-A",
        workspace_id="default",
        hashes=[h1],
        domains=[d1],
        protected_identities=["Acme Corporation"],
        time_start=t1
    )
    prof_b = IncidentCorrelationProfile(
        incident_id="INC-B",
        workspace_id="default",
        hashes=[h1],
        domains=[d1],
        protected_identities=["Acme Corporation"],
        time_start=t1 + timedelta(minutes=45)
    )

    res = engine_service.correlate_incident_pair(prof_a, prof_b, test_db)
    assert res.correlation_score >= 0.70
    assert res.relationship_label == "Strong cross-incident similarity"
    assert "same attacker" not in res.relationship_label.lower()
    assert "same attacker" not in res.assessment_meaning.lower()

    # Verify supporting evidence includes exact hash and rare domain
    types = [e.evidence_type for e in res.supporting_evidence]
    assert "SHARED_FILE_HASH" in types
    assert any("DOMAIN" in t for t in types)
    assert "SHARED_TARGET_IDENTITY" in types


def test_scenario_b_common_infrastructure_control(engine_service, test_db):
    """
    Scenario B:
    Incident A: IP = major shared cloud fixture (e.g. 104.16.0.1 Cloudflare)
    Incident B: same IP, no other overlap
    Expected: Weak / no meaningful campaign correlation.
    """
    prof_a = IncidentCorrelationProfile(
        incident_id="INC-A",
        workspace_id="default",
        ips=["104.16.0.1"]
    )
    prof_b = IncidentCorrelationProfile(
        incident_id="INC-B",
        workspace_id="default",
        ips=["104.16.0.1"]
    )

    res = engine_service.correlate_incident_pair(prof_a, prof_b, test_db)
    assert res.correlation_score < 0.20
    assert res.relationship_label == "Inconclusive / No significant relationship"
    assert any(ce.factor == "COMMON_CDN_INFRASTRUCTURE" for ce in res.contradicting_evidence)


def test_scenario_c_lookalike_and_template_campaign(engine_service, test_db):
    """
    Scenario C:
    Incident A: secure-acme-login.test, targets Acme, template T1, close timing
    Incident B: verify-acme-account.test, targets Acme, template T1, close timing
    Expected: Campaign candidate threshold met.
    """
    t0 = datetime(2026, 10, 2, 8, 0, 0, tzinfo=timezone.utc)
    tmpl_sim = f"{0x12345678abcdef01:016x}"

    prof_a = IncidentCorrelationProfile(
        incident_id="INC-A",
        workspace_id="default",
        domains=["secure-acme-login.test"],
        protected_identities=["Acme"],
        template_fingerprint=tmpl_sim,
        time_start=t0
    )
    prof_b = IncidentCorrelationProfile(
        incident_id="INC-B",
        workspace_id="default",
        domains=["verify-acme-account.test"],
        protected_identities=["Acme"],
        template_fingerprint=tmpl_sim,
        time_start=t0 + timedelta(minutes=75)
    )

    res = engine_service.correlate_incident_pair(prof_a, prof_b, test_db)
    assert res.correlation_score >= 0.40
    types = [e.evidence_type for e in res.supporting_evidence]
    assert "SIMILAR_LOOKALIKE_DOMAIN_PATTERN" in types
    assert "SIMILAR_MESSAGE_TEMPLATE" in types
    assert "SHARED_TARGET_IDENTITY" in types
    assert "CLOSE_TEMPORAL_PROXIMITY" in types


def test_scenario_d_target_only_weak_evidence(engine_service, test_db):
    """
    Scenario D:
    Incident A: targets Acme
    Incident B: targets Acme
    Different infrastructure, different artifacts, different content, months apart.
    Expected: No strong campaign conclusion (same target alone is weak).
    """
    t_a = datetime(2026, 5, 1, tzinfo=timezone.utc)
    t_b = datetime(2026, 10, 1, tzinfo=timezone.utc)

    prof_a = IncidentCorrelationProfile(
        incident_id="INC-A",
        workspace_id="default",
        protected_identities=["Acme"],
        domains=["random-attack-infra-1.test"],
        hashes=["1111111111111111111111111111111111111111111111111111111111111111"],
        time_start=t_a
    )
    prof_b = IncidentCorrelationProfile(
        incident_id="INC-B",
        workspace_id="default",
        protected_identities=["Acme"],
        domains=["unrelated-infra-2.test"],
        hashes=["2222222222222222222222222222222222222222222222222222222222222222"],
        time_start=t_b
    )

    res = engine_service.correlate_incident_pair(prof_a, prof_b, test_db)
    assert res.correlation_score < 0.20
    assert res.relationship_label == "Inconclusive / No significant relationship"
    assert any(ce.factor == "LARGE_TIME_SEPARATION" for ce in res.contradicting_evidence)


def test_scenario_e_transitive_correlation_control(engine_service, test_db):
    """
    Scenario E:
    Incident A: file hash H
    Incident B: file hash H
    Incident C: shares only common CDN (104.16.0.1) with B
    Expected:
    A and B have strong correlation.
    C must NOT be automatically pulled into the campaign cluster merely through B.
    """
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b899"
    cdn_ip = "104.16.0.1"
    now = datetime.now(timezone.utc)

    inc_a = IncidentModel(id="INC-A", incident_number="INC-2026-0001", title="Phishing A", workspace_id="default", opened_at=now)
    inc_b = IncidentModel(id="INC-B", incident_number="INC-2026-0002", title="Phishing B", workspace_id="default", opened_at=now)
    inc_c = IncidentModel(id="INC-C", incident_number="INC-2026-0003", title="Web Traffic C", workspace_id="default", opened_at=now)
    test_db.add_all([inc_a, inc_b, inc_c])
    test_db.commit()

    prof_a = IncidentCorrelationProfile(incident_id="INC-A", workspace_id="default", hashes=[h], domains=["malware-c2.test"], time_start=now)
    prof_b = IncidentCorrelationProfile(incident_id="INC-B", workspace_id="default", hashes=[h], domains=["malware-c2.test"], ips=[cdn_ip], time_start=now)
    prof_c = IncidentCorrelationProfile(incident_id="INC-C", workspace_id="default", ips=[cdn_ip], time_start=now)

    # 1. Correlate A <-> B
    res_ab = engine_service.correlate_incident_pair(prof_a, prof_b, test_db)
    assert res_ab.correlation_score >= 0.70

    # 2. Correlate B <-> C
    res_bc = engine_service.correlate_incident_pair(prof_b, prof_c, test_db)
    assert res_bc.correlation_score < 0.20

    # Save records in database
    db_ab = IncidentCorrelationModel(
        id="corr-ab",
        workspace_id="default",
        incident_a_id="INC-A",
        incident_b_id="INC-B",
        correlation_score=res_ab.correlation_score,
        relationship_label=res_ab.relationship_label,
        supporting_evidence_json=json.dumps([e.model_dump() for e in res_ab.supporting_evidence]),
        contradicting_evidence_json=json.dumps([e.model_dump() for e in res_ab.contradicting_evidence]),
        feature_breakdown_json=json.dumps(res_ab.feature_breakdown.model_dump()),
        status="ACTIVE"
    )
    db_bc = IncidentCorrelationModel(
        id="corr-bc",
        workspace_id="default",
        incident_a_id="INC-B",
        incident_b_id="INC-C",
        correlation_score=res_bc.correlation_score,
        relationship_label=res_bc.relationship_label,
        supporting_evidence_json=json.dumps([e.model_dump() for e in res_bc.supporting_evidence]),
        contradicting_evidence_json=json.dumps([e.model_dump() for e in res_bc.contradicting_evidence]),
        feature_breakdown_json=json.dumps(res_bc.feature_breakdown.model_dump()),
        status="ACTIVE"
    )
    test_db.add_all([db_ab, db_bc])
    test_db.commit()

    # Generate campaign candidates
    candidates = engine_service.generate_campaign_candidates("default", test_db)
    assert len(candidates) == 1
    cand = candidates[0]
    assert "INC-A" in cand.incident_ids
    assert "INC-B" in cand.incident_ids
    assert "INC-C" not in cand.incident_ids  # C must NOT be bridged in!


# -----------------------------------------------------------------------------
# 2. False-Positive Controls
# -----------------------------------------------------------------------------

def test_false_positive_controls(engine_service, test_db):
    """
    Verifies that CyberGuard does NOT strongly correlate incidents solely because of:
    - Same major cloud IP
    - Same CDN
    - Same public resolver
    - Same webmail domain
    - Same generic URL path
    """
    # 1. Public Resolver (8.8.8.8)
    p1 = IncidentCorrelationProfile(incident_id="P1", workspace_id="default", ips=["8.8.8.8"])
    p2 = IncidentCorrelationProfile(incident_id="P2", workspace_id="default", ips=["8.8.8.8"])
    res1 = engine_service.correlate_incident_pair(p1, p2, test_db)
    assert res1.correlation_score < 0.10

    # 2. Webmail domain (gmail.com)
    p3 = IncidentCorrelationProfile(incident_id="P3", workspace_id="default", domains=["gmail.com"])
    p4 = IncidentCorrelationProfile(incident_id="P4", workspace_id="default", domains=["gmail.com"])
    res2 = engine_service.correlate_incident_pair(p3, p4, test_db)
    assert res2.correlation_score < 0.10

    # 3. Generic URL (/login)
    p5 = IncidentCorrelationProfile(incident_id="P5", workspace_id="default", urls=["https://attacker1.test/login"])
    p6 = IncidentCorrelationProfile(incident_id="P6", workspace_id="default", urls=["https://attacker2.test/login"])
    res3 = engine_service.correlate_incident_pair(p5, p6, test_db)
    assert res3.correlation_score < 0.10


# -----------------------------------------------------------------------------
# 3. Profile Extraction & Specificity
# -----------------------------------------------------------------------------

def test_profile_extraction_from_incident(engine_service, test_db):
    """Verifies that incident profile extracts indicators without re-parsing raw files."""
    inc = IncidentModel(
        id="INC-PROFILE-01",
        incident_number="INC-2026-9999",
        title="Spear Phishing Investigation",
        workspace_id="default",
        metadata_json=json.dumps({
            "domains": ["phish-portal.test"],
            "ips": ["198.51.100.44"],
            "hashes": ["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
            "protected_identities": ["Microsoft"],
            "subject": "Urgent Password Expiration Alert Notice"
        })
    )
    test_db.add(inc)
    test_db.commit()

    prof = engine_service.extract_incident_profile(inc, test_db)
    assert "phish-portal.test" in prof.domains
    assert "198.51.100.44" in prof.ips
    assert "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in prof.hashes
    assert "Microsoft" in prof.protected_identities
    assert prof.template_fingerprint is not None
    assert prof.profile_version == CONFIG_VERSION


def test_rarity_weighting_and_prevalence(engine_service, test_db):
    """Verifies that rare domains get HIGH specificity and ubiquitous ones are downweighted."""
    rare_dom = "targeted-c2-single-use.test"
    spec, wt = prevalence_tracker.classify_specificity("domain", rare_dom, "default", test_db)
    assert spec == IndicatorSpecificity.HIGH
    assert wt >= 0.25

    webmail = "yahoo.com"
    spec_w, wt_w = prevalence_tracker.classify_specificity("domain", webmail, "default", test_db)
    assert spec_w == IndicatorSpecificity.LOW
    assert wt_w <= 0.05


# -----------------------------------------------------------------------------
# 4. Analyst Feedback & Audit Trail
# -----------------------------------------------------------------------------

def test_analyst_review_and_audit(engine_service, test_db):
    """Verifies analyst confirmation and rejection updates status and logs audit trail."""
    inc_a = IncidentModel(id="INC-X1", incident_number="INC-X1", title="Inc X1", workspace_id="default")
    inc_b = IncidentModel(id="INC-X2", incident_number="INC-X2", title="Inc X2", workspace_id="default")
    test_db.add_all([inc_a, inc_b])

    corr = IncidentCorrelationModel(
        id="corr-test-review",
        workspace_id="default",
        incident_a_id="INC-X1",
        incident_b_id="INC-X2",
        correlation_score=0.85,
        relationship_label="Strong cross-incident similarity",
        supporting_evidence_json="[]",
        contradicting_evidence_json="[]",
        feature_breakdown_json="{}",
        status="ACTIVE"
    )
    test_db.add(corr)
    test_db.commit()

    # Confirm
    res_conf = engine_service.review_correlation(
        correlation_id="corr-test-review",
        decision="CONFIRM",
        notes="Verified shared infrastructure in sandbox",
        analyst_id="analyst_alice",
        db=test_db
    )
    assert res_conf.status == "CONFIRMED"
    assert res_conf.reviewed_by == "analyst_alice"

    # Check Audit Log
    audit = test_db.query(AuditLogModel).filter(
        AuditLogModel.resource_id == "corr-test-review",
        AuditLogModel.action == "CORRELATION_CONFIRMED"
    ).first()
    assert audit is not None
    assert audit.user == "analyst_alice"


# -----------------------------------------------------------------------------
# 5. Workspace Isolation
# -----------------------------------------------------------------------------

def test_workspace_isolation(engine_service, test_db):
    """Verifies that incidents in workspace A cannot correlate with workspace B."""
    inc_w1 = IncidentModel(id="INC-W1", incident_number="INC-W1", title="Phish W1", workspace_id="tenant_alpha")
    inc_w2 = IncidentModel(id="INC-W2", incident_number="INC-W2", title="Phish W2", workspace_id="tenant_beta")
    test_db.add_all([inc_w1, inc_w2])
    test_db.commit()

    prof_w1 = IncidentCorrelationProfile(
        incident_id="INC-W1",
        workspace_id="tenant_alpha",
        domains=["shared-c2.test"],
        hashes=["sha256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"]
    )

    candidates = engine_service.generate_candidate_incident_ids(prof_w1, "tenant_alpha", test_db)
    assert "INC-W2" not in candidates


# -----------------------------------------------------------------------------
# 6. REST API Endpoints
# -----------------------------------------------------------------------------

def test_api_related_incidents_endpoint(client, test_db):
    """Tests GET /api/incidents/{incident_id}/related."""
    inc1 = IncidentModel(
        id="inc-api-1",
        incident_number="INC-2026-A1",
        title="Spearphish A1",
        workspace_id="default",
        metadata_json=json.dumps({"domains": ["c2-api.test"], "hashes": ["sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]})
    )
    inc2 = IncidentModel(
        id="inc-api-2",
        incident_number="INC-2026-A2",
        title="Spearphish A2",
        workspace_id="default",
        metadata_json=json.dumps({"domains": ["c2-api.test"], "hashes": ["sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]})
    )
    test_db.add_all([inc1, inc2])
    test_db.commit()

    resp = client.get(f"/api/incidents/inc-api-1/related")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "inc-api-1"
    assert len(data["related_incidents"]) >= 1
    rel = data["related_incidents"][0]
    assert rel["incident_id"] == "inc-api-2"
    assert rel["correlation_score"] >= 0.70


def test_api_compare_endpoint(client, test_db):
    """Tests POST /api/correlations/compare."""
    inc1 = IncidentModel(id="inc-cmp-1", incident_number="INC-CMP-1", title="Inc 1", workspace_id="default")
    inc2 = IncidentModel(id="inc-cmp-2", incident_number="INC-CMP-2", title="Inc 2", workspace_id="default")
    test_db.add_all([inc1, inc2])
    test_db.commit()

    payload = {
        "incident_a_id": "inc-cmp-1",
        "incident_b_id": "inc-cmp-2",
        "workspace_id": "default"
    }
    resp = client.post("/api/correlations/compare", json=payload)
    assert resp.status_code == 200
    data = resp.json()
    assert "correlation_score" in data
    assert "relationship_label" in data
    assert "supporting_evidence" in data
    assert "contradicting_evidence" in data


def test_api_campaign_candidate_review(client, test_db):
    """Tests POST /api/campaigns/candidates/{campaign_id}/review."""
    camp = CampaignModel(
        id="camp-test-api",
        campaign_id="CAMP-CAND-099",
        name="Candidate 99",
        workspace_id="default",
        status="CANDIDATE"
    )
    test_db.add(camp)
    test_db.commit()

    resp = client.post(
        "/api/campaigns/candidates/camp-test-api/review",
        json={"decision": "CONFIRM", "notes": "Approved campaign cluster", "analyst_id": "soc_lead"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "REVIEWED_CONFIRMED"
