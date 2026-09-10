import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, get_db
from backend.services.campaign_correlator import CampaignCorrelator
from backend.services.graph_service import global_graph_service
from backend.tests.fixtures.campaign_fixtures import (
    FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_A,
    FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_B,
    FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_A,
    FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_B,
    FIXTURE_SAME_CAMPAIGN_ROTATING_IP_A,
    FIXTURE_SAME_CAMPAIGN_ROTATING_IP_B,
    FIXTURE_UNRELATED_AWS_EMAIL_A,
    FIXTURE_UNRELATED_AWS_EMAIL_B,
    FIXTURE_TEMPLATE_REUSE_TARGET_A,
    FIXTURE_TEMPLATE_REUSE_TARGET_B,
    FIXTURE_LEGIT_NEWSLETTER_A,
    FIXTURE_LEGIT_NEWSLETTER_B,
)


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
def engine():
    return CampaignCorrelator()


# -----------------------------------------------------------------------------
# Test Scenario 1: Same Campaign, Different Sender Addresses
# -----------------------------------------------------------------------------

def test_same_campaign_different_senders(engine):
    """Verifies that rotating sender identities in the same campaign yields high confidence."""
    fp1 = engine.generate_fingerprint(FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_A)
    fp2 = engine.generate_fingerprint(FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_B)

    scores = engine.calculate_category_similarities(fp1, fp2)

    assert scores.overall_confidence >= 80.0
    assert scores.infrastructure_similarity >= 50.0
    assert scores.domain_similarity >= 60.0
    assert scores.url_similarity >= 60.0
    assert scores.template_similarity >= 70.0
    assert any("185.220.101.42" in sig for sig in scores.strongest_signals)


# -----------------------------------------------------------------------------
# Test Scenario 2: Same Campaign, Rotating Domains
# -----------------------------------------------------------------------------

def test_same_campaign_rotating_domains(engine):
    """Verifies that campaigns rotating their domains correlate on ASN, URL paths, and bulletproof hosting."""
    fp1 = engine.generate_fingerprint(FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_A)
    fp2 = engine.generate_fingerprint(FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_B)

    scores = engine.calculate_category_similarities(fp1, fp2)

    assert scores.overall_confidence >= 65.0
    assert scores.url_similarity >= 20.0  # Shared path pattern /auth/sso/verify.php
    assert scores.template_similarity >= 70.0
    assert scores.content_similarity >= 70.0


# -----------------------------------------------------------------------------
# Test Scenario 3: Same Campaign, Rotating IPs
# -----------------------------------------------------------------------------

def test_same_campaign_rotating_ips(engine):
    """Verifies that fast-flux IP rotation correlates on domain, template, and nameservers."""
    fp1 = engine.generate_fingerprint(FIXTURE_SAME_CAMPAIGN_ROTATING_IP_A)
    fp2 = engine.generate_fingerprint(FIXTURE_SAME_CAMPAIGN_ROTATING_IP_B)

    scores = engine.calculate_category_similarities(fp1, fp2)

    assert scores.overall_confidence >= 75.0
    assert scores.domain_similarity >= 70.0
    assert scores.template_similarity >= 75.0
    assert scores.url_similarity >= 70.0


# -----------------------------------------------------------------------------
# Test Scenario 4: False-Positive Suppression (Shared Cloud Infrastructure)
# -----------------------------------------------------------------------------

def test_false_positive_control_cloud_providers(engine):
    """
    CRITICAL TEST: Verifies that unrelated benign emails sharing Amazon AWS SES (AS16509)
    and Cloudflare nameservers do NOT correlate into a campaign.
    """
    fp1 = engine.generate_fingerprint(FIXTURE_UNRELATED_AWS_EMAIL_A)
    fp2 = engine.generate_fingerprint(FIXTURE_UNRELATED_AWS_EMAIL_B)

    scores = engine.calculate_category_similarities(fp1, fp2)

    # Must be strictly below clustering threshold (< 15%)
    assert scores.overall_confidence < 15.0
    assert scores.domain_similarity == 0.0
    assert scores.url_similarity == 0.0


# -----------------------------------------------------------------------------
# Test Scenario 5: Template Reuse Across Different Targets
# -----------------------------------------------------------------------------

def test_template_reuse_across_targets(engine):
    """Verifies that phishing kits reusing the same HTML DOM structure flag template similarity."""
    fp1 = engine.generate_fingerprint(FIXTURE_TEMPLATE_REUSE_TARGET_A)
    fp2 = engine.generate_fingerprint(FIXTURE_TEMPLATE_REUSE_TARGET_B)

    scores = engine.calculate_category_similarities(fp1, fp2)

    # Template SimHash should match strongly
    assert scores.template_similarity >= 70.0
    assert scores.content_similarity >= 60.0
    assert scores.overall_confidence >= 45.0


# -----------------------------------------------------------------------------
# Test Scenario 6: Legitimate Newsletters (Benign Controls)
# -----------------------------------------------------------------------------

def test_legitimate_newsletters_no_correlation(engine):
    """Verifies that two legitimate newsletters return zero/minimal correlation."""
    fp1 = engine.generate_fingerprint(FIXTURE_LEGIT_NEWSLETTER_A)
    fp2 = engine.generate_fingerprint(FIXTURE_LEGIT_NEWSLETTER_B)

    scores = engine.calculate_category_similarities(fp1, fp2)

    assert scores.overall_confidence < 15.0
    assert scores.domain_similarity == 0.0
    assert scores.url_similarity == 0.0


# -----------------------------------------------------------------------------
# Clustering & Duplicate Prevention Tests
# -----------------------------------------------------------------------------

def test_clustering_and_duplicate_prevention(engine):
    """Verifies that related emails cluster into one campaign without creating duplicates."""
    emails = [
        FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_A,
        FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_B,
        FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_A,
        FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_B,
        FIXTURE_UNRELATED_AWS_EMAIL_A,
        FIXTURE_UNRELATED_AWS_EMAIL_B,
    ]

    clusters = engine.cluster_emails(emails, threshold=0.65)

    # Should group into 4 distinct clusters (diff senders together, rotating domains together, and 2 unrelated AWS separate)
    assert len(clusters) == 4

    # Check first cluster contains 2 emails
    c_wire = [c for c in clusters if c.email_count == 2]
    assert len(c_wire) >= 1
    assert c_wire[0].overall_confidence >= 80.0


# -----------------------------------------------------------------------------
# First-Class Campaign Graph Tests
# -----------------------------------------------------------------------------

def test_campaign_graph_generation():
    """Verifies that global_graph_service builds a graph with Campaign as central node."""
    campaign_dict = {
        "campaign_id": "C-042",
        "name": "Global Financial Wire Scam",
        "overall_confidence": 91.0,
        "dominant_attack_type": "Business Email Compromise (BEC)",
        "emails": [{"id": "eml-1", "subject": "Urgent Wire #1"}],
        "domains": ["bank-corp-update.com"],
        "ips": ["185.220.101.42"],
        "urls": ["https://bank-corp-update.com/auth/v2/login.php"],
        "recipient_summary": {"recipients": ["cfo@bankcorp.com"]}
    }

    graph = global_graph_service.build_campaign_graph(campaign_dict)

    node_types = {n.type.value for n in graph.nodes}
    assert "Campaign" in node_types
    assert "Email" in node_types
    assert "Domain" in node_types
    assert "IP" in node_types
    assert "URL" in node_types
    assert "Email Address" in node_types

    edge_labels = {e.label for e in graph.edges}
    assert "INCLUDES_EMAIL" in edge_labels
    assert "UTILIZES_DOMAIN" in edge_labels
    assert "HOSTED_ON_IP" in edge_labels
    assert "DEPLOYS_URL" in edge_labels
    assert "TARGETS_RECIPIENT" in edge_labels


# -----------------------------------------------------------------------------
# API Route Integration Tests
# -----------------------------------------------------------------------------

def test_api_list_campaigns(client):
    """Tests GET /api/campaigns endpoint."""
    res = client.get("/api/campaigns")
    assert res.status_code == 200
    data = res.json()

    assert len(data) >= 1
    c042 = next((c for c in data if c["campaign_id"] == "C-042"), None)
    assert c042 is not None
    assert c042["email_count"] == 73
    assert c042["recipient_count"] == 21
    assert c042["sender_count"] == 14
    assert c042["domain_count"] == 8
    assert c042["ip_count"] == 5
    assert c042["asn_count"] == 3
    assert c042["overall_confidence"] == 91.0


def test_api_get_campaign_detail_c042(client):
    """Tests GET /api/campaigns/C-042 endpoint with all 9 tabs data."""
    res = client.get("/api/campaigns/C-042")
    assert res.status_code == 200
    data = res.json()

    assert data["campaign_id"] == "C-042"
    assert "Global Financial Wire" in data["name"]
    assert len(data["timeline"]) >= 5
    assert len(data["associated_iocs"]) >= 5
    assert len(data["emails"]) >= 2
    assert "infrastructure_summary" in data
    assert "domain_summary" in data
    assert "url_summary" in data
    assert "recipient_summary" in data


def test_api_campaign_graph(client):
    """Tests GET /api/campaigns/C-042/graph endpoint."""
    res = client.get("/api/campaigns/C-042/graph")
    assert res.status_code == 200
    data = res.json()

    assert len(data["nodes"]) > 0
    assert len(data["edges"]) > 0
    assert any(n["type"] == "Campaign" for n in data["nodes"])


def test_api_detect_campaign_alert(client):
    """Tests POST /api/campaigns/detect-alert endpoint."""
    res = client.post("/api/campaigns/detect-alert", json=FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_A)
    assert res.status_code == 200
    data = res.json()

    assert data["is_campaign_detected"] is True
    assert data["campaign_id"] == "C-042"
    assert "This email shares infrastructure or behavioral characteristics" in data["message_alert"]
    assert len(data["strongest_reasons"]) > 0
    assert data["category_scores"]["infrastructure_similarity"] >= 50.0
