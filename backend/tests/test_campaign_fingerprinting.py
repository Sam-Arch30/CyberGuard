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


def seed_test_campaign_c042(db):
    from datetime import datetime, timezone
    import json
    from backend.db.models import CampaignModel, CampaignEmailModel

    correlator = CampaignCorrelator()
    fp = correlator.generate_fingerprint({
        "subject": "URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement",
        "from": "Robert Vance (CEO) <robert.vance@bank-corp-update.com>",
        "reply_to": "financial-operations-secure@wire-transfer-node.ru",
        "ips": ["185.220.101.42", "194.165.16.88", "194.26.29.112", "185.220.101.55", "194.5.249.18"],
        "domains": ["bank-corp-update.com", "wire-transfer-node.ru", "secure-wire-swift.org", "paypa1-secure-billing.com", "corp-settlement-gateway.net", "exec-finance-corp.net", "auth-portal-verify.biz", "shadow-node.ru"],
        "urls": [
            "https://bank-corp-update.com/auth/v2/secure_login.php?client=token9912",
            "https://wire-transfer-node.ru/dropzone/receipt_download.php?id=8819",
            "https://secure-wire-swift.org/verification/token_auth.aspx"
        ],
        "html_body": "<div class='email-wrapper'><table class='wire-table'><tr><td>Urgent Wire Settlement</td></tr><tr><td><a href='https://bank-corp-update.com/auth/v2/secure_login.php'>Confirm Wire Instructions</a></td></tr></table></div>",
        "plain_text_body": "Please process the attached Q3 executive wire transfer instructions immediately. This settlement must be executed today. Confirm wire payment details via secure portal.",
        "brands": ["BankCorp", "SWIFT", "Chase"],
        "attachments": [
            {"filename": "Vendor_Settlement_Instructions.pdf.exe", "sha256": "a8f7c9e1b2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "mime_type": "application/x-dosexec"}
        ]
    })
    fp_dict = fp.model_dump()
    fp_dict["category_scores"] = {
        "infrastructure_similarity": 92.0,
        "domain_similarity": 78.0,
        "url_similarity": 96.0,
        "content_similarity": 81.0,
        "template_similarity": 89.0,
        "authentication_similarity": 75.0,
        "attachment_similarity": 90.0,
        "overall_confidence": 91.0
    }

    c042 = CampaignModel(
        campaign_id="C-042",
        name="Global Financial Wire & Executive Impersonation Campaign",
        first_seen=datetime(2026, 8, 14, 9, 22, 10, tzinfo=timezone.utc),
        last_seen=datetime(2026, 9, 5, 10, 42, 15, tzinfo=timezone.utc),
        email_count=73,
        recipient_count=21,
        sender_count=14,
        domain_count=8,
        ip_count=5,
        asn_count=3,
        overall_confidence=91.0,
        dominant_attack_type="Business Email Compromise (BEC)",
        targeted_brands_json=json.dumps(["BankCorp Global", "Chase Commercial", "SWIFT Wire"]),
        targeted_organizations_json=json.dumps(["Finance Dept", "Treasury Operations", "Accounts Payable", "Executive Office"]),
        fingerprint_json=json.dumps(fp_dict),
        associated_iocs_json=json.dumps([
            {"type": "ip", "value": "185.220.101.42", "first_seen": "2026-08-14 09:22:10 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.98},
            {"type": "ip", "value": "194.165.16.88", "first_seen": "2026-08-16 11:15:00 UTC", "last_seen": "2026-09-04 18:20:00 UTC", "confidence": 0.92},
            {"type": "ip", "value": "194.26.29.112", "first_seen": "2026-08-20 14:02:11 UTC", "last_seen": "2026-09-03 08:30:19 UTC", "confidence": 0.88},
            {"type": "domain", "value": "bank-corp-update.com", "first_seen": "2026-08-14 09:22:10 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.96},
            {"type": "domain", "value": "wire-transfer-node.ru", "first_seen": "2026-08-15 08:00:00 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.95},
            {"type": "domain", "value": "secure-wire-swift.org", "first_seen": "2026-08-22 13:45:00 UTC", "last_seen": "2026-09-01 16:10:00 UTC", "confidence": 0.90},
            {"type": "url", "value": "https://bank-corp-update.com/auth/v2/secure_login.php", "first_seen": "2026-08-14 09:22:10 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.97},
            {"type": "url", "value": "https://wire-transfer-node.ru/dropzone/receipt_download.php", "first_seen": "2026-08-18 10:00:00 UTC", "last_seen": "2026-09-04 12:00:00 UTC", "confidence": 0.94},
            {"type": "hash", "value": "a8f7c9e1b2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9", "first_seen": "2026-08-25 15:30:00 UTC", "last_seen": "2026-09-05 10:42:15 UTC", "confidence": 0.99}
        ]),
        timeline_events_json=json.dumps([
            {"id": "c042-evt-1", "timestamp": "2026-08-14 09:22:10 UTC", "event_type": "first_email", "title": "First Campaign Wave Detected", "description": "Initial spear-phishing wire transfer lure sent to CFO office from robert.vance@bank-corp-update.com", "severity": "high", "indicators": ["robert.vance@bank-corp-update.com", "185.220.101.42"]},
            {"id": "c042-evt-2", "timestamp": "2026-08-18 14:05:22 UTC", "event_type": "new_domain", "title": "New Domain Infrastructure Registered: wire-transfer-node.ru", "description": "Attacker registered fallback dropzone domain through RegRu LLC with hidden WHOIS privacy proxy", "severity": "critical", "indicators": ["wire-transfer-node.ru"]},
            {"id": "c042-evt-3", "timestamp": "2026-08-24 16:30:00 UTC", "event_type": "infrastructure_change", "title": "Infrastructure Shift to Bulletproof Relay (194.165.16.88)", "description": "Origin SMTP hop shifted to newly routed subnet announced via AS49281 (ShadowNode Hosting)", "severity": "high", "indicators": ["194.165.16.88", "AS49281"]},
            {"id": "c042-evt-4", "timestamp": "2026-08-28 11:10:45 UTC", "event_type": "attachment_seen", "title": "Double-Extension Executable Attachment Introduced", "description": "Malicious payload Vendor_Settlement_Instructions.pdf.exe deployed across 18 target finance mailboxes", "severity": "critical", "indicators": ["a8f7c9e1b2d3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9"]},
            {"id": "c042-evt-5", "timestamp": "2026-09-05 10:42:15 UTC", "event_type": "escalation", "title": "High-Volume Wave Detected Across EMEA Branch", "description": "Over 24 concurrent wire transfer authorization lure emails detected within 30-minute window", "severity": "critical", "indicators": ["bank-corp-update.com", "185.220.101.42"]}
        ])
    )
    db.add(c042)
    db.flush()

    em1 = CampaignEmailModel(
        campaign_id=c042.id,
        email_id="EML-2026-8819",
        subject="URGENT: Executive Wire Transfer Instructions - Settlement #8819",
        sender="robert.vance@bank-corp-update.com",
        recipient="cfo-desk@megacorp.com",
        sent_at=datetime(2026, 9, 5, 10, 42, 15, tzinfo=timezone.utc),
        similarity_to_campaign=94.5,
        correlation_reasons_json=json.dumps(["Shared dropzone IP 185.220.101.42", "Direct credential harvester URL"])
    )
    em2 = CampaignEmailModel(
        campaign_id=c042.id,
        email_id="EML-2026-8820",
        subject="URGENT: Executive Wire Transfer Authorization - Settlement #8820",
        sender="accounting@bank-corp-update.com",
        recipient="treasury-ops@megacorp.com",
        sent_at=datetime(2026, 9, 5, 11, 0, 0, tzinfo=timezone.utc),
        similarity_to_campaign=91.0,
        correlation_reasons_json=json.dumps(["Shared dropzone IP 185.220.101.42", "Identical invoice HTML template"])
    )
    db.add(em1)
    db.add(em2)
    db.commit()


@pytest.fixture
def client(test_db):
    seed_test_campaign_c042(test_db)
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
