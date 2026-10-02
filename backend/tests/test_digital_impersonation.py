"""
Comprehensive Test Suite for Section 12 — Digital Impersonation Detection Engine.
Validates:
1. Protected identity creation, domain normalization, and revision tracking.
2. Identity claim extraction from email, website, and URL artifacts.
3. Email display-name spoofing vs. authentic senders.
4. Reply-To domain deception.
5. Authorized delegated sender handling (e.g. Mailchimp/SendGrid).
6. Lookalike, homoglyph, and typosquatting domain detection.
7. Deceptive brand subdomain hierarchies (e.g. paypal.com.evil.test).
8. Website title brand claims, login-portal context, and credential harvesting.
9. Executive & internal authority role impersonation and BEC intent.
10. Cross-channel aggregation (Email + URL + Website claiming same protected identity).
11. Contradicting evidence calibration (DMARC pass, legitimate infrastructure).
12. Scoped assessment classification and ThreatEvent creation.
13. False-positive safety (newsletters, common names, articles, legitimate IDNs).
14. Audit logging on identity configuration changes.
15. REST API endpoints and re-analysis support.
"""
import json
import uuid
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    ThreatEventModel,
    EntityModel,
    RelationshipModel,
    AuditLogModel,
    ProtectedIdentityModel,
)
from backend.schemas.unified import ArtifactTypeEnum, SeverityEnum
from backend.schemas.impersonation import (
    IdentityClaimTypeEnum,
    ReferenceSourceEnum,
    VerificationStatusEnum,
    ComparisonOutcomeEnum,
    ImpersonationClassificationEnum,
    IdentityEvidenceCategoryEnum,
    IdentityClaim,
    ProtectedIdentityProfile,
    CreateProtectedIdentityRequest,
    UpdateProtectedIdentityRequest,
    ImpersonationAnalysisRequest,
)
from backend.services.impersonation_service import (
    ProtectedIdentityManager,
    IdentityClaimExtractor,
    IdentityComparisonService,
    DigitalImpersonationPipeline,
    global_protected_identity_manager,
    global_impersonation_pipeline,
)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def api_client():
    return TestClient(app)


# ============================================================================
# 1. PROTECTED IDENTITY PROFILE MANAGEMENT & NORMALIZATION
# ============================================================================

def test_01_protected_identity_creation(db_session: Session):
    """Verifies creating a protected reference identity with audit logging."""
    manager = ProtectedIdentityManager()
    req = CreateProtectedIdentityRequest(
        display_name="MegaBank International",
        entity_type=IdentityClaimTypeEnum.ORGANIZATION,
        trusted_domains=["megabank.com", "online.megabank.com"],
        trusted_email_patterns=["*@megabank.com"],
        known_names=["MegaBank", "MegaBank Security", "MegaBank Support"],
        known_brand_terms=["megabank"],
        authorized_delegated_senders=["sendgrid.net"],
        source=ReferenceSourceEnum.ORGANIZATION_CONFIGURED,
        verification_status=VerificationStatusEnum.VERIFIED,
    )

    profile = manager.create_profile(req, db=db_session, user="Admin Auditor")
    assert profile.id is not None
    assert profile.display_name == "MegaBank International"
    assert profile.revision == 1
    assert "megabank.com" in profile.trusted_domains

    # Verify audit log in DB
    audit = db_session.query(AuditLogModel).filter(
        AuditLogModel.resource_id == profile.id,
        AuditLogModel.action == "PROTECTED_IDENTITY_CREATED",
    ).first()
    assert audit is not None
    assert audit.user == "Admin Auditor"


def test_02_trusted_domain_normalization():
    """Verifies domain case, trailing dots, and whitespace normalization."""
    manager = ProtectedIdentityManager()
    req = CreateProtectedIdentityRequest(
        display_name="CloudSecure Inc",
        trusted_domains=["  CloudSecure.COM.  ", "PORTAL.cloudsecure.com  "],
        known_brand_terms=[" CLOUDSECURE "],
    )
    profile = manager.create_profile(req)
    assert "cloudsecure.com" in profile.trusted_domains
    assert "portal.cloudsecure.com" in profile.trusted_domains
    assert "cloudsecure" in profile.known_brand_terms


def test_03_profile_update_and_revision_increment(db_session: Session):
    """Verifies profile update increments revision number and records domain additions."""
    manager = ProtectedIdentityManager()
    req = CreateProtectedIdentityRequest(
        display_name="GlobalCorp",
        trusted_domains=["globalcorp.com"],
    )
    profile = manager.create_profile(req, db=db_session)
    orig_rev = profile.revision

    # Update domains
    up_req = UpdateProtectedIdentityRequest(
        trusted_domains=["globalcorp.com", "globalcorp.net"],
    )
    updated = manager.update_profile(profile.id, up_req, db=db_session, user="Auditor Two")
    assert updated is not None
    assert updated.revision == orig_rev + 1
    assert "globalcorp.net" in updated.trusted_domains

    # Audit records
    audit = db_session.query(AuditLogModel).filter(
        AuditLogModel.resource_id == profile.id,
        AuditLogModel.action.contains("TRUSTED_DOMAIN_ADDED"),
    ).first()
    assert audit is not None


# ============================================================================
# 2. IDENTITY CLAIM EXTRACTION
# ============================================================================

def test_04_identity_claim_extraction_email():
    """Extracts identity claims from From display name, address, and body roles."""
    email_data = {
        "from_display_name": "Acme Security Team",
        "from_address": "security@acme.example",
        "from_domain": "acme.example",
        "reply_to_address": "billing@acme.example",
        "reply_to_domain": "acme.example",
        "subject": "Urgent: CEO Directive for Security Review",
        "body_text": "Please confirm your credentials with IT Support immediately.",
    }

    claims = IdentityClaimExtractor.extract_from_email(email_data)
    assert len(claims) >= 2
    claim_names = [c.claimed_name for c in claims]
    assert "Acme Security Team" in claim_names
    assert "CEO" in claim_names or "IT Support" in claim_names


def test_05_identity_claim_extraction_website_and_url():
    """Extracts identity claims from website HTML title and deceptive subdomains."""
    web_data = {
        "title": "Acme Employee Portal - Login",
        "url": "https://acme.portal.fake-server.test/auth",
        "base_domain": "fake-server.test",
        "brand_mentions": ["Acme", "Acme Corporation"],
    }
    claims = IdentityClaimExtractor.extract_from_website(web_data)
    claimed_names = [c.claimed_name for c in claims]
    assert any("Acme" in name for name in claimed_names)

    # URL extractor
    url_claims = IdentityClaimExtractor.extract_from_url("https://paypal.com.account-update.fake.test/login")
    assert len(url_claims) >= 1
    assert any("paypal" in c.claimed_name.lower() for c in url_claims)


# ============================================================================
# 3. EMAIL IDENTITY SIGNALS & SENDER COMPARISON
# ============================================================================

def test_06_display_name_impersonation_detection():
    """
    Scenario: Display name claims 'Acme Security', but From address is random user on unrelated domain.
    Expected: DISPLAY_NAME_IMPERSONATION_SIGNAL (IMP_NAME_001).
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Acme Security",
        "from_address": "attacker101@unrelated-hacker.test",
        "from_domain": "unrelated-hacker.test",
        "subject": "Urgent Security Alert",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    assert res.assessment.target_identity == "Acme Corporation"
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "DISPLAY_NAME_IMPERSONATION_SIGNAL" in finding_types
    assert res.assessment.classification == ImpersonationClassificationEnum.IMPERSONATION_SUSPECTED


def test_07_reply_to_mismatch_detection():
    """
    Scenario: From domain is legitimate/trusted, but Reply-To redirects replies to attacker domain.
    Expected: IDENTITY_REPLY_TO_MISMATCH (IMP_RT_001).
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Acme Corporation",
        "from_address": "billing@acme.example",
        "from_domain": "acme.example",
        "reply_to_address": "phish_collector@attacker-inbox.test",
        "reply_to_domain": "attacker-inbox.test",
        "subject": "Invoice Details",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "IDENTITY_REPLY_TO_MISMATCH" in finding_types


def test_08_authorized_delegated_sender_handling():
    """
    Scenario: Marketing newsletter sent via configured authorized delegated sender (Mailchimp).
    Expected: AUTHORIZED_DELEGATED_SENDER finding, NO_IMPERSONATION_EVIDENCE.
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Acme Support",
        "from_address": "newsletter@mailchimp.com",
        "from_domain": "mailchimp.com",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "subject": "Monthly Customer Update",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    contra_types = [f.finding_type for f in res.assessment.contradicting_findings]
    assert "AUTHORIZED_DELEGATED_SENDER" in contra_types
    assert res.assessment.classification == ImpersonationClassificationEnum.NO_IMPERSONATION_EVIDENCE


def test_09_legitimate_authenticated_email_no_impersonation():
    """
    Scenario: Authentic email from acme.example with matching domain and passing DKIM/DMARC.
    Expected: NO_IMPERSONATION_EVIDENCE.
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Acme Corporation",
        "from_address": "support@acme.example",
        "from_domain": "acme.example",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "subject": "Welcome to Acme",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    assert res.assessment.classification == ImpersonationClassificationEnum.NO_IMPERSONATION_EVIDENCE
    assert res.assessment.risk_score == 0.0


# ============================================================================
# 4. DOMAIN & LOOKALIKE IMPERSONATION
# ============================================================================

def test_10_typosquatting_lookalike_domain_detection():
    """
    Scenario: Email From domain is 'acm3.example' (Levenshtein distance 1 from 'acme.example').
    Expected: DOMAIN_IMPERSONATION_SIGNAL (IMP_DOM_001).
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Support",
        "from_address": "support@acm3.example",
        "from_domain": "acm3.example",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "DOMAIN_IMPERSONATION_SIGNAL" in finding_types
    assert res.assessment.target_identity == "Acme Corporation"


def test_11_homoglyph_unicode_domain_detection():
    """
    Scenario: Cyrillic 'a' (\u0430) replaces Latin 'a' in 'аcme.example'.
    Expected: HOMOGLYPH_IMPERSONATION_SIGNAL (IMP_HOM_001).
    """
    pipeline = DigitalImpersonationPipeline()
    # Cyrillic small letter a: \u0430
    cyrillic_domain = "\u0430cme.example"
    email_data = {
        "from_display_name": "Security Notice",
        "from_address": f"notice@{cyrillic_domain}",
        "from_domain": cyrillic_domain,
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "HOMOGLYPH_IMPERSONATION_SIGNAL" in finding_types


def test_12_deceptive_brand_subdomain():
    """
    Scenario: Host is 'acme.example.phishing-portal.test'.
    Expected: DECEPTIVE_BRAND_SUBDOMAIN (IMP_SUB_001).
    """
    pipeline = DigitalImpersonationPipeline()
    url_data = {"url": "https://acme.example.phishing-portal.test/login"}

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.URL, url_data=url_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "DECEPTIVE_BRAND_SUBDOMAIN" in finding_types


# ============================================================================
# 5. WEBSITE IMPERSONATION & CREDENTIAL HARVESTING
# ============================================================================

def test_13_website_title_brand_claim_mismatch():
    """
    Scenario: Web page title claims 'Acme Employee Portal', but hosted on 'unrelated-host.test'.
    Expected: WEBSITE_BRAND_CLAIM and WEBSITE_IDENTITY_MISMATCH.
    """
    pipeline = DigitalImpersonationPipeline()
    web_data = {
        "title": "Acme Employee Portal - Welcome",
        "url": "https://unrelated-host.test/home",
        "base_domain": "unrelated-host.test",
        "has_login_form": False,
        "has_password_field": False,
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.URL, website_data=web_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "WEBSITE_BRAND_CLAIM" in finding_types
    assert "WEBSITE_IDENTITY_MISMATCH" in finding_types


def test_14_credential_harvesting_fake_login_portal():
    """
    Scenario: Fake login page claiming 'Acme Corporation' with active password fields on untrusted domain.
    Expected: CREDENTIAL_HARVESTING_IMPERSONATION_SUSPECTED (IMP_HARV_001) & STRONG_IMPERSONATION_INDICATORS.
    """
    pipeline = DigitalImpersonationPipeline()
    web_data = {
        "title": "Acme Account Login",
        "url": "https://fake-login-collector.test/auth",
        "base_domain": "fake-login-collector.test",
        "has_login_form": True,
        "has_password_field": True,
        "has_cross_domain_form": True,
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.URL, website_data=web_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "CREDENTIAL_HARVESTING_IMPERSONATION_SUSPECTED" in finding_types
    assert res.assessment.classification == ImpersonationClassificationEnum.STRONG_IMPERSONATION_INDICATORS


def test_15_authentic_website_on_trusted_domain():
    """
    Scenario: Website title claims 'Acme' and is hosted on 'acme.example'.
    Expected: AUTHENTIC_WEBSITE_DESTINATION, NO_IMPERSONATION_EVIDENCE.
    """
    pipeline = DigitalImpersonationPipeline()
    web_data = {
        "title": "Acme Corporate Portal",
        "url": "https://acme.example/login",
        "base_domain": "acme.example",
        "has_login_form": True,
        "has_password_field": True,
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.URL, website_data=web_data)
    contra_types = [f.finding_type for f in res.assessment.contradicting_findings]
    assert "AUTHENTIC_WEBSITE_DESTINATION" in contra_types
    assert res.assessment.classification == ImpersonationClassificationEnum.NO_IMPERSONATION_EVIDENCE


# ============================================================================
# 6. EXECUTIVE & AUTHORITY IMPERSONATION (BEC)
# ============================================================================

def test_16_executive_impersonation_detection():
    """
    Scenario: From display name matches configured executive 'Alice Example', but from random address.
    Expected: EXECUTIVE_IMPERSONATION_SUSPECTED (IMP_EXEC_001).
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Alice Example",
        "from_address": "alice.exec99@freemail-service.test",
        "from_domain": "freemail-service.test",
        "subject": "Quick question regarding project",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "EXECUTIVE_IMPERSONATION_SUSPECTED" in finding_types
    assert res.assessment.classification == ImpersonationClassificationEnum.STRONG_IMPERSONATION_INDICATORS


def test_17_business_email_compromise_bec_detection():
    """
    Scenario: Executive impersonation of 'Alice Example' combined with urgent wire transfer request.
    Expected: BUSINESS_EMAIL_IMPERSONATION_SUSPECTED (IMP_BEC_001).
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Alice Example",
        "from_address": "alice.exec99@freemail-service.test",
        "from_domain": "freemail-service.test",
        "subject": "Urgent Wire Transfer Required Today",
        "body_text": "Please process an immediate bank transfer for the attached vendor invoice before 5pm.",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "BUSINESS_EMAIL_IMPERSONATION_SUSPECTED" in finding_types


def test_18_generic_authority_role_impersonation():
    """
    Scenario: Sender claims 'IT Support' role with external untrusted domain.
    Expected: AUTHORITY_IMPERSONATION_SIGNAL (IMP_AUTH_001).
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Support Agent",
        "from_address": "agent@external-temp.test",
        "from_domain": "external-temp.test",
        "subject": "Urgent Notice from IT Support",
        "body_text": "Internal IT Support requests password update.",
    }

    res = pipeline.analyze(
        artifact_type=ArtifactTypeEnum.EMAIL,
        email_data=email_data,
        target_identity_hint="sys-prof-acme",
    )
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "AUTHORITY_IMPERSONATION_SIGNAL" in finding_types


# ============================================================================
# 7. CROSS-CHANNEL CORRELATION
# ============================================================================

def test_19_cross_channel_correlation_email_url_website():
    """
    Scenario:
    1. Email display name claims 'Acme Security' (From: security@acme-support.test)
    2. Email contains URL: https://acme-login.test/
    3. Website title is 'Acme Account Verification' with password form.
    Expected:
    All signals bind to 'Acme Corporation' reference identity; classification is STRONG_IMPERSONATION_INDICATORS.
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Acme Security",
        "from_address": "security@acme-support.test",
        "from_domain": "acme-support.test",
        "reply_to_address": "verify@acme-login.test",
        "reply_to_domain": "acme-login.test",
    }
    url_data = {"url": "https://acme-login.test/"}
    web_data = {
        "title": "Acme Account Verification",
        "url": "https://acme-login.test/",
        "base_domain": "acme-login.test",
        "has_login_form": True,
        "has_password_field": True,
    }

    res = pipeline.analyze(
        artifact_type=ArtifactTypeEnum.EMAIL,
        email_data=email_data,
        url_data=url_data,
        website_data=web_data,
    )

    assert res.assessment.target_identity == "Acme Corporation"
    finding_types = {f.finding_type for f in res.assessment.supporting_findings}
    assert "DISPLAY_NAME_IMPERSONATION_SIGNAL" in finding_types
    assert "CREDENTIAL_HARVESTING_IMPERSONATION_SUSPECTED" in finding_types
    assert res.assessment.classification == ImpersonationClassificationEnum.STRONG_IMPERSONATION_INDICATORS


# ============================================================================
# 8. FALSE-POSITIVE SAFETY TESTS
# ============================================================================

def test_20_false_positive_common_human_name():
    """
    Scenario: Single first name or non-executive common name (e.g. 'John')
    does not trigger executive impersonation.
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "John",
        "from_address": "john@external-freemail.test",
        "from_domain": "external-freemail.test",
        "subject": "Lunch meeting tomorrow?",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    finding_types = [f.finding_type for f in res.assessment.supporting_findings]
    assert "EXECUTIVE_IMPERSONATION_SUSPECTED" not in finding_types


def test_21_false_positive_unconfigured_brand_mention():
    """
    Scenario: Content mentions a company name for which no protected identity exists.
    Expected: INSUFFICIENT_EVIDENCE / limitations, NOT malicious declaration.
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Unknown Startup",
        "from_address": "info@unknown-startup-xyz.test",
        "from_domain": "unknown-startup-xyz.test",
        "subject": "Quarterly News",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    assert res.assessment.classification == ImpersonationClassificationEnum.INSUFFICIENT_EVIDENCE
    assert res.assessment.risk_score == 0.0
    assert len(res.assessment.supporting_findings) == 0


def test_22_false_positive_dmarc_pass_reduces_suspicion():
    """
    Scenario: Display name claims 'Google', From is google.com, DKIM & DMARC pass.
    Expected: Contradicting evidence discount ensures NO_IMPERSONATION_EVIDENCE.
    """
    pipeline = DigitalImpersonationPipeline()
    email_data = {
        "from_display_name": "Google Security",
        "from_address": "no-reply@google.com",
        "from_domain": "google.com",
        "spf_result": "pass",
        "dkim_result": "pass",
        "dmarc_result": "pass",
        "subject": "Security Alert for your Google Account",
    }

    res = pipeline.analyze(artifact_type=ArtifactTypeEnum.EMAIL, email_data=email_data)
    assert res.assessment.classification == ImpersonationClassificationEnum.NO_IMPERSONATION_EVIDENCE
    assert res.assessment.risk_score == 0.0


# ============================================================================
# 9. DATABASE PERSISTENCE & CANONICAL GRAPH TESTS
# ============================================================================

def test_23_canonical_persistence_and_relationships(db_session: Session):
    """
    Scenario: Run impersonation analysis with an ArtifactModel ID in the database.
    Verifies creation of:
    - AnalysisRunModel
    - FindingModel & FindingEvidenceModel
    - EntityModel (reference organization)
    - RelationshipModel (CLAIMS_IDENTITY, TARGETS)
    - ThreatEventModel
    """
    pipeline = DigitalImpersonationPipeline()

    # 1. Create source Artifact
    art = ArtifactModel(
        id=f"art-imp-{uuid.uuid4().hex[:8]}",
        artifact_type=ArtifactTypeEnum.EMAIL.value,
        name="phish_sample.eml",
        source="TEST",
        mime_type="message/rfc822",
        size=1024,
        sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
    )
    db_session.add(art)
    db_session.commit()

    email_data = {
        "from_display_name": "Acme Security",
        "from_address": "hacker@evil-spoof.test",
        "from_domain": "evil-spoof.test",
        "subject": "Password Expired",
    }

    res = pipeline.analyze(
        artifact_type=ArtifactTypeEnum.EMAIL,
        email_data=email_data,
        artifact_id=art.id,
        db=db_session,
    )

    assert res.analysis_run_id is not None
    assert len(res.entities_created) >= 1
    assert len(res.relationships_created) >= 2
    assert len(res.threat_events_created) >= 1

    # Verify AnalysisRun
    run = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.id == res.analysis_run_id).first()
    assert run is not None
    assert run.artifact_id == art.id

    # Verify RelationshipModel
    rel = db_session.query(RelationshipModel).filter(
        RelationshipModel.source_id == art.id,
        RelationshipModel.relationship_type == "CLAIMS_IDENTITY",
    ).first()
    assert rel is not None

    # Verify ThreatEventModel
    te = db_session.query(ThreatEventModel).filter(
        ThreatEventModel.source_artifact_id == art.id,
    ).first()
    assert te is not None
    assert te.event_type in ("DIGITAL_IMPERSONATION_SUSPECTED", "BRAND_IMPERSONATION_SUSPECTED")


def test_24_reanalysis_creates_new_run_without_destroying_history(db_session: Session):
    """
    Verifies that reanalyzing an artifact produces a new distinct AnalysisRunModel
    while preserving original historical records.
    """
    pipeline = DigitalImpersonationPipeline()
    art_id = f"art-re-{uuid.uuid4().hex[:8]}"
    email_data = {
        "from_display_name": "Acme Support",
        "from_address": "random@attacker-domain.test",
        "from_domain": "attacker-domain.test",
    }

    art = ArtifactModel(
        id=art_id,
        artifact_type=ArtifactTypeEnum.EMAIL.value,
        name="test_email.eml",
        source="TEST",
        mime_type="message/rfc822",
        size=512,
        sha256="ffff1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
        metadata_json=json.dumps({"email_data": email_data}),
    )
    db_session.add(art)
    db_session.commit()

    # Initial Run
    res1 = pipeline.analyze(
        artifact_type=ArtifactTypeEnum.EMAIL,
        email_data=email_data,
        artifact_id=art_id,
        db=db_session,
    )
    run_1 = res1.analysis_run_id

    # Second Run (Re-analysis)
    res2 = pipeline.analyze(
        artifact_type=ArtifactTypeEnum.EMAIL,
        email_data=email_data,
        artifact_id=art_id,
        db=db_session,
    )
    run_2 = res2.analysis_run_id

    assert run_1 != run_2
    runs = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id == art_id).all()
    assert len(runs) >= 2


# ============================================================================
# 10. REST API ROUTE TESTS
# ============================================================================

def test_25_api_profiles_crud(api_client: TestClient):
    """Verifies REST API endpoints for profile CRUD."""
    # 1. Create Profile
    new_prof = {
        "display_name": "Test Org API",
        "entity_type": "ORGANIZATION",
        "trusted_domains": ["testorg-api.example"],
        "known_names": ["Test Org"],
        "authorized_delegated_senders": ["mailgun.org"],
    }
    create_res = api_client.post("/api/impersonation/profiles", json=new_prof)
    assert create_res.status_code == 201
    created_id = create_res.json()["id"]

    # 2. Get Profile
    get_res = api_client.get(f"/api/impersonation/profiles/{created_id}")
    assert get_res.status_code == 200
    assert get_res.json()["display_name"] == "Test Org API"

    # 3. Update Profile
    update_data = {"display_name": "Test Org API Updated"}
    put_res = api_client.put(f"/api/impersonation/profiles/{created_id}", json=update_data)
    assert put_res.status_code == 200
    assert put_res.json()["display_name"] == "Test Org API Updated"
    assert put_res.json()["revision"] == 2

    # 4. List Profiles
    list_res = api_client.get("/api/impersonation/profiles")
    assert list_res.status_code == 200
    assert any(p["id"] == created_id for p in list_res.json())

    # 5. Delete Profile (Deactivation)
    del_res = api_client.delete(f"/api/impersonation/profiles/{created_id}")
    assert del_res.status_code == 204


def test_26_api_analyze_endpoint(api_client: TestClient):
    """Verifies POST /api/impersonation/analyze."""
    payload = {
        "artifact_type": "EMAIL",
        "email_data": {
            "from_display_name": "PayPal Support",
            "from_address": "support@paypa1-security.test",
            "from_domain": "paypa1-security.test",
            "subject": "Account Suspended",
        },
    }
    res = api_client.post("/api/impersonation/analyze", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["assessment"]["target_identity"] == "PayPal"
    assert data["assessment"]["classification"] == "IMPERSONATION_SUSPECTED"


def test_27_api_audit_logs_endpoint(api_client: TestClient):
    """Verifies GET /api/impersonation/audit-logs."""
    res = api_client.get("/api/impersonation/audit-logs?limit=10")
    assert res.status_code == 200
    assert isinstance(res.json(), list)
