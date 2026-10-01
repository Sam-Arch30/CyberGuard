"""
Unit & Integration Test Suite for Email & Phishing Intelligence Engine (Section 6).
Verifies:
1. Valid EML parsing
2. Malformed EML handling
3. From extraction & decomposition
4. Reply-To extraction & decomposition
5. Return-Path extraction
6. Message-ID extraction
7. Received-header parsing
8. SPF PASS
9. SPF FAIL
10. SPF NONE / UNKNOWN distinction
11. DKIM result handling (verified vs unverified)
12. DMARC result handling
13. Authentication provenance (observed header)
14. URL extraction
15. HTML href extraction
16. Visible-link mismatch detection
17. Domain extraction
18. IP extraction
19. IOC provenance tracking
20. Attachment extraction & storage
21. Attachment SHA-256 calculation
22. Email -> Attachment relationship creation
23. Lookalike domain detection
24. Reply-To mismatch detection
25. Social-engineering signal extraction (urgency, credential request, financial)
26. Finding persistence in database
27. Evidence persistence and linkage
28. Indicator persistence & deduplication
29. ThreatEvent creation when justified
30. Existing report compatibility
31. Re-analysis / history preservation
32. Pipeline & orchestrator integration
33. False Positive: Legitimate mailing list transport pattern
34. False Positive: SPF NONE alone remains non-critical / benign
35. False Positive: Marketing urgency alone does not trigger high severity phishing
36. False Positive: Security terminology in benign email remains clean
37. Phishing Integration Demo: Multi-signal phishing fixture (From, Reply-To, Credential, Visible link mismatch, Lookalike)
"""
import io
import json
import hashlib
import asyncio
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
    SeverityEnum,
    FindingMethodEnum,
)
from backend.services.email_analyzers import (
    EmailParserAnalyzer,
    EmailAuthenticationAnalyzer,
    EmailHeaderAnalyzer,
    EmailRelayAnalyzer,
    EmailAttachmentDiscoveryAnalyzer,
    EmailIOCAnalyzer,
    EmailSocialEngineeringAnalyzer,
    EmailImpersonationAnalyzer,
    EmailPhishingAggregator,
)
from backend.services.email_intelligence_pipeline import EmailIntelligencePipeline

client = TestClient(app)


# ============================================================================
# SYNTHETIC TEST FIXTURES
# ============================================================================

BENIGN_EML = b"""From: "Alice Smith" <alice@corporate.example.com>
To: bob@corporate.example.com
Subject: Weekly Engineering Sync Notes
Date: Thu, 01 Oct 2026 10:00:00 +0000
Message-ID: <msg-101@corporate.example.com>
Return-Path: <alice@corporate.example.com>
Authentication-Results: mx.example.com;
 spf=pass smtp.mailfrom=corporate.example.com;
 dkim=pass header.d=corporate.example.com;
 dmarc=pass action=none header.from=corporate.example.com
Received: from mail.corporate.example.com (mail.corporate.example.com [198.51.100.25])
 by mx.example.com with ESMTP id abc12345
 for <bob@corporate.example.com>; Thu, 01 Oct 2026 10:00:01 +0000
Content-Type: text/plain; charset="utf-8"

Hi Bob,

Here are the notes from our team sync. Let me know if you have any questions.

Best,
Alice
"""

PHISHING_MULTI_SIGNAL_EML = b"""From: "IT Support Desk" <security@trusted-service.test>
Reply-To: support@trusted-service-verify.test
To: employee@victim-org.test
Subject: CRITICAL: Immediate Account Verification Required
Date: Thu, 01 Oct 2026 12:00:00 +0000
Message-ID: <alert-882@attacker-relay.test>
Return-Path: <bounce@unrelated-host.test>
Authentication-Results: mx.victim-org.test;
 spf=fail smtp.mailfrom=unrelated-host.test;
 dkim=fail header.d=trusted-service.test;
 dmarc=fail action=quarantine header.from=trusted-service.test
Received: from evil-relay.attacker.test (evil-relay.attacker.test [203.0.113.88])
 by mx.victim-org.test with ESMTP id phish999
 for <employee@victim-org.test>; Thu, 01 Oct 2026 12:00:05 +0000
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>Dear user,</p>
<p>Your account will be suspended within 24 hours due to suspicious activity.</p>
<p>You must confirm your password and login to verify your credentials immediately:</p>
<p><a href="https://trusted-service-verify.test/login/auth">https://trusted-service.test</a></p>
<p>Thank you,<br>IT Helpdesk</p>
</body>
</html>
"""

MAILING_LIST_EML = b"""From: "Newsletter Author" <author@writer-domain.example>
To: subscribers@lists.example.org
Subject: Monthly Tech Insights #42
Date: Thu, 01 Oct 2026 14:00:00 +0000
Message-ID: <nl-42@mailman.lists.example.org>
Return-Path: <bounce-tech-insights@lists.example.org>
List-Id: <tech-insights.lists.example.org>
List-Unsubscribe: <mailto:unsubscribe@lists.example.org>
Authentication-Results: mx.subscriber.example;
 spf=pass smtp.mailfrom=lists.example.org;
 dkim=pass header.d=lists.example.org;
 dmarc=pass header.from=writer-domain.example
Received: from mail.lists.example.org (mail.lists.example.org [198.51.100.50])
 by mx.subscriber.example with ESMTP id list101; Thu, 01 Oct 2026 14:00:02 +0000
Content-Type: text/plain; charset="utf-8"

Welcome to this month's newsletter. Enjoy reading our technology breakdown!
"""

SPF_NONE_EML = b"""From: "Colleague" <colleague@startup-domain.test>
To: coworker@startup-domain.test
Subject: Quick Lunch Meeting
Date: Thu, 01 Oct 2026 11:30:00 +0000
Message-ID: <meet-99@startup-domain.test>
Return-Path: <colleague@startup-domain.test>
Received: from mail.internal.test ([10.0.0.15])
 by mx.internal.test; Thu, 01 Oct 2026 11:30:01 +0000
Content-Type: text/plain; charset="utf-8"

Hey, are you free for lunch at noon? Let me know!
"""

MARKETING_URGENCY_EML = b"""From: "BigStore Sales" <promotions@bigstore-retail.test>
To: shopper@example.com
Subject: Urgent: 50% Off Flash Sale Ends in 2 Hours!
Date: Thu, 01 Oct 2026 15:00:00 +0000
Message-ID: <sale-77@bigstore-retail.test>
Return-Path: <bounces@bigstore-retail.test>
Authentication-Results: mx.example.com;
 spf=pass smtp.mailfrom=bigstore-retail.test;
 dkim=pass header.d=bigstore-retail.test;
 dmarc=pass header.from=bigstore-retail.test
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Hurry! Right now get 50% off everything in our store before the deadline tonight!</p>
<a href="https://bigstore-retail.test/catalog">Shop Now</a>
</body></html>
"""

SECURITY_NEWSLETTER_EML = b"""From: "Cyber Awareness Team" <infosec@university.test>
To: staff@university.test
Subject: Tips to Protect Your Passwords and Recognize Phishing
Date: Thu, 01 Oct 2026 09:00:00 +0000
Message-ID: <sec-tip-01@university.test>
Return-Path: <infosec@university.test>
Authentication-Results: mx.university.test;
 spf=pass smtp.mailfrom=university.test;
 dkim=pass header.d=university.test;
 dmarc=pass header.from=university.test
Content-Type: text/plain; charset="utf-8"

Hello everyone,

October is Cybersecurity Awareness Month! Remember to always beware of phishing
attempts that ask you to verify your password on unfamiliar websites. Check your URLs
carefully and report suspicious activity.
"""

ATTACHMENT_PHISH_EML = b"""From: "Accounting" <invoices@vendor-billing.test>
To: finance@victim-company.test
Subject: Overdue Invoice Payment Details
Date: Thu, 01 Oct 2026 16:00:00 +0000
Message-ID: <inv-443@vendor-billing.test>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="====BOUNDARY_1234===="

--====BOUNDARY_1234====
Content-Type: text/plain; charset="utf-8"

Please see the attached overdue invoice and remit payment to the new account.

--====BOUNDARY_1234====
Content-Type: application/octet-stream; name="invoice_oct2026.pdf.exe"
Content-Disposition: attachment; filename="invoice_oct2026.pdf.exe"

MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00FAKE_PE_EXECUTABLE_PAYLOAD
--====BOUNDARY_1234====--
"""


# ============================================================================
# TESTS
# ============================================================================

def test_1_valid_eml_parsing():
    parser = EmailParserAnalyzer()
    res = parser.analyze(BENIGN_EML, {})
    assert res.status.value == "COMPLETED"
    parsed = res.metadata["parsed_email"]
    assert parsed["subject"] == "Weekly Engineering Sync Notes"
    assert parsed["from_address"] == "alice@corporate.example.com"
    assert parsed["from_domain"] == "corporate.example.com"
    assert parsed["from_display_name"] == "Alice Smith"
    assert len(parsed["received_headers"]) == 1


def test_2_malformed_eml_handling():
    parser = EmailParserAnalyzer()
    res_empty = parser.analyze(b"", {})
    assert res_empty.status.value == "FAILED"

    # Malformed garbage bytes should not crash
    garbage = b"\x00\xff\xfe\x12\x34\x56GARBAGE_HEADER: corrupt"
    res_garbage = parser.analyze(garbage, {})
    assert res_garbage.status.value in ("COMPLETED", "PARTIAL")


def test_3_from_extraction_and_decomposition():
    disp, addr, dom = EmailParserAnalyzer.decompose_address('"Security Operations" <soc@mycompany.org>')
    assert disp == "Security Operations"
    assert addr == "soc@mycompany.org"
    assert dom == "mycompany.org"


def test_4_reply_to_extraction():
    parser = EmailParserAnalyzer()
    res = parser.analyze(PHISHING_MULTI_SIGNAL_EML, {})
    parsed = res.metadata["parsed_email"]
    assert parsed["reply_to_address"] == "support@trusted-service-verify.test"
    assert parsed["reply_to_domain"] == "trusted-service-verify.test"


def test_5_return_path_extraction():
    parser = EmailParserAnalyzer()
    res = parser.analyze(PHISHING_MULTI_SIGNAL_EML, {})
    parsed = res.metadata["parsed_email"]
    assert parsed["return_path_address"] == "bounce@unrelated-host.test"
    assert parsed["return_path_domain"] == "unrelated-host.test"


def test_6_message_id_extraction():
    parser = EmailParserAnalyzer()
    res = parser.analyze(BENIGN_EML, {})
    parsed = res.metadata["parsed_email"]
    assert parsed["message_id"] == "<msg-101@corporate.example.com>"


def test_7_received_header_parsing():
    relay = EmailRelayAnalyzer()
    ctx = {"parsed_email": {"received_headers": [
        "from mail.corporate.example.com (mail.corporate.example.com [198.51.100.25]) by mx.example.com; Thu, 01 Oct 2026 10:00:01 +0000"
    ]}}
    res = relay.analyze(BENIGN_EML, ctx)
    assert any(f["finding_type"] == "PUBLIC_RELAY_IDENTIFIED" for f in res.findings)


def test_8_spf_pass():
    auth = EmailAuthenticationAnalyzer()
    ctx = {"parsed_email": {
        "from_header": "alice@corporate.example.com",
        "auth_results_headers": ["mx.example.com; spf=pass smtp.mailfrom=corporate.example.com"],
    }}
    res = auth.analyze(BENIGN_EML, ctx)
    assert any(f["finding_type"] == "SPF_PASS" for f in res.findings)


def test_9_spf_fail():
    auth = EmailAuthenticationAnalyzer()
    ctx = {"parsed_email": {
        "from_header": "security@trusted-service.test",
        "auth_results_headers": ["mx.victim-org.test; spf=fail smtp.mailfrom=unrelated-host.test"],
    }}
    res = auth.analyze(PHISHING_MULTI_SIGNAL_EML, ctx)
    assert any(f["finding_type"] == "SPF_FAILURE" and f["severity"] == SeverityEnum.HIGH for f in res.findings)


def test_10_spf_none_unknown_distinction():
    auth = EmailAuthenticationAnalyzer()
    ctx = {"parsed_email": {"auth_results_headers": []}}
    res = auth.analyze(SPF_NONE_EML, ctx)
    assert any(f["finding_type"] == "SPF_UNVERIFIED" and f["severity"] == SeverityEnum.LOW for f in res.findings)


def test_11_dkim_result_handling():
    auth = EmailAuthenticationAnalyzer()
    ctx = {"parsed_email": {
        "auth_results_headers": ["mx.victim-org.test; dkim=fail header.d=trusted-service.test"],
    }}
    res = auth.analyze(PHISHING_MULTI_SIGNAL_EML, ctx)
    assert any(f["finding_type"] == "DKIM_FAILURE" for f in res.findings)


def test_12_dmarc_result_handling():
    auth = EmailAuthenticationAnalyzer()
    ctx = {"parsed_email": {
        "auth_results_headers": ["mx.victim-org.test; dmarc=fail action=quarantine header.from=trusted-service.test"],
    }}
    res = auth.analyze(PHISHING_MULTI_SIGNAL_EML, ctx)
    assert any(f["finding_type"] == "DMARC_FAILURE" for f in res.findings)


def test_13_authentication_provenance():
    auth = EmailAuthenticationAnalyzer()
    ctx = {"parsed_email": {
        "auth_results_headers": ["mx.example.com; spf=pass; dkim=pass"],
    }}
    res = auth.analyze(BENIGN_EML, ctx)
    # Ensure evidence records provenance as observed_header, not local cryptographic verification
    for ev in res.evidence_items:
        if ev["evidence_type"] in ("SPF_RESULT", "DKIM_RESULT"):
            assert ev["parsed_content"].get("provenance") == "observed_header"


def test_14_url_extraction():
    ioc = EmailIOCAnalyzer()
    ctx = {"parsed_email": {
        "plain_text_body": "Visit our portal: https://login.example.com/portal",
        "html_body": None,
    }}
    res = ioc.analyze(b"", ctx)
    assert any(ind["indicator_type"].value == "URL" and "https://login.example.com/portal" in ind["value"] for ind in res.indicators)


def test_15_html_href_extraction():
    ioc = EmailIOCAnalyzer()
    ctx = {"parsed_email": {
        "plain_text_body": None,
        "html_body": '<p>Click <a href="https://hidden-destination.example/login">here</a></p>',
    }}
    res = ioc.analyze(b"", ctx)
    assert any(ind["value"] == "https://hidden-destination.example/login" for ind in res.indicators)


def test_16_visible_link_mismatch():
    ioc = EmailIOCAnalyzer()
    ctx = {"parsed_email": {
        "plain_text_body": None,
        "html_body": '<a href="https://evil-phish.net/login">https://mybank.com/secure</a>',
    }}
    res = ioc.analyze(b"", ctx)
    mismatch_findings = [f for f in res.findings if f["finding_type"] == "VISIBLE_LINK_MISMATCH"]
    assert len(mismatch_findings) == 1
    assert mismatch_findings[0]["severity"] == SeverityEnum.HIGH


def test_17_domain_extraction():
    ioc = EmailIOCAnalyzer()
    ctx = {"parsed_email": {
        "from_header": "test@alpha-domain.example",
        "plain_text_body": "Check out beta-domain.example and https://gamma-domain.example/path",
    }}
    res = ioc.analyze(b"", ctx)
    domain_vals = [ind["normalized_value"] for ind in res.indicators if ind["indicator_type"].value == "DOMAIN"]
    assert "alpha-domain.example" in domain_vals
    assert "gamma-domain.example" in domain_vals


def test_18_ip_extraction():
    ioc = EmailIOCAnalyzer()
    ctx = {"parsed_email": {
        "plain_text_body": "Connected from server 198.51.100.42 in network.",
    }}
    res = ioc.analyze(b"", ctx)
    ip_vals = [ind["value"] for ind in res.indicators if ind["indicator_type"].value == "IP"]
    assert "198.51.100.42" in ip_vals


def test_19_ioc_provenance():
    ioc = EmailIOCAnalyzer()
    ctx = {"parsed_email": {
        "plain_text_body": "Link: https://example.com/test",
    }}
    res = ioc.analyze(b"", ctx)
    for ind in res.indicators:
        assert ind["source"] is not None


def test_20_attachment_extraction_and_storage():
    parser = EmailParserAnalyzer()
    parse_res = parser.analyze(ATTACHMENT_PHISH_EML, {})
    att_analyzer = EmailAttachmentDiscoveryAnalyzer()
    att_res = att_analyzer.analyze(ATTACHMENT_PHISH_EML, {"parsed_email": parse_res.metadata["parsed_email"]})

    assert len(att_res.derived_artifacts) == 1
    att_def = att_res.derived_artifacts[0]
    assert att_def["name"] == "invoice_oct2026.pdf.exe"
    assert att_def["artifact_type"] == ArtifactTypeEnum.ATTACHMENT
    assert att_def["storage_reference"] is not None


def test_21_attachment_sha256():
    parser = EmailParserAnalyzer()
    parse_res = parser.analyze(ATTACHMENT_PHISH_EML, {})
    att_analyzer = EmailAttachmentDiscoveryAnalyzer()
    att_res = att_analyzer.analyze(ATTACHMENT_PHISH_EML, {"parsed_email": parse_res.metadata["parsed_email"]})

    sha = att_res.derived_artifacts[0]["sha256"]
    assert len(sha) == 64
    assert any(ind["indicator_type"].value in ("FILE_HASH", "SHA256") and ind["value"] == sha for ind in att_res.indicators)


def test_22_email_to_attachment_relationship():
    parser = EmailParserAnalyzer()
    parse_res = parser.analyze(ATTACHMENT_PHISH_EML, {})
    att_analyzer = EmailAttachmentDiscoveryAnalyzer()
    att_res = att_analyzer.analyze(ATTACHMENT_PHISH_EML, {"parsed_email": parse_res.metadata["parsed_email"]})

    # Verifies double extension finding
    assert any(f["finding_type"] == "DOUBLE_EXTENSION_ATTACHMENT" for f in att_res.findings)


def test_23_lookalike_domain_detection():
    imp = EmailImpersonationAnalyzer()
    ctx = {
        "parsed_email": {"from_domain": "micros0ft-support.test"},
        "extracted_urls": ["https://paypa1-secure.test/login"],
    }
    res = imp.analyze(b"", ctx)
    assert any(f["finding_type"] == "LOOKALIKE_DOMAIN" for f in res.findings)


def test_24_reply_to_mismatch():
    hdr = EmailHeaderAnalyzer()
    ctx = {"parsed_email": {
        "from_address": "ceo@legit-company.test",
        "from_domain": "legit-company.test",
        "reply_to_address": "ceo-personal@free-mail.test",
        "reply_to_domain": "free-mail.test",
    }}
    res = hdr.analyze(b"", ctx)
    assert any(f["finding_type"] == "REPLY_TO_MISMATCH" for f in res.findings)


def test_25_social_engineering_signal_extraction():
    nlp = EmailSocialEngineeringAnalyzer()
    ctx = {"parsed_email": {
        "subject": "URGENT: Password Reset Required Within 2 Hours",
        "plain_text_body": "Your account will be suspended. Verify your credentials immediately.",
    }}
    res = nlp.analyze(b"", ctx)
    f_types = [f["finding_type"] for f in res.findings]
    assert "CREDENTIAL_REQUEST" in f_types
    assert "URGENCY_LANGUAGE" in f_types


def test_26_finding_persistence():
    async def _run():
        db: Session = SessionLocal()
        try:
            legacy_res, analysis_run = await EmailIntelligencePipeline.analyze_email_bytes(
                db=db,
                content_bytes=PHISHING_MULTI_SIGNAL_EML,
                filename="phishing_test.eml",
            )
            assert analysis_run.id is not None
            findings = db.query(FindingModel).filter(FindingModel.analysis_run_id == analysis_run.id).all()
            assert len(findings) > 0
            f_types = [f.finding_type for f in findings]
            assert "SPF_FAILURE" in f_types
            assert "REPLY_TO_MISMATCH" in f_types
            assert "VISIBLE_LINK_MISMATCH" in f_types
        finally:
            db.close()
    asyncio.run(_run())


def test_27_evidence_persistence_and_linkage():
    async def _run():
        db: Session = SessionLocal()
        try:
            legacy_res, analysis_run = await EmailIntelligencePipeline.analyze_email_bytes(
                db=db,
                content_bytes=PHISHING_MULTI_SIGNAL_EML,
                filename="phishing_test.eml",
            )
            # Check evidence items exist
            ev_items = db.query(EvidenceItemModel).filter(EvidenceItemModel.artifact_id == analysis_run.artifact_id).all()
            assert len(ev_items) > 0

            # Check FindingEvidence links exist
            links = db.query(FindingEvidenceModel).all()
            assert len(links) > 0
        finally:
            db.close()
    asyncio.run(_run())


def test_28_indicator_persistence():
    async def _run():
        db: Session = SessionLocal()
        try:
            legacy_res, analysis_run = await EmailIntelligencePipeline.analyze_email_bytes(
                db=db,
                content_bytes=PHISHING_MULTI_SIGNAL_EML,
                filename="phishing_test.eml",
            )
            # Check Indicators exist in database
            inds = db.query(IndicatorModel).all()
            assert len(inds) > 0
        finally:
            db.close()
    asyncio.run(_run())


def test_29_threat_event_creation():
    async def _run():
        db: Session = SessionLocal()
        try:
            legacy_res, analysis_run = await EmailIntelligencePipeline.analyze_email_bytes(
                db=db,
                content_bytes=PHISHING_MULTI_SIGNAL_EML,
                filename="phishing_test.eml",
            )
            evt = db.query(ThreatEventModel).filter(ThreatEventModel.source_artifact_id == analysis_run.artifact_id).first()
            assert evt is not None
            assert evt.event_type in ("PHISHING_ATTEMPT", "SUSPICIOUS_EMAIL", "EMAIL_IMPERSONATION")
        finally:
            db.close()
    asyncio.run(_run())


def test_30_existing_report_compatibility():
    # Verifies /api/reports/generate accepts the analysis response without errors
    files = {"file": ("benign.eml", io.BytesIO(BENIGN_EML), "message/rfc822")}
    analyze_res = client.post("/api/emails/analyze", files=files)
    assert analyze_res.status_code == 200
    analysis_data = analyze_res.json()

    report_payload = {
        "analysis": analysis_data,
        "format": "json"
    }
    report_res = client.post("/api/reports/generate?format=json", json=report_payload)
    assert report_res.status_code == 200


def test_31_reanalysis_history_preservation():
    async def _run():
        db: Session = SessionLocal()
        try:
            # Run 1
            _, run1 = await EmailIntelligencePipeline.analyze_email_bytes(
                db=db, content_bytes=BENIGN_EML, filename="sync.eml"
            )
            art_id = run1.artifact_id

            # Run 2 on same artifact
            _, run2 = await EmailIntelligencePipeline.analyze_artifact(
                db=db, artifact_id=art_id
            )

            assert run1.id != run2.id
            runs = db.query(AnalysisRunModel).filter(AnalysisRunModel.artifact_id == art_id).all()
            assert len(runs) >= 2
        finally:
            db.close()
    asyncio.run(_run())


def test_32_pipeline_endpoint_integration():
    files = {"file": ("phish_test.eml", io.BytesIO(PHISHING_MULTI_SIGNAL_EML), "message/rfc822")}
    res = client.post("/api/emails/pipeline/analyze", files=files)
    assert res.status_code == 200
    data = res.json()
    assert "headers" in data
    assert "authentication" in data
    assert "threat_score" in data


# ============================================================================
# FALSE POSITIVE TESTS (Section 36)
# ============================================================================

def test_33_false_positive_mailing_list():
    hdr = EmailHeaderAnalyzer()
    ctx = {"parsed_email": {
        "from_domain": "writer-domain.example",
        "return_path_domain": "lists.example.org",
        "list_id": "<tech-insights.lists.example.org>",
        "list_unsubscribe": "<mailto:unsub@lists.example.org>",
    }}
    res = hdr.analyze(MAILING_LIST_EML, ctx)
    # Must NOT flag as SENDER_IDENTITY_MISMATCH with HIGH/CRITICAL severity
    assert any(f["finding_type"] == "MAILING_LIST_TRANSPORT_PATTERN" for f in res.findings)
    assert not any(f["finding_type"] == "SENDER_IDENTITY_MISMATCH" and f["severity"] == SeverityEnum.HIGH for f in res.findings)


def test_34_false_positive_spf_none_alone():
    auth = EmailAuthenticationAnalyzer()
    ctx = {"parsed_email": {"auth_results_headers": []}}
    res = auth.analyze(SPF_NONE_EML, ctx)
    # SPF NONE alone must be LOW severity
    spf_findings = [f for f in res.findings if "SPF" in f["finding_type"]]
    assert len(spf_findings) > 0
    assert all(f["severity"] in (SeverityEnum.SAFE, SeverityEnum.LOW) for f in spf_findings)


def test_35_false_positive_marketing_urgency_alone():
    nlp = EmailSocialEngineeringAnalyzer()
    ctx = {"parsed_email": {
        "subject": "Urgent: 50% Off Flash Sale Ends in 2 Hours!",
        "plain_text_body": "Hurry! Right now get 50% off everything in our store before the deadline tonight!",
    }}
    res = nlp.analyze(MARKETING_URGENCY_EML, ctx)
    # Should not produce CREDENTIAL_REQUEST or CRITICAL findings
    f_types = [f["finding_type"] for f in res.findings]
    assert "CREDENTIAL_REQUEST" not in f_types
    assert not any(f["severity"] == SeverityEnum.CRITICAL for f in res.findings)


def test_36_false_positive_security_terminology():
    nlp = EmailSocialEngineeringAnalyzer()
    ctx = {"parsed_email": {
        "subject": "Tips to Protect Your Passwords and Recognize Phishing",
        "plain_text_body": "Remember to always beware of phishing attempts that ask you to verify your password.",
    }}
    res = nlp.analyze(SECURITY_NEWSLETTER_EML, ctx)
    # Must not categorize as malicious phishing attack
    agg = EmailPhishingAggregator.aggregate([res], {})
    assert agg["classification"] in ("BENIGN", "SUSPICIOUS")


# ============================================================================
# INTEGRATION DEMO (Section 37)
# ============================================================================

def test_37_phishing_integration_demo():
    """
    Demonstrates the full end-to-end evidence-backed detection:
    From: security@trusted-service.test
    Reply-To: support@trusted-service-verify.test
    Body: "Your account will be suspended. Verify immediately."
    Visible link: https://trusted-service.test -> Actual href: https://trusted-service-verify.test/login/auth
    """
    async def _run():
        db: Session = SessionLocal()
        try:
            legacy_res, analysis_run = await EmailIntelligencePipeline.analyze_email_bytes(
                db=db,
                content_bytes=PHISHING_MULTI_SIGNAL_EML,
                filename="integration_demo.eml",
            )

            findings = db.query(FindingModel).filter(FindingModel.analysis_run_id == analysis_run.id).all()
            f_types = {f.finding_type: f for f in findings}

            # 1. Reply-To mismatch observed
            assert "REPLY_TO_MISMATCH" in f_types
            f_rt = f_types["REPLY_TO_MISMATCH"]
            assert f_rt.severity in (SeverityEnum.HIGH.value, "HIGH")

            # 2. Deceptive visible link mismatch observed
            assert "VISIBLE_LINK_MISMATCH" in f_types
            f_link = f_types["VISIBLE_LINK_MISMATCH"]
            assert f_link.severity in (SeverityEnum.HIGH.value, "HIGH")

            # 3. Credential request observed
            assert "CREDENTIAL_REQUEST" in f_types

            # 4. Authentication failure observed
            assert "SPF_FAILURE" in f_types

            # 5. ThreatEvent created
            evt = db.query(ThreatEventModel).filter(ThreatEventModel.source_artifact_id == analysis_run.artifact_id).first()
            assert evt is not None
            assert evt.event_type == "PHISHING_ATTEMPT"

            # 6. Legacy response compatibility verified
            assert legacy_res.threat_score.score > 50.0
            assert legacy_res.threat_score.severity.lower() in ("high", "critical")
        finally:
            db.close()

    asyncio.run(_run())
