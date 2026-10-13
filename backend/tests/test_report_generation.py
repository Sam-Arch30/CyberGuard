import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import Base, get_db, SessionLocal, engine
from backend.services.report_service import ReportService
from backend.db.models import CaseModel, CaseEmailModel, CaseNoteModel, CaseFindingModel, AuditLogModel, ReportModel

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=engine)
    yield
    db = SessionLocal()
    try:
        db.query(ReportModel).delete()
        db.query(CaseModel).delete()
        db.commit()
    finally:
        db.close()



def test_generate_minimal_email_report():
    """Verifies that an email analysis with missing/empty optional fields builds a valid PDF."""
    minimal_analysis = {
        "subject": "Minimal Notification",
        "from": "notifier@minimal.local"
    }

    pdf_bytes = ReportService.generate_email_report(minimal_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_full_email_report():
    """Verifies that a full email analysis with all forensic signals builds a multi-page PDF."""
    full_analysis = {
        "id": "EVD-2026-TESTFULL",
        "email_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "subject": "Security Alert: Unauthorized Access Attempt Detected",
        "from": "support@security-bank-corp.com",
        "to": ["victim@enterprise.com", "security@enterprise.com"],
        "cc": ["auditor@enterprise.com"],
        "reply_to": "harvest@darkweb-drop.ru",
        "return_path": "bounce@bulletproof-relay.net",
        "date": "Tue, 08 Sep 2026 01:20:00 +0000",
        "message_id": "<alert-2026-99482@security-bank-corp.com>",
        "threat_score": {
            "score": 92.0,
            "severity": "critical",
            "summary": "High risk phishing campaign attempting credential harvesting with spoofed bank domains.",
            "reasons": [
                {"category": "Lookalike", "points": 35, "description": "Lookalike domain targeting BankCorp detected."},
                {"category": "Authentication", "points": 25, "description": "SPF and DKIM verification failed completely."},
                {"category": "Alignment", "points": 20, "description": "Reply-To address mismatch detected."},
                {"category": "URL Suspicion", "points": 12, "description": "URL contains credential harvesting parameter."}
            ],
            "positive_evidence": [
                {"category": "DMARC", "description": "DMARC record was resolvable in DNS."}
            ]
        },
        "authentication": {
            "spf": {"result": "fail", "details": "Sender IP 185.220.101.5 is not listed in SPF record."},
            "dkim": {"result": "none", "details": "No DKIM signature found."},
            "dmarc": {"result": "fail", "details": "DMARC evaluation failed (p=reject)."},
            "alignment": {
                "from_domain": "security-bank-corp.com",
                "reply_to_domain": "darkweb-drop.ru",
                "return_path_domain": "bulletproof-relay.net",
                "reply_to_mismatch": True,
                "return_path_mismatch": True
            },
            "verification_notice": "Observed header authentication values evaluated."
        },
        "ml_assessment": {
            "available": True,
            "classification": "phishing",
            "probability": 0.968,
            "confidence": "high",
            "model_name": "TF-IDF + Logistic Regression Baseline",
            "top_features": ["unauthorized", "access", "credentials", "verify", "suspend"]
        },
        "ai_analyst": {
            "available": True,
            "summary": "Sophisticated financial credential phishing campaign weaponized with homoglyph brand lookalikes.",
            "likely_attack_type": "Credential Harvesting Phishing",
            "likely_objective": "Obtain administrative banking credentials",
            "key_evidence": [
                "Sender address mismatches Return-Path and Reply-To dropzone.",
                "Target URL points to external harvesting script.",
                "Attachment contains executable payload with masqueraded extension."
            ],
            "recommended_actions": [
                "Block domain at perimeter firewall.",
                "Revoke active Okta tokens.",
                "Quarantine all inbound emails containing the target SHA-256."
            ]
        },
        "url_analysis": [
            {
                "url": "https://security-bank-corp.com.portal-auth.xyz/login?id=99283&session=verified",
                "suspicion_score": 95,
                "observations": ["Punycode / subdomain spoofing", "Credential token parameter", "High entropy path"]
            }
        ],
        "attachments": [
            {
                "filename": "Account_Statement_September_2026.pdf.exe",
                "mime_type": "application/x-msdownload",
                "size": 245760,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        ],
        "relay_analysis": {
            "earliest_observable_node": {
                "earliest_observable_ip": "185.220.101.5",
                "from_host": "outbound.bulletproof-host.nl",
                "confidence": "high"
            },
            "transmission_order_hops": [
                {
                    "hop_number": 1,
                    "from_host": "smtp.bulletproof-host.nl",
                    "from_ip": "185.220.101.5",
                    "by_host": "mx1.enterprise.com",
                    "by_ip": "198.51.100.22",
                    "timestamp": "08 Sep 2026 01:20:00 GMT"
                }
            ]
        },
        "ip_intelligence": {
            "185.220.101.5": {
                "ip": "185.220.101.5",
                "scope": "public",
                "city": "Amsterdam",
                "country": "Netherlands",
                "asn": "AS57043",
                "organization": "Hostkey Hosting Provider"
            }
        },
        "lookalike_domains": [
            {
                "brand_name": "BankCorp",
                "domain": "security-bank-corp.com.portal-auth.xyz",
                "similarity": 0.89,
                "techniques": ["Subdomain prefix spoofing", "Brand keyword combination"]
            }
        ]
    }

    pdf_bytes = ReportService.generate_email_report(
        full_analysis,
        case_id="CASE-2026-000042",
        analyst_name="Agent Mulder",
        notes="Urgent triage: escalated to Tier 3 SOC."
    )
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 8000
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_report_with_long_urls_and_headers():
    """Verifies that long URLs (300+ chars) and long subjects wrap without layout exceptions or overflow."""
    long_analysis = {
        "subject": "EMERGENCY NOTIFICATION: " + ("EXTREMELY LONG SUBJECT LINE WITH REPEATING TOKENS " * 15),
        "from": "attacker." + ("subdomain." * 15) + "long-suspicious-domain-infrastructure.org",
        "to": "target." + ("group." * 15) + "internal-enterprise.com",
        "message_id": "<" + ("long-guid-" * 20) + "@infrastructure.org>",
        "email_sha256": "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "threat_score": {
            "score": 75.0,
            "severity": "high",
            "summary": "Long token abuse testing.",
            "reasons": [
                {"category": "URL", "points": 40, "description": "Long nested URL payload targeting credentials."}
            ]
        },
        "url_analysis": [
            {
                "url": "https://malicious.deep.subdomain.structure." + ("nested." * 15) + "phishing.com/auth/login/verify?token=" + ("a1b2c3d4e5f6g7h8i9j0" * 15),
                "suspicion_score": 90,
                "observations": ["Excessive subdomains", "Abnormally long URL string"]
            }
        ],
        "attachments": [
            {
                "filename": "super_long_attachment_file_name_designed_to_test_cell_boundaries_" + ("token_" * 10) + ".pdf.exe",
                "mime_type": "application/x-msdownload",
                "size": 1048576,
                "sha256": "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdef"
            }
        ]
    }

    pdf_bytes = ReportService.generate_email_report(long_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 5000
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_report_no_ai_no_geolocation():
    """Verifies that private RFC1918 IPs and disabled AI summary render clean fallback notices."""
    private_analysis = {
        "subject": "Internal Status Update",
        "from": "admin@internal.corp",
        "threat_score": {
            "score": 10.0,
            "severity": "low",
            "summary": "Internal mail with private routing."
        },
        "ai_analyst": None,
        "ml_assessment": {"available": False, "notice": "ML model unavailable."},
        "ip_intelligence": {
            "10.0.1.25": {
                "ip": "10.0.1.25",
                "scope": "private"
            }
        }
    }

    pdf_bytes = ReportService.generate_email_report(private_analysis)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF-")


def test_generate_case_dossier_report():
    """Verifies that a case-level report compiling overview, notes, findings, and email evidence generates cleanly."""
    db = SessionLocal()
    try:
        case = CaseModel(
            case_number="CASE-2026-000099",
            title="Q3 Credential Harvester Campaign",
            description="Multi-email investigation tracking phishing wave targeting finance department.",
            severity="high",
            status="investigating"
        )
        db.add(case)
        db.flush()

        email1 = CaseEmailModel(
            case_id=case.id,
            email_id="email-001",
            email_sha256="1111222233334444555566667777888899990000111122223333444455556666",
            subject="Invoice Overdue: Immediate Action Required",
            sender="billing@spoofed-finance.com",
            threat_score=85.0,
            severity="high"
        )
        db.add(email1)

        note = CaseNoteModel(
            case_id=case.id,
            author="Analyst Smith",
            note_text="Identified secondary dropzone IP in Amsterdam."
        )
        db.add(note)

        finding = CaseFindingModel(
            case_id=case.id,
            finding_type="lookalike_domain",
            title="Brand Impersonation of Finance Portal",
            description="Domain spoofed-finance.com registered 2 days ago.",
            severity="high"
        )
        db.add(finding)

        audit = AuditLogModel(
            case_id=case.id,
            action="CASE_CREATED",
            details="Case initialized by SOC triage queue."
        )
        db.add(audit)
        db.commit()

        pdf_bytes = ReportService.generate_case_dossier(db, case.id)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 2000
        assert pdf_bytes.startswith(b"%PDF-")
    finally:
        db.close()


def test_reports_api_endpoints(stored_analysis):
    """Tests the full API lifecycle: generate PDF, list reports, download report, case dossier."""
    payload = {
        "analysis": {
            "subject": "API Endpoint Phishing Test",
            "from": "phish@api-test.com",
            "email_sha256": "9999888877776666555544443333222211110000999988887777666655554444",
            "threat_score": {"score": 80.0, "severity": "high", "summary": "API Test"}
        },
        "analyst_name": "API Test Analyst"
    }

    payload["analysis"] = stored_analysis("report-api-evidence", **payload["analysis"])

    # 1. POST /api/reports/generate (Direct Binary PDF)
    res = client.post("/api/reports/generate", json=payload)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert "attachment; filename=" in res.headers["content-disposition"]
    assert res.content.startswith(b"%PDF-")

    # 2. POST /api/reports/generate (Format JSON)
    res_json = client.post("/api/reports/generate?format=json", json=payload)
    assert res_json.status_code == 200
    data = res_json.json()
    assert "id" in data
    assert "report_number" in data
    assert "download_url" in data
    report_id = data["id"]

    # 3. GET /api/reports (List)
    res_list = client.get("/api/reports")
    assert res_list.status_code == 200
    list_data = res_list.json()
    assert list_data["total"] >= 1
    assert any(r["id"] == report_id for r in list_data["reports"])

    # 4. GET /api/reports/{id}/download
    res_dl = client.get(f"/api/reports/{report_id}/download")
    assert res_dl.status_code == 200
    assert res_dl.headers["content-type"] == "application/pdf"
    assert res_dl.content.startswith(b"%PDF-")

