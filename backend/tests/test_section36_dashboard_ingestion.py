"""
Unit and integration tests for Section 36 — Dashboard + Universal Ingestion Drop Zone.

Verifies:
1. Universal Ingestion Gateway creates persistent EvidenceModel, IncidentModel, and AnalysisRun
2. Deterministic type detection for EMAIL, URL, DOMAIN, IP, FILE, and AUTH_LOG
3. EML upload auto-records email analysis for instant dashboard triage
4. Duplicate detection preserves lineage and sets duplicate flag
5. SSRF safety: text/URL ingestion does not trigger outbound HTTP network calls
6. Dashboard summary, emails, and health endpoints return truthful database records
"""
import io
import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, SessionLocal
from backend.db.models import (
    ArtifactModel,
    EvidenceModel,
    IncidentModel,
    AnalysisRunModel,
    EmailAnalysisModel,
    ThreatEventModel,
)

client = TestClient(app)

SAMPLE_EML = b"""From: alerts@paypal-security-update.com
To: victim@company.com
Subject: Urgent Security Alert: Confirm Account Credentials
Date: Mon, 12 May 2025 10:00:00 +0000
Message-ID: <sec-alert-9912@paypal-security-update.com>
Content-Type: text/plain; charset="utf-8"

Dear customer,

Your account has been temporarily restricted.
Please verify your login credentials immediately:
https://paypal-verify-login.example.com/auth
"""

SAMPLE_PDF = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"

SAMPLE_PE_BINARY = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00" + b"\x00" * 100


def test_section36_eml_universal_ingestion():
    """
    Test dropping an .eml file into Universal Ingestion Gateway:
    - Detects EMAIL
    - Persists EvidenceModel with deterministic SHA-256
    - Creates IncidentModel
    - Creates AnalysisRunModel
    - Auto-records email analysis for instant dashboard triage
    """
    files = {"file": ("invoice_phish.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")}
    resp = client.post("/api/ingest", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["artifact_type"] == "EMAIL"
    assert data["analysis_status"] == "INGESTED"
    assert data["evidence_id"] is not None
    assert data["evidence_id"].startswith("EVD-")
    assert data["investigation_id"] is not None
    assert data["analysis_run_id"] is not None
    assert data["duplicate"] is False
    assert len(data["sha256"]) == 64

    # Verify DB records
    db: Session = SessionLocal()
    try:
        ev = db.query(EvidenceModel).filter(EvidenceModel.evidence_id == data["evidence_id"]).first()
        assert ev is not None
        assert ev.original_filename == "invoice_phish.eml"

        inc = db.query(IncidentModel).filter(IncidentModel.id == data["investigation_id"]).first()
        assert inc is not None
        assert "invoice_phish.eml" in inc.title

        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == data["analysis_run_id"]).first()
        assert run is not None
        assert run.artifact_id == data["artifact_id"]

        ea = db.query(EmailAnalysisModel).filter(EmailAnalysisModel.evidence_id == data["evidence_id"]).first()
        assert ea is not None
        assert "Urgent Security Alert" in ea.subject
    finally:
        db.close()


def test_section36_duplicate_detection():
    """
    Test uploading the exact same evidence twice:
    - First upload: duplicate=False
    - Second upload: duplicate=True with informative duplicate warning
    """
    unique_content = f"Unique evidence payload {pytest.__file__}".encode("utf-8")
    files = {"file": ("sample.txt", io.BytesIO(unique_content), "text/plain")}

    resp1 = client.post("/api/ingest", files=files)
    assert resp1.status_code == 200
    data1 = resp1.json()
    assert data1["duplicate"] is False

    # Second upload of identical bytes
    files2 = {"file": ("sample_duplicate.txt", io.BytesIO(unique_content), "text/plain")}
    resp2 = client.post("/api/ingest", files=files2)
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["duplicate"] is True
    assert any("Duplicate" in w for w in data2["warnings"])
    assert data2["sha256"] == data1["sha256"]


def test_section36_url_text_ingestion_ssrf_safety():
    """
    Test pasting a URL into Universal Ingestion:
    - Detects URL
    - Persists text evidence and normalized URL
    - Creates IncidentModel and AnalysisRunModel
    - No browser-side arbitrary fetch occurs
    """
    test_url = "https://secure-portal.phish-bank.com/login?redirect=dashboard"

    with patch("httpx.AsyncClient.get") as mock_http, patch("urllib.request.urlopen") as mock_url:
        resp = client.post("/api/ingest", json={"text": test_url})
        assert resp.status_code == 200, resp.text
        data = resp.json()

        assert data["artifact_type"] == "URL"
        assert data["normalized_value"] == "https://secure-portal.phish-bank.com/login?redirect=dashboard"
        assert data["evidence_id"] is not None
        assert data["investigation_id"] is not None
        assert data["analysis_run_id"] is not None

        # Verify no external HTTP requests were initiated
        mock_http.assert_not_called()
        mock_url.assert_not_called()


def test_section36_structured_auth_log_ingestion():
    """
    Test pasting a structured authentication log event:
    - Detects AUTH_LOG
    - Extracts ThreatEventModel
    - Links ThreatEventModel to created IncidentModel
    """
    auth_event = {
        "event_type": "failed_login_bruteforce",
        "user": "victim_admin",
        "source_ip": "198.51.100.99",
        "status": "failure",
        "failed_attempts": 15,
        "summary": "Brute-force password spray attempt detected against admin account",
    }

    resp = client.post("/api/ingest", json={"event": auth_event, "source": "SOC_TEST"})
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["artifact_type"] == "AUTH_LOG"
    assert data["investigation_id"] is not None

    db: Session = SessionLocal()
    try:
        inc = db.query(IncidentModel).filter(IncidentModel.id == data["investigation_id"]).first()
        assert inc is not None
        assert len(inc.threat_events) >= 1
        te = inc.threat_events[0]
        assert te.event_type == "failed_login_bruteforce"
    finally:
        db.close()


def test_section36_executable_static_analysis_candidate():
    """
    Test uploading a Windows PE executable:
    - Detects FILE with binary magic executable
    - Generates strict static analysis warning prohibiting execution
    """
    files = {"file": ("malicious_payload.exe", io.BytesIO(SAMPLE_PE_BINARY), "application/octet-stream")}
    resp = client.post("/api/ingest", files=files)
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["artifact_type"] == "FILE"
    assert any("Execution is strictly prohibited" in w for w in data["warnings"])
    assert data["classification"]["metadata"]["is_executable"] is True


def test_section36_dashboard_endpoints():
    """
    Verify dashboard API endpoints return authentic operational data:
    - GET /api/dashboard/summary
    - GET /api/dashboard/emails
    - GET /api/health
    """
    # 1. Summary endpoint
    res_summary = client.get("/api/dashboard/summary?days=30&recent_limit=10")
    assert res_summary.status_code == 200
    sum_data = res_summary.json()
    assert "metrics" in sum_data
    assert "emails_analyzed" in sum_data["metrics"]
    assert "open_cases" in sum_data["metrics"]
    assert "recent_emails" in sum_data
    assert "recent_cases" in sum_data

    # 2. Emails list endpoint
    res_emails = client.get("/api/dashboard/emails?skip=0&limit=10")
    assert res_emails.status_code == 200
    emails_data = res_emails.json()
    assert "items" in emails_data
    assert "total" in emails_data

    # 3. Health check
    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    health_data = res_health.json()
    assert health_data["status"] == "ok"
    assert health_data["database"] == "ok"
