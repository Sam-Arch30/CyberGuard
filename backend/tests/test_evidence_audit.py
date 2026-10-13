import io
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal, Base, engine
from backend.db.models import AuditLogModel, EvidenceModel, CaseModel, ReportModel
from backend.services.audit_service import AuditService

client = TestClient(app)

SAMPLE_EML = b"""From: security-alert@paypal-update.com
To: victim@company.com
Subject: Urgent Security Alert: Account Suspicious Access
Date: Tue, 08 Sep 2026 10:30:00 +0000
Message-ID: <evd-test-12345@paypal-update.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear customer, please verify your credentials immediately at http://paypal-update.com/login
"""


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.create_all(bind=engine)
    yield
    # Cleanup for isolation
    db = SessionLocal()
    try:
        # Enable temporary cleanup flag on connection
        conn = db.connection()
        conn._allow_audit_cleanup = True
        db.query(AuditLogModel).delete()
        db.query(EvidenceModel).delete()
        db.query(ReportModel).delete()
        db.query(CaseModel).delete()
        db.commit()
    finally:
        db.close()


# =====================================================================
# 1. Evidence Hash Persistence Tests
# =====================================================================

def test_evidence_hash_persistence():
    """Verifies SHA-256 is accurately calculated and persisted in the database for every uploaded email."""
    files = {"file": ("suspicious_wire.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")}
    headers = {"X-User": "Forensic Lead Specialist"}
    response = client.post("/api/emails/analyze", files=files, headers=headers)
    assert response.status_code == 200
    data = response.json()

    assert "evidence_id" in data
    assert data["evidence_id"].startswith("EVD-")
    assert "email_sha256" in data
    assert len(data["email_sha256"]) == 64
    assert data["original_filename"] == "suspicious_wire.eml"
    assert data["size"] == len(SAMPLE_EML)
    assert data["uploader"] == "Forensic Lead Specialist"
    assert "upload_timestamp" in data

    # Verify directly in SQLite evidence table
    db = SessionLocal()
    try:
        evidence = db.query(EvidenceModel).filter(EvidenceModel.sha256 == data["email_sha256"]).first()
        assert evidence is not None
        assert evidence.evidence_id == data["evidence_id"]
        assert evidence.original_filename == "suspicious_wire.eml"
        assert evidence.size == len(SAMPLE_EML)
        assert evidence.uploader == "Forensic Lead Specialist"
    finally:
        db.close()

    # Query evidence via API
    ev_res = client.get(f"/api/evidence/{data['evidence_id']}")
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["evidence_id"] == data["evidence_id"]
    assert ev_data["sha256"] == data["email_sha256"]
    assert ev_data["size"] == len(SAMPLE_EML)

    # Query evidence via SHA-256 alias
    ev_hash_res = client.get(f"/api/evidence/{data['email_sha256']}")
    assert ev_hash_res.status_code == 200
    assert ev_hash_res.json()["evidence_id"] == data["evidence_id"]


# =====================================================================
# 2. Audit Creation Tests
# =====================================================================

def test_audit_creation_on_upload_and_analysis():
    """Verifies that email upload records EMAIL_UPLOADED, ANALYSIS_STARTED, and ANALYSIS_COMPLETED."""
    files = {"file": ("phish_test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")}
    headers = {"X-User": "Analyst-42"}
    response = client.post("/api/emails/analyze", files=files, headers=headers)
    assert response.status_code == 200
    evidence_id = response.json()["evidence_id"]

    # Query audit logs for this evidence item
    audit_res = client.get(f"/api/audit?resource_id={evidence_id}")
    assert audit_res.status_code == 200
    logs = audit_res.json()["items"]
    actions = [item["action"] for item in logs]

    assert "EMAIL_UPLOADED" in actions
    assert "ANALYSIS_STARTED" in actions
    assert "ANALYSIS_COMPLETED" in actions

    # Verify standard audit fields
    upload_log = next(item for item in logs if item["action"] == "EMAIL_UPLOADED")
    assert upload_log["id"] is not None
    assert upload_log["timestamp"] is not None
    assert upload_log["user"] == "Analyst-42"
    assert upload_log["resource_type"] == "email"
    assert upload_log["resource_id"] == evidence_id
    assert "sha256" in upload_log["metadata"]
    assert upload_log["metadata"]["filename"] == "phish_test.eml"

    analysis_log = next(item for item in logs if item["action"] == "ANALYSIS_COMPLETED")
    assert "threat_score" in analysis_log["metadata"]
    assert "severity" in analysis_log["metadata"]


# =====================================================================
# 3. Case Update Audit Tests
# =====================================================================

def test_case_lifecycle_audit():
    """Verifies CASE_CREATED, EMAIL_ADDED_TO_CASE, CASE_STATUS_CHANGED, and NOTE_ADDED audit entries."""
    # 1. Create case
    case_res = client.post("/api/cases", json={
        "title": "Phishing Incident Investigation",
        "description": "Suspicious credential harvesting campaign",
        "severity": "high",
        "status": "open"
    })
    assert case_res.status_code == 201
    case_data = case_res.json()
    case_id = case_data["id"]
    case_num = case_data["case_number"]

    # Verify CASE_CREATED audit log
    audit_res = client.get(f"/api/audit?resource_id={case_id}")
    actions = [item["action"] for item in audit_res.json()["items"]]
    assert "CASE_CREATED" in actions

    # 2. Add email to case
    add_email_res = client.post(f"/api/cases/{case_id}/emails", json={
        "email_id": "eml-001",
        "email_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "subject": "Wire Transfer Urgent Request",
        "sender": "ceo@lookalike.com",
        "threat_score": 85,
        "severity": "high",
        "indicators": {"domains": ["lookalike.com"]}
    })
    assert add_email_res.status_code == 201

    # Verify EMAIL_ADDED_TO_CASE audit log
    audit_res = client.get(f"/api/audit?resource_id={case_id}")
    actions = [item["action"] for item in audit_res.json()["items"]]
    assert "EMAIL_ADDED_TO_CASE" in actions

    email_added_entry = next(i for i in audit_res.json()["items"] if i["action"] == "EMAIL_ADDED_TO_CASE")
    assert email_added_entry["metadata"]["email_id"] == "eml-001"
    assert email_added_entry["metadata"]["case_number"] == case_num

    # 3. Update case status
    update_res = client.patch(f"/api/cases/{case_id}", json={
        "status": "investigating"
    })
    assert update_res.status_code == 200

    # Verify CASE_STATUS_CHANGED audit log
    audit_res = client.get(f"/api/audit?resource_id={case_id}&action=CASE_STATUS_CHANGED")
    status_logs = audit_res.json()["items"]
    assert len(status_logs) >= 1
    assert status_logs[0]["metadata"]["old_status"] == "OPEN"
    assert status_logs[0]["metadata"]["new_status"] == "IN_PROGRESS"

    # 4. Add analyst note
    note_res = client.post(f"/api/cases/{case_id}/notes", json={
        "author": "Analyst Alice",
        "note_text": "Pivot to WHOIS records shows recent registration."
    })
    assert note_res.status_code == 201

    # Verify NOTE_ADDED audit log
    audit_res = client.get(f"/api/audit?resource_id={case_id}&action=NOTE_ADDED")
    note_logs = audit_res.json()["items"]
    assert len(note_logs) >= 1
    assert note_logs[0]["metadata"]["author"] == "Analyst Alice"


# =====================================================================
# 4. Report Generation Audit Tests
# =====================================================================

def test_report_generation_audit():
    """Verifies that report generation generates a REPORT_GENERATED audit log."""
    upload_res = client.post("/api/emails/analyze", files={"file": ("report_test.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")})
    analysis = upload_res.json()
    evidence_id = analysis["evidence_id"]
    sha256 = analysis["email_sha256"]

    # Generate PDF report (with format=json to inspect payload)
    report_res = client.post("/api/reports/generate?format=json", json={
        "analysis": analysis,
        "analyst_name": "Lead Forensic Examiner"
    })
    assert report_res.status_code == 200
    report_data = report_res.json()
    report_id = report_data["id"]
    report_num = report_data["report_number"]

    # Query audit logs for report
    audit_res = client.get(f"/api/audit?action=REPORT_GENERATED")
    assert audit_res.status_code == 200
    report_logs = audit_res.json()["items"]
    matching_log = next((l for l in report_logs if l["resource_id"] == report_id), None)

    assert matching_log is not None
    assert matching_log["action"] == "REPORT_GENERATED"
    assert matching_log["user"] == "Lead Forensic Examiner"
    assert matching_log["metadata"]["report_number"] == report_num
    assert matching_log["metadata"]["evidence_id"] == evidence_id
    assert matching_log["metadata"]["email_sha256"] == sha256


# =====================================================================
# 5. Immutability Behavior Tests
# =====================================================================

def test_immutability_prevents_updates_and_deletions():
    """Verifies that application logic cannot update or delete existing audit logs."""
    db = SessionLocal()
    try:
        # Create an audit log record
        audit_entry = AuditService.log_audit(
            db=db,
            action="TEST_ACTION",
            resource_type="email",
            resource_id="EVD-TEST-IMMUTABLE",
            user="Tester",
            metadata={"test": "immutable"}
        )
        audit_id = audit_entry.id

        # Attempt to modify the audit record -> MUST raise PermissionError
        audit_entry.action = "TAMPERED_ACTION"
        with pytest.raises(PermissionError, match="immutable"):
            db.commit()

        db.rollback()

        # Re-fetch unchanged entry
        refetched = db.query(AuditLogModel).filter(AuditLogModel.id == audit_id).first()
        assert refetched.action == "TEST_ACTION"

        # Attempt to delete the audit record -> MUST raise PermissionError
        db.delete(refetched)
        with pytest.raises(PermissionError, match="immutable"):
            db.commit()

        db.rollback()

        # Confirm record still exists intact
        still_there = db.query(AuditLogModel).filter(AuditLogModel.id == audit_id).first()
        assert still_there is not None
        assert still_there.action == "TEST_ACTION"
    finally:
        db.close()


# =====================================================================
# 6. Privacy & Secrets Protection Tests
# =====================================================================

def test_privacy_metadata_omits_raw_bodies_and_secrets():
    """Verifies that raw email bodies and secret credentials are never logged to audit metadata."""
    sensitive_metadata = {
        "filename": "invoice.eml",
        "sha256": "1234567890abcdef",
        "raw_email": "From: evil@attacker.com\nBody text with sensitive PII...",
        "plain_text_body": "This is raw body content that should never be stored in audit logs.",
        "html_body": "<html><body>Secret private text</body></html>",
        "password": "SuperSecretPassword123!",
        "api_key": "sk-proj-1234567890abcdef",
        "auth_token": "Bearer xyz-987654",
        "clean_field": "Legitimate forensic indicator"
    }

    sanitized = AuditService.sanitize_metadata(sensitive_metadata)

    assert "filename" in sanitized
    assert "sha256" in sanitized
    assert "clean_field" in sanitized
    # Bodies MUST NOT be present
    assert "raw_email" not in sanitized
    assert "plain_text_body" not in sanitized
    assert "html_body" not in sanitized
    # Secrets MUST NOT be present
    assert "password" not in sanitized
    assert "api_key" not in sanitized
    assert "auth_token" not in sanitized


# =====================================================================
# 7. Investigation Timeline Reconstruction Tests
# =====================================================================

def test_investigation_timeline_reconstruction():
    """Verifies that the chronological timeline endpoint aggregates actions into a coherent timeline."""
    # 1. Upload email
    files = {"file": ("timeline_sample.eml", io.BytesIO(SAMPLE_EML), "message/rfc822")}
    res = client.post("/api/emails/analyze", files=files)
    evidence_id = res.json()["evidence_id"]
    sha256 = res.json()["email_sha256"]

    # 2. Add to case
    case_res = client.post("/api/cases", json={"title": "Timeline Case", "severity": "medium"})
    case_id = case_res.json()["id"]
    case_num = case_res.json()["case_number"]

    client.post(f"/api/cases/{case_id}/emails", json={
        "email_id": evidence_id,
        "email_sha256": sha256,
        "subject": "Urgent Security Alert",
        "sender": "security-alert@paypal-update.com"
    })

    # 3. Generate report
    client.post("/api/reports/generate?format=json", json={
        "analysis": res.json(),
        "case_id": case_id
    })

    # 4. Fetch timeline via evidence endpoint
    timeline_res = client.get(f"/api/evidence/{evidence_id}/timeline")
    assert timeline_res.status_code == 200
    timeline = timeline_res.json()

    assert timeline["evidence_id"] == evidence_id
    assert timeline["sha256"] == sha256
    events = timeline["events"]
    assert len(events) >= 3

    event_titles = [e["title"] for e in events]
    # Verify titles include Email uploaded, Analysis completed, Added to Case, Report generated
    assert any("Email uploaded" in t for t in event_titles)
    assert any("Analysis completed" in t for t in event_titles)
    assert any(case_num in t or "Added" in t for t in event_titles)
    assert any("Report generated" in t for t in event_titles)

    # Verify time_display exists on each event (HH:MM format)
    for e in events:
        assert "time_display" in e
        assert ":" in e["time_display"]
