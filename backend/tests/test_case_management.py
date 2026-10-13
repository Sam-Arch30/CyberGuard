import re
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import get_db, SessionLocal, Base, engine
from backend.db.models import CaseModel

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_and_teardown_db():
    """Ensures a clean database state before each test."""
    Base.metadata.create_all(bind=engine)
    yield
    # Clean up cases
    db = SessionLocal()
    try:
        db.query(CaseModel).delete()
        db.commit()
    finally:
        db.close()


# =====================================================================
# 1. Case Creation & Readable Identifier Tests
# =====================================================================

def test_create_case():
    payload = {
        "title": "Suspected Executive BEC Wire Fraud",
        "description": "CFO received targeted email requesting swift transfer.",
        "severity": "high",
        "status": "open"
    }
    response = client.post("/api/cases", json=payload)
    assert response.status_code == 201
    data = response.json()

    assert "id" in data
    assert "case_number" in data
    # Format must be CASE-YYYY-00000X
    assert re.match(r"^CG-\d{4}-[A-F0-9]{12}$", data["case_number"])
    assert data["title"] == payload["title"]
    assert data["description"] == payload["description"]
    assert data["severity"] == "HIGH"
    assert data["status"] == "OPEN"
    assert "created_at" in data
    assert "updated_at" in data

    # Verify audit log recorded creation
    audit_actions = [a["action"] for a in data["audit_logs"]]
    assert "CASE_CREATED" in audit_actions


def test_create_case_collision_safe_numbering():
    res1 = client.post("/api/cases", json={"title": "Case 1", "severity": "low"})
    res2 = client.post("/api/cases", json={"title": "Case 2", "severity": "medium"})

    assert res1.status_code == 201
    assert res2.status_code == 201

    num1 = res1.json()["case_number"]
    num2 = res2.json()["case_number"]

    assert num1 != num2
    assert re.match(r"^CG-\d{4}-[A-F0-9]{12}$", num1)
    assert re.match(r"^CG-\d{4}-[A-F0-9]{12}$", num2)


# =====================================================================
# 2. Email Assignment & Duplicate Detection Tests
# =====================================================================

def test_email_assignment():
    # 1. Create case
    case_res = client.post("/api/cases", json={"title": "Phishing Incident"})
    case_id = case_res.json()["id"]

    # 2. Add email
    email_payload = {
        "email_id": "email-msg-9921",
        "email_sha256": "abcdef1234567890abcdef1234567890",
        "subject": "Urgent: Verify Your Account",
        "sender": "security@micros0ft-example.com",
        "threat_score": 88,
        "severity": "critical",
        "indicators": {
            "domains": ["micros0ft-example.com", "evil-tracker.example"],
            "ips": ["203.0.113.25"],
            "urls": ["https://micros0ft-example.com/login"]
        }
    }
    assign_res = client.post(f"/api/cases/{case_id}/emails", json=email_payload)
    assert assign_res.status_code == 201
    email_data = assign_res.json()
    assert email_data["email_id"] == "email-msg-9921"
    assert email_data["threat_score"] == 88

    # 3. Verify email appears in case details and aggregated indicators are calculated
    detail_res = client.get(f"/api/cases/{case_id}")
    assert detail_res.status_code == 200
    case_detail = detail_res.json()
    assert len(case_detail["emails"]) == 1
    assert case_detail["emails"][0]["email_id"] == "email-msg-9921"

    # Verify aggregated indicators
    agg = case_detail["aggregated_indicators"]
    assert "micros0ft-example.com" in agg["domains"]
    assert "203.0.113.25" in agg["ips"]
    assert "https://micros0ft-example.com/login" in agg["urls"]

    # Verify audit log
    audit_actions = [a["action"] for a in case_detail["audit_logs"]]
    assert "EMAIL_ADDED" in audit_actions


def test_duplicate_email_assignment_rejected():
    case_res = client.post("/api/cases", json={"title": "Phishing Investigation"})
    case_id = case_res.json()["id"]

    email_payload = {
        "email_id": "duplicate-msg-123",
        "subject": "Invoice Reminder",
        "sender": "billing@fake.com"
    }

    # First assignment -> Success 201
    res1 = client.post(f"/api/cases/{case_id}/emails", json=email_payload)
    assert res1.status_code == 201

    # Second assignment with same email_id -> Rejected 400
    res2 = client.post(f"/api/cases/{case_id}/emails", json=email_payload)
    assert res2.status_code == 400
    assert "already linked" in res2.json()["detail"].lower()


def test_email_removal():
    case_res = client.post("/api/cases", json={"title": "Investigation Case"})
    case_id = case_res.json()["id"]

    client.post(f"/api/cases/{case_id}/emails", json={
        "email_id": "email-to-remove-1",
        "subject": "Test Email"
    })

    # Remove email
    del_res = client.delete(f"/api/cases/{case_id}/emails/email-to-remove-1")
    assert del_res.status_code == 204

    # Verify empty
    detail_res = client.get(f"/api/cases/{case_id}")
    assert len(detail_res.json()["emails"]) == 0

    # Audit log verification
    audit_actions = [a["action"] for a in detail_res.json()["audit_logs"]]
    assert "EMAIL_REMOVED" in audit_actions


# =====================================================================
# 3. Status & Severity Change Tests
# =====================================================================

def test_case_status_and_severity_changes():
    case_res = client.post("/api/cases", json={
        "title": "Credential Harvest Incident",
        "status": "open",
        "severity": "medium"
    })
    case_id = case_res.json()["id"]

    # Change to investigating
    patch_res1 = client.patch(f"/api/cases/{case_id}", json={"status": "investigating"})
    assert patch_res1.status_code == 200
    assert patch_res1.json()["status"] == "IN_PROGRESS"

    # Escalate and bump severity to critical
    patch_res2 = client.patch(f"/api/cases/{case_id}", json={
        "status": "escalated",
        "severity": "critical"
    })
    assert patch_res2.status_code == 200
    updated = patch_res2.json()
    assert updated["status"] == "IN_PROGRESS"
    assert updated["severity"] == "CRITICAL"

    # Resolve case
    patch_res3 = client.patch(f"/api/cases/{case_id}", json={"status": "resolved"})
    assert patch_res3.status_code == 200
    assert patch_res3.json()["status"] == "RESOLVED"

    # Verify audit trail recorded all transitions
    audit_actions = [a["action"] for a in patch_res3.json()["audit_logs"]]
    assert audit_actions.count("STATUS_CHANGED") == 2  # Escalation maps to the same operational status.
    assert "SEVERITY_CHANGED" in audit_actions


# =====================================================================
# 4. Notes & Findings Tests
# =====================================================================

def test_case_notes():
    case_res = client.post("/api/cases", json={"title": "Targeted Spear Phishing"})
    case_id = case_res.json()["id"]

    note_payload = {
        "author": "Analyst Jane Doe",
        "note_text": "Confirmed sending IP belongs to Bulletproof hosting ASN."
    }
    note_res = client.post(f"/api/cases/{case_id}/notes", json=note_payload)
    assert note_res.status_code == 201
    note_data = note_res.json()
    assert note_data["author"] == "Analyst Jane Doe"
    assert note_data["note_text"] == note_payload["note_text"]

    # Verify notes in case detail
    detail = client.get(f"/api/cases/{case_id}").json()
    assert len(detail["notes"]) == 1
    assert detail["notes"][0]["note_text"] == note_payload["note_text"]


def test_case_findings():
    case_res = client.post("/api/cases", json={"title": "Brand Impersonation Case"})
    case_id = case_res.json()["id"]

    finding_payload = {
        "finding_type": "lookalike_domain",
        "title": "Homograph attack on bank domain",
        "description": "Substituted unicode cyrillic 'а' for latin 'a'.",
        "severity": "critical"
    }
    find_res = client.post(f"/api/cases/{case_id}/findings", json=finding_payload)
    assert find_res.status_code == 201
    finding_data = find_res.json()
    assert finding_data["title"] == finding_payload["title"]
    assert finding_data["severity"] == "critical"

    # Verify finding in case detail
    detail = client.get(f"/api/cases/{case_id}").json()
    assert len(detail["findings"]) == 1
    assert detail["findings"][0]["finding_type"] == "lookalike_domain"


# =====================================================================
# 5. Invalid Case Handling (404)
# =====================================================================

def test_invalid_case_not_found():
    res_get = client.get("/api/cases/non-existent-uuid-12345")
    assert res_get.status_code == 404
    assert "not found" in res_get.json()["detail"].lower()

    res_patch = client.patch("/api/cases/non-existent-uuid-12345", json={"title": "New Title"})
    assert res_patch.status_code == 404

    res_note = client.post("/api/cases/non-existent-uuid-12345/notes", json={"note_text": "Note"})
    assert res_note.status_code == 404


# =====================================================================
# 6. Listing & Filtering Tests
# =====================================================================

def test_list_and_filter_cases():
    client.post("/api/cases", json={"title": "Open Critical Case", "status": "open", "severity": "critical"})
    client.post("/api/cases", json={"title": "Investigating Medium Case", "status": "investigating", "severity": "medium"})
    client.post("/api/cases", json={"title": "Resolved Low Case", "status": "resolved", "severity": "low"})

    # All
    res_all = client.get("/api/cases")
    assert res_all.status_code == 200
    assert res_all.json()["total"] == 3

    # Filter status=open
    res_open = client.get("/api/cases?status=open")
    assert res_open.status_code == 200
    assert res_open.json()["total"] == 1
    assert res_open.json()["cases"][0]["status"] == "OPEN"

    # Filter severity=critical
    res_crit = client.get("/api/cases?severity=critical")
    assert res_crit.status_code == 200
    assert res_crit.json()["total"] == 1
    assert res_crit.json()["cases"][0]["severity"] == "CRITICAL"

    # Search keyword
    res_search = client.get("/api/cases?search=Investigating")
    assert res_search.status_code == 200
    assert res_search.json()["total"] == 1
