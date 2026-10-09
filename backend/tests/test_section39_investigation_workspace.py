"""
Tests for Section 39: Investigation Workspace.
Verifies unified workspace summary aggregation, status transitions, notes,
evidence browser separation, and chronological timeline events.
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.session import SessionLocal
from backend.main import app
from backend.services.universal_ingestion import UniversalIngestionService
from backend.services.analysis_orchestrator import AnalysisOrchestrator


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_section39_summary_aggregation_and_resolution(client, db_session: Session):
    """Verifies that an ingested artifact aggregates into the authoritative 9-part workspace summary."""
    marker = uuid.uuid4().hex[:8]
    raw_eml = f"""From: Security Ops <sec-ops@paypal-verify-alert.com>
To: target-analyst@enterprise.corp
Subject: Urgent Security Notice {marker}
Date: Mon, 12 Oct 2026 14:22:00 +0000
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain; charset=utf-8

Please click http://login-secure-auth.target-verify.com to verify your credentials immediately.
"""
    ingest_res = UniversalIngestionService.ingest_file(
        db=db_session,
        content_bytes=raw_eml.encode("utf-8"),
        filename=f"phish_inv_{marker}.eml",
        reported_mime="message/rfc822",
        source="SEC39_TEST",
    )
    run_id = ingest_res.analysis_run_id
    assert run_id is not None

    # Execute analysis synchronously
    import asyncio
    asyncio.run(AnalysisOrchestrator.execute_run(db_session, run_id))

    # 1. Query workspace summary by run_id
    res_summary = client.get(f"/api/investigations/{run_id}/summary")
    assert res_summary.status_code == 200, res_summary.text
    data = res_summary.json()

    # Verify workspace identity
    inv = data["investigation"]
    assert inv["investigation_id"]
    assert inv["incident_number"].startswith(("INV-", "INC-"))
    assert inv["title"]
    assert inv["status"] in ("OPEN", "INVESTIGATING")
    assert inv["artifact_name"] == f"phish_inv_{marker}.eml"
    assert inv["sha256"]

    # Verify risk header
    risk = data["risk"]
    assert "score" in risk
    assert risk["level"] in ("HIGH", "CRITICAL", "MEDIUM", "LOW", "INFO")
    assert risk["is_pending"] is False

    # Verify counts
    counts = data["counts"]
    assert counts["findings_count"] >= 1
    assert counts["evidence_count"] >= 1
    assert counts["timeline_events_count"] >= 1

    # Verify resolution by incident_number
    res_inc = client.get(f"/api/investigations/{inv['incident_number']}/summary")
    assert res_inc.status_code == 200
    assert res_inc.json()["investigation"]["investigation_id"] == inv["investigation_id"]


def test_section39_status_lifecycle_transitions(client, db_session: Session):
    """Verifies that investigation status transitions follow valid lifecycle paths."""
    marker = uuid.uuid4().hex[:8]
    raw_eml = f"From: user@{marker}.com\r\nSubject: Test {marker}\r\n\r\nBody"
    ingest_res = UniversalIngestionService.ingest_file(
        db=db_session,
        content_bytes=raw_eml.encode("utf-8"),
        filename=f"status_test_{marker}.eml",
        reported_mime="message/rfc822",
    )
    run_id = ingest_res.analysis_run_id

    # Get initial summary
    res_init = client.get(f"/api/investigations/{run_id}/summary")
    assert res_init.status_code == 200
    inv_id = res_init.json()["investigation"]["investigation_id"]

    # Valid Transition: INVESTIGATING -> CONTAINED
    patch_res = client.patch(
        f"/api/investigations/{inv_id}/status",
        json={"status": "CONTAINED", "reason": "Isolated affected mailbox", "analyst": "SOC Lead"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["investigation"]["status"] == "CONTAINED"

    # Valid Transition: CONTAINED -> RESOLVED
    res_res = client.patch(
        f"/api/investigations/{inv_id}/status",
        json={"status": "RESOLVED", "reason": "Remediation verified"},
    )
    assert res_res.status_code == 200
    assert res_res.json()["investigation"]["status"] == "RESOLVED"

    # Invalid Transition: Invalid state name
    bad_res = client.patch(
        f"/api/investigations/{inv_id}/status",
        json={"status": "INVALID_STATE_XYZ"},
    )
    assert bad_res.status_code == 400


def test_section39_analyst_notes_persistence(client, db_session: Session):
    """Verifies adding and listing auditable analyst notes."""
    marker = uuid.uuid4().hex[:8]
    raw_eml = f"From: notes@{marker}.com\r\nSubject: Note Test {marker}\r\n\r\nBody"
    ingest_res = UniversalIngestionService.ingest_file(
        db=db_session,
        content_bytes=raw_eml.encode("utf-8"),
        filename=f"notes_test_{marker}.eml",
        reported_mime="message/rfc822",
    )
    run_id = ingest_res.analysis_run_id

    # Post a new note
    note_payload = {
        "note_text": "Investigated sender infrastructure. Confirmed newly registered registrar.",
        "author": "Analyst Jane Doe",
    }
    post_res = client.post(f"/api/investigations/{run_id}/notes", json={
        "note_text": note_payload["note_text"],
        "author": note_payload["author"]
    })
    assert post_res.status_code == 201, post_res.text
    note_data = post_res.json()
    assert note_data["author"] == "Analyst Jane Doe"
    assert "newly registered" in note_data["note_text"]

    # List notes
    list_res = client.get(f"/api/investigations/{run_id}/notes")
    assert list_res.status_code == 200
    notes = list_res.json()
    assert len(notes) >= 1
    assert any(n["note_text"] == note_payload["note_text"] for n in notes)


def test_section39_evidence_browser_immutability(client, db_session: Session):
    """Verifies that original immutable artifacts are clearly marked from derived signals."""
    marker = uuid.uuid4().hex[:8]
    raw_eml = f"From: hr@{marker}.com\r\nSubject: Evidence {marker}\r\n\r\nBody"
    ingest_res = UniversalIngestionService.ingest_file(
        db=db_session,
        content_bytes=raw_eml.encode("utf-8"),
        filename=f"evid_test_{marker}.eml",
        reported_mime="message/rfc822",
    )
    run_id = ingest_res.analysis_run_id

    res_ev = client.get(f"/api/investigations/{run_id}/evidence")
    assert res_ev.status_code == 200
    evidence_items = res_ev.json()
    assert len(evidence_items) >= 1

    # Original artifact must have is_original == True
    orig = next((e for e in evidence_items if e["is_original"] is True), None)
    assert orig is not None
    assert orig["name"] == f"evid_test_{marker}.eml"
    assert orig["sha256"] is not None


def test_section39_chronological_timeline(client, db_session: Session):
    """Verifies that timeline events are ordered chronologically with sources and severity."""
    marker = uuid.uuid4().hex[:8]
    raw_eml = f"From: tl@{marker}.com\r\nSubject: Timeline {marker}\r\n\r\nBody"
    ingest_res = UniversalIngestionService.ingest_file(
        db=db_session,
        content_bytes=raw_eml.encode("utf-8"),
        filename=f"tl_test_{marker}.eml",
        reported_mime="message/rfc822",
    )
    run_id = ingest_res.analysis_run_id

    res_tl = client.get(f"/api/investigations/{run_id}/timeline")
    assert res_tl.status_code == 200
    timeline = res_tl.json()
    assert len(timeline) >= 1

    # First event should be ingestion
    first_evt = timeline[0]
    assert first_evt["event_type"] == "ARTIFACT_INGESTION"
    assert first_evt["timestamp"] is not None
    assert first_evt["source"] is not None
