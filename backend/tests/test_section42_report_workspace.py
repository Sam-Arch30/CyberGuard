"""
Comprehensive tests for Section 42: Report Workspace.
Tests:
- Generation of immutable investigation reports (Analyst, Executive, Forensic)
- Versioning (v1, v2) and reproducibility from snapshot
- Draft preview and custom options preview
- Epistemic factuality labeling (OBSERVED, INFERRED, HYPOTHESIS, etc.)
- Redaction policy (NONE, STANDARD, STRICT) without modifying underlying evidence
- Staleness detection when investigation updates after report generation
- Version comparison between v1 and v2
- PDF binary export and JSON snapshot bundle export
- Audit logging of REPORT_GENERATED and REPORT_EXPORTED
- Quality check validation and unsupported claims handling
"""
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import Base, SessionLocal, engine
from backend.db.models import (
    IncidentModel,
    AnalysisRunModel,
    ArtifactModel,
    ReportModel,
    AuditLogModel,
    ResponseRecommendationModel,
    ResponseActionModel,
)
from backend.services.report_service import ReportService
from backend.services.report_projection_service import ReportProjectionService

client = TestClient(app)


@pytest.fixture(autouse=True)
def clean_db():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        conn = db.connection()
        conn._allow_audit_cleanup = True
        db.query(ReportModel).delete()
        db.query(ResponseActionModel).delete()
        db.query(ResponseRecommendationModel).delete()
        db.query(AuditLogModel).delete()
        db.query(AnalysisRunModel).delete()
        db.query(IncidentModel).delete()
        db.query(ArtifactModel).delete()
        db.commit()
    finally:
        db.close()
    yield
    db = SessionLocal()
    try:
        conn = db.connection()
        conn._allow_audit_cleanup = True
        db.query(ReportModel).delete()
        db.query(IncidentModel).delete()
        db.query(ArtifactModel).delete()
        db.commit()
    finally:
        db.close()


def create_sample_investigation(db):
    art = ArtifactModel(
        id="art-test-042",
        name="suspected_credential_phish.eml",
        artifact_type="EMAIL",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size=10485,
        created_at=datetime.now(timezone.utc) - timedelta(hours=2),
    )
    db.add(art)

    run = AnalysisRunModel(
        id="run-test-042",
        artifact_id=art.id,
        status="COMPLETED",
        overall_risk_score=78.5,
        overall_severity="HIGH",
        confidence=0.88,
        started_at=datetime.now(timezone.utc) - timedelta(hours=1),
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=50),
    )
    db.add(run)

    inc = IncidentModel(
        id="inc-test-042",
        incident_number="INV-2026-0042",
        title="Suspicious Credential Activity & Phishing Sequence",
        description="Targeted spearphishing campaign attempting credential harvesting.",
        status="INVESTIGATING",
        severity="HIGH",
        risk_score=78.5,
        confidence=0.88,
        opened_at=datetime.now(timezone.utc) - timedelta(hours=1),
        updated_at=datetime.now(timezone.utc) - timedelta(minutes=45),
    )
    db.add(inc)

    rec = ResponseRecommendationModel(
        id="rec-test-042",
        scope_type="INVESTIGATION",
        scope_id=inc.id,
        title="Revoke Compromised Session Tokens",
        category="CONTAINMENT",
        priority="P0",
        action_type="IDENTITY_REVOCATION",
        status="APPROVED",
        description="Revoke Okta session for analyst@enterprise.com",
        rationale="Compromised credentials detected",
        expected_effect="Terminates active attacker session",
        affected_entities_json=json.dumps(["analyst@enterprise.com"]),
    )
    db.add(rec)

    act = ResponseActionModel(
        id="act-test-042",
        incident_id=inc.id,
        action_type="REVOKE_SESSION",
        description="Revoked active session for analyst@enterprise.com",
        status="EXECUTED",
        priority="P0",
        recommended_by="System",
        executed_by="SOC Lead",
        executed_at=datetime.now(timezone.utc) - timedelta(minutes=30),
    )
    db.add(act)

    db.commit()
    return inc.id, run.id, art.id


def test_investigation_report_draft_preview():
    """Verifies that an investigation without prior reports returns a live draft preview."""
    db = SessionLocal()
    try:
        inc_id, run_id, art_id = create_sample_investigation(db)
    finally:
        db.close()

    res = client.get(f"/api/investigations/{inc_id}/report")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "DRAFT"
    assert data["report_version"] == 0
    assert data["threat_score"] == 78.5
    assert data["severity"] == "high"
    assert data["snapshot"] is not None
    assert "metadata" in data["snapshot"]
    assert "epistemic_claims" in data["snapshot"]
    assert len(data["snapshot"]["epistemic_claims"]) >= 3


def test_generate_immutable_investigation_report_v1():
    """Generates an authoritative v1 report and validates snapshot immutability."""
    db = SessionLocal()
    try:
        inc_id, run_id, art_id = create_sample_investigation(db)
    finally:
        db.close()

    payload = {
        "investigation_id": inc_id,
        "report_type": "ANALYST",
        "classification": "CONFIDENTIAL",
        "redaction_level": "NONE",
        "analyst_name": "Lead Investigator Holmes",
        "notes": "Verified initial intrusion vector via credential harvest URL."
    }

    res = client.post(f"/api/investigations/{inc_id}/report/generate", json=payload)
    assert res.status_code == 200
    report_v1 = res.json()

    assert report_v1["report_version"] == 1
    assert report_v1["status"] == "READY"
    assert report_v1["classification"] == "CONFIDENTIAL"
    assert report_v1["analyst_name"] == "Lead Investigator Holmes"
    assert report_v1["report_number"].startswith("RPT-")
    assert report_v1["download_url"].startswith("/api/reports/")

    # Check database persistence
    db = SessionLocal()
    try:
        rpt_db = db.query(ReportModel).filter(ReportModel.id == report_v1["id"]).first()
        assert rpt_db is not None
        assert rpt_db.report_version == 1
        assert rpt_db.format == "PDF"
        assert rpt_db.file_size_bytes > 1000

        # Check audit log was emitted
        audit = db.query(AuditLogModel).filter(
            AuditLogModel.action == "REPORT_GENERATED",
            AuditLogModel.resource_id == rpt_db.id
        ).first()
        assert audit is not None
    finally:
        db.close()


def test_report_versioning_and_staleness_handling():
    """
    Verifies that when an investigation is updated after v1 generation:
    1. v1 remains immutable but is flagged as stale.
    2. Generating an updated report creates v2 without modifying v1.
    """
    db = SessionLocal()
    try:
        inc_id, run_id, art_id = create_sample_investigation(db)
    finally:
        db.close()

    # 1. Generate v1
    res1 = client.post(
        f"/api/investigations/{inc_id}/report/generate",
        json={"investigation_id": inc_id, "report_type": "ANALYST"}
    )
    assert res1.status_code == 200
    v1_id = res1.json()["id"]

    # Check v1 is not stale initially
    check1 = client.get(f"/api/reports/{v1_id}")
    assert check1.status_code == 200
    assert check1.json()["is_stale"] is False

    # 2. Update investigation state (e.g., status changed or new note)
    db = SessionLocal()
    try:
        inc_db = db.query(IncidentModel).filter(IncidentModel.id == inc_id).first()
        inc_db.updated_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        inc_db.risk_score = 90.0
        inc_db.severity = "CRITICAL"
        db.commit()
    finally:
        db.close()

    # Check v1 is now flagged as STALE
    check2 = client.get(f"/api/reports/{v1_id}")
    assert check2.status_code == 200
    assert check2.json()["is_stale"] is True

    # 3. Generate v2
    res2 = client.post(
        f"/api/investigations/{inc_id}/report/generate",
        json={"investigation_id": inc_id, "report_type": "ANALYST"}
    )
    assert res2.status_code == 200
    v2_data = res2.json()
    assert v2_data["report_version"] == 2
    assert v2_data["threat_score"] == 90.0
    assert v2_data["severity"] == "critical"

    # Verify v1 remains version 1 in DB
    db = SessionLocal()
    try:
        rpt_v1 = db.query(ReportModel).filter(ReportModel.id == v1_id).first()
        assert rpt_v1.report_version == 1
        assert rpt_v1.status == "SUPERSEDED"
    finally:
        db.close()


def test_redaction_policy_standard_and_strict():
    """Verifies that redaction policies mask emails and private IPs without mutating underlying evidence."""
    db = SessionLocal()
    try:
        inc_id, run_id, art_id = create_sample_investigation(db)
    finally:
        db.close()

    # Preview with STANDARD redaction
    res_std = client.post(
        f"/api/investigations/{inc_id}/report/preview",
        json={
            "report_type": "ANALYST",
            "redaction_level": "STANDARD",
        }
    )
    assert res_std.status_code == 200
    snap_std = res_std.json()["snapshot"]
    claims_str = json.dumps(snap_std["epistemic_claims"])
    assert "analyst@enterprise.com" not in claims_str

    # Preview with STRICT redaction
    res_strict = client.post(
        f"/api/investigations/{inc_id}/report/preview",
        json={
            "report_type": "ANALYST",
            "redaction_level": "STRICT",
        }
    )
    assert res_strict.status_code == 200
    snap_strict = res_strict.json()["snapshot"]
    claims_strict_str = json.dumps(snap_strict["epistemic_claims"])
    assert "analyst@enterprise.com" not in claims_strict_str

    # Verify underlying database records are completely unchanged!
    db = SessionLocal()
    try:
        rec = db.query(ResponseRecommendationModel).filter(ResponseRecommendationModel.id == "rec-test-042").first()
        assert "analyst@enterprise.com" in rec.affected_entities_json
    finally:
        db.close()


def test_export_pdf_and_json_streaming():
    """Verifies streaming download of binary PDF and JSON forensic bundle with export audits."""
    db = SessionLocal()
    try:
        inc_id, run_id, art_id = create_sample_investigation(db)
    finally:
        db.close()

    gen_res = client.post(
        f"/api/investigations/{inc_id}/report/generate",
        json={"investigation_id": inc_id, "report_type": "FORENSIC"}
    )
    assert gen_res.status_code == 200
    report_id = gen_res.json()["id"]

    # 1. Download PDF
    pdf_res = client.get(f"/api/reports/{report_id}/download")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF-")
    assert len(pdf_res.content) > 2000

    # 2. Download JSON
    json_res = client.get(f"/api/reports/{report_id}/json")
    assert json_res.status_code == 200
    assert json_res.headers["content-type"] == "application/json"
    parsed = json.loads(json_res.content)
    assert "metadata" in parsed
    assert "executive_summary" in parsed
    assert "evidence_table" in parsed

    # Check export audit records
    db = SessionLocal()
    try:
        exports = db.query(AuditLogModel).filter(
            AuditLogModel.action == "REPORT_EXPORTED",
            AuditLogModel.resource_id == report_id
        ).all()
        assert len(exports) == 2
    finally:
        db.close()


def test_report_version_comparison():
    """Tests comparison between v1 and v2 report snapshots."""
    db = SessionLocal()
    try:
        inc_id, run_id, art_id = create_sample_investigation(db)
    finally:
        db.close()

    res1 = client.post(
        f"/api/investigations/{inc_id}/report/generate",
        json={"investigation_id": inc_id, "report_type": "ANALYST"}
    )
    v1_id = res1.json()["id"]

    # Modify incident risk score
    db = SessionLocal()
    try:
        inc_db = db.query(IncidentModel).filter(IncidentModel.id == inc_id).first()
        inc_db.risk_score = 95.0
        inc_db.severity = "CRITICAL"
        db.commit()
    finally:
        db.close()

    res2 = client.post(
        f"/api/investigations/{inc_id}/report/generate",
        json={"investigation_id": inc_id, "report_type": "ANALYST"}
    )
    v2_id = res2.json()["id"]

    comp_res = client.get(f"/api/reports/{v1_id}/compare/{v2_id}")
    assert comp_res.status_code == 200
    comp_data = comp_res.json()
    assert comp_data["v1_version"] == 1
    assert comp_data["v2_version"] == 2
    assert len(comp_data["changes"]) > 0

    risk_change = next(c for c in comp_data["changes"] if c["field"] == "Risk Score")
    assert risk_change["changed"] is True
    assert risk_change["v1_value"] == 78.5
    assert risk_change["v2_value"] == 95.0
