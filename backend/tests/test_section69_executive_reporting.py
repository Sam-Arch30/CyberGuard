"""
Section 69: Executive Reporting & Intelligence Dissemination Test Suite.
Verifies versioned templates, immutable point-in-time snapshots, anti-data-drift guarantees,
redaction pipelines, review/approval workflows, and secure external share links.
"""
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db
from backend.db.models import (
    ReportModel,
    ReportTemplateModel,
    ReportSnapshotModel,
    ReportShareLinkModel,
    IncidentModel,
    CaseModel,
)
from backend.services.executive_report_service import ExecutiveReportService
from backend.schemas.executive_reports import (
    ReportClassificationEnum,
    ReportRedactionLevelEnum,
    ReportTypeEnum,
    ReportStatusEnum,
    ReportTemplateCreateRequest,
    ReportSectionConfig,
    ExecutiveReportCreateRequest,
    ExecutiveReportUpdateRequest,
    ReportReviewRequest,
    ReportApprovalRequest,
    ReportFinalizeRequest,
    ReportShareLinkCreateRequest,
)

client = TestClient(app)

AUTH_HEADERS_ANALYST = {
    "X-User": "analyst_bob",
    "X-Role": "analyst",
}

AUTH_HEADERS_LEAD = {
    "X-User": "lead_alice",
    "X-Role": "lead",
}

AUTH_HEADERS_ADMIN = {
    "X-User": "admin_root",
    "X-Role": "admin",
}

AUTH_HEADERS_UNAUTH = {
    "X-User": "hacker_mallory",
    "X-Role": "unauthorized",
}


@pytest.fixture
def db_session():
    db: Session = next(get_db())
    try:
        yield db
    finally:
        db.close()


def test_01_system_templates_initialization(db_session: Session):
    """Verifies that all 5 standard system templates are seeded and retrievable."""
    ExecutiveReportService.ensure_system_templates(db_session, workspace_id="default")
    templates = ExecutiveReportService.list_templates(db_session, workspace_id="default")

    keys = {t.template_key for t in templates}
    expected = {
        "EXECUTIVE_BRIEFING",
        "TECHNICAL_INCIDENT_DOSSIER",
        "FORENSIC_CHAIN_OF_CUSTODY",
        "REGULATORY_COMPLIANCE_DISCLOSURE",
        "THREAT_ACTOR_INTEL_DISSEMINATION",
    }
    for exp in expected:
        assert exp in keys, f"Expected system template {exp} to be present"

    # Verify through API
    resp = client.get("/api/executive-reports/templates", headers=AUTH_HEADERS_ANALYST)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 5


def test_02_custom_template_creation_and_versioning(db_session: Session):
    """Tests creating and updating a custom report template."""
    tmpl_key = f"CUSTOM_BOARD_{datetime.now(timezone.utc).timestamp()}"
    create_payload = {
        "template_key": tmpl_key,
        "template_name": "Quarterly Board Cyber Threat Summary",
        "report_type": "EXECUTIVE_BRIEFING",
        "description": "Custom board overview template",
        "sections_config": [
            {
                "section_id": "exec_summary",
                "title": "Board Summary",
                "enabled": True,
                "order": 1,
            }
        ],
        "default_classification": "CONFIDENTIAL",
        "default_redaction": "NONE",
    }

    resp = client.post(
        "/api/executive-reports/templates",
        json=create_payload,
        headers=AUTH_HEADERS_LEAD,
    )
    assert resp.status_code == 201
    created_tmpl = resp.json()
    assert created_tmpl["template_key"] == tmpl_key
    assert created_tmpl["version"] == 1

    # Update template
    update_payload = {
        "template_name": "Quarterly Board Cyber Threat Summary (Revised)",
        "default_classification": "RESTRICTED",
    }
    resp_up = client.put(
        f"/api/executive-reports/templates/{created_tmpl['id']}",
        json=update_payload,
        headers=AUTH_HEADERS_LEAD,
    )
    assert resp_up.status_code == 200
    updated_tmpl = resp_up.json()
    assert updated_tmpl["template_name"] == "Quarterly Board Cyber Threat Summary (Revised)"
    assert updated_tmpl["version"] == 2
    assert updated_tmpl["default_classification"] == "RESTRICTED"


def test_03_create_report_with_immutable_snapshot(db_session: Session):
    """
    Creates an incident, then creates an Executive Report.
    Verifies that a point-in-time snapshot with SHA-256 hash is created.
    """
    # 1. Create a test incident
    inc = IncidentModel(
        incident_number=f"INC-SEC69-{int(datetime.now(timezone.utc).timestamp())}",
        title="Active APT29 Spear-Phishing Campaign",
        severity="critical",
        status="INVESTIGATING",
        risk_score=88.5,
        confidence=0.95,
        description="Coordinated spear-phishing targeting executive credentials.",
        category="PHISHING",
        workspace_id="default",
    )
    db_session.add(inc)
    db_session.commit()
    db_session.refresh(inc)

    # 2. Create executive report
    report_req = {
        "title": "Critical Incident Briefing: APT29 Intrusion",
        "report_type": "EXECUTIVE_BRIEFING",
        "incident_id": inc.id,
        "classification": "CONFIDENTIAL",
        "redaction_level": "NONE",
        "summary": "Immediate briefing for executive risk committee.",
    }
    resp = client.post(
        "/api/executive-reports/reports",
        json=report_req,
        headers=AUTH_HEADERS_ANALYST,
    )
    assert resp.status_code == 201
    rpt_data = resp.json()
    assert rpt_data["title"] == report_req["title"]
    assert rpt_data["status"] == "DRAFT"
    assert rpt_data["threat_score"] == 88.5
    assert rpt_data["source_snapshot_id"] is not None
    assert rpt_data["source_data_hash"] is not None
    assert len(rpt_data["source_data_hash"]) == 64  # SHA-256

    # 3. Verify snapshot record
    snapshot = db_session.query(ReportSnapshotModel).filter(ReportSnapshotModel.id == rpt_data["source_snapshot_id"]).first()
    assert snapshot is not None
    assert snapshot.snapshot_hash == rpt_data["source_data_hash"]
    payload = json.loads(snapshot.snapshot_payload_json)
    assert payload["incident"]["title"] == "Active APT29 Spear-Phishing Campaign"
    assert payload["incident"]["severity"] == "critical"


def test_04_anti_data_drift_guarantee(db_session: Session):
    """
    Modifies the underlying Incident (e.g. status changed, severity downgraded).
    Verifies that the frozen report snapshot does NOT change (Zero Data Drift).
    """
    inc = IncidentModel(
        incident_number=f"INC-DRIFT-{int(datetime.now(timezone.utc).timestamp())}",
        title="Original Incident Title At Generation Time",
        severity="high",
        status="CONTAINED",
        risk_score=75.0,
        workspace_id="default",
    )
    db_session.add(inc)
    db_session.commit()
    db_session.refresh(inc)

    report = ExecutiveReportService.create_executive_report(
        db=db_session,
        req=ExecutiveReportCreateRequest(
            title="Dossier Subject to Data Drift Test",
            report_type=ReportTypeEnum.TECHNICAL_INCIDENT_DOSSIER,
            incident_id=inc.id,
        ),
        created_by="analyst_bob",
    )
    original_hash = report.source_data_hash
    original_snapshot = db_session.query(ReportSnapshotModel).filter(ReportSnapshotModel.id == report.source_snapshot_id).first()
    original_payload = json.loads(original_snapshot.snapshot_payload_json)
    assert original_payload["incident"]["title"] == "Original Incident Title At Generation Time"

    # Now mutate the underlying incident radically
    inc.title = "Completely Mutated Incident Title Post-Report"
    inc.severity = "low"
    inc.status = "RESOLVED"
    db_session.commit()

    # Re-fetch report snapshot and verify it has NOT drifted
    db_session.refresh(original_snapshot)
    rechecked_payload = json.loads(original_snapshot.snapshot_payload_json)
    assert rechecked_payload["incident"]["title"] == "Original Incident Title At Generation Time"
    assert rechecked_payload["incident"]["severity"] == "high"
    assert original_snapshot.snapshot_hash == original_hash


def test_05_redaction_pipeline_determinism(db_session: Session):
    """Verifies that redaction masks IPs, emails, and credentials deterministically."""
    raw_text = "Analyst contacted john.doe@company.corp regarding beaconing to 192.168.1.100 using Bearer secrettoken1234567890."

    none_redacted = ExecutiveReportService.apply_redaction_to_text(raw_text, "NONE")
    assert none_redacted == raw_text

    standard_redacted = ExecutiveReportService.apply_redaction_to_text(raw_text, "STANDARD")
    assert "john.doe@" not in standard_redacted
    assert "j***@company.corp" in standard_redacted
    assert "secrettoken1234567890" not in standard_redacted
    assert "[REDACTED_SECRET]" in standard_redacted
    # Standard does not mask IP by default
    assert "192.168.1.100" in standard_redacted

    strict_redacted = ExecutiveReportService.apply_redaction_to_text(raw_text, "STRICT")
    assert "192.168.1.100" not in strict_redacted
    assert "[REDACTED_IP]" in strict_redacted
    assert "j***@company.corp" in strict_redacted

    priv_redacted = ExecutiveReportService.apply_redaction_to_text(raw_text, "LEGAL_PRIVILEGED")
    assert "[ATTORNEY-CLIENT PRIVILEGED & CONFIDENTIAL DOCUMENT]" in priv_redacted
    assert "[REDACTED_IP]" in priv_redacted


def test_06_review_approval_and_finalization_lifecycle(db_session: Session):
    """
    Tests complete review, approval, and finalization workflow.
    Verifies that finalized reports become immutable.
    """
    # 1. Create Report
    report = ExecutiveReportService.create_executive_report(
        db=db_session,
        req=ExecutiveReportCreateRequest(
            title="Lifecycle Test Report",
            report_type=ReportTypeEnum.EXECUTIVE_BRIEFING,
        ),
        created_by="analyst_bob",
    )
    assert report.status == "DRAFT"
    assert not report.is_immutable

    # 2. Request Review
    rev_resp = client.post(
        f"/api/executive-reports/reports/{report.id}/review",
        json={"reviewers": ["lead_alice"], "note": "Please review section 2."},
        headers=AUTH_HEADERS_ANALYST,
    )
    assert rev_resp.status_code == 200
    assert rev_resp.json()["status"] == "REVIEW_REQUESTED"

    # 3. Add Review Note
    note_resp = client.post(
        f"/api/executive-reports/reports/{report.id}/review-note",
        json={"note": "Crown jewel assets verified.", "status": "APPROVED"},
        headers=AUTH_HEADERS_LEAD,
    )
    assert note_resp.status_code == 200

    # 4. Formally Approve
    app_resp = client.post(
        f"/api/executive-reports/reports/{report.id}/approve",
        json={"approval_notes": "Formal sign-off granted by SOC Lead."},
        headers=AUTH_HEADERS_LEAD,
    )
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "APPROVED"
    assert app_resp.json()["approved_by"] == "lead_alice"

    # 5. Finalize Report
    fin_resp = client.post(
        f"/api/executive-reports/reports/{report.id}/finalize",
        json={"finalization_notes": "Official release locked."},
        headers=AUTH_HEADERS_LEAD,
    )
    assert fin_resp.status_code == 200
    fin_data = fin_resp.json()
    assert fin_data["status"] == "FINALIZED"
    assert fin_data["is_immutable"] is True
    assert fin_data["finalized_by"] == "lead_alice"

    # 6. Verify Immutability Lock: Attempts to modify report are rejected with 400
    bad_edit_resp = client.put(
        f"/api/executive-reports/reports/{report.id}",
        json={"title": "Unauthorized Mutation Attempt"},
        headers=AUTH_HEADERS_ANALYST,
    )
    assert bad_edit_resp.status_code == 400
    assert "immutable" in bad_edit_resp.json()["detail"].lower()


def test_07_report_versioning_from_finalized(db_session: Session):
    """Verifies that spawning a new version from a finalized report creates a linked mutable child."""
    report = ExecutiveReportService.create_executive_report(
        db=db_session,
        req=ExecutiveReportCreateRequest(
            title="Version Branching Test",
            report_type=ReportTypeEnum.EXECUTIVE_BRIEFING,
        ),
        created_by="analyst_bob",
    )
    ExecutiveReportService.finalize_report(
        db=db_session,
        report_id=report.id,
        req=ReportFinalizeRequest(finalization_notes="Lock v1"),
        finalized_by="lead_alice",
    )

    # Spawn new version
    ver_resp = client.post(
        f"/api/executive-reports/reports/{report.id}/version",
        headers=AUTH_HEADERS_ANALYST,
    )
    assert ver_resp.status_code == 200
    child_data = ver_resp.json()
    assert child_data["report_version"] == 2
    assert child_data["status"] == "DRAFT"
    assert child_data["is_immutable"] is False
    assert "-v2" in child_data["report_number"]


def test_08_secure_share_link_lifecycle_and_public_access(db_session: Session):
    """
    Tests creating a cryptographically secure external share link,
    resolving it via public unauthenticated API, tracking use counts,
    and enforcing revocation.
    """
    report = ExecutiveReportService.create_executive_report(
        db=db_session,
        req=ExecutiveReportCreateRequest(
            title="Share Link Dissemination Test",
            report_type=ReportTypeEnum.EXECUTIVE_BRIEFING,
            summary="Confidential executive brief for legal counsel.",
        ),
        created_by="analyst_bob",
    )

    # 1. Create Share Link (max 2 uses, expires in 2 hours)
    share_req = {
        "format": "HTML",
        "classification": "CONFIDENTIAL",
        "redaction_level": "STANDARD",
        "expires_in_hours": 2,
        "max_uses": 2,
    }
    resp = client.post(
        f"/api/executive-reports/reports/{report.id}/share-links",
        json=share_req,
        headers=AUTH_HEADERS_ANALYST,
    )
    assert resp.status_code == 201
    link_data = resp.json()
    assert link_data["share_token"] is not None
    token = link_data["share_token"]
    link_id = link_data["id"]

    # 2. Public Access (Use #1) - No Auth Headers needed!
    pub_resp1 = client.get(f"/api/executive-reports/public/share/{token}")
    assert pub_resp1.status_code == 200
    pub_data1 = pub_resp1.json()
    assert pub_data1["title"] == report.title
    assert pub_data1["classification"] == "CONFIDENTIAL"
    assert pub_data1["html_content"] is not None

    # Verify use count is now 1
    db_link = db_session.query(ReportShareLinkModel).filter(ReportShareLinkModel.id == link_id).first()
    db_session.refresh(db_link)
    assert db_link.use_count == 1

    # 3. Public Access (Use #2)
    pub_resp2 = client.get(f"/api/executive-reports/public/share/{token}")
    assert pub_resp2.status_code == 200

    db_session.refresh(db_link)
    assert db_link.use_count == 2

    # 4. Public Access (Use #3 - Exceeded max_uses)
    pub_resp3 = client.get(f"/api/executive-reports/public/share/{token}")
    assert pub_resp3.status_code == 429
    assert "maximum" in pub_resp3.json()["detail"].lower()

    # 5. Revocation test on fresh link
    fresh_link, fresh_token = ExecutiveReportService.create_share_link(
        db=db_session,
        report_id=report.id,
        req=ReportShareLinkCreateRequest(max_uses=10),
        created_by="analyst_bob",
    )
    # Revoke it
    rev_resp = client.post(
        f"/api/executive-reports/share-links/{fresh_link.id}/revoke",
        headers=AUTH_HEADERS_ANALYST,
    )
    assert rev_resp.status_code == 200
    assert rev_resp.json()["is_revoked"] is True

    # Attempting to access revoked token returns 403 Forbidden
    rev_access = client.get(f"/api/executive-reports/public/share/{fresh_token}")
    assert rev_access.status_code == 403
    assert "revoked" in rev_access.json()["detail"].lower()


def test_09_rbac_permission_boundaries(db_session: Session):
    """Verifies that unauthorized actors cannot create templates or approve reports."""
    # Unauthorized role blocked
    resp_unauth = client.get("/api/executive-reports/reports", headers=AUTH_HEADERS_UNAUTH)
    assert resp_unauth.status_code == 403

    # Analyst cannot finalize report (Lead or Admin required)
    report = ExecutiveReportService.create_executive_report(
        db=db_session,
        req=ExecutiveReportCreateRequest(title="RBAC Gating Test"),
        created_by="analyst_bob",
    )
    resp_analyst_fin = client.post(
        f"/api/executive-reports/reports/{report.id}/finalize",
        json={"finalization_notes": "Trying to finalize"},
        headers=AUTH_HEADERS_ANALYST,
    )
    assert resp_analyst_fin.status_code == 403


def test_10_executive_metrics(db_session: Session):
    """Verifies executive reporting metrics endpoint returns accurate counts."""
    resp = client.get("/api/executive-reports/metrics", headers=AUTH_HEADERS_ANALYST)
    assert resp.status_code == 200
    metrics = resp.json()
    assert "total_reports" in metrics
    assert "draft_reports" in metrics
    assert "approved_reports" in metrics
    assert "finalized_reports" in metrics
    assert "active_share_links" in metrics
    assert "by_classification" in metrics
    assert "by_type" in metrics
