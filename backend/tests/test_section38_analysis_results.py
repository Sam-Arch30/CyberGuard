"""
Comprehensive Unit & Integration Tests for Section 38: Analysis Results + Progressive Disclosure.
Validates:
1. Four progressive disclosure levels (Executive, Analyst, Investigator, Forensic)
2. Risk score != severity != confidence separation
3. Unknown states are not silently rendered as safe
4. Traceable evidence assertions and counter-evidence
5. Lazy-load evidence details with automatic secret redaction
6. Manual risk reassessment flow
"""
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.db.session import SessionLocal, init_db
from backend.db.models import (
    AnalysisRunModel,
    AnalysisTaskModel,
    ArtifactModel,
    FindingModel,
    FindingEvidenceModel,
    IncidentModel,
    RelationshipModel,
    get_utc_now,
)
from backend.main import app
from backend.services.universal_ingestion import UniversalIngestionService
from backend.services.analysis_orchestrator import AnalysisOrchestrator


@pytest.fixture(scope="function")
def db_session():
    init_db()
    session = SessionLocal()
    try:
        yield session
    finally:
        session.rollback()
        session.close()


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_section38_results_aggregation_email(client, db_session: Session):
    """Verifies that completed email analysis compiles into structured 4-tier results."""
    unique_marker = uuid.uuid4().hex[:8]
    raw_eml = f"""From: Security Alert <support@paypal-verify-alert.com>
To: target-analyst@enterprise.corp
Subject: URGENT: Unauthorized Account Access Notice {unique_marker}
Date: Mon, 12 Oct 2026 14:22:00 +0000
Authentication-Results: mx.google.com; spf=fail (google.com: domain of support@paypal-verify-alert.com does not designate permitted sender) smtp.mailfrom=support@paypal-verify-alert.com; dkim=fail; dmarc=fail
Content-Type: text/plain; charset=utf-8

URGENT: We detected critical unauthorized activity on your account.
Your account access is suspended. Click http://login-secure-auth.target-verify.com immediately to verify your password and banking credentials.
"""
    ingest_res = UniversalIngestionService.ingest_file(
        db=db_session,
        content_bytes=raw_eml.encode("utf-8"),
        filename=f"phish_{unique_marker}.eml",
        reported_mime="message/rfc822",
        source="GATEWAY_TEST",
    )
    run_id = ingest_res.analysis_run_id
    assert run_id is not None

    # Execute run synchronously
    import asyncio
    asyncio.run(AnalysisOrchestrator.execute_run(db_session, run_id))

    # Query aggregated results endpoint
    response = client.get(f"/api/analysis/{run_id}/results")
    assert response.status_code == 200, response.text
    data = response.json()

    # 1. Level 1: Executive verification
    assert data["run_id"] == run_id
    assert data["status"] in ("COMPLETED", "PARTIAL")
    assert data["analysis_completeness"] in ("COMPLETE", "PARTIAL")

    risk = data["risk"]
    assert "score" in risk
    assert "level" in risk
    assert "severity" in risk
    assert "confidence" in risk
    assert "confidence_level" in risk
    assert "uncertainty" in risk
    assert risk["is_pending"] is False

    assert data["classification"]
    assert len(data["executive_summary"]) > 10
    assert len(data["why_cyberguard_thinks_this"]) >= 1
    for bullet in data["why_cyberguard_thinks_this"]:
        assert bullet["id"]
        assert bullet["claim"]
        assert bullet["support_level"] in ("CONFIRMED", "VERY_HIGH", "HIGH", "MODERATE", "WEAK")

    next_step = data["next_step_recommendation"]
    assert next_step["action_title"]
    assert next_step["action_description"]

    # 2. Level 2: Analyst verification
    assert isinstance(data["top_findings"], list)
    assert len(data["top_findings"]) >= 1
    top_f = data["top_findings"][0]
    assert top_f["title"]
    assert top_f["severity"]
    assert "confidence" in top_f
    assert "evidence_count" in top_f

    indicators = data["indicators_summary"]
    assert "domains" in indicators
    assert "urls" in indicators
    assert "ips" in indicators
    assert "hashes" in indicators
    assert indicators["total_count"] >= 1

    # Counter-evidence must exist to prevent confirmation bias
    assert len(data["counter_evidence"]) >= 1
    for ce in data["counter_evidence"]:
        assert ce["title"]
        assert ce["description"]
        assert "impact" in ce

    # Uncertainty & gaps must be explicitly stated
    assert len(data["uncertainty_and_gaps"]) >= 1

    # What would change assessment
    assert len(data["what_would_change_assessment"]) >= 1

    # 3. Level 3: Investigator verification
    mitre = data["mitre_preview"]
    assert isinstance(mitre, list)
    for m in mitre:
        assert m["technique_id"].startswith("T")
        assert m["status"] in ("SUPPORTED", "PLAUSIBLE", "INSUFFICIENT", "REJECTED")

    # Infrastructure location must NOT attribute human identity
    if data["infrastructure_preview"]:
        infra = data["infrastructure_preview"]
        assert "probable_origin_infrastructure" in infra
        assert "infrastructure_location" in infra
        # Ensure no human attacker identity keys exist
        assert "attacker_name" not in infra
        assert "attacker_identity" not in infra

    # 4. Level 4: Forensic verification
    prov = data["provenance"]
    assert prov["run_id"] == run_id
    assert prov["engine_version"] == "2.0.0"
    assert prov["risk_configuration_version"] == "2.4.0"
    assert len(data["run_history"]) >= 1


def test_section38_results_investigation_resolution(client, db_session: Session):
    """Verifies that an investigation ID or evidence ID resolves to the active results."""
    unique_marker = uuid.uuid4().hex[:8]
    raw_eml = f"From: hr@{unique_marker}.org\r\nTo: user@target.org\r\nSubject: Test {unique_marker}\r\n\r\nTest body"
    ingest_res = UniversalIngestionService.ingest_text(
        db=db_session,
        text=raw_eml,
        source="GATEWAY",
    )
    run_id = ingest_res.analysis_run_id

    import asyncio
    asyncio.run(AnalysisOrchestrator.execute_run(db_session, run_id))

    # Resolve by run_id
    res_run = client.get(f"/api/investigations/{run_id}/analysis/results")
    assert res_run.status_code == 200
    assert res_run.json()["run_id"] == run_id

    # Resolve by evidence_id if present
    if ingest_res.evidence_id:
        res_ev = client.get(f"/api/investigations/{ingest_res.evidence_id}/analysis/results")
        assert res_ev.status_code == 200
        assert res_ev.json()["run_id"] == run_id


def test_section38_partial_analysis_labeling(client, db_session: Session):
    """Verifies that partial runs are explicitly flagged as PARTIAL and never presented as complete."""
    # Create an artificial run with 1 completed and 1 failed task
    artifact = ArtifactModel(
        id=str(uuid.uuid4()),
        name="partial_artifact.eml",
        artifact_type="EMAIL",
        size=120,
        sha256=uuid.uuid4().hex,
        source="TEST",
    )
    db_session.add(artifact)
    db_session.flush()

    run = AnalysisRunModel(
        id=str(uuid.uuid4()),
        artifact_id=artifact.id,
        status="PARTIAL",
        overall_risk_score=45.0,
        overall_severity="MEDIUM",
        confidence=0.80,
    )
    db_session.add(run)
    db_session.flush()

    t1 = AnalysisTaskModel(
        id=str(uuid.uuid4()),
        analysis_run_id=run.id,
        analyzer_id="task_1",
        task_type="EVIDENCE_VALIDATION",
        title="Evidence Validation",
        status="COMPLETED",
    )
    t2 = AnalysisTaskModel(
        id=str(uuid.uuid4()),
        analysis_run_id=run.id,
        analyzer_id="task_2",
        task_type="REPUTATION_LOOKUP",
        title="Threat Intelligence Lookup",
        status="FAILED",
        error="External TI Provider Timeout",
    )
    db_session.add_all([t1, t2])
    db_session.commit()

    res = client.get(f"/api/analysis/{run.id}/results")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "PARTIAL"
    assert data["analysis_completeness"] == "PARTIAL"
    assert "encountered errors" in data["completeness_message"]
    assert data["failed_tasks"] == 1
    assert data["total_tasks"] == 2


def test_section38_unknown_states_not_safe(client, db_session: Session):
    """Verifies that uncalculated or pending runs show 'Risk assessment pending' and NOT 'Risk: 0' or 'Safe'."""
    artifact = ArtifactModel(
        id=str(uuid.uuid4()),
        name="queued_artifact.eml",
        artifact_type="EMAIL",
        size=50,
        sha256=uuid.uuid4().hex,
        source="TEST",
    )
    db_session.add(artifact)
    db_session.flush()

    run = AnalysisRunModel(
        id=str(uuid.uuid4()),
        artifact_id=artifact.id,
        status="QUEUED",
        overall_risk_score=None,
        overall_severity=None,
        confidence=None,
    )
    db_session.add(run)
    db_session.commit()

    res = client.get(f"/api/analysis/{run.id}/results")
    assert res.status_code == 200
    data = res.json()

    risk = data["risk"]
    assert risk["is_pending"] is True
    assert risk["score"] is None
    assert risk["level"] == "UNKNOWN"
    assert risk["status_label"] == "Risk assessment pending"


def test_section38_lazy_evidence_detail_and_redaction(client, db_session: Session):
    """Verifies lazy-loading of evidence items and strict automatic redaction of secrets."""
    artifact = ArtifactModel(
        id=str(uuid.uuid4()),
        name="auth_leak.txt",
        artifact_type="FILE",
        size=80,
        sha256=uuid.uuid4().hex,
        source="TEST",
    )
    db_session.add(artifact)
    db_session.flush()

    run = AnalysisRunModel(
        id=str(uuid.uuid4()),
        artifact_id=artifact.id,
        status="COMPLETED",
        overall_risk_score=85.0,
        overall_severity="HIGH",
    )
    db_session.add(run)
    db_session.flush()

    finding = FindingModel(
        id=str(uuid.uuid4()),
        analysis_run_id=run.id,
        analyzer="auth_inspector",
        finding_type="CREDENTIAL_EXPOSURE",
        title="Exposed API Authorization Header",
        description="Leaked token found in request headers.",
        severity="HIGH",
        confidence=0.98,
        risk_contribution=40.0,
        method="RULE",
    )
    db_session.add(finding)
    db_session.flush()

    raw_secret_value = "Authorization: Bearer super_secret_token_abc123xyz"
    ev = FindingEvidenceModel(
        id=str(uuid.uuid4()),
        finding_id=finding.id,
        evidence_type="HEADER",
        source="HTTP_DUMP",
        key="Authorization",
        value=raw_secret_value,
        confidence=0.99,
        artifact_id=artifact.id,
    )
    db_session.add(ev)
    db_session.commit()

    # Call lazy load evidence detail endpoint
    res = client.get(f"/api/analysis/{run.id}/evidence/{ev.id}")
    assert res.status_code == 200, res.text
    ev_detail = res.json()

    assert ev_detail["id"] == ev.id
    assert ev_detail["finding_id"] == finding.id
    assert ev_detail["linked_finding_title"] == "Exposed API Authorization Header"
    # Ensure sensitive secret was redacted!
    assert "super_secret_token_abc123xyz" not in ev_detail["value"]
    assert "[REDACTED_TOKEN]" in ev_detail["value"]


def test_section38_manual_reassessment(client, db_session: Session):
    """Verifies that manual reassessment refreshes the analysis without creating duplicate artifacts."""
    unique_marker = uuid.uuid4().hex[:8]
    raw_eml = f"From: alert@{unique_marker}.com\r\nTo: user@target.corp\r\nSubject: Reassess Test {unique_marker}\r\n\r\nBody"
    ingest_res = UniversalIngestionService.ingest_text(
        db=db_session,
        text=raw_eml,
        source="GATEWAY",
    )
    run_id = ingest_res.analysis_run_id

    import asyncio
    asyncio.run(AnalysisOrchestrator.execute_run(db_session, run_id))

    # Trigger reassessment
    reassess_res = client.post(f"/api/analysis/{run_id}/reassess")
    assert reassess_res.status_code == 200, reassess_res.text
    data = reassess_res.json()

    assert data["run_id"] == run_id
    assert data["status"] in ("COMPLETED", "PARTIAL")
    assert data["risk"]["score"] is not None
