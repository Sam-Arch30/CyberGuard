"""
Unit & Integration Tests for Section 37 — Live Analysis & Real-Time Task DAG Execution.
"""
import asyncio
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    AnalysisTaskModel,
    AnalysisEventModel,
    IncidentModel,
    EvidenceModel,
    RelationshipModel,
)
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.universal_ingestion import UniversalIngestionService
from backend.schemas.unified import ArtifactTypeEnum, AnalysisStatusEnum

client = TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


SAMPLE_EML = b"""From: alerts@paypal-verification.com
To: user@example.com
Subject: Urgent Security Warning: Account Suspension Imminent
Date: Wed, 08 Oct 2026 12:00:00 +0000
Message-ID: <sec-20261008-01@paypal-verification.com>
Received: from mail.paypal-verification.com (198.51.100.25) by mx.example.com; Wed, 08 Oct 2026 12:00:01 +0000
Authentication-Results: mx.example.com; dkim=fail; spf=fail smtp.mailfrom=paypal-verification.com; dmarc=fail
Content-Type: text/html; charset="UTF-8"

<html><body>
<p>Dear customer, your account has been locked due to unauthorized access.</p>
<p>Click <a href="http://paypal-verification.com/login">here</a> immediately to restore access.</p>
</body></html>
"""


def test_section37_dag_initialization_email(db: Session):
    """Verifies that an EMAIL artifact produces the full multimodal task DAG with dependencies."""
    # 1. Create Artifact
    art = ArtifactModel(
        artifact_type="EMAIL",
        name="test_suspicious.eml",
        source="DASHBOARD_UPLOAD",
        mime_type="message/rfc822",
        size=len(SAMPLE_EML),
        sha256="aabbcc11223344556677889900aabbcc11223344556677889900aabbcc112233",
    )
    db.add(art)
    db.flush()

    run = AnalysisRunModel(
        artifact_id=art.id,
        status="QUEUED",
        trigger="USER",
        pipeline_version="1.0.0",
    )
    db.add(run)
    db.flush()

    # 2. Initialize DAG
    tasks = AnalysisOrchestrator.initialize_run_dag(db, run.id)
    assert len(tasks) == 9, f"Expected 9 tasks for EMAIL DAG, got {len(tasks)}"

    task_types = [t.task_type for t in tasks]
    assert "EVIDENCE_VALIDATION" in task_types
    assert "MIME_PARSING" in task_types
    assert "AUTHENTICATION_ANALYSIS" in task_types
    assert "SMTP_RELAY_ANALYSIS" in task_types
    assert "ATTACHMENT_DISCOVERY" in task_types
    assert "IOC_EXTRACTION" in task_types
    assert "INTELLIGENCE_ENRICHMENT" in task_types
    assert "NLP_SOCIAL_ENGINEERING" in task_types
    assert "RISK_ASSESSMENT" in task_types

    # Verify all tasks start in PENDING
    for t in tasks:
        assert t.status == "PENDING"
        assert t.analysis_run_id == run.id

    # Verify risk_engine depends on upstream tasks
    risk_task = next(t for t in tasks if t.task_type == "RISK_ASSESSMENT")
    dep_ids = json.loads(risk_task.dependency_ids_json)
    assert len(dep_ids) >= 4, "Risk assessment must depend on upstream findings"


def test_section37_dag_initialization_multimodal_variants(db: Session):
    """Verifies that URL, FILE, and AUTH_LOG receive their own dedicated, non-hardcoded DAGs."""
    # URL Artifact
    art_url = ArtifactModel(
        artifact_type="URL",
        name="https://malicious.example.com/login",
        source="PASTE_URL",
        mime_type="text/plain",
        size=35,
    )
    db.add(art_url)
    db.flush()
    run_url = AnalysisRunModel(artifact_id=art_url.id, status="QUEUED")
    db.add(run_url)
    db.flush()
    tasks_url = AnalysisOrchestrator.initialize_run_dag(db, run_url.id)
    url_types = {t.task_type for t in tasks_url}
    assert "PASSIVE_URL_ANALYSIS" in url_types
    assert "DOMAIN_INTELLIGENCE" in url_types
    assert "ACTIVE_INSPECTION" in url_types
    assert "MIME_PARSING" not in url_types  # Must not assume email

    # AUTH_LOG Artifact
    art_log = ArtifactModel(
        artifact_type="AUTH_LOG",
        name="auth_telemetry.json",
        source="API_TELEMETRY",
        mime_type="application/json",
        size=100,
    )
    db.add(art_log)
    db.flush()
    run_log = AnalysisRunModel(artifact_id=art_log.id, status="QUEUED")
    db.add(run_log)
    db.flush()
    tasks_log = AnalysisOrchestrator.initialize_run_dag(db, run_log.id)
    log_types = {t.task_type for t in tasks_log}
    assert "EVENT_NORMALIZATION" in log_types
    assert "BEHAVIORAL_BASELINE" in log_types
    assert "ANOMALY_DETECTION" in log_types
    assert "PASSIVE_URL_ANALYSIS" not in log_types


def test_section37_live_execution_and_events(db: Session):
    """Tests end-to-end DAG execution: status transitions, real event logging, and risk calculation."""
    # Ingest an EML through Universal Ingestion
    ing_res = UniversalIngestionService.ingest_file(
        db=db,
        filename="phishing_invoice_sec37.eml",
        content_bytes=SAMPLE_EML,
        reported_mime="message/rfc822",
        submitted_by="SOC Analyst",
    )
    assert ing_res.analysis_run_id is not None
    run_id = ing_res.analysis_run_id

    # Execute DAG using asyncio.run
    executed_run = asyncio.run(AnalysisOrchestrator.execute_run(db, run_id))
    assert executed_run.status == "COMPLETED"
    assert executed_run.started_at is not None
    assert executed_run.completed_at is not None
    assert executed_run.overall_risk_score is not None
    assert executed_run.overall_risk_score > 0
    assert executed_run.overall_severity in ("HIGH", "CRITICAL")

    # Verify tasks are marked COMPLETED with real durations
    tasks = db.query(AnalysisTaskModel).filter(AnalysisTaskModel.analysis_run_id == run_id).all()
    for t in tasks:
        assert t.status == "COMPLETED"
        assert t.duration_seconds is not None
        assert t.duration_seconds >= 0

    # Verify real events emitted into analysis_events table
    events = db.query(AnalysisEventModel).filter(AnalysisEventModel.analysis_run_id == run_id).all()
    assert len(events) >= 10, f"Expected at least 10 lifecycle events, got {len(events)}"
    event_types = {e.event_type for e in events}
    assert "RUN_STARTED" in event_types
    assert "TASK_STARTED" in event_types
    assert "TASK_COMPLETED" in event_types
    assert "RUN_COMPLETED" in event_types


def test_section37_live_analysis_endpoints(db: Session):
    """Verifies /api/analysis/{run_id} and /api/investigations/{id}/analysis endpoints."""
    # Ingest file
    ing_res = UniversalIngestionService.ingest_file(
        db=db,
        filename="endpoint_test_sec37.eml",
        content_bytes=SAMPLE_EML + b"\nX-Endpoint-Test: true\n",
        reported_mime="message/rfc822",
        submitted_by="Test Operator",
    )
    run_id = ing_res.analysis_run_id
    inv_id = ing_res.investigation_id
    evd_id = ing_res.evidence_id

    # 1. Fetch live analysis by run_id
    res_run = client.get(f"/api/analysis/{run_id}")
    assert res_run.status_code == 200
    data_run = res_run.json()
    assert data_run["id"] == run_id
    assert data_run["artifact_name"] == "endpoint_test_sec37.eml"
    assert len(data_run["tasks"]) == 9

    # 2. Fetch live analysis by investigation ID (/api/investigations/{id}/analysis)
    if inv_id:
        res_inv = client.get(f"/api/investigations/{inv_id}/analysis")
        assert res_inv.status_code == 200
        data_inv = res_inv.json()
        assert data_inv["id"] == run_id

    # 3. Fetch live analysis by evidence ID
    if evd_id:
        res_evd = client.get(f"/api/investigations/{evd_id}/analysis")
        assert res_evd.status_code == 200
        data_evd = res_evd.json()
        assert data_evd["id"] == run_id


def test_section37_cancellation_and_retry(db: Session):
    """Verifies cancel and retry workflows."""
    art = ArtifactModel(
        artifact_type="EMAIL",
        name="cancel_test_sec37.eml",
        source="TEST",
        mime_type="message/rfc822",
        size=100,
    )
    db.add(art)
    db.flush()
    run = AnalysisRunModel(artifact_id=art.id, status="QUEUED")
    db.add(run)
    db.flush()
    AnalysisOrchestrator.initialize_run_dag(db, run.id)

    # 1. Cancel
    res_cancel = client.post(f"/api/analysis/{run.id}/cancel")
    assert res_cancel.status_code == 200
    data_cancel = res_cancel.json()
    assert data_cancel["status"] == "CANCELLED"

    # 2. Retry
    res_retry = client.post(f"/api/analysis/{run.id}/retry")
    assert res_retry.status_code == 200
    data_retry = res_retry.json()
    assert data_retry["status"] in ("QUEUED", "RUNNING", "COMPLETED", "PARTIAL")


def test_section37_sse_stream_initial_snapshot(db: Session):
    """Verifies that the SSE stream endpoint provides valid event-stream with snapshot."""
    art = ArtifactModel(
        artifact_type="EMAIL",
        name="sse_test_sec37.eml",
        source="TEST",
        mime_type="message/rfc822",
        size=100,
    )
    db.add(art)
    db.flush()
    run = AnalysisRunModel(artifact_id=art.id, status="COMPLETED")
    db.add(run)
    db.flush()
    AnalysisOrchestrator.initialize_run_dag(db, run.id)

    response = client.get(f"/api/analysis/{run.id}/stream")
    assert response.status_code == 200
    assert "text/event-stream" in response.headers.get("content-type", "")
    assert "event: snapshot" in response.text
    assert "event: terminal" in response.text
