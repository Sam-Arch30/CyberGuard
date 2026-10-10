"""
Unit and Integration Tests for Section 48: Alert Management & Triage Workspace.
Verifies authoritative alert retrieval, status lifecycle transitions, provenance aggregation,
audit recording, and strict workspace isolation.
"""
import pytest
import uuid
import json
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.models import (
    Base,
    NotificationModel,
    FindingModel,
    FindingEvidenceModel,
    AnalysisRunModel,
    ArtifactModel,
    IncidentModel,
    AuditLogModel,
)
from backend.schemas.alerts import (
    AlertStatusEnum,
    AlertSeverityEnum,
)
from backend.services.alert_service import AlertService
from backend.main import app
from backend.db.session import get_db


@pytest.fixture
def db_session():
    """In-memory SQLite session with table schema creation."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(db_session):
    """Test client overriding the FastAPI get_db dependency."""
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.clear()


def create_sample_provenance_alert(db, workspace_id="ws-alpha", status="OPEN", severity="CRITICAL"):
    """Helper to seed an artifact, analysis run, finding, evidence, and security alert."""
    artifact_id = str(uuid.uuid4())
    artifact = ArtifactModel(
        id=artifact_id,
        name="malicious_credential_phish.eml",
        artifact_type="EMAIL_RFC822",
        source="ingest",
        mime_type="message/rfc822",
        sha256="abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        size=1024,
    )
    db.add(artifact)

    run_id = str(uuid.uuid4())
    run = AnalysisRunModel(
        id=run_id,
        artifact_id=artifact_id,
        status="COMPLETED",
        overall_severity=severity,
        overall_risk_score=94.5,
    )
    db.add(run)

    finding_id = str(uuid.uuid4())
    finding = FindingModel(
        id=finding_id,
        analysis_run_id=run_id,
        analyzer="CredentialHarvesterDetector",
        finding_type="CREDENTIAL_THEFT",
        method="RULE",
        severity=severity,
        confidence=0.96,
        risk_contribution=45.0,
        title="High-confidence Credential Harvesting Form Detected",
        description="Analyzed login page redirects to rogue credential-stealing endpoint.",
        rule_id="RULE-PHISH-009",
    )
    db.add(finding)

    evidence_id = str(uuid.uuid4())
    evidence = FindingEvidenceModel(
        id=evidence_id,
        finding_id=finding_id,
        evidence_type="SUSPICIOUS_URL",
        key="suspicious_form_action",
        value="https://secure-login.fakeweb.xyz/login.php",
        source="HTMLParser",
        confidence=0.98,
    )
    db.add(evidence)

    alert_id = str(uuid.uuid4())
    alert = NotificationModel(
        id=alert_id,
        workspace_id=workspace_id,
        category="SECURITY_ALERT",
        notification_type="CREDENTIAL_THEFT",
        severity=severity,
        status=status,
        title="Credential theft detected in inbound message",
        message="A phishing email containing a credential harvesting form was blocked.",
        source_type="FINDING",
        source_id=finding_id,
        finding_id=finding_id,
        analysis_run_id=run_id,
        navigation_target=f"/alerts/{alert_id}",
        deduplication_key=f"dedup-{alert_id}",
        metadata_json=json.dumps({"explanation": "Domain resembles trusted authentication portal"}),
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def test_list_alerts_and_metrics(client, db_session):
    """Verifies listing, filtering, pagination, and triage metrics calculation."""
    # Seed 3 alerts in ws-alpha
    create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN", severity="CRITICAL")
    create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN", severity="HIGH")
    create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="RESOLVED", severity="MEDIUM")

    # Metrics endpoint
    res = client.get("/api/alerts/metrics", headers={"X-Workspace-ID": "ws-alpha"})
    assert res.status_code == 200
    metrics = res.json()
    assert metrics["total_alerts"] == 3
    assert metrics["open_count"] == 2
    assert metrics["critical_open"] == 1
    assert metrics["high_open"] == 1
    assert metrics["resolved_count"] == 1

    # List open alerts
    res_open = client.get("/api/alerts?status=OPEN", headers={"X-Workspace-ID": "ws-alpha"})
    assert res_open.status_code == 200
    data_open = res_open.json()
    assert data_open["total"] == 2
    assert len(data_open["items"]) == 2
    # Verify sorting by severity (CRITICAL before HIGH)
    assert data_open["items"][0]["severity"] == "CRITICAL"
    assert data_open["items"][1]["severity"] == "HIGH"


def test_alert_detail_provenance_and_explainability(client, db_session):
    """Verifies that alert detail loads explainability why-cards, finding, evidence, and audit activity."""
    alert = create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN", severity="CRITICAL")

    res = client.get(f"/api/alerts/{alert.id}", headers={"X-Workspace-ID": "ws-alpha"})
    assert res.status_code == 200
    detail = res.json()

    assert detail["id"] == alert.id
    assert detail["severity"] == "CRITICAL"
    assert detail["status"] == "OPEN"
    # Explainability items
    assert len(detail["why_created"]) >= 2
    assert any("credential-stealing endpoint" in w for w in detail["why_created"])
    assert any("Domain resembles" in w for w in detail["why_created"])
    # Provenance finding and evidence
    assert detail["finding_detail"] is not None
    assert detail["finding_detail"]["analyzer"] == "CredentialHarvesterDetector"
    assert len(detail["evidence_items"]) == 1
    assert "secure-login.fakeweb.xyz" in detail["evidence_items"][0]["indicator_value"]
    # Analysis run
    assert detail["analysis_run_detail"] is not None
    assert detail["analysis_run_detail"]["artifact_name"] == "malicious_credential_phish.eml"
    # Initial creation activity
    assert len(detail["activity_timeline"]) >= 1
    assert detail["activity_timeline"][0]["action"] == "ALERT_CREATED"


def test_alert_lifecycle_state_transitions(client, db_session):
    """Verifies complete state transitions: Acknowledge -> Assign -> Investigate -> Resolve with audit."""
    alert = create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN", severity="CRITICAL")

    # 1. Acknowledge
    ack_res = client.post(
        f"/api/alerts/{alert.id}/acknowledge",
        json={"analyst_name": "Alice SOC", "note": "Acknowledged threat signal."},
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == AlertStatusEnum.ACKNOWLEDGED.value
    assert ack_res.json()["acknowledged_by"] == "Alice SOC"

    # 2. Assign
    assign_res = client.post(
        f"/api/alerts/{alert.id}/assign",
        json={"assigned_to": "Tier-2 Incident Team", "analyst_name": "Alice SOC"},
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert assign_res.status_code == 200
    assert assign_res.json()["assigned_to"] == "Tier-2 Incident Team"

    # 3. Investigate
    inv_res = client.post(
        f"/api/alerts/{alert.id}/investigate",
        headers={"X-Workspace-ID": "ws-alpha", "X-User": "Bob Analyst"},
    )
    assert inv_res.status_code == 200
    assert inv_res.json()["status"] == AlertStatusEnum.INVESTIGATING.value

    # 4. Add Triage Note
    note_res = client.post(
        f"/api/alerts/{alert.id}/notes",
        json={"note": "Confirmed weaponized payload in attachment. Coordinated with DNS team.", "analyst_name": "Bob Analyst"},
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert note_res.status_code == 200

    # 5. Resolve
    resolve_res = client.post(
        f"/api/alerts/{alert.id}/resolve",
        json={"resolution_reason": "Rogue domain sinkholed and credentials revoked.", "analyst_name": "Bob Analyst"},
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == AlertStatusEnum.RESOLVED.value
    assert resolve_res.json()["resolved_by"] == "Bob Analyst"

    # Verify audit logs in db
    logs = db_session.query(AuditLogModel).filter(AuditLogModel.resource_id == alert.id).all()
    logged_actions = [l.action for l in logs]
    assert "ALERT_ACKNOWLEDGED" in logged_actions
    assert "ALERT_ASSIGNED" in logged_actions
    assert "ALERT_INVESTIGATING" in logged_actions
    assert "ALERT_NOTE_ADDED" in logged_actions
    assert "ALERT_RESOLVED" in logged_actions


def test_false_positive_and_suppression(client, db_session):
    """Verifies False Positive and Suppression state changes."""
    alert1 = create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN", severity="HIGH")
    alert2 = create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN", severity="MEDIUM")

    # Mark alert1 as false positive
    fp_res = client.post(
        f"/api/alerts/{alert1.id}/false-positive",
        json={"reason": "Internal authorized vulnerability scanning suite", "analyst_name": "Lead Analyst"},
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert fp_res.status_code == 200
    assert fp_res.json()["status"] == AlertStatusEnum.FALSE_POSITIVE.value

    # Suppress alert2
    supp_res = client.post(
        f"/api/alerts/{alert2.id}/suppress",
        json={"reason": "Known testing lab domain", "scope": "THIS_ALERT", "analyst_name": "Lead Analyst"},
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert supp_res.status_code == 200
    assert supp_res.json()["status"] == AlertStatusEnum.SUPPRESSED.value

    # Verify detail shows reasons
    det1 = client.get(f"/api/alerts/{alert1.id}", headers={"X-Workspace-ID": "ws-alpha"}).json()
    assert det1["false_positive_reason"] == "Internal authorized vulnerability scanning suite"

    det2 = client.get(f"/api/alerts/{alert2.id}", headers={"X-Workspace-ID": "ws-alpha"}).json()
    assert det2["suppression_reason"] == "Known testing lab domain"
    assert det2["suppression_scope"] == "THIS_ALERT"


def test_bulk_acknowledge(client, db_session):
    """Verifies bulk acknowledgement functionality."""
    a1 = create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN")
    a2 = create_sample_provenance_alert(db_session, workspace_id="ws-alpha", status="OPEN")

    bulk_res = client.post(
        "/api/alerts/bulk/acknowledge",
        json={"alert_ids": [a1.id, a2.id], "analyst_name": "Shift Supervisor"},
        headers={"X-Workspace-ID": "ws-alpha"},
    )
    assert bulk_res.status_code == 200
    data = bulk_res.json()
    assert data["acknowledged_count"] == 2
    assert set(data["acknowledged_ids"]) == {a1.id, a2.id}


def test_tenant_isolation(client, db_session):
    """Verifies that alerts created in workspace A are not visible or editable in workspace B."""
    alert_a = create_sample_provenance_alert(db_session, workspace_id="workspace-a", status="OPEN")

    # In workspace-b, list returns 0 items
    list_b = client.get("/api/alerts", headers={"X-Workspace-ID": "workspace-b"}).json()
    assert list_b["total"] == 0

    # In workspace-b, detail returns 404
    detail_b = client.get(f"/api/alerts/{alert_a.id}", headers={"X-Workspace-ID": "workspace-b"})
    assert detail_b.status_code == 404

    # In workspace-b, acknowledge returns 404
    ack_b = client.post(
        f"/api/alerts/{alert_a.id}/acknowledge",
        json={"analyst_name": "Attacker"},
        headers={"X-Workspace-ID": "workspace-b"},
    )
    assert ack_b.status_code == 404
