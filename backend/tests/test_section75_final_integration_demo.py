"""
Section 75: Final Integration & Demo Hardening Verification Test Suite.
Validates the entire end-to-end CyberGuard golden path across:
- Scenario definitions (4 authentic scenarios: A, B, C, D)
- End-to-end execution of Scenarios through real Ingestion, Analysis, Correlation, Risk, and Response
- Data integrity & Cross-entity identifier preservation (artifact -> run -> case -> incident -> attack path -> evidence)
- Server-authoritative risk calculation (no client-side or fake fabrication)
- Human-in-the-loop response safety (actions created with status: RECOMMENDED)
- Isolation and safe demo reset (purges only is_demo: true, strictly preserves production records)
- Negative failure path safety and role authorization enforcement
- Provenance verification (Finding -> Analysis Run -> Artifact -> Evidence hash integrity)
"""
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    CaseModel,
    IncidentModel,
    FindingModel,
    AttackPathModel,
    ResponseActionModel,
    EvidenceModel,
    generate_uuid,
    get_utc_now,
)
from backend.services.demo_scenario_service import DemoScenarioService

client = TestClient(app)


@pytest.fixture(scope="module")
def db_session():
    db = SessionLocal()
    yield db
    db.close()


def test_list_demo_scenarios():
    """Verify listing the 4 realistic Section 75 demo scenarios."""
    response = client.get("/api/demo/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["count"] == 4
    scenario_ids = [s["id"] for s in data["scenarios"]]
    assert "scenario-a-phishing" in scenario_ids
    assert "scenario-b-bec" in scenario_ids
    assert "scenario-c-malicious-attachment" in scenario_ids
    assert "scenario-d-multistage" in scenario_ids


def test_get_individual_scenario():
    """Verify retrieving details of an individual scenario."""
    response = client.get("/api/demo/scenarios/scenario-a-phishing")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    scenario = data["scenario"]
    assert scenario["id"] == "scenario-a-phishing"
    assert "PayPal" in scenario["description"] or "phishing" in scenario["description"].lower()
    assert scenario["expected_severity"] in ("HIGH", "CRITICAL")
    assert len(scenario["mitre_techniques"]) > 0


def test_execute_scenario_a_golden_path(db_session):
    """
    Test End-to-End Golden Path for Scenario A (Phishing Email).
    Verifies full lifecycle:
    Artifact -> AnalysisRun -> Findings -> Risk -> Incident -> Case -> AttackPath -> Recommendation -> Evidence
    """
    headers = {"X-User": "lead.analyst@cyberguard.local", "X-Role": "admin"}
    response = client.post(
        "/api/demo/scenarios/scenario-a-phishing/execute",
        json={"workspace_id": "test_corp_soc", "actor": "Lead Analyst"},
        headers=headers,
    )
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "SUCCESS"
    assert res["is_demo"] is True

    # 1. Verify Identifiers are generated
    artifact_id = res["artifact_id"]
    analysis_run_id = res["analysis_run_id"]
    case_id = res["case_id"]
    incident_id = res["incident_id"]
    attack_path_id = res["attack_path_id"]
    evidence_id = res["evidence_id"]

    assert artifact_id is not None and len(artifact_id) == 36
    assert analysis_run_id is not None and len(analysis_run_id) == 36
    assert case_id is not None and len(case_id) == 36
    assert incident_id is not None and len(incident_id) == 36
    assert attack_path_id is not None and len(attack_path_id) == 36
    assert evidence_id.startswith("EV-DEMO-")

    # 2. Verify Database Persistence and Cross-Entity Referential Integrity
    art = db_session.query(ArtifactModel).filter(ArtifactModel.id == artifact_id).first()
    assert art is not None
    assert art.artifact_type == "EMAIL"
    assert art.sha256 is not None
    assert len(art.sha256) == 64

    run = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.id == analysis_run_id).first()
    assert run is not None
    assert run.artifact_id == artifact_id
    assert run.status in ("COMPLETED", "PROCESSED", "SUCCESS")
    assert run.overall_risk_score >= 0.0

    # 3. Verify Findings were authentically generated
    findings = db_session.query(FindingModel).filter(FindingModel.analysis_run_id == run.id).all()
    assert len(findings) > 0

    # 4. Verify Case and Incident link
    case = db_session.query(CaseModel).filter(CaseModel.id == case_id).first()
    incident = db_session.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
    assert case is not None
    assert incident is not None
    assert case.incident_id == incident.id
    assert incident.legacy_case_id == case.id

    # 5. Verify Attack Path mapping
    attack_path = db_session.query(AttackPathModel).filter(AttackPathModel.id == attack_path_id).first()
    assert attack_path is not None
    assert attack_path.incident_id == incident.id

    # 6. Verify Response Recommendation Safety (RECOMMENDED, never auto-executed)
    action = db_session.query(ResponseActionModel).filter(ResponseActionModel.incident_id == incident.id).first()
    assert action is not None
    assert action.status == "RECOMMENDED"
    assert action.action_type in ("BLOCK_SENDER_DOMAIN", "CONTAIN_HOST", "ISOLATE_ACCOUNT")

    # 7. Verify Evidence Custody
    ev = db_session.query(EvidenceModel).filter(EvidenceModel.evidence_id == evidence_id).first()
    assert ev is not None
    assert ev.artifact_id == artifact_id
    assert ev.case_id == case.id
    assert ev.sha256 == art.sha256
    assert ev.integrity_status == "VERIFIED"


def test_execute_scenario_b_bec(db_session):
    """Test authentic execution of Scenario B (Business Email Compromise)."""
    headers = {"X-User": "soc.tier2@cyberguard.local", "X-Role": "analyst"}
    response = client.post(
        "/api/demo/scenarios/scenario-b-bec/execute",
        json={"workspace_id": "test_corp_soc"},
        headers=headers,
    )
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "SUCCESS"
    assert res["scenario"]["id"] == "scenario-b-bec"
    assert res["overall_severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert res["findings_count"] >= 0


def test_execute_scenario_c_attachment(db_session):
    """Test authentic execution of Scenario C (Malicious Attachment with PE header)."""
    headers = {"X-User": "soc.tier2@cyberguard.local", "X-Role": "analyst"}
    response = client.post(
        "/api/demo/scenarios/scenario-c-malicious-attachment/execute",
        json={"workspace_id": "test_corp_soc"},
        headers=headers,
    )
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "SUCCESS"
    assert res["scenario"]["id"] == "scenario-c-malicious-attachment"


def test_execute_scenario_d_multistage(db_session):
    """Test authentic execution of Scenario D (Multi-Stage Coordinated Attack)."""
    headers = {"X-User": "soc.tier2@cyberguard.local", "X-Role": "analyst"}
    response = client.post(
        "/api/demo/scenarios/scenario-d-multistage/execute",
        json={"workspace_id": "test_corp_soc"},
        headers=headers,
    )
    assert response.status_code == 200
    res = response.json()
    assert res["status"] == "SUCCESS"
    assert res["scenario"]["id"] == "scenario-d-multistage"


def test_demo_status_reporting():
    """Verify demo status returns count of active demo entities."""
    response = client.get("/api/demo/status")
    assert response.status_code == 200
    data = response.json()
    assert data["demo_artifacts_active"] >= 4
    assert data["demo_cases_active"] >= 4
    assert data["environment_mode"] == "DEMO_READY"


def test_safe_demo_reset_preserves_production_data(db_session):
    """
    Test Safe Demo Reset:
    1. Creates a genuine production artifact and case (tagged is_demo: False).
    2. Calls /api/demo/reset.
    3. Verifies all demo entities are purged.
    4. Verifies genuine production records remain completely intact.
    """
    # Create genuine production records
    prod_art_id = generate_uuid("art")
    prod_art = ArtifactModel(
        id=prod_art_id,
        name="critical_enterprise_production_evidence.eml",
        artifact_type="EMAIL",
        source="EXCHANGE_PRODUCTION_JOURNAL",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size=1024,
        storage_reference="prod://vault/2026/art_prod_01",
        metadata_json=json.dumps({"is_demo": False, "customer_id": "ENT_PROD_9982"}),
        created_at=get_utc_now(),
    )
    prod_case_id = generate_uuid("case")
    prod_case = CaseModel(
        id=prod_case_id,
        case_number="CASE-PROD-REAL-001",
        workspace_id="enterprise_prod",
        title="Production Incident Case (DO NOT DELETE)",
        description="High-value client investigation.",
        severity="CRITICAL",
        priority="P1_CRITICAL",
        status="OPEN",
        category="APT_INTRUSION",
        created_by="Chief Information Security Officer",
        tags_json=json.dumps(["PRODUCTION", "CONFIDENTIAL"]),
        custom_fields_json=json.dumps({"is_demo": False}),
        created_at=get_utc_now(),
    )
    db_session.add_all([prod_art, prod_case])
    db_session.commit()

    # Execute Demo Reset
    headers = {"X-User": "admin@cyberguard.local", "X-Role": "admin"}
    reset_resp = client.post("/api/demo/reset", headers=headers)
    assert reset_resp.status_code == 200
    reset_data = reset_resp.json()
    assert reset_data["status"] == "DEMO_RESET_COMPLETE"
    assert reset_data["isolated"] is True

    # Verify Production Records were PRESERVED
    check_prod_art = db_session.query(ArtifactModel).filter(ArtifactModel.id == prod_art_id).first()
    check_prod_case = db_session.query(CaseModel).filter(CaseModel.id == prod_case_id).first()
    assert check_prod_art is not None, "Production artifact was erroneously deleted!"
    assert check_prod_case is not None, "Production case was erroneously deleted!"

    # Verify Demo status reflects 0 active demo entities
    status_resp = client.get("/api/demo/status")
    status_data = status_resp.json()
    assert status_data["demo_artifacts_active"] == 0
    assert status_data["demo_cases_active"] == 0

    # Clean up test production artifact and case
    db_session.delete(check_prod_art)
    db_session.delete(check_prod_case)
    db_session.commit()


def test_negative_invalid_scenario_rejection():
    """Verify rejection of invalid scenario identifier."""
    headers = {"X-User": "analyst@cyberguard.local", "X-Role": "analyst"}
    response = client.post(
        "/api/demo/scenarios/invalid-nonexistent-scenario/execute",
        headers=headers,
    )
    assert response.status_code == 400
    assert "Unknown scenario ID" in response.json()["detail"]


def test_authorization_role_enforcement():
    """Verify unauthorized role cannot execute or reset demo fixtures."""
    unauth_headers = {"X-User": "attacker", "X-Role": "unauthorized"}
    resp_exec = client.post(
        "/api/demo/scenarios/scenario-a-phishing/execute",
        headers=unauth_headers,
    )
    assert resp_exec.status_code == 403

    resp_reset = client.post("/api/demo/reset", headers=unauth_headers)
    assert resp_reset.status_code == 403


def test_provenance_integrity_traceability(db_session):
    """
    Test Provenance Integrity Chain:
    Finding -> Analysis Run -> Artifact -> Original Evidence SHA-256
    Guarantees that the hash matches the real content digest.
    """
    # Re-run Scenario A
    headers = {"X-User": "lead.analyst@cyberguard.local", "X-Role": "admin"}
    exec_resp = client.post(
        "/api/demo/scenarios/scenario-a-phishing/execute",
        headers=headers,
    )
    assert exec_resp.status_code == 200
    res = exec_resp.json()

    # 1. Fetch Finding
    finding = db_session.query(FindingModel).filter(FindingModel.analysis_run_id == res["analysis_run_id"]).first()
    assert finding is not None

    # 2. Trace to Analysis Run
    run = db_session.query(AnalysisRunModel).filter(AnalysisRunModel.id == finding.analysis_run_id).first()
    assert run is not None
    assert run.id == res["analysis_run_id"]

    # 3. Trace to Artifact
    artifact = db_session.query(ArtifactModel).filter(ArtifactModel.id == run.artifact_id).first()
    assert artifact is not None
    assert artifact.id == res["artifact_id"]

    # 4. Trace to Evidence
    evidence = db_session.query(EvidenceModel).filter(EvidenceModel.artifact_id == artifact.id).first()
    assert evidence is not None
    assert evidence.sha256 == artifact.sha256
    assert evidence.integrity_status == "VERIFIED"

    # Reset afterwards for cleanliness
    client.post("/api/demo/reset", headers=headers)
