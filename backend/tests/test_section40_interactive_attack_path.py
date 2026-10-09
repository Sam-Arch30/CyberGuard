"""
Unit and integration tests for Section 40: Interactive Attack Path.
Verifies path projection endpoint, truthful empty states, stage order,
causal vs temporal transitions, gaps, contradictions, alternatives,
and multiple analysis runs.
"""
import json
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from backend.db.session import SessionLocal, get_db
from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    AttackEdgeModel,
    AttackHypothesisModel,
    AttackPathModel,
    AttackStageModel,
    AttackTechniqueMappingModel,
    EntityModel,
    FindingModel,
    IncidentModel,
    InfrastructureAttributionModel,
    get_utc_now,
)
from backend.main import app


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


def test_attack_path_404_for_unknown_investigation(client):
    """Unknown investigation returns 404."""
    resp = client.get("/api/investigations/unknown-nonexistent-id/attack-path")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


def test_attack_path_truthful_inconclusive_state(client, db_session):
    """When an incident exists without correlated telemetry, return truthful inconclusive state."""
    inc = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number="INV-2026-EMPTY1",
        title="Empty Test Incident",
        description="Incident without events",
        status="OPEN",
        severity="LOW",
        risk_score=10.0,
    )
    db_session.add(inc)
    db_session.commit()

    resp = client.get(f"/api/investigations/{inc.id}/attack-path")
    assert resp.status_code == 200
    data = resp.json()

    assert data["investigation_id"] == inc.id
    assert data["incident_number"] == inc.incident_number
    assert data["has_path"] is False
    assert data["status"] == "INCONCLUSIVE"
    assert len(data["stages"]) == 0
    assert len(data["transitions"]) == 0
    assert data["confidence"] == 0.0
    assert len(data["limitations"]) > 0


def test_attack_path_reconstructed_full_projection(client, db_session):
    """
    Tests complete reconstructed path with stages, transitions, causal/temporal
    classification, gaps, contradictions, alternatives, MITRE, and infrastructure.
    """
    now = datetime(2026, 10, 9, 14, 30, 0, tzinfo=timezone.utc)

    # 1. Artifact & Run
    art = ArtifactModel(
        id=str(uuid.uuid4()),
        name="spearphish_email.eml",
        artifact_type="EMAIL",
        sha256="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        size=1024,
        mime_type="message/rfc822",
        source="GATEWAY",
    )
    db_session.add(art)
    db_session.flush()

    run = AnalysisRunModel(
        id=str(uuid.uuid4()),
        artifact_id=art.id,
        pipeline_version="2.0.0",
        status="COMPLETED",
        overall_severity="HIGH",
        overall_risk_score=88.0,
        confidence=0.92,
        started_at=now,
        completed_at=now + timedelta(seconds=15),
    )
    db_session.add(run)

    # 2. Incident
    inc = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number="INV-2026-SEC40A",
        title="Spearphishing with Credential Harvesting",
        description="Observed targeted lure",
        status="INVESTIGATING",
        severity="HIGH",
        risk_score=88.0,
    )
    db_session.add(inc)
    db_session.flush()

    # 3. Entity & Finding
    ent = EntityModel(
        id=str(uuid.uuid4()),
        entity_type="DOMAIN",
        name="secure-portal-auth.com",
        canonical_key="domain:secure-portal-auth.com",
        attributes_json=json.dumps({"risk_score": 92.0}),
    )
    db_session.add(ent)
    db_session.flush()

    finding = FindingModel(
        id=str(uuid.uuid4()),
        analysis_run_id=run.id,
        finding_type="LOOKALIKE_DOMAIN",
        title="Impersonation Domain Detected",
        description="Domain impersonates corporate SSO portal.",
        severity="HIGH",
        method="HEURISTIC",
        analyzer="DomainIntelligenceEngine",
        confidence=0.95,
    )
    db_session.add(finding)
    db_session.flush()

    # 4. AttackPathModel
    path = AttackPathModel(
        id=str(uuid.uuid4()),
        incident_id=inc.id,
        name="Spearphishing to Credential Harvest",
        classification="STRONG_RECONSTRUCTION",
        confidence=0.91,
        confidence_level="HIGH",
        status="CURRENT",
        start_time=now,
        end_time=now + timedelta(minutes=15),
        version=1,
        engine_version="1.0.0",
        rule_version="1.0.0",
        evidence_gaps_json=json.dumps(["NO_PROCESS_TELEMETRY"]),
        contradicting_evidence_json=json.dumps([{
            "title": "Legitimate Source Subnet",
            "description": "Source IP belongs to regular corporate egress subnet.",
            "impact": "Reduces confidence in external threat hypothesis."
        }]),
        metadata_json=json.dumps({"completeness_score": 0.90, "confidence_level": "HIGH"}),
    )
    db_session.add(path)
    db_session.flush()

    # 5. Stages
    s1 = AttackStageModel(
        id=str(uuid.uuid4()),
        attack_path_id=path.id,
        stage_order=1,
        stage_type="DELIVERY",
        stage_status="OBSERVED",
        technique_id="T1566.002",
        tactic="Initial Access",
        name="Phishing Email Delivered",
        description="Target received email lure with malicious redirect.",
        start_time=now,
        end_time=now,
        confidence=0.95,
        confidence_level="HIGH",
        entity_ids_json=json.dumps([ent.id]),
        finding_ids_json=json.dumps([finding.id]),
        supporting_evidence_json=json.dumps([{"source": "email_header", "spf": "FAIL"}]),
    )
    s2 = AttackStageModel(
        id=str(uuid.uuid4()),
        attack_path_id=path.id,
        stage_order=2,
        stage_type="CREDENTIAL_ACTIVITY",
        stage_status="INFERRED",
        technique_id="T1556",
        tactic="Credential Access",
        name="Credential Harvest Portal",
        description="Victim redirected to fake single sign-on portal.",
        start_time=now + timedelta(minutes=2),
        end_time=now + timedelta(minutes=2),
        confidence=0.82,
        confidence_level="HIGH",
        entity_ids_json=json.dumps([ent.id]),
        finding_ids_json=json.dumps([finding.id]),
        supporting_evidence_json=json.dumps([{"source": "url_scan", "form_action": "post"}]),
    )
    db_session.add_all([s1, s2])
    db_session.flush()

    # 6. Edge (Temporal link, not causal)
    edge = AttackEdgeModel(
        id=str(uuid.uuid4()),
        attack_path_id=path.id,
        source_stage_id=s1.id,
        target_stage_id=s2.id,
        relationship_type="TEMPORAL_LINK",
        edge_status="DERIVED",
        temporal_gap_seconds=120.0,
        shared_entities_json=json.dumps([ent.id]),
        confidence=0.88,
        confidence_level="HIGH",
    )
    db_session.add(edge)

    # 7. Hypothesis (Alternative)
    hyp = AttackHypothesisModel(
        id=str(uuid.uuid4()),
        incident_id=inc.id,
        attack_path_id=path.id,
        title="Accidental Misconfiguration Lure",
        description="Internal test campaign rather than external adversary.",
        status="PLAUSIBLE",
        is_primary=False,
        stage_ids_json=json.dumps([s1.id]),
        confidence=0.35,
        confidence_level="LOW",
        missing_evidence_json=json.dumps(["NO_EXTERNAL_C2_TRAFFIC"]),
    )
    db_session.add(hyp)

    # 8. MITRE Technique Mapping
    mitre = AttackTechniqueMappingModel(
        id=str(uuid.uuid4()),
        incident_id=inc.id,
        attack_path_id=path.id,
        source_type="ATTACK_STAGE",
        source_id=s1.id,
        technique_id="T1566.002",
        technique_name="Spearphishing Link",
        tactic_names_json=json.dumps(["Initial Access"]),
        status="SUPPORTED",
        confidence=0.95,
        confidence_level="HIGH",
        explanation="Deceptive email lure containing credential solicitation URL.",
    )
    db_session.add(mitre)

    # 9. Infrastructure Attribution
    infra = InfrastructureAttributionModel(
        id=str(uuid.uuid4()),
        incident_id=inc.id,
        origin_value="198.51.100.42",
        origin_type="IP_ADDRESS",
        hypothesis_title="Dedicated Phishing Redirector",
        hypothesis_type="DEDICATED_THREAT_INFRASTRUCTURE",
        status="PROBABLE",
        confidence_level="HIGH",
        confidence_score=0.89,
        evidence_count=3,
        limitations_json=json.dumps([
            "Identifies technical network infrastructure; does not establish physical attacker identity."
        ]),
    )
    db_session.add(infra)
    db_session.commit()

    # Query endpoint
    resp = client.get(f"/api/investigations/{inc.id}/attack-path")
    assert resp.status_code == 200
    data = resp.json()

    assert data["has_path"] is True
    assert data["path_id"] == path.id
    assert data["confidence"] == 0.91
    assert data["confidence_level"] == "HIGH"
    assert data["status"] in ("ESTABLISHED", "PARTIAL", "SUPPORTED_HYPOTHESIS")
    assert len(data["stages"]) == 2

    # Verify stage 1
    st1 = data["stages"][0]
    assert st1["stage_order"] == 1
    assert st1["stage_status"] == "OBSERVED"
    assert st1["title"] == "Phishing Email Delivered"
    assert st1["technique_id"] == "T1566.002"
    assert len(st1["entities_detail"]) == 1
    assert st1["entities_detail"][0]["value"] == "secure-portal-auth.com"

    # Verify stage 2
    st2 = data["stages"][1]
    assert st2["stage_order"] == 2
    assert st2["stage_status"] == "INFERRED"
    assert st2["time_uncertainty"] == "±30s"

    # Verify transition (temporal, not causal)
    assert len(data["transitions"]) == 1
    tr = data["transitions"][0]
    assert tr["from_stage_id"] == s1.id
    assert tr["to_stage_id"] == s2.id
    assert tr["is_causal"] is False
    assert tr["relationship_label"] == "TEMPORAL ASSOCIATION"
    assert "2m" in tr["temporal_gap_formatted"]

    # Verify gaps
    assert len(data["gaps"]) == 1
    assert data["gaps"][0]["category"] == "MISSING_ENDPOINT_TELEMETRY"

    # Verify contradictions
    assert len(data["contradictions"]) == 1
    assert "Legitimate Source Subnet" in data["contradictions"][0]["title"]

    # Verify alternatives
    assert len(data["alternatives"]) == 1
    assert data["alternatives"][0]["title"] == "Accidental Misconfiguration Lure"
    assert data["alternatives"][0]["is_primary"] is False

    # Verify MITRE
    assert len(data["mitre_techniques"]) >= 1
    assert any(m["technique_id"] == "T1566.002" for m in data["mitre_techniques"])

    # Verify Infrastructure (never implies human identity)
    assert len(data["infrastructure"]) == 1
    inf_proj = data["infrastructure"][0]
    assert inf_proj["origin_value"] == "198.51.100.42"
    assert "human" in inf_proj["limitations"][0].lower() or "physical" in inf_proj["limitations"][0].lower()


def test_attack_path_run_selection(client, db_session):
    """Verifies available runs listing and run_id query parameter behavior."""
    now = datetime(2026, 10, 9, 14, 0, 0, tzinfo=timezone.utc)
    art = ArtifactModel(
        id=str(uuid.uuid4()),
        name="test_artifact.eml",
        artifact_type="EMAIL",
        sha256="1234567890123456789012345678901234567890123456789012345678901234",
    )
    db_session.add(art)
    db_session.flush()

    run1 = AnalysisRunModel(
        id=str(uuid.uuid4()),
        artifact_id=art.id,
        pipeline_version="1.0.0",
        status="COMPLETED",
        overall_severity="LOW",
        overall_risk_score=20.0,
        started_at=now,
    )
    run2 = AnalysisRunModel(
        id=str(uuid.uuid4()),
        artifact_id=art.id,
        pipeline_version="2.0.0",
        status="COMPLETED",
        overall_severity="HIGH",
        overall_risk_score=85.0,
        started_at=now + timedelta(hours=1),
    )
    db_session.add_all([run1, run2])

    inc = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number="INV-2026-MULTI-RUN",
        title="Multi-Run Incident",
        status="OPEN",
        severity="HIGH",
    )
    db_session.add(inc)
    db_session.commit()

    resp = client.get(f"/api/investigations/{inc.id}/attack-path?run_id={run1.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis_run_id"] == run1.id
