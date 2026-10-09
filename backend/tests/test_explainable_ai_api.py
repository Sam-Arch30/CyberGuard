"""
REST API Contract Tests for Section 27: Explainable AI (XAI).

Tests:
1. GET /api/v1/explanation/{scope_type}/{scope_id}
2. Progressive disclosure layers: GET /api/v1/explanation/{scope_type}/{scope_id}/layers/{layer}
3. Evidence graph retrieval: GET /api/v1/explanation/{scope_type}/{scope_id}/graph
4. Evidence chain retrieval: GET /api/v1/explanation/{scope_type}/{scope_id}/evidence-chain
5. Contributors and attribution: GET /api/v1/explanation/{scope_type}/{scope_id}/contributors
6. Counter-evidence and contradictions: GET /api/v1/explanation/{scope_type}/{scope_id}/contradictions
7. Uncertainty and what-would-change: GET /api/v1/explanation/{scope_type}/{scope_id}/uncertainty
8. Explainability quality metrics: GET /api/v1/explanation/{scope_type}/{scope_id}/metrics
9. Analyst feedback submission: POST /api/v1/explanation/{scope_type}/{scope_id}/feedback
10. Grounded narrative generation: POST /api/v1/explanation/{scope_type}/{scope_id}/generate-narrative
11. Historical snapshots: GET & POST /api/v1/explanation/{scope_type}/{scope_id}/snapshots
"""
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    AttackTechniqueMappingModel,
    FindingEvidenceModel,
    FindingModel,
    RiskAssessmentModel,
    ThreatEventModel,
    generate_uuid,
    get_utc_now,
)
from backend.services.risk_engine_service import RiskEngineService


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seeded_event():
    with SessionLocal() as db:
        event_id = generate_uuid()
        artifact_id = generate_uuid()
        run_id = generate_uuid()
        now = get_utc_now()

        artifact = ArtifactModel(
            id=artifact_id,
            artifact_type="EMAIL",
            name="api_test.eml",
            created_at=now,
        )
        db.add(artifact)

        run = AnalysisRunModel(
            id=run_id,
            artifact_id=artifact_id,
            status="COMPLETED",
            overall_risk_score=78.0,
            overall_severity="HIGH",
            confidence=0.88,
            created_at=now,
        )
        db.add(run)

        event = ThreatEventModel(
            id=event_id,
            event_type="credential_harvesting",
            source_artifact_id=artifact_id,
            analysis_run_id=run_id,
            risk_score=78.0,
            severity="HIGH",
            confidence=0.88,
            summary="Targeted credential harvesting attack observed via API route test.",
            metadata_json=json.dumps({"domain": "login-verify-account.com"}),
            created_at=now,
            updated_at=now,
        )
        db.add(event)

        finding = FindingModel(
            id=generate_uuid(),
            analysis_run_id=run_id,
            analyzer="url_analyzer",
            finding_type="CREDENTIAL_FORM",
            title="Credential Form Harvest",
            description="Hosted login form submitting passwords to unauthorized endpoint.",
            severity="HIGH",
            confidence=0.90,
            method="RULE",
            created_at=now,
        )
        db.add(finding)
        db.flush()

        finding_ev = FindingEvidenceModel(
            id=generate_uuid(),
            finding_id=finding.id,
            evidence_type="URL",
            source="url_analyzer",
            key="url",
            value="https://login-verify-account.com/submit",
            confidence=0.95,
            created_at=now,
        )
        db.add(finding_ev)

        db.commit()

        # Evaluate risk assessment
        RiskEngineService.evaluate_threat_event(
            db=db,
            threat_event_id=event_id,
            workspace_id="test_ws",
        )

        return event_id


class TestExplainableAIAPI:
    """REST API test suite for Explainable AI."""

    def test_get_full_explanation(self, client: TestClient, seeded_event: str):
        response = client.get(f"/api/v1/explanation/EVENT/{seeded_event}?workspace_id=test_ws")
        assert response.status_code == 200
        data = response.json()
        assert data["scope_id"] == seeded_event
        assert data["scope_type"] == "EVENT"
        assert "risk_score" in data
        assert data["risk_score"] > 0.0
        assert "summary" in data
        assert "explanation_units" in data
        assert len(data["explanation_units"]) > 0

    def test_progressive_disclosure_layers(self, client: TestClient, seeded_event: str):
        # 1. Executive
        r_exec = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/layers/EXECUTIVE?workspace_id=test_ws")
        assert r_exec.status_code == 200
        d_exec = r_exec.json()
        assert d_exec["layer"] == "EXECUTIVE"
        assert "summary" in d_exec
        assert "top_reasons" in d_exec

        # 2. Analyst
        r_analyst = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/layers/ANALYST?workspace_id=test_ws")
        assert r_analyst.status_code == 200
        d_analyst = r_analyst.json()
        assert d_analyst["layer"] == "ANALYST"
        assert "contributors" in d_analyst
        assert "assessment_change_guidance" in d_analyst

        # 3. Investigator
        r_inv = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/layers/INVESTIGATOR?workspace_id=test_ws")
        assert r_inv.status_code == 200
        d_inv = r_inv.json()
        assert d_inv["layer"] == "INVESTIGATOR"
        assert "explanation_units" in d_inv
        assert "mitre_explanations" in d_inv

        # 4. Forensic
        r_for = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/layers/FORENSIC?workspace_id=test_ws")
        assert r_for.status_code == 200
        d_for = r_for.json()
        assert d_for["layer"] == "FORENSIC"
        assert "evidence_graph" in d_for

    def test_evidence_graph_endpoint(self, client: TestClient, seeded_event: str):
        response = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/graph?workspace_id=test_ws")
        assert response.status_code == 200
        data = response.json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) > 0
        assert len(data["edges"]) > 0

    def test_evidence_chain_endpoint(self, client: TestClient, seeded_event: str):
        response = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/evidence-chain?workspace_id=test_ws")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert "claim" in data[0]
        assert "evidence_refs" in data[0]

    def test_contributors_endpoint(self, client: TestClient, seeded_event: str):
        response = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/contributors?workspace_id=test_ws")
        assert response.status_code == 200
        data = response.json()
        assert "contributors" in data
        assert "detectors" in data
        assert "rules" in data

    def test_contradictions_and_counter_evidence_endpoint(self, client: TestClient, seeded_event: str):
        response = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/contradictions?workspace_id=test_ws")
        assert response.status_code == 200
        data = response.json()
        assert "counter_evidence" in data
        assert "contradictions" in data

    def test_uncertainty_and_change_guidance_endpoint(self, client: TestClient, seeded_event: str):
        response = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/uncertainty?workspace_id=test_ws")
        assert response.status_code == 200
        data = response.json()
        assert "uncertainty_level" in data
        assert "what_would_change" in data
        assert "what_would_strengthen" in data["what_would_change"]
        assert "what_would_weaken" in data["what_would_change"]

    def test_quality_metrics_endpoint(self, client: TestClient, seeded_event: str):
        response = client.get(f"/api/v1/explanation/EVENT/{seeded_event}/metrics?workspace_id=test_ws")
        assert response.status_code == 200
        data = response.json()
        assert "claim_grounding_rate" in data
        assert data["claim_grounding_rate"] > 0.0

    def test_analyst_feedback_endpoint(self, client: TestClient, seeded_event: str):
        feedback_payload = {
            "analyst_id": "soc_analyst_1",
            "feedback_type": "ANALYST_CONFIRMED",
            "target_claim_id": "CLAIM-001",
            "notes": "Verified against network egress proxy logs.",
            "correction_payload": {"verified_by": "proxy_log_id_992"},
        }
        response = client.post(
            f"/api/v1/explanation/EVENT/{seeded_event}/feedback?workspace_id=test_ws",
            json=feedback_payload,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["feedback_type"] == "ANALYST_CONFIRMED"
        assert data["analyst_id"] == "soc_analyst_1"

    def test_generate_narrative_endpoint(self, client: TestClient, seeded_event: str):
        req_payload = {
            "scope_id": seeded_event,
            "scope_type": "EVENT",
            "detail_level": "ANALYST",
            "strict_validation": True,
        }
        response = client.post(
            f"/api/v1/explanation/EVENT/{seeded_event}/generate-narrative?workspace_id=test_ws",
            json=req_payload,
        )
        assert response.status_code == 200
        data = response.json()
        assert "narrative" in data
        assert "used_fallback" in data

    def test_snapshots_endpoints(self, client: TestClient, seeded_event: str):
        # 1. Create snapshot
        create_res = client.post(
            f"/api/v1/explanation/EVENT/{seeded_event}/snapshots?workspace_id=test_ws"
        )
        assert create_res.status_code == 201
        snap_data = create_res.json()
        assert "checksum" in snap_data
        assert snap_data["explanation_version"] >= 1

        # 2. List snapshots
        list_res = client.get(
            f"/api/v1/explanation/EVENT/{seeded_event}/snapshots?workspace_id=test_ws"
        )
        assert list_res.status_code == 200
        snaps = list_res.json()
        assert isinstance(snaps, list)
        assert len(snaps) >= 1
