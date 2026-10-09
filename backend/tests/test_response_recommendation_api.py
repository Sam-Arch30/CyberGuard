"""
API integration tests for Section 28: Response Recommendation Engine.
Tests all endpoints mounted under /api/v1/recommendations using standard SessionLocal.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ThreatEventModel,
    RiskAssessmentModel,
    ExplanationModel,
    ResponseRecommendationModel,
    generate_uuid,
    get_utc_now
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def seeded_event():
    with SessionLocal() as db:
        event_id = f"EVT-API-{generate_uuid()[:8]}"
        meta = {
            "sender": "spoof@attacker-auth.com",
            "sender_domain": "attacker-auth.com",
            "recipient": "finance_mgr@corp.com",
            "urls": ["https://attacker-auth.com/portal/login"],
            "domains": ["attacker-auth.com"],
            "hostname": "WORKSTATION-FIN-01"
        }
        event = ThreatEventModel(
            id=event_id,
            event_type="EMAIL_RECEIVED",
            severity="CRITICAL",
            status="PROCESSED",
            summary="Phishing attempt detected with lookalike domain.",
            source_artifact_id="MSG-API-01",
            analysis_run_id="RUN-API-01",
            metadata_json=json.dumps(meta),
            created_at=get_utc_now()
        )
        db.add(event)

        ra = RiskAssessmentModel(
            id=f"RA-{event_id}",
            workspace_id="default",
            scope_type="EVENT",
            scope_id=event_id,
            version=1,
            risk_score=91.0,
            risk_level="CRITICAL",
            severity="CRITICAL",
            confidence=0.94,
            confidence_level="VERY_HIGH",
            uncertainty_score=0.06,
            uncertainty="LOW",
            signals_json=json.dumps([{"category": "EMAIL", "evidence_refs": ["EV-01"]}]),
            evidence_refs_json=json.dumps(["EV-01", "EV-02"])
        )
        db.add(ra)

        expl = ExplanationModel(
            id=f"EX-{event_id}",
            workspace_id="default",
            scope_type="EVENT",
            scope_id=event_id,
            explanation_version=1,
            risk_assessment_id=ra.id,
            summary="Grounded phishing attack explanation.",
            explanation_units_json=json.dumps([
                {"id": "U-1", "claim": "Lookalike domain impersonation", "claim_type": "URL", "evidence_refs": ["EV-01"]}
            ])
        )
        db.add(expl)
        db.commit()
        return event_id


def test_api_get_recommendations_by_scope(client, seeded_event):
    """GET /api/v1/recommendations/by-scope/{scope_type}/{scope_id} auto-generates recommendations."""
    res = client.get(f"/api/v1/recommendations/by-scope/EVENT/{seeded_event}")
    assert res.status_code == 200
    data = res.json()
    assert len(data) > 0
    actions = [r["action_type"] for r in data]
    assert "PRESERVE_EMAIL" in actions
    assert "BLOCK_DOMAIN" in actions


def test_api_generate_recommendations_force(client, seeded_event):
    """POST /api/v1/recommendations/generate with force_regenerate replaces prior recommendations."""
    res = client.post("/api/v1/recommendations/generate", json={
        "scope_type": "EVENT",
        "scope_id": seeded_event,
        "workspace_id": "default",
        "force_regenerate": True
    })
    assert res.status_code == 200
    data = res.json()
    assert len(data) > 0


def test_api_get_recommendation_by_id(client, seeded_event):
    """GET /api/v1/recommendations/{id} returns single recommendation."""
    res = client.get(f"/api/v1/recommendations/by-scope/EVENT/{seeded_event}")
    first_id = res.json()[0]["id"]

    res_single = client.get(f"/api/v1/recommendations/{first_id}")
    assert res_single.status_code == 200
    assert res_single.json()["id"] == first_id


def test_api_approve_recommendation(client, seeded_event):
    """POST /api/v1/recommendations/{id}/approve marks recommendation APPROVED."""
    res = client.get(f"/api/v1/recommendations/by-scope/EVENT/{seeded_event}")
    block_rec = next(r for r in res.json() if r["action_type"] == "BLOCK_DOMAIN")

    appr_res = client.post(
        f"/api/v1/recommendations/{block_rec['id']}/approve",
        json={
            "reviewer_id": "analyst_sarah",
            "disposition": "APPROVED",
            "notes": "Domain matches active typo-squatting campaign; authorized."
        }
    )
    assert appr_res.status_code == 200
    data = appr_res.json()
    assert data["status"] == "APPROVED"
    assert data["reviewed_by"] == "analyst_sarah"


def test_api_reject_recommendation(client, seeded_event):
    """POST /api/v1/recommendations/{id}/reject marks recommendation REJECTED."""
    res = client.get(f"/api/v1/recommendations/by-scope/EVENT/{seeded_event}")
    block_rec = next(r for r in res.json() if r["action_type"] == "BLOCK_DOMAIN")

    rej_res = client.post(
        f"/api/v1/recommendations/{block_rec['id']}/reject",
        json={
            "reviewer_id": "analyst_sarah",
            "disposition": "REJECTED",
            "notes": "False positive domain; internal simulation."
        }
    )
    assert rej_res.status_code == 200
    assert rej_res.json()["status"] == "REJECTED"


def test_api_defer_recommendation(client, seeded_event):
    """POST /api/v1/recommendations/{id}/defer marks recommendation DEFERRED."""
    res = client.get(f"/api/v1/recommendations/by-scope/EVENT/{seeded_event}")
    first_id = res.json()[0]["id"]

    def_res = client.post(
        f"/api/v1/recommendations/{first_id}/defer",
        json={
            "reviewer_id": "analyst_mark",
            "disposition": "DEFERRED",
            "notes": "Deferring action until reverse engineering completes."
        }
    )
    assert def_res.status_code == 200
    assert def_res.json()["status"] == "DEFERRED"


def test_api_list_capabilities(client):
    """GET /api/v1/recommendations/capabilities returns registered capabilities."""
    res = client.get("/api/v1/recommendations/capabilities")
    assert res.status_code == 200
    caps = res.json()
    assert len(caps) > 0
    actions = [c["action_type"] for c in caps]
    assert "BLOCK_DOMAIN" in actions
    assert "ISOLATE_DEVICE" in actions


def test_api_register_capability(client):
    """POST /api/v1/recommendations/capabilities updates capability state."""
    res = client.post(
        "/api/v1/recommendations/capabilities",
        json={
            "action_type": "ISOLATE_DEVICE",
            "provider": "CrowdStrike Falcon Connector",
            "environment": "PRODUCTION",
            "enabled": True,
            "reversible": True,
            "approval_required": True,
            "capability_state": "AVAILABLE",
            "state_reason": "Live API integration connected and verified."
        }
    )
    assert res.status_code == 200
    data = res.json()
    assert data["capability_state"] == "AVAILABLE"
    assert data["provider"] == "CrowdStrike Falcon Connector"


def test_api_get_summary(client, seeded_event):
    """GET /api/v1/recommendations/summary/{scope_type}/{scope_id} returns workspace metrics."""
    res = client.get(f"/api/v1/recommendations/summary/EVENT/{seeded_event}")
    assert res.status_code == 200
    data = res.json()
    assert "total_count" in data
    assert "by_priority" in data
    assert "by_category" in data
    assert "pending_approval_count" in data
    assert data["total_count"] > 0
