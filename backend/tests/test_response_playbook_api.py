"""
REST API Tests for Section 29: Response Playbooks.
Tests verify:
- Listing and creating playbooks.
- Structural validation and linter checks via API.
- Dry-run simulation plan generation.
- Conversion of recommendations into playbooks.
- Execution triggering and status reporting.
- Analyst approval endpoint.
- Execution audit retrieval.
"""

import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base, get_db
from backend.main import app
from backend.db.models import (
    ResponseCapabilityModel,
    ResponseRecommendationModel,
    generate_uuid
)
from backend.services.response_recommendation_engine import DEFAULT_CAPABILITIES


from sqlalchemy.pool import StaticPool


@pytest.fixture
def client_and_session():
    """Sets up in-memory database and FastAPI test client."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()

    # Seed default capabilities
    for cap in DEFAULT_CAPABILITIES:
        m = ResponseCapabilityModel(
            id=generate_uuid(),
            workspace_id="default",
            action_type=cap["action_type"],
            provider=cap["provider"],
            environment=cap["environment"],
            enabled=cap["enabled"],
            reversible=cap["reversible"],
            approval_required=cap["approval_required"],
            capability_state=cap["capability_state"],
            state_reason=cap["state_reason"]
        )
        session.add(m)
    session.commit()

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    yield client, session

    app.dependency_overrides.clear()
    session.close()


def test_api_list_playbooks_auto_seeds(client_and_session):
    """GET /api/v1/playbooks auto-seeds and lists default playbooks."""
    client, _ = client_and_session
    res = client.get("/api/v1/playbooks")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 3
    keys = [p["playbook_key"] for p in data]
    assert "phishing-containment" in keys


def test_api_validate_playbook(client_and_session):
    """POST /api/v1/playbooks/{id}/validate runs validation and linter."""
    client, _ = client_and_session
    res = client.get("/api/v1/playbooks")
    pb_id = res.json()[0]["id"]

    val_res = client.post(f"/api/v1/playbooks/{pb_id}/validate")
    assert val_res.status_code == 200
    val_data = val_res.json()
    assert val_data["valid"] is True
    assert "errors" in val_data


def test_api_simulate_playbook(client_and_session):
    """POST /api/v1/playbooks/{id}/simulate compiles a safe dry-run simulation plan."""
    client, _ = client_and_session
    res = client.get("/api/v1/playbooks")
    phish = next(p for p in res.json() if p["playbook_key"] == "phishing-containment")

    sim_res = client.post(
        f"/api/v1/playbooks/{phish['id']}/simulate",
        json={"target_override": {"target_type": "DOMAIN", "target_id": "simulated-malicious.org"}}
    )
    assert sim_res.status_code == 200
    plan = sim_res.json()
    assert plan["mode"] == "DRY_RUN"
    assert len(plan["steps"]) >= 4
    assert plan["approval_required_overall"] is True


def test_api_create_from_recommendation(client_and_session):
    """POST /api/v1/playbooks/from-recommendation/{id} creates a tailored playbook."""
    client, session = client_and_session

    rec = ResponseRecommendationModel(
        id="REC-API-01",
        workspace_id="default",
        scope_type="EVENT",
        scope_id="EVT-101",
        action_type="REVOKE_SESSION",
        category="CONTAINMENT",
        title="Revoke Compromised Session",
        description="Session hijacking detected.",
        rationale="Unusual login followed by privileged API abuse.",
        priority="P0",
        urgency="IMMEDIATE",
        expected_effect="Terminates active session token.",
        affected_entities_json=json.dumps([{"entity_type": "session", "identifier": "SESS-OAUTH-991"}]),
        approval_required=True,
        safety_class="CONTAINMENT",
        reversibility="REVERSIBLE",
        status="APPROVED"
    )
    session.add(rec)
    session.commit()

    res = client.post("/api/v1/playbooks/from-recommendation/REC-API-01")
    assert res.status_code == 200
    pb_data = res.json()
    assert pb_data["source_recommendation_id"] == "REC-API-01"
    assert len(pb_data["steps"]) == 3


def test_api_execute_and_approve_playbook(client_and_session):
    """Tests execution creation, approval gating, and audit trail retrieval."""
    client, _ = client_and_session
    res = client.get("/api/v1/playbooks")
    phish = next(p for p in res.json() if p["playbook_key"] == "phishing-containment")

    # 1. Execute in LIVE mode (pauses on approval requirement)
    exec_res = client.post(
        f"/api/v1/playbooks/{phish['id']}/execute",
        json={
            "mode": "LIVE",
            "requested_by": "analyst_api",
            "target_override": {"target_type": "DOMAIN", "target_id": "c2-domain.com"}
        }
    )
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    exec_id = exec_data["id"]
    assert exec_data["status"] == "WAITING_FOR_APPROVAL"

    # 2. Approve execution
    appr_res = client.post(
        f"/api/v1/playbooks/executions/{exec_id}/approve",
        json={
            "decision": "APPROVED",
            "approved_by": "lead_analyst",
            "reason": "Authorized after triage review."
        }
    )
    assert appr_res.status_code == 200
    appr_data = appr_res.json()
    assert appr_data["decision"] == "APPROVED"

    # 3. Fetch execution audit trail
    audit_res = client.get(f"/api/v1/playbooks/executions/{exec_id}/audit")
    assert audit_res.status_code == 200
    audit_events = audit_res.json()
    assert len(audit_events) >= 1
    assert any(a["action"] == "EXECUTION_STARTED" for a in audit_events)
