"""
REST API Integration Tests for Section 30: LLM SOC Copilot.
Tests all endpoints mounted under /api/v1/copilot using FastAPI TestClient with StaticPool in-memory SQLite.
"""

import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.session import Base, get_db
from backend.main import app
from backend.db.models import (
    IncidentModel,
    RiskAssessmentModel,
    ExplanationModel,
    EvidenceModel,
    FindingModel,
    generate_uuid,
    get_utc_now
)


@pytest.fixture
def client_and_db():
    """Sets up an in-memory SQLite database and FastAPI test client with StaticPool."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    session = TestingSession()

    # Seed test incident
    inc_id = "INC-API-30"
    inc = IncidentModel(
        id=inc_id,
        incident_number="INC-API-30",
        workspace_id="default",
        title="API Test Phishing Incident",
        severity="HIGH",
        risk_score=88.0,
        confidence=0.95,
        opened_at=get_utc_now()
    )
    session.add(inc)

    ra = RiskAssessmentModel(
        id=f"RA-{inc_id}",
        workspace_id="default",
        scope_type="INCIDENT",
        scope_id=inc_id,
        version=1,
        risk_score=88.0,
        risk_level="HIGH",
        severity="HIGH",
        confidence=0.95,
        confidence_level="HIGH",
        uncertainty_score=0.05,
        signals_json=json.dumps([{"category": "LOOKALIKE", "weight": 0.8}]),
        evidence_refs_json=json.dumps(["EV-API-01"])
    )
    session.add(ra)

    expl = ExplanationModel(
        id=f"EX-{inc_id}",
        workspace_id="default",
        scope_type="INCIDENT",
        scope_id=inc_id,
        explanation_version=1,
        summary="Deceptive lookalike domain targeting corporate login portal.",
        explanation_units_json=json.dumps([{"claim": "Lookalike domain login lure", "evidence_refs": ["EV-API-01"]}])
    )
    session.add(expl)

    ev = EvidenceModel(
        id=generate_uuid(),
        evidence_id="EV-API-01",
        original_filename="phish_lure.eml",
        sha256="deadbeef12345678",
        upload_timestamp=get_utc_now(),
        size=2048,
        uploader="analyst_test"
    )
    session.add(ev)
    session.commit()

    def override_get_db():
        db = TestingSession()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    yield client, session, inc_id

    app.dependency_overrides.clear()
    session.close()


def test_api_conversation_lifecycle(client_and_db):
    """Tests creating, listing, and getting conversations."""
    client, _, inc_id = client_and_db

    # 1. Create conversation
    res = client.post("/api/v1/copilot/conversations", json={
        "title": "Investigation Dialogue 1",
        "investigation_id": inc_id,
        "workspace_id": "default"
    })
    assert res.status_code == 201
    conv = res.json()
    assert conv["title"] == "Investigation Dialogue 1"
    conv_id = conv["id"]

    # 2. List conversations
    list_res = client.get("/api/v1/copilot/conversations?workspace_id=default")
    assert list_res.status_code == 200
    convs = list_res.json()
    assert len(convs) >= 1
    assert any(c["id"] == conv_id for c in convs)

    # 3. Get single conversation
    get_res = client.get(f"/api/v1/copilot/conversations/{conv_id}?workspace_id=default")
    assert get_res.status_code == 200
    assert get_res.json()["id"] == conv_id


def test_api_post_message_and_grounded_answer(client_and_db):
    """Tests posting a question to a conversation and receiving a structured answer."""
    client, _, inc_id = client_and_db

    # Create conversation
    res = client.post("/api/v1/copilot/conversations", json={
        "title": "Risk Analysis Dialogue",
        "investigation_id": inc_id
    })
    conv_id = res.json()["id"]

    # Post message
    msg_res = client.post(
        f"/api/v1/copilot/conversations/{conv_id}/messages?workspace_id=default",
        json={
            "content": "Why is this incident classified as HIGH risk?",
            "mode": "ANALYST",
            "target_scope_id": inc_id
        }
    )
    assert msg_res.status_code == 200
    answer = msg_res.json()
    assert answer["role"] == "ASSISTANT"
    assert answer["conversation_id"] == conv_id
    assert "content" in answer
    assert "Score: **88.0/100**" in answer["content"] or "88" in answer["content"]

    # List messages
    msgs_res = client.get(f"/api/v1/copilot/conversations/{conv_id}/messages?workspace_id=default")
    assert msgs_res.status_code == 200
    messages = msgs_res.json()
    assert len(messages) >= 2  # user + assistant


def test_api_standalone_query(client_and_db):
    """Tests POST /api/v1/copilot/query which auto-provisions a conversation."""
    client, _, inc_id = client_and_db

    res = client.post("/api/v1/copilot/query", json={
        "query": "What happened in this incident?",
        "mode": "ANALYST",
        "workspace_id": "default",
        "investigation_id": inc_id
    })
    assert res.status_code == 200
    answer = res.json()
    assert answer["role"] == "ASSISTANT"
    assert answer["conversation_id"] is not None


def test_api_inspect_context(client_and_db):
    """Tests GET /api/v1/copilot/context/{investigation_id}."""
    client, _, inc_id = client_and_db

    res = client.get(f"/api/v1/copilot/context/{inc_id}?workspace_id=default&intent=RISK_EXPLANATION")
    assert res.status_code == 200
    ctx = res.json()
    assert ctx["intent"] == "RISK_EXPLANATION"
    assert ctx["risk_assessment"]["risk_score"] == 88.0


def test_api_feedback_submission(client_and_db):
    """Tests submitting analyst feedback on a Copilot message."""
    client, _, inc_id = client_and_db

    # Ask query to produce assistant message
    res = client.post("/api/v1/copilot/query", json={
        "query": "Summarize this incident",
        "investigation_id": inc_id
    })
    msg_id = res.json()["id"]

    # Submit feedback
    fb_res = client.post(f"/api/v1/copilot/messages/{msg_id}/feedback", json={
        "rating": "HELPFUL",
        "feedback_text": "Clear evidence grounding.",
        "analyst_id": "lead_soc_analyst"
    })
    assert fb_res.status_code == 200
    fb_data = fb_res.json()
    assert fb_data["rating"] == "HELPFUL"
    assert fb_data["message_id"] == msg_id
