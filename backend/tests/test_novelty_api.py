"""
REST API Route Integration Tests for Novelty & Emerging-Threat Detection (Section 22).

Tests endpoints for evaluation, investigation summaries, pattern / sequence / infrastructure
breakdowns, entity queries, emerging pattern lifecycle status transitions, and suppressions.
"""
import pytest
from datetime import datetime, timezone, timedelta
import json
import uuid
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import IncidentModel


@pytest.fixture
def client_and_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSessionLocal = sessionmaker(bind=engine)
    session = TestingSessionLocal()

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    yield client, session
    app.dependency_overrides.clear()
    session.close()


def test_api_01_evaluate_novelty(client_and_session):
    client, session = client_and_session

    inc = IncidentModel(
        id=str(uuid.uuid4()),
        incident_number="INC-2026-901",
        workspace_id="default",
        title="Test Incident for Novelty",
    )
    session.add(inc)
    session.commit()

    payload = {
        "workspace_id": "default",
        "incident_id": inc.id,
        "entity_type": "SERVICE",
        "entity_id": "payment-api",
        "novelty_type": "NOVEL_API_BEHAVIOR",
        "attributes": {
            "method": "POST",
            "path": "/api/v1/payments/refund_batch",
            "is_privileged": True,
        },
        "is_entity_anomalous": True,
    }

    res = client.post("/api/v1/novelty/evaluate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "assessment" in data
    assert data["assessment"]["novelty_level"] in ("HIGH", "VERY_HIGH")
    assert data["assessment"]["behavior_familiarity_matrix"] == "UNUSUAL_NOVEL"
    assert data["assessment"]["novelty_score"] >= 0.70


def test_api_02_investigation_novelty_summary(client_and_session):
    client, session = client_and_session
    inc_id = str(uuid.uuid4())

    inc = IncidentModel(
        id=inc_id,
        incident_number="INC-2026-902",
        workspace_id="default",
        title="Novelty Investigation Test",
    )
    session.add(inc)
    session.commit()

    # Evaluate an event for this incident
    payload = {
        "workspace_id": "default",
        "incident_id": inc_id,
        "entity_type": "DOMAIN",
        "entity_id": "suspicious-relay.com",
        "novelty_type": "NOVEL_DOMAIN_PATTERN",
        "attributes": {"domain": "suspicious-relay.com", "is_ip": False},
    }
    client.post("/api/v1/novelty/evaluate", json=payload)

    # Query investigation novelty summary
    res = client.get(f"/api/v1/investigations/{inc_id}/novelty")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == inc_id
    assert data["total_assessments"] >= 1
    assert data["novel_assessments_count"] >= 1


def test_api_03_investigation_sub_endpoints(client_and_session):
    client, session = client_and_session
    inc_id = str(uuid.uuid4())

    inc = IncidentModel(
        id=inc_id,
        incident_number="INC-2026-903",
        workspace_id="default",
        title="Sub Endpoints Test",
    )
    session.add(inc)
    session.commit()

    # Seed API pattern
    client.post("/api/v1/novelty/evaluate", json={
        "workspace_id": "default",
        "incident_id": inc_id,
        "entity_type": "SERVICE",
        "entity_id": "api1",
        "novelty_type": "NOVEL_API_BEHAVIOR",
        "attributes": {"method": "GET", "path": "/api/users"},
    })

    # Seed Network pattern
    client.post("/api/v1/novelty/evaluate", json={
        "workspace_id": "default",
        "incident_id": inc_id,
        "entity_type": "DEVICE",
        "entity_id": "dev1",
        "novelty_type": "NOVEL_NETWORK_BEHAVIOR",
        "attributes": {"port": 8443, "destination_category": "EXTERNAL"},
    })

    # Test patterns endpoint
    patterns_res = client.get(f"/api/v1/investigations/{inc_id}/novelty/patterns")
    assert patterns_res.status_code == 200
    assert len(patterns_res.json()) >= 1

    # Test infrastructure endpoint
    infra_res = client.get(f"/api/v1/investigations/{inc_id}/novelty/infrastructure")
    assert infra_res.status_code == 200
    assert len(infra_res.json()) >= 1


def test_api_04_entity_novelty(client_and_session):
    client, session = client_and_session

    client.post("/api/v1/novelty/evaluate", json={
        "workspace_id": "default",
        "entity_type": "USER",
        "entity_id": "carol",
        "novelty_type": "NOVEL_AUTHENTICATION_PATTERN",
        "attributes": {"auth_method": "PASSWORD", "source_network_class": "EXTERNAL_ISP"},
    })

    res = client.get("/api/v1/entities/carol/novelty")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    assert data[0]["entity_id"] == "carol"


def test_api_05_emerging_pattern_transition(client_and_session):
    client, session = client_and_session

    eval_res = client.post("/api/v1/novelty/evaluate", json={
        "workspace_id": "default",
        "entity_type": "SERVICE",
        "entity_id": "svc1",
        "novelty_type": "NOVEL_API_BEHAVIOR",
        "attributes": {"method": "DELETE", "path": "/internal/data/purge", "is_privileged": True},
    })
    cand = eval_res.json().get("emerging_candidate")
    assert cand is not None
    cand_id = cand["id"]

    transition_payload = {
        "actor": "analyst-dave",
        "new_status": "INVESTIGATING",
        "reason": "Investigating unexpected purge route invocation",
    }
    trans_res = client.post(f"/api/v1/novelty/emerging-patterns/{cand_id}/status", json=transition_payload)
    assert trans_res.status_code == 200
    assert trans_res.json()["status"] == "INVESTIGATING"


def test_api_06_suppression_and_stats(client_and_session):
    client, session = client_and_session

    # Register suppression
    supp_payload = {
        "id": str(uuid.uuid4()),
        "workspace_id": "default",
        "pattern_type": "NOVEL_API_BEHAVIOR",
        "entity_type": "SERVICE",
        "entity_id": "billing-app",
        "reason": "Quarterly billing migration",
        "approved_by": "SecOps Manager",
    }
    supp_res = client.post("/api/v1/novelty/suppressions", json=supp_payload)
    assert supp_res.status_code == 200
    assert supp_res.json()["approved_by"] == "SecOps Manager"

    # Get stats
    stats_res = client.get("/api/v1/novelty/stats")
    assert stats_res.status_code == 200
    assert stats_res.json()["status"] == "active"
    assert "metrics" in stats_res.json()
