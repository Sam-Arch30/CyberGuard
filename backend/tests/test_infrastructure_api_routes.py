"""
FastAPI REST Route Integration Tests for Section 20:
Probable Origin Infrastructure & Threat Infrastructure Attribution Endpoints.
"""
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import get_db
from backend.db.models import Base, IncidentModel, SecurityEventModel


@pytest.fixture
def client_with_db():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)

    def override_get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)

    # Populate a sample incident
    db = Session()
    inc = IncidentModel(id="INC-API-TEST", incident_number="INC-2026-API", title="API Test Incident", workspace_id="default")
    db.add(inc)

    se = SecurityEventModel(
        id="SE-API-01",
        incident_id=inc.id,
        workspace_id="default",
        event_type="AUTH",
        source_type="IDP",
        event_time=datetime.now(timezone.utc),
        attributes_json=json.dumps({"source_ip": "198.51.100.123", "domain": "malicious-portal.test"}),
    )
    db.add(se)
    db.commit()
    db.close()

    yield client

    app.dependency_overrides.clear()


def test_api_01_analyze_infrastructure(client_with_db):
    """POST /api/v1/investigations/{id}/infrastructure/analyze computes and persists assessment."""
    resp = client_with_db.post("/api/v1/investigations/INC-API-TEST/infrastructure/analyze")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "INC-API-TEST"
    assert data["incident_number"] == "INC-2026-API"
    assert len(data["observed_infrastructure"]) >= 1
    assert data["primary_hypothesis"] is not None
    assert "disclaimer" in data


def test_api_02_get_infrastructure(client_with_db):
    """GET /api/v1/investigations/{id}/infrastructure returns full assessment."""
    resp = client_with_db.get("/api/v1/investigations/INC-API-TEST/infrastructure")
    assert resp.status_code == 200
    data = resp.json()
    assert data["incident_id"] == "INC-API-TEST"
    assert len(data["observed_infrastructure"]) >= 1


def test_api_03_get_origin_hypothesis(client_with_db):
    """GET /api/v1/investigations/{id}/infrastructure/origin returns primary origin hypothesis."""
    resp = client_with_db.get("/api/v1/investigations/INC-API-TEST/infrastructure/origin")
    assert resp.status_code == 200
    data = resp.json()
    assert data is not None
    assert "origin_value" in data
    assert "hypothesis_type" in data
    assert data["confidence_score"] > 0


def test_api_04_get_clusters(client_with_db):
    """GET /api/v1/investigations/{id}/infrastructure/clusters returns list of clusters."""
    resp = client_with_db.get("/api/v1/investigations/INC-API-TEST/infrastructure/clusters")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)


def test_api_05_get_timeline(client_with_db):
    """GET /api/v1/investigations/{id}/infrastructure/timeline returns chronological events."""
    resp = client_with_db.get("/api/v1/investigations/INC-API-TEST/infrastructure/timeline")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_api_06_get_hypotheses(client_with_db):
    """GET /api/v1/investigations/{id}/infrastructure/hypotheses returns all competing hypotheses."""
    resp = client_with_db.get("/api/v1/investigations/INC-API-TEST/infrastructure/hypotheses")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert any(h["hypothesis_id"] == "H1" for h in data)
