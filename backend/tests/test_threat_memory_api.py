"""
REST API Route Integration Tests for CyberGuard Threat Memory (Section 23).
Tests observation recording, exact lookup, context building, analyst decisions,
history exploration, operational statistics, and natural-language query triage.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import IncidentModel


@pytest.fixture
def client_and_session():
    """In-memory SQLite fixture with FastAPI dependency override."""
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


def test_api_01_create_observation_and_lookup(client_and_session):
    """POST observation creates entry; GET lookup retrieves it deterministically."""
    client, session = client_and_session

    obs_payload = {
        "canonical_key": "DOMAIN:phish-portal-api-test.com",
        "subject_type": "DOMAIN",
        "workspace_id": "test-ws",
        "source_type": "FINDING",
        "source_id": "f-api-01",
        "investigation_id": "inv-api-01",
        "classification": "MALICIOUS",
        "severity": "HIGH",
        "confidence": 0.95,
        "evidence_reference": "E-API-01",
        "detector_name": "url_domain_pipeline",
    }

    res_post = client.post("/api/v1/memory/observations", json=obs_payload)
    assert res_post.status_code == 201
    post_data = res_post.json()
    assert post_data["canonical_key"] == "DOMAIN:phish-portal-api-test.com"
    assert post_data["is_new_entry"] is True
    entry_id = post_data["entry_id"]

    # Exact lookup via canonical_key
    res_get = client.get(
        "/api/v1/memory/lookup",
        params={"canonical_key": "DOMAIN:phish-portal-api-test.com", "workspace_id": "test-ws"},
    )
    assert res_get.status_code == 200
    lookup_data = res_get.json()
    assert lookup_data["id"] == entry_id
    assert lookup_data["observation_count"] == 1

    # Exact lookup via raw value
    res_get_val = client.get(
        "/api/v1/memory/lookup",
        params={"value": "phish-portal-api-test.com", "subject_type": "DOMAIN", "workspace_id": "test-ws"},
    )
    assert res_get_val.status_code == 200
    assert res_get_val.json()["id"] == entry_id


def test_api_02_get_context(client_and_session):
    """GET /api/v1/memory/context returns complete standardized ThreatMemoryContext."""
    client, session = client_and_session

    domain = "context-test-domain.com"
    # Seed observation
    client.post(
        "/api/v1/memory/observations",
        json={
            "canonical_key": f"DOMAIN:{domain}",
            "subject_type": "DOMAIN",
            "workspace_id": "test-ws",
            "source_type": "FINDING",
            "classification": "MALICIOUS",
            "confidence": 0.9,
        },
    )

    res_ctx = client.get(
        "/api/v1/memory/context",
        params={"value": domain, "subject_type": "DOMAIN", "workspace_id": "test-ws"},
    )
    assert res_ctx.status_code == 200
    ctx_data = res_ctx.json()

    assert ctx_data["canonical_key"] == f"DOMAIN:{domain}"
    assert ctx_data["historical_context_available"] is True
    assert ctx_data["observation_count"] == 1
    assert "limitations" in ctx_data
    assert any("CURRENT EVIDENCE > HISTORICAL MEMORY" in lim for lim in ctx_data["limitations"])


def test_api_03_record_analyst_decision(client_and_session):
    """POST /api/v1/memory/decisions promotes entry to VERIFIED with analyst provenance."""
    client, session = client_and_session

    domain = "sso-verified-legit.com"
    res_obs = client.post(
        "/api/v1/memory/observations",
        json={
            "canonical_key": f"DOMAIN:{domain}",
            "subject_type": "DOMAIN",
            "workspace_id": "test-ws",
            "source_type": "FINDING",
            "classification": "SUSPICIOUS",
        },
    )
    entry_id = res_obs.json()["entry_id"]

    dec_payload = {
        "memory_entry_id": entry_id,
        "workspace_id": "test-ws",
        "decision": "FALSE_POSITIVE",
        "reason": "Authorized partner SSO domain added to legitimate federation.",
        "approved_by": "analyst_bob@cyberguard.internal",
        "scope": "ORGANIZATION",
    }
    res_dec = client.post("/api/v1/memory/decisions", json=dec_payload)
    assert res_dec.status_code == 201
    assert res_dec.json()["decision"] == "FALSE_POSITIVE"

    # Verify entry status is now VERIFIED
    res_entry = client.get(f"/api/v1/memory/{entry_id}", params={"workspace_id": "test-ws"})
    assert res_entry.status_code == 200
    assert res_entry.json()["status"] == "VERIFIED"


def test_api_04_observations_and_history(client_and_session):
    """GET /api/v1/memory/{id}/observations and /history return chronological records."""
    client, session = client_and_session

    domain = "history-test.com"
    res_obs = client.post(
        "/api/v1/memory/observations",
        json={
            "canonical_key": f"DOMAIN:{domain}",
            "subject_type": "DOMAIN",
            "workspace_id": "test-ws",
            "source_type": "SECURITY_EVENT",
            "classification": "BENIGN",
        },
    )
    entry_id = res_obs.json()["entry_id"]

    # Observations endpoint
    res_obs_list = client.get(f"/api/v1/memory/{entry_id}/observations", params={"workspace_id": "test-ws"})
    assert res_obs_list.status_code == 200
    assert len(res_obs_list.json()) == 1

    # History endpoint
    res_hist = client.get(f"/api/v1/memory/{entry_id}/history", params={"workspace_id": "test-ws"})
    assert res_hist.status_code == 200
    assert res_hist.json()["canonical_key"] == f"DOMAIN:{domain}"


def test_api_05_stats_endpoint(client_and_session):
    """GET /api/v1/memory/stats returns operational metrics."""
    client, session = client_and_session

    res = client.get("/api/v1/memory/stats", params={"workspace_id": "test-ws"})
    assert res.status_code == 200
    data = res.json()
    assert "total_memory_entries" in data
    assert "total_observations" in data


def test_api_06_query_copilot_question(client_and_session):
    """POST /api/v1/memory/query returns evidence-grounded answer."""
    client, session = client_and_session

    domain = "copilot-query-test.com"
    client.post(
        "/api/v1/memory/observations",
        json={
            "canonical_key": f"DOMAIN:{domain}",
            "subject_type": "DOMAIN",
            "workspace_id": "test-ws",
            "source_type": "FINDING",
            "classification": "MALICIOUS",
        },
    )

    query_payload = {
        "query_type": "HISTORICAL_LOOKUP",
        "value": domain,
        "workspace_id": "test-ws",
    }
    res = client.post("/api/v1/memory/query", json=query_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["seen_before"] is True
    assert "observed 1 time(s)" in data["answer"]
