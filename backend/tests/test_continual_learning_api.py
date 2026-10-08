"""
REST API Route Integration Tests for Controlled Continual Learning (Section 24).
Tests endpoints:
1. /api/v1/learning/candidates (GET, POST, review, from-threat-memory)
2. /api/v1/learning/datasets (GET, POST build, GET id)
3. /api/v1/learning/jobs (GET, POST, GET id)
4. /api/v1/models (GET, GET id, GET card)
5. /api/v1/models/{id}/approve (POST)
6. /api/v1/models/{id}/stage (POST)
7. /api/v1/models/{id}/promote (POST)
8. /api/v1/models/{id}/rollback (POST)
9. /api/v1/learning/drift (GET)
10. /api/v1/learning/stats (GET)
11. Role authorization checks (unauthorized role receives 403 Forbidden).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import Base, get_db
from backend.db.models import (
    LearningCandidateModel,
    LearningDatasetModel,
    RegisteredModelModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.continual_learning import ModelLifecycleStatus
from backend.services.continual_learning_service import (
    ContinualLearningService,
    CANDIDATES_DIR,
)


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


def test_api_01_candidates_lifecycle(client_and_session):
    """Verifies creating, listing, and reviewing learning candidates via REST API."""
    client, session = client_and_session

    # 1. Create candidate via POST
    cand_payload = {
        "workspace_id": "ws-api",
        "source_type": "THREAT_MEMORY",
        "source_reference": "DOMAIN:suspicious-login.com",
        "text_content": "Urgent alert: Update your banking credentials at suspicious-login.com",
        "label": "phishing",
        "label_source": "ANALYST_VERIFIED",
        "confidence": 0.95,
    }
    resp = client.post("/api/v1/learning/candidates", json=cand_payload, headers={"X-Role": "analyst"})
    assert resp.status_code == 201
    cand_data = resp.json()
    assert cand_data["source_reference"] == "DOMAIN:suspicious-login.com"
    assert cand_data["eligibility_status"] == "ELIGIBLE"
    cand_id = cand_data["id"]

    # 2. List candidates
    resp_list = client.get("/api/v1/learning/candidates?workspace_id=ws-api")
    assert resp_list.status_code == 200
    items = resp_list.json()
    assert len(items) >= 1

    # 3. Review candidate
    review_payload = {
        "review_status": "ACCEPTED",
        "reviewer": "soc_lead",
        "reason": "Confirmed active credential harvesting form",
    }
    resp_rev = client.post(
        f"/api/v1/learning/candidates/{cand_id}/review?workspace_id=ws-api",
        json=review_payload,
        headers={"X-Role": "analyst"},
    )
    assert resp_rev.status_code == 200
    assert resp_rev.json()["review_status"] == "ACCEPTED"


def test_api_02_authorization_enforcement(client_and_session):
    """Verifies unprivileged roles receive 403 Forbidden on management endpoints."""
    client, session = client_and_session

    # Unauthorized role on candidate creation
    cand_payload = {
        "workspace_id": "ws-api",
        "source_type": "EXTERNAL",
        "source_reference": "REF:123",
        "text_content": "Phishing text message alert",
        "label": "phishing",
    }
    resp_unauth = client.post(
        "/api/v1/learning/candidates",
        json=cand_payload,
        headers={"X-Role": "unauthorized"},
    )
    assert resp_unauth.status_code == 403

    # Unauthorized role on model promotion
    resp_promo = client.post(
        "/api/v1/models/dummy-model-id/promote",
        json={"reviewer": "bad_actor", "reason": "unauthorized replace"},
        headers={"X-Role": "guest"},
    )
    assert resp_promo.status_code == 403


def test_api_03_ingest_from_threat_memory(client_and_session):
    """Verifies POST /api/v1/learning/candidates/from-threat-memory ingests decisions."""
    client, session = client_and_session
    now = get_utc_now()

    entry = ThreatMemoryEntryModel(
        id=generate_uuid(),
        workspace_id="ws-tm",
        memory_type="URL",
        subject_type="URL",
        subject_id="https://portal.bank.com/auth",
        canonical_key="URL:https://portal.bank.com/auth",
        status="VERIFIED",
        created_at=now,
    )
    session.add(entry)
    session.flush()

    dec = ThreatMemoryDecisionModel(
        id=generate_uuid(),
        workspace_id="ws-tm",
        memory_entry_id=entry.id,
        decision="VERIFIED_MALICIOUS",
        approved_by="analyst_alice",
        reason="Credential harvester targeting banking clients",
        created_at=now,
    )
    session.add(dec)
    session.commit()

    resp = client.post(
        "/api/v1/learning/candidates/from-threat-memory",
        json={"decision_id": dec.id, "workspace_id": "ws-tm"},
        headers={"X-Role": "analyst"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["label"] == "phishing"
    assert data["source_type"] == "THREAT_MEMORY"


def test_api_04_dataset_and_training_lifecycle(client_and_session):
    """Verifies dataset compilation, training job execution, model card retrieval, and registry endpoints."""
    client, session = client_and_session

    # Seed 10 candidates for dataset building
    now = get_utc_now()
    for i in range(5):
        c1 = LearningCandidateModel(
            id=f"api-phish-{i}",
            workspace_id="ws-flow",
            source_type="THREAT_MEMORY",
            source_reference=f"phish-{i}",
            text_content=f"Urgent: Reset your banking credentials now {i}",
            label="phishing",
            label_source="ANALYST_VERIFIED",
            confidence=0.95,
            observed_at=now + timedelta(days=i),
            eligibility_status="ELIGIBLE",
            review_status="ACCEPTED",
            raw_payload_json="{}",
            created_at=now + timedelta(days=i),
        )
        c2 = LearningCandidateModel(
            id=f"api-legit-{i}",
            workspace_id="ws-flow",
            source_type="THREAT_MEMORY",
            source_reference=f"legit-{i}",
            text_content=f"Team standup notes for release milestone {i}",
            label="legitimate",
            label_source="ANALYST_VERIFIED",
            confidence=0.95,
            observed_at=now + timedelta(days=i),
            eligibility_status="ELIGIBLE",
            review_status="ACCEPTED",
            raw_payload_json="{}",
            created_at=now + timedelta(days=i),
        )
        session.add(c1)
        session.add(c2)
    session.commit()

    # 1. Build Dataset via POST
    ds_resp = client.post(
        "/api/v1/learning/datasets/build",
        json={"workspace_id": "ws-flow", "stratify_by_time": True, "group_by_campaign": True},
        headers={"X-Role": "admin"},
    )
    assert ds_resp.status_code == 201
    ds_data = ds_resp.json()
    ds_id = ds_data["id"]
    ds_version = ds_data["version"]
    assert ds_version == "D-001"

    # 2. Get Dataset by ID
    get_ds = client.get(f"/api/v1/learning/datasets/{ds_id}?workspace_id=ws-flow")
    assert get_ds.status_code == 200
    assert get_ds.json()["manifest_checksum"] == ds_data["manifest_checksum"]

    # 3. Launch Training Job via POST
    train_resp = client.post(
        "/api/v1/learning/jobs",
        json={"workspace_id": "ws-flow", "dataset_version": ds_version, "model_type": "PHISHING_CLASSIFIER"},
        headers={"X-Role": "admin"},
    )
    assert train_resp.status_code == 201
    job_data = train_resp.json()
    assert job_data["status"] == "SUCCEEDED"

    # 4. List Models in Registry
    models_resp = client.get("/api/v1/models?workspace_id=ws-flow")
    assert models_resp.status_code == 200
    models = models_resp.json()
    assert len(models) >= 1
    cand_model = models[0]
    model_id = cand_model["id"]
    assert cand_model["status"] == "CANDIDATE"

    # 5. Get Model Card
    card_resp = client.get(f"/api/v1/models/{model_id}/card?workspace_id=ws-flow")
    assert card_resp.status_code == 200
    card = card_resp.json()
    assert card["model_id"] == model_id
    assert "metrics" in card
    assert "baseline_comparison" in card

    # 6. Approve Candidate
    app_resp = client.post(
        f"/api/v1/models/{model_id}/approve?workspace_id=ws-flow",
        json={"reviewer": "lead_sec_engineer", "reason": "Evaluated offline against benchmarks successfully"},
        headers={"X-Role": "admin"},
    )
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "APPROVED"

    # 7. Stage Approved Model
    stg_resp = client.post(
        f"/api/v1/models/{model_id}/stage?workspace_id=ws-flow",
        json={"reviewer": "devops_lead", "reason": "Deploying canary to test environment"},
        headers={"X-Role": "admin"},
    )
    assert stg_resp.status_code == 200
    assert stg_resp.json()["status"] == "STAGED"

    # 8. Promote Staged Model to PRODUCTION
    promo_resp = client.post(
        f"/api/v1/models/{model_id}/promote?workspace_id=ws-flow",
        json={"reviewer": "ciso", "reason": "Promoting validated model into production"},
        headers={"X-Role": "admin"},
    )
    assert promo_resp.status_code == 200
    assert promo_resp.json()["status"] == "PRODUCTION"

    # 9. Rollback Model
    roll_resp = client.post(
        f"/api/v1/models/{model_id}/rollback?workspace_id=ws-flow",
        json={"reviewer": "sre_oncall", "reason": "Reverting canary due to false alarm spike"},
        headers={"X-Role": "admin"},
    )
    assert roll_resp.status_code == 200

    # 10. Query Drift & Dashboard Stats
    drift_resp = client.get("/api/v1/learning/drift?workspace_id=ws-flow")
    assert drift_resp.status_code == 200
    assert "drift_detected" in drift_resp.json()

    stats_resp = client.get("/api/v1/learning/stats?workspace_id=ws-flow")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["workspace_id"] == "ws-flow"
    assert stats["total_candidates"] >= 10
    assert stats["total_datasets"] >= 1
