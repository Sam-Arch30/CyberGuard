"""
REST API Contract and Authorization Tests for Section 26: Unified Risk Engine.

Validates:
1. Retrieval of risk assessments, breakdowns, and explanations via HTTP endpoints.
2. Evaluating risk for scope or raw signals.
3. Reassessing existing assessments with new evidence.
4. Authorization enforcement: unprivileged roles rejected with HTTP 403 when updating config.
5. Admin role successfully updates versioned configuration.
6. Executive dashboard risk statistics endpoint.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    RiskAssessmentModel,
    RiskConfigurationModel,
    RiskSignalModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.risk_engine import RiskScope


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def clean_db():
    with SessionLocal() as db:
        db.query(RiskSignalModel).delete()
        db.query(RiskAssessmentModel).delete()
        db.query(RiskConfigurationModel).delete()
        db.commit()
    yield
    with SessionLocal() as db:
        db.query(RiskSignalModel).delete()
        db.query(RiskAssessmentModel).delete()
        db.query(RiskConfigurationModel).delete()
        db.commit()


def test_api_01_evaluate_and_get_assessment(client: TestClient, clean_db):
    """Tests evaluating risk via POST /evaluate and retrieving via GET /assessments/{id}."""
    payload = {
        "workspace_id": "ws-api-test",
        "scope_type": "EVENT",
        "scope_id": "ev-api-01",
        "additional_signals": [
            {
                "signal_type": "SUSPICIOUS_PHISHING_URL",
                "source_type": "URL_ANALYZER",
                "detector_id": "url_domain_intel",
                "evidence_family": "URL",
                "semantics": "THREAT_SCORE",
                "direction": "SUPPORTING",
                "raw_score": 85.0,
                "correlation_group": "URL:phish.example.com",
            },
            {
                "signal_type": "EXECUTIVE_IMPERSONATION",
                "source_type": "IMPERSONATION_DETECTOR",
                "detector_id": "impersonation_service",
                "evidence_family": "IDENTITY",
                "semantics": "THREAT_SCORE",
                "direction": "SUPPORTING",
                "raw_score": 80.0,
                "correlation_group": "USER:exec@example.com",
            }
        ],
        "context_metadata": {
            "is_privileged_account": True
        }
    }

    # Evaluate
    create_resp = client.post("/api/v1/risk/evaluate", json=payload, headers={"X-Role": "analyst"})
    assert create_resp.status_code == 201
    assessment_data = create_resp.json()

    assert assessment_data["scope_id"] == "ev-api-01"
    assert assessment_data["risk_score"] > 0.0
    assert assessment_data["version"] == 1
    assessment_id = assessment_data["id"]

    # Get by ID
    get_resp = client.get(f"/api/v1/risk/assessments/{assessment_id}", params={"workspace_id": "ws-api-test"})
    assert get_resp.status_code == 200
    fetched = get_resp.json()
    assert fetched["id"] == assessment_id
    assert fetched["risk_level"] in ("HIGH", "CRITICAL", "MEDIUM")

    # Get breakdown
    breakdown_resp = client.get(f"/api/v1/risk/assessments/{assessment_id}/breakdown", params={"workspace_id": "ws-api-test"})
    assert breakdown_resp.status_code == 200
    components = breakdown_resp.json()
    assert len(components) >= 2

    # Get explanation
    expl_resp = client.get(f"/api/v1/risk/assessments/{assessment_id}/explanation", params={"workspace_id": "ws-api-test"})
    assert expl_resp.status_code == 200
    expl = expl_resp.json()
    assert "summary" in expl
    assert len(expl["top_contributors"]) >= 1


def test_api_02_reassess_assessment(client: TestClient, clean_db):
    """Tests triggering reassessment creating version 2 via POST /reassess/{id}."""
    # First create v1
    eval_payload = {
        "workspace_id": "ws-reassess-api",
        "scope_type": "EVENT",
        "scope_id": "ev-reassess-01",
        "additional_signals": [
            {
                "signal_type": "ANOMALOUS_LOGIN",
                "source_type": "AUTH_MONITOR",
                "detector_id": "auth_pipeline",
                "evidence_family": "AUTHENTICATION",
                "raw_score": 40.0,
            }
        ]
    }
    v1_resp = client.post("/api/v1/risk/evaluate", json=eval_payload, headers={"X-Role": "analyst"})
    assert v1_resp.status_code == 201
    v1_id = v1_resp.json()["id"]
    initial_score = v1_resp.json()["risk_score"]

    # Reassess with confirmed ransomware
    reassess_payload = {
        "workspace_id": "ws-reassess-api",
        "reassessment_reason": "Sandbox confirmed ransomware execution",
        "additional_signals": [
            {
                "signal_type": "RANSOMWARE_PAYLOAD",
                "source_type": "SANDBOX",
                "detector_id": "file_security_pipeline",
                "evidence_family": "FILE",
                "raw_score": 95.0,
            }
        ],
        "context_metadata": {"is_critical_asset": True}
    }

    reassess_resp = client.post(f"/api/v1/risk/reassess/{v1_id}", json=reassess_payload, headers={"X-Role": "analyst"})
    assert reassess_resp.status_code == 200
    v2_data = reassess_resp.json()

    assert v2_data["version"] == 2
    assert v2_data["parent_assessment_id"] == v1_id
    assert v2_data["risk_score"] > initial_score
    assert v2_data["severity"] == "CRITICAL"

    # Verify history endpoint
    hist_resp = client.get(f"/api/v1/risk/assessments/{v2_data['id']}/history", params={"workspace_id": "ws-reassess-api"})
    assert hist_resp.status_code == 200
    history = hist_resp.json()["history"]
    assert len(history) == 2
    assert history[0]["version"] == 1
    assert history[1]["version"] == 2


def test_api_03_config_authorization_enforcement(client: TestClient, clean_db):
    """
    Validates that updating risk configuration is restricted to administrative roles.
    Unauthorized / guest requests must receive HTTP 403.
    """
    # 1. Read config (open to analyst)
    get_cfg = client.get("/api/v1/risk/config")
    assert get_cfg.status_code == 200
    active_cfg = get_cfg.json()

    # 2. Modify config as unprivileged user -> 403 FORBIDDEN
    new_cfg = dict(active_cfg)
    new_cfg["version"] = "2.0.0-unauthorized"
    unauth_resp = client.post("/api/v1/risk/config", json=new_cfg, headers={"X-Role": "guest"})
    assert unauth_resp.status_code == 403

    # 3. Modify config as admin -> 201 CREATED
    new_cfg["version"] = "2.0.0-custom-admin"
    admin_resp = client.post("/api/v1/risk/config", json=new_cfg, headers={"X-Role": "admin"})
    assert admin_resp.status_code == 201
    assert admin_resp.json()["version"] == "2.0.0-custom-admin"


def test_api_04_dashboard_stats(client: TestClient, clean_db):
    """Validates retrieving executive risk statistics."""
    # Create sample assessments
    client.post(
        "/api/v1/risk/evaluate",
        json={
            "workspace_id": "ws-stats",
            "scope_type": "EVENT",
            "scope_id": "ev-stats-1",
            "additional_signals": [{"signal_type": "SIG1", "raw_score": 85.0, "source_type": "TEST", "detector_id": "test"}],
        },
        headers={"X-Role": "analyst"},
    )
    client.post(
        "/api/v1/risk/evaluate",
        json={
            "workspace_id": "ws-stats",
            "scope_type": "EVENT",
            "scope_id": "ev-stats-2",
            "additional_signals": [{"signal_type": "SIG2", "raw_score": 30.0, "source_type": "TEST", "detector_id": "test"}],
        },
        headers={"X-Role": "analyst"},
    )

    stats_resp = client.get("/api/v1/risk/dashboard/stats", params={"workspace_id": "ws-stats"})
    assert stats_resp.status_code == 200
    stats = stats_resp.json()

    assert stats["total_assessments"] >= 2
    assert "average_risk_score" in stats
    assert "level_counts" in stats
