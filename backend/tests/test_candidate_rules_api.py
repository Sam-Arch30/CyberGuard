"""
REST API Contract and Authorization Tests for Section 25: Candidate Rule Engine.

Validates:
1. Listing and creating candidate rules via HTTP endpoints.
2. Synthesizing candidate rules from EmergingPatternCandidate.
3. Historical backtesting API execution.
4. Authorization enforcement: unprivileged roles (guest, unauthorized) rejected with HTTP 403.
5. Lifecycle stage, activate, disable, and version history endpoints.
6. Safe runtime evaluation endpoint and executive dashboard statistics.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    EmergingPatternCandidateModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import RuleLifecycleStatus


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def clean_db():
    with SessionLocal() as db:
        db.query(CandidateRuleExecutionModel).delete()
        db.query(CandidateRuleVersionModel).delete()
        db.query(CandidateRuleModel).delete()
        db.commit()
    yield
    with SessionLocal() as db:
        db.query(CandidateRuleExecutionModel).delete()
        db.query(CandidateRuleVersionModel).delete()
        db.query(CandidateRuleModel).delete()
        db.commit()


def test_api_01_create_and_list_candidate_rules(client, clean_db):
    """Verifies creating and listing candidate rules via REST API."""
    payload = {
        "workspace_id": "ws-api",
        "name": "API Structural Rule",
        "description": "Rule created via API",
        "rule_type": "STRUCTURAL",
        "scope": "URL",
        "severity": "HIGH",
        "confidence": 0.85,
        "generalization_level": "STRUCTURAL",
        "definition": {
            "logical_operator": "AND",
            "conditions": [
                {"field": "url.path", "operator": "contains", "value": "login"},
                {"field": "url.domain_similarity", "operator": "gte", "value": 0.88},
            ],
        },
        "created_by": "analyst_api",
    }
    resp = client.post("/api/v1/rule-candidates", json=payload, headers={"X-Role": "analyst"})
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["name"] == "API Structural Rule"
    assert data["status"] == "DRAFT"
    assert data["version"] == "v1"
    rule_id = data["id"]

    # List
    list_resp = client.get("/api/v1/rule-candidates?workspace_id=ws-api", headers={"X-Role": "analyst"})
    assert list_resp.status_code == 200
    candidates = list_resp.json()
    assert len(candidates) == 1
    assert candidates[0]["id"] == rule_id


def test_api_02_authorization_enforcement(client, clean_db):
    """Verifies unprivileged roles are forbidden (HTTP 403)."""
    forbidden_headers = [
        {"X-Role": "guest"},
        {"X-Role": "unauthorized"},
        {"X-Role": "viewer"},
        {"Authorization": "Bearer untrusted_token"},
    ]
    for headers in forbidden_headers:
        resp = client.post(
            "/api/v1/rule-candidates/dummy-rule/approve",
            json={"workspace_id": "default", "reviewer": "attacker", "reason": "malicious approve"},
            headers=headers,
        )
        assert resp.status_code == 403, f"Expected 403 for {headers}, got {resp.status_code}"


def test_api_03_from_pattern_and_backtest(client, clean_db):
    """Verifies synthesizing candidate rule from pattern and running backtest."""
    # Seed EmergingPatternCandidate
    with SessionLocal() as db:
        pat = EmergingPatternCandidateModel(
            id="pat-api-01",
            workspace_id="ws-pat",
            incident_id="inc-api-1",
            pattern_type="NOVEL_URL_STRUCTURE",
            fingerprint_hash="hash-api-01",
            fingerprint_repr="path:login+brand:bank",
            novelty_score=0.90,
            recurrence_score=60.0,
            observation_count=10,
            entity_count=3,
            incident_count=2,
            status="EMERGING",
            supporting_evidence_json="[]",
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )
        db.add(pat)
        db.commit()

    # Generate candidate rule from pattern
    synth_resp = client.post(
        "/api/v1/rule-candidates/from-pattern",
        json={"workspace_id": "ws-pat", "pattern_candidate_id": "pat-api-01"},
        headers={"X-Role": "analyst"},
    )
    assert synth_resp.status_code == 201, synth_resp.text
    cand_data = synth_resp.json()
    rule_id = cand_data["id"]
    assert cand_data["status"] == "DISCOVERED"

    # Backtest
    backtest_resp = client.post(
        f"/api/v1/rule-candidates/{rule_id}/backtest",
        json={"workspace_id": "ws-pat", "lookback_days": 30},
        headers={"X-Role": "analyst"},
    )
    assert backtest_resp.status_code == 200, backtest_resp.text
    backtest_data = backtest_resp.json()
    assert "historical_match_count" in backtest_data
    assert "precision" in backtest_data


def test_api_04_full_lifecycle_and_evaluation(client, clean_db):
    """Verifies approve -> stage -> activate -> evaluate -> dashboard stats."""
    # Create rule in DRAFT
    payload = {
        "workspace_id": "ws-flow",
        "name": "Flow Candidate Rule",
        "rule_type": "STRUCTURAL",
        "scope": "GLOBAL",
        "severity": "HIGH",
        "definition": {
            "logical_operator": "AND",
            "conditions": [
                {"field": "indicator_code", "operator": "eq", "value": "CR_FLOW_TEST"},
            ],
        },
    }
    create_resp = client.post("/api/v1/rule-candidates", json=payload, headers={"X-Role": "analyst"})
    assert create_resp.status_code == 201
    rule_id = create_resp.json()["id"]

    # 1. Approve
    action_body = {"workspace_id": "ws-flow", "reviewer": "lead_eng", "reason": "Valid logic verified"}
    app_resp = client.post(f"/api/v1/rule-candidates/{rule_id}/approve", json=action_body, headers={"X-Role": "admin"})
    assert app_resp.status_code == 200
    assert app_resp.json()["status"] == "APPROVED"

    # 2. Stage in shadow mode
    stage_resp = client.post(f"/api/v1/rules/{rule_id}/stage", json=action_body, headers={"X-Role": "admin"})
    assert stage_resp.status_code == 200
    assert stage_resp.json()["status"] == "STAGED"

    # 3. Evaluate in shadow mode
    eval_payload = {
        "workspace_id": "ws-flow",
        "target_payload": {"indicator_code": "CR_FLOW_TEST", "event_id": "evt-01"},
        "include_staged_shadow": True,
    }
    eval_resp = client.post("/api/v1/rules/evaluate", json=eval_payload, headers={"X-Role": "analyst"})
    assert eval_resp.status_code == 200
    results = eval_resp.json()
    assert len(results) == 1
    assert results[0]["matched"] is True

    # 4. Activate in production
    act_resp = client.post(f"/api/v1/rules/{rule_id}/activate", json=action_body, headers={"X-Role": "admin"})
    assert act_resp.status_code == 200
    assert act_resp.json()["status"] == "ACTIVE"

    # 5. List versions
    ver_resp = client.get(f"/api/v1/rules/{rule_id}/versions?workspace_id=ws-flow", headers={"X-Role": "analyst"})
    assert ver_resp.status_code == 200
    versions = ver_resp.json()
    assert len(versions) >= 1
    assert versions[0]["version"] == "v1"

    # 6. Dashboard stats
    stats_resp = client.get("/api/v1/rules/dashboard/stats?workspace_id=ws-flow", headers={"X-Role": "analyst"})
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_candidate_rules"] >= 1
    assert stats["active_production_count"] >= 1
