"""
API Endpoint Integration Tests for MITRE ATT&CK Mapping & Intelligence Engine (Section 19).
Verifies HTTP endpoints for tactics, techniques, incident mapping, timelines, feedback,
LLM suggestion validation, and environment exclusions.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import IncidentModel, SecurityEventModel, AttackTechniqueMappingModel


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def test_api_list_tactics(client):
    """GET /api/attack-mapping/tactics returns all 14 Enterprise tactics."""
    response = client.get("/api/attack-mapping/tactics")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 14
    tactic_ids = [t["tactic_id"] for t in data]
    assert "TA0001" in tactic_ids
    assert "TA0006" in tactic_ids


def test_api_list_techniques(client):
    """GET /api/attack-mapping/techniques returns techniques with filters."""
    # List all
    response = client.get("/api/attack-mapping/techniques")
    assert response.status_code == 200
    all_techs = response.json()
    assert len(all_techs) >= 20

    # Filter by tactic
    response_tactic = client.get("/api/attack-mapping/techniques?tactic_id=TA0001")
    assert response_tactic.status_code == 200
    init_access = response_tactic.json()
    for t in init_access:
        assert "TA0001" in t["tactic_ids"]

    # Filter subtechniques only
    response_subs = client.get("/api/attack-mapping/techniques?subtechniques_only=true")
    assert response_subs.status_code == 200
    for s in response_subs.json():
        assert s["is_subtechnique"] is True


def test_api_get_technique_detail(client):
    """GET /api/attack-mapping/techniques/{technique_id} returns detail or 404."""
    response = client.get("/api/attack-mapping/techniques/T1566.002")
    assert response.status_code == 200
    data = response.json()
    assert data["technique_id"] == "T1566.002"
    assert data["name"] == "Spearphishing Link"
    assert data["parent_technique_id"] == "T1566"

    # Nonexistent
    resp_404 = client.get("/api/attack-mapping/techniques/T9999")
    assert resp_404.status_code == 404


def test_api_incident_mitre_mapping_flow(client, db_session):
    """Full incident mapping flow via REST endpoints."""
    inc = IncidentModel(
        title="API Test Spray Incident",
        incident_number=f"INC-{uuid.uuid4().hex[:6]}",
        status="OPEN"
    )
    db_session.add(inc)
    db_session.flush()

    sev = SecurityEventModel(
        incident_id=inc.id,
        event_type="AUTH_FAILURE",
        event_time=datetime.now(timezone.utc),
        source_type="AUTH_LOG",
        summary="Password spray attempt",
        attributes_json=json.dumps({"distinct_accounts": 20, "attempt_count": 30, "source_ip": "198.51.100.8"})
    )
    db_session.add(sev)
    db_session.commit()

    # 1. POST /api/incidents/{incident_id}/mitre-map
    resp_map = client.post(f"/api/incidents/{inc.id}/mitre-map")
    assert resp_map.status_code == 200
    report = resp_map.json()
    assert report["incident_id"] == inc.id
    assert len(report["supported_mappings"]) >= 1
    assert "T1110.003" in [m["technique_id"] for m in report["supported_mappings"]]

    # 2. GET /api/incidents/{incident_id}/mitre-mappings
    resp_get = client.get(f"/api/incidents/{inc.id}/mitre-mappings")
    assert resp_get.status_code == 200
    mappings = resp_get.json()
    assert len(mappings) >= 1
    mapping_id = mappings[0]["id"]

    # 3. GET /api/incidents/{incident_id}/mitre-timeline
    resp_timeline = client.get(f"/api/incidents/{inc.id}/mitre-timeline")
    assert resp_timeline.status_code == 200
    timeline_data = resp_timeline.json()
    assert "sequence" in timeline_data
    assert "tactic_timeline" in timeline_data

    # 4. POST /api/mitre-mappings/{mapping_id}/feedback
    resp_fb = client.post(
        f"/api/mitre-mappings/{mapping_id}/feedback",
        json={"disposition": "CONFIRMED", "notes": "Validated via IdP log telemetry.", "reviewed_by": "Lead SOC"}
    )
    assert resp_fb.status_code == 200
    assert resp_fb.json()["disposition"] == "CONFIRMED"


def test_api_validate_llm_suggestion(client):
    """POST /api/attack-mapping/validate-llm-suggestion validates candidate technique."""
    # Invalid technique
    resp_invalid = client.post(
        "/api/attack-mapping/validate-llm-suggestion",
        json={"suggestion": {"candidate_technique_id": "T0000", "reason": "Fictitious technique"}}
    )
    assert resp_invalid.status_code == 200
    assert resp_invalid.json()["technique_exists"] is False
    assert resp_invalid.json()["resulting_status"] == "REJECTED"

    # Valid technique without evidence -> PLAUSIBLE / INSUFFICIENT
    resp_valid = client.post(
        "/api/attack-mapping/validate-llm-suggestion",
        json={"suggestion": {"candidate_technique_id": "T1059.001", "reason": "Likely PowerShell"}}
    )
    assert resp_valid.status_code == 200
    assert resp_valid.json()["technique_exists"] is True
    assert resp_valid.json()["resulting_status"] != "SUPPORTED"


def test_api_environment_exclusions(client):
    """GET and POST /api/attack-mapping/environment-exclusions."""
    resp_get = client.get("/api/attack-mapping/environment-exclusions")
    assert resp_get.status_code == 200
    orig_config = resp_get.json()

    # Update
    new_scanners = orig_config.get("trusted_scanners", []) + ["192.168.100.99"]
    resp_post = client.post(
        "/api/attack-mapping/environment-exclusions",
        json={**orig_config, "trusted_scanners": new_scanners}
    )
    assert resp_post.status_code == 200
    assert "192.168.100.99" in resp_post.json()["trusted_scanners"]
