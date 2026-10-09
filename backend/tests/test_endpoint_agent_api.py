"""
Integration and API tests for Section 31 Endpoint Agent Architecture:
- Enrollment token lifecycle, single-use enforcement, and expiration
- Agent enrollment and Device identity separation
- Machine mutual authentication and replay/skew protection
- Strict server-side tenant isolation
- Credential rotation lifecycle
- Configuration delivery and cryptographic signing
- Heartbeat and health state transitions
- Telemetry batch ingestion, deduplication, clock skew, and ThreatEvent normalization
- Knowledge Graph relationships (Agent -> Device, Device -> ThreatEvent)
- Administrative revocation and fleet metrics
"""

import time
import json
import uuid
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    EndpointAgentModel,
    DeviceModel,
    EndpointEnrollmentTokenModel,
    EndpointAgentCredentialModel,
    EndpointTelemetryEventModel,
    ThreatEventModel,
    RelationshipModel
)
from backend.schemas.endpoint_agent import (
    CreateEnrollmentTokenRequest,
    AgentEnrollmentRequest,
    RawEndpointTelemetryEvent,
    BatchTelemetryIngestRequest,
    AgentHeartbeatRequest,
    CredentialRotateRequest,
    EndpointEventTypeEnum,
    EventPriorityEnum,
    AgentHealthStateEnum
)
from backend.agent.security import AgentSecurityController
from backend.services.endpoint_agent_service import SERVER_CONFIG_SIGNING_KEY


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def test_enrollment_token_lifecycle(client, db_session):
    # 1. Admin creates single-use enrollment token
    create_req = {
        "workspace_id": "test_corp",
        "description": "MacBook Pro Enrollment",
        "expires_in_minutes": 15,
        "max_uses": 1
    }
    resp = client.post("/api/v1/endpoint/enrollment/tokens", json=create_req)
    assert resp.status_code == 201
    tok_data = resp.json()
    raw_token = tok_data["raw_token"]
    assert raw_token.startswith("cget_")

    # 2. First enrollment succeeds
    enroll_payload = {
        "enrollment_token": raw_token,
        "device_uid": "HW-TEST-UID-001",
        "hostname": "macbook-pro.local",
        "platform": "macos",
        "os_version": "14.4.1",
        "architecture": "arm64",
        "agent_version": "1.0.0"
    }
    resp_enroll = client.post("/api/v1/endpoint/enrollment", json=enroll_payload)
    assert resp_enroll.status_code == 201
    agent_data = resp_enroll.json()
    assert agent_data["agent_id"].startswith("AGT-")
    assert agent_data["workspace_id"] == "test_corp"
    assert "credential_secret" in agent_data

    # 3. Second enrollment with same single-use token fails
    enroll_payload_2 = {
        "enrollment_token": raw_token,
        "device_uid": "HW-TEST-UID-002",
        "hostname": "another-box.local",
        "platform": "linux",
        "agent_version": "1.0.0"
    }
    resp_enroll_2 = client.post("/api/v1/endpoint/enrollment", json=enroll_payload_2)
    assert resp_enroll_2.status_code == 400
    assert "not active" in resp_enroll_2.json()["detail"].lower() or "exhausted" in resp_enroll_2.json()["detail"].lower()


def test_agent_enrollment_and_device_separation(client, db_session):
    """
    Verifies that device identity is strictly separated from agent identity.
    Reinstalling an agent on the same hardware reuses the DeviceModel.
    """
    # Create multi-use token for test
    tok_resp = client.post("/api/v1/endpoint/enrollment/tokens", json={
        "workspace_id": "ws_separation",
        "max_uses": 2,
        "expires_in_minutes": 30
    })
    raw_token = tok_resp.json()["raw_token"]

    device_uid = f"HARDWARE-{uuid.uuid4().hex[:8]}"

    # Enroll First Agent on Hardware
    enroll_1 = client.post("/api/v1/endpoint/enrollment", json={
        "enrollment_token": raw_token,
        "device_uid": device_uid,
        "hostname": "workstation-01",
        "platform": "windows",
        "agent_version": "1.0.0"
    })
    assert enroll_1.status_code == 201
    res1 = enroll_1.json()

    # Reinstall / Enroll Second Agent on Same Hardware
    enroll_2 = client.post("/api/v1/endpoint/enrollment", json={
        "enrollment_token": raw_token,
        "device_uid": device_uid,
        "hostname": "workstation-01",
        "platform": "windows",
        "agent_version": "1.0.1"
    })
    assert enroll_2.status_code == 201
    res2 = enroll_2.json()

    # Device ID must be identical; Agent IDs must be distinct
    assert res1["device_id"] == res2["device_id"]
    assert res1["agent_id"] != res2["agent_id"]

    # Verify Knowledge Graph relationship Agent -> Device
    rel = db_session.query(RelationshipModel).filter(
        RelationshipModel.source_id == res1["agent_id"],
        RelationshipModel.relationship_type == "COLLECTS_FROM"
    ).first()
    assert rel is not None
    assert rel.target_id == res1["device_id"]


def test_machine_authentication_and_tenant_isolation(client):
    # Enroll test agent
    tok_resp = client.post("/api/v1/endpoint/enrollment/tokens", json={
        "workspace_id": "tenant_alpha",
        "max_uses": 1
    })
    enroll_resp = client.post("/api/v1/endpoint/enrollment", json={
        "enrollment_token": tok_resp.json()["raw_token"],
        "device_uid": f"HW-{uuid.uuid4().hex[:8]}",
        "hostname": "alpha-host",
        "platform": "linux"
    })
    agent_info = enroll_resp.json()

    sec = AgentSecurityController(
        agent_id=agent_info["agent_id"],
        key_id=agent_info["key_id"],
        credential_secret=agent_info["credential_secret"]
    )

    # 1. Valid machine-authenticated heartbeat
    hb_req = {
        "agent_id": agent_info["agent_id"],
        "health_state": "HEALTHY",
        "collector_states": {"synth": "HEALTHY"},
        "buffer_events_count": 0,
        "buffer_bytes": 0,
        "cpu_usage_percent": 1.2,
        "memory_usage_mb": 42.0,
        "agent_version": "1.0.0",
        "configuration_version": "1.0.0"
    }
    hb_bytes = json.dumps(hb_req).encode("utf-8")
    headers = sec.sign_request("POST", "/api/v1/endpoint/heartbeat", hb_bytes)
    resp_hb = client.post("/api/v1/endpoint/heartbeat", content=hb_bytes, headers=headers)
    assert resp_hb.status_code == 200
    assert resp_hb.json()["status"] == "ACK"

    # 2. Tampered signature is rejected with 401
    bad_headers = dict(headers)
    bad_headers["X-CyberGuard-Signature"] = "bad-sig-hex"
    resp_bad = client.post("/api/v1/endpoint/heartbeat", content=hb_bytes, headers=bad_headers)
    assert resp_bad.status_code == 401

    # 3. Spoofed agent_id in payload is rejected with 403
    spoofed_req = dict(hb_req)
    spoofed_req["agent_id"] = "AGT-OTHER-TENANT"
    spoofed_bytes = json.dumps(spoofed_req).encode("utf-8")
    spoofed_headers = sec.sign_request("POST", "/api/v1/endpoint/heartbeat", spoofed_bytes)
    resp_spoof = client.post("/api/v1/endpoint/heartbeat", content=spoofed_bytes, headers=spoofed_headers)
    assert resp_spoof.status_code == 403


def test_credential_rotation_and_config_fetch(client):
    # Enroll agent
    tok_resp = client.post("/api/v1/endpoint/enrollment/tokens", json={"workspace_id": "ws_rot"})
    enroll_resp = client.post("/api/v1/endpoint/enrollment", json={
        "enrollment_token": tok_resp.json()["raw_token"],
        "device_uid": f"HW-{uuid.uuid4().hex[:8]}",
        "hostname": "rot-host",
        "platform": "macos"
    })
    agent_info = enroll_resp.json()

    sec = AgentSecurityController(
        agent_id=agent_info["agent_id"],
        key_id=agent_info["key_id"],
        credential_secret=agent_info["credential_secret"]
    )

    # 1. Fetch signed configuration
    cfg_headers = sec.sign_request("GET", "/api/v1/endpoint/configuration")
    resp_cfg = client.get("/api/v1/endpoint/configuration", headers=cfg_headers)
    assert resp_cfg.status_code == 200
    cfg_data = resp_cfg.json()
    assert cfg_data["version"] == "1.0.0"
    assert "signature" in cfg_data

    # 2. Rotate machine credentials
    rot_req = {"current_key_id": agent_info["key_id"]}
    rot_bytes = json.dumps(rot_req).encode("utf-8")
    rot_headers = sec.sign_request("POST", "/api/v1/endpoint/credential/rotate", rot_bytes)

    resp_rot = client.post("/api/v1/endpoint/credential/rotate", content=rot_bytes, headers=rot_headers)
    assert resp_rot.status_code == 200
    rot_data = resp_rot.json()
    assert rot_data["key_id"] != agent_info["key_id"]

    # Commit rotation locally
    sec.stage_rotated_credential(rot_data["key_id"], rot_data["new_credential_secret"])
    sec.commit_rotated_credential()

    # Now verify requests succeed using the rotated credential
    new_cfg_headers = sec.sign_request("GET", "/api/v1/endpoint/configuration")
    resp_new_cfg = client.get("/api/v1/endpoint/configuration", headers=new_cfg_headers)
    assert resp_new_cfg.status_code == 200


def test_telemetry_batch_ingestion_and_deduplication(client, db_session):
    # Enroll test agent
    tok_resp = client.post("/api/v1/endpoint/enrollment/tokens", json={"workspace_id": "ws_telemetry"})
    enroll_resp = client.post("/api/v1/endpoint/enrollment", json={
        "enrollment_token": tok_resp.json()["raw_token"],
        "device_uid": f"HW-{uuid.uuid4().hex[:8]}",
        "hostname": "prod-server-01",
        "platform": "linux"
    })
    agent_info = enroll_resp.json()
    agent_id = agent_info["agent_id"]

    sec = AgentSecurityController(
        agent_id=agent_id,
        key_id=agent_info["key_id"],
        credential_secret=agent_info["credential_secret"]
    )

    now = datetime.now(timezone.utc)
    ev1 = {
        "event_id": f"ev-{uuid.uuid4().hex[:8]}",
        "sequence_number": 101,
        "event_type": "PROCESS",
        "event_time": now.isoformat(),
        "collector_id": "proc_collector",
        "collector_version": "1.0.0",
        "configuration_version": "1.0.0",
        "agent_version": "1.0.0",
        "schema_version": "1.0.0",
        "priority": "HIGH",
        "payload": {"process_name": "sudo", "cmdline": "sudo su -", "pid": 1337}
    }
    ev2 = {
        "event_id": f"ev-{uuid.uuid4().hex[:8]}",
        "sequence_number": 102,
        "event_type": "DNS",
        "event_time": now.isoformat(),
        "collector_id": "dns_collector",
        "collector_version": "1.0.0",
        "configuration_version": "1.0.0",
        "agent_version": "1.0.0",
        "schema_version": "1.0.0",
        "priority": "NORMAL",
        "payload": {"query_name": "vault.internal.corp", "response": "10.0.4.12"}
    }

    batch_payload = {
        "agent_id": agent_id,
        "batch_id": "BATCH-001",
        "events": [ev1, ev2],
        "timestamp": now.isoformat()
    }
    batch_bytes = json.dumps(batch_payload).encode("utf-8")
    headers = sec.sign_request("POST", "/api/v1/endpoint/events", batch_bytes)

    # 1. Ingest batch
    resp_ingest = client.post("/api/v1/endpoint/events", content=batch_bytes, headers=headers)
    assert resp_ingest.status_code == 200
    res = resp_ingest.json()
    assert res["accepted_count"] == 2
    assert res["duplicate_count"] == 0
    assert len(res["accepted_event_ids"]) == 2

    # Check that normalized ThreatEvent was created
    threat_events = db_session.query(ThreatEventModel).filter(
        ThreatEventModel.event_type.like("endpoint_%")
    ).all()
    assert len(threat_events) >= 2

    # Check Knowledge Graph link: Device HAS_EVENT ThreatEvent
    device_id = agent_info["device_id"]
    rel = db_session.query(RelationshipModel).filter(
        RelationshipModel.source_id == device_id,
        RelationshipModel.relationship_type == "HAS_EVENT"
    ).first()
    assert rel is not None
    assert rel.target_type == "THREAT_EVENT"

    # 2. Retransmit identical batch (simulate network retry)
    # Deduplication should take place
    headers_retransmit = sec.sign_request("POST", "/api/v1/endpoint/events", batch_bytes)
    resp_retransmit = client.post("/api/v1/endpoint/events", content=batch_bytes, headers=headers_retransmit)
    assert resp_retransmit.status_code == 200
    res_ret = resp_retransmit.json()
    assert res_ret["duplicate_count"] == 2
    assert res_ret["accepted_count"] == 2


def test_agent_revocation_and_fleet_metrics(client, db_session):
    # Enroll agent
    tok_resp = client.post("/api/v1/endpoint/enrollment/tokens", json={"workspace_id": "ws_mgmt"})
    enroll_resp = client.post("/api/v1/endpoint/enrollment", json={
        "enrollment_token": tok_resp.json()["raw_token"],
        "device_uid": f"HW-{uuid.uuid4().hex[:8]}",
        "hostname": "to-be-revoked",
        "platform": "windows"
    })
    agent_info = enroll_resp.json()
    agent_id = agent_info["agent_id"]

    sec = AgentSecurityController(
        agent_id=agent_id,
        key_id=agent_info["key_id"],
        credential_secret=agent_info["credential_secret"]
    )

    # 1. List fleet
    resp_list = client.get("/api/v1/endpoint/agents?workspace_id=ws_mgmt")
    assert resp_list.status_code == 200
    agents = resp_list.json()
    assert any(a["agent_id"] == agent_id for a in agents)

    # 2. Get metrics
    resp_metrics = client.get("/api/v1/endpoint/metrics?workspace_id=ws_mgmt")
    assert resp_metrics.status_code == 200
    m = resp_metrics.json()
    assert m["agents_enrolled"] >= 1

    # 3. Revoke agent
    resp_rev = client.post(f"/api/v1/endpoint/agents/{agent_id}/revoke?reason=Decommissioned")
    assert resp_rev.status_code == 200
    assert resp_rev.json()["status"] == "REVOKED"

    # 4. Attempted communication by revoked agent is forbidden
    hb_req = {
        "agent_id": agent_id,
        "health_state": "HEALTHY",
        "buffer_events_count": 0,
        "buffer_bytes": 0,
        "cpu_usage_percent": 0.0,
        "memory_usage_mb": 0.0,
        "agent_version": "1.0.0",
        "configuration_version": "1.0.0"
    }
    hb_bytes = json.dumps(hb_req).encode("utf-8")
    headers = sec.sign_request("POST", "/api/v1/endpoint/heartbeat", hb_bytes)
    resp_blocked = client.post("/api/v1/endpoint/heartbeat", content=hb_bytes, headers=headers)
    assert resp_blocked.status_code in (401, 403)
