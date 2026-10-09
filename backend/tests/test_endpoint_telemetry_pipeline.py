"""
Integration tests for Section 32: Endpoint Telemetry Pipeline.
Tests end-to-end telemetry ingestion, multi-hop Security Knowledge Graph relationships,
Threat Memory indicator matching, Novelty tagging, deduplication, capabilities endpoint,
and telemetry query filtering.
"""

import json
import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    EndpointAgentModel,
    DeviceModel,
    EndpointTelemetryEventModel,
    ThreatEventModel,
    RelationshipModel,
    ThreatMemoryEntryModel
)
from backend.agent.security import AgentSecurityController


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


def _enroll_test_agent(client, workspace_id: str, hostname: str = "host-alpha"):
    tok_resp = client.post("/api/v1/endpoint/enrollment/tokens", json={"workspace_id": workspace_id})
    assert tok_resp.status_code == 201
    raw_token = tok_resp.json()["raw_token"]

    enroll_resp = client.post("/api/v1/endpoint/enrollment", json={
        "enrollment_token": raw_token,
        "device_uid": f"DEVICE-UID-{uuid.uuid4().hex[:8]}",
        "hostname": hostname,
        "platform": "macos",
        "os_version": "14.4",
        "agent_version": "1.0.0"
    })
    assert enroll_resp.status_code == 201
    return enroll_resp.json()


# ============================================================================
# 1. END-TO-END TELEMETRY PIPELINE & SECURITY KNOWLEDGE GRAPH
# ============================================================================

def test_end_to_end_telemetry_pipeline(client, db_session):
    workspace = f"ws_pipeline_{uuid.uuid4().hex[:6]}"
    hostname = "macbook-secops"
    agent_info = _enroll_test_agent(client, workspace_id=workspace, hostname=hostname)
    agent_id = agent_info["agent_id"]
    device_id = agent_info["device_id"]

    sec = AgentSecurityController(
        agent_id=agent_id,
        key_id=agent_info["key_id"],
        credential_secret=agent_info["credential_secret"]
    )

    now = datetime.now(timezone.utc)
    ev_process_id = f"ev-proc-{uuid.uuid4().hex[:8]}"
    ev_net_id = f"ev-net-{uuid.uuid4().hex[:8]}"
    ev_dns_id = f"ev-dns-{uuid.uuid4().hex[:8]}"
    ev_auth_id = f"ev-auth-{uuid.uuid4().hex[:8]}"
    ev_file_id = f"ev-file-{uuid.uuid4().hex[:8]}"
    ev_sys_id = f"ev-sys-{uuid.uuid4().hex[:8]}"
    ev_health_id = f"ev-health-{uuid.uuid4().hex[:8]}"

    batch_payload = {
        "agent_id": agent_id,
        "batch_id": f"BATCH-{uuid.uuid4().hex[:6]}",
        "timestamp": now.isoformat(),
        "events": [
            # 1. PROCESS
            {
                "event_id": ev_process_id,
                "sequence_number": 1,
                "event_type": "PROCESS",
                "event_time": now.isoformat(),
                "collector_id": "process_telemetry_collector",
                "collector_version": "1.0.0",
                "configuration_version": "1.0.0",
                "agent_version": "1.0.0",
                "schema_version": "1.0.0",
                "priority": "HIGH",
                "payload": {
                    "process_id": 4120,
                    "parent_process_id": 1,
                    "process_name": "security_sensor",
                    "executable_path": "/usr/local/bin/security_sensor",
                    "command_line": "/usr/local/bin/security_sensor --daemon",
                    "username": "secops_user",
                    "executable_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
                    "lifecycle_action": "STARTED"
                }
            },
            # 2. NETWORK
            {
                "event_id": ev_net_id,
                "sequence_number": 2,
                "event_type": "NETWORK",
                "event_time": now.isoformat(),
                "collector_id": "network_telemetry_collector",
                "collector_version": "1.0.0",
                "configuration_version": "1.0.0",
                "agent_version": "1.0.0",
                "schema_version": "1.0.0",
                "priority": "HIGH",
                "payload": {
                    "process_name": "security_sensor",
                    "local_address": "192.168.1.100",
                    "local_port": 54321,
                    "remote_address": "203.0.113.10",
                    "remote_port": 443,
                    "protocol": "TCP",
                    "direction": "OUTBOUND",
                    "connection_state": "ESTABLISHED",
                    "is_external": True
                }
            },
            # 3. DNS
            {
                "event_id": ev_dns_id,
                "sequence_number": 3,
                "event_type": "DNS",
                "event_time": now.isoformat(),
                "collector_id": "dns_telemetry_collector",
                "collector_version": "1.0.0",
                "configuration_version": "1.0.0",
                "agent_version": "1.0.0",
                "schema_version": "1.0.0",
                "priority": "NORMAL",
                "payload": {
                    "process_name": "security_sensor",
                    "queried_domain": "telemetry-test.example",
                    "query_type": "A",
                    "resolved_addresses": ["203.0.113.10"],
                    "response_status": "NOERROR"
                }
            },
            # 4. AUTHENTICATION
            {
                "event_id": ev_auth_id,
                "sequence_number": 4,
                "event_type": "AUTHENTICATION",
                "event_time": now.isoformat(),
                "collector_id": "authentication_telemetry_collector",
                "collector_version": "1.0.0",
                "configuration_version": "1.0.0",
                "agent_version": "1.0.0",
                "schema_version": "1.0.0",
                "priority": "NORMAL",
                "payload": {
                    "action": "LOGIN_SUCCESS",
                    "username": "secops_user",
                    "auth_method": "FIDO2_U2F",
                    "status": "SUCCESS",
                    "terminal": "console"
                }
            },
            # 5. FILE_METADATA
            {
                "event_id": ev_file_id,
                "sequence_number": 5,
                "event_type": "FILE_METADATA",
                "event_time": now.isoformat(),
                "collector_id": "file_metadata_telemetry_collector",
                "collector_version": "1.0.0",
                "configuration_version": "1.0.0",
                "agent_version": "1.0.0",
                "schema_version": "1.0.0",
                "priority": "HIGH",
                "payload": {
                    "action": "FILE_CREATED",
                    "file_path": "/etc/cyberguard/agent.conf",
                    "filename": "agent.conf",
                    "extension": ".conf",
                    "file_size": 1024,
                    "sha256": "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
                    "username": "secops_user"
                }
            },
            # 6. SYSTEM_SECURITY
            {
                "event_id": ev_sys_id,
                "sequence_number": 6,
                "event_type": "SYSTEM_SECURITY",
                "event_time": now.isoformat(),
                "collector_id": "system_security_telemetry_collector",
                "collector_version": "1.0.0",
                "configuration_version": "1.0.0",
                "agent_version": "1.0.0",
                "schema_version": "1.0.0",
                "priority": "NORMAL",
                "payload": {
                    "action": "SECURITY_POSTURE_BASELINE",
                    "system_integrity_protection": "ENABLED",
                    "platform": "macos"
                }
            },
            # 7. DEVICE_HEALTH
            {
                "event_id": ev_health_id,
                "sequence_number": 7,
                "event_type": "DEVICE_HEALTH",
                "event_time": now.isoformat(),
                "collector_id": "device_health_telemetry_collector",
                "collector_version": "1.0.0",
                "configuration_version": "1.0.0",
                "agent_version": "1.0.0",
                "schema_version": "1.0.0",
                "priority": "LOW",
                "payload": {
                    "agent_version": "1.0.0",
                    "platform": "macos",
                    "agent_uptime_seconds": 3600.0,
                    "memory_usage_mb": 45.2,
                    "disk_free_mb": 150000,
                    "under_pressure": False
                }
            }
        ]
    }

    batch_bytes = json.dumps(batch_payload).encode("utf-8")
    headers = sec.sign_request("POST", "/api/v1/endpoint/telemetry", batch_bytes)

    # Ingest using POST /api/v1/endpoint/telemetry
    resp = client.post("/api/v1/endpoint/telemetry", content=batch_bytes, headers=headers)
    assert resp.status_code == 200
    ingest_res = resp.json()
    assert ingest_res["accepted_count"] == 7
    assert ingest_res["rejected_count"] == 0
    assert ingest_res["duplicate_count"] == 0

    # Verify raw events persisted in DB
    raw_events = db_session.query(EndpointTelemetryEventModel).filter(
        EndpointTelemetryEventModel.workspace_id == workspace
    ).all()
    assert len(raw_events) == 7
    for re in raw_events:
        assert re.status == "NORMALIZED"
        assert re.threat_event_id is not None

    # Verify normalized ThreatEvent records
    threat_events = db_session.query(ThreatEventModel).filter(
        ThreatEventModel.summary.like(f"%{hostname}%")
    ).all()
    assert len(threat_events) == 7

    # Verify Security Knowledge Graph Multi-Hop Relationships:
    rels = db_session.query(RelationshipModel).filter(
        RelationshipModel.workspace_id == workspace
    ).all()
    rel_types = {r.relationship_type for r in rels}

    # Verify expected relationship topologies
    assert "COLLECTS_FROM" in rel_types   # AGENT -> DEVICE (from enrollment)
    assert "HAS_EVENT" in rel_types       # DEVICE -> THREAT_EVENT
    assert "RUNNING_ON" in rel_types      # PROCESS -> DEVICE
    assert "EXECUTED_BY" in rel_types     # PROCESS -> USER
    assert "CONNECTED_TO" in rel_types    # PROCESS -> IP
    assert "QUERIED" in rel_types         # PROCESS -> DOMAIN
    assert "CREATED_ON" in rel_types      # FILE -> DEVICE
    assert "LOGGED_INTO" in rel_types     # USER -> DEVICE

    # Verify observation provenance on relationships
    for r in rels:
        if r.method == "ENDPOINT_TELEMETRY":
            assert r.origin == "OBSERVED"
            assert r.evidence_reference is not None


# ============================================================================
# 2. DEDUPLICATION AND RETRY SEMANTICS
# ============================================================================

def test_telemetry_deduplication_and_retry(client, db_session):
    workspace = f"ws_dedup_{uuid.uuid4().hex[:6]}"
    agent_info = _enroll_test_agent(client, workspace_id=workspace)
    agent_id = agent_info["agent_id"]

    sec = AgentSecurityController(
        agent_id=agent_id,
        key_id=agent_info["key_id"],
        credential_secret=agent_info["credential_secret"]
    )

    ev_id = f"ev-dup-{uuid.uuid4().hex[:8]}"
    batch = {
        "agent_id": agent_id,
        "batch_id": "BATCH-DUP-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events": [{
            "event_id": ev_id,
            "sequence_number": 50,
            "event_type": "DNS",
            "event_time": datetime.now(timezone.utc).isoformat(),
            "collector_id": "dns_telemetry_collector",
            "collector_version": "1.0.0",
            "configuration_version": "1.0.0",
            "agent_version": "1.0.0",
            "schema_version": "1.0.0",
            "priority": "NORMAL",
            "payload": {"queried_domain": "idempotent.example"}
        }]
    }

    batch_bytes = json.dumps(batch).encode("utf-8")
    headers1 = sec.sign_request("POST", "/api/v1/endpoint/telemetry", batch_bytes)

    # 1. First submission
    r1 = client.post("/api/v1/endpoint/telemetry", content=batch_bytes, headers=headers1)
    assert r1.status_code == 200
    assert r1.json()["accepted_count"] == 1
    assert r1.json()["duplicate_count"] == 0

    # 2. Retry submission with same payload
    headers2 = sec.sign_request("POST", "/api/v1/endpoint/telemetry", batch_bytes)
    r2 = client.post("/api/v1/endpoint/telemetry", content=batch_bytes, headers=headers2)
    assert r2.status_code == 200
    assert r2.json()["accepted_count"] == 1  # Idempotently acknowledged
    assert r2.json()["duplicate_count"] == 1

    # Verify only ONE database record exists
    count = db_session.query(EndpointTelemetryEventModel).filter(
        EndpointTelemetryEventModel.event_id == ev_id
    ).count()
    assert count == 1


# ============================================================================
# 3. THREAT MEMORY INDICATOR ENRICHMENT
# ============================================================================

def test_threat_memory_indicator_enrichment(client, db_session):
    workspace = f"ws_tm_{uuid.uuid4().hex[:6]}"
    agent_info = _enroll_test_agent(client, workspace_id=workspace)
    agent_id = agent_info["agent_id"]

    # Seed an indicator into Threat Memory
    malicious_hash = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    from backend.services.threat_memory_service import ThreatMemoryService
    from backend.schemas.threat_memory import MemoryType, ObservationClassification
    ThreatMemoryService.record_observation(
        db=db_session,
        workspace_id=workspace,
        subject_type=MemoryType.HASH,
        value=malicious_hash,
        source_type="ANALYST_INTEL",
        classification=ObservationClassification.MALICIOUS,
        severity="CRITICAL",
        confidence=0.99,
        is_analyst_verified=True
    )
    db_session.commit()
    db_session.rollback()

    sec = AgentSecurityController(
        agent_id=agent_id,
        key_id=agent_info["key_id"],
        credential_secret=agent_info["credential_secret"]
    )

    # Submit event carrying the malicious hash
    ev_id = f"ev-tm-{uuid.uuid4().hex[:8]}"
    batch = {
        "agent_id": agent_id,
        "batch_id": "BATCH-TM-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events": [{
            "event_id": ev_id,
            "sequence_number": 88,
            "event_type": "PROCESS",
            "event_time": datetime.now(timezone.utc).isoformat(),
            "collector_id": "process_telemetry_collector",
            "collector_version": "1.0.0",
            "configuration_version": "1.0.0",
            "agent_version": "1.0.0",
            "schema_version": "1.0.0",
            "priority": "NORMAL",
            "payload": {
                "process_name": "stealth_loader",
                "executable_hash": malicious_hash
            }
        }]
    }

    batch_bytes = json.dumps(batch).encode("utf-8")
    headers = sec.sign_request("POST", "/api/v1/endpoint/telemetry", batch_bytes)
    resp = client.post("/api/v1/endpoint/telemetry", content=batch_bytes, headers=headers)
    assert resp.status_code == 200

    # Find the ThreatEvent generated
    db_session.expire_all()
    te = db_session.query(ThreatEventModel).filter(
        ThreatEventModel.summary.like(f"%stealth_loader%")
    ).first()
    assert te is not None
    # Severity must be elevated to CRITICAL due to threat memory match
    assert te.severity == "CRITICAL"
    assert te.risk_score == 90.0
    assert "ALERT: Matched prior Threat Memory" in te.summary
    meta = json.loads(te.metadata_json)
    assert meta["threat_memory_match"] is not None
    assert malicious_hash in meta["threat_memory_match"]["canonical_key"]


# ============================================================================
# 4. CAPABILITIES AND TELEMETRY QUERY APIS
# ============================================================================

def test_collector_capabilities_and_query_apis(client, db_session):
    # 1. Test capabilities endpoint on host OS
    resp_caps = client.get("/api/v1/endpoint/capabilities")
    assert resp_caps.status_code == 200
    caps = resp_caps.json()
    assert isinstance(caps, list)
    assert len(caps) == 7
    collector_ids = {c["collector_id"] for c in caps}
    assert "process_telemetry_collector" in collector_ids
    assert "network_telemetry_collector" in collector_ids
    assert "dns_telemetry_collector" in collector_ids
    assert "authentication_telemetry_collector" in collector_ids
    assert "system_security_telemetry_collector" in collector_ids
    assert "file_metadata_telemetry_collector" in collector_ids
    assert "device_health_telemetry_collector" in collector_ids

    # 2. Test capabilities when explicitly querying Windows on macOS
    resp_win = client.get("/api/v1/endpoint/capabilities?platform=windows")
    assert resp_win.status_code == 200
    win_caps = resp_win.json()
    for wc in win_caps:
        assert wc["platform"] == "windows"
        assert wc["capability_state"] == "UNAVAILABLE"

    # 3. Test telemetry querying endpoint
    workspace = f"ws_query_{uuid.uuid4().hex[:6]}"
    agent_info = _enroll_test_agent(client, workspace_id=workspace)
    agent_id = agent_info["agent_id"]
    sec = AgentSecurityController(agent_id=agent_id, key_id=agent_info["key_id"], credential_secret=agent_info["credential_secret"])

    batch = {
        "agent_id": agent_id,
        "batch_id": "BATCH-Q-01",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "events": [{
            "event_id": f"ev-q-{uuid.uuid4().hex[:6]}",
            "sequence_number": 1,
            "event_type": "DNS",
            "event_time": datetime.now(timezone.utc).isoformat(),
            "collector_id": "dns_telemetry_collector",
            "collector_version": "1.0.0",
            "configuration_version": "1.0.0",
            "agent_version": "1.0.0",
            "schema_version": "1.0.0",
            "priority": "NORMAL",
            "payload": {"queried_domain": "query-test.example"}
        }]
    }
    b_bytes = json.dumps(batch).encode("utf-8")
    client.post("/api/v1/endpoint/telemetry", content=b_bytes, headers=sec.sign_request("POST", "/api/v1/endpoint/telemetry", b_bytes))

    # Query without filter
    q_all = client.get(f"/api/v1/endpoint/telemetry?workspace_id={workspace}")
    assert q_all.status_code == 200
    assert len(q_all.json()) == 1

    # Query with type filter matching
    q_dns = client.get(f"/api/v1/endpoint/telemetry?workspace_id={workspace}&event_type=DNS")
    assert q_dns.status_code == 200
    assert len(q_dns.json()) == 1

    # Query with non-matching filter
    q_net = client.get(f"/api/v1/endpoint/telemetry?workspace_id={workspace}&event_type=NETWORK")
    assert q_net.status_code == 200
    assert len(q_net.json()) == 0
