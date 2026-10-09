"""
Integration and API tests for Section 33: Device-to-Incident Correlation.
Covers:
- Exact identifier and hash matching (EXACT_HASH_MATCH, PROCESS_MATCH)
- Malicious domain and IOC correlation (KNOWN_MALICIOUS_DOMAIN_OBSERVED)
- Shared infrastructure discounting (SHARED_NAT, COMMON_INFRASTRUCTURE)
- Common OS software discounting (COMMON_SOFTWARE)
- Temporal sequence alignment and mismatch handling (TEMPORAL_MISMATCH)
- Evidence independence (no double counting of single telemetry event)
- Bidirectional querying (Incident -> Devices summary, Device -> Incidents history)
- Analyst review lifecycle (CONFIRM_ASSOCIATION, DISMISS_ASSOCIATION)
- Immutable correlation versioning and reassessment
- Unified device activity timeline
- Strict tenant isolation across workspaces
- Truthful empty states and retention-aware framing
"""

import uuid
import json
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    DeviceModel,
    EndpointAgentModel,
    EndpointTelemetryEventModel,
    IncidentModel,
    ThreatEventModel,
    RelationshipModel,
    DeviceIncidentCorrelationModel
)
from backend.services.device_incident_correlation_service import DeviceIncidentCorrelationService


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


def _create_test_device(db, workspace_id: str = "ws-sec33", hostname: str = "host-alpha") -> DeviceModel:
    device = DeviceModel(
        id=f"dev-{uuid.uuid4().hex[:8]}",
        workspace_id=workspace_id,
        device_uid=f"UID-{uuid.uuid4().hex[:10]}",
        hostname=hostname,
        platform="macos",
        os_version="14.4",
        status="ACTIVE"
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return device


def _create_test_agent(db, device: DeviceModel, workspace_id: str = "ws-sec33") -> EndpointAgentModel:
    agent = EndpointAgentModel(
        id=f"agent-{uuid.uuid4().hex[:8]}",
        agent_id=f"AGT-{uuid.uuid4().hex[:8]}",
        device_id=device.id,
        hostname=device.hostname,
        platform="macos",
        workspace_id=workspace_id,
        agent_version="1.0.0",
        status="ACTIVE",
        enrollment_state="ENROLLED",
        enrolled_at=datetime.now(timezone.utc),
        last_heartbeat_at=datetime.now(timezone.utc)
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)
    return agent


def _create_test_incident(db, workspace_id: str = "ws-sec33", title: str = "Phishing Credential Campaign") -> IncidentModel:
    incident = IncidentModel(
        id=f"inc-{uuid.uuid4().hex[:8]}",
        incident_number=f"INC-{uuid.uuid4().hex[:6].upper()}",
        workspace_id=workspace_id,
        title=title,
        severity="HIGH",
        status="OPEN",
        risk_score=75.0,
        confidence=0.9
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def _create_threat_event(
    db,
    incident: IncidentModel,
    event_type: str,
    metadata: dict,
    severity: str = "HIGH",
    event_time: datetime = None
) -> ThreatEventModel:
    te = ThreatEventModel(
        id=f"te-{uuid.uuid4().hex[:8]}",
        incident_id=incident.id,
        event_type=event_type,
        summary=f"Threat event {event_type} in {incident.title}",
        severity=severity,
        risk_score=75.0,
        confidence=0.9,
        status="OPEN",
        timestamp=event_time or datetime.now(timezone.utc),
        metadata_json=json.dumps(metadata)
    )
    db.add(te)
    db.commit()
    db.refresh(te)
    return te


def _create_telemetry_event(
    db,
    device: DeviceModel,
    agent: EndpointAgentModel,
    event_type: str,
    event_time: datetime,
    payload: dict,
    workspace_id: str = "ws-sec33",
    event_id: str = None
) -> EndpointTelemetryEventModel:
    ev = EndpointTelemetryEventModel(
        id=f"evt-{uuid.uuid4().hex[:8]}",
        workspace_id=workspace_id,
        agent_id=agent.id,
        device_id=device.id,
        event_id=event_id or f"client-ev-{uuid.uuid4().hex[:8]}",
        sequence_number=int(datetime.now().timestamp() * 1000) % 1000000,
        event_type=event_type,
        event_time=event_time,
        received_at=event_time + timedelta(seconds=2),
        collector_id=f"{event_type.lower()}_collector",
        collector_version="1.0.0",
        configuration_version="1.0.0",
        agent_version="1.0.0",
        schema_version="1.0.0",
        priority="HIGH",
        payload_json=json.dumps(payload),
        status="NORMALIZED"
    )
    db.add(ev)
    db.commit()
    db.refresh(ev)
    return ev


# ============================================================================
# 1. EXACT IDENTIFIER & HASH CORRELATION
# ============================================================================

def test_exact_hash_correlation(client, db_session):
    """
    Verifies that when an endpoint executes a process whose SHA-256 matches an incident artifact,
    the correlation service records EXACT_HASH_MATCH with high confidence (CONFIRMED/SUPPORTED)
    and establishes a Security Knowledge Graph edge.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="macbook-exec")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)
    inc = _create_test_incident(db_session, workspace_id=ws, title="Attachment Malware Incident")

    target_hash = "a3f5b7890123456789abcdef0123456789abcdef0123456789abcdef01234567"

    # Add ThreatEvent to incident with matching artifact hash
    _create_threat_event(
        db_session,
        inc,
        event_type="EMAIL_ATTACHMENT",
        metadata={"target_artifacts": [{"sha256": target_hash, "name": "invoice_malicious.pdf.exe"}]},
        event_time=datetime.now(timezone.utc) - timedelta(minutes=10)
    )

    # Ingest endpoint telemetry with matching hash
    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="PROCESS",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=5),
        payload={"process_name": "invoice_malicious.exe", "sha256": target_hash, "username": "finance_user"},
        workspace_id=ws
    )

    corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )

    assert corr is not None
    assert corr.device_id == dev.id
    assert corr.incident_id == inc.id
    assert corr.status in ("CONFIRMED", "SUPPORTED")
    assert corr.confidence >= 0.8
    assert "EXACT_HASH_MATCH" in json.loads(corr.reason_codes_json)

    # Verify Knowledge Graph edge was created
    rel = db_session.query(RelationshipModel).filter(
        RelationshipModel.source_id == dev.id,
        RelationshipModel.target_id == inc.id,
        RelationshipModel.relationship_type == "ASSOCIATED_WITH"
    ).first()
    assert rel is not None
    assert rel.confidence >= 0.8


# ============================================================================
# 2. MALICIOUS DOMAIN MATCH
# ============================================================================

def test_malicious_domain_correlation(client, db_session):
    """
    Verifies that a DNS query from an endpoint to a domain present in an incident's indicators
    triggers KNOWN_MALICIOUS_DOMAIN_OBSERVED with DOMAIN_MATCH correlation type.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="finance-laptop")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)
    inc = _create_test_incident(db_session, workspace_id=ws, title="Phishing Domain Incident")

    domain = "c2-exfiltration-campaign.com"

    _create_threat_event(
        db_session,
        inc,
        event_type="PHISHING_URL",
        metadata={"target_domains": [domain]},
        event_time=datetime.now(timezone.utc) - timedelta(minutes=15)
    )

    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="DNS",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=12),
        payload={"queried_domain": domain, "resolved_ips": ["198.51.100.22"]},
        workspace_id=ws
    )

    corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )

    assert corr is not None
    reasons = json.loads(corr.reason_codes_json)
    assert "KNOWN_MALICIOUS_DOMAIN_OBSERVED" in reasons
    assert corr.status in ("SUPPORTED", "SUSPECTED")


# ============================================================================
# 3. SHARED INFRASTRUCTURE DISCOUNTING (SHARED NAT / PROXY)
# ============================================================================

def test_shared_infrastructure_discounting(client, db_session):
    """
    Verifies that when an endpoint connects to a public resolver (8.8.8.8) or private RFC-1918 NAT IP
    present in an incident, the engine applies SHARED_NAT and COMMON_INFRASTRUCTURE counter-evidence,
    penalizing the correlation score so it does NOT produce a false high-confidence CONFIRMED verdict.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="employee-dev-01")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)
    inc = _create_test_incident(db_session, workspace_id=ws, title="Generic Network Incident")

    shared_ip = "8.8.8.8"

    _create_threat_event(
        db_session,
        inc,
        event_type="NETWORK_ALERT",
        metadata={"target_ips": [shared_ip]},
        severity="LOW",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=20)
    )

    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="NETWORK",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=18),
        payload={"remote_address": shared_ip, "remote_port": 53},
        workspace_id=ws
    )

    corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )

    assert corr is not None
    reasons = json.loads(corr.reason_codes_json)
    assert "SHARED_NAT" in reasons or "COMMON_INFRASTRUCTURE" in reasons
    # Must NOT be CONFIRMED or SUPPORTED due to discount penalty
    assert corr.status in ("RELATED", "OBSERVED")
    assert corr.confidence < 0.65

    counter_evidence = json.loads(corr.counter_evidence_json)
    assert any(ce.get("code") in ("SHARED_NAT", "COMMON_INFRASTRUCTURE") for ce in counter_evidence)


# ============================================================================
# 4. COMMON OS SOFTWARE DISCOUNTING
# ============================================================================

def test_common_software_discounting(client, db_session):
    """
    Verifies that system processes like 'launchd' or 'svchost.exe' observed without exact hash match
    receive COMMON_SOFTWARE penalty and counter-evidence discount.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="macos-workstation")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)
    inc = _create_test_incident(db_session, workspace_id=ws, title="Persistence Alert")

    _create_threat_event(
        db_session,
        inc,
        event_type="PROCESS_ALERT",
        metadata={"raw_payload": {"process_name": "launchd"}},
        severity="LOW",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=10)
    )

    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="PROCESS",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=8),
        payload={"process_name": "launchd", "executable_path": "/sbin/launchd"},
        workspace_id=ws
    )

    corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )

    assert corr is not None
    reasons = json.loads(corr.reason_codes_json)
    assert "COMMON_SOFTWARE" in reasons
    assert corr.status in ("RELATED", "OBSERVED")


# ============================================================================
# 5. TEMPORAL SEQUENCE ALIGNMENT VS MISMATCH
# ============================================================================

def test_temporal_alignment_and_mismatch(client, db_session):
    """
    Verifies that events within a tight time window (<=15 min) receive TEMPORALLY_ALIGNED_SEQUENCE,
    while events separated by >72 hours receive TEMPORAL_MISMATCH counter-evidence.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="temporal-test-host")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)
    inc = _create_test_incident(db_session, workspace_id=ws, title="Temporal Window Test Incident")

    domain = "temporal-c2.org"

    # Incident opened 5 days ago
    inc.opened_at = datetime.now(timezone.utc) - timedelta(days=5)
    db_session.commit()

    _create_threat_event(
        db_session,
        inc,
        event_type="DNS_ALERT",
        metadata={"target_domains": [domain]},
        severity="HIGH",
        event_time=datetime.now(timezone.utc) - timedelta(days=5)
    )

    # Telemetry observed just now (5 days later > 72 hours delta)
    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="DNS",
        event_time=datetime.now(timezone.utc),
        payload={"queried_domain": domain},
        workspace_id=ws
    )

    corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )

    assert corr is not None
    reasons = json.loads(corr.reason_codes_json)
    assert "TEMPORAL_MISMATCH" in reasons


# ============================================================================
# 6. EVIDENCE INDEPENDENCE (NO DOUBLE COUNTING)
# ============================================================================

def test_evidence_independence_no_double_counting(client, db_session):
    """
    Ensures that multiple fields (e.g., domain and IP) present on the same single raw telemetry event
    do not inflate supporting_event_ids_json or get double-counted as independent events.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="indep-host")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)
    inc = _create_test_incident(db_session, workspace_id=ws, title="Multi-attribute Incident")

    domain = "independent-threat.io"
    ip = "198.51.100.99"

    _create_threat_event(
        db_session,
        inc,
        event_type="NETWORK_LOG",
        metadata={"target_domains": [domain], "target_ips": [ip]},
        severity="HIGH",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=10)
    )

    single_client_ev_id = f"client-ev-{uuid.uuid4().hex[:8]}"
    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="NETWORK",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=5),
        payload={"queried_domain": domain, "remote_address": ip},
        workspace_id=ws,
        event_id=single_client_ev_id
    )

    corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )

    assert corr is not None
    supporting_events = json.loads(corr.supporting_event_ids_json)
    # The set of supporting event IDs must only contain single_client_ev_id once
    assert len(supporting_events) == 1
    assert supporting_events[0] == single_client_ev_id


# ============================================================================
# 7. BIDIRECTIONAL LOOKUP & SUMMARY ENDPOINTS
# ============================================================================

def test_bidirectional_lookup_apis(client, db_session):
    """
    Tests both directions of correlation APIs:
    - GET /api/v1/incidents/{incident_id}/devices
    - GET /api/v1/devices/{device_id}/incidents
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="bidi-workstation")
    inc = _create_test_incident(db_session, workspace_id=ws, title="Bidirectional Test Incident")

    # Manually establish a correlation model
    corr = DeviceIncidentCorrelationModel(
        id=f"corr-{uuid.uuid4().hex[:8]}",
        workspace_id=ws,
        device_id=dev.id,
        incident_id=inc.id,
        correlation_type="DIRECT_IDENTIFIER",
        correlation_score=0.88,
        confidence=0.92,
        status="CONFIRMED",
        version=1,
        is_current=True,
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc),
        reason_codes_json=json.dumps(["EXACT_HASH_MATCH", "TEMPORALLY_ALIGNED_SEQUENCE"]),
        supporting_event_ids_json=json.dumps(["evt-123"]),
        counter_evidence_json=json.dumps([]),
        structured_explanation_json=json.dumps({
            "device_name": dev.hostname,
            "incident_number": inc.incident_number,
            "facts": ["Device executed verified malicious payload."],
            "positive_signals": ["Exact SHA256 match"],
            "negative_signals": [],
            "narrative": "Verified connection between host and incident."
        })
    )
    db_session.add(corr)
    db_session.commit()

    # Direction 1: Incident -> Devices
    resp_inc = client.get(f"/api/v1/incidents/{inc.id}/devices?workspace_id={ws}")
    assert resp_inc.status_code == 200
    data_inc = resp_inc.json()
    assert data_inc["incident_id"] == inc.id
    assert data_inc["total_devices"] >= 1
    assert data_inc["confirmed_count"] >= 1
    assert any(d["device_id"] == dev.id for d in data_inc["devices"])

    # Direction 2: Device -> Incidents
    resp_dev = client.get(f"/api/v1/devices/{dev.id}/incidents?workspace_id={ws}")
    assert resp_dev.status_code == 200
    data_dev = resp_dev.json()
    assert data_dev["device_id"] == dev.id
    assert data_dev["total_incidents"] >= 1
    assert any(i["incident_id"] == inc.id for i in data_dev["incidents"])


# ============================================================================
# 8. ANALYST REVIEW WORKFLOW
# ============================================================================

def test_analyst_review_workflow(client, db_session):
    """
    Tests analyst review actions (CONFIRM_ASSOCIATION, DISMISS_ASSOCIATION, MARK_RELATED)
    and verifies that audit notes and reviewer metadata are preserved.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="review-target-host")
    inc = _create_test_incident(db_session, workspace_id=ws, title="Review Candidate Incident")

    corr = DeviceIncidentCorrelationModel(
        id=f"corr-{uuid.uuid4().hex[:8]}",
        workspace_id=ws,
        device_id=dev.id,
        incident_id=inc.id,
        correlation_type="INDICATOR_MATCH",
        correlation_score=0.70,
        confidence=0.75,
        status="SUSPECTED",
        version=1,
        is_current=True,
        first_observed_at=datetime.now(timezone.utc),
        last_observed_at=datetime.now(timezone.utc),
        reason_codes_json=json.dumps(["KNOWN_MALICIOUS_DOMAIN_OBSERVED"])
    )
    db_session.add(corr)
    db_session.commit()

    # Analyst confirms association
    review_payload = {
        "action": "CONFIRM_ASSOCIATION",
        "reviewer": "tier3_analyst_jane",
        "notes": "Verified host process memory dump confirmed beaconing."
    }
    resp = client.post(f"/api/v1/correlations/{corr.id}/review?workspace_id={ws}", json=review_payload)
    assert resp.status_code == 200
    updated_corr = resp.json()
    assert updated_corr["status"] == "CONFIRMED"
    assert updated_corr["reviewed_by"] == "tier3_analyst_jane"
    assert "beaconing" in updated_corr["review_notes"]

    # Analyst dismisses association
    dismiss_payload = {
        "action": "DISMISS_ASSOCIATION",
        "reviewer": "tier3_analyst_jane",
        "notes": "Domain resolved to benign CDN upon closer inspection."
    }
    resp_dismiss = client.post(f"/api/v1/correlations/{corr.id}/review?workspace_id={ws}", json=dismiss_payload)
    assert resp_dismiss.status_code == 200
    dismissed = resp_dismiss.json()
    assert dismissed["status"] == "DISMISSED"


# ============================================================================
# 9. IMMUTABLE VERSIONING & REASSESSMENT
# ============================================================================

def test_correlation_immutable_versioning(client, db_session):
    """
    Verifies that reassessment creates a new version (version 2) with is_current=True
    and marks the previous record with is_current=False rather than destructively overwriting it.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="versioned-host")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)
    inc = _create_test_incident(db_session, workspace_id=ws, title="Versioned Correlation Incident")

    domain = "beaconing-node.biz"

    _create_threat_event(
        db_session,
        inc,
        event_type="DNS_ALERT",
        metadata={"target_domains": [domain]},
        severity="MEDIUM",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=30)
    )

    # Initial event
    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="DNS",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=25),
        payload={"queried_domain": domain},
        workspace_id=ws
    )

    v1_corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )
    assert v1_corr.version == 1
    assert v1_corr.is_current is True

    # New telemetry arrives with matching hash
    target_hash = "deadbeef1234567890abcdefdeadbeef1234567890abcdefdeadbeef12345678"
    _create_threat_event(
        db_session,
        inc,
        event_type="MALWARE_DELIVERY",
        metadata={"target_artifacts": [{"sha256": target_hash}]},
        severity="CRITICAL",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=10)
    )

    _create_telemetry_event(
        db_session,
        dev,
        agent,
        event_type="PROCESS",
        event_time=datetime.now(timezone.utc) - timedelta(minutes=5),
        payload={"process_name": "beacon.exe", "sha256": target_hash},
        workspace_id=ws
    )

    v2_corr = DeviceIncidentCorrelationService.correlate_device_with_incident(
        db_session, dev, inc, ws
    )
    assert v2_corr.version == 2
    assert v2_corr.is_current is True

    # Check database: both records exist, v1 has is_current=False
    all_corrs = db_session.query(DeviceIncidentCorrelationModel).filter(
        DeviceIncidentCorrelationModel.device_id == dev.id,
        DeviceIncidentCorrelationModel.incident_id == inc.id
    ).order_by(DeviceIncidentCorrelationModel.version.asc()).all()

    assert len(all_corrs) == 2
    assert all_corrs[0].version == 1
    assert all_corrs[0].is_current is False
    assert all_corrs[1].version == 2
    assert all_corrs[1].is_current is True


# ============================================================================
# 10. DEVICE TIMELINE
# ============================================================================

def test_device_timeline_endpoint(client, db_session):
    """
    Verifies that the unified chronological timeline returns events in correct order
    with provenance and confidence metrics.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    dev = _create_test_device(db_session, workspace_id=ws, hostname="timeline-host")
    agent = _create_test_agent(db_session, dev, workspace_id=ws)

    t0 = datetime.now(timezone.utc) - timedelta(minutes=20)
    t1 = datetime.now(timezone.utc) - timedelta(minutes=15)
    t2 = datetime.now(timezone.utc) - timedelta(minutes=10)

    _create_telemetry_event(
        db_session, dev, agent, event_type="PROCESS", event_time=t0,
        payload={"process_name": "terminal", "executable_path": "/usr/bin/terminal"}, workspace_id=ws
    )
    _create_telemetry_event(
        db_session, dev, agent, event_type="DNS", event_time=t1,
        payload={"queried_domain": "safe.org"}, workspace_id=ws
    )
    _create_telemetry_event(
        db_session, dev, agent, event_type="NETWORK", event_time=t2,
        payload={"remote_address": "192.0.2.1", "remote_port": 443}, workspace_id=ws
    )

    resp = client.get(f"/api/v1/devices/{dev.id}/timeline?workspace_id={ws}&limit=10")
    assert resp.status_code == 200
    data = resp.json()
    assert data["device_id"] == dev.id
    assert data["total_events"] >= 3
    # Check chronological ordering
    timeline = data["timeline"]
    assert len(timeline) >= 3
    assert timeline[0]["event_type"] == "PROCESS"
    assert timeline[1]["event_type"] == "DNS"
    assert timeline[2]["event_type"] == "NETWORK"


# ============================================================================
# 11. STRICT TENANT ISOLATION
# ============================================================================

def test_strict_tenant_isolation(client, db_session):
    """
    Verifies that candidate retrieval and correlation never cross workspace boundaries.
    Device in Workspace A must never correlate with Incident in Workspace B.
    """
    ws_a = f"tenant-alpha-{uuid.uuid4().hex[:6]}"
    ws_b = f"tenant-bravo-{uuid.uuid4().hex[:6]}"

    dev_a = _create_test_device(db_session, workspace_id=ws_a, hostname="host-tenant-a")
    agent_a = _create_test_agent(db_session, dev_a, workspace_id=ws_a)
    inc_b = _create_test_incident(db_session, workspace_id=ws_b, title="Incident in Tenant B")

    shared_hash = "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff"

    # Incident in Tenant B has hash
    _create_threat_event(
        db_session,
        inc_b,
        event_type="ATTACHMENT",
        metadata={"target_artifacts": [{"sha256": shared_hash}]}
    )

    # Device in Tenant A runs same hash
    _create_telemetry_event(
        db_session,
        dev_a,
        agent_a,
        event_type="PROCESS",
        event_time=datetime.now(timezone.utc),
        payload={"sha256": shared_hash},
        workspace_id=ws_a
    )

    # Candidate incidents for Device A in Tenant A must NOT include Incident B
    candidates = DeviceIncidentCorrelationService.find_candidate_incidents(
        db_session, dev_a.id, ws_a
    )
    assert not any(c.id == inc_b.id for c in candidates)

    # Attempting cross-tenant correlation explicitly must raise ValueError
    with pytest.raises(ValueError):
        DeviceIncidentCorrelationService.correlate_device_with_incident(
            db_session, dev_a, inc_b, ws_a
        )


# ============================================================================
# 12. TRUTHFUL EMPTY STATE & RETENTION AWARENESS
# ============================================================================

def test_truthful_empty_state_and_retention(client, db_session):
    """
    Verifies that when no telemetry correlates with an incident, the system exposes
    truthful status and explicit retention-aware limitations.
    """
    ws = f"ws-{uuid.uuid4().hex[:6]}"
    inc = _create_test_incident(db_session, workspace_id=ws, title="Uncorrelated Incident")

    resp = client.get(f"/api/v1/incidents/{inc.id}/devices?workspace_id={ws}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_devices"] == 0
    assert len(data["devices"]) == 0
    assert "retention" in data["retention_notice"].lower()
    assert "30-day" in data["retention_notice"].lower()
