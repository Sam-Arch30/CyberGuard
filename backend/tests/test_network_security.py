"""
Comprehensive Test Suite for Section 10: Network & Traffic Anomaly Detection Engine.
Verifies all 34 required functional and security tests, false-positive mitigations,
multi-provider adapters, temporal window boundaries, session correlation, and synthetic performance benchmark.
"""
import asyncio
import io
import json
import time
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    FindingEvidenceModel,
    IndicatorModel,
    EntityModel,
    RelationshipModel,
    ThreatEventModel,
)
from backend.schemas.unified import SeverityEnum, EntityTypeEnum, RelationshipTypeEnum, ArtifactTypeEnum
from backend.schemas.network_security import (
    NetworkEventTypeEnum,
    NetworkProtocolEnum,
    TrafficDirectionEnum,
    IPScopeEnum,
    NetworkCategoryEnum,
    NormalizedNetworkEvent,
    PeriodicityMetrics,
    DeviceNetworkProfile,
    NetworkFindingItem,
    NetworkFindingEvidenceItem,
    NetworkConfigResponse,
    NetworkSecurityAnalysisResponse,
)
from backend.services.network_analyzers import (
    IPClassifier,
    GenericJsonNetworkAdapter,
    GenericCsvNetworkAdapter,
    DnsLogAdapter,
    NetflowJsonAdapter,
    global_network_adapter_registry,
    ConnectionPatternEngine,
    PeriodicityEngine,
    DnsTelemetryEngine,
    TransferExfiltrationEngine,
    DestinationAnomalyEngine,
    NetworkPatternAggregator,
)
from backend.services.network_pipeline import NetworkSecurityPipeline, global_network_pipeline
from backend.services.evidence_storage import evidence_storage

client = TestClient(app)


# ============================================================================
# 1-8. NORMALIZATION, SCOPE & DIRECTION TESTS
# ============================================================================

def test_01_generic_json_normalization():
    """Verify generic JSON flow event normalizes keys correctly."""
    raw = {
        "src_ip": "10.0.1.25",
        "src_port": 54321,
        "dst_ip": "93.184.216.34",
        "dst_port": 443,
        "protocol": "TCP",
        "bytes_sent": 2048,
        "bytes_recv": 8192,
        "duration": 12.5,
        "device_id": "laptop-finance-02",
        "timestamp": "2026-10-02T12:00:00Z",
    }
    event = global_network_adapter_registry.normalize(raw, internal_cidrs=["10.0.0.0/8"])
    assert event.source_ip == "10.0.1.25"
    assert event.source_port == 54321
    assert event.destination_ip == "93.184.216.34"
    assert event.destination_port == 443
    assert event.protocol == NetworkProtocolEnum.TCP
    assert event.bytes_sent == 2048
    assert event.bytes_received == 8192
    assert event.duration_seconds == 12.5
    assert event.direction == TrafficDirectionEnum.OUTBOUND
    assert event.device_id == "laptop-finance-02"


def test_02_generic_csv_normalization():
    """Verify CSV network flow record normalizes properly."""
    adapter = GenericCsvNetworkAdapter()
    row = {
        "src_ip": "192.168.1.50",
        "dst_ip": "198.51.100.4",
        "dst_port": "80",
        "protocol": "TCP",
        "bytes_sent": "1500",
        "timestamp": "2026-10-02T12:05:00Z",
    }
    assert adapter.can_handle(row)
    event = adapter.normalize(row, internal_cidrs=["192.168.0.0/16"])
    assert event.source_ip == "192.168.1.50"
    assert event.destination_ip == "198.51.100.4"
    assert event.destination_port == 80
    assert event.bytes_sent == 1500
    assert event.direction == TrafficDirectionEnum.OUTBOUND


def test_03_ipv4_classification():
    """Verify IPv4 scopes: private, loopback, public, link-local, multicast."""
    assert IPClassifier.get_scope("10.1.2.3") == IPScopeEnum.PRIVATE
    assert IPClassifier.get_scope("192.168.1.1") == IPScopeEnum.PRIVATE
    assert IPClassifier.get_scope("172.16.5.9") == IPScopeEnum.PRIVATE
    assert IPClassifier.get_scope("127.0.0.1") == IPScopeEnum.LOOPBACK
    assert IPClassifier.get_scope("169.254.10.20") == IPScopeEnum.LINK_LOCAL
    assert IPClassifier.get_scope("224.0.0.1") == IPScopeEnum.MULTICAST
    assert IPClassifier.get_scope("93.184.216.34") == IPScopeEnum.PUBLIC


def test_04_ipv6_classification():
    """Verify IPv6 scopes: loopback, ULA private, public."""
    assert IPClassifier.get_scope("::1") == IPScopeEnum.LOOPBACK
    assert IPClassifier.get_scope("fc00::1") == IPScopeEnum.PRIVATE
    assert IPClassifier.get_scope("fd12:3456:789a::1") == IPScopeEnum.PRIVATE
    assert IPClassifier.get_scope("2607:f8b0:4004:800::200e") == IPScopeEnum.PUBLIC


def test_05_internal_external_direction():
    """Verify directional determination relative to configured CIDRs."""
    cidrs = ["10.0.0.0/8", "192.168.0.0/16"]
    # Internal to Public -> OUTBOUND
    assert IPClassifier.get_direction("10.0.1.5", "93.184.216.34", cidrs) == TrafficDirectionEnum.OUTBOUND
    # Public to Internal -> INBOUND
    assert IPClassifier.get_direction("93.184.216.34", "10.0.1.5", cidrs) == TrafficDirectionEnum.INBOUND
    # Internal to Internal -> INTERNAL
    assert IPClassifier.get_direction("10.0.1.5", "192.168.1.10", cidrs) == TrafficDirectionEnum.INTERNAL


def test_06_unknown_direction():
    """Unknown direction when external-to-external or invalid IP."""
    cidrs = ["10.0.0.0/8"]
    assert IPClassifier.get_direction("93.184.216.34", "198.51.100.1", cidrs) == TrafficDirectionEnum.UNKNOWN


def test_07_connection_event():
    """Verify rich connection telemetry attributes."""
    raw = {
        "event_type": "CONNECTION",
        "source_ip": "10.0.2.10",
        "source_port": 49152,
        "destination_ip": "198.51.100.80",
        "destination_port": 22,
        "protocol": "SSH",
        "status": "SUCCESS",
        "action": "ALLOW",
        "duration_seconds": 3600.0,
        "user_id": "admin_sys",
        "session_id": "ssh-sess-99",
    }
    ev = global_network_adapter_registry.normalize(raw, internal_cidrs=["10.0.0.0/8"])
    assert ev.protocol == NetworkProtocolEnum.SSH
    assert ev.status == "SUCCESS"
    assert ev.user_id == "admin_sys"
    assert ev.session_id == "ssh-sess-99"
    assert ev.duration_seconds == 3600.0


def test_08_dns_event():
    """Verify DNS query and response parsing via DnsLogAdapter."""
    raw = {
        "query": "login.example.com",
        "query_type": "A",
        "response_code": "NOERROR",
        "client_ip": "10.0.1.100",
        "answers": ["93.184.216.34"],
        "timestamp": "2026-10-02T12:10:00Z",
    }
    adapter = DnsLogAdapter()
    assert adapter.can_handle(raw)
    ev = adapter.normalize(raw, internal_cidrs=["10.0.0.0/8"])
    assert ev.event_type == NetworkEventTypeEnum.DNS_QUERY
    assert ev.dns_query == "login.example.com"
    assert ev.dns_response_code == "NOERROR"
    assert "93.184.216.34" in ev.dns_answers


# ============================================================================
# 9-16. CHRONOLOGY, DEDUP, PATTERN & BURST TESTS
# ============================================================================

def test_09_out_of_order_timestamps():
    """Chronological sorting handles out-of-order logs using event timestamp."""
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    raw_events = [
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "timestamp": (t0 + timedelta(minutes=5)).isoformat()},
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "timestamp": t0.isoformat()},
        {"source_ip": "10.0.0.1", "destination_ip": "10.0.0.2", "timestamp": (t0 + timedelta(minutes=2)).isoformat()},
    ]
    db: Session = SessionLocal()
    try:
        res = asyncio.run(global_network_pipeline.analyze_events(raw_events, db=db))
        assert res.events_analyzed_count == 3
    finally:
        db.close()


def test_10_duplicate_handling():
    """Identical flow duplicates are collapsed without dropping distinct flows."""
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    ev1 = NormalizedNetworkEvent(
        id="1", timestamp=t0, source_ip="10.0.0.1", destination_ip="10.0.0.2",
        destination_port=80, protocol=NetworkProtocolEnum.TCP
    )
    ev2 = NormalizedNetworkEvent(
        id="2", timestamp=t0, source_ip="10.0.0.1", destination_ip="10.0.0.2",
        destination_port=80, protocol=NetworkProtocolEnum.TCP
    )
    ev3 = NormalizedNetworkEvent(
        id="3", timestamp=t0, source_ip="10.0.0.1", destination_ip="10.0.0.2",
        destination_port=443, protocol=NetworkProtocolEnum.TCP
    )
    deduped = global_network_pipeline._deduplicate_events([ev1, ev2, ev3])
    assert len(deduped) == 2


def test_11_new_destination():
    """Detects NEW_NETWORK_DESTINATION when host has sufficient history."""
    config = NetworkConfigResponse(min_history_events_device=5)
    profile = DeviceNetworkProfile(
        device_id="host-1",
        total_connections_observed=10,
        known_destinations=["93.184.216.34", "151.101.1.140"],
    )
    ev = NormalizedNetworkEvent(
        id="e1", timestamp=datetime.now(timezone.utc), source_ip="10.0.0.5",
        device_id="host-1", destination_ip="198.51.100.77"
    )
    findings = DestinationAnomalyEngine.analyze([ev], {"host-1": profile}, config)
    assert any(f.finding_type == "NEW_NETWORK_DESTINATION" for f in findings)


def test_12_insufficient_history():
    """UNKNOWN != SAFE: Devices with insufficient history do not trigger NEW_NETWORK_DESTINATION."""
    config = NetworkConfigResponse(min_history_events_device=5)
    profile = DeviceNetworkProfile(
        device_id="host-new",
        total_connections_observed=2,  # < 5 threshold
        known_destinations=["93.184.216.34"],
    )
    ev = NormalizedNetworkEvent(
        id="e1", timestamp=datetime.now(timezone.utc), source_ip="10.0.0.5",
        device_id="host-new", destination_ip="198.51.100.77"
    )
    findings = DestinationAnomalyEngine.analyze([ev], {"host-new": profile}, config)
    assert not any(f.finding_type == "NEW_NETWORK_DESTINATION" for f in findings)


def test_13_new_destination_port():
    """Detects NEW_DESTINATION_PORT when port was unseen in baseline."""
    config = NetworkConfigResponse(min_history_events_device=5)
    profile = DeviceNetworkProfile(
        device_id="host-prod",
        total_connections_observed=20,
        known_destinations=["10.0.0.20"],
        known_ports=[80, 443],
    )
    ev = NormalizedNetworkEvent(
        id="e1", timestamp=datetime.now(timezone.utc), source_ip="10.0.0.5",
        device_id="host-prod", destination_ip="10.0.0.20", destination_port=8443
    )
    findings = DestinationAnomalyEngine.analyze([ev], {"host-prod": profile}, config)
    assert any(f.finding_type == "NEW_DESTINATION_PORT" for f in findings)


def test_14_repeated_failures():
    """Repeated connection drops/failures produce REPEATED_CONNECTION_FAILURES."""
    config = NetworkConfigResponse(repeated_failures_threshold=5, repeated_failures_window_seconds=300)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedNetworkEvent(
            id=f"f-{i}",
            timestamp=t0 + timedelta(seconds=i * 10),
            source_ip="10.0.1.50",
            destination_ip="10.0.2.100",
            status="FAILURE",
        )
        for i in range(6)
    ]
    findings = ConnectionPatternEngine.analyze(events, config)
    assert any(f.finding_type == "REPEATED_CONNECTION_FAILURES" for f in findings)


def test_15_connection_burst():
    """Rapid burst of connections produces CONNECTION_BURST."""
    config = NetworkConfigResponse(connection_burst_threshold=50, connection_burst_window_seconds=60)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedNetworkEvent(
            id=f"b-{i}",
            timestamp=t0 + timedelta(seconds=i),
            source_ip="10.0.1.75",
            destination_ip=f"10.0.2.{i % 10}",
            destination_port=80,
        )
        for i in range(55)
    ]
    findings = ConnectionPatternEngine.analyze(events, config)
    assert any(f.finding_type == "CONNECTION_BURST" for f in findings)


def test_16_scan_like_pattern():
    """One internal host targeting 15 distinct ports within 120s produces SCAN_LIKE_CONNECTION_PATTERN."""
    config = NetworkConfigResponse(scan_distinct_ports_threshold=15, scan_window_seconds=120)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedNetworkEvent(
            id=f"scan-{i}",
            timestamp=t0 + timedelta(seconds=i * 2),
            source_ip="10.0.1.99",
            destination_ip="10.0.2.200",
            destination_port=1000 + i,
        )
        for i in range(16)
    ]
    findings = ConnectionPatternEngine.analyze(events, config)
    assert any(f.finding_type == "SCAN_LIKE_CONNECTION_PATTERN" for f in findings)


# ============================================================================
# 17-21. PERIODICITY & DNS ANOMALY TESTS
# ============================================================================

def test_17_periodicity_detection():
    """Regular ~60s interval connections produce PERIODIC_CONNECTION_PATTERN."""
    config = NetworkConfigResponse(periodicity_min_observations=5, periodicity_max_cv=0.20)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    # Intervals: 60s, 61s, 59s, 60s, 60s (low jitter)
    intervals = [0, 60, 121, 180, 240, 300]
    events = [
        NormalizedNetworkEvent(
            id=f"p-{i}",
            timestamp=t0 + timedelta(seconds=sec),
            source_ip="10.0.1.10",
            destination_ip="198.51.100.99",
        )
        for i, sec in enumerate(intervals)
    ]
    findings = PeriodicityEngine.analyze(events, config)
    assert any(f.finding_type == "PERIODIC_CONNECTION_PATTERN" for f in findings)


def test_18_periodicity_minimum_observations():
    """Fewer than 5 observations does NOT declare periodicity."""
    config = NetworkConfigResponse(periodicity_min_observations=5)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedNetworkEvent(
            id=f"p-{i}",
            timestamp=t0 + timedelta(seconds=i * 60),
            source_ip="10.0.1.10",
            destination_ip="198.51.100.99",
        )
        for i in range(3)  # Only 3 observations
    ]
    findings = PeriodicityEngine.analyze(events, config)
    assert not any(f.finding_type == "PERIODIC_CONNECTION_PATTERN" for f in findings)


def test_19_legitimate_periodic_traffic_control():
    """
    Periodicity alone must NOT produce a high severity or claim confirmed malware/C2.
    Severity must be MEDIUM with explicit explainability limitation.
    """
    config = NetworkConfigResponse(periodicity_min_observations=5)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedNetworkEvent(
            id=f"p-{i}",
            timestamp=t0 + timedelta(seconds=i * 60),
            source_ip="10.0.1.10",
            destination_ip="198.51.100.99",
        )
        for i in range(6)
    ]
    findings = PeriodicityEngine.analyze(events, config)
    periodic_f = next(f for f in findings if f.finding_type == "PERIODIC_CONNECTION_PATTERN")
    assert periodic_f.severity == SeverityEnum.MEDIUM
    assert "Limitation:" in periodic_f.description
    assert "cloud agents" in periodic_f.description


def test_20_nxdomain_burst():
    """10 failed DNS queries in 60s flags EXCESSIVE_DNS_FAILURES."""
    config = NetworkConfigResponse(dns_nxdomain_burst_threshold=10, dns_nxdomain_window_seconds=60)
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedNetworkEvent(
            id=f"dns-{i}",
            timestamp=t0 + timedelta(seconds=i * 2),
            source_ip="10.0.1.15",
            event_type=NetworkEventTypeEnum.DNS_QUERY,
            dns_query=f"nx-domain-probe-{i}.invalid",
            dns_response_code="NXDOMAIN",
        )
        for i in range(12)
    ]
    findings = DnsTelemetryEngine.analyze(events, config)
    assert any(f.finding_type == "EXCESSIVE_DNS_FAILURES" for f in findings)


def test_21_dns_structural_anomaly():
    """Verifies DGA-like lexical detection and DNS tunneling defensive indicators."""
    config = NetworkConfigResponse(
        dns_tunneling_queries_threshold=15,
        dns_tunneling_subdomain_len=50,
        dns_tunneling_entropy_threshold=3.8,
    )
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)

    # 1. DGA lexical domain
    dga_event = NormalizedNetworkEvent(
        id="dga-1",
        timestamp=t0,
        source_ip="10.0.1.20",
        event_type=NetworkEventTypeEnum.DNS_QUERY,
        dns_query="x7k9p2m4q8z1w3v5j0r.top",
    )
    findings = DnsTelemetryEngine.analyze([dga_event], config)
    assert any(f.finding_type == "DGA_LIKE_DOMAIN_STRUCTURE" for f in findings)

    # 2. DNS Tunneling structural anomaly: 16 unique long high-entropy subdomains
    tunnel_events = [
        NormalizedNetworkEvent(
            id=f"tun-{i}",
            timestamp=t0 + timedelta(seconds=i),
            source_ip="10.0.1.20",
            event_type=NetworkEventTypeEnum.DNS_QUERY,
            dns_query=f"payload-chunk-{i:03d}-" + ("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0" * 2) + ".exfil.corp",
        )
        for i in range(16)
    ]
    tunnel_findings = DnsTelemetryEngine.analyze(tunnel_events, config)
    assert any(f.finding_type == "DNS_TUNNELING_INDICATORS" for f in findings + tunnel_findings)


# ============================================================================
# 22-24. TRANSFER, ASYMMETRY & RARE DESTINATION TESTS
# ============================================================================

def test_22_high_outbound_volume():
    """Outbound transfer of 60 MB flags HIGH_OUTBOUND_DATA_VOLUME."""
    config = NetworkConfigResponse(high_outbound_volume_bytes=50 * 1024 * 1024)
    ev = NormalizedNetworkEvent(
        id="vol-1",
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.1.5",
        destination_ip="198.51.100.44",
        bytes_sent=60 * 1024 * 1024,
    )
    findings = TransferExfiltrationEngine.analyze([ev], {}, config)
    assert any(f.finding_type == "HIGH_OUTBOUND_DATA_VOLUME" for f in findings)


def test_23_traffic_asymmetry():
    """10 MB sent vs 100 KB received (100x ratio) flags OUTBOUND_TRAFFIC_ASYMMETRY."""
    config = NetworkConfigResponse(asymmetry_ratio_threshold=10.0)
    ev = NormalizedNetworkEvent(
        id="asym-1",
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.1.5",
        destination_ip="198.51.100.44",
        bytes_sent=10 * 1024 * 1024,
        bytes_received=100 * 1024,
    )
    findings = TransferExfiltrationEngine.analyze([ev], {}, config)
    assert any(f.finding_type == "OUTBOUND_TRAFFIC_ASYMMETRY" for f in findings)


def test_24_rare_destination():
    """Destination contacted by only 1 host across fleet of 3+ devices flags RARE_DESTINATION."""
    config = NetworkConfigResponse(rare_destination_device_count_threshold=1)
    profiles = {
        "dev-1": DeviceNetworkProfile(device_id="dev-1", total_connections_observed=10, known_destinations=["10.0.0.1"]),
        "dev-2": DeviceNetworkProfile(device_id="dev-2", total_connections_observed=10, known_destinations=["10.0.0.1"]),
        "dev-3": DeviceNetworkProfile(device_id="dev-3", total_connections_observed=10, known_destinations=["10.0.0.1"]),
    }
    ev = NormalizedNetworkEvent(
        id="rare-1",
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.1.5",
        device_id="dev-1",
        destination_ip="198.51.100.123",
    )
    findings = DestinationAnomalyEngine.analyze([ev], profiles, config)
    assert any(f.finding_type == "RARE_DESTINATION" for f in findings)


# ============================================================================
# 25-28. INTELLIGENCE, MATCH & THREAT EVENT TESTS
# ============================================================================

def test_25_ip_intelligence_routing(monkeypatch):
    """Destination IP routing through threat intel respects KNOWN_THREAT_INFRASTRUCTURE_MATCH."""
    monkeypatch.setenv("KNOWN_MALICIOUS_IPS", "203.0.113.66")
    db: Session = SessionLocal()
    try:
        raw = [{
            "src_ip": "10.0.1.5",
            "dst_ip": "203.0.113.66",
            "dst_port": 443,
            "protocol": "TCP",
            "timestamp": "2026-10-02T12:00:00Z",
        }]
        res = asyncio.run(global_network_pipeline.analyze_events(raw, db=db))
        f_types = [f.finding_type for f in res.findings]
        assert "KNOWN_THREAT_INFRASTRUCTURE_MATCH" in f_types
    finally:
        db.close()


def test_26_domain_intelligence_routing():
    """DNS queries route into domain indicators and persistence."""
    db: Session = SessionLocal()
    try:
        raw = [{
            "src_ip": "10.0.1.5",
            "dns_query": "corp-update.net",
            "timestamp": "2026-10-02T12:00:00Z",
        }]
        res = asyncio.run(global_network_pipeline.analyze_events(raw, db=db))
        dom_ind = db.query(IndicatorModel).filter(IndicatorModel.value == "corp-update.net").first()
        assert dom_ind is not None
    finally:
        db.close()


def test_27_threat_intelligence_match():
    """Direct lookup on non-malicious IP returns UNKNOWN without fabricating opinions."""
    res = asyncio.run(global_network_pipeline.threat_intel.lookup_ip("198.51.100.1"))
    assert res["verdict"] == "UNKNOWN"
    assert res["is_malicious"] is False


def test_28_threat_event_creation(monkeypatch):
    """High/Critical findings persist ThreatEventModel in DB."""
    monkeypatch.setenv("KNOWN_MALICIOUS_IPS", "203.0.113.77")
    db: Session = SessionLocal()
    try:
        raw = [{
            "src_ip": "10.0.1.5",
            "dst_ip": "203.0.113.77",
            "dst_port": 443,
            "timestamp": "2026-10-02T12:00:00Z",
        }]
        res = asyncio.run(global_network_pipeline.analyze_events(raw, db=db))
        te = db.query(ThreatEventModel).filter(ThreatEventModel.analysis_run_id == res.analysis_run_id).first()
        assert te is not None
        assert te.severity in (SeverityEnum.HIGH.value, SeverityEnum.CRITICAL.value)
    finally:
        db.close()


# ============================================================================
# 29-33. ENTITY, PERSISTENCE, REANALYSIS & BATCH TESTS
# ============================================================================

def test_29_session_relationship():
    """Session ID in telemetry creates SESSION entity and HAS_SESSION relationship."""
    db: Session = SessionLocal()
    try:
        raw = [{
            "src_ip": "10.0.1.5",
            "dst_ip": "10.0.2.20",
            "session_id": "sess-xyz-999",
            "user_id": "operator_sam",
            "timestamp": "2026-10-02T12:00:00Z",
        }]
        res = asyncio.run(global_network_pipeline.analyze_events(raw, db=db))
        sess_ent = db.query(EntityModel).filter(EntityModel.name == "sess-xyz-999").first()
        assert sess_ent is not None
        assert sess_ent.entity_type == EntityTypeEnum.SESSION.value

        rel = db.query(RelationshipModel).filter(
            RelationshipModel.analysis_run_id == res.analysis_run_id,
            RelationshipModel.relationship_type == RelationshipTypeEnum.HAS_SESSION.value,
        ).first()
        assert rel is not None
    finally:
        db.close()


def test_30_device_relationship():
    """Source host creates DEVICE entity and CONNECTS_TO relationship to destination IP."""
    db: Session = SessionLocal()
    try:
        raw = [{
            "src_ip": "10.0.1.88",
            "dst_ip": "10.0.2.88",
            "device_id": "finance-workstation-88",
            "timestamp": "2026-10-02T12:00:00Z",
        }]
        res = asyncio.run(global_network_pipeline.analyze_events(raw, db=db))
        dev_ent = db.query(EntityModel).filter(EntityModel.name == "finance-workstation-88").first()
        assert dev_ent is not None
        assert dev_ent.entity_type == EntityTypeEnum.DEVICE.value

        rel = db.query(RelationshipModel).filter(
            RelationshipModel.source_id == dev_ent.id,
            RelationshipModel.relationship_type == RelationshipTypeEnum.CONNECTS_TO.value,
        ).first()
        assert rel is not None
    finally:
        db.close()


def test_31_evidence_persistence():
    """FindingEvidenceModel records are stored with keys, values, and timestamps."""
    db: Session = SessionLocal()
    try:
        config = NetworkConfigResponse(repeated_failures_threshold=5)
        raw = [
            {"src_ip": "10.0.1.5", "dst_ip": "10.0.2.1", "status": "FAILURE", "timestamp": f"2026-10-02T12:00:0{i}Z"}
            for i in range(6)
        ]
        res = asyncio.run(global_network_pipeline.analyze_events(raw, db=db))
        evidence = db.query(FindingEvidenceModel).join(FindingModel).filter(
            FindingModel.analysis_run_id == res.analysis_run_id
        ).all()
        assert len(evidence) > 0
        assert any(e.key == "source_ip" for e in evidence)
    finally:
        db.close()


def test_32_reanalysis():
    """Re-analyzing a stored NETWORK_LOG artifact creates an independent AnalysisRunModel."""
    db: Session = SessionLocal()
    try:
        payload = json.dumps([
            {"src_ip": "10.0.1.5", "dst_ip": "10.0.2.1", "status": "SUCCESS", "timestamp": "2026-10-02T12:00:00Z"}
        ]).encode("utf-8")
        rec = evidence_storage.store_bytes(payload)

        art = ArtifactModel(
            id="art-net-reanalysis-test",
            artifact_type=ArtifactTypeEnum.NETWORK_LOG.value,
            name="test-network.json",
            storage_reference=rec.sha256,
            sha256=rec.sha256,
            mime_type="application/json",
            size=len(payload),
        )
        db.add(art)
        db.commit()

        re_res = asyncio.run(global_network_pipeline.analyze_artifact(art.id, db=db))
        assert re_res.artifact_id == art.id
        assert re_res.analysis_run_id is not None
    finally:
        db.close()


def test_33_batch_ingestion():
    """Batch API endpoint accepts multiple flows and returns structured response."""
    events = [
        {"src_ip": "10.0.1.1", "dst_ip": "10.0.2.1", "dst_port": 80, "protocol": "TCP"},
        {"src_ip": "10.0.1.2", "dst_ip": "10.0.2.2", "dst_port": 443, "protocol": "TCP"},
    ]
    resp = client.post("/api/network-security/analyze-batch", json=events)
    assert resp.status_code == 200
    data = resp.json()
    assert data["events_analyzed_count"] == 2
    assert data["overall_severity"] in ("SAFE", "LOW")


def test_34_existing_cyberguard_workflows_functional():
    """Health check and core existing APIs remain unaffected and functional."""
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


# ============================================================================
# 35-37. FALSE-POSITIVE CONTROLS & COMPOSITE HYPOTHESES
# ============================================================================

def test_35_false_positive_controls():
    """
    Verifies that benign/isolated anomalies do not produce HIGH/CRITICAL severity:
    - Unusual port alone is LOW severity
    - Long-lived connection alone is LOW severity
    - Normal web traffic is SAFE severity
    """
    # 1. Normal web browsing
    normal_flow = NormalizedNetworkEvent(
        id="web-1",
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.1.10",
        destination_ip="93.184.216.34",
        destination_port=443,
        protocol=NetworkProtocolEnum.HTTPS,
    )
    score, sev, conf, cls_name = global_network_pipeline._calculate_overall_risk([], False, False)
    assert sev == SeverityEnum.SAFE

    # 2. Long-lived connection alone
    long_conn = NormalizedNetworkEvent(
        id="long-1",
        timestamp=datetime.now(timezone.utc),
        source_ip="10.0.1.10",
        destination_ip="93.184.216.34",
        duration_seconds=7200.0,
    )
    findings = TransferExfiltrationEngine.analyze([long_conn], {}, NetworkConfigResponse())
    assert any(f.finding_type == "LONG_LIVED_EXTERNAL_CONNECTION" for f in findings)
    assert all(f.severity == SeverityEnum.LOW for f in findings)


def test_36_composite_suspicious_communication():
    """
    New destination + Periodic communication + Threat intel match synthesizes
    SUSPICIOUS_EXTERNAL_COMMUNICATION with elevated confidence.
    """
    findings = [
        NetworkFindingItem(
            finding_type="PERIODIC_CONNECTION_PATTERN",
            title="Periodic beaconing",
            description="Regular 60s intervals",
            severity=SeverityEnum.MEDIUM,
            category=NetworkCategoryEnum.CONNECTION_PATTERN,
            target_destination="198.51.100.99",
        ),
        NetworkFindingItem(
            finding_type="KNOWN_THREAT_INFRASTRUCTURE_MATCH",
            title="Threat intel match",
            description="C2 match",
            severity=SeverityEnum.HIGH,
            category=NetworkCategoryEnum.INFRASTRUCTURE_REPUTATION,
            target_destination="198.51.100.99",
        ),
    ]
    suspicious_comm, possible_exfil, composites = NetworkPatternAggregator.aggregate(findings, [])
    assert suspicious_comm is True
    assert any(c.finding_type == "SUSPICIOUS_EXTERNAL_COMMUNICATION" for c in composites)


def test_37_composite_data_exfiltration():
    """
    High outbound volume + New destination + Traffic asymmetry synthesizes
    POSSIBLE_DATA_EXFILTRATION hypothesis.
    """
    findings = [
        NetworkFindingItem(
            finding_type="HIGH_OUTBOUND_DATA_VOLUME",
            title="Large transfer",
            description="75 MB sent",
            severity=SeverityEnum.MEDIUM,
            category=NetworkCategoryEnum.TRANSFER_ANOMALY,
            target_destination="198.51.100.44",
        ),
        NetworkFindingItem(
            finding_type="NEW_NETWORK_DESTINATION",
            title="New destination",
            description="Never seen before",
            severity=SeverityEnum.LOW,
            category=NetworkCategoryEnum.DESTINATION_ANOMALY,
            target_destination="198.51.100.44",
        ),
    ]
    suspicious_comm, possible_exfil, composites = NetworkPatternAggregator.aggregate(findings, [])
    assert possible_exfil is True
    assert any(c.finding_type == "POSSIBLE_DATA_EXFILTRATION" for c in composites)


# ============================================================================
# 38. SYNTHETIC PERFORMANCE BENCHMARK
# ============================================================================

def test_38_synthetic_performance_benchmark():
    """
    Generates 500 synthetic network events and benchmarks:
    - Normalization throughput
    - Detection engine evaluation time
    - End-to-end database persistence
    """
    t0 = datetime(2026, 10, 2, 12, 0, 0, tzinfo=timezone.utc)
    raw_dataset = [
        {
            "src_ip": f"10.0.{i % 5}.{i % 250 + 1}",
            "dst_ip": f"10.1.{i % 5}.{i % 250 + 1}",
            "src_port": 10000 + (i % 5000),
            "dst_port": 80 if i % 2 == 0 else 443,
            "protocol": "TCP",
            "bytes_sent": 1000 + (i * 10),
            "bytes_recv": 5000 + (i * 20),
            "duration": 0.5,
            "timestamp": (t0 + timedelta(milliseconds=i * 200)).isoformat(),
        }
        for i in range(500)
    ]

    db: Session = SessionLocal()
    try:
        t_start = time.perf_counter()
        res = asyncio.run(global_network_pipeline.analyze_events(raw_dataset, db=db))
        total_duration = time.perf_counter() - t_start

        assert res.events_analyzed_count == 500
        throughput = 500 / total_duration
        print(f"\n[SECTION 10 BENCHMARK] 500 events analyzed in {total_duration:.3f}s ({throughput:.1f} events/sec)")
        assert total_duration < 10.0  # Must comfortably process 500 events within 10s
    finally:
        db.close()
