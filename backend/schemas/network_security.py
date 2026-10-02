"""
Network and Traffic Anomaly Security Schemas.
Pydantic V2 models defining normalized network events, flow records, DNS telemetry,
periodicity metrics, and network security analysis responses.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from backend.schemas.unified import SeverityEnum


# ============================================================================
# CANONICAL NETWORK ENUMS
# ============================================================================

class NetworkEventTypeEnum(str, Enum):
    CONNECTION = "CONNECTION"
    FLOW = "FLOW"
    DNS_QUERY = "DNS_QUERY"
    DNS_RESPONSE = "DNS_RESPONSE"
    FIREWALL_EVENT = "FIREWALL_EVENT"
    PROXY_REQUEST = "PROXY_REQUEST"
    NETWORK_ALERT = "NETWORK_ALERT"
    OTHER = "OTHER"


class NetworkProtocolEnum(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    TLS = "TLS"
    SSH = "SSH"
    OTHER = "OTHER"


class TrafficDirectionEnum(str, Enum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    INTERNAL = "INTERNAL"
    UNKNOWN = "UNKNOWN"


class IPScopeEnum(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    LOOPBACK = "LOOPBACK"
    LINK_LOCAL = "LINK_LOCAL"
    MULTICAST = "MULTICAST"
    RESERVED = "RESERVED"
    UNKNOWN = "UNKNOWN"


class NetworkCategoryEnum(str, Enum):
    DESTINATION_ANOMALY = "DESTINATION_ANOMALY"
    CONNECTION_PATTERN = "CONNECTION_PATTERN"
    DNS_ANOMALY = "DNS_ANOMALY"
    TRANSFER_ANOMALY = "TRANSFER_ANOMALY"
    INFRASTRUCTURE_REPUTATION = "INFRASTRUCTURE_REPUTATION"
    TEMPORAL_ANOMALY = "TEMPORAL_ANOMALY"


# ============================================================================
# NORMALIZED NETWORK EVENT
# ============================================================================

class NormalizedNetworkEvent(BaseModel):
    """
    Canonical representation of a single normalized network event or flow record.
    Operates strictly on authorized telemetry without packet payload capture.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique identifier for this network event")
    timestamp: datetime = Field(description="Normalized UTC event occurrence timestamp")
    event_type: NetworkEventTypeEnum = Field(default=NetworkEventTypeEnum.CONNECTION, description="Network event category")
    source_ip: str = Field(description="Source IPv4 or IPv6 address")
    source_port: Optional[int] = Field(default=None, description="Source TCP/UDP port")
    destination_ip: Optional[str] = Field(default=None, description="Destination IPv4 or IPv6 address")
    destination_port: Optional[int] = Field(default=None, description="Destination TCP/UDP port")
    protocol: NetworkProtocolEnum = Field(default=NetworkProtocolEnum.TCP, description="Transport/Application protocol")
    direction: TrafficDirectionEnum = Field(default=TrafficDirectionEnum.UNKNOWN, description="Traffic direction relative to internal networks")
    source_scope: IPScopeEnum = Field(default=IPScopeEnum.UNKNOWN, description="Source IP network scope")
    destination_scope: IPScopeEnum = Field(default=IPScopeEnum.UNKNOWN, description="Destination IP network scope")
    bytes_sent: Optional[int] = Field(default=None, description="Outbound bytes sent by source")
    bytes_received: Optional[int] = Field(default=None, description="Inbound bytes received from destination")
    packets_sent: Optional[int] = Field(default=None, description="Outbound packet count")
    packets_received: Optional[int] = Field(default=None, description="Inbound packet count")
    duration_seconds: Optional[float] = Field(default=None, description="Connection or flow duration in seconds")
    domain: Optional[str] = Field(default=None, description="Destination hostname or SNI")
    dns_query: Optional[str] = Field(default=None, description="Requested DNS query name")
    dns_query_type: Optional[str] = Field(default=None, description="DNS query type (A, AAAA, TXT, MX, etc.)")
    dns_response_code: Optional[str] = Field(default=None, description="DNS response status (NOERROR, NXDOMAIN, SERVFAIL, etc.)")
    dns_answers: List[str] = Field(default_factory=list, description="Resolved IP or CNAME answers")
    device_id: Optional[str] = Field(default=None, description="Reporting host or endpoint device identifier")
    host_name: Optional[str] = Field(default=None, description="Reporting host friendly name or netbios name")
    user_id: Optional[str] = Field(default=None, description="Associated user identity if mapped in telemetry")
    session_id: Optional[str] = Field(default=None, description="Associated session identifier if mapped")
    action: Optional[str] = Field(default=None, description="Defensive firewall action (ALLOW, BLOCK, DROP, REJECT)")
    status: Optional[str] = Field(default=None, description="Connection state (SUCCESS, FAILURE, TIMEOUT, RESET)")
    provider: str = Field(default="generic", description="Originating telemetry source or log adapter name")
    raw_artifact_id: Optional[str] = Field(default=None, description="Parent stored artifact reference")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Sanitized auxiliary metadata")


# ============================================================================
# METRICS & BASELINE PROFILES
# ============================================================================

class PeriodicityMetrics(BaseModel):
    """
    Statistical metrics evaluating potential beaconing or periodic communication.
    """
    event_count: int
    mean_interval_seconds: float
    median_interval_seconds: float
    interval_variance: float
    coefficient_of_variation: float = Field(description="Standard deviation divided by mean (CV = sigma / mu)")
    min_interval_seconds: float
    max_interval_seconds: float
    observation_duration_seconds: float
    is_periodic: bool = False


class DeviceNetworkProfile(BaseModel):
    """
    Lightweight baseline profile of observed network behaviors for a host/device.
    """
    device_id: str
    total_connections_observed: int = 0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    known_destinations: List[str] = Field(default_factory=list)
    known_ports: List[int] = Field(default_factory=list)
    known_domains: List[str] = Field(default_factory=list)
    total_bytes_sent: int = 0
    total_bytes_received: int = 0


# ============================================================================
# FINDINGS & CONFIGURATION SCHEMAS
# ============================================================================

class NetworkFindingEvidenceItem(BaseModel):
    key: str
    value: str
    source: str
    confidence: float = 1.0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NetworkFindingItem(BaseModel):
    finding_type: str
    title: str
    description: str
    severity: SeverityEnum
    confidence: float = 1.0
    risk_contribution: float = 0.0
    method: str = "DETERMINISTIC"
    rule_id: Optional[str] = None
    category: NetworkCategoryEnum
    target_device: Optional[str] = None
    target_destination: Optional[str] = None
    evidence_items: List[NetworkFindingEvidenceItem] = Field(default_factory=list)
    mitre_attack_ids: List[str] = Field(default_factory=list)


class NetworkConfigResponse(BaseModel):
    version: str = "1.0.0"
    repeated_failures_threshold: int = 5
    repeated_failures_window_seconds: int = 300
    scan_distinct_ports_threshold: int = 15
    scan_distinct_hosts_threshold: int = 10
    scan_window_seconds: int = 120
    connection_burst_threshold: int = 50
    connection_burst_window_seconds: int = 60
    periodicity_min_observations: int = 5
    periodicity_max_cv: float = 0.20
    high_outbound_volume_bytes: int = 50 * 1024 * 1024  # 50 MB
    asymmetry_ratio_threshold: float = 10.0
    long_lived_connection_seconds: float = 3600.0  # 1 hour
    dns_nxdomain_burst_threshold: int = 10
    dns_nxdomain_window_seconds: int = 60
    dns_query_burst_threshold: int = 30
    dns_query_burst_window_seconds: int = 60
    dns_tunneling_subdomain_len: int = 50
    dns_tunneling_entropy_threshold: float = 3.8
    dns_tunneling_queries_threshold: int = 15
    rare_destination_device_count_threshold: int = 1
    min_history_events_device: int = 5
    internal_networks_cidrs: List[str] = Field(default_factory=lambda: [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "::1", "fc00::/7"
    ])
    supported_adapters: List[str] = Field(default_factory=lambda: [
        "generic_json", "generic_csv", "dns_log", "netflow_json"
    ])


class NetworkSecurityAnalysisResponse(BaseModel):
    analysis_run_id: str
    artifact_id: Optional[str] = None
    events_analyzed_count: int
    devices_observed_count: int
    unique_destinations_count: int
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    overall_risk_score: float = Field(ge=0.0, le=100.0)
    overall_severity: SeverityEnum
    confidence: float = Field(ge=0.0, le=1.0)
    classification: str
    findings: List[NetworkFindingItem] = Field(default_factory=list)
    corroborated_threat_events: List[Dict[str, Any]] = Field(default_factory=list)
    device_profiles: Dict[str, DeviceNetworkProfile] = Field(default_factory=dict)
    suspicious_communication_detected: bool = False
    possible_exfiltration_detected: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
