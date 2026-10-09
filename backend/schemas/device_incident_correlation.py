"""
Pydantic v2 schemas for Section 33: Device-to-Incident Correlation.
Defines contracts for bidirectional device-incident correlation, multi-vector evidence matching,
structured reason codes, counter-evidence, timeline synthesis, and analyst review.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# ENUMS
# ============================================================================

class DeviceCorrelationTypeEnum(str, Enum):
    OBSERVED = "OBSERVED"
    DIRECT_IDENTIFIER = "DIRECT_IDENTIFIER"
    INDICATOR_MATCH = "INDICATOR_MATCH"
    PROCESS_MATCH = "PROCESS_MATCH"
    FILE_HASH_MATCH = "FILE_HASH_MATCH"
    DOMAIN_MATCH = "DOMAIN_MATCH"
    IP_MATCH = "IP_MATCH"
    URL_MATCH = "URL_MATCH"
    USER_MATCH = "USER_MATCH"
    ACCOUNT_MATCH = "ACCOUNT_MATCH"
    SESSION_MATCH = "SESSION_MATCH"
    NETWORK_BEHAVIOR_MATCH = "NETWORK_BEHAVIOR_MATCH"
    DNS_BEHAVIOR_MATCH = "DNS_BEHAVIOR_MATCH"
    TEMPORAL_SEQUENCE = "TEMPORAL_SEQUENCE"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"
    GRAPH_PATH = "GRAPH_PATH"
    CAMPAIGN_ASSOCIATION = "CAMPAIGN_ASSOCIATION"
    ATTACK_PATH_ASSOCIATION = "ATTACK_PATH_ASSOCIATION"
    THREAT_MEMORY_MATCH = "THREAT_MEMORY_MATCH"
    MULTI_SIGNAL_CORRELATION = "MULTI_SIGNAL_CORRELATION"


class DeviceAssociationStatusEnum(str, Enum):
    OBSERVED = "OBSERVED"
    RELATED = "RELATED"
    SUSPECTED = "SUSPECTED"
    SUPPORTED = "SUPPORTED"
    CONFIRMED = "CONFIRMED"
    DISMISSED = "DISMISSED"


class CorrelationReasonCodeEnum(str, Enum):
    # Positive Supporting Reasons
    EXACT_HASH_MATCH = "EXACT_HASH_MATCH"
    KNOWN_MALICIOUS_DOMAIN_OBSERVED = "KNOWN_MALICIOUS_DOMAIN_OBSERVED"
    INCIDENT_IP_OBSERVED = "INCIDENT_IP_OBSERVED"
    SAME_USER_SESSION = "SAME_USER_SESSION"
    TEMPORALLY_ALIGNED_SEQUENCE = "TEMPORALLY_ALIGNED_SEQUENCE"
    GRAPH_PATH_SUPPORTED = "GRAPH_PATH_SUPPORTED"
    BEHAVIORAL_DEVIATION_ALIGNED = "BEHAVIORAL_DEVIATION_ALIGNED"
    THREAT_MEMORY_MATCH = "THREAT_MEMORY_MATCH"
    CAMPAIGN_ASSOCIATION = "CAMPAIGN_ASSOCIATION"
    MULTI_SIGNAL_SUPPORT = "MULTI_SIGNAL_SUPPORT"

    # Counter-Evidence / Negative Discounting Reasons
    SHARED_NAT = "SHARED_NAT"
    COMMON_INFRASTRUCTURE = "COMMON_INFRASTRUCTURE"
    STALE_INDICATOR = "STALE_INDICATOR"
    TEMPORAL_MISMATCH = "TEMPORAL_MISMATCH"
    INSUFFICIENT_TELEMETRY = "INSUFFICIENT_TELEMETRY"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    COMMON_SOFTWARE = "COMMON_SOFTWARE"
    RETENTION_WINDOW_NOTICE = "RETENTION_WINDOW_NOTICE"


class AnalystReviewActionEnum(str, Enum):
    CONFIRM_ASSOCIATION = "CONFIRM_ASSOCIATION"
    DISMISS_ASSOCIATION = "DISMISS_ASSOCIATION"
    MARK_RELATED = "MARK_RELATED"
    MARK_FALSE_ASSOCIATION = "MARK_FALSE_ASSOCIATION"


# ============================================================================
# STRUCTURED EVIDENCE & CONTEXT SCHEMAS
# ============================================================================

class MatchedIndicatorItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    type: str = Field(..., description="Indicator type: HASH, DOMAIN, IP, URL, USER")
    value: str = Field(..., description="Normalized indicator value")
    provenance: str = Field("ENDPOINT_TELEMETRY", description="Origin of indicator observation")
    age_days: Optional[float] = Field(None, description="Age of incident indicator in days")
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    source: str = Field("telemetry_payload", description="Telemetry or incident source")


class TemporalContextItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    delta_seconds: float = Field(..., description="Absolute seconds delta between incident and telemetry observation")
    temporal_relationship: str = Field(
        "TEMPORALLY_SUPPORTIVE",
        description="TEMPORALLY_ADJACENT, TEMPORALLY_SUPPORTIVE, CAUSALLY_SUPPORTED, CONCURRENT, INDEPENDENT"
    )
    clock_skew_ms: float = Field(0.0, description="Endpoint clock skew offset")
    telemetry_time: Optional[datetime] = None
    incident_time: Optional[datetime] = None


class CounterEvidenceItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    code: CorrelationReasonCodeEnum
    description: str
    penalty: float = Field(0.0, ge=0.0, le=1.0, description="Confidence/strength discount penalty")
    severity: str = Field("LOW", description="LOW, MEDIUM, HIGH")


class CorrelationExplanationFacts(BaseModel):
    model_config = ConfigDict(extra="ignore")
    device_name: str
    incident_number: str
    facts: List[str] = Field(default_factory=list, description="Ordered transparent factual premises")
    positive_signals: List[str] = Field(default_factory=list)
    negative_signals: List[str] = Field(default_factory=list)
    narrative: str = Field("", description="Explainable AI human-readable summary narrative")


# ============================================================================
# RESPONSE SCHEMAS
# ============================================================================

class DeviceIncidentCorrelationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    workspace_id: str
    device_id: str
    incident_id: str
    correlation_type: DeviceCorrelationTypeEnum
    correlation_score: float = Field(..., ge=0.0, le=1.0, description="Strength of association")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Evidence confidence")
    status: DeviceAssociationStatusEnum
    version: int = 1
    is_current: bool = True
    first_observed_at: datetime
    last_observed_at: datetime
    supporting_event_ids: List[str] = Field(default_factory=list)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    supporting_entity_ids: List[str] = Field(default_factory=list)
    supporting_relationship_ids: List[str] = Field(default_factory=list)
    matched_indicators: List[MatchedIndicatorItem] = Field(default_factory=list)
    matched_behaviors: List[Dict[str, Any]] = Field(default_factory=list)
    temporal_context: Dict[str, Any] = Field(default_factory=dict)
    reason_codes: List[str] = Field(default_factory=list)
    counter_evidence: List[CounterEvidenceItem] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    structured_explanation: Dict[str, Any] = Field(default_factory=dict)
    correlation_engine_version: str = "1.0.0"
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    # Denormalized context for UI views
    device_hostname: Optional[str] = None
    device_platform: Optional[str] = None
    incident_number: Optional[str] = None
    incident_title: Optional[str] = None


class IncidentDevicesSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    incident_id: str
    incident_number: str
    total_devices: int
    confirmed_count: int
    supported_count: int
    suspected_count: int
    related_count: int
    observed_count: int
    dismissed_count: int
    devices: List[Dict[str, Any]] = Field(default_factory=list)
    retention_notice: str = "Telemetry evaluation constrained to available 30-day retention window."


class DeviceIncidentsHistoryResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    device_id: str
    hostname: str
    platform: str
    total_incidents: int
    incidents: List[Dict[str, Any]] = Field(default_factory=list)
    retention_notice: str = "Telemetry evaluation constrained to available 30-day retention window."


class DeviceTimelineItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    timestamp: datetime
    event_type: str
    source: str
    description: str
    priority: str = "NORMAL"
    confidence: float = 1.0
    raw_event_id: Optional[str] = None
    threat_event_id: Optional[str] = None
    incident_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DeviceTimelineResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    device_id: str
    hostname: str
    total_events: int
    timeline: List[DeviceTimelineItem] = Field(default_factory=list)
    retention_notice: str = "Displaying observations within available telemetry retention window."


class ReviewCorrelationRequest(BaseModel):
    action: AnalystReviewActionEnum
    reviewer: str = Field(..., min_length=1, description="Analyst identity performing review")
    notes: Optional[str] = Field(None, description="Auditable reasoning for analyst override")


class TriggerCorrelationRequest(BaseModel):
    window_hours: int = Field(72, ge=1, le=720, description="Temporal correlation search window (default 72h)")
