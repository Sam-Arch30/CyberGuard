"""
Section 50: Pydantic Schemas for Incident Management & Case Lifecycle.
Provides typed contracts for operational incident cases, state transitions,
alert/cluster promotion, timeline events, analyst notes, and metrics.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IncidentStatusEnum(str, Enum):
    NEW = "NEW"
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DUPLICATE = "DUPLICATE"


class IncidentSeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


class IncidentPriorityEnum(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class IncidentCategoryEnum(str, Enum):
    PHISHING = "PHISHING"
    CREDENTIAL_COMPROMISE = "CREDENTIAL_COMPROMISE"
    MALWARE = "MALWARE"
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    MALICIOUS_ATTACHMENT = "MALICIOUS_ATTACHMENT"
    IMPERSONATION = "IMPERSONATION"
    NETWORK_INTRUSION = "NETWORK_INTRUSION"
    API_ABUSE = "API_ABUSE"
    ENDPOINT_COMPROMISE = "ENDPOINT_COMPROMISE"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    OTHER = "OTHER"


class IncidentResolutionReasonEnum(str, Enum):
    THREAT_CONTAINED = "THREAT_CONTAINED"
    THREAT_REMEDIATED = "THREAT_REMEDIATED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    DUPLICATE = "DUPLICATE"
    BENIGN_ACTIVITY = "BENIGN_ACTIVITY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    OTHER = "OTHER"


# =============================================================================
# Request Schemas
# =============================================================================

class IncidentCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    severity: Optional[str] = "MEDIUM"
    priority: Optional[str] = None
    category: Optional[str] = "OTHER"
    assigned_to: Optional[str] = None
    team_id: Optional[str] = None
    primary_alert_id: Optional[str] = None
    primary_cluster_id: Optional[str] = None
    investigation_id: Optional[str] = None
    notes: Optional[str] = None
    auto_route: bool = False


class IncidentPromoteAlertRequest(BaseModel):
    alert_id: str
    title: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    category: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    auto_route: bool = False


class IncidentPromoteClusterRequest(BaseModel):
    cluster_id: str
    title: Optional[str] = None
    severity: Optional[str] = None
    priority: Optional[str] = None
    category: Optional[str] = None
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    auto_route: bool = False


class IncidentUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    category: Optional[str] = None
    team_id: Optional[str] = None


class IncidentStatusChangeRequest(BaseModel):
    status: str
    reason: Optional[str] = None
    resolution_reason: Optional[str] = None
    notes: Optional[str] = None
    duplicate_of_id: Optional[str] = None


class IncidentAssignRequest(BaseModel):
    assigned_to: Optional[str] = None
    team_id: Optional[str] = None
    reason: Optional[str] = None


class IncidentResolveRequest(BaseModel):
    resolution_reason: str
    notes: Optional[str] = None


class IncidentCloseRequest(BaseModel):
    notes: Optional[str] = None


class IncidentReopenRequest(BaseModel):
    reason: str = Field(..., min_length=3)
    notes: Optional[str] = None


class IncidentNoteCreateRequest(BaseModel):
    note_text: str = Field(..., min_length=1)
    author: Optional[str] = None


# =============================================================================
# Response Schemas
# =============================================================================

class IncidentTimelineEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_type: str
    timestamp: datetime
    actor: str
    source_type: str
    source_id: Optional[str] = None
    summary: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentNoteResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    author: str
    note_text: str
    created_at: datetime
    updated_at: datetime


class IncidentNextBestActionResponse(BaseModel):
    recommendation_id: Optional[str] = None
    action_type: str
    title: str
    description: str
    priority: str
    confidence: float
    target_entity: Optional[str] = None


class IncidentItemResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_number: str
    title: str
    description: Optional[str] = None
    status: str
    severity: str
    priority: str
    category: str
    risk_score: float
    confidence: float
    assigned_to: Optional[str] = None
    team_id: Optional[str] = None
    primary_alert_id: Optional[str] = None
    primary_cluster_id: Optional[str] = None
    investigation_id: Optional[str] = None
    report_id: Optional[str] = None
    created_by: Optional[str] = None
    resolution_reason: Optional[str] = None
    duplicate_of_id: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    opened_at: datetime
    acknowledged_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    alert_count: int = 0
    cluster_count: int = 0
    escalation_level: int = 0
    sla_status: str = "HEALTHY"
    next_sla_deadline: Optional[datetime] = None
    time_remaining_mins: Optional[float] = None
    is_overdue: bool = False


class IncidentDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    incident_number: str
    workspace_id: str
    title: str
    description: Optional[str] = None
    status: str
    severity: str
    priority: str
    category: str
    risk_score: float
    confidence: float
    assigned_to: Optional[str] = None
    team_id: Optional[str] = None
    primary_alert_id: Optional[str] = None
    primary_cluster_id: Optional[str] = None
    investigation_id: Optional[str] = None
    report_id: Optional[str] = None
    created_by: Optional[str] = None
    resolved_by: Optional[str] = None
    resolution_reason: Optional[str] = None
    duplicate_of_id: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    opened_at: datetime
    acknowledged_at: Optional[datetime] = None
    contained_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    escalation_level: int = 0
    sla_status: str = "HEALTHY"
    next_sla_deadline: Optional[datetime] = None

    # Associated Operational Context
    alert_count: int = 0
    cluster_count: int = 0
    findings_count: int = 0
    evidence_count: int = 0
    related_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    related_clusters: List[Dict[str, Any]] = Field(default_factory=list)
    affected_entities: Dict[str, List[str]] = Field(default_factory=dict)
    next_best_action: Optional[IncidentNextBestActionResponse] = None
    timeline_events: List[IncidentTimelineEventResponse] = Field(default_factory=list)
    notes: List[IncidentNoteResponse] = Field(default_factory=list)


class IncidentListResponse(BaseModel):
    items: List[IncidentItemResponse]
    total: int
    offset: int = 0
    limit: int = 50


class IncidentMetricsResponse(BaseModel):
    total_incidents: int
    open_incidents: int
    critical_incidents: int
    unassigned_incidents: int
    investigating_incidents: int
    contained_incidents: int
    resolved_incidents: int
    closed_incidents: int
    avg_time_to_acknowledge_sec: Optional[float] = None
    avg_time_to_contain_sec: Optional[float] = None
    avg_time_to_resolve_sec: Optional[float] = None
    sla_breaches: int = 0
    approaching_sla: int = 0
    unacknowledged_critical: int = 0
    escalated_incidents: int = 0
    unassigned_critical: int = 0
    by_category: Dict[str, int] = Field(default_factory=dict)
    by_severity: Dict[str, int] = Field(default_factory=dict)
    by_priority: Dict[str, int] = Field(default_factory=dict)
