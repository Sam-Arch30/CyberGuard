"""
Section 49: Pydantic Schemas for Alert Correlation & Incident Clustering.
Defines contracts for alert clusters, member alerts, explainable correlation signals,
cluster queries, investigation handoffs, and operational summaries.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ClusterStatusEnum(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"
    MERGED = "MERGED"


class CorrelationSignalTypeEnum(str, Enum):
    SAME_USER = "SAME_USER"
    SAME_SENDER = "SAME_SENDER"
    SAME_DOMAIN = "SAME_DOMAIN"
    SAME_PARENT_DOMAIN = "SAME_PARENT_DOMAIN"
    SAME_IP = "SAME_IP"
    SAME_URL = "SAME_URL"
    SAME_ATTACHMENT_HASH = "SAME_ATTACHMENT_HASH"
    SAME_IOC = "SAME_IOC"
    SAME_SOURCE_ARTIFACT = "SAME_SOURCE_ARTIFACT"
    SAME_ANALYSIS_RUN = "SAME_ANALYSIS_RUN"
    SAME_INVESTIGATION = "SAME_INVESTIGATION"
    SAME_CAMPAIGN = "SAME_CAMPAIGN"
    SAME_ENDPOINT = "SAME_ENDPOINT"
    TEMPORAL_PROXIMITY = "TEMPORAL_PROXIMITY"
    GRAPH_RELATIONSHIP = "GRAPH_RELATIONSHIP"
    ATTACK_SEQUENCE = "ATTACK_SEQUENCE"


class CorrelationSignal(BaseModel):
    """Atomic explainable correlation signal connecting alerts."""
    type: str = Field(..., description="Canonical signal type from CorrelationSignalTypeEnum")
    strength: float = Field(1.0, ge=0.0, le=1.0, description="Normalized signal confidence weight")
    description: str = Field("Correlated security signal", description="Human-readable forensic rationale")
    matched_value: Optional[str] = Field(None, description="Actual matching value (domain, IOC, user, etc.)")


class AlertClusterMemberResponse(BaseModel):
    """Membership record representing an alert joined into a cluster."""
    id: str
    alert_id: str
    cluster_id: str
    workspace_id: str
    membership_confidence: float = Field(..., ge=0.0, le=1.0)
    signals: List[CorrelationSignal] = Field(default_factory=list)
    alert_summary: Optional[Dict[str, Any]] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertClusterItemResponse(BaseModel):
    """Compact summary for alert cluster lists."""
    id: str
    cluster_number: str
    workspace_id: str
    title: str
    summary: str
    status: str
    severity: str
    risk_score: float
    confidence: float
    alert_count: int
    primary_alert_id: Optional[str] = None
    investigation_id: Optional[str] = None
    campaign_id: Optional[str] = None
    correlation_version: str = "1.0.0"
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertClusterDetailResponse(AlertClusterItemResponse):
    """Comprehensive cluster detail with member alerts, entities, timeline, and provenance."""
    members: List[AlertClusterMemberResponse] = Field(default_factory=list)
    aggregated_signals: List[CorrelationSignal] = Field(default_factory=list)
    entities: Dict[str, List[str]] = Field(default_factory=dict, description="Extracted users, domains, IPs, URLs, hashes")
    affected_entities: Dict[str, List[str]] = Field(default_factory=dict, description="Alias for extracted entities")
    timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological sequence of member alert events")
    investigation_detail: Optional[Dict[str, Any]] = None
    campaign_detail: Optional[Dict[str, Any]] = None
    activity_log: List[Dict[str, Any]] = Field(default_factory=list, description="Audit trail for cluster lifecycle")


class AlertClusterListResponse(BaseModel):
    items: List[AlertClusterItemResponse]
    total: int
    limit: int
    offset: int
    counts_by_status: Dict[str, int] = Field(default_factory=dict)
    counts_by_severity: Dict[str, int] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class AlertCorrelationRunRequest(BaseModel):
    """Parameters to trigger correlation for an alert or candidate pool."""
    alert_id: Optional[str] = Field(None, description="Target alert ID to correlate")
    time_window_hours: int = Field(48, ge=1, le=168, description="Temporal window to search candidates")
    force_recluster: bool = Field(False, description="Re-evaluate already clustered alerts")


class AlertClusterUpdateStatusRequest(BaseModel):
    status: str = Field(..., description="Target status: OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE, SUPPRESSED")
    reason: Optional[str] = Field(None, description="Operational justification for state change")
    analyst_name: Optional[str] = Field(None, description="Analyst making the status change")


class AlertClusterLinkInvestigationRequest(BaseModel):
    investigation_id: Optional[str] = Field(None, description="Existing investigation/incident ID to attach, or None to create new")
    title: Optional[str] = Field(None, description="Title if creating new investigation")
    analyst_name: Optional[str] = Field(None, description="Analyst creating/linking investigation")
