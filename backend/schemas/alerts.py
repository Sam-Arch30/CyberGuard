"""
Section 48: Pydantic schemas for Alert Management & Triage Workspace.
Defines lifecycle statuses, triage actions, provenance detail contracts,
explainability why-cards, and aggregate triage metrics.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AlertStatusEnum(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    SUPPRESSED = "SUPPRESSED"


class AlertSeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertItemResponse(BaseModel):
    """Compact record for alert queue listing."""
    id: str
    workspace_id: str = "default"
    alert_type: str = Field(..., description="Canonical security alert taxonomy type")
    severity: str = Field("HIGH", description="Authoritative severity: CRITICAL, HIGH, MEDIUM, LOW, INFO")
    status: str = Field("OPEN", description="OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE, SUPPRESSED")
    title: str
    message: str
    risk_score: float = Field(0.0, description="Evaluated threat/risk contribution 0-100")
    confidence: float = Field(1.0, description="Model or analyzer confidence 0-1.0")
    source_type: str = Field("FINDING", description="FINDING, ANALYSIS_RUN, INVESTIGATION")
    source_id: str
    investigation_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    finding_id: Optional[str] = None
    navigation_target: Optional[str] = None
    assigned_to: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class AlertDetailResponse(AlertItemResponse):
    """Detailed record with full provenance, evidence items, explainability, and activity audit."""
    why_created: List[str] = Field(default_factory=list, description="Section 27 Explainable AI reasoning items")
    finding_detail: Optional[Dict[str, Any]] = None
    evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    analysis_run_detail: Optional[Dict[str, Any]] = None
    investigation_detail: Optional[Dict[str, Any]] = None
    activity_timeline: List[Dict[str, Any]] = Field(default_factory=list)
    resolution_reason: Optional[str] = None
    false_positive_reason: Optional[str] = None
    suppression_reason: Optional[str] = None
    suppression_scope: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AlertListResponse(BaseModel):
    items: List[AlertItemResponse]
    total: int
    limit: int
    offset: int
    counts_by_status: Dict[str, int] = Field(default_factory=dict)
    counts_by_severity: Dict[str, int] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class AlertMetricsResponse(BaseModel):
    total_alerts: int
    open_count: int
    critical_open: int
    high_open: int
    unacknowledged_count: int
    investigating_count: int
    resolved_count: int

    model_config = ConfigDict(from_attributes=True)


class AlertAcknowledgeRequest(BaseModel):
    analyst_name: Optional[str] = Field(None, description="Analyst acknowledging alert")
    note: Optional[str] = Field(None, description="Triage acknowledgement note")


class AlertAssignRequest(BaseModel):
    assigned_to: str = Field(..., min_length=1, description="Analyst or team assignment identity")
    analyst_name: Optional[str] = Field(None, description="Identity of analyst making assignment")


class AlertResolveRequest(BaseModel):
    resolution_reason: str = Field(..., min_length=3, description="Deterministic reason for resolution")
    analyst_name: Optional[str] = Field(None, description="Resolving analyst name")


class AlertFalsePositiveRequest(BaseModel):
    reason: str = Field(..., min_length=3, description="Justification why alert is benign / false positive")
    analyst_name: Optional[str] = Field(None, description="Analyst recording false positive")


class AlertSuppressRequest(BaseModel):
    reason: str = Field(..., min_length=3, description="Justification for alert suppression")
    scope: str = Field("THIS_ALERT", description="THIS_ALERT, INDICATOR, PATTERN")
    analyst_name: Optional[str] = Field(None, description="Analyst applying suppression")


class AlertAddNoteRequest(BaseModel):
    note: str = Field(..., min_length=1, description="Triage note or forensic case observation")
    analyst_name: Optional[str] = Field(None, description="Author of the note")


class AlertBulkAcknowledgeRequest(BaseModel):
    alert_ids: List[str] = Field(..., min_length=1, max_length=50)
    analyst_name: Optional[str] = None
