"""
Section 60: Behavioral Detection & Anomaly Analytics Schemas.

Pydantic V2 models for behavioral profiles, multi-dimensional anomaly evaluation,
evidence-backed findings, cold-start lifecycle states, learning quarantine against
baseline poisoning, and SOC operational overviews.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ProfileStatusEnum(str, Enum):
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    LEARNING = "LEARNING"
    ACTIVE = "ACTIVE"
    STALE = "STALE"
    DEGRADED = "DEGRADED"
    SUSPENDED = "SUSPENDED"


class QuarantineDispositionEnum(str, Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class QuarantineReasonEnum(str, Enum):
    HIGH_ANOMALY = "HIGH_ANOMALY"
    UNVERIFIED_TELEMETRY = "UNVERIFIED_TELEMETRY"
    SUSPECTED_POISONING = "SUSPECTED_POISONING"
    SUSPICIOUS_BURST = "SUSPICIOUS_BURST"


class BehaviorProfileRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    entity_type: str
    entity_id: str
    entity_category: str
    profile_status: str
    sample_count: int
    first_observed_at: datetime
    last_observed_at: datetime
    last_anomaly_at: Optional[datetime] = None
    anomaly_count: int
    quality_status: str
    confidence_score: float
    baseline_version: str
    feature_schema_version: str
    active_metrics: List[str] = Field(default_factory=list)
    top_deviations: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


class BehaviorProfileDetail(BehaviorProfileRead):
    recent_deviations: List[Dict[str, Any]] = Field(default_factory=list)
    active_baselines: List[Dict[str, Any]] = Field(default_factory=list)
    pending_quarantine_count: int = 0


class BehavioralAnomalyDetail(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    entity_type: str
    entity_id: str
    metric_type: str
    observed_value: str
    baseline_expected_range: str
    deviation_score: float
    severity_hint: str
    direction: str
    explanation: str
    evidence_ids: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    finding_id: Optional[str] = None
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    created_at: datetime


class BehavioralEvaluationRequest(BaseModel):
    workspace_id: str = "default"
    entity_type: str
    entity_id: str
    metric_type: str
    observed_value: Any
    observed_at: Optional[datetime] = None
    event_id: Optional[str] = None
    context_data: Dict[str, Any] = Field(default_factory=dict)
    enforce_quarantine: bool = True


class BehavioralEvaluationResponse(BaseModel):
    evaluated: bool
    is_anomaly: bool
    deviation_score: float
    severity: str
    explanation: str
    profile_status: str
    quality_status: str
    quarantined: bool = False
    quarantine_reason: Optional[str] = None
    finding_id: Optional[str] = None
    alert_id: Optional[str] = None
    deviation_id: Optional[str] = None
    baseline_version: str = "1.0.0"


class LearningQuarantineItemRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    entity_type: str
    entity_id: str
    metric_type: str
    observed_value: str
    event_id: Optional[str] = None
    quarantine_reason: str
    disposition: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class QuarantineReviewRequest(BaseModel):
    disposition: QuarantineDispositionEnum
    review_notes: Optional[str] = None


class BehavioralOverviewStats(BaseModel):
    total_profiles: int
    active_profiles: int
    learning_profiles: int
    insufficient_profiles: int
    degraded_profiles: int
    anomalies_today: int
    high_severity_anomalies_today: int
    pending_quarantines: int
    recent_deviations: List[BehavioralAnomalyDetail] = Field(default_factory=list)


class BaselineRefreshRequest(BaseModel):
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    force_all: bool = False
