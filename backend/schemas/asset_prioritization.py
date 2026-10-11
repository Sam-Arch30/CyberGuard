"""
Section 64: Pydantic schemas for Risk-Based Asset Prioritization.
Provides contracts for priority bands, factor contributions, structured explanations,
policies, overrides, snapshots, and prioritized asset listings.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PriorityBandEnum(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    UNPRIORITIZED = "UNPRIORITIZED"


class PriorityDataQualityEnum(str, Enum):
    GOOD = "GOOD"
    DEGRADED = "DEGRADED"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class PriorityPolicyStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DRAFT = "DRAFT"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class PrioritizationFactorContribution(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    factor: str = Field(..., description="Factor identifier, e.g. unified_security_risk, business_criticality")
    label: str = Field(..., description="Human-readable factor title")
    value: Any = Field(..., description="Raw underlying value")
    points: float = Field(..., description="Normalized factor points (0.0 - 100.0)")
    weight: float = Field(..., description="Configured policy weight (0.0 - 1.0)")
    weighted_points: float = Field(..., description="Contribution to total score: points * weight")
    source: str = Field(..., description="Authoritative origin system")
    contribution_level: str = Field("MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE")
    description: str = Field(..., description="Explainable description of this factor's impact")


class PriorityDataQualityReport(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: str = Field("GOOD", description="GOOD, DEGRADED, STALE, UNKNOWN")
    issues: List[str] = Field(default_factory=list, description="List of detected data quality issues")
    stale_sources: List[str] = Field(default_factory=list, description="Sources with stale observations")
    uncertain_sources: List[str] = Field(default_factory=list, description="Attributes with missing/unknown values")


class PriorityExplanationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    asset_id: str
    canonical_name: str
    display_name: str
    asset_type: str
    priority_band: str
    priority_score: float
    effective_priority: str
    is_overridden: bool
    override_priority: Optional[str] = None
    override_reason: Optional[str] = None
    override_by: Optional[str] = None
    override_at: Optional[datetime] = None
    override_expires_at: Optional[datetime] = None
    contributors: List[PrioritizationFactorContribution] = Field(default_factory=list)
    data_quality: PriorityDataQualityReport
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    policy_version: int = 1
    calculated_at: Optional[datetime] = None


class PrioritizedAssetItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_type: str
    canonical_name: str
    display_name: str
    priority_band: str
    priority_score: float
    effective_priority: str
    is_overridden: bool
    override_priority: Optional[str] = None
    override_reason: Optional[str] = None
    risk_score: float
    risk_level: str
    criticality: str
    exposure_state: str
    environment: str
    owner: Optional[str] = None
    team: Optional[str] = None
    department: Optional[str] = None
    is_managed: bool
    is_stale: bool
    active_incident_count: int = 0
    priority_data_quality: str
    priority_calculated_at: Optional[datetime] = None
    last_seen_at: datetime


class PrioritizedAssetListResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    items: List[PrioritizedAssetItem]
    total: int
    p1_count: int
    p2_count: int
    p3_count: int
    p4_count: int
    unprioritized_count: int
    overridden_count: int
    limit: int
    offset: int


class PriorityHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    priority_band: str
    priority_score: float
    previous_priority_band: Optional[str] = None
    transition_type: str
    is_override: bool
    override_priority: Optional[str] = None
    override_reason: Optional[str] = None
    override_by: Optional[str] = None
    risk_score: float
    business_criticality: str
    exposure_state: str
    data_quality: str
    policy_version: int
    calculated_at: datetime


class PriorityHistoryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    items: List[PriorityHistoryItem]
    total: int


class PriorityOverrideRequest(BaseModel):
    priority: str = Field(..., description="Target priority band: P1, P2, P3, P4")
    reason: str = Field(..., min_length=3, description="Analyst reason for manual override")
    expires_in_hours: Optional[int] = Field(None, ge=1, le=8760, description="Optional expiry in hours")


class PriorityRecalculateRequest(BaseModel):
    asset_ids: Optional[List[str]] = Field(None, description="Optional subset of asset IDs; None recalculates all")
    force: bool = Field(False, description="Force recalculation even if recently calculated")


class PriorityPolicyCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    configuration: Dict[str, Any] = Field(..., description="Prioritization weights and thresholds configuration")


class PriorityPolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    configuration: Optional[Dict[str, Any]] = None


class PriorityPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    version: int
    status: str
    configuration: Dict[str, Any]
    created_by: str
    activated_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class PrioritizedAssetSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    canonical_name: str
    display_name: str
    asset_type: str
    effective_priority: str
    priority_score: float
    risk_score: float
    criticality: str
    exposure_state: str
    primary_reason: str
    owner: Optional[str] = None
    active_incidents: int = 0
