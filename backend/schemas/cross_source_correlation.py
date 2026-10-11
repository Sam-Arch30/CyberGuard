"""
Section 61: Cross-Source Correlation & Unified Entity Correlation Schemas.
Provides data contracts for deterministic entity resolution, normalized correlation signals,
bounded cross-source correlations, composite findings, and evidence-backed explanations.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# 1. CONTROLLED TAXONOMY & ENUMS
# ============================================================================

class CorrelationTypeEnum(str, Enum):
    SAME_ENTITY = "SAME_ENTITY"
    SAME_INDICATOR = "SAME_INDICATOR"
    SHARED_INFRASTRUCTURE = "SHARED_INFRASTRUCTURE"
    TEMPORAL_ATTACK_SEQUENCE = "TEMPORAL_ATTACK_SEQUENCE"
    SHARED_ARTIFACT = "SHARED_ARTIFACT"
    AUTH_AND_ENDPOINT = "AUTH_AND_ENDPOINT"
    EMAIL_URL_DOMAIN_IP = "EMAIL_URL_DOMAIN_IP"
    API_AND_NETWORK = "API_AND_NETWORK"
    BEHAVIORAL_AND_RULE_DETECTION = "BEHAVIORAL_AND_RULE_DETECTION"
    WATCHLIST_AND_OBSERVATION = "WATCHLIST_AND_OBSERVATION"


class CorrelationStatusEnum(str, Enum):
    CANDIDATE = "CANDIDATE"
    CORRELATED = "CORRELATED"
    PARTIALLY_CORRELATED = "PARTIALLY_CORRELATED"
    STALE = "STALE"
    INVALIDATED = "INVALIDATED"
    ARCHIVED = "ARCHIVED"


class CorrelationConfidenceEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class MemberTypeEnum(str, Enum):
    ENTITY = "ENTITY"
    FINDING = "FINDING"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    INDICATOR = "INDICATOR"
    EVIDENCE = "EVIDENCE"
    RELATIONSHIP = "RELATIONSHIP"
    SIGNAL = "SIGNAL"


class SourceTypeEnum(str, Enum):
    EMAIL = "EMAIL"
    ENDPOINT = "ENDPOINT"
    NETWORK = "NETWORK"
    AUTH = "AUTH"
    API = "API"
    BEHAVIORAL = "BEHAVIORAL"
    DETECTION_RULE = "DETECTION_RULE"
    THREAT_INTEL = "THREAT_INTEL"
    WATCHLIST = "WATCHLIST"
    GENERIC = "GENERIC"


class ResolutionMethodEnum(str, Enum):
    EXACT_ID = "EXACT_ID"
    CANONICAL_NORMALIZATION = "CANONICAL_NORMALIZATION"
    COMPOSITE_KEY = "COMPOSITE_KEY"
    GRAPH_LINK = "GRAPH_LINK"
    FUZZY_MATCH = "FUZZY_MATCH"
    UNRESOLVED = "UNRESOLVED"


class ResolutionStatusEnum(str, Enum):
    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


# ============================================================================
# 2. SIGNAL & RESOLUTION DTOs
# ============================================================================

class CorrelationSignal(BaseModel):
    """
    Normalized security observation ready for cross-source temporal & entity alignment.
    """
    signal_id: str
    workspace_id: str = "default"
    source_type: SourceTypeEnum
    source_id: str
    signal_type: str
    entity_refs: List[str] = Field(default_factory=list)
    finding_refs: List[str] = Field(default_factory=list)
    indicator_refs: List[str] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    occurred_at: datetime
    received_at: Optional[datetime] = None
    processed_at: Optional[datetime] = None
    severity: str = "LOW"
    confidence: float = 1.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    schema_version: str = "1.0.0"


class EntityResolutionRequest(BaseModel):
    """
    Request to resolve an entity identifier into a canonical knowledge graph entity.
    """
    entity_type: str
    raw_identifier: str
    workspace_id: str = "default"
    context: Optional[str] = None
    allow_fuzzy: bool = False


class EntityResolutionResult(BaseModel):
    """
    Deterministic entity resolution response with complete provenance facts.
    """
    entity_type: str
    raw_identifier: str
    normalized_identifier: str
    canonical_entity_id: Optional[str] = None
    canonical_key: Optional[str] = None
    display_name: Optional[str] = None
    resolution_method: ResolutionMethodEnum
    resolution_confidence: float
    status: ResolutionStatusEnum
    matched_attributes: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# 3. CORRELATION QUERY & RESPONSE DTOs
# ============================================================================

class CorrelationMemberRead(BaseModel):
    """
    Single contributing member of a Cross-Source Correlation.
    """
    id: str
    correlation_id: str
    member_type: MemberTypeEnum
    member_id: str
    source_type: SourceTypeEnum
    role: str
    occurred_at: Optional[datetime] = None
    confidence: float = 1.0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class CrossSourceCorrelationRead(BaseModel):
    """
    Summary view of a Cross-Source Correlation for tables, cards, and feeds.
    """
    id: str
    workspace_id: str
    correlation_number: str
    correlation_type: CorrelationTypeEnum
    title: str
    description: str
    status: CorrelationStatusEnum
    confidence_score: float
    confidence_level: CorrelationConfidenceEnum
    risk_score: float
    risk_level: str
    severity: str
    first_observed_at: datetime
    last_observed_at: datetime
    time_window_seconds: float
    parent_finding_id: Optional[str] = None
    alert_id: Optional[str] = None
    incident_id: Optional[str] = None
    campaign_id: Optional[str] = None
    explanation_summary: str
    member_count: int = 0
    sources: List[str] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    analyst_disposition: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CrossSourceCorrelationDetail(CrossSourceCorrelationRead):
    """
    Full progressive-disclosure detail view for analysts and investigators.
    """
    members: List[CorrelationMemberRead] = Field(default_factory=list)
    supporting_reasons: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    missing_context: List[str] = Field(default_factory=list)
    quality_metrics: Dict[str, Any] = Field(default_factory=dict)
    rule_version: str = "1.0.0"
    schema_version: str = "1.0.0"
    analyst_notes: Optional[str] = None
    dispositioned_by: Optional[str] = None
    dispositioned_at: Optional[datetime] = None


class CorrelationTimelineItem(BaseModel):
    """
    Chronological activity milestone in a correlated cross-source sequence.
    """
    timestamp: datetime
    source_type: str
    event_type: str
    description: str
    member_id: str
    severity: str = "INFO"
    confidence: float = 1.0
    details: Dict[str, Any] = Field(default_factory=dict)


class WhyCorrelatedExplanation(BaseModel):
    """
    Structured progressive-disclosure explanation for the 'Why Correlated?' panel.
    """
    correlation_id: str
    correlation_type: CorrelationTypeEnum
    confidence_score: float
    risk_score: float
    time_window_human: str
    primary_facts: List[str] = Field(default_factory=list)
    shared_entities: List[Dict[str, Any]] = Field(default_factory=list)
    shared_indicators: List[Dict[str, Any]] = Field(default_factory=list)
    temporal_chain: List[Dict[str, Any]] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    missing_context: List[str] = Field(default_factory=list)
    data_quality_assessment: Dict[str, Any] = Field(default_factory=dict)


class CorrelationDispositionRequest(BaseModel):
    """
    Analyst review action to confirm, reject, or mark a correlation as uncertain.
    """
    disposition: str = Field(..., description="CONFIRMED, REJECTED, or UNCERTAIN")
    notes: str = Field(..., description="Analyst rationale and justification notes")
    actor: str = Field("analyst", description="Analyst user or role identifier")


class CorrelationOverviewStats(BaseModel):
    """
    Platform-wide correlation executive and operational health KPIs.
    """
    total_correlations: int = 0
    active_correlations: int = 0
    correlated_threats: int = 0
    high_confidence_sequences: int = 0
    entities_resolved: int = 0
    avg_time_window_seconds: float = 0.0
    correlations_by_type: Dict[str, int] = Field(default_factory=dict)
    correlations_by_source: Dict[str, int] = Field(default_factory=dict)


class CorrelationEvaluationRequest(BaseModel):
    """
    Trigger real-time cross-source correlation evaluation on an entity or finding.
    """
    workspace_id: str = "default"
    entity_id: Optional[str] = None
    finding_id: Optional[str] = None
    incident_id: Optional[str] = None
    correlation_window_minutes: int = 60
