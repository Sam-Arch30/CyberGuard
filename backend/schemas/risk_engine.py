"""
Pydantic V2 Schemas for Section 26: Unified Risk Engine.

Defines schemas for:
- Normalized Risk Signals across diverse detection pipelines
- Deterministic Risk Assessments with explicit separation of Risk, Severity, Confidence, Uncertainty
- Structured breakdowns, counter-evidence, contradictions, and explanations
- Versioned configuration and history tracking
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict


class RiskScope(str, Enum):
    EVENT = "EVENT"
    INVESTIGATION = "INVESTIGATION"
    INCIDENT = "INCIDENT"
    CAMPAIGN = "CAMPAIGN"
    ENTITY = "ENTITY"


class RiskLevel(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskSeverityEnum(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SignalSemantics(str, Enum):
    THREAT_SCORE = "THREAT_SCORE"
    CONFIDENCE = "CONFIDENCE"
    PROBABILITY = "PROBABILITY"
    NOVELTY = "NOVELTY"
    ANOMALY_SCORE = "ANOMALY_SCORE"
    SEVERITY = "SEVERITY"
    BOOLEAN_INDICATOR = "BOOLEAN_INDICATOR"
    COUNT = "COUNT"
    DISTANCE = "DISTANCE"


class SignalDirection(str, Enum):
    SUPPORTING = "SUPPORTING"
    COUNTER = "COUNTER"
    CONTRADICTORY = "CONTRADICTORY"


class EvidenceFamily(str, Enum):
    IDENTITY = "IDENTITY"
    CONTENT = "CONTENT"
    URL = "URL"
    DOMAIN = "DOMAIN"
    FILE = "FILE"
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK = "NETWORK"
    API = "API"
    BEHAVIOR = "BEHAVIOR"
    NOVELTY = "NOVELTY"
    HISTORICAL = "HISTORICAL"
    GRAPH = "GRAPH"
    TEMPORAL = "TEMPORAL"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    MULTIMEDIA = "MULTIMEDIA"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    RULE_DETECTION = "RULE_DETECTION"


class UncertaintyLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    VERY_HIGH = "VERY_HIGH"


class RiskSignalCreate(BaseModel):
    signal_type: str = Field(..., min_length=2, max_length=100)
    source_type: str = Field(..., max_length=50)
    detector_id: str = Field(..., max_length=100)
    detector_version: str = Field("1.0.0", max_length=50)
    evidence_family: EvidenceFamily = EvidenceFamily.RULE_DETECTION
    semantics: SignalSemantics = SignalSemantics.THREAT_SCORE
    direction: SignalDirection = SignalDirection.SUPPORTING
    raw_score: float = Field(..., ge=0.0)
    reliability: float = Field(1.0, ge=0.0, le=1.0)
    correlation_group: Optional[str] = Field(None, max_length=255)
    evidence_refs: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)


class RiskSignalResponse(BaseModel):
    id: str
    assessment_id: str
    signal_type: str
    source_type: str
    detector_id: str
    detector_version: str
    evidence_family: EvidenceFamily
    semantics: SignalSemantics
    direction: SignalDirection
    raw_score: float
    normalized_score: float
    reliability: float
    weight: float
    contribution: float
    correlation_group: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskComponent(BaseModel):
    family: EvidenceFamily
    name: str
    contribution: float = Field(..., description="Calculated point contribution to final risk score")
    raw_value: Optional[float] = None
    direction: SignalDirection = SignalDirection.SUPPORTING
    correlation_group: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    description: str


class RiskContradiction(BaseModel):
    topic: str
    supporting_claim: str
    counter_claim: str
    supporting_signal_id: Optional[str] = None
    counter_signal_id: Optional[str] = None
    severity_impact: str = "Uncertainty elevated; confidence discounted"


class RiskExplanation(BaseModel):
    summary: str
    risk_level: RiskLevel
    risk_score: float
    severity: RiskSeverityEnum
    confidence: float
    uncertainty: UncertaintyLevel
    top_contributors: List[RiskComponent] = Field(default_factory=list)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    counter_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradictions: List[RiskContradiction] = Field(default_factory=list)
    uncertainty_factors: List[str] = Field(default_factory=list)
    contextual_factors: Dict[str, Any] = Field(default_factory=dict)
    limitations: List[str] = Field(default_factory=list)


class RiskAssessmentCreate(BaseModel):
    workspace_id: str = "default"
    scope_type: RiskScope = RiskScope.EVENT
    scope_id: str
    threat_event_id: Optional[str] = None
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    signals: List[RiskSignalCreate] = Field(default_factory=list)
    context_metadata: Dict[str, Any] = Field(default_factory=dict)
    reassessment_reason: Optional[str] = None


class RiskAssessmentResponse(BaseModel):
    id: str
    workspace_id: str
    scope_type: RiskScope
    scope_id: str
    threat_event_id: Optional[str] = None
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    risk_score: float
    risk_level: RiskLevel
    severity: RiskSeverityEnum
    confidence: float
    confidence_level: ConfidenceLevel
    uncertainty: UncertaintyLevel
    uncertainty_score: float
    version: int
    status: str
    parent_assessment_id: Optional[str] = None
    aggregation_version: str
    configuration_version: str
    components: List[RiskComponent] = Field(default_factory=list)
    signals: List[RiskSignalResponse] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    counter_evidence_refs: List[str] = Field(default_factory=list)
    contradictions: List[RiskContradiction] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    contextual_factors: Dict[str, Any] = Field(default_factory=dict)
    explanation_summary: Optional[str] = None
    created_by: str
    reassessment_reason: Optional[str] = None
    created_at: datetime
    evaluated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class RiskAssessmentHistoryResponse(BaseModel):
    assessment_id: str
    scope_type: RiskScope
    scope_id: str
    current_version: int
    history: List[RiskAssessmentResponse]


class RiskEvaluationRequest(BaseModel):
    workspace_id: str = "default"
    scope_type: RiskScope = RiskScope.EVENT
    scope_id: str
    threat_event_id: Optional[str] = None
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    additional_signals: List[RiskSignalCreate] = Field(default_factory=list)
    context_metadata: Dict[str, Any] = Field(default_factory=dict)


class RiskReassessRequest(BaseModel):
    workspace_id: str = "default"
    reassessment_reason: str = Field(..., min_length=3, max_length=255)
    additional_signals: List[RiskSignalCreate] = Field(default_factory=list)
    context_metadata: Dict[str, Any] = Field(default_factory=dict)


class RiskConfigurationSchema(BaseModel):
    version: str
    thresholds: Dict[str, Dict[str, Any]]
    confidence_levels: Dict[str, Dict[str, Any]]
    uncertainty_levels: Dict[str, Dict[str, Any]]
    family_caps: Dict[str, float]
    family_weights: Dict[str, float]
    correlation_discount_schedule: List[float]
    reliability_defaults: Dict[str, float]
    contextual_modifiers: Dict[str, float]
    severity_rules: Dict[str, Any]


class RiskDashboardStats(BaseModel):
    workspace_id: str
    total_assessments: int
    level_counts: Dict[str, int]
    severity_counts: Dict[str, int]
    average_risk_score: float
    average_confidence: float
    scope_counts: Dict[str, int]
    high_uncertainty_count: int
