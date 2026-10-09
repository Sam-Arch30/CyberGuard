"""
Pydantic V2 Schemas for Section 27: Explainable AI (XAI).

Defines schemas for:
- Traceable, evidence-backed Explanation Units and Evidence Groups
- Decoupled explanation models preserving Section 26 authoritative risk values
- Progressive disclosure layers (Executive, Analyst, Investigator, Forensic)
- Counter-evidence, Contradictions, Unknowns, Missing Information, and Limitations
- Causal vs Temporal link distinctions
- Detector, Model, and Candidate Rule contribution audits
- Attack Path, MITRE, Novelty, Behavioral, and Threat Memory explanations
- "What Would Change This Assessment?" guidance
- Evidence Graph representation for UI and forensic tracing
- Analyst Feedback, Snapshots, and Explainability Quality Metrics
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, ConfigDict

from backend.schemas.risk_engine import (
    ConfidenceLevel,
    EvidenceFamily,
    RiskLevel,
    RiskSeverityEnum,
    UncertaintyLevel,
)


class ExplanationScope(str, Enum):
    EVENT = "EVENT"
    INVESTIGATION = "INVESTIGATION"
    INCIDENT = "INCIDENT"
    CAMPAIGN = "CAMPAIGN"
    ENTITY = "ENTITY"
    ATTACK_PATH = "ATTACK_PATH"
    STAGE = "STAGE"


class ExplanationLayer(str, Enum):
    EXECUTIVE = "EXECUTIVE"         # Level 1: 1-2 sentence high-level summary
    ANALYST = "ANALYST"             # Level 2: Top risk contributors, evidence, counter-evidence
    INVESTIGATOR = "INVESTIGATOR"   # Level 3: Full evidence chain, graph, MITRE, attack path
    FORENSIC = "FORENSIC"           # Level 4: Hashes, raw telemetry IDs, configuration versions, audit logs


class ClaimType(str, Enum):
    DETECTION = "DETECTION"
    IDENTITY = "IDENTITY"
    PHISHING = "PHISHING"
    MALWARE = "MALWARE"
    URL = "URL"
    DOMAIN = "DOMAIN"
    AUTHENTICATION = "AUTHENTICATION"
    NETWORK = "NETWORK"
    API = "API"
    BEHAVIOR = "BEHAVIOR"
    NOVELTY = "NOVELTY"
    CAMPAIGN = "CAMPAIGN"
    ATTACK_STAGE = "ATTACK_STAGE"
    ATTACK_PATH = "ATTACK_PATH"
    MITRE = "MITRE"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    RISK = "RISK"
    IMPACT = "IMPACT"


class SupportLevel(str, Enum):
    CONFIRMED = "CONFIRMED"
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MODERATE = "MODERATE"
    WEAK = "WEAK"
    CONTRADICTED = "CONTRADICTED"


class ContradictionSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ResolutionStatus(str, Enum):
    UNRESOLVED = "UNRESOLVED"
    RESOLVED_BENIGN = "RESOLVED_BENIGN"
    RESOLVED_MALICIOUS = "RESOLVED_MALICIOUS"
    EXPLAINED_BY_CONTEXT = "EXPLAINED_BY_CONTEXT"


class FeedbackType(str, Enum):
    ANALYST_CONFIRMED = "ANALYST_CONFIRMED"
    ANALYST_DISMISSED = "ANALYST_DISMISSED"
    ANALYST_CORRECTED = "ANALYST_CORRECTED"
    ANALYST_COMMENT = "ANALYST_COMMENT"


class ValidationStatus(str, Enum):
    VALIDATED = "VALIDATED"
    FALLBACK = "FALLBACK"
    REJECTED = "REJECTED"


# ============================================================================
# 1. CORE EXPLANATION UNITS & GROUPS
# ============================================================================

class ExplanationUnit(BaseModel):
    """
    Atomic evidence-backed explanation statement.
    Every claim must trace directly to one or more verified Evidence, Finding, or Signal records.
    """
    id: str = Field(description="Unique claim identifier, e.g. CLAIM-101")
    claim: str = Field(description="Factual, observable security assertion")
    claim_type: ClaimType = Field(description="Category of the claim")
    support_level: SupportLevel = Field(default=SupportLevel.HIGH, description="Strength of backing telemetry")
    evidence_refs: List[str] = Field(default_factory=list, description="Authoritative Evidence or Finding IDs")
    source_refs: List[str] = Field(default_factory=list, description="Original artifact or telemetry sources")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Calibrated confidence in claim (0.0-1.0)")
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)
    limitations: List[str] = Field(default_factory=list, description="Caveats or boundaries for this claim")
    explanation_order: int = Field(default=1, description="Priority ordering in presentation")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Detector, version, analysis run metadata")

    model_config = ConfigDict(extra="ignore")


class EvidenceGroup(BaseModel):
    """
    Correlated or independent group of evidence supporting an analytical theme.
    """
    family: EvidenceFamily = Field(description="Evidence family, e.g. IDENTITY, URL, AUTHENTICATION")
    name: str = Field(description="Human-readable title of evidence theme")
    summary: str = Field(description="Summary of findings in this group")
    claims: List[ExplanationUnit] = Field(default_factory=list)
    evidence_count: int = Field(default=0)
    is_independent: bool = Field(default=True, description="Whether this group acts as an independent corroborator")
    correlation_group: Optional[str] = Field(default=None, description="Shared correlation entity if grouped")

    model_config = ConfigDict(extra="ignore")


# ============================================================================
# 2. COUNTER-EVIDENCE, CONTRADICTIONS, UNKNOWNS, LIMITATIONS
# ============================================================================

class CounterEvidenceItem(BaseModel):
    """
    Evidence supporting non-threat / legitimate interpretation.
    Explainability must represent disagreement and exonerating factors.
    """
    claim: str = Field(description="Legitimate or exonerating observation (e.g. SPF/DKIM passed)")
    evidence_refs: List[str] = Field(default_factory=list)
    source: str = Field(description="Telemetry source providing counter-evidence")
    interpretation: str = Field(description="Contextual meaning of the counter-evidence")
    mitigation_strength: str = Field(default="MODERATE", description="HIGH, MODERATE, WEAK")

    model_config = ConfigDict(extra="ignore")


class ContradictionRecord(BaseModel):
    """
    Explicit record of conflicting signals or contradictory evidence.
    """
    id: str = Field(description="Contradiction identifier")
    claim: str = Field(description="Primary threat claim")
    conflicting_signal: str = Field(description="Conflicting counter-signal observed")
    evidence_refs: List[str] = Field(default_factory=list)
    severity: ContradictionSeverity = Field(default=ContradictionSeverity.MEDIUM)
    impact_on_confidence: str = Field(description="Effect on overall confidence (e.g. uncertainty elevated)")
    resolution_status: ResolutionStatus = Field(default=ResolutionStatus.UNRESOLVED)
    resolution_notes: Optional[str] = Field(default=None)

    model_config = ConfigDict(extra="ignore")


class UnknownItem(BaseModel):
    """
    Explicit representation of what the system does NOT know.
    """
    topic: str = Field(description="Area of inquiry")
    unknown: str = Field(description="What could not be determined")
    reason: str = Field(description="Why the data is unavailable")
    impact: str = Field(description="Impact on final assessment confidence")

    model_config = ConfigDict(extra="ignore")


class MissingInformationItem(BaseModel):
    """
    Identified gaps in telemetry.
    Missing information must not be silently treated as negative evidence.
    """
    telemetry_source: str = Field(description="Missing sensor or feed (e.g. Endpoint Telemetry)")
    description: str = Field(description="Description of what is missing")
    impact: str = Field(description="Analytical boundary caused by the gap")
    remedy: Optional[str] = Field(default=None, description="Action to acquire missing data")

    model_config = ConfigDict(extra="ignore")


class CausalLink(BaseModel):
    """
    Distinguishes strictly causal transitions from temporal correlations.
    """
    source_node: str = Field(description="Originating event or stage")
    target_node: str = Field(description="Subsequent event or stage")
    link_type: str = Field(description="CAUSAL, TEMPORAL_CORRELATION, BEHAVIORAL_FOLLOWUP")
    evidence_refs: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0)
    description: str = Field(description="Reasoning describing connection between events")

    model_config = ConfigDict(extra="ignore")


# ============================================================================
# 3. DETECTOR, MODEL, AND RULE CONTRIBUTIONS
# ============================================================================

class DetectorContribution(BaseModel):
    """
    Telemetry contribution from a specific analyzer or subsystem.
    """
    detector_id: str
    detector_name: str
    detector_version: str = "1.0.0"
    status: str = "TRIGGERED"  # TRIGGERED, OBSERVED, INACTIVE, ERROR
    finding: str
    evidence_refs: List[str] = Field(default_factory=list)
    contribution_points: float = 0.0
    is_independent: bool = True

    model_config = ConfigDict(extra="ignore")


class ModelContribution(BaseModel):
    """
    Machine learning model output explanation.
    Never exposes uncalibrated probability percentages.
    """
    model_name: str
    model_version: str
    feature_set: List[str] = Field(default_factory=list)
    output_label: str
    confidence_label: str = "HIGH"  # Categorical label, avoiding misleading pseudo-probabilities
    calibrated_score: Optional[float] = None
    evaluation_status: str = "VALIDATED"

    model_config = ConfigDict(extra="ignore")


class RuleContribution(BaseModel):
    """
    Candidate or active detection rule matches (Section 25).
    """
    rule_id: str
    rule_name: str
    rule_version: str = "v1"
    rule_type: str = "STRUCTURAL"
    matched_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    evaluation_status: str = "ACTIVE_MATCH"  # ACTIVE_MATCH, SHADOW_MATCH, SUPPRESSED

    model_config = ConfigDict(extra="ignore")


# ============================================================================
# 4. DOMAIN-SPECIFIC EXPLANATION COMPONENTS
# ============================================================================

class MITREExplanationItem(BaseModel):
    """
    Evidence-grounded explanation for MITRE ATT&CK technique mapping.
    """
    technique_id: str = Field(description="e.g. T1566.002")
    technique_name: str = Field(description="Spearphishing Link")
    tactic: str = Field(description="Initial Access")
    why_mapped: str = Field(description="Observable evidence justifying mapping")
    evidence_refs: List[str] = Field(default_factory=list)
    mapping_method: str = "DETERMINISTIC_RULE"
    mapping_status: str = "SUPPORTED"
    confidence: float = 0.90

    model_config = ConfigDict(extra="ignore")


class AttackPathExplanation(BaseModel):
    """
    Reconstructed attack path and temporal progression.
    """
    path_id: Optional[str] = None
    stage_sequence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_continuity: str = "HIGH"  # HIGH, MODERATE, LOW
    weakest_transitions: List[Dict[str, Any]] = Field(default_factory=list)
    bottleneck_summary: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class NoveltyExplanationItem(BaseModel):
    """
    Novelty context preserving distinction between unfamiliarity and malice.
    """
    entity_or_feature: str
    historical_observations: int = 0
    lookback_window_days: int = 90
    novelty_level: str = "HIGH"
    interpretation: str = "The entity is novel, but novelty alone does not establish maliciousness."

    model_config = ConfigDict(extra="ignore")


class BehavioralExplanationItem(BaseModel):
    """
    Statistical deviation explanation from Section 21 behavioral baseline.
    """
    entity_id: str
    metric: str
    typical_value: str
    observed_value: str
    deviation_score: float
    baseline_quality: str = "STABLE"

    model_config = ConfigDict(extra="ignore")


class ThreatMemoryExplanationItem(BaseModel):
    """
    Historical context from Section 23 Threat Memory.
    """
    indicator: str
    memory_id: str
    previous_investigations_count: int = 0
    previous_outcomes: Dict[str, int] = Field(default_factory=dict)
    most_recent_observation_days_ago: Optional[int] = None
    status: str = "OBSERVED"  # VERIFIED, OBSERVED, CORRELATED, DISMISSED, EXPIRED, SUPERSEDED
    summary: str = ""

    model_config = ConfigDict(extra="ignore")


class AssessmentChangeGuidance(BaseModel):
    """
    Actionable guidance on what would strengthen or weaken the current security assessment.
    """
    what_would_strengthen: List[str] = Field(default_factory=list)
    what_would_weaken: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


# ============================================================================
# 5. EVIDENCE GRAPH FOR INTERACTIVE TRACEABILITY
# ============================================================================

class EvidenceGraphNode(BaseModel):
    id: str
    label: str
    node_type: str  # CONCLUSION, FINDING, EVIDENCE, ARTIFACT, DETECTOR, RULE, MITRE
    category: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(extra="ignore")


class EvidenceGraphEdge(BaseModel):
    source: str
    target: str
    relation: str  # supported_by, derived_from, observed_in, mapped_to, triggered_by
    evidence_ref: Optional[str] = None

    model_config = ConfigDict(extra="ignore")


class EvidenceGraph(BaseModel):
    nodes: List[EvidenceGraphNode] = Field(default_factory=list)
    edges: List[EvidenceGraphEdge] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


# ============================================================================
# 6. EXPLANATION RESPONSES & PROGRESSIVE DISCLOSURE
# ============================================================================

class ExplanationResponse(BaseModel):
    """
    Full structured Explanation response supporting progressive disclosure.
    """
    id: str
    workspace_id: str
    scope_type: ExplanationScope
    scope_id: str
    explanation_version: int = 1
    risk_assessment_id: Optional[str] = None
    threat_event_id: Optional[str] = None
    incident_id: Optional[str] = None

    # Authoritative Section 26 metrics (consumed, NOT recalculated)
    risk_score: float
    risk_level: RiskLevel
    severity: RiskSeverityEnum
    confidence: float
    confidence_level: ConfidenceLevel
    uncertainty: UncertaintyLevel

    # Progressive Disclosure Summaries
    summary: str
    executive_summary: str  # Level 1
    analyst_summary: str    # Level 2
    generated_text: Optional[str] = None

    # Structured Components
    conclusions: List[Dict[str, Any]] = Field(default_factory=list)
    explanation_units: List[ExplanationUnit] = Field(default_factory=list)
    evidence_groups: List[EvidenceGroup] = Field(default_factory=list)
    contributors: List[Dict[str, Any]] = Field(default_factory=list)
    counter_evidence: List[CounterEvidenceItem] = Field(default_factory=list)
    contradictions: List[ContradictionRecord] = Field(default_factory=list)
    uncertainty_items: List[UnknownItem] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    missing_information: List[MissingInformationItem] = Field(default_factory=list)
    causal_links: List[CausalLink] = Field(default_factory=list)

    # Attribution & Provenance
    detector_contributions: List[DetectorContribution] = Field(default_factory=list)
    model_contributions: List[ModelContribution] = Field(default_factory=list)
    rule_contributions: List[RuleContribution] = Field(default_factory=list)
    mitre_explanations: List[MITREExplanationItem] = Field(default_factory=list)
    attack_path_explanation: AttackPathExplanation = Field(default_factory=AttackPathExplanation)
    novelty_explanation: Optional[NoveltyExplanationItem] = None
    behavioral_explanation: Optional[BehavioralExplanationItem] = None
    threat_memory_explanation: Optional[ThreatMemoryExplanationItem] = None
    assessment_change_guidance: AssessmentChangeGuidance = Field(default_factory=AssessmentChangeGuidance)

    # Traceability Graph
    evidence_graph: EvidenceGraph = Field(default_factory=EvidenceGraph)

    # Progressive Details
    investigator_details: Dict[str, Any] = Field(default_factory=dict)  # Level 3
    forensic_details: Dict[str, Any] = Field(default_factory=dict)      # Level 4

    validation_status: ValidationStatus = ValidationStatus.VALIDATED
    validation_details: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, extra="ignore")


# ============================================================================
# 7. FEEDBACK, SNAPSHOTS, & METRICS
# ============================================================================

class ExplanationFeedbackCreate(BaseModel):
    analyst_id: str = Field(..., max_length=100)
    feedback_type: FeedbackType
    target_claim_id: Optional[str] = Field(None, max_length=64)
    notes: str = Field(..., min_length=3, max_length=2000)
    correction_payload: Dict[str, Any] = Field(default_factory=dict)


class ExplanationFeedbackResponse(BaseModel):
    id: str
    explanation_id: str
    workspace_id: str
    analyst_id: str
    feedback_type: FeedbackType
    target_claim_id: Optional[str] = None
    notes: str
    correction_payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ExplanationSnapshotResponse(BaseModel):
    id: str
    explanation_id: str
    workspace_id: str
    scope_type: str
    scope_id: str
    assessment_version: int
    explanation_version: int
    evidence_snapshot: List[Dict[str, Any]] = Field(default_factory=list)
    risk_snapshot: Dict[str, Any] = Field(default_factory=dict)
    model_versions: Dict[str, Any] = Field(default_factory=dict)
    rule_versions: Dict[str, Any] = Field(default_factory=dict)
    checksum: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NarrativeGenerationRequest(BaseModel):
    explanation_id: Optional[str] = None
    scope_type: ExplanationScope = ExplanationScope.EVENT
    scope_id: str
    detail_level: ExplanationLayer = ExplanationLayer.ANALYST
    strict_validation: bool = True


class NarrativeGenerationResponse(BaseModel):
    explanation_id: str
    narrative: str
    validation_passed: bool
    used_fallback: bool
    unsupported_entities_detected: List[str] = Field(default_factory=list)
    generation_duration_ms: float
    model_used: str


class ExplanationQualityMetrics(BaseModel):
    """
    Internal explainability quality metrics (NOT security accuracy metrics).
    Measures forensic grounding completeness and rigor.
    """
    total_claims: int
    grounded_claims: int
    claim_grounding_rate: float  # grounded / total
    unsupported_claim_rate: float
    counter_evidence_count: int
    contradiction_count: int
    independent_evidence_families: int
    provenance_resolution_rate: float
    evidence_coverage: float
    fallback_rate: float
    validation_failure_count: int

    model_config = ConfigDict(extra="ignore")
