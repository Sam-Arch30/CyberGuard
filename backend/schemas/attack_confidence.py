"""
Attack Path Confidence & Explainability Engine Schemas (Section 18).
Defines canonical confidence vocabulary, multidimensional breakdown models,
evidence family lineage, source trust hierarchy, contradiction models,
evidence gap models, hypothesis comparison structures, and report-ready explanations.

CORE PRINCIPLES:
1. CONFIDENCE IS NOT CERTAINTY:
   Confidence represents heuristic evidence strength (0.0-1.0) for a specific conclusion,
   NOT statistical probability that CyberGuard is correct.
2. EXPLAINABILITY FROM EVIDENCE:
   Evidence -> structured reasoning -> confidence decomposition -> explanation.
   Explanations are never generated prior to evidence analysis.
3. CONFIDENCE != RISK != SEVERITY:
   Confidence measures evidence strength. Risk is likelihood x impact. Severity is potential harm.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# 1. CANONICAL VOCABULARY & ENUMS
# ============================================================================

class ConfidenceLevel(str, Enum):
    """
    Canonical 6-level confidence vocabulary across CyberGuard attack reconstruction.
    """
    VERY_LOW = "VERY_LOW"      # Heuristic score: 0.00 - 0.19
    LOW = "LOW"                # Heuristic score: 0.20 - 0.39
    MODERATE = "MODERATE"      # Heuristic score: 0.40 - 0.59
    HIGH = "HIGH"              # Heuristic score: 0.60 - 0.79
    VERY_HIGH = "VERY_HIGH"    # Heuristic score: 0.80 - 1.00
    UNKNOWN = "UNKNOWN"        # Detector unavailable or inconclusive evidence


class SourceTrustLevel(str, Enum):
    """
    Categorical source trust classification.
    Trust affects evidence weight but does not replace forensic evidence semantics.
    """
    DIRECT_TELEMETRY = "DIRECT_TELEMETRY"            # Server auth log, network sensor, API gateway log, crypto hash
    DERIVED_DETERMINISTIC = "DERIVED_DETERMINISTIC"  # DNS resolution, regex match, base64 payload decoding
    LOCAL_MODEL = "LOCAL_MODEL"                      # Local ML model: anomaly detector, NLP, deepfake detector
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"  # Third-party intelligence, WHOIS, IP reputation
    USER_SUPPLIED = "USER_SUPPLIED"                  # User report, helpdesk ticket, analyst manual input
    UNTRUSTED_CONTENT = "UNTRUSTED_CONTENT"          # Sender-controlled email headers, unverified metadata
    LLM_DERIVED = "LLM_DERIVED"                      # LLM summarization or extraction (uncalibrated)


class ConfidenceDimension(str, Enum):
    """
    Granular dimensions contributing to heuristic evidence strength.
    Confidence is NEVER an opaque single number.
    """
    OBSERVATION_STRENGTH = "OBSERVATION_STRENGTH"      # Direct authoritative telemetry vs circumstantial
    ENTITY_CONTINUITY = "ENTITY_CONTINUITY"            # Same session/account/device vs generic IP/ASN
    TEMPORAL_CONSISTENCY = "TEMPORAL_CONSISTENCY"      # Logical ordering, tight time delta, low skew
    GRAPH_CONNECTIVITY = "GRAPH_CONNECTIVITY"          # Provenance-backed graph edges connecting entities
    SOURCE_INDEPENDENCE = "SOURCE_INDEPENDENCE"        # Corroboration across independent sensor families
    INDICATOR_SPECIFICITY = "INDICATOR_SPECIFICITY"    # Rare high-entropy IOC vs common CDN/cloud IP
    DETECTOR_CONFIDENCE = "DETECTOR_CONFIDENCE"        # Normalized underlying analyzer score
    HISTORICAL_SUPPORT = "HISTORICAL_SUPPORT"          # Cross-incident pattern / campaign corroboration
    CONTRADICTION_STRENGTH = "CONTRADICTION_STRENGTH"  # Impact of conflicting or baseline-matching evidence
    EVIDENCE_COMPLETENESS = "EVIDENCE_COMPLETENESS"    # Ratio of observed transitions to missing critical telemetry


class ContradictionType(str, Enum):
    """
    Structured types of evidence conflicting with an attack hypothesis.
    """
    MANAGED_DEVICE = "MANAGED_DEVICE"                  # Confirmed corporate-enrolled managed device
    CORPORATE_VPN = "CORPORATE_VPN"                    # Source IP belongs to corporate egress/VPN range
    EXPECTED_MFA = "EXPECTED_MFA"                      # Expected, verified multi-factor challenge succeeded
    TELEMETRY_DISCREPANCY = "TELEMETRY_DISCREPANCY"    # Authoritative log indicates different origin or actor
    NORMAL_BASELINE = "NORMAL_BASELINE"                # Activity strictly matches established historical baseline
    VERIFIED_LEGITIMATE_TRAVEL = "VERIFIED_LEGITIMATE_TRAVEL"  # User travel explains impossible velocity
    CONFLICTING_TIMELINE = "CONFLICTING_TIMELINE"      # Concurrently active in verified physical location
    CUSTOM_CONTRADICTION = "CUSTOM_CONTRADICTION"      # Custom contextual contradiction


class EvidenceGapType(str, Enum):
    """
    Controlled catalog of absent forensic telemetry.
    Differentiated from contradictions: missing != contradictory.
    """
    NO_CLICK_TELEMETRY = "NO_CLICK_TELEMETRY"
    NO_PROCESS_TELEMETRY = "NO_PROCESS_TELEMETRY"
    NO_CREDENTIAL_CAPTURE_EVIDENCE = "NO_CREDENTIAL_CAPTURE_EVIDENCE"
    NO_ENDPOINT_TELEMETRY = "NO_ENDPOINT_TELEMETRY"
    NO_DIRECT_EXFILTRATION_CONFIRMATION = "NO_DIRECT_EXFILTRATION_CONFIRMATION"
    NO_IDENTITY_REFERENCE = "NO_IDENTITY_REFERENCE"
    NO_MEDIA_PROVENANCE = "NO_MEDIA_PROVENANCE"
    DETECTOR_UNAVAILABLE = "DETECTOR_UNAVAILABLE"


# ============================================================================
# 2. CONFIGURATION & VERSIONING
# ============================================================================

class ConfidenceConfig(BaseModel):
    """
    Configurable, versioned threshold and weight specifications.
    Ensures historical confidence assessments remain reproducible.
    """
    model_config = ConfigDict(extra="ignore")

    engine_version: str = "1.0.0"
    configuration_version: str = "2026.10"
    rule_version: str = "1.0.0"

    threshold_very_low: float = 0.20
    threshold_low: float = 0.40
    threshold_moderate: float = 0.60
    threshold_high: float = 0.80

    dimension_weights: Dict[str, float] = Field(default_factory=lambda: {
        ConfidenceDimension.OBSERVATION_STRENGTH.value: 0.22,
        ConfidenceDimension.ENTITY_CONTINUITY.value: 0.18,
        ConfidenceDimension.TEMPORAL_CONSISTENCY.value: 0.15,
        ConfidenceDimension.GRAPH_CONNECTIVITY.value: 0.12,
        ConfidenceDimension.SOURCE_INDEPENDENCE.value: 0.12,
        ConfidenceDimension.INDICATOR_SPECIFICITY.value: 0.08,
        ConfidenceDimension.DETECTOR_CONFIDENCE.value: 0.05,
        ConfidenceDimension.HISTORICAL_SUPPORT.value: 0.04,
        ConfidenceDimension.CONTRADICTION_STRENGTH.value: 0.02,
        ConfidenceDimension.EVIDENCE_COMPLETENESS.value: 0.02,
    })

    source_trust_weights: Dict[str, float] = Field(default_factory=lambda: {
        SourceTrustLevel.DIRECT_TELEMETRY.value: 0.95,
        SourceTrustLevel.DERIVED_DETERMINISTIC.value: 0.85,
        SourceTrustLevel.LOCAL_MODEL.value: 0.70,
        SourceTrustLevel.EXTERNAL_INTELLIGENCE.value: 0.65,
        SourceTrustLevel.USER_SUPPLIED.value: 0.45,
        SourceTrustLevel.LLM_DERIVED.value: 0.35,
        SourceTrustLevel.UNTRUSTED_CONTENT.value: 0.25,
    })

    contradiction_penalties: Dict[str, float] = Field(default_factory=lambda: {
        ContradictionType.TELEMETRY_DISCREPANCY.value: 0.45,
        ContradictionType.CORPORATE_VPN.value: 0.35,
        ContradictionType.MANAGED_DEVICE.value: 0.30,
        ContradictionType.EXPECTED_MFA.value: 0.25,
        ContradictionType.NORMAL_BASELINE.value: 0.20,
        ContradictionType.VERIFIED_LEGITIMATE_TRAVEL.value: 0.30,
        ContradictionType.CONFLICTING_TIMELINE.value: 0.40,
        ContradictionType.CUSTOM_CONTRADICTION.value: 0.20,
    })

    gap_penalties: Dict[str, float] = Field(default_factory=lambda: {
        EvidenceGapType.NO_CLICK_TELEMETRY.value: 0.25,
        EvidenceGapType.NO_CREDENTIAL_CAPTURE_EVIDENCE.value: 0.30,
        EvidenceGapType.NO_DIRECT_EXFILTRATION_CONFIRMATION.value: 0.30,
        EvidenceGapType.NO_PROCESS_TELEMETRY.value: 0.20,
        EvidenceGapType.NO_ENDPOINT_TELEMETRY.value: 0.15,
        EvidenceGapType.NO_IDENTITY_REFERENCE.value: 0.15,
        EvidenceGapType.NO_MEDIA_PROVENANCE.value: 0.10,
        EvidenceGapType.DETECTOR_UNAVAILABLE.value: 0.05,
    })


def score_to_confidence_level(
    score: Optional[float],
    config: Optional[ConfidenceConfig] = None
) -> ConfidenceLevel:
    """
    Maps an internal heuristic evidence score (0.0-1.0) into the canonical ConfidenceLevel.
    """
    if score is None:
        return ConfidenceLevel.UNKNOWN
    cfg = config or ConfidenceConfig()
    if score < cfg.threshold_very_low:
        return ConfidenceLevel.VERY_LOW
    elif score < cfg.threshold_low:
        return ConfidenceLevel.LOW
    elif score < cfg.threshold_moderate:
        return ConfidenceLevel.MODERATE
    elif score < cfg.threshold_high:
        return ConfidenceLevel.HIGH
    return ConfidenceLevel.VERY_HIGH


# ============================================================================
# 3. EVIDENCE FAMILY & LINEAGE
# ============================================================================

class EvidenceFamily(BaseModel):
    """
    Groups evidence items sharing the same root observation to prevent double-counting.
    e.g. Lookalike domain finding and Impersonation signal both derived from the same domain observation.
    """
    model_config = ConfigDict(extra="ignore")

    family_id: str = Field(description="Unique identifier for root evidence family")
    root_observation_key: str = Field(description="Root entity or raw observation source identifier")
    source_trust: SourceTrustLevel = Field(default=SourceTrustLevel.DIRECT_TELEMETRY)
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of raw evidence items in family")
    finding_ids: List[str] = Field(default_factory=list, description="Derived findings originating from this family")
    description: str = Field(default="", description="Descriptive summary of the observation source")


# ============================================================================
# 4. CONTRADICTIONS & EVIDENCE GAPS
# ============================================================================

class ContradictionItem(BaseModel):
    """
    Explicit piece of evidence that contradicts or weakens an attack hypothesis.
    """
    model_config = ConfigDict(extra="ignore")

    subject_id: str = Field(description="Stage, edge, path, or hypothesis UUID affected")
    subject_type: str = Field(description="STAGE, TRANSITION, PATH, or HYPOTHESIS")
    type: ContradictionType = Field(description="Standard contradiction taxonomy")
    evidence_id: Optional[str] = Field(default=None, description="Conflicting evidence UUID if known")
    penalty: float = Field(default=0.25, ge=0.0, le=1.0, description="Deduction applied to evidence strength")
    description: str = Field(description="Clear analyst-readable explanation of contradiction")
    resolution_hint: Optional[str] = Field(default=None, description="Investigative action to resolve conflict")


class EvidenceGapItem(BaseModel):
    """
    Identified absence of forensic telemetry affecting reconstruction confidence.
    """
    model_config = ConfigDict(extra="ignore")

    gap_type: EvidenceGapType = Field(description="Categorical gap code")
    affected_stages: List[str] = Field(default_factory=list, description="Stage UUIDs impacted")
    affected_transitions: List[str] = Field(default_factory=list, description="Transition/Edge UUIDs impacted")
    impact_description: str = Field(description="Explanation of why this gap limits certainty")
    penalty: float = Field(default=0.15, ge=0.0, le=1.0, description="Deduction applied to confidence")
    what_would_strengthen: List[str] = Field(default_factory=list, description="Telemetry that would verify step")
    what_would_weaken: List[str] = Field(default_factory=list, description="Telemetry that would refute step")


# ============================================================================
# 5. CONFIDENCE BREAKDOWN & COMPONENTS
# ============================================================================

class ConfidenceComponent(BaseModel):
    """
    Single evaluated dimension contributing to a confidence breakdown.
    """
    model_config = ConfigDict(extra="ignore")

    dimension: ConfidenceDimension = Field(description="Evaluated dimension")
    score: float = Field(ge=0.0, le=1.0, description="Heuristic score for this dimension (0.0-1.0)")
    weight: float = Field(ge=0.0, le=1.0, description="Weight in composite formula")
    weighted_score: float = Field(ge=0.0, le=1.0, description="score * weight")
    evidence_ids: List[str] = Field(default_factory=list, description="Specific evidence IDs assessed")
    reason: str = Field(description="Detailed reason explaining score assignment")
    limitations: List[str] = Field(default_factory=list, description="Limitations or caveats identified")


class ConfidenceBottleneck(BaseModel):
    """
    Identifies the weakest link in an attack path to prevent misleading averages.
    A path with 5 high-confidence stages and 1 speculative transition is bounded by the bottleneck.
    """
    model_config = ConfigDict(extra="ignore")

    bottleneck_id: str = Field(description="Identifier for bottleneck report")
    bottleneck_type: str = Field(description="STAGE or TRANSITION")
    subject_id: str = Field(description="Stage or Edge UUID")
    subject_name: str = Field(description="Human-readable title (e.g. Phishing -> Credential Compromise)")
    confidence: float = Field(ge=0.0, le=1.0, description="Score of weakest link")
    confidence_level: ConfidenceLevel = Field(description="Categorical level of weakest link")
    primary_uncertainty: str = Field(description="Summary of why this link is speculative")
    affected_stages: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class ConfidenceBreakdown(BaseModel):
    """
    Full transparent audit breakdown for an attack stage, transition, path, or hypothesis.
    """
    model_config = ConfigDict(extra="ignore")

    subject_type: str = Field(description="STAGE, TRANSITION, PATH, or HYPOTHESIS")
    subject_id: str = Field(description="Subject UUID")
    raw_score: float = Field(ge=0.0, le=1.0, description="Normalized internal heuristic score (NOT probability)")
    confidence_level: ConfidenceLevel = Field(description="Banded categorical level")
    epistemic_status: str = Field(default="INFERRED", description="OBSERVED, DERIVED, INFERRED, UNRESOLVED")
    components: List[ConfidenceComponent] = Field(default_factory=list)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[ContradictionItem] = Field(default_factory=list)
    missing_evidence: List[EvidenceGapItem] = Field(default_factory=list)
    evidence_families: List[EvidenceFamily] = Field(default_factory=list)
    independent_sources_count: int = Field(default=1, description="Count of independent sensor sources")
    adjustments: List[Dict[str, Any]] = Field(default_factory=list, description="Audit log of score adjustments")
    engine_version: str = Field(default="1.0.0")
    configuration_version: str = "2026.10"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ConfidenceAudit(BaseModel):
    """
    Reproducible audit log of confidence inputs, weights, adjustments, and output.
    """
    model_config = ConfigDict(extra="ignore")

    subject_id: str
    subject_type: str
    inputs: Dict[str, Any] = Field(default_factory=dict)
    weights: Dict[str, float] = Field(default_factory=dict)
    adjustments: List[Dict[str, Any]] = Field(default_factory=list)
    final_score: float
    final_level: ConfidenceLevel
    engine_version: str
    configuration_version: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# 6. EXPLANATION SCHEMAS
# ============================================================================

class Explanation(BaseModel):
    """
    Complete evidence-grounded explanation for an attack stage, transition, path, or hypothesis.
    """
    model_config = ConfigDict(extra="ignore")

    subject_type: str = Field(description="STAGE, TRANSITION, PATH, or HYPOTHESIS")
    subject_id: str = Field(description="Target UUID")
    title: str = Field(description="Concise analytical title")
    summary: str = Field(description="One-paragraph analyst-readable conclusion")
    why: List[str] = Field(default_factory=list, description="Bulleted evidence-backed reasons")
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[ContradictionItem] = Field(default_factory=list)
    missing_evidence: List[EvidenceGapItem] = Field(default_factory=list)
    confidence_breakdown: ConfidenceBreakdown = Field(description="Decomposed evidence strength")
    alternative_explanations: List[str] = Field(default_factory=list, description="Plausible non-malicious alternatives")
    what_would_strengthen: List[str] = Field(default_factory=list, description="Targeted telemetry that would prove conclusion")
    what_would_weaken: List[str] = Field(default_factory=list, description="Telemetry that would disprove conclusion")
    limitations: List[str] = Field(default_factory=list, description="Known visibility boundaries and caveats")


class HypothesisComparisonResult(BaseModel):
    """
    Deterministic comparison explaining why one hypothesis ranks higher than another.
    Eliminates black-box hypothesis ranking.
    """
    model_config = ConfigDict(extra="ignore")

    hypothesis_a_id: str
    hypothesis_a_title: str
    hypothesis_a_score: float
    hypothesis_a_level: ConfidenceLevel
    hypothesis_b_id: str
    hypothesis_b_title: str
    hypothesis_b_score: float
    hypothesis_b_level: ConfidenceLevel
    winning_hypothesis_id: Optional[str] = None
    score_difference: float = 0.0
    why_ranks_higher: List[str] = Field(default_factory=list)
    key_differentiators: List[str] = Field(default_factory=list)
    hypothesis_a_strengths: List[str] = Field(default_factory=list)
    hypothesis_b_strengths: List[str] = Field(default_factory=list)
    hypothesis_a_weaknesses: List[str] = Field(default_factory=list)
    hypothesis_b_weaknesses: List[str] = Field(default_factory=list)


class ReportReadyExplanation(BaseModel):
    """
    Executive and technical report summary formatted for PDF, UI, and external audits.
    Preserves epistemic safety (never claims speculation as proven fact).
    """
    model_config = ConfigDict(extra="ignore")

    incident_id: str
    path_id: Optional[str] = None
    overall_confidence_level: ConfidenceLevel
    overall_evidence_strength: str = Field(description="e.g. MODERATE–HIGH")
    strongly_supported: List[Dict[str, Any]] = Field(default_factory=list)
    moderately_supported: List[Dict[str, Any]] = Field(default_factory=list)
    weakest_transitions: List[Dict[str, Any]] = Field(default_factory=list)
    confidence_bottleneck: Optional[ConfidenceBottleneck] = None
    important_evidence_gaps: List[str] = Field(default_factory=list)
    contradictions_observed: List[str] = Field(default_factory=list)
    alternative_explanations: List[str] = Field(default_factory=list)
    executive_summary: str = Field(description="Epistemically safe summary of reconstructed incident")
