"""
AI Attack Reconstruction Engine Schemas (Section 17).
Provides evidence-driven hypothesis generation schemas, stage models, transition contracts,
evidence gap specifications, and alternative hypothesis structures.

GOLDEN RULE:
ATTACK RECONSTRUCTION = EVIDENCE-CONSTRAINED HYPOTHESIS GENERATION (NOT STORY GENERATION).
Every reconstructed stage and relationship MUST be categorized as strictly
OBSERVED, DERIVED, or INFERRED, and NEVER silently transition between them.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, ConfigDict


# ============================================================================
# 1. CONTROLLED VOCABULARY & ENUMS
# ============================================================================

class StageStatusEnum(str, Enum):
    """
    Forensic certainty classification for attack stages and transitions.
    """
    OBSERVED = "OBSERVED"        # Direct telemetry/evidence represents the activity
    DERIVED = "DERIVED"          # Deterministic interpretation from observations
    INFERRED = "INFERRED"        # Reasonable security hypothesis supported indirectly
    UNRESOLVED = "UNRESOLVED"    # Potential activity where telemetry is absent or inconclusive


class AttackStageType(str, Enum):
    """
    Controlled CyberGuard stage vocabulary.
    Stages are only created when backed by actual normalized evidence.
    """
    DELIVERY = "DELIVERY"
    SOCIAL_ENGINEERING = "SOCIAL_ENGINEERING"
    USER_INTERACTION = "USER_INTERACTION"
    FILE_ACTIVITY = "FILE_ACTIVITY"
    EXECUTION = "EXECUTION"
    INFRASTRUCTURE_CONTACT = "INFRASTRUCTURE_CONTACT"
    CREDENTIAL_ACTIVITY = "CREDENTIAL_ACTIVITY"
    AUTHENTICATION = "AUTHENTICATION"
    SESSION_ESTABLISHMENT = "SESSION_ESTABLISHMENT"
    DISCOVERY = "DISCOVERY"
    ENUMERATION = "ENUMERATION"
    PRIVILEGED_ACTIVITY = "PRIVILEGED_ACTIVITY"
    PERSISTENCE = "PERSISTENCE"
    LATERAL_ACTIVITY = "LATERAL_ACTIVITY"
    COLLECTION = "COLLECTION"
    DATA_ACCESS = "DATA_ACCESS"
    OUTBOUND_TRANSFER = "OUTBOUND_TRANSFER"
    IMPERSONATION = "IMPERSONATION"
    UNKNOWN_ACTIVITY = "UNKNOWN_ACTIVITY"
    EARLIEST_OBSERVED_STAGE = "EARLIEST_OBSERVED_STAGE"
    LATEST_OBSERVED_STAGE = "LATEST_OBSERVED_STAGE"
    UNKNOWN_PRECEDING_ACTIVITY = "UNKNOWN_PRECEDING_ACTIVITY"
    NO_FURTHER_TELEMETRY = "NO_FURTHER_TELEMETRY"


class StageRelationshipType(str, Enum):
    """
    Conservative directed relationships between reconstructed stages.
    Avoids 'CAUSED' unless authoritative proof exists.
    """
    PRECEDES = "PRECEDES"
    FOLLOWED_BY = "FOLLOWED_BY"
    SUPPORTED_BY = "SUPPORTED_BY"
    SHARES_ENTITY_WITH = "SHARES_ENTITY_WITH"
    POSSIBLY_ENABLED = "POSSIBLY_ENABLED"
    POSSIBLY_RELATED = "POSSIBLY_RELATED"


class AttackPathClassification(str, Enum):
    """
    Overall classification of the reconstructed path.
    Avoids CONFIRMED_ATTACK_PATH unless every stage has authoritative direct telemetry.
    """
    PARTIAL_RECONSTRUCTION = "PARTIAL_RECONSTRUCTION"
    PLAUSIBLE_RECONSTRUCTION = "PLAUSIBLE_RECONSTRUCTION"
    STRONG_RECONSTRUCTION = "STRONG_RECONSTRUCTION"


class ConfidenceLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class ReconstructionStatusEnum(str, Enum):
    CURRENT = "CURRENT"
    SUPERSEDED = "SUPERSEDED"
    INVALIDATED = "INVALIDATED"


class AnalystDispositionEnum(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    MODIFIED = "MODIFIED"
    PENDING = "PENDING"


# ============================================================================
# 2. EVIDENCE GAP CONSTANTS
# ============================================================================

GAP_NO_URL_CLICK = "NO_EVIDENCE_OF_URL_CLICK"
GAP_NO_PROCESS_TELEMETRY = "NO_PROCESS_TELEMETRY"
GAP_NO_CREDENTIAL_THEFT_PROOF = "NO_PROOF_OF_CREDENTIAL_THEFT"
GAP_NO_EXFILTRATION_CONFIRMATION = "NO_DIRECT_EXFILTRATION_CONFIRMATION"
GAP_NO_VICTIM_INTERACTION = "NO_VICTIM_INTERACTION_TELEMETRY"
GAP_UNKNOWN_PRECEDING = "UNKNOWN_PRECEDING_ACTIVITY"
GAP_NO_FURTHER_TELEMETRY = "NO_FURTHER_TELEMETRY"


# ============================================================================
# 3. PRIVACY & SANITIZATION UTILITIES
# ============================================================================

SENSITIVE_KEY_SUBSTRINGS = {
    "password", "secret", "token", "auth", "credential", "cookie",
    "api_key", "apikey", "bearer", "private_key", "session_key", "jwt",
    "mfa_code", "totp", "otp", "authorization"
}


def sanitize_reconstruction_attributes(data: Any) -> Any:
    """Recursively redacts credential keys and secret tokens from reconstruction attributes."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(sub in k_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_reconstruction_attributes(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_reconstruction_attributes(x) for x in data]
    return data


def calculate_confidence_level(score: float) -> ConfidenceLevel:
    """Converts a calibrated 0.0-1.0 confidence score into explainable categorical bands."""
    if score >= 0.75:
        return ConfidenceLevel.HIGH
    elif score >= 0.40:
        return ConfidenceLevel.MODERATE
    return ConfidenceLevel.LOW


# ============================================================================
# 4. STAGE & TRANSITION SCHEMAS
# ============================================================================

class AttackStageSchema(BaseModel):
    """
    Evidence-backed attack stage node.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique UUID for stage")
    stage_order: int = Field(default=1, description="Relative chronological position")
    stage_type: AttackStageType = Field(description="Stage category from controlled vocabulary")
    stage_status: StageStatusEnum = Field(description="OBSERVED, DERIVED, INFERRED, or UNRESOLVED")
    technique_id: Optional[str] = Field(default=None, description="Optional MITRE technique (e.g. T1566)")
    tactic: Optional[str] = Field(default=None, description="Optional MITRE tactic (e.g. Initial Access)")
    title: str = Field(description="Human-readable concise title")
    description: Optional[str] = Field(default=None, description="Detailed explanatory context")
    status: str = Field(default="ACTIVE")
    start_time: Optional[datetime] = Field(default=None, description="Earliest observation timestamp")
    end_time: Optional[datetime] = Field(default=None, description="Latest observation timestamp")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Heuristic evidence strength")
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)
    entity_ids: List[str] = Field(default_factory=list, description="Associated canonical Entity IDs")
    event_ids: List[str] = Field(default_factory=list, description="Underlying SecurityEvent IDs")
    finding_ids: List[str] = Field(default_factory=list, description="Underlying Finding IDs")
    evidence_ids: List[str] = Field(default_factory=list, description="Underlying FindingEvidence IDs")
    relationship_ids: List[str] = Field(default_factory=list, description="Underlying Relationship IDs")
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Structured supporting evidence items")
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Structured contradicting evidence items")
    limitations: List[str] = Field(default_factory=list, description="Explicit caveats and missing telemetry notes")
    analyst_disposition: Optional[str] = Field(default=None, description="Analyst review verdict")
    analyst_notes: Optional[str] = Field(default=None, description="Analyst feedback notes")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackTransitionSchema(BaseModel):
    """
    Evidence-backed directed edge between two attack stages.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique UUID for transition edge")
    from_stage_id: str = Field(description="Source AttackStage UUID")
    to_stage_id: str = Field(description="Target AttackStage UUID")
    relationship_type: StageRelationshipType = Field(default=StageRelationshipType.PRECEDES)
    edge_status: StageStatusEnum = Field(default=StageStatusEnum.DERIVED)
    temporal_gap_seconds: Optional[float] = Field(default=None, description="Time delta between stages in seconds")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Connection strength")
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.HIGH)
    shared_entities: List[str] = Field(default_factory=list, description="Canonical entity keys linking stages")
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    analyst_disposition: Optional[str] = Field(default=None)
    analyst_notes: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# 5. HYPOTHESIS & PATH SCHEMAS
# ============================================================================

class AttackHypothesisSchema(BaseModel):
    """
    Explainable alternative or primary hypothesis for an incident reconstruction.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique UUID for hypothesis")
    incident_id: str = Field(description="Parent incident UUID")
    attack_path_id: Optional[str] = Field(default=None, description="Associated AttackPath UUID if primary")
    title: str = Field(description="Descriptive title of the hypothesis")
    description: Optional[str] = Field(default=None, description="Analytical rationale")
    status: str = Field(default="PLAUSIBLE", description="PLAUSIBLE, ACTIVE, REJECTED, SUPERSEDED")
    is_primary: bool = Field(default=False, description="True if primary reconstructed path")
    stage_ids: List[str] = Field(default_factory=list, description="Ordered stage IDs included in this hypothesis")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.MODERATE)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list, description="Evidence gaps affecting this hypothesis")
    analyst_disposition: Optional[str] = Field(default=None)
    analyst_notes: Optional[str] = Field(default=None)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackPathSchema(BaseModel):
    """
    Complete reconstructed attack path with ordered stages, transitions, gaps, and hypotheses.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(description="Unique UUID for attack path")
    incident_id: str = Field(description="Parent incident UUID")
    workspace_id: str = Field(default="default", description="Workspace isolation partition")
    name: str = Field(description="Attack path title")
    description: Optional[str] = Field(default=None)
    classification: AttackPathClassification = Field(default=AttackPathClassification.PLAUSIBLE_RECONSTRUCTION)
    status: ReconstructionStatusEnum = Field(default=ReconstructionStatusEnum.CURRENT)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    confidence_level: ConfidenceLevel = Field(default=ConfidenceLevel.MODERATE)
    completeness_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Explainable proportion of stages with direct/derived evidence (NOT attack probability)"
    )
    start_time: Optional[datetime] = Field(default=None)
    end_time: Optional[datetime] = Field(default=None)
    stages: List[AttackStageSchema] = Field(default_factory=list)
    transitions: List[AttackTransitionSchema] = Field(default_factory=list)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list, description="Identified missing telemetry items")
    alternative_hypotheses: List[AttackHypothesisSchema] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    version: int = Field(default=1)
    engine_version: str = Field(default="1.0.0")
    rule_version: str = Field(default="1.0.0")
    analyst_disposition: Optional[str] = Field(default=None)
    analyst_notes: Optional[str] = Field(default=None)
    reviewed_by: Optional[str] = Field(default=None)
    reviewed_at: Optional[datetime] = Field(default=None)
    created_at: Optional[datetime] = Field(default=None)
    updated_at: Optional[datetime] = Field(default=None)


# ============================================================================
# 6. CONTEXT & API REQUEST / RESPONSE SCHEMAS
# ============================================================================

class ReconstructionContext(BaseModel):
    """
    Context summary loaded for incident reconstruction.
    """
    model_config = ConfigDict(extra="ignore")

    incident_id: str
    workspace_id: str
    time_range: Dict[str, Optional[datetime]] = Field(default_factory=dict)
    artifact_count: int = 0
    entity_count: int = 0
    relationship_count: int = 0
    event_count: int = 0
    finding_count: int = 0
    threat_event_count: int = 0
    sequence_count: int = 0
    campaign_count: int = 0
    engine_version: str = "1.0.0"
    configuration_version: str = "1.0.0"


class ReconstructIncidentRequest(BaseModel):
    """Request payload to trigger attack path reconstruction."""
    force_reanalysis: bool = Field(default=False, description="Force creating a new version even if current exists")
    max_stages: int = Field(default=50, ge=1, le=100, description="Max stages to include in DAG")
    include_llm_summary: bool = Field(default=False, description="Optionally invoke auxiliary LLM for narrative summary")


class AttackReconstructionResponse(BaseModel):
    """Unified API response for attack reconstruction."""
    attack_path: Optional[AttackPathSchema] = None
    stages: List[AttackStageSchema] = Field(default_factory=list)
    transitions: List[AttackTransitionSchema] = Field(default_factory=list)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    alternative_hypotheses: List[AttackHypothesisSchema] = Field(default_factory=list)
    confidence: float = 0.5
    confidence_level: ConfidenceLevel = ConfidenceLevel.MODERATE
    limitations: List[str] = Field(default_factory=list)
    context: Optional[ReconstructionContext] = None


class HypothesesResponse(BaseModel):
    """List of all hypotheses evaluated for an incident."""
    incident_id: str
    workspace_id: str
    hypotheses: List[AttackHypothesisSchema]
    total: int


class EvidenceGapsResponse(BaseModel):
    """Explicit evidence gaps for an incident."""
    incident_id: str
    workspace_id: str
    evidence_gaps: List[str]
    total: int


class TransitionEvidenceResponse(BaseModel):
    """Detailed evidence explanation for a transition edge."""
    transition_id: str
    from_stage_id: str
    to_stage_id: str
    relationship_type: str
    edge_status: str
    confidence: float
    confidence_level: ConfidenceLevel
    shared_entities: List[str]
    temporal_gap_seconds: Optional[float]
    supporting_evidence: List[Dict[str, Any]]
    contradicting_evidence: List[Dict[str, Any]]


class AnalystFeedbackRequest(BaseModel):
    """Analyst review input for a stage, transition, or hypothesis."""
    disposition: AnalystDispositionEnum = Field(description="CONFIRMED, REJECTED, MODIFIED, or PENDING")
    notes: Optional[str] = Field(default=None, description="Analyst justification")
    reviewer: Optional[str] = Field(default=None, description="Analyst identifier")
