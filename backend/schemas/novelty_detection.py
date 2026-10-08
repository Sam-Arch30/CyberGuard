"""
Novelty Detection & Emerging-Threat Identification Schemas (Section 22).

Pydantic V2 models defining novelty categories, deterministic pattern fingerprints,
similarity distance models, 4-quadrant behavior-familiarity matrix, emerging pattern
candidates, suppression rules, and retention-aware assessments.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import math
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, ConfigDict, field_validator


# ============================================================================
# 1. CONTROLLED VOCABULARY & ENUMS
# ============================================================================

class NoveltyCategory(str, Enum):
    """Controlled vocabulary for categories of novelty in CyberGuard."""
    NOVEL_ARTIFACT = "NOVEL_ARTIFACT"
    NOVEL_URL_STRUCTURE = "NOVEL_URL_STRUCTURE"
    NOVEL_DOMAIN_PATTERN = "NOVEL_DOMAIN_PATTERN"
    NOVEL_NETWORK_BEHAVIOR = "NOVEL_NETWORK_BEHAVIOR"
    NOVEL_API_BEHAVIOR = "NOVEL_API_BEHAVIOR"
    NOVEL_AUTHENTICATION_PATTERN = "NOVEL_AUTHENTICATION_PATTERN"
    NOVEL_DEVICE_BEHAVIOR = "NOVEL_DEVICE_BEHAVIOR"
    NOVEL_USER_BEHAVIOR = "NOVEL_USER_BEHAVIOR"
    NOVEL_INFRASTRUCTURE_RELATIONSHIP = "NOVEL_INFRASTRUCTURE_RELATIONSHIP"
    NOVEL_ATTACK_SEQUENCE = "NOVEL_ATTACK_SEQUENCE"
    NOVEL_EVENT_COMBINATION = "NOVEL_EVENT_COMBINATION"
    NOVEL_CAMPAIGN_PATTERN = "NOVEL_CAMPAIGN_PATTERN"
    NOVEL_ENTITY_RELATIONSHIP = "NOVEL_ENTITY_RELATIONSHIP"
    NOVEL_MULTIMODAL_PATTERN = "NOVEL_MULTIMODAL_PATTERN"


class NoveltyLevel(str, Enum):
    """Categorical classification of relative pattern novelty."""
    KNOWN = "KNOWN"              # Exact or highly similar pattern exists in historical library (novelty < 0.15)
    LOW = "LOW"                  # Minor variations from established patterns (0.15 <= novelty < 0.40)
    MODERATE = "MODERATE"        # Substantial structural or sequence deviation (0.40 <= novelty < 0.70)
    HIGH = "HIGH"                # Distinct, previously unseen pattern or combination (0.70 <= novelty < 0.90)
    VERY_HIGH = "VERY_HIGH"      # Completely unprecedented pattern in retained telemetry (novelty >= 0.90)
    UNKNOWN = "UNKNOWN"          # Insufficient telemetry or unrepresented category


class BehaviorFamiliarityMatrix(str, Enum):
    """
    4-Quadrant matrix distinguishing Behavioral Anomaly (Section 21) from Novelty (Section 22).
    Prevents confusing entity-specific anomalies with global/retained unfamiliarity.
    """
    NORMAL_FAMILIAR = "NORMAL_FAMILIAR"    # Normal for entity, familiar pattern globally
    NORMAL_NOVEL = "NORMAL_NOVEL"          # Normal for entity, but previously unseen pattern (e.g. approved new SaaS)
    UNUSUAL_FAMILIAR = "UNUSUAL_FAMILIAR"  # Anomalous for entity, but familiar pattern globally (e.g. off-hours login)
    UNUSUAL_NOVEL = "UNUSUAL_NOVEL"        # Anomalous for entity AND unprecedented pattern in retained knowledge


class ComparisonMethod(str, Enum):
    """Method used to calculate distance/similarity against historical patterns."""
    EXACT_MATCH = "EXACT_MATCH"
    STRUCTURAL_SIMILARITY = "STRUCTURAL_SIMILARITY"
    SEQUENCE_ALIGNMENT = "SEQUENCE_ALIGNMENT"
    COMBINATION_TUPLE = "COMBINATION_TUPLE"
    JACCARD_DISTANCE = "JACCARD_DISTANCE"
    LEVENSHTEIN_DISTANCE = "LEVENSHTEIN_DISTANCE"


class EmergingPatternStatus(str, Enum):
    """Lifecycle states for recurring novelty clusters."""
    OBSERVED = "OBSERVED"          # Single or low-frequency novel observation
    EMERGING = "EMERGING"          # Recurring novel pattern across multiple entities/incidents
    INVESTIGATING = "INVESTIGATING"# Active investigation into emerging pattern
    VALIDATED = "VALIDATED"        # Validated emerging threat pattern by security team
    REJECTED = "REJECTED"          # Confirmed benign business change or tool rollout
    ARCHIVED = "ARCHIVED"          # Historical pattern preserved for reference


class AssessmentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUPPRESSED = "SUPPRESSED"
    RECURRING = "RECURRING"


# ============================================================================
# 2. PRIVACY SAFEGUARDS & RESTRICTED KEYS
# ============================================================================

FORBIDDEN_NOVELTY_KEYWORDS = {
    "password", "passwd", "secret", "token", "apikey", "api_key",
    "cookie", "session_secret", "mfa_code", "totp_code", "auth_header",
    "authorization", "bearer", "private_key", "credential"
}


def validate_novelty_privacy(key: str, value: Any) -> None:
    """Verifies that sensitive credentials, session secrets, or tokens are never used as novelty features or fingerprints."""
    lower_key = key.lower()
    for kw in FORBIDDEN_NOVELTY_KEYWORDS:
        if kw in lower_key:
            raise ValueError(
                f"Privacy violation: Key '{key}' contains sensitive credential keyword '{kw}'. "
                "Raw credentials, tokens, and authorization secrets must never be ingested or persisted in novelty engine."
            )
    if isinstance(value, str):
        lower_val = value.lower()
        if lower_val.startswith("bearer ") or lower_val.startswith("basic "):
            raise ValueError("Privacy violation: Raw authorization bearer/basic strings cannot be stored in novelty features.")


# ============================================================================
# 3. CORE DATA MODELS
# ============================================================================

class NoveltyAssessment(BaseModel):
    """
    Standardized, explainable assessment of pattern novelty.
    Explicitly distinguishes novelty distance from probability of maliciousness.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Unique UUID for novelty assessment")
    workspace_id: str = Field(default="default", description="Tenant workspace identifier")
    incident_id: Optional[str] = Field(default=None, description="Associated incident ID if linked")
    investigation_id: Optional[str] = Field(default=None, description="Associated investigation ID")
    entity_type: str = Field(description="Type of entity evaluated (USER, DEVICE, SERVICE, API, NETWORK, etc.)")
    entity_id: str = Field(description="Stable identifier of entity evaluated")
    novelty_type: NoveltyCategory = Field(description="Controlled novelty category")
    novelty_score: float = Field(
        ge=0.0, le=1.0,
        description="Relative distance from previously observed patterns [0.0 = familiar, 1.0 = completely novel]. NOT a threat probability."
    )
    novelty_level: NoveltyLevel = Field(description="Categorical novelty classification")
    similarity_score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Maximum similarity score to nearest historical pattern [0.0 = completely distinct, 1.0 = identical]"
    )
    historical_sample_count: int = Field(default=0, ge=0, description="Number of historical samples evaluated in window")
    comparison_window: str = Field(default="90_DAYS", description="Retained telemetry lookback window used for comparison")
    behavior_familiarity_matrix: BehaviorFamiliarityMatrix = Field(
        default=BehaviorFamiliarityMatrix.NORMAL_NOVEL,
        description="4-quadrant classification separating entity anomaly from historical familiarity"
    )
    feature_version: str = Field(default="1.0.0", description="Feature representation version")
    baseline_version: str = Field(default="1.0.0", description="Behavioral baseline engine version")
    status: AssessmentStatus = Field(default=AssessmentStatus.ACTIVE, description="Lifecycle status")
    fingerprint_hash: Optional[str] = Field(default=None, description="Deterministic SHA-256 pattern hash")
    fingerprint_repr: Optional[str] = Field(default=None, description="Human-readable sanitized pattern representation")
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Independent evidence items supporting novelty")
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Evidence items indicating familiarity or known exceptions")
    limitations: List[str] = Field(default_factory=list, description="Analytical boundaries and telemetry retention limits")
    threat_assessment_note: Optional[str] = Field(
        default="Novelty represents technical unfamiliarity within retained telemetry and does not constitute independent evidence of malicious compromise.",
        description="Epistemic humility disclaimer"
    )
    engine_version: str = Field(default="1.0.0", description="Novelty engine version")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Evaluation timestamp")


class PatternFingerprint(BaseModel):
    """
    Compact, deterministic representation of an observed pattern or structure.
    Used for sub-linear exact matching and structural similarity comparisons.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Unique fingerprint record ID")
    workspace_id: str = Field(default="default", description="Workspace ID")
    pattern_type: str = Field(description="Category of pattern (API_ROUTE, URL_STRUCTURE, AUTH_COMBO, EVENT_SEQUENCE, etc.)")
    fingerprint_hash: str = Field(description="Deterministic SHA-256 hash of canonical representation")
    fingerprint_repr: str = Field(description="Sanitized human-readable pattern representation")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Structured attributes forming the fingerprint")
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="First observed time in retained telemetry")
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Most recent observation time")
    observation_count: int = Field(default=1, ge=1, description="Total observations in retained telemetry")
    entity_count: int = Field(default=1, ge=1, description="Number of distinct entities observed with this pattern")
    incident_count: int = Field(default=1, ge=0, description="Number of distinct incidents featuring this pattern")
    is_suppressed: bool = Field(default=False, description="Whether pattern is administratively suppressed")
    suppression_reason: Optional[str] = Field(default=None, description="Justification for suppression")


class EmergingPatternCandidate(BaseModel):
    """
    Cluster candidate tracking recurring novel patterns across multiple entities or incidents.
    Bridges novelty detection toward cross-incident investigation without premature rule creation.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Candidate identifier")
    workspace_id: str = Field(default="default", description="Workspace ID")
    incident_id: Optional[str] = Field(default=None, description="Originating incident ID")
    pattern_type: str = Field(description="Pattern category")
    fingerprint_hash: str = Field(description="Pattern fingerprint hash")
    fingerprint_repr: str = Field(description="Sanitized pattern summary")
    similarity_cluster: Optional[str] = Field(default=None, description="Cluster identifier if grouped")
    novelty_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Initial novelty score when first detected")
    recurrence_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Calculated recurrence significance [0.0 - 100.0]")
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    observation_count: int = Field(default=1, ge=1)
    entity_count: int = Field(default=1, ge=1)
    incident_count: int = Field(default=1, ge=0)
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    status: EmergingPatternStatus = Field(default=EmergingPatternStatus.OBSERVED)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NoveltySuppressionRule(BaseModel):
    """
    Auditable contextual exception rule for approved business changes, migrations, or maintenance.
    """
    model_config = ConfigDict(from_attributes=True)

    id: str = Field(description="Unique suppression rule ID")
    workspace_id: str = Field(default="default")
    pattern_type: Optional[str] = None
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    fingerprint_hash: Optional[str] = None
    reason: str = Field(description="Business justification (e.g. 'Approved SaaS rollout Q4')")
    approved_by: str = Field(description="Approving authority or Change Advisory Board ticket")
    valid_from: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    valid_until: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# 4. API REQUEST & RESPONSE MODELS
# ============================================================================

class NoveltyEvaluationRequest(BaseModel):
    """Request to evaluate novelty of an observed event, sequence, or combination."""
    workspace_id: str = Field(default="default")
    incident_id: Optional[str] = None
    entity_type: str = Field(description="USER, DEVICE, SERVICE, API, NETWORK, etc.")
    entity_id: str = Field(description="Identifier of entity")
    novelty_type: NoveltyCategory
    attributes: Dict[str, Any] = Field(description="Structured features of the observed pattern")
    is_entity_anomalous: bool = Field(
        default=False,
        description="Whether entity-specific detector (Section 21) flagged this observation as anomalous"
    )
    event_sequence: Optional[List[str]] = Field(
        default=None,
        description="Optional ordered event sequence for sequence novelty evaluation"
    )


class NoveltyEvaluationResponse(BaseModel):
    """Response containing novelty assessment and emerging pattern status."""
    assessment: NoveltyAssessment
    emerging_candidate: Optional[EmergingPatternCandidate] = None
    is_suppressed: bool = False
    suppression_details: Optional[Dict[str, Any]] = None


class NoveltyInvestigationSummary(BaseModel):
    """Summary of novelty assessments within an incident investigation."""
    investigation_id: str
    incident_id: str
    total_assessments: int
    novel_assessments_count: int
    high_novelty_count: int
    assessments: List[NoveltyAssessment]
    emerging_patterns: List[EmergingPatternCandidate]
    limitations: List[str]
    retention_window: str = "90_DAYS"


class EmergingStatusTransitionRequest(BaseModel):
    """Request to transition emerging pattern candidate status."""
    actor: str = Field(description="Analyst ID or system service transitioning state")
    new_status: EmergingPatternStatus
    reason: str = Field(description="Justification for status transition")
