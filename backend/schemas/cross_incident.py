"""
Canonical schemas and contracts for Section 15:
Cross-Incident Pattern Detection & Campaign Correlation Engine.
"""
from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict


class CorrelationFeatureCategory(str, Enum):
    INFRASTRUCTURE = "INFRASTRUCTURE"
    ARTIFACT = "ARTIFACT"
    IDENTITY = "IDENTITY"
    CONTENT = "CONTENT"
    BEHAVIOR = "BEHAVIOR"
    TACTIC = "TACTIC"
    TEMPORAL = "TEMPORAL"
    TARGETING = "TARGETING"


class IndicatorSpecificity(str, Enum):
    HIGH = "HIGH"        # Exact malicious file hash, rare exact URL, rare domain (prevalence <= 5)
    MEDIUM = "MEDIUM"    # Dedicated IP (prevalence <= 3), lookalike domain family, auth pattern
    LOW = "LOW"          # Major CDN IP, public resolver, common cloud ASN, generic webmail domain


class CorrelationStatus(str, Enum):
    ACTIVE = "ACTIVE"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class CampaignStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    LIKELY_RELATED = "LIKELY_RELATED"
    REVIEWED_CONFIRMED = "REVIEWED_CONFIRMED"
    REVIEWED_REJECTED = "REVIEWED_REJECTED"


class CorrelationEvidenceItem(BaseModel):
    category: CorrelationFeatureCategory
    evidence_type: str  # e.g., SHARED_FILE_HASH, SHARED_RARE_DOMAIN, SHARED_RARE_IP, SHARED_URL, etc.
    description: str
    weight: float = Field(ge=0.0, le=1.0)
    weight_label: str  # "strong", "moderate", "weak", "negligible"
    specificity: IndicatorSpecificity
    value: str
    prevalence_count: int = 1
    incident_a_evidence_ref: Optional[str] = None
    incident_b_evidence_ref: Optional[str] = None
    source_artifact_ids: List[str] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class ContradictingEvidenceItem(BaseModel):
    category: CorrelationFeatureCategory
    factor: str  # e.g., LARGE_TIME_SEPARATION, COMMON_CDN_INFRASTRUCTURE, CONFLICTING_TARGETS, HIGH_PREVALENCE
    description: str
    weight_penalty: float = Field(ge=0.0, le=1.0)
    weight_label: str  # "strong", "moderate", "weak"

    model_config = ConfigDict(extra="ignore")


class FeatureBreakdown(BaseModel):
    category_scores: Dict[str, float] = Field(default_factory=dict)
    category_weights: Dict[str, float] = Field(default_factory=dict)
    raw_score: float = 0.0
    penalty_score: float = 0.0
    final_score: float = 0.0

    model_config = ConfigDict(extra="ignore")


class IncidentCorrelationProfile(BaseModel):
    incident_id: str
    workspace_id: str = "default"
    time_start: Optional[datetime] = None
    time_end: Optional[datetime] = None

    domains: List[str] = Field(default_factory=list)
    ips: List[str] = Field(default_factory=list)
    urls: List[str] = Field(default_factory=list)
    hashes: List[str] = Field(default_factory=list)

    sender_domains: List[str] = Field(default_factory=list)
    sender_addresses: List[str] = Field(default_factory=list)

    protected_identities: List[str] = Field(default_factory=list)
    targeted_accounts: List[str] = Field(default_factory=list)
    targeted_services: List[str] = Field(default_factory=list)

    file_features: List[Dict[str, Any]] = Field(default_factory=list)
    email_features: List[Dict[str, Any]] = Field(default_factory=list)
    auth_features: List[Dict[str, Any]] = Field(default_factory=list)
    network_features: List[Dict[str, Any]] = Field(default_factory=list)
    api_features: List[Dict[str, Any]] = Field(default_factory=list)
    media_features: List[Dict[str, Any]] = Field(default_factory=list)

    threat_event_types: List[str] = Field(default_factory=list)
    finding_types: List[str] = Field(default_factory=list)
    tactic_features: List[str] = Field(default_factory=list)

    template_fingerprint: Optional[str] = None
    profile_version: str = "2.0.0"
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="ignore")


class IncidentCorrelationResult(BaseModel):
    id: Optional[str] = None
    workspace_id: str = "default"
    incident_a_id: str
    incident_b_id: str

    correlation_score: float = Field(ge=0.0, le=1.0)  # Strength of observed similarity, NOT same attacker probability
    confidence: float = Field(ge=0.0, le=1.0, default=1.0)
    relationship_label: str  # e.g., "Strong cross-incident similarity"
    assessment_meaning: str = "The incidents share multiple uncommon characteristics and may represent related activity (not attribution to same actor)."

    supporting_evidence: List[CorrelationEvidenceItem] = Field(default_factory=list)
    contradicting_evidence: List[ContradictingEvidenceItem] = Field(default_factory=list)
    feature_breakdown: FeatureBreakdown = Field(default_factory=FeatureBreakdown)

    status: str = "ACTIVE"
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None

    engine_version: str = "2.0.0"
    config_version: str = "2.0.0"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="ignore")


class CampaignCandidateResponse(BaseModel):
    id: str
    campaign_id: str
    workspace_id: str = "default"
    name: str
    status: str = "CANDIDATE"
    overall_confidence: float = 0.0
    correlation_summary: str = ""

    incident_count: int = 0
    incident_ids: List[str] = Field(default_factory=list)

    supporting_evidence: List[CorrelationEvidenceItem] = Field(default_factory=list)
    contradicting_evidence: List[ContradictingEvidenceItem] = Field(default_factory=list)

    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    dominant_attack_type: str = "Phishing / Fraud"
    engine_version: str = "2.0.0"

    model_config = ConfigDict(extra="ignore")


class RelatedIncidentItem(BaseModel):
    incident_id: str
    incident_number: str
    title: str
    correlation_score: float
    relationship_label: str
    shared_indicators_summary: List[str] = Field(default_factory=list)
    supporting_evidence_count: int = 0
    contradicting_evidence_count: int = 0
    status: str = "ACTIVE"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="ignore")


class CrossIncidentSearchResponse(BaseModel):
    incident_id: str
    incident_number: str
    total_candidates: int
    related_incidents: List[RelatedIncidentItem] = Field(default_factory=list)

    model_config = ConfigDict(extra="ignore")


class IncidentPairCompareRequest(BaseModel):
    incident_a_id: str
    incident_b_id: str
    workspace_id: str = "default"

    model_config = ConfigDict(extra="ignore")


class AnalystReviewRequest(BaseModel):
    decision: str  # "CONFIRM" or "REJECT"
    notes: Optional[str] = None
    analyst_id: str = "analyst"

    model_config = ConfigDict(extra="ignore")
