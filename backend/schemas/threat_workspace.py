"""
Section 65: Threat Actor & Campaign Workspace Schemas.
Analyst-facing orchestration contracts enforcing:
- Strict separation of Observed Fact, Correlation, Analyst Hypothesis, and Attribution.
- Independent confidence (0.0 - 1.0) strictly separate from Risk/Severity.
- Supporting and Contradicting evidence tracking.
- Controlled attribution states and candidate promotion/merge/split workflows.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AttributionStateEnum(str, Enum):
    UNKNOWN = "UNKNOWN"
    SUSPECTED = "SUSPECTED"
    POSSIBLE = "POSSIBLE"
    PROBABLE = "PROBABLE"
    ASSESSED = "ASSESSED"
    CONFIRMED = "CONFIRMED"
    DISPUTED = "DISPUTED"
    REJECTED = "REJECTED"


class SemanticClassificationEnum(str, Enum):
    OBSERVED = "OBSERVED"
    CORRELATED = "CORRELATED"
    INFERRED = "INFERRED"
    HYPOTHESIZED = "HYPOTHESIZED"
    ASSESSED = "ASSESSED"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    ANALYST_ASSERTED = "ANALYST_ASSERTED"


class CampaignLifecycleEnum(str, Enum):
    CANDIDATE = "CANDIDATE"
    OPEN = "OPEN"
    ACTIVE = "ACTIVE"
    MONITORING = "MONITORING"
    CONTAINED = "CONTAINED"
    INACTIVE = "INACTIVE"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


class CampaignActivityEnum(str, Enum):
    ACTIVE = "ACTIVE"
    QUIET = "QUIET"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class CampaignWatchStateEnum(str, Enum):
    MONITORED = "MONITORED"
    NOT_MONITORED = "NOT_MONITORED"


class HypothesisStatusEnum(str, Enum):
    OPEN = "OPEN"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    REJECTED = "REJECTED"
    CONFIRMED = "CONFIRMED"


class ActorTypeEnum(str, Enum):
    NATION_STATE = "NATION_STATE"
    CYBERCRIME = "CYBERCRIME"
    HACKTIVIST = "HACKTIVIST"
    INSIDER = "INSIDER"
    OPPORTUNISTIC = "OPPORTUNISTIC"
    UNKNOWN = "UNKNOWN"


class IdentityStateEnum(str, Enum):
    OBSERVED = "OBSERVED"
    TARGETED = "TARGETED"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    UNKNOWN = "UNKNOWN"


# -----------------------------------------------------------------------------
# Granular Evidence & Provenance
# -----------------------------------------------------------------------------

class EvidenceItem(BaseModel):
    id: str = Field(..., description="Unique evidence identifier")
    evidence_type: str = Field(..., description="Category (INFRASTRUCTURE, CERTIFICATE, URL_PATTERN, TIMING, BEHAVIOR, INTEL_FEED)")
    description: str = Field(..., description="Concrete description of what was observed")
    semantic_class: SemanticClassificationEnum = Field(default=SemanticClassificationEnum.OBSERVED)
    observed_at: Optional[str] = Field(None, description="ISO timestamp of observation")
    source: str = Field(..., description="Authoritative origin (telemetry, feed, certificate_log, analyst)")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence in this specific piece of evidence")
    is_contradicting: bool = Field(default=False, description="True if evidence contradicts attribution/hypothesis")
    raw_reference: Optional[str] = Field(None, description="Artifact ID, log ID, or external record ID")


class ActorAlias(BaseModel):
    alias: str = Field(..., description="Name used by other vendors or communities")
    source: str = Field(..., description="Vendor/source asserting this alias (e.g., CISA, Mandiant, CrowdStrike)")
    source_record_id: Optional[str] = Field(None, description="External intelligence reference ID")
    observed_at: Optional[str] = Field(None, description="Timestamp first referenced")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class AnalystNote(BaseModel):
    id: str = Field(..., description="Unique note ID")
    author: str = Field(..., description="Analyst username")
    timestamp: str = Field(..., description="ISO creation timestamp")
    content: str = Field(..., description="Analyst note text")
    scope: str = Field(default="WORKSPACE", description="Visibility scope")


class SourceConflict(BaseModel):
    id: str = Field(..., description="Conflict identifier")
    provider_a: str = Field(..., description="Source A claiming identity/attribution")
    claim_a: str = Field(..., description="Claim by Source A")
    provider_b: str = Field(..., description="Source B claiming conflicting identity")
    claim_b: str = Field(..., description="Claim by Source B")
    subject: str = Field(..., description="Entity or indicator in conflict")
    status: str = Field(default="DISPUTED", description="DISPUTED, RESOLVED, UNRESOLVED")
    analyst_note: Optional[str] = None


# -----------------------------------------------------------------------------
# Threat Actor Schemas
# -----------------------------------------------------------------------------

class ThreatActorCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255, description="Threat actor name")
    canonical_name: Optional[str] = Field(None, description="Standardized canonical designation")
    actor_type: Optional[ActorTypeEnum] = Field(default=ActorTypeEnum.UNKNOWN)
    attribution_state: Optional[AttributionStateEnum] = Field(default=AttributionStateEnum.SUSPECTED)
    attribution_confidence: Optional[float] = Field(default=0.5, ge=0.0, le=1.0)
    motivation: Optional[str] = Field(None, description="Suspected motivation")
    sophistication: Optional[str] = Field(default="UNKNOWN", description="ADVANCED, INTERMEDIATE, COMMODITY, UNKNOWN")
    description: Optional[str] = Field(None, description="Analyst profile description")
    aliases: Optional[List[ActorAlias]] = Field(default_factory=list)
    primary_targets: Optional[List[str]] = Field(default_factory=list)
    observed_techniques: Optional[List[str]] = Field(default_factory=list)
    observed_infrastructure: Optional[List[str]] = Field(default_factory=list)
    supporting_evidence: Optional[List[EvidenceItem]] = Field(default_factory=list)
    contradicting_evidence: Optional[List[EvidenceItem]] = Field(default_factory=list)


class ThreatActorUpdateRequest(BaseModel):
    name: Optional[str] = None
    canonical_name: Optional[str] = None
    actor_type: Optional[ActorTypeEnum] = None
    status: Optional[str] = None
    attribution_state: Optional[AttributionStateEnum] = None
    attribution_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    description: Optional[str] = None
    aliases: Optional[List[ActorAlias]] = None
    primary_targets: Optional[List[str]] = None
    observed_techniques: Optional[List[str]] = None
    observed_infrastructure: Optional[List[str]] = None
    supporting_evidence: Optional[List[EvidenceItem]] = None
    contradicting_evidence: Optional[List[EvidenceItem]] = None


class ThreatActorResponse(BaseModel):
    id: str
    actor_id: str
    workspace_id: str
    name: str
    canonical_name: str
    actor_type: str
    status: str
    attribution_state: str
    attribution_confidence: float
    motivation: Optional[str] = None
    sophistication: str
    description: Optional[str] = None
    first_observed_at: Optional[str] = None
    last_observed_at: Optional[str] = None
    aliases: List[ActorAlias] = Field(default_factory=list)
    primary_targets: List[str] = Field(default_factory=list)
    observed_techniques: List[str] = Field(default_factory=list)
    observed_infrastructure: List[str] = Field(default_factory=list)
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    contradicting_evidence: List[EvidenceItem] = Field(default_factory=list)
    associated_campaigns_count: int = 0
    affected_assets_count: int = 0
    open_incidents_count: int = 0
    created_by: str
    created_at: str
    updated_at: str


class ThreatActorListResponse(BaseModel):
    items: List[ThreatActorResponse]
    total: int
    page: int
    page_size: int


# -----------------------------------------------------------------------------
# Campaign Workspace Schemas
# -----------------------------------------------------------------------------

class CampaignCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    description: Optional[str] = None
    threat_actor_id: Optional[str] = None
    attribution_state: Optional[AttributionStateEnum] = Field(default=AttributionStateEnum.UNKNOWN)
    attribution_confidence: Optional[float] = Field(default=0.0, ge=0.0, le=1.0)
    lifecycle_status: Optional[CampaignLifecycleEnum] = Field(default=CampaignLifecycleEnum.OPEN)
    dominant_attack_type: Optional[str] = Field(default="Phishing / Credential Harvesting")
    targeted_brands: Optional[List[str]] = Field(default_factory=list)
    mitre_techniques: Optional[List[str]] = Field(default_factory=list)


class CampaignUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    threat_actor_id: Optional[str] = None
    attribution_state: Optional[AttributionStateEnum] = None
    attribution_confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    lifecycle_status: Optional[CampaignLifecycleEnum] = None
    activity_state: Optional[CampaignActivityEnum] = None
    watch_state: Optional[CampaignWatchStateEnum] = None
    dominant_attack_type: Optional[str] = None
    targeted_brands: Optional[List[str]] = None
    mitre_techniques: Optional[List[str]] = None
    supporting_evidence: Optional[List[EvidenceItem]] = None
    contradicting_evidence: Optional[List[EvidenceItem]] = None


class AffectedAssetRef(BaseModel):
    asset_id: str
    name: str
    asset_type: str
    priority_band: str  # P1, P2, P3, P4, UNPRIORITIZED
    business_criticality: str
    risk_score: float
    active_incidents: int = 0


class AffectedIdentityRef(BaseModel):
    identity_id: str
    email: str
    display_name: Optional[str] = None
    state: IdentityStateEnum = IdentityStateEnum.OBSERVED  # OBSERVED, TARGETED, SUSPICIOUS, COMPROMISED
    is_privileged: bool = False
    observation_count: int = 1


class CampaignWorkspaceDetailResponse(BaseModel):
    id: str
    campaign_id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    lifecycle_status: str
    activity_state: str
    watch_state: str
    attribution_state: str
    attribution_confidence: float
    threat_actor: Optional[ThreatActorResponse] = None
    overall_confidence: float
    first_seen: str
    last_seen: str
    dominant_attack_type: str
    targeted_brands: List[str] = Field(default_factory=list)
    email_count: int = 0
    recipient_count: int = 0
    domain_count: int = 0
    ip_count: int = 0
    asn_count: int = 0
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    contradicting_evidence: List[EvidenceItem] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    affected_assets: List[AffectedAssetRef] = Field(default_factory=list)
    affected_identities: List[AffectedIdentityRef] = Field(default_factory=list)
    related_alerts: List[str] = Field(default_factory=list)
    related_incidents: List[str] = Field(default_factory=list)
    source_conflicts: List[SourceConflict] = Field(default_factory=list)
    hypotheses_count: int = 0
    analyst_notes: List[AnalystNote] = Field(default_factory=list)
    provenance_history: List[Dict[str, Any]] = Field(default_factory=list)
    correlation_summary: Optional[str] = None
    created_at: str
    updated_at: str


class CampaignListWorkspaceResponse(BaseModel):
    items: List[CampaignWorkspaceDetailResponse]
    total: int
    page: int
    page_size: int


# -----------------------------------------------------------------------------
# Candidate Review & Merge / Split Workflows
# -----------------------------------------------------------------------------

class CandidateReviewRequest(BaseModel):
    action: str = Field(..., description="PROMOTE, MERGE, REJECT, or REVIEW")
    name: Optional[str] = Field(None, description="New campaign name if promoting")
    target_campaign_id: Optional[str] = Field(None, description="Existing campaign ID if merging")
    threat_actor_id: Optional[str] = Field(None, description="Associated actor ID if known")
    reason: str = Field(..., min_length=3, description="Analyst rationale for candidate decision")


class CampaignMergePreviewRequest(BaseModel):
    source_campaign_id: str = Field(..., description="Campaign being absorbed")
    target_campaign_id: str = Field(..., description="Campaign receiving assets/indicators")


class CampaignMergePreviewResponse(BaseModel):
    source_campaign_id: str
    source_name: str
    target_campaign_id: str
    target_name: str
    source_indicators_count: int
    source_assets_count: int
    source_incidents_count: int
    conflicting_sources: List[SourceConflict] = Field(default_factory=list)
    is_safe: bool = True
    warning_message: Optional[str] = None


class CampaignMergeRequest(BaseModel):
    source_campaign_id: str
    target_campaign_id: str
    reason: str = Field(..., min_length=5, description="Analyst reason for merge")
    confirm_override_conflicts: bool = Field(default=False, description="Explicit approval if conflicts present")


class CampaignSplitRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Analyst reason for splitting campaign")
    new_campaign_name: str = Field(..., min_length=2, description="Name for the newly formed cluster")
    incident_ids_to_move: List[str] = Field(..., min_length=1, description="Incident IDs to detach and move")
    indicator_values_to_move: Optional[List[str]] = Field(default_factory=list)


# -----------------------------------------------------------------------------
# Attribution Assessment & Hypothesis Schemas
# -----------------------------------------------------------------------------

class AttributionAssessmentCreateRequest(BaseModel):
    subject_type: str = Field(default="CAMPAIGN", description="CAMPAIGN or THREAT_ACTOR")
    subject_id: str = Field(..., description="ID of campaign or actor being assessed")
    target_type: str = Field(default="THREAT_ACTOR", description="Target type")
    target_id: Optional[str] = Field(None, description="Threat actor ID being attributed")
    new_attribution_state: AttributionStateEnum = Field(...)
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this attribution (not risk)")
    justification: str = Field(..., min_length=5, description="Analyst justification and evidence summary")
    supporting_evidence: Optional[List[EvidenceItem]] = Field(default_factory=list)
    contradicting_evidence: Optional[List[EvidenceItem]] = Field(default_factory=list)
    external_conflicts: Optional[List[SourceConflict]] = Field(default_factory=list)


class AttributionAssessmentResponse(BaseModel):
    id: str
    workspace_id: str
    subject_type: str
    subject_id: str
    target_type: str
    target_id: Optional[str] = None
    prior_attribution_state: str
    new_attribution_state: str
    confidence: float
    justification: str
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    contradicting_evidence: List[EvidenceItem] = Field(default_factory=list)
    external_conflicts: List[SourceConflict] = Field(default_factory=list)
    assessed_by: str
    assessed_at: str


class HypothesisCreateRequest(BaseModel):
    subject_type: str = Field(default="CAMPAIGN", description="CAMPAIGN, THREAT_ACTOR, INFRASTRUCTURE")
    subject_id: str = Field(..., description="Campaign or actor UUID")
    title: str = Field(..., min_length=3, max_length=255)
    hypothesis_text: str = Field(..., min_length=5)
    status: Optional[HypothesisStatusEnum] = Field(default=HypothesisStatusEnum.OPEN)
    confidence: Optional[float] = Field(default=0.5, ge=0.0, le=1.0)
    supporting_evidence: Optional[List[EvidenceItem]] = Field(default_factory=list)
    contradicting_evidence: Optional[List[EvidenceItem]] = Field(default_factory=list)


class HypothesisUpdateRequest(BaseModel):
    title: Optional[str] = None
    hypothesis_text: Optional[str] = None
    status: Optional[HypothesisStatusEnum] = None
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0)
    supporting_evidence: Optional[List[EvidenceItem]] = None
    contradicting_evidence: Optional[List[EvidenceItem]] = None
    reason: Optional[str] = Field(None, description="Reason for status change")


class HypothesisResponse(BaseModel):
    id: str
    workspace_id: str
    subject_type: str
    subject_id: str
    title: str
    hypothesis_text: str
    status: str
    confidence: float
    supporting_evidence: List[EvidenceItem] = Field(default_factory=list)
    contradicting_evidence: List[EvidenceItem] = Field(default_factory=list)
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str


# -----------------------------------------------------------------------------
# Timeline & Handoffs
# -----------------------------------------------------------------------------

class CampaignTimelineEventItem(BaseModel):
    timestamp: str
    event_type: str  # OBSERVED_INDICATOR, INCIDENT_OPENED, ALERT_FIRED, ATTRIBUTION_ASSESSED, INFRASTRUCTURE_MIGRATION
    title: str
    description: str
    semantic_class: SemanticClassificationEnum = SemanticClassificationEnum.OBSERVED
    source: str
    raw_reference_id: Optional[str] = None


class CampaignTimelineResponse(BaseModel):
    campaign_id: str
    events: List[CampaignTimelineEventItem]
    first_seen: str
    last_seen: str
    activity_state: str


class ThreatHuntHandoffResponse(BaseModel):
    campaign_id: str
    campaign_name: str
    suggested_queries: List[Dict[str, Any]]
    hunt_indicators: List[str]


class DetectionHandoffResponse(BaseModel):
    campaign_id: str
    campaign_name: str
    recommended_rule_title: str
    recommended_rule_description: str
    indicators_to_match: List[str]
    attack_techniques: List[str]
    suggested_severity: str = "HIGH"
