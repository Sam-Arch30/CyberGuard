"""
Probable Origin Infrastructure & Threat Infrastructure Attribution Schemas (Section 20).
Defines contracts for observed and associated technical infrastructure, candidate ranking,
infrastructure clustering, temporal tracking, hypothesis generation, and evidence links.

STRICT FORENSIC NON-ATTRIBUTION GUARANTEES:
1. NEVER claims to identify human attackers, personal identities, physical locations, or ownership.
2. Identifies technical network and hosting infrastructure (IPs, ASNs, hosting networks, domains).
3. IP geolocation is strictly characterized as infrastructure location, not human location.
4. Outputs: "CyberGuard mapped observed activity to infrastructure cluster...", never "Attacker used...".
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field, ConfigDict, model_validator

from backend.schemas.attack_confidence import ConfidenceLevel, SourceTrustLevel


FORENSIC_INFRASTRUCTURE_DISCLAIMER = (
    "Location refers to observed network infrastructure and should not be interpreted "
    "as the physical location of the threat actor. This assessment represents a technical "
    "infrastructure-origin hypothesis based on observed evidence and does not establish "
    "human identity, personal location, or legal ownership."
)

FORBIDDEN_ATTRIBUTION_KEYS = {
    "human_attacker_identity",
    "person_name",
    "attacker_location",
    "confirmed_owner",
    "threat_actor_identity",
    "attacker_identity",
    "real_name",
    "physical_address",
}


# ============================================================================
# 1. CONTROLLED ENUMS & VOCABULARY
# ============================================================================

class OriginType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    HOSTING_INFRASTRUCTURE = "HOSTING_INFRASTRUCTURE"
    ASN = "ASN"
    NETWORK_CLUSTER = "NETWORK_CLUSTER"
    DOMAIN_CLUSTER = "DOMAIN_CLUSTER"
    INFRASTRUCTURE_CLUSTER = "INFRASTRUCTURE_CLUSTER"
    CAMPAIGN_INFRASTRUCTURE = "CAMPAIGN_INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"


class InfrastructureRole(str, Enum):
    ORIGIN_CANDIDATE = "ORIGIN_CANDIDATE"
    COMMAND_INFRASTRUCTURE_CANDIDATE = "COMMAND_INFRASTRUCTURE_CANDIDATE"
    REDIRECT_INFRASTRUCTURE = "REDIRECT_INFRASTRUCTURE"
    HOSTING_INFRASTRUCTURE = "HOSTING_INFRASTRUCTURE"
    MAIL_RELAY = "MAIL_RELAY"
    DNS_INFRASTRUCTURE = "DNS_INFRASTRUCTURE"
    PROXY_OR_INTERMEDIARY = "PROXY_OR_INTERMEDIARY"
    VICTIM_INFRASTRUCTURE = "VICTIM_INFRASTRUCTURE"
    LEGITIMATE_SERVICE = "LEGITIMATE_SERVICE"
    SHARED_INFRASTRUCTURE = "SHARED_INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"


class InfrastructureDirection(str, Enum):
    OBSERVED_SOURCE = "OBSERVED_SOURCE"
    OBSERVED_DESTINATION = "OBSERVED_DESTINATION"
    INFRASTRUCTURE_ENDPOINT = "INFRASTRUCTURE_ENDPOINT"
    INTERMEDIARY_INFRASTRUCTURE = "INTERMEDIARY_INFRASTRUCTURE"
    RELAY_INFRASTRUCTURE = "RELAY_INFRASTRUCTURE"
    HOSTING_INFRASTRUCTURE = "HOSTING_INFRASTRUCTURE"
    UNKNOWN = "UNKNOWN"


class AttributionStatus(str, Enum):
    PROBABLE = "PROBABLE"
    PLAUSIBLE = "PLAUSIBLE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    REJECTED = "REJECTED"


class AttributionHypothesisType(str, Enum):
    DEDICATED_THREAT_INFRASTRUCTURE = "DEDICATED_THREAT_INFRASTRUCTURE"
    COMPROMISED_HOSTING = "COMPROMISED_HOSTING"
    SHARED_INFRASTRUCTURE_PROXY = "SHARED_INFRASTRUCTURE_PROXY"
    ORIGIN_INSUFFICIENT_EVIDENCE = "ORIGIN_INSUFFICIENT_EVIDENCE"


class EvidenceFamily(str, Enum):
    DIRECT_TELEMETRY = "DIRECT_TELEMETRY"
    DNS = "DNS"
    DOMAIN_INTELLIGENCE = "DOMAIN_INTELLIGENCE"
    NETWORK_INTELLIGENCE = "NETWORK_INTELLIGENCE"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    HISTORICAL_INCIDENT = "HISTORICAL_INCIDENT"
    CAMPAIGN_CORRELATION = "CAMPAIGN_CORRELATION"
    TEMPORAL_CORRELATION = "TEMPORAL_CORRELATION"
    GRAPH_RELATIONSHIP = "GRAPH_RELATIONSHIP"
    USER_ANALYST_INPUT = "USER_ANALYST_INPUT"


class SupportDirection(str, Enum):
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    NEUTRAL = "NEUTRAL"


# ============================================================================
# 2. EVIDENCE & CANDIDATE MODELS
# ============================================================================

class InfrastructureAttributionEvidence(BaseModel):
    """
    Forensic link connecting an attribution hypothesis to concrete evidence or graph relationship.
    """
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique evidence linkage identifier")
    attribution_id: str = Field(..., description="Target attribution hypothesis identifier")
    evidence_id: Optional[str] = Field(None, description="Referenced raw Evidence ID or Artifact ID")
    relationship_id: Optional[str] = Field(None, description="Referenced Knowledge Graph relationship ID")
    source_entity_id: str = Field(..., description="Source entity ID or canonical key")
    target_entity_id: Optional[str] = Field(None, description="Target entity ID or canonical key")
    relationship_type: str = Field(..., description="Graph relationship type (e.g. RESOLVES_TO, BELONGS_TO, HOSTED_BY)")
    evidence_family: EvidenceFamily = Field(..., description="Independent evidence family classification")
    support_direction: SupportDirection = Field(SupportDirection.SUPPORTS, description="SUPPORTS, CONTRADICTS, or NEUTRAL")
    strength: float = Field(1.0, ge=0.0, le=1.0, description="Evidentiary weight or strength 0.0-1.0")
    explanation: str = Field(..., description="Forensic explanation of how this evidence influences the hypothesis")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="after")
    def verify_no_human_attribution(self) -> InfrastructureAttributionEvidence:
        lower_exp = self.explanation.lower()
        for forbidden in FORBIDDEN_ATTRIBUTION_KEYS:
            if forbidden in lower_exp:
                raise ValueError(f"Forbidden human attribution term '{forbidden}' detected in explanation")
        return self


class InfrastructureCandidate(BaseModel):
    """
    Candidate infrastructure entity evaluated for role classification and origin attribution.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Entity ID or canonical key")
    entity_type: str = Field(..., description="IP, DOMAIN, ASN, URL, NAMESERVER, etc.")
    canonical_key: str = Field(..., description="Deterministic canonical identity key")
    value: str = Field(..., description="Raw display value (e.g. 203.0.113.10, login-evil.test)")
    role: InfrastructureRole = Field(InfrastructureRole.UNKNOWN, description="Classified technical role")
    direction: InfrastructureDirection = Field(InfrastructureDirection.UNKNOWN, description="Observed traffic direction")
    is_observed: bool = Field(True, description="True if directly observed in incident telemetry")
    is_direct: bool = Field(True, description="True if direct observation vs derived/correlated")

    asn: Optional[str] = Field(None, description="Autonomous System Number (e.g. AS64512)")
    asn_org: Optional[str] = Field(None, description="Organization operating the Autonomous System")
    network: Optional[str] = Field(None, description="CIDR network block if available")
    hosting_provider: Optional[str] = Field(None, description="Hosting provider or ISP name")
    country: Optional[str] = Field(None, description="Hosting infrastructure country (not attacker location)")
    country_code: Optional[str] = Field(None, description="2-letter ISO country code")
    city: Optional[str] = Field(None, description="Hosting infrastructure approximate city")

    is_shared_infrastructure: bool = Field(False, description="True if cloud hosting, CDN, shared hosting")
    is_cloud_provider: bool = Field(False, description="True if AWS, Azure, GCP, OCI, etc.")
    is_cdn: bool = Field(False, description="True if Cloudflare, Fastly, Akamai, etc.")
    is_vpn_proxy_tor: bool = Field(False, description="True if known VPN, open proxy, or Tor exit")

    reputation_verdict: Optional[str] = Field(None, description="External threat intel verdict (e.g. MALICIOUS, SUSPICIOUS, BENIGN)")
    historical_incident_ids: List[str] = Field(default_factory=list, description="IDs of past incidents sharing this entity")
    campaign_ids: List[str] = Field(default_factory=list, description="IDs of campaigns associated with this entity")

    first_seen: Optional[datetime] = Field(None, description="Earliest observation timestamp")
    last_seen: Optional[datetime] = Field(None, description="Most recent observation timestamp")
    evidence_refs: List[str] = Field(default_factory=list, description="Associated evidence or telemetry IDs")

    ranking_score: float = Field(0.0, description="Calculated origin ranking score (0.0 to 1.0)")
    confidence_level: ConfidenceLevel = Field(ConfidenceLevel.MODERATE, description="Heuristic evidence strength")
    confidence_score: float = Field(0.5, ge=0.0, le=1.0, description="Confidence score 0.0 to 1.0")
    limitations: List[str] = Field(default_factory=list, description="Caveats and limitations for this candidate")


class InfrastructureClusterMember(BaseModel):
    """Member entity of an infrastructure cluster."""
    entity_id: str
    entity_type: str
    value: str
    role: str
    is_observed: bool
    direction: str


class InfrastructureCluster(BaseModel):
    """
    Cluster of technically related infrastructure entities exhibiting shared relationships.
    """
    model_config = ConfigDict(extra="ignore")

    cluster_id: str = Field(..., description="Unique cluster identifier (e.g. CLUSTER-2026-001)")
    name: str = Field(..., description="Descriptive display title for the infrastructure cluster")
    members: List[InfrastructureClusterMember] = Field(default_factory=list, description="Member entities")
    relationship_types: List[str] = Field(default_factory=list, description="Observed binding relationships")
    evidence_count: int = Field(0, description="Total supporting evidence references")
    incident_count: int = Field(0, description="Number of distinct incidents connected to this cluster")
    campaign_count: int = Field(0, description="Number of threat campaigns associated")
    supporting_signals: List[str] = Field(default_factory=list, description="Signals supporting the cluster grouping")
    contradicting_signals: List[str] = Field(default_factory=list, description="Signals indicating potential divergence or shared host")
    confidence: float = Field(0.5, ge=0.0, le=1.0, description="Cluster cohesion confidence 0.0-1.0")
    confidence_level: ConfidenceLevel = Field(ConfidenceLevel.MODERATE, description="Confidence tier")


class InfrastructureTimelineEvent(BaseModel):
    """Chronological infrastructure observation or state transition."""
    id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(..., description="Observation timestamp")
    event_type: str = Field(..., description="DNS_RESOLUTION, HTTP_COMMUNICATION, AUTHENTICATION, MIGRATION, ROTATION")
    entity_value: str = Field(..., description="Primary infrastructure entity value")
    related_entity: Optional[str] = Field(None, description="Associated destination or target entity")
    description: str = Field(..., description="Forensic event summary")
    evidence_id: Optional[str] = Field(None, description="Linked evidence record")
    is_migration: bool = Field(False, description="True if indicates IP/hosting migration")
    is_rotation: bool = Field(False, description="True if indicates dynamic IP/DNS rotation")


# ============================================================================
# 3. ATTRIBUTION HYPOTHESIS & REPORT RESPONSE MODELS
# ============================================================================

class InfrastructureAttribution(BaseModel):
    """
    Structured infrastructure attribution hypothesis.
    Explains the most plausible technical origin infrastructure without human attribution.
    """
    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Unique attribution hypothesis ID (e.g. ATTR-INC001-H1)")
    incident_id: str = Field(..., description="Associated Incident identifier")
    investigation_id: Optional[str] = Field(None, description="Optional Investigation/Case identifier")
    subject_entity_id: Optional[str] = Field(None, description="Target entity being analyzed (e.g. Victim endpoint)")
    origin_entity_id: Optional[str] = Field(None, description="Identified origin entity ID or cluster ID")
    origin_value: str = Field(..., description="Display value of origin (e.g. 203.0.113.10, Cluster-001)")
    origin_type: OriginType = Field(OriginType.UNKNOWN, description="Classification of origin entity")

    hypothesis_id: str = Field("H1", description="Hypothesis label (e.g. H1, H2, H3)")
    hypothesis_type: AttributionHypothesisType = Field(..., description="Categorical hypothesis classification")
    hypothesis: str = Field(..., description="Clear human-readable summary of the hypothesis")
    status: AttributionStatus = Field(AttributionStatus.PROBABLE, description="PROBABLE, PLAUSIBLE, INSUFFICIENT_EVIDENCE, REJECTED")

    confidence_level: ConfidenceLevel = Field(ConfidenceLevel.MODERATE, description="Categorical confidence level")
    confidence_score: float = Field(0.5, ge=0.0, le=1.0, description="Evidence-weighted confidence score (0.0 to 1.0)")

    evidence_count: int = Field(0, description="Total evidence links")
    supporting_evidence_count: int = Field(0, description="Number of supporting evidence items")
    contradicting_evidence_count: int = Field(0, description="Number of contradicting/caveat evidence items")

    limitations: List[str] = Field(default_factory=list, description="Forensic caveats, ambiguities, and limitations")
    evidence_items: List[InfrastructureAttributionEvidence] = Field(default_factory=list, description="Itemized evidence links")

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    engine_version: str = Field("1.0.0", description="Attribution engine version")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional structured parameters")

    @model_validator(mode="after")
    def enforce_strict_non_attribution(self) -> InfrastructureAttribution:
        """
        HARD SAFETY BOUNDARY: Prohibits personal identity claims or physical location assertions.
        """
        combined = f"{self.hypothesis} {' '.join(self.limitations)}".lower()
        for forbidden in FORBIDDEN_ATTRIBUTION_KEYS:
            if forbidden in combined:
                raise ValueError(f"CRITICAL SAFETY VIOLATION: Forbidden attribution concept '{forbidden}' detected in hypothesis")
        return self


class InvestigationInfrastructureResponse(BaseModel):
    """
    Comprehensive infrastructure assessment response for an investigation or incident.
    """
    model_config = ConfigDict(extra="ignore")

    incident_id: str = Field(..., description="Incident identifier")
    incident_number: Optional[str] = Field(None, description="Human-readable incident number")
    workspace_id: str = Field("default", description="Workspace isolation ID")

    observed_infrastructure: List[InfrastructureCandidate] = Field(default_factory=list, description="Directly observed infrastructure")
    associated_infrastructure: List[InfrastructureCandidate] = Field(default_factory=list, description="Technically associated infrastructure")
    clusters: List[InfrastructureCluster] = Field(default_factory=list, description="Identified infrastructure clusters")

    primary_hypothesis: Optional[InfrastructureAttribution] = Field(None, description="Highest-ranked origin hypothesis")
    competing_hypotheses: List[InfrastructureAttribution] = Field(default_factory=list, description="Alternative hypotheses (H2, H3, etc.)")

    timeline: List[InfrastructureTimelineEvent] = Field(default_factory=list, description="Chronological infrastructure events")
    evidence_links: List[InfrastructureAttributionEvidence] = Field(default_factory=list, description="Itemized evidence relationships")

    limitations: List[str] = Field(default_factory=list, description="High-level assessment limitations")
    summary: str = Field(..., description="SOC analyst executive and technical summary")
    disclaimer: str = Field(FORENSIC_INFRASTRUCTURE_DISCLAIMER, description="Mandatory forensic disclaimer")

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
