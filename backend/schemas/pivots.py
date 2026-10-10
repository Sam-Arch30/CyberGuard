"""
Section 55: Pydantic Schemas & DTOs for Advanced Threat Hunting & Investigation Pivots.
Provides structured contracts for:
- Pivot taxonomy & controlled pivot registry
- Interactive multi-hop pivot requests and responses
- Graph node and edge serialization with evidence provenance
- Entity frequency analysis (first seen, last seen, co-occurrence, investigation counts)
- Analyst hypotheses with evidence classification (SUPPORTING / CONTRADICTING / NEUTRAL)
- Explainable AI-assisted pivot recommendations
- Handoff contracts to Investigations, Watchlists, and Threat Hunting queries.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.schemas.hunting import QueryTimeRange, HuntQueryDefinition


# =============================================================================
# 1. Enums & Taxonomies
# =============================================================================

class PivotCategoryEnum(str, Enum):
    INFRASTRUCTURE = "INFRASTRUCTURE"
    ACTIVITY = "ACTIVITY"
    SECURITY = "SECURITY"


class PivotSourceTypeEnum(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"
    EMAIL = "EMAIL"
    CERTIFICATE = "CERTIFICATE"
    ASN = "ASN"
    DEVICE = "DEVICE"
    USER = "USER"
    ARTIFACT = "ARTIFACT"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    CAMPAIGN = "CAMPAIGN"


class PivotTypeEnum(str, Enum):
    # Infrastructure Pivots
    RESOLVED_IPS = "RESOLVED_IPS"
    REVERSE_DNS_DOMAINS = "REVERSE_DNS_DOMAINS"
    ASSOCIATED_CERTIFICATES = "ASSOCIATED_CERTIFICATES"
    SHARED_CERTIFICATE_DOMAINS = "SHARED_CERTIFICATE_DOMAINS"
    SHARED_IP_DOMAINS = "SHARED_IP_DOMAINS"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    ASN_INFRASTRUCTURE = "ASN_INFRASTRUCTURE"
    NAMESERVERS = "NAMESERVERS"
    REGISTRAR = "REGISTRAR"

    # Activity & Telemetry Pivots
    RELATED_EMAILS = "RELATED_EMAILS"
    EMAIL_RECIPIENTS = "EMAIL_RECIPIENTS"
    EMAIL_ATTACHMENTS = "EMAIL_ATTACHMENTS"
    ENDPOINT_ACTIVITY = "ENDPOINT_ACTIVITY"
    NETWORK_ACTIVITY = "NETWORK_ACTIVITY"
    ARTIFACT_OBSERVATIONS = "ARTIFACT_OBSERVATIONS"
    API_ACTIVITY = "API_ACTIVITY"

    # Security Context Pivots
    RELATED_ALERTS = "RELATED_ALERTS"
    RELATED_INVESTIGATIONS = "RELATED_INVESTIGATIONS"
    ASSOCIATED_CAMPAIGNS = "ASSOCIATED_CAMPAIGNS"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    WATCHLIST_STATUS = "WATCHLIST_STATUS"
    ATTRIBUTION_HYPOTHESIS = "ATTRIBUTION_HYPOTHESIS"
    ATTACK_TECHNIQUES = "ATTACK_TECHNIQUES"
    KNOWLEDGE_GRAPH_NEIGHBORS = "KNOWLEDGE_GRAPH_NEIGHBORS"


class PivotCostClassEnum(str, Enum):
    FAST = "FAST"
    NORMAL = "NORMAL"
    EXPENSIVE = "EXPENSIVE"
    BACKGROUND = "BACKGROUND"


class PivotOriginEnum(str, Enum):
    OBSERVED = "OBSERVED"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    DERIVED = "DERIVED"
    CORRELATED = "CORRELATED"
    ANALYST_ASSERTED = "ANALYST_ASSERTED"


class EvidenceClassificationEnum(str, Enum):
    SUPPORTING = "SUPPORTING"
    CONTRADICTING = "CONTRADICTING"
    NEUTRAL = "NEUTRAL"


class HypothesisStatusEnum(str, Enum):
    PROPOSED = "PROPOSED"
    INVESTIGATING = "INVESTIGATING"
    CONFIRMED = "CONFIRMED"
    DISPROVED = "DISPROVED"
    ABANDONED = "ABANDONED"


# =============================================================================
# 2. Pivot Definition & Registry
# =============================================================================

class PivotDefinition(BaseModel):
    source_type: PivotSourceTypeEnum
    pivot_type: PivotTypeEnum
    target_type: PivotSourceTypeEnum
    display_name: str
    category: PivotCategoryEnum
    relationship_name: str
    description: str
    cost_class: PivotCostClassEnum = PivotCostClassEnum.NORMAL
    is_multi_hop_capable: bool = True
    reverse_pivot_type: Optional[PivotTypeEnum] = None


class PivotRegistryResponse(BaseModel):
    supported_source_types: List[str]
    pivots: List[PivotDefinition]
    max_depth_allowed: int = Field(3, description="Maximum permitted graph/pivot traversal depth")
    max_results_allowed: int = Field(200, description="Upper bound for returned pivot target items")


# =============================================================================
# 3. Pivot Request & Execution
# =============================================================================

class PivotRequest(BaseModel):
    source_type: PivotSourceTypeEnum
    source_value: str = Field(..., description="Observable value (e.g., domain name, IP, hash)")
    pivot_type: PivotTypeEnum
    source_id: Optional[str] = None
    time_range: Optional[QueryTimeRange] = None
    depth: int = Field(1, ge=1, le=3, description="Traversal hop depth (1 to 3)")
    limit: int = Field(50, ge=1, le=200, description="Maximum target records to retrieve")
    investigation_id: Optional[str] = Field(None, description="Optional active investigation/incident context")
    execution_mode: str = Field("FAST", description="Execution mode: FAST or BACKGROUND")


class PivotResultItem(BaseModel):
    id: str
    target_type: str
    target_value: str
    target_id: Optional[str] = None
    display_label: str
    relationship_type: str
    relationship_description: str
    origin: str = "OBSERVED"
    confidence: float = 1.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_reference: Optional[str] = None
    evidence_reference: Optional[str] = None
    co_occurrence_count: int = 1
    classification: Optional[EvidenceClassificationEnum] = None
    matched_context: Dict[str, Any] = Field(default_factory=dict)
    pivot_links: Dict[str, str] = Field(default_factory=dict)


class EntityFrequencyContext(BaseModel):
    source_type: str
    source_value: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    observed_days_span: int = 0
    artifact_count: int = 0
    investigation_count: int = 0
    alert_count: int = 0
    is_watchlist_monitored: bool = False
    reputation_verdict: Optional[str] = None
    threat_score: Optional[float] = None


class PivotGraphNode(BaseModel):
    id: str
    label: str
    entity_type: str
    value: str
    is_root: bool = False
    hop_distance: int = 0
    verdict: Optional[str] = None
    threat_score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class PivotGraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str
    label: str
    origin: str = "OBSERVED"
    confidence: float = 1.0
    evidence_reference: Optional[str] = None
    provenance_explanation: str


class PivotResponse(BaseModel):
    source_type: str
    source_value: str
    pivot_type: str
    depth: int
    execution_time_ms: float
    total_results: int
    truncated: bool = False
    items: List[PivotResultItem]
    frequency_context: EntityFrequencyContext
    graph_nodes: List[PivotGraphNode]
    graph_edges: List[PivotGraphEdge]
    job_id: Optional[str] = None
    execution_id: Optional[str] = None
    partial_failures: List[str] = Field(default_factory=list)


# =============================================================================
# 4. AI-Assisted Recommendations
# =============================================================================

class AIPivotRecommendationItem(BaseModel):
    pivot_type: PivotTypeEnum
    display_name: str
    category: PivotCategoryEnum
    rationale: str
    expected_yield: str
    confidence: float = 0.85


class AIPivotRecommendationResponse(BaseModel):
    source_type: str
    source_value: str
    recommendations: List[AIPivotRecommendationItem]


# =============================================================================
# 5. Analyst Hypothesis & Evidence Classification
# =============================================================================

class HypothesisRecordRequest(BaseModel):
    title: str = Field(..., max_length=255)
    hypothesis_text: str
    source_observable: Optional[str] = None
    investigation_id: Optional[str] = None
    supporting_items: List[str] = Field(default_factory=list)
    contradicting_items: List[str] = Field(default_factory=list)
    neutral_items: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    status: HypothesisStatusEnum = HypothesisStatusEnum.PROPOSED


class HypothesisResponse(BaseModel):
    id: str
    workspace_id: str
    investigation_id: Optional[str] = None
    title: str
    hypothesis_text: str
    status: str
    source_observable: Optional[str] = None
    supporting_count: int
    contradicting_count: int
    neutral_count: int
    supporting_items: List[str] = Field(default_factory=list)
    contradicting_items: List[str] = Field(default_factory=list)
    neutral_items: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


# =============================================================================
# 6. Handoff Workflows
# =============================================================================

class PromoteToInvestigationRequest(BaseModel):
    investigation_id: Optional[str] = Field(None, description="Existing investigation/incident ID; creates new if omitted")
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = "HIGH"
    selected_target_values: List[str] = Field(..., min_length=1)
    source_value: str
    source_type: str
    pivot_type: str
    hypothesis_id: Optional[str] = None
    analyst_notes: Optional[str] = None


class PromoteToInvestigationResponse(BaseModel):
    investigation_id: str
    created_relationships_count: int
    incident_number: Optional[str] = None
    message: str


class PromoteToWatchlistRequest(BaseModel):
    watchlist_id: Optional[str] = None
    watchlist_name: Optional[str] = None
    selected_target_values: List[str] = Field(..., min_length=1)
    target_type: str
    reason: str = "Discovered via Threat Hunting Investigation Pivot"


class PromoteToWatchlistResponse(BaseModel):
    watchlist_id: str
    added_items_count: int
    message: str


class PivotToHuntQueryRequest(BaseModel):
    selected_target_values: List[str] = Field(..., min_length=1)
    target_type: str


class PivotToHuntQueryResponse(BaseModel):
    query_definition: HuntQueryDefinition
    suggested_hunt_name: str
