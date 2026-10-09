"""
Pydantic schemas for Section 43: History & Search.
Unified Investigation, Evidence, Intelligence & Report Discovery layer.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SearchResultItem(BaseModel):
    """Normalized search result row for unified discovery."""
    id: str
    type: str  # investigation, report, indicator, evidence, finding, campaign, threat_memory
    title: str
    subtitle: Optional[str] = None
    relevance: float = 1.0
    timestamp: Optional[datetime] = None
    risk_score: Optional[float] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    source_type: Optional[str] = None
    matched_field: Optional[str] = None
    highlights: List[str] = Field(default_factory=list)
    navigation_target: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SearchResponse(BaseModel):
    """Response returned by unified search endpoint."""
    query: str
    total: int
    results: List[SearchResultItem]
    grouped_counts: Dict[str, int] = Field(default_factory=dict)
    has_more: bool = False
    next_offset: Optional[int] = None
    execution_time_ms: float = 0.0


class IndicatorOccurrenceItem(BaseModel):
    """Occurrence of an indicator within an investigation or case."""
    investigation_id: str
    incident_number: str
    title: str
    severity: str
    status: str
    observed_at: datetime
    source: str


class CrossInvestigationIndicatorResponse(BaseModel):
    """Authoritative cross-investigation indicator lookup."""
    indicator_value: str
    normalized_value: str
    indicator_type: str
    total_investigations: int
    total_campaigns: int
    total_evidence_objects: int
    first_observed_at: Optional[datetime] = None
    last_observed_at: Optional[datetime] = None
    reputation: Optional[str] = None
    current_observations: List[Dict[str, Any]] = Field(default_factory=list)
    historical_memory: Optional[Dict[str, Any]] = None
    external_intelligence: Optional[Dict[str, Any]] = None
    analyst_verifications: List[Dict[str, Any]] = Field(default_factory=list)
    related_investigations: List[IndicatorOccurrenceItem] = Field(default_factory=list)
    related_campaigns: List[Dict[str, Any]] = Field(default_factory=list)


class SearchFacetsResponse(BaseModel):
    """Facet counts in the current search query scope."""
    risk: Dict[str, int] = Field(default_factory=dict)
    severity: Dict[str, int] = Field(default_factory=dict)
    status: Dict[str, int] = Field(default_factory=dict)
    source_type: Dict[str, int] = Field(default_factory=dict)
    resource_types: Dict[str, int] = Field(default_factory=dict)


class InvestigationListItem(BaseModel):
    """Investigation entry in the historical investigations browser."""
    id: str
    investigation_number: str
    title: str
    description: Optional[str] = None
    status: str
    severity: str
    risk_score: float
    confidence: float
    source_type: str
    classification: str
    findings_count: int = 0
    indicators_count: int = 0
    evidence_count: int = 0
    affected_entities: List[str] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class InvestigationListResponse(BaseModel):
    """Paginated response for the investigations list."""
    total: int
    limit: int
    offset: int
    has_more: bool
    items: List[InvestigationListItem]
    facets: SearchFacetsResponse
