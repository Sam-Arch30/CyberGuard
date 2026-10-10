"""
Section 52: Pydantic schemas for Threat Intelligence & External Intelligence Enrichment.
Defines normalized indicator types, provider intelligence records, aggregated consensus verdicts,
conflicting provider representations, privacy scopes, and provider configuration schemas.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IndicatorTypeEnum(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    SHA256 = "SHA256"
    SHA1 = "SHA1"
    MD5 = "MD5"
    EMAIL = "EMAIL"
    CERTIFICATE = "CERTIFICATE"
    ASN = "ASN"
    HOSTNAME = "HOSTNAME"


class VerdictEnum(str, Enum):
    UNKNOWN = "UNKNOWN"
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNVERIFIED = "UNVERIFIED"


class SeverityEnum(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PrivacyScopeEnum(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    INTERNAL = "INTERNAL"
    SENSITIVE = "SENSITIVE"
    UNKNOWN = "UNKNOWN"


class ProviderStatusEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    RATE_LIMITED = "RATE_LIMITED"
    UNAVAILABLE = "UNAVAILABLE"
    MISCONFIGURED = "MISCONFIGURED"


class NormalizedIndicator(BaseModel):
    """Canonical normalized observable structure."""
    type: IndicatorTypeEnum
    raw_value: str
    normalized_value: str
    privacy_scope: PrivacyScopeEnum
    is_routable_public: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProviderIntelligenceItem(BaseModel):
    """Intelligence record from an individual provider."""
    provider: str
    display_name: str
    verdict: VerdictEnum
    confidence: float = Field(..., ge=0.0, le=1.0)
    severity: SeverityEnum = SeverityEnum.NONE
    threat_types: List[str] = Field(default_factory=list)
    retrieved_at: datetime
    observed_at: Optional[datetime] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    details: Optional[str] = None
    source_url: Optional[str] = None
    raw_reference: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    is_stale: bool = False


class AggregatedIndicatorIntelligence(BaseModel):
    """
    Consolidated, multi-source threat intelligence report for an indicator.
    Preserves all source provenance, exposes conflicts without suppressing disagreement,
    and isolates confidence from risk score.
    """
    indicator_type: IndicatorTypeEnum
    raw_value: str
    normalized_value: str
    privacy_scope: PrivacyScopeEnum
    overall_verdict: VerdictEnum
    consensus_confidence: float = Field(..., ge=0.0, le=1.0)
    overall_severity: SeverityEnum
    total_sources_queried: int = 0
    verdict_breakdown: Dict[str, int] = Field(default_factory=dict)
    is_conflicting: bool = False
    conflict_summary: Optional[str] = None
    threat_types: List[str] = Field(default_factory=list)
    is_stale: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    last_refreshed_at: datetime
    providers_data: List[ProviderIntelligenceItem] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    internal_memory_matched: bool = False
    associated_campaigns: List[str] = Field(default_factory=list)
    associated_threat_actors: List[str] = Field(default_factory=list)


class IndicatorObservationHistoryItem(BaseModel):
    """Historical point-in-time observation item for an indicator."""
    timestamp: datetime
    verdict: VerdictEnum
    confidence: float
    provider: str
    source_type: str  # DIRECT_OBSERVATION, EXTERNAL_FEED, INCIDENT, ANALYSIS
    summary: Optional[str] = None
    threat_types: List[str] = Field(default_factory=list)


class IndicatorHistoryResponse(BaseModel):
    """Timeline of observations for an indicator."""
    indicator_type: IndicatorTypeEnum
    normalized_value: str
    total_observations: int
    history: List[IndicatorObservationHistoryItem]


class ThreatIntelProviderConfigResponse(BaseModel):
    """Safe, sanitized representation of a configured intelligence provider."""
    id: str
    workspace_id: str
    provider_name: str
    display_name: str
    enabled: bool
    priority: int
    supported_types: List[str]
    rate_limit_per_minute: int
    timeout_seconds: float
    is_configured: bool
    status: ProviderStatusEnum
    last_health_check_at: Optional[datetime] = None
    error_message: Optional[str] = None
    capabilities: Dict[str, Any] = Field(default_factory=dict)


class ThreatIntelProviderUpdateRequest(BaseModel):
    """Update settings for an intelligence provider."""
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    api_key: Optional[str] = None
    rate_limit_per_minute: Optional[int] = None
    timeout_seconds: Optional[float] = None


class PrivacyPolicyClassificationResponse(BaseModel):
    """Describes privacy classification results and rules for indicators."""
    indicator_type: IndicatorTypeEnum
    raw_value: str
    normalized_value: str
    privacy_scope: PrivacyScopeEnum
    external_lookup_permitted: bool
    reason: str


class IndicatorEnrichmentRequest(BaseModel):
    """Request to enrich or refresh an indicator."""
    sync: bool = True
    force_refresh: bool = False


class BatchEnrichmentRequest(BaseModel):
    """Batch enrichment request for multiple indicators."""
    indicators: List[Dict[str, str]]  # [{"type": "IP", "value": "198.51.100.1"}, ...]
    force_refresh: bool = False


class BatchEnrichmentResponse(BaseModel):
    """Batch enrichment response."""
    total_requested: int
    enriched_count: int
    results: List[AggregatedIndicatorIntelligence]
    partial_failures: List[Dict[str, Any]] = Field(default_factory=list)
