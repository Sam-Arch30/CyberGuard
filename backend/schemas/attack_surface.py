"""
Section 62: Attack Surface Intelligence Schemas & Controlled Vocabularies.
Provides normalized data contracts for Assets, Exposures, Network Services,
Authorized Discovery Scopes, and Snapshot Diffs.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ============================================================================
# 1. CONTROLLED TAXONOMY & ENUMS
# ============================================================================

class AssetTypeEnum(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    PUBLIC_IP = "PUBLIC_IP"
    PRIVATE_IP = "PRIVATE_IP"
    ENDPOINT = "ENDPOINT"
    SERVER = "SERVER"
    DEVICE = "DEVICE"
    APPLICATION = "APPLICATION"
    WEB_APPLICATION = "WEB_APPLICATION"
    API = "API"
    SERVICE = "SERVICE"
    CERTIFICATE = "CERTIFICATE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    EMAIL_INFRASTRUCTURE = "EMAIL_INFRASTRUCTURE"
    IDENTITY = "IDENTITY"
    USER_ACCOUNT = "USER_ACCOUNT"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"


class AssetStatusEnum(str, Enum):
    DISCOVERED = "DISCOVERED"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    STALE = "STALE"
    RETIRED = "RETIRED"
    UNKNOWN = "UNKNOWN"


class ExposureStateEnum(str, Enum):
    PUBLICLY_EXPOSED = "PUBLICLY_EXPOSED"
    INTERNALLY_REACHABLE = "INTERNALLY_REACHABLE"
    INTERNALLY_ONLY = "INTERNALLY_ONLY"
    UNKNOWN = "UNKNOWN"


class CriticalityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class OwnershipConfidenceEnum(str, Enum):
    MANUAL = "MANUAL"
    CMDB = "CMDB"
    DIRECTORY = "DIRECTORY"
    ENDPOINT_AGENT = "ENDPOINT_AGENT"
    CLOUD_INVENTORY = "CLOUD_INVENTORY"
    DOMAIN_MAPPING = "DOMAIN_MAPPING"
    INFERENCE = "INFERENCE"
    UNKNOWN = "UNKNOWN"


class AssetSourceEnum(str, Enum):
    ENDPOINT_AGENT = "ENDPOINT_AGENT"
    EMAIL_ANALYSIS = "EMAIL_ANALYSIS"
    URL_ANALYSIS = "URL_ANALYSIS"
    DOMAIN_ANALYSIS = "DOMAIN_ANALYSIS"
    NETWORK_TELEMETRY = "NETWORK_TELEMETRY"
    API_TELEMETRY = "API_TELEMETRY"
    AUTHENTICATION = "AUTHENTICATION"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    WATCHLIST = "WATCHLIST"
    INVESTIGATION = "INVESTIGATION"
    THREAT_HUNT = "THREAT_HUNT"
    MANUAL_ANALYST = "MANUAL_ANALYST"
    EXTERNAL_DISCOVERY = "EXTERNAL_DISCOVERY"
    INTERNAL_DISCOVERY = "INTERNAL_DISCOVERY"


class ExposureTypeEnum(str, Enum):
    PUBLIC_ASSET = "PUBLIC_ASSET"
    UNKNOWN_ASSET = "UNKNOWN_ASSET"
    UNKNOWN_SERVICE = "UNKNOWN_SERVICE"
    EXPOSED_API = "EXPOSED_API"
    EXPOSED_IDENTITY = "EXPOSED_IDENTITY"
    STALE_ASSET = "STALE_ASSET"
    UNMAPPED_DOMAIN = "UNMAPPED_DOMAIN"
    UNEXPECTED_ENDPOINT = "UNEXPECTED_ENDPOINT"
    UNAPPROVED_PORT = "UNAPPROVED_PORT"
    CERTIFICATE_EXPIRING = "CERTIFICATE_EXPIRING"


class ExposureStatusEnum(str, Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    ACCEPTED = "ACCEPTED"
    SUPPRESSED = "SUPPRESSED"
    STALE = "STALE"
    UNKNOWN = "UNKNOWN"


class ExposureSeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ScopeTypeEnum(str, Enum):
    DOMAIN = "DOMAIN"
    CIDR = "CIDR"
    IP = "IP"
    CLOUD_ACCOUNT = "CLOUD_ACCOUNT"
    ASN = "ASN"


# ============================================================================
# 2. SERVICE & PORT INVENTORY SCHEMAS
# ============================================================================

class AssetServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    workspace_id: str
    asset_id: str
    port: Optional[int] = None
    protocol: str = "TCP"
    service_name: str = "unknown"
    service_version: Optional[str] = None
    transport: str = "IP"
    exposure: str = "UNKNOWN"
    source: str = "DISCOVERY"
    banner_snippet: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_dict")
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime


class AssetServiceCreateRequest(BaseModel):
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: str = Field("TCP", description="TCP, UDP, ICMP")
    service_name: str = Field("unknown", max_length=100)
    service_version: Optional[str] = None
    transport: str = "IP"
    exposure: str = Field("UNKNOWN", description="PUBLIC, INTERNAL, RESTRICTED")
    source: str = "DISCOVERY"
    banner_snippet: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# 3. EXPOSURE SCHEMAS
# ============================================================================

class ExposureRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    asset_id: str
    exposure_type: ExposureTypeEnum
    title: str
    description: str
    status: ExposureStatusEnum
    severity: ExposureSeverityEnum
    confidence: float
    remediation_guidance: Optional[str] = None
    evidence_refs: List[str] = Field(default_factory=list)
    source_refs: List[str] = Field(default_factory=list)
    risk_context: Dict[str, Any] = Field(default_factory=dict)
    first_seen_at: datetime
    last_seen_at: datetime
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class ExposureDetail(ExposureRead):
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    asset_exposure_state: Optional[str] = None
    asset_criticality: Optional[str] = None
    asset_owner: Optional[str] = None


class ExposureResolveRequest(BaseModel):
    action: str = Field("RESOLVE", description="RESOLVE, ACCEPT, SUPPRESS")
    notes: str = Field(..., min_length=3, description="Forensic rationale for resolution/acceptance")
    actor: str = Field("SOC Analyst", description="Analyst identity")


class ExposureListResponse(BaseModel):
    items: List[ExposureRead]
    total: number if False else int
    limit: int
    offset: int


# ============================================================================
# 4. ASSET SCHEMAS
# ============================================================================

class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: str
    workspace_id: str
    asset_type: AssetTypeEnum
    canonical_name: str
    display_name: str
    status: AssetStatusEnum
    exposure_state: ExposureStateEnum
    criticality: CriticalityEnum
    owner: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    environment: str = "UNKNOWN"
    ownership_confidence: OwnershipConfidenceEnum
    source: AssetSourceEnum
    external_id: Optional[str] = None
    canonical_entity_id: Optional[str] = None
    risk_score: float
    risk_level: str
    active_finding_count: int
    active_exposure_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    last_scanned_at: Optional[datetime] = None
    last_analyzed_at: Optional[datetime] = None
    metadata: Dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_dict")
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetRead):
    exposures: List[ExposureRead] = Field(default_factory=list)
    services: List[AssetServiceRead] = Field(default_factory=list)
    related_findings: List[Dict[str, Any]] = Field(default_factory=list)
    related_correlations: List[Dict[str, Any]] = Field(default_factory=list)
    threat_intelligence: Optional[Dict[str, Any]] = None
    graph_neighbors: List[Dict[str, Any]] = Field(default_factory=list)


class AssetCreateRequest(BaseModel):
    asset_type: AssetTypeEnum
    raw_name: str = Field(..., min_length=1, max_length=500, description="Raw domain, IP, endpoint name, or email")
    display_name: Optional[str] = None
    criticality: CriticalityEnum = CriticalityEnum.MEDIUM
    environment: str = "PRODUCTION"
    owner: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    source: AssetSourceEnum = AssetSourceEnum.MANUAL_ANALYST
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AssetUpdateRequest(BaseModel):
    display_name: Optional[str] = None
    status: Optional[AssetStatusEnum] = None
    exposure_state: Optional[ExposureStateEnum] = None
    criticality: Optional[CriticalityEnum] = None
    owner: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    environment: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AssetListResponse(BaseModel):
    items: List[AssetRead]
    total: int
    limit: int
    offset: int


# ============================================================================
# 5. DISCOVERY SCOPE SCHEMAS
# ============================================================================

class AttackSurfaceScopeRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    workspace_id: str
    scope_type: ScopeTypeEnum
    target: str
    is_authorized: bool
    description: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class AttackSurfaceScopeCreateRequest(BaseModel):
    scope_type: ScopeTypeEnum
    target: str = Field(..., min_length=2, max_length=255, description="FQDN, wildcard domain, CIDR, or IP range")
    is_authorized: bool = True
    description: str = Field("", description="Authorized scope justification or ownership reference")


# ============================================================================
# 6. OVERVIEW & DIFF SCHEMAS
# ============================================================================

class AttackSurfaceOverviewStats(BaseModel):
    total_assets: int
    publicly_exposed_assets: int
    internally_reachable_assets: int
    unknown_assets_count: int
    critical_assets_count: int
    high_risk_assets_count: int
    open_exposures_count: int
    critical_exposures_count: int
    by_type: Dict[str, int] = Field(default_factory=dict)
    by_exposure: Dict[str, int] = Field(default_factory=dict)
    by_criticality: Dict[str, int] = Field(default_factory=dict)
    authorized_scopes_count: int = 0
    recent_exposures: List[ExposureRead] = Field(default_factory=list)


class AttackSurfaceDiffResponse(BaseModel):
    snapshot_name: str
    previous_snapshot_time: Optional[datetime] = None
    current_snapshot_time: datetime
    assets_added: int
    assets_removed: int
    exposures_added: int
    exposures_resolved: int
    added_asset_names: List[str] = Field(default_factory=list)
    removed_asset_names: List[str] = Field(default_factory=list)
    new_exposure_titles: List[str] = Field(default_factory=list)
    diff_summary: Dict[str, Any] = Field(default_factory=dict)


# ============================================================================
# 7. UNKNOWN ASSET & DISCOVERY WORKFLOW SCHEMAS
# ============================================================================

class UnknownAssetReviewRequest(BaseModel):
    action: str = Field(..., description="APPROVE, ASSIGN_OWNER, MAP_TO_EXISTING, MARK_UNAUTHORIZED, ADD_TO_WATCHLIST")
    owner: Optional[str] = None
    team: Optional[str] = None
    criticality: Optional[CriticalityEnum] = None
    target_asset_id: Optional[str] = None
    notes: str = Field(..., min_length=2, description="Analyst triage rationale")
    actor: str = Field("SOC Analyst")


class AttackSurfaceDiscoveryRequest(BaseModel):
    sync_from_endpoints: bool = True
    sync_from_identities: bool = True
    sync_from_telemetry: bool = True
    resolve_dns_records: bool = True
    scope_filter: Optional[str] = None


class AttackSurfaceDiscoveryResponse(BaseModel):
    status: str = "COMPLETED"
    assets_discovered: int
    assets_updated: int
    unknown_assets_flagged: int
    exposures_created: int
    scopes_evaluated: int
    duration_ms: float
    message: str
