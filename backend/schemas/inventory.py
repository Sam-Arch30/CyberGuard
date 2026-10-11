"""
Section 63: Asset & Identity Inventory Pydantic Schemas.
Controlled vocabularies, DTOs, and serialization contracts for enterprise assets,
identities, source registry, and conflict reconciliation.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Controlled Vocabularies & Enums
# ---------------------------------------------------------------------------

class InventoryAssetType(str, Enum):
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
    DATABASE = "DATABASE"
    CERTIFICATE = "CERTIFICATE"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    NETWORK_DEVICE = "NETWORK_DEVICE"


class InventoryIdentityType(str, Enum):
    USER = "USER"
    ACCOUNT = "ACCOUNT"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    APPLICATION_IDENTITY = "APPLICATION_IDENTITY"
    API_CLIENT = "API_CLIENT"


class InventoryAssetStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    STALE = "STALE"
    RETIRED = "RETIRED"
    UNKNOWN = "UNKNOWN"
    DISCOVERED = "DISCOVERED"


class InventoryIdentityStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DORMANT = "DORMANT"
    SUSPENDED = "SUSPENDED"
    RETIRED = "RETIRED"
    UNKNOWN = "UNKNOWN"


class OwnershipStatusEnum(str, Enum):
    ASSIGNED = "ASSIGNED"
    UNASSIGNED = "UNASSIGNED"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"
    INFERRED = "INFERRED"


class CriticalityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class EnvironmentEnum(str, Enum):
    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    CORP = "CORP"
    LAB = "LAB"
    TEST = "TEST"
    PERSONAL = "PERSONAL"
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


class InventorySourceType(str, Enum):
    DIRECTORY = "DIRECTORY"
    CMDB = "CMDB"
    ENDPOINT_AGENT = "ENDPOINT_AGENT"
    CLOUD_PROVIDER = "CLOUD_PROVIDER"
    APPLICATION_REGISTRY = "APPLICATION_REGISTRY"
    NETWORK_TELEMETRY = "NETWORK_TELEMETRY"
    MANUAL = "MANUAL"


class SourceHealthStatus(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"


class ConflictStatusEnum(str, Enum):
    AUTO_RESOLVED = "AUTO_RESOLVED"
    PENDING_REVIEW = "PENDING_REVIEW"
    MANUALLY_RESOLVED = "MANUALLY_RESOLVED"
    IGNORED = "IGNORED"


# ---------------------------------------------------------------------------
# Asset Schemas
# ---------------------------------------------------------------------------

class AssetBase(BaseModel):
    asset_type: str = Field(..., description="Asset classification type")
    canonical_name: str = Field(..., description="Normalized deterministic identifier")
    display_name: str = Field(..., description="Human-readable label")
    status: str = Field(default="ACTIVE", description="Lifecycle status")
    exposure_state: str = Field(default="UNKNOWN", description="Exposure tier")
    criticality: str = Field(default="MEDIUM", description="Business criticality tier")
    owner: Optional[str] = Field(None, description="Responsible owner or contact")
    team: Optional[str] = Field(None, description="Managing team")
    business_unit: Optional[str] = Field(None, description="Managing business unit")
    department: Optional[str] = Field(None, description="Organizational department")
    ownership_status: str = Field(default="UNASSIGNED", description="Ownership lifecycle status")
    classification: Optional[str] = Field(None, description="Hardware or service classification")
    environment: str = Field(default="UNKNOWN", description="Environment classification")
    ownership_confidence: str = Field(default="UNKNOWN", description="Confidence provenance")
    source: str = Field(default="INTERNAL_DISCOVERY", description="Ingestion source")
    external_id: Optional[str] = Field(None, description="Source external identifier")
    is_managed: bool = Field(default=True, description="Whether asset has active endpoint/cloud management")
    is_stale: bool = Field(default=False, description="Whether asset telemetry has lapsed")
    tags: List[str] = Field(default_factory=list, description="Categorical tags")


class AssetCreate(AssetBase):
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary attributes")


class AssetUpdate(BaseModel):
    display_name: Optional[str] = None
    status: Optional[str] = None
    exposure_state: Optional[str] = None
    criticality: Optional[str] = None
    owner: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    department: Optional[str] = None
    ownership_status: Optional[str] = None
    classification: Optional[str] = None
    environment: Optional[str] = None
    is_managed: Optional[bool] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class AssetRead(AssetBase):
    id: str
    workspace_id: str
    canonical_entity_id: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    active_finding_count: int = 0
    active_exposure_count: int = 0
    first_seen_at: datetime
    last_seen_at: datetime
    last_observed_at: Optional[datetime] = None
    last_sync_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_dict")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class OwnershipAssignRequest(BaseModel):
    owner: str = Field(..., description="Target owner name or email")
    team: Optional[str] = Field(None, description="Target managing team")
    department: Optional[str] = Field(None, description="Target department")
    business_unit: Optional[str] = Field(None, description="Target business unit")
    reason: Optional[str] = Field(None, description="Analyst justification for assignment")


class AssetDetailRead(AssetRead):
    exposures: List[Dict[str, Any]] = Field(default_factory=list)
    services: List[Dict[str, Any]] = Field(default_factory=list)
    conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    graph_neighbors: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Identity Schemas
# ---------------------------------------------------------------------------

class IdentityBase(BaseModel):
    identity_type: str = Field(default="USER", description="USER, ACCOUNT, SERVICE_ACCOUNT, APPLICATION_IDENTITY, API_CLIENT")
    canonical_identifier: str = Field(..., description="Normalized identifier: email, username, UPN")
    display_name: str = Field(..., description="Full name or service account description")
    email: Optional[str] = Field(None, description="Primary email address")
    username: Optional[str] = Field(None, description="Account login username")
    department: Optional[str] = Field(None, description="Department")
    team: Optional[str] = Field(None, description="Team")
    business_unit: Optional[str] = Field(None, description="Business unit")
    manager: Optional[str] = Field(None, description="Manager name or email")
    status: str = Field(default="ACTIVE", description="ACTIVE, INACTIVE, DORMANT, SUSPENDED, RETIRED, UNKNOWN")
    criticality: str = Field(default="MEDIUM", description="CRITICAL, HIGH, MEDIUM, LOW")
    is_privileged: bool = Field(default=False, description="Whether identity has administrative / privileged roles")
    is_service_account: bool = Field(default=False, description="Whether identity is non-human service account")
    is_orphaned: bool = Field(default=False, description="Whether account is missing a verified human owner or app")
    is_dormant: bool = Field(default=False, description="Whether identity has no authentication activity > threshold")
    source: str = Field(default="DIRECTORY", description="DIRECTORY, IDP, HR_SYSTEM, ENDPOINT_AGENT, CLOUD_IAM, MANUAL_ANALYST")
    external_id: Optional[str] = Field(None, description="IdP / Directory GUID")
    tags: List[str] = Field(default_factory=list, description="Tags")


class IdentityCreate(IdentityBase):
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary attributes")


class IdentityUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[str] = None
    username: Optional[str] = None
    department: Optional[str] = None
    team: Optional[str] = None
    business_unit: Optional[str] = None
    manager: Optional[str] = None
    status: Optional[str] = None
    criticality: Optional[str] = None
    is_privileged: Optional[bool] = None
    is_service_account: Optional[bool] = None
    is_orphaned: Optional[bool] = None
    is_dormant: Optional[bool] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class IdentityRead(IdentityBase):
    id: str
    workspace_id: str
    canonical_entity_id: Optional[str] = None
    risk_score: float = 0.0
    risk_level: str = "LOW"
    first_seen_at: datetime
    last_seen_at: datetime
    last_authenticated_at: Optional[datetime] = None
    last_sync_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_dict")

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class IdentityDetailRead(IdentityRead):
    associated_assets: List[Dict[str, Any]] = Field(default_factory=list)
    conflicts: List[Dict[str, Any]] = Field(default_factory=list)
    graph_neighbors: List[Dict[str, Any]] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Inventory Source Registry Schemas
# ---------------------------------------------------------------------------

class InventorySourceBase(BaseModel):
    source_type: str = Field(..., description="DIRECTORY, CMDB, ENDPOINT_AGENT, CLOUD_PROVIDER, APPLICATION_REGISTRY, NETWORK_TELEMETRY, MANUAL")
    name: str = Field(..., description="Human-readable source name")
    status: str = Field(default="ACTIVE", description="ACTIVE, DEGRADED, OFFLINE, PAUSED")
    authority_weight: int = Field(default=50, ge=1, le=100, description="Deterministic precedence score (1-100)")
    sync_interval_seconds: int = Field(default=3600, ge=60, description="Sync frequency in seconds")
    health_status: str = Field(default="HEALTHY", description="HEALTHY, DEGRADED, UNHEALTHY")
    capabilities: List[str] = Field(default_factory=list, description="Supported entity classes")


class InventorySourceCreate(InventorySourceBase):
    config: Dict[str, Any] = Field(default_factory=dict, description="Source connector configuration")


class InventorySourceUpdate(BaseModel):
    name: Optional[str] = None
    status: Optional[str] = None
    authority_weight: Optional[int] = Field(None, ge=1, le=100)
    sync_interval_seconds: Optional[int] = Field(None, ge=60)
    health_status: Optional[str] = None
    capabilities: Optional[List[str]] = None
    config: Optional[Dict[str, Any]] = None


class InventorySourceRead(InventorySourceBase):
    id: str
    workspace_id: str
    last_sync_at: Optional[datetime] = None
    last_sync_status: Optional[str] = None
    last_sync_record_count: int = 0
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ---------------------------------------------------------------------------
# Inventory Conflict & Resolution Schemas
# ---------------------------------------------------------------------------

class InventoryConflictRead(BaseModel):
    id: str
    workspace_id: str
    target_type: str = Field(..., description="ASSET or IDENTITY")
    target_id: str
    target_canonical_name: str
    field_name: str = Field(..., description="Field with conflicting source data")
    conflicting_values: List[Dict[str, Any]] = Field(default_factory=list, validation_alias="conflicting_values_list")
    resolved_value: Optional[str] = None
    resolved_source: Optional[str] = None
    resolution_reason: Optional[str] = None
    status: str = Field(default="PENDING_REVIEW", description="AUTO_RESOLVED, PENDING_REVIEW, MANUALLY_RESOLVED, IGNORED")
    resolved_by: Optional[str] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class InventoryConflictResolveRequest(BaseModel):
    selected_value: str = Field(..., description="The chosen resolution value")
    selected_source: str = Field(default="MANUAL_OVERRIDE", description="Source or manual justification tag")
    resolution_reason: str = Field(..., description="Analyst justification explaining resolution")


# ---------------------------------------------------------------------------
# Overview & Reconciliation Schemas
# ---------------------------------------------------------------------------

class InventoryOverviewStats(BaseModel):
    total_assets: int = 0
    active_assets: int = 0
    stale_assets: int = 0
    unmanaged_assets: int = 0
    unowned_assets: int = 0
    total_identities: int = 0
    active_identities: int = 0
    privileged_identities: int = 0
    dormant_identities: int = 0
    orphaned_identities: int = 0
    pending_conflicts: int = 0
    active_sources: int = 0
    last_reconciliation_at: Optional[datetime] = None


class InventorySyncRequest(BaseModel):
    source_ids: Optional[List[str]] = Field(None, description="Optional specific source IDs to sync")
    sync_endpoints: bool = Field(default=True, description="Sync from Endpoint Device & Agent registries")
    sync_identities: bool = Field(default=True, description="Sync from Protected Identity & Directory models")
    sync_telemetry: bool = Field(default=True, description="Sync from live telemetry observations")


class InventorySyncResponse(BaseModel):
    assets_synced: int = 0
    identities_synced: int = 0
    conflicts_detected: int = 0
    sync_duration_ms: float = 0.0
    status: str = "COMPLETED"
    message: str = "Inventory synchronization sweep completed successfully."


class InventoryReconciliationReport(BaseModel):
    timestamp: datetime
    stale_assets_flagged: int = 0
    unmanaged_endpoints_flagged: int = 0
    unowned_assets_flagged: int = 0
    dormant_identities_flagged: int = 0
    orphaned_accounts_flagged: int = 0
    conflicts_auto_resolved: int = 0
    conflicts_pending_review: int = 0
    total_records_processed: int = 0
    reconciliation_duration_ms: float = 0.0
