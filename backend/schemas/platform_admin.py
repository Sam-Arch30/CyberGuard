"""
Section 71: Platform Administration & Governance Schemas
Comprehensive Pydantic schemas, enumerations, DTOs, and validation models for:
- Users & Access Management
- Roles & Permission Matrices
- Teams & Organizational Hierarchies
- Tenant Configurations & Isolation Bounds
- Security Policy Lifecycles & Impact Previews
- Integration Registry & Credential Protections
- System Settings with Scoped Precedence
- Feature Controls & Role Gating
- System Health Diagnostics
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class AdminRoleEnum(str, Enum):
    PLATFORM_ADMIN = "PLATFORM_ADMIN"
    TENANT_ADMIN = "TENANT_ADMIN"
    SECURITY_ADMIN = "SECURITY_ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    READ_ONLY_AUDITOR = "READ_ONLY_AUDITOR"


class UserStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    INVITED = "INVITED"
    LOCKED = "LOCKED"
    PENDING_VERIFICATION = "PENDING_VERIFICATION"


class TenantStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    PROVISIONING = "PROVISIONING"
    DISABLED = "DISABLED"


class TenantPlanTierEnum(str, Enum):
    COMMUNITY = "COMMUNITY"
    STANDARD = "STANDARD"
    ENTERPRISE = "ENTERPRISE"


class PolicyTypeEnum(str, Enum):
    AUTHENTICATION = "AUTHENTICATION"
    SESSION_MANAGEMENT = "SESSION_MANAGEMENT"
    DATA_RETENTION = "DATA_RETENTION"
    ROLE_DELEGATION = "ROLE_DELEGATION"
    EXTERNAL_SHARING = "EXTERNAL_SHARING"
    API_ACCESS = "API_ACCESS"


class PolicyStatusEnum(str, Enum):
    DRAFT = "DRAFT"
    VALIDATING = "VALIDATING"
    ACTIVE = "ACTIVE"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class SettingCategoryEnum(str, Enum):
    GENERAL = "GENERAL"
    SECURITY = "SECURITY"
    AUTHENTICATION = "AUTHENTICATION"
    ANALYSIS = "ANALYSIS"
    THREAT_INTEL = "THREAT_INTEL"
    NOTIFICATIONS = "NOTIFICATIONS"
    RETENTION = "RETENTION"
    PERFORMANCE = "PERFORMANCE"


class SettingScopeEnum(str, Enum):
    GLOBAL = "GLOBAL"
    TENANT = "TENANT"


class IntegrationCategoryEnum(str, Enum):
    THREAT_INTEL = "THREAT_INTEL"
    SIEM = "SIEM"
    EDR = "EDR"
    IDENTITY = "IDENTITY"
    NOTIFICATION = "NOTIFICATION"
    COMMUNICATION = "COMMUNICATION"


class IntegrationHealthStatusEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNCONFIGURED = "UNCONFIGURED"
    ERROR = "ERROR"


class FeatureScopeEnum(str, Enum):
    GLOBAL = "GLOBAL"
    TENANT = "TENANT"
    ENVIRONMENT = "ENVIRONMENT"


# ---------------------------------------------------------------------------
# Permissions Model
# ---------------------------------------------------------------------------

class PermissionDefinition(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key: str
    resource: str
    action: str
    scope: str
    description: str


class RoleDefinition(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    role: AdminRoleEnum
    display_name: str
    description: str
    is_system_managed: bool = True
    permissions: List[str]
    assigned_users_count: int = 0


# ---------------------------------------------------------------------------
# User Schemas
# ---------------------------------------------------------------------------

class AdminUserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., min_length=5, max_length=255)
    full_name: str = Field(..., min_length=1, max_length=255)
    role: AdminRoleEnum = AdminRoleEnum.SOC_ANALYST
    team_id: Optional[str] = None
    custom_permissions: List[str] = Field(default_factory=list)


class AdminUserCreateRequest(AdminUserBase):
    initial_status: UserStatusEnum = UserStatusEnum.ACTIVE
    tenant_id: Optional[str] = None


class AdminUserUpdateRequest(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    team_id: Optional[str] = None
    custom_permissions: Optional[List[str]] = None


class AdminRoleChangeRequest(BaseModel):
    new_role: AdminRoleEnum
    reason: str = Field(..., min_length=5, description="Audited business justification for role change")


class AdminUserStatusChangeRequest(BaseModel):
    reason: str = Field(..., min_length=5, description="Audited justification for account status transition")


class AdminUserResponse(AdminUserBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    workspace_id: str
    status: UserStatusEnum
    is_platform_admin: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class AdminUserListResponse(BaseModel):
    items: List[AdminUserResponse]
    total: int


# ---------------------------------------------------------------------------
# Team Schemas
# ---------------------------------------------------------------------------

class AdminTeamCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    description: Optional[str] = None
    team_lead_id: Optional[str] = None
    tenant_id: Optional[str] = None


class AdminTeamUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    team_lead_id: Optional[str] = None


class AdminTeamResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    name: str
    description: Optional[str] = None
    team_lead_id: Optional[str] = None
    team_lead_name: Optional[str] = None
    members_count: int = 0
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Tenant Schemas
# ---------------------------------------------------------------------------

class AdminTenantCreateRequest(BaseModel):
    id: str = Field(..., min_length=2, max_length=64, description="Unique alphanumeric tenant slug/ID")
    name: str = Field(..., min_length=2, max_length=150)
    plan_tier: TenantPlanTierEnum = TenantPlanTierEnum.ENTERPRISE
    retention_days: int = Field(default=90, ge=7, le=3650)
    configuration: Dict[str, Any] = Field(default_factory=dict)


class AdminTenantUpdateRequest(BaseModel):
    name: Optional[str] = None
    status: Optional[TenantStatusEnum] = None
    plan_tier: Optional[TenantPlanTierEnum] = None
    retention_days: Optional[int] = Field(None, ge=7, le=3650)
    configuration: Optional[Dict[str, Any]] = None
    reason: Optional[str] = None


class AdminTenantResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    status: TenantStatusEnum
    plan_tier: TenantPlanTierEnum
    retention_days: int
    configuration: Dict[str, Any] = Field(default_factory=dict)
    users_count: int = 0
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Security Policy Schemas
# ---------------------------------------------------------------------------

class AdminSecurityPolicyCreateRequest(BaseModel):
    policy_type: PolicyTypeEnum
    name: str = Field(..., min_length=3, max_length=200)
    description: Optional[str] = None
    rules: Dict[str, Any] = Field(..., description="Structured non-executable policy rule parameters")
    tenant_id: Optional[str] = None


class AdminSecurityPolicyUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    rules: Optional[Dict[str, Any]] = None
    status: Optional[PolicyStatusEnum] = None
    reason: Optional[str] = None


class PolicyImpactPreviewResponse(BaseModel):
    policy_id: str
    policy_name: str
    policy_type: PolicyTypeEnum
    proposed_status: PolicyStatusEnum
    affected_users_count: int
    affected_roles: List[str]
    affected_integrations: List[str]
    warnings: List[str]
    is_safe_to_apply: bool
    summary: str


class AdminSecurityPolicyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    policy_type: PolicyTypeEnum
    name: str
    description: Optional[str] = None
    status: PolicyStatusEnum
    version: int
    rules: Dict[str, Any]
    created_by: str
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# System Settings Schemas
# ---------------------------------------------------------------------------

class AdminSystemSettingUpdateRequest(BaseModel):
    value: Any
    scope: SettingScopeEnum = SettingScopeEnum.GLOBAL
    tenant_id: Optional[str] = None
    expected_version: Optional[int] = None


class AdminSystemSettingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    key: str
    value: Any
    category: SettingCategoryEnum
    scope: SettingScopeEnum
    is_secret: bool
    version: int
    updated_by: str
    updated_at: datetime
    default_value: Optional[Any] = None
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Integration Schemas
# ---------------------------------------------------------------------------

class AdminIntegrationUpdateRequest(BaseModel):
    enabled: Optional[bool] = None
    endpoint_url: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None
    api_key_replacement: Optional[str] = Field(None, description="Protected write-only replacement secret")


class AdminIntegrationTestResponse(BaseModel):
    provider_name: str
    success: bool
    health_status: IntegrationHealthStatusEnum
    latency_ms: int
    message: str
    tested_at: datetime


class AdminIntegrationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    provider_name: str
    display_name: str
    category: IntegrationCategoryEnum
    enabled: bool
    health_status: IntegrationHealthStatusEnum
    endpoint_url: Optional[str] = None
    credential_configured: bool
    settings: Dict[str, Any]
    last_health_check_at: Optional[datetime] = None
    last_error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime


# ---------------------------------------------------------------------------
# Feature Control Schemas
# ---------------------------------------------------------------------------

class AdminFeatureControlUpdateRequest(BaseModel):
    enabled: bool
    requires_role: Optional[AdminRoleEnum] = None
    tenant_id: Optional[str] = None


class AdminFeatureControlResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    feature_key: str
    display_name: str
    description: Optional[str] = None
    enabled: bool
    scope: FeatureScopeEnum
    requires_role: str
    updated_by: str
    updated_at: datetime


# ---------------------------------------------------------------------------
# Platform Overview & System Health Schemas
# ---------------------------------------------------------------------------

class PlatformOverviewResponse(BaseModel):
    platform_name: str = "CyberGuard AI Defense Platform"
    version: str = "2.5.0-Enterprise"
    active_tenants_count: int
    total_users_count: int
    active_users_count: int
    total_teams_count: int
    active_policies_count: int
    configured_integrations_count: int
    healthy_integrations_count: int
    system_status: str  # OPERATIONAL, DEGRADED, MAINTENANCE
    active_features_count: int
    pending_audit_events_24h: int


class ComponentHealthItem(BaseModel):
    name: str
    status: str  # HEALTHY, DEGRADED, UNHEALTHY, UNKNOWN
    details: Optional[str] = None
    latency_ms: Optional[int] = None


class SystemHealthResponse(BaseModel):
    overall_status: str  # HEALTHY, DEGRADED, UNHEALTHY
    checked_at: datetime
    components: List[ComponentHealthItem]
    warnings: List[str]
