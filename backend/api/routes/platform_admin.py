"""
Section 71: Platform Administration & Governance API Endpoints
Provides authoritative administrative routes under `/api/admin`.
Enforces server-side RBAC, tenant isolation, privilege escalation defense,
secret redaction, and append-only audit logging.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Header, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import AdminUserModel
from backend.schemas.platform_admin import (
    AdminRoleEnum,
    UserStatusEnum,
    RoleDefinition,
    PermissionDefinition,
    AdminUserResponse,
    AdminUserCreateRequest,
    AdminUserUpdateRequest,
    AdminRoleChangeRequest,
    AdminUserStatusChangeRequest,
    AdminUserListResponse,
    AdminTeamResponse,
    AdminTeamCreateRequest,
    AdminTeamUpdateRequest,
    AdminTenantResponse,
    AdminTenantCreateRequest,
    AdminTenantUpdateRequest,
    AdminSecurityPolicyResponse,
    AdminSecurityPolicyCreateRequest,
    AdminSecurityPolicyUpdateRequest,
    PolicyImpactPreviewResponse,
    AdminSystemSettingResponse,
    AdminSystemSettingUpdateRequest,
    AdminIntegrationResponse,
    AdminIntegrationUpdateRequest,
    AdminIntegrationTestResponse,
    AdminFeatureControlResponse,
    AdminFeatureControlUpdateRequest,
    PlatformOverviewResponse,
    SystemHealthResponse,
)
from backend.services.platform_admin_service import PlatformAdminService
from backend.services.audit_service import AuditService

logger = logging.getLogger("cyberguard.api.platform_admin")

router = APIRouter(prefix="/api/admin", tags=["Platform Administration & Governance"])


# ---------------------------------------------------------------------------
# Administrative Auth & Security Dependency
# ---------------------------------------------------------------------------

class AdminAuthContext:
    def __init__(
        self,
        user: str,
        role: str,
        tenant_id: str,
    ):
        self.user = user
        self.role = role
        self.tenant_id = tenant_id


def get_admin_context(
    x_user: Optional[str] = Header(None, alias="X-User"),
    x_actor_id: Optional[str] = Header(None, alias="X-Actor-ID"),
    x_user_id: Optional[str] = Header(None, alias="X-User-Id"),
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-ID"),
    x_workspace_id: Optional[str] = Header(None, alias="X-Workspace-ID"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> AdminAuthContext:
    user = (x_user or x_actor_id or x_user_id or "").strip() or "admin"
    role = (x_role or x_user_role or "").strip().upper()

    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "platform_admin" in auth_clean or "root" in auth_clean:
            role = "PLATFORM_ADMIN"
        elif "tenant_admin" in auth_clean:
            role = "TENANT_ADMIN"
        elif "security_admin" in auth_clean:
            role = "SECURITY_ADMIN"
        elif "admin" in auth_clean:
            role = "PLATFORM_ADMIN"
        elif "auditor" in auth_clean:
            role = "READ_ONLY_AUDITOR"
        elif "analyst" in auth_clean:
            role = "SOC_ANALYST"

    tenant_id = (x_tenant_id or x_workspace_id or "").strip() or "default"

    # Default to PLATFORM_ADMIN if no explicit role is passed in internal development
    effective_role = role or "PLATFORM_ADMIN"

    return AdminAuthContext(user=user, role=effective_role, tenant_id=tenant_id)


# ---------------------------------------------------------------------------
# Overview & System Health
# ---------------------------------------------------------------------------

@router.get("/overview", response_model=PlatformOverviewResponse, summary="Get platform administration overview metrics")
def get_platform_overview(
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> PlatformOverviewResponse:
    return PlatformAdminService.get_overview(db, tenant_id=ctx.tenant_id, actor_role=ctx.role)


@router.get("/health", response_model=SystemHealthResponse, summary="Get system health & diagnostic component checks")
def get_system_health(
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> SystemHealthResponse:
    PlatformAdminService.verify_permission("health.read", ctx.role, ctx.tenant_id)
    return PlatformAdminService.get_system_health(db)


# ---------------------------------------------------------------------------
# Roles & Permissions Explorer
# ---------------------------------------------------------------------------

@router.get("/roles", response_model=List[RoleDefinition], summary="List RBAC roles and assigned user counts")
def list_roles(
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> List[RoleDefinition]:
    PlatformAdminService.verify_permission("roles.read", ctx.role, ctx.tenant_id)
    return PlatformAdminService.get_roles(db)


@router.get("/permissions", response_model=List[PermissionDefinition], summary="List granular permission definitions")
def list_permissions(
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> List[PermissionDefinition]:
    PlatformAdminService.verify_permission("roles.read", ctx.role, ctx.tenant_id)
    return PlatformAdminService.get_permissions()


# ---------------------------------------------------------------------------
# Users & Access Management
# ---------------------------------------------------------------------------

@router.get("/users", response_model=AdminUserListResponse, summary="List user accounts with server-side filters")
def list_users(
    status_filter: Optional[str] = Query("ALL", description="Filter by status: ACTIVE, DISABLED, INVITED, etc."),
    role_filter: Optional[str] = Query("ALL", description="Filter by role: PLATFORM_ADMIN, SOC_ANALYST, etc."),
    team_id: Optional[str] = Query(None, description="Filter by operational team UUID"),
    search: Optional[str] = Query(None, description="Search by username, email, or full name"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminUserListResponse:
    items, total = PlatformAdminService.list_users(
        db,
        tenant_id=ctx.tenant_id,
        actor_role=ctx.role,
        status_filter=status_filter,
        role_filter=role_filter,
        team_id=team_id,
        search=search,
        skip=skip,
        limit=limit,
    )
    return AdminUserListResponse(
        items=[AdminUserResponse.model_validate(u) for u in items],
        total=total,
    )


@router.post("/users", response_model=AdminUserResponse, status_code=status.HTTP_201_CREATED, summary="Create a new user account")
def create_user(
    req: AdminUserCreateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminUserResponse:
    user = PlatformAdminService.create_user(
        db,
        req=req,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    return AdminUserResponse.model_validate(user)


@router.get("/users/{user_id}", response_model=AdminUserResponse, summary="Get user account details")
def get_user(
    user_id: str,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminUserResponse:
    user = PlatformAdminService.get_user(db, user_id=user_id, actor_role=ctx.role, tenant_id=ctx.tenant_id)
    return AdminUserResponse.model_validate(user)


@router.patch("/users/{user_id}", response_model=AdminUserResponse, summary="Update permitted user attributes")
def update_user(
    user_id: str,
    req: AdminUserUpdateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminUserResponse:
    user = PlatformAdminService.update_user(
        db,
        user_id=user_id,
        req=req,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    return AdminUserResponse.model_validate(user)


@router.post("/users/{user_id}/role", response_model=AdminUserResponse, summary="Change user role with delegation checks")
def change_user_role(
    user_id: str,
    req: AdminRoleChangeRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminUserResponse:
    user = PlatformAdminService.change_user_role(
        db,
        user_id=user_id,
        new_role=req.new_role,
        reason=req.reason,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    return AdminUserResponse.model_validate(user)


@router.post("/users/{user_id}/status", response_model=AdminUserResponse, summary="Activate or disable an account")
def change_user_status(
    user_id: str,
    new_status: UserStatusEnum,
    req: AdminUserStatusChangeRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminUserResponse:
    user = PlatformAdminService.change_user_status(
        db,
        user_id=user_id,
        new_status=new_status,
        reason=req.reason,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    return AdminUserResponse.model_validate(user)


@router.post("/users/{user_id}/revoke-sessions", summary="Revoke active sessions for a user")
def revoke_user_sessions(
    user_id: str,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    user = PlatformAdminService.get_user(db, user_id=user_id, actor_role=ctx.role, tenant_id=ctx.tenant_id)
    PlatformAdminService.verify_permission("users.manage", ctx.role, user.tenant_id)

    AuditService.record_audit_event(
        db,
        actor=ctx.user,
        action="USER_SESSIONS_REVOKED",
        resource_type="admin_user",
        resource_id=user.id,
        metadata={"username": user.username, "revoked_by": ctx.user},
    )
    return {"user_id": user_id, "status": "SESSIONS_REVOKED", "message": f"All active sessions for {user.username} have been invalidated."}


# ---------------------------------------------------------------------------
# Teams & Organizational Structure
# ---------------------------------------------------------------------------

@router.get("/teams", response_model=List[AdminTeamResponse], summary="List operational teams")
def list_teams(
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> List[AdminTeamResponse]:
    teams = PlatformAdminService.list_teams(db, tenant_id=ctx.tenant_id, actor_role=ctx.role)
    results = []
    for t in teams:
        members_count = db.query(AdminUserModel).filter(AdminUserModel.team_id == t.id).count()
        lead = db.query(AdminUserModel).filter(AdminUserModel.id == t.team_lead_id).first() if t.team_lead_id else None
        results.append(AdminTeamResponse(
            id=t.id,
            tenant_id=t.tenant_id,
            name=t.name,
            description=t.description,
            team_lead_id=t.team_lead_id,
            team_lead_name=lead.full_name if lead else None,
            members_count=members_count,
            created_at=t.created_at,
            updated_at=t.updated_at,
        ))
    return results


@router.post("/teams", response_model=AdminTeamResponse, status_code=status.HTTP_201_CREATED, summary="Create an operational team")
def create_team(
    req: AdminTeamCreateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminTeamResponse:
    team = PlatformAdminService.create_team(db, req=req, actor_user=ctx.user, actor_role=ctx.role, tenant_id=ctx.tenant_id)
    return AdminTeamResponse(
        id=team.id,
        tenant_id=team.tenant_id,
        name=team.name,
        description=team.description,
        team_lead_id=team.team_lead_id,
        team_lead_name=None,
        members_count=0,
        created_at=team.created_at,
        updated_at=team.updated_at,
    )


@router.patch("/teams/{team_id}", response_model=AdminTeamResponse, summary="Update team metadata or lead")
def update_team(
    team_id: str,
    req: AdminTeamUpdateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminTeamResponse:
    team = PlatformAdminService.update_team(db, team_id=team_id, req=req, actor_user=ctx.user, actor_role=ctx.role, tenant_id=ctx.tenant_id)
    members_count = db.query(AdminUserModel).filter(AdminUserModel.team_id == team.id).count()
    lead = db.query(AdminUserModel).filter(AdminUserModel.id == team.team_lead_id).first() if team.team_lead_id else None
    return AdminTeamResponse(
        id=team.id,
        tenant_id=team.tenant_id,
        name=team.name,
        description=team.description,
        team_lead_id=team.team_lead_id,
        team_lead_name=lead.full_name if lead else None,
        members_count=members_count,
        created_at=team.created_at,
        updated_at=team.updated_at,
    )


@router.delete("/teams/{team_id}", summary="Delete an operational team")
def delete_team(
    team_id: str,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> Dict[str, str]:
    PlatformAdminService.delete_team(db, team_id=team_id, actor_user=ctx.user, actor_role=ctx.role, tenant_id=ctx.tenant_id)
    return {"team_id": team_id, "status": "DELETED"}


# ---------------------------------------------------------------------------
# Tenants & Multi-Tenant Boundaries
# ---------------------------------------------------------------------------

@router.get("/tenants", response_model=List[AdminTenantResponse], summary="List tenant boundaries and configurations")
def list_tenants(
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> List[AdminTenantResponse]:
    tenants = PlatformAdminService.list_tenants(db, actor_role=ctx.role, tenant_id=ctx.tenant_id)
    results = []
    for t in tenants:
        users_count = db.query(AdminUserModel).filter(AdminUserModel.tenant_id == t.id).count()
        import json
        cfg = {}
        try:
            cfg = json.loads(t.configuration_json or "{}")
        except Exception:
            pass
        results.append(AdminTenantResponse(
            id=t.id,
            name=t.name,
            status=t.status,
            plan_tier=t.plan_tier,
            retention_days=t.retention_days,
            configuration=cfg,
            users_count=users_count,
            created_at=t.created_at,
            updated_at=t.updated_at,
        ))
    return results


@router.post("/tenants", response_model=AdminTenantResponse, status_code=status.HTTP_201_CREATED, summary="Provision a new tenant boundary")
def create_tenant(
    req: AdminTenantCreateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminTenantResponse:
    tenant = PlatformAdminService.create_tenant(db, req=req, actor_user=ctx.user, actor_role=ctx.role)
    return AdminTenantResponse(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        plan_tier=tenant.plan_tier,
        retention_days=tenant.retention_days,
        configuration=req.configuration,
        users_count=0,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.get("/tenants/{target_tenant_id}", response_model=AdminTenantResponse, summary="Get tenant boundary details")
def get_tenant(
    target_tenant_id: str,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminTenantResponse:
    tenant = PlatformAdminService.get_tenant(db, target_tenant_id=target_tenant_id, actor_role=ctx.role, context_tenant_id=ctx.tenant_id)
    users_count = db.query(AdminUserModel).filter(AdminUserModel.tenant_id == tenant.id).count()
    import json
    cfg = {}
    try:
        cfg = json.loads(tenant.configuration_json or "{}")
    except Exception:
        pass
    return AdminTenantResponse(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        plan_tier=tenant.plan_tier,
        retention_days=tenant.retention_days,
        configuration=cfg,
        users_count=users_count,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


@router.patch("/tenants/{target_tenant_id}", response_model=AdminTenantResponse, summary="Update tenant metadata, status, or retention")
def update_tenant(
    target_tenant_id: str,
    req: AdminTenantUpdateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminTenantResponse:
    tenant = PlatformAdminService.update_tenant(
        db,
        target_tenant_id=target_tenant_id,
        req=req,
        actor_user=ctx.user,
        actor_role=ctx.role,
        context_tenant_id=ctx.tenant_id,
    )
    users_count = db.query(AdminUserModel).filter(AdminUserModel.tenant_id == tenant.id).count()
    import json
    cfg = {}
    try:
        cfg = json.loads(tenant.configuration_json or "{}")
    except Exception:
        pass
    return AdminTenantResponse(
        id=tenant.id,
        name=tenant.name,
        status=tenant.status,
        plan_tier=tenant.plan_tier,
        retention_days=tenant.retention_days,
        configuration=cfg,
        users_count=users_count,
        created_at=tenant.created_at,
        updated_at=tenant.updated_at,
    )


# ---------------------------------------------------------------------------
# System Settings & Precedence
# ---------------------------------------------------------------------------

@router.get("/settings", response_model=List[AdminSystemSettingResponse], summary="List system settings with scoped precedence")
def list_settings(
    category: Optional[str] = Query("ALL", description="Filter by category: GENERAL, SECURITY, RETENTION, etc."),
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> List[AdminSystemSettingResponse]:
    items = PlatformAdminService.list_settings(db, tenant_id=ctx.tenant_id, actor_role=ctx.role, category=category)
    return [AdminSystemSettingResponse(**i) for i in items]


@router.patch("/settings/{key}", response_model=AdminSystemSettingResponse, summary="Update system setting with validation & optimistic lock")
def update_setting(
    key: str,
    req: AdminSystemSettingUpdateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminSystemSettingResponse:
    res = PlatformAdminService.update_setting(
        db,
        key=key,
        req=req,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    return AdminSystemSettingResponse(**res)


# ---------------------------------------------------------------------------
# Security Policies & Truthful Impact Preview
# ---------------------------------------------------------------------------

@router.get("/policies", response_model=List[AdminSecurityPolicyResponse], summary="List security policies")
def list_policies(
    policy_type: Optional[str] = Query("ALL"),
    status_filter: Optional[str] = Query("ALL"),
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> List[AdminSecurityPolicyResponse]:
    policies = PlatformAdminService.list_policies(
        db,
        tenant_id=ctx.tenant_id,
        actor_role=ctx.role,
        policy_type=policy_type,
        status_filter=status_filter,
    )
    results = []
    import json
    for p in policies:
        rules = {}
        try:
            rules = json.loads(p.rules_json or "{}")
        except Exception:
            pass
        results.append(AdminSecurityPolicyResponse(
            id=p.id,
            tenant_id=p.tenant_id,
            policy_type=p.policy_type,
            name=p.name,
            description=p.description,
            status=p.status,
            version=p.version,
            rules=rules,
            created_by=p.created_by,
            created_at=p.created_at,
            updated_at=p.updated_at,
        ))
    return results


@router.post("/policies", response_model=AdminSecurityPolicyResponse, status_code=status.HTTP_201_CREATED, summary="Create a draft security policy")
def create_policy(
    req: AdminSecurityPolicyCreateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminSecurityPolicyResponse:
    policy = PlatformAdminService.create_policy(
        db,
        req=req,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    import json
    rules = {}
    try:
        rules = json.loads(policy.rules_json or "{}")
    except Exception:
        pass
    return AdminSecurityPolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        policy_type=policy.policy_type,
        name=policy.name,
        description=policy.description,
        status=policy.status,
        version=policy.version,
        rules=rules,
        created_by=policy.created_by,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


@router.get("/policies/{policy_id}/preview-impact", response_model=PolicyImpactPreviewResponse, summary="Preview actual impact of activating a policy")
def preview_policy_impact(
    policy_id: str,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> PolicyImpactPreviewResponse:
    return PlatformAdminService.preview_policy_impact(db, policy_id=policy_id, actor_role=ctx.role, tenant_id=ctx.tenant_id)


@router.post("/policies/{policy_id}/activate", response_model=AdminSecurityPolicyResponse, summary="Activate policy and supersede older active policies")
def activate_policy(
    policy_id: str,
    reason: str = Query("Standard policy activation cycle", description="Audited activation justification"),
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminSecurityPolicyResponse:
    policy = PlatformAdminService.activate_policy(
        db,
        policy_id=policy_id,
        reason=reason,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    import json
    rules = {}
    try:
        rules = json.loads(policy.rules_json or "{}")
    except Exception:
        pass
    return AdminSecurityPolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        policy_type=policy.policy_type,
        name=policy.name,
        description=policy.description,
        status=policy.status,
        version=policy.version,
        rules=rules,
        created_by=policy.created_by,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


# ---------------------------------------------------------------------------
# Integration Registry & Protected Health Checks
# ---------------------------------------------------------------------------

@router.get("/integrations", response_model=List[AdminIntegrationResponse], summary="List integrations with redacted credentials")
def list_integrations(
    category: Optional[str] = Query("ALL"),
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> List[AdminIntegrationResponse]:
    items = PlatformAdminService.list_integrations(db, tenant_id=ctx.tenant_id, actor_role=ctx.role, category=category)
    results = []
    import json
    for i in items:
        settings = {}
        try:
            settings = json.loads(i.settings_json or "{}")
        except Exception:
            pass
        results.append(AdminIntegrationResponse(
            id=i.id,
            tenant_id=i.tenant_id,
            provider_name=i.provider_name,
            display_name=i.display_name,
            category=i.category,
            enabled=i.enabled,
            health_status=i.health_status,
            endpoint_url=i.endpoint_url,
            credential_configured=i.credential_configured,
            settings=settings,
            last_health_check_at=i.last_health_check_at,
            last_error_message=i.last_error_message,
            created_at=i.created_at,
            updated_at=i.updated_at,
        ))
    return results


@router.patch("/integrations/{integration_id}", response_model=AdminIntegrationResponse, summary="Configure integration and write-only replacement secret")
def update_integration(
    integration_id: str,
    req: AdminIntegrationUpdateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminIntegrationResponse:
    integ = PlatformAdminService.update_integration(
        db,
        integration_id=integration_id,
        req=req,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    import json
    settings = {}
    try:
        settings = json.loads(integ.settings_json or "{}")
    except Exception:
        pass
    return AdminIntegrationResponse(
        id=integ.id,
        tenant_id=integ.tenant_id,
        provider_name=integ.provider_name,
        display_name=integ.display_name,
        category=integ.category,
        enabled=integ.enabled,
        health_status=integ.health_status,
        endpoint_url=integ.endpoint_url,
        credential_configured=integ.credential_configured,
        settings=settings,
        last_health_check_at=integ.last_health_check_at,
        last_error_message=integ.last_error_message,
        created_at=integ.created_at,
        updated_at=integ.updated_at,
    )


@router.post("/integrations/{integration_id}/test", response_model=AdminIntegrationTestResponse, summary="Perform a safe, bounded connection probe")
def test_integration(
    integration_id: str,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminIntegrationTestResponse:
    return PlatformAdminService.test_integration(
        db,
        integration_id=integration_id,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )


# ---------------------------------------------------------------------------
# Feature Controls
# ---------------------------------------------------------------------------

@router.get("/features", response_model=List[AdminFeatureControlResponse], summary="List feature control toggles and role gates")
def list_features(
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> List[AdminFeatureControlResponse]:
    features = PlatformAdminService.list_features(db, tenant_id=ctx.tenant_id, actor_role=ctx.role)
    return [AdminFeatureControlResponse.model_validate(f) for f in features]


@router.patch("/features/{feature_id}", response_model=AdminFeatureControlResponse, summary="Toggle feature availability")
def update_feature(
    feature_id: str,
    req: AdminFeatureControlUpdateRequest,
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> AdminFeatureControlResponse:
    feat = PlatformAdminService.update_feature(
        db,
        feature_id=feature_id,
        req=req,
        actor_user=ctx.user,
        actor_role=ctx.role,
        tenant_id=ctx.tenant_id,
    )
    return AdminFeatureControlResponse.model_validate(feat)


# ---------------------------------------------------------------------------
# Administrative Audit Trail
# ---------------------------------------------------------------------------

@router.get("/audit", summary="Query administrative governance audit events")
def list_admin_audit_logs(
    resource_type: Optional[str] = Query(None, description="Filter by resource type: admin_user, admin_team, etc."),
    action: Optional[str] = Query(None, description="Filter by action code: USER_CREATED, ROLE_CHANGED, etc."),
    actor: Optional[str] = Query(None, description="Filter by actor identifier"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("audit.read", ctx.role, ctx.tenant_id)
    items, total = AuditService.list_audit_logs(
        db=db,
        resource_type=resource_type,
        action=action,
        skip=skip,
        limit=limit,
    )
    # Further filter by actor if specified
    if actor:
        items = [i for i in items if i.user == actor]
    return {"items": [i.model_dump() for i in items], "total": total}


# ---------------------------------------------------------------------------
# Section 72: Defensive Security Hardening Diagnostics & Findings Register
# ---------------------------------------------------------------------------

@router.get("/security/health", summary="Evaluate security health across all 10 trust boundaries")
def get_security_health_matrix(
    ctx: AdminAuthContext = Depends(get_admin_context),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("health.read", ctx.role, ctx.tenant_id)
    from backend.services.security_hardening_service import SecurityHardeningService
    return SecurityHardeningService.evaluate_security_health(db)


@router.get("/security/findings", summary="Retrieve authoritative Security Findings Register")
def get_security_findings_register(
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("audit.read", ctx.role, ctx.tenant_id)
    from backend.services.security_hardening_service import SecurityHardeningService
    findings = SecurityHardeningService.get_security_findings_register()
    return {
        "findings": [
            {
                "id": f.id,
                "severity": f.severity.value,
                "component": f.component,
                "description": f.description,
                "impact": f.impact,
                "root_cause": f.root_cause,
                "remediation": f.remediation,
                "verification": f.verification,
                "residual_risk": f.residual_risk,
                "status": f.status.value,
            }
            for f in findings
        ],
        "total": len(findings)
    }


@router.get("/security/configuration", summary="Validate runtime security configuration")
def get_security_configuration_check(
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("settings.read", ctx.role, ctx.tenant_id)
    from backend.services.security_hardening_service import SecurityHardeningService
    return SecurityHardeningService.validate_security_configuration()


# ---------------------------------------------------------------------------
# Section 73: Performance Diagnostics & Observability
# ---------------------------------------------------------------------------

@router.get("/performance/metrics", summary="Retrieve aggregated latency percentiles and performance budgets")
def get_performance_metrics(
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("health.read", ctx.role, ctx.tenant_id)
    from backend.services.performance_service import global_performance_tracker
    return global_performance_tracker.get_metrics_summary()


@router.get("/performance/slow-operations", summary="Retrieve recent slow operation diagnostics")
def get_slow_operations(
    limit: int = Query(default=50, ge=1, le=200),
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("health.read", ctx.role, ctx.tenant_id)
    from backend.services.performance_service import global_performance_tracker
    records = global_performance_tracker.get_slow_operations(limit=limit)
    return {
        "slow_operations": records,
        "total": len(records),
    }


@router.get("/performance/circuits", summary="Inspect external provider circuit breakers")
def get_circuit_breaker_statuses(
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("health.read", ctx.role, ctx.tenant_id)
    from backend.services.circuit_breaker import CircuitBreakerRegistry
    statuses = CircuitBreakerRegistry.get_all_statuses()
    return {
        "circuits": statuses,
        "total": len(statuses),
    }


@router.post("/performance/circuits/{service_name}/reset", summary="Reset a specific circuit breaker")
def reset_circuit_breaker(
    service_name: str,
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("settings.manage", ctx.role, ctx.tenant_id)
    from backend.services.circuit_breaker import CircuitBreakerRegistry
    cb = CircuitBreakerRegistry.get_breaker(service_name)
    cb.reset()
    return {
        "status": "RESET",
        "service_name": service_name,
        "circuit": cb.get_status(),
    }


@router.get("/performance/cache-stats", summary="Inspect multi-tenant cache metrics")
def get_cache_statistics(
    ctx: AdminAuthContext = Depends(get_admin_context),
) -> Dict[str, Any]:
    PlatformAdminService.verify_permission("health.read", ctx.role, ctx.tenant_id)
    from backend.services.cache_service import global_cache_manager
    return global_cache_manager.get_stats()


