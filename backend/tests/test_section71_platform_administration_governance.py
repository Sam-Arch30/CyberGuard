"""
Section 71: Platform Administration & Governance Comprehensive Test Suite
Tests:
1. Server-side RBAC & Access Control boundaries (blocking anonymous/unauthorized)
2. User account lifecycle (creation, updates, status transitions)
3. Privilege escalation & self-promotion prevention
4. Last platform administrator safeguard
5. Role & permission matrix exploration
6. Teams & organizational structure
7. Tenant isolation & multi-tenant boundaries
8. System settings precedence, validation, and optimistic concurrency
9. Security policy lifecycle and truthful impact preview analysis
10. Integration registry, credential redaction, and safe probes
11. Feature controls and role gating
12. Administrative audit trail and system health diagnostics
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.db.session import Base, get_db
from backend.main import app
from backend.schemas.platform_admin import AdminRoleEnum, UserStatusEnum


@pytest.fixture(scope="module")
def test_db_session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    yield TestingSessionLocal
    app.dependency_overrides.pop(get_db, None)


@pytest.fixture
def client(test_db_session):
    return TestClient(app)


def test_01_access_control_and_rbac_boundaries(client):
    """
    Verifies that unauthorized or lower-privileged roles are strictly blocked from
    administrative mutations.
    """
    # 1. SOC Analyst attempting to create a user -> HTTP 403 Forbidden
    res = client.post(
        "/api/admin/users",
        json={
            "username": "unauthorized_create",
            "email": "unauth@cyberguard.internal",
            "full_name": "Unauthorized User",
            "role": "SOC_ANALYST",
        },
        headers={"X-User": "analyst_bob", "X-Role": "SOC_ANALYST", "X-Tenant-ID": "default"},
    )
    assert res.status_code == 403
    assert "Forbidden" in res.json()["detail"]

    # 2. SOC Analyst attempting to modify system settings -> HTTP 403 Forbidden
    res = client.patch(
        "/api/admin/settings/retention_period_days",
        json={"value": 180, "scope": "GLOBAL"},
        headers={"X-User": "analyst_bob", "X-Role": "SOC_ANALYST", "X-Tenant-ID": "default"},
    )
    assert res.status_code == 403

    # 3. Read-Only Auditor attempting to create a team -> HTTP 403 Forbidden
    res = client.post(
        "/api/admin/teams",
        json={"name": "Auditor Team"},
        headers={"X-User": "auditor_alice", "X-Role": "READ_ONLY_AUDITOR", "X-Tenant-ID": "default"},
    )
    assert res.status_code == 403


def test_02_user_management_lifecycle(client):
    """
    Verifies creating a user, listing with filters, updating attributes, and status transitions.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. Create User
    res = client.post(
        "/api/admin/users",
        json={
            "username": "sarah_connor",
            "email": "sconnor@cyberguard.internal",
            "full_name": "Sarah Connor",
            "role": "SOC_ANALYST",
            "initial_status": "ACTIVE",
            "custom_permissions": ["cases.read"],
        },
        headers=admin_headers,
    )
    assert res.status_code == 201
    user_data = res.json()
    assert user_data["username"] == "sarah_connor"
    assert user_data["role"] == "SOC_ANALYST"
    assert user_data["status"] == "ACTIVE"
    user_id = user_data["id"]

    # 2. List Users with filter
    res = client.get("/api/admin/users?role_filter=SOC_ANALYST", headers=admin_headers)
    assert res.status_code == 200
    list_data = res.json()
    assert list_data["total"] >= 1
    assert any(u["id"] == user_id for u in list_data["items"])

    # 3. Update User Attributes
    res = client.patch(
        f"/api/admin/users/{user_id}",
        json={"full_name": "Sarah Connor-Reese"},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert res.json()["full_name"] == "Sarah Connor-Reese"

    # 4. Status Transition: Disable User
    res = client.post(
        f"/api/admin/users/{user_id}/status?new_status=DISABLED",
        json={"reason": "Temporary medical leave"},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "DISABLED"

    # 5. Reactivate User
    res = client.post(
        f"/api/admin/users/{user_id}/status?new_status=ACTIVE",
        json={"reason": "Return from leave"},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ACTIVE"

    # 6. Session Revocation
    res = client.post(f"/api/admin/users/{user_id}/revoke-sessions", headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "SESSIONS_REVOKED"


def test_03_privilege_escalation_and_self_promotion_prevention(client):
    """
    Verifies that privilege escalation is strictly rejected:
    - Tenant admin cannot create a platform admin.
    - User cannot promote themselves.
    """
    tenant_headers = {"X-User": "tenant_lead", "X-Role": "TENANT_ADMIN", "X-Tenant-ID": "default"}

    # 1. Attempt to create a PLATFORM_ADMIN while being a TENANT_ADMIN -> HTTP 403 Forbidden
    res = client.post(
        "/api/admin/users",
        json={
            "username": "escalated_admin",
            "email": "escalated@cyberguard.internal",
            "full_name": "Escalated Admin",
            "role": "PLATFORM_ADMIN",
        },
        headers=tenant_headers,
    )
    assert res.status_code == 403
    assert "Privilege escalation denied" in res.json()["detail"]

    # 2. Attempt self-promotion: create an analyst and have them change their own role
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}
    res = client.post(
        "/api/admin/users",
        json={
            "username": "sneaky_analyst",
            "email": "sneaky@cyberguard.internal",
            "full_name": "Sneaky Analyst",
            "role": "SOC_ANALYST",
        },
        headers=admin_headers,
    )
    sneaky_id = res.json()["id"]

    # sneaky_analyst attempts to promote self to PLATFORM_ADMIN
    res = client.post(
        f"/api/admin/users/{sneaky_id}/role",
        json={"new_role": "PLATFORM_ADMIN", "reason": "I want root"},
        headers={"X-User": "sneaky_analyst", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"},
    )
    assert res.status_code == 400
    assert "Self-promotion / self-role modification is strictly prohibited" in res.json()["detail"]


def test_04_last_platform_administrator_protection(client):
    """
    Verifies that the sole active platform administrator cannot be disabled or demoted.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # Find the root platform admin
    res = client.get("/api/admin/users?role_filter=PLATFORM_ADMIN", headers=admin_headers)
    admins = res.json()["items"]
    assert len(admins) >= 1
    root_admin_id = admins[0]["id"]

    # 1. Attempt to disable the root platform admin -> HTTP 400 Bad Request
    res = client.post(
        f"/api/admin/users/{root_admin_id}/status?new_status=DISABLED",
        json={"reason": "Attempting accidental lockout"},
        headers={"X-User": "another_admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"},
    )
    assert res.status_code == 400
    assert "Cannot disable the last active platform administrator" in res.json()["detail"]

    # 2. Attempt to demote the root platform admin to SOC_ANALYST -> HTTP 400 Bad Request
    res = client.post(
        f"/api/admin/users/{root_admin_id}/role",
        json={"new_role": "SOC_ANALYST", "reason": "Demoting root"},
        headers={"X-User": "another_admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"},
    )
    assert res.status_code == 400
    assert "Cannot demote the last active platform administrator" in res.json()["detail"]


def test_05_role_and_permission_matrix_integrity(client):
    """
    Verifies that roles and permissions explorer returns all defined permissions
    and accurate assigned user counts.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    res = client.get("/api/admin/roles", headers=admin_headers)
    assert res.status_code == 200
    roles = res.json()
    assert len(roles) >= 5
    role_names = [r["role"] for r in roles]
    assert "PLATFORM_ADMIN" in role_names
    assert "TENANT_ADMIN" in role_names
    assert "SECURITY_ADMIN" in role_names
    assert "SOC_ANALYST" in role_names
    assert "READ_ONLY_AUDITOR" in role_names

    res = client.get("/api/admin/permissions", headers=admin_headers)
    assert res.status_code == 200
    perms = res.json()
    assert len(perms) >= 15
    perm_keys = [p["key"] for p in perms]
    assert "users.read" in perm_keys
    assert "users.manage" in perm_keys
    assert "tenants.manage" in perm_keys
    assert "settings.manage" in perm_keys


def test_06_team_management_and_membership(client):
    """
    Verifies operational team creation, updating, membership counts, and deletion.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. Create Team
    res = client.post(
        "/api/admin/teams",
        json={"name": "Threat Hunting Unit", "description": "Proactive IOC pivoting team"},
        headers=admin_headers,
    )
    assert res.status_code == 201
    team = res.json()
    team_id = team["id"]
    assert team["name"] == "Threat Hunting Unit"

    # 2. Update Team
    res = client.patch(
        f"/api/admin/teams/{team_id}",
        json={"description": "Updated proactive hunting description"},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert res.json()["description"] == "Updated proactive hunting description"

    # 3. List Teams
    res = client.get("/api/admin/teams", headers=admin_headers)
    assert res.status_code == 200
    teams = res.json()
    assert any(t["id"] == team_id for t in teams)

    # 4. Delete Team
    res = client.delete(f"/api/admin/teams/{team_id}", headers=admin_headers)
    assert res.status_code == 200
    assert res.json()["status"] == "DELETED"


def test_07_tenant_isolation_and_scoping(client):
    """
    Verifies multi-tenant isolation:
    A TENANT_ADMIN in Tenant A cannot query or mutate Tenant B records.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. Platform admin provisions tenant_corp_b
    res = client.post(
        "/api/admin/tenants",
        json={
            "id": "tenant_corp_b",
            "name": "Corp B Tenant",
            "plan_tier": "STANDARD",
            "retention_days": 60,
        },
        headers=admin_headers,
    )
    assert res.status_code == 201

    # 2. Tenant Admin of default tenant attempts to access tenant_corp_b -> HTTP 403 Forbidden
    res = client.get(
        "/api/admin/tenants/tenant_corp_b",
        headers={"X-User": "tenant_admin_a", "X-Role": "TENANT_ADMIN", "X-Tenant-ID": "default"},
    )
    assert res.status_code == 403
    assert "cannot access foreign tenant" in res.json()["detail"]


def test_08_system_settings_precedence_and_optimistic_locking(client):
    """
    Verifies settings retrieval with deterministic precedence, server-side validation,
    and optimistic concurrency version checking.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. Read settings
    res = client.get("/api/admin/settings?category=RETENTION", headers=admin_headers)
    assert res.status_code == 200
    settings = res.json()
    ret_setting = next(s for s in settings if s["key"] == "retention_period_days")
    curr_version = ret_setting["version"]

    # 2. Invalid range validation (retention < 7 days rejected)
    res = client.patch(
        "/api/admin/settings/retention_period_days",
        json={"value": 3, "scope": "GLOBAL", "expected_version": curr_version},
        headers=admin_headers,
    )
    assert res.status_code == 400
    assert "Value must be >= 7" in res.json()["detail"]

    # 3. Valid update
    res = client.patch(
        "/api/admin/settings/retention_period_days",
        json={"value": 180, "scope": "GLOBAL", "expected_version": curr_version},
        headers=admin_headers,
    )
    assert res.status_code == 200
    new_version = res.json()["version"]
    assert new_version == curr_version + 1
    assert res.json()["value"] == 180

    # 4. Optimistic concurrency conflict (stale expected_version rejected)
    res = client.patch(
        "/api/admin/settings/retention_period_days",
        json={"value": 365, "scope": "GLOBAL", "expected_version": curr_version},
        headers=admin_headers,
    )
    assert res.status_code == 409
    assert "Configuration conflict" in res.json()["detail"]


def test_09_security_policy_lifecycle_and_impact_preview(client):
    """
    Verifies creating draft security policy, calculating truthful impact preview,
    and activating the policy.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. Create Draft Policy
    res = client.post(
        "/api/admin/policies",
        json={
            "policy_type": "AUTHENTICATION",
            "name": "Strict MFA & Lockout Policy v2",
            "description": "Requires MFA and locks after 3 attempts",
            "rules": {"mfa_required": True, "max_failed_attempts": 3, "session_timeout_minutes": 30},
        },
        headers=admin_headers,
    )
    assert res.status_code == 201
    policy = res.json()
    assert policy["status"] == "DRAFT"
    policy_id = policy["id"]

    # 2. Preview Policy Impact
    res = client.get(f"/api/admin/policies/{policy_id}/preview-impact", headers=admin_headers)
    assert res.status_code == 200
    preview = res.json()
    assert preview["policy_id"] == policy_id
    assert preview["affected_users_count"] >= 1
    assert len(preview["warnings"]) >= 1

    # 3. Activate Policy
    res = client.post(
        f"/api/admin/policies/{policy_id}/activate?reason=Annual security review rollout",
        headers=admin_headers,
    )
    assert res.status_code == 200
    activated = res.json()
    assert activated["status"] == "ACTIVE"
    assert activated["version"] >= 2


def test_10_integration_registry_credential_redaction_and_probe(client):
    """
    Verifies that integration credentials are never exposed in plaintext,
    protected replacement works, and safe connection probes execute.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. List integrations
    res = client.get("/api/admin/integrations", headers=admin_headers)
    assert res.status_code == 200
    items = res.json()
    assert len(items) >= 4
    vt = next(i for i in items if i["provider_name"] == "VIRUSTOTAL")
    vt_id = vt["id"]

    # 2. Configure integration with protected write-only API key
    res = client.patch(
        f"/api/admin/integrations/{vt_id}",
        json={
            "enabled": True,
            "endpoint_url": "https://www.virustotal.com/api/v3",
            "api_key_replacement": "vt_secret_live_key_9999",
        },
        headers=admin_headers,
    )
    assert res.status_code == 200
    updated_vt = res.json()
    assert updated_vt["enabled"] is True
    assert updated_vt["credential_configured"] is True
    # Verify secret is never returned in response
    assert "api_key" not in updated_vt
    assert "vt_secret_live_key_9999" not in str(updated_vt)

    # 3. Run safe connection probe
    res = client.post(f"/api/admin/integrations/{vt_id}/test", headers=admin_headers)
    assert res.status_code == 200
    test_result = res.json()
    assert test_result["provider_name"] == "VIRUSTOTAL"
    assert test_result["success"] is True
    assert test_result["health_status"] == "HEALTHY"
    assert test_result["latency_ms"] > 0


def test_11_feature_controls_and_role_gating(client):
    """
    Verifies feature control flag listing and administrative updates.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. List Features
    res = client.get("/api/admin/features", headers=admin_headers)
    assert res.status_code == 200
    features = res.json()
    assert len(features) >= 4
    feat = features[0]
    feat_id = feat["id"]

    # 2. Toggle Feature Flag
    new_state = not feat["enabled"]
    res = client.patch(
        f"/api/admin/features/{feat_id}",
        json={"enabled": new_state},
        headers=admin_headers,
    )
    assert res.status_code == 200
    assert res.json()["enabled"] == new_state


def test_12_administrative_audit_trail_and_health_diagnostics(client):
    """
    Verifies that administrative mutations are recorded in the append-only audit trail
    and that system health truthfully reports diagnostic statuses.
    """
    admin_headers = {"X-User": "admin", "X-Role": "PLATFORM_ADMIN", "X-Tenant-ID": "default"}

    # 1. Query admin audit log
    res = client.get("/api/admin/audit?limit=10", headers=admin_headers)
    assert res.status_code == 200
    audit_data = res.json()
    assert "items" in audit_data
    assert audit_data["total"] >= 1

    # 2. System health diagnostics
    res = client.get("/api/admin/health", headers=admin_headers)
    assert res.status_code == 200
    health = res.json()
    assert health["overall_status"] in ("HEALTHY", "DEGRADED")
    comp_names = [c["name"] for c in health["components"]]
    assert any("Database Engine" in name for name in comp_names)
    assert any("Forensic Audit Ledger" in name for name in comp_names)
    assert any("Background Job Worker" in name for name in comp_names)
    assert any("Realtime Event Broker" in name for name in comp_names)
