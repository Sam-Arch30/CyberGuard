"""
Unit and Integration Tests for Section 63: Asset & Identity Inventory.
Validates authoritative normalization, idempotency, deterministic source precedence,
conflict resolution workspace, manual overrides, stale asset reconciliation,
dormant/orphaned identity detection, Knowledge Graph linkage, background jobs,
REST API endpoints, and multi-tenant isolation.
"""

import json
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from backend.db.models import (
    Base,
    AssetModel,
    IdentityModel,
    InventorySourceModel,
    InventoryConflictModel,
    InventoryOverrideModel,
    DeviceModel,
    EndpointAgentModel,
    ProtectedIdentityModel,
    AuditLogModel,
    get_utc_now,
)
from backend.services.inventory_service import InventoryService
from backend.services.background_job_worker import (
    handle_inventory_sync_job,
    handle_inventory_reconciliation_job,
    handle_inventory_stale_check_job,
    JobExecutionContext,
)
from backend.schemas.inventory import (
    AssetCreate,
    AssetUpdate,
    IdentityCreate,
    OwnershipAssignRequest,
    InventorySourceCreate,
    InventorySyncRequest,
)
from backend.main import app


from sqlalchemy.pool import StaticPool


@pytest.fixture
def db_session():
    """In-memory SQLite session with full schema initialized."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def test_client(db_session):
    """TestClient overriding get_db dependency."""
    from backend.db.session import get_db
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# TEST 1: ASSET NORMALIZATION & IDEMPOTENCY
# ---------------------------------------------------------------------------

def test_asset_upsert_normalization_and_idempotency(db_session):
    workspace = "tenant-inv-01"
    payload = AssetCreate(
        asset_type="DOMAIN",
        canonical_name="HTTPS://API.PROD.EXAMPLE.COM:443/V1/ENDPOINT?REF=ABC#ANCHOR",
        display_name="Production API Gateway",
        status="ACTIVE",
        criticality="CRITICAL",
        owner="Cloud Engineering",
        environment="PRODUCTION",
    )

    asset1, created1 = InventoryService.upsert_asset(db_session, workspace, payload, source="CMDB")
    assert created1 is True
    assert asset1.canonical_name == "api.prod.example.com"
    assert asset1.criticality == "CRITICAL"
    assert asset1.ownership_status == "ASSIGNED"

    # Repeated sync should be idempotent and not create duplicate records
    asset2, created2 = InventoryService.upsert_asset(db_session, workspace, payload, source="CMDB")
    assert created2 is False
    assert asset2.id == asset1.id

    total = db_session.query(AssetModel).filter(AssetModel.workspace_id == workspace).count()
    assert total == 1


# ---------------------------------------------------------------------------
# TEST 2: IDENTITY NORMALIZATION & IDEMPOTENCY
# ---------------------------------------------------------------------------

def test_identity_upsert_normalization_and_idempotency(db_session):
    workspace = "tenant-inv-02"
    payload = IdentityCreate(
        identity_type="USER",
        canonical_identifier="  ALICE.SMITH@EXAMPLE.COM  ",
        display_name="Alice Smith",
        department="Security Operations",
        team="Blue Team",
        is_privileged=True,
    )

    ident1, created1 = InventoryService.upsert_identity(db_session, workspace, payload, source="DIRECTORY")
    assert created1 is True
    assert ident1.canonical_identifier == "alice.smith@example.com"
    assert ident1.is_privileged is True
    assert ident1.status == "ACTIVE"

    # Repeated sync must be idempotent
    ident2, created2 = InventoryService.upsert_identity(db_session, workspace, payload, source="DIRECTORY")
    assert created2 is False
    assert ident2.id == ident1.id

    total = db_session.query(IdentityModel).filter(IdentityModel.workspace_id == workspace).count()
    assert total == 1


# ---------------------------------------------------------------------------
# TEST 3: AUTHORITY-BASED CONFLICT DETECTION & RESOLUTION
# ---------------------------------------------------------------------------

def test_authority_based_conflict_resolution(db_session):
    workspace = "tenant-inv-03"

    # 1. Asset first discovered by Endpoint Agent (weight 60)
    p1 = AssetCreate(
        asset_type="ENDPOINT",
        canonical_name="sec-host-99.corp.local",
        display_name="SecHost-99",
        owner="IT Support",
        team="Desktop Support",
    )
    asset, _ = InventoryService.upsert_asset(db_session, workspace, p1, source="ENDPOINT_AGENT")
    assert asset.owner == "IT Support"

    # 2. CMDB (weight 100) reports owner is "Platform Security Team"
    p2 = AssetCreate(
        asset_type="ENDPOINT",
        canonical_name="sec-host-99.corp.local",
        display_name="SecHost-99",
        owner="Platform Security Team",
        team="SecOps",
    )
    asset_updated, _ = InventoryService.upsert_asset(db_session, workspace, p2, source="CMDB")

    # Higher authority CMDB should take precedence
    assert asset_updated.owner == "Platform Security Team"

    # Verify conflict record was created and marked AUTO_RESOLVED with explanation
    conflict = db_session.query(InventoryConflictModel).filter(
        InventoryConflictModel.workspace_id == workspace,
        InventoryConflictModel.target_id == asset.id,
        InventoryConflictModel.field_name == "owner"
    ).first()
    assert conflict is not None
    assert conflict.status == "AUTO_RESOLVED"
    assert conflict.resolved_value == "Platform Security Team"
    assert "CMDB (weight 100) took precedence" in conflict.resolution_reason


# ---------------------------------------------------------------------------
# TEST 4: EQUAL AUTHORITY CONFLICT FLAGS PENDING REVIEW
# ---------------------------------------------------------------------------

def test_equal_authority_conflict_pending_review(db_session):
    workspace = "tenant-inv-04"

    # Source A (Directory weight 80) reports department is Finance
    p1 = IdentityCreate(
        identity_type="USER",
        canonical_identifier="bob@example.com",
        display_name="Bob Jones",
        department="Finance",
    )
    ident, _ = InventoryService.upsert_identity(db_session, workspace, p1, source="DIRECTORY", authority_weight=80)

    # Source B (IdP weight 80) reports department is Accounting
    p2 = IdentityCreate(
        identity_type="USER",
        canonical_identifier="bob@example.com",
        display_name="Bob Jones",
        department="Accounting",
    )
    ident_after, _ = InventoryService.upsert_identity(db_session, workspace, p2, source="IDP", authority_weight=80)

    # Values must not be arbitrarily overwritten on equal weights
    assert ident_after.department == "Finance"

    # Conflict must be flagged PENDING_REVIEW
    conflict = db_session.query(InventoryConflictModel).filter(
        InventoryConflictModel.workspace_id == workspace,
        InventoryConflictModel.target_id == ident.id,
        InventoryConflictModel.field_name == "department"
    ).first()
    assert conflict is not None
    assert conflict.status == "PENDING_REVIEW"
    assert "Equal source authority weights" in conflict.resolution_reason


# ---------------------------------------------------------------------------
# TEST 5: MANUAL CONFLICT RESOLUTION & OVERRIDE
# ---------------------------------------------------------------------------

def test_manual_conflict_resolution_and_override(db_session):
    workspace = "tenant-inv-05"

    p = IdentityCreate(
        identity_type="USER",
        canonical_identifier="carol@example.com",
        display_name="Carol White",
        department="Sales",
    )
    ident, _ = InventoryService.upsert_identity(db_session, workspace, p, source="DIRECTORY", authority_weight=80)

    # Trigger conflict
    p2 = IdentityCreate(
        identity_type="USER",
        canonical_identifier="carol@example.com",
        display_name="Carol White",
        department="Marketing",
    )
    InventoryService.upsert_identity(db_session, workspace, p2, source="IDP", authority_weight=80)

    conflict = db_session.query(InventoryConflictModel).filter(
        InventoryConflictModel.workspace_id == workspace,
        InventoryConflictModel.target_id == ident.id,
    ).first()
    assert conflict.status == "PENDING_REVIEW"

    # Analyst manually resolves conflict to "Revenue Operations"
    resolved = InventoryService.resolve_conflict(
        db_session,
        workspace_id=workspace,
        conflict_id=conflict.id,
        selected_value="Revenue Operations",
        selected_source="MANUAL_OVERRIDE",
        resolution_reason="Confirmed Carol transitioned to RevOps team in Q3",
        actor="Security Lead",
    )

    assert resolved.status == "MANUALLY_RESOLVED"
    assert resolved.resolved_value == "Revenue Operations"

    # Target entity must reflect manual resolution
    db_session.refresh(ident)
    assert ident.department == "Revenue Operations"

    # Verify audit entry was created
    audit = db_session.query(AuditLogModel).filter(
        AuditLogModel.action == "INVENTORY_CONFLICT_RESOLVED",
        AuditLogModel.resource_id == ident.id
    ).first()
    assert audit is not None


# ---------------------------------------------------------------------------
# TEST 6: MANUAL OVERRIDE PRECEDENCE OVER FUTURE AUTOMATED SYNCS
# ---------------------------------------------------------------------------

def test_manual_override_precedence_over_automated_sources(db_session):
    workspace = "tenant-inv-06"

    p = AssetCreate(
        asset_type="SERVER",
        canonical_name="db-prod-01.internal",
        display_name="DB Prod 01",
        owner="Unknown",
    )
    asset, _ = InventoryService.upsert_asset(db_session, workspace, p, source="INTERNAL_DISCOVERY")

    # Analyst explicitly assigns owner
    InventoryService.assign_asset_owner(
        db_session,
        workspace_id=workspace,
        asset_id=asset.id,
        req=OwnershipAssignRequest(owner="Data Platform Lead", team="DataOps", reason="Verified DBA ownership"),
        actor="Lead Architect",
    )
    db_session.refresh(asset)
    assert asset.owner == "Data Platform Lead"

    # Future automated CMDB sync trying to revert owner to "Infrastructure Pool" should be ignored
    p_cmdb = AssetCreate(
        asset_type="SERVER",
        canonical_name="db-prod-01.internal",
        display_name="DB Prod 01",
        owner="Infrastructure Pool",
    )
    InventoryService.upsert_asset(db_session, workspace, p_cmdb, source="CMDB", authority_weight=100)

    db_session.refresh(asset)
    assert asset.owner == "Data Platform Lead"  # Manual override upheld!


# ---------------------------------------------------------------------------
# TEST 7: STALE ASSET RECONCILIATION
# ---------------------------------------------------------------------------

def test_stale_asset_reconciliation(db_session):
    workspace = "tenant-inv-07"

    # Create an asset last observed 45 days ago
    old_time = get_utc_now() - timedelta(days=45)
    asset = AssetModel(
        workspace_id=workspace,
        asset_type="ENDPOINT",
        canonical_name="legacy-workstation-04.corp",
        display_name="Legacy Workstation 04",
        status="ACTIVE",
        criticality="LOW",
        owner="Unassigned",
        first_seen_at=old_time,
        last_seen_at=old_time,
        is_managed=True,
        is_stale=False,
    )
    db_session.add(asset)
    db_session.commit()

    # Run reconciliation
    report = InventoryService.run_reconciliation(db_session, workspace)
    assert report.stale_assets_flagged == 1

    db_session.refresh(asset)
    assert asset.status == "STALE"
    assert asset.is_stale is True
    # STALE does not delete or retire
    assert asset.status != "RETIRED"


# ---------------------------------------------------------------------------
# TEST 8: UNMANAGED ENDPOINT DETECTION
# ---------------------------------------------------------------------------

def test_unmanaged_endpoint_detection(db_session):
    workspace = "tenant-inv-08"

    # Create endpoint asset with no device/agent record
    p = AssetCreate(
        asset_type="ENDPOINT",
        canonical_name="rogue-laptop.local",
        display_name="Rogue Laptop",
        external_id=None,
    )
    asset, _ = InventoryService.upsert_asset(db_session, workspace, p)

    report = InventoryService.run_reconciliation(db_session, workspace)
    assert report.unmanaged_endpoints_flagged >= 1

    db_session.refresh(asset)
    assert asset.is_managed is False


# ---------------------------------------------------------------------------
# TEST 9: DORMANT AND ORPHANED IDENTITY DETECTION
# ---------------------------------------------------------------------------

def test_dormant_and_orphaned_identity_detection(db_session):
    workspace = "tenant-inv-09"

    # 1. Dormant identity (no authentication in 120 days)
    old_auth = get_utc_now() - timedelta(days=120)
    dormant_user = IdentityModel(
        workspace_id=workspace,
        identity_type="USER",
        canonical_identifier="dormant.user@example.com",
        display_name="Dormant User",
        status="ACTIVE",
        first_seen_at=old_auth,
        last_seen_at=old_auth,
        last_authenticated_at=old_auth,
        is_dormant=False,
    )
    db_session.add(dormant_user)

    # 2. Orphaned service account (no department, team, or manager)
    orphaned_svc = IdentityCreate(
        identity_type="SERVICE_ACCOUNT",
        canonical_identifier="svc-batch-worker@internal",
        display_name="Service Batch Worker",
        department=None,
        team=None,
        manager=None,
        is_service_account=True,
    )
    svc_ident, _ = InventoryService.upsert_identity(db_session, workspace, orphaned_svc)

    report = InventoryService.run_reconciliation(db_session, workspace)
    assert report.dormant_identities_flagged >= 1
    assert report.orphaned_accounts_flagged >= 1

    db_session.refresh(dormant_user)
    assert dormant_user.is_dormant is True
    assert dormant_user.status == "DORMANT"

    db_session.refresh(svc_ident)
    assert svc_ident.is_orphaned is True


# ---------------------------------------------------------------------------
# TEST 10: KNOWLEDGE GRAPH LINKAGE
# ---------------------------------------------------------------------------

def test_knowledge_graph_linkage(db_session):
    workspace = "tenant-inv-10"

    p_asset = AssetCreate(
        asset_type="SERVER",
        canonical_name="k8s-master-01.cloud",
        display_name="K8s Master 01",
    )
    asset, _ = InventoryService.upsert_asset(db_session, workspace, p_asset)
    assert asset.canonical_entity_id is not None

    p_ident = IdentityCreate(
        identity_type="USER",
        canonical_identifier="dave.devops@example.com",
        display_name="Dave DevOps",
    )
    ident, _ = InventoryService.upsert_identity(db_session, workspace, p_ident)
    assert ident.canonical_entity_id is not None


# ---------------------------------------------------------------------------
# TEST 11: BACKGROUND JOB HANDLERS
# ---------------------------------------------------------------------------

@pytest.mark.anyio
async def test_background_job_handlers(db_session):
    workspace = "tenant-inv-11"

    # Context mock
    class DummyContext(JobExecutionContext):
        def __init__(self):
            super().__init__(
                job_id="job-inv-test",
                workspace_id=workspace,
                job_type="INVENTORY_SYNC",
                payload={"sync_endpoints": True, "sync_identities": True},
                worker_id="worker_test",
                attempt=1,
                timeout_seconds=60,
            )

        def update_progress(self, db, progress, phase, message=None):
            pass

    ctx = DummyContext()
    sync_res = await handle_inventory_sync_job(ctx, db_session)
    assert sync_res["status"] == "COMPLETED"

    reconcile_res = await handle_inventory_reconciliation_job(ctx, db_session)
    assert "timestamp" in reconcile_res

    stale_res = await handle_inventory_stale_check_job(ctx, db_session)
    assert "timestamp" in stale_res


# ---------------------------------------------------------------------------
# TEST 12: REST API FULL LIFECYCLE
# ---------------------------------------------------------------------------

def test_inventory_api_full_lifecycle(test_client, db_session):
    headers = {"X-Workspace-ID": "api-tenant-12", "X-Role": "admin"}

    # 1. Overview stats
    resp = test_client.get("/api/v1/inventory/overview", headers=headers)
    assert resp.status_code == 200
    assert "total_assets" in resp.json()

    # 2. Create asset
    asset_payload = {
        "asset_type": "API",
        "canonical_name": "api.billing.internal",
        "display_name": "Billing API Gateway",
        "status": "ACTIVE",
        "criticality": "HIGH",
        "environment": "PRODUCTION",
        "owner": "Billing Team",
    }
    resp = test_client.post("/api/v1/inventory/assets", json=asset_payload, headers=headers)
    assert resp.status_code == 201
    asset_id = resp.json()["id"]

    # 3. List assets
    resp = test_client.get("/api/v1/inventory/assets", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # 4. Get asset detail
    resp = test_client.get(f"/api/v1/inventory/assets/{asset_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["canonical_name"] == "api.billing.internal"

    # 5. Assign owner
    resp = test_client.post(
        f"/api/v1/inventory/assets/{asset_id}/assign-owner",
        json={"owner": "Payments Team Lead", "team": "FinTech", "reason": "Department reorganization"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json()["owner"] == "Payments Team Lead"

    # 6. Create identity
    ident_payload = {
        "identity_type": "USER",
        "canonical_identifier": "emma.security@example.com",
        "display_name": "Emma Security",
        "department": "InfoSec",
        "is_privileged": True,
    }
    resp = test_client.post("/api/v1/inventory/identities", json=ident_payload, headers=headers)
    assert resp.status_code == 201
    ident_id = resp.json()["id"]

    # 7. Get identity detail
    resp = test_client.get(f"/api/v1/inventory/identities/{ident_id}", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["is_privileged"] is True

    # 8. List sources
    resp = test_client.get("/api/v1/inventory/sources", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 9. Trigger reconciliation
    resp = test_client.post("/api/v1/inventory/reconcile", headers=headers)
    assert resp.status_code == 200
    assert "timestamp" in resp.json()

    # 10. Trigger sync
    resp = test_client.post("/api/v1/inventory/sync", json={"sync_endpoints": True}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "COMPLETED"


# ---------------------------------------------------------------------------
# TEST 13: MULTI-TENANT WORKSPACE CONTAINMENT
# ---------------------------------------------------------------------------

def test_multi_tenant_workspace_isolation(test_client, db_session):
    headers_a = {"X-Workspace-ID": "tenant-alpha", "X-Role": "admin"}
    headers_b = {"X-Workspace-ID": "tenant-bravo", "X-Role": "admin"}

    # Tenant Alpha creates asset
    resp = test_client.post(
        "/api/v1/inventory/assets",
        json={"asset_type": "SERVER", "canonical_name": "alpha-vault.internal", "display_name": "Alpha Vault"},
        headers=headers_a,
    )
    assert resp.status_code == 201
    alpha_asset_id = resp.json()["id"]

    # Tenant Bravo must not see Alpha's asset in list or direct detail
    resp_b = test_client.get("/api/v1/inventory/assets", headers=headers_b)
    assert resp_b.status_code == 200
    assert resp_b.json()["total"] == 0

    resp_b_detail = test_client.get(f"/api/v1/inventory/assets/{alpha_asset_id}", headers=headers_b)
    assert resp_b_detail.status_code == 404
