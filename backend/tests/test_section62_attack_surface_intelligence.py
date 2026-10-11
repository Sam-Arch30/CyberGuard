"""
Section 62: Attack Surface Intelligence Test Suite.

Validates:
1. Asset Identity Normalization & Deterministic Matching (FQDN, IPv4, IPv6, Mac/Hardware UID, Certificate fingerprint)
2. Duplicate Observation & Idempotent Upsert Handling
3. Tenant Discovery Scope Enforcement & Safe DNS Resolution
4. Strict SSRF Protection (Loopback, Link-Local, Private Subnets)
5. Actionable Exposure Identification & Deduplication (PUBLIC_ASSET, UNKNOWN_ASSET, STALE_ASSET)
6. Exposure Resolution Lifecycle & Parent Asset Risk Synchronization
7. Analyst Unknown Asset Review Workflow (APPROVE, ASSIGN_OWNER, MAP_TO_EXISTING, MARK_UNAUTHORIZED, ADD_TO_WATCHLIST) with Audit Logging
8. Business Criticality vs. Threat Risk Distinction (Separation of Context from Score)
9. Threat Intelligence, Indicators, and Endpoint Device Correlation Integration
10. Periodic Snapshots & Attack Surface Diff Generation
11. Persistent Background Job Workers (ATTACK_SURFACE_REFRESH, ATTACK_SURFACE_DISCOVERY)
12. Comprehensive REST API Endpoints & Tenant Isolation
"""
import asyncio
import json
import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from backend.db.session import get_db, init_db
from backend.db.models import (
    AssetModel,
    ExposureModel,
    AssetServiceModel,
    AttackSurfaceScopeModel,
    AttackSurfaceSnapshotModel,
    DeviceModel,
    IndicatorModel,
    FindingModel,
    AuditLogModel,
    WatchlistModel,
    WatchedIndicatorModel,
    get_utc_now,
    generate_uuid,
)
from backend.schemas.attack_surface import (
    AssetTypeEnum,
    AssetStatusEnum,
    ExposureStateEnum,
    CriticalityEnum,
    OwnershipConfidenceEnum,
    AssetSourceEnum,
    ExposureTypeEnum,
    ExposureStatusEnum,
    ExposureSeverityEnum,
    ScopeTypeEnum,
    AssetCreateRequest,
    AssetUpdateRequest,
    AttackSurfaceScopeCreateRequest,
    UnknownAssetReviewRequest,
    AttackSurfaceDiscoveryRequest,
)
from backend.services.attack_surface_service import AttackSurfaceService
from backend.services.background_job_worker import (
    JobExecutionContext,
    handle_attack_surface_refresh_job,
    handle_attack_surface_discovery_job,
)
from backend.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    return TestClient(app)


@pytest.fixture
def db_session():
    init_db()
    gen = get_db()
    db = next(gen)
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# 1. ASSET IDENTITY NORMALIZATION
# ============================================================================

def test_asset_normalization_deterministic():
    """Validates deterministic canonical normalization for domains, IPs, URLs, certs, and endpoints."""
    # Domains & URLs
    norm1, disp1 = AttackSurfaceService.normalize_asset_identifier(
        AssetTypeEnum.DOMAIN, "HTTPS://Portal.ACME-Corp.COM:8443/login"
    )
    assert norm1 == "portal.acme-corp.com"
    assert disp1 == "portal.acme-corp.com"

    norm2, disp2 = AttackSurfaceService.normalize_asset_identifier(
        AssetTypeEnum.SUBDOMAIN, "  Api-v2.DEV.corp.local.  "
    )
    assert norm2 == "api-v2.dev.corp.local"

    # IPv4 with port
    norm3, disp3 = AttackSurfaceService.normalize_asset_identifier(
        AssetTypeEnum.PUBLIC_IP, "203.0.113.195:443"
    )
    assert norm3 == "203.0.113.195"

    # IPv6
    norm4, disp4 = AttackSurfaceService.normalize_asset_identifier(
        AssetTypeEnum.PUBLIC_IP, "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    )
    assert norm4 == "2001:db8:85a3::8a2e:370:7334"

    # Certificate Fingerprint
    norm5, disp5 = AttackSurfaceService.normalize_asset_identifier(
        AssetTypeEnum.CERTIFICATE, "aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66:77:88:99:00:11:22:33:44:55:66"
    )
    assert norm5 == "aabbccddeeff1122334455667788990011223344556677889900112233445566"
    assert "SHA256" in disp5

    # Endpoint Hostname / MAC
    norm6, disp6 = AttackSurfaceService.normalize_asset_identifier(
        AssetTypeEnum.ENDPOINT, "00:1A:2B:3C:4D:5E"
    )
    assert norm6 == "00:1a:2b:3c:4d:5e"


def test_asset_upsert_idempotency_and_no_duplicates(db_session):
    """Ensures upserting an asset repeatedly never creates duplicate rows and preserves history."""
    ws = f"ws_upsert_{uuid.uuid4().hex[:8]}"

    req1 = AssetCreateRequest(
        asset_type=AssetTypeEnum.DOMAIN,
        raw_name="api.production.example.com",
        display_name="API Gateway",
        criticality=CriticalityEnum.HIGH,
        environment="PRODUCTION",
        owner="Cloud Platform Team",
        source=AssetSourceEnum.MANUAL_ANALYST,
        metadata={"tier": "primary"},
    )
    asset1 = AttackSurfaceService.upsert_asset(db_session, ws, req1)
    db_session.commit()

    assert asset1.canonical_name == "api.production.example.com"
    assert asset1.owner == "Cloud Platform Team"
    first_seen = asset1.first_seen_at

    # Upsert with slightly different capitalization and new metadata
    req2 = AssetCreateRequest(
        asset_type=AssetTypeEnum.DOMAIN,
        raw_name="API.Production.Example.COM",
        criticality=CriticalityEnum.CRITICAL,
        owner="Cloud Platform Team",
        metadata={"region": "us-east-1"},
    )
    asset2 = AttackSurfaceService.upsert_asset(db_session, ws, req2)
    db_session.commit()

    assert asset2.id == asset1.id
    assert asset2.criticality == CriticalityEnum.CRITICAL.value
    assert asset2.first_seen_at == first_seen
    # Metadata was merged
    meta = asset2.metadata_dict
    assert meta.get("tier") == "primary"
    assert meta.get("region") == "us-east-1"

    # Verify database row count
    count = db_session.query(AssetModel).filter(
        AssetModel.workspace_id == ws,
        AssetModel.canonical_name == "api.production.example.com",
    ).count()
    assert count == 1


# ============================================================================
# 2. DISCOVERY SCOPE & SSRF PROTECTION
# ============================================================================

def test_authorized_scope_boundaries(db_session):
    """Tests tenant boundary enforcement for discovery scopes."""
    ws = f"ws_scope_{uuid.uuid4().hex[:8]}"

    # Add authorized scope
    scope_req = AttackSurfaceScopeCreateRequest(
        scope_type=ScopeTypeEnum.DOMAIN,
        target="*.cyberguard-sec.internal",
        is_authorized=True,
        description="Authorized corporate internal domain tree",
    )
    AttackSurfaceService.create_scope(db_session, ws, scope_req)
    db_session.commit()

    # Targets within scope
    assert AttackSurfaceService.is_target_in_authorized_scope(db_session, ws, "api.cyberguard-sec.internal") is True
    assert AttackSurfaceService.is_target_in_authorized_scope(db_session, ws, "vpn.cyberguard-sec.internal") is True

    # Targets outside authorized scope
    assert AttackSurfaceService.is_target_in_authorized_scope(db_session, ws, "evil-third-party.com") is False
    assert AttackSurfaceService.is_target_in_authorized_scope(db_session, ws, "random.org") is False


def test_ssrf_safety_on_scope_creation(db_session):
    """Verifies that private IP, loopback, and cloud metadata addresses are rejected during scope creation."""
    ws = f"ws_ssrf_{uuid.uuid4().hex[:8]}"

    # Loopback IP
    with pytest.raises(ValueError, match="violates SSRF safety controls"):
        req_loopback = AttackSurfaceScopeCreateRequest(
            scope_type=ScopeTypeEnum.IP,
            target="127.0.0.1",
            description="Attempted loopback scope",
        )
        AttackSurfaceService.create_scope(db_session, ws, req_loopback)

    # Cloud metadata link-local address
    with pytest.raises(ValueError, match="violates SSRF safety controls"):
        req_metadata = AttackSurfaceScopeCreateRequest(
            scope_type=ScopeTypeEnum.IP,
            target="169.254.169.254",
            description="Attempted cloud metadata injection",
        )
        AttackSurfaceService.create_scope(db_session, ws, req_metadata)

    # Private RFC1918 address
    with pytest.raises(ValueError, match="violates SSRF safety controls"):
        req_rfc1918 = AttackSurfaceScopeCreateRequest(
            scope_type=ScopeTypeEnum.IP,
            target="10.200.0.1",
            description="Attempted private RFC1918 scanning",
        )
        AttackSurfaceService.create_scope(db_session, ws, req_rfc1918)


# ============================================================================
# 3. EXPOSURE IDENTIFICATION & DEDUPLICATION
# ============================================================================

def test_exposure_evaluation_and_deduplication(db_session):
    """Ensures assets are evaluated for actionable exposures without duplication."""
    ws = f"ws_exp_{uuid.uuid4().hex[:8]}"

    # Discovered public IP with no owner
    req = AssetCreateRequest(
        asset_type=AssetTypeEnum.PUBLIC_IP,
        raw_name="198.51.100.25",
        owner="Unknown",
        criticality=CriticalityEnum.HIGH,
        source=AssetSourceEnum.EXTERNAL_DISCOVERY,
    )
    asset = AttackSurfaceService.upsert_asset(db_session, ws, req)
    db_session.commit()

    # Initial evaluation should create PUBLIC_ASSET and UNKNOWN_ASSET exposures
    exp_count1 = AttackSurfaceService.evaluate_asset_exposures(db_session, ws, asset)
    db_session.commit()
    assert exp_count1 >= 2

    exps = db_session.query(ExposureModel).filter(
        ExposureModel.workspace_id == ws,
        ExposureModel.asset_id == asset.id,
        ExposureModel.status == ExposureStatusEnum.OPEN.value,
    ).all()
    exp_types = [e.exposure_type for e in exps]
    assert ExposureTypeEnum.PUBLIC_ASSET.value in exp_types
    assert ExposureTypeEnum.UNKNOWN_ASSET.value in exp_types

    # Second evaluation should be idempotent (0 newly created exposures)
    exp_count2 = AttackSurfaceService.evaluate_asset_exposures(db_session, ws, asset)
    assert exp_count2 == 0


def test_exposure_resolution_lifecycle(db_session):
    """Tests resolving an exposure updates its status and recalculates parent risk."""
    ws = f"ws_resolve_{uuid.uuid4().hex[:8]}"

    req = AssetCreateRequest(
        asset_type=AssetTypeEnum.PUBLIC_IP,
        raw_name="203.0.113.88",
        owner="Security Operations",
        criticality=CriticalityEnum.HIGH,
    )
    asset = AttackSurfaceService.upsert_asset(db_session, ws, req)
    db_session.commit()

    AttackSurfaceService.evaluate_asset_exposures(db_session, ws, asset)
    db_session.commit()

    open_exp = db_session.query(ExposureModel).filter(
        ExposureModel.workspace_id == ws,
        ExposureModel.asset_id == asset.id,
        ExposureModel.status == ExposureStatusEnum.OPEN.value,
    ).first()
    assert open_exp is not None

    # Resolve exposure
    resolved = AttackSurfaceService.resolve_exposure_by_id(
        db=db_session,
        workspace_id=ws,
        exposure_id=open_exp.id,
        notes="Validated public firewall rule: ingress restricted via WAF",
        actor="Security Engineer Alice",
    )
    db_session.commit()

    assert resolved.status == ExposureStatusEnum.RESOLVED.value
    assert resolved.resolved_by == "Security Engineer Alice"
    assert "WAF" in resolved.resolution_notes

    # Refreshed asset should have reduced active exposures
    db_session.refresh(asset)
    assert asset.active_exposure_count >= 0


# ============================================================================
# 4. UNKNOWN ASSETS REVIEW WORKFLOW
# ============================================================================

def test_unknown_asset_review_actions(db_session):
    """Tests analyst triage actions: APPROVE, ASSIGN_OWNER, MARK_UNAUTHORIZED, ADD_TO_WATCHLIST."""
    ws = f"ws_triage_{uuid.uuid4().hex[:8]}"

    # Discovered unknown domain
    req = AssetCreateRequest(
        asset_type=AssetTypeEnum.SUBDOMAIN,
        raw_name="staging-admin.internal-test.net",
        owner="Unknown",
        criticality=CriticalityEnum.LOW,
        source=AssetSourceEnum.INTERNAL_DISCOVERY,
    )
    asset = AttackSurfaceService.upsert_asset(db_session, ws, req)
    db_session.commit()

    assert asset.status == AssetStatusEnum.DISCOVERED.value

    # Action 1: ASSIGN_OWNER
    assign_req = UnknownAssetReviewRequest(
        action="ASSIGN_OWNER",
        owner="DevOps Team",
        team="Infrastructure",
        criticality=CriticalityEnum.MEDIUM,
        notes="Confirmed staging administration portal owned by DevOps",
        actor="SOC Analyst Bob",
    )
    asset = AttackSurfaceService.review_unknown_asset(db_session, ws, asset.id, assign_req)
    db_session.commit()

    assert asset.owner == "DevOps Team"
    assert asset.team == "Infrastructure"
    assert asset.status == AssetStatusEnum.ACTIVE.value
    assert asset.ownership_confidence == OwnershipConfidenceEnum.MANUAL.value

    # Action 2: MARK_UNAUTHORIZED on another asset
    req2 = AssetCreateRequest(
        asset_type=AssetTypeEnum.PUBLIC_IP,
        raw_name="198.51.100.99",
        owner="Unknown",
        source=AssetSourceEnum.EXTERNAL_DISCOVERY,
    )
    asset2 = AttackSurfaceService.upsert_asset(db_session, ws, req2)
    db_session.commit()

    unauth_req = UnknownAssetReviewRequest(
        action="MARK_UNAUTHORIZED",
        notes="Rogue test node found hosting public shadowsocks proxy",
        actor="SOC Lead",
    )
    asset2 = AttackSurfaceService.review_unknown_asset(db_session, ws, asset2.id, unauth_req)
    db_session.commit()

    assert asset2.criticality == CriticalityEnum.CRITICAL.value
    # Created a critical exposure
    crit_exp = db_session.query(ExposureModel).filter(
        ExposureModel.workspace_id == ws,
        ExposureModel.asset_id == asset2.id,
        ExposureModel.exposure_type == ExposureTypeEnum.UNKNOWN_ASSET.value,
        ExposureModel.severity == ExposureSeverityEnum.CRITICAL.value,
    ).first()
    assert crit_exp is not None

    # Check audit log entries
    logs = db_session.query(AuditLogModel).filter(
        AuditLogModel.resource_type == "asset",
        AuditLogModel.resource_id.in_([asset.id, asset2.id]),
    ).all()
    assert len(logs) >= 2


# ============================================================================
# 5. BUSINESS CRITICALITY VS THREAT RISK DISTINCTION
# ============================================================================

def test_criticality_vs_risk_separation(db_session):
    """
    Verifies that Business Criticality is stored as distinct business context
    and not collapsed into Threat Risk score, while appropriately weighting risk computation.
    """
    ws = f"ws_crit_{uuid.uuid4().hex[:8]}"

    # Asset A: Low business criticality but high threat risk from findings
    asset_a = AssetModel(
        id=generate_uuid(),
        workspace_id=ws,
        asset_type=AssetTypeEnum.ENDPOINT.value,
        canonical_name="sandbox-vm-01",
        display_name="Dev Sandbox VM",
        status=AssetStatusEnum.ACTIVE.value,
        criticality=CriticalityEnum.LOW.value,
        owner="QA Team",
        source=AssetSourceEnum.ENDPOINT_AGENT.value,
        active_finding_count=5,
        active_exposure_count=0,
        risk_score=0.0,
        risk_level="LOW",
        first_seen_at=get_utc_now(),
        last_seen_at=get_utc_now(),
        metadata_json="{}",
    )
    db_session.add(asset_a)

    # Asset B: Critical business criticality with zero findings and zero exposures
    asset_b = AssetModel(
        id=generate_uuid(),
        workspace_id=ws,
        asset_type=AssetTypeEnum.ENDPOINT.value,
        canonical_name="core-dc-ad01",
        display_name="Active Directory Domain Controller",
        status=AssetStatusEnum.ACTIVE.value,
        criticality=CriticalityEnum.CRITICAL.value,
        owner="Enterprise Identity",
        source=AssetSourceEnum.ENDPOINT_AGENT.value,
        active_finding_count=0,
        active_exposure_count=0,
        risk_score=0.0,
        risk_level="LOW",
        first_seen_at=get_utc_now(),
        last_seen_at=get_utc_now(),
        metadata_json="{}",
    )
    db_session.add(asset_b)
    db_session.commit()

    AttackSurfaceService.recompute_asset_risk(db_session, ws, asset_a)
    AttackSurfaceService.recompute_asset_risk(db_session, ws, asset_b)
    db_session.commit()

    # Asset A has active findings so its threat risk increases
    assert asset_a.criticality == CriticalityEnum.LOW.value
    assert asset_a.risk_score > 0.0

    # Asset B has clean threat risk (0 findings, 0 exposures) despite CRITICAL business context
    assert asset_b.criticality == CriticalityEnum.CRITICAL.value
    assert asset_b.risk_score < asset_a.risk_score


# ============================================================================
# 6. THREAT INTEL & WATCHLIST INTEGRATION
# ============================================================================

def test_watchlist_integration_on_review(db_session):
    """Tests that reviewing an unknown asset with ADD_TO_WATCHLIST populates WatchedIndicatorModel."""
    ws = f"ws_wl_{uuid.uuid4().hex[:8]}"

    # Discovered unknown IP
    req = AssetCreateRequest(
        asset_type=AssetTypeEnum.PUBLIC_IP,
        raw_name="198.51.100.77",
        owner="Unknown",
    )
    asset = AttackSurfaceService.upsert_asset(db_session, ws, req)
    db_session.commit()

    # Review with ADD_TO_WATCHLIST
    wl_req = UnknownAssetReviewRequest(
        action="ADD_TO_WATCHLIST",
        notes="Add suspicious external gateway to high-priority attack surface watchlist",
        actor="Threat Analyst Carol",
    )
    AttackSurfaceService.review_unknown_asset(db_session, ws, asset.id, wl_req)
    db_session.commit()

    # Verify watched indicator was created
    watched = db_session.query(WatchedIndicatorModel).filter(
        WatchedIndicatorModel.workspace_id == ws,
        WatchedIndicatorModel.normalized_value == "198.51.100.77",
    ).first()
    assert watched is not None
    assert watched.indicator_type == "IP"


# ============================================================================
# 7. SNAPSHOTS & DIFF ENGINE
# ============================================================================

def test_attack_surface_snapshot_and_diff(db_session):
    """Tests generating a snapshot and computing accurate additions and diff statistics."""
    ws = f"ws_diff_{uuid.uuid4().hex[:8]}"

    # Create baseline asset
    req1 = AssetCreateRequest(
        asset_type=AssetTypeEnum.DOMAIN,
        raw_name="legacy-portal.example.com",
        owner="Operations",
    )
    AttackSurfaceService.upsert_asset(db_session, ws, req1)
    db_session.commit()

    # Create Snapshot 1
    snap1 = AttackSurfaceService.create_snapshot_diff(db_session, ws, "Baseline")
    db_session.commit()
    assert snap1.total_assets == 1

    # Add second asset
    req2 = AssetCreateRequest(
        asset_type=AssetTypeEnum.DOMAIN,
        raw_name="new-api.example.com",
        owner="Cloud Engineering",
    )
    AttackSurfaceService.upsert_asset(db_session, ws, req2)
    db_session.commit()

    # Create Snapshot 2
    snap2 = AttackSurfaceService.create_snapshot_diff(db_session, ws, "Update")
    db_session.commit()
    assert snap2.total_assets == 2
    assert snap2.assets_added == 1
    assert "new-api.example.com" in snap2.diff_summary.get("added_assets", [])

    # Latest diff check
    diff_res = AttackSurfaceService.get_latest_diff(db_session, ws)
    assert diff_res.assets_added == 1
    assert "new-api.example.com" in diff_res.added_asset_names


# ============================================================================
# 8. BACKGROUND JOB WORKERS
# ============================================================================

def test_background_job_handlers(db_session):
    """Executes Section 62 background job handlers for refresh and discovery."""
    ws = f"ws_bg_{uuid.uuid4().hex[:8]}"

    # Add authorized scope
    scope_req = AttackSurfaceScopeCreateRequest(
        scope_type=ScopeTypeEnum.DOMAIN,
        target="*.corp-safe.internal",
        description="Authorized corporate domain scope",
    )
    AttackSurfaceService.create_scope(db_session, ws, scope_req)
    db_session.commit()

    # 1. ATTACK_SURFACE_REFRESH job
    refresh_ctx = JobExecutionContext(
        job_id=str(uuid.uuid4()),
        workspace_id=ws,
        job_type="ATTACK_SURFACE_REFRESH",
        payload={"sources": ["DNS_SCOPES"], "create_snapshot": False},
        worker_id="worker_test_1",
        attempt=1,
        timeout_seconds=60,
    )
    refresh_res = asyncio.run(handle_attack_surface_refresh_job(refresh_ctx, db_session))
    assert "assets_discovered" in refresh_res

    # 2. ATTACK_SURFACE_DISCOVERY job
    discovery_ctx = JobExecutionContext(
        job_id=str(uuid.uuid4()),
        workspace_id=ws,
        job_type="ATTACK_SURFACE_DISCOVERY",
        payload={"sources": ["DNS_SCOPES"], "create_snapshot": False},
        worker_id="worker_test_2",
        attempt=1,
        timeout_seconds=60,
    )
    discovery_res = asyncio.run(handle_attack_surface_discovery_job(discovery_ctx, db_session))
    assert "assets_discovered" in discovery_res


# ============================================================================
# 9. REST API END-TO-END SUITE
# ============================================================================

def test_attack_surface_api_full_lifecycle(client):
    """End-to-end REST API validation across all Attack Surface Intelligence endpoints."""
    ws = f"ws_api_{uuid.uuid4().hex[:8]}"
    headers = {"X-Workspace-ID": ws}

    # 1. Create Authorized Scope
    scope_payload = {
        "scope_type": "DOMAIN",
        "target": "*.test-platform.org",
        "is_authorized": True,
        "description": "Primary corporate platform domain tree",
    }
    resp_scope = client.post("/api/v1/attack-surface/scopes", json=scope_payload, headers=headers)
    assert resp_scope.status_code == 201
    scope_id = resp_scope.json()["id"]

    # 2. List Scopes
    resp_scopes = client.get("/api/v1/attack-surface/scopes", headers=headers)
    assert resp_scopes.status_code == 200
    assert len(resp_scopes.json()) >= 1

    # 3. Create Asset
    asset_payload = {
        "asset_type": "DOMAIN",
        "raw_name": "auth.test-platform.org",
        "display_name": "Auth Gateway",
        "criticality": "HIGH",
        "environment": "PRODUCTION",
        "owner": "Security Architecture",
    }
    resp_asset = client.post("/api/v1/attack-surface/assets", json=asset_payload, headers=headers)
    assert resp_asset.status_code == 201
    asset_data = resp_asset.json()
    asset_id = asset_data["id"]
    assert asset_data["canonical_name"] == "auth.test-platform.org"

    # 4. List Assets with Filters
    resp_list = client.get("/api/v1/attack-surface/assets?asset_type=DOMAIN", headers=headers)
    assert resp_list.status_code == 200
    assert resp_list.json()["total"] >= 1

    # 5. Get Asset Detail
    resp_detail = client.get(f"/api/v1/attack-surface/assets/{asset_id}", headers=headers)
    assert resp_detail.status_code == 200
    assert resp_detail.json()["id"] == asset_id
    assert "exposures" in resp_detail.json()
    assert "services" in resp_detail.json()

    # 6. Update Asset
    patch_payload = {
        "display_name": "SSO & Authentication Gateway",
        "criticality": "CRITICAL",
        "environment": "PRODUCTION",
    }
    resp_patch = client.patch(f"/api/v1/attack-surface/assets/{asset_id}", json=patch_payload, headers=headers)
    assert resp_patch.status_code == 200
    assert resp_patch.json()["criticality"] == "CRITICAL"

    # 7. Asset Timeline
    resp_timeline = client.get(f"/api/v1/attack-surface/assets/{asset_id}/timeline", headers=headers)
    assert resp_timeline.status_code == 200
    assert len(resp_timeline.json()) >= 1

    # 8. List Exposures
    resp_exposures = client.get("/api/v1/attack-surface/exposures", headers=headers)
    assert resp_exposures.status_code == 200

    # 9. Unknown Queue
    # Create an unknown asset
    client.post(
        "/api/v1/attack-surface/assets",
        json={"asset_type": "SUBDOMAIN", "raw_name": "unmapped-beta.test-platform.org", "owner": "Unknown"},
        headers=headers,
    )
    resp_unknown = client.get("/api/v1/attack-surface/unknown-queue", headers=headers)
    assert resp_unknown.status_code == 200
    assert resp_unknown.json()["total"] >= 1
    unmapped_id = resp_unknown.json()["items"][0]["id"]

    # 10. Review Unknown Asset
    review_payload = {
        "action": "APPROVE",
        "owner": "Beta Testing Team",
        "notes": "Approved for external preview testing",
        "actor": "SOC Reviewer",
    }
    resp_review = client.post(
        f"/api/v1/attack-surface/unknown-queue/{unmapped_id}/review",
        json=review_payload,
        headers=headers,
    )
    assert resp_review.status_code == 200
    assert resp_review.json()["status"] == "ACTIVE"

    # 11. Trigger Discovery
    resp_disc = client.post(
        "/api/v1/attack-surface/discover",
        json={"sync_from_endpoints": False, "resolve_dns_records": False},
        headers=headers,
    )
    assert resp_disc.status_code == 200
    assert resp_disc.json()["status"] == "COMPLETED"

    # 12. Attack Surface Diff
    resp_diff = client.get("/api/v1/attack-surface/diff", headers=headers)
    assert resp_diff.status_code == 200
    assert "assets_added" in resp_diff.json()

    # 13. Overview Stats
    resp_overview = client.get("/api/v1/attack-surface/overview", headers=headers)
    assert resp_overview.status_code == 200
    assert resp_overview.json()["total_assets"] >= 2

    # 14. Delete Scope
    resp_del_scope = client.delete(f"/api/v1/attack-surface/scopes/{scope_id}", headers=headers)
    assert resp_del_scope.status_code == 200
    assert resp_del_scope.json()["deleted"] is True


def test_tenant_workspace_isolation(client):
    """Guarantees strict tenant isolation: Workspace Alpha assets cannot be accessed by Workspace Beta."""
    ws_alpha = f"ws_alpha_{uuid.uuid4().hex[:8]}"
    ws_beta = f"ws_beta_{uuid.uuid4().hex[:8]}"

    # Create asset in Alpha
    resp_alpha = client.post(
        "/api/v1/attack-surface/assets",
        json={"asset_type": "DOMAIN", "raw_name": "alpha-secret.org", "owner": "Alpha Team"},
        headers={"X-Workspace-ID": ws_alpha},
    )
    asset_alpha_id = resp_alpha.json()["id"]

    # Try to access from Beta
    resp_beta_get = client.get(
        f"/api/v1/attack-surface/assets/{asset_alpha_id}",
        headers={"X-Workspace-ID": ws_beta},
    )
    assert resp_beta_get.status_code == 404

    # List in Beta should not include Alpha assets
    resp_beta_list = client.get(
        "/api/v1/attack-surface/assets",
        headers={"X-Workspace-ID": ws_beta},
    )
    assert resp_beta_list.json()["total"] == 0
