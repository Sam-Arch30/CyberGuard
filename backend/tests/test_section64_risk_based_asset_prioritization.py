"""
Unit and Integration Tests for Section 64: Risk-Based Asset Prioritization.
Validates:
1. Deterministic priority scoring and band assignment (P1, P2, P3, P4).
2. Risk vs Priority operational distinction (High Risk / Low Criticality vs Mod Risk / Critical Asset).
3. Criticality and Attack Surface exposure modifiers.
4. Active incident escalation and SLA breach urgency.
5. Double-counting protection (Risk Engine score as unified input).
6. Data quality and uncertainty handling (Unknown != Safe).
7. Freshness and staleness penalties.
8. Manual analyst override lifecycle (effective vs calculated).
9. Override expiration mechanics.
10. Policy versioning and activation.
11. Snapshot history timeline transitions (INITIAL, ESCALATED, DEESCALATED, OVERRIDDEN).
12. Background recalculation job worker execution.
13. SOC overview top prioritized assets integration.
14. REST API full lifecycle endpoints.
15. Multi-tenant workspace boundaries.
"""

import json
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from backend.db.models import (
    Base,
    AssetModel,
    AssetPrioritizationPolicyModel,
    AssetPrioritySnapshotModel,
    IncidentModel,
    NotificationModel,
    InventoryOverrideModel,
    get_utc_now,
)
from backend.services.asset_prioritization_service import (
    AssetPrioritizationService,
    DEFAULT_POLICY_CONFIGURATION,
)
from backend.services.background_job_worker import (
    handle_asset_priority_recalculation_job,
    JobExecutionContext,
)
from backend.services.soc_dashboard_service import SocDashboardService
from backend.schemas.asset_prioritization import (
    PriorityBandEnum,
    PriorityDataQualityEnum,
    PriorityPolicyStatusEnum,
)
from backend.main import app


@pytest.fixture
def db_session():
    """In-memory SQLite session with full schema initialized and static pool for multithread safety."""
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
    """TestClient overriding get_db dependency with in-memory session."""
    from backend.db.session import get_db
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()


def create_test_asset(
    db,
    workspace_id="test_ws",
    canonical_name="srv-prod-api.corp.local",
    asset_type="SERVER",
    risk_score=75.0,
    criticality="HIGH",
    exposure_state="PUBLICLY_EXPOSED",
    environment="PRODUCTION",
    is_managed=True,
    is_stale=False,
    last_seen_at=None,
):
    now = get_utc_now()
    asset = AssetModel(
        workspace_id=workspace_id,
        asset_type=asset_type,
        canonical_name=canonical_name,
        display_name=canonical_name,
        status="ACTIVE",
        risk_score=risk_score,
        risk_level="HIGH" if risk_score >= 60 else "LOW",
        criticality=criticality,
        exposure_state=exposure_state,
        environment=environment,
        owner="Platform Team",
        team="DevOps",
        is_managed=is_managed,
        is_stale=is_stale,
        first_seen_at=now,
        last_seen_at=last_seen_at or now,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


# ---------------------------------------------------------------------------
# TEST 1: DETERMINISTIC SCORING & BAND ASSIGNMENT
# ---------------------------------------------------------------------------
def test_priority_calculation_deterministic_scoring(db_session):
    asset = create_test_asset(
        db_session,
        risk_score=85.0,
        criticality="CRITICAL",
        exposure_state="PUBLICLY_EXPOSED",
        environment="PRODUCTION",
    )
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")

    calculated_asset, snapshot = AssetPrioritizationService.calculate_asset_priority(
        db_session, asset, policy=policy, save_snapshot=True
    )

    # 85*0.40(34.0) + 100*0.25(25.0) + 100*0.15(15.0) + 0*0.10(0) + 0*0.05(0) + 100*0.05(5.0) = 79.0
    assert calculated_asset.priority_score >= 75.0
    assert calculated_asset.priority_band in [PriorityBandEnum.P1.value, PriorityBandEnum.P2.value]
    assert snapshot is not None
    assert snapshot.policy_version == policy.version
    assert snapshot.data_quality == PriorityDataQualityEnum.GOOD.value


# ---------------------------------------------------------------------------
# TEST 2: RISK VS PRIORITY OPERATIONAL DISTINCTION
# ---------------------------------------------------------------------------
def test_risk_vs_priority_distinction(db_session):
    # Asset A: High technical risk but low business criticality, internal only, no incidents
    asset_a = create_test_asset(
        db_session,
        canonical_name="dev-test-sandbox.local",
        risk_score=85.0,
        criticality="LOW",
        exposure_state="INTERNALLY_ONLY",
        environment="DEVELOPMENT",
    )

    # Asset B: Moderate technical risk, but critical production asset, internet exposed
    asset_b = create_test_asset(
        db_session,
        canonical_name="api.payments.prod.cyberguard.io",
        risk_score=65.0,
        criticality="CRITICAL",
        exposure_state="PUBLICLY_EXPOSED",
        environment="PRODUCTION",
    )

    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")
    AssetPrioritizationService.calculate_asset_priority(db_session, asset_a, policy)
    AssetPrioritizationService.calculate_asset_priority(db_session, asset_b, policy)

    # Verify Asset B has higher operational priority than Asset A despite Asset A having higher raw security risk
    assert asset_b.priority_score > asset_a.priority_score
    assert asset_b.effective_priority in ["P1", "P2"]
    assert asset_a.effective_priority in ["P3", "P4"]


# ---------------------------------------------------------------------------
# TEST 3: CRITICALITY AND EXPOSURE MODIFIERS
# ---------------------------------------------------------------------------
def test_criticality_and_exposure_modifiers(db_session):
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")

    # Base internal low asset
    asset_low = create_test_asset(
        db_session,
        canonical_name="int-low.local",
        risk_score=30.0,
        criticality="LOW",
        exposure_state="INTERNALLY_ONLY",
    )
    AssetPrioritizationService.calculate_asset_priority(db_session, asset_low, policy)

    # Same risk, but exposed + high criticality
    asset_high = create_test_asset(
        db_session,
        canonical_name="ext-high.local",
        risk_score=30.0,
        criticality="CRITICAL",
        exposure_state="PUBLICLY_EXPOSED",
    )
    AssetPrioritizationService.calculate_asset_priority(db_session, asset_high, policy)

    # Exposure + Criticality should increase priority score significantly
    assert asset_high.priority_score > asset_low.priority_score + 30.0


# ---------------------------------------------------------------------------
# TEST 4: ACTIVE INCIDENT ESCALATION AND SLA URGENCY
# ---------------------------------------------------------------------------
def test_active_incident_escalation(db_session):
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")

    asset = create_test_asset(
        db_session,
        canonical_name="auth.company.com",
        risk_score=50.0,
        criticality="MEDIUM",
        exposure_state="INTERNALLY_REACHABLE",
    )
    AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)
    score_before = asset.priority_score

    # Open active incident linking this asset with BREACHED SLA
    inc = IncidentModel(
        workspace_id="test_ws",
        title=f"Credential Abuse on {asset.canonical_name}",
        description=f"Active brute force on {asset.id}",
        status="INVESTIGATING",
        severity="HIGH",
        sla_status="BREACHED",
    )
    db_session.add(inc)
    db_session.commit()

    # Recalculate priority
    AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)
    assert asset.priority_score > score_before
    # Contributor explanation should document active incident
    expl = asset.priority_explanation_dict
    inc_contrib = next(c for c in expl["contributors"] if c["factor"] == "active_incidents")
    assert inc_contrib["value"] == 1
    assert "SLA urgency" in inc_contrib["description"]


# ---------------------------------------------------------------------------
# TEST 5: DOUBLE-COUNTING PROTECTION
# ---------------------------------------------------------------------------
def test_double_counting_protection(db_session):
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")
    asset = create_test_asset(db_session, risk_score=80.0)

    AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)
    expl = asset.priority_explanation_dict

    # Check contributors: Authoritative unified_security_risk is the sole security risk contributor
    factors = [c["factor"] for c in expl["contributors"]]
    assert "unified_security_risk" in factors
    assert factors.count("unified_security_risk") == 1
    # Raw findings, raw indicators, or duplicate threat scores are NOT added as separate factors
    assert "raw_finding_severity" not in factors
    assert "duplicate_threat_intel_score" not in factors


# ---------------------------------------------------------------------------
# TEST 6: DATA QUALITY & UNCERTAINTY HANDLING
# ---------------------------------------------------------------------------
def test_data_quality_and_uncertainty_handling(db_session):
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")

    # Asset with UNKNOWN criticality and UNKNOWN exposure
    asset = create_test_asset(
        db_session,
        canonical_name="shadow-host.local",
        risk_score=20.0,
        criticality="UNKNOWN",
        exposure_state="UNKNOWN",
        is_managed=False,
    )

    AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)

    # Must NOT treat unknown as 0 or safe
    assert asset.priority_data_quality in [PriorityDataQualityEnum.DEGRADED.value, PriorityDataQualityEnum.UNKNOWN.value]
    expl = asset.priority_explanation_dict
    dq = expl["data_quality"]
    assert "criticality" in dq["uncertain_sources"]
    assert "exposure_state" in dq["uncertain_sources"]
    assert len(dq["issues"]) >= 2


# ---------------------------------------------------------------------------
# TEST 7: STALENESS HANDLING
# ---------------------------------------------------------------------------
def test_staleness_handling(db_session):
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")

    stale_time = get_utc_now() - timedelta(days=45)
    asset = create_test_asset(
        db_session,
        canonical_name="dormant-workstation.local",
        last_seen_at=stale_time,
        is_stale=True,
    )

    AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)

    assert asset.priority_data_quality == PriorityDataQualityEnum.STALE.value
    expl = asset.priority_explanation_dict
    assert "inventory" in expl["data_quality"]["stale_sources"]


# ---------------------------------------------------------------------------
# TEST 8: MANUAL OVERRIDE LIFECYCLE
# ---------------------------------------------------------------------------
def test_manual_override_lifecycle(db_session):
    asset = create_test_asset(
        db_session,
        canonical_name="support-portal.corp.local",
        risk_score=20.0,
        criticality="LOW",
        exposure_state="INTERNALLY_ONLY",
    )
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")
    AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)

    # Calculated priority should be P4
    assert asset.priority_band == "P4"
    assert asset.effective_priority == "P4"

    # Analyst applies manual P1 override
    AssetPrioritizationService.apply_manual_override(
        db_session,
        workspace_id="test_ws",
        asset_id=asset.id,
        priority="P1",
        reason="Target of targeted spearphishing campaign under active investigation",
        actor="lead_analyst",
        expires_in_hours=48,
    )

    assert asset.priority_override == "P1"
    assert asset.effective_priority == "P1"
    # Underlying calculated band remains preserved as P4
    assert asset.priority_band == "P4"

    # Remove override
    AssetPrioritizationService.remove_manual_override(
        db_session, workspace_id="test_ws", asset_id=asset.id, actor="lead_analyst"
    )

    assert asset.priority_override is None
    assert asset.effective_priority == "P4"


# ---------------------------------------------------------------------------
# TEST 9: OVERRIDE EXPIRATION
# ---------------------------------------------------------------------------
def test_override_expiry(db_session):
    asset = create_test_asset(db_session, risk_score=15.0, criticality="LOW")
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")
    AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)

    # Apply override with expiration in the past
    asset.priority_override = "P1"
    asset.priority_override_reason = "Temporary drill"
    asset.priority_override_expires_at = get_utc_now() - timedelta(minutes=5)
    db_session.commit()

    # effective_priority property should detect expiration and return calculated_band
    assert asset.effective_priority == asset.priority_band


# ---------------------------------------------------------------------------
# TEST 10: POLICY VERSIONING AND ACTIVATION
# ---------------------------------------------------------------------------
def test_policy_versioning_and_activation(db_session):
    # Default policy v1
    v1 = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")
    assert v1.version == 1

    # Create policy v2 with heavy risk weight
    v2_config = dict(DEFAULT_POLICY_CONFIGURATION)
    v2_config["weights"] = dict(DEFAULT_POLICY_CONFIGURATION["weights"])
    v2_config["weights"]["unified_security_risk"] = 0.70
    v2_config["weights"]["business_criticality"] = 0.10

    v2 = AssetPrioritizationService.create_policy(
        db_session,
        workspace_id="test_ws",
        name="Risk-Heavy Prioritization Policy",
        configuration=v2_config,
        status="DRAFT",
    )
    assert v2.version == 2
    assert v2.status == PriorityPolicyStatusEnum.DRAFT.value

    # Activate policy v2
    activated_v2 = AssetPrioritizationService.activate_policy(db_session, "test_ws", v2.id)
    assert activated_v2.status == PriorityPolicyStatusEnum.ACTIVE.value

    # Refresh v1: should be archived
    db_session.refresh(v1)
    assert v1.status == PriorityPolicyStatusEnum.ARCHIVED.value

    # Next calculation uses policy v2
    asset = create_test_asset(db_session, risk_score=90.0)
    AssetPrioritizationService.calculate_asset_priority(db_session, asset)
    assert asset.priority_policy_version == 2


# ---------------------------------------------------------------------------
# TEST 11: SNAPSHOT HISTORY TIMELINE TRANSITIONS
# ---------------------------------------------------------------------------
def test_priority_snapshot_history_transitions(db_session):
    asset = create_test_asset(db_session, risk_score=20.0, criticality="LOW")
    policy = AssetPrioritizationService.get_or_create_active_policy(db_session, "test_ws")

    # Initial calculation: transition_type = INITIAL
    _, snap1 = AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)
    assert snap1.transition_type == "INITIAL"

    # Escalate risk: transition_type = ESCALATED
    asset.risk_score = 90.0
    asset.criticality = "CRITICAL"
    _, snap2 = AssetPrioritizationService.calculate_asset_priority(db_session, asset, policy)
    assert snap2.transition_type == "ESCALATED"

    # History timeline
    history = AssetPrioritizationService.get_asset_priority_history(db_session, "test_ws", asset.id)
    assert len(history) == 2
    assert history[0].transition_type == "ESCALATED"
    assert history[1].transition_type == "INITIAL"


# ---------------------------------------------------------------------------
# TEST 12: BACKGROUND RECALCULATION JOB
# ---------------------------------------------------------------------------
def test_background_recalculation_job(db_session):
    import asyncio
    from backend.db.models import BackgroundJobModel

    create_test_asset(db_session, canonical_name="node-1.corp")
    create_test_asset(db_session, canonical_name="node-2.corp")

    job = BackgroundJobModel(
        id="job-rec-001",
        workspace_id="test_ws",
        job_type="ASSET_PRIORITY_RECALCULATION",
        status="RUNNING",
    )
    db_session.add(job)
    db_session.commit()

    ctx = JobExecutionContext(
        job_id="job-rec-001",
        workspace_id="test_ws",
        job_type="ASSET_PRIORITY_RECALCULATION",
        payload={"actor": "test_runner"},
        worker_id="worker_test_1",
        attempt=1,
        timeout_seconds=60,
    )

    result = asyncio.run(handle_asset_priority_recalculation_job(ctx, db_session))
    assert result["processed"] == 2
    assert "p1_count" in result
    assert "p4_count" in result


# ---------------------------------------------------------------------------
# TEST 13: SOC OVERVIEW TOP PRIORITIZED ASSETS INTEGRATION
# ---------------------------------------------------------------------------
def test_soc_overview_integration(db_session):
    # Create a high priority asset
    create_test_asset(
        db_session,
        canonical_name="critical-gateway.corp.io",
        risk_score=95.0,
        criticality="CRITICAL",
        exposure_state="PUBLICLY_EXPOSED",
    )
    AssetPrioritizationService.recalculate_workspace_priorities(db_session, "test_ws")

    overview = SocDashboardService.get_overview(db_session, workspace_id="test_ws")
    assert hasattr(overview, "highest_priority_assets")
    assert len(overview.highest_priority_assets) > 0
    top_asset = overview.highest_priority_assets[0]
    assert "critical-gateway" in top_asset["canonical_name"]
    assert top_asset["effective_priority"] in ["P1", "P2"]


# ---------------------------------------------------------------------------
# TEST 14: REST API FULL LIFECYCLE
# ---------------------------------------------------------------------------
def test_prioritization_api_lifecycle(db_session, test_client):
    client = test_client
    asset = create_test_asset(db_session, canonical_name="api-test.corp")
    AssetPrioritizationService.recalculate_workspace_priorities(db_session, "test_ws")

    headers = {"X-Workspace-Id": "test_ws", "X-Role": "admin"}

    # 1. List assets
    r = client.get("/api/v1/prioritization/assets", headers=headers)
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    assert "p1_count" in data

    # 2. Get explanation
    r = client.get(f"/api/v1/prioritization/assets/{asset.id}/explanation", headers=headers)
    assert r.status_code == 200
    expl = r.json()
    assert expl["asset_id"] == asset.id
    assert len(expl["contributors"]) > 0

    # 3. Apply override
    r = client.post(
        f"/api/v1/prioritization/assets/{asset.id}/override",
        headers=headers,
        json={"priority": "P1", "reason": "VIP host drill", "expires_in_hours": 12},
    )
    assert r.status_code == 200
    assert r.json()["effective_priority"] == "P1"

    # 4. History
    r = client.get(f"/api/v1/prioritization/assets/{asset.id}/history", headers=headers)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1

    # 5. Remove override
    r = client.delete(f"/api/v1/prioritization/assets/{asset.id}/override", headers=headers)
    assert r.status_code == 200

    # 6. Recalculate
    r = client.post("/api/v1/prioritization/recalculate", headers=headers, json={})
    assert r.status_code == 200
    assert r.json()["status"] == "COMPLETED"

    # 7. Policies
    r = client.get("/api/v1/prioritization/policies", headers=headers)
    assert r.status_code == 200
    assert len(r.json()) >= 1

    # 8. Overview
    r = client.get("/api/v1/prioritization/overview", headers=headers)
    assert r.status_code == 200
    assert "top_assets" in r.json()


# ---------------------------------------------------------------------------
# TEST 15: MULTI-TENANT WORKSPACE ISOLATION
# ---------------------------------------------------------------------------
def test_multi_tenant_workspace_isolation(db_session, test_client):
    client = test_client

    # Asset in Tenant A
    asset_a = create_test_asset(db_session, workspace_id="tenant_a", canonical_name="vault.tenant_a.internal")
    # Asset in Tenant B
    asset_b = create_test_asset(db_session, workspace_id="tenant_b", canonical_name="vault.tenant_b.internal")

    AssetPrioritizationService.recalculate_workspace_priorities(db_session, "tenant_a")
    AssetPrioritizationService.recalculate_workspace_priorities(db_session, "tenant_b")

    # Tenant A lists assets: should only see asset_a
    r_a = client.get(
        "/api/v1/prioritization/assets",
        headers={"X-Workspace-Id": "tenant_a", "X-Role": "analyst"},
    )
    assert r_a.status_code == 200
    ids_a = [item["id"] for item in r_a.json()["items"]]
    assert asset_a.id in ids_a
    assert asset_b.id not in ids_a

    # Tenant A attempts to access asset_b: 404
    r_leak = client.get(
        f"/api/v1/prioritization/assets/{asset_b.id}/explanation",
        headers={"X-Workspace-Id": "tenant_a", "X-Role": "analyst"},
    )
    assert r_leak.status_code == 404

    # Tenant A attempts to override asset_b: 400 or 404
    r_override = client.post(
        f"/api/v1/prioritization/assets/{asset_b.id}/override",
        headers={"X-Workspace-Id": "tenant_a", "X-Role": "analyst"},
        json={"priority": "P1", "reason": "Cross-tenant intrusion attempt"},
    )
    assert r_override.status_code in [400, 404]
