"""
Section 54: Test Suite for Threat Hunting Workspace & Query Engine.
Validates:
1. Data Source Registry integrity and field allowlists
2. Type-safe query validation & explainable plan generation
3. Deterministic query execution across Indicators, Alerts, Findings, Intelligence
4. Server-side aggregations and Top-N grouping
5. Saved Hunts CRUD and automated template seeding
6. Natural language query translation heuristics
7. Investigation and Watchlist handoffs
8. Multi-tenant isolation boundaries
9. REST API endpoints
"""
from datetime import datetime, timedelta, timezone
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from backend.db.session import get_db
from backend.db.models import (
    Base,
    get_utc_now,
    IndicatorModel,
    NotificationModel,
    FindingModel,
    ThreatIntelligenceRecordModel,
    IntelligenceChangeModel,
    WatchlistModel,
    WatchedIndicatorModel,
    IncidentModel,
    SavedHuntModel,
    HuntExecutionModel,
)
from backend.schemas.hunting import (
    HuntSourceEnum,
    QueryOperatorEnum,
    TimePresetEnum,
    HuntVisibilityEnum,
    HuntExecutionModeEnum,
    QueryFilter,
    QueryTimeRange,
    QuerySort,
    HuntQueryDefinition,
    HuntExecutionRequest,
    SavedHuntCreateRequest,
    SavedHuntUpdateRequest,
    NaturalLanguageHuntRequest,
    HuntInvestigationHandoffRequest,
    HuntWatchlistHandoffRequest,
)
from backend.services.threat_hunting_service import ThreatHuntingService
from backend.main import app

# In-memory SQLite with StaticPool for test isolation
TEST_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    test_client = TestClient(app)
    yield test_client
    app.dependency_overrides.pop(get_db, None)


# =============================================================================
# 1. Registry & Validation Tests
# =============================================================================

def test_data_source_registry_completeness():
    """Verifies that all core CyberGuard datasets are registered with valid field definitions."""
    registry = ThreatHuntingService.get_data_source_registry(workspace_id="test-ws")
    sources = {s.key: s for s in registry.sources}

    assert HuntSourceEnum.INDICATORS in sources
    assert HuntSourceEnum.ALERTS in sources
    assert HuntSourceEnum.FINDINGS in sources
    assert HuntSourceEnum.ARTIFACTS in sources
    assert HuntSourceEnum.THREAT_INTELLIGENCE in sources
    assert HuntSourceEnum.WATCHLIST_CHANGES in sources
    assert HuntSourceEnum.INCIDENTS in sources

    ind_src = sources[HuntSourceEnum.INDICATORS]
    field_names = [f.name for f in ind_src.fields]
    assert "indicator_type" in field_names
    assert "normalized_value" in field_names
    assert "reputation" in field_names
    assert "last_seen" in field_names


def test_query_validation_success_and_query_plan():
    """Validates that a well-structured query passes validation and generates a detailed query plan."""
    qdef = HuntQueryDefinition(
        data_source=HuntSourceEnum.INDICATORS,
        filters=[
            QueryFilter(field="indicator_type", operator=QueryOperatorEnum.EQUALS, value="DOMAIN"),
            QueryFilter(field="reputation", operator=QueryOperatorEnum.IN, value=["MALICIOUS", "SUSPICIOUS"]),
        ],
        time_range=QueryTimeRange(preset=TimePresetEnum.D7),
        limit=50,
    )

    res = ThreatHuntingService.validate_query(qdef, workspace_id="ws-1")
    assert res.is_valid is True
    assert len(res.errors) == 0
    assert len(res.query_plan) >= 3
    assert res.estimated_cost in ("LOW", "MEDIUM")


def test_query_validation_rejects_unsupported_fields_and_sql_injection():
    """Ensures queries with non-allowlisted fields or incompatible operators are strictly rejected."""
    # 1. Non-existent / secret field
    q_bad_field = HuntQueryDefinition(
        data_source=HuntSourceEnum.INDICATORS,
        filters=[
            QueryFilter(field="password_hash", operator=QueryOperatorEnum.EQUALS, value="secret123"),
        ],
    )
    res1 = ThreatHuntingService.validate_query(q_bad_field, workspace_id="ws-1")
    assert res1.is_valid is False
    assert any("not queryable" in err for err in res1.errors)

    # 2. Incompatible operator (e.g. numeric comparison on string)
    q_bad_op = HuntQueryDefinition(
        data_source=HuntSourceEnum.INDICATORS,
        filters=[
            QueryFilter(field="normalized_value", operator=QueryOperatorEnum.GREATER_THAN, value="example.com"),
        ],
    )
    res2 = ThreatHuntingService.validate_query(q_bad_op, workspace_id="ws-1")
    assert res2.is_valid is False
    assert any("not supported" in err for err in res2.errors)


# =============================================================================
# 2. Query Execution Tests
# =============================================================================

def test_query_execution_indicators(db_session):
    """Verifies querying indicator records with deterministic results and explainability."""
    now = get_utc_now()
    i1 = IndicatorModel(
        id="ind-hunt-1",
        indicator_type="DOMAIN",
        value="evil-phish.com",
        normalized_value="evil-phish.com",
        reputation="MALICIOUS",
        confidence=0.98,
        first_seen=now - timedelta(days=2),
        last_seen=now,
    )
    i2 = IndicatorModel(
        id="ind-hunt-2",
        indicator_type="IP",
        value="198.51.100.42",
        normalized_value="198.51.100.42",
        reputation="CLEAN",
        confidence=0.90,
        first_seen=now - timedelta(days=3),
        last_seen=now,
    )
    db_session.add_all([i1, i2])
    db_session.commit()

    qdef = HuntQueryDefinition(
        data_source=HuntSourceEnum.INDICATORS,
        filters=[
            QueryFilter(field="indicator_type", operator=QueryOperatorEnum.EQUALS, value="DOMAIN"),
            QueryFilter(field="reputation", operator=QueryOperatorEnum.EQUALS, value="MALICIOUS"),
        ],
        time_range=QueryTimeRange(preset=TimePresetEnum.D7),
        limit=10,
    )

    req = HuntExecutionRequest(query_definition=qdef)
    res = ThreatHuntingService.execute_hunt(db_session, "ws-test", req)

    assert res.status == "SUCCEEDED"
    assert res.total_matches >= 1
    found_ids = [item.id for item in res.items]
    assert "ind-hunt-1" in found_ids
    assert "ind-hunt-2" not in found_ids

    # Verify explainability on matched item
    matched_item = next(it for it in res.items if it.id == "ind-hunt-1")
    assert matched_item.verdict == "MALICIOUS"
    assert matched_item.primary_value == "evil-phish.com"
    assert len(matched_item.matched_reasons) > 0
    assert matched_item.pivot_links.get("osint_url") is not None


def test_query_execution_alerts(db_session):
    """Verifies querying Section 48 Security Alerts."""
    now = get_utc_now()
    a1 = NotificationModel(
        id="notif-hunt-1",
        workspace_id="ws-test",
        category="SECURITY_ALERT",
        notification_type="SUSPICIOUS_BEACON",
        severity="CRITICAL",
        status="UNREAD",
        title="Critical C2 Outbound Traffic Detected",
        message="Active command and control beacon observed",
        created_at=now,
    )
    a2 = NotificationModel(
        id="notif-hunt-2",
        workspace_id="ws-test",
        category="SECURITY_ALERT",
        notification_type="LOGIN_ANOMALY",
        severity="LOW",
        status="READ",
        title="Minor login deviation",
        message="Non-standard user agent",
        created_at=now,
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    qdef = HuntQueryDefinition(
        data_source=HuntSourceEnum.ALERTS,
        filters=[
            QueryFilter(field="severity", operator=QueryOperatorEnum.EQUALS, value="CRITICAL"),
        ],
        time_range=QueryTimeRange(preset=TimePresetEnum.D7),
        limit=10,
    )

    res = ThreatHuntingService.execute_hunt(db_session, "ws-test", HuntExecutionRequest(query_definition=qdef))
    assert res.total_matches >= 1
    ids = [it.id for it in res.items]
    assert "notif-hunt-1" in ids
    assert "notif-hunt-2" not in ids


def test_query_aggregations_and_grouping(db_session):
    """Verifies server-side group-by aggregation and percentage calculations."""
    now = get_utc_now()
    for idx, rep in enumerate(["MALICIOUS", "MALICIOUS", "SUSPICIOUS", "CLEAN"]):
        db_session.add(
            IndicatorModel(
                id=f"ind-agg-{idx}",
                indicator_type="DOMAIN",
                value=f"domain-{idx}.com",
                normalized_value=f"domain-{idx}.com",
                reputation=rep,
                confidence=0.9,
                first_seen=now,
                last_seen=now,
            )
        )
    db_session.commit()

    qdef = HuntQueryDefinition(
        data_source=HuntSourceEnum.INDICATORS,
        filters=[
            QueryFilter(field="indicator_type", operator=QueryOperatorEnum.EQUALS, value="DOMAIN"),
        ],
        group_by="reputation",
        top_n=5,
        limit=20,
    )

    res = ThreatHuntingService.execute_hunt(db_session, "ws-test", HuntExecutionRequest(query_definition=qdef))
    assert res.aggregations is not None
    assert "reputation" in res.aggregations
    rep_buckets = {b.key: b for b in res.aggregations["reputation"]}
    assert "MALICIOUS" in rep_buckets
    assert rep_buckets["MALICIOUS"].count >= 2


# =============================================================================
# 3. Saved Hunts & Templates Tests
# =============================================================================

def test_saved_hunts_crud_and_template_seeding(db_session):
    """Verifies that templates are seeded and custom hunts can be created, updated, and deleted."""
    # List should automatically seed templates
    listing = ThreatHuntingService.list_saved_hunts(db_session, "ws-test")
    assert len(listing.templates) >= 3
    tpl_names = [t.name for t in listing.templates]
    assert any("Newly Malicious" in n for n in tpl_names)

    # Create new custom saved hunt
    create_req = SavedHuntCreateRequest(
        name="Custom Phishing Hunt",
        description="Tracks suspicious phishing observables",
        data_source=HuntSourceEnum.INDICATORS,
        query_definition=HuntQueryDefinition(
            data_source=HuntSourceEnum.INDICATORS,
            filters=[
                QueryFilter(field="reputation", operator=QueryOperatorEnum.EQUALS, value="SUSPICIOUS")
            ],
            limit=25,
        ),
        hypothesis="Targeted domains masquerading as corporate login portals.",
        tags=["phishing", "brand-abuse"],
        visibility=HuntVisibilityEnum.TEAM,
    )

    created = ThreatHuntingService.create_saved_hunt(db_session, "ws-test", create_req, actor="analyst_bob")
    assert created.id is not None
    assert created.name == "Custom Phishing Hunt"
    assert created.is_template is False

    # Update
    updated = ThreatHuntingService.update_saved_hunt(
        db_session, "ws-test", created.id, SavedHuntUpdateRequest(name="Renamed Phishing Hunt")
    )
    assert updated.name == "Renamed Phishing Hunt"

    # Delete
    del_ok = ThreatHuntingService.delete_saved_hunt(db_session, "ws-test", created.id)
    assert del_ok is True


# =============================================================================
# 4. Natural Language Assistant
# =============================================================================

def test_natural_language_to_query_translation():
    """Verifies that natural language questions map to valid, bounded Query DSL representations."""
    req = NaturalLanguageHuntRequest(prompt="Find all high severity domains observed in the last 24 hours")
    res = ThreatHuntingService.natural_language_to_query(req)

    assert res.proposed_query.data_source == HuntSourceEnum.INDICATORS
    assert res.proposed_query.time_range.preset == TimePresetEnum.H24
    filter_fields = [f.field for f in res.proposed_query.filters]
    assert "indicator_type" in filter_fields


# =============================================================================
# 5. Handoffs: Investigation & Watchlist
# =============================================================================

def test_investigation_and_watchlist_handoffs(db_session):
    """Verifies converting hunt results into an investigation and adding to a Section 53 Watchlist."""
    now = get_utc_now()
    ind = IndicatorModel(
        id="ind-handoff-1",
        indicator_type="DOMAIN",
        value="c2-stealth.org",
        normalized_value="c2-stealth.org",
        reputation="MALICIOUS",
        confidence=0.99,
        first_seen=now,
        last_seen=now,
    )
    exec_rec = HuntExecutionModel(
        id="exec-handoff-1",
        workspace_id="ws-test",
        data_source="indicators",
        query_definition_json=HuntQueryDefinition(data_source=HuntSourceEnum.INDICATORS).model_dump_json(),
        execution_mode="FAST",
        status="SUCCEEDED",
        result_count=1,
        matched_record_ids_json=json.dumps(["ind-handoff-1"]),
        executed_by="analyst_alice",
        started_at=now,
    )
    db_session.add_all([ind, exec_rec])
    db_session.commit()

    # 1. Investigation handoff
    inv_req = HuntInvestigationHandoffRequest(
        execution_id="exec-handoff-1",
        selected_record_ids=["ind-handoff-1"],
        investigation_title="Automated Hunt Incident",
        reason="Suspicious C2 beaconing observed",
    )
    inv_res = ThreatHuntingService.handoff_to_investigation(db_session, "ws-test", inv_req, actor="analyst_alice")
    assert inv_res.success is True
    assert inv_res.investigation_id is not None

    # Verify incident persisted
    inc = db_session.query(IncidentModel).filter(IncidentModel.id == inv_res.investigation_id).first()
    assert inc is not None
    assert "Automated Hunt Incident" in inc.title

    # 2. Watchlist handoff
    wl_req = HuntWatchlistHandoffRequest(
        execution_id="exec-handoff-1",
        selected_record_ids=["ind-handoff-1"],
        new_watchlist_name="Hunt C2 Observables",
        reason="Continuous monitoring required",
    )
    wl_res = ThreatHuntingService.handoff_to_watchlist(db_session, "ws-test", wl_req, actor="analyst_alice")
    assert wl_res.success is True
    assert wl_res.added_indicators_count == 1


# =============================================================================
# 6. Multi-Tenant Isolation
# =============================================================================

def test_multi_tenant_isolation_hunting(db_session):
    """Guarantees that a query in tenant-A cannot return alerts or saved hunts from tenant-B."""
    now = get_utc_now()
    a_tenant = NotificationModel(
        id="alert-tenant-a",
        workspace_id="tenant-a",
        category="SECURITY_ALERT",
        notification_type="TEST",
        severity="HIGH",
        status="UNREAD",
        title="Tenant A Private Alert",
        message="Confidential alert",
        created_at=now,
    )
    b_tenant = NotificationModel(
        id="alert-tenant-b",
        workspace_id="tenant-b",
        category="SECURITY_ALERT",
        notification_type="TEST",
        severity="HIGH",
        status="UNREAD",
        title="Tenant B Private Alert",
        message="Confidential alert",
        created_at=now,
    )
    db_session.add_all([a_tenant, b_tenant])
    db_session.commit()

    qdef = HuntQueryDefinition(
        data_source=HuntSourceEnum.ALERTS,
        filters=[QueryFilter(field="severity", operator=QueryOperatorEnum.EQUALS, value="HIGH")],
        limit=50,
    )

    res_a = ThreatHuntingService.execute_hunt(db_session, "tenant-a", HuntExecutionRequest(query_definition=qdef))
    ids_a = [item.id for item in res_a.items]
    assert "alert-tenant-a" in ids_a
    assert "alert-tenant-b" not in ids_a


# =============================================================================
# 7. REST API Endpoints
# =============================================================================

def test_rest_api_hunting_routes(client):
    """Verifies all FastAPI routes for threat hunting."""
    headers = {"X-Workspace-ID": "ws-api-test", "X-User-ID": "test_analyst"}

    # 1. Get Registry
    resp = client.get("/hunting/registry", headers=headers)
    assert resp.status_code == 200
    assert len(resp.json()["sources"]) > 0

    # 2. Validate Query
    val_payload = {
        "data_source": "indicators",
        "filters": [
            {"field": "indicator_type", "operator": "equals", "value": "DOMAIN"}
        ],
        "limit": 10
    }
    resp = client.post("/hunting/validate", json=val_payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["is_valid"] is True

    # 3. Execute Query (Fast mode)
    exec_payload = {
        "query_definition": val_payload,
        "execution_mode": "FAST"
    }
    resp = client.post("/hunting/execute", json=exec_payload, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "SUCCEEDED"

    # 4. Saved Hunts CRUD
    saved_payload = {
        "name": "API Saved Hunt",
        "description": "Created via REST test",
        "data_source": "indicators",
        "query_definition": val_payload,
        "hypothesis": "Test hypothesis",
        "tags": ["api-test"],
        "visibility": "TEAM"
    }
    resp = client.post("/hunting/saved", json=saved_payload, headers=headers)
    assert resp.status_code == 201
    hunt_id = resp.json()["id"]

    # List saved hunts
    resp = client.get("/hunting/saved", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] >= 1

    # Delete saved hunt
    resp = client.delete(f"/hunting/saved/{hunt_id}", headers=headers)
    assert resp.status_code == 204

    # 5. Assistant route
    asst_payload = {"prompt": "Show malicious domains in the last 7 days"}
    resp = client.post("/hunting/assistant", json=asst_payload, headers=headers)
    assert resp.status_code == 200
    assert "proposed_query" in resp.json()
