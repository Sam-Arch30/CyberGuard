"""
Section 58: Automated Detection Validation & Continuous Rule Quality Tests.

Validates the full Section 58 specification including all critical semantic cases:
1. Semantic Case 1: Rule executes successfully, 0 matches, healthy data source -> PASS (NOT FAIL).
2. Semantic Case 2: Rule executes successfully, match volume surge over historical baseline -> WARNING / REGRESSION (NOT FAIL).
3. Semantic Case 3: Required dependency unavailable -> BLOCKED (NOT NO MATCHES, NOT clean).
4. Semantic Case 4: Rule syntax invalid -> FAIL (AST_SYNTAX_INVALID).
5. Semantic Case 5: Evaluator timeout -> TIMED_OUT (Never PASS).
6. Semantic Case 6: Realtime publisher failure does not compromise backend validation completion.
7. Semantic Case 7: Rule version updated -> marks prior validation STALE.
8. Semantic Case 8: Validation request deduplication with idempotency key.
9. Production Promotion Gate: Unvalidated or failed rule blocked from PRODUCTION promotion; validated PASS rule allowed.
10. Deterministic Test Fixtures: Positive and negative test case evaluation and regression detection.
11. Data Compatibility & Schema Drift: Detection of unregistered or removed schema fields.
12. Multi-tenant Isolation & RBAC: Cross-tenant isolation on validation runs, gates, and fixtures.
13. Validation Run Cancellation: Cancels queued/active runs cleanly.
14. SOC Overview: Authoritative continuous quality metrics from real persisted runs.
"""
from datetime import datetime, timedelta
import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import (
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    DetectionValidationRunModel,
    DetectionValidationResultModel,
    DetectionRuleTestFixtureModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import RuleLifecycleStatus, RuleSeverity, RuleType
from backend.schemas.detection_rules import (
    DeploymentStateEnum,
    OperationalHealthEnum,
    ValidationStatusEnum,
    ValidationTypeEnum,
)
from backend.services.detection_rule_validation_service import (
    DetectionRuleValidationService,
)
from backend.services.detection_rule_management_service import (
    DetectionRuleManagementService,
)
from backend.services.detection_rule_lifecycle_service import (
    DetectionRuleLifecycleService,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    db = SessionLocal()
    try:
        db.query(DetectionRuleTestFixtureModel).filter(
            DetectionRuleTestFixtureModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])
        ).delete(synchronize_session=False)
        db.query(DetectionValidationResultModel).filter(
            DetectionValidationResultModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])
        ).delete(synchronize_session=False)
        db.query(DetectionValidationRunModel).filter(
            DetectionValidationRunModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])
        ).delete(synchronize_session=False)
        db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])
        ).delete(synchronize_session=False)
        db.query(CandidateRuleVersionModel).filter(
            CandidateRuleVersionModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])
        ).delete(synchronize_session=False)
        db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])
        ).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield


# =============================================================================
# Helper to create valid candidate rules for testing
# =============================================================================

def _create_test_rule(
    name: str = "Test Phishing Domain Rule",
    category: str = "EMAIL",
    data_sources: list = None,
    conditions: list = None,
    workspace_id: str = "default",
    version: str = "v1",
) -> str:
    if data_sources is None:
        data_sources = ["EMAIL_EVENT"]
    if conditions is None:
        conditions = [
            {"field": "sender_domain", "operator": "CONTAINS", "value": "attacker.com"},
            {"field": "has_attachments", "operator": "EQUALS", "value": True},
        ]

    res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_bob", "X-Workspace-ID": workspace_id},
        json={
            "workspace_id": workspace_id,
            "name": name,
            "category": category,
            "data_sources": data_sources,
            "severity": "HIGH",
            "scope": "EMAIL",
            "rule_type": "STRUCTURAL",
            "definition": {
                "source": data_sources[0],
                "logical_operator": "AND",
                "conditions": conditions,
            },
        },
    )
    assert res.status_code == 201, f"Failed to create rule: {res.text}"
    return res.json()["id"]


# =============================================================================
# 1. CRITICAL SEMANTIC TESTS (SECTION 64)
# =============================================================================

def test_semantic_case_1_zero_matches_healthy_datasource():
    """
    Critical Case 1: Rule executes successfully with 0 matches on a healthy data source.
    Expected: PASS (NOT FAIL!).
    """
    rule_id = _create_test_rule(name="Zero Matches Legitimate Rule")

    res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "trigger_type": "MANUAL", "run_async": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("PASS", "PASS_WITH_WARNINGS")
    assert data["status"] != "FAIL", "Zero matches on healthy rule must NOT be FAIL!"

    # Verify check items include ZERO_MATCHES_HEALTHY
    check_codes = [c["code"] for c in data["checks"]]
    assert "ZERO_MATCHES_HEALTHY" in check_codes or "FP_RATE_ACCEPTABLE" in check_codes or "INSUFFICIENT_DISPOSITION_EVIDENCE" in check_codes


def test_semantic_case_2_match_volume_surge_regression_warning():
    """
    Critical Case 2: Rule executes with 10,000 matches while baseline was 20.
    Expected: WARNING / REGRESSION (NOT automatically FAIL).
    """
    rule_id = _create_test_rule(name="Match Surge Rule")
    db = SessionLocal()
    try:
        now = get_utc_now()
        # Seed 20 historical matches 30h ago (baseline window)
        for _ in range(20):
            db.add(
                CandidateRuleExecutionModel(
                    id=generate_uuid(),
                    rule_id=rule_id,
                    rule_version="v1",
                    workspace_id="default",
                    mode="PRODUCTION",
                    matched=True,
                    executed_at=now - timedelta(hours=30),
                )
            )
        # Seed 500 current matches in last 24h
        for _ in range(500):
            db.add(
                CandidateRuleExecutionModel(
                    id=generate_uuid(),
                    rule_id=rule_id,
                    rule_version="v1",
                    workspace_id="default",
                    mode="PRODUCTION",
                    matched=True,
                    executed_at=now - timedelta(hours=2),
                )
            )
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "trigger_type": "MANUAL", "run_async": False},
    )
    assert res.status_code == 200
    data = res.json()
    # Surge is flagged as warning, not outright structural failure
    assert data["status"] == "PASS_WITH_WARNINGS"
    assert data["status"] != "FAIL"
    codes = [c["code"] for c in data["checks"]]
    assert "MATCH_RATE_SURGE" in codes


def test_semantic_case_3_required_dependency_unavailable():
    """
    Critical Case 3: Required dependency is unavailable.
    Expected: BLOCKED (NOT NO MATCHES, NOT clean).
    """
    rule_id = _create_test_rule(name="Behavioral Anomaly Rule", category="BEHAVIORAL")

    # Mock dependency resolver to return FAILING baseline engine
    from backend.schemas.detection_rules import RuleDependency, DependencyHealthEnum, DependencyTypeEnum
    mock_deps = [
        RuleDependency(
            name="Behavioral Baseline Engine",
            type=DependencyTypeEnum.BASELINE,
            required=True,
            health=DependencyHealthEnum.FAILING,
            details="Baseline service crashed",
        )
    ]

    with patch.object(DetectionRuleManagementService, "_resolve_rule_dependencies", return_value=mock_deps):
        res = client.post(
            f"/api/v1/rules/{rule_id}/validation",
            headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
            json={"validation_type": "FULL", "trigger_type": "MANUAL", "run_async": False},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "BLOCKED"
        codes = [c["code"] for c in data["checks"]]
        assert "REQUIRED_DEPENDENCY_UNAVAILABLE" in codes


def test_semantic_case_4_invalid_rule_syntax():
    """
    Critical Case 4: Rule syntax invalid.
    Expected: FAIL.
    """
    rule_id = _create_test_rule(name="Syntax Test Rule")
    db = SessionLocal()
    try:
        rule = db.query(CandidateRuleModel).filter(CandidateRuleModel.id == rule_id).first()
        # Corrupt definition with empty conditions and nested groups
        rule.definition_json = json.dumps({"source": "EMAIL_EVENT", "logical_operator": "AND", "conditions": []})
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "trigger_type": "MANUAL", "run_async": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FAIL"
    codes = [c["code"] for c in data["checks"]]
    assert "AST_SYNTAX_INVALID" in codes


def test_semantic_case_5_evaluator_timeout_guard():
    """
    Critical Case 5: Evaluator times out during execution.
    Expected: TIMED_OUT / FAIL (Never PASS).
    """
    rule_id = _create_test_rule(name="Timeout Test Rule")

    # Patch evaluator execution to simulate exceeding 5.0 seconds SLA
    def _slow_eval(*args, **kwargs):
        import time
        time.sleep(0.05)  # fast sleep in test
        return {"matched": False}

    with patch("backend.services.detection_rule_validation_service.EXECUTION_TIMEOUT_SECONDS", 0.01):
        with patch.object(DetectionRuleLifecycleService, "_evaluate_ast_against_record", side_effect=_slow_eval):
            res = client.post(
                f"/api/v1/rules/{rule_id}/validation",
                headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
                json={"validation_type": "FULL", "trigger_type": "MANUAL", "run_async": False},
            )
            assert res.status_code == 200
            data = res.json()
            assert data["status"] == "TIMED_OUT"
            codes = [c["code"] for c in data["checks"]]
            assert "EVALUATOR_TIMEOUT" in codes


def test_semantic_case_6_realtime_failure_backend_still_completes():
    """
    Critical Case 6: Realtime publisher raises error, backend validation still completes authoritative state.
    """
    rule_id = _create_test_rule(name="Realtime Resilient Rule")

    with patch("backend.services.realtime_service.RealtimePublisher.publish_event", side_effect=RuntimeError("Websocket down")):
        res = client.post(
            f"/api/v1/rules/{rule_id}/validation",
            headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
            json={"validation_type": "FULL", "trigger_type": "MANUAL", "run_async": False},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] in ("PASS", "PASS_WITH_WARNINGS")


def test_semantic_case_7_old_validation_becomes_stale_on_version_update():
    """
    Critical Case 7: Old validation exists, rule version changed -> OLD RESULT = STALE.
    """
    rule_id = _create_test_rule(name="Stale Transition Rule")

    # 1. Run initial validation
    res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "trigger_type": "MANUAL", "run_async": False},
    )
    assert res.status_code == 200
    assert res.json()["status"] in ("PASS", "PASS_WITH_WARNINGS")

    # 2. Mark stale via version change / stale detector
    db = SessionLocal()
    try:
        stale_count = DetectionRuleValidationService.detect_and_mark_stale(
            db=db,
            rule_id=rule_id,
            reason="Rule version updated to v2",
            workspace_id="default",
        )
        assert stale_count >= 1
    finally:
        db.close()

    # 3. Query rule state
    rule_res = client.get(
        f"/api/v1/rules/{rule_id}",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
    )
    assert rule_res.status_code == 200
    assert rule_res.json()["validation_status"] == "STALE"


def test_semantic_case_8_idempotency_deduplication():
    """
    Critical Case 8: Validation requested twice with same idempotency key -> No duplicate execution.
    """
    rule_id = _create_test_rule(name="Idempotency Test Rule")
    idemp_key = "idemp-val-12345"

    res1 = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "idempotency_key": idemp_key, "run_async": False},
    )
    assert res1.status_code == 200
    run1_id = res1.json()["id"]

    # Second request with same idempotency key
    res2 = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "idempotency_key": idemp_key, "run_async": False},
    )
    assert res2.status_code == 200
    run2_id = res2.json()["id"]

    assert run1_id == run2_id, "Idempotent requests must return identical validation run record."


# =============================================================================
# 2. PRODUCTION PROMOTION GATE TESTS
# =============================================================================

def test_deployment_gate_blocks_unvalidated_rule():
    """
    Rule that has NOT_RUN validation status cannot be promoted to PRODUCTION.
    """
    rule_id = _create_test_rule(name="Unvalidated Gate Rule")

    # Gate check endpoint
    gate_res = client.get(
        f"/api/v1/rules/{rule_id}/validation/gate",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
    )
    assert gate_res.status_code == 200
    assert gate_res.json()["can_promote"] is False
    assert "NOT_RUN" in gate_res.json()["blocking_reasons"][0]

    # Attempting to deploy to PRODUCTION must be blocked with 400
    deploy_res = client.post(
        f"/api/v1/rules/{rule_id}/deploy",
        headers={"X-Role": "approver", "X-User-ID": "lead_bob"},
        json={"target_state": "PRODUCTION", "reason": "Deploy without validation"},
    )
    assert deploy_res.status_code == 400
    assert "validation gate check blocked" in deploy_res.json()["detail"]


def test_deployment_gate_allows_validated_rule():
    """
    Rule with passing validation status is allowed to promote to PRODUCTION.
    """
    rule_id = _create_test_rule(name="Validated Gate Rule")

    # Run validation
    val_res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "run_async": False},
    )
    assert val_res.status_code == 200
    assert val_res.json()["status"] in ("PASS", "PASS_WITH_WARNINGS")

    # Check gate
    gate_res = client.get(
        f"/api/v1/rules/{rule_id}/validation/gate",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
    )
    assert gate_res.status_code == 200
    assert gate_res.json()["can_promote"] is True

    # Promotion to PRODUCTION succeeds
    deploy_res = client.post(
        f"/api/v1/rules/{rule_id}/deploy",
        headers={"X-Role": "approver", "X-User-ID": "lead_bob"},
        json={"target_state": "PRODUCTION", "reason": "Validated rule promotion"},
    )
    assert deploy_res.status_code == 200
    assert deploy_res.json()["deployment_state"] == "PRODUCTION"


# =============================================================================
# 3. DETERMINISTIC TEST FIXTURES (POSITIVE & NEGATIVE)
# =============================================================================

def test_positive_and_negative_test_fixtures():
    """
    Test positive fixture (expected match) and negative fixture (expected non-match).
    """
    rule_id = _create_test_rule(name="Fixture Evaluation Rule")

    # 1. Create Positive Fixture (attacker domain -> expected match: True)
    pos_res = client.post(
        f"/api/v1/rules/{rule_id}/fixtures",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={
            "name": "Attacker Domain Positive Test",
            "description": "Must match known malicious domain",
            "fixture_type": "POSITIVE",
            "expected_match": True,
            "payload": {
                "sender_domain": "attacker.com",
                "has_attachments": True,
            },
        },
    )
    assert pos_res.status_code == 200
    pos_id = pos_res.json()["id"]

    # 2. Create Negative Fixture (legitimate domain -> expected match: False)
    neg_res = client.post(
        f"/api/v1/rules/{rule_id}/fixtures",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={
            "name": "Internal Corp Negative Test",
            "description": "Must NOT match legitimate internal communications",
            "fixture_type": "NEGATIVE",
            "expected_match": False,
            "payload": {
                "sender_domain": "corp.internal",
                "has_attachments": True,
            },
        },
    )
    assert neg_res.status_code == 200
    neg_id = neg_res.json()["id"]

    # 3. Execute individual fixtures
    run_pos = client.post(
        f"/api/v1/rules/{rule_id}/fixtures/{pos_id}/run",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
    )
    assert run_pos.status_code == 200
    assert run_pos.json()["last_result"] == "PASS"

    run_neg = client.post(
        f"/api/v1/rules/{rule_id}/fixtures/{neg_id}/run",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
    )
    assert run_neg.status_code == 200
    assert run_neg.json()["last_result"] == "PASS"

    # 4. Trigger full validation run which evaluates all fixtures automatically
    full_val = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "run_async": False},
    )
    assert full_val.status_code == 200
    codes = [c["code"] for c in full_val.json()["checks"]]
    assert "ALL_FIXTURES_PASSED" in codes


# =============================================================================
# 4. DATA COMPATIBILITY & SCHEMA DRIFT
# =============================================================================

def test_schema_drift_missing_field_detection():
    """
    Detection of unallowlisted / removed schema fields flags SCHEMA_DRIFT_FIELD_MISSING.
    """
    rule_id = _create_test_rule(name="Drift Test Rule")
    db = SessionLocal()
    try:
        rule = db.query(CandidateRuleModel).filter(CandidateRuleModel.id == rule_id).first()
        # Insert a condition with a field that does not exist in DATA_SOURCE_FIELD_REGISTRY
        rule.definition_json = json.dumps({
            "source": "EMAIL_EVENT",
            "logical_operator": "AND",
            "conditions": [
                {"field": "nonexistent_deprecated_field_xyz", "operator": "EQUALS", "value": "test"}
            ],
        })
        db.commit()
    finally:
        db.close()

    res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "run_async": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "FAIL"
    codes = [c["code"] for c in data["checks"]]
    assert "SCHEMA_DRIFT_FIELD_MISSING" in codes


# =============================================================================
# 5. MULTI-TENANT ISOLATION & RBAC
# =============================================================================

def test_cross_tenant_validation_isolation():
    """
    Tenant A cannot access, validate, or inspect Tenant B's detection rules or fixtures.
    """
    # Create rule in tenant_a
    rule_id = _create_test_rule(name="Tenant A Secret Rule", workspace_id="tenant_a")

    # Tenant B attempts to run validation
    res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_mallory", "X-Workspace-ID": "tenant_b"},
        json={"validation_type": "FULL"},
    )
    assert res.status_code == 404, "Tenant B must not see or validate Tenant A's rule!"

    # Tenant B attempts to fetch fixtures
    fix_res = client.get(
        f"/api/v1/rules/{rule_id}/fixtures",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_mallory", "X-Workspace-ID": "tenant_b"},
    )
    assert fix_res.status_code == 404


# =============================================================================
# 6. VALIDATION CANCELLATION
# =============================================================================

def test_validation_run_cancellation():
    """
    Authoritative cancellation of in-progress or queued validation runs.
    """
    rule_id = _create_test_rule(name="Cancellable Validation Rule")

    # Request async run
    res = client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "run_async": True},
    )
    assert res.status_code == 200
    run_id = res.json()["id"]

    # Cancel run
    cancel_res = client.post(
        f"/api/v1/rules/validation/runs/{run_id}/cancel",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"


# =============================================================================
# 7. CONTINUOUS QUALITY SWEEP & OVERVIEW STATS
# =============================================================================

def test_continuous_quality_sweep_and_overview():
    """
    Sweeps active and staged rules, verifies overview metrics reflect real counts.
    """
    rule_id = _create_test_rule(name="Continuous Quality Rule")

    # Run validation once
    client.post(
        f"/api/v1/rules/{rule_id}/validation",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={"validation_type": "FULL", "run_async": False},
    )

    # Fetch SOC Overview
    overview_res = client.get(
        "/api/v1/rules/validation/overview",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
    )
    assert overview_res.status_code == 200
    ov = overview_res.json()
    assert ov["total_rules"] >= 1
    assert (ov["passed_rules"] + ov["warning_rules"]) >= 1
    assert ov["total_validation_runs_24h"] >= 1

    # Execute continuous sweep
    db = SessionLocal()
    try:
        sweep_res = DetectionRuleValidationService.continuous_quality_sweep(db, "default")
        assert "rules_checked" in sweep_res
    finally:
        db.close()
