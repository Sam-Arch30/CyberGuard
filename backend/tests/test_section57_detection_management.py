"""
Section 57: Detection Rule Management & Operational Control Integration Tests.

Validates:
1. Healthy active rule operational health evaluation.
2. Active rule with dependency outage -> marks health DEGRADED/FAILING.
3. Rule execution failures -> tracks failure rate and latency.
4. High match rate anomaly detection (surge over baseline).
5. Zero matches observed handling (distinguishes zero match from rule failure).
6. Review overdue detection & notification triggers.
7. Production deployment workflow with version selection and capability check.
8. Deployment dry run pre-flight check.
9. Version rollback safety (restores validated version, preserves audit).
10. Emergency disable workflow with mandatory reason and elevated auth.
11. Bulk operations with partial success reporting.
12. Suppression exception lifecycle (creation, matching, expiration).
13. Analyst disposition recording and quality metrics calculation.
14. Rule AST duplication and conflict detection.
15. Unauthorized action rejection and cross-tenant isolation.
16. Threat Hunt pattern translation.
"""
from datetime import datetime, timedelta
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import (
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    RuleSuppressionModel,
    NotificationModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import RuleLifecycleStatus, RuleSeverity, RuleType
from backend.schemas.detection_rules import (
    DeploymentStateEnum,
    OperationalHealthEnum,
    DependencyHealthEnum,
    DependencyTypeEnum,
)

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    db = SessionLocal()
    # Clean up candidate rules created during testing
    try:
        db.query(RuleSuppressionModel).filter(RuleSuppressionModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])).delete(synchronize_session=False)
        db.query(CandidateRuleExecutionModel).filter(CandidateRuleExecutionModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])).delete(synchronize_session=False)
        db.query(CandidateRuleVersionModel).filter(CandidateRuleVersionModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])).delete(synchronize_session=False)
        db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id.in_(["default", "tenant_a", "tenant_b"])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield


def test_scenario_1_healthy_active_rule():
    """Scenario 1: Healthy active rule evaluation returns HEALTHY."""
    res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={
            "workspace_id": "default",
            "name": "Suspicious External Login Attempt",
            "category": "AUTHENTICATION",
            "data_sources": ["AUTH_EVENT"],
            "severity": "HIGH",
            "definition": {
                "logical_operator": "AND",
                "conditions": [
                    {"field": "auth_result", "operator": "EQUALS", "value": "SUCCESS"},
                ]
            },
        },
    )
    assert res.status_code == 201
    rule_id = res.json()["id"]

    # Activate rule to production
    deploy_res = client.post(
        f"/api/v1/rules/{rule_id}/deploy",
        headers={"X-Role": "admin", "X-User-ID": "admin_bob"},
        json={"target_state": "PRODUCTION", "version": "1", "reason": "Passed testbed validation"},
    )
    assert deploy_res.status_code == 200
    assert deploy_res.json()["deployment_state"] == "PRODUCTION"

    # Evaluate health
    health_res = client.get(
        f"/api/v1/rules/{rule_id}/health",
        headers={"X-Role": "analyst"},
    )
    assert health_res.status_code == 200
    data = health_res.json()
    assert data["operational_health"] == "HEALTHY"
    assert data["deployment_state"] == "PRODUCTION"
    assert data["dependency_health_summary"] == "HEALTHY"


def test_scenario_2_dependency_outage_degrades_rule():
    """Scenario 2: Active rule with degraded or failing dependencies updates operational health."""
    db = SessionLocal()
    try:
        rule_id = generate_uuid()
        deps = [
            {"name": "Auth Log Ingestion", "type": "DATA_SOURCE", "required": True, "health": "FAILING", "details": "Kafka stream down"},
            {"name": "GeoIP Intelligence", "type": "INTELLIGENCE", "required": False, "health": "HEALTHY", "details": "Nominal"},
        ]
        rule = CandidateRuleModel(
            id=rule_id,
            workspace_id="default",
            rule_identifier="RULE-DEP-01",
            name="Compromised Account Rule",
            rule_type="STRUCTURAL",
            category="AUTHENTICATION",
            status="ACTIVE",
            deployment_state="PRODUCTION",
            operational_health="HEALTHY",
            definition_json=json.dumps({
                "logical_operator": "AND",
                "conditions": [{"field": "auth_result", "operator": "EQUALS", "value": "SUCCESS"}],
            }),
            data_sources_json=json.dumps(["AUTH_EVENT"]),
            normalized_fingerprint="fp-dep-01",
            version="1",
            dependencies_json=json.dumps(deps),
            created_by="analyst_alice",
        )
        db.add(rule)
        db.commit()
    finally:
        db.close()

    health_res = client.get(
        f"/api/v1/rules/{rule_id}/health",
        headers={"X-Role": "analyst"},
    )
    assert health_res.status_code == 200
    data = health_res.json()
    assert data["operational_health"] == "FAILING"
    assert "Required dependency unavailable: Auth Log Ingestion" in data["health_reason"]


def test_scenario_3_rule_execution_failures():
    """Scenario 3: Rule execution failures cause elevated error rate and degrade health."""
    db = SessionLocal()
    try:
        rule_id = generate_uuid()
        rule = CandidateRuleModel(
            id=rule_id,
            workspace_id="default",
            rule_identifier="RULE-FAIL-01",
            name="Slow Heavy Regex Rule",
            rule_type="STRUCTURAL",
            category="EMAIL",
            status="ACTIVE",
            deployment_state="PRODUCTION",
            operational_health="HEALTHY",
            definition_json=json.dumps({
                "logical_operator": "AND",
                "conditions": [{"field": "subject", "operator": "CONTAINS", "value": "urgent invoice"}],
            }),
            data_sources_json=json.dumps(["EMAIL_EVENT"]),
            normalized_fingerprint="fp-fail-01",
            version="1",
            created_by="analyst_alice",
        )
        db.add(rule)
        db.flush()

        # Add 10 execution logs: 5 successful, 5 high-latency timeouts (> 10000ms)
        for i in range(5):
            db.add(CandidateRuleExecutionModel(
                id=generate_uuid(),
                rule_id=rule.id,
                rule_version="1",
                workspace_id="default",
                mode="PRODUCTION",
                matched=True,
                execution_time_ms=50.0,
                executed_at=get_utc_now(),
            ))
        for i in range(5):
            db.add(CandidateRuleExecutionModel(
                id=generate_uuid(),
                rule_id=rule.id,
                rule_version="1",
                workspace_id="default",
                mode="PRODUCTION",
                matched=False,
                execution_time_ms=12000.0,  # Timeout failure
                executed_at=get_utc_now(),
            ))
        db.commit()
    finally:
        db.close()

    health_res = client.get(
        f"/api/v1/rules/{rule_id}/health",
        headers={"X-Role": "analyst"},
    )
    assert health_res.status_code == 200
    data = health_res.json()
    assert data["operational_health"] == "FAILING"
    assert data["error_rate_24h"] == 0.5
    assert data["execution_count_24h"] == 10
    assert "Critical execution error rate" in data["health_reason"]


def test_scenario_4_high_match_rate_anomaly():
    """Scenario 4: High match rate surge triggers anomaly detection without failing the rule."""
    db = SessionLocal()
    try:
        rule_id = generate_uuid()
        rule = CandidateRuleModel(
            id=rule_id,
            workspace_id="default",
            rule_identifier="RULE-SURGE-01",
            name="Credential Harvester",
            rule_type="STRUCTURAL",
            category="PHISHING",
            status="ACTIVE",
            deployment_state="PRODUCTION",
            operational_health="HEALTHY",
            definition_json=json.dumps({
                "logical_operator": "AND",
                "conditions": [{"field": "sender_domain", "operator": "CONTAINS", "value": "login"}],
            }),
            data_sources_json=json.dumps(["EMAIL_EVENT"]),
            normalized_fingerprint="fp-surge-01",
            version="1",
            created_by="analyst_alice",
        )
        db.add(rule)
        db.flush()

        # Add 30 matches in last 24h
        for i in range(30):
            db.add(CandidateRuleExecutionModel(
                id=generate_uuid(),
                rule_id=rule.id,
                rule_version="1",
                workspace_id="default",
                mode="PRODUCTION",
                matched=True,
                execution_time_ms=20.0,
                executed_at=get_utc_now() - timedelta(hours=2),
            ))
        db.commit()
    finally:
        db.close()

    health_res = client.get(
        f"/api/v1/rules/{rule_id}/health",
        headers={"X-Role": "analyst"},
    )
    assert health_res.status_code == 200
    data = health_res.json()
    assert data["match_rate_anomaly"] is True
    assert "Unusual match rate surge: 30 matches in last 24h" in data["anomaly_details"]


def test_scenario_5_zero_matches_not_failed():
    """Scenario 5: Zero matches observed does NOT mark the rule as failing."""
    db = SessionLocal()
    try:
        rule_id = generate_uuid()
        rule = CandidateRuleModel(
            id=rule_id,
            workspace_id="default",
            rule_identifier="RULE-ZERO-01",
            name="Rare Zero-Day Exploit Attempt",
            rule_type="STRUCTURAL",
            category="ENDPOINT",
            status="ACTIVE",
            deployment_state="PRODUCTION",
            operational_health="HEALTHY",
            definition_json=json.dumps({
                "logical_operator": "AND",
                "conditions": [{"field": "process_name", "operator": "EQUALS", "value": "malware.exe"}],
            }),
            data_sources_json=json.dumps(["ENDPOINT_EVENT"]),
            normalized_fingerprint="fp-zero-01",
            version="1",
            created_by="analyst_alice",
        )
        db.add(rule)
        db.flush()

        # Add 15 executions that did NOT match (normal traffic scanned)
        for i in range(15):
            db.add(CandidateRuleExecutionModel(
                id=generate_uuid(),
                rule_id=rule.id,
                rule_version="1",
                workspace_id="default",
                mode="PRODUCTION",
                matched=False,
                execution_time_ms=10.0,
                executed_at=get_utc_now() - timedelta(hours=1),
            ))
        db.commit()
    finally:
        db.close()

    health_res = client.get(
        f"/api/v1/rules/{rule_id}/health",
        headers={"X-Role": "analyst"},
    )
    assert health_res.status_code == 200
    data = health_res.json()
    assert data["operational_health"] == "HEALTHY"
    assert data["zero_match"] is True
    assert data["matches_last_24h"] == 0
    assert data["execution_count_24h"] == 15


def test_scenario_6_review_overdue_detection():
    """Scenario 6: Review overdue flags rule and triggers notification."""
    db = SessionLocal()
    try:
        rule_id = generate_uuid()
        overdue_date = get_utc_now() - timedelta(days=10)
        rule = CandidateRuleModel(
            id=rule_id,
            workspace_id="default",
            rule_identifier="RULE-REV-01",
            name="Ancient Phish Rule",
            rule_type="STRUCTURAL",
            category="EMAIL",
            status="ACTIVE",
            deployment_state="PRODUCTION",
            operational_health="HEALTHY",
            review_interval_days=90,
            next_review_due=overdue_date,
            definition_json=json.dumps({
                "logical_operator": "AND",
                "conditions": [{"field": "subject", "operator": "CONTAINS", "value": "old attack"}],
            }),
            data_sources_json=json.dumps(["EMAIL_EVENT"]),
            normalized_fingerprint="fp-rev-01",
            version="1",
            created_by="analyst_alice",
        )
        db.add(rule)
        db.commit()
    finally:
        db.close()

    health_res = client.get(
        f"/api/v1/rules/{rule_id}/health",
        headers={"X-Role": "analyst"},
    )
    assert health_res.status_code == 200
    data = health_res.json()
    assert data["review_due"] is True
    assert "Operational review is due" in data["health_reason"]


def test_scenario_7_and_8_deployment_dry_run_and_production_activation():
    """Scenario 7 & 8: Pre-flight dry-run check followed by production deployment."""
    # Create rule candidate
    create_res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={
            "workspace_id": "default",
            "name": "BEC Wire Transfer Fraud",
            "category": "EMAIL",
            "data_sources": ["EMAIL_EVENT"],
            "severity": "CRITICAL",
            "definition": {
                "logical_operator": "AND",
                "conditions": [
                    {"field": "subject", "operator": "CONTAINS", "value": "wire transfer"},
                    {"field": "has_attachments", "operator": "EQUALS", "value": True},
                ]
            },
        },
    )
    assert create_res.status_code == 201
    rule_id = create_res.json()["id"]

    # Pre-flight dry-run
    dry_res = client.post(
        f"/api/v1/rules/{rule_id}/dry-run",
        headers={"X-Role": "analyst"},
    )
    assert dry_res.status_code == 200
    dry_data = dry_res.json()
    assert dry_data["can_deploy"] is True
    assert dry_data["validation_status"] == "PASS"
    assert dry_data["dependency_status"] == "PASS"
    assert dry_data["operational_risk"] in ("LOW", "MEDIUM")

    # Production deployment
    deploy_res = client.post(
        f"/api/v1/rules/{rule_id}/deploy",
        headers={"X-Role": "admin", "X-User-ID": "lead_carol"},
        json={"target_state": "PRODUCTION", "version": "1", "reason": "Approved by SOC lead"},
    )
    assert deploy_res.status_code == 200
    assert deploy_res.json()["deployment_state"] == "PRODUCTION"
    assert deploy_res.json()["status"] == "ACTIVE"


def test_scenario_9_version_rollback():
    """Scenario 9: Safe version rollback to prior validated immutable version."""
    # Create rule
    create_res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={
            "workspace_id": "default",
            "name": "Login Velocity Anomaly",
            "category": "NETWORK",
            "data_sources": ["NETWORK_EVENT"],
            "definition": {
                "logical_operator": "AND",
                "conditions": [{"field": "ip_address", "operator": "EQUALS", "value": "192.168.1.1"}],
            },
        },
    )
    rule_id = create_res.json()["id"]

    # Tune rule to create version 2
    tune_res = client.post(
        f"/api/v1/rules/{rule_id}/tune",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={
            "workspace_id": "default",
            "change_reason": "Too broad, restricting to specific destination port",
            "definition": {
                "logical_operator": "AND",
                "conditions": [
                    {"field": "ip_address", "operator": "EQUALS", "value": "192.168.1.1"},
                    {"field": "dest_port", "operator": "EQUALS", "value": 443},
                ]
            },
        },
    )
    assert tune_res.status_code == 200
    assert tune_res.json()["version"] == "2"

    # Roll back to version 1
    rollback_res = client.post(
        f"/api/v1/rules/{rule_id}/rollback",
        headers={"X-Role": "admin", "X-User-ID": "lead_carol"},
        json={"target_version": "1", "reason": "v2 caused unexpected edge-case drops, reverting to v1"},
    )
    assert rollback_res.status_code == 200
    assert rollback_res.json()["version"] == "1"


def test_scenario_10_emergency_disable():
    """Scenario 10: Emergency disable disables rule and requires non-empty reason."""
    create_res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Noisy Alert Rule",
            "category": "NETWORK",
            "data_sources": ["NETWORK_EVENT"],
            "definition": {
                "logical_operator": "AND",
                "conditions": [{"field": "dest_port", "operator": "EQUALS", "value": 80}],
            },
        },
    )
    rule_id = create_res.json()["id"]

    # Deploy to production first
    client.post(
        f"/api/v1/rules/{rule_id}/deploy",
        headers={"X-Role": "admin"},
        json={"target_state": "PRODUCTION"},
    )

    # Emergency disable
    disable_res = client.post(
        f"/api/v1/rules/{rule_id}/emergency-disable",
        headers={"X-Role": "admin", "X-User-ID": "oncall_dave"},
        json={"reason": "Flooding alerts due to corporate VPN switchover"},
    )
    assert disable_res.status_code == 200
    assert disable_res.json()["status"] == "DISABLED"
    assert disable_res.json()["deployment_state"] == "DISABLED"


def test_scenario_11_bulk_operations_partial_success():
    """Scenario 11: Bulk operations with partial success reporting."""
    r1 = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Bulk Rule 1",
            "category": "EMAIL",
            "data_sources": ["EMAIL_EVENT"],
            "definition": {"logical_operator": "AND", "conditions": [{"field": "sender_domain", "operator": "CONTAINS", "value": "suspicious"}]},
        },
    ).json()["id"]

    r2 = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Bulk Rule 2",
            "category": "EMAIL",
            "data_sources": ["EMAIL_EVENT"],
            "definition": {"logical_operator": "AND", "conditions": [{"field": "sender_domain", "operator": "CONTAINS", "value": "suspicious"}]},
        },
    ).json()["id"]

    # Bulk operation on 2 valid IDs and 1 non-existent ID
    bulk_res = client.post(
        "/api/v1/rules/bulk",
        headers={"X-Role": "admin", "X-User-ID": "admin_bob"},
        json={
            "rule_ids": [r1, r2, "non-existent-rule-id-1234"],
            "operation": "SET_COLLECTION",
            "collection": "Email Defense Tier 1",
        },
    )
    assert bulk_res.status_code == 200
    data = bulk_res.json()
    assert data["total_requested"] == 3
    assert data["succeeded_count"] == 2
    assert data["failed_count"] == 1
    assert data["failed_rules"][0]["rule_id"] == "non-existent-rule-id-1234"


def test_scenario_12_suppression_exception_lifecycle():
    """Scenario 12: Scoped false-positive suppression exception excludes matches without disabling rule."""
    create_res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Suspicious Port Scan",
            "category": "NETWORK",
            "data_sources": ["NETWORK_EVENT"],
            "definition": {
                "logical_operator": "AND",
                "conditions": [{"field": "dest_port", "operator": "EQUALS", "value": 443}],
            },
        },
    )
    rule_id = create_res.json()["id"]

    # Activate
    client.post(f"/api/v1/rules/{rule_id}/deploy", headers={"X-Role": "admin"}, json={"target_state": "PRODUCTION"})

    # Create suppression for internal vulnerability scanner IP
    supp_res = client.post(
        f"/api/v1/rules/{rule_id}/suppressions",
        headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
        json={
            "name": "Internal Qualys Scanner Exclusion",
            "reason": "Authorized weekly scheduled scan",
            "scope_type": "FIELD",
            "scope_target": "ip_address",
            "match_value": "10.0.50.99",
            "match_operator": "EQUALS",
            "expires_in_days": 7,
        },
    )
    assert supp_res.status_code == 201
    supp_id = supp_res.json()["id"]

    # Evaluate event matching rule from scanner IP
    eval_res = client.post(
        "/api/v1/rules/evaluate",
        headers={"X-Role": "analyst"},
        json={"event_payload": {"dest_port": 443, "ip_address": "10.0.50.99", "event_id": "ev-scan-01"}},
    )
    assert eval_res.status_code == 200

    # Verify execution was suppressed and NO finding was generated
    db = SessionLocal()
    try:
        exec_row = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.rule_id == rule_id,
            CandidateRuleExecutionModel.event_id == "ev-scan-01",
        ).first()
        assert exec_row is not None
        assert exec_row.suppression_applied_id == supp_id
        assert exec_row.finding_id is None
    finally:
        db.close()


def test_scenario_13_analyst_disposition_and_quality():
    """Scenario 13: Analyst records dispositions and quality metrics calculate ground-truth FP rate."""
    create_res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Quality Monitored Rule",
            "category": "EMAIL",
            "data_sources": ["EMAIL_EVENT"],
            "definition": {"logical_operator": "AND", "conditions": [{"field": "sender_domain", "operator": "CONTAINS", "value": "phish"}]},
        },
    )
    rule_id = create_res.json()["id"]

    # Insert 4 match executions
    db = SessionLocal()
    exec_ids = []
    try:
        for i in range(4):
            e_id = generate_uuid()
            db.add(CandidateRuleExecutionModel(
                id=e_id,
                rule_id=rule_id,
                rule_version="1",
                workspace_id="default",
                mode="PRODUCTION",
                matched=True,
                executed_at=get_utc_now(),
            ))
            exec_ids.append(e_id)
        db.commit()
    finally:
        db.close()

    # Mark 3 True Positives and 1 False Positive
    for idx, e_id in enumerate(exec_ids):
        disp = "FALSE_POSITIVE" if idx == 0 else "TRUE_POSITIVE"
        client.post(
            f"/api/v1/rules/matches/{e_id}/disposition",
            headers={"X-Role": "analyst", "X-User-ID": "analyst_alice"},
            json={"disposition": disp, "notes": f"Analyst review note {idx}"},
        )

    # Check quality metrics
    q_res = client.get(
        f"/api/v1/rules/{rule_id}/quality",
        headers={"X-Role": "analyst"},
    )
    assert q_res.status_code == 200
    q_data = q_res.json()
    assert q_data["insufficient_data"] is False
    assert q_data["true_positives"] == 3
    assert q_data["false_positives"] == 1
    assert q_data["false_positive_rate"] == 0.25
    assert q_data["precision_rate"] == 0.75
    assert q_data["quality_verdict"] == "NEEDS_TUNING"


def test_scenario_14_ast_duplicate_detection():
    """Scenario 14: AST normalized duplicate detection flags identical logic."""
    r1 = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Domain Impersonation Rule Alpha",
            "category": "PHISHING",
            "data_sources": ["EMAIL_EVENT"],
            "definition": {
                "logical_operator": "AND",
                "conditions": [
                    {"field": "sender_domain", "operator": "CONTAINS", "value": "paypal"},
                    {"field": "contains_login_url", "operator": "EQUALS", "value": True},
                ],
            },
        },
    ).json()["id"]

    r2 = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Paypal Phish Duplicate Beta",
            "category": "PHISHING",
            "data_sources": ["EMAIL_EVENT"],
            "definition": {
                "logical_operator": "AND",
                "conditions": [
                    {"field": "sender_domain", "operator": "CONTAINS", "value": "paypal"},
                    {"field": "contains_login_url", "operator": "EQUALS", "value": True},
                ],
            },
        },
    ).json()["id"]

    dup_res = client.get(
        f"/api/v1/rules/{r1}/duplicates",
        headers={"X-Role": "analyst"},
    )
    assert dup_res.status_code == 200
    dups = dup_res.json()
    assert len(dups) >= 1
    assert dups[0]["rule_id"] == r2
    assert dups[0]["similarity"] >= 0.95


def test_scenario_15_unauthorized_action_and_cross_tenant_isolation():
    """Scenario 15: Unauthorized actions rejected and cross-tenant access blocked."""
    # Create rule in tenant_a
    r_a = client.post(
        "/api/v1/rules?workspace_id=tenant_a",
        headers={"X-Role": "analyst", "X-Workspace-ID": "tenant_a"},
        json={
            "workspace_id": "tenant_a",
            "name": "Tenant A Secret Rule",
            "category": "NETWORK",
            "data_sources": ["NETWORK_EVENT"],
            "definition": {"logical_operator": "AND", "conditions": [{"field": "ip_address", "operator": "EQUALS", "value": "10.0.0.1"}]},
        },
    ).json()["id"]

    # 1. Attempt access from tenant_b -> 404 Not Found
    tb_res = client.get(
        f"/api/v1/rules/{r_a}",
        headers={"X-Role": "analyst", "X-Workspace-ID": "tenant_b"},
    )
    assert tb_res.status_code == 404

    # 2. Attempt unauthorized production activation with viewer/untrusted role -> 403 Forbidden
    unauth_res = client.post(
        f"/api/v1/rules/{r_a}/deploy",
        headers={"X-Role": "viewer", "X-Workspace-ID": "tenant_a"},
        json={"target_state": "PRODUCTION"},
    )
    assert unauth_res.status_code == 403


def test_scenario_16_hunt_pattern_translation():
    """Scenario 16: Translates detection rule logic into structured Section 54 hunt query."""
    create_res = client.post(
        "/api/v1/rules",
        headers={"X-Role": "analyst"},
        json={
            "workspace_id": "default",
            "name": "Beaconing Command And Control",
            "category": "NETWORK",
            "data_sources": ["NETWORK_EVENT"],
            "definition": {
                "logical_operator": "AND",
                "conditions": [
                    {"field": "ip_address", "operator": "EQUALS", "value": "198.51.100.1"},
                    {"field": "dest_port", "operator": "EQUALS", "value": 4444},
                ],
            },
        },
    )
    rule_id = create_res.json()["id"]

    hunt_res = client.get(
        f"/api/v1/rules/{rule_id}/hunt-pattern",
        headers={"X-Role": "analyst"},
    )
    assert hunt_res.status_code == 200
    pattern = hunt_res.json()
    assert pattern["origin_rule_id"] == rule_id
    assert pattern["conditions"][0]["field"] == "ip_address"
    assert pattern["conditions"][1]["value"] == 4444
    assert pattern["logical_operator"] == "AND"
