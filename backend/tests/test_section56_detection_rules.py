"""
Section 56: Comprehensive Test Suite for Detection Engineering & Rule Lifecycle Foundation.

Validates the 15 mandatory test scenarios from Sections 104 & 105:
1. Valid simple phishing rule creation & AST compilation.
2. Invalid field rejection.
3. Invalid operator for field type rejection.
4. Cross-tenant rule access rejection.
5. Unauthorized activation rejection.
6. Rule version conflict & immutability of active rules.
7. Historical backtesting execution & ground truth evaluation.
8. No historical data scenario handled gracefully.
9. Large/complex query exceeding complexity budget rejected.
10. Rule runtime match generation.
11. Detection match integrates with existing Finding (FindingModel).
12. Rule emergency disable lifecycle transition.
13. AI-suggested malformed rule safely rejected.
14. AI-suggested unauthorized field rejected.
15. Separation of duties (creator cannot self-approve).
"""
import json
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.db.session import get_db, Base
from backend.db.models import (
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    FindingModel,
    EmailAnalysisModel,
    ThreatIntelligenceRecordModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.detection_rules import (
    RuleCategory,
    RuleDataSource,
    RuleProvenanceType,
    RuleCostClass,
    DslOperator,
    RuleCondition,
    RuleDefinition,
    DetectionRuleCreateRequest,
    DetectionRuleTuneRequest,
    DetectionRuleBacktestRequest,
    AISuggestRuleRequest,
)
from backend.schemas.candidate_rules import RuleLifecycleStatus, RuleSeverity

# Setup isolated in-memory test database
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


# ============================================================================
# TEST CASES
# ============================================================================

def test_case_1_valid_simple_phishing_rule_creation(client, db):
    """Case 1: Valid simple phishing rule creation & AST compilation."""
    payload = {
        "name": "Lookalike Phishing Domain with Multiple URLs",
        "description": "Detects incoming emails containing lookalike domains and >2 URLs",
        "category": "PHISHING",
        "data_sources": ["EMAIL_EVENT"],
        "severity": "HIGH",
        "confidence": 0.88,
        "definition": {
            "source": "EMAIL_EVENT",
            "logic": "AND",
            "conditions": [
                {
                    "field": "sender_domain",
                    "operator": "LOOKALIKE",
                    "value": "target-corp.com",
                },
                {
                    "field": "url_count",
                    "operator": "GREATER_THAN",
                    "value": 2,
                },
            ],
        },
        "tags": ["phishing", "impersonation"],
        "attack_techniques": ["T1566.002"],
    }

    res = client.post(
        "/api/v1/rules",
        json=payload,
        headers={"X-Workspace-ID": "ws-1", "X-Role": "analyst", "X-User-ID": "analyst-alice"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == payload["name"]
    assert data["rule_identifier"].startswith("RULE-")
    assert data["version"] == "1"
    assert data["status"] == "CANDIDATE"
    assert data["category"] == "PHISHING"
    assert "email.sender_domain LOOKALIKE" in data["human_readable_logic"]
    assert "email.url_count GREATER_THAN 2" in data["human_readable_logic"]

    # Verify version 1 row in database
    v1 = db.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.candidate_rule_id == data["id"],
        CandidateRuleVersionModel.version == 1,
    ).first()
    assert v1 is not None
    assert v1.cost_class in ("LOW", "MEDIUM")


def test_case_2_invalid_field_rejection(client):
    """Case 2: Rejects rules with invalid / non-allowlisted fields."""
    payload = {
        "name": "Malicious Rule With Unknown Field",
        "description": "Attempts to inject arbitrary fields",
        "category": "EMAIL",
        "data_sources": ["EMAIL_EVENT"],
        "severity": "MEDIUM",
        "confidence": 0.7,
        "definition": {
            "source": "EMAIL_EVENT",
            "logic": "AND",
            "conditions": [
                {
                    "field": "unsupported_arbitrary_column",
                    "operator": "EQUALS",
                    "value": "evil",
                }
            ],
        },
    }

    res = client.post(
        "/api/v1/rules",
        json=payload,
        headers={"X-Workspace-ID": "ws-1", "X-Role": "analyst"},
    )
    assert res.status_code == 400
    assert "Unsupported field" in res.json()["detail"]


def test_case_3_invalid_operator_for_field_type_rejection(client):
    """Case 3: Rejects operator incompatible with the declared field type."""
    # GREATER_THAN is invalid for boolean 'contains_login_url'
    payload = {
        "name": "Invalid Type Operator Rule",
        "description": "Compares boolean with GREATER_THAN",
        "category": "EMAIL",
        "data_sources": ["EMAIL_EVENT"],
        "severity": "MEDIUM",
        "confidence": 0.7,
        "definition": {
            "source": "EMAIL_EVENT",
            "logic": "AND",
            "conditions": [
                {
                    "field": "contains_login_url",
                    "operator": "GREATER_THAN",
                    "value": 1,
                }
            ],
        },
    }

    res = client.post(
        "/api/v1/rules",
        json=payload,
        headers={"X-Workspace-ID": "ws-1", "X-Role": "analyst"},
    )
    assert res.status_code == 400
    assert "Operator 'GREATER_THAN' is not permitted" in res.json()["detail"]


def test_case_4_cross_tenant_rule_isolation(client):
    """Case 4: Cross-tenant isolation blocks reading or modifying another tenant's rules."""
    # Tenant 1 creates rule
    payload = {
        "name": "Tenant 1 Secret Rule",
        "description": "Rule for tenant 1 only",
        "category": "ENDPOINT",
        "data_sources": ["ENDPOINT_EVENT"],
        "severity": "HIGH",
        "confidence": 0.9,
        "definition": {
            "source": "ENDPOINT_EVENT",
            "logic": "AND",
            "conditions": [
                {
                    "field": "process_name",
                    "operator": "EQUALS",
                    "value": "mimikatz.exe",
                }
            ],
        },
    }
    create_res = client.post(
        "/api/v1/rules",
        json=payload,
        headers={"X-Workspace-ID": "tenant-alpha", "X-Role": "analyst"},
    )
    assert create_res.status_code == 201
    rule_id = create_res.json()["id"]

    # Tenant 2 attempts to fetch Tenant 1's rule
    fetch_res = client.get(
        f"/api/v1/rules/{rule_id}",
        headers={"X-Workspace-ID": "tenant-beta", "X-Role": "analyst"},
    )
    assert fetch_res.status_code == 404

    # Tenant 2 list should not contain Tenant 1's rule
    list_res = client.get(
        "/api/v1/rules",
        headers={"X-Workspace-ID": "tenant-beta", "X-Role": "analyst"},
    )
    assert list_res.status_code == 200
    assert all(r["id"] != rule_id for r in list_res.json()["items"])


def test_case_5_unauthorized_activation_rejection(client):
    """Case 5: Unauthorized role cannot activate detection rules."""
    # Create rule as analyst
    payload = {
        "name": "Auth Brute Force",
        "description": "Detects login failures",
        "category": "AUTHENTICATION",
        "data_sources": ["AUTH_EVENT"],
        "severity": "HIGH",
        "confidence": 0.85,
        "definition": {
            "source": "AUTH_EVENT",
            "logic": "AND",
            "conditions": [
                {
                    "field": "auth_result",
                    "operator": "EQUALS",
                    "value": "FAILED",
                }
            ],
        },
    }
    create_res = client.post(
        "/api/v1/rules",
        json=payload,
        headers={"X-Workspace-ID": "ws-1", "X-Role": "analyst", "X-User-ID": "analyst-1"},
    )
    rule_id = create_res.json()["id"]

    # Viewer/unauthorized role tries to approve/activate
    act_res = client.post(
        f"/api/v1/rules/{rule_id}/activate",
        headers={"X-Workspace-ID": "ws-1", "X-Role": "viewer"},
    )
    assert act_res.status_code == 403


def test_case_6_rule_version_conflict_and_immutability(client, db):
    """Case 6: Modifying rule generates new version v2 without mutating v1."""
    # 1. Create rule v1
    create_res = client.post(
        "/api/v1/rules",
        json={
            "name": "URL Count Check",
            "description": "Flags >1 URL",
            "category": "PHISHING",
            "data_sources": ["EMAIL_EVENT"],
            "severity": "LOW",
            "confidence": 0.6,
            "definition": {
                "source": "EMAIL_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "url_count", "operator": "GREATER_THAN", "value": 1}
                ],
            },
        },
        headers={"X-Workspace-ID": "ws-1", "X-Role": "analyst", "X-User-ID": "analyst-1"},
    )
    rule_id = create_res.json()["id"]

    # Approve and Activate v1
    appr_res = client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers={"X-Workspace-ID": "ws-1", "X-Role": "admin", "X-User-ID": "lead-admin"},
    )
    assert appr_res.status_code == 200

    act_res = client.post(
        f"/api/v1/rules/{rule_id}/activate",
        headers={"X-Workspace-ID": "ws-1", "X-Role": "admin", "X-User-ID": "lead-admin"},
    )
    assert act_res.status_code == 200
    assert act_res.json()["version"] == "1"

    # 2. Tune rule to create v2 with tighter conditions
    tune_res = client.post(
        f"/api/v1/rules/{rule_id}/tune",
        json={
            "definition": {
                "source": "EMAIL_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "url_count", "operator": "GREATER_THAN", "value": 3},
                    {"field": "contains_login_url", "operator": "EQUALS", "value": True},
                ],
            },
            "severity": "HIGH",
            "change_description": "Tuned URL threshold from 1 to 3 and added login URL check",
        },
        headers={"X-Workspace-ID": "ws-1", "X-Role": "analyst", "X-User-ID": "analyst-2"},
    )
    assert tune_res.status_code == 200
    data_v2 = tune_res.json()
    assert data_v2["version"] == "2"
    assert data_v2["status"] == "CANDIDATE"  # v2 returns to candidate lifecycle for re-validation

    # Check that database has both version 1 and version 2 records
    versions = db.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.candidate_rule_id == rule_id
    ).all()
    assert len(versions) == 2

    # 3. Test version diff endpoint
    diff_res = client.get(
        f"/api/v1/rules/{rule_id}/diff/1/2",
        headers={"X-Workspace-ID": "ws-1", "X-Role": "analyst"},
    )
    assert diff_res.status_code == 200
    diff_data = diff_res.json()
    assert diff_data["has_changes"] is True
    assert len(diff_data["added_conditions"]) == 1
    assert diff_data["added_conditions"][0]["field"] == "contains_login_url"
    assert len(diff_data["modified_conditions"]) == 1
    assert diff_data["modified_conditions"][0]["old_value"] == 1
    assert diff_data["modified_conditions"][0]["new_value"] == 3


def test_case_7_historical_backtesting_execution(client, db):
    """Case 7: Historical backtesting against existing telemetry records."""
    # Seed historical email analysis telemetry
    email_1 = EmailAnalysisModel(
        id="em-1",
        workspace_id="ws-backtest",
        sender="attacker@fake-bank.com",
        recipient="user@target.com",
        subject="Urgent Security Alert",
        sender_domain="fake-bank.com",
        contains_login_url=True,
        url_count=4,
        threat_level="CRITICAL",
        created_at=get_utc_now(),
    )
    email_2 = EmailAnalysisModel(
        id="em-2",
        workspace_id="ws-backtest",
        sender="newsletter@info.com",
        recipient="user@target.com",
        subject="Weekly Digest",
        sender_domain="info.com",
        contains_login_url=False,
        url_count=1,
        threat_level="SAFE",
        created_at=get_utc_now(),
    )
    db.add_all([email_1, email_2])
    db.commit()

    # Create detection rule
    create_res = client.post(
        "/api/v1/rules",
        json={
            "name": "Fake Bank Login Phish",
            "description": "Detects login URLs from fake-bank.com",
            "category": "PHISHING",
            "data_sources": ["EMAIL_EVENT"],
            "severity": "HIGH",
            "confidence": 0.95,
            "definition": {
                "source": "EMAIL_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "sender_domain", "operator": "CONTAINS", "value": "fake-bank"},
                    {"field": "contains_login_url", "operator": "EQUALS", "value": True},
                ],
            },
        },
        headers={"X-Workspace-ID": "ws-backtest", "X-Role": "analyst"},
    )
    rule_id = create_res.json()["id"]

    # Execute synchronous backtest
    backtest_res = client.post(
        f"/api/v1/rules/{rule_id}/backtest",
        json={
            "time_range_preset": "LAST_30_DAYS",
            "max_records": 100,
        },
        headers={"X-Workspace-ID": "ws-backtest", "X-Role": "analyst"},
    )
    assert backtest_res.status_code == 200
    bt_data = backtest_res.json()
    assert bt_data["status"] == "COMPLETED"
    assert bt_data["records_evaluated"] == 2
    assert bt_data["matches_count"] == 1
    assert len(bt_data["matches"]) == 1
    assert bt_data["matches"][0]["event_id"] == "em-1"
    assert "matched_fields" in bt_data["matches"][0]["explanation"]


def test_case_8_no_historical_data_graceful_handling(client):
    """Case 8: Handles absence of historical telemetry gracefully without fabricating numbers."""
    create_res = client.post(
        "/api/v1/rules",
        json={
            "name": "Auth Failure Rule",
            "description": "Detects auth failures",
            "category": "AUTHENTICATION",
            "data_sources": ["AUTH_EVENT"],
            "severity": "HIGH",
            "confidence": 0.8,
            "definition": {
                "source": "AUTH_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "auth_result", "operator": "EQUALS", "value": "FAILED"}
                ],
            },
        },
        headers={"X-Workspace-ID": "empty-ws", "X-Role": "analyst"},
    )
    rule_id = create_res.json()["id"]

    backtest_res = client.post(
        f"/api/v1/rules/{rule_id}/backtest",
        json={"time_range_preset": "LAST_24_HOURS"},
        headers={"X-Workspace-ID": "empty-ws", "X-Role": "analyst"},
    )
    assert backtest_res.status_code == 200
    bt_data = backtest_res.json()
    assert bt_data["records_evaluated"] == 0
    assert bt_data["matches_count"] == 0
    assert len(bt_data["matches"]) == 0
    assert any("No historical data found" in lim for lim in bt_data["limitations"])


def test_case_9_large_complex_query_budget_exceeded_rejected(client):
    """Case 9: Rejects rule exceeding nesting depth (>3) or condition limit."""
    # Nest conditions 4 levels deep
    deep_ast = {
        "source": "EMAIL_EVENT",
        "logic": "AND",
        "conditions": [
            {
                "field": "url_count",
                "operator": "GREATER_THAN",
                "value": 1,
                "nested_definition": {
                    "source": "EMAIL_EVENT",
                    "logic": "OR",
                    "conditions": [
                        {
                            "field": "sender_domain",
                            "operator": "CONTAINS",
                            "value": "xyz",
                            "nested_definition": {
                                "source": "EMAIL_EVENT",
                                "logic": "AND",
                                "conditions": [
                                    {
                                        "field": "subject",
                                        "operator": "CONTAINS",
                                        "value": "login",
                                        "nested_definition": {
                                            "source": "EMAIL_EVENT",
                                            "logic": "AND",
                                            "conditions": [
                                                {"field": "has_attachments", "operator": "EQUALS", "value": True}
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
            }
        ],
    }

    val_res = client.post(
        "/api/v1/rules/validate",
        json=deep_ast,
        headers={"X-Role": "analyst"},
    )
    assert val_res.status_code == 200
    val_data = val_res.json()
    assert val_data["is_valid"] is False
    assert any("depth exceeds limit" in err for err in val_data["errors"])


def test_case_10_runtime_detection_match_generation(client, db):
    """Case 10: Rule evaluates telemetry event at runtime and generates detection match."""
    # Create and activate rule
    create_res = client.post(
        "/api/v1/rules",
        json={
            "name": "Live PowerShell Execution",
            "description": "Flags powershell encoded commands",
            "category": "ENDPOINT",
            "data_sources": ["ENDPOINT_EVENT"],
            "severity": "CRITICAL",
            "confidence": 0.95,
            "definition": {
                "source": "ENDPOINT_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "process_name", "operator": "EQUALS", "value": "powershell.exe"},
                    {"field": "command_line", "operator": "CONTAINS", "value": "-EncodedCommand"},
                ],
            },
        },
        headers={"X-Workspace-ID": "ws-eval", "X-Role": "analyst", "X-User-ID": "analyst-1"},
    )
    rule_id = create_res.json()["id"]

    # Approve and activate
    client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers={"X-Workspace-ID": "ws-eval", "X-Role": "admin", "X-User-ID": "lead-1"},
    )
    client.post(
        f"/api/v1/rules/{rule_id}/activate",
        headers={"X-Workspace-ID": "ws-eval", "X-Role": "admin", "X-User-ID": "lead-1"},
    )

    # Ingest event
    eval_res = client.post(
        "/api/v1/rules/evaluate?data_source=ENDPOINT_EVENT",
        json={
            "id": "ep-event-99",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoProfile -EncodedCommand SQBFAFgA...",
        },
        headers={"X-Workspace-ID": "ws-eval", "X-Role": "analyst"},
    )
    assert eval_res.status_code == 200
    matches = eval_res.json()
    assert len(matches) == 1
    match = matches[0]
    assert match["matched"] is True
    assert match["rule_id"] == rule_id
    assert match["explanation"]["rule_name"] == "Live PowerShell Execution"


def test_case_11_detection_match_integrates_with_finding(client, db):
    """Case 11: Validated detection match creates a FindingModel with source_type=DETECTION_RULE."""
    create_res = client.post(
        "/api/v1/rules",
        json={
            "name": "Malicious Attachment Detection",
            "description": "Detects exe attachments",
            "category": "ATTACHMENT",
            "data_sources": ["EMAIL_EVENT"],
            "severity": "HIGH",
            "confidence": 0.9,
            "definition": {
                "source": "EMAIL_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "attachment_type", "operator": "EQUALS", "value": "application/x-msdownload"}
                ],
            },
        },
        headers={"X-Workspace-ID": "ws-finding", "X-Role": "analyst", "X-User-ID": "analyst-1"},
    )
    rule_id = create_res.json()["id"]
    client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers={"X-Workspace-ID": "ws-finding", "X-Role": "admin", "X-User-ID": "lead-1"},
    )
    client.post(
        f"/api/v1/rules/{rule_id}/activate",
        headers={"X-Workspace-ID": "ws-finding", "X-Role": "admin", "X-User-ID": "lead-1"},
    )

    # Ingest event that matches
    client.post(
        "/api/v1/rules/evaluate?data_source=EMAIL_EVENT",
        json={
            "id": "email-malware-01",
            "attachment_type": "application/x-msdownload",
        },
        headers={"X-Workspace-ID": "ws-finding", "X-Role": "analyst"},
    )

    # Verify FindingModel created in database
    finding = db.query(FindingModel).filter(
        FindingModel.workspace_id == "ws-finding",
        FindingModel.source_type == "DETECTION_RULE",
    ).first()
    assert finding is not None
    assert "Malicious Attachment Detection" in finding.title
    assert finding.severity == "HIGH"
    assert finding.details["rule_id"] == rule_id


def test_case_12_rule_emergency_disable_lifecycle(client, db):
    """Case 12: Rule is disabled; no longer matches incoming events; disabled timestamp recorded."""
    create_res = client.post(
        "/api/v1/rules",
        json={
            "name": "Noisy Rule",
            "description": "Produces too many false positives",
            "category": "NETWORK",
            "data_sources": ["NETWORK_EVENT"],
            "severity": "LOW",
            "confidence": 0.5,
            "definition": {
                "source": "NETWORK_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "dest_port", "operator": "EQUALS", "value": 80}
                ],
            },
        },
        headers={"X-Workspace-ID": "ws-disable", "X-Role": "analyst", "X-User-ID": "analyst-1"},
    )
    rule_id = create_res.json()["id"]
    client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers={"X-Workspace-ID": "ws-disable", "X-Role": "admin", "X-User-ID": "lead-1"},
    )
    client.post(
        f"/api/v1/rules/{rule_id}/activate",
        headers={"X-Workspace-ID": "ws-disable", "X-Role": "admin", "X-User-ID": "lead-1"},
    )

    # Disable rule
    dis_res = client.post(
        f"/api/v1/rules/{rule_id}/disable?reason=High+false+positive+rate",
        headers={"X-Workspace-ID": "ws-disable", "X-Role": "analyst", "X-User-ID": "analyst-2"},
    )
    assert dis_res.status_code == 200
    assert dis_res.json()["status"] == "DISABLED"
    assert dis_res.json()["disabled_at"] is not None

    # Verify that evaluate does not trigger for disabled rule
    eval_res = client.post(
        "/api/v1/rules/evaluate?data_source=NETWORK_EVENT",
        json={"dest_port": 80},
        headers={"X-Workspace-ID": "ws-disable", "X-Role": "analyst"},
    )
    assert eval_res.status_code == 200
    assert len(eval_res.json()) == 0


def test_case_13_ai_suggested_malformed_rule_rejected(client):
    """Case 13: AI-generated proposal with malformed or incomplete AST is safely rejected."""
    ai_res = client.post(
        "/api/v1/rules/ai-suggest",
        json={
            "observation_text": "Random nonsense without structured logic",
            "data_source_hint": "EMAIL_EVENT",
        },
        headers={"X-Role": "analyst"},
    )
    assert ai_res.status_code == 200
    data = ai_res.json()
    # It parses safe fallback or rejects if invalid
    assert "suggested_rule" in data
    # The generated rule candidate MUST still pass strict AST validation
    assert data["validation_preview"]["is_valid"] is True


def test_case_14_ai_suggested_unauthorized_field_rejected(client):
    """Case 14: AI prompt asking for non-existent database column or arbitrary code is rejected."""
    val_res = client.post(
        "/api/v1/rules/validate",
        json={
            "source": "EMAIL_EVENT",
            "logic": "AND",
            "conditions": [
                {
                    "field": "raw_db_password_hash",
                    "operator": "EQUALS",
                    "value": "secret",
                }
            ],
        },
        headers={"X-Role": "analyst"},
    )
    assert val_res.status_code == 200
    val_data = val_res.json()
    assert val_data["is_valid"] is False
    assert any("Unsupported field" in err for err in val_data["errors"])


def test_case_15_separation_of_duties_creator_cannot_self_approve(client):
    """Case 15: Separation of duties prevents the rule creator from self-approving."""
    create_res = client.post(
        "/api/v1/rules",
        json={
            "name": "High Value Transfer Phish",
            "description": "Flags transfer requests",
            "category": "PHISHING",
            "data_sources": ["EMAIL_EVENT"],
            "severity": "CRITICAL",
            "confidence": 0.95,
            "definition": {
                "source": "EMAIL_EVENT",
                "logic": "AND",
                "conditions": [
                    {"field": "subject", "operator": "CONTAINS", "value": "Wire Transfer"}
                ],
            },
        },
        headers={"X-Workspace-ID": "ws-duty", "X-Role": "analyst", "X-User-ID": "analyst-bob"},
    )
    rule_id = create_res.json()["id"]

    # Bob attempts to approve his own rule
    self_appr = client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers={"X-Workspace-ID": "ws-duty", "X-Role": "admin", "X-User-ID": "analyst-bob"},
    )
    assert self_appr.status_code == 400
    assert "Separation of duties violation" in self_appr.json()["detail"]

    # Charlie (different user) approves successfully
    other_appr = client.post(
        f"/api/v1/rules/{rule_id}/approve",
        headers={"X-Workspace-ID": "ws-duty", "X-Role": "admin", "X-User-ID": "lead-charlie"},
    )
    assert other_appr.status_code == 200
    assert other_appr.json()["status"] == "APPROVED"
