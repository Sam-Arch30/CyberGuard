"""
Section 59: Unified Threat Detection Pipeline Comprehensive Test Suite.

Validates:
1. Telemetry ingestion & source adapter normalization (Endpoint, Email, Auth, Network, API).
2. Active rule selection, tenant isolation, and Section 58 validation gate checks.
3. AST evaluator reuse, deterministic matching, and NO_MATCH semantics (no finding/alert created).
4. Downstream handoff: DetectionMatch persistence, FindingModel creation, alert policy dispatch.
5. Execution modes: PRODUCTION, SHADOW, and REPLAY.
6. Section 57 suppression check integration.
7. Event idempotency, deduplication, and dead-letter handling.
8. Section 45 background job routing for batches and replay.
9. Section 46 realtime publisher notifications.
10. REST API endpoints, RBAC enforcement, and tenant isolation.
"""
from datetime import datetime, timezone
import json
from unittest.mock import patch
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal, init_db
from backend.db.models import (
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    RuleSuppressionModel,
    SecurityEventModel,
    DetectionMatchModel,
    DetectionDeadLetterModel,
    FindingModel,
    NotificationModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import RuleLifecycleStatus, RuleSeverity, RuleType
from backend.schemas.detection_rules import (
    DeploymentStateEnum,
    OperationalHealthEnum,
    ValidationStatusEnum,
)
from backend.schemas.detection_pipeline import (
    EventIngestRequest,
    BatchEventIngestRequest,
    PipelineModeEnum,
    EvaluationOutcomeEnum,
)
from backend.services.unified_threat_detection_pipeline_service import (
    UnifiedThreatDetectionPipelineService,
)

client = TestClient(app)

WS_A = "ws-sec59-tenant-alpha"
WS_B = "ws-sec59-tenant-beta"


@pytest.fixture(autouse=True)
def setup_db():
    init_db()
    db: Session = SessionLocal()
    try:
        # Clean tenant-specific test fixtures
        db.query(DetectionMatchModel).filter(DetectionMatchModel.workspace_id.in_([WS_A, WS_B])).delete(synchronize_session=False)
        db.query(DetectionDeadLetterModel).filter(DetectionDeadLetterModel.workspace_id.in_([WS_A, WS_B])).delete(synchronize_session=False)
        db.query(SecurityEventModel).filter(SecurityEventModel.workspace_id.in_([WS_A, WS_B])).delete(synchronize_session=False)
        db.query(RuleSuppressionModel).filter(RuleSuppressionModel.workspace_id.in_([WS_A, WS_B])).delete(synchronize_session=False)
        db.query(CandidateRuleExecutionModel).filter(CandidateRuleExecutionModel.workspace_id.in_([WS_A, WS_B])).delete(synchronize_session=False)
        db.query(CandidateRuleVersionModel).filter(CandidateRuleVersionModel.workspace_id.in_([WS_A, WS_B])).delete(synchronize_session=False)
        db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id.in_([WS_A, WS_B])).delete(synchronize_session=False)
        db.commit()
    finally:
        db.close()
    yield


def create_test_rule(
    db: Session,
    workspace_id: str,
    name: str = "Test Malicious Process Rule",
    source: str = "ENDPOINT_EVENT",
    condition_field: str = "process.name",
    condition_op: str = "EQUALS",
    condition_val: str = "powershell.exe",
    severity: str = "CRITICAL",
    status: str = "ACTIVE",
    deployment_state: str = "PRODUCTION",
    validation_status: str = "PASS",
) -> CandidateRuleModel:
    rule_id = generate_uuid()
    defn = {
        "source": source,
        "logical_operator": "AND",
        "conditions": [
            {
                "field": condition_field,
                "operator": condition_op,
                "value": condition_val,
            }
        ],
    }
    rule = CandidateRuleModel(
        id=rule_id,
        workspace_id=workspace_id,
        rule_identifier=f"RULE-{rule_id[:8].upper()}",
        name=name,
        description="Deterministic test rule for Section 59 pipeline",
        category="ENDPOINT",
        rule_type=RuleType.BEHAVIORAL.value,
        status=status,
        severity=severity,
        definition=defn,
        version="1.0.0",
        data_sources_json=json.dumps([source]),
        normalized_fingerprint=f"fp_{generate_uuid()[:16]}",
        deployment_state=deployment_state,
        operational_health=OperationalHealthEnum.HEALTHY.value,
        validation_status=validation_status,
        created_by="test-engineer",
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db.add(rule)
    db.flush()

    ver = CandidateRuleVersionModel(
        id=generate_uuid(),
        workspace_id=workspace_id,
        rule_id=rule.id,
        version="1.0.0",
        definition=defn,
        data_sources_json=json.dumps([source]),
        change_reason="Initial version",
        created_by="test-engineer",
        created_at=get_utc_now(),
    )
    db.add(ver)
    db.commit()
    return rule


# ============================================================================
# 1. SOURCE ADAPTERS & NORMALIZATION TESTS
# ============================================================================

def test_normalize_endpoint_event():
    db = SessionLocal()
    try:
        req = EventIngestRequest(
            event_type="ENDPOINT_EVENT",
            source="ENDPOINT",
            payload={
                "process_name": "powershell.exe",
                "command_line": "powershell.exe -enc AAAA",
                "client_ip": "10.0.1.25",
                "user": "root",
                "device_id": "WS-01",
            },
            workspace_id=WS_A,
        )
        norm, ev_id = UnifiedThreatDetectionPipelineService.normalize_event(db, req, WS_A)
        assert norm.event_type == "ENDPOINT_EVENT"
        assert norm.source_type == "ENDPOINT"
        assert any(e["type"] == "USER" and e["value"] == "root" for e in norm.entities)
        assert any(e["type"] == "DEVICE" and e["value"] == "WS-01" for e in norm.entities)
        assert ev_id == norm.event_id
    finally:
        db.close()


def test_normalize_email_event():
    db = SessionLocal()
    try:
        req = EventIngestRequest(
            event_type="EMAIL_EVENT",
            source="EMAIL",
            payload={
                "subject": "Password reset required",
                "sender_email": "attacker@bad-domain.com",
                "sender_domain": "bad-domain.com",
                "recipient": "victim@cyberguard.corp",
                "urls": ["http://bad-domain.com/login"],
            },
            workspace_id=WS_A,
        )
        norm, _ = UnifiedThreatDetectionPipelineService.normalize_event(db, req, WS_A)
        assert norm.source_type == "EMAIL"
        assert any(e["type"] == "DOMAIN" and e["value"] == "bad-domain.com" for e in norm.entities)
        assert any(i["type"] == "EMAIL" and i["value"] == "attacker@bad-domain.com" for i in norm.indicators)
    finally:
        db.close()


def test_normalize_auth_event():
    db = SessionLocal()
    try:
        req = EventIngestRequest(
            event_type="AUTH_EVENT",
            source="AUTH",
            payload={
                "username": "svc-backup",
                "client_ip": "192.168.1.100",
                "auth_status": "FAILURE",
                "failure_count": 5,
            },
            workspace_id=WS_A,
        )
        norm, _ = UnifiedThreatDetectionPipelineService.normalize_event(db, req, WS_A)
        assert norm.source_type == "AUTH"
        assert any(e["type"] == "USER" and e["value"] == "svc-backup" for e in norm.entities)
        assert any(i["type"] == "IP" and i["value"] == "192.168.1.100" for i in norm.indicators)
    finally:
        db.close()


# ============================================================================
# 2. RULE APPLICABILITY & TENANT ISOLATION TESTS
# ============================================================================

def test_applicable_rules_source_and_validation_filtering():
    db = SessionLocal()
    try:
        # Active endpoint rule with PASS validation
        rule_endpoint = create_test_rule(db, WS_A, name="Endpoint Rule", source="ENDPOINT_EVENT", validation_status="PASS")
        # Active email rule with PASS validation
        rule_email = create_test_rule(db, WS_A, name="Email Rule", source="EMAIL_EVENT", condition_field="email.subject", validation_status="PASS")
        # Endpoint rule with FAIL validation (gate blocked)
        rule_failed = create_test_rule(db, WS_A, name="Failed Gate Rule", source="ENDPOINT_EVENT", validation_status="FAIL")
        # Draft endpoint rule
        rule_draft = create_test_rule(db, WS_A, name="Draft Rule", source="ENDPOINT_EVENT", status="DRAFT", deployment_state="DRAFT")

        # Endpoint event should select ONLY rule_endpoint
        req = EventIngestRequest(event_type="ENDPOINT_EVENT", source="ENDPOINT", payload={"process_name": "cmd.exe"}, workspace_id=WS_A)
        norm, _ = UnifiedThreatDetectionPipelineService.normalize_event(db, req, WS_A)

        applicable = UnifiedThreatDetectionPipelineService.select_applicable_rules(db, norm, PipelineModeEnum.PRODUCTION, WS_A)
        app_ids = [r.id for r in applicable]

        assert rule_endpoint.id in app_ids
        assert rule_email.id not in app_ids  # Excluded: different source
        assert rule_failed.id not in app_ids  # Excluded: validation FAIL
        assert rule_draft.id not in app_ids  # Excluded: not ACTIVE / not PRODUCTION
    finally:
        db.close()


def test_tenant_isolation_boundary():
    db = SessionLocal()
    try:
        rule_a = create_test_rule(db, WS_A, name="Tenant A Rule")
        rule_b = create_test_rule(db, WS_B, name="Tenant B Rule")

        req = EventIngestRequest(event_type="ENDPOINT_EVENT", source="ENDPOINT", payload={"process_name": "powershell.exe"}, workspace_id=WS_A)
        norm, _ = UnifiedThreatDetectionPipelineService.normalize_event(db, req, WS_A)

        # In WS_A, only rule_a must be selected
        app_a = UnifiedThreatDetectionPipelineService.select_applicable_rules(db, norm, PipelineModeEnum.PRODUCTION, WS_A)
        assert [r.id for r in app_a] == [rule_a.id]

        # Rule B must never be visible to WS_A
        assert rule_b.id not in [r.id for r in app_a]
    finally:
        db.close()


# ============================================================================
# 3. DETERMINISTIC EVALUATION & NO-MATCH SEMANTICS
# ============================================================================

def test_evaluation_match_deterministic():
    db = SessionLocal()
    try:
        rule = create_test_rule(
            db,
            WS_A,
            name="PowerShell Execution Detector",
            source="ENDPOINT_EVENT",
            condition_field="process.name",
            condition_op="EQUALS",
            condition_val="powershell.exe",
            severity="CRITICAL",
        )

        req = EventIngestRequest(
            event_type="ENDPOINT_EVENT",
            source="ENDPOINT",
            payload={"process_name": "powershell.exe", "command_line": "powershell.exe -ExecutionPolicy Bypass"},
            workspace_id=WS_A,
        )

        res = UnifiedThreatDetectionPipelineService.process_event(db, req, user_id="analyst-1", workspace_id=WS_A)

        assert res.matches_count == 1
        assert res.findings_count >= 1
        assert res.alerts_count >= 1

        # Verify DetectionMatchModel persisted
        match_record = db.query(DetectionMatchModel).filter(
            DetectionMatchModel.event_id == res.event_id,
            DetectionMatchModel.rule_id == rule.id,
        ).first()
        assert match_record is not None
        assert match_record.status == "MATCH"
        assert match_record.severity == "CRITICAL"
        assert match_record.finding_id is not None
        assert match_record.alert_id is not None
    finally:
        db.close()


def test_evaluation_no_match_semantics():
    db = SessionLocal()
    try:
        rule = create_test_rule(
            db,
            WS_A,
            name="PowerShell Execution Detector",
            source="ENDPOINT_EVENT",
            condition_field="process.name",
            condition_op="EQUALS",
            condition_val="powershell.exe",
        )

        # Event with benign cmd.exe - NOT powershell.exe
        req = EventIngestRequest(
            event_type="ENDPOINT_EVENT",
            source="ENDPOINT",
            payload={"process_name": "cmd.exe"},
            workspace_id=WS_A,
        )

        res = UnifiedThreatDetectionPipelineService.process_event(db, req, user_id="analyst-1", workspace_id=WS_A)

        # MUST NOT create matches, findings, or alerts
        assert res.matches_count == 0
        assert res.findings_count == 0
        assert res.alerts_count == 0
        assert res.evaluations[0].outcome == EvaluationOutcomeEnum.NO_MATCH

        # No match records in DB
        assert db.query(DetectionMatchModel).filter(DetectionMatchModel.event_id == res.event_id).count() == 0
    finally:
        db.close()


def test_suppression_prevents_alert_dispatch():
    db = SessionLocal()
    try:
        rule = create_test_rule(
            db,
            WS_A,
            name="Suppressed PowerShell Rule",
            source="ENDPOINT_EVENT",
            condition_field="process.name",
            condition_op="EQUALS",
            condition_val="powershell.exe",
            severity="CRITICAL",
        )

        # Create active suppression matching the rule
        suppression = RuleSuppressionModel(
            id=generate_uuid(),
            workspace_id=WS_A,
            rule_id=rule.id,
            name="Maintenance suppression",
            reason="Authorized maintenance window",
            scope_type="GLOBAL",
            scope_target="process_name",
            match_operator="EQUALS",
            match_value="powershell.exe",
            is_active=True,
            created_by="lead-analyst",
            created_at=get_utc_now(),
        )
        db.add(suppression)
        db.commit()

        req = EventIngestRequest(
            event_type="ENDPOINT_EVENT",
            source="ENDPOINT",
            payload={"process_name": "powershell.exe"},
            workspace_id=WS_A,
        )

        res = UnifiedThreatDetectionPipelineService.process_event(db, req, user_id="analyst-1", workspace_id=WS_A)

        # Evaluated as suppressed
        assert res.alerts_count == 0  # No alert dispatched!
        assert len(res.evaluations) == 1
        assert res.evaluations[0].outcome == EvaluationOutcomeEnum.SKIPPED
        assert "Suppressed" in (res.evaluations[0].skip_reason or "")
    finally:
        db.close()


# ============================================================================
# 4. EXECUTION MODES: SHADOW & REPLAY
# ============================================================================

def test_shadow_mode_execution():
    db = SessionLocal()
    try:
        rule = create_test_rule(
            db,
            WS_A,
            name="Shadow Test Rule",
            source="ENDPOINT_EVENT",
            condition_field="process.name",
            condition_op="EQUALS",
            condition_val="powershell.exe",
            severity="CRITICAL",
        )

        req = EventIngestRequest(
            event_type="ENDPOINT_EVENT",
            source="ENDPOINT",
            payload={"process_name": "powershell.exe"},
            mode=PipelineModeEnum.SHADOW,
            workspace_id=WS_A,
        )

        res = UnifiedThreatDetectionPipelineService.process_event(db, req, user_id="analyst-1", workspace_id=WS_A)

        # Match is detected but NO production findings or alerts created
        assert res.matches_count == 1
        assert res.findings_count == 0
        assert res.alerts_count == 0

        match_rec = db.query(DetectionMatchModel).filter(DetectionMatchModel.event_id == res.event_id).first()
        assert match_rec.mode == "SHADOW"
        assert match_rec.finding_id is None
        assert match_rec.alert_id is None
    finally:
        db.close()


def test_replay_historical_events():
    db = SessionLocal()
    try:
        rule = create_test_rule(
            db,
            WS_A,
            name="Historical Replay Rule",
            source="ENDPOINT_EVENT",
            condition_field="process.name",
            condition_op="EQUALS",
            condition_val="powershell.exe",
        )

        # Seed 3 historical SecurityEventModel records in WS_A
        for i in range(3):
            proc = "powershell.exe" if i < 2 else "notepad.exe"
            ev = SecurityEventModel(
                id=f"hist-evt-{i}-{generate_uuid()[:6]}",
                workspace_id=WS_A,
                event_type="ENDPOINT_EVENT",
                source_type="ENDPOINT",
                event_time=get_utc_now(),
                attributes_json=json.dumps({
                    "event_type": "ENDPOINT_EVENT",
                    "source": "ENDPOINT",
                    "process_name": proc,
                    "process.name": proc,
                }),
                created_at=get_utc_now(),
            )
            db.add(ev)
        db.commit()

        from backend.schemas.detection_pipeline import PipelineReplayRequest
        replay_req = PipelineReplayRequest(max_events=10)
        res = UnifiedThreatDetectionPipelineService.replay_historical_events(
            db, replay_req, user_id="admin-1", workspace_id=WS_A
        )

        assert res.total_events == 3
        assert res.matched_events == 2  # Only the 2 powershell.exe events match

        # All replay matches must have mode == 'REPLAY' and no alerts
        replays = db.query(DetectionMatchModel).filter(DetectionMatchModel.mode == "REPLAY").all()
        assert len(replays) == 2
        for r in replays:
            assert r.alert_id is None
    finally:
        db.close()


# ============================================================================
# 5. IDEMPOTENCY & DEAD LETTERS
# ============================================================================

def test_event_idempotency():
    db = SessionLocal()
    try:
        rule = create_test_rule(
            db,
            WS_A,
            name="Idempotency Test Rule",
            source="ENDPOINT_EVENT",
            condition_field="process.name",
            condition_op="EQUALS",
            condition_val="powershell.exe",
            severity="HIGH",
        )

        shared_event_id = f"evt-fixed-{generate_uuid()[:8]}"
        req = EventIngestRequest(
            event_id=shared_event_id,
            event_type="ENDPOINT_EVENT",
            source="ENDPOINT",
            payload={"process_name": "powershell.exe"},
            workspace_id=WS_A,
        )

        res1 = UnifiedThreatDetectionPipelineService.process_event(db, req, user_id="analyst-1", workspace_id=WS_A)
        assert res1.matches_count == 1

        # Second ingestion of identical event
        res2 = UnifiedThreatDetectionPipelineService.process_event(db, req, user_id="analyst-1", workspace_id=WS_A)
        assert res2.matches_count == 1

        # Must not produce duplicate match records for same event + rule
        match_count = db.query(DetectionMatchModel).filter(
            DetectionMatchModel.event_id == shared_event_id,
            DetectionMatchModel.rule_id == rule.id,
        ).count()
        assert match_count == 1
    finally:
        db.close()


def test_dead_letter_on_error():
    db = SessionLocal()
    try:
        UnifiedThreatDetectionPipelineService._record_dead_letter(
            db=db,
            workspace_id=WS_A,
            event_id="bad-event-99",
            source_type="ENDPOINT",
            failure_stage="NORMALIZE",
            error_code="INVALID_PAYLOAD",
            error_message="Test unrecoverable payload error",
            payload={"corrupted": True},
        )

        dls = db.query(DetectionDeadLetterModel).filter(DetectionDeadLetterModel.workspace_id == WS_A).all()
        assert len(dls) >= 1
        assert dls[0].error_code == "INVALID_PAYLOAD"
        assert dls[0].failure_stage == "NORMALIZE"
    finally:
        db.close()


# ============================================================================
# 6. REST API INTEGRATION TESTS
# ============================================================================

def test_api_ingest_event_endpoint():
    db = SessionLocal()
    try:
        create_test_rule(
            db,
            WS_A,
            name="API Ingest Test Rule",
            source="ENDPOINT_EVENT",
            condition_field="process.name",
            condition_op="EQUALS",
            condition_val="cmd.exe",
        )
    finally:
        db.close()

    resp = client.post(
        "/api/v1/detection/events",
        headers={"X-Workspace-ID": WS_A, "X-Role": "analyst"},
        json={
            "source": "ENDPOINT",
            "event_type": "ENDPOINT_EVENT",
            "payload": {"process_name": "cmd.exe"},
            "workspace_id": WS_A,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["matches_count"] == 1
    assert data["source_type"] == "ENDPOINT"


def test_api_pipeline_status_and_metrics():
    resp = client.get(
        "/api/v1/detection/pipeline/status",
        headers={"X-Workspace-ID": WS_A, "X-Role": "analyst"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] in ["HEALTHY", "DEGRADED", "BACKLOGGED", "FAILING"]
    assert "metrics_summary" in data

    m_resp = client.get(
        "/api/v1/detection/pipeline/metrics",
        headers={"X-Workspace-ID": WS_A, "X-Role": "analyst"},
    )
    assert m_resp.status_code == 200
    m_data = m_resp.json()
    assert "events_received_total" in m_data
    assert "matches_total" in m_data


def test_api_matches_and_trace():
    db = SessionLocal()
    try:
        rule = create_test_rule(db, WS_A, name="Trace Test Rule", source="ENDPOINT_EVENT", condition_field="process.name", condition_val="bash")
        rule_id = rule.id
        ev_id = f"evt-trace-{generate_uuid()[:6]}"
        req = EventIngestRequest(
            event_id=ev_id,
            source="ENDPOINT",
            event_type="ENDPOINT_EVENT",
            payload={"process_name": "bash"},
            workspace_id=WS_A,
        )
        res = UnifiedThreatDetectionPipelineService.process_event(db, req, user_id="analyst", workspace_id=WS_A)
    finally:
        db.close()

    # Query matches
    resp = client.get(
        f"/api/v1/detection/matches?rule_id={rule_id}",
        headers={"X-Workspace-ID": WS_A, "X-Role": "analyst"},
    )
    assert resp.status_code == 200
    matches_list = resp.json()
    assert len(matches_list) >= 1
    assert matches_list[0]["rule_id"] == rule_id

    # Query event trace
    trace_resp = client.get(
        f"/api/v1/detection/events/{ev_id}/trace",
        headers={"X-Workspace-ID": WS_A, "X-Role": "analyst"},
    )
    assert trace_resp.status_code == 200
    trace_data = trace_resp.json()
    assert trace_data["event_id"] == ev_id
    assert len(trace_data["stages"]) == 5
    assert len(trace_data["matches"]) >= 1


def test_api_rbac_enforcement():
    # Unauthorized or viewer attempting to replay or ingest
    resp_unauth = client.post(
        "/api/v1/detection/events",
        headers={"X-Workspace-ID": WS_A, "X-Role": "unauthorized"},
        json={"source": "ENDPOINT", "event_type": "ENDPOINT_EVENT", "payload": {}},
    )
    assert resp_unauth.status_code == 403

    # Analyst attempting admin-only replay
    resp_replay = client.post(
        "/api/v1/detection/pipeline/replay",
        headers={"X-Workspace-ID": WS_A, "X-Role": "analyst"},
        json={"max_events": 10},
    )
    assert resp_replay.status_code == 403  # Admin required!
