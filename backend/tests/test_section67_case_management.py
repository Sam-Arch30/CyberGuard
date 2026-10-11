"""
Section 67: Comprehensive Test Suite for Authoritative Case Management.
Tests case creation, numbering, state machine, resolution, closure, reopening,
tasks, gap recommendations, entity linking, safe merging, concurrency, RBAC,
tenant isolation, and background job handling.
"""
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import get_db, SessionLocal, init_db
from backend.db.models import (
    CaseModel,
    CaseTaskModel,
    CaseNoteModel,
    CaseFindingModel,
    IncidentModel,
    CampaignModel,
    AuditLogModel,
)
from backend.schemas.case import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseAssignRequest,
    CaseResolveRequest,
    CaseCloseRequest,
    CaseReopenRequest,
    CaseMergeRequest,
    CaseLinkRequest,
    CaseTaskCreate,
    CaseTaskUpdate,
    CaseNoteCreateRequest,
    CaseNoteUpdateRequest,
    CaseFindingCreateRequest,
    CaseResolutionCode,
    TaskStatus,
    TaskPriority,
)
from backend.services.case_service import CaseService
from backend.services.background_job_worker import (
    handle_case_management_jobs,
    JobExecutionContext,
)
from backend.schemas.jobs import JobTypeEnum


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    init_db()


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    return TestClient(app)


def test_case_creation_and_numbering(db: Session, client: TestClient):
    """
    TC-67-01: Verifies server-side collision-safe case numbering (CG-{YEAR}-000001),
    initial status, priority, and creation audit log.
    """
    req1 = CaseCreateRequest(
        title="Active Phishing Outbreak",
        description="High-volume phishing emails detected targeting executives.",
        severity="HIGH",
        priority="P2_HIGH",
        category="PHISHING",
        classification="CONFIDENTIAL",
        owner_id="analyst.jane",
        team_id="tier2-soc",
        tags=["phishing", "exec-targets"],
    )
    case1 = CaseService.create_case(db, req1, workspace_id="ws-test-67", user="analyst.jane")
    assert case1.case_number.startswith(f"CG-{datetime.now(timezone.utc).year}-")
    assert case1.status == "OPEN"
    assert case1.priority == "P2_HIGH"
    assert case1.severity == "HIGH"
    assert case1.version == 1

    # Second case must have sequential non-colliding number
    req2 = CaseCreateRequest(
        title="Secondary Suspicious Login",
        severity="MEDIUM",
        priority="P3_MEDIUM",
    )
    case2 = CaseService.create_case(db, req2, workspace_id="ws-test-67", user="analyst.bob")
    assert case2.case_number.startswith(f"CG-{datetime.now(timezone.utc).year}-")
    assert case2.case_number != case1.case_number

    # Verify audit log exists
    audit = db.query(AuditLogModel).filter(AuditLogModel.case_id == case1.id).first()
    assert audit is not None
    assert audit.action == "CASE_CREATED"


def test_case_state_machine_transitions(db: Session):
    """
    TC-67-02: Verifies strict state machine transitions:
    OPEN -> IN_PROGRESS -> PENDING -> IN_PROGRESS.
    Rejects invalid transition (e.g. NEW directly to CLOSED without resolution).
    """
    req = CaseCreateRequest(title="State Machine Test Case", status="OPEN")
    case = CaseService.create_case(db, req, workspace_id="ws-test-67")
    assert case.status == "OPEN"

    # Valid: OPEN -> IN_PROGRESS
    up1 = CaseUpdateRequest(status="IN_PROGRESS")
    case = CaseService.update_case(db, case.id, up1, workspace_id="ws-test-67")
    assert case.status == "IN_PROGRESS"

    # Valid: IN_PROGRESS -> PENDING
    up2 = CaseUpdateRequest(status="PENDING")
    case = CaseService.update_case(db, case.id, up2, workspace_id="ws-test-67")
    assert case.status == "PENDING"

    # Valid: PENDING -> IN_PROGRESS
    up3 = CaseUpdateRequest(status="IN_PROGRESS")
    case = CaseService.update_case(db, case.id, up3, workspace_id="ws-test-67")
    assert case.status == "IN_PROGRESS"

    # Invalid: IN_PROGRESS directly to CLOSED
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        CaseService.update_case(db, case.id, CaseUpdateRequest(status="CLOSED"), workspace_id="ws-test-67")
    assert exc_info.value.status_code == 400
    assert "Invalid case status transition" in exc_info.value.detail


def test_case_resolution_and_closure(db: Session):
    """
    TC-67-03: Verifies resolution requires resolution code and summary,
    and closure validates task checklist.
    """
    case = CaseService.create_case(
        db,
        CaseCreateRequest(title="Resolution & Closure Case", status="OPEN"),
        workspace_id="ws-test-67",
    )
    # Transition to IN_PROGRESS
    CaseService.update_case(db, case.id, CaseUpdateRequest(status="IN_PROGRESS"), workspace_id="ws-test-67")

    # Add an open task
    task = CaseService.create_task(
        db,
        case.id,
        CaseTaskCreate(title="Inspect firewall rule logs", priority=TaskPriority.HIGH),
        workspace_id="ws-test-67",
    )

    # Resolve case
    res_req = CaseResolveRequest(
        resolution_code=CaseResolutionCode.TRUE_POSITIVE,
        resolution_summary="Confirmed credential harvesting page blocked at DNS level.",
    )
    resolved_case = CaseService.resolve_case(db, case.id, res_req, workspace_id="ws-test-67", user="lead.analyst")
    assert resolved_case.status == "RESOLVED"
    assert resolved_case.resolution_code == "TRUE_POSITIVE"
    assert resolved_case.resolved_at is not None
    assert resolved_case.resolved_by == "lead.analyst"

    # Attempt closure without completing open tasks or force_close_tasks -> should fail
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        CaseService.close_case(
            db,
            case.id,
            CaseCloseRequest(closure_notes="Closing case", force_close_tasks=False),
            workspace_id="ws-test-67",
        )
    assert exc_info.value.status_code == 400
    assert "tasks remain open" in exc_info.value.detail

    # Now close with force_close_tasks=True
    closed_case = CaseService.close_case(
        db,
        case.id,
        CaseCloseRequest(closure_notes="Post-incident review complete. All remediation verified.", force_close_tasks=True),
        workspace_id="ws-test-67",
        user="lead.analyst",
    )
    assert closed_case.status == "CLOSED"
    assert closed_case.closed_at is not None
    assert closed_case.closed_by == "lead.analyst"

    # Verify previously open task was marked CANCELLED
    db_task = db.query(CaseTaskModel).filter(CaseTaskModel.id == task.id).first()
    assert db_task.status == "CANCELLED"


def test_case_reopening_with_justification(db: Session):
    """
    TC-67-04: Verifies closed/resolved cases can be reopened with mandatory reason.
    """
    case = CaseService.create_case(
        db,
        CaseCreateRequest(title="Reopen Verification Case", status="OPEN"),
        workspace_id="ws-test-67",
    )
    CaseService.update_case(db, case.id, CaseUpdateRequest(status="IN_PROGRESS"), workspace_id="ws-test-67")
    CaseService.resolve_case(
        db,
        case.id,
        CaseResolveRequest(resolution_code=CaseResolutionCode.RESOLVED, resolution_summary="Initial resolution complete."),
        workspace_id="ws-test-67",
    )
    CaseService.close_case(
        db,
        case.id,
        CaseCloseRequest(closure_notes="Closed normally.", force_close_tasks=True),
        workspace_id="ws-test-67",
    )

    # Reopen
    reopen_req = CaseReopenRequest(reopen_reason="New telemetry observed from target domain.")
    reopened = CaseService.reopen_case(db, case.id, reopen_req, workspace_id="ws-test-67", user="senior.analyst")
    assert reopened.status == "IN_PROGRESS"
    assert reopened.reopened_at is not None
    assert reopened.reopened_by == "senior.analyst"
    assert reopened.reopen_reason == "New telemetry observed from target domain."
    assert reopened.closed_at is None


def test_case_task_lifecycle_and_gap_recommendations(db: Session):
    """
    TC-67-05: Verifies task creation, completion, and automated generation from Section 66 investigation gaps.
    """
    case = CaseService.create_case(
        db,
        CaseCreateRequest(title="Task Lifecycle Case"),
        workspace_id="ws-test-67",
    )

    # Manual task creation
    task = CaseService.create_task(
        db,
        case.id,
        CaseTaskCreate(
            title="Perform mailbox purge for malicious message",
            description="Purge message with ID msg-98234 from all inboxes.",
            priority=TaskPriority.CRITICAL,
            assignee_id="analyst.mark",
        ),
        workspace_id="ws-test-67",
        user="lead.analyst",
    )
    assert task.status == "TODO"
    assert task.priority == "CRITICAL"
    assert task.assignee_id == "analyst.mark"

    # Update task to COMPLETED
    updated_task = CaseService.update_task(
        db,
        case.id,
        task.id,
        CaseTaskUpdate(status=TaskStatus.COMPLETED),
        workspace_id="ws-test-67",
        user="analyst.mark",
    )
    assert updated_task.status == "COMPLETED"
    assert updated_task.completed_at is not None
    assert updated_task.completed_by == "analyst.mark"

    # Automated tasks from investigation gaps
    gaps = [
        {
            "category": "TELEMETRY_MISSING",
            "title": "Endpoint sensor offline for Host-042",
            "severity": "HIGH",
            "remediation_recommendation": "Verify agent connectivity and restart daemon.",
        },
        {
            "category": "UNRESOLVED_IDENTITY",
            "title": "User account 'service-api' lacks department metadata",
            "severity": "LOW",
            "remediation_recommendation": "Query LDAP catalog for owner.",
        },
    ]
    auto_tasks = CaseService.generate_tasks_from_investigation_gaps(db, case.id, gaps, workspace_id="ws-test-67")
    assert len(auto_tasks) == 2
    assert auto_tasks[0].is_automated_recommendation is True
    assert auto_tasks[0].priority == "HIGH"
    assert auto_tasks[1].priority == "MEDIUM"


def test_multi_entity_linking_and_timeline(db: Session):
    """
    TC-67-06: Verifies linking external Incident, Investigation, Alert, Evidence, Asset,
    and checks unified timeline extraction.
    """
    # Create incident to link
    inc = IncidentModel(
        incident_number=f"INC-{datetime.now(timezone.utc).year}-778899",
        workspace_id="ws-test-67",
        title="Underlying Incident",
        severity="HIGH",
        status="INVESTIGATING",
    )
    db.add(inc)
    db.commit()

    case = CaseService.create_case(
        db,
        CaseCreateRequest(title="Entity Linking Case"),
        workspace_id="ws-test-67",
    )

    # Link Incident
    CaseService.link_entity(db, case.id, CaseLinkRequest(entity_type="INCIDENT", entity_id=inc.id), workspace_id="ws-test-67")
    # Link Investigation
    CaseService.link_entity(db, case.id, CaseLinkRequest(entity_type="INVESTIGATION", entity_id="INV-9988"), workspace_id="ws-test-67")
    # Link Alert
    CaseService.link_entity(db, case.id, CaseLinkRequest(entity_type="ALERT", entity_id="ALT-1234"), workspace_id="ws-test-67")
    # Link Asset
    CaseService.link_entity(db, case.id, CaseLinkRequest(entity_type="ASSET", entity_id="Laptop-007"), workspace_id="ws-test-67")
    # Link Identity
    CaseService.link_entity(db, case.id, CaseLinkRequest(entity_type="IDENTITY", entity_id="cfo@corp.com"), workspace_id="ws-test-67")

    detail = CaseService.get_case_detail(db, case.id, workspace_id="ws-test-67")
    assert detail.incident_id == inc.id
    assert detail.primary_investigation_id == "INV-9988"
    assert "ALT-1234" in detail.related_alerts
    assert "Laptop-007" in detail.affected_assets
    assert "cfo@corp.com" in detail.affected_identities

    # Verify unified timeline
    timeline = CaseService.get_case_timeline(db, case.id, workspace_id="ws-test-67")
    assert len(timeline) >= 4
    event_types = {e.event_type for e in timeline}
    assert "CASE_OPENED" in event_types
    assert "INCIDENT_LINKED" in event_types
    assert "INVESTIGATION_LINKED" in event_types


def test_safe_case_merging_preserves_provenance(db: Session):
    """
    TC-67-07: Verifies merging secondary cases into target case repoints tasks and notes,
    marks source cases as DUPLICATE, and preserves full history without deletion.
    """
    target = CaseService.create_case(db, CaseCreateRequest(title="Target Incident Case"), workspace_id="ws-test-67")
    source1 = CaseService.create_case(db, CaseCreateRequest(title="Duplicate Source 1"), workspace_id="ws-test-67")
    source2 = CaseService.create_case(db, CaseCreateRequest(title="Duplicate Source 2"), workspace_id="ws-test-67")

    # Add task & note to source1
    CaseService.create_task(db, source1.id, CaseTaskCreate(title="Task from Source 1"), workspace_id="ws-test-67")
    CaseService.add_note(db, source1.id, CaseNoteCreateRequest(note_text="Note from Source 1"), workspace_id="ws-test-67")

    # Merge
    merge_req = CaseMergeRequest(source_case_ids=[source1.id, source2.id], reason="Correlated to identical campaign infrastructure.")
    merged_target = CaseService.merge_cases(db, target.id, merge_req, workspace_id="ws-test-67", user="lead.analyst")

    assert merged_target.id == target.id

    # Verify source cases are marked DUPLICATE and resolved, not deleted
    db.refresh(source1)
    db.refresh(source2)
    assert source1.status == "RESOLVED"
    assert source1.resolution_code == "DUPLICATE"
    assert source1.merged_into_id == target.id

    assert source2.status == "RESOLVED"
    assert source2.resolution_code == "DUPLICATE"
    assert source2.merged_into_id == target.id

    # Verify tasks and notes were repointed to target
    detail = CaseService.get_case_detail(db, target.id, workspace_id="ws-test-67")
    task_titles = [t.title for t in detail.tasks]
    assert "Task from Source 1" in task_titles
    note_texts = [n.note_text for n in detail.notes]
    assert any("Note from Source 1" in nt for nt in note_texts)


def test_optimistic_concurrency_control(db: Session):
    """
    TC-67-08: Verifies 409 Conflict is raised when updating with a stale expected_version.
    """
    case = CaseService.create_case(db, CaseCreateRequest(title="Concurrency Case"), workspace_id="ws-test-67")
    assert case.version == 1

    # Update with correct version
    CaseService.update_case(db, case.id, CaseUpdateRequest(title="Updated Title 1", expected_version=1), workspace_id="ws-test-67")
    db.refresh(case)
    assert case.version == 2

    # Attempt update with stale version 1 -> should fail with 409 Conflict
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as exc_info:
        CaseService.update_case(db, case.id, CaseUpdateRequest(title="Stale Update", expected_version=1), workspace_id="ws-test-67")
    assert exc_info.value.status_code == 409
    assert "Concurrent modification detected" in exc_info.value.detail


def test_note_editing_with_audit_history(db: Session):
    """
    TC-67-09: Verifies note editing preserves prior revisions in edit_history_json.
    """
    case = CaseService.create_case(db, CaseCreateRequest(title="Notes Test Case"), workspace_id="ws-test-67")
    note = CaseService.add_note(db, case.id, CaseNoteCreateRequest(note_text="Original observation."), workspace_id="ws-test-67")

    # Edit note
    updated_note = CaseService.update_note(
        db,
        case.id,
        note.id,
        CaseNoteUpdateRequest(note_text="Revised observation with new IOCs."),
        workspace_id="ws-test-67",
        user="analyst.bob",
    )
    assert updated_note.note_text == "Revised observation with new IOCs."

    db.refresh(note)
    import json
    history = json.loads(note.edit_history_json)
    assert len(history) == 1
    assert history[0]["previous_text"] == "Original observation."
    assert history[0]["edited_by"] == "analyst.bob"


def test_rbac_and_tenant_isolation(client: TestClient):
    """
    TC-67-10: Verifies 403 Forbidden for unauthorized roles,
    and 404 Not Found for cross-workspace resource access.
    """
    # 1. Unauthorized role test
    res = client.post(
        "/api/cases",
        headers={"X-Role": "unauthorized", "X-Workspace-ID": "ws-sec-test"},
        json={"title": "Unauthorized Case"},
    )
    assert res.status_code == 403

    # 2. Create case in Tenant A
    res_a = client.post(
        "/api/cases",
        headers={"X-Role": "analyst", "X-Workspace-ID": "tenant-alpha"},
        json={"title": "Tenant Alpha Confidential Case"},
    )
    assert res_a.status_code == 201
    case_a_id = res_a.json()["id"]

    # 3. Tenant B attempts to read Tenant A's case -> 404 Not Found
    res_b = client.get(
        f"/api/cases/{case_a_id}",
        headers={"X-Role": "analyst", "X-Workspace-ID": "tenant-bravo"},
    )
    assert res_b.status_code == 404


def test_background_job_case_operations(db: Session):
    """
    TC-67-11: Verifies background worker execution of CASE_EXPORT, CASE_SLA_SWEEP,
    and CASE_METRICS_AGGREGATION jobs.
    """
    import asyncio

    case = CaseService.create_case(db, CaseCreateRequest(title="Background Job Target Case"), workspace_id="ws-bg-test")

    # 1. Export job
    ctx_export = JobExecutionContext(
        job_id="job-exp-01",
        workspace_id="ws-bg-test",
        job_type=JobTypeEnum.CASE_EXPORT.value,
        payload={"case_id": case.id},
        worker_id="test-worker",
        attempt=1,
        timeout_seconds=30,
    )
    res_export = asyncio.run(handle_case_management_jobs(ctx_export, db))
    assert res_export["status"] == "EXPORT_READY"
    assert res_export["case_id"] == case.id

    # 2. SLA sweep job
    ctx_sla = JobExecutionContext(
        job_id="job-sla-01",
        workspace_id="ws-bg-test",
        job_type=JobTypeEnum.CASE_SLA_SWEEP.value,
        payload={},
        worker_id="test-worker",
        attempt=1,
        timeout_seconds=30,
    )
    res_sla = asyncio.run(handle_case_management_jobs(ctx_sla, db))
    assert res_sla["status"] == "SLA_SWEEP_COMPLETED"
    assert "metrics" in res_sla

    # 3. Metrics aggregation job
    ctx_metrics = JobExecutionContext(
        job_id="job-met-01",
        workspace_id="ws-bg-test",
        job_type=JobTypeEnum.CASE_METRICS_AGGREGATION.value,
        payload={},
        worker_id="test-worker",
        attempt=1,
        timeout_seconds=30,
    )
    res_metrics = asyncio.run(handle_case_management_jobs(ctx_metrics, db))
    assert res_metrics["status"] == "METRICS_AGGREGATED"
    assert res_metrics["metrics"]["total_cases"] >= 1
