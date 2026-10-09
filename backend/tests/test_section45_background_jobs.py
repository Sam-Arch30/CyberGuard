"""
Section 45: Comprehensive Test Suite for Persistent Background Jobs & Asynchronous Orchestration.
Validates:
1. Job Submission & Idempotency
2. Lifecycle Transitions & State Machine Validation
3. Atomic Job Claiming & Concurrency Safety
4. Transient vs Permanent Failure Handling & Exponential Backoff
5. Retry Exhaustion & Dead-Letter Handling
6. Stuck-Job Reaper & Lease Recovery
7. Cooperative Cancellation Semantics
8. Real Handlers Integration (Artifact Analysis & Report Generation)
9. Tenant Isolation & Security Boundary Enforcement
10. REST API Endpoints & Observability Metrics
"""
import pytest
import asyncio
import json
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    BackgroundJobModel,
    BackgroundJobEventModel,
    AnalysisRunModel,
    ArtifactModel,
    ReportModel,
    IncidentModel,
    get_utc_now,
)
from backend.schemas.jobs import (
    JobTypeEnum,
    JobStatusEnum,
    JobPriorityEnum,
)
from backend.services.background_job_service import (
    BackgroundJobService,
    JobLifecycleManager,
    InvalidJobStateTransitionError,
    JobNotFoundError,
)
from backend.services.background_job_worker import (
    BackgroundJobWorker,
    PermanentJobError,
    TransientJobError,
    JobExecutionContext,
)


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        try:
            db.query(BackgroundJobEventModel).delete()
            db.query(BackgroundJobModel).delete()
            db.commit()
        except Exception:
            db.rollback()
        db.close()


@pytest.fixture
def api_client():
    return TestClient(app)


# ============================================================================
# 1. Job Submission & Idempotency Tests
# ============================================================================

def test_job_submission_and_idempotency(db_session: Session):
    """Verifies job creation, state persistence, and idempotent deduplication."""
    key = f"idemp-{uuid.uuid4().hex[:12]}"

    # 1. First submission: creates job
    job1, created1 = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.ARTIFACT_ANALYSIS.value,
        workspace_id="default",
        requested_by="analyst_alice",
        priority="HIGH",
        payload={"sample_param": "test_value", "password": "SHOULD_BE_STRIPPED"},
        idempotency_key=key,
    )

    assert created1 is True
    assert job1.id is not None
    assert job1.status == JobStatusEnum.QUEUED.value
    assert job1.priority == "HIGH"
    assert job1.priority_weight == 3
    assert job1.attempt_count == 0
    assert job1.max_attempts == 3

    # Verify sensitive fields are stripped from payload_json
    payload_dict = json.loads(job1.payload_json)
    assert "sample_param" in payload_dict
    assert "password" not in payload_dict

    # 2. Duplicate submission with same key: returns existing job
    job2, created2 = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.ARTIFACT_ANALYSIS.value,
        workspace_id="default",
        idempotency_key=key,
    )

    assert created2 is False
    assert job2.id == job1.id
    assert job2.status == JobStatusEnum.QUEUED.value


def test_reject_unsupported_job_type(db_session: Session):
    """Ensures arbitrary or malicious job types are rejected."""
    with pytest.raises(ValueError, match="Unsupported job_type"):
        BackgroundJobService.submit_job(
            db=db_session,
            job_type="EXECUTE_ARBITRARY_SHELL",
            workspace_id="default",
        )


# ============================================================================
# 2. Lifecycle State Machine & Transition Rules
# ============================================================================

def test_legal_lifecycle_transitions(db_session: Session):
    """Verifies that legal transitions apply cleanly and log auditable events."""
    job, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.MAINTENANCE.value,
        workspace_id="default",
    )
    assert job.status == "QUEUED"

    # QUEUED -> RUNNING
    JobLifecycleManager.transition(db_session, job, "RUNNING", message="Worker claimed job")
    assert job.status == "RUNNING"
    assert job.started_at is not None

    # RUNNING -> SUCCEEDED
    JobLifecycleManager.transition(
        db_session, job, "SUCCEEDED",
        progress_percent=100.0,
        result_json={"items_cleaned": 5},
    )
    assert job.status == "SUCCEEDED"
    assert job.completed_at is not None
    assert job.progress_percent == 100.0

    # Verify auditable event sequence
    events = (
        db_session.query(BackgroundJobEventModel)
        .filter(BackgroundJobEventModel.job_id == job.id)
        .order_by(BackgroundJobEventModel.timestamp)
        .all()
    )
    event_types = [e.event_type for e in events]
    assert "JOB_QUEUED" in event_types
    assert "JOB_RUNNING" in event_types
    assert "JOB_SUCCEEDED" in event_types


def test_illegal_lifecycle_transitions(db_session: Session):
    """Ensures illegal state transitions are strictly rejected with InvalidJobStateTransitionError."""
    job, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.MAINTENANCE.value,
        workspace_id="default",
    )

    # Cannot transition directly from QUEUED to SUCCEEDED without running
    with pytest.raises(InvalidJobStateTransitionError):
        JobLifecycleManager.transition(db_session, job, "SUCCEEDED")

    # Mark as SUCCEEDED
    job.status = "SUCCEEDED"
    db_session.commit()

    # Terminal state cannot transition to RUNNING
    with pytest.raises(InvalidJobStateTransitionError):
        JobLifecycleManager.transition(db_session, job, "RUNNING")


# ============================================================================
# 3. Safe Atomic Claiming & Concurrency Safety
# ============================================================================

def test_atomic_job_claiming(db_session: Session):
    """Verifies atomic Compare-And-Swap claiming prevents duplicate execution."""
    ws = f"ws-atomic-{uuid.uuid4().hex[:8]}"
    job, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.MAINTENANCE.value,
        workspace_id=ws,
        priority="CRITICAL",
    )

    worker_a = "worker-host-1-aaa"
    worker_b = "worker-host-2-bbb"

    # Worker A claims the job
    claimed_a = BackgroundJobWorker.claim_next_job(db_session, worker_a, workspace_id=ws)
    assert claimed_a is not None
    assert claimed_a.id == job.id
    assert claimed_a.status == "RUNNING"
    assert claimed_a.worker_id == worker_a
    assert claimed_a.attempt_count == 1

    # Worker B tries to claim immediately: must receive None (job is now RUNNING)
    claimed_b = BackgroundJobWorker.claim_next_job(db_session, worker_b, workspace_id=ws)
    assert claimed_b is None


# ============================================================================
# 4. Retries, Backoff, and Dead-Letter Handling
# ============================================================================

def test_permanent_failure_transitions_to_failed_without_retry(db_session: Session):
    """Ensures permanent unrecoverable failures do not waste retry budgets."""
    ws = f"ws-perm-{uuid.uuid4().hex[:8]}"
    worker = BackgroundJobWorker(worker_id="test-worker")
    job, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.ARTIFACT_ANALYSIS.value,
        workspace_id=ws,
        payload={},  # Missing analysis_run_id causes PermanentJobError
    )

    # Claim
    claimed = BackgroundJobWorker.claim_next_job(db_session, worker.worker_id, workspace_id=ws)
    assert claimed is not None
    assert claimed.id == job.id

    # Execute
    asyncio.run(worker.execute_job(claimed.id))

    # Reload from DB
    db_session.refresh(job)
    assert job.status == "FAILED"
    assert job.error_code == "PERMANENT_ERROR"
    assert "Missing required 'analysis_run_id'" in (job.sanitized_error_message or "")


def test_retry_exhaustion_transitions_to_dead_letter(db_session: Session):
    """Verifies that transient errors retry until max_attempts, then transition to DEAD_LETTER."""
    job = BackgroundJobModel(
        workspace_id="default",
        job_type=JobTypeEnum.MAINTENANCE.value,
        status="RUNNING",
        attempt_count=3,
        max_attempts=3,
        created_at=get_utc_now(),
        scheduled_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add(job)
    db_session.commit()

    # Trigger failure directly
    worker = BackgroundJobWorker(worker_id="test-worker")

    # Simulate transient error handler
    async def mock_fail_handler(ctx, db):
        raise TransientJobError("Database connection timed out during execution")

    from backend.services.background_job_worker import JOB_HANDLERS
    orig_handler = JOB_HANDLERS.get(JobTypeEnum.MAINTENANCE.value)
    JOB_HANDLERS[JobTypeEnum.MAINTENANCE.value] = mock_fail_handler

    try:
        asyncio.run(worker.execute_job(job.id))
        db_session.refresh(job)
        assert job.status == "DEAD_LETTER"
        assert job.error_code == "RETRY_EXHAUSTED"
        assert "Database connection timed out" in (job.sanitized_error_message or "")
    finally:
        if orig_handler:
            JOB_HANDLERS[JobTypeEnum.MAINTENANCE.value] = orig_handler


# ============================================================================
# 5. Stuck-Job Recovery & Reaper
# ============================================================================

def test_stuck_job_reaper_recovery(db_session: Session):
    """Verifies that abandoned jobs with expired leases are recovered by the reaper."""
    now = get_utc_now()
    expired_time = now - timedelta(seconds=120)

    # Create abandoned job with expired heartbeat and remaining retry budget
    stuck_job = BackgroundJobModel(
        workspace_id="default",
        job_type=JobTypeEnum.MAINTENANCE.value,
        status="RUNNING",
        attempt_count=1,
        max_attempts=3,
        worker_id="dead-worker-pid-999",
        heartbeat_at=expired_time,
        lease_expires_at=expired_time,
        created_at=expired_time,
        scheduled_at=expired_time,
        updated_at=expired_time,
    )
    db_session.add(stuck_job)
    db_session.commit()

    reaped_count = BackgroundJobWorker.reap_stuck_jobs(db_session, lease_timeout_seconds=60)
    assert reaped_count >= 1

    db_session.refresh(stuck_job)
    assert stuck_job.status == "RETRY_WAIT"
    assert stuck_job.worker_id is None
    sched = stuck_job.scheduled_at
    if sched.tzinfo is None:
        sched = sched.replace(tzinfo=timezone.utc)
    assert sched > now


# ============================================================================
# 6. Cancellation Semantics
# ============================================================================

def test_cancel_queued_and_running_job(db_session: Session):
    """Verifies cancellation of queued and running jobs."""
    # 1. Cancel QUEUED job
    job1, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.MAINTENANCE.value,
        workspace_id="default",
    )
    res1 = BackgroundJobService.cancel_job(db_session, job1.id)
    assert res1.success is True
    assert res1.current_status == "CANCELLED"

    db_session.refresh(job1)
    assert job1.status == "CANCELLED"

    # 2. Cancel RUNNING job (signals CANCEL_REQUESTED)
    job2, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.MAINTENANCE.value,
        workspace_id="default",
    )
    JobLifecycleManager.transition(db_session, job2, "RUNNING")

    res2 = BackgroundJobService.cancel_job(db_session, job2.id)
    assert res2.success is True
    assert res2.current_status == "CANCEL_REQUESTED"

    db_session.refresh(job2)
    assert job2.status == "CANCEL_REQUESTED"


# ============================================================================
# 7. Real Handlers Integration: Artifact Analysis & Reports
# ============================================================================

def test_artifact_analysis_handler_execution(db_session: Session):
    """Verifies ARTIFACT_ANALYSIS handler executes DAG, updates AnalysisRunModel, and completes job."""
    ws = f"ws-artifact-{uuid.uuid4().hex[:8]}"
    # Create test artifact and AnalysisRunModel
    artifact = ArtifactModel(
        artifact_type="EMAIL",
        name="phishing_evidence.eml",
        size=1024,
        sha256="aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    )
    db_session.add(artifact)
    db_session.commit()

    run = AnalysisRunModel(
        artifact_id=artifact.id,
        status="QUEUED",
        trigger="USER",
    )
    db_session.add(run)
    db_session.commit()

    # Submit background job
    job, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.ARTIFACT_ANALYSIS.value,
        workspace_id=ws,
        resource_type="ARTIFACT",
        resource_id=artifact.id,
        analysis_run_id=run.id,
    )

    worker = BackgroundJobWorker(worker_id="test-analysis-worker")
    claimed = BackgroundJobWorker.claim_next_job(db_session, worker.worker_id, workspace_id=ws)
    assert claimed is not None
    assert claimed.id == job.id

    # Execute
    asyncio.run(worker.execute_job(claimed.id))

    db_session.refresh(job)
    db_session.refresh(run)

    # Job and run should both have succeeded
    assert job.status in ("SUCCEEDED", "PARTIALLY_SUCCEEDED")
    assert run.status in ("COMPLETED", "PARTIAL")
    assert job.progress_percent == 100.0


# ============================================================================
# 8. Tenant Isolation & Security Boundaries
# ============================================================================

def test_tenant_isolation_boundary(db_session: Session, api_client: TestClient):
    """Ensures jobs belonging to tenant A cannot be viewed or manipulated by tenant B."""
    job, _ = BackgroundJobService.submit_job(
        db=db_session,
        job_type=JobTypeEnum.MAINTENANCE.value,
        workspace_id="tenant-alpha",
    )

    # Access with correct tenant header: 200 OK
    res_ok = api_client.get(f"/api/jobs/{job.id}", headers={"X-Workspace-ID": "tenant-alpha"})
    assert res_ok.status_code == 200
    assert res_ok.json()["id"] == job.id

    # Access with different tenant header: 404 NOT FOUND
    res_forbidden = api_client.get(f"/api/jobs/{job.id}", headers={"X-Workspace-ID": "tenant-beta"})
    assert res_forbidden.status_code == 404

    # Cancellation from wrong tenant: 404 NOT FOUND
    res_cancel_forbidden = api_client.post(
        f"/api/jobs/{job.id}/cancel", headers={"X-Workspace-ID": "tenant-beta"}
    )
    assert res_cancel_forbidden.status_code == 404


# ============================================================================
# 9. REST API Endpoints & Observability Metrics
# ============================================================================

def test_jobs_api_crud_and_metrics(api_client: TestClient):
    """Verifies submit, list, get, events, retry, and metrics endpoints."""
    # 1. Submit job via API
    submit_payload = {
        "job_type": "MAINTENANCE",
        "priority": "HIGH",
        "payload": {"clean_scratch": True},
        "idempotency_key": f"api-test-{uuid.uuid4().hex[:8]}",
    }
    create_res = api_client.post("/api/jobs", json=submit_payload, headers={"X-Workspace-ID": "default"})
    assert create_res.status_code == 201
    job_data = create_res.json()
    job_id = job_data["id"]
    assert job_data["status"] == "QUEUED"
    assert job_data["priority"] == "HIGH"

    # 2. Get job
    get_res = api_client.get(f"/api/jobs/{job_id}", headers={"X-Workspace-ID": "default"})
    assert get_res.status_code == 200
    assert get_res.json()["id"] == job_id

    # 3. List jobs
    list_res = api_client.get("/api/jobs", headers={"X-Workspace-ID": "default"})
    assert list_res.status_code == 200
    list_data = list_res.json()
    assert list_data["total"] >= 1
    assert any(j["id"] == job_id for j in list_data["items"])

    # 4. Get events
    events_res = api_client.get(f"/api/jobs/{job_id}/events", headers={"X-Workspace-ID": "default"})
    assert events_res.status_code == 200
    events_data = events_res.json()
    assert len(events_data) >= 1
    assert events_data[0]["event_type"] == "JOB_QUEUED"

    # 5. Cancel job
    cancel_res = api_client.post(f"/api/jobs/{job_id}/cancel", headers={"X-Workspace-ID": "default"})
    assert cancel_res.status_code == 200
    assert cancel_res.json()["success"] is True

    # 6. Retry job
    # First transition to FAILED manually to allow retry
    with SessionLocal() as db:
        job = db.query(BackgroundJobModel).filter(BackgroundJobModel.id == job_id).first()
        job.status = "FAILED"
        db.commit()

    retry_res = api_client.post(f"/api/jobs/{job_id}/retry", headers={"X-Workspace-ID": "default"})
    assert retry_res.status_code == 200
    assert retry_res.json()["current_status"] == "QUEUED"

    # 7. Get Metrics Summary
    metrics_res = api_client.get("/api/jobs/metrics/summary", headers={"X-Workspace-ID": "default"})
    assert metrics_res.status_code == 200
    metrics = metrics_res.json()
    assert "queued" in metrics
    assert "running" in metrics
    assert "succeeded" in metrics
    assert "failed" in metrics
    assert "dead_letter" in metrics
    assert metrics["total_jobs"] >= 1
