"""
Section 46: Comprehensive Test Suite for Real-Time Analysis Updates & SSE Infrastructure.
Validates:
1. Structured RealtimeEvent Schema Contract (schema_version: 1, sequence, safety)
2. In-Memory Hub Topic Routing, Monotonic Sequencing & Bounded Backpressure
3. Database Event Persistence & Last-Event-ID Replay
4. Analysis Orchestrator Lifecycle Transitions & Finding Emission
5. Background Job Lifecycle Events & Worker Integration
6. Failure Isolation (Transport / Hub failures never compromise core execution)
7. Tenant Isolation & Resource-Scoped Authorization on SSE Endpoints
8. Terminal State Stream Handling & Replay Reconnection
"""
import pytest
import asyncio
import json
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.main import app
from backend.db.session import SessionLocal
from backend.db.models import (
    BackgroundJobModel,
    BackgroundJobEventModel,
    AnalysisRunModel,
    AnalysisEventModel,
    ArtifactModel,
    FindingModel,
    ReportModel,
    IncidentModel,
    get_utc_now,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
    RealtimeEventPayload,
    sanitize_error_message,
)
from backend.services.realtime_service import (
    RealtimeEventHub,
    RealtimePublisher,
    global_realtime_hub,
)
from backend.services.background_job_service import (
    BackgroundJobService,
    JobLifecycleManager,
)
from backend.schemas.jobs import (
    JobTypeEnum,
    JobStatusEnum,
    JobPriorityEnum,
)
from backend.services.analysis_orchestrator import AnalysisOrchestrator


@pytest.fixture
def db_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        try:
            db.query(AnalysisEventModel).delete()
            db.query(BackgroundJobEventModel).delete()
            db.query(FindingModel).delete()
            db.query(AnalysisRunModel).delete()
            db.query(BackgroundJobModel).delete()
            db.query(ArtifactModel).delete()
            db.query(ReportModel).delete()
            db.query(IncidentModel).delete()
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()


@pytest.fixture
def test_client():
    return TestClient(app)


# =========================================================================
# 1. EVENT SCHEMA CONTRACT & ERROR SANITIZATION TESTS
# =========================================================================

def test_realtime_event_schema_contract():
    """Verify that RealtimeEvent enforces schema_version 1, monotonic sequence, and fields."""
    event = RealtimeEvent(
        schema_version=1,
        event_id="evt-1001",
        sequence=42,
        event_type=RealtimeEventTypeEnum.ANALYSIS_STAGE_STARTED.value,
        resource_type=RealtimeResourceScopeEnum.ANALYSIS_RUN.value,
        resource_id="run-123",
        workspace_id="test-workspace",
        stage="URL_INTELLIGENCE",
        status="RUNNING",
        message="Stage URL_INTELLIGENCE begun",
        payload=RealtimeEventPayload(
            task_id="task-456",
            task_type="URL_ANALYSIS",
            completed_tasks=3,
            total_tasks=7,
        ),
    )

    data = event.model_dump()
    assert data["schema_version"] == 1
    assert data["sequence"] == 42
    assert data["event_type"] == "ANALYSIS_STAGE_STARTED"
    assert data["resource_type"] == "ANALYSIS_RUN"
    assert data["payload"]["completed_tasks"] == 3
    assert data["payload"]["total_tasks"] == 7


def test_sanitize_error_message_scrubs_sensitive_details():
    """Verify that internal tracebacks, passwords, tokens, and raw DB exceptions are sanitized."""
    raw_error = "PostgresConnectionError: password authentication failed for user 'admin' at 10.0.0.1; Traceback (most recent call last):"
    sanitized = sanitize_error_message(raw_error)
    assert "password" not in sanitized.lower()
    assert "Traceback" not in sanitized
    assert "10.0.0.1" not in sanitized

    raw_token_err = "Auth failed: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret_jwt_token"
    sanitized_tok = sanitize_error_message(raw_token_err)
    assert "secret_jwt_token" not in sanitized_tok


# =========================================================================
# 2. EVENT HUB TOPIC ROUTING, SEQUENCING & BACKPRESSURE TESTS
# =========================================================================

def test_event_hub_subscribe_publish_and_sequence():
    """Verify RealtimeEventHub routes events by topic with monotonically increasing sequence."""
    async def _test():
        hub = RealtimeEventHub()
        topic = "run:test-run-1"

        queue = await hub.subscribe(topic, max_queue_size=20)
        assert queue is not None

        evt1 = RealtimeEvent(
            schema_version=1,
            event_id="evt-1",
            sequence=1,
            event_type=RealtimeEventTypeEnum.ANALYSIS_STARTED.value,
            resource_type=RealtimeResourceScopeEnum.ANALYSIS_RUN.value,
            resource_id="test-run-1",
            analysis_run_id="test-run-1",
            workspace_id="default",
            message="Started",
        )
        evt2 = RealtimeEvent(
            schema_version=1,
            event_id="evt-2",
            sequence=2,
            event_type=RealtimeEventTypeEnum.ANALYSIS_STAGE_STARTED.value,
            resource_type=RealtimeResourceScopeEnum.ANALYSIS_RUN.value,
            resource_id="test-run-1",
            analysis_run_id="test-run-1",
            workspace_id="default",
            stage="HEADER_ANALYSIS",
            message="Stage started",
        )

        await hub.publish(topic, evt1)
        await hub.publish(topic, evt2)

        received1 = await asyncio.wait_for(queue.get(), timeout=1.0)
        received2 = await asyncio.wait_for(queue.get(), timeout=1.0)

        assert received1["event_id"] == "evt-1"
        assert received1["sequence"] == 1
        assert received2["event_id"] == "evt-2"
        assert received2["sequence"] == 2

        # Unsubscribe cleans up
        await hub.unsubscribe(topic, queue)
        assert hub.get_subscriber_count(topic) == 0

    asyncio.run(_test())


def test_event_hub_backpressure_handles_full_queue():
    """Verify that when queue is full, high-frequency progress updates can be dropped without failing."""
    async def _test():
        hub = RealtimeEventHub()
        topic = "job:test-job-backpressure"

        queue = await hub.subscribe(topic, max_queue_size=2)

        # Fill queue with 2 events
        for i in range(1, 3):
            evt = RealtimeEvent(
                schema_version=1,
                event_id=f"evt-{i}",
                sequence=i,
                event_type=RealtimeEventTypeEnum.JOB_PROGRESS.value,
                resource_type=RealtimeResourceScopeEnum.JOB.value,
                resource_id="test-job-backpressure",
                job_id="test-job-backpressure",
                workspace_id="default",
                message=f"Progress {i}",
            )
            await hub.publish(topic, evt)

        assert queue.qsize() == 2

        # Third progress event arrives with full queue - should not raise exception
        overflow_evt = RealtimeEvent(
            schema_version=1,
            event_id="evt-3",
            sequence=3,
            event_type=RealtimeEventTypeEnum.JOB_PROGRESS.value,
            resource_type=RealtimeResourceScopeEnum.JOB.value,
            resource_id="test-job-backpressure",
            job_id="test-job-backpressure",
            workspace_id="default",
            message="Progress 3 (overflow)",
        )
        await hub.publish(topic, overflow_evt)

        # Queue remains capped at maxsize
        assert queue.qsize() == 2
        await hub.unsubscribe(topic, queue)

    asyncio.run(_test())


# =========================================================================
# 3. DATABASE REPLAY & LAST-EVENT-ID TESTS
# =========================================================================

def test_database_replay_events_for_reconnection(db_session: Session):
    """Verify that RealtimeEventHub.get_replay_events retrieves persisted events after last_event_id."""
    hub = RealtimeEventHub()
    run_id = f"run-replay-{uuid.uuid4().hex[:8]}"

    # Insert 4 historical analysis events with sequences 1, 2, 3, 4
    for seq in range(1, 5):
        event_model = AnalysisEventModel(
            id=f"evt-replay-{seq}",
            analysis_run_id=run_id,
            sequence=seq,
            event_type="STAGE_STARTED" if seq < 4 else "RUN_COMPLETED",
            message=f"Message for seq {seq}",
            task_status="RUNNING" if seq < 4 else "COMPLETED",
            timestamp=get_utc_now(),
        )
        db_session.add(event_model)
    db_session.commit()

    # Client reconnects with Last-Event-ID = 2
    replayed = hub.get_replay_events(db_session, f"run:{run_id}", last_event_id=2)
    assert len(replayed) == 2
    assert replayed[0].sequence == 3
    assert replayed[1].sequence == 4
    assert replayed[1].event_type == "RUN_COMPLETED"


# =========================================================================
# 4. ANALYSIS ORCHESTRATOR EVENT EMISSION
# =========================================================================

def test_orchestrator_emits_canonical_events_with_sequence(db_session: Session):
    """Verify that AnalysisOrchestrator emits structured events persisted with monotonic sequences."""
    # Create test artifact
    artifact_id = f"art-{uuid.uuid4().hex[:8]}"
    artifact = ArtifactModel(
        id=artifact_id,
        artifact_type="EMAIL",
        name="phishing_test.eml",
        source="TEST",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        metadata_json=json.dumps({"workspace_id": "test-ws"}),
    )
    db_session.add(artifact)

    run_id = f"run-{uuid.uuid4().hex[:8]}"
    run_model = AnalysisRunModel(
        id=run_id,
        artifact_id=artifact_id,
        status="RUNNING",
    )
    db_session.add(run_model)
    db_session.commit()

    # Emit analysis stage started
    AnalysisOrchestrator.emit_event(
        db=db_session,
        run_id=run_id,
        event_type="ANALYSIS_STAGE_STARTED",
        message="Header analysis in progress",
        task_status="HEADER_AUTHENTICATION",
    )

    # Emit finding persisted
    AnalysisOrchestrator.emit_event(
        db=db_session,
        run_id=run_id,
        event_type="FINDING_PERSISTED",
        message="SPF Authentication failure detected",
        task_status="HEADER_AUTHENTICATION",
        metadata={
            "finding_id": "find-101",
            "finding_type": "SPF_FAIL",
            "severity": "HIGH",
            "risk_contribution": 35.0,
        },
    )

    # Check DB persistence
    persisted_events = (
        db_session.query(AnalysisEventModel)
        .filter(AnalysisEventModel.analysis_run_id == run_id)
        .order_by(AnalysisEventModel.sequence.asc())
        .all()
    )

    assert len(persisted_events) >= 2
    assert persisted_events[0].sequence == 1
    assert persisted_events[0].event_type == "ANALYSIS_STAGE_STARTED"
    assert persisted_events[1].sequence == 2
    assert persisted_events[1].event_type == "FINDING_PERSISTED"


# =========================================================================
# 5. BACKGROUND JOB LIFECYCLE EVENTS
# =========================================================================

def test_job_lifecycle_manager_emits_realtime_events(db_session: Session):
    """Verify that JobLifecycleManager emits monotonic events on state transitions."""
    job_id = f"job-{uuid.uuid4().hex[:8]}"
    job = BackgroundJobModel(
        id=job_id,
        workspace_id="test-ws",
        job_type=JobTypeEnum.ARTIFACT_ANALYSIS.value,
        resource_id="res-123",
        status=JobStatusEnum.QUEUED.value,
        priority=JobPriorityEnum.NORMAL.value,
        max_attempts=3,
    )
    db_session.add(job)
    db_session.commit()

    # Transition to RUNNING
    JobLifecycleManager.transition(
        db=db_session,
        job=job,
        target_status=JobStatusEnum.RUNNING.value,
        message="Worker started job",
    )

    events = (
        db_session.query(BackgroundJobEventModel)
        .filter(BackgroundJobEventModel.job_id == job_id)
        .order_by(BackgroundJobEventModel.sequence.asc())
        .all()
    )

    assert len(events) >= 1
    latest_evt = events[-1]
    assert latest_evt.event_type in ("JOB_RUNNING", "JOB_STARTED")
    assert latest_evt.sequence >= 1


# =========================================================================
# 6. FAILURE ISOLATION (TRANSPORT OUTAGE DOES NOT COMPROMISE JOBS)
# =========================================================================

def test_transport_failure_does_not_fail_publisher(db_session: Session, monkeypatch):
    """Verify that publisher catches and isolates transport/hub errors so jobs and analysis proceed."""
    async def broken_broadcast(*args, **kwargs):
        raise RuntimeError("Network socket broken / hub offline")

    monkeypatch.setattr(global_realtime_hub, "broadcast", broken_broadcast)

    # Calling RealtimePublisher.publish_event should not raise exception
    try:
        RealtimePublisher.publish_event(
            db=db_session,
            topic="job:safe-test-job",
            event_type="JOB_PROGRESS",
            resource_type="JOB",
            resource_id="safe-test-job",
            workspace_id="default",
            message="Progress update during transport glitch",
            persist_job_event=True,
        )
    except Exception as exc:
        pytest.fail(f"RealtimePublisher failed when transport threw error: {exc}")


# =========================================================================
# 7. TENANT ISOLATION & AUTHORIZATION ON SSE STREAMS
# =========================================================================

def test_sse_endpoint_rejects_cross_tenant_access(test_client: TestClient, db_session: Session):
    """Verify that tenant B cannot stream events for a job or analysis belonging to tenant A."""
    job_id = f"job-sec-{uuid.uuid4().hex[:8]}"
    job = BackgroundJobModel(
        id=job_id,
        workspace_id="tenant-alpha",
        job_type=JobTypeEnum.ARTIFACT_ANALYSIS.value,
        status=JobStatusEnum.SUCCEEDED.value,
    )
    db_session.add(job)

    # Create Analysis Run with artifact belonging to tenant-alpha
    art_id = f"art-sec-{uuid.uuid4().hex[:8]}"
    art = ArtifactModel(
        id=art_id,
        artifact_type="EMAIL",
        name="secret.eml",
        metadata_json=json.dumps({"workspace_id": "tenant-alpha"}),
    )
    db_session.add(art)

    run_id = f"run-sec-{uuid.uuid4().hex[:8]}"
    run_model = AnalysisRunModel(
        id=run_id,
        artifact_id=art_id,
        status="COMPLETED",
    )
    db_session.add(run_model)
    db_session.commit()

    # 1. Tenant Alpha (Authorized) accesses stream
    res_auth = test_client.get(
        f"/api/jobs/{job_id}/stream",
        headers={"X-Workspace-ID": "tenant-alpha"},
    )
    assert res_auth.status_code == 200

    # 2. Tenant Beta (Unauthorized / Attacker) attempts access to Job Stream
    res_unauth = test_client.get(
        f"/api/jobs/{job_id}/stream",
        headers={"X-Workspace-ID": "tenant-beta"},
    )
    assert res_unauth.status_code in [403, 404]

    # 3. Tenant Beta attempts access to Analysis Run Stream
    res_run_unauth = test_client.get(
        f"/api/analysis/{run_id}/stream",
        headers={"X-Workspace-ID": "tenant-beta"},
    )
    assert res_run_unauth.status_code in [403, 404]


# =========================================================================
# 8. TERMINAL STATE HANDLING IN STREAM
# =========================================================================

def test_sse_terminal_state_handling(test_client: TestClient, db_session: Session):
    """Verify that an already terminal job sends terminal event and closes cleanly."""
    job_id = f"job-term-{uuid.uuid4().hex[:8]}"
    job = BackgroundJobModel(
        id=job_id,
        workspace_id="default",
        job_type=JobTypeEnum.REPORT_GENERATION.value,
        status=JobStatusEnum.SUCCEEDED.value,
    )
    db_session.add(job)
    db_session.commit()

    res = test_client.get(
        f"/api/jobs/{job_id}/stream",
        headers={"X-Workspace-ID": "default"},
    )
    assert res.status_code == 200
    content = res.text
    # Should include terminal event
    assert "event: terminal" in content
    assert "SUCCEEDED" in content
