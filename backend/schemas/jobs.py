"""
Section 45: Pydantic schemas for Persistent Background Jobs & Asynchronous Orchestration.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class JobTypeEnum(str, Enum):
    ARTIFACT_ANALYSIS = "ARTIFACT_ANALYSIS"
    REPORT_GENERATION = "REPORT_GENERATION"
    CROSS_INCIDENT_CORRELATION = "CROSS_INCIDENT_CORRELATION"
    ATTACK_PATH_RECONSTRUCTION = "ATTACK_PATH_RECONSTRUCTION"
    ENDPOINT_TELEMETRY_PROCESSING = "ENDPOINT_TELEMETRY_PROCESSING"
    EVIDENCE_EXPORT = "EVIDENCE_EXPORT"
    MAINTENANCE = "MAINTENANCE"


class JobStatusEnum(str, Enum):
    QUEUED = "QUEUED"
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    RETRY_WAIT = "RETRY_WAIT"
    SUCCEEDED = "SUCCEEDED"
    PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED"
    FAILED = "FAILED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    DEAD_LETTER = "DEAD_LETTER"


class JobPriorityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    NORMAL = "NORMAL"
    LOW = "LOW"


PRIORITY_WEIGHTS = {
    JobPriorityEnum.CRITICAL.value: 4,
    JobPriorityEnum.HIGH.value: 3,
    JobPriorityEnum.NORMAL.value: 2,
    JobPriorityEnum.LOW.value: 1,
}


class JobSubmitRequest(BaseModel):
    """Client request to submit an asynchronous background job."""
    job_type: JobTypeEnum = Field(..., description="Registered job type to execute")
    resource_type: Optional[str] = Field(None, description="Resource category, e.g. ARTIFACT, REPORT")
    resource_id: Optional[str] = Field(None, description="Identifier of the resource being operated on")
    analysis_run_id: Optional[str] = Field(None, description="Optional AnalysisRunModel foreign key")
    report_id: Optional[str] = Field(None, description="Optional ReportModel foreign key")
    priority: JobPriorityEnum = Field(JobPriorityEnum.NORMAL, description="Job priority level")
    payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Job input parameters (no secrets or raw bytes)")
    idempotency_key: Optional[str] = Field(None, description="Client idempotency key to prevent duplicate jobs")
    timeout_seconds: Optional[int] = Field(None, ge=10, le=3600, description="Execution timeout in seconds")
    max_attempts: Optional[int] = Field(None, ge=1, le=10, description="Maximum retry attempts")


class JobEventRead(BaseModel):
    """Serialized background job event record."""
    id: str
    job_id: str
    workspace_id: str
    event_type: str
    stage: Optional[str] = None
    progress_percent: Optional[float] = None
    message: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime


class JobReadResponse(BaseModel):
    """Comprehensive status response for a background job."""
    id: str
    workspace_id: str
    job_type: str
    status: str
    priority: str
    priority_weight: int
    requested_by: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    report_id: Optional[str] = None
    attempt_count: int
    max_attempts: int
    created_at: datetime
    scheduled_at: datetime
    started_at: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    updated_at: datetime
    timeout_seconds: int
    worker_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    progress_percent: Optional[float] = None
    current_stage: Optional[str] = None
    error_code: Optional[str] = None
    sanitized_error_message: Optional[str] = None
    result_reference: Optional[str] = None
    result: Dict[str, Any] = Field(default_factory=dict)
    events: Optional[List[JobEventRead]] = None


class JobListResponse(BaseModel):
    """Paginated list of background jobs."""
    total: int
    page: int
    page_size: int
    items: List[JobReadResponse]


class JobMetricsSummary(BaseModel):
    """Operational observability metrics for the background job subsystem."""
    queued: int
    scheduled: int
    running: int
    retry_wait: int
    succeeded: int
    partially_succeeded: int
    failed: int
    dead_letter: int
    cancelled: int
    timed_out: int
    total_jobs: int
    avg_wait_duration_seconds: float
    avg_execution_duration_seconds: float
    active_workers: List[str]


class JobActionResponse(BaseModel):
    """Response returned upon cancelling or retrying a job."""
    success: bool
    job_id: str
    previous_status: str
    current_status: str
    message: str
