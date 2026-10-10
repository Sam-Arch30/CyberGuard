"""
Pydantic schemas for Section 37 Live Analysis & Task DAG Orchestration.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AnalysisTaskStatusEnum(str, Enum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    CANCELLED = "CANCELLED"


class AnalysisEventTypeEnum(str, Enum):
    RUN_STARTED = "RUN_STARTED"
    TASK_STARTED = "TASK_STARTED"
    TASK_PROGRESS = "TASK_PROGRESS"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    FINDING_PRODUCED = "FINDING_PRODUCED"
    RISK_ASSESSED = "RISK_ASSESSED"
    RUN_COMPLETED = "RUN_COMPLETED"
    RUN_FAILED = "RUN_FAILED"
    RUN_CANCELLED = "RUN_CANCELLED"
    # Section 46 Canonical Lifecycle Names
    ANALYSIS_STARTED = "ANALYSIS_STARTED"
    ANALYSIS_STAGE_STARTED = "ANALYSIS_STAGE_STARTED"
    ANALYSIS_STAGE_COMPLETED = "ANALYSIS_STAGE_COMPLETED"
    ANALYSIS_PROGRESS = "ANALYSIS_PROGRESS"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_PARTIAL = "ANALYSIS_PARTIAL"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    ANALYSIS_CANCELLED = "ANALYSIS_CANCELLED"
    FINDING_PERSISTED = "FINDING_PERSISTED"
    INDICATOR_DISCOVERED = "INDICATOR_DISCOVERED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"
    ANALYZER_WARNING = "ANALYZER_WARNING"
    ANALYZER_DEGRADED = "ANALYZER_DEGRADED"


class AnalysisTaskRead(BaseModel):
    id: str
    analysis_run_id: str
    analyzer_id: str
    task_type: str
    title: str
    description: Optional[str] = None
    status: AnalysisTaskStatusEnum
    dependency_ids: List[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    progress: Optional[float] = None
    message: Optional[str] = None
    error: Optional[str] = None
    result_count: int = 0
    version: str = "1.0.0"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class AnalysisEventRead(BaseModel):
    id: str
    analysis_run_id: str
    task_id: Optional[str] = None
    event_type: AnalysisEventTypeEnum
    sequence: int = 1
    timestamp: datetime
    task_status: Optional[str] = None
    message: str
    result_count: int = 0
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class FindingPreview(BaseModel):
    id: str
    analyzer: str
    finding_type: str
    title: str
    severity: str
    confidence: float = 1.0
    risk_contribution: float = 0.0

    model_config = ConfigDict(from_attributes=True)


class AnalysisRunLiveResponse(BaseModel):
    id: str
    artifact_id: str
    investigation_id: Optional[str] = None
    evidence_id: Optional[str] = None
    artifact_name: str
    artifact_type: str
    artifact_size: int
    artifact_sha256: Optional[str] = None
    artifact_source: str
    status: str
    trigger: str
    pipeline_version: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    overall_risk_score: Optional[float] = None
    overall_severity: Optional[str] = None
    confidence: Optional[float] = None
    error: Optional[str] = None
    total_tasks: int = 0
    completed_tasks: int = 0
    running_tasks: int = 0
    failed_tasks: int = 0
    pending_tasks: int = 0
    progress: Optional[float] = None
    current_task: Optional[AnalysisTaskRead] = None
    tasks: List[AnalysisTaskRead] = Field(default_factory=list)
    events: List[AnalysisEventRead] = Field(default_factory=list)
    findings: List[FindingPreview] = Field(default_factory=list)
    previous_runs_count: int = 0

    model_config = ConfigDict(from_attributes=True)
