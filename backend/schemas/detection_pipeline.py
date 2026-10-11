"""
Section 59: Pydantic Schemas and Contracts for the Unified Threat Detection Pipeline.
Defines:
- Canonical normalized detection event contract
- Ingestion requests (single and batch)
- Rule evaluation detail and pipeline execution responses
- Observability and pipeline metrics
- Historical replay and dead-letter schemas
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.schemas.candidate_rules import RuleSeverity
from backend.schemas.detection_rules import (
    RuleCategory,
    RuleDataSource,
    RuleScope,
    ValidationStatusEnum,
)


class PipelineStageEnum(str, Enum):
    RECEIVE = "RECEIVE"
    VALIDATE = "VALIDATE"
    NORMALIZE = "NORMALIZE"
    TENANT_SCOPE = "TENANT_SCOPE"
    RESOLVE_RULES = "RESOLVE_RULES"
    EXECUTE = "EXECUTE"
    PERSIST_MATCH = "PERSIST_MATCH"
    CREATE_FINDING = "CREATE_FINDING"
    RISK_EVALUATION = "RISK_EVALUATION"
    ALERT_POLICY = "ALERT_POLICY"
    NOTIFICATION = "NOTIFICATION"
    REALTIME = "REALTIME"
    AUDIT = "AUDIT"


class EvaluationOutcomeEnum(str, Enum):
    MATCH = "MATCH"
    NO_MATCH = "NO_MATCH"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    ERROR = "ERROR"
    TIMEOUT = "TIMEOUT"


class PipelineHealthStatusEnum(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    BACKLOGGED = "BACKLOGGED"
    FAILING = "FAILING"


class PipelineModeEnum(str, Enum):
    PRODUCTION = "PRODUCTION"
    SHADOW = "SHADOW"
    REPLAY = "REPLAY"


# ============================================================================
# 1. CANONICAL NORMALIZED DETECTION EVENT CONTRACT
# ============================================================================

class NormalizedDetectionEvent(BaseModel):
    """
    Canonical normalized security event schema for all Section 59 detection evaluation.
    Preserves exact provenance, entity mappings, and original payload.
    """
    model_config = ConfigDict(from_attributes=True)

    event_id: str = Field(description="Unique or deterministic identifier for event")
    workspace_id: str = Field(default="default", description="Multi-tenant workspace boundary")
    event_type: str = Field(description="Normalized event type e.g. EMAIL_EVENT, ENDPOINT_EVENT")
    source_type: str = Field(description="High-level source category e.g. EMAIL, ENDPOINT, NETWORK, AUTH, API")
    source_id: Optional[str] = Field(default=None, description="Identifier of source artifact, host, or sensor")
    occurred_at: datetime = Field(description="Real-world event occurrence timestamp (UTC)")
    received_at: datetime = Field(description="Platform ingestion timestamp (UTC)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Normalized key-value attributes for rule AST evaluation")
    entities: List[Dict[str, Any]] = Field(default_factory=list, description="Resolved entity references (user, device, ip, domain)")
    indicators: List[Dict[str, Any]] = Field(default_factory=list, description="Extracted observables/IOCs (hash, domain, url)")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Ingestion pathway, adapter, artifact references")
    schema_version: str = Field(default="1.0", description="Contract version")


# ============================================================================
# 2. INGESTION REQUESTS & PAYLOADS
# ============================================================================

class EventIngestRequest(BaseModel):
    """Payload to ingest and evaluate a single telemetry event."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    workspace_id: Optional[str] = Field(default="default")
    source_type: str = Field(default="GENERIC", description="EMAIL, ENDPOINT, NETWORK, AUTH, API, GENERIC")
    event_type: Optional[str] = Field(default=None, description="Optional override e.g. EMAIL_EVENT")
    event_id: Optional[str] = Field(default=None, description="Optional caller-supplied unique event ID for idempotency")
    occurred_at: Optional[datetime] = Field(default=None, description="Event occurrence time; defaults to now")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Raw or normalized event key-values")
    source_id: Optional[str] = Field(default=None, description="Artifact or device identifier")
    provenance: Optional[Dict[str, Any]] = Field(default=None, description="Optional tracing references")
    mode: PipelineModeEnum = Field(default=PipelineModeEnum.PRODUCTION, description="PRODUCTION, SHADOW, or REPLAY")

    @model_validator(mode="before")
    @classmethod
    def resolve_source_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "source" in data and "source_type" not in data:
                data["source_type"] = data["source"]
        return data


class BatchEventIngestRequest(BaseModel):
    """Payload to ingest and evaluate a batch of telemetry events."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    workspace_id: Optional[str] = Field(default="default")
    events: List[EventIngestRequest] = Field(..., min_length=1, max_length=5000)
    run_async: bool = Field(default=False, description="If True, processes via Section 45 Background Job")
    priority: str = Field(default="NORMAL", description="CRITICAL, HIGH, NORMAL, LOW")
    mode: PipelineModeEnum = Field(default=PipelineModeEnum.PRODUCTION, description="PRODUCTION, SHADOW, or REPLAY")
    stop_on_error: bool = Field(default=False, description="Whether to stop on first processing error")


# ============================================================================
# 3. RULE EVALUATION & PIPELINE EXECUTION RESPONSES
# ============================================================================

class RuleEvaluationDetail(BaseModel):
    """Individual rule evaluation outcome on an event."""
    rule_id: str
    rule_identifier: Optional[str] = None
    rule_name: str
    rule_version: str
    category: str
    severity: str
    outcome: EvaluationOutcomeEnum
    matched: bool
    execution_time_ms: float
    matched_conditions: List[Dict[str, Any]] = Field(default_factory=list)
    explanation: Optional[str] = None
    skip_reason: Optional[str] = None
    error_message: Optional[str] = None
    detection_id: Optional[str] = None
    finding_id: Optional[str] = None
    alert_id: Optional[str] = None


class PipelineExecutionResponse(BaseModel):
    """End-to-end execution outcome for a processed detection event."""
    event_id: str
    workspace_id: str
    source_type: str
    event_type: str
    occurred_at: datetime
    processed_at: datetime
    duration_ms: float
    mode: PipelineModeEnum
    applicable_rules_count: int
    evaluated_rules_count: int
    matches_count: int
    findings_count: int
    alerts_count: int
    evaluations: List[RuleEvaluationDetail] = Field(default_factory=list)
    matches: List[Dict[str, Any]] = Field(default_factory=list)
    trace: Dict[str, Any] = Field(default_factory=dict)


class BatchPipelineResponse(BaseModel):
    """Response summary for batch ingestion and processing."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    batch_id: str
    workspace_id: str
    total_events: int
    processed_events: int
    failed_events: int
    total_matches: int
    total_findings: int
    total_alerts: int
    duration_ms: float
    results: List[PipelineExecutionResponse] = Field(default_factory=list)
    job_id: Optional[str] = None

    @property
    def matched_events(self) -> int:
        return self.total_matches

    @property
    def error_events(self) -> int:
        return self.failed_events


# ============================================================================
# 4. REPLAY & DEAD-LETTER DTOs
# ============================================================================

class PipelineReplayRequest(BaseModel):
    """Controlled historical replay of security events against rules."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    workspace_id: str = Field(default="default")
    rule_ids: Optional[List[str]] = Field(default=None, description="Optional filter of rule IDs to evaluate")
    start_time: Optional[datetime] = Field(default=None, description="Start of historical replay window")
    end_time: Optional[datetime] = Field(default=None, description="End of historical replay window")
    source_type: Optional[str] = Field(default=None, description="Filter source e.g. EMAIL, ENDPOINT")
    limit: int = Field(default=100, ge=1, le=5000, description="Maximum events to reprocess")
    run_async: bool = Field(default=False, description="Process in background job")

    @model_validator(mode="before")
    @classmethod
    def resolve_replay_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "max_events" in data and "limit" not in data:
                data["limit"] = data["max_events"]
        return data


class DeadLetterItem(BaseModel):
    """Failed unrecoverable event record."""
    id: str
    workspace_id: str
    event_id: str
    source_type: str
    failure_stage: str
    error_code: str
    error_message: str
    attempt_count: int
    payload: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    resolved: bool = False
    created_at: datetime


# ============================================================================
# 5. PIPELINE METRICS & OBSERVABILITY
# ============================================================================

class PipelineMetricsResponse(BaseModel):
    """Realtime and historical operational telemetry for detection pipeline."""
    model_config = ConfigDict(populate_by_name=True, extra="allow")

    workspace_id: str
    events_received_total: int = 0
    events_processed_total: int = 0
    events_failed_total: int = 0
    rules_evaluated_total: int = 0
    matches_total: int = 0
    no_matches_total: int = 0
    evaluation_errors_total: int = 0
    findings_created_total: int = 0
    alerts_created_total: int = 0
    avg_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    dead_letter_total: int = 0
    backlog_count: int = 0
    pipeline_health: PipelineHealthStatusEnum = PipelineHealthStatusEnum.HEALTHY
    health_reason: Optional[str] = None
    active_rules_count: int = 0
    staged_rules_count: int = 0

    @property
    def health_status(self) -> PipelineHealthStatusEnum:
        return self.pipeline_health

    @property
    def events_received(self) -> int:
        return self.events_received_total

    @property
    def events_processed(self) -> int:
        return self.events_processed_total

    @property
    def matches_created(self) -> int:
        return self.matches_total

    @property
    def findings_created(self) -> int:
        return self.findings_created_total

    @property
    def alerts_created(self) -> int:
        return self.alerts_created_total

    @property
    def errors_total(self) -> int:
        return self.events_failed_total

    @property
    def dead_letters_total(self) -> int:
        return self.dead_letter_total

    @property
    def avg_processing_latency_ms(self) -> float:
        return self.avg_latency_ms


class DetectionMatchListItem(BaseModel):
    """First-class detection match summary item for SOC tables."""
    id: str
    workspace_id: str
    rule_id: str
    rule_identifier: Optional[str] = None
    rule_name: str
    rule_version: str
    event_id: str
    execution_id: Optional[str] = None
    finding_id: Optional[str] = None
    alert_id: Optional[str] = None
    mode: str
    status: str
    severity: str
    confidence: float
    matched_at: datetime
    matched_fields: List[str] = Field(default_factory=list)
    explanation: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)
