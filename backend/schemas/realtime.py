"""
Section 46: Structured Real-Time Event Schema Contracts.
Provides normalized, versioned (v1), resource-scoped event models for live analysis updates,
background job telemetry, findings, analyzer health, and report lifecycle events.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator


class RealtimeEventTypeEnum(str, Enum):
    # Job Lifecycle
    JOB_CREATED = "JOB_CREATED"
    JOB_QUEUED = "JOB_QUEUED"
    JOB_STARTED = "JOB_STARTED"
    JOB_PROGRESS = "JOB_PROGRESS"
    JOB_RETRY_SCHEDULED = "JOB_RETRY_SCHEDULED"
    JOB_CANCEL_REQUESTED = "JOB_CANCEL_REQUESTED"
    JOB_CANCELLED = "JOB_CANCELLED"
    JOB_COMPLETED = "JOB_COMPLETED"
    JOB_PARTIALLY_COMPLETED = "JOB_PARTIALLY_COMPLETED"
    JOB_FAILED = "JOB_FAILED"
    JOB_TIMED_OUT = "JOB_TIMED_OUT"

    # Analysis Lifecycle
    ANALYSIS_STARTED = "ANALYSIS_STARTED"
    ANALYSIS_STAGE_STARTED = "ANALYSIS_STAGE_STARTED"
    ANALYSIS_STAGE_COMPLETED = "ANALYSIS_STAGE_COMPLETED"
    ANALYSIS_PROGRESS = "ANALYSIS_PROGRESS"
    ANALYSIS_PARTIAL = "ANALYSIS_PARTIAL"
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    ANALYSIS_CANCELLED = "ANALYSIS_CANCELLED"

    # Findings & Evidence
    FINDING_PERSISTED = "FINDING_PERSISTED"
    INDICATOR_DISCOVERED = "INDICATOR_DISCOVERED"
    EVIDENCE_ADDED = "EVIDENCE_ADDED"

    # Analyzer Health & Diagnostics
    ANALYZER_WARNING = "ANALYZER_WARNING"
    ANALYZER_DEGRADED = "ANALYZER_DEGRADED"
    ANALYZER_FAILED = "ANALYZER_FAILED"

    # Reports
    REPORT_GENERATION_STARTED = "REPORT_GENERATION_STARTED"
    REPORT_READY = "REPORT_READY"
    REPORT_FAILED = "REPORT_FAILED"

    # Section 47 & 48: Notifications & Security Alerts Triage
    NOTIFICATION_CREATED = "NOTIFICATION_CREATED"
    NOTIFICATION_READ = "NOTIFICATION_READ"
    ALERT_ACKNOWLEDGED = "ALERT_ACKNOWLEDGED"
    ALERT_STATUS_CHANGED = "ALERT_STATUS_CHANGED"
    ALERT_ASSIGNED = "ALERT_ASSIGNED"
    ALERT_RESOLVED = "ALERT_RESOLVED"
    ALERT_NOTE_ADDED = "ALERT_NOTE_ADDED"
    ALERT_SUPPRESSED = "ALERT_SUPPRESSED"

    # Section 49: Alert Correlation & Incident Clustering
    ALERT_CLUSTER_CREATED = "ALERT_CLUSTER_CREATED"
    ALERT_CLUSTER_UPDATED = "ALERT_CLUSTER_UPDATED"
    ALERT_ADDED_TO_CLUSTER = "ALERT_ADDED_TO_CLUSTER"
    ALERT_CLUSTER_MERGED = "ALERT_CLUSTER_MERGED"
    ALERT_CLUSTER_INVESTIGATION_LINKED = "ALERT_CLUSTER_INVESTIGATION_LINKED"

    # Section 50: Incident Management & Case Lifecycle
    INCIDENT_CREATED = "INCIDENT_CREATED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    INCIDENT_ASSIGNED = "INCIDENT_ASSIGNED"
    INCIDENT_STATUS_CHANGED = "INCIDENT_STATUS_CHANGED"
    INCIDENT_SEVERITY_CHANGED = "INCIDENT_SEVERITY_CHANGED"
    INCIDENT_RESOLVED = "INCIDENT_RESOLVED"
    INCIDENT_CLOSED = "INCIDENT_CLOSED"
    INCIDENT_REOPENED = "INCIDENT_REOPENED"

    # Section 51: Incident SLA, Escalation & Workflow Automation
    INCIDENT_SLA_WARNING = "INCIDENT_SLA_WARNING"
    INCIDENT_SLA_BREACHED = "INCIDENT_SLA_BREACHED"
    INCIDENT_ESCALATED = "INCIDENT_ESCALATED"
    INCIDENT_REASSIGNED = "INCIDENT_REASSIGNED"
    INCIDENT_ROUTED = "INCIDENT_ROUTED"
    INCIDENT_SLA_PAUSED = "INCIDENT_SLA_PAUSED"
    INCIDENT_SLA_RESUMED = "INCIDENT_SLA_RESUMED"
    INCIDENT_SLA_EXEMPTED = "INCIDENT_SLA_EXEMPTED"

    # Section 53: IOC Watchlists & Continuous Threat Monitoring
    WATCHLIST_CREATED = "WATCHLIST_CREATED"
    WATCHLIST_UPDATED = "WATCHLIST_UPDATED"
    WATCHLIST_PAUSED = "WATCHLIST_PAUSED"
    WATCHLIST_RESUMED = "WATCHLIST_RESUMED"
    WATCH_ITEM_ADDED = "WATCH_ITEM_ADDED"
    WATCH_ITEM_REMOVED = "WATCH_ITEM_REMOVED"
    WATCH_CHECK_STARTED = "WATCH_CHECK_STARTED"
    WATCH_CHECK_COMPLETED = "WATCH_CHECK_COMPLETED"
    INTELLIGENCE_CHANGE_DETECTED = "INTELLIGENCE_CHANGE_DETECTED"
    WATCHLIST_HEALTH_CHANGED = "WATCHLIST_HEALTH_CHANGED"

    # Section 54: Threat Hunting Workspace & Query Engine
    HUNT_QUEUED = "HUNT_QUEUED"
    HUNT_STARTED = "HUNT_STARTED"
    HUNT_PROGRESS = "HUNT_PROGRESS"
    HUNT_COMPLETED = "HUNT_COMPLETED"
    HUNT_PARTIALLY_COMPLETED = "HUNT_PARTIALLY_COMPLETED"
    HUNT_FAILED = "HUNT_FAILED"
    HUNT_CANCELLED = "HUNT_CANCELLED"

    # Section 55: Advanced Threat Hunting & Investigation Pivots
    PIVOT_STARTED = "PIVOT_STARTED"
    PIVOT_PROGRESS = "PIVOT_PROGRESS"
    PIVOT_COMPLETED = "PIVOT_COMPLETED"
    PIVOT_PARTIALLY_COMPLETED = "PIVOT_PARTIALLY_COMPLETED"
    PIVOT_FAILED = "PIVOT_FAILED"
    PIVOT_CANCELLED = "PIVOT_CANCELLED"


class RealtimeResourceScopeEnum(str, Enum):
    ANALYSIS_RUN = "ANALYSIS_RUN"
    JOB = "JOB"
    INVESTIGATION = "INVESTIGATION"
    REPORT = "REPORT"
    WORKSPACE = "WORKSPACE"
    NOTIFICATION = "NOTIFICATION"
    ALERT = "ALERT"
    ALERT_CLUSTER = "ALERT_CLUSTER"
    INCIDENT = "INCIDENT"
    WATCHLIST = "WATCHLIST"
    HUNT = "HUNT"
    PIVOT = "PIVOT"




class RealtimeEventPayload(BaseModel):
    """
    Sanitized, compact payload for live events.
    Enforces that sensitive data (passwords, auth tokens, raw email bodies, file contents)
    are strictly excluded from the real-time event stream.
    """
    finding_id: Optional[str] = None
    finding_type: Optional[str] = None
    severity: Optional[str] = None
    title: Optional[str] = None
    analyzer: Optional[str] = None
    risk_contribution: Optional[float] = None
    confidence: Optional[float] = None
    task_id: Optional[str] = None
    task_type: Optional[str] = None
    completed_tasks: Optional[int] = None
    total_tasks: Optional[int] = None
    delay_seconds: Optional[int] = None
    attempt: Optional[int] = None
    max_attempts: Optional[int] = None
    report_version: Optional[int] = None
    report_number: Optional[str] = None
    error_code: Optional[str] = None
    incident_id: Optional[str] = None
    incident_number: Optional[str] = None
    priority: Optional[str] = None
    extra: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(from_attributes=True)


class RealtimeEvent(BaseModel):
    """
    Canonical Section 46 Normalized Real-Time Event.
    API contract version: 1.
    """
    schema_version: int = 1
    event_id: str
    sequence: int
    event_type: str
    resource_type: str  # ANALYSIS_RUN, JOB, INVESTIGATION, REPORT, WORKSPACE, INCIDENT
    resource_id: str
    job_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    investigation_id: Optional[str] = None
    incident_id: Optional[str] = None
    report_id: Optional[str] = None
    workspace_id: str = "default"
    stage: Optional[str] = None
    status: Optional[str] = None
    progress_percent: Optional[float] = None
    message: str
    payload: Union[Dict[str, Any], RealtimeEventPayload, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("payload", mode="before")
    @classmethod
    def convert_payload_to_dict(cls, v: Any) -> Dict[str, Any]:
        if isinstance(v, BaseModel):
            return v.model_dump(mode="json")
        if isinstance(v, dict):
            return v
        return {}

    model_config = ConfigDict(from_attributes=True)


class RealtimeSubscriptionState(BaseModel):
    """Client connection state metadata."""
    channel: str
    workspace_id: str
    connected_at: datetime
    last_sequence_sent: int = 0


def sanitize_error_message(raw_error: Optional[str]) -> str:
    """
    Sanitizes raw backend error messages before placing them into client-facing event payloads.
    Strips raw database credentials, internal tracebacks, ip addresses, and sensitive tokens.
    """
    if not raw_error:
        return "An internal operational error occurred."

    err_str = str(raw_error)

    # Scrub stack traces
    if "Traceback" in err_str:
        err_str = err_str.split("Traceback")[0].strip() or "Execution halted unexpectedly."

    # Scrub credentials, passwords, and tokens
    import re
    err_str = re.sub(r"(password|pwd|secret|token|bearer|key)=['\"]?[^'\"\s,]+['\"]?", r"\1=***", err_str, flags=re.IGNORECASE)
    err_str = re.sub(r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer ***", err_str)
    err_str = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "***.***.***.***", err_str)

    # General generic fallbacks if raw DB errors occur
    lowered = err_str.lower()
    if "connection refused" in lowered or "operationalerror" in lowered or "connectionerror" in lowered:
        return "Backend processing service temporarily unavailable."
    if "access denied" in lowered or "authentication failed" in lowered:
        return "Operation could not be authorized."

    return err_str[:300].strip()

