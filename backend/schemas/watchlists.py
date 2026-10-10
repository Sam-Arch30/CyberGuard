"""
Section 53: Pydantic Schemas for IOC Watchlists & Continuous Threat Monitoring.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class WatchlistStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    ARCHIVED = "ARCHIVED"


class WatchlistPriorityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ChangeSensitivityEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AlertThresholdEnum(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    NONE = "NONE"


class MonitoringStatusEnum(str, Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    CHECKING = "CHECKING"
    HEALTHY = "HEALTHY"
    STALE = "STALE"
    DEGRADED = "DEGRADED"
    ERROR = "ERROR"


class ChangeTypeEnum(str, Enum):
    NEWLY_MALICIOUS = "NEWLY_MALICIOUS"
    NEWLY_SUSPICIOUS = "NEWLY_SUSPICIOUS"
    BECAME_CLEAN = "BECAME_CLEAN"
    VERDICT_CHANGED = "VERDICT_CHANGED"
    CONFIDENCE_CHANGED = "CONFIDENCE_CHANGED"
    SEVERITY_CHANGED = "SEVERITY_CHANGED"
    PROVIDER_CONFLICT_CHANGED = "PROVIDER_CONFLICT_CHANGED"
    ASN_CHANGED = "ASN_CHANGED"
    HOSTING_CHANGED = "HOSTING_CHANGED"
    CAMPAIGN_ASSOCIATION_CHANGED = "CAMPAIGN_ASSOCIATION_CHANGED"


class MonitoringRunTriggerEnum(str, Enum):
    SCHEDULED = "SCHEDULED"
    MANUAL = "MANUAL"
    EVENT_DRIVEN = "EVENT_DRIVEN"


class MonitoringRunStatusEnum(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    PARTIALLY_SUCCEEDED = "PARTIALLY_SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# =============================================================================
# Request Schemas
# =============================================================================

class WatchlistCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=150, description="Name of the watchlist")
    description: Optional[str] = Field(None, description="Detailed purpose of the watchlist")
    priority: WatchlistPriorityEnum = Field(WatchlistPriorityEnum.MEDIUM, description="Monitoring business priority")
    check_interval_minutes: int = Field(60, ge=15, le=10080, description="Check frequency in minutes (min 15m, max 7d)")
    change_sensitivity: ChangeSensitivityEnum = Field(ChangeSensitivityEnum.MEDIUM, description="Threshold sensitivity for changes")
    alert_threshold: AlertThresholdEnum = Field(AlertThresholdEnum.HIGH, description="Minimum change severity to generate security alerts")
    notify_on_change: bool = Field(True, description="Whether to dispatch in-app notifications on changes")
    cooldown_minutes: int = Field(360, ge=15, le=43200, description="Cooldown period in minutes to suppress duplicate alerts")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom metadata tags or context")


class WatchlistUpdateRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=150)
    description: Optional[str] = None
    status: Optional[WatchlistStatusEnum] = None
    priority: Optional[WatchlistPriorityEnum] = None
    check_interval_minutes: Optional[int] = Field(None, ge=15, le=10080)
    change_sensitivity: Optional[ChangeSensitivityEnum] = None
    alert_threshold: Optional[AlertThresholdEnum] = None
    notify_on_change: Optional[bool] = None
    cooldown_minutes: Optional[int] = Field(None, ge=15, le=43200)
    metadata: Optional[Dict[str, Any]] = None


class WatchedIndicatorCreateRequest(BaseModel):
    indicator_value: str = Field(..., min_length=1, description="Raw observable value (e.g. IP, domain, URL, hash)")
    indicator_type: Optional[str] = Field(None, description="Optional type hint: IP, DOMAIN, URL, SHA256, etc.")
    priority: WatchlistPriorityEnum = Field(WatchlistPriorityEnum.MEDIUM)
    source_incident_id: Optional[str] = None
    source_investigation_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class WatchedIndicatorBulkAddRequest(BaseModel):
    indicators: List[WatchedIndicatorCreateRequest] = Field(..., min_length=1, max_length=500)
    default_priority: WatchlistPriorityEnum = Field(WatchlistPriorityEnum.MEDIUM)
    source_incident_id: Optional[str] = None
    source_investigation_id: Optional[str] = None


class QuickWatchRequest(BaseModel):
    indicator_value: str = Field(..., min_length=1)
    indicator_type: Optional[str] = None
    watchlist_id: Optional[str] = Field(None, description="Target watchlist ID; if omitted, added to default investigation watchlist")
    watchlist_name: Optional[str] = Field(None, description="Name of new watchlist if creating one on the fly")
    source_incident_id: Optional[str] = None
    source_investigation_id: Optional[str] = None
    reason: Optional[str] = None


# =============================================================================
# Response Schemas
# =============================================================================

class WatchedIndicatorResponse(BaseModel):
    id: str
    watchlist_id: str
    workspace_id: str
    indicator_id: Optional[str] = None
    indicator_type: str
    raw_value: str
    normalized_value: str
    display_value: str
    monitoring_status: str
    priority: str
    first_watched_at: datetime
    last_checked_at: Optional[datetime] = None
    next_check_at: Optional[datetime] = None
    last_successful_check_at: Optional[datetime] = None
    last_failed_check_at: Optional[datetime] = None
    last_change_detected_at: Optional[datetime] = None
    last_snapshot_id: Optional[str] = None
    last_verdict: str
    last_confidence: float
    last_severity: str
    failure_count: int
    consecutive_failure_count: int
    last_error_message: Optional[str] = None
    source_incident_id: Optional[str] = None
    source_investigation_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class WatchedIndicatorListResponse(BaseModel):
    items: List[WatchedIndicatorResponse]
    total: int
    offset: int
    limit: int


class IntelligenceChangeResponse(BaseModel):
    id: str
    workspace_id: str
    watchlist_id: str
    watched_indicator_id: str
    indicator_type: str
    normalized_value: str
    change_type: str
    change_severity: str
    previous_snapshot_id: Optional[str] = None
    current_snapshot_id: Optional[str] = None
    previous_verdict: Optional[str] = None
    current_verdict: Optional[str] = None
    previous_confidence: Optional[float] = None
    current_confidence: Optional[float] = None
    previous_severity: Optional[str] = None
    current_severity: Optional[str] = None
    change_summary: str
    change_details: Dict[str, Any]
    alert_id: Optional[str] = None
    notification_id: Optional[str] = None
    acknowledged: bool
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    detected_at: datetime


class IntelligenceChangeListResponse(BaseModel):
    items: List[IntelligenceChangeResponse]
    total: int
    offset: int
    limit: int


class WatchlistMonitoringRunResponse(BaseModel):
    id: str
    workspace_id: str
    watchlist_id: str
    job_id: Optional[str] = None
    trigger_type: str
    status: str
    items_due: int
    items_checked: int
    items_changed: int
    items_failed: int
    alerts_created: int
    notifications_created: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    error_message: Optional[str] = None
    run_summary: Dict[str, Any] = Field(default_factory=dict)


class WatchlistMonitoringRunListResponse(BaseModel):
    items: List[WatchlistMonitoringRunResponse]
    total: int


class WatchlistSummaryResponse(BaseModel):
    id: str
    workspace_id: str
    name: str
    description: Optional[str] = None
    status: str
    priority: str
    owner_user_id: Optional[str] = None
    team_id: Optional[str] = None
    check_interval_minutes: int
    change_sensitivity: str
    alert_threshold: str
    notify_on_change: bool
    cooldown_minutes: int
    total_indicators_count: int
    active_indicators_count: int
    stale_indicators_count: int
    malicious_indicators_count: int
    last_monitored_at: Optional[datetime] = None
    next_monitoring_cycle_at: Optional[datetime] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class WatchlistDetailResponse(WatchlistSummaryResponse):
    recent_changes: List[IntelligenceChangeResponse] = Field(default_factory=list)
    recent_runs: List[WatchlistMonitoringRunResponse] = Field(default_factory=list)


class WatchlistListResponse(BaseModel):
    items: List[WatchlistSummaryResponse]
    total: int
    offset: int
    limit: int


class WatchlistHealthResponse(BaseModel):
    watchlist_id: str
    status: str  # HEALTHY, DEGRADED, STALE, ERROR
    total_indicators: int
    healthy_count: int
    stale_count: int
    error_count: int
    malicious_count: int
    last_monitored_at: Optional[datetime] = None
    next_cycle_at: Optional[datetime] = None
    provider_health_summary: Dict[str, str] = Field(default_factory=dict)
