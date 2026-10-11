"""
Section 47: Pydantic schemas for Notifications & Alert Center.
Defines controlled taxonomy, distinction between Security Alerts and System Notifications,
provenance metadata, and unread counts.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class NotificationCategoryEnum(str, Enum):
    NOTIFICATION = "NOTIFICATION"
    SECURITY_ALERT = "SECURITY_ALERT"


class NotificationStatusEnum(str, Enum):
    UNREAD = "UNREAD"
    READ = "READ"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DISMISSED = "DISMISSED"


class NotificationSeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class NotificationTypeEnum(str, Enum):
    # Security Alerts
    CRITICAL_THREAT_DETECTED = "CRITICAL_THREAT_DETECTED"
    HIGH_RISK_THREAT_DETECTED = "HIGH_RISK_THREAT_DETECTED"
    MALICIOUS_ATTACHMENT_DETECTED = "MALICIOUS_ATTACHMENT_DETECTED"
    CREDENTIAL_THEFT_DETECTED = "CREDENTIAL_THEFT_DETECTED"
    LOOKALIKE_IMPERSONATION_DETECTED = "LOOKALIKE_IMPERSONATION_DETECTED"
    CAMPAIGN_CORRELATED = "CAMPAIGN_CORRELATED"
    ACCOUNT_TAKEOVER_DETECTED = "ACCOUNT_TAKEOVER_DETECTED"
    AUTHENTICATION_FAILURE = "AUTHENTICATION_FAILURE"

    # System Notifications
    ANALYSIS_COMPLETED = "ANALYSIS_COMPLETED"
    ANALYSIS_PARTIALLY_COMPLETED = "ANALYSIS_PARTIALLY_COMPLETED"
    ANALYSIS_FAILED = "ANALYSIS_FAILED"
    REPORT_READY = "REPORT_READY"
    REPORT_FAILED = "REPORT_FAILED"
    JOB_FAILED = "JOB_FAILED"
    JOB_RETRYING = "JOB_RETRYING"
    INVESTIGATION_STATUS_CHANGED = "INVESTIGATION_STATUS_CHANGED"
    INVESTIGATION_RISK_CHANGED = "INVESTIGATION_RISK_CHANGED"

    # Section 51: Incident SLA & Escalation Notifications
    INCIDENT_SLA_WARNING = "INCIDENT_SLA_WARNING"
    INCIDENT_SLA_BREACHED = "INCIDENT_SLA_BREACHED"
    INCIDENT_ESCALATED = "INCIDENT_ESCALATED"
    INCIDENT_REASSIGNED = "INCIDENT_REASSIGNED"
    INCIDENT_ROUTED = "INCIDENT_ROUTED"
    INCIDENT_UNASSIGNED_CRITICAL = "INCIDENT_UNASSIGNED_CRITICAL"
    INCIDENT_REOPENED = "INCIDENT_REOPENED"

    # Section 57: Detection Rule Management Notifications
    RULE_EMERGENCY_DISABLED = "RULE_EMERGENCY_DISABLED"
    RULE_DEPLOYMENT_FAILED = "RULE_DEPLOYMENT_FAILED"
    RULE_DEPENDENCY_FAILED = "RULE_DEPENDENCY_FAILED"
    RULE_REVIEW_DUE = "RULE_REVIEW_DUE"
    RULE_HEALTH_DEGRADED = "RULE_HEALTH_DEGRADED"
    RULE_ROLLED_BACK = "RULE_ROLLED_BACK"

    # Section 58: Automated Detection Validation & Continuous Rule Quality Notifications
    VALIDATION_FAILED_CRITICAL = "VALIDATION_FAILED_CRITICAL"
    VALIDATION_SCHEMA_DRIFT = "VALIDATION_SCHEMA_DRIFT"
    VALIDATION_PERFORMANCE_REGRESSION = "VALIDATION_PERFORMANCE_REGRESSION"
    VALIDATION_GATE_BLOCKED = "VALIDATION_GATE_BLOCKED"

    # Section 59: Unified Threat Detection Pipeline Notifications
    DETECTION_RULE_ALERT = "DETECTION_RULE_ALERT"
    PIPELINE_ERROR_ALERT = "PIPELINE_ERROR_ALERT"
    PIPELINE_BATCH_COMPLETED = "PIPELINE_BATCH_COMPLETED"

    # Section 60: Behavioral Detection & Anomaly Analytics Notifications
    BEHAVIORAL_ANOMALY_ALERT = "BEHAVIORAL_ANOMALY_ALERT"
    BEHAVIORAL_BASELINE_DEGRADED = "BEHAVIORAL_BASELINE_DEGRADED"

    # Section 61: Cross-Source Correlation & Unified Entity Correlation Notifications
    CROSS_SOURCE_THREAT_CORRELATED = "CROSS_SOURCE_THREAT_CORRELATED"
    COMPOSITE_ATTACK_PATTERN_DETECTED = "COMPOSITE_ATTACK_PATTERN_DETECTED"

    # Section 62: Attack Surface Intelligence Notifications
    CRITICAL_EXTERNAL_EXPOSURE_DETECTED = "CRITICAL_EXTERNAL_EXPOSURE_DETECTED"
    UNKNOWN_PUBLIC_ASSET_DETECTED = "UNKNOWN_PUBLIC_ASSET_DETECTED"
    HIGH_RISK_ATTACK_SURFACE_CHANGE = "HIGH_RISK_ATTACK_SURFACE_CHANGE"

    # Section 63: Asset & Identity Inventory Notifications
    CRITICAL_ASSET_STALE_DETECTED = "CRITICAL_ASSET_STALE_DETECTED"
    UNOWNED_CRITICAL_ASSET_DETECTED = "UNOWNED_CRITICAL_ASSET_DETECTED"
    ORPHANED_PRIVILEGED_ACCOUNT_DETECTED = "ORPHANED_PRIVILEGED_ACCOUNT_DETECTED"
    INVENTORY_SOURCE_FAILED = "INVENTORY_SOURCE_FAILED"
    INVENTORY_CONFLICT_DETECTED = "INVENTORY_CONFLICT_DETECTED"

    # Section 64: Risk-Based Asset Prioritization Notifications
    ASSET_PRIORITY_ESCALATED_P1 = "ASSET_PRIORITY_ESCALATED_P1"
    CRITICAL_ASSET_PRIORITY_P1 = "CRITICAL_ASSET_PRIORITY_P1"
    ASSET_PRIORITY_DATA_DEGRADED = "ASSET_PRIORITY_DATA_DEGRADED"


class NotificationRead(BaseModel):
    id: str
    workspace_id: str = "default"
    user_id: Optional[str] = None
    category: str = Field("NOTIFICATION", description="NOTIFICATION or SECURITY_ALERT")
    notification_type: str = Field(..., description="Controlled notification taxonomy type")
    severity: str = Field("INFO", description="CRITICAL, HIGH, MEDIUM, LOW, INFO")
    status: str = Field("UNREAD", description="UNREAD, READ, ACKNOWLEDGED, DISMISSED")
    title: str
    message: str
    source_type: str
    source_id: str
    investigation_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    finding_id: Optional[str] = None
    job_id: Optional[str] = None
    report_id: Optional[str] = None
    navigation_target: Optional[str] = None
    deduplication_key: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    read_at: Optional[datetime] = None
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class NotificationListResponse(BaseModel):
    items: List[NotificationRead]
    total: int
    unread_total: int
    unread_alerts: int
    unread_notifications: int
    limit: int
    offset: int

    model_config = ConfigDict(from_attributes=True)


class NotificationUnreadCountResponse(BaseModel):
    total_unread: int
    alerts_unread: int
    notifications_unread: int

    model_config = ConfigDict(from_attributes=True)


class NotificationAcknowledgeRequest(BaseModel):
    analyst_name: Optional[str] = Field(None, description="Name of acknowledging SOC analyst")
    note: Optional[str] = Field(None, description="Optional acknowledgement triage note")
