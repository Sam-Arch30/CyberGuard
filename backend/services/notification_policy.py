"""
Section 47: Notification & Security Alert Policy Engine.
Defines deterministic decision rules that convert meaningful system/security events
into persisted notifications or security alerts while suppressing technical noise.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple
from backend.schemas.notification import (
    NotificationCategoryEnum,
    NotificationSeverityEnum,
    NotificationTypeEnum,
)
from backend.schemas.realtime import sanitize_error_message

logger = logging.getLogger("cyberguard.services.notification_policy")

# Technical events that MUST NEVER generate user-facing notifications
IGNORED_EVENT_TYPES = {
    "JOB_CREATED",
    "JOB_QUEUED",
    "JOB_STARTED",
    "JOB_PROGRESS",
    "JOB_RETRY_SCHEDULED",
    "JOB_HEARTBEAT",
    "ANALYSIS_STARTED",
    "ANALYSIS_STAGE_STARTED",
    "ANALYSIS_STAGE_COMPLETED",
    "ANALYSIS_PROGRESS",
    "TASK_STARTED",
    "TASK_PROGRESS",
    "TASK_COMPLETED",
    "INDICATOR_DISCOVERED",
    "EVIDENCE_ADDED",
    "ANALYZER_WARNING",
}


class NotificationPolicyDecision:
    """Represents the policy decision outcome."""
    def __init__(
        self,
        should_notify: bool,
        category: str = NotificationCategoryEnum.NOTIFICATION.value,
        notification_type: str = NotificationTypeEnum.ANALYSIS_COMPLETED.value,
        severity: str = NotificationSeverityEnum.INFO.value,
        title: str = "",
        message: str = "",
        deduplication_key: str = "",
        navigation_target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.should_notify = should_notify
        self.category = category
        self.notification_type = notification_type
        self.severity = severity
        self.title = title
        self.message = message
        self.deduplication_key = deduplication_key
        self.navigation_target = navigation_target
        self.metadata = metadata or {}


class NotificationPolicy:
    """
    Deterministic policy evaluator.
    Evaluates incoming events, findings, reports, and jobs to determine
    if they qualify for user notification or security alerts.
    """

    @classmethod
    def evaluate_finding(
        cls,
        finding_id: str,
        finding_type: str,
        title: str,
        severity: str,
        risk_contribution: float,
        analyzer: str,
        investigation_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        description: Optional[str] = None,
        workspace_id: str = "default",
    ) -> NotificationPolicyDecision:
        """
        Evaluates a persisted Finding.
        Only CRITICAL and HIGH severity findings qualify for Security Alerts.
        Routine LOW/SAFE findings are suppressed from alerting.
        """
        clean_sev = str(severity).upper()
        if clean_sev not in ("CRITICAL", "HIGH"):
            return NotificationPolicyDecision(should_notify=False)

        # Map to specific controlled alert type
        alert_type = NotificationTypeEnum.HIGH_RISK_THREAT_DETECTED.value
        lowered_type = (finding_type or "").lower()
        if clean_sev == "CRITICAL":
            alert_type = NotificationTypeEnum.CRITICAL_THREAT_DETECTED.value

        if "attachment" in lowered_type or "executable" in lowered_type or "double_ext" in lowered_type:
            alert_type = NotificationTypeEnum.MALICIOUS_ATTACHMENT_DETECTED.value
        elif "credential" in lowered_type or "harvest" in lowered_type:
            alert_type = NotificationTypeEnum.CREDENTIAL_THEFT_DETECTED.value
        elif "lookalike" in lowered_type or "impersonat" in lowered_type or "spoof" in lowered_type:
            alert_type = NotificationTypeEnum.LOOKALIKE_IMPERSONATION_DETECTED.value
        elif "auth" in lowered_type or "spf" in lowered_type or "dmarc" in lowered_type:
            alert_type = NotificationTypeEnum.AUTHENTICATION_FAILURE.value
        elif "account_takeover" in lowered_type or "ato" in lowered_type:
            alert_type = NotificationTypeEnum.ACCOUNT_TAKEOVER_DETECTED.value

        inv_link = f"/investigations/{investigation_id}" if investigation_id else "/dashboard"
        dedup_key = f"alert:finding:{workspace_id}:{finding_id}"

        # Safe concise message with explainability snippet
        desc_snippet = (description or title or "").strip()
        if len(desc_snippet) > 200:
            desc_snippet = desc_snippet[:197] + "..."

        msg = f"{clean_sev} threat detected by {analyzer}. Risk impact: +{risk_contribution:.0f} pts. {desc_snippet}"

        return NotificationPolicyDecision(
            should_notify=True,
            category=NotificationCategoryEnum.SECURITY_ALERT.value,
            notification_type=alert_type,
            severity=clean_sev,
            title=f"Security Alert: {title[:80]}",
            message=msg,
            deduplication_key=dedup_key,
            navigation_target=inv_link,
            metadata={
                "finding_id": finding_id,
                "finding_type": finding_type,
                "analyzer": analyzer,
                "risk_contribution": risk_contribution,
                "explanation": desc_snippet,
            },
        )

    @classmethod
    def evaluate_analysis_run(
        cls,
        run_id: str,
        status: str,
        overall_severity: Optional[str] = None,
        overall_risk_score: Optional[float] = None,
        investigation_id: Optional[str] = None,
        error_message: Optional[str] = None,
        workspace_id: str = "default",
    ) -> NotificationPolicyDecision:
        """
        Evaluates a concluded AnalysisRun.
        Triggers on COMPLETED, PARTIAL, or FAILED.
        """
        clean_status = str(status).upper()
        if clean_status not in ("COMPLETED", "PARTIAL", "FAILED"):
            return NotificationPolicyDecision(should_notify=False)

        inv_target = f"/investigations/{investigation_id}/analysis" if investigation_id else f"/investigations/{run_id}/analysis"
        dedup_key = f"notif:run:{workspace_id}:{run_id}:{clean_status}"

        if clean_status == "COMPLETED":
            score = overall_risk_score or 0.0
            sev = (overall_severity or "LOW").upper()
            title = f"Analysis Run Completed"
            msg = f"Forensic analysis concluded. Overall risk score: {score:.0f}/100 ({sev})."
            notif_sev = NotificationSeverityEnum.INFO.value
            if sev in ("HIGH", "CRITICAL"):
                notif_sev = sev
            return NotificationPolicyDecision(
                should_notify=True,
                category=NotificationCategoryEnum.NOTIFICATION.value,
                notification_type=NotificationTypeEnum.ANALYSIS_COMPLETED.value,
                severity=notif_sev,
                title=title,
                message=msg,
                deduplication_key=dedup_key,
                navigation_target=inv_target,
                metadata={
                    "run_id": run_id,
                    "risk_score": score,
                    "severity": sev,
                },
            )

        if clean_status == "PARTIAL":
            return NotificationPolicyDecision(
                should_notify=True,
                category=NotificationCategoryEnum.NOTIFICATION.value,
                notification_type=NotificationTypeEnum.ANALYSIS_PARTIALLY_COMPLETED.value,
                severity=NotificationSeverityEnum.MEDIUM.value,
                title="Analysis Partially Completed",
                message="Forensic pipeline finished with degraded or partial analyzer outputs.",
                deduplication_key=dedup_key,
                navigation_target=inv_target,
                metadata={"run_id": run_id},
            )

        if clean_status == "FAILED":
            sanitized_err = sanitize_error_message(error_message)
            return NotificationPolicyDecision(
                should_notify=True,
                category=NotificationCategoryEnum.NOTIFICATION.value,
                notification_type=NotificationTypeEnum.ANALYSIS_FAILED.value,
                severity=NotificationSeverityEnum.HIGH.value,
                title="Analysis Execution Failed",
                message=f"Forensic pipeline halted: {sanitized_err}",
                deduplication_key=dedup_key,
                navigation_target=inv_target,
                metadata={"run_id": run_id, "error": sanitized_err},
            )

        return NotificationPolicyDecision(should_notify=False)

    @classmethod
    def evaluate_report(
        cls,
        report_id: str,
        report_number: str,
        status: str,
        investigation_id: Optional[str] = None,
        workspace_id: str = "default",
        error_message: Optional[str] = None,
    ) -> NotificationPolicyDecision:
        """Evaluates Report compilation outcome."""
        clean_status = str(status).upper()
        if clean_status not in ("READY", "FAILED"):
            return NotificationPolicyDecision(should_notify=False)

        inv_target = f"/investigations/{investigation_id}/report" if investigation_id else "/reports"
        dedup_key = f"notif:report:{workspace_id}:{report_id}:{clean_status}"

        if clean_status == "READY":
            return NotificationPolicyDecision(
                should_notify=True,
                category=NotificationCategoryEnum.NOTIFICATION.value,
                notification_type=NotificationTypeEnum.REPORT_READY.value,
                severity=NotificationSeverityEnum.INFO.value,
                title=f"Report {report_number} Ready",
                message=f"Forensic dossier {report_number} has been compiled and is ready for export.",
                deduplication_key=dedup_key,
                navigation_target=inv_target,
                metadata={"report_id": report_id, "report_number": report_number},
            )

        if clean_status == "FAILED":
            sanitized_err = sanitize_error_message(error_message)
            return NotificationPolicyDecision(
                should_notify=True,
                category=NotificationCategoryEnum.NOTIFICATION.value,
                notification_type=NotificationTypeEnum.REPORT_FAILED.value,
                severity=NotificationSeverityEnum.HIGH.value,
                title=f"Report {report_number} Generation Failed",
                message=f"Report compiler encountered an error: {sanitized_err}",
                deduplication_key=dedup_key,
                navigation_target=inv_target,
                metadata={"report_id": report_id, "error": sanitized_err},
            )

        return NotificationPolicyDecision(should_notify=False)

    @classmethod
    def evaluate_job(
        cls,
        job_id: str,
        job_type: str,
        status: str,
        workspace_id: str = "default",
        error_message: Optional[str] = None,
        investigation_id: Optional[str] = None,
    ) -> NotificationPolicyDecision:
        """Evaluates background job execution state."""
        clean_status = str(status).upper()
        # Normal queuing, progress, and success do not spam the user
        if clean_status != "FAILED":
            return NotificationPolicyDecision(should_notify=False)

        sanitized_err = sanitize_error_message(error_message)
        dedup_key = f"notif:job:{workspace_id}:{job_id}:FAILED"
        nav_link = f"/investigations/{investigation_id}" if investigation_id else "/dashboard"

        return NotificationPolicyDecision(
            should_notify=True,
            category=NotificationCategoryEnum.NOTIFICATION.value,
            notification_type=NotificationTypeEnum.JOB_FAILED.value,
            severity=NotificationSeverityEnum.HIGH.value,
            title=f"Background Operation Failed ({job_type})",
            message=f"Background job '{job_type}' failed: {sanitized_err}",
            deduplication_key=dedup_key,
            navigation_target=nav_link,
            metadata={"job_id": job_id, "job_type": job_type, "error": sanitized_err},
        )
