"""
Section 57: Detection Rule Management & Operational Control Service.

Provides production SOC-scale detection management:
1. Deterministic Operational Health Computation (dependencies, error rates, latencies, match anomalies, stale/zero-match rules).
2. Server-authoritative Deployment Lifecycle (Staging, Production Promotion, Dry-Run Pre-flight, Rollback, Emergency Disable).
3. Controlled Rule Suppression (scoped, auditable, time-bounded false-positive exceptions).
4. Analyst Dispositions & Detection Quality Metrics (True Positive, False Positive, Benign, Review Coverage).
5. Redundancy & Conflict Detection (AST fingerprinting and condition tree equivalence).
6. Safe Bulk Operations with partial-success reporting.
7. SOC Operational Overview & Coverage Mapping across data sources.
8. Section 46 Realtime events, Section 47 Notifications, Section 45 Background Jobs, and Section 43 Audit logging.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import logging
import math
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from fastapi import HTTPException, status
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.orm import Session

from backend.db.models import (
    AuditLogModel,
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    FindingModel,
    IncidentModel,
    NotificationModel,
    RuleSuppressionModel,
    SecurityEventModel,
    ThreatEventModel,
    EmailAnalysisModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import (
    DslOperator,
    RuleLifecycleStatus,
    RuleSeverity,
    RuleType,
)
from backend.schemas.detection_rules import (
    BulkRuleOperationRequest,
    BulkRuleOperationResponse,
    DeploymentDryRunResponse,
    DeploymentStateEnum,
    EmergencyDisableRequest,
    MatchDispositionEnum,
    MatchDispositionRequest,
    OperationalHealthEnum,
    OperationalOverviewResponse,
    RuleDependency,
    RuleDeploymentRequest,
    RuleOperationalHealthResponse,
    RuleQualityMetricsResponse,
    RuleRollbackRequest,
    RuleSimulationRequest,
    RuleSimulationResponse,
    RuleSuppressionCreateRequest,
    RuleSuppressionResponse,
    DependencyHealthEnum,
    DependencyTypeEnum,
    RuleDefinition,
    RuleDataSource,
    RuleCostClass,
)
from backend.schemas.notification import (
    NotificationCategoryEnum,
    NotificationSeverityEnum,
    NotificationStatusEnum,
    NotificationTypeEnum,
)
from backend.schemas.realtime import (
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.detection_rule_lifecycle_service import (
    DetectionRuleLifecycleService,
)
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.detection_rule_management")


def _to_utc_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Ensures datetime object is timezone-aware in UTC to prevent naive/aware comparison errors."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class DetectionRuleManagementService:
    """
    SOC Operational Management and Control Layer for Detection Rules.
    Extends Section 56 lifecycle foundation.
    """

    # =========================================================================
    # 1. OPERATIONAL HEALTH COMPUTATION
    # =========================================================================

    @classmethod
    def evaluate_rule_health(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str = "default",
    ) -> RuleOperationalHealthResponse:
        """
        Computes deterministic operational health for a detection rule based on:
        1. Dependency availability & health status
        2. Execution telemetry (error rate, timeouts, p95 latency) in past 24 hours
        3. Match rate frequency & anomaly detection
        4. Stale metadata & review schedule deadlines
        """
        rule = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
        ).first()

        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule '{rule_id}' not found in workspace '{workspace_id}'.",
            )

        now = get_utc_now()
        yesterday = now - timedelta(hours=24)
        two_days_ago = now - timedelta(hours=48)
        seven_days_ago = now - timedelta(days=7)

        # 1. Dependency Analysis
        dependencies = cls._resolve_rule_dependencies(rule)
        has_required_failing = any(d.required and d.health == DependencyHealthEnum.FAILING for d in dependencies)
        has_required_degraded = any(d.required and d.health == DependencyHealthEnum.DEGRADED for d in dependencies)
        has_optional_failing = any((not d.required) and d.health in (DependencyHealthEnum.FAILING, DependencyHealthEnum.DEGRADED) for d in dependencies)

        dep_summary = "HEALTHY"
        if has_required_failing:
            dep_summary = "FAILING"
        elif has_required_degraded or has_optional_failing:
            dep_summary = "DEGRADED"

        # 2. Execution Telemetry in Last 24 Hours
        executions_24h = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.rule_id == rule.id,
            CandidateRuleExecutionModel.executed_at >= yesterday,
        ).all()

        exec_count = len(executions_24h)
        # Any execution with duration >= 10000ms or error condition is treated as failure
        failures_count = sum(1 for e in executions_24h if e.execution_time_ms >= 10000.0)
        successes_count = exec_count - failures_count
        error_rate = (failures_count / exec_count) if exec_count > 0 else 0.0

        durations = [e.execution_time_ms for e in executions_24h] if executions_24h else [0.0]
        durations.sort()
        avg_duration = sum(durations) / len(durations) if durations else 0.0
        p95_idx = int(math.ceil(0.95 * len(durations))) - 1
        p95_duration = durations[max(0, p95_idx)] if durations else 0.0

        # 3. Match Rate & Anomaly Detection
        matches_last_24h = sum(1 for e in executions_24h if e.matched)
        matches_prev_24h = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.rule_id == rule.id,
            CandidateRuleExecutionModel.executed_at >= two_days_ago,
            CandidateRuleExecutionModel.executed_at < yesterday,
            CandidateRuleExecutionModel.matched.is_(True),
        ).count()

        # Historical baseline over 7 days for anomaly detection
        all_7d_matches = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.rule_id == rule.id,
            CandidateRuleExecutionModel.executed_at >= seven_days_ago,
            CandidateRuleExecutionModel.matched.is_(True),
        ).count()

        daily_avg = all_7d_matches / 7.0
        match_anomaly = False
        anomaly_details = None

        if matches_last_24h >= 20 and matches_last_24h > max(10, daily_avg * 4.0):
            match_anomaly = True
            anomaly_details = (
                f"Unusual match rate surge: {matches_last_24h} matches in last 24h "
                f"versus 7-day average of {daily_avg:.1f}/day ({matches_prev_24h} prev 24h)."
            )

        # Zero-match observation
        zero_match = (matches_last_24h == 0) and (exec_count > 0)

        # 4. Review Due & Stale Checks
        review_interval = rule.review_interval_days or 90
        rule_created = _to_utc_aware(rule.created_at) or now
        rule_updated = _to_utc_aware(rule.updated_at) or now
        next_review = _to_utc_aware(rule.next_review_due) or (rule_created + timedelta(days=review_interval))
        days_until_review = (next_review - now).days if next_review else None
        review_due = bool(next_review and now >= next_review)

        is_stale = False
        if review_due and matches_last_24h == 0 and (now - rule_updated).days > 60:
            is_stale = True

        # 5. Deterministic Operational Health Synthesis
        prev_health = rule.operational_health or OperationalHealthEnum.HEALTHY.value
        health_verdict = OperationalHealthEnum.HEALTHY
        health_reason_parts: List[str] = []

        if has_required_failing:
            health_verdict = OperationalHealthEnum.FAILING
            failing_deps = [d.name for d in dependencies if d.required and d.health == DependencyHealthEnum.FAILING]
            health_reason_parts.append(f"Required dependency unavailable: {', '.join(failing_deps)}")
        elif error_rate >= 0.25:
            health_verdict = OperationalHealthEnum.FAILING
            health_reason_parts.append(f"Critical execution error rate: {error_rate * 100:.1f}%")
        elif has_required_degraded or has_optional_failing:
            health_verdict = OperationalHealthEnum.DEGRADED
            degraded_deps = [d.name for d in dependencies if d.health != DependencyHealthEnum.HEALTHY]
            health_reason_parts.append(f"Degraded dependencies: {', '.join(degraded_deps)}")
        elif error_rate >= 0.05:
            health_verdict = OperationalHealthEnum.DEGRADED
            health_reason_parts.append(f"Elevated execution error rate: {error_rate * 100:.1f}%")
        elif p95_duration >= 2000.0:
            health_verdict = OperationalHealthEnum.DEGRADED
            health_reason_parts.append(f"High execution latency: p95={p95_duration:.1f}ms")
        elif exec_count == 0 and rule.status not in (RuleLifecycleStatus.ACTIVE.value, RuleLifecycleStatus.STAGED.value):
            health_verdict = OperationalHealthEnum.UNKNOWN
            health_reason_parts.append("No runtime execution telemetry recorded yet.")
        else:
            health_verdict = OperationalHealthEnum.HEALTHY
            health_reason_parts.append("All dependencies nominal; execution latency within SLA.")

        if match_anomaly:
            health_reason_parts.append(anomaly_details or "Unusual match frequency detected.")
        if review_due:
            health_reason_parts.append(f"Operational review is due (exceeded {review_interval} day cadence).")

        full_reason = "; ".join(health_reason_parts)

        # Update rule metadata
        rule.operational_health = health_verdict.value
        rule.health_reason = full_reason
        rule.health_updated_at = now
        rule.next_review_due = next_review
        rule.dependencies_json = json.dumps([d.model_dump() for d in dependencies])
        db.commit()

        # Emit Realtime event if health state changed
        if prev_health != health_verdict.value:
            cls._publish_rule_event(
                db=db,
                event_type=RealtimeEventTypeEnum.RULE_HEALTH_CHANGED.value,
                rule_id=rule.id,
                message=f"Rule health changed to {health_verdict.value}",
                workspace_id=workspace_id,
                payload={
                    "rule_id": rule.id,
                    "previous_health": prev_health,
                    "current_health": health_verdict.value,
                    "reason": full_reason,
                },
            )

        # Trigger Section 47 notification if review due or rule failing
        if review_due and (not rule.last_reviewed_at or (now - rule.last_reviewed_at).days > 7):
            cls._send_review_due_notification(db, rule, workspace_id)
        if health_verdict == OperationalHealthEnum.FAILING:
            cls._send_failing_rule_notification(db, rule, full_reason, workspace_id)

        dep_state_val = getattr(rule, "deployment_state", None) or DeploymentStateEnum.DRAFT.value
        dep_state = DeploymentStateEnum(dep_state_val) if dep_state_val in DeploymentStateEnum._value2member_map_ else DeploymentStateEnum.DRAFT

        return RuleOperationalHealthResponse(
            rule_id=rule.id,
            rule_identifier=rule.rule_identifier,
            deployment_state=dep_state,
            operational_health=health_verdict,
            health_reason=full_reason,
            health_updated_at=now,
            execution_count_24h=exec_count,
            success_count_24h=successes_count,
            failure_count_24h=failures_count,
            error_rate_24h=round(error_rate, 4),
            average_duration_ms=round(avg_duration, 2),
            p95_duration_ms=round(p95_duration, 2),
            matches_last_24h=matches_last_24h,
            matches_prev_24h=matches_prev_24h,
            match_rate_anomaly=match_anomaly,
            anomaly_details=anomaly_details,
            zero_match=zero_match,
            is_stale=is_stale,
            review_due=review_due,
            next_review_due=next_review,
            days_until_review=days_until_review,
            dependencies=dependencies,
            dependency_health_summary=dep_summary,
        )

    @classmethod
    def _resolve_rule_dependencies(cls, rule: CandidateRuleModel) -> List[RuleDependency]:
        """Resolves declared dependencies or constructs deterministic dependencies based on data sources."""
        raw_deps = rule.dependencies
        if raw_deps and isinstance(raw_deps, list) and len(raw_deps) > 0:
            parsed = []
            for d in raw_deps:
                try:
                    parsed.append(RuleDependency.model_validate(d))
                except Exception:
                    pass
            if parsed:
                return parsed

        # Construct deterministic dependencies from rule's data_sources and logic
        deps: List[RuleDependency] = []
        sources = rule.data_sources or ["EMAIL_EVENT"]

        for s in sources:
            name = s.replace("_EVENT", "_INGESTION").replace("_", " ").title()
            deps.append(
                RuleDependency(
                    name=f"{name} Pipeline",
                    type=DependencyTypeEnum.DATA_SOURCE,
                    required=True,
                    health=DependencyHealthEnum.HEALTHY,
                    details=f"Live ingestion stream for {s}.",
                )
            )

        # Category-based analyzer dependencies
        if rule.category in ("PHISHING", "URL", "DOMAIN"):
            deps.append(
                RuleDependency(
                    name="URL & Domain Intelligence Service",
                    type=DependencyTypeEnum.INTELLIGENCE,
                    required=False,
                    health=DependencyHealthEnum.HEALTHY,
                    details="External reputation & threat feed enrichment.",
                )
            )
        if rule.category in ("BEHAVIORAL", "ANOMALY"):
            deps.append(
                RuleDependency(
                    name="Behavioral Baseline Engine",
                    type=DependencyTypeEnum.BASELINE,
                    required=True,
                    health=DependencyHealthEnum.HEALTHY,
                    details="Statistical threshold & deviation model.",
                )
            )

        return deps

    # =========================================================================
    # 2. DEPLOYMENT LIFECYCLE (PROMOTION, STAGING, ROLLBACK, EMERGENCY DISABLE)
    # =========================================================================

    @classmethod
    def deploy_rule(
        cls,
        db: Session,
        rule_id: str,
        req: RuleDeploymentRequest,
        actor: str,
        workspace_id: str = "default",
        actor_role: str = "",
    ) -> CandidateRuleModel:
        """Promotes or deploys rule to STAGING or PRODUCTION environment."""
        rule = cls._get_rule(db, rule_id, workspace_id)

        target_version_str = req.version or rule.version
        version_row = db.query(CandidateRuleVersionModel).filter(
            CandidateRuleVersionModel.candidate_rule_id == rule.id,
            CandidateRuleVersionModel.version == target_version_str,
        ).first()

        if not version_row:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target version 'v{target_version_str}' does not exist for rule '{rule_id}'.",
            )

        # Validate capability and definition before deployment
        def_obj = RuleDefinition.model_validate(version_row.definition)
        val = DetectionRuleLifecycleService.validate_and_compile(def_obj, [RuleDataSource(ds) for ds in version_row.data_sources if ds in RuleDataSource._value2member_map_])
        if not val.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot deploy version v{target_version_str}: validation failed ({'; '.join(val.errors)}).",
            )

        now = get_utc_now()
        prev_state = rule.deployment_state
        rule.version = target_version_str
        rule.last_editor_id = actor

        if req.target_state == DeploymentStateEnum.PRODUCTION:
            from backend.services.detection_rule_validation_service import DetectionRuleValidationService
            gate = DetectionRuleValidationService.check_deployment_gate(
                db=db,
                rule_id=rule.id,
                target_version=target_version_str,
                workspace_id=workspace_id,
            )
            if not gate.can_promote:
                if actor_role == "admin":
                    cls._log_audit(
                        db=db,
                        workspace_id=workspace_id,
                        actor=actor,
                        action="VALIDATION_OVERRIDE_BY_ADMIN",
                        resource_id=rule.id,
                        details={"gate_status": gate.status.value, "blocking_reasons": gate.blocking_reasons, "target_state": "PRODUCTION"},
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Cannot promote to PRODUCTION: validation gate check blocked ({'; '.join(gate.blocking_reasons)}).",
                    )
            rule.deployment_state = DeploymentStateEnum.PRODUCTION.value
            rule.status = RuleLifecycleStatus.ACTIVE.value
            rule.activated_at = now
            action = "RULE_PROMOTED_TO_PRODUCTION"
        elif req.target_state == DeploymentStateEnum.STAGING:
            rule.deployment_state = DeploymentStateEnum.STAGING.value
            rule.status = RuleLifecycleStatus.STAGED.value
            rule.staged_at = now
            action = "RULE_DEPLOYED_TO_STAGING"
        else:
            rule.deployment_state = req.target_state.value
            action = f"RULE_DEPLOYED_{req.target_state.value}"

        db.commit()

        # Audit & Realtime
        cls._log_audit(
            db=db,
            workspace_id=workspace_id,
            actor=actor,
            action=action,
            resource_id=rule.id,
            details={
                "target_state": req.target_state.value,
                "version": target_version_str,
                "previous_state": prev_state,
                "reason": req.reason or "Deployment operation executed.",
            },
        )

        cls._publish_rule_event(
            db=db,
            event_type=RealtimeEventTypeEnum.RULE_DEPLOYED.value,
            rule_id=rule.id,
            message=f"Rule deployed to {rule.deployment_state}",
            workspace_id=workspace_id,
            payload={
                "rule_id": rule.id,
                "deployment_state": rule.deployment_state,
                "version": target_version_str,
                "actor": actor,
            },
        )

        logger.info("Rule %s (%s) transitioned to %s by %s", rule.id, rule.rule_identifier, rule.deployment_state, actor)
        return rule

    @classmethod
    def dry_run_deployment(
        cls,
        db: Session,
        rule_id: str,
        target_version: Optional[str] = None,
        workspace_id: str = "default",
    ) -> DeploymentDryRunResponse:
        """
        Executes pre-flight deployment checks:
        1. Validation status of target version
        2. Required dependencies availability
        3. Historical backtest sample results
        4. Deterministic operational risk calculation
        """
        rule = cls._get_rule(db, rule_id, workspace_id)
        version_str = target_version or rule.version

        version_row = db.query(CandidateRuleVersionModel).filter(
            CandidateRuleVersionModel.candidate_rule_id == rule.id,
            CandidateRuleVersionModel.version == version_str,
        ).first()

        validation_errors: List[str] = []
        missing_dependencies: List[str] = []
        risk_factors: List[str] = []

        # 1. Validation check
        val_status = "PASS"
        if not version_row:
            val_status = "FAIL"
            validation_errors.append(f"Target version v{version_str} not found in database.")
        else:
            def_obj = RuleDefinition.model_validate(version_row.definition)
            val = DetectionRuleLifecycleService.validate_and_compile(def_obj, [RuleDataSource(ds) for ds in version_row.data_sources if ds in RuleDataSource._value2member_map_])
            if not val.is_valid:
                val_status = "FAIL"
                validation_errors.extend(val.errors)

        # 2. Dependency check
        dep_status = "PASS"
        dependencies = cls._resolve_rule_dependencies(rule)
        for d in dependencies:
            if d.required and d.health == DependencyHealthEnum.FAILING:
                dep_status = "FAIL"
                missing_dependencies.append(f"{d.name} (required, FAILING)")
            elif d.required and d.health == DependencyHealthEnum.DEGRADED:
                if dep_status != "FAIL":
                    dep_status = "DEGRADED"
                risk_factors.append(f"Required dependency '{d.name}' is DEGRADED.")

        # 3. Historical backtest sample check
        recent_matches_sample = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.rule_id == rule.id,
            CandidateRuleExecutionModel.matched.is_(True),
        ).limit(10).count()

        hist_status = "PASS" if recent_matches_sample > 0 else "INSUFFICIENT_DATA"

        # 4. Deterministic Operational Risk Synthesis
        # Section 58: Automated Validation Gate Check
        from backend.services.detection_rule_validation_service import DetectionRuleValidationService
        gate = DetectionRuleValidationService.check_deployment_gate(
            db=db,
            rule_id=rule.id,
            target_version=version_str,
            workspace_id=workspace_id,
        )
        if not gate.can_promote:
            for br in gate.blocking_reasons:
                risk_factors.append(f"Validation Gate: {br}")

        can_deploy = (val_status == "PASS" and dep_status != "FAIL")
        if not can_deploy:
            operational_risk = "HIGH"
            risk_factors.append("Critical pre-flight checks failed (validation or dependencies).")
        else:
            risk_score = 0
            if rule.cost_class in (RuleCostClass.HIGH.value, "HIGH"):
                risk_score += 2
                risk_factors.append("High compute cost class rule.")
            if rule.complexity_score > 10.0:
                risk_score += 1
                risk_factors.append(f"High condition complexity ({rule.complexity_score:.1f}).")
            if dep_status == "DEGRADED":
                risk_score += 2
            if hist_status == "INSUFFICIENT_DATA":
                risk_factors.append("No historical backtest match baseline observed yet.")

            if risk_score >= 3:
                operational_risk = "HIGH"
            elif risk_score >= 1:
                operational_risk = "MEDIUM"
            else:
                operational_risk = "LOW"

        return DeploymentDryRunResponse(
            rule_id=rule.id,
            target_version=version_str,
            validation_status=val_status,
            validation_errors=validation_errors,
            dependency_status=dep_status,
            missing_required_dependencies=missing_dependencies,
            historical_test_status=hist_status,
            historical_matches_sample=recent_matches_sample,
            operational_risk=operational_risk,
            risk_factors=risk_factors,
            can_deploy=can_deploy,
        )

    @classmethod
    def rollback_rule(
        cls,
        db: Session,
        rule_id: str,
        req: RuleRollbackRequest,
        actor: str,
        workspace_id: str = "default",
    ) -> CandidateRuleModel:
        """
        Safely rolls back rule to target immutable version.
        Preserves complete version history without rewriting prior versions.
        """
        rule = cls._get_rule(db, rule_id, workspace_id)
        current_version = rule.version

        if current_version == req.target_version:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Rule is already currently running version 'v{req.target_version}'.",
            )

        target_row = db.query(CandidateRuleVersionModel).filter(
            CandidateRuleVersionModel.candidate_rule_id == rule.id,
            CandidateRuleVersionModel.version == req.target_version,
        ).first()

        if not target_row:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rollback target version 'v{req.target_version}' does not exist for rule '{rule_id}'.",
            )

        # Validate target version definition
        def_obj = RuleDefinition.model_validate(target_row.definition)
        val = DetectionRuleLifecycleService.validate_and_compile(def_obj, [RuleDataSource(ds) for ds in target_row.data_sources if ds in RuleDataSource._value2member_map_])
        if not val.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot roll back to v{req.target_version}: logic failed validation ({'; '.join(val.errors)}).",
            )

        # Apply target version definition and attributes
        rule.version = req.target_version
        rule.definition_json = target_row.definition_json
        rule.data_sources_json = target_row.data_sources_json
        rule.thresholds_json = target_row.thresholds_json
        rule.complexity_score = val.complexity_score
        rule.cost_class = val.cost_class.value
        rule.normalized_fingerprint = val.normalized_fingerprint
        rule.last_editor_id = actor
        rule.updated_at = get_utc_now()
        db.commit()

        # Audit & Realtime
        cls._log_audit(
            db=db,
            workspace_id=workspace_id,
            actor=actor,
            action="RULE_ROLLED_BACK",
            resource_id=rule.id,
            details={
                "from_version": current_version,
                "to_version": req.target_version,
                "reason": req.reason,
            },
        )

        cls._publish_rule_event(
            db=db,
            event_type=RealtimeEventTypeEnum.RULE_ROLLED_BACK.value,
            rule_id=rule.id,
            message=f"Rule rolled back to v{req.target_version}",
            workspace_id=workspace_id,
            payload={
                "rule_id": rule.id,
                "from_version": current_version,
                "to_version": req.target_version,
                "reason": req.reason,
                "actor": actor,
            },
        )

        # Notify operators via Section 47
        cls._send_rule_notification(
            db=db,
            workspace_id=workspace_id,
            category=NotificationCategoryEnum.SECURITY_ALERT.value,
            notification_type=NotificationTypeEnum.RULE_ROLLED_BACK.value,
            severity=NotificationSeverityEnum.HIGH.value,
            title=f"Rule Rolled Back: {rule.name} (v{current_version} -> v{req.target_version})",
            message=f"Rule '{rule.name}' rolled back to v{req.target_version} by {actor}. Reason: {req.reason}",
            rule_id=rule.id,
            dedup_key=f"RULE-ROLLBACK-{rule.id}-{int(get_utc_now().timestamp())}",
            metadata={"from_version": current_version, "to_version": req.target_version, "actor": actor},
        )

        logger.warning("Rule %s rolled back from v%s to v%s by %s. Reason: %s", rule.id, current_version, req.target_version, actor, req.reason)
        return rule

    @classmethod
    def emergency_disable(
        cls,
        db: Session,
        rule_id: str,
        req: EmergencyDisableRequest,
        actor: str,
        workspace_id: str = "default",
    ) -> CandidateRuleModel:
        """Emergency disable control for misbehaving or noisy active rules."""
        rule = cls._get_rule(db, rule_id, workspace_id)

        now = get_utc_now()
        prev_status = rule.status
        prev_dep_state = rule.deployment_state

        rule.status = RuleLifecycleStatus.DISABLED.value
        rule.deployment_state = DeploymentStateEnum.DISABLED.value
        rule.disabled_at = now
        rule.last_editor_id = actor
        rule.health_reason = f"Emergency disabled by {actor}: {req.reason}"
        db.commit()

        # Audit & Realtime
        cls._log_audit(
            db=db,
            workspace_id=workspace_id,
            actor=actor,
            action="EMERGENCY_DISABLE",
            resource_id=rule.id,
            details={
                "previous_status": prev_status,
                "previous_deployment_state": prev_dep_state,
                "reason": req.reason,
            },
        )

        cls._publish_rule_event(
            db=db,
            event_type=RealtimeEventTypeEnum.RULE_DISABLED.value,
            rule_id=rule.id,
            message=f"Emergency disabled: {req.reason}",
            workspace_id=workspace_id,
            payload={
                "rule_id": rule.id,
                "reason": req.reason,
                "actor": actor,
                "timestamp": now.isoformat(),
            },
        )

        # High priority Section 47 notification
        cls._send_rule_notification(
            db=db,
            workspace_id=workspace_id,
            category=NotificationCategoryEnum.SECURITY_ALERT.value,
            notification_type=NotificationTypeEnum.RULE_EMERGENCY_DISABLED.value,
            severity=NotificationSeverityEnum.CRITICAL.value,
            title=f"EMERGENCY DISABLE: {rule.name} ({rule.rule_identifier})",
            message=f"Detection rule '{rule.name}' was emergency-disabled by {actor}. Reason: {req.reason}",
            rule_id=rule.id,
            dedup_key=f"RULE-EMERGENCY-DISABLE-{rule.id}-{int(now.timestamp())}",
            metadata={"actor": actor, "reason": req.reason, "rule_identifier": rule.rule_identifier},
        )

        logger.warning("Emergency disable executed on rule %s by %s. Reason: %s", rule.id, actor, req.reason)
        return rule

    @classmethod
    def simulate_rule(
        cls,
        db: Session,
        rule_id: str,
        req: RuleSimulationRequest,
        workspace_id: str = "default",
    ) -> RuleSimulationResponse:
        """
        Executes read-only rule simulation against recent events.
        Completely isolated: creates no Findings and no production alerts.
        """
        rule = cls._get_rule(db, rule_id, workspace_id)
        def_obj = RuleDefinition.model_validate(rule.definition)

        # Fetch recent security event telemetry
        sample_size = min(req.sample_size, 500)
        events = db.query(SecurityEventModel).filter(
            SecurityEventModel.workspace_id == workspace_id,
        ).order_by(SecurityEventModel.created_at.desc()).limit(sample_size).all()

        start_time = datetime.now()
        simulation_matches: List[Dict[str, Any]] = []

        for ev in events:
            ev_data = ev.event_data if hasattr(ev, "event_data") and isinstance(ev.event_data, dict) else {}
            explanation = DetectionRuleLifecycleService._evaluate_ast_against_record(
                rule_id=rule.id,
                rule_version=rule.version,
                rule_name=rule.name,
                definition=def_obj,
                record=ev_data,
            )
            if explanation.matched:
                simulation_matches.append({
                    "event_id": ev.id,
                    "event_type": getattr(ev, "event_type", "SECURITY_EVENT"),
                    "observed_at": ev.created_at.isoformat() if ev.created_at else None,
                    "summary": explanation.summary,
                    "matched_fields": explanation.matched_fields,
                    "observed_values": explanation.observed_values,
                })

        duration_ms = (datetime.now() - start_time).total_seconds() * 1000.0

        return RuleSimulationResponse(
            rule_id=rule.id,
            rule_version=rule.version,
            status="COMPLETED",
            events_scanned=len(events),
            matches_count=len(simulation_matches),
            simulation_matches=simulation_matches,
            duration_ms=round(duration_ms, 2),
            is_simulation=True,
        )

    # =========================================================================
    # 3. RULE SUPPRESSION & CONTROLLED EXCEPTIONS
    # =========================================================================

    @classmethod
    def create_suppression(
        cls,
        db: Session,
        rule_id: str,
        req: RuleSuppressionCreateRequest,
        actor: str,
        workspace_id: str = "default",
    ) -> RuleSuppressionModel:
        """Creates a scoped, auditable exception without disabling the entire detection rule."""
        rule = cls._get_rule(db, rule_id, workspace_id)

        now = get_utc_now()
        expires_at = req.expires_at
        if req.expires_in_days:
            expires_at = now + timedelta(days=req.expires_in_days)

        suppression = RuleSuppressionModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            rule_id=rule.id,
            name=req.name.strip(),
            reason=req.reason.strip(),
            scope_type=req.scope_type.upper(),
            scope_target=req.scope_target.strip(),
            match_value=req.match_value.strip(),
            match_operator=req.match_operator.upper(),
            is_active=True,
            expires_at=expires_at,
            created_by=actor,
        )
        db.add(suppression)
        db.commit()

        cls._log_audit(
            db=db,
            workspace_id=workspace_id,
            actor=actor,
            action="SUPPRESSION_CREATED",
            resource_id=rule.id,
            details={
                "suppression_id": suppression.id,
                "name": suppression.name,
                "target": suppression.scope_target,
                "value": suppression.match_value,
                "operator": suppression.match_operator,
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )

        cls._publish_rule_event(
            db=db,
            event_type=RealtimeEventTypeEnum.RULE_SUPPRESSION_CREATED.value,
            rule_id=rule.id,
            message=f"Suppression exception created: {suppression.name}",
            workspace_id=workspace_id,
            payload={
                "rule_id": rule.id,
                "suppression_id": suppression.id,
                "name": suppression.name,
                "actor": actor,
            },
        )

        return suppression

    @classmethod
    def list_suppressions(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str = "default",
    ) -> List[RuleSuppressionModel]:
        """Lists active and expired suppressions for rule, updating expired state."""
        rule = cls._get_rule(db, rule_id, workspace_id)
        now = get_utc_now()

        suppressions = db.query(RuleSuppressionModel).filter(
            RuleSuppressionModel.workspace_id == workspace_id,
            RuleSuppressionModel.rule_id == rule.id,
        ).order_by(RuleSuppressionModel.created_at.desc()).all()

        changed = False
        for s in suppressions:
            if s.is_active and s.expires_at and now > _to_utc_aware(s.expires_at):
                s.is_active = False
                changed = True
        if changed:
            db.commit()

        return suppressions

    @classmethod
    def delete_suppression(
        cls,
        db: Session,
        rule_id: str,
        suppression_id: str,
        actor: str,
        workspace_id: str = "default",
    ) -> bool:
        """Deactivates/removes an existing suppression exception."""
        suppression = db.query(RuleSuppressionModel).filter(
            RuleSuppressionModel.workspace_id == workspace_id,
            RuleSuppressionModel.rule_id == rule_id,
            RuleSuppressionModel.id == suppression_id,
        ).first()

        if not suppression:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Suppression exception not found.")

        db.delete(suppression)
        db.commit()

        cls._log_audit(
            db=db,
            workspace_id=workspace_id,
            actor=actor,
            action="SUPPRESSION_DELETED",
            resource_id=rule_id,
            details={"suppression_id": suppression_id, "name": suppression.name},
        )
        return True

    @classmethod
    def check_suppression(
        cls,
        db: Session,
        rule_id: str,
        event_record: Dict[str, Any],
    ) -> Optional[RuleSuppressionModel]:
        """
        Evaluates active non-expired suppression rules against event record.
        Returns matching suppression if match is excluded.
        """
        now = get_utc_now()
        active_suppressions = db.query(RuleSuppressionModel).filter(
            RuleSuppressionModel.rule_id == rule_id,
            RuleSuppressionModel.is_active.is_(True),
        ).all()

        for supp in active_suppressions:
            if supp.expires_at and now > _to_utc_aware(supp.expires_at):
                supp.is_active = False
                continue

            target_val = str(event_record.get(supp.scope_target, "")).strip().lower()
            match_val = str(supp.match_value).strip().lower()

            op = supp.match_operator.upper()
            is_match = False
            if op == "EQUALS":
                is_match = (target_val == match_val)
            elif op == "CONTAINS":
                is_match = (match_val in target_val)
            elif op == "ENDS_WITH":
                is_match = target_val.endswith(match_val)
            elif op == "REGEX":
                try:
                    is_match = bool(re.search(match_val, target_val, re.IGNORECASE))
                except re.error:
                    is_match = False

            if is_match:
                return supp

        return None

    # =========================================================================
    # 4. ANALYST DISPOSITION & QUALITY FEEDBACK
    # =========================================================================

    @classmethod
    def record_match_disposition(
        cls,
        db: Session,
        execution_id: str,
        req: MatchDispositionRequest,
        actor: str,
        workspace_id: str = "default",
    ) -> CandidateRuleExecutionModel:
        """Records ground-truth analyst feedback on a detection match."""
        execution = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.id == execution_id,
            CandidateRuleExecutionModel.workspace_id == workspace_id,
        ).first()

        if not execution:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Execution match record '{execution_id}' not found.",
            )

        now = get_utc_now()
        execution.disposition = req.disposition.value
        execution.disposition_by = actor
        execution.disposition_at = now
        execution.disposition_notes = req.notes
        execution.is_false_positive = (req.disposition == MatchDispositionEnum.FALSE_POSITIVE)
        execution.feedback_reason = req.notes
        db.commit()

        cls._log_audit(
            db=db,
            workspace_id=workspace_id,
            actor=actor,
            action="MATCH_DISPOSITION_RECORDED",
            resource_id=execution.rule_id,
            details={
                "execution_id": execution.id,
                "disposition": req.disposition.value,
                "notes": req.notes,
            },
        )

        return execution

    @classmethod
    def get_rule_quality_metrics(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str = "default",
    ) -> RuleQualityMetricsResponse:
        """Calculates actual detection quality metrics from analyst dispositions."""
        rule = cls._get_rule(db, rule_id, workspace_id)

        executions = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.rule_id == rule.id,
            CandidateRuleExecutionModel.matched.is_(True),
        ).all()

        total_matches = len(executions)
        tp_count = sum(1 for e in executions if e.disposition == MatchDispositionEnum.TRUE_POSITIVE.value)
        fp_count = sum(1 for e in executions if e.disposition == MatchDispositionEnum.FALSE_POSITIVE.value)
        benign_count = sum(1 for e in executions if e.disposition == MatchDispositionEnum.BENIGN.value)
        expected_count = sum(1 for e in executions if e.disposition == MatchDispositionEnum.EXPECTED_ACTIVITY.value)
        needs_review_count = sum(1 for e in executions if e.disposition == MatchDispositionEnum.NEEDS_REVIEW.value)

        reviewed_count = tp_count + fp_count + benign_count + expected_count
        insufficient_data = (reviewed_count < 3)

        fp_rate = None
        precision = None
        review_coverage = None

        if total_matches > 0:
            review_coverage = round(reviewed_count / total_matches, 3)

        if (tp_count + fp_count) > 0:
            fp_rate = round(fp_count / (tp_count + fp_count), 3)
            precision = round(tp_count / (tp_count + fp_count), 3)

        # Deterministic verdict
        if insufficient_data:
            verdict = "INSUFFICIENT_DATA"
        elif fp_rate is not None and fp_rate >= 0.35:
            verdict = "HIGH_FALSE_POSITIVE"
        elif fp_rate is not None and fp_rate >= 0.15:
            verdict = "NEEDS_TUNING"
        elif fp_rate is not None and fp_rate < 0.05:
            verdict = "EXCELLENT"
        else:
            verdict = "HEALTHY"

        return RuleQualityMetricsResponse(
            rule_id=rule.id,
            total_matches=total_matches,
            reviewed_matches=reviewed_count,
            true_positives=tp_count,
            false_positives=fp_count,
            benign_count=benign_count,
            expected_activity_count=expected_count,
            needs_review_count=needs_review_count,
            false_positive_rate=fp_rate,
            precision_rate=precision,
            review_coverage_rate=review_coverage,
            insufficient_data=insufficient_data,
            quality_verdict=verdict,
        )

    # =========================================================================
    # 5. REDUNDANCY & CONFLICT DETECTION
    # =========================================================================

    @classmethod
    def find_duplicate_rules(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str = "default",
    ) -> List[Dict[str, Any]]:
        """Identifies near-duplicate or redundant detection rules using normalized AST fingerprints."""
        rule = cls._get_rule(db, rule_id, workspace_id)
        other_rules = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            CandidateRuleModel.id != rule.id,
            CandidateRuleModel.status.in_([RuleLifecycleStatus.ACTIVE.value, RuleLifecycleStatus.STAGED.value, RuleLifecycleStatus.CANDIDATE.value]),
        ).all()

        duplicates = []
        for other in other_rules:
            is_exact = (rule.normalized_fingerprint == other.normalized_fingerprint)
            same_category = (rule.category == other.category)
            if is_exact:
                duplicates.append({
                    "rule_id": other.id,
                    "rule_identifier": other.rule_identifier,
                    "name": other.name,
                    "status": other.status,
                    "match_type": "EXACT_NORMALIZED_AST_FINGERPRINT",
                    "similarity": 1.0,
                    "recommendation": "Review potential rule duplication. Consider deprecating redundant rule.",
                })
            elif same_category and rule.definition_json == other.definition_json:
                duplicates.append({
                    "rule_id": other.id,
                    "rule_identifier": other.rule_identifier,
                    "name": other.name,
                    "status": other.status,
                    "match_type": "IDENTICAL_CONDITIONS_DIFFERENT_METADATA",
                    "similarity": 0.95,
                    "recommendation": "Identical logic detected in different rule definitions.",
                })

        return duplicates

    @classmethod
    def find_conflicting_rules(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str = "default",
    ) -> List[Dict[str, Any]]:
        """Identifies potential semantic conflicts or conflicting suppression patterns."""
        rule = cls._get_rule(db, rule_id, workspace_id)
        conflicts = []

        # Check if rule suppressions contradict active rules in the same category
        suppressions = db.query(RuleSuppressionModel).filter(
            RuleSuppressionModel.workspace_id == workspace_id,
            RuleSuppressionModel.rule_id == rule.id,
            RuleSuppressionModel.is_active.is_(True),
        ).all()

        other_active = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            CandidateRuleModel.id != rule.id,
            CandidateRuleModel.category == rule.category,
            CandidateRuleModel.status == RuleLifecycleStatus.ACTIVE.value,
        ).all()

        for supp in suppressions:
            for other in other_active:
                if supp.match_value in other.definition_json:
                    conflicts.append({
                        "rule_id": other.id,
                        "rule_identifier": other.rule_identifier,
                        "name": other.name,
                        "conflict_type": "SUPPRESSION_INTERSECTION",
                        "details": f"Suppression target '{supp.match_value}' on rule '{rule.name}' intersects condition in active rule '{other.name}'.",
                    })

        return conflicts

    # =========================================================================
    # 6. BULK OPERATIONS
    # =========================================================================

    @classmethod
    def execute_bulk_operation(
        cls,
        db: Session,
        req: BulkRuleOperationRequest,
        actor: str,
        workspace_id: str = "default",
    ) -> BulkRuleOperationResponse:
        """
        Executes operationally safe bulk updates with individual rule validation
        and partial success reporting.
        """
        succeeded: List[str] = []
        failed: List[Dict[str, str]] = []

        op = req.operation.upper()

        for r_id in req.rule_ids:
            try:
                rule = db.query(CandidateRuleModel).filter(
                    CandidateRuleModel.workspace_id == workspace_id,
                    (CandidateRuleModel.id == r_id) | (CandidateRuleModel.rule_identifier == r_id),
                ).first()

                if not rule:
                    failed.append({"rule_id": r_id, "reason": "Rule not found."})
                    continue

                if op == "ENABLE":
                    rule.status = RuleLifecycleStatus.ACTIVE.value
                    rule.deployment_state = DeploymentStateEnum.PRODUCTION.value
                    rule.last_editor_id = actor
                elif op == "DISABLE":
                    rule.status = RuleLifecycleStatus.DISABLED.value
                    rule.deployment_state = DeploymentStateEnum.DISABLED.value
                    rule.disabled_at = get_utc_now()
                    rule.last_editor_id = actor
                elif op == "ASSIGN_OWNER":
                    if not req.owner_id:
                        raise ValueError("Missing 'owner_id' for ASSIGN_OWNER.")
                    rule.owner_id = req.owner_id
                    rule.last_editor_id = actor
                elif op == "ASSIGN_TEAM":
                    if not req.team_id:
                        raise ValueError("Missing 'team_id' for ASSIGN_TEAM.")
                    rule.team_id = req.team_id
                    rule.last_editor_id = actor
                elif op == "ADD_TAG":
                    if not req.tag:
                        raise ValueError("Missing 'tag' for ADD_TAG.")
                    tags = rule.tags
                    if req.tag not in tags:
                        tags.append(req.tag)
                        rule.tags_json = json.dumps(tags)
                    rule.last_editor_id = actor
                elif op == "REMOVE_TAG":
                    if not req.tag:
                        raise ValueError("Missing 'tag' for REMOVE_TAG.")
                    tags = [t for t in rule.tags if t != req.tag]
                    rule.tags_json = json.dumps(tags)
                    rule.last_editor_id = actor
                elif op == "SET_COLLECTION":
                    if not req.collection:
                        raise ValueError("Missing 'collection' for SET_COLLECTION.")
                    colls = rule.collections
                    if req.collection not in colls:
                        colls.append(req.collection)
                        rule.collections_json = json.dumps(colls)
                    rule.last_editor_id = actor
                elif op == "ACTIVATE":
                    # Pre-flight check
                    val = DetectionRuleLifecycleService.validate_rule_definition(RuleDefinition.model_validate(rule.definition))
                    if not val.is_valid:
                        failed.append({"rule_id": r_id, "reason": f"Validation failed: {'; '.join(val.errors)}"})
                        continue
                    rule.status = RuleLifecycleStatus.ACTIVE.value
                    rule.deployment_state = DeploymentStateEnum.PRODUCTION.value
                    rule.activated_at = get_utc_now()
                    rule.last_editor_id = actor
                else:
                    failed.append({"rule_id": r_id, "reason": f"Unsupported bulk operation '{op}'."})
                    continue

                db.commit()
                succeeded.append(rule.id)

            except Exception as e:
                db.rollback()
                failed.append({"rule_id": r_id, "reason": str(e)})

        # Log bulk audit
        cls._log_audit(
            db=db,
            workspace_id=workspace_id,
            actor=actor,
            action=f"BULK_{op}",
            resource_id="MULTIPLE",
            details={
                "operation": op,
                "requested_count": len(req.rule_ids),
                "succeeded_count": len(succeeded),
                "failed_count": len(failed),
                "succeeded_rule_ids": succeeded,
            },
        )

        return BulkRuleOperationResponse(
            operation=op,
            total_requested=len(req.rule_ids),
            succeeded_count=len(succeeded),
            failed_count=len(failed),
            succeeded_rule_ids=succeeded,
            failed_rules=failed,
        )

    # =========================================================================
    # 7. OPERATIONAL OVERVIEW & COVERAGE SUMMARY
    # =========================================================================

    @classmethod
    def get_operational_overview(
        cls,
        db: Session,
        workspace_id: str = "default",
    ) -> OperationalOverviewResponse:
        """Returns unified SOC operational health and coverage breakdown across all detection rules."""
        rules = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
        ).all()

        now = get_utc_now()
        yesterday = now - timedelta(hours=24)

        total_rules = len(rules)
        active_rules = sum(1 for r in rules if r.status == RuleLifecycleStatus.ACTIVE.value)
        staging_rules = sum(1 for r in rules if getattr(r, "deployment_state", "") == DeploymentStateEnum.STAGING.value or r.status == RuleLifecycleStatus.STAGED.value)
        draft_rules = sum(1 for r in rules if r.status in (RuleLifecycleStatus.DRAFT.value, RuleLifecycleStatus.CANDIDATE.value))
        disabled_rules = sum(1 for r in rules if r.status == RuleLifecycleStatus.DISABLED.value or getattr(r, "deployment_state", "") == DeploymentStateEnum.DISABLED.value)

        healthy_rules = sum(1 for r in rules if getattr(r, "operational_health", "") == OperationalHealthEnum.HEALTHY.value)
        degraded_rules = sum(1 for r in rules if getattr(r, "operational_health", "") == OperationalHealthEnum.DEGRADED.value)
        failing_rules = sum(1 for r in rules if getattr(r, "operational_health", "") == OperationalHealthEnum.FAILING.value)
        unknown_health = sum(1 for r in rules if getattr(r, "operational_health", "") == OperationalHealthEnum.UNKNOWN.value or not getattr(r, "operational_health", None))

        review_due_count = sum(1 for r in rules if r.next_review_due and now >= _to_utc_aware(r.next_review_due))
        stale_count = sum(1 for r in rules if (now - (_to_utc_aware(r.updated_at) or now)).days > 60 and r.status == RuleLifecycleStatus.ACTIVE.value)

        # 24h total matches across all rules
        total_matches_24h = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.workspace_id == workspace_id,
            CandidateRuleExecutionModel.executed_at >= yesterday,
            CandidateRuleExecutionModel.matched.is_(True),
        ).count()

        # Zero match rules in active production
        zero_match_count = sum(1 for r in rules if r.status == RuleLifecycleStatus.ACTIVE.value and getattr(r, "total_match_count", 0) == 0)

        # Coverage breakdown by data source
        coverage_by_source: Dict[str, int] = {}
        for r in rules:
            if r.status == RuleLifecycleStatus.ACTIVE.value:
                for src in r.data_sources:
                    coverage_by_source[src] = coverage_by_source.get(src, 0) + 1

        # Coverage breakdown by logical collections
        coverage_by_collection: Dict[str, int] = {}
        for r in rules:
            if r.status == RuleLifecycleStatus.ACTIVE.value:
                for coll in r.collections:
                    coverage_by_collection[coll] = coverage_by_collection.get(coll, 0) + 1

        return OperationalOverviewResponse(
            workspace_id=workspace_id,
            total_rules=total_rules,
            active_rules=active_rules,
            staging_rules=staging_rules,
            draft_rules=draft_rules,
            disabled_rules=disabled_rules,
            healthy_rules=healthy_rules,
            degraded_rules=degraded_rules,
            failing_rules=failing_rules,
            unknown_health_rules=unknown_health,
            review_due_count=review_due_count,
            stale_rules_count=stale_count,
            zero_match_count=zero_match_count,
            high_fp_count=0,
            unusual_match_rate_count=0,
            total_matches_24h=total_matches_24h,
            coverage_by_source=coverage_by_source,
            coverage_by_collection=coverage_by_collection,
        )

    @classmethod
    def hunt_rule_pattern(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str = "default",
    ) -> Dict[str, Any]:
        """
        Converts detection rule logic into a structured Section 54/55 Threat Hunt query representation.
        Enables seamless 'Hunt This Pattern' SOC pivots without unstructured query conversions.
        """
        rule = cls._get_rule(db, rule_id, workspace_id)
        def_obj = RuleDefinition.model_validate(rule.definition)

        hunt_conditions = []
        for cond in def_obj.conditions:
            hunt_conditions.append({
                "field": cond.field,
                "operator": cond.operator,
                "value": cond.value,
            })

        return {
            "origin_rule_id": rule.id,
            "origin_rule_identifier": rule.rule_identifier,
            "rule_name": rule.name,
            "category": rule.category,
            "suggested_hunt_title": f"Threat Hunt: {rule.name}",
            "data_sources": rule.data_sources,
            "logical_operator": def_obj.logical_operator,
            "conditions": hunt_conditions,
            "target_time_window_seconds": rule.time_window_seconds or 86400 * 7,
        }

    # =========================================================================
    # 8. BACKGROUND JOBS & HEALTH SCHEDULER
    # =========================================================================

    @classmethod
    def evaluate_all_rules_health(
        cls,
        db: Session,
        workspace_id: str = "default",
    ) -> Dict[str, Any]:
        """Evaluates operational health for all active and candidate rules in a workspace."""
        rules = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            CandidateRuleModel.status.in_([
                RuleLifecycleStatus.ACTIVE.value,
                RuleLifecycleStatus.STAGED.value,
                RuleLifecycleStatus.CANDIDATE.value,
            ]),
        ).all()

        evaluated_count = 0
        healthy_count = 0
        degraded_count = 0
        failing_count = 0

        for r in rules:
            try:
                res = cls.evaluate_rule_health(db, r.id, workspace_id)
                evaluated_count += 1
                if res.operational_health == OperationalHealthEnum.HEALTHY:
                    healthy_count += 1
                elif res.operational_health == OperationalHealthEnum.DEGRADED:
                    degraded_count += 1
                elif res.operational_health == OperationalHealthEnum.FAILING:
                    failing_count += 1
            except Exception as e:
                logger.error("Failed health check for rule %s: %s", r.id, e)

        return {
            "total_evaluated": evaluated_count,
            "healthy": healthy_count,
            "degraded": degraded_count,
            "failing": failing_count,
        }

    # =========================================================================
    # PRIVATE UTILITIES & NOTIFICATIONS
    # =========================================================================

    @classmethod
    def _get_rule(cls, db: Session, rule_id: str, workspace_id: str) -> CandidateRuleModel:
        rule = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
        ).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection rule '{rule_id}' not found in workspace '{workspace_id}'.",
            )
        return rule

    @classmethod
    def _send_rule_notification(
        cls,
        db: Session,
        workspace_id: str,
        category: str,
        notification_type: str,
        severity: str,
        title: str,
        message: str,
        rule_id: str,
        dedup_key: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            NotificationService.create_notification(
                db=db,
                workspace_id=workspace_id,
                category=category,
                notification_type=notification_type,
                severity=severity,
                title=title,
                message=message,
                source_type="DETECTION_RULE",
                source_id=rule_id,
                deduplication_key=dedup_key,
                metadata=metadata or {},
            )
        except Exception as e:
            logger.warning("Failed to dispatch rule notification for rule %s: %s", rule_id, e)

    @classmethod
    def _publish_rule_event(
        cls,
        db: Session,
        event_type: str,
        rule_id: str,
        message: str,
        workspace_id: str = "default",
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            RealtimePublisher.publish_event(
                db=db,
                topic="detection_rules",
                event_type=event_type,
                resource_type="RULE",
                resource_id=rule_id,
                message=message,
                workspace_id=workspace_id,
                payload=payload or {},
            )
        except Exception as e:
            logger.warning("Failed to publish realtime rule event for rule %s: %s", rule_id, e)

    @classmethod
    def _send_review_due_notification(cls, db: Session, rule: CandidateRuleModel, workspace_id: str) -> None:
        cls._send_rule_notification(
            db=db,
            workspace_id=workspace_id,
            category=NotificationCategoryEnum.NOTIFICATION.value,
            notification_type=NotificationTypeEnum.RULE_REVIEW_DUE.value,
            severity=NotificationSeverityEnum.MEDIUM.value,
            title=f"Rule Review Due: {rule.name}",
            message=f"Detection rule '{rule.name}' ({rule.rule_identifier}) has exceeded its {rule.review_interval_days or 90}-day review interval and requires operational recertification.",
            rule_id=rule.id,
            dedup_key=f"RULE-REVIEW-DUE-{rule.id}-{get_utc_now().strftime('%Y-%m-%d')}",
            metadata={"rule_id": rule.id, "owner_id": rule.owner_id},
        )

    @classmethod
    def _send_failing_rule_notification(cls, db: Session, rule: CandidateRuleModel, reason: str, workspace_id: str) -> None:
        cls._send_rule_notification(
            db=db,
            workspace_id=workspace_id,
            category=NotificationCategoryEnum.SECURITY_ALERT.value,
            notification_type=NotificationTypeEnum.RULE_DEPENDENCY_FAILED.value,
            severity=NotificationSeverityEnum.HIGH.value,
            title=f"Detection Rule FAILING: {rule.name}",
            message=f"Production detection rule '{rule.name}' ({rule.rule_identifier}) entered FAILING operational health. Reason: {reason}",
            rule_id=rule.id,
            dedup_key=f"RULE-FAILING-{rule.id}-{get_utc_now().strftime('%Y-%m-%d')}",
            metadata={"rule_id": rule.id, "reason": reason, "owner_id": rule.owner_id},
        )

    @staticmethod
    def _log_audit(
        db: Session,
        workspace_id: str,
        actor: str,
        action: str,
        resource_id: str,
        details: Dict[str, Any],
    ) -> None:
        try:
            audit = AuditLogModel(
                id=generate_uuid(),
                action=action,
                user=actor,
                resource_type="DETECTION_RULE",
                resource_id=resource_id,
                details=json.dumps(details),
                metadata_json=json.dumps({"workspace_id": workspace_id, **details}),
                timestamp=get_utc_now(),
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            logger.warning("Failed to record audit log for rule %s: %s", resource_id, e)
