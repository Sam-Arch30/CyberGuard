"""
Service layer for Section 44: SOC Overview Dashboard.
Provides authoritative aggregation of Security Posture, Priority Queue,
Risk Distribution, Investigation Activity, Threat Intelligence, and System/Fleet Health.
Enforces real persisted data only and tenant/workspace boundaries.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Set
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_, text

from backend.db.models import (
    IncidentModel,
    CaseModel,
    FindingModel,
    IndicatorModel,
    CampaignModel,
    CampaignIncidentModel,
    AnalysisRunModel,
    AnalysisTaskModel,
    AuditLogModel,
    ResponseRecommendationModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    ThreatMemoryDecisionModel,
    EndpointAgentModel,
    RelationshipModel,
    BackgroundJobModel,
    get_utc_now,
)
from backend.schemas.soc_overview import (
    SocOverviewResponse,
    SocPostureMetrics,
    SocRiskDistribution,
    SocPriorityQueueItem,
    SocActivityItem,
    SocThreatIntelItem,
    SocCampaignSummaryItem,
    SocEndpointFleetSummary,
    SocSystemHealth,
)
from backend.services.endpoint_agent_service import EndpointAgentService

logger = logging.getLogger("cyberguard.services.soc_dashboard_service")


class SocDashboardService:
    """
    Central aggregation engine for Section 44: SOC Overview.
    Executes bounded, indexed queries across persistent models to build
    an actionable operational security view for analysts.
    """

    @classmethod
    def get_overview(
        cls,
        db: Session,
        time_window: str = "30d",
        workspace_id: str = "default",
        limit_queue: int = 10,
        limit_activity: int = 15,
    ) -> SocOverviewResponse:
        now = datetime.now(timezone.utc)
        partial_failures: List[str] = []

        # 1. Resolve Time Window boundary
        window_start: Optional[datetime] = None
        if time_window == "24h":
            window_start = now - timedelta(hours=24)
        elif time_window == "7d":
            window_start = now - timedelta(days=7)
        elif time_window == "30d":
            window_start = now - timedelta(days=30)
        elif time_window == "all":
            window_start = None
        else:
            time_window = "30d"
            window_start = now - timedelta(days=30)

        # 2. Query Incidents and Cases
        incidents: List[IncidentModel] = []
        cases: List[CaseModel] = []
        try:
            incidents_query = db.query(IncidentModel).filter(IncidentModel.workspace_id == workspace_id)
            incidents = incidents_query.all()
        except Exception as e:
            logger.warning(f"Failed to query incidents: {e}")
            partial_failures.append("incidents")

        try:
            cases = db.query(CaseModel).all()
        except Exception as e:
            logger.warning(f"Failed to query legacy cases: {e}")
            partial_failures.append("cases")

        # Map distinct investigations
        seen_case_ids: Set[str] = set()
        active_investigations_count = 0
        high_risk_open_count = 0
        total_investigations_count = 0

        # Risk distribution tallies
        crit_count = 0
        high_count = 0
        med_count = 0
        low_count = 0
        safe_count = 0

        # Candidate priority items
        priority_candidates: List[SocPriorityQueueItem] = []

        # Process Incidents
        for inc in incidents:
            if inc.legacy_case_id:
                seen_case_ids.add(inc.legacy_case_id)
            total_investigations_count += 1

            status_upper = (inc.status or "OPEN").upper()
            is_active = status_upper in {"OPEN", "INVESTIGATING", "CONTAINED"}
            if is_active:
                active_investigations_count += 1

            score = float(inc.risk_score or 0.0)
            sev_upper = (inc.severity or "MEDIUM").upper()

            is_high_risk = sev_upper in {"HIGH", "CRITICAL"} or score >= 60.0
            if is_active and is_high_risk:
                high_risk_open_count += 1

            # Tally risk distribution
            if sev_upper == "CRITICAL" or score >= 80.0:
                crit_count += 1
            elif sev_upper == "HIGH" or score >= 60.0:
                high_count += 1
            elif sev_upper == "MEDIUM" or score >= 40.0:
                med_count += 1
            elif sev_upper == "LOW" or score >= 20.0:
                low_count += 1
            else:
                safe_count += 1

            # Consider for Priority Queue if active
            if is_active:
                sla_stat = getattr(inc, "sla_status", "HEALTHY")
                time_rem = None
                if getattr(inc, "next_sla_deadline", None):
                    dl = inc.next_sla_deadline
                    if dl.tzinfo is None:
                        dl = dl.replace(tzinfo=timezone.utc)
                    time_rem = round(max(0.0, (dl - now).total_seconds() / 60.0), 1)

                if sla_stat == "BREACHED":
                    urgency = "P0"
                    reason = f"CRITICAL SLA BREACH: Incident {inc.incident_number} breached target"
                elif sla_stat == "WARNING":
                    urgency = "P1"
                    reason = f"SLA WARNING: Incident {inc.incident_number} approaching breach ({time_rem or 0}m left)"
                elif sev_upper == "CRITICAL" and (not inc.assigned_to or inc.assigned_to == "Unassigned"):
                    urgency = "P0"
                    reason = f"UNASSIGNED CRITICAL: Immediate assignment required"
                elif sev_upper == "CRITICAL" or score >= 80.0:
                    urgency = "P0"
                    reason = "Critical-risk active incident requiring immediate response"
                elif sev_upper == "HIGH" or score >= 60.0:
                    urgency = "P1"
                    reason = "High-risk active investigation awaiting analyst review"
                elif status_upper == "OPEN":
                    urgency = "P2"
                    reason = "Unresolved incident open in workspace"
                else:
                    urgency = "P3"
                    reason = "Active investigation in progress"

                iso_updated = (inc.updated_at or inc.created_at or now).isoformat()
                priority_candidates.append(
                    SocPriorityQueueItem(
                        id=inc.id,
                        investigation_id=inc.id,
                        title=inc.title or f"Incident {inc.incident_number}",
                        risk_score=score,
                        severity=sev_upper,
                        status=status_upper,
                        resource_type="INCIDENT",
                        reason_for_inclusion=reason,
                        urgency=urgency,
                        updated_at=iso_updated,
                        navigation_target=f"/incidents/{inc.id}",
                        sla_status=sla_stat,
                        time_remaining_mins=time_rem,
                    )
                )

        # Process non-overlapping Cases
        for c in cases:
            if c.id in seen_case_ids:
                continue
            total_investigations_count += 1

            c_status_upper = (c.status or "open").upper()
            is_active = c_status_upper in {"OPEN", "INVESTIGATING", "CONTAINED"}
            if is_active:
                active_investigations_count += 1

            c_sev_upper = (c.severity or "low").upper()
            c_score = 90.0 if c_sev_upper == "CRITICAL" else 70.0 if c_sev_upper == "HIGH" else 40.0 if c_sev_upper == "MEDIUM" else 15.0

            if is_active and (c_sev_upper in {"HIGH", "CRITICAL"} or c_score >= 60.0):
                high_risk_open_count += 1

            if c_sev_upper == "CRITICAL":
                crit_count += 1
            elif c_sev_upper == "HIGH":
                high_count += 1
            elif c_sev_upper == "MEDIUM":
                med_count += 1
            elif c_sev_upper == "LOW":
                low_count += 1
            else:
                safe_count += 1

            if is_active:
                urgency = "P0" if c_sev_upper == "CRITICAL" else "P1" if c_sev_upper == "HIGH" else "P2"
                reason = "Active security incident case requiring triage"
                iso_updated = (c.updated_at or c.created_at or now).isoformat()
                priority_candidates.append(
                    SocPriorityQueueItem(
                        id=c.id,
                        investigation_id=c.id,
                        title=c.title or f"Case {c.case_number}",
                        risk_score=c_score,
                        severity=c_sev_upper,
                        status=c_status_upper,
                        resource_type="INVESTIGATION",
                        reason_for_inclusion=reason,
                        urgency=urgency,
                        updated_at=iso_updated,
                        navigation_target=f"/investigations/{c.id}/overview",
                    )
                )

        # 3. Response Recommendations awaiting approval
        pending_approvals_count = 0
        try:
            recs_query = db.query(ResponseRecommendationModel).filter(
                ResponseRecommendationModel.workspace_id == workspace_id,
                or_(
                    ResponseRecommendationModel.status == "REVIEW_REQUIRED",
                    and_(
                        ResponseRecommendationModel.approval_required.is_(True),
                        ResponseRecommendationModel.status.in_(["GENERATED", "REVIEW_REQUIRED"]),
                    ),
                ),
            )
            recs = recs_query.all()
            pending_approvals_count = len(recs)

            for rec in recs[:5]:
                prio_urgency = "P0" if rec.priority == "P0" else "P1" if rec.priority == "P1" else "P2"
                iso_created = (rec.updated_at or rec.created_at or now).isoformat()
                target_inv = rec.incident_id or rec.scope_id
                priority_candidates.append(
                    SocPriorityQueueItem(
                        id=rec.id,
                        investigation_id=target_inv,
                        title=f"Response Approval: {rec.title}",
                        risk_score=85.0 if rec.priority in {"P0", "P1"} else 50.0,
                        severity="HIGH" if rec.priority in {"P0", "P1"} else "MEDIUM",
                        status=rec.status,
                        resource_type="RECOMMENDATION",
                        reason_for_inclusion=f"Defensive action requires approval ({rec.action_type})",
                        urgency=prio_urgency,
                        updated_at=iso_created,
                        navigation_target=f"/investigations/{target_inv}/response" if target_inv else "/investigations",
                    )
                )
        except Exception as e:
            logger.warning(f"Failed to query response recommendations: {e}")
            partial_failures.append("response_recommendations")

        # 4. Failed Analysis & Background Jobs within time window
        failed_jobs_count = 0
        try:
            runs_query = db.query(AnalysisRunModel).filter(AnalysisRunModel.status == "FAILED")
            if window_start:
                runs_query = runs_query.filter(AnalysisRunModel.started_at >= window_start)
            failed_runs = runs_query.order_by(desc(AnalysisRunModel.started_at)).all()
            failed_jobs_count += len(failed_runs)

            bg_jobs_query = db.query(BackgroundJobModel).filter(
                BackgroundJobModel.status.in_(["FAILED", "DEAD_LETTER", "TIMED_OUT"])
            )
            if window_start:
                bg_jobs_query = bg_jobs_query.filter(BackgroundJobModel.created_at >= window_start)
            failed_bg_jobs = bg_jobs_query.order_by(desc(BackgroundJobModel.created_at)).all()
            failed_jobs_count += len(failed_bg_jobs)

            for fr in failed_runs[:2]:
                iso_time = (fr.started_at or now).isoformat()
                priority_candidates.append(
                    SocPriorityQueueItem(
                        id=fr.id,
                        investigation_id=None,
                        title=f"Analysis Run Failed (Artifact: {fr.artifact_id[:12]})",
                        risk_score=60.0,
                        severity="HIGH",
                        status="FAILED",
                        resource_type="ANALYSIS_RUN",
                        reason_for_inclusion="Asynchronous pipeline failure requiring triage",
                        urgency="P2",
                        updated_at=iso_time,
                        navigation_target=f"/investigations/{fr.id}/overview",
                    )
                )

            for bj in failed_bg_jobs[:2]:
                iso_time = (bj.completed_at or bj.created_at or now).isoformat()
                priority_candidates.append(
                    SocPriorityQueueItem(
                        id=bj.id,
                        investigation_id=bj.resource_id if bj.resource_type in {"INCIDENT", "INVESTIGATION"} else None,
                        title=f"Background Job {bj.status} ({bj.job_type})",
                        risk_score=65.0,
                        severity="HIGH",
                        status=bj.status,
                        resource_type="BACKGROUND_JOB",
                        reason_for_inclusion=f"Background job failed: {bj.sanitized_error_message or bj.error_code or 'Processing error'}",
                        urgency="P2",
                        updated_at=iso_time,
                        navigation_target=f"/investigations/{bj.resource_id}/overview" if bj.resource_id else "/dashboard",
                    )
                )
        except Exception as e:
            logger.warning(f"Failed to query failed analysis runs or background jobs: {e}")
            partial_failures.append("analysis_runs")
            partial_failures.append("analysis_runs")

        # 5. New Findings Count within time window
        new_findings_count = 0
        try:
            findings_q = db.query(FindingModel)
            if window_start:
                findings_q = findings_q.filter(FindingModel.created_at >= window_start)
            new_findings_count = findings_q.count()
        except Exception as e:
            logger.warning(f"Failed to query findings count: {e}")
            partial_failures.append("findings")

        # 6. Active Endpoint Fleet Agents
        active_agents_count = 0
        fleet_summary: Optional[SocEndpointFleetSummary] = None
        try:
            metrics = EndpointAgentService.get_metrics(db, workspace_id)
            active_agents_count = metrics.get("agents_active", 0)
            fleet_summary = SocEndpointFleetSummary(
                enrolled=metrics.get("agents_enrolled", 0),
                active=metrics.get("agents_active", 0),
                degraded=metrics.get("agents_degraded", 0),
                revoked=metrics.get("agents_revoked", 0),
                events_received=metrics.get("events_received", 0),
            )
        except Exception as e:
            logger.warning(f"Failed to query endpoint fleet metrics: {e}")
            partial_failures.append("endpoint_agents")

        # 7. Sort Priority Queue deterministically
        def priority_sort_key(item: SocPriorityQueueItem):
            urgency_weight = {"P0": 4, "P1": 3, "P2": 2, "P3": 1}.get(item.urgency, 0)
            return (urgency_weight, item.risk_score, item.updated_at)

        priority_candidates.sort(key=priority_sort_key, reverse=True)
        final_priority_queue = priority_candidates[:limit_queue]

        # 8. Recent Meaningful Activity Feed (Audit Log)
        activity_items: List[SocActivityItem] = []
        try:
            audit_query = db.query(AuditLogModel).order_by(desc(AuditLogModel.timestamp))
            if window_start:
                audit_query = audit_query.filter(AuditLogModel.timestamp >= window_start)
            audit_records = audit_query.limit(limit_activity).all()

            action_descriptions = {
                "EMAIL_UPLOADED": "Evidence telemetry artifact ingested",
                "ANALYSIS_STARTED": "Pipeline analysis execution initiated",
                "ANALYSIS_COMPLETED": "Deep analysis completed with verified findings",
                "CASE_CREATED": "New investigation incident record established",
                "CASE_STATUS_CHANGED": "Investigation status updated",
                "NOTE_ADDED": "Analyst forensic note recorded",
                "REPORT_GENERATED": "Forensic investigation report dossier compiled",
                "RECOMMENDATION_APPROVED": "Response recommendation approved for execution",
                "DECISION_RECORDED": "Analyst decision and feedback logged",
            }

            for rec in audit_records:
                desc_text = action_descriptions.get(rec.action, f"{rec.action.replace('_', ' ').capitalize()} recorded")
                if rec.details:
                    desc_text += f" - {rec.details}"

                nav_target = None
                if rec.case_id:
                    nav_target = f"/investigations/{rec.case_id}/overview"
                elif rec.resource_type in {"case", "incident", "investigation"} and rec.resource_id:
                    nav_target = f"/investigations/{rec.resource_id}/overview"
                elif rec.resource_type == "report" and rec.resource_id:
                    nav_target = f"/reports/{rec.resource_id}"

                activity_items.append(
                    SocActivityItem(
                        id=rec.id,
                        event_type=rec.action,
                        timestamp=(rec.timestamp or now).isoformat(),
                        resource_type=rec.resource_type,
                        resource_id=rec.resource_id,
                        description=desc_text,
                        user=rec.user or "System",
                        severity=None,
                        source="AUDIT_LOG",
                        navigation_target=nav_target,
                    )
                )
        except Exception as e:
            logger.warning(f"Failed to query audit logs for activity feed: {e}")
            partial_failures.append("audit_logs")

        # 9. Threat Intelligence & Emerging Campaigns Summary
        threat_intel_items: List[SocThreatIntelItem] = []
        try:
            indicators = (
                db.query(IndicatorModel)
                .order_by(desc(IndicatorModel.created_at))
                .limit(6)
                .all()
            )

            for ind in indicators:
                # Count investigations this indicator appears in
                inv_count = 1
                try:
                    rel_count = (
                        db.query(RelationshipModel)
                        .filter(
                            RelationshipModel.target_id == ind.id,
                            RelationshipModel.source_type == "INCIDENT",
                        )
                        .count()
                    )
                    inv_count = max(1, rel_count)
                except Exception:
                    pass

                # Check Threat Memory provenance
                provenance = "CURRENT_OBSERVATION"
                try:
                    mem_entry = (
                        db.query(ThreatMemoryEntryModel)
                        .filter(ThreatMemoryEntryModel.canonical_key == ind.normalized_value)
                        .first()
                    )
                    if mem_entry:
                        dec = (
                            db.query(ThreatMemoryDecisionModel)
                            .filter(ThreatMemoryDecisionModel.memory_entry_id == mem_entry.id)
                            .first()
                        )
                        if dec:
                            provenance = "ANALYST_VERIFIED"
                        else:
                            provenance = "HISTORICAL_MEMORY"
                except Exception:
                    pass

                iso_last_seen = (getattr(ind, "last_seen", None) or getattr(ind, "first_seen", None) or ind.created_at or now).isoformat()
                threat_intel_items.append(
                    SocThreatIntelItem(
                        indicator_value=ind.value,
                        indicator_type=(ind.indicator_type or "INDICATOR").upper(),
                        investigation_count=inv_count,
                        provenance=provenance,
                        reputation=ind.reputation or "UNKNOWN",
                        last_seen_at=iso_last_seen,
                    )
                )
        except Exception as e:
            logger.warning(f"Failed to query threat intelligence: {e}")
            partial_failures.append("threat_intel")

        # Active campaigns
        campaign_items: List[SocCampaignSummaryItem] = []
        try:
            campaigns = (
                db.query(CampaignModel)
                .order_by(desc(CampaignModel.updated_at))
                .limit(4)
                .all()
            )

            for cmp in campaigns:
                inc_count = (
                    db.query(CampaignIncidentModel)
                    .filter(CampaignIncidentModel.campaign_id == cmp.id)
                    .count()
                )
                campaign_items.append(
                    SocCampaignSummaryItem(
                        id=cmp.id,
                        campaign_id=cmp.campaign_id or f"CMP-{cmp.id[:8]}",
                        name=cmp.name,
                        status=cmp.status or "ACTIVE",
                        incident_count=inc_count,
                        dominant_attack_type=cmp.dominant_attack_type,
                        updated_at=(cmp.updated_at or cmp.created_at or now).isoformat(),
                    )
                )
        except Exception as e:
            logger.warning(f"Failed to query campaigns: {e}")
            partial_failures.append("campaigns")

        # 10. Platform & Pipeline Health Check
        db_status = "connected"
        api_status = "healthy"
        engine_status = "operational"
        active_tasks = 0
        failed_tasks = 0

        try:
            db.execute(text("SELECT 1"))
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            db_status = "disconnected"
            partial_failures.append("database")

        try:
            active_tasks = (
                db.query(AnalysisTaskModel)
                .filter(AnalysisTaskModel.status.in_(["PENDING", "RUNNING"]))
                .count()
            )
            active_tasks += (
                db.query(BackgroundJobModel)
                .filter(BackgroundJobModel.status.in_(["QUEUED", "RUNNING", "RETRY_WAIT"]))
                .count()
            )
            failed_tasks = (
                db.query(AnalysisTaskModel)
                .filter(AnalysisTaskModel.status == "FAILED")
                .count()
            )
            failed_tasks += (
                db.query(BackgroundJobModel)
                .filter(BackgroundJobModel.status.in_(["FAILED", "DEAD_LETTER", "TIMED_OUT"]))
                .count()
            )
            if failed_tasks > 10:
                engine_status = "degraded"
        except Exception as e:
            logger.warning(f"Failed to inspect task and job engine status: {e}")
            partial_failures.append("task_engine")

        overall_status = "operational"
        if db_status != "connected":
            overall_status = "unavailable"
        elif len(partial_failures) > 0 or engine_status == "degraded":
            overall_status = "degraded"

        system_health = SocSystemHealth(
            status=overall_status,
            api_status=api_status,
            database_status=db_status,
            analysis_engine_status=engine_status,
            active_tasks=active_tasks,
            failed_tasks=failed_tasks,
            endpoint_fleet=fleet_summary,
        )

        # Assemble Posture Metrics
        sla_breaches_count = sum(
            1 for inc in incidents
            if getattr(inc, "sla_status", "") == "BREACHED" and (inc.status or "").upper() in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )
        approaching_sla_count = sum(
            1 for inc in incidents
            if getattr(inc, "sla_status", "") == "WARNING" and (inc.status or "").upper() in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )
        unack_critical_count = sum(
            1 for inc in incidents
            if (inc.severity or "").upper() == "CRITICAL" and not inc.acknowledged_at and (inc.status or "").upper() in ("NEW", "OPEN")
        )
        escalated_incidents_count = sum(
            1 for inc in incidents
            if (getattr(inc, "escalation_level", 0) or 0) > 0 and (inc.status or "").upper() in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )
        unassigned_critical_count = sum(
            1 for inc in incidents
            if (inc.severity or "").upper() == "CRITICAL" and (not inc.assigned_to or inc.assigned_to == "Unassigned") and (inc.status or "").upper() in ("NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING")
        )

        posture = SocPostureMetrics(
            active_investigations=active_investigations_count,
            high_risk_open=high_risk_open_count,
            pending_response_approvals=pending_approvals_count,
            failed_analysis_jobs=failed_jobs_count,
            new_findings_count=new_findings_count,
            active_endpoint_agents=active_agents_count,
            total_investigations=total_investigations_count,
            sla_breaches=sla_breaches_count,
            approaching_sla=approaching_sla_count,
            unacknowledged_critical=unack_critical_count,
            escalated_incidents=escalated_incidents_count,
            unassigned_critical=unassigned_critical_count,
        )

        risk_dist = SocRiskDistribution(
            critical=crit_count,
            high=high_count,
            medium=med_count,
            low=low_count,
            safe=safe_count,
            total=crit_count + high_count + med_count + low_count + safe_count,
        )

        # Section 64: Top Operational Prioritized Assets
        try:
            from backend.services.asset_prioritization_service import AssetPrioritizationService
            highest_priority_assets = AssetPrioritizationService.get_top_prioritized_assets(db, workspace_id, limit=5)
        except Exception as e:
            logger.warning("Failed to fetch highest priority assets for SOC overview: %s", e)
            highest_priority_assets = []

        return SocOverviewResponse(
            generated_at=now.isoformat(),
            time_window=time_window,
            posture=posture,
            risk_distribution=risk_dist,
            priority_queue=final_priority_queue,
            recent_activity=activity_items,
            threat_intel=threat_intel_items,
            active_campaigns=campaign_items,
            system_health=system_health,
            highest_priority_assets=highest_priority_assets,
            partial_failures=partial_failures,
        )
