"""
Section 66: Advanced Investigation Automation Core Service.
Coordinates automated, analyst-guided investigation runs, step execution,
approval gates, background job dispatch, loop prevention, telemetry coverage audit,
gap tracking, and realtime notification broadcasts.
"""
from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    InvestigationAutomationRunModel,
    InvestigationAutomationStepModel,
    InvestigationAutomationPolicyModel,
    InvestigationGapModel,
    IncidentModel,
    AnalysisRunModel,
    ArtifactModel,
    AuditLogModel,
    get_utc_now,
    generate_uuid,
)
from backend.schemas.investigation_automation import (
    AutomationBudget,
    AutomationMode,
    AutomationRunStatus,
    AutomationStepCreate,
    AutomationStepRead,
    AutomationTriggerType,
    ActionApprovalLevel,
    ActionCostClass,
    ActionIdEnum,
    GapCategory,
    GapSeverity,
    InvestigationAutomationRunCreate,
    InvestigationAutomationRunRead,
    InvestigationCoverageReport,
    InvestigationGapRead,
    InvestigationSummaryReport,
    RecommendedNextStep,
    StepStatus,
    TelemetryCoverageItem,
    TelemetryCoverageStatus,
    AutomationPolicyCreate,
    AutomationPolicyRead,
    AutomationTemplateDefinition,
)
from backend.services.investigation_action_registry import (
    ACTION_REGISTRY,
    get_action_entry,
    SecurityActionProhibitedError,
    StepExecutionOutput,
)
from backend.services.investigation_workspace_service import InvestigationWorkspaceService
from backend.services.realtime_service import RealtimePublisher
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
    RealtimeEventPayload,
)

logger = logging.getLogger("cyberguard.services.investigation_automation_service")

# =============================================================================
# Standard Investigation Templates
# =============================================================================

INVESTIGATION_TEMPLATES: Dict[str, AutomationTemplateDefinition] = {
    "PHISHING_INVESTIGATION": AutomationTemplateDefinition(
        template_name="PHISHING_INVESTIGATION",
        title="Automated Phishing & Credential Harvest Investigation",
        description="Extracts indicators, enriches external domains/URLs, resolves targeted identities, correlates campaigns, and audits timeline.",
        target_trigger="Suspicious Email / Phishing Campaign Detection",
        steps=[
            AutomationStepCreate(step_index=0, action_id=ActionIdEnum.GET_INDICATOR_CONTEXT, name="Extract Email Indicators"),
            AutomationStepCreate(step_index=1, action_id=ActionIdEnum.GET_THREAT_INTELLIGENCE, name="Enrich Indicators with Threat Intel"),
            AutomationStepCreate(step_index=2, action_id=ActionIdEnum.GET_WATCHLIST_CONTEXT, name="Check Active Watchlists"),
            AutomationStepCreate(step_index=3, action_id=ActionIdEnum.GET_IDENTITY_CONTEXT, name="Resolve Targeted Employee Identities"),
            AutomationStepCreate(step_index=4, action_id=ActionIdEnum.GET_ASSET_CONTEXT, name="Resolve Associated Endpoint Assets"),
            AutomationStepCreate(step_index=5, action_id=ActionIdEnum.GET_CAMPAIGN_CONTEXT, name="Correlate Known Threat Campaigns"),
            AutomationStepCreate(step_index=6, action_id=ActionIdEnum.BUILD_TIMELINE, name="Reconstruct Email Attack Timeline"),
            AutomationStepCreate(step_index=7, action_id=ActionIdEnum.CHECK_DATA_COVERAGE, name="Audit Telemetry Coverage & Gaps"),
            AutomationStepCreate(step_index=8, action_id=ActionIdEnum.GENERATE_INVESTIGATION_SUMMARY, name="Compile Investigation Summary & Next Steps"),
        ],
    ),
    "ACCOUNT_TAKEOVER_INVESTIGATION": AutomationTemplateDefinition(
        template_name="ACCOUNT_TAKEOVER_INVESTIGATION",
        title="Account Takeover (ATO) & Identity Compromise Investigation",
        description="Inspects identity context, authentication history, behavioral anomalies, asset exposure, and related security alerts.",
        target_trigger="Impossible Travel / Suspicious Authentication / ATO Alert",
        steps=[
            AutomationStepCreate(step_index=0, action_id=ActionIdEnum.GET_IDENTITY_CONTEXT, name="Resolve Compromised Identity Context"),
            AutomationStepCreate(step_index=1, action_id=ActionIdEnum.GET_BEHAVIOR_CONTEXT, name="Evaluate User Behavioral Deviations"),
            AutomationStepCreate(step_index=2, action_id=ActionIdEnum.GET_ASSET_CONTEXT, name="Check Associated Access Endpoints"),
            AutomationStepCreate(step_index=3, action_id=ActionIdEnum.GET_THREAT_INTELLIGENCE, name="Query Origin IP Intelligence"),
            AutomationStepCreate(step_index=4, action_id=ActionIdEnum.GET_RELATED_ALERTS, name="Correlate Concurrent Identity Alerts"),
            AutomationStepCreate(step_index=5, action_id=ActionIdEnum.BUILD_TIMELINE, name="Reconstruct Authentication Timeline"),
            AutomationStepCreate(step_index=6, action_id=ActionIdEnum.CHECK_DATA_COVERAGE, name="Audit IdP & Telemetry Coverage"),
            AutomationStepCreate(step_index=7, action_id=ActionIdEnum.GENERATE_INVESTIGATION_SUMMARY, name="Compile ATO Investigation Summary"),
        ],
    ),
    "MALICIOUS_ATTACHMENT_INVESTIGATION": AutomationTemplateDefinition(
        template_name="MALICIOUS_ATTACHMENT_INVESTIGATION",
        title="Malicious Attachment & Endpoint Payload Investigation",
        description="Extracts file hashes, inspects multi-engine intelligence, evaluates endpoint telemetry, and traverses the knowledge graph.",
        target_trigger="High-Risk Attachment / Weaponized Document Alert",
        steps=[
            AutomationStepCreate(step_index=0, action_id=ActionIdEnum.GET_INDICATOR_CONTEXT, name="Extract Attachment Hashes & Metadata"),
            AutomationStepCreate(step_index=1, action_id=ActionIdEnum.GET_THREAT_INTELLIGENCE, name="Query File Hash Reputation"),
            AutomationStepCreate(step_index=2, action_id=ActionIdEnum.GET_ASSET_CONTEXT, name="Inspect Recipient Endpoint Asset"),
            AutomationStepCreate(step_index=3, action_id=ActionIdEnum.GET_GRAPH_RELATIONSHIPS, name="Traverse Security Knowledge Graph"),
            AutomationStepCreate(step_index=4, action_id=ActionIdEnum.GET_CAMPAIGN_CONTEXT, name="Check Associated Threat Actor Clusters"),
            AutomationStepCreate(step_index=5, action_id=ActionIdEnum.BUILD_TIMELINE, name="Reconstruct Delivery & Execution Timeline"),
            AutomationStepCreate(step_index=6, action_id=ActionIdEnum.CHECK_DATA_COVERAGE, name="Audit Endpoint EDR Coverage & Gaps"),
            AutomationStepCreate(step_index=7, action_id=ActionIdEnum.GENERATE_INVESTIGATION_SUMMARY, name="Compile Malware Investigation Summary"),
        ],
    ),
    "GENERAL_INCIDENT_INVESTIGATION": AutomationTemplateDefinition(
        template_name="GENERAL_INCIDENT_INVESTIGATION",
        title="Comprehensive Multi-Source Incident Investigation",
        description="Standard full-spectrum automated investigation workflow covering indicators, assets, identities, alerts, and campaigns.",
        target_trigger="General Security Incident / Manual Analyst Trigger",
        steps=[
            AutomationStepCreate(step_index=0, action_id=ActionIdEnum.GET_INDICATOR_CONTEXT, name="Extract Technical Indicators"),
            AutomationStepCreate(step_index=1, action_id=ActionIdEnum.GET_ASSET_CONTEXT, name="Retrieve Affected Asset Context"),
            AutomationStepCreate(step_index=2, action_id=ActionIdEnum.GET_IDENTITY_CONTEXT, name="Retrieve Affected Identity Context"),
            AutomationStepCreate(step_index=3, action_id=ActionIdEnum.GET_THREAT_INTELLIGENCE, name="Query Threat Intelligence Cache"),
            AutomationStepCreate(step_index=4, action_id=ActionIdEnum.GET_WATCHLIST_CONTEXT, name="Check Active Watchlists"),
            AutomationStepCreate(step_index=5, action_id=ActionIdEnum.GET_RELATED_ALERTS, name="Correlate Related Security Alerts"),
            AutomationStepCreate(step_index=6, action_id=ActionIdEnum.GET_RELATED_INCIDENTS, name="Correlate Parallel Incidents"),
            AutomationStepCreate(step_index=7, action_id=ActionIdEnum.GET_GRAPH_RELATIONSHIPS, name="Expand Knowledge Graph (2-Hop)"),
            AutomationStepCreate(step_index=8, action_id=ActionIdEnum.BUILD_TIMELINE, name="Reconstruct Multi-Source Timeline"),
            AutomationStepCreate(step_index=9, action_id=ActionIdEnum.CHECK_DATA_COVERAGE, name="Audit Telemetry Coverage & Blindspots"),
            AutomationStepCreate(step_index=10, action_id=ActionIdEnum.GENERATE_INVESTIGATION_SUMMARY, name="Compile Investigation Summary & Next Steps"),
        ],
    ),
}


def emit_automation_event(
    event_type: RealtimeEventTypeEnum,
    investigation_id: str,
    message: str,
    payload_dict: Optional[Dict[str, Any]] = None,
) -> None:
    """Helper to safely construct and broadcast RealtimeEvent with all required fields."""
    try:
        evt = RealtimeEvent(
            event_id=str(uuid.uuid4()),
            sequence=1,
            event_type=event_type.value if hasattr(event_type, "value") else str(event_type),
            resource_type=RealtimeResourceScopeEnum.INVESTIGATION.value,
            resource_id=investigation_id,
            investigation_id=investigation_id,
            message=message,
            payload=payload_dict or {},
        )
        RealtimePublisher.publish(evt)
    except Exception as e:
        logger.warning("Failure broadcasting automation event: %s", e)


class InvestigationAutomationService:
    """
    Authoritative backend service for Section 66 Advanced Investigation Automation.
    """

    @classmethod
    def resolve_context_data(cls, db: Session, identifier: str) -> Dict[str, Any]:
        """
        Resolves authoritative investigation context (incident, run, artifact, indicators).
        """
        incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, identifier)
        context: Dict[str, Any] = {
            "investigation_id": incident.id if incident else (run.id if run else identifier),
            "incident_number": incident.incident_number if incident else None,
            "title": incident.title if incident else (artifact.name if artifact else "Investigation"),
            "analysis_run_id": run.id if run else None,
            "artifact_id": artifact.id if artifact else None,
            "extracted_ips": [],
            "extracted_domains": [],
            "extracted_emails": [],
            "hostnames": [],
        }

        # Extract indicators
        from backend.db.models import IndicatorModel
        inds = db.query(IndicatorModel).limit(50).all()
        for ind in inds:
            val = str(ind.normalized_value or ind.value or "").strip()
            t = str(ind.indicator_type or "").upper()
            if t in ("IP", "IPV4", "IPV6") and val not in context["extracted_ips"]:
                context["extracted_ips"].append(val)
            elif t in ("DOMAIN", "HOSTNAME") and val not in context["extracted_domains"]:
                context["extracted_domains"].append(val)
            elif t in ("EMAIL", "RECIPIENT", "SENDER", "EMAIL_ADDRESS") and val not in context["extracted_emails"]:
                context["extracted_emails"].append(val)

        return context

    @classmethod
    def list_templates(cls) -> List[AutomationTemplateDefinition]:
        """Lists available registered investigation templates."""
        return list(INVESTIGATION_TEMPLATES.values())

    @classmethod
    def create_automation_run(
        cls,
        db: Session,
        workspace_id: str,
        investigation_id: str,
        request: InvestigationAutomationRunCreate,
        created_by: str = "SOC Analyst",
    ) -> InvestigationAutomationRunModel:
        """
        Plans and creates an automation run with bounded steps.
        Does not execute immediately if asynchronous background execution is preferred.
        """
        # Resolve investigation context
        ctx = cls.resolve_context_data(db, investigation_id)
        effective_inv_id = ctx["investigation_id"]

        budget = request.budget or AutomationBudget()
        template_name = request.template_name or "GENERAL_INCIDENT_INVESTIGATION"

        # Resolve steps from custom or template
        step_definitions: List[AutomationStepCreate] = []
        if request.custom_steps and len(request.custom_steps) > 0:
            step_definitions = request.custom_steps[:budget.max_steps]
        else:
            tmpl = INVESTIGATION_TEMPLATES.get(template_name, INVESTIGATION_TEMPLATES["GENERAL_INCIDENT_INVESTIGATION"])
            step_definitions = tmpl.steps[:budget.max_steps]

        run_id = str(uuid.uuid4())
        run = InvestigationAutomationRunModel(
            id=run_id,
            workspace_id=workspace_id,
            investigation_id=effective_inv_id,
            trigger_type=request.trigger_type.value if request.trigger_type else AutomationTriggerType.MANUAL_ANALYST.value,
            mode=request.mode.value if request.mode else AutomationMode.ASSISTED.value,
            template_name=template_name,
            plan_version="v1.0",
            status=AutomationRunStatus.QUEUED.value,
            budget_json=json.dumps(budget.model_dump()),
            visited_entities_json="[]",
            total_steps=len(step_definitions),
            completed_steps=0,
            failed_steps=0,
            coverage_summary_json="{}",
            investigation_summary_json="{}",
            created_by=created_by,
        )
        db.add(run)
        db.flush()

        for idx, s in enumerate(step_definitions):
            # Verify action exists and is not destructive
            action_entry = get_action_entry(s.action_id.value if hasattr(s.action_id, 'value') else str(s.action_id))
            step = InvestigationAutomationStepModel(
                id=str(uuid.uuid4()),
                run_id=run.id,
                step_index=idx,
                action_id=action_entry.action_id.value,
                name=s.name or action_entry.name,
                cost_class=action_entry.cost_class.value,
                approval_level=action_entry.approval_level.value,
                status=StepStatus.QUEUED.value,
                input_params_json=json.dumps(s.input_params or {}),
                result_summary_json="{}",
                result_count=0,
                warnings_json="[]",
            )
            db.add(step)

        # Audit log
        db.add(
            AuditLogModel(
                id=str(uuid.uuid4()),
                user=created_by,
                action="INVESTIGATION_AUTOMATION_CREATED",
                resource_type="INVESTIGATION_AUTOMATION_RUN",
                resource_id=run.id,
                details=json.dumps({
                    "investigation_id": effective_inv_id,
                    "template": template_name,
                    "total_steps": len(step_definitions),
                }),
            )
        )
        db.commit()
        db.refresh(run)

        # Broadcast realtime event
        emit_automation_event(
            event_type=RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_CREATED,
            investigation_id=effective_inv_id,
            message=f"Investigation automation run created ({template_name}, {run.total_steps} steps)",
            payload_dict={"run_id": run.id, "template": template_name, "total_steps": run.total_steps},
        )

        return run

    @classmethod
    def execute_automation_run(
        cls,
        db: Session,
        run_id: str,
    ) -> InvestigationAutomationRunModel:
        """
        Executes an automation run synchronously or as part of a background worker task.
        Executes steps sequentially until completed or blocked by an analyst approval gate.
        """
        run = db.query(InvestigationAutomationRunModel).filter(InvestigationAutomationRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"Investigation automation run '{run_id}' not found.")

        if run.status in (AutomationRunStatus.COMPLETED.value, AutomationRunStatus.CANCELLED.value):
            return run

        budget_dict = json.loads(run.budget_json or "{}")
        budget = AutomationBudget(**budget_dict) if budget_dict else AutomationBudget()
        visited_entities: Set[str] = set(json.loads(run.visited_entities_json or "[]"))

        ctx = cls.resolve_context_data(db, run.investigation_id)

        run.status = AutomationRunStatus.RUNNING.value
        if not run.started_at:
            run.started_at = get_utc_now()
        db.commit()

        # Emit started
        emit_automation_event(
            event_type=RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_STARTED,
            investigation_id=run.investigation_id,
            message=f"Investigation automation run {run.id} started",
            payload_dict={"run_id": run.id},
        )

        steps = (
            db.query(InvestigationAutomationStepModel)
            .filter(InvestigationAutomationStepModel.run_id == run.id)
            .order_by(InvestigationAutomationStepModel.step_index.asc())
            .all()
        )

        start_time = time.time()
        for step in steps:
            # Respect run cancellation
            db.refresh(run)
            if run.status == AutomationRunStatus.CANCELLED.value:
                break

            # Skip completed or skipped steps
            if step.status in (StepStatus.COMPLETED.value, StepStatus.SKIPPED.value):
                continue

            # Check budget limits: max execution time
            elapsed = time.time() - start_time
            if elapsed > budget.max_time_seconds:
                run.status = AutomationRunStatus.TIMED_OUT.value
                run.error_message = f"Automation run exceeded budget timeout limit of {budget.max_time_seconds} seconds."
                db.commit()
                break

            # Approval gate check
            if (
                step.approval_level in (ActionApprovalLevel.ANALYST_APPROVAL_REQUIRED.value, ActionApprovalLevel.ADMIN_APPROVAL_REQUIRED.value)
                and not step.approved_by
            ):
                step.status = StepStatus.WAITING_APPROVAL.value
                run.status = AutomationRunStatus.WAITING_FOR_ANALYST.value
                db.commit()
                # Broadcast waiting event
                emit_automation_event(
                    event_type=RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_WAITING,
                    investigation_id=run.investigation_id,
                    message=f"Step {step.step_index} ({step.action_id}) waiting for analyst approval",
                    payload_dict={"run_id": run.id, "step_index": step.step_index, "action_id": step.action_id},
                )
                return run

            # Execute step
            step.status = StepStatus.RUNNING.value
            step.started_at = get_utc_now()
            db.commit()

            # Emit step started
            emit_automation_event(
                event_type=RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_STEP_STARTED,
                investigation_id=run.investigation_id,
                message=f"Step {step.step_index}: {step.name} started",
                payload_dict={"step_index": step.step_index, "action_id": step.action_id},
            )

            step_start = time.time()
            try:
                action_entry = get_action_entry(step.action_id)
                step_params = json.loads(step.input_params_json or "{}")

                output: StepExecutionOutput = action_entry.handler(
                    db,
                    run.workspace_id,
                    ctx,
                    step_params,
                    visited_entities,
                    budget,
                )

                step.duration_ms = int((time.time() - step_start) * 1000)
                step.result_count = output.result_count
                step.result_summary_json = json.dumps(output.result_summary)
                step.warnings_json = json.dumps(output.warnings)
                step.status = StepStatus.COMPLETED.value
                step.completed_at = get_utc_now()
                run.completed_steps += 1

                # Persist discovered gaps
                for g in output.gaps:
                    gap_rec = InvestigationGapModel(
                        id=str(uuid.uuid4()),
                        workspace_id=run.workspace_id,
                        investigation_id=run.investigation_id,
                        run_id=run.id,
                        category=g.get("category", GapCategory.TELEMETRY_MISSING.value),
                        severity=g.get("severity", GapSeverity.MEDIUM.value),
                        title=g.get("title", "Investigation Telemetry Gap"),
                        description=g.get("description", "Missing telemetry identified during investigation automation."),
                        remediation_recommendation=g.get("remediation_recommendation"),
                    )
                    db.add(gap_rec)
                    emit_automation_event(
                        event_type=RealtimeEventTypeEnum.INVESTIGATION_GAP_DISCOVERED,
                        investigation_id=run.investigation_id,
                        message=f"Investigation gap discovered: {gap_rec.title}",
                        payload_dict={"title": gap_rec.title, "severity": gap_rec.severity},
                    )

                # Update context if coverage or summary was executed
                if step.action_id == ActionIdEnum.CHECK_DATA_COVERAGE.value:
                    run.coverage_summary_json = step.result_summary_json
                elif step.action_id == ActionIdEnum.GENERATE_INVESTIGATION_SUMMARY.value:
                    run.investigation_summary_json = step.result_summary_json

            except Exception as exc:
                logger.exception(f"Step execution failed for {step.action_id}: {exc}")
                step.duration_ms = int((time.time() - step_start) * 1000)
                step.status = StepStatus.FAILED.value
                step.error_message = str(exc)
                step.completed_at = get_utc_now()
                run.failed_steps += 1

            db.commit()

            # Emit step completed/failed
            emit_automation_event(
                event_type=RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_STEP_COMPLETED
                if step.status == StepStatus.COMPLETED.value
                else RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_STEP_FAILED,
                investigation_id=run.investigation_id,
                message=f"Step {step.step_index}: {step.name} {step.status}",
                payload_dict={"step_index": step.step_index, "status": step.status},
            )

        # Check overall run status
        db.refresh(run)
        if run.status not in (AutomationRunStatus.CANCELLED.value, AutomationRunStatus.TIMED_OUT.value, AutomationRunStatus.WAITING_FOR_ANALYST.value):
            if run.failed_steps > 0 and run.completed_steps > 0:
                run.status = AutomationRunStatus.PARTIALLY_COMPLETED.value
            elif run.failed_steps > 0 and run.completed_steps == 0:
                run.status = AutomationRunStatus.FAILED.value
            else:
                run.status = AutomationRunStatus.COMPLETED.value
            run.completed_at = get_utc_now()

        run.visited_entities_json = json.dumps(list(visited_entities))
        db.commit()
        db.refresh(run)

        # Broadcast final completion/partial event
        final_event = (
            RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_COMPLETED
            if run.status == AutomationRunStatus.COMPLETED.value
            else (
                RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_PARTIAL
                if run.status == AutomationRunStatus.PARTIALLY_COMPLETED.value
                else RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_STEP_FAILED
            )
        )
        emit_automation_event(
            event_type=final_event,
            investigation_id=run.investigation_id,
            message=f"Investigation automation run finished with status {run.status}",
            payload_dict={"run_id": run.id, "status": run.status, "completed_steps": run.completed_steps},
        )

        return run

    @classmethod
    def approve_step(
        cls,
        db: Session,
        run_id: str,
        step_index: int,
        analyst_id: str = "SOC Analyst",
        approve: bool = True,
        reason: Optional[str] = None,
    ) -> InvestigationAutomationRunModel:
        """
        Approves or rejects a gated investigation step.
        If approved and run was waiting, resumes execution.
        """
        step = (
            db.query(InvestigationAutomationStepModel)
            .filter(
                InvestigationAutomationStepModel.run_id == run_id,
                InvestigationAutomationStepModel.step_index == step_index,
            )
            .first()
        )
        if not step:
            raise ValueError(f"Step index {step_index} not found on run {run_id}.")

        run = db.query(InvestigationAutomationRunModel).filter(InvestigationAutomationRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found.")

        if approve:
            step.approved_by = analyst_id
            step.status = StepStatus.QUEUED.value
            db.commit()
            if run.status == AutomationRunStatus.WAITING_FOR_ANALYST.value:
                # Resume execution
                return cls.execute_automation_run(db, run_id)
        else:
            step.status = StepStatus.SKIPPED.value
            step.error_message = f"Analyst rejected approval: {reason or 'No reason provided'}"
            db.commit()
            if run.status == AutomationRunStatus.WAITING_FOR_ANALYST.value:
                return cls.execute_automation_run(db, run_id)

        return run

    @classmethod
    def cancel_automation_run(
        cls,
        db: Session,
        run_id: str,
        analyst_id: str = "SOC Analyst",
    ) -> InvestigationAutomationRunModel:
        """
        Cancels an ongoing or queued automation run.
        Preserves all collected results and evidence without deletion.
        """
        run = db.query(InvestigationAutomationRunModel).filter(InvestigationAutomationRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found.")

        if run.status in (AutomationRunStatus.COMPLETED.value, AutomationRunStatus.CANCELLED.value):
            return run

        run.status = AutomationRunStatus.CANCELLED.value
        run.completed_at = get_utc_now()
        run.error_message = f"Investigation automation cancelled by {analyst_id}."

        # Mark any remaining queued steps as CANCELLED
        queued_steps = (
            db.query(InvestigationAutomationStepModel)
            .filter(
                InvestigationAutomationStepModel.run_id == run.id,
                InvestigationAutomationStepModel.status.in_([StepStatus.QUEUED.value, StepStatus.WAITING_APPROVAL.value]),
            )
            .all()
        )
        for s in queued_steps:
            s.status = StepStatus.CANCELLED.value

        db.commit()
        db.refresh(run)

        emit_automation_event(
            event_type=RealtimeEventTypeEnum.INVESTIGATION_AUTOMATION_CANCELLED,
            investigation_id=run.investigation_id,
            message=f"Investigation automation run {run.id} cancelled",
            payload_dict={"run_id": run.id},
        )

        return run

    @classmethod
    def retry_failed_steps(
        cls,
        db: Session,
        run_id: str,
        analyst_id: str = "SOC Analyst",
    ) -> InvestigationAutomationRunModel:
        """
        Resets failed steps back to QUEUED and re-executes the automation run.
        """
        run = db.query(InvestigationAutomationRunModel).filter(InvestigationAutomationRunModel.id == run_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found.")

        failed_steps = (
            db.query(InvestigationAutomationStepModel)
            .filter(
                InvestigationAutomationStepModel.run_id == run.id,
                InvestigationAutomationStepModel.status == StepStatus.FAILED.value,
            )
            .all()
        )
        for s in failed_steps:
            s.status = StepStatus.QUEUED.value
            s.error_message = None

        run.failed_steps = 0
        run.status = AutomationRunStatus.QUEUED.value
        db.commit()

        return cls.execute_automation_run(db, run_id)

    @classmethod
    def get_run(cls, db: Session, run_id: str) -> Optional[InvestigationAutomationRunRead]:
        """Retrieves an automation run with steps, gaps, and coverage."""
        run = db.query(InvestigationAutomationRunModel).filter(InvestigationAutomationRunModel.id == run_id).first()
        if not run:
            return None
        return cls._serialize_run(run)

    @classmethod
    def list_runs(
        cls,
        db: Session,
        investigation_id: str,
        workspace_id: Optional[str] = None,
        limit: int = 20,
    ) -> List[InvestigationAutomationRunRead]:
        """Lists historical automation runs for an investigation, enforcing workspace tenant isolation."""
        ctx = cls.resolve_context_data(db, investigation_id)
        eff_id = ctx["investigation_id"]

        query = db.query(InvestigationAutomationRunModel).filter(
            or_(
                InvestigationAutomationRunModel.investigation_id == eff_id,
                InvestigationAutomationRunModel.investigation_id == investigation_id,
            )
        )
        if workspace_id:
            query = query.filter(InvestigationAutomationRunModel.workspace_id == workspace_id)

        runs = query.order_by(desc(InvestigationAutomationRunModel.created_at)).limit(limit).all()
        return [cls._serialize_run(r) for r in runs]

    @classmethod
    def get_investigation_gaps(
        cls,
        db: Session,
        investigation_id: str,
        workspace_id: Optional[str] = None,
    ) -> List[InvestigationGapRead]:
        """Retrieves all identified gaps for an investigation, respecting tenant workspace isolation."""
        ctx = cls.resolve_context_data(db, investigation_id)
        eff_id = ctx["investigation_id"]

        query = db.query(InvestigationGapModel).filter(
            or_(
                InvestigationGapModel.investigation_id == eff_id,
                InvestigationGapModel.investigation_id == investigation_id,
            )
        )
        if workspace_id:
            query = query.filter(InvestigationGapModel.workspace_id == workspace_id)

        gaps = query.order_by(desc(InvestigationGapModel.created_at)).all()
        return [
            InvestigationGapRead(
                id=g.id,
                workspace_id=g.workspace_id,
                investigation_id=g.investigation_id,
                run_id=g.run_id,
                category=g.category,
                severity=g.severity,
                title=g.title,
                description=g.description,
                remediation_recommendation=g.remediation_recommendation,
                created_at=g.created_at,
            )
            for g in gaps
        ]

    # Policy CRUD
    @classmethod
    def list_policies(
        cls,
        db: Session,
        workspace_id: str,
    ) -> List[AutomationPolicyRead]:
        policies = (
            db.query(InvestigationAutomationPolicyModel)
            .filter(InvestigationAutomationPolicyModel.workspace_id == workspace_id)
            .order_by(desc(InvestigationAutomationPolicyModel.created_at))
            .all()
        )
        return [
            AutomationPolicyRead(
                id=p.id,
                workspace_id=p.workspace_id,
                name=p.name,
                description=p.description,
                status=p.status,
                template_name=p.template_name,
                trigger_conditions=json.loads(p.trigger_conditions_json or "{}"),
                allowed_steps=json.loads(p.allowed_steps_json or "[]"),
                limits=json.loads(p.limits_json or "{}"),
                version=p.version,
                created_by=p.created_by,
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
            for p in policies
        ]

    @classmethod
    def create_policy(
        cls,
        db: Session,
        workspace_id: str,
        req: AutomationPolicyCreate,
        created_by: str = "Security Admin",
    ) -> AutomationPolicyRead:
        p = InvestigationAutomationPolicyModel(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            name=req.name,
            description=req.description,
            status="ACTIVE",
            template_name=req.template_name,
            trigger_conditions_json=json.dumps(req.trigger_conditions or {}),
            allowed_steps_json=json.dumps(req.allowed_steps or []),
            limits_json=json.dumps(req.limits or {}),
            version="1.0",
            created_by=created_by,
        )
        db.add(p)
        db.commit()
        db.refresh(p)
        return AutomationPolicyRead(
            id=p.id,
            workspace_id=p.workspace_id,
            name=p.name,
            description=p.description,
            status=p.status,
            template_name=p.template_name,
            trigger_conditions=req.trigger_conditions or {},
            allowed_steps=req.allowed_steps or [],
            limits=req.limits or {},
            version=p.version,
            created_by=p.created_by,
            created_at=p.created_at,
            updated_at=p.updated_at,
        )

    @classmethod
    def _serialize_run(cls, run: InvestigationAutomationRunModel) -> InvestigationAutomationRunRead:
        budget_dict = json.loads(run.budget_json or "{}")
        budget = AutomationBudget(**budget_dict) if budget_dict else AutomationBudget()

        steps_read = [
            AutomationStepRead(
                id=s.id,
                run_id=s.run_id,
                step_index=s.step_index,
                action_id=s.action_id,
                name=s.name,
                cost_class=s.cost_class,
                approval_level=s.approval_level,
                status=s.status,
                input_params=json.loads(s.input_params_json or "{}"),
                result_summary=json.loads(s.result_summary_json or "{}"),
                result_count=s.result_count,
                warnings=json.loads(s.warnings_json or "[]"),
                error_message=s.error_message,
                approved_by=s.approved_by,
                started_at=s.started_at,
                completed_at=s.completed_at,
                duration_ms=s.duration_ms,
            )
            for s in run.steps
        ]

        gaps_read = [
            InvestigationGapRead(
                id=g.id,
                workspace_id=g.workspace_id,
                investigation_id=g.investigation_id,
                run_id=g.run_id,
                category=g.category,
                severity=g.severity,
                title=g.title,
                description=g.description,
                remediation_recommendation=g.remediation_recommendation,
                created_at=g.created_at,
            )
            for g in run.gaps
        ]

        cov_dict = json.loads(run.coverage_summary_json or "{}")
        cov_report = None
        if cov_dict and "coverage_sources" in cov_dict:
            cov_report = InvestigationCoverageReport(
                sources=[
                    TelemetryCoverageItem(
                        source=item["source"],
                        status=TelemetryCoverageStatus(item["status"]),
                        message=item["message"],
                        last_observed_at=datetime.fromisoformat(item["last_observed_at"]) if item.get("last_observed_at") else None,
                    )
                    for item in cov_dict.get("coverage_sources", [])
                ],
                coverage_score=cov_dict.get("coverage_score", 0.0),
                gaps_count=len(gaps_read),
            )

        sum_dict = json.loads(run.investigation_summary_json or "{}")
        sum_report = None
        if sum_dict and ("knowns" in sum_dict or "assessment_summary" in sum_dict):
            sum_report = InvestigationSummaryReport(
                knowns=sum_dict.get("knowns", []),
                unknowns=sum_dict.get("unknowns", []),
                assessment_summary=sum_dict.get("assessment_summary", ""),
                confidence=sum_dict.get("confidence", 0.5),
                recommended_next_steps=[
                    RecommendedNextStep(**ns) for ns in sum_dict.get("recommended_next_steps", [])
                ],
            )

        return InvestigationAutomationRunRead(
            id=run.id,
            workspace_id=run.workspace_id,
            investigation_id=run.investigation_id,
            trigger_type=run.trigger_type,
            mode=run.mode,
            template_name=run.template_name,
            plan_version=run.plan_version,
            status=run.status,
            budget=budget,
            total_steps=run.total_steps,
            completed_steps=run.completed_steps,
            failed_steps=run.failed_steps,
            steps=steps_read,
            gaps=gaps_read,
            coverage_summary=cov_report,
            investigation_summary=sum_report,
            error_message=run.error_message,
            created_by=run.created_by,
            started_at=run.started_at,
            completed_at=run.completed_at,
            created_at=run.created_at,
            updated_at=run.updated_at,
        )
