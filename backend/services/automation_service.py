"""
Section 70: Security Operations Automation (SOAR) Service.
Authoritative workflow orchestration engine coordinating incident triage,
case management, investigations, response playbooks, and evidence reporting.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from backend.db.models import (
    AutomationWorkflowModel,
    AutomationWorkflowVersionModel,
    AutomationRunModel,
    AutomationRunStepModel,
    AutomationApprovalRequestModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.automation_workflow import (
    WorkflowCreateRequest,
    WorkflowUpdateRequest,
    WorkflowTypeEnum,
    WorkflowStatusEnum,
    WorkflowExecutionModeEnum,
    AutomationRunStatusEnum,
    StepStatusEnum,
    ActionRiskClassificationEnum,
    ActionApprovalLevelEnum,
    ApprovalStatusEnum,
    FailureCategoryEnum,
    TriggerTypeEnum,
    ConditionGroup,
    ConditionRule,
    WorkflowActionDefinition,
    WorkflowExecutionLimits,
)
from backend.services.automation_action_registry import (
    ACTION_REGISTRY,
    RegisteredAction,
    PreconditionResult,
    ExecutionResult,
    VerificationResult,
)
from backend.services.audit_service import AuditService
from backend.services.realtime_service import RealtimePublisher, RealtimeResourceScopeEnum
from backend.schemas.realtime import RealtimeEventTypeEnum

logger = logging.getLogger("cyberguard.services.automation_service")


class AutomationWorkflowService:
    """Central engine for Section 70 Security Operations Automation."""

    # =========================================================================
    # WORKFLOW DEFINITIONS & LIFECYCLE
    # =========================================================================

    @staticmethod
    def create_workflow(
        db: Session,
        req: WorkflowCreateRequest,
        tenant_id: str = "default",
        user_id: str = "analyst",
        user_name: str = "SOC Analyst",
    ) -> AutomationWorkflowModel:
        """Creates a new workflow in DRAFT status."""
        workflow = AutomationWorkflowModel(
            workspace_id="default",
            tenant_id=tenant_id,
            name=req.name,
            description=req.description,
            workflow_type=req.workflow_type.value,
            status=WorkflowStatusEnum.DRAFT.value,
            version=1,
            owner_id=req.owner_id,
            team_id=req.team_id,
            trigger_type=req.trigger_type.value,
            trigger_config_json=json.dumps(req.trigger_config or {}),
            conditions_json=json.dumps(req.conditions.model_dump() if req.conditions else {}),
            actions_json=json.dumps([a.model_dump() for a in req.actions] if req.actions else []),
            approval_policy_json=json.dumps(req.approval_policy or {}),
            execution_limits_json=json.dumps(req.execution_limits.model_dump() if req.execution_limits else {}),
            is_active=False,
            created_by=user_name,
        )
        db.add(workflow)
        db.commit()
        db.refresh(workflow)

        AuditService.log_audit(
            db=db,
            user=user_name,
            action="AUTOMATION_WORKFLOW_CREATED",
            resource_type="AUTOMATION_WORKFLOW",
            resource_id=workflow.id,
            metadata={"name": workflow.name, "type": workflow.workflow_type, "version": 1},
        )
        return workflow

    @staticmethod
    def validate_workflow(
        db: Session,
        workflow_id: str,
        tenant_id: str = "default",
    ) -> Tuple[bool, List[str]]:
        """
        Validates workflow nodes, action references, structured conditions, and DAG safety.
        Returns (is_valid, validation_errors).
        """
        workflow = db.query(AutomationWorkflowModel).filter(
            AutomationWorkflowModel.id == workflow_id,
            AutomationWorkflowModel.tenant_id == tenant_id,
        ).first()
        if not workflow:
            return False, [f"Workflow {workflow_id} not found in tenant {tenant_id}"]

        errors: List[str] = []
        try:
            actions: List[Dict[str, Any]] = json.loads(workflow.actions_json)
        except Exception:
            return False, ["Malformed actions_json"]

        if not actions:
            errors.append("Workflow must contain at least one action step.")

        step_keys = set()
        for i, act in enumerate(actions):
            action_id = act.get("action_id")
            step_key = act.get("step_key")
            if not step_key:
                errors.append(f"Step {i} is missing 'step_key'.")
            elif step_key in step_keys:
                errors.append(f"Duplicate step_key '{step_key}' detected.")
            else:
                step_keys.add(step_key)

            if not action_id or action_id not in ACTION_REGISTRY:
                errors.append(f"Step '{step_key or i}' references unknown action_id '{action_id}'.")

        # Validate conditions
        try:
            conds = json.loads(workflow.conditions_json)
            rules = conds.get("rules", [])
            for r in rules:
                if not r.get("field") or not r.get("operator"):
                    errors.append("Condition rule missing field or operator.")
        except Exception:
            errors.append("Malformed conditions_json")

        # Execution limits validation
        try:
            limits = json.loads(workflow.execution_limits_json)
            if limits.get("max_steps", 0) > 50:
                errors.append("max_steps exceeds platform limit (50).")
        except Exception:
            pass

        if not errors:
            workflow.status = WorkflowStatusEnum.VALIDATING.value
            db.commit()
            return True, []
        return False, errors

    @staticmethod
    def activate_workflow(
        db: Session,
        workflow_id: str,
        tenant_id: str = "default",
        user_id: str = "analyst",
        user_name: str = "SOC Analyst",
    ) -> AutomationWorkflowModel:
        """
        Validates workflow, creates an immutable version record, and marks the workflow ACTIVE.
        Never allows execution of DRAFT workflows.
        """
        is_valid, errors = AutomationWorkflowService.validate_workflow(db, workflow_id, tenant_id)
        if not is_valid:
            raise ValueError(f"Cannot activate invalid workflow: {'; '.join(errors)}")

        workflow = db.query(AutomationWorkflowModel).filter(
            AutomationWorkflowModel.id == workflow_id,
            AutomationWorkflowModel.tenant_id == tenant_id,
        ).first()

        # Build full definition snapshot
        definition = {
            "name": workflow.name,
            "description": workflow.description,
            "workflow_type": workflow.workflow_type,
            "trigger_type": workflow.trigger_type,
            "trigger_config": json.loads(workflow.trigger_config_json),
            "conditions": json.loads(workflow.conditions_json),
            "actions": json.loads(workflow.actions_json),
            "approval_policy": json.loads(workflow.approval_policy_json),
            "execution_limits": json.loads(workflow.execution_limits_json),
        }

        # Check existing version
        existing_version = db.query(AutomationWorkflowVersionModel).filter(
            AutomationWorkflowVersionModel.workflow_id == workflow.id,
            AutomationWorkflowVersionModel.version == workflow.version,
        ).first()

        if not existing_version:
            version_snapshot = AutomationWorkflowVersionModel(
                workspace_id="default",
                tenant_id=tenant_id,
                workflow_id=workflow.id,
                version=workflow.version,
                definition_json=json.dumps(definition),
                status="ACTIVE",
                change_summary=f"Activated version {workflow.version}",
                validated_at=get_utc_now(),
                created_by=user_name,
            )
            db.add(version_snapshot)

        workflow.status = WorkflowStatusEnum.ACTIVE.value
        workflow.is_active = True
        workflow.updated_at = get_utc_now()
        db.commit()
        db.refresh(workflow)

        AuditService.log_audit(
            db=db,
            user=user_name,
            action="AUTOMATION_WORKFLOW_ACTIVATED",
            resource_type="AUTOMATION_WORKFLOW",
            resource_id=workflow.id,
            metadata={"version": workflow.version},
        )
        return workflow

    @staticmethod
    def pause_workflow(db: Session, workflow_id: str, tenant_id: str = "default", user_name: str = "SOC Analyst") -> AutomationWorkflowModel:
        wf = db.query(AutomationWorkflowModel).filter(AutomationWorkflowModel.id == workflow_id, AutomationWorkflowModel.tenant_id == tenant_id).first()
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")
        wf.status = WorkflowStatusEnum.PAUSED.value
        wf.is_active = False
        db.commit()
        db.refresh(wf)
        return wf

    @staticmethod
    def disable_workflow(db: Session, workflow_id: str, tenant_id: str = "default", user_name: str = "SOC Analyst") -> AutomationWorkflowModel:
        wf = db.query(AutomationWorkflowModel).filter(AutomationWorkflowModel.id == workflow_id, AutomationWorkflowModel.tenant_id == tenant_id).first()
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")
        wf.status = WorkflowStatusEnum.DISABLED.value
        wf.is_active = False
        db.commit()
        db.refresh(wf)
        return wf

    @staticmethod
    def create_new_version(db: Session, workflow_id: str, tenant_id: str = "default", user_name: str = "SOC Analyst") -> AutomationWorkflowModel:
        wf = db.query(AutomationWorkflowModel).filter(AutomationWorkflowModel.id == workflow_id, AutomationWorkflowModel.tenant_id == tenant_id).first()
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")
        wf.version = wf.version + 1
        wf.status = WorkflowStatusEnum.DRAFT.value
        wf.is_active = False
        wf.updated_at = get_utc_now()
        db.commit()
        db.refresh(wf)
        return wf

    @staticmethod
    def update_workflow(
        db: Session,
        workflow_id: str,
        req: WorkflowUpdateRequest,
        tenant_id: str = "default",
        user_name: str = "SOC Analyst",
    ) -> AutomationWorkflowModel:
        wf = db.query(AutomationWorkflowModel).filter(AutomationWorkflowModel.id == workflow_id, AutomationWorkflowModel.tenant_id == tenant_id).first()
        if not wf:
            raise ValueError(f"Workflow {workflow_id} not found")
        if wf.status == WorkflowStatusEnum.ACTIVE.value:
            raise ValueError("Active workflow cannot be modified in-place. Create a new version first.")

        if req.name is not None:
            wf.name = req.name
        if req.description is not None:
            wf.description = req.description
        if req.workflow_type is not None:
            wf.workflow_type = req.workflow_type.value
        if req.trigger_type is not None:
            wf.trigger_type = req.trigger_type.value
        if req.trigger_config is not None:
            wf.trigger_config_json = json.dumps(req.trigger_config)
        if req.conditions is not None:
            wf.conditions_json = json.dumps(req.conditions.model_dump())
        if req.actions is not None:
            wf.actions_json = json.dumps([a.model_dump() for a in req.actions])
        if req.approval_policy is not None:
            wf.approval_policy_json = json.dumps(req.approval_policy)
        if req.execution_limits is not None:
            wf.execution_limits_json = json.dumps(req.execution_limits.model_dump())
        if req.owner_id is not None:
            wf.owner_id = req.owner_id
        if req.team_id is not None:
            wf.team_id = req.team_id

        wf.updated_at = get_utc_now()
        db.commit()
        db.refresh(wf)
        return wf

    @staticmethod
    def list_workflows(
        db: Session,
        tenant_id: str = "default",
        status: Optional[str] = None,
        workflow_type: Optional[str] = None,
        trigger_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[AutomationWorkflowModel], int]:
        q = db.query(AutomationWorkflowModel).filter(AutomationWorkflowModel.tenant_id == tenant_id)
        if status and status != "ALL":
            q = q.filter(AutomationWorkflowModel.status == status)
        if workflow_type and workflow_type != "ALL":
            q = q.filter(AutomationWorkflowModel.workflow_type == workflow_type)
        if trigger_type and trigger_type != "ALL":
            q = q.filter(AutomationWorkflowModel.trigger_type == trigger_type)
        total = q.count()
        items = q.order_by(desc(AutomationWorkflowModel.updated_at)).offset(skip).limit(limit).all()
        return items, total

    @staticmethod
    def get_workflow(db: Session, workflow_id: str, tenant_id: str = "default") -> Optional[AutomationWorkflowModel]:
        return db.query(AutomationWorkflowModel).filter(
            AutomationWorkflowModel.id == workflow_id,
            AutomationWorkflowModel.tenant_id == tenant_id,
        ).first()

    # =========================================================================
    # STRUCTURED CONDITION EVALUATOR (TYPE-SAFE, NO ARBITRARY CODE)
    # =========================================================================

    @staticmethod
    def evaluate_condition_group(conditions_data: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """
        Evaluates a structured condition group against a flat or nested trigger context dictionary.
        Strictly prohibits Python eval/exec, shell, or SQL expressions.
        """
        if not conditions_data or not conditions_data.get("rules"):
            return True

        logic = (conditions_data.get("logic") or "AND").upper()
        rules = conditions_data.get("rules", [])

        results = []
        for rule in rules:
            field_name = rule.get("field", "")
            operator = (rule.get("operator") or "eq").lower()
            expected_val = rule.get("value")

            # Extract actual value from context (supporting dot notation)
            actual_val = context
            for part in field_name.split("."):
                if isinstance(actual_val, dict):
                    actual_val = actual_val.get(part)
                else:
                    actual_val = None
                    break

            res = AutomationWorkflowService._evaluate_rule_op(actual_val, operator, expected_val)
            results.append(res)

        if logic == "OR":
            return any(results)
        return all(results)

    @staticmethod
    def _evaluate_rule_op(actual: Any, op: str, expected: Any) -> bool:
        if actual is None and expected is not None:
            return op in ["neq", "!="]

        try:
            if op in ["eq", "=="]:
                return str(actual).lower() == str(expected).lower()
            elif op in ["neq", "!="]:
                return str(actual).lower() != str(expected).lower()
            elif op in ["gt", ">"]:
                return float(actual) > float(expected)
            elif op in ["gte", ">="]:
                return float(actual) >= float(expected)
            elif op in ["lt", "<"]:
                return float(actual) < float(expected)
            elif op in ["lte", "<="]:
                return float(actual) <= float(expected)
            elif op in ["in"]:
                if isinstance(expected, list):
                    return str(actual).lower() in [str(x).lower() for x in expected]
                return str(actual).lower() in str(expected).lower()
            elif op in ["contains"]:
                return str(expected).lower() in str(actual).lower()
            else:
                return False
        except Exception:
            return False

    # =========================================================================
    # EVENT TRIGGER EVALUATION, DEDUPLICATION & LOOP PREVENTION
    # =========================================================================

    @staticmethod
    def evaluate_trigger(
        db: Session,
        trigger_type: str,
        resource_type: Optional[str],
        resource_id: Optional[str],
        payload: Dict[str, Any],
        tenant_id: str = "default",
    ) -> List[AutomationRunModel]:
        """
        Discovers matching active workflows, applies deduplication and loop guards,
        evaluates preconditions, and queues/executes authoritative automation runs.
        """
        workflows = db.query(AutomationWorkflowModel).filter(
            AutomationWorkflowModel.tenant_id == tenant_id,
            AutomationWorkflowModel.status == WorkflowStatusEnum.ACTIVE.value,
            AutomationWorkflowModel.trigger_type == trigger_type,
        ).all()

        runs_started: List[AutomationRunModel] = []
        for wf in workflows:
            # 1. Evaluate condition group
            conds = json.loads(wf.conditions_json or "{}")
            eval_ctx = {**payload, "trigger_type": trigger_type, "resource_type": resource_type, "resource_id": resource_id}
            if not AutomationWorkflowService.evaluate_condition_group(conds, eval_ctx):
                logger.debug(f"Workflow {wf.id} conditions not met for trigger {trigger_type}.")
                continue

            # 2. Loop & recursion guard
            recursion_depth = int(payload.get("_soar_recursion_depth", 0))
            limits = json.loads(wf.execution_limits_json or "{}")
            max_depth = limits.get("max_recursion_depth", 3)
            if recursion_depth >= max_depth:
                logger.warning(f"Recursion guard triggered: depth {recursion_depth} exceeds max {max_depth} for wf {wf.id}")
                continue

            # 3. Idempotency & deduplication key
            dedup_window = limits.get("deduplication_window_seconds", 300)
            idempotency_raw = f"{tenant_id}:{wf.id}:v{wf.version}:{trigger_type}:{resource_id or 'none'}"
            idempotency_key = hashlib.sha256(idempotency_raw.encode()).hexdigest()

            # Check existing recent run with this key
            cutoff = get_utc_now() - timedelta(seconds=dedup_window)
            existing_run = db.query(AutomationRunModel).filter(
                AutomationRunModel.idempotency_key == idempotency_key,
                or_(
                    AutomationRunModel.created_at >= cutoff,
                    AutomationRunModel.status.in_([AutomationRunStatusEnum.RUNNING.value, AutomationRunStatusEnum.WAITING_FOR_APPROVAL.value]),
                ),
            ).first()

            if existing_run:
                logger.info(f"Deduplication: skipped duplicate run for key {idempotency_key}")
                continue

            # 4. Create and execute run
            run = AutomationWorkflowService.create_and_execute_run(
                db=db,
                workflow=wf,
                trigger_type=trigger_type,
                resource_type=resource_type,
                resource_id=resource_id,
                payload=payload,
                execution_mode=WorkflowExecutionModeEnum.PRODUCTION.value,
                idempotency_key=idempotency_key,
                recursion_depth=recursion_depth + 1,
                tenant_id=tenant_id,
            )
            runs_started.append(run)

        return runs_started

    # =========================================================================
    # RUN EXECUTION ENGINE
    # =========================================================================

    @staticmethod
    def create_and_execute_run(
        db: Session,
        workflow: AutomationWorkflowModel,
        trigger_type: str,
        resource_type: Optional[str],
        resource_id: Optional[str],
        payload: Dict[str, Any],
        execution_mode: str = "PRODUCTION",
        idempotency_key: Optional[str] = None,
        recursion_depth: int = 0,
        tenant_id: str = "default",
        user_name: str = "SOAR Engine",
    ) -> AutomationRunModel:
        """
        Creates run record, initializes discrete steps, and starts sequential step execution.
        """
        actions: List[Dict[str, Any]] = json.loads(workflow.actions_json or "[]")
        run = AutomationRunModel(
            workspace_id="default",
            tenant_id=tenant_id,
            workflow_id=workflow.id,
            workflow_version=workflow.version,
            status=AutomationRunStatusEnum.QUEUED.value,
            trigger_type=trigger_type,
            trigger_resource_type=resource_type,
            trigger_resource_id=resource_id,
            trigger_payload_json=json.dumps(payload),
            execution_mode=execution_mode,
            idempotency_key=idempotency_key,
            recursion_depth=recursion_depth,
            total_steps=len(actions),
            completed_steps=0,
            failed_steps=0,
            skipped_steps=0,
            budget_consumed_json=json.dumps({"steps": 0, "duration_ms": 0}),
            output_summary_json=json.dumps({}),
            explainability_trace_json=json.dumps({
                "trigger_type": trigger_type,
                "workflow_name": workflow.name,
                "workflow_version": workflow.version,
                "started_by": user_name,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }),
            created_by=user_name,
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        # Initialize discrete steps
        for idx, act in enumerate(actions):
            action_id = act.get("action_id", "UNKNOWN")
            reg_action = ACTION_REGISTRY.get(action_id)
            risk = reg_action.risk_classification.value if reg_action else act.get("risk_classification", "LOW_IMPACT")
            approval = reg_action.default_approval_level.value if reg_action else act.get("approval_level", "AUTOMATIC")
            req_approval = (approval != "AUTOMATIC")

            step = AutomationRunStepModel(
                workspace_id="default",
                tenant_id=tenant_id,
                run_id=run.id,
                step_index=idx,
                step_key=act.get("step_key", f"step_{idx}"),
                action_id=action_id,
                name=act.get("name", reg_action.name if reg_action else action_id),
                status=StepStatusEnum.PENDING.value,
                risk_classification=risk,
                approval_level=approval,
                requires_approval=req_approval,
                input_params_json=json.dumps(act.get("parameters", {})),
                output_data_json="{}",
                verification_result_json="{}",
                verified_state=False,
                max_retries=act.get("max_retries", 0),
            )
            db.add(step)
        db.commit()

        # Publish realtime event
        RealtimePublisher.publish_event(
            db=db,
            topic=f"automation:{run.id}",
            event_type=RealtimeEventTypeEnum.AUTOMATION_STARTED.value,
            resource_type=RealtimeResourceScopeEnum.AUTOMATION.value,
            resource_id=run.id,
            message=f"Automation run started for {workflow.name}",
            workspace_id="default",
            payload={"run_id": run.id, "workflow_name": workflow.name, "total_steps": run.total_steps},
        )

        # Execute run steps
        return AutomationWorkflowService.execute_run_steps(db=db, run_id=run.id, tenant_id=tenant_id)

    @staticmethod
    def execute_run_steps(db: Session, run_id: str, tenant_id: str = "default") -> AutomationRunModel:
        """
        Executes pending steps sequentially, handling precondition checks, approvals,
        execution, verification, failure classifications, and final state outcomes.
        """
        run = db.query(AutomationRunModel).filter(AutomationRunModel.id == run_id, AutomationRunModel.tenant_id == tenant_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found")

        if run.status in [AutomationRunStatusEnum.COMPLETED.value, AutomationRunStatusEnum.CANCELLED.value, AutomationRunStatusEnum.TIMED_OUT.value]:
            return run

        run.status = AutomationRunStatusEnum.RUNNING.value
        if not run.started_at:
            run.started_at = get_utc_now()
        db.commit()

        steps = db.query(AutomationRunStepModel).filter(
            AutomationRunStepModel.run_id == run.id,
        ).order_by(AutomationRunStepModel.step_index.asc()).all()

        trigger_ctx = json.loads(run.trigger_payload_json or "{}")
        trace = json.loads(run.explainability_trace_json or "{}")
        step_traces = trace.get("steps", [])

        is_dry_run = (run.execution_mode == WorkflowExecutionModeEnum.DRY_RUN.value)

        for step in steps:
            # If step is already completed or skipped, skip it
            if step.status in [StepStatusEnum.COMPLETED.value, StepStatusEnum.SKIPPED.value]:
                continue

            # If step was waiting for approval and hasn't been approved yet
            if step.status == StepStatusEnum.WAITING_FOR_APPROVAL.value:
                # Still waiting
                run.status = AutomationRunStatusEnum.WAITING_FOR_APPROVAL.value
                db.commit()
                return run

            # If step was rejected by human analyst
            if step.status == StepStatusEnum.REJECTED.value:
                run.status = AutomationRunStatusEnum.PARTIALLY_COMPLETED.value
                run.completed_at = get_utc_now()
                db.commit()
                return run

            # Look up registered action
            reg_action = ACTION_REGISTRY.get(step.action_id)
            if not reg_action:
                step.status = StepStatusEnum.FAILED.value
                step.error_message = f"Action {step.action_id} not registered"
                step.failure_category = FailureCategoryEnum.VALIDATION_FAILURE.value
                run.failed_steps += 1
                run.status = AutomationRunStatusEnum.FAILED.value
                db.commit()
                return run

            step_params = json.loads(step.input_params_json or "{}")

            # 1. Precondition Check & TOCTOU Defense
            pre_res = reg_action.precondition_fn(db, tenant_id, trigger_ctx, step_params)
            if not pre_res.passed:
                step.status = StepStatusEnum.FAILED.value
                step.error_message = pre_res.error_message or "Precondition check failed"
                step.failure_category = (pre_res.failure_category or FailureCategoryEnum.RESOURCE_STATE_CONFLICT).value
                run.failed_steps += 1
                run.status = AutomationRunStatusEnum.PARTIALLY_COMPLETED.value
                db.commit()
                return run

            # 2. Approval Gate for Consequential / High-Impact Actions
            if step.requires_approval and step.status != StepStatusEnum.APPROVED.value:
                step.status = StepStatusEnum.WAITING_FOR_APPROVAL.value
                step.approval_requested_at = get_utc_now()
                # Create Approval Request record
                expires_at = get_utc_now() + timedelta(hours=24)
                approval_req = AutomationApprovalRequestModel(
                    workspace_id="default",
                    tenant_id=tenant_id,
                    run_id=run.id,
                    step_id=step.id,
                    action_id=step.action_id,
                    status=ApprovalStatusEnum.PENDING.value,
                    required_role=reg_action.required_role,
                    requested_by="SOAR Engine",
                    expires_at=expires_at,
                    action_payload_json=step.input_params_json,
                    context_summary_json=json.dumps({"run_id": run.id, "trigger_type": run.trigger_type, "action_name": reg_action.name}),
                )
                db.add(approval_req)
                db.commit()
                db.refresh(approval_req)

                step.approval_id = approval_req.id
                run.status = AutomationRunStatusEnum.WAITING_FOR_APPROVAL.value
                db.commit()

                # Realtime broadcast & notification
                RealtimePublisher.publish_event(
                    db=db,
                    topic=f"automation:{run.id}",
                    event_type=RealtimeEventTypeEnum.AUTOMATION_WAITING_FOR_APPROVAL.value,
                    resource_type=RealtimeResourceScopeEnum.AUTOMATION.value,
                    resource_id=run.id,
                    message=f"Automation run waiting for approval: {reg_action.name}",
                    workspace_id="default",
                    payload={"approval_id": approval_req.id, "action_id": step.action_id, "required_role": reg_action.required_role},
                )
                return run

            # 3. Execution (Simulated or Production)
            step.status = StepStatusEnum.RUNNING.value
            step.started_at = get_utc_now()
            db.commit()

            start_t = time.perf_counter()
            if is_dry_run:
                exec_res = ExecutionResult(
                    success=True,
                    output_data={"simulated": True, "action_id": step.action_id, "note": "DRY_RUN: No action executed."},
                )
            else:
                exec_res = reg_action.execute_fn(db, tenant_id, trigger_ctx, step_params)

            elapsed_ms = int((time.perf_counter() - start_t) * 1000)
            step.execution_duration_ms = elapsed_ms
            step.completed_at = get_utc_now()

            if not exec_res.success:
                step.status = StepStatusEnum.FAILED.value
                step.error_message = exec_res.error_message
                step.failure_category = (exec_res.failure_category or FailureCategoryEnum.INTERNAL_ERROR).value
                run.failed_steps += 1
                step_traces.append({"step": step.step_key, "action": step.action_id, "status": "FAILED", "error": exec_res.error_message})
                trace["steps"] = step_traces
                run.explainability_trace_json = json.dumps(trace)
                run.status = AutomationRunStatusEnum.PARTIALLY_COMPLETED.value
                run.completed_at = get_utc_now()
                db.commit()
                return run

            # 4. Truthful Verification
            step.output_data_json = json.dumps(exec_res.output_data)
            if is_dry_run:
                ver_res = VerificationResult(verified=True, details={"simulated": True})
            else:
                ver_res = reg_action.verify_fn(db, tenant_id, step_params, exec_res)

            step.verification_result_json = json.dumps(ver_res.details)
            step.verified_state = ver_res.verified

            if not ver_res.verified:
                step.status = StepStatusEnum.FAILED.value
                step.error_message = f"Post-action verification failed: {ver_res.error_message}"
                step.failure_category = FailureCategoryEnum.RESOURCE_STATE_CONFLICT.value
                run.failed_steps += 1
                run.status = AutomationRunStatusEnum.PARTIALLY_COMPLETED.value
                db.commit()
                return run

            step.status = StepStatusEnum.COMPLETED.value
            run.completed_steps += 1
            step_traces.append({"step": step.step_key, "action": step.action_id, "status": "COMPLETED", "duration_ms": elapsed_ms})
            trace["steps"] = step_traces
            run.explainability_trace_json = json.dumps(trace)
            db.commit()

            # Merge step output into trigger context for downstream steps
            trigger_ctx.update(exec_res.output_data)

        # All steps successfully completed
        run.status = AutomationRunStatusEnum.COMPLETED.value
        run.completed_at = get_utc_now()
        db.commit()
        db.refresh(run)

        # Realtime event
        RealtimePublisher.publish_event(
            db=db,
            topic=f"automation:{run.id}",
            event_type=RealtimeEventTypeEnum.AUTOMATION_COMPLETED.value,
            resource_type=RealtimeResourceScopeEnum.AUTOMATION.value,
            resource_id=run.id,
            message="Automation run completed successfully",
            workspace_id="default",
            payload={"run_id": run.id, "status": run.status, "completed_steps": run.completed_steps},
        )
        return run

    # =========================================================================
    # APPROVAL PROCESSING
    # =========================================================================

    @staticmethod
    def decide_approval(
        db: Session,
        approval_id: str,
        decision: str,  # APPROVED or REJECTED
        user_id: str,
        user_name: str,
        user_role: str,
        reason: Optional[str] = None,
        tenant_id: str = "default",
    ) -> AutomationApprovalRequestModel:
        """
        Processes human-in-the-loop approval decision.
        Enforces role permissions, expiration gates, and resumes run execution upon approval.
        """
        approval = db.query(AutomationApprovalRequestModel).filter(
            AutomationApprovalRequestModel.id == approval_id,
            AutomationApprovalRequestModel.tenant_id == tenant_id,
        ).first()
        if not approval:
            raise ValueError(f"Approval request {approval_id} not found")

        if approval.status != ApprovalStatusEnum.PENDING.value:
            raise ValueError(f"Approval request already resolved as {approval.status}")

        # Check expiration
        now_utc = get_utc_now()
        exp_dt = approval.expires_at
        if exp_dt and exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if exp_dt and exp_dt < now_utc:
            approval.status = ApprovalStatusEnum.EXPIRED.value
            db.commit()
            raise ValueError("Approval request has EXPIRED. Cannot execute stale approval.")

        # Check role permission
        if approval.required_role in ["senior_analyst", "admin"]:
            if user_role not in ["senior_analyst", "admin", "lead"]:
                raise PermissionError(f"Action requires '{approval.required_role}' authorization.")

        decision_upper = decision.upper()
        if decision_upper not in ["APPROVED", "REJECTED"]:
            raise ValueError("Decision must be APPROVED or REJECTED")

        approval.status = decision_upper
        approval.decision = decision_upper
        approval.decided_by = user_name
        approval.decided_at = now_utc
        approval.reason = reason

        step = db.query(AutomationRunStepModel).filter(AutomationRunStepModel.id == approval.step_id).first()
        if step:
            step.approval_decision = decision_upper
            step.approved_by = user_name
            step.approved_at = now_utc
            step.approval_reason = reason
            if decision_upper == "APPROVED":
                step.status = StepStatusEnum.APPROVED.value
            else:
                step.status = StepStatusEnum.REJECTED.value

        db.commit()

        AuditService.log_audit(
            db=db,
            user=user_name,
            action=f"AUTOMATION_APPROVAL_{decision_upper}",
            resource_type="AUTOMATION_APPROVAL",
            resource_id=approval.id,
            metadata={"decision": decision_upper, "reason": reason, "step_id": approval.step_id},
        )

        # If approved, resume run execution
        if decision_upper == "APPROVED":
            AutomationWorkflowService.execute_run_steps(db=db, run_id=approval.run_id, tenant_id=tenant_id)
        else:
            run = db.query(AutomationRunModel).filter(AutomationRunModel.id == approval.run_id).first()
            if run:
                run.status = AutomationRunStatusEnum.PARTIALLY_COMPLETED.value
                run.completed_at = get_utc_now()
                db.commit()

        db.refresh(approval)
        return approval

    # =========================================================================
    # MANUAL OVERRIDES (CANCEL, PAUSE, RESUME)
    # =========================================================================

    @staticmethod
    def cancel_run(db: Session, run_id: str, user_name: str = "SOC Analyst", tenant_id: str = "default") -> AutomationRunModel:
        run = db.query(AutomationRunModel).filter(AutomationRunModel.id == run_id, AutomationRunModel.tenant_id == tenant_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found")
        if run.status in [AutomationRunStatusEnum.COMPLETED.value, AutomationRunStatusEnum.CANCELLED.value]:
            return run

        run.status = AutomationRunStatusEnum.CANCELLED.value
        run.completed_at = get_utc_now()

        # Mark remaining pending steps as SKIPPED
        steps = db.query(AutomationRunStepModel).filter(
            AutomationRunStepModel.run_id == run.id,
            AutomationRunStepModel.status.in_([StepStatusEnum.PENDING.value, StepStatusEnum.WAITING_FOR_APPROVAL.value]),
        ).all()
        for st in steps:
            st.status = StepStatusEnum.SKIPPED.value
            run.skipped_steps += 1

        db.commit()
        db.refresh(run)

        AuditService.log_audit(
            db=db,
            user=user_name,
            action="AUTOMATION_RUN_CANCELLED",
            resource_type="AUTOMATION_RUN",
            resource_id=run.id,
            metadata={"skipped_steps": run.skipped_steps},
        )
        return run

    @staticmethod
    def pause_run(db: Session, run_id: str, user_name: str = "SOC Analyst", tenant_id: str = "default") -> AutomationRunModel:
        run = db.query(AutomationRunModel).filter(AutomationRunModel.id == run_id, AutomationRunModel.tenant_id == tenant_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found")
        run.status = AutomationRunStatusEnum.PAUSED.value
        run.paused_at = get_utc_now()
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def resume_run(db: Session, run_id: str, user_name: str = "SOC Analyst", tenant_id: str = "default") -> AutomationRunModel:
        run = db.query(AutomationRunModel).filter(AutomationRunModel.id == run_id, AutomationRunModel.tenant_id == tenant_id).first()
        if not run:
            raise ValueError(f"Run {run_id} not found")
        if run.status != AutomationRunStatusEnum.PAUSED.value:
            return run
        run.status = AutomationRunStatusEnum.RUNNING.value
        db.commit()
        return AutomationWorkflowService.execute_run_steps(db=db, run_id=run.id, tenant_id=tenant_id)

    # =========================================================================
    # RUN QUERIES & METRICS (REAL DATA ONLY, ZERO FABRICATION)
    # =========================================================================

    @staticmethod
    def list_runs(
        db: Session,
        tenant_id: str = "default",
        workflow_id: Optional[str] = None,
        status: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[AutomationRunModel], int]:
        q = db.query(AutomationRunModel).filter(AutomationRunModel.tenant_id == tenant_id)
        if workflow_id:
            q = q.filter(AutomationRunModel.workflow_id == workflow_id)
        if status and status != "ALL":
            q = q.filter(AutomationRunModel.status == status)
        total = q.count()
        items = q.order_by(desc(AutomationRunModel.created_at)).offset(skip).limit(limit).all()
        return items, total

    @staticmethod
    def get_run(db: Session, run_id: str, tenant_id: str = "default") -> Optional[AutomationRunModel]:
        return db.query(AutomationRunModel).filter(
            AutomationRunModel.id == run_id,
            AutomationRunModel.tenant_id == tenant_id,
        ).first()

    @staticmethod
    def list_pending_approvals(db: Session, tenant_id: str = "default") -> List[AutomationApprovalRequestModel]:
        now_utc = get_utc_now()
        return db.query(AutomationApprovalRequestModel).filter(
            AutomationApprovalRequestModel.tenant_id == tenant_id,
            AutomationApprovalRequestModel.status == ApprovalStatusEnum.PENDING.value,
            AutomationApprovalRequestModel.expires_at >= now_utc,
        ).order_by(AutomationApprovalRequestModel.created_at.desc()).all()

    @staticmethod
    def get_metrics(db: Session, tenant_id: str = "default") -> Dict[str, Any]:
        """Calculates authoritative SOAR operational metrics from actual database records."""
        total_wf = db.query(AutomationWorkflowModel).filter(AutomationWorkflowModel.tenant_id == tenant_id).count()
        active_wf = db.query(AutomationWorkflowModel).filter(
            AutomationWorkflowModel.tenant_id == tenant_id,
            AutomationWorkflowModel.status == WorkflowStatusEnum.ACTIVE.value,
        ).count()
        draft_wf = db.query(AutomationWorkflowModel).filter(
            AutomationWorkflowModel.tenant_id == tenant_id,
            AutomationWorkflowModel.status == WorkflowStatusEnum.DRAFT.value,
        ).count()

        runs = db.query(AutomationRunModel).filter(AutomationRunModel.tenant_id == tenant_id).all()
        total_runs = len(runs)
        completed_runs = sum(1 for r in runs if r.status == AutomationRunStatusEnum.COMPLETED.value)
        partial_runs = sum(1 for r in runs if r.status == AutomationRunStatusEnum.PARTIALLY_COMPLETED.value)
        failed_runs = sum(1 for r in runs if r.status == AutomationRunStatusEnum.FAILED.value)

        success_rate = (completed_runs / total_runs * 100.0) if total_runs > 0 else 100.0

        # Duration
        durations = []
        for r in runs:
            if r.started_at and r.completed_at:
                durations.append((r.completed_at - r.started_at).total_seconds() * 1000.0)
        avg_dur = (sum(durations) / len(durations)) if durations else 0.0

        pending_approvals = db.query(AutomationApprovalRequestModel).filter(
            AutomationApprovalRequestModel.tenant_id == tenant_id,
            AutomationApprovalRequestModel.status == ApprovalStatusEnum.PENDING.value,
        ).count()

        # Failure breakdown
        failure_breakdown: Dict[str, int] = {}
        for r in runs:
            if r.failure_category:
                failure_breakdown[r.failure_category] = failure_breakdown.get(r.failure_category, 0) + 1

        return {
            "total_workflows": total_wf,
            "active_workflows": active_wf,
            "draft_workflows": draft_wf,
            "total_runs": total_runs,
            "completed_runs": completed_runs,
            "partially_completed_runs": partial_runs,
            "failed_runs": failed_runs,
            "pending_approvals": pending_approvals,
            "success_rate": round(success_rate, 2),
            "average_duration_ms": round(avg_dur, 2),
            "failure_breakdown": failure_breakdown,
        }
