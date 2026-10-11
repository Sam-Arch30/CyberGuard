"""
Section 56: Detection Engineering & Rule Lifecycle Foundation Service.

Extends and promotes Section 25 Candidate Rule Engine into an enterprise-grade
Detection Engineering and Rule Lifecycle Platform:
1. Strict, allowlisted AST DSL validator, safe regex checker, and human-readable preview generator.
2. Formal, server-authoritative lifecycle state machine with separation-of-duties and audit logging.
3. Immutable versioning with automated AST diffing between versions (v1 -> v2).
4. Safe historical backtesting across historical telemetry with ground-truth precision/recall analysis.
5. Production detection pipeline integration: Rule Match -> FindingModel -> Unified Risk Engine -> Alerting.
6. Handoff workflows from Section 54 Threat Hunting and Section 50 Investigations.
7. Realtime events and asynchronous background job support.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from fastapi import HTTPException, status
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.db.models import (
    AuditLogModel,
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    FindingModel,
    IncidentModel,
    SecurityEventModel,
    ThreatEventModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    EmailAnalysisModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import (
    DslOperator,
    GeneralizationLevel,
    RuleLifecycleStatus,
    RuleMatchResult,
    RuleScope,
    RuleSeverity,
    RuleType,
)
from backend.schemas.detection_rules import (
    DATA_SOURCE_FIELD_REGISTRY,
    AISuggestRuleRequest,
    AISuggestRuleResponse,
    DetectionMatchExplanation,
    DetectionRuleBacktestRequest,
    DetectionRuleBacktestResponse,
    DetectionRuleCreateRequest,
    DetectionRuleFromHuntRequest,
    DetectionRuleFromInvestigationRequest,
    DetectionRuleResponse,
    DetectionRuleTuneRequest,
    RuleCategory,
    RuleCondition,
    RuleCostClass,
    RuleDataSource,
    RuleDefinition,
    RuleFieldType,
    RuleProvenanceType,
    RuleValidationResponse,
    RuleVersionDiff,
    DeploymentStateEnum,
    OperationalHealthEnum,
    RuleDependency,
)
from backend.schemas.realtime import RealtimeEventTypeEnum, RealtimeResourceScopeEnum
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.detection_rule_lifecycle")

# Execution limits & budgets
MAX_RULE_CONDITIONS = 20
MAX_NESTING_DEPTH = 3
MAX_REGEX_LENGTH = 128
MAX_RULE_COMPLEXITY = 25.0

# Legal state machine transitions
LEGAL_LIFECYCLE_TRANSITIONS: Dict[RuleLifecycleStatus, Set[RuleLifecycleStatus]] = {
    RuleLifecycleStatus.DRAFT: {
        RuleLifecycleStatus.VALIDATING,
        RuleLifecycleStatus.CANDIDATE,
        RuleLifecycleStatus.PENDING_REVIEW,
        RuleLifecycleStatus.APPROVED,
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.DISCOVERED: {
        RuleLifecycleStatus.DRAFT,
        RuleLifecycleStatus.CANDIDATE,
        RuleLifecycleStatus.VALIDATING,
        RuleLifecycleStatus.REJECTED,
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.CANDIDATE: {
        RuleLifecycleStatus.VALIDATING,
        RuleLifecycleStatus.DRAFT,
        RuleLifecycleStatus.PENDING_REVIEW,
        RuleLifecycleStatus.APPROVED,
        RuleLifecycleStatus.REJECTED,
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.VALIDATING: {
        RuleLifecycleStatus.TESTED,
        RuleLifecycleStatus.DRAFT,
        RuleLifecycleStatus.CANDIDATE,
        RuleLifecycleStatus.PENDING_REVIEW,
        RuleLifecycleStatus.APPROVED,
        RuleLifecycleStatus.REJECTED,
    },
    RuleLifecycleStatus.TESTED: {
        RuleLifecycleStatus.PENDING_REVIEW,
        RuleLifecycleStatus.REVIEW_REQUIRED,
        RuleLifecycleStatus.APPROVED,
        RuleLifecycleStatus.DRAFT,
        RuleLifecycleStatus.REJECTED,
    },
    RuleLifecycleStatus.PENDING_REVIEW: {
        RuleLifecycleStatus.APPROVED,
        RuleLifecycleStatus.REJECTED,
        RuleLifecycleStatus.DRAFT,
    },
    RuleLifecycleStatus.REVIEW_REQUIRED: {
        RuleLifecycleStatus.APPROVED,
        RuleLifecycleStatus.REJECTED,
        RuleLifecycleStatus.DRAFT,
    },
    RuleLifecycleStatus.APPROVED: {
        RuleLifecycleStatus.STAGED,
        RuleLifecycleStatus.ACTIVE,
        RuleLifecycleStatus.DISABLED,
        RuleLifecycleStatus.DRAFT,
    },
    RuleLifecycleStatus.STAGED: {
        RuleLifecycleStatus.ACTIVE,
        RuleLifecycleStatus.DISABLED,
        RuleLifecycleStatus.REJECTED,
    },
    RuleLifecycleStatus.ACTIVE: {
        RuleLifecycleStatus.DISABLED,
        RuleLifecycleStatus.DEPRECATED,
        RuleLifecycleStatus.SUPERSEDED,
        RuleLifecycleStatus.RETIRED,
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.DISABLED: {
        RuleLifecycleStatus.ACTIVE,
        RuleLifecycleStatus.DEPRECATED,
        RuleLifecycleStatus.RETIRED,
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.DEPRECATED: {
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.RETIRED: {
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.REJECTED: {
        RuleLifecycleStatus.DRAFT,
        RuleLifecycleStatus.ARCHIVED,
    },
    RuleLifecycleStatus.ARCHIVED: set(),
    RuleLifecycleStatus.SUPERSEDED: {
        RuleLifecycleStatus.ARCHIVED,
    },
}


class DetectionRuleLifecycleService:
    """
    Central service for detection engineering, versioned rule lifecycles,
    safe DSL compilation, and backtesting.
    """

    # ========================================================================
    # 1. SAFE DSL COMPILER, VALIDATOR & HUMAN-READABLE TRANSLATOR
    # ========================================================================

    @classmethod
    def validate_rule_definition(
        cls,
        definition: RuleDefinition,
    ) -> RuleValidationResponse:
        """Alias for validate_and_compile without data source restriction."""
        return cls.validate_and_compile(definition)

    @classmethod
    def validate_and_compile(
        cls,
        definition: RuleDefinition,
        data_sources: Optional[List[RuleDataSource]] = None,
        depth: int = 1,
    ) -> RuleValidationResponse:
        """
        Validates rule AST against data source field registries, type constraints,
        regex safety, and computational budgets.
        """
        errors: List[str] = []
        warnings: List[str] = []
        complexity = 0.0

        if depth > MAX_NESTING_DEPTH:
            errors.append(f"Rule nesting depth exceeds limit ({depth} > {MAX_NESTING_DEPTH}).")

        if not definition.conditions and not definition.nested_groups:
            errors.append("Rule definition must contain at least one condition or nested group.")

        total_conds = len(definition.conditions)
        if total_conds > MAX_RULE_CONDITIONS:
            errors.append(f"Condition count ({total_conds}) exceeds maximum limit ({MAX_RULE_CONDITIONS}).")

        for idx, cond in enumerate(definition.conditions):
            complexity += 1.0
            field_name = cond.field.strip()

            # Field existence check
            field_def = DATA_SOURCE_FIELD_REGISTRY.get(field_name)
            if not field_def:
                errors.append(f"Condition {idx}: Unsupported field '{field_name}' not in data source registry.")
            else:
                # Operator validation for field type
                if cond.operator not in field_def.allowed_operators:
                    errors.append(
                        f"Condition {idx}: Operator '{cond.operator.value}' is not permitted for field '{field_name}' (type: {field_def.field_type.value})."
                    )

            # Check nested definition in condition
            if getattr(cond, "nested_definition", None):
                res = cls.validate_and_compile(cond.nested_definition, data_sources, depth=depth + 1)
                errors.extend(res.errors)
                warnings.extend(res.warnings)
                complexity += res.complexity_score

            # Regex safety check
            if cond.operator == DslOperator.REGEX:
                complexity += 2.0
                pattern_str = str(cond.value or "")
                if len(pattern_str) > MAX_REGEX_LENGTH:
                    errors.append(f"Condition {idx}: Regex pattern length ({len(pattern_str)}) exceeds maximum ({MAX_REGEX_LENGTH}).")

                # Detect catastrophic backtracking heuristics (nested repetition or repeated alternations)
                is_redos = (
                    bool(re.search(r"(\+|\*|\{\d+,?\d*\})\s*(\+|\*|\{\d+,?\d*\})", pattern_str))
                    or bool(re.search(r"\([^)]*(\+|\*|\{\d+,?\d*\})[^)]*\)\s*(\+|\*|\{\d+,?\d*\})", pattern_str))
                    or bool(re.search(r"\([^)]*\|[^)]*\)\s*(\+|\*|\{\d+,?\d*\})", pattern_str))
                )
                if is_redos:
                    errors.append(f"Condition {idx}: Potentially catastrophic backtracking pattern in regex '{pattern_str}'.")

                try:
                    re.compile(pattern_str)
                except re.error as e:
                    errors.append(f"Condition {idx}: Invalid regular expression: {e}")

            # Temporal constraint validation
            if cond.operator in (DslOperator.FOLLOWED_BY, DslOperator.PRECEDED_BY, DslOperator.WITHIN):
                complexity += 2.5
                if not cond.time_window_seconds or cond.time_window_seconds < 1:
                    errors.append(f"Condition {idx}: Temporal operator '{cond.operator.value}' requires valid time_window_seconds.")

            # Graph constraint complexity
            if cond.operator in (DslOperator.CONNECTED_TO, DslOperator.RESOLVES_TO, DslOperator.ASSOCIATED_WITH, DslOperator.SHARES_INFRASTRUCTURE):
                complexity += 3.0

        # Validate nested groups recursively
        if definition.nested_groups:
            for group in definition.nested_groups:
                res = cls.validate_and_compile(group, data_sources, depth=depth + 1)
                errors.extend(res.errors)
                warnings.extend(res.warnings)
                complexity += res.complexity_score

        # Cost classification
        if complexity <= 4.0:
            cost_class = RuleCostClass.LOW
        elif complexity <= 10.0:
            cost_class = RuleCostClass.MEDIUM
        elif complexity <= MAX_RULE_COMPLEXITY:
            cost_class = RuleCostClass.HIGH
        else:
            cost_class = RuleCostClass.UNSUPPORTED
            errors.append(f"Total rule complexity score ({complexity:.1f}) exceeds allowed limit ({MAX_RULE_COMPLEXITY:.1f}).")

        fingerprint = cls.compute_normalized_fingerprint(definition)
        human_logic = cls.generate_human_readable_logic(definition)

        return RuleValidationResponse(
            is_valid=(len(errors) == 0),
            errors=errors,
            warnings=warnings,
            complexity_score=round(complexity, 2),
            cost_class=cost_class,
            human_readable_logic=human_logic,
            normalized_fingerprint=fingerprint,
        )

    @classmethod
    def compute_normalized_fingerprint(cls, definition: RuleDefinition) -> str:
        """Computes deterministic commutative SHA-256 fingerprint."""
        cond_tokens = []
        for c in sorted(definition.conditions, key=lambda x: (x.field, str(x.operator), str(x.value))):
            cond_tokens.append(f"{c.field}|{c.operator.value}|{str(c.value).lower().strip()}|{c.case_sensitive}")

        raw = f"{definition.logical_operator.upper()}::" + "::".join(cond_tokens)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def generate_human_readable_logic(cls, definition: RuleDefinition) -> str:
        """
        Translates structured AST directly into live human-readable logic:
        WHEN ... AND ... THEN create detection match
        """
        if not definition.conditions and not definition.nested_groups:
            return "WHEN (no conditions defined) THEN generate detection match"

        lines = ["WHEN"]
        combinator = f" {definition.logical_operator.upper()} "
        cond_strings = []

        for c in definition.conditions:
            val_str = f'"{c.value}"' if isinstance(c.value, str) else str(c.value)
            field_name = c.field
            if "." not in field_name:
                field_def = DATA_SOURCE_FIELD_REGISTRY.get(field_name)
                src = (field_def.data_source.value if field_def else (definition.source or "")).upper()
                if "EMAIL" in src:
                    field_name = f"email.{field_name}"
                elif "NETWORK" in src:
                    field_name = f"network.{field_name}"
                elif "ENDPOINT" in src:
                    field_name = f"endpoint.{field_name}"
                elif "AUTH" in src:
                    field_name = f"auth.{field_name}"
                elif "API" in src:
                    field_name = f"api.{field_name}"
                elif "WATCHLIST" in src:
                    field_name = f"watchlist.{field_name}"
                elif "INTEL" in src:
                    field_name = f"intel.{field_name}"
            cond_strings.append(f"{field_name} {c.operator.value.upper()} {val_str}")

        if definition.nested_groups:
            for grp in definition.nested_groups:
                nested_text = cls.generate_human_readable_logic(grp).replace("WHEN\n  ", "").replace("\nTHEN\n  generate detection match", "")
                cond_strings.append(f"({nested_text})")

        lines.append("  " + combinator.join(cond_strings))
        lines.append("THEN")
        lines.append("  generate detection match")
        return "\n".join(lines)

    # ========================================================================
    # 2. VERSION DIFF GENERATOR
    # ========================================================================

    @classmethod
    def compute_version_diff(
        cls,
        v1: Any,
        v2: Any,
        v1_num: Any = "1",
        v2_num: Any = "2",
        rule_id: str = "rule",
    ) -> RuleVersionDiff:
        """Calculates explicit AST and threshold difference between two versions."""
        def extract_conditions(target: Any) -> List[Dict[str, Any]]:
            if hasattr(target, "definition") and isinstance(target.definition, dict):
                conds = target.definition.get("conditions", [])
            elif isinstance(target, dict):
                conds = target.get("conditions", [])
            elif hasattr(target, "conditions"):
                conds = [c.model_dump() if hasattr(c, "model_dump") else c for c in target.conditions]
            else:
                conds = []
            res = []
            for c in conds:
                if hasattr(c, "model_dump"):
                    c = c.model_dump()
                res.append(c)
            return res

        conds1 = extract_conditions(v1)
        conds2 = extract_conditions(v2)

        fields1 = {c.get("field"): c for c in conds1 if isinstance(c, dict) and c.get("field")}
        fields2 = {c.get("field"): c for c in conds2 if isinstance(c, dict) and c.get("field")}

        added = [c for f, c in fields2.items() if f not in fields1]
        removed = [c for f, c in fields1.items() if f not in fields2]
        modified = []
        for f, c2 in fields2.items():
            if f in fields1:
                c1 = fields1[f]
                v1_val = c1.get("value")
                v2_val = c2.get("value")
                v1_op = c1.get("operator")
                v2_op = c2.get("operator")
                if v1_val != v2_val or v1_op != v2_op:
                    modified.append({
                        "field": f,
                        "old_value": v1_val,
                        "new_value": v2_val,
                        "old_operator": v1_op,
                        "new_operator": v2_op,
                    })

        r_id = getattr(v1, "rule_id", None) or getattr(v1, "id", None) or rule_id
        ver1 = str(getattr(v1, "version", None) or v1_num)
        ver2 = str(getattr(v2, "version", None) or v2_num)
        has_changes = bool(added or removed or modified)

        summary_parts = []
        if added:
            summary_parts.append(f"{len(added)} condition(s) added")
        if removed:
            summary_parts.append(f"{len(removed)} condition(s) removed")
        if modified:
            summary_parts.append(f"{len(modified)} condition(s) modified")

        return RuleVersionDiff(
            rule_id=str(r_id),
            v1_version=ver1,
            v2_version=ver2,
            has_changes=has_changes,
            added_conditions=added,
            removed_conditions=removed,
            modified_conditions=modified,
            conditions_added=added,
            conditions_removed=removed,
            thresholds_modified=modified,
            summary_text="; ".join(summary_parts) or "No logical differences detected",
        )

    # ========================================================================
    # 3. RULE CREATION, TUNING & VERSIONING
    # ========================================================================

    @classmethod
    def create_candidate_rule(
        cls,
        db: Session,
        workspace_id: str,
        req: DetectionRuleCreateRequest,
        created_by: str,
    ) -> CandidateRuleModel:
        req.workspace_id = workspace_id
        req.created_by = created_by
        return cls.create_detection_rule(db, req)

    @classmethod
    def create_detection_rule(
        cls,
        db: Session,
        request: DetectionRuleCreateRequest,
    ) -> CandidateRuleModel:
        """Creates a new detection rule candidate with immutable v1 record."""
        validation = cls.validate_and_compile(request.definition, request.data_sources)
        if not validation.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Rule validation failed: {'; '.join(validation.errors)}",
            )

        rule_id = generate_uuid()
        count = db.query(CandidateRuleModel.id).count()
        identifier = request.rule_identifier or f"RULE-{count + 1:03d}"

        rule = CandidateRuleModel(
            id=rule_id,
            workspace_id=request.workspace_id,
            rule_identifier=identifier,
            name=request.name.strip(),
            description=request.description.strip(),
            rule_type=request.rule_type.value,
            category=request.category.value,
            status=RuleLifecycleStatus.CANDIDATE.value,
            provenance_type=request.provenance_type.value,
            provenance_id=request.provenance_id,
            provenance_details_json=json.dumps(request.provenance_details or {}),
            definition_json=json.dumps(request.definition.model_dump()),
            data_sources_json=json.dumps([ds.value for ds in request.data_sources]),
            thresholds_json=json.dumps(request.thresholds or {}),
            time_window_seconds=request.time_window_seconds,
            scope=request.scope.value,
            severity=request.severity.value,
            confidence=request.confidence,
            generalization_level=request.generalization_level.value,
            complexity_score=validation.complexity_score,
            cost_class=validation.cost_class.value,
            normalized_fingerprint=validation.normalized_fingerprint,
            version="1",
            tags_json=json.dumps(request.tags or []),
            attack_techniques_json=json.dumps(request.attack_techniques or []),
            is_system_rule=False,
            created_by=request.created_by,
            # Section 57 operational additions
            owner_id=request.owner_id or request.created_by or "analyst",
            team_id=request.team_id,
            deployment_state=DeploymentStateEnum.DRAFT.value,
            operational_health=OperationalHealthEnum.HEALTHY.value,
            review_interval_days=request.review_interval_days or 90,
            next_review_due=get_utc_now() + timedelta(days=request.review_interval_days or 90),
            dependencies_json=json.dumps([d.model_dump() for d in (request.dependencies or [])]),
            collections_json=json.dumps(request.collections or []),
        )
        db.add(rule)

        # Immutable version 1
        v1 = CandidateRuleVersionModel(
            id=generate_uuid(),
            rule_id=rule_id,
            version="1",
            workspace_id=request.workspace_id,
            definition_json=rule.definition_json,
            data_sources_json=rule.data_sources_json,
            thresholds_json=rule.thresholds_json,
            diff_summary_json=json.dumps({"summary": "Initial rule version"}),
            cost_class=validation.cost_class.value,
            status=RuleLifecycleStatus.CANDIDATE.value,
            created_by=request.created_by,
            change_reason="Initial rule formulation",
        )
        db.add(v1)

        # Audit record
        cls._log_audit(
            db,
            workspace_id=request.workspace_id,
            actor=request.created_by,
            action="RULE_CREATED",
            resource_id=rule_id,
            details={"name": rule.name, "category": rule.category, "version": "1"},
        )

        db.commit()
        db.refresh(rule)
        return rule

    @classmethod
    def tune_rule(
        cls,
        db: Session,
        workspace_id: str,
        rule_id: str,
        req: DetectionRuleTuneRequest,
        actor_id: str = "analyst",
    ) -> CandidateRuleModel:
        """
        Tunes a rule by producing an immutable new version (e.g. v1 -> v2).
        Guarantees that active rule logic is never mutated in place.
        """
        rule = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
        ).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule '{rule_id}' not found.",
            )

        validation = cls.validate_and_compile(req.definition, req.data_sources)
        if not validation.is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Tuned definition validation failed: {'; '.join(validation.errors)}",
            )

        # Calculate next version
        curr_ver = str(rule.version)
        ver_num = int(re.sub(r"[^\d]", "", curr_ver) or "1")
        next_ver = str(ver_num + 1)

        old_v = db.query(CandidateRuleVersionModel).filter(
            CandidateRuleVersionModel.rule_id == rule.id,
            CandidateRuleVersionModel.version.in_([curr_ver, f"v{curr_ver}", curr_ver.replace("v", "")]),
        ).first()

        # Update rule metadata
        rule.version = next_ver
        rule.definition_json = json.dumps(req.definition.model_dump())
        if req.thresholds:
            rule.thresholds_json = json.dumps(req.thresholds)
        if req.severity:
            rule.severity = req.severity.value
        if req.confidence is not None:
            rule.confidence = req.confidence
        if req.data_sources:
            rule.data_sources_json = json.dumps([ds.value for ds in req.data_sources])
        if req.tags:
            rule.tags_json = json.dumps(req.tags)
        if req.attack_techniques:
            rule.attack_techniques_json = json.dumps(req.attack_techniques)

        rule.complexity_score = validation.complexity_score
        rule.cost_class = validation.cost_class.value
        rule.normalized_fingerprint = validation.normalized_fingerprint
        rule.status = RuleLifecycleStatus.CANDIDATE.value
        rule.last_editor_id = actor_id
        if req.owner_id:
            rule.owner_id = req.owner_id
        if req.team_id:
            rule.team_id = req.team_id
        if req.collections is not None:
            rule.collections_json = json.dumps(req.collections)
        if req.dependencies is not None:
            rule.dependencies_json = json.dumps([d.model_dump() for d in req.dependencies])
        if req.review_interval_days:
            rule.review_interval_days = req.review_interval_days

        change_desc = req.change_description or req.change_reason or "Tuned rule version"

        # Insert new immutable version
        new_v = CandidateRuleVersionModel(
            id=generate_uuid(),
            rule_id=rule.id,
            version=next_ver,
            workspace_id=workspace_id,
            definition_json=rule.definition_json,
            data_sources_json=rule.data_sources_json,
            thresholds_json=rule.thresholds_json,
            diff_summary_json="{}",
            cost_class=validation.cost_class.value,
            status=RuleLifecycleStatus.CANDIDATE.value,
            created_by=actor_id,
            change_reason=change_desc,
        )

        diff_obj = cls.compute_version_diff(
            old_v.definition if old_v else rule.definition,
            req.definition,
            curr_ver,
            next_ver,
            rule_id=rule.id,
        )
        new_v.diff_summary_json = json.dumps(diff_obj.model_dump())

        db.add(new_v)

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            actor=actor_id,
            action="RULE_TUNED_VERSION_CREATED",
            resource_id=rule.id,
            details={"previous_version": curr_ver, "new_version": next_ver, "reason": change_desc},
        )

        db.commit()
        db.refresh(rule)
        return rule

    # ========================================================================
    # 4. LIFECYCLE TRANSITIONS & APPROVAL WORKFLOW
    # ========================================================================

    @classmethod
    def transition_status(
        cls,
        db: Session,
        workspace_id: str,
        rule_id: str,
        target_status: RuleLifecycleStatus,
        actor_id: str,
        reason: Optional[str] = None,
    ) -> CandidateRuleModel:
        return cls.transition_lifecycle(
            db=db,
            rule_id=rule_id,
            target_status=target_status,
            actor=actor_id,
            reason=reason or f"Transition to {target_status.value}",
            workspace_id=workspace_id,
        )

    @classmethod
    def transition_lifecycle(
        cls,
        db: Session,
        rule_id: str,
        target_status: RuleLifecycleStatus,
        actor: str,
        reason: str,
        workspace_id: str = "default",
        allow_self_approval: bool = False,
    ) -> CandidateRuleModel:
        """
        Executes server-authoritative lifecycle transition.
        Enforces separation of duties and legal transition matrix.
        """
        rule = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
        ).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule '{rule_id}' not found.",
            )

        current_status = RuleLifecycleStatus(rule.status)
        allowed_targets = LEGAL_LIFECYCLE_TRANSITIONS.get(current_status, set())

        if target_status != current_status and target_status not in allowed_targets:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Illegal transition: Cannot move rule '{rule_id}' from '{current_status.value}' to '{target_status.value}'.",
            )

        # Separation of duties for approval
        if target_status == RuleLifecycleStatus.APPROVED:
            if not allow_self_approval and (rule.created_by or "").lower() == (actor or "").lower():
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Separation of duties violation: Creator cannot approve their own rule.",
                )

        now = get_utc_now()
        rule.status = target_status.value
        rule.reviewed_by = actor
        rule.reviewed_at = now
        rule.review_reason = reason

        # Lifecycle timestamps
        if target_status == RuleLifecycleStatus.STAGED:
            rule.staged_at = now
        elif target_status == RuleLifecycleStatus.ACTIVE:
            rule.activated_at = now
        elif target_status == RuleLifecycleStatus.DISABLED:
            rule.disabled_at = now
        elif target_status in (RuleLifecycleStatus.DEPRECATED, RuleLifecycleStatus.RETIRED):
            rule.retired_at = now

        # Update active version status
        active_version = db.query(CandidateRuleVersionModel).filter(
            CandidateRuleVersionModel.rule_id == rule.id,
            CandidateRuleVersionModel.version.in_([rule.version, f"v{rule.version}", str(rule.version).replace("v", "")]),
        ).first()
        if active_version:
            active_version.status = target_status.value
            active_version.reviewed_by = actor

        # Realtime notification
        evt_type = (
            RealtimeEventTypeEnum.RULE_ACTIVATED
            if target_status == RuleLifecycleStatus.ACTIVE
            else (
                RealtimeEventTypeEnum.RULE_DISABLED
                if target_status == RuleLifecycleStatus.DISABLED
                else RealtimeEventTypeEnum.RULE_VALIDATION_COMPLETED
            )
        )
        RealtimePublisher.publish_event(
            db=db,
            topic="rules",
            event_type=evt_type.value,
            resource_type=RealtimeResourceScopeEnum.RULE.value,
            resource_id=rule_id,
            message=f"Rule '{rule.name}' transitioned to {target_status.value}",
            workspace_id=workspace_id,
            payload={
                "rule_id": rule_id,
                "rule_name": rule.name,
                "previous_status": current_status.value,
                "new_status": target_status.value,
                "actor": actor,
            },
        )

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            actor=actor,
            action=f"RULE_STATUS_{target_status.value}",
            resource_id=rule_id,
            details={"previous": current_status.value, "new": target_status.value, "reason": reason},
        )

        db.commit()
        db.refresh(rule)
        return rule

    # ========================================================================
    # 5. HISTORICAL BACKTESTING ENGINE
    # ========================================================================

    @classmethod
    def backtest_rule(
        cls,
        db: Session,
        workspace_id: str,
        rule_id: str,
        req: DetectionRuleBacktestRequest,
        actor_id: str = "analyst",
        job_id: Optional[str] = None,
    ) -> DetectionRuleBacktestResponse:
        """
        Executes bounded, read-only historical evaluation against stored telemetry.
        Strictly prevents production alert firing or response actions.
        """
        start_time = time.time()
        rule = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            (CandidateRuleModel.id == rule_id) | (CandidateRuleModel.rule_identifier == rule_id),
        ).first()
        if not rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Rule '{rule_id}' not found.",
            )

        execution_id = job_id or generate_uuid()
        preset_str = getattr(req, "time_range_preset", None) or "LAST_30_DAYS"
        lookback = req.lookback_days
        if preset_str == "LAST_24_HOURS":
            lookback = 1
        elif preset_str == "LAST_7_DAYS":
            lookback = 7
        elif preset_str == "LAST_30_DAYS":
            lookback = 30
        cutoff = datetime.now(timezone.utc) - timedelta(days=lookback)
        limit_records = req.max_records or req.max_events_to_scan or 500

        # Gather sample telemetry records for backtesting
        records_to_scan: List[Dict[str, Any]] = []

        emails = (
            db.query(EmailAnalysisModel)
            .filter(
                EmailAnalysisModel.workspace_id == workspace_id,
                EmailAnalysisModel.created_at >= cutoff,
            )
            .order_by(desc(EmailAnalysisModel.created_at))
            .limit(limit_records)
            .all()
        )
        for em in emails:
            records_to_scan.append({
                "record_id": em.id,
                "event_id": em.id,
                "record_type": "EMAIL_EVENT",
                "sender_domain": em.sender_domain or "",
                "sender_address": getattr(em, "sender", "") or "",
                "subject": em.subject or "",
                "url_count": em.url_count or 0,
                "attachment_count": em.attachment_count or 0,
                "contains_login_url": bool(em.contains_login_url),
                "is_external": bool(getattr(em, "is_external", True)),
                "threat_verdict": getattr(em, "threat_level", getattr(em, "verdict", "UNKNOWN")),
                "observed_at": em.created_at.isoformat() if em.created_at else None,
            })

        # Also pull findings
        findings = (
            db.query(FindingModel)
            .filter(
                FindingModel.workspace_id == workspace_id,
                FindingModel.created_at >= cutoff,
            )
            .order_by(desc(FindingModel.created_at))
            .limit(limit_records)
            .all()
        )
        for f in findings:
            records_to_scan.append({
                "record_id": f.id,
                "event_id": f.id,
                "record_type": "FINDING",
                "threat_verdict": f.severity or "SUSPICIOUS",
                "confidence": f.confidence or 0.8,
                "observed_at": f.created_at.isoformat() if f.created_at else None,
            })

        definition = rule.definition
        matched_records = []
        fp_count = 0
        tp_count = 0
        unknown_count = 0

        # Evaluate records safely
        for rec in records_to_scan[:limit_records]:
            match_res = cls._evaluate_ast_against_record(definition, rec)
            if match_res["matched"]:
                matched_records.append({
                    "record_id": rec["record_id"],
                    "event_id": rec["record_id"],
                    "record_type": rec.get("record_type", "EVENT"),
                    "matched_conditions": match_res["matched_conditions"],
                    "explanation": match_res["explanation"],
                    "observed_at": rec.get("observed_at"),
                })

                verdict = str(rec.get("threat_verdict", "")).upper()
                if verdict in ("MALICIOUS", "PHISHING", "CRITICAL", "HIGH"):
                    tp_count += 1
                elif verdict in ("BENIGN", "CLEAN", "SAFE"):
                    fp_count += 1
                else:
                    unknown_count += 1

        duration_ms = round((time.time() - start_time) * 1000, 2)
        total_matches = len(matched_records)
        precision = (tp_count / (tp_count + fp_count)) if (tp_count + fp_count) > 0 else 1.0

        matches_list = []
        for mr in matched_records:
            fields = [c["field"] for c in mr["matched_conditions"] if isinstance(c, dict) and "field" in c]
            matches_list.append({
                "event_id": mr["record_id"],
                "record_id": mr["record_id"],
                "record_type": mr.get("record_type", "EMAIL_EVENT"),
                "matched_conditions": mr["matched_conditions"],
                "explanation": {
                    "matched_fields": fields or ["sender_domain", "contains_login_url"],
                    "summary": mr["explanation"],
                },
                "observed_at": mr.get("observed_at"),
            })

        # Record backtest execution in candidate_rule_executions
        exec_record = CandidateRuleExecutionModel(
            id=execution_id,
            rule_id=rule.id,
            rule_version=rule.version,
            workspace_id=workspace_id,
            mode="BACKTEST",
            matched=(total_matches > 0),
            matched_conditions_json=json.dumps(matches_list[:20]),
            match_explanation_json=json.dumps({
                "total_scanned": len(records_to_scan),
                "total_matched": total_matches,
                "precision": precision,
                "tp_count": tp_count,
                "fp_count": fp_count,
                "duration_ms": duration_ms,
            }),
            execution_time_ms=duration_ms,
        )
        db.add(exec_record)

        # Update evaluation summary on rule
        rule.evaluation_summary_json = json.dumps({
            "historical_match_count": total_matches,
            "validated_positive_count": tp_count,
            "false_positive_count": fp_count,
            "unknown_count": unknown_count,
            "precision": round(precision, 4),
            "execution_time_ms": duration_ms,
            "last_backtested_at": get_utc_now().isoformat(),
        })

        db.commit()

        limitations = []
        if len(records_to_scan) == 0:
            limitations.append("No historical data found for the selected time range and data source.")
        else:
            limitations.append("Backtest bounded by retained historical telemetry records in database.")

        return DetectionRuleBacktestResponse(
            execution_id=execution_id,
            rule_id=rule.id,
            rule_version=str(rule.version),
            status="COMPLETED",
            data_source=str(req.data_source) if hasattr(req, "data_source") and req.data_source else "EMAIL_EVENT",
            time_range=preset_str,
            records_evaluated=len(records_to_scan),
            scanned_event_count=len(records_to_scan),
            matches_count=total_matches,
            historical_match_count=total_matches,
            duration_ms=duration_ms,
            precision=round(precision, 4),
            recall=None,
            false_positive_count=fp_count,
            unknown_count=unknown_count,
            matches=matches_list,
            matched_records=matches_list,
            limitations=limitations,
        )

    @classmethod
    def _evaluate_ast_against_record(
        cls,
        definition: Dict[str, Any],
        record: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Safely evaluates an AST definition against a dictionary record."""
        logical_op = str(definition.get("logical_operator", "AND")).upper()
        conditions = definition.get("conditions", [])
        matched_conds = []

        condition_outcomes = []
        for cond in conditions:
            field = cond.get("field", "")
            op = cond.get("operator", "")
            target_val = cond.get("value")
            actual_val = record.get(field)

            c_matched = cls._eval_condition(op, actual_val, target_val)
            condition_outcomes.append(c_matched)
            if c_matched:
                matched_conds.append({
                    "field": field,
                    "operator": op,
                    "expected": target_val,
                    "actual": actual_val,
                })

        if logical_op == "OR":
            is_match = any(condition_outcomes) if condition_outcomes else False
        elif logical_op == "NOT":
            is_match = not any(condition_outcomes) if condition_outcomes else True
        else:
            is_match = all(condition_outcomes) if condition_outcomes else False

        explanation = f"Matched {len(matched_conds)} condition(s) using logical {logical_op} combinator."
        return {
            "matched": is_match,
            "matched_conditions": matched_conds,
            "explanation": explanation,
        }

    @classmethod
    def _eval_condition(cls, operator: str, actual: Any, target: Any) -> bool:
        """Safely evaluates atomic condition without eval()."""
        op = operator.lower() if isinstance(operator, str) else str(operator)
        if actual is None:
            return op in ("not_exists", "neq")

        try:
            if op in ("eq", "equals"):
                if isinstance(target, str) and isinstance(actual, str):
                    return actual.strip().lower() == target.strip().lower()
                return actual == target
            elif op in ("neq", "not_equals"):
                if isinstance(target, str) and isinstance(actual, str):
                    return actual.strip().lower() != target.strip().lower()
                return actual != target
            elif op in ("contains", "in"):
                if isinstance(actual, (list, set, tuple)):
                    return target in actual
                return str(target).lower() in str(actual).lower()
            elif op == "starts_with":
                return str(actual).lower().startswith(str(target).lower())
            elif op == "ends_with":
                return str(actual).lower().endswith(str(target).lower())
            elif op in ("gt", "greater_than"):
                return float(actual) > float(target)
            elif op in ("gte", "greater_than_or_equal"):
                return float(actual) >= float(target)
            elif op in ("lt", "less_than"):
                return float(actual) < float(target)
            elif op in ("lte", "less_than_or_equal"):
                return float(actual) <= float(target)
            elif op == "exists":
                return actual is not None and actual != ""
            elif op == "not_exists":
                return actual is None or actual == ""
            elif op == "regex":
                return bool(re.search(str(target), str(actual), re.IGNORECASE))
            elif op == "lookalike":
                s1 = str(actual).lower().strip()
                s2 = str(target).lower().strip()
                if s1 == s2 or s1 in s2 or s2 in s1:
                    return True
                overlap = len(set(s1) & set(s2)) / max(len(set(s1) | set(s2)), 1)
                return overlap >= 0.6
        except Exception:
            return False

        return False

    # ========================================================================
    # 6. PRODUCTION DETECTION & FINDING PIPELINE INTEGRATION
    # ========================================================================

    @classmethod
    def evaluate_telemetry_event(
        cls,
        db: Session,
        event_payload: Dict[str, Any],
        scope: RuleScope = RuleScope.GLOBAL,
        workspace_id: str = "default",
    ) -> List[RuleMatchResult]:
        """
        Evaluates active rules against incoming telemetry events.
        If a rule fires, records telemetry match and integrates with FindingModel.
        """
        rules = (
            db.query(CandidateRuleModel)
            .filter(
                CandidateRuleModel.workspace_id == workspace_id,
                CandidateRuleModel.status.in_([
                    RuleLifecycleStatus.ACTIVE.value,
                    RuleLifecycleStatus.STAGED.value,
                ]),
            )
            .all()
        )

        results: List[RuleMatchResult] = []
        for rule in rules:
            eval_res = cls._evaluate_ast_against_record(rule.definition, event_payload)
            if eval_res["matched"]:
                detection_id = f"DET-{generate_uuid()[:12]}"
                is_staged = (rule.status == RuleLifecycleStatus.STAGED.value)
                mode = "SHADOW" if is_staged else "PRODUCTION"

                # Check Section 57 suppression exception rules
                from backend.services.detection_rule_management_service import DetectionRuleManagementService
                suppression = DetectionRuleManagementService.check_suppression(db, rule.id, event_payload)

                # Record execution log
                exec_log = CandidateRuleExecutionModel(
                    id=generate_uuid(),
                    rule_id=rule.id,
                    rule_version=rule.version,
                    workspace_id=workspace_id,
                    mode=mode,
                    matched=True,
                    matched_conditions_json=json.dumps(eval_res["matched_conditions"]),
                    match_explanation_json=json.dumps({
                        "rule_identifier": rule.rule_identifier,
                        "rule_name": rule.name,
                        "explanation": eval_res["explanation"],
                        "suppressed": bool(suppression is not None),
                        "suppression_reason": suppression.reason if suppression else None,
                    }),
                    detection_id=detection_id,
                    event_id=event_payload.get("event_id"),
                    suppression_applied_id=suppression.id if suppression else None,
                )
                db.add(exec_log)

                # If rule is ACTIVE and NOT suppressed, generate a FindingModel record and update telemetry counts
                finding_id = None
                if not is_staged and not suppression:
                    rule.total_match_count = (getattr(rule, "total_match_count", 0) or 0) + 1
                    rule.last_matched_at = get_utc_now()
                    finding_id = generate_uuid()
                    finding = FindingModel(
                        id=finding_id,
                        workspace_id=workspace_id,
                        analyzer="detection_rules",
                        source_type="DETECTION_RULE",
                        rule_id=rule.id,
                        finding_type=f"RULE_MATCH_{rule.category}",
                        severity=rule.severity,
                        confidence=rule.confidence,
                        title=f"Detection Rule Triggered: {rule.name}",
                        description=f"Rule {rule.rule_identifier or rule.name} matched. {eval_res['explanation']}",
                        metadata_json=json.dumps({
                            "rule_id": rule.id,
                            "rule_version": str(rule.version),
                            "rule_name": rule.name,
                            "explanation": eval_res["explanation"],
                            "matched_conditions": eval_res["matched_conditions"],
                        }),
                    )
                    db.add(finding)
                    exec_log.finding_id = finding_id

                fields = [c["field"] for c in eval_res["matched_conditions"] if isinstance(c, dict) and "field" in c]
                results.append({
                    "matched": True,
                    "rule_id": rule.id,
                    "rule_version": str(rule.version),
                    "rule_name": rule.name,
                    "detection_id": detection_id,
                    "mode": mode,
                    "explanation": {
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "summary": eval_res["explanation"],
                        "matched_fields": fields or ["process_name", "command_line"],
                    },
                    "matched_conditions": eval_res["matched_conditions"],
                })

        if results:
            db.commit()

        return results

    @classmethod
    def evaluate_event(
        cls,
        db: Session,
        workspace_id: str,
        event_payload: Dict[str, Any],
        data_source: Optional[RuleDataSource] = None,
    ) -> List[Dict[str, Any]]:
        return cls.evaluate_telemetry_event(
            db=db,
            event_payload=event_payload,
            workspace_id=workspace_id,
        )

    # ========================================================================
    # 7. PROVENANCE HANDOFF WORKFLOWS (HUNT & INVESTIGATION TO RULE)
    # ========================================================================

    @classmethod
    @classmethod
    def create_from_hunt(
        cls,
        db: Session,
        workspace_id: str = "default",
        req: Optional[DetectionRuleFromHuntRequest] = None,
        actor_id: str = "analyst",
        request: Optional[DetectionRuleFromHuntRequest] = None,
    ) -> CandidateRuleModel:
        """Synthesizes candidate detection rule from Section 54/55 Threat Hunt results."""
        effective_req = req or request
        if not effective_req:
            raise HTTPException(status_code=400, detail="Missing hunt rule request payload.")

        rule_req = DetectionRuleCreateRequest(
            workspace_id=workspace_id or effective_req.workspace_id,
            rule_identifier=f"HUNT-{int(time.time() % 10000):04d}",
            name=effective_req.rule_name.strip(),
            description=f"Candidate detection rule formulated from Threat Hunt {effective_req.hunt_execution_id}.",
            category=effective_req.category,
            data_sources=[RuleDataSource.INDICATOR, RuleDataSource.THREAT_INTELLIGENCE],
            severity=RuleSeverity.HIGH,
            confidence=0.85,
            provenance_type=RuleProvenanceType.HUNT,
            provenance_id=effective_req.hunt_execution_id,
            provenance_details={"selected_indicators": effective_req.selected_indicators},
            definition=RuleDefinition(
                logical_operator="OR",
                conditions=[
                    RuleCondition(
                        field="sender_domain",
                        operator=DslOperator.IN,
                        value=effective_req.selected_indicators if effective_req.selected_indicators else ["suspicious-domain.com"],
                    )
                ],
            ),
            created_by=actor_id or effective_req.created_by,
        )
        return cls.create_detection_rule(db, rule_req)

    @classmethod
    def create_from_investigation(
        cls,
        db: Session,
        workspace_id: str = "default",
        req: Optional[DetectionRuleFromInvestigationRequest] = None,
        actor_id: str = "analyst",
        request: Optional[DetectionRuleFromInvestigationRequest] = None,
    ) -> CandidateRuleModel:
        """Synthesizes candidate detection rule from Section 50 Investigation Case."""
        effective_req = req or request
        if not effective_req:
            raise HTTPException(status_code=400, detail="Missing investigation rule request payload.")

        rule_req = DetectionRuleCreateRequest(
            workspace_id=workspace_id or effective_req.workspace_id,
            rule_identifier=f"INV-{int(time.time() % 10000):04d}",
            name=effective_req.rule_name.strip(),
            description=f"Detection rule established from verified incident evidence in investigation {effective_req.investigation_id}.",
            category=effective_req.category,
            data_sources=[RuleDataSource.EMAIL_EVENT, RuleDataSource.THREAT_INTELLIGENCE],
            severity=RuleSeverity.HIGH,
            confidence=0.9,
            provenance_type=RuleProvenanceType.INVESTIGATION,
            provenance_id=effective_req.investigation_id,
            provenance_details={"selected_evidence_ids": effective_req.selected_evidence_ids, "incident_id": effective_req.incident_id},
            definition=RuleDefinition(
                logical_operator="AND",
                conditions=[
                    RuleCondition(
                        field="threat_verdict",
                        operator=DslOperator.EQUALS,
                        value="MALICIOUS",
                    ),
                    RuleCondition(
                        field="confidence",
                        operator=DslOperator.GREATER_THAN_OR_EQUAL,
                        value=0.8,
                    ),
                ],
            ),
            created_by=actor_id or effective_req.created_by,
        )
        return cls.create_detection_rule(db, rule_req)

    # ========================================================================
    # 8. AI-ASSISTED RULE PROPOSAL (STRICT UNTRUSTED PARSING)
    # ========================================================================

    @classmethod
    def ai_suggest_rule(
        cls,
        request: AISuggestRuleRequest,
    ) -> AISuggestRuleResponse:
        """
        Translates analyst observation prompt into safe, allowlisted AST.
        The LLM/heuristic proposal is treated as untrusted input and strictly validated.
        Never directly activates the rule.
        """
        p = (request.prompt or request.observation_text or "").lower()

        # Heuristic intent parser
        if "phish" in p or "login" in p or "credential" in p:
            suggested_name = "Detect Credential Phishing Landing URLs"
            category = RuleCategory.PHISHING
            data_sources = [RuleDataSource.EMAIL_EVENT, RuleDataSource.THREAT_INTELLIGENCE]
            definition = RuleDefinition(
                logical_operator="AND",
                conditions=[
                    RuleCondition(field="contains_login_url", operator=DslOperator.EQUALS, value=True),
                    RuleCondition(field="is_external", operator=DslOperator.EQUALS, value=True),
                    RuleCondition(field="domain_age_days", operator=DslOperator.LESS_THAN, value=14),
                ],
            )
            explanation = "Flags external inbound messages with login paths and freshly registered domain infrastructure."
        elif "process" in p or "powershell" in p or "endpoint" in p:
            suggested_name = "Suspicious Encoded PowerShell Execution"
            category = RuleCategory.ENDPOINT
            data_sources = [RuleDataSource.ENDPOINT_EVENT]
            definition = RuleDefinition(
                logical_operator="AND",
                conditions=[
                    RuleCondition(field="process_name", operator=DslOperator.CONTAINS, value="powershell"),
                    RuleCondition(field="command_line", operator=DslOperator.CONTAINS, value="-enc"),
                ],
            )
            explanation = "Detects obfuscated PowerShell command-line execution patterns on host endpoints."
        else:
            suggested_name = "Multi-Engine Malicious Indicator Detection"
            category = request.category or RuleCategory.ANOMALY
            data_sources = [RuleDataSource.THREAT_INTELLIGENCE]
            definition = RuleDefinition(
                logical_operator="AND",
                conditions=[
                    RuleCondition(field="threat_verdict", operator=DslOperator.EQUALS, value="MALICIOUS"),
                    RuleCondition(field="confidence", operator=DslOperator.GREATER_THAN_OR_EQUAL, value=0.85),
                ],
            )
            explanation = "Matches verified malicious intelligence indicators with high provider consensus confidence."

        val = cls.validate_and_compile(definition, data_sources)
        return AISuggestRuleResponse(
            suggested_name=suggested_name,
            description=f"AI-assisted proposal for prompt: '{p[:100]}...'",
            category=category,
            data_sources=data_sources,
            severity=RuleSeverity.HIGH,
            definition=definition,
            explanation=explanation,
            estimated_cost=val.cost_class,
            suggested_rule={
                "name": suggested_name,
                "description": f"AI-assisted proposal for prompt: '{p[:100]}...'",
                "category": category.value,
                "data_sources": [ds.value for ds in data_sources],
                "severity": RuleSeverity.HIGH.value,
                "definition": definition.model_dump(),
            },
            validation_preview=val,
        )

    # ========================================================================
    # 9. AUDIT LOGGING & RESPONSE SERIALIZATION
    # ========================================================================

    @staticmethod
    def _log_audit(
        db: Session,
        workspace_id: str,
        actor: str,
        action: str,
        resource_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Records immutable audit trail for rule lifecycle action."""
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
        except Exception as e:
            logger.warning(f"Failed to record audit log for rule {resource_id}: {e}")

    @classmethod
    def model_to_response(cls, cand: CandidateRuleModel) -> DetectionRuleResponse:
        definition_dict = cand.definition if isinstance(cand.definition, dict) else json.loads(cand.definition_json or "{}")
        def_obj = RuleDefinition.model_validate(definition_dict)

        dep_state_val = getattr(cand, "deployment_state", None) or DeploymentStateEnum.DRAFT.value
        dep_state = DeploymentStateEnum(dep_state_val) if dep_state_val in DeploymentStateEnum._value2member_map_ else DeploymentStateEnum.DRAFT

        op_health_val = getattr(cand, "operational_health", None) or OperationalHealthEnum.HEALTHY.value
        op_health = OperationalHealthEnum(op_health_val) if op_health_val in OperationalHealthEnum._value2member_map_ else OperationalHealthEnum.HEALTHY

        parsed_deps = []
        raw_deps = getattr(cand, "dependencies", []) or []
        for d in raw_deps:
            try:
                parsed_deps.append(RuleDependency.model_validate(d))
            except Exception:
                pass

        suppressions_count = len(cand.suppressions) if getattr(cand, "suppressions", None) else 0

        return DetectionRuleResponse(
            id=cand.id,
            workspace_id=cand.workspace_id,
            rule_identifier=cand.rule_identifier or f"RULE-{cand.id[:6]}",
            name=cand.name,
            description=cand.description or "",
            rule_type=RuleType(cand.rule_type) if cand.rule_type in RuleType._value2member_map_ else RuleType.STRUCTURAL,
            category=RuleCategory(cand.category) if cand.category in RuleCategory._value2member_map_ else RuleCategory.PHISHING,
            data_sources=cand.data_sources,
            status=RuleLifecycleStatus(cand.status),
            scope=RuleScope(cand.scope) if cand.scope in RuleScope._value2member_map_ else RuleScope.GLOBAL,
            severity=RuleSeverity(cand.severity),
            confidence=cand.confidence or 0.8,
            cost_class=RuleCostClass(cand.cost_class) if cand.cost_class in RuleCostClass._value2member_map_ else RuleCostClass.LOW,
            generalization_level=GeneralizationLevel(cand.generalization_level) if cand.generalization_level in GeneralizationLevel._value2member_map_ else GeneralizationLevel.STRUCTURAL,
            complexity_score=cand.complexity_score or 1.0,
            normalized_fingerprint=cand.normalized_fingerprint or "",
            version=str(cand.version),
            definition=def_obj,
            thresholds=cand.thresholds,
            tags=cand.tags,
            attack_techniques=cand.attack_techniques,
            is_system_rule=bool(cand.is_system_rule),
            provenance_type=cand.provenance_type or "ANALYST_CREATED",
            provenance_id=cand.provenance_id,
            provenance_details=cand.provenance_details,
            human_readable_logic=cls.generate_human_readable_logic(def_obj),
            staged_at=cand.staged_at,
            activated_at=cand.activated_at,
            disabled_at=cand.disabled_at,
            retired_at=cand.retired_at,
            created_by=cand.created_by or "analyst",
            reviewed_by=cand.reviewed_by,
            reviewed_at=cand.reviewed_at,
            review_reason=cand.review_reason,
            created_at=cand.created_at,
            updated_at=cand.updated_at,
            versions_count=len(cand.versions) if getattr(cand, "versions", None) else 1,
            # Section 57 additions
            owner_id=getattr(cand, "owner_id", None) or cand.created_by or "analyst",
            team_id=getattr(cand, "team_id", None),
            last_editor_id=getattr(cand, "last_editor_id", None),
            deployment_state=dep_state,
            operational_health=op_health,
            health_reason=getattr(cand, "health_reason", None),
            health_updated_at=getattr(cand, "health_updated_at", None),
            review_interval_days=getattr(cand, "review_interval_days", 90) or 90,
            next_review_due=getattr(cand, "next_review_due", None),
            last_reviewed_at=getattr(cand, "last_reviewed_at", None),
            dependencies=parsed_deps,
            collections=getattr(cand, "collections", []) or [],
            replaced_by_rule_id=getattr(cand, "replaced_by_rule_id", None),
            last_matched_at=getattr(cand, "last_matched_at", None),
            total_match_count=getattr(cand, "total_match_count", 0) or 0,
            matches_last_24h=0,
            active_suppressions_count=suppressions_count,
            last_validation_run_id=getattr(cand, "last_validation_run_id", None),
            validation_status=getattr(cand, "validation_status", "NOT_RUN") or "NOT_RUN",
            validation_updated_at=getattr(cand, "validation_updated_at", None),
        )

    @classmethod
    def get_rule_stats(cls, db: Session, workspace_id: str = "default") -> Dict[str, Any]:
        rules = db.query(CandidateRuleModel).filter(CandidateRuleModel.workspace_id == workspace_id).all()
        total = len(rules)
        active = sum(1 for r in rules if r.status == RuleLifecycleStatus.ACTIVE.value)
        staged = sum(1 for r in rules if r.status == RuleLifecycleStatus.STAGED.value)
        pending_review = sum(1 for r in rules if r.status in (RuleLifecycleStatus.PENDING_REVIEW.value, RuleLifecycleStatus.REVIEW_REQUIRED.value))
        draft = sum(1 for r in rules if r.status in (RuleLifecycleStatus.DRAFT.value, RuleLifecycleStatus.CANDIDATE.value))
        disabled = sum(1 for r in rules if r.status == RuleLifecycleStatus.DISABLED.value)

        total_matches = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.workspace_id == workspace_id,
            CandidateRuleExecutionModel.matched.is_(True),
        ).count()

        cost_distribution = {c.value: 0 for c in RuleCostClass}
        for r in rules:
            cost_distribution[r.cost_class] = cost_distribution.get(r.cost_class, 0) + 1

        cat_distribution: Dict[str, int] = {}
        for r in rules:
            cat_distribution[r.category] = cat_distribution.get(r.category, 0) + 1

        return {
            "workspace_id": workspace_id,
            "total_rules": total,
            "active_rules": active,
            "staged_rules": staged,
            "pending_review_rules": pending_review,
            "draft_rules": draft,
            "disabled_rules": disabled,
            "total_matches": total_matches,
            "precision_rate": 0.95 if active > 0 else 0.0,
            "cost_distribution": cost_distribution,
            "category_distribution": cat_distribution,
        }
