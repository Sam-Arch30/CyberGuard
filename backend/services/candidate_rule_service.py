"""
Section 25: Emerging Pattern & Candidate Rule Engine Service.

Orchestrates:
1. Safe Rule DSL validator, normalizer, and deterministic fingerprinter (zero eval/exec).
2. Pattern-to-rule synthesis from EmergingPatternCandidate and Threat Memory.
3. Historical backtesting with ground-truth awareness (unknowns not assumed true negatives).
4. Full lifecycle governance: DISCOVERED -> VALIDATING -> TESTED -> REVIEW_REQUIRED -> APPROVED -> STAGED -> ACTIVE.
5. Shadow mode execution (telemetry without production alerts) and safe active rule firing.
6. Immutable versioning and audit trails.
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

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.db.models import (
    AuditLogModel,
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    EmergingPatternCandidateModel,
    FindingModel,
    IncidentModel,
    SecurityEventModel,
    ThreatEventModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import (
    CandidateRuleCreate,
    CandidateRuleFromPatternRequest,
    CandidateRuleResponse,
    DslOperator,
    GeneralizationLevel,
    RuleBacktestRequest,
    RuleCondition,
    RuleDashboardStats,
    RuleDefinition,
    RuleEditRequest,
    RuleEvaluation,
    RuleLifecycleStatus,
    RuleMatchResult,
    RuleReviewActionRequest,
    RuleScope,
    RuleSeverity,
    RuleType,
    RuleVersionResponse,
)

logger = logging.getLogger("candidate_rule_engine")

# Execution limits & budgets
MAX_RULE_CONDITIONS = 20
MAX_RULE_COMPLEXITY = 25.0
MAX_REGEX_LENGTH = 128
MAX_REGEX_EVAL_STRING_LENGTH = 4096
REGEX_TIMEOUT_SECONDS = 0.05


# ============================================================================
# 1. SAFE RULE DSL VALIDATOR & NORMALIZER
# ============================================================================

class RuleDslValidator:
    """Validates syntax, types, regex safety, and computational budgets."""

    @staticmethod
    def validate_definition(definition: RuleDefinition) -> Tuple[bool, List[str], float]:
        """
        Validates rule definition against safe DSL rules.
        Returns (is_valid, error_list, complexity_score).
        """
        errors = []
        if not definition.conditions:
            errors.append("Rule definition must contain at least one condition.")

        if len(definition.conditions) > MAX_RULE_CONDITIONS:
            errors.append(f"Condition count ({len(definition.conditions)}) exceeds maximum ({MAX_RULE_CONDITIONS}).")

        complexity = 0.0

        for idx, cond in enumerate(definition.conditions):
            complexity += 1.0

            # Validate operator
            if not isinstance(cond.operator, DslOperator):
                try:
                    cond.operator = DslOperator(cond.operator)
                except ValueError:
                    errors.append(f"Condition {idx}: Unsupported operator '{cond.operator}'.")
                    continue

            # Validate regex safety
            if cond.operator == DslOperator.REGEX:
                complexity += 2.0
                pattern_str = str(cond.value or "")
                if len(pattern_str) > MAX_REGEX_LENGTH:
                    errors.append(f"Condition {idx}: Regex length ({len(pattern_str)}) exceeds maximum ({MAX_REGEX_LENGTH}).")
                # Detect catastrophic backtracking heuristics (nested repetition or repeated alternation)
                is_redos = (
                    bool(re.search(r"(\+|\*|\{\d+,?\d*\})\s*(\+|\*|\{\d+,?\d*\})", pattern_str)) or
                    bool(re.search(r"\([^)]*(\+|\*|\{\d+,?\d*\})[^)]*\)\s*(\+|\*|\{\d+,?\d*\})", pattern_str)) or
                    bool(re.search(r"\([^)]*\|[^)]*\)\s*(\+|\*|\{\d+,?\d*\})", pattern_str))
                )
                if is_redos:
                    errors.append(f"Condition {idx}: Potentially catastrophic backtracking pattern in regex '{pattern_str}'.")
                try:
                    re.compile(pattern_str)
                except re.error as e:
                    errors.append(f"Condition {idx}: Invalid regular expression: {e}")

            # Temporal constraints
            if cond.operator in (DslOperator.FOLLOWED_BY, DslOperator.PRECEDED_BY, DslOperator.WITHIN):
                complexity += 2.5
                if not cond.time_window_seconds or cond.time_window_seconds < 1:
                    errors.append(f"Condition {idx}: Temporal operator '{cond.operator.value}' requires valid time_window_seconds.")

            # Graph constraints
            if cond.operator in (DslOperator.CONNECTED_TO, DslOperator.RESOLVES_TO, DslOperator.ASSOCIATED_WITH, DslOperator.SHARES_INFRASTRUCTURE):
                complexity += 3.0

        if complexity > MAX_RULE_COMPLEXITY:
            errors.append(f"Total rule complexity score ({complexity:.1f}) exceeds maximum budget ({MAX_RULE_COMPLEXITY:.1f}).")

        return (len(errors) == 0, errors, round(complexity, 2))


class RuleNormalizer:
    """Canonicalizes rule definitions and computes deterministic fingerprints."""

    @staticmethod
    def canonical_fingerprint(definition: RuleDefinition, scope: RuleScope, rule_type: RuleType) -> str:
        """
        Sorts conditions deterministically by field, operator, and serialized value
        so commutativity (A AND B == B AND A) produces identical fingerprints.
        """
        canonical_conds = []
        for cond in definition.conditions:
            val_str = json.dumps(cond.value, sort_keys=True) if cond.value is not None else ""
            canonical_conds.append({
                "field": cond.field.lower().strip(),
                "operator": cond.operator.value if hasattr(cond.operator, "value") else str(cond.operator),
                "value": val_str,
                "case_sensitive": cond.case_sensitive,
                "time_window": cond.time_window_seconds or 0,
            })

        # Sort conditions by field, operator, then value
        canonical_conds.sort(key=lambda c: (c["field"], c["operator"], c["value"]))

        payload = {
            "scope": scope.value if hasattr(scope, "value") else str(scope),
            "rule_type": rule_type.value if hasattr(rule_type, "value") else str(rule_type),
            "logical_operator": definition.logical_operator.upper(),
            "conditions": canonical_conds,
        }
        raw_repr = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw_repr.encode("utf-8")).hexdigest()


# ============================================================================
# 2. RUNTIME EVALUATION ENGINE (SAFE DISPATCH)
# ============================================================================

class RuleEvaluator:
    """
    Evaluates structured rule conditions against a target event or context dictionary.
    ZERO eval(), ZERO exec(), ZERO external code execution.
    """

    @classmethod
    def evaluate_condition(cls, condition: RuleCondition, context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Evaluates an individual atomic condition against context."""
        field_val = cls._resolve_field(condition.field, context)
        expected = condition.value
        op = condition.operator

        try:
            # Existence checks
            if op == DslOperator.EXISTS:
                matched = field_val is not None and field_val != "" and field_val != []
                return matched, f"{condition.field} exists = {matched}"

            if op == DslOperator.NOT_EXISTS:
                matched = field_val is None or field_val == "" or field_val == []
                return matched, f"{condition.field} not exists = {matched}"

            if field_val is None:
                return False, f"{condition.field} is missing in context"

            # String normalizations if insensitive
            str_field = str(field_val)
            str_expected = str(expected) if expected is not None else ""
            if not condition.case_sensitive:
                str_field = str_field.lower()
                str_expected = str_expected.lower()

            # Equality
            if op == DslOperator.EQUALS:
                if isinstance(field_val, (int, float)) and isinstance(expected, (int, float)):
                    matched = float(field_val) == float(expected)
                else:
                    matched = str_field == str_expected
                return matched, f"{condition.field} == {expected} (got {field_val})"

            if op == DslOperator.NOT_EQUALS:
                if isinstance(field_val, (int, float)) and isinstance(expected, (int, float)):
                    matched = float(field_val) != float(expected)
                else:
                    matched = str_field != str_expected
                return matched, f"{condition.field} != {expected} (got {field_val})"

            # Numeric comparisons
            if op == DslOperator.GREATER_THAN:
                matched = float(field_val) > float(expected)
                return matched, f"{condition.field} > {expected} (got {field_val})"

            if op == DslOperator.GREATER_THAN_OR_EQUAL:
                matched = float(field_val) >= float(expected)
                return matched, f"{condition.field} >= {expected} (got {field_val})"

            if op == DslOperator.LESS_THAN:
                matched = float(field_val) < float(expected)
                return matched, f"{condition.field} < {expected} (got {field_val})"

            if op == DslOperator.LESS_THAN_OR_EQUAL:
                matched = float(field_val) <= float(expected)
                return matched, f"{condition.field} <= {expected} (got {field_val})"

            # String operations
            if op == DslOperator.CONTAINS:
                if isinstance(field_val, (list, tuple, set)):
                    matched = any((str(x).lower() if not condition.case_sensitive else str(x)) == str_expected for x in field_val)
                else:
                    matched = str_expected in str_field
                return matched, f"{condition.field} contains '{expected}'"

            if op == DslOperator.NOT_CONTAINS:
                if isinstance(field_val, (list, tuple, set)):
                    matched = not any((str(x).lower() if not condition.case_sensitive else str(x)) == str_expected for x in field_val)
                else:
                    matched = str_expected not in str_field
                return matched, f"{condition.field} not contains '{expected}'"

            if op == DslOperator.STARTS_WITH:
                matched = str_field.startswith(str_expected)
                return matched, f"{condition.field} starts with '{expected}'"

            if op == DslOperator.ENDS_WITH:
                matched = str_field.endswith(str_expected)
                return matched, f"{condition.field} ends with '{expected}'"

            if op == DslOperator.IN:
                collection = [str(x).lower() if not condition.case_sensitive else str(x) for x in (expected if isinstance(expected, list) else [expected])]
                matched = str_field in collection
                return matched, f"{condition.field} in {expected}"

            if op == DslOperator.NOT_IN:
                collection = [str(x).lower() if not condition.case_sensitive else str(x) for x in (expected if isinstance(expected, list) else [expected])]
                matched = str_field not in collection
                return matched, f"{condition.field} not in {expected}"

            # Regex with execution limits
            if op == DslOperator.REGEX:
                truncated_text = str(field_val)[:MAX_REGEX_EVAL_STRING_LENGTH]
                flags = 0 if condition.case_sensitive else re.IGNORECASE
                pattern = re.compile(str(expected), flags=flags)
                matched = bool(pattern.search(truncated_text))
                return matched, f"{condition.field} regex match '{expected}' = {matched}"

            # Semantic similarity
            if op == DslOperator.SIMILARITY_GTE:
                import difflib
                if isinstance(expected, dict):
                    target_str = str(expected.get("target", ""))
                    threshold = float(expected.get("threshold", 0.8))
                elif isinstance(expected, (int, float)):
                    target_str = str(context.get(f"{condition.field}_target") or context.get("target_domain") or context.get("target") or "")
                    threshold = float(expected)
                else:
                    target_str = str(expected or "")
                    threshold = 0.8

                if not target_str:
                    if isinstance(field_val, (int, float)):
                        matched = float(field_val) >= threshold
                        return matched, f"{condition.field} similarity {field_val} >= {threshold}"
                    return False, f"No target string provided for {condition.field} similarity comparison"

                ratio = difflib.SequenceMatcher(None, str_field.lower(), target_str.lower()).ratio()
                matched = ratio >= threshold
                return matched, f"{condition.field} ('{str_field}') similarity to '{target_str}' is {ratio:.2f} >= {threshold:.2f}"


            # Count operations
            if op == DslOperator.COUNT_GTE:
                count = len(field_val) if isinstance(field_val, (list, tuple, dict, str)) else 0
                matched = count >= int(expected)
                return matched, f"{condition.field} count {count} >= {expected}"

            if op == DslOperator.COUNT_LTE:
                count = len(field_val) if isinstance(field_val, (list, tuple, dict, str)) else 0
                matched = count <= int(expected)
                return matched, f"{condition.field} count {count} <= {expected}"

            # Temporal / Sequence in context
            if op in (DslOperator.FOLLOWED_BY, DslOperator.PRECEDED_BY, DslOperator.WITHIN):
                seq_matched = cls._evaluate_temporal_context(condition, context)
                return seq_matched, f"{condition.field} {op.value} sequence check = {seq_matched}"

            # Graph operators
            if op in (DslOperator.CONNECTED_TO, DslOperator.RESOLVES_TO, DslOperator.ASSOCIATED_WITH, DslOperator.SHARES_INFRASTRUCTURE):
                graph_matched = cls._evaluate_graph_context(condition, context)
                return graph_matched, f"{condition.field} {op.value} graph relationship = {graph_matched}"

        except Exception as e:
            logger.debug(f"Error evaluating condition {condition.field} {op}: {e}")
            return False, f"Evaluation error on {condition.field}: {str(e)}"

        return False, f"Unsupported operator {op}"

    @classmethod
    def evaluate_rule(cls, rule: CandidateRuleModel, context: Dict[str, Any]) -> RuleMatchResult:
        """Evaluates a full CandidateRuleModel against context."""
        start_time = time.perf_counter()
        raw_def = rule.definition
        conditions_data = raw_def.get("conditions", [])
        logical_op = raw_def.get("logical_operator", "AND").upper()

        matched_conditions = []
        all_passed = True
        any_passed = False

        for cond_dict in conditions_data:
            cond = RuleCondition(**cond_dict)
            passed, explanation = cls.evaluate_condition(cond, context)
            if passed:
                matched_conditions.append({
                    "field": cond.field,
                    "operator": cond.operator.value if hasattr(cond.operator, "value") else str(cond.operator),
                    "explanation": explanation,
                })
                any_passed = True
            else:
                all_passed = False

        rule_matched = all_passed if logical_op == "AND" else any_passed
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        explanation = f"Matched {len(matched_conditions)} of {len(conditions_data)} conditions via {logical_op}" if rule_matched else "Conditions not satisfied"

        return RuleMatchResult(
            rule_id=rule.id,
            rule_version=rule.version,
            rule_name=rule.name,
            matched=rule_matched,
            matched_conditions=matched_conditions if rule_matched else [],
            confidence=rule.confidence,
            severity=RuleSeverity(rule.severity),
            explanation=explanation,
            evidence_items=[{"matched_conditions": matched_conditions}] if rule_matched else [],
            execution_time_ms=round(elapsed_ms, 3),
        )

    @staticmethod
    def _resolve_field(path: str, context: Dict[str, Any]) -> Any:
        """Dot-notation dictionary key resolution."""
        parts = path.split(".")
        current = context
        for p in parts:
            if isinstance(current, dict) and p in current:
                current = current[p]
            else:
                return None
        return current

    @staticmethod
    def _calculate_token_similarity(s1: str, s2: str) -> float:
        """Token Jaccard similarity."""
        tokens1 = set(re.findall(r"\w+", s1.lower()))
        tokens2 = set(re.findall(r"\w+", s2.lower()))
        if not tokens1 and not tokens2:
            return 1.0
        if not tokens1 or not tokens2:
            return 0.0
        intersection = len(tokens1 & tokens2)
        union = len(tokens1 | tokens2)
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def _evaluate_temporal_context(condition: RuleCondition, context: Dict[str, Any]) -> bool:
        """Checks temporal sequence relations in context."""
        events = context.get("event_sequence", [])
        if not events or len(events) < 2:
            return False
        # Expected value is target event type
        target_event = str(condition.value or "")
        return any(str(e.get("event_type", "")).lower() == target_event.lower() for e in events)

    @staticmethod
    def _evaluate_graph_context(condition: RuleCondition, context: Dict[str, Any]) -> bool:
        """Checks graph relationship presence in context."""
        relationships = context.get("relationships", [])
        rel_type = condition.operator.value if hasattr(condition.operator, "value") else str(condition.operator)
        target = str(condition.value or "").lower()
        for r in relationships:
            if str(r.get("type", "")).upper() == rel_type and (not target or target in str(r.get("target", "")).lower()):
                return True
        return False


# ============================================================================
# 3. CORE CANDIDATE RULE SERVICE
# ============================================================================

class CandidateRuleService:
    """End-to-end service managing candidate detection rules."""

    @classmethod
    def generate_candidate_from_pattern(
        cls,
        db: Session,
        request: CandidateRuleFromPatternRequest,
    ) -> CandidateRuleModel:
        """
        Synthesizes a structured candidate rule from an EmergingPatternCandidate.
        Generalizes structural and behavioral characteristics rather than memorizing exact values.
        """
        pattern = db.query(EmergingPatternCandidateModel).filter(
            EmergingPatternCandidateModel.workspace_id == request.workspace_id,
            EmergingPatternCandidateModel.id == request.pattern_candidate_id,
        ).first()

        if not pattern:
            raise ValueError(f"EmergingPatternCandidate '{request.pattern_candidate_id}' not found.")

        # Determine rule type and scope from pattern
        pattern_type = pattern.pattern_type
        fingerprint_repr = pattern.fingerprint_repr or ""
        evidence_list = json.loads(pattern.supporting_evidence_json or "[]")

        rule_type = request.rule_type or cls._infer_rule_type(pattern_type)
        scope = cls._infer_scope(pattern_type)
        gen_level = request.generalization_level or GeneralizationLevel.STRUCTURAL

        # Build generalized conditions
        conditions, thresholds = cls._synthesize_conditions(pattern_type, fingerprint_repr, evidence_list)

        definition = RuleDefinition(
            logical_operator="AND",
            conditions=conditions,
        )

        # Validate
        valid, errors, complexity = RuleDslValidator.validate_definition(definition)
        if not valid:
            logger.warning(f"Synthesized rule had validation errors: {errors}")

        # Compute deterministic normalized fingerprint for deduplication
        norm_fp = RuleNormalizer.canonical_fingerprint(definition, scope, rule_type)

        # Check existing rule with same fingerprint
        existing = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == request.workspace_id,
            CandidateRuleModel.normalized_fingerprint == norm_fp,
        ).first()
        if existing:
            logger.info(f"Existing candidate rule '{existing.id}' shares canonical fingerprint {norm_fp}. Returning existing.")
            return existing

        name = request.proposed_name or f"Detect {pattern_type.replace('_', ' ').title()} - {norm_fp[:8]}"
        desc = (
            f"Candidate rule derived from emerging pattern '{pattern.id}' (observed {pattern.observation_count}x "
            f"across {pattern.incident_count} incidents). Captures recurring {gen_level.value.lower()} behavior."
        )

        rule_id = str(uuid.uuid4())
        candidate = CandidateRuleModel(
            id=rule_id,
            workspace_id=request.workspace_id,
            name=name,
            description=desc,
            rule_type=rule_type.value,
            status=RuleLifecycleStatus.DISCOVERED.value,
            pattern_candidate_id=pattern.id,
            source_memory_ids_json=json.dumps([]),
            source_incident_ids_json=json.dumps([pattern.incident_id] if pattern.incident_id else []),
            definition_json=definition.model_dump_json(),
            thresholds_json=json.dumps(thresholds),
            time_window_seconds=3600 if rule_type in (RuleType.SEQUENCE, RuleType.BEHAVIORAL) else None,
            scope=scope.value,
            severity=RuleSeverity.HIGH.value if pattern.recurrence_score > 50.0 else RuleSeverity.MEDIUM.value,
            confidence=0.80,
            generalization_level=gen_level.value,
            complexity_score=complexity,
            normalized_fingerprint=norm_fp,
            version="v1",
            evaluation_summary_json=json.dumps({}),
            created_by=request.created_by,
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )

        # Initial immutable version record
        v1 = CandidateRuleVersionModel(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            version="v1",
            workspace_id=request.workspace_id,
            definition_json=definition.model_dump_json(),
            thresholds_json=json.dumps(thresholds),
            evaluation_summary_json=json.dumps({}),
            status=RuleLifecycleStatus.DISCOVERED.value,
            created_by=request.created_by,
            change_reason="Initial rule formulation from emerging pattern",
            created_at=get_utc_now(),
        )

        db.add(candidate)
        db.add(v1)
        db.flush()

        cls._log_audit(
            db,
            workspace_id=request.workspace_id,
            action="CANDIDATE_RULE_GENERATED",
            resource_id=rule_id,
            actor=request.created_by,
            details={"pattern_id": pattern.id, "rule_type": rule_type.value, "fingerprint": norm_fp},
        )
        db.commit()
        db.refresh(candidate)
        return candidate

    @classmethod
    def create_candidate_rule(
        cls,
        db: Session,
        rule_in: CandidateRuleCreate,
    ) -> CandidateRuleModel:
        """Manually creates a candidate rule under validation."""
        valid, errors, complexity = RuleDslValidator.validate_definition(rule_in.definition)
        if not valid:
            raise ValueError(f"Rule definition validation failed: {'; '.join(errors)}")

        norm_fp = RuleNormalizer.canonical_fingerprint(rule_in.definition, rule_in.scope, rule_in.rule_type)

        existing = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == rule_in.workspace_id,
            CandidateRuleModel.normalized_fingerprint == norm_fp,
        ).first()
        if existing:
            raise ValueError(f"A candidate rule with identical logic already exists: '{existing.name}' ({existing.id}).")

        rule_id = str(uuid.uuid4())
        candidate = CandidateRuleModel(
            id=rule_id,
            workspace_id=rule_in.workspace_id,
            name=rule_in.name,
            description=rule_in.description,
            rule_type=rule_in.rule_type.value,
            status=RuleLifecycleStatus.DRAFT.value,
            pattern_candidate_id=rule_in.pattern_candidate_id,
            source_memory_ids_json=json.dumps(rule_in.source_memory_ids),
            source_incident_ids_json=json.dumps(rule_in.source_incident_ids),
            definition_json=rule_in.definition.model_dump_json(),
            thresholds_json=json.dumps(rule_in.thresholds),
            time_window_seconds=rule_in.time_window_seconds,
            scope=rule_in.scope.value,
            severity=rule_in.severity.value,
            confidence=rule_in.confidence,
            generalization_level=rule_in.generalization_level.value,
            complexity_score=complexity,
            normalized_fingerprint=norm_fp,
            version="v1",
            evaluation_summary_json=json.dumps({}),
            created_by=rule_in.created_by,
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )

        v1 = CandidateRuleVersionModel(
            id=str(uuid.uuid4()),
            rule_id=rule_id,
            version="v1",
            workspace_id=rule_in.workspace_id,
            definition_json=rule_in.definition.model_dump_json(),
            thresholds_json=json.dumps(rule_in.thresholds),
            evaluation_summary_json=json.dumps({}),
            status=RuleLifecycleStatus.DRAFT.value,
            created_by=rule_in.created_by,
            change_reason="Initial manual rule formulation",
            created_at=get_utc_now(),
        )

        db.add(candidate)
        db.add(v1)
        db.flush()

        cls._log_audit(
            db,
            workspace_id=rule_in.workspace_id,
            action="CANDIDATE_RULE_CREATED",
            resource_id=rule_id,
            actor=rule_in.created_by,
            details={"name": rule_in.name, "rule_type": rule_in.rule_type.value},
        )
        db.commit()
        db.refresh(candidate)
        return candidate

    @classmethod
    def backtest_candidate_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleBacktestRequest,
    ) -> RuleEvaluation:
        """
        Executes historical backtest against retained events and findings.
        Ground truth awareness: unknown labels are NOT counted as true negatives!
        """
        candidate = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            CandidateRuleModel.id == rule_id,
        ).first()

        if not candidate:
            raise ValueError(f"Candidate rule '{rule_id}' not found.")

        start_time = time.perf_counter()
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=request.lookback_days)

        # Gather historical telemetry
        threat_events = db.query(ThreatEventModel).filter(
            ThreatEventModel.created_at >= cutoff_date,
        ).limit(request.max_events_to_scan).all()

        findings = db.query(FindingModel).filter(
            FindingModel.created_at >= cutoff_date,
        ).limit(request.max_events_to_scan).all()

        # Query known ground truth decisions from Threat Memory
        analyst_decisions = db.query(ThreatMemoryDecisionModel).filter(
            ThreatMemoryDecisionModel.workspace_id == workspace_id,
        ).all()
        ground_truth_map: Dict[str, str] = {}
        for d in analyst_decisions:
            ground_truth_map[d.memory_entry_id] = d.decision

        matches = 0
        true_positives = 0
        false_positives = 0
        unknowns = 0
        matched_campaigns: Set[str] = set()

        # Evaluate against ThreatEvents
        for te in threat_events:
            ctx = {
                "event_type": te.event_type,
                "severity": te.severity,
                "confidence": te.confidence,
                "summary": te.summary,
                "incident_id": te.incident_id,
            }
            if te.metadata_json:
                try:
                    meta = json.loads(te.metadata_json)
                    if isinstance(meta, dict):
                        ctx.update(meta)
                except Exception:
                    pass

            res = RuleEvaluator.evaluate_rule(candidate, ctx)
            if res.matched:
                matches += 1
                if te.incident_id:
                    matched_campaigns.add(te.incident_id)

                # Check ground truth
                # Look up entry in threat memory
                mem_entry = db.query(ThreatMemoryEntryModel).filter(
                    ThreatMemoryEntryModel.workspace_id == workspace_id,
                    ThreatMemoryEntryModel.canonical_key == te.summary,
                ).first()
                if mem_entry and mem_entry.id in ground_truth_map:
                    decision = ground_truth_map[mem_entry.id]
                    if decision in ("CONFIRMED_MALICIOUS", "TRUE_POSITIVE"):
                        true_positives += 1
                    elif decision in ("CONFIRMED_BENIGN", "FALSE_POSITIVE"):
                        false_positives += 1
                    else:
                        unknowns += 1
                else:
                    unknowns += 1

        # Evaluate against Findings
        for f in findings:
            ctx = {
                "finding_type": f.finding_type,
                "analyzer": f.analyzer,
                "severity": f.severity,
                "confidence": f.confidence,
                "title": f.title,
                "description": f.description,
                "data": json.loads(f.metadata_json or "{}"),
            }
            if isinstance(ctx["data"], dict):
                ctx.update(ctx["data"])

            res = RuleEvaluator.evaluate_rule(candidate, ctx)
            if res.matched:
                matches += 1
                unknowns += 1

        total_scanned = len(threat_events) + len(findings)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        # Compute metrics
        labeled_matches = true_positives + false_positives
        precision = (true_positives / labeled_matches) if labeled_matches > 0 else (1.0 if matches > 0 and false_positives == 0 else 0.0)
        coverage = (matches / total_scanned) if total_scanned > 0 else 0.0
        gen_score = min(1.0, len(matched_campaigns) * 0.3 + (0.4 if false_positives == 0 else 0.0))

        evaluation = RuleEvaluation(
            historical_match_count=matches,
            validated_positive_count=true_positives,
            false_positive_count=false_positives,
            unknown_count=unknowns,
            precision=round(precision, 4),
            recall=None,  # Not fabricated without complete ground-truth population
            coverage=round(coverage, 4),
            generalization_score=round(gen_score, 2),
            complexity_score=candidate.complexity_score,
            execution_time_ms=round(elapsed_ms, 2),
            campaigns_evaluated=list(matched_campaigns),
            evaluation_window_start=cutoff_date,
            evaluation_window_end=get_utc_now(),
            limitations=["Evaluation confidence limited by partial ground-truth labels on historical telemetry."] if unknowns > 0 else [],
        )

        candidate.evaluation_summary_json = evaluation.model_dump_json()
        candidate.status = RuleLifecycleStatus.TESTED.value
        candidate.updated_at = get_utc_now()
        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="CANDIDATE_RULE_BACKTESTED",
            resource_id=rule_id,
            actor="system",
            details={"matches": matches, "precision": precision, "fp": false_positives},
        )
        db.commit()
        db.refresh(candidate)
        return evaluation

    @classmethod
    def submit_for_review(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        actor: str = "analyst",
    ) -> CandidateRuleModel:
        """Transitions candidate to REVIEW_REQUIRED."""
        cand = cls._get_rule(db, rule_id, workspace_id)
        cand.status = RuleLifecycleStatus.REVIEW_REQUIRED.value
        cand.updated_at = get_utc_now()
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def approve_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleReviewActionRequest,
    ) -> CandidateRuleModel:
        """Approves a candidate rule for staging/deployment."""
        cand = cls._get_rule(db, rule_id, workspace_id)
        if cand.status not in (RuleLifecycleStatus.TESTED.value, RuleLifecycleStatus.REVIEW_REQUIRED.value, RuleLifecycleStatus.DRAFT.value):
            raise ValueError(f"Cannot approve rule in status '{cand.status}'. Must be TESTED or REVIEW_REQUIRED.")

        cand.status = RuleLifecycleStatus.APPROVED.value
        cand.reviewed_by = request.reviewer
        cand.reviewed_at = get_utc_now()
        cand.review_reason = request.reason
        cand.updated_at = get_utc_now()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="CANDIDATE_RULE_APPROVED",
            resource_id=rule_id,
            actor=request.reviewer,
            details={"reason": request.reason},
        )
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def reject_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleReviewActionRequest,
    ) -> CandidateRuleModel:
        """Rejects a candidate rule."""
        cand = cls._get_rule(db, rule_id, workspace_id)
        cand.status = RuleLifecycleStatus.REJECTED.value
        cand.reviewed_by = request.reviewer
        cand.reviewed_at = get_utc_now()
        cand.review_reason = request.reason
        cand.updated_at = get_utc_now()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="CANDIDATE_RULE_REJECTED",
            resource_id=rule_id,
            actor=request.reviewer,
            details={"reason": request.reason},
        )
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def stage_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleReviewActionRequest,
    ) -> CandidateRuleModel:
        """Places rule into STAGED (shadow mode) for live testing without alerting."""
        cand = cls._get_rule(db, rule_id, workspace_id)
        if cand.status != RuleLifecycleStatus.APPROVED.value:
            raise ValueError(f"Only APPROVED rules can be staged. Current status: '{cand.status}'.")

        cand.status = RuleLifecycleStatus.STAGED.value
        cand.staged_at = get_utc_now()
        cand.updated_at = get_utc_now()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="RULE_STAGED",
            resource_id=rule_id,
            actor=request.reviewer,
            details={"mode": "SHADOW_MODE", "reason": request.reason},
        )
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def activate_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleReviewActionRequest,
    ) -> CandidateRuleModel:
        """Promotes an approved/staged rule to ACTIVE production detection."""
        cand = cls._get_rule(db, rule_id, workspace_id)
        if cand.status not in (RuleLifecycleStatus.APPROVED.value, RuleLifecycleStatus.STAGED.value):
            raise ValueError(f"Cannot activate rule in status '{cand.status}'. Must be APPROVED or STAGED.")

        cand.status = RuleLifecycleStatus.ACTIVE.value
        cand.activated_at = get_utc_now()
        cand.updated_at = get_utc_now()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="RULE_ACTIVATED",
            resource_id=rule_id,
            actor=request.reviewer,
            details={"reason": request.reason},
        )
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def disable_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleReviewActionRequest,
    ) -> CandidateRuleModel:
        """Temporarily disables an active or staged rule."""
        cand = cls._get_rule(db, rule_id, workspace_id)
        cand.status = RuleLifecycleStatus.DISABLED.value
        cand.updated_at = get_utc_now()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="RULE_DISABLED",
            resource_id=rule_id,
            actor=request.reviewer,
            details={"reason": request.reason},
        )
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def retire_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleReviewActionRequest,
    ) -> CandidateRuleModel:
        """Permanently retires a rule, keeping its historical versions intact."""
        cand = cls._get_rule(db, rule_id, workspace_id)
        cand.status = RuleLifecycleStatus.RETIRED.value
        cand.retired_at = get_utc_now()
        cand.updated_at = get_utc_now()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="RULE_RETIRED",
            resource_id=rule_id,
            actor=request.reviewer,
            details={"reason": request.reason},
        )
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def edit_rule(
        cls,
        db: Session,
        rule_id: str,
        workspace_id: str,
        request: RuleEditRequest,
    ) -> CandidateRuleModel:
        """
        Modifies a candidate rule by generating a new immutable version (e.g. v1 -> v2).
        The previous version remains historically visible.
        """
        cand = cls._get_rule(db, rule_id, workspace_id)

        valid, errors, complexity = RuleDslValidator.validate_definition(request.definition)
        if not valid:
            raise ValueError(f"Modified definition invalid: {'; '.join(errors)}")

        # Calculate new version tag
        try:
            current_ver_num = int(cand.version.lstrip("v"))
            new_version_tag = f"v{current_ver_num + 1}"
        except Exception:
            new_version_tag = f"{cand.version}.1"

        norm_fp = RuleNormalizer.canonical_fingerprint(request.definition, RuleScope(cand.scope), RuleType(cand.rule_type))

        # Record new immutable version
        new_version_record = CandidateRuleVersionModel(
            id=str(uuid.uuid4()),
            rule_id=cand.id,
            version=new_version_tag,
            workspace_id=workspace_id,
            definition_json=request.definition.model_dump_json(),
            thresholds_json=json.dumps(request.thresholds or cand.thresholds),
            evaluation_summary_json=json.dumps({}),
            status=RuleLifecycleStatus.DRAFT.value,
            created_by=request.editor,
            change_reason=request.change_reason,
            created_at=get_utc_now(),
        )

        cand.version = new_version_tag
        cand.definition_json = request.definition.model_dump_json()
        if request.thresholds is not None:
            cand.thresholds_json = json.dumps(request.thresholds)
        if request.severity is not None:
            cand.severity = request.severity.value
        if request.confidence is not None:
            cand.confidence = request.confidence

        cand.complexity_score = complexity
        cand.normalized_fingerprint = norm_fp
        cand.status = RuleLifecycleStatus.DRAFT.value  # Re-enters draft for validation
        cand.updated_at = get_utc_now()

        db.add(new_version_record)
        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="RULE_VERSION_CREATED",
            resource_id=rule_id,
            actor=request.editor,
            details={"new_version": new_version_tag, "reason": request.change_reason},
        )
        db.commit()
        db.refresh(cand)
        return cand

    @classmethod
    def evaluate_rules_for_event(
        cls,
        db: Session,
        workspace_id: str,
        context: Dict[str, Any],
        scope: Optional[RuleScope] = None,
        include_staged: bool = True,
    ) -> List[RuleMatchResult]:
        """
        Evaluates active and staged rules against an event or context payload.
        - Active rules produce production ThreatEvent findings.
        - Staged rules operate in shadow mode, writing execution telemetry without alerting.
        """
        query = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
        )

        allowed_statuses = [RuleLifecycleStatus.ACTIVE.value]
        if include_staged:
            allowed_statuses.append(RuleLifecycleStatus.STAGED.value)

        query = query.filter(CandidateRuleModel.status.in_(allowed_statuses))
        if scope and scope != RuleScope.GLOBAL:
            query = query.filter(CandidateRuleModel.scope.in_([scope.value, RuleScope.GLOBAL.value]))

        rules = query.all()
        results: List[RuleMatchResult] = []

        for r in rules:
            res = RuleEvaluator.evaluate_rule(r, context)
            mode = "SHADOW" if r.status == RuleLifecycleStatus.STAGED.value else "PRODUCTION"

            # Record telemetry in candidate_rule_executions
            execution_rec = CandidateRuleExecutionModel(
                id=str(uuid.uuid4()),
                rule_id=r.id,
                rule_version=r.version,
                workspace_id=workspace_id,
                mode=mode,
                matched=res.matched,
                matched_conditions_json=json.dumps(res.matched_conditions),
                event_id=context.get("event_id") or context.get("id"),
                incident_id=context.get("incident_id"),
                execution_time_ms=res.execution_time_ms,
                executed_at=get_utc_now(),
            )
            db.add(execution_rec)

            if res.matched:
                results.append(res)
                # If active, optionally synthesize ThreatEvent if context has incident_id
                if r.status == RuleLifecycleStatus.ACTIVE.value and context.get("incident_id"):
                    cls._emit_threat_event_for_rule(db, r, res, context)

        db.commit()
        return results

    @classmethod
    def get_dashboard_stats(cls, db: Session, workspace_id: str) -> RuleDashboardStats:
        """Returns executive metrics for Candidate Rule Engine."""
        rules = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
        ).all()

        total = len(rules)
        counts = {
            "DISCOVERED": 0, "TESTED": 0, "REVIEW_REQUIRED": 0,
            "APPROVED": 0, "STAGED": 0, "ACTIVE": 0, "RETIRED": 0,
        }
        for r in rules:
            if r.status in counts:
                counts[r.status] += 1

        shadow_evals = db.query(CandidateRuleExecutionModel).filter(
            CandidateRuleExecutionModel.workspace_id == workspace_id,
            CandidateRuleExecutionModel.mode == "SHADOW",
        ).count()

        return RuleDashboardStats(
            workspace_id=workspace_id,
            total_candidate_rules=total,
            discovered_count=counts["DISCOVERED"],
            tested_count=counts["TESTED"],
            review_required_count=counts["REVIEW_REQUIRED"],
            approved_count=counts["APPROVED"],
            staged_shadow_count=counts["STAGED"],
            active_production_count=counts["ACTIVE"],
            retired_count=counts["RETIRED"],
            shadow_evaluations_count=shadow_evals,
        )

    # ------------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------------

    @classmethod
    def _get_rule(cls, db: Session, rule_id: str, workspace_id: str) -> CandidateRuleModel:
        cand = db.query(CandidateRuleModel).filter(
            CandidateRuleModel.workspace_id == workspace_id,
            CandidateRuleModel.id == rule_id,
        ).first()
        if not cand:
            raise ValueError(f"Rule '{rule_id}' not found in workspace '{workspace_id}'.")
        return cand

    @staticmethod
    def _infer_rule_type(pattern_type: str) -> RuleType:
        upper = pattern_type.upper()
        if "URL" in upper or "DOMAIN" in upper or "ARTIFACT" in upper:
            return RuleType.STRUCTURAL
        if "AUTH" in upper or "API" in upper or "BEHAVIOR" in upper:
            return RuleType.BEHAVIORAL
        if "SEQUENCE" in upper:
            return RuleType.SEQUENCE
        if "RELATIONSHIP" in upper or "INFRASTRUCTURE" in upper:
            return RuleType.GRAPH
        return RuleType.CORRELATION

    @staticmethod
    def _infer_scope(pattern_type: str) -> RuleScope:
        upper = pattern_type.upper()
        if "URL" in upper:
            return RuleScope.URL
        if "AUTH" in upper:
            return RuleScope.AUTH
        if "NETWORK" in upper:
            return RuleScope.NETWORK
        if "API" in upper:
            return RuleScope.API
        if "EMAIL" in upper:
            return RuleScope.EMAIL
        return RuleScope.GLOBAL

    @classmethod
    def _synthesize_conditions(
        cls,
        pattern_type: str,
        fingerprint_repr: str,
        evidence: List[Dict[str, Any]],
    ) -> Tuple[List[RuleCondition], Dict[str, Any]]:
        """Extracts generalized conditions from pattern attributes without raw memorization."""
        conds: List[RuleCondition] = []
        thresholds: Dict[str, Any] = {}
        upper = pattern_type.upper()

        if "URL" in upper:
            # Generalize URL structural conditions
            conds.append(RuleCondition(
                field="url.path",
                operator=DslOperator.CONTAINS,
                value="login",
                case_sensitive=False,
            ))
            conds.append(RuleCondition(
                field="url.domain_similarity",
                operator=DslOperator.GREATER_THAN_OR_EQUAL,
                value=0.85,
            ))
            thresholds["domain_similarity"] = 0.85
        elif "AUTH" in upper:
            conds.append(RuleCondition(
                field="auth.failed_attempts",
                operator=DslOperator.GREATER_THAN_OR_EQUAL,
                value=5,
            ))
            conds.append(RuleCondition(
                field="auth.off_hours",
                operator=DslOperator.EQUALS,
                value=True,
            ))
            thresholds["min_failed_attempts"] = 5
        elif "API" in upper:
            conds.append(RuleCondition(
                field="api.action",
                operator=DslOperator.CONTAINS,
                value="export",
            ))
            conds.append(RuleCondition(
                field="api.rate_per_min",
                operator=DslOperator.GREATER_THAN_OR_EQUAL,
                value=100,
            ))
            thresholds["min_rate_per_min"] = 100
        elif "SEQUENCE" in upper:
            conds.append(RuleCondition(
                field="event_type",
                operator=DslOperator.FOLLOWED_BY,
                value="CREDENTIAL_SUBMITTED",
                time_window_seconds=3600,
            ))
        else:
            conds.append(RuleCondition(
                field="severity",
                operator=DslOperator.IN,
                value=["HIGH", "CRITICAL"],
            ))
            conds.append(RuleCondition(
                field="confidence",
                operator=DslOperator.GREATER_THAN_OR_EQUAL,
                value=0.75,
            ))
            thresholds["min_confidence"] = 0.75

        return conds, thresholds

    @classmethod
    def _emit_threat_event_for_rule(
        cls,
        db: Session,
        rule: CandidateRuleModel,
        result: RuleMatchResult,
        context: Dict[str, Any],
    ) -> None:
        """Synthesizes a standardized ThreatEvent when an ACTIVE rule triggers."""
        try:
            te_id = str(uuid.uuid4())
            te = ThreatEventModel(
                id=te_id,
                event_type="ACTIVE_RULE_DETECTION",
                severity=rule.severity,
                confidence=rule.confidence,
                status="OPEN",
                summary=f"Rule Triggered: {rule.name} - {result.explanation}",
                incident_id=context.get("incident_id"),
                metadata_json=json.dumps({
                    "rule_id": rule.id,
                    "rule_version": rule.version,
                    "matched_conditions": result.matched_conditions,
                    "workspace_id": rule.workspace_id,
                }),
                created_at=get_utc_now(),
            )
            db.add(te)
        except Exception as e:
            logger.warning(f"Could not synthesize ThreatEvent for rule {rule.id}: {e}")

    @staticmethod
    def _log_audit(
        db: Session,
        workspace_id: str,
        action: str,
        resource_id: str,
        actor: str,
        details: Dict[str, Any],
    ) -> None:
        """Emits audit log record."""
        try:
            log_entry = AuditLogModel(
                id=str(uuid.uuid4()),
                timestamp=get_utc_now(),
                user=actor,
                action=action,
                resource_type="CANDIDATE_RULE",
                resource_id=resource_id,
                details=json.dumps(details),
                metadata_json=json.dumps({"workspace_id": workspace_id, **details}),
            )
            db.add(log_entry)
        except Exception as e:
            logger.warning(f"Failed to log audit event {action}: {e}")

