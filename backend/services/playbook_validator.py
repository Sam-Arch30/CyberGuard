"""
Section 29: Response Playbook Validator, Linter, and Safe Condition Evaluator.
Guarantees:
1. Structural integrity and DAG acyclicity.
2. Controlled step types allowlisting (zero arbitrary code execution).
3. Bounded timeouts and retries.
4. Safe typed condition evaluation without eval() or runtime injection.
5. Admin/Analyst linting notices for missing verification or unconstrained targets.
"""

from __future__ import annotations
import logging
from typing import Dict, Any, List, Set, Tuple, Optional
from sqlalchemy.orm import Session

from backend.schemas.response_playbook import (
    StepTypeEnum,
    SafetyClassEnum,
    ApprovalPolicyEnum,
    PlaybookValidationResult,
    ResponsePlaybookCreate
)
from backend.services.playbook_adapters import ADAPTER_REGISTRY, get_adapter_for_step_type

logger = logging.getLogger(__name__)


# ============================================================================
# SAFE CONDITION EVALUATOR (NO EVAL / ARBITRARY CODE)
# ============================================================================

def evaluate_safe_condition(condition: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Safely evaluates a structured condition against execution context.
    Strictly forbids eval(), exec(), or arbitrary code.
    Condition schema:
    {
      "field": "risk_score",
      "operator": ">=",
      "value": 75
    }
    """
    if not condition:
        return True  # Empty condition always passes

    field = condition.get("field")
    operator = condition.get("operator", "==")
    expected_value = condition.get("value")

    if not field:
        return True

    # Resolve context value safely
    actual_value = context.get(field)
    if actual_value is None:
        # Check sub-keys (e.g. previous_step.status)
        if "." in field:
            parts = field.split(".")
            curr = context
            for p in parts:
                if isinstance(curr, dict):
                    curr = curr.get(p)
                else:
                    curr = None
                    break
            actual_value = curr

    if actual_value is None:
        return False

    try:
        if operator == "==":
            return actual_value == expected_value
        elif operator == "!=":
            return actual_value != expected_value
        elif operator == ">":
            return float(actual_value) > float(expected_value)
        elif operator == ">=":
            return float(actual_value) >= float(expected_value)
        elif operator == "<":
            return float(actual_value) < float(expected_value)
        elif operator == "<=":
            return float(actual_value) <= float(expected_value)
        elif operator == "in":
            return actual_value in expected_value if isinstance(expected_value, (list, set, tuple)) else False
        elif operator == "not_in":
            return actual_value not in expected_value if isinstance(expected_value, (list, set, tuple)) else True
        elif operator == "contains":
            return expected_value in actual_value if isinstance(actual_value, (list, set, str)) else False
        else:
            logger.warning(f"Unsupported operator '{operator}' in condition evaluation.")
            return False
    except Exception as e:
        logger.warning(f"Error evaluating condition ({field} {operator} {expected_value}): {e}")
        return False


# ============================================================================
# PLAYBOOK VALIDATOR & LINTER
# ============================================================================

class PlaybookValidator:
    """
    Deterministic validator and linter for Response Playbooks.
    """

    MAX_STEP_TIMEOUT = 300       # 5 minutes per step
    MAX_PLAYBOOK_TIMEOUT = 1800  # 30 minutes total
    MAX_RETRY_ATTEMPTS = 5

    @classmethod
    def validate_and_lint(
        cls,
        playbook_data: Dict[str, Any],
        db: Optional[Session] = None
    ) -> PlaybookValidationResult:
        """
        Validates structural requirements, safety boundaries, DAG dependencies,
        and produces informative linter warnings.
        """
        errors: List[str] = []
        warnings: List[str] = []
        lint_notices: List[str] = []

        # 1. Structural Checks
        playbook_key = playbook_data.get("playbook_key", "").strip()
        if not playbook_key:
            errors.append("playbook_key cannot be empty.")

        name = playbook_data.get("name", "").strip()
        if not name:
            errors.append("Playbook name cannot be empty.")

        version = playbook_data.get("version", 1)
        if version < 1:
            errors.append("Playbook version must be >= 1.")

        timeout = playbook_data.get("timeout_seconds", 300)
        if timeout <= 0 or timeout > cls.MAX_PLAYBOOK_TIMEOUT:
            errors.append(f"Playbook timeout_seconds must be between 1 and {cls.MAX_PLAYBOOK_TIMEOUT}.")

        steps = playbook_data.get("steps", [])
        if not steps:
            errors.append("Playbook must contain at least one step.")

        step_keys: Set[str] = set()
        step_deps: Dict[str, List[str]] = {}

        for idx, s in enumerate(steps, start=1):
            if isinstance(s, dict):
                s_dict = s
            elif hasattr(s, "model_dump"):
                s_dict = s.model_dump()
            elif hasattr(s, "dict"):
                s_dict = s.dict()
            else:
                s_dict = {
                    "step_key": getattr(s, "step_key", ""),
                    "sequence": getattr(s, "sequence", 1),
                    "step_type": getattr(s, "step_type", ""),
                    "name": getattr(s, "name", ""),
                    "description": getattr(s, "description", ""),
                    "parameters": getattr(s, "parameters", {}),
                    "target_selector": getattr(s, "target_selector", {}),
                    "condition": getattr(s, "condition", {}),
                    "on_success": getattr(s, "on_success", "CONTINUE"),
                    "on_failure": getattr(s, "on_failure", "FAIL"),
                    "timeout_seconds": getattr(s, "timeout_seconds", 60),
                    "retry_policy": getattr(s, "retry_policy", {}),
                    "requires_approval": getattr(s, "requires_approval", False),
                    "approval_policy": getattr(s, "approval_policy", "NO_APPROVAL"),
                    "safety_class": getattr(s, "safety_class", "INFORMATIONAL"),
                    "verification_policy": getattr(s, "verification_policy", {}),
                    "rollback_policy": getattr(s, "rollback_policy", {}),
                    "depends_on": getattr(s, "depends_on", []),
                    "enabled": getattr(s, "enabled", True)
                }
            s_key = s_dict.get("step_key", "").strip()
            s_type = s_dict.get("step_type", "")

            # Check unique key
            if not s_key:
                errors.append(f"Step at index {idx} missing step_key.")
            elif s_key in step_keys:
                errors.append(f"Duplicate step_key '{s_key}' found in playbook.")
            else:
                step_keys.add(s_key)

            # Check allowlisted step type
            valid_types = [t.value for t in StepTypeEnum]
            if s_type not in valid_types:
                errors.append(f"Step '{s_key}': Unknown step_type '{s_type}'. Arbitrary code/untyped steps are prohibited.")

            adapter_cls = get_adapter_for_step_type(s_type)
            if not adapter_cls:
                errors.append(f"Step '{s_key}': No authorized adapter registered for step_type '{s_type}'.")

            # Check safety classes and approval requirements
            safety = s_dict.get("safety_class", SafetyClassEnum.INFORMATIONAL.value)
            requires_appr = s_dict.get("requires_approval", False)
            if safety in [SafetyClassEnum.CONTAINMENT.value, SafetyClassEnum.HIGH_IMPACT.value, SafetyClassEnum.DESTRUCTIVE.value]:
                if not requires_appr:
                    errors.append(f"Step '{s_key}': High-impact or containment step ({safety}) must require approval (requires_approval=True).")

            # Check timeouts
            s_timeout = s_dict.get("timeout_seconds", 60)
            if s_timeout <= 0 or s_timeout > cls.MAX_STEP_TIMEOUT:
                errors.append(f"Step '{s_key}': Step timeout must be between 1 and {cls.MAX_STEP_TIMEOUT} seconds.")

            # Check retries
            retry = s_dict.get("retry_policy", {})
            max_att = retry.get("max_attempts", 1) if isinstance(retry, dict) else retry.max_attempts
            if max_att < 1 or max_att > cls.MAX_RETRY_ATTEMPTS:
                errors.append(f"Step '{s_key}': Retry policy max_attempts must be bounded between 1 and {cls.MAX_RETRY_ATTEMPTS}.")

            # Collect dependencies for DAG check
            deps = s_dict.get("depends_on", [])
            step_deps[s_key] = deps

            # Linter Notices
            v_policy = s_dict.get("verification_policy", {})
            v_enabled = v_policy.get("enabled", True) if isinstance(v_policy, dict) else getattr(v_policy, "enabled", True)
            if not v_enabled:
                lint_notices.append(f"Notice: Step '{s_key}' has verification disabled.")

            rb_policy = s_dict.get("rollback_policy", {})
            rb_supported = rb_policy.get("supports_rollback", False) if isinstance(rb_policy, dict) else getattr(rb_policy, "supports_rollback", False)
            if safety in [SafetyClassEnum.CONTAINMENT.value, SafetyClassEnum.HIGH_IMPACT.value] and not rb_supported:
                warnings.append(f"Warning: Step '{s_key}' is high-impact but declares no rollback policy.")

            target_sel = s_dict.get("target_selector", {})
            if not target_sel:
                lint_notices.append(f"Notice: Step '{s_key}' relies entirely on runtime target inheritance.")

        # 2. Dependency Graph & Circular Dependency Detection
        for s_key, deps in step_deps.items():
            for d in deps:
                if d not in step_keys:
                    errors.append(f"Step '{s_key}' depends on non-existent step '{d}'.")
                elif d == s_key:
                    errors.append(f"Step '{s_key}' cannot depend on itself.")

        if not errors:
            has_cycle, cycle_path = cls._check_cycles(step_deps)
            if has_cycle:
                errors.append(f"Circular dependency detected in playbook step sequence: {' -> '.join(cycle_path)}")

        is_valid = len(errors) == 0
        return PlaybookValidationResult(
            valid=is_valid,
            errors=errors,
            warnings=warnings,
            lint_notices=lint_notices
        )

    @classmethod
    def _check_cycles(cls, graph: Dict[str, List[str]]) -> Tuple[bool, List[str]]:
        """DFS cycle detection in dependency DAG."""
        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        path: List[str] = []

        def dfs(node: str) -> bool:
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for neighbor in graph.get(node, []):
                if neighbor not in visited:
                    if dfs(neighbor):
                        return True
                elif neighbor in rec_stack:
                    path.append(neighbor)
                    return True

            rec_stack.remove(node)
            path.pop()
            return False

        for n in graph:
            if n not in visited:
                if dfs(n):
                    return True, path

        return False, []
