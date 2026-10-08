"""
Baseline Context & Exception Manager (Section 21).

Manages entity profile categories (Service Accounts, Administrators, Human Users)
and contextual exceptions (Maintenance windows, Authorized VPNs, Approved travel, Pen-tests).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from backend.schemas.behavioral_baseline import (
    BaselineEntityType,
    BaselineException,
    BaselineMetricType,
    EntityProfileCategory,
)


class BaselineContextManager:
    """
    Applies contextual profile policies and manages auditable exceptions.
    """

    # In-memory storage for active exceptions (backed by database or memory during tests)
    _active_exceptions: List[BaselineException] = []

    @classmethod
    def register_exception(cls, exception_record: BaselineException) -> None:
        """Registers an explicit, auditable exception."""
        cls._active_exceptions.append(exception_record)

    @classmethod
    def get_active_exceptions(
        cls,
        entity_type: BaselineEntityType,
        entity_id: str,
        metric_type: Optional[BaselineMetricType] = None,
        at_time: Optional[datetime] = None,
    ) -> List[BaselineException]:
        """Finds active exceptions matching the entity and time window."""
        check_time = at_time or datetime.now(timezone.utc)
        matched: List[BaselineException] = []

        for exc in cls._active_exceptions:
            if not exc.is_active:
                continue
            if exc.entity_type != entity_type:
                continue
            if exc.entity_id.lower() != entity_id.lower() and exc.entity_id != "*":
                continue
            if exc.metric_type and metric_type and exc.metric_type != metric_type:
                continue

            # Check time range
            start = exc.valid_from
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if check_time < start:
                continue
            if exc.valid_until:
                end = exc.valid_until
                if end.tzinfo is None:
                    end = end.replace(tzinfo=timezone.utc)
                if check_time > end:
                    continue

            matched.append(exc)

        return matched

    @classmethod
    def apply_contextual_policy(
        cls,
        category: EntityProfileCategory,
        metric_type: BaselineMetricType,
        observed_value: Any,
        raw_deviation_score: float,
        explanation: str,
    ) -> Tuple[float, str, List[str]]:
        """
        Adjusts deviation score and explanation based on entity category
        (e.g. Service accounts running 24/7 or administrators accessing resources).
        """
        limitations: List[str] = []

        if category == EntityProfileCategory.SERVICE_ACCOUNT:
            limitations.append("Entity classified as automated service account; adjusted for machine execution.")
            # Service accounts operating overnight or with high request frequency is standard behavior
            if metric_type in (BaselineMetricType.LOGIN_HOUR, BaselineMetricType.LOGIN_DAY_PATTERN):
                return 0.0, f"Service account continuous execution: {explanation}", limitations
            elif metric_type == BaselineMetricType.API_REQUEST_RATE:
                # Moderate suppression of burst rates for machine clients
                adjusted_score = max(0.0, raw_deviation_score - 0.3)
                return adjusted_score, f"Service account API rate: {explanation}", limitations

        elif category == EntityProfileCategory.ADMINISTRATOR:
            limitations.append("Entity has administrative privileges; broad access context considered.")
            if metric_type == BaselineMetricType.RESOURCE_ACCESS_FREQUENCY:
                adjusted_score = max(0.0, raw_deviation_score - 0.2)
                return adjusted_score, f"Administrative resource access: {explanation}", limitations

        return raw_deviation_score, explanation, limitations
