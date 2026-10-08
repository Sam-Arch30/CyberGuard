"""
Behavioral Baseline Engine (Section 21).

Coordinates entity-specific baseline creation, persistence, robust statistical evaluation,
outlier handling, poisoning protection, lifecycle freezing/relearning, and deviation scoring.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import math
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy.orm import Session

from backend.db.models import (
    BehavioralBaselineModel,
    BehavioralDeviationModel,
    BaselineAuditModel,
    SecurityEventModel,
)
from backend.schemas.behavioral_baseline import (
    BaselineConfidenceLevel,
    BaselineEntityType,
    BaselineException,
    BaselineMetricType,
    BaselinePercentiles,
    BaselineQuality,
    BaselineWindowType,
    BehavioralBaseline,
    BehavioralDeviation,
    CircularHourDistribution,
    DeviationDirection,
    EntityProfileCategory,
    LearningMode,
    validate_feature_privacy,
)
from backend.services.behavioral_feature_extractor import (
    BehavioralFeatureExtractor,
    ExtractedFeatureObservation,
)
from backend.services.behavioral_statistics import BehavioralStatisticsEngine
from backend.services.baseline_poisoning_guard import BaselinePoisoningGuard
from backend.services.baseline_context_manager import BaselineContextManager


class BehavioralBaselineService:
    """
    Core service managing entity behavioral baselines and deviation evaluations.
    """

    # In-memory baseline cache for sub-millisecond retrieval
    _baseline_cache: Dict[str, BehavioralBaseline] = {}

    @classmethod
    def _cache_key(cls, workspace_id: str, entity_type: str, entity_id: str, metric_type: str) -> str:
        return f"{workspace_id}:{entity_type.upper()}:{entity_id.lower()}:{metric_type.upper()}"

    @classmethod
    def get_baseline_from_db(
        cls,
        session: Session,
        entity_type: BaselineEntityType,
        entity_id: str,
        metric_type: BaselineMetricType,
        workspace_id: str = "default",
    ) -> Optional[BehavioralBaseline]:
        """Retrieves existing baseline record from database."""
        etype_str = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
        mtype_str = metric_type.value if hasattr(metric_type, "value") else str(metric_type)

        model = session.query(BehavioralBaselineModel).filter(
            BehavioralBaselineModel.workspace_id == workspace_id,
            BehavioralBaselineModel.entity_type == etype_str,
            BehavioralBaselineModel.entity_id == entity_id.lower(),
            BehavioralBaselineModel.metric_type == mtype_str,
        ).first()

        if not model:
            return None

        return cls._model_to_schema(model)

    @classmethod
    def _model_to_schema(cls, model: BehavioralBaselineModel) -> BehavioralBaseline:
        percentiles = None
        if model.percentiles_json:
            try:
                p_dict = json.loads(model.percentiles_json)
                percentiles = BaselinePercentiles(**p_dict)
            except Exception:
                pass

        cat_dist = {}
        circ_dist = None
        if model.distribution_json:
            try:
                dist_data = json.loads(model.distribution_json)
                if model.metric_type == BaselineMetricType.LOGIN_HOUR.value:
                    circ_dist = CircularHourDistribution(**dist_data)
                else:
                    cat_dist = dist_data
            except Exception:
                pass

        return BehavioralBaseline(
            id=model.id,
            workspace_id=model.workspace_id,
            entity_type=BaselineEntityType(model.entity_type),
            entity_id=model.entity_id,
            entity_category=EntityProfileCategory(model.entity_category),
            metric_type=BaselineMetricType(model.metric_type),
            metric_version=model.metric_version,
            window_type=BaselineWindowType(model.window_type),
            window_start=model.window_start,
            window_end=model.window_end,
            sample_count=model.sample_count,
            valid_sample_count=model.valid_sample_count,
            missing_sample_count=model.missing_sample_count,
            median_value=model.median_value,
            mean_value=model.mean_value,
            standard_deviation=model.std_dev,
            mad=model.mad_value,
            percentiles=percentiles,
            minimum=model.min_value,
            maximum=model.max_value,
            categorical_distribution=cat_dist,
            circular_hour_distribution=circ_dist,
            expected_range_summary=model.expected_range_summary,
            confidence_score=model.confidence_score,
            confidence_level=BaselineConfidenceLevel(model.confidence_level),
            quality_status=BaselineQuality(model.quality_status),
            learning_mode=LearningMode(model.learning_mode),
            is_frozen=model.is_frozen,
            frozen_reason=model.frozen_reason,
            frozen_by=model.frozen_by,
            frozen_at=model.frozen_at,
            baseline_version=model.baseline_version,
            feature_version=model.feature_version,
            calculation_method=model.calculation_method,
            configuration_version=model.configuration_version,
            source_count=model.source_count,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    @classmethod
    def build_baseline(
        cls,
        session: Session,
        entity_type: BaselineEntityType,
        entity_id: str,
        metric_type: BaselineMetricType,
        window_days: int = 30,
        workspace_id: str = "default",
        force_recalculate: bool = False,
    ) -> BehavioralBaseline:
        """
        Builds or recalculates an entity baseline from persisted SecurityEventModel records.
        Applies robust statistics and outlier/poisoning protection.
        """
        etype_str = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
        mtype_str = metric_type.value if hasattr(metric_type, "value") else str(metric_type)
        norm_entity_id = entity_id.strip().lower()

        # Check existing model
        existing = session.query(BehavioralBaselineModel).filter(
            BehavioralBaselineModel.workspace_id == workspace_id,
            BehavioralBaselineModel.entity_type == etype_str,
            BehavioralBaselineModel.entity_id == norm_entity_id,
            BehavioralBaselineModel.metric_type == mtype_str,
        ).first()

        # If frozen and not explicitly forced, preserve existing frozen state
        if existing and existing.is_frozen and not force_recalculate:
            return cls._model_to_schema(existing)

        now = datetime.now(timezone.utc)
        window_start = now - timedelta(days=window_days)

        # 1. Query candidate historical security events (indexed on entity_time)
        events = session.query(SecurityEventModel).filter(
            SecurityEventModel.workspace_id == workspace_id,
            SecurityEventModel.event_time >= window_start.replace(tzinfo=None),
        ).order_by(SecurityEventModel.event_time.asc()).limit(1000).all()

        # Filter events for entity
        entity_events: List[SecurityEventModel] = []
        for ev in events:
            # Check entity IDs json
            ent_list = []
            if ev.entity_ids_json:
                try:
                    ent_list = [str(x).lower() for x in json.loads(ev.entity_ids_json)]
                except Exception:
                    pass
            if norm_entity_id in ent_list:
                entity_events.append(ev)
                continue

            # Fallback: check attributes_json
            if ev.attributes_json:
                try:
                    attr = json.loads(ev.attributes_json)
                    account_val = attr.get("account_id") or attr.get("user") or attr.get("source_ip") or attr.get("ip")
                    if account_val and str(account_val).lower() == norm_entity_id:
                        entity_events.append(ev)
                except Exception:
                    pass

        # 2. Extract feature observations
        raw_obs: List[ExtractedFeatureObservation] = []
        for ev in entity_events:
            obs_list = BehavioralFeatureExtractor.extract_from_security_event_model(ev)
            for o in obs_list:
                if o.metric_type == metric_type and o.entity_id.lower() == norm_entity_id:
                    raw_obs.append(o)

        # 3. Filter out contaminated events (poisoning protection)
        clean_obs, rejected = BaselinePoisoningGuard.filter_clean_observations(raw_obs, session=session)

        # 4. Infer entity category
        entity_category = BehavioralFeatureExtractor.infer_entity_category(norm_entity_id)

        sample_count = len(clean_obs)
        quality, conf_score, conf_level = BehavioralStatisticsEngine.assess_baseline_quality(
            sample_count=sample_count,
            window_start=clean_obs[0].event_time if clean_obs else None,
            window_end=clean_obs[-1].event_time if clean_obs else None,
            missing_count=len(rejected),
        )

        learning_mode = LearningMode.STABLE if quality == BaselineQuality.STABLE else LearningMode.LEARNING

        # 5. Compute statistical distributions
        median_val: Optional[float] = None
        mean_val: Optional[float] = None
        std_val: Optional[float] = None
        mad_val: Optional[float] = None
        percentiles: Optional[BaselinePercentiles] = None
        cat_dist: Dict[str, int] = {}
        circ_dist: Optional[CircularHourDistribution] = None
        expected_range_str = "Insufficient history"

        if sample_count > 0:
            # Numerical metric path
            if metric_type in (
                BaselineMetricType.LOGIN_HOUR,
                BaselineMetricType.AUTH_FAILURE_RATE,
                BaselineMetricType.OUTBOUND_BYTES,
                BaselineMetricType.INBOUND_BYTES,
                BaselineMetricType.API_RESPONSE_VOLUME,
                BaselineMetricType.NETWORK_PORT_FREQUENCY,
                BaselineMetricType.LOGIN_DAY_PATTERN,
            ):
                num_vals = [o.numeric_value for o in clean_obs if o.numeric_value is not None]
                if num_vals:
                    # Winsorize to remove extreme leverage
                    clean_nums = BehavioralStatisticsEngine.winsorize(num_vals)
                    median_val = BehavioralStatisticsEngine.calculate_median(clean_nums)
                    mean_val = float(sum(clean_nums) / len(clean_nums))
                    mad_val = BehavioralStatisticsEngine.calculate_mad(clean_nums, median=median_val)
                    percentiles = BehavioralStatisticsEngine.calculate_percentiles(clean_nums)

                    if len(clean_nums) > 1:
                        var = sum((x - mean_val) ** 2 for x in clean_nums) / (len(clean_nums) - 1)
                        std_val = float(math.sqrt(var))
                    else:
                        std_val = 0.0

                    if metric_type == BaselineMetricType.LOGIN_HOUR:
                        circ_dist = BehavioralStatisticsEngine.build_circular_hour_distribution(num_vals)
                        if circ_dist.active_hours:
                            expected_range_str = f"Active hours: {min(circ_dist.active_hours):02d}:00–{max(circ_dist.active_hours):02d}:59"
                    else:
                        expected_range_str = f"Median={median_val:.2f}, MAD={mad_val:.2f}"

            # Categorical metric path
            cat_vals = [o.categorical_value for o in clean_obs if o.categorical_value]
            if cat_vals:
                for c in cat_vals:
                    cat_dist[c] = cat_dist.get(c, 0) + 1
                if metric_type != BaselineMetricType.LOGIN_HOUR:
                    top_items = sorted(cat_dist.items(), key=lambda x: x[1], reverse=True)[:3]
                    expected_range_str = f"Known: {', '.join(k for k, _ in top_items)}"

        dist_json_str = "{}"
        if circ_dist:
            dist_json_str = circ_dist.model_dump_json()
        elif cat_dist:
            dist_json_str = json.dumps(cat_dist)

        perc_json_str = percentiles.model_dump_json() if percentiles else "{}"

        # 6. Save or update DB record
        if not existing:
            baseline_id = str(uuid.uuid4())
            existing = BehavioralBaselineModel(
                id=baseline_id,
                workspace_id=workspace_id,
                entity_type=etype_str,
                entity_id=norm_entity_id,
                entity_category=entity_category.value,
                metric_type=mtype_str,
                window_type=f"ROLLING_{window_days}D",
                window_start=window_start.replace(tzinfo=None),
                window_end=now.replace(tzinfo=None),
                sample_count=sample_count,
                valid_sample_count=sample_count,
                missing_sample_count=len(rejected),
                median_value=median_val,
                mean_value=mean_val,
                std_dev=std_val,
                mad_value=mad_val,
                percentiles_json=perc_json_str,
                distribution_json=dist_json_str,
                expected_range_summary=expected_range_str,
                confidence_score=conf_score,
                confidence_level=conf_level.value,
                quality_status=quality.value,
                learning_mode=learning_mode.value,
                is_frozen=False,
                baseline_version="1.0.0",
                feature_version="1.0.0",
                calculation_method="ROBUST_STATISTICS",
                configuration_version="2026.10",
                source_count=len(entity_events),
            )
            session.add(existing)
        else:
            existing.window_start = window_start.replace(tzinfo=None)
            existing.window_end = now.replace(tzinfo=None)
            existing.sample_count = sample_count
            existing.valid_sample_count = sample_count
            existing.missing_sample_count = len(rejected)
            existing.median_value = median_val
            existing.mean_value = mean_val
            existing.std_dev = std_val
            existing.mad_value = mad_val
            existing.percentiles_json = perc_json_str
            existing.distribution_json = dist_json_str
            existing.expected_range_summary = expected_range_str
            existing.confidence_score = conf_score
            existing.confidence_level = conf_level.value
            existing.quality_status = quality.value
            existing.learning_mode = learning_mode.value
            existing.source_count = len(entity_events)

        session.commit()
        session.refresh(existing)

        schema_obj = cls._model_to_schema(existing)
        cache_k = cls._cache_key(workspace_id, etype_str, norm_entity_id, mtype_str)
        cls._baseline_cache[cache_k] = schema_obj
        return schema_obj

    @classmethod
    def get_or_create_baseline(
        cls,
        session: Session,
        entity_type: BaselineEntityType,
        entity_id: str,
        metric_type: BaselineMetricType,
        window_days: int = 30,
        workspace_id: str = "default",
    ) -> BehavioralBaseline:
        """Retrieves active baseline from cache/DB or builds on demand."""
        etype_str = entity_type.value if hasattr(entity_type, "value") else str(entity_type)
        mtype_str = metric_type.value if hasattr(metric_type, "value") else str(metric_type)
        norm_entity_id = entity_id.strip().lower()

        cache_k = cls._cache_key(workspace_id, etype_str, norm_entity_id, mtype_str)
        if cache_k in cls._baseline_cache:
            return cls._baseline_cache[cache_k]

        existing = cls.get_baseline_from_db(
            session=session,
            entity_type=entity_type,
            entity_id=norm_entity_id,
            metric_type=metric_type,
            workspace_id=workspace_id,
        )
        if existing:
            cls._baseline_cache[cache_k] = existing
            return existing

        return cls.build_baseline(
            session=session,
            entity_type=entity_type,
            entity_id=norm_entity_id,
            metric_type=metric_type,
            window_days=window_days,
            workspace_id=workspace_id,
        )

    @classmethod
    def evaluate_deviation(
        cls,
        session: Session,
        baseline: BehavioralBaseline,
        observed_value: Union[float, int, str],
        event_time: Optional[datetime] = None,
        incident_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
    ) -> Optional[BehavioralDeviation]:
        """
        Evaluates an observed value against an established baseline.
        Returns BehavioralDeviation if anomalous, or None if completely normal.
        """
        check_time = event_time or datetime.now(timezone.utc)
        evidence_list = evidence_ids or []

        # 1. Handle Insufficient History
        if baseline.quality_status in (BaselineQuality.NO_DATA, BaselineQuality.INSUFFICIENT_HISTORY):
            return BehavioralDeviation(
                id=str(uuid.uuid4()),
                baseline_id=baseline.id,
                incident_id=incident_id,
                investigation_id=investigation_id,
                workspace_id=baseline.workspace_id,
                entity_type=baseline.entity_type,
                entity_id=baseline.entity_id,
                metric_type=baseline.metric_type,
                observed_value=str(observed_value),
                expected_range_summary="Insufficient historical data (< 5 events)",
                deviation_score=0.0,
                deviation_direction=DeviationDirection.CHANGED,
                severity_hint="LOW",
                baseline_confidence=baseline.confidence_score,
                baseline_quality=baseline.quality_status,
                evidence_ids=evidence_list,
                explanation="No baseline deviation assessed: insufficient historical telemetry to establish normal patterns.",
                limitations=["Insufficient history; baseline is in learning state."],
            )

        # 2. Check Contextual Exceptions
        exceptions = BaselineContextManager.get_active_exceptions(
            entity_type=baseline.entity_type,
            entity_id=baseline.entity_id,
            metric_type=baseline.metric_type,
            at_time=check_time,
        )
        if exceptions:
            exc = exceptions[0]
            return BehavioralDeviation(
                id=str(uuid.uuid4()),
                baseline_id=baseline.id,
                incident_id=incident_id,
                investigation_id=investigation_id,
                workspace_id=baseline.workspace_id,
                entity_type=baseline.entity_type,
                entity_id=baseline.entity_id,
                metric_type=baseline.metric_type,
                observed_value=str(observed_value),
                expected_range_summary=f"Exception active: {exc.reason}",
                deviation_score=0.0,
                deviation_direction=DeviationDirection.CHANGED,
                severity_hint="LOW",
                baseline_confidence=baseline.confidence_score,
                baseline_quality=baseline.quality_status,
                evidence_ids=evidence_list,
                explanation=f"Deviation suppressed by active authorized exception: {exc.reason} (approved by {exc.approved_by}).",
                limitations=[f"Authorized exception active until {exc.valid_until}"],
            )

        # 3. Statistical Deviation Evaluation
        score = 0.0
        direction = DeviationDirection.CHANGED
        expl = ""

        if baseline.metric_type == BaselineMetricType.LOGIN_HOUR and baseline.circular_hour_distribution:
            # Circular hour evaluation
            hour_f = float(observed_value)
            score, direction, expl = BehavioralStatisticsEngine.evaluate_circular_hour_deviation(
                observed_hour=hour_f,
                dist=baseline.circular_hour_distribution,
            )
        elif isinstance(observed_value, (int, float)) and baseline.median_value is not None:
            # Numerical evaluation
            score, direction, expl = BehavioralStatisticsEngine.evaluate_numerical_deviation(
                observed=float(observed_value),
                median=baseline.median_value,
                mad=baseline.mad or 0.0,
                percentiles=baseline.percentiles,
            )
        else:
            # Categorical evaluation
            score, direction, expl = BehavioralStatisticsEngine.evaluate_categorical_deviation(
                observed_category=str(observed_value),
                distribution=baseline.categorical_distribution,
                total_samples=baseline.sample_count,
            )

        # 4. Contextual Policy Application (Service accounts, admins)
        adj_score, adj_expl, limits = BaselineContextManager.apply_contextual_policy(
            category=baseline.entity_category,
            metric_type=baseline.metric_type,
            observed_value=observed_value,
            raw_deviation_score=score,
            explanation=expl,
        )

        # Determine severity hint
        severity_hint = "LOW"
        if adj_score >= 0.85:
            severity_hint = "HIGH"
        elif adj_score >= 0.60:
            severity_hint = "MEDIUM"

        dev_schema = BehavioralDeviation(
            id=str(uuid.uuid4()),
            baseline_id=baseline.id,
            incident_id=incident_id,
            investigation_id=investigation_id,
            workspace_id=baseline.workspace_id,
            entity_type=baseline.entity_type,
            entity_id=baseline.entity_id,
            metric_type=baseline.metric_type,
            observed_value=str(observed_value),
            expected_range_summary=baseline.expected_range_summary,
            deviation_score=adj_score,
            deviation_direction=direction,
            severity_hint=severity_hint,
            baseline_confidence=baseline.confidence_score,
            baseline_quality=baseline.quality_status,
            evidence_ids=evidence_list,
            explanation=adj_expl,
            limitations=limits,
        )

        # 5. Persist to DB if incident or investigation is associated
        if incident_id or investigation_id or adj_score > 0.40:
            dev_model = BehavioralDeviationModel(
                id=dev_schema.id,
                baseline_id=baseline.id,
                incident_id=incident_id,
                investigation_id=investigation_id,
                workspace_id=baseline.workspace_id,
                entity_type=baseline.entity_type.value,
                entity_id=baseline.entity_id,
                metric_type=baseline.metric_type.value,
                observed_value=dev_schema.observed_value,
                expected_range_summary=dev_schema.expected_range_summary,
                deviation_score=dev_schema.deviation_score,
                deviation_direction=dev_schema.deviation_direction.value,
                severity_hint=dev_schema.severity_hint,
                baseline_confidence=dev_schema.baseline_confidence,
                baseline_quality=dev_schema.baseline_quality.value,
                evidence_ids_json=json.dumps(evidence_list),
                explanation=dev_schema.explanation,
                limitations_json=json.dumps(dev_schema.limitations),
            )
            session.add(dev_model)
            session.commit()

        return dev_schema

    @classmethod
    def freeze_baseline(
        cls,
        session: Session,
        baseline_id: str,
        actor: str,
        reason: str,
    ) -> BehavioralBaseline:
        """Freezes baseline to prevent ongoing security incidents from contaminating normal patterns."""
        model = session.query(BehavioralBaselineModel).filter(BehavioralBaselineModel.id == baseline_id).first()
        if not model:
            raise ValueError(f"Baseline '{baseline_id}' not found.")

        model.is_frozen = True
        model.frozen_by = actor
        model.frozen_reason = reason
        model.frozen_at = datetime.now(timezone.utc).replace(tzinfo=None)
        model.learning_mode = LearningMode.FROZEN.value

        audit = BaselineAuditModel(
            baseline_id=baseline_id,
            action="FREEZE",
            actor=actor,
            reason=reason,
            details_json=json.dumps({"learning_mode": "FROZEN"}),
        )
        session.add(audit)
        session.commit()
        session.refresh(model)

        schema_obj = cls._model_to_schema(model)
        cache_k = cls._cache_key(model.workspace_id, model.entity_type, model.entity_id, model.metric_type)
        cls._baseline_cache[cache_k] = schema_obj
        return schema_obj

    @classmethod
    def unfreeze_baseline(
        cls,
        session: Session,
        baseline_id: str,
        actor: str,
        reason: str,
    ) -> BehavioralBaseline:
        """Unfreezes baseline, returning it to stable adaptive state."""
        model = session.query(BehavioralBaselineModel).filter(BehavioralBaselineModel.id == baseline_id).first()
        if not model:
            raise ValueError(f"Baseline '{baseline_id}' not found.")

        model.is_frozen = False
        model.frozen_by = None
        model.frozen_reason = None
        model.frozen_at = None
        model.learning_mode = LearningMode.STABLE.value

        audit = BaselineAuditModel(
            baseline_id=baseline_id,
            action="UNFREEZE",
            actor=actor,
            reason=reason,
            details_json=json.dumps({"learning_mode": "STABLE"}),
        )
        session.add(audit)
        session.commit()
        session.refresh(model)

        schema_obj = cls._model_to_schema(model)
        cache_k = cls._cache_key(model.workspace_id, model.entity_type, model.entity_id, model.metric_type)
        cls._baseline_cache[cache_k] = schema_obj
        return schema_obj

    @classmethod
    def relearn_baseline(
        cls,
        session: Session,
        baseline_id: str,
        actor: str,
        reason: str,
        window_days: int = 14,
    ) -> BehavioralBaseline:
        """Triggers controlled relearning period for permanent legitimate behavioral shifts."""
        model = session.query(BehavioralBaselineModel).filter(BehavioralBaselineModel.id == baseline_id).first()
        if not model:
            raise ValueError(f"Baseline '{baseline_id}' not found.")

        audit = BaselineAuditModel(
            baseline_id=baseline_id,
            action="RELEARN",
            actor=actor,
            reason=reason,
            details_json=json.dumps({"window_days": window_days, "previous_samples": model.sample_count}),
        )
        session.add(audit)
        session.commit()

        # Recalculate with new window
        return cls.build_baseline(
            session=session,
            entity_type=BaselineEntityType(model.entity_type),
            entity_id=model.entity_id,
            metric_type=BaselineMetricType(model.metric_type),
            window_days=window_days,
            workspace_id=model.workspace_id,
            force_recalculate=True,
        )
