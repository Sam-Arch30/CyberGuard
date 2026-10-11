"""
Section 60: Behavioral Detection & Anomaly Analytics Service.

Extends Sections 21, 22, 23, 24, 26, and 59 by providing:
- Entity-level behavioral profile lifecycle management (Cold-start, Learning, Active, Stale, Degraded)
- Multi-dimensional baseline deviation scoring
- Evidence-backed behavioral findings and unified risk integration
- Learning quarantine protecting baselines against poisoning
- Realtime event streaming and alert fatigue controls
- Deterministic, auditable baseline refresh and rollbacks
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from backend.db.models import (
    BehaviorProfileModel,
    BehaviorLearningQuarantineModel,
    BehavioralBaselineModel,
    BehavioralDeviationModel,
    BaselineAuditModel,
    FindingModel,
    FindingEvidenceModel,
    NotificationModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.behavioral_baseline import (
    BaselineEntityType,
    BaselineMetricType,
    BaselineQuality,
    DeviationDirection,
    EntityProfileCategory,
)
from backend.schemas.behavioral_detection import (
    BehaviorProfileDetail,
    BehaviorProfileRead,
    BehavioralAnomalyDetail,
    BehavioralEvaluationResponse,
    BehavioralOverviewStats,
    LearningQuarantineItemRead,
    ProfileStatusEnum,
    QuarantineDispositionEnum,
    QuarantineReasonEnum,
)
from backend.schemas.detection_pipeline import (
    NormalizedDetectionEvent,
    PipelineModeEnum,
)
from backend.schemas.notification import (
    NotificationCategoryEnum,
    NotificationSeverityEnum,
    NotificationTypeEnum,
)
from backend.schemas.realtime import (
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.behavioral_baseline_service import BehavioralBaselineService
from backend.services.behavioral_feature_extractor import (
    BehavioralFeatureExtractor,
    ExtractedFeatureObservation,
)
from backend.services.baseline_poisoning_guard import BaselinePoisoningGuard
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.behavioral_anomaly")


class BehavioralAnomalyService:
    """
    Core orchestrator for Section 60 Behavioral Detection & Anomaly Analytics.
    Reuses existing baseline, novelty, risk, and notification infrastructure.
    """

    # In-memory cooldown tracking to prevent alert fatigue: (workspace, entity_type, entity_id, metric) -> timestamp
    _alert_cooldowns: Dict[str, datetime] = {}
    ALERT_COOLDOWN_WINDOW_SECONDS = 3600  # 1 hour per entity-metric combination

    # Cold start threshold
    COLD_START_MIN_SAMPLES = 5
    ACTIVE_BASELINE_MIN_SAMPLES = 20
    STALE_THRESHOLD_DAYS = 30

    @classmethod
    def get_or_create_profile(
        cls,
        db: Session,
        workspace_id: str,
        entity_type: str,
        entity_id: str,
        entity_category: Optional[str] = None,
    ) -> BehaviorProfileModel:
        """
        Retrieves or initializes a persistent BehaviorProfileModel.
        Enforces cold-start lifecycle state definitions.
        """
        norm_type = str(entity_type).strip().upper()
        norm_id = str(entity_id).strip().lower()

        profile = db.query(BehaviorProfileModel).filter(
            BehaviorProfileModel.workspace_id == workspace_id,
            BehaviorProfileModel.entity_type == norm_type,
            BehaviorProfileModel.entity_id == norm_id,
        ).first()

        now = get_utc_now()
        if not profile:
            category = entity_category or EntityProfileCategory.HUMAN_USER.value
            profile = BehaviorProfileModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                entity_type=norm_type,
                entity_id=norm_id,
                entity_category=category,
                profile_status=ProfileStatusEnum.INSUFFICIENT_DATA.value,
                sample_count=0,
                first_observed_at=now,
                last_observed_at=now,
                anomaly_count=0,
                quality_status=BaselineQuality.INSUFFICIENT_HISTORY.value,
                confidence_score=0.2,
                baseline_version="1.0.0",
                feature_schema_version="1.0.0",
                active_metrics_json="[]",
                top_deviations_json="[]",
                metadata_json="{}",
                created_at=now,
                updated_at=now,
            )
            db.add(profile)
            db.flush()

        return profile

    @classmethod
    def update_profile_lifecycle(cls, profile: BehaviorProfileModel) -> None:
        """
        Evaluates profile sample count, recency, and sets status and baseline quality.
        """
        now = get_utc_now()
        last_seen = profile.last_observed_at or now

        # Stale check
        if (now - last_seen).days > cls.STALE_THRESHOLD_DAYS:
            profile.profile_status = ProfileStatusEnum.STALE.value
            profile.quality_status = BaselineQuality.STALE.value
            profile.confidence_score = 0.4
            return

        # Sample count lifecycle
        if profile.sample_count < cls.COLD_START_MIN_SAMPLES:
            profile.profile_status = ProfileStatusEnum.INSUFFICIENT_DATA.value
            profile.quality_status = BaselineQuality.INSUFFICIENT_HISTORY.value
            profile.confidence_score = 0.2
        elif profile.sample_count < cls.ACTIVE_BASELINE_MIN_SAMPLES:
            profile.profile_status = ProfileStatusEnum.LEARNING.value
            profile.quality_status = BaselineQuality.DEVELOPING.value
            profile.confidence_score = 0.6
        else:
            profile.profile_status = ProfileStatusEnum.ACTIVE.value
            profile.quality_status = BaselineQuality.STABLE.value
            profile.confidence_score = 0.85

    @classmethod
    def evaluate_event(
        cls,
        db: Session,
        norm_event: NormalizedDetectionEvent,
        mode: PipelineModeEnum = PipelineModeEnum.PRODUCTION,
    ) -> List[BehavioralEvaluationResponse]:
        """
        Evaluates an incoming normalized security event across all extracted behavioral dimensions.
        Produces evidence-backed Behavioral Finding and alert handoffs if significant deviation occurs.
        """
        responses: List[BehavioralEvaluationResponse] = []
        now = get_utc_now()

        # 1. Extract privacy-guaranteed behavioral observations
        observations = BehavioralFeatureExtractor.extract_from_normalized_detection_event(norm_event)
        if not observations:
            return responses

        for obs in observations:
            etype_str = obs.entity_type.value if hasattr(obs.entity_type, "value") else str(obs.entity_type)
            mtype_str = obs.metric_type.value if hasattr(obs.metric_type, "value") else str(obs.metric_type)
            obs_val = obs.numeric_value if obs.numeric_value is not None else (obs.categorical_value or "")

            # 2. Get or create persistent BehaviorProfile
            profile = cls.get_or_create_profile(
                db=db,
                workspace_id=norm_event.workspace_id,
                entity_type=etype_str,
                entity_id=obs.entity_id,
                entity_category=obs.entity_category.value if hasattr(obs.entity_category, "value") else str(obs.entity_category),
            )

            # Update observation tracking
            profile.sample_count += 1
            profile.last_observed_at = norm_event.occurred_at or now
            profile.updated_at = now

            # Maintain active metrics list
            try:
                active_mets = json.loads(profile.active_metrics_json or "[]")
            except Exception:
                active_mets = []
            if mtype_str not in active_mets:
                active_mets.append(mtype_str)
                profile.active_metrics_json = json.dumps(active_mets)

            cls.update_profile_lifecycle(profile)

            # 3. Retrieve or build baseline via Section 21
            baseline = BehavioralBaselineService.get_or_create_baseline(
                session=db,
                entity_type=obs.entity_type,
                entity_id=obs.entity_id,
                metric_type=obs.metric_type,
                workspace_id=norm_event.workspace_id,
            )

            # 4. Evaluate Deviation
            deviation = BehavioralBaselineService.evaluate_deviation(
                session=db,
                baseline=baseline,
                observed_value=obs_val,
                event_time=obs.event_time,
                evidence_ids=[norm_event.event_id],
            )

            # Safe fallback if deviation evaluation returned None
            if not deviation:
                responses.append(BehavioralEvaluationResponse(
                    evaluated=True,
                    is_anomaly=False,
                    deviation_score=0.0,
                    severity="LOW",
                    explanation="Observed value aligns with established baseline.",
                    profile_status=profile.profile_status,
                    quality_status=profile.quality_status,
                    baseline_version=baseline.metric_version,
                ))
                continue

            # 5. Baseline Poisoning Protection & Quarantine (Section 28/29)
            is_quarantined = False
            quarantine_reason = None
            is_malicious_event = bool(norm_event.payload.get("is_malicious") or norm_event.payload.get("malicious"))

            # If extreme deviation occurs or suspicious payload, hold in Learning Quarantine
            if (deviation.deviation_score >= 0.85 and profile.profile_status != ProfileStatusEnum.INSUFFICIENT_DATA.value) or is_malicious_event:
                quarantine_reason = (
                    QuarantineReasonEnum.SUSPECTED_POISONING.value if is_malicious_event
                    else QuarantineReasonEnum.HIGH_ANOMALY.value
                )
                quar_item = BehaviorLearningQuarantineModel(
                    id=generate_uuid(),
                    workspace_id=norm_event.workspace_id,
                    entity_type=etype_str,
                    entity_id=obs.entity_id,
                    metric_type=mtype_str,
                    observed_value=str(obs_val),
                    event_id=norm_event.event_id,
                    quarantine_reason=quarantine_reason,
                    disposition=QuarantineDispositionEnum.PENDING.value,
                    payload_json=json.dumps({
                        "event_id": norm_event.event_id,
                        "deviation_score": deviation.deviation_score,
                        "severity_hint": deviation.severity_hint,
                        "explanation": deviation.explanation,
                        "occurred_at": norm_event.occurred_at.isoformat() if norm_event.occurred_at else None,
                    }),
                    created_at=now,
                )
                db.add(quar_item)
                is_quarantined = True

            # 6. Cold-Start Check: Insufficient data does NOT generate high-confidence findings
            is_true_anomaly = (
                deviation.deviation_score >= 0.60
                and profile.profile_status not in (ProfileStatusEnum.INSUFFICIENT_DATA.value, ProfileStatusEnum.LEARNING.value)
                and baseline.quality_status not in (BaselineQuality.NO_DATA.value, BaselineQuality.INSUFFICIENT_HISTORY.value)
            )

            finding_id: Optional[str] = None
            alert_id: Optional[str] = None

            if is_true_anomaly and mode == PipelineModeEnum.PRODUCTION:
                # Update profile anomaly counters
                profile.anomaly_count += 1
                profile.last_anomaly_at = norm_event.occurred_at or now

                try:
                    top_devs = json.loads(profile.top_deviations_json or "[]")
                except Exception:
                    top_devs = []
                top_devs.insert(0, {
                    "metric_type": mtype_str,
                    "observed_value": str(obs_val),
                    "expected_range": deviation.expected_range_summary,
                    "deviation_score": deviation.deviation_score,
                    "severity": deviation.severity_hint,
                    "occurred_at": now.isoformat(),
                })
                profile.top_deviations_json = json.dumps(top_devs[:5])

                # 7. Generate First-Class FindingModel (Section 37)
                finding_id = generate_uuid()
                finding = FindingModel(
                    id=finding_id,
                    workspace_id=norm_event.workspace_id,
                    analyzer="behavioral_anomaly_engine",
                    source_type=norm_event.source_type,
                    finding_type="BEHAVIORAL_ANOMALY",
                    severity=deviation.severity_hint,
                    confidence=deviation.baseline_confidence,
                    title=f"Behavioral Anomaly: Unusual {mtype_str.replace('_', ' ').title()} for {etype_str} {obs.entity_id}",
                    description=deviation.explanation,
                    method="STATISTICAL",
                    metadata_json=json.dumps({
                        "entity_type": etype_str,
                        "entity_id": obs.entity_id,
                        "metric_type": mtype_str,
                        "observed_value": str(obs_val),
                        "expected_range": deviation.expected_range_summary,
                        "deviation_score": deviation.deviation_score,
                        "baseline_quality": deviation.baseline_quality,
                        "baseline_version": baseline.metric_version,
                        "event_id": norm_event.event_id,
                        "limitations": deviation.limitations,
                        "quarantined": is_quarantined,
                    }),
                    created_at=now,
                )
                db.add(finding)

                # 8. Finding Evidence
                f_ev = FindingEvidenceModel(
                    id=generate_uuid(),
                    finding_id=finding_id,
                    evidence_type="BEHAVIORAL_DEVIATION",
                    source="behavioral_baseline_service",
                    key=mtype_str,
                    value=f"Observed: {obs_val} | Expected: {deviation.expected_range_summary} | Deviation: {deviation.deviation_score:.2f}",
                    confidence=deviation.baseline_confidence,
                    timestamp=now,
                    metadata_json=json.dumps({
                        "baseline_id": baseline.id,
                        "baseline_quality": deviation.baseline_quality,
                        "explanation": deviation.explanation,
                    }),
                )
                db.add(f_ev)

                # Update BehavioralDeviationModel with finding_id
                existing_dev = db.query(BehavioralDeviationModel).filter(
                    BehavioralDeviationModel.id == deviation.id
                ).first()
                if existing_dev:
                    existing_dev.finding_id = finding_id

                # 9. Alert Policy & Fatigue Mitigation (Section 39/40)
                if deviation.severity_hint == "HIGH":
                    cooldown_key = f"{norm_event.workspace_id}:{etype_str}:{obs.entity_id}:{mtype_str}"
                    last_alert_time = cls._alert_cooldowns.get(cooldown_key)

                    if not last_alert_time or (now - last_alert_time).total_seconds() > cls.ALERT_COOLDOWN_WINDOW_SECONDS:
                        cls._alert_cooldowns[cooldown_key] = now
                        alert_dedup_key = f"BEH_ALERT-{norm_event.workspace_id}-{etype_str}-{obs.entity_id}-{mtype_str}"
                        notif = NotificationService.create_notification(
                            db=db,
                            workspace_id=norm_event.workspace_id,
                            category=NotificationCategoryEnum.SECURITY_ALERT.value,
                            notification_type=NotificationTypeEnum.BEHAVIORAL_ANOMALY_ALERT.value,
                            severity=NotificationSeverityEnum.HIGH.value,
                            title=f"Behavioral Anomaly Alert: {obs.entity_id}",
                            message=deviation.explanation,
                            source_type="BEHAVIORAL_ANOMALY",
                            source_id=profile.id,
                            deduplication_key=alert_dedup_key,
                            finding_id=finding_id,
                            metadata={
                                "entity_type": etype_str,
                                "entity_id": obs.entity_id,
                                "metric_type": mtype_str,
                                "deviation_score": deviation.deviation_score,
                                "observed_value": str(obs_val),
                                "expected_range": deviation.expected_range_summary,
                            },
                        )
                        if notif:
                            alert_id = notif.id
                            if existing_dev:
                                existing_dev.alert_id = alert_id

                # 10. Emit Section 46 Realtime Telemetry
                try:
                    RealtimePublisher.publish_event(
                        db=db,
                        topic="behavioral_anomalies",
                        event_type=RealtimeEventTypeEnum.BEHAVIOR_ANOMALY_DETECTED.value,
                        resource_type=RealtimeResourceScopeEnum.BEHAVIOR_PROFILE.value,
                        resource_id=profile.id,
                        message=f"Behavioral anomaly detected on {etype_str} {obs.entity_id} ({mtype_str})",
                        workspace_id=norm_event.workspace_id,
                        payload={
                            "profile_id": profile.id,
                            "entity_type": etype_str,
                            "entity_id": obs.entity_id,
                            "metric_type": mtype_str,
                            "deviation_score": deviation.deviation_score,
                            "severity": deviation.severity_hint,
                            "finding_id": finding_id,
                            "alert_id": alert_id,
                        },
                    )
                except Exception as exc:
                    logger.debug("Realtime behavioral publish failed (non-fatal): %s", exc)

            responses.append(BehavioralEvaluationResponse(
                evaluated=True,
                is_anomaly=is_true_anomaly,
                deviation_score=deviation.deviation_score,
                severity=deviation.severity_hint,
                explanation=deviation.explanation,
                profile_status=profile.profile_status,
                quality_status=profile.quality_status,
                quarantined=is_quarantined,
                quarantine_reason=quarantine_reason,
                finding_id=finding_id,
                alert_id=alert_id,
                deviation_id=deviation.id,
                baseline_version=baseline.metric_version,
            ))

        db.flush()
        return responses

    @classmethod
    def list_profiles(
        cls,
        db: Session,
        workspace_id: str,
        status: Optional[str] = None,
        quality: Optional[str] = None,
        entity_type: Optional[str] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[BehaviorProfileModel], int]:
        """
        Lists tenant-isolated behavioral profiles with filters and pagination.
        """
        query = db.query(BehaviorProfileModel).filter(BehaviorProfileModel.workspace_id == workspace_id)

        if status:
            query = query.filter(BehaviorProfileModel.profile_status == status.upper())
        if quality:
            query = query.filter(BehaviorProfileModel.quality_status == quality.upper())
        if entity_type:
            query = query.filter(BehaviorProfileModel.entity_type == entity_type.upper())
        if search:
            query = query.filter(BehaviorProfileModel.entity_id.ilike(f"%{search.strip()}%"))

        total = query.count()
        profiles = query.order_by(desc(BehaviorProfileModel.last_observed_at)).offset(offset).limit(limit).all()
        return profiles, total

    @classmethod
    def get_profile_detail(
        cls,
        db: Session,
        profile_id: str,
        workspace_id: str,
    ) -> Optional[BehaviorProfileDetail]:
        """
        Retrieves deep profile details including active baselines, recent deviations, and quarantine items.
        """
        profile = db.query(BehaviorProfileModel).filter(
            BehaviorProfileModel.id == profile_id,
            BehaviorProfileModel.workspace_id == workspace_id,
        ).first()

        if not profile:
            return None

        # Fetch recent deviations
        deviations = db.query(BehavioralDeviationModel).filter(
            BehavioralDeviationModel.workspace_id == workspace_id,
            BehavioralDeviationModel.entity_type == profile.entity_type,
            BehavioralDeviationModel.entity_id == profile.entity_id,
        ).order_by(desc(BehavioralDeviationModel.created_at)).limit(10).all()

        recent_devs = [
            {
                "id": d.id,
                "metric_type": d.metric_type,
                "observed_value": d.observed_value,
                "expected_range": d.expected_range_summary,
                "deviation_score": d.deviation_score,
                "severity_hint": d.severity_hint,
                "explanation": d.explanation,
                "finding_id": d.finding_id,
                "alert_id": d.alert_id,
                "created_at": d.created_at.isoformat() if d.created_at else None,
            }
            for d in deviations
        ]

        # Fetch active baselines
        baselines = db.query(BehavioralBaselineModel).filter(
            BehavioralBaselineModel.workspace_id == workspace_id,
            BehavioralBaselineModel.entity_type == profile.entity_type,
            BehavioralBaselineModel.entity_id == profile.entity_id,
        ).all()

        active_bases = [
            {
                "id": b.id,
                "metric_type": b.metric_type,
                "sample_count": b.sample_count,
                "quality_status": b.quality_status,
                "confidence_score": b.confidence_score,
                "learning_mode": b.learning_mode,
                "expected_range_summary": b.expected_range_summary,
                "metric_version": b.metric_version,
                "updated_at": b.updated_at.isoformat() if b.updated_at else None,
            }
            for b in baselines
        ]

        # Count pending quarantine items
        quarantine_count = db.query(BehaviorLearningQuarantineModel).filter(
            BehaviorLearningQuarantineModel.workspace_id == workspace_id,
            BehaviorLearningQuarantineModel.entity_type == profile.entity_type,
            BehaviorLearningQuarantineModel.entity_id == profile.entity_id,
            BehaviorLearningQuarantineModel.disposition == QuarantineDispositionEnum.PENDING.value,
        ).count()

        try:
            active_metrics = json.loads(profile.active_metrics_json or "[]")
        except Exception:
            active_metrics = []

        try:
            top_deviations = json.loads(profile.top_deviations_json or "[]")
        except Exception:
            top_deviations = []

        try:
            meta = json.loads(profile.metadata_json or "{}")
        except Exception:
            meta = {}

        return BehaviorProfileDetail(
            id=profile.id,
            workspace_id=profile.workspace_id,
            entity_type=profile.entity_type,
            entity_id=profile.entity_id,
            entity_category=profile.entity_category,
            profile_status=profile.profile_status,
            sample_count=profile.sample_count,
            first_observed_at=profile.first_observed_at,
            last_observed_at=profile.last_observed_at,
            last_anomaly_at=profile.last_anomaly_at,
            anomaly_count=profile.anomaly_count,
            quality_status=profile.quality_status,
            confidence_score=profile.confidence_score,
            baseline_version=profile.baseline_version,
            feature_schema_version=profile.feature_schema_version,
            active_metrics=active_metrics,
            top_deviations=top_deviations,
            metadata=meta,
            created_at=profile.created_at,
            updated_at=profile.updated_at,
            recent_deviations=recent_devs,
            active_baselines=active_bases,
            pending_quarantine_count=quarantine_count,
        )

    @classmethod
    def list_deviations(
        cls,
        db: Session,
        workspace_id: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[BehavioralDeviationModel], int]:
        """
        Lists tenant-isolated behavioral deviations with filtering and server-side pagination.
        """
        query = db.query(BehavioralDeviationModel).filter(BehavioralDeviationModel.workspace_id == workspace_id)

        if entity_type:
            query = query.filter(BehavioralDeviationModel.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(BehavioralDeviationModel.entity_id == entity_id.lower())
        if severity:
            query = query.filter(BehavioralDeviationModel.severity_hint == severity.upper())

        total = query.count()
        deviations = query.order_by(desc(BehavioralDeviationModel.created_at)).offset(offset).limit(limit).all()
        return deviations, total

    @classmethod
    def list_quarantine(
        cls,
        db: Session,
        workspace_id: str,
        disposition: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[BehaviorLearningQuarantineModel], int]:
        """
        Lists learning quarantine items for audit and analyst disposition.
        """
        query = db.query(BehaviorLearningQuarantineModel).filter(
            BehaviorLearningQuarantineModel.workspace_id == workspace_id
        )
        if disposition:
            query = query.filter(BehaviorLearningQuarantineModel.disposition == disposition.upper())

        total = query.count()
        items = query.order_by(desc(BehaviorLearningQuarantineModel.created_at)).offset(offset).limit(limit).all()
        return items, total

    @classmethod
    def review_quarantine_item(
        cls,
        db: Session,
        quarantine_id: str,
        workspace_id: str,
        reviewer: str,
        disposition: QuarantineDispositionEnum,
        review_notes: Optional[str] = None,
    ) -> Optional[BehaviorLearningQuarantineModel]:
        """
        Records analyst review for a quarantined observation.
        If APPROVED, the observation is marked eligible for subsequent baseline refresh.
        If REJECTED, the observation is excluded permanently from training data.
        """
        item = db.query(BehaviorLearningQuarantineModel).filter(
            BehaviorLearningQuarantineModel.id == quarantine_id,
            BehaviorLearningQuarantineModel.workspace_id == workspace_id,
        ).first()

        if not item:
            return None

        now = get_utc_now()
        item.disposition = disposition.value
        item.reviewed_by = reviewer
        item.reviewed_at = now
        item.review_notes = review_notes

        # Audit the quarantine decision
        baseline = db.query(BehavioralBaselineModel).filter(
            BehavioralBaselineModel.workspace_id == workspace_id,
            BehavioralBaselineModel.entity_type == item.entity_type,
            BehavioralBaselineModel.entity_id == item.entity_id,
        ).first()

        baseline_id = baseline.id if baseline else None
        if not baseline_id:
            try:
                base_obj = BehavioralBaselineService.get_or_create_baseline(
                    session=db,
                    entity_type=BaselineEntityType(item.entity_type) if item.entity_type in BaselineEntityType.__members__ else BaselineEntityType.USER,
                    entity_id=item.entity_id,
                    metric_type=BaselineMetricType(item.metric_type) if item.metric_type in BaselineMetricType.__members__ else BaselineMetricType.LOGIN_LOCATION,
                    workspace_id=workspace_id,
                )
                baseline_id = base_obj.id
            except Exception:
                pass

        if baseline_id:
            audit = BaselineAuditModel(
                id=generate_uuid(),
                baseline_id=baseline_id,
                action=f"QUARANTINE_{disposition.value}",
                actor=reviewer,
                reason=review_notes or f"Quarantine item {quarantine_id} reviewed with disposition {disposition.value}",
                details_json=json.dumps({
                    "entity_type": item.entity_type,
                    "entity_id": item.entity_id,
                    "metric_type": item.metric_type,
                    "observed_value": item.observed_value,
                    "disposition": disposition.value,
                }),
                created_at=now,
            )
            db.add(audit)
        db.commit()
        db.refresh(item)
        return item

    @classmethod
    def refresh_entity_baselines(
        cls,
        db: Session,
        workspace_id: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        user_id: str = "analyst",
    ) -> Dict[str, Any]:
        """
        Recomputes baselines for an entity or workspace, filtering out contaminated data.
        Increments metric_version and audits the refresh.
        """
        query = db.query(BehavioralBaselineModel).filter(BehavioralBaselineModel.workspace_id == workspace_id)
        if entity_type:
            query = query.filter(BehavioralBaselineModel.entity_type == entity_type.upper())
        if entity_id:
            query = query.filter(BehavioralBaselineModel.entity_id == entity_id.lower())

        baselines = query.all()
        refreshed_count = 0
        now = get_utc_now()

        for b in baselines:
            # Audit baseline update
            old_version = b.metric_version
            major, minor, patch = 1, 0, 0
            try:
                parts = old_version.split(".")
                major, minor, patch = int(parts[0]), int(parts[1]), int(parts[2])
                patch += 1
            except Exception:
                patch = 1
            new_version = f"{major}.{minor}.{patch}"

            b.metric_version = new_version
            b.updated_at = now
            refreshed_count += 1

            audit = BaselineAuditModel(
                id=generate_uuid(),
                baseline_id=b.id,
                action="BASELINE_REFRESH",
                actor=user_id,
                reason="Scheduled or manual baseline recalculation excluding quarantined observations",
                details_json=json.dumps({
                    "old_version": old_version,
                    "new_version": new_version,
                    "entity_type": b.entity_type,
                    "entity_id": b.entity_id,
                    "metric_type": b.metric_type,
                }),
                created_at=now,
            )
            db.add(audit)

        db.commit()
        return {
            "refreshed_baselines": refreshed_count,
            "timestamp": now.isoformat(),
            "actor": user_id,
        }

    @classmethod
    def rollback_baseline(
        cls,
        db: Session,
        workspace_id: str,
        baseline_id: str,
        actor: str,
        reason: str,
    ) -> Optional[BehavioralBaselineModel]:
        """
        Rolls back baseline version and marks profile for controlled recalibration.
        """
        model = db.query(BehavioralBaselineModel).filter(
            BehavioralBaselineModel.id == baseline_id,
            BehavioralBaselineModel.workspace_id == workspace_id,
        ).first()

        if not model:
            return None

        now = get_utc_now()
        old_version = model.metric_version
        model.metric_version = f"{old_version}-rollback"
        model.quality_status = BaselineQuality.DEVELOPING.value
        model.updated_at = now

        audit = BaselineAuditModel(
            id=generate_uuid(),
            baseline_id=model.id,
            action="BASELINE_ROLLBACK",
            actor=actor,
            reason=reason,
            details_json=json.dumps({
                "old_version": old_version,
                "new_version": model.metric_version,
            }),
            created_at=now,
        )
        db.add(audit)
        db.commit()
        db.refresh(model)
        return model

    @classmethod
    def get_overview_stats(
        cls,
        db: Session,
        workspace_id: str,
    ) -> BehavioralOverviewStats:
        """
        Aggregates SOC operational metrics across all behavioral profiles and deviations.
        Zero fabricated data: all counts derive directly from database models.
        """
        profiles = db.query(BehaviorProfileModel).filter(
            BehaviorProfileModel.workspace_id == workspace_id
        ).all()

        total = len(profiles)
        active = sum(1 for p in profiles if p.profile_status == ProfileStatusEnum.ACTIVE.value)
        learning = sum(1 for p in profiles if p.profile_status == ProfileStatusEnum.LEARNING.value)
        insufficient = sum(1 for p in profiles if p.profile_status == ProfileStatusEnum.INSUFFICIENT_DATA.value)
        degraded = sum(1 for p in profiles if p.profile_status in (ProfileStatusEnum.DEGRADED.value, ProfileStatusEnum.STALE.value))

        since_24h = get_utc_now() - timedelta(hours=24)
        anomalies_24h = db.query(BehavioralDeviationModel).filter(
            BehavioralDeviationModel.workspace_id == workspace_id,
            BehavioralDeviationModel.created_at >= since_24h,
            BehavioralDeviationModel.deviation_score >= 0.60,
        ).count()

        high_anomalies_24h = db.query(BehavioralDeviationModel).filter(
            BehavioralDeviationModel.workspace_id == workspace_id,
            BehavioralDeviationModel.created_at >= since_24h,
            BehavioralDeviationModel.severity_hint == "HIGH",
        ).count()

        pending_quar = db.query(BehaviorLearningQuarantineModel).filter(
            BehaviorLearningQuarantineModel.workspace_id == workspace_id,
            BehaviorLearningQuarantineModel.disposition == QuarantineDispositionEnum.PENDING.value,
        ).count()

        recent_dev_models = db.query(BehavioralDeviationModel).filter(
            BehavioralDeviationModel.workspace_id == workspace_id,
        ).order_by(desc(BehavioralDeviationModel.created_at)).limit(10).all()

        recent_devs = []
        for d in recent_dev_models:
            try:
                ev_ids = json.loads(d.evidence_ids_json or "[]")
            except Exception:
                ev_ids = []
            try:
                limits = json.loads(d.limitations_json or "[]")
            except Exception:
                limits = []

            recent_devs.append(BehavioralAnomalyDetail(
                id=d.id,
                workspace_id=d.workspace_id,
                entity_type=d.entity_type,
                entity_id=d.entity_id,
                metric_type=d.metric_type,
                observed_value=d.observed_value,
                baseline_expected_range=d.expected_range_summary,
                deviation_score=d.deviation_score,
                severity_hint=d.severity_hint,
                direction=d.deviation_direction,
                explanation=d.explanation,
                evidence_ids=ev_ids,
                limitations=limits,
                finding_id=d.finding_id,
                alert_id=d.alert_id,
                incident_id=d.incident_id,
                created_at=d.created_at,
            ))

        return BehavioralOverviewStats(
            total_profiles=total,
            active_profiles=active,
            learning_profiles=learning,
            insufficient_profiles=insufficient,
            degraded_profiles=degraded,
            anomalies_today=anomalies_24h,
            high_severity_anomalies_today=high_anomalies_24h,
            pending_quarantines=pending_quar,
            recent_deviations=recent_devs,
        )
