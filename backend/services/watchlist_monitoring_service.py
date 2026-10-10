"""
Section 53: Watchlist Monitoring & Continuous Intelligence Change Detection Service.
Provides persistent analyst watchlists, scheduled intelligence checks, deterministic
fingerprinting, material change detection, alert suppression/cooldowns, and audit logging.
"""
from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import desc, func, and_, or_
from sqlalchemy.orm import Session

from backend.db.models import (
    WatchlistModel,
    WatchedIndicatorModel,
    IntelligenceSnapshotModel,
    IntelligenceChangeModel,
    WatchlistMonitoringRunModel,
    IndicatorModel,
    RelationshipModel,
    NotificationModel,
    get_utc_now,
)
from backend.schemas.watchlists import (
    WatchlistCreateRequest,
    WatchlistUpdateRequest,
    WatchedIndicatorCreateRequest,
    WatchedIndicatorBulkAddRequest,
    QuickWatchRequest,
    WatchlistStatusEnum,
    WatchlistPriorityEnum,
    MonitoringStatusEnum,
    ChangeTypeEnum,
    ChangeSensitivityEnum,
    AlertThresholdEnum,
    MonitoringRunTriggerEnum,
    MonitoringRunStatusEnum,
    WatchlistSummaryResponse,
    WatchlistDetailResponse,
    WatchlistListResponse,
    WatchedIndicatorResponse,
    WatchedIndicatorListResponse,
    IntelligenceChangeResponse,
    IntelligenceChangeListResponse,
    WatchlistMonitoringRunResponse,
    WatchlistMonitoringRunListResponse,
    WatchlistHealthResponse,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
    RealtimeEventPayload,
)
from backend.services.indicator_normalizer import IndicatorNormalizer
from backend.services.threat_intelligence_service import ThreatIntelligenceService
from backend.services.notification_service import NotificationService
from backend.services.realtime_service import RealtimePublisher, global_realtime_hub

logger = logging.getLogger("cyberguard.services.watchlist_monitoring")

# Severity order for comparison
SEVERITY_ORDER = {
    "NONE": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


class WatchlistMonitoringService:
    """
    Subsystem orchestrating IOC Watchlists and Continuous Threat Intelligence Monitoring.
    """

    # =========================================================================
    # 1. Deterministic Fingerprinting & Change Detection
    # =========================================================================

    @classmethod
    def compute_snapshot_fingerprint(
        cls,
        verdict: str,
        severity: str,
        confidence: float,
        threat_types: List[str],
        has_conflicts: bool,
        material_attributes: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Calculates deterministic SHA-256 fingerprint for material intelligence state.
        Excludes volatile timestamps and random JSON ordering.
        Rounds confidence to nearest 0.05 to avoid micro-jitter noise.
        """
        attrs = material_attributes or {}
        rounded_conf = round((confidence or 0.0) * 20) / 20.0
        sorted_threats = sorted(threat_types or [])

        filtered_attrs = {
            "asn": attrs.get("asn"),
            "country": attrs.get("country"),
            "registrar": attrs.get("registrar"),
            "campaigns": sorted(attrs.get("campaigns") or []),
            "malware_families": sorted(attrs.get("malware_families") or []),
        }

        canonical_data = {
            "verdict": (verdict or "UNKNOWN").upper(),
            "severity": (severity or "NONE").upper(),
            "confidence": rounded_conf,
            "threat_types": sorted_threats,
            "has_conflicts": bool(has_conflicts),
            "attrs": filtered_attrs,
        }

        serialized = json.dumps(canonical_data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def detect_material_change(
        cls,
        prev: IntelligenceSnapshotModel,
        curr_verdict: str,
        curr_confidence: float,
        curr_severity: str,
        curr_threat_types: List[str],
        curr_has_conflicts: bool,
        curr_attrs: Dict[str, Any],
        sensitivity: str = "MEDIUM",
    ) -> Optional[Tuple[str, str, str, Dict[str, Any]]]:
        """
        Compares previous snapshot with current intelligence state.
        Returns: (change_type, change_severity, summary, details_dict) or None if not material.
        """
        prev_verdict = (prev.provider_consensus_verdict or "UNKNOWN").upper()
        curr_verdict = (curr_verdict or "UNKNOWN").upper()

        prev_conf = prev.consensus_confidence or 0.0
        curr_conf = curr_confidence or 0.0

        prev_sev = (prev.severity or "NONE").upper()
        curr_sev = (curr_severity or "NONE").upper()

        prev_threats = set(json.loads(prev.threat_types_json or "[]"))
        curr_threats = set(curr_threat_types or [])

        prev_attrs = json.loads(prev.normalized_data_json or "{}")

        # 1. Newly Malicious Transition (Highest Impact)
        if curr_verdict == "MALICIOUS" and prev_verdict != "MALICIOUS":
            summary = f"Observable transitioned from {prev_verdict} to MALICIOUS (confidence: {round(curr_conf*100)}%)."
            details = {
                "previous_verdict": prev_verdict,
                "current_verdict": curr_verdict,
                "confidence": curr_conf,
                "threat_types": list(curr_threats),
            }
            return (ChangeTypeEnum.NEWLY_MALICIOUS.value, "CRITICAL", summary, details)

        # 2. Newly Suspicious Transition
        if curr_verdict == "SUSPICIOUS" and prev_verdict in ("CLEAN", "UNKNOWN"):
            summary = f"Observable escalated from {prev_verdict} to SUSPICIOUS (confidence: {round(curr_conf*100)}%)."
            details = {
                "previous_verdict": prev_verdict,
                "current_verdict": curr_verdict,
                "confidence": curr_conf,
            }
            return (ChangeTypeEnum.NEWLY_SUSPICIOUS.value, "HIGH", summary, details)

        # 3. Became Clean
        if curr_verdict == "CLEAN" and prev_verdict in ("MALICIOUS", "SUSPICIOUS"):
            sev = "MEDIUM" if prev_verdict == "MALICIOUS" else "LOW"
            summary = f"Observable reputation recovered from {prev_verdict} to CLEAN."
            details = {"previous_verdict": prev_verdict, "current_verdict": curr_verdict}
            return (ChangeTypeEnum.BECAME_CLEAN.value, sev, summary, details)

        # 4. Provider Conflict Changed
        if curr_has_conflicts and not prev.has_conflicts:
            summary = "Contradictory intelligence emerged across configured threat intel providers."
            details = {"has_conflicts": True}
            return (ChangeTypeEnum.PROVIDER_CONFLICT_CHANGED.value, "HIGH", summary, details)

        # 5. New Malware Family or Campaign Associated
        prev_camps = set(prev_attrs.get("campaigns") or [])
        curr_camps = set(curr_attrs.get("campaigns") or [])
        new_camps = curr_camps - prev_camps

        prev_malware = set(prev_attrs.get("malware_families") or [])
        curr_malware = set(curr_attrs.get("malware_families") or [])
        new_malware = curr_malware - prev_malware

        if new_camps or new_malware:
            items = list(new_camps | new_malware)
            summary = f"New campaign or malware association detected: {', '.join(items)}."
            details = {"new_campaigns": list(new_camps), "new_malware": list(new_malware)}
            return (ChangeTypeEnum.CAMPAIGN_ASSOCIATION_CHANGED.value, "HIGH", summary, details)

        # 6. ASN Infrastructure Change
        prev_asn = str(prev_attrs.get("asn") or "")
        curr_asn = str(curr_attrs.get("asn") or "")
        if prev_asn and curr_asn and prev_asn != curr_asn:
            summary = f"Autonomous System Network changed from AS{prev_asn} to AS{curr_asn}."
            details = {"previous_asn": prev_asn, "current_asn": curr_asn}
            return (ChangeTypeEnum.ASN_CHANGED.value, "MEDIUM", summary, details)

        # 7. Hosting / Registrar Change
        prev_reg = prev_attrs.get("registrar")
        curr_reg = curr_attrs.get("registrar")
        if prev_reg and curr_reg and prev_reg != curr_reg:
            summary = f"Domain registrar updated from '{prev_reg}' to '{curr_reg}'."
            details = {"previous_registrar": prev_reg, "current_registrar": curr_reg}
            return (ChangeTypeEnum.HOSTING_CHANGED.value, "LOW", summary, details)

        # 8. Severity Escalation
        if SEVERITY_ORDER.get(curr_sev, 0) > SEVERITY_ORDER.get(prev_sev, 0):
            summary = f"Severity rating escalated from {prev_sev} to {curr_sev}."
            details = {"previous_severity": prev_sev, "current_severity": curr_sev}
            return (ChangeTypeEnum.SEVERITY_CHANGED.value, "MEDIUM", summary, details)

        # 9. Large Confidence Shift (sensitivity-based)
        conf_delta = abs(curr_conf - prev_conf)
        threshold = 0.15 if sensitivity == "HIGH" else (0.25 if sensitivity == "MEDIUM" else 0.40)
        if conf_delta >= threshold:
            direction = "increased" if curr_conf > prev_conf else "decreased"
            summary = f"Intelligence confidence {direction} significantly by {round(conf_delta*100)}%."
            details = {"previous_confidence": prev_conf, "current_confidence": curr_conf, "delta": conf_delta}
            return (ChangeTypeEnum.CONFIDENCE_CHANGED.value, "LOW", summary, details)

        return None

    # =========================================================================
    # 2. Watchlist Lifecycle Management
    # =========================================================================

    @classmethod
    def create_watchlist(
        cls,
        db: Session,
        workspace_id: str,
        req: WatchlistCreateRequest,
        actor: str = "system",
    ) -> WatchlistModel:
        now = get_utc_now()
        wl = WatchlistModel(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id or "default",
            name=req.name.strip(),
            description=req.description.strip() if req.description else None,
            status=WatchlistStatusEnum.ACTIVE.value,
            priority=req.priority.value,
            check_interval_minutes=req.check_interval_minutes,
            change_sensitivity=req.change_sensitivity.value,
            alert_threshold=req.alert_threshold.value,
            notify_on_change=req.notify_on_change,
            cooldown_minutes=req.cooldown_minutes,
            next_monitoring_cycle_at=now,  # Due immediately
            metadata_json=json.dumps(req.metadata or {}),
            created_by=actor,
            created_at=now,
            updated_at=now,
        )
        db.add(wl)
        db.commit()
        db.refresh(wl)

        # Broadcast realtime event
        cls._broadcast_watchlist_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.WATCHLIST_CREATED,
            watchlist_id=wl.id,
            payload={"name": wl.name, "priority": wl.priority, "status": wl.status},
        )
        return wl

    @classmethod
    def update_watchlist(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
        req: WatchlistUpdateRequest,
        actor: str = "system",
    ) -> WatchlistModel:
        wl = (
            db.query(WatchlistModel)
            .filter(WatchlistModel.workspace_id == workspace_id, WatchlistModel.id == watchlist_id)
            .first()
        )
        if not wl:
            raise ValueError(f"Watchlist '{watchlist_id}' not found.")

        now = get_utc_now()
        if req.name is not None:
            wl.name = req.name.strip()
        if req.description is not None:
            wl.description = req.description.strip()
        if req.priority is not None:
            wl.priority = req.priority.value
        if req.check_interval_minutes is not None:
            wl.check_interval_minutes = req.check_interval_minutes
        if req.change_sensitivity is not None:
            wl.change_sensitivity = req.change_sensitivity.value
        if req.alert_threshold is not None:
            wl.alert_threshold = req.alert_threshold.value
        if req.notify_on_change is not None:
            wl.notify_on_change = req.notify_on_change
        if req.cooldown_minutes is not None:
            wl.cooldown_minutes = req.cooldown_minutes
        if req.metadata is not None:
            wl.metadata_json = json.dumps(req.metadata)

        # Status transition handling
        if req.status is not None and req.status.value != wl.status:
            old_status = wl.status
            wl.status = req.status.value
            event_type = (
                RealtimeEventTypeEnum.WATCHLIST_PAUSED
                if wl.status == WatchlistStatusEnum.PAUSED.value
                else RealtimeEventTypeEnum.WATCHLIST_RESUMED
            )
            # Sync child items if paused
            if wl.status == WatchlistStatusEnum.PAUSED.value:
                db.query(WatchedIndicatorModel).filter(
                    WatchedIndicatorModel.watchlist_id == wl.id
                ).update({"monitoring_status": MonitoringStatusEnum.PAUSED.value})
            elif wl.status == WatchlistStatusEnum.ACTIVE.value and old_status == WatchlistStatusEnum.PAUSED.value:
                db.query(WatchedIndicatorModel).filter(
                    WatchedIndicatorModel.watchlist_id == wl.id
                ).update({"monitoring_status": MonitoringStatusEnum.ACTIVE.value, "next_check_at": now})

            cls._broadcast_watchlist_event(
                workspace_id=workspace_id,
                event_type=event_type,
                watchlist_id=wl.id,
                payload={"old_status": old_status, "new_status": wl.status},
            )

        wl.updated_by = actor
        wl.updated_at = now
        db.commit()
        db.refresh(wl)

        cls._broadcast_watchlist_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.WATCHLIST_UPDATED,
            watchlist_id=wl.id,
            payload={"name": wl.name, "priority": wl.priority, "status": wl.status},
        )
        return wl

    @classmethod
    def delete_watchlist(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
        actor: str = "system",
    ) -> bool:
        wl = (
            db.query(WatchlistModel)
            .filter(WatchlistModel.workspace_id == workspace_id, WatchlistModel.id == watchlist_id)
            .first()
        )
        if not wl:
            return False

        db.delete(wl)
        db.commit()
        return True

    @classmethod
    def get_watchlist(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
    ) -> Optional[WatchlistDetailResponse]:
        wl = (
            db.query(WatchlistModel)
            .filter(WatchlistModel.workspace_id == workspace_id, WatchlistModel.id == watchlist_id)
            .first()
        )
        if not wl:
            return None

        summary = cls._build_watchlist_summary(db, wl)

        # Recent changes (up to 10)
        recent_changes_rows = (
            db.query(IntelligenceChangeModel)
            .filter(IntelligenceChangeModel.watchlist_id == wl.id)
            .order_by(desc(IntelligenceChangeModel.detected_at))
            .limit(10)
            .all()
        )
        recent_changes = [cls._build_change_response(c) for c in recent_changes_rows]

        # Recent runs (up to 5)
        recent_runs_rows = (
            db.query(WatchlistMonitoringRunModel)
            .filter(WatchlistMonitoringRunModel.watchlist_id == wl.id)
            .order_by(desc(WatchlistMonitoringRunModel.started_at))
            .limit(5)
            .all()
        )
        recent_runs = [cls._build_run_response(r) for r in recent_runs_rows]

        return WatchlistDetailResponse(
            **summary.model_dump(),
            recent_changes=recent_changes,
            recent_runs=recent_runs,
        )

    @classmethod
    def list_watchlists(
        cls,
        db: Session,
        workspace_id: str,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> WatchlistListResponse:
        query = db.query(WatchlistModel).filter(WatchlistModel.workspace_id == workspace_id)

        if status:
            statuses = [s.strip().upper() for s in status.split(",") if s.strip()]
            query = query.filter(WatchlistModel.status.in_(statuses))

        if priority:
            query = query.filter(WatchlistModel.priority == priority.strip().upper())

        if q and q.strip():
            term = f"%{q.strip().lower()}%"
            query = query.filter(
                or_(
                    func.lower(WatchlistModel.name).like(term),
                    func.lower(WatchlistModel.description).like(term),
                )
            )

        total = query.count()
        rows = (
            query.order_by(
                desc(WatchlistModel.updated_at)
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

        summaries = [cls._build_watchlist_summary(db, row) for row in rows]
        return WatchlistListResponse(
            items=summaries,
            total=total,
            offset=offset,
            limit=limit,
        )

    @classmethod
    def get_watchlist_health(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
    ) -> WatchlistHealthResponse:
        wl = (
            db.query(WatchlistModel)
            .filter(WatchlistModel.workspace_id == workspace_id, WatchlistModel.id == watchlist_id)
            .first()
        )
        if not wl:
            raise ValueError(f"Watchlist '{watchlist_id}' not found.")

        total = db.query(WatchedIndicatorModel).filter(WatchedIndicatorModel.watchlist_id == wl.id).count()
        healthy = (
            db.query(WatchedIndicatorModel)
            .filter(WatchedIndicatorModel.watchlist_id == wl.id, WatchedIndicatorModel.monitoring_status == "HEALTHY")
            .count()
        )
        stale = (
            db.query(WatchedIndicatorModel)
            .filter(WatchedIndicatorModel.watchlist_id == wl.id, WatchedIndicatorModel.monitoring_status == "STALE")
            .count()
        )
        errors = (
            db.query(WatchedIndicatorModel)
            .filter(
                WatchedIndicatorModel.watchlist_id == wl.id,
                WatchedIndicatorModel.monitoring_status.in_(["ERROR", "DEGRADED"]),
            )
            .count()
        )
        malicious = (
            db.query(WatchedIndicatorModel)
            .filter(WatchedIndicatorModel.watchlist_id == wl.id, WatchedIndicatorModel.last_verdict == "MALICIOUS")
            .count()
        )

        if errors > 0:
            status = "ERROR"
        elif stale > 0:
            status = "STALE"
        elif total > 0 and healthy == total:
            status = "HEALTHY"
        elif wl.status == "PAUSED":
            status = "PAUSED"
        else:
            status = "HEALTHY"

        return WatchlistHealthResponse(
            watchlist_id=wl.id,
            status=status,
            total_indicators=total,
            healthy_count=healthy,
            stale_count=stale,
            error_count=errors,
            malicious_count=malicious,
            last_monitored_at=wl.last_monitored_at,
            next_cycle_at=wl.next_monitoring_cycle_at,
            provider_health_summary={"internal_memory": "HEALTHY", "local_feed": "HEALTHY"},
        )

    # =========================================================================
    # 3. Watched Indicators Management
    # =========================================================================

    @classmethod
    def add_indicator(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
        req: WatchedIndicatorCreateRequest,
        actor: str = "system",
    ) -> WatchedIndicatorModel:
        wl = (
            db.query(WatchlistModel)
            .filter(WatchlistModel.workspace_id == workspace_id, WatchlistModel.id == watchlist_id)
            .first()
        )
        if not wl:
            raise ValueError(f"Watchlist '{watchlist_id}' not found.")

        # Normalize indicator
        norm = IndicatorNormalizer.normalize(req.indicator_value, req.indicator_type)
        now = get_utc_now()

        # Check for duplicate in this watchlist
        existing = (
            db.query(WatchedIndicatorModel)
            .filter(
                WatchedIndicatorModel.workspace_id == workspace_id,
                WatchedIndicatorModel.watchlist_id == wl.id,
                WatchedIndicatorModel.normalized_value == norm.normalized_value,
            )
            .first()
        )
        if existing:
            return existing

        # Connect or reference canonical IndicatorModel
        ind_entity = (
            db.query(IndicatorModel)
            .filter(
                IndicatorModel.indicator_type == norm.type.value,
                IndicatorModel.normalized_value == norm.normalized_value,
            )
            .first()
        )
        if not ind_entity:
            ind_entity = IndicatorModel(
                id=str(uuid.uuid4()),
                indicator_type=norm.type.value,
                value=norm.raw_value,
                normalized_value=norm.normalized_value,
                first_seen=now,
                last_seen=now,
                confidence=1.0,
                reputation="UNKNOWN",
                metadata_json="{}",
                created_at=now,
                updated_at=now,
            )
            db.add(ind_entity)
            db.flush()

        item = WatchedIndicatorModel(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id or "default",
            watchlist_id=wl.id,
            indicator_id=ind_entity.id,
            indicator_type=norm.type.value,
            raw_value=norm.raw_value,
            normalized_value=norm.normalized_value,
            display_value=norm.normalized_value,
            monitoring_status=MonitoringStatusEnum.ACTIVE.value,
            priority=req.priority.value if req.priority else wl.priority,
            first_watched_at=now,
            last_checked_at=None,
            next_check_at=now,  # Eligible for immediate first check
            failure_count=0,
            consecutive_failure_count=0,
            source_incident_id=req.source_incident_id,
            source_investigation_id=req.source_investigation_id,
            created_by=actor,
            metadata_json=json.dumps(req.metadata or {}),
            created_at=now,
            updated_at=now,
        )
        db.add(item)

        # Knowledge Graph relationship (Section 23)
        cls._link_knowledge_graph(
            db=db,
            source_type="Watchlist",
            source_id=wl.id,
            rel_type="WATCHES",
            target_type="Indicator",
            target_id=ind_entity.id,
        )

        db.commit()
        db.refresh(item)

        # Realtime dispatch
        cls._broadcast_watchlist_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.WATCH_ITEM_ADDED,
            watchlist_id=wl.id,
            payload={
                "item_id": item.id,
                "type": item.indicator_type,
                "normalized_value": item.normalized_value,
            },
        )
        return item

    @classmethod
    def bulk_add_indicators(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
        req: WatchedIndicatorBulkAddRequest,
        actor: str = "system",
    ) -> List[WatchedIndicatorModel]:
        created: List[WatchedIndicatorModel] = []
        for ind_req in req.indicators:
            if req.source_incident_id and not ind_req.source_incident_id:
                ind_req.source_incident_id = req.source_incident_id
            if req.source_investigation_id and not ind_req.source_investigation_id:
                ind_req.source_investigation_id = req.source_investigation_id
            item = cls.add_indicator(db, workspace_id, watchlist_id, ind_req, actor)
            created.append(item)
        return created

    @classmethod
    def remove_indicator(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
        item_id: str,
        actor: str = "system",
    ) -> bool:
        item = (
            db.query(WatchedIndicatorModel)
            .filter(
                WatchedIndicatorModel.workspace_id == workspace_id,
                WatchedIndicatorModel.watchlist_id == watchlist_id,
                WatchedIndicatorModel.id == item_id,
            )
            .first()
        )
        if not item:
            return False

        norm_val = item.normalized_value
        db.delete(item)
        db.commit()

        cls._broadcast_watchlist_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.WATCH_ITEM_REMOVED,
            watchlist_id=watchlist_id,
            payload={"item_id": item_id, "normalized_value": norm_val},
        )
        return True

    @classmethod
    def list_indicators(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
        status: Optional[str] = None,
        verdict: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> WatchedIndicatorListResponse:
        query = db.query(WatchedIndicatorModel).filter(
            WatchedIndicatorModel.workspace_id == workspace_id,
            WatchedIndicatorModel.watchlist_id == watchlist_id,
        )

        if status:
            statuses = [s.strip().upper() for s in status.split(",") if s.strip()]
            query = query.filter(WatchedIndicatorModel.monitoring_status.in_(statuses))

        if verdict:
            query = query.filter(WatchedIndicatorModel.last_verdict == verdict.strip().upper())

        if q and q.strip():
            term = f"%{q.strip().lower()}%"
            query = query.filter(
                or_(
                    func.lower(WatchedIndicatorModel.normalized_value).like(term),
                    func.lower(WatchedIndicatorModel.raw_value).like(term),
                )
            )

        total = query.count()
        rows = (
            query.order_by(
                desc(WatchedIndicatorModel.last_change_detected_at),
                desc(WatchedIndicatorModel.updated_at),
            )
            .offset(offset)
            .limit(limit)
            .all()
        )

        items = [cls._build_indicator_response(r) for r in rows]
        return WatchedIndicatorListResponse(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
        )

    # =========================================================================
    # 4. Monitoring Execution Engine
    # =========================================================================

    @classmethod
    async def execute_single_indicator_check(
        cls,
        db: Session,
        item: WatchedIndicatorModel,
        force: bool = False,
    ) -> Optional[IntelligenceChangeModel]:
        """
        Executes a single continuous monitoring check for a watched indicator.
        Integrates with Section 52 ThreatIntelligenceService, creates snapshot,
        evaluates material changes, and dispatches alerts/notifications.
        """
        now = get_utc_now()
        wl: WatchlistModel = item.watchlist
        if not wl:
            return None

        # If watchlist or item is paused and not force, abort
        if (wl.status == WatchlistStatusEnum.PAUSED.value or item.monitoring_status == MonitoringStatusEnum.PAUSED.value) and not force:
            return None

        intel_svc = ThreatIntelligenceService()

        try:
            # 1. Query threat intelligence layer
            intel_res = await intel_svc.enrich_indicator(
                db=db,
                raw_indicator=item.raw_value,
                indicator_type=item.indicator_type,
                workspace_id=item.workspace_id,
                force_refresh=force,
            )

            curr_verdict = intel_res.overall_verdict.value.upper()
            curr_conf = intel_res.consensus_confidence
            curr_sev = "HIGH" if curr_verdict == "MALICIOUS" else ("MEDIUM" if curr_verdict == "SUSPICIOUS" else "NONE")
            curr_threats = intel_res.threat_types or []
            curr_conflicts = intel_res.is_conflicting
            curr_attrs = {
                "total_sources": intel_res.total_sources_queried,
            }

            # 2. Compute material fingerprint
            fp = cls.compute_snapshot_fingerprint(
                verdict=curr_verdict,
                severity=curr_sev,
                confidence=curr_conf,
                threat_types=curr_threats,
                has_conflicts=curr_conflicts,
                material_attributes=curr_attrs,
            )

            # 3. Fetch previous snapshot
            prev_snapshot = None
            if item.last_snapshot_id:
                prev_snapshot = (
                    db.query(IntelligenceSnapshotModel)
                    .filter(IntelligenceSnapshotModel.id == item.last_snapshot_id)
                    .first()
                )

            change_record = None

            # 4. Material Change Evaluation
            if prev_snapshot and prev_snapshot.fingerprint != fp:
                change_detected = cls.detect_material_change(
                    prev=prev_snapshot,
                    curr_verdict=curr_verdict,
                    curr_confidence=curr_conf,
                    curr_severity=curr_sev,
                    curr_threat_types=curr_threats,
                    curr_has_conflicts=curr_conflicts,
                    curr_attrs=curr_attrs,
                    sensitivity=wl.change_sensitivity,
                )

                if change_detected:
                    change_type, change_sev, summary, details = change_detected

                    # Create Snapshot record
                    new_snapshot = IntelligenceSnapshotModel(
                        id=str(uuid.uuid4()),
                        workspace_id=item.workspace_id,
                        watched_indicator_id=item.id,
                        indicator_type=item.indicator_type,
                        normalized_value=item.normalized_value,
                        provider_consensus_verdict=curr_verdict,
                        consensus_confidence=curr_conf,
                        severity=curr_sev,
                        sources_count=intel_res.total_sources_queried,
                        has_conflicts=curr_conflicts,
                        threat_types_json=json.dumps(curr_threats),
                        normalized_data_json=json.dumps(curr_attrs),
                        fingerprint=fp,
                        retrieved_at=now,
                        created_at=now,
                    )
                    db.add(new_snapshot)
                    db.flush()

                    # Create Change record
                    change_record = IntelligenceChangeModel(
                        id=str(uuid.uuid4()),
                        workspace_id=item.workspace_id,
                        watchlist_id=wl.id,
                        watched_indicator_id=item.id,
                        indicator_type=item.indicator_type,
                        normalized_value=item.normalized_value,
                        change_type=change_type,
                        change_severity=change_sev,
                        previous_snapshot_id=prev_snapshot.id,
                        current_snapshot_id=new_snapshot.id,
                        previous_verdict=prev_snapshot.provider_consensus_verdict,
                        current_verdict=curr_verdict,
                        previous_confidence=prev_snapshot.consensus_confidence,
                        current_confidence=curr_conf,
                        previous_severity=prev_snapshot.severity,
                        current_severity=curr_sev,
                        change_summary=summary,
                        change_details_json=json.dumps(details),
                        detected_at=now,
                    )
                    db.add(change_record)

                    # 5. Evaluate Alert Creation (Section 48) with Cooldown Protection
                    if cls._should_create_alert(wl, change_sev):
                        if not cls._is_alert_in_cooldown(db, item, change_type, wl.cooldown_minutes):
                            alert_notif = cls._dispatch_security_alert(
                                db=db,
                                wl=wl,
                                item=item,
                                change=change_record,
                                summary=summary,
                                severity=change_sev,
                            )
                            if alert_notif:
                                change_record.alert_id = alert_notif.id

                    # 6. Evaluate In-App Notification (Section 47)
                    if wl.notify_on_change:
                        sys_notif = cls._dispatch_system_notification(
                            db=db,
                            wl=wl,
                            item=item,
                            change=change_record,
                            summary=summary,
                            severity=change_sev,
                        )
                        if sys_notif:
                            change_record.notification_id = sys_notif.id

                    # Update item last change
                    item.last_change_detected_at = now
                    item.last_snapshot_id = new_snapshot.id

                    # Broadcast change event
                    cls._broadcast_watchlist_event(
                        workspace_id=item.workspace_id,
                        event_type=RealtimeEventTypeEnum.INTELLIGENCE_CHANGE_DETECTED,
                        watchlist_id=wl.id,
                        payload={
                            "change_id": change_record.id,
                            "change_type": change_type,
                            "severity": change_sev,
                            "normalized_value": item.normalized_value,
                            "summary": summary,
                        },
                    )

            elif not prev_snapshot:
                # First snapshot creation
                new_snapshot = IntelligenceSnapshotModel(
                    id=str(uuid.uuid4()),
                    workspace_id=item.workspace_id,
                    watched_indicator_id=item.id,
                    indicator_type=item.indicator_type,
                    normalized_value=item.normalized_value,
                    provider_consensus_verdict=curr_verdict,
                    consensus_confidence=curr_conf,
                    severity=curr_sev,
                    sources_count=intel_res.total_sources_queried,
                    has_conflicts=curr_conflicts,
                    threat_types_json=json.dumps(curr_threats),
                    normalized_data_json=json.dumps(curr_attrs),
                    fingerprint=fp,
                    retrieved_at=now,
                    created_at=now,
                )
                db.add(new_snapshot)
                item.last_snapshot_id = new_snapshot.id

            # 7. Update Item Status & Schedule
            interval_mins = wl.check_interval_minutes or 60
            item.last_checked_at = now
            item.last_successful_check_at = now
            item.next_check_at = now + timedelta(minutes=interval_mins)
            item.monitoring_status = MonitoringStatusEnum.HEALTHY.value
            item.last_verdict = curr_verdict
            item.last_confidence = curr_conf
            item.last_severity = curr_sev
            item.consecutive_failure_count = 0
            item.last_error_message = None
            item.updated_at = now

            db.commit()
            return change_record

        except Exception as exc:
            logger.error("Error checking watched indicator %s: %s", item.id, exc, exc_info=True)
            item.last_checked_at = now
            item.last_failed_check_at = now
            item.failure_count += 1
            item.consecutive_failure_count += 1
            item.last_error_message = str(exc)

            if item.consecutive_failure_count >= 3:
                item.monitoring_status = MonitoringStatusEnum.ERROR.value
            else:
                item.monitoring_status = MonitoringStatusEnum.DEGRADED.value

            # Retry after 15 minutes on failure
            item.next_check_at = now + timedelta(minutes=15)
            item.updated_at = now
            db.commit()
            return None

    @classmethod
    async def execute_monitoring_cycle(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: Optional[str] = None,
        job_id: Optional[str] = None,
        trigger_type: str = "SCHEDULED",
    ) -> List[WatchlistMonitoringRunResponse]:
        """
        Executes continuous monitoring check cycle for all due watchlists.
        Records WatchlistMonitoringRunModel execution metrics.
        """
        now = get_utc_now()
        query = db.query(WatchlistModel).filter(
            WatchlistModel.workspace_id == workspace_id,
            WatchlistModel.status == WatchlistStatusEnum.ACTIVE.value,
        )
        if watchlist_id:
            query = query.filter(WatchlistModel.id == watchlist_id)
        else:
            query = query.filter(
                or_(
                    WatchlistModel.next_monitoring_cycle_at.is_(None),
                    WatchlistModel.next_monitoring_cycle_at <= now,
                )
            )

        watchlists = query.all()
        runs: List[WatchlistMonitoringRunResponse] = []

        for wl in watchlists:
            run_id = str(uuid.uuid4())
            started_at = get_utc_now()

            # Find due items
            due_items = (
                db.query(WatchedIndicatorModel)
                .filter(
                    WatchedIndicatorModel.watchlist_id == wl.id,
                    WatchedIndicatorModel.monitoring_status.in_(
                        [
                            MonitoringStatusEnum.ACTIVE.value,
                            MonitoringStatusEnum.HEALTHY.value,
                            MonitoringStatusEnum.STALE.value,
                            MonitoringStatusEnum.DEGRADED.value,
                        ]
                    ),
                    or_(
                        WatchedIndicatorModel.next_check_at.is_(None),
                        WatchedIndicatorModel.next_check_at <= started_at,
                    ),
                )
                .all()
            )

            run = WatchlistMonitoringRunModel(
                id=run_id,
                workspace_id=workspace_id,
                watchlist_id=wl.id,
                job_id=job_id,
                trigger_type=trigger_type,
                status=MonitoringRunStatusEnum.RUNNING.value,
                items_due=len(due_items),
                items_checked=0,
                items_changed=0,
                items_failed=0,
                alerts_created=0,
                notifications_created=0,
                started_at=started_at,
            )
            db.add(run)
            db.commit()

            items_checked = 0
            items_changed = 0
            items_failed = 0
            alerts_created = 0
            notifications_created = 0

            for item in due_items:
                chg = await cls.execute_single_indicator_check(db, item, force=(trigger_type == "MANUAL"))
                items_checked += 1
                if chg:
                    items_changed += 1
                    if chg.alert_id:
                        alerts_created += 1
                    if chg.notification_id:
                        notifications_created += 1
                if item.consecutive_failure_count > 0:
                    items_failed += 1

            completed_at = get_utc_now()
            duration_ms = int((completed_at - started_at).total_seconds() * 1000)

            run_status = (
                MonitoringRunStatusEnum.SUCCEEDED.value
                if items_failed == 0
                else (
                    MonitoringRunStatusEnum.PARTIALLY_SUCCEEDED.value
                    if items_checked > items_failed
                    else MonitoringRunStatusEnum.FAILED.value
                )
            )

            run.status = run_status
            run.items_checked = items_checked
            run.items_changed = items_changed
            run.items_failed = items_failed
            run.alerts_created = alerts_created
            run.notifications_created = notifications_created
            run.completed_at = completed_at
            run.duration_ms = duration_ms

            # Update Watchlist next cycle
            interval_mins = wl.check_interval_minutes or 60
            wl.last_monitored_at = completed_at
            wl.next_monitoring_cycle_at = completed_at + timedelta(minutes=interval_mins)

            db.commit()
            runs.append(cls._build_run_response(run))

            # Broadcast run completion
            cls._broadcast_watchlist_event(
                workspace_id=workspace_id,
                event_type=RealtimeEventTypeEnum.WATCH_CHECK_COMPLETED,
                watchlist_id=wl.id,
                payload={
                    "run_id": run.id,
                    "status": run.status,
                    "items_checked": items_checked,
                    "items_changed": items_changed,
                },
            )

        return runs

    # =========================================================================
    # 5. Quick-Watch & Investigation Integration
    # =========================================================================

    @classmethod
    async def quick_watch(
        cls,
        db: Session,
        workspace_id: str,
        req: QuickWatchRequest,
        actor: str = "system",
    ) -> WatchedIndicatorResponse:
        """
        Instant watch workflow from Investigation, Incident, or Alert.
        Finds or creates watchlist, links source context, and triggers immediate check.
        """
        target_wl: Optional[WatchlistModel] = None

        if req.watchlist_id:
            target_wl = (
                db.query(WatchlistModel)
                .filter(WatchlistModel.workspace_id == workspace_id, WatchlistModel.id == req.watchlist_id)
                .first()
            )

        if not target_wl:
            wl_name = req.watchlist_name or "Investigation Watchlist"
            target_wl = (
                db.query(WatchlistModel)
                .filter(WatchlistModel.workspace_id == workspace_id, WatchlistModel.name == wl_name)
                .first()
            )
            if not target_wl:
                target_wl = cls.create_watchlist(
                    db=db,
                    workspace_id=workspace_id,
                    req=WatchlistCreateRequest(
                        name=wl_name,
                        description="Default watchlist tracking observables added from active investigations & incidents.",
                        priority=WatchlistPriorityEnum.HIGH,
                        check_interval_minutes=60,
                        alert_threshold=AlertThresholdEnum.HIGH,
                    ),
                    actor=actor,
                )

        item = cls.add_indicator(
            db=db,
            workspace_id=workspace_id,
            watchlist_id=target_wl.id,
            req=WatchedIndicatorCreateRequest(
                indicator_value=req.indicator_value,
                indicator_type=req.indicator_type,
                priority=WatchlistPriorityEnum.HIGH,
                source_incident_id=req.source_incident_id,
                source_investigation_id=req.source_investigation_id,
                metadata={"reason": req.reason} if req.reason else {},
            ),
            actor=actor,
        )

        # Trigger immediate synchronous first check for snappy analyst feedback
        await cls.execute_single_indicator_check(db, item, force=True)
        db.refresh(item)
        return cls._build_indicator_response(item)

    # =========================================================================
    # 6. Change and Run Listing Queries
    # =========================================================================

    @classmethod
    def list_changes(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: Optional[str] = None,
        severity: Optional[str] = None,
        change_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> IntelligenceChangeListResponse:
        query = db.query(IntelligenceChangeModel).filter(IntelligenceChangeModel.workspace_id == workspace_id)
        if watchlist_id:
            query = query.filter(IntelligenceChangeModel.watchlist_id == watchlist_id)
        if severity:
            query = query.filter(IntelligenceChangeModel.change_severity == severity.strip().upper())
        if change_type:
            query = query.filter(IntelligenceChangeModel.change_type == change_type.strip())

        total = query.count()
        rows = (
            query.order_by(desc(IntelligenceChangeModel.detected_at))
            .offset(offset)
            .limit(limit)
            .all()
        )
        return IntelligenceChangeListResponse(
            items=[cls._build_change_response(r) for r in rows],
            total=total,
            offset=offset,
            limit=limit,
        )

    @classmethod
    def list_runs(
        cls,
        db: Session,
        workspace_id: str,
        watchlist_id: str,
        limit: int = 20,
    ) -> WatchlistMonitoringRunListResponse:
        query = db.query(WatchlistMonitoringRunModel).filter(
            WatchlistMonitoringRunModel.workspace_id == workspace_id,
            WatchlistMonitoringRunModel.watchlist_id == watchlist_id,
        )
        total = query.count()
        rows = query.order_by(desc(WatchlistMonitoringRunModel.started_at)).limit(limit).all()
        return WatchlistMonitoringRunListResponse(
            items=[cls._build_run_response(r) for r in rows],
            total=total,
        )

    # =========================================================================
    # 7. Helper & Integration Functions
    # =========================================================================

    @classmethod
    def _should_create_alert(cls, wl: WatchlistModel, change_sev: str) -> bool:
        if not wl.alert_threshold or wl.alert_threshold == AlertThresholdEnum.NONE.value:
            return False
        return SEVERITY_ORDER.get(change_sev, 0) >= SEVERITY_ORDER.get(wl.alert_threshold, 0)

    @classmethod
    def _is_alert_in_cooldown(
        cls,
        db: Session,
        item: WatchedIndicatorModel,
        change_type: str,
        cooldown_minutes: int,
    ) -> bool:
        """
        Suppresses duplicate alert generation if an alert for this indicator
        and change type was already created within the cooldown window.
        """
        if not cooldown_minutes or cooldown_minutes <= 0:
            return False

        since = get_utc_now() - timedelta(minutes=cooldown_minutes)
        recent_alert = (
            db.query(IntelligenceChangeModel)
            .filter(
                IntelligenceChangeModel.watched_indicator_id == item.id,
                IntelligenceChangeModel.change_type == change_type,
                IntelligenceChangeModel.alert_id.isnot(None),
                IntelligenceChangeModel.detected_at >= since,
            )
            .first()
        )
        return recent_alert is not None

    @classmethod
    def _dispatch_security_alert(
        cls,
        db: Session,
        wl: WatchlistModel,
        item: WatchedIndicatorModel,
        change: IntelligenceChangeModel,
        summary: str,
        severity: str,
    ) -> Optional[NotificationModel]:
        """
        Creates a formal Security Alert in the Section 48 Alert Management Workspace.
        """
        dedup_key = f"watchlist_alert:{wl.id}:{item.id}:{change.change_type}:{change.current_verdict}"
        title = f"Watched {item.indicator_type}: '{item.normalized_value}' changed ({change.change_type})"
        message = f"Monitored indicator in watchlist '{wl.name}' transitioned. {summary}"

        return NotificationService.create_notification(
            db=db,
            workspace_id=wl.workspace_id,
            category="SECURITY_ALERT",
            notification_type="WATCHLIST_INDICATOR_CHANGED",
            severity=severity,
            title=title,
            message=message,
            source_type="WATCHLIST",
            source_id=wl.id,
            deduplication_key=dedup_key,
            investigation_id=item.source_investigation_id,
            metadata={
                "watchlist_id": wl.id,
                "watchlist_name": wl.name,
                "watched_indicator_id": item.id,
                "change_id": change.id,
                "indicator_type": item.indicator_type,
                "normalized_value": item.normalized_value,
                "source_incident_id": item.source_incident_id,
                "source_investigation_id": item.source_investigation_id,
            },
        )

    @classmethod
    def _dispatch_system_notification(
        cls,
        db: Session,
        wl: WatchlistModel,
        item: WatchedIndicatorModel,
        change: IntelligenceChangeModel,
        summary: str,
        severity: str,
    ) -> Optional[NotificationModel]:
        dedup_key = f"watchlist_notif:{wl.id}:{item.id}:{change.change_type}:{change.id}"
        return NotificationService.create_notification(
            db=db,
            workspace_id=wl.workspace_id,
            category="SYSTEM",
            notification_type="WATCHLIST_CHANGE",
            severity=severity,
            title=f"Watchlist Alert: {item.normalized_value}",
            message=summary,
            source_type="WATCHLIST",
            source_id=wl.id,
            deduplication_key=dedup_key,
            investigation_id=item.source_investigation_id,
            metadata={"watchlist_id": wl.id, "watched_indicator_id": item.id},
        )

    @classmethod
    def _link_knowledge_graph(
        cls,
        db: Session,
        source_type: str,
        source_id: str,
        rel_type: str,
        target_type: str,
        target_id: str,
    ) -> None:
        try:
            existing = (
                db.query(RelationshipModel)
                .filter(
                    RelationshipModel.source_type == source_type,
                    RelationshipModel.source_id == source_id,
                    RelationshipModel.relationship_type == rel_type,
                    RelationshipModel.target_type == target_type,
                    RelationshipModel.target_id == target_id,
                )
                .first()
            )
            if not existing:
                rel = RelationshipModel(
                    id=str(uuid.uuid4()),
                    source_type=source_type,
                    source_id=source_id,
                    relationship_type=rel_type,
                    target_type=target_type,
                    target_id=target_id,
                    confidence=1.0,
                )
                db.add(rel)
                db.flush()
        except Exception as e:
            logger.warning("Failed to link relationship in Knowledge Graph: %s", e)

    @classmethod
    def _broadcast_watchlist_event(
        cls,
        workspace_id: str,
        event_type: RealtimeEventTypeEnum,
        watchlist_id: str,
        payload: Dict[str, Any],
    ) -> None:
        try:
            event = RealtimeEvent(
                event_type=event_type,
                resource_scope=RealtimeResourceScopeEnum.WATCHLIST,
                resource_id=watchlist_id,
                workspace_id=workspace_id,
                payload=RealtimeEventPayload(
                    stage=event_type.value,
                    message=f"Watchlist event: {event_type.value}",
                    details=payload,
                ),
            )
            RealtimePublisher.publish_event(event)
        except Exception as exc:
            logger.debug("Realtime dispatch failed (non-blocking): %s", exc)

    @classmethod
    def _build_watchlist_summary(cls, db: Session, wl: WatchlistModel) -> WatchlistSummaryResponse:
        total = db.query(WatchedIndicatorModel).filter(WatchedIndicatorModel.watchlist_id == wl.id).count()
        active = (
            db.query(WatchedIndicatorModel)
            .filter(
                WatchedIndicatorModel.watchlist_id == wl.id,
                WatchedIndicatorModel.monitoring_status.in_(["ACTIVE", "HEALTHY"]),
            )
            .count()
        )
        stale = (
            db.query(WatchedIndicatorModel)
            .filter(WatchedIndicatorModel.watchlist_id == wl.id, WatchedIndicatorModel.monitoring_status == "STALE")
            .count()
        )
        malicious = (
            db.query(WatchedIndicatorModel)
            .filter(WatchedIndicatorModel.watchlist_id == wl.id, WatchedIndicatorModel.last_verdict == "MALICIOUS")
            .count()
        )

        return WatchlistSummaryResponse(
            id=wl.id,
            workspace_id=wl.workspace_id,
            name=wl.name,
            description=wl.description,
            status=wl.status,
            priority=wl.priority,
            owner_user_id=wl.owner_user_id,
            team_id=wl.team_id,
            check_interval_minutes=wl.check_interval_minutes,
            change_sensitivity=wl.change_sensitivity,
            alert_threshold=wl.alert_threshold,
            notify_on_change=wl.notify_on_change,
            cooldown_minutes=wl.cooldown_minutes,
            total_indicators_count=total,
            active_indicators_count=active,
            stale_indicators_count=stale,
            malicious_indicators_count=malicious,
            last_monitored_at=wl.last_monitored_at,
            next_monitoring_cycle_at=wl.next_monitoring_cycle_at,
            created_by=wl.created_by,
            created_at=wl.created_at,
            updated_at=wl.updated_at,
        )

    @classmethod
    def _build_indicator_response(cls, item: WatchedIndicatorModel) -> WatchedIndicatorResponse:
        return WatchedIndicatorResponse(
            id=item.id,
            watchlist_id=item.watchlist_id,
            workspace_id=item.workspace_id,
            indicator_id=item.indicator_id,
            indicator_type=item.indicator_type,
            raw_value=item.raw_value,
            normalized_value=item.normalized_value,
            display_value=item.display_value,
            monitoring_status=item.monitoring_status,
            priority=item.priority,
            first_watched_at=item.first_watched_at,
            last_checked_at=item.last_checked_at,
            next_check_at=item.next_check_at,
            last_successful_check_at=item.last_successful_check_at,
            last_failed_check_at=item.last_failed_check_at,
            last_change_detected_at=item.last_change_detected_at,
            last_snapshot_id=item.last_snapshot_id,
            last_verdict=item.last_verdict,
            last_confidence=item.last_confidence,
            last_severity=item.last_severity,
            failure_count=item.failure_count,
            consecutive_failure_count=item.consecutive_failure_count,
            last_error_message=item.last_error_message,
            source_incident_id=item.source_incident_id,
            source_investigation_id=item.source_investigation_id,
            created_at=item.created_at,
            updated_at=item.updated_at,
        )

    @classmethod
    def _build_change_response(cls, chg: IntelligenceChangeModel) -> IntelligenceChangeResponse:
        details = {}
        try:
            details = json.loads(chg.change_details_json or "{}")
        except Exception:
            pass
        return IntelligenceChangeResponse(
            id=chg.id,
            workspace_id=chg.workspace_id,
            watchlist_id=chg.watchlist_id,
            watched_indicator_id=chg.watched_indicator_id,
            indicator_type=chg.indicator_type,
            normalized_value=chg.normalized_value,
            change_type=chg.change_type,
            change_severity=chg.change_severity,
            previous_snapshot_id=chg.previous_snapshot_id,
            current_snapshot_id=chg.current_snapshot_id,
            previous_verdict=chg.previous_verdict,
            current_verdict=chg.current_verdict,
            previous_confidence=chg.previous_confidence,
            current_confidence=chg.current_confidence,
            previous_severity=chg.previous_severity,
            current_severity=chg.current_severity,
            change_summary=chg.change_summary,
            change_details=details,
            alert_id=chg.alert_id,
            notification_id=chg.notification_id,
            acknowledged=chg.acknowledged,
            acknowledged_at=chg.acknowledged_at,
            acknowledged_by=chg.acknowledged_by,
            detected_at=chg.detected_at,
        )

    @classmethod
    def _build_run_response(cls, run: WatchlistMonitoringRunModel) -> WatchlistMonitoringRunResponse:
        summary = {}
        try:
            summary = json.loads(run.run_summary_json or "{}")
        except Exception:
            pass
        return WatchlistMonitoringRunResponse(
            id=run.id,
            workspace_id=run.workspace_id,
            watchlist_id=run.watchlist_id,
            job_id=run.job_id,
            trigger_type=run.trigger_type,
            status=run.status,
            items_due=run.items_due,
            items_checked=run.items_checked,
            items_changed=run.items_changed,
            items_failed=run.items_failed,
            alerts_created=run.alerts_created,
            notifications_created=run.notifications_created,
            started_at=run.started_at,
            completed_at=run.completed_at,
            duration_ms=run.duration_ms,
            error_message=run.error_message,
            run_summary=summary,
        )
