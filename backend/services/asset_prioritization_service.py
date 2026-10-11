"""
Section 64: Risk-Based Asset Prioritization Service.
Authoritative operational prioritization engine determining which assets, identities,
applications, and services require immediate analyst attention.

Builds on existing authoritative systems:
- Section 63 Asset & Identity Inventory (AssetModel, IdentityModel)
- Section 26 Unified Risk Engine (authoritative security risk)
- Section 62 Attack Surface Intelligence (exposure state)
- Section 48/50/51 Alerts and Incidents (operational cases)
- Section 45 Background Jobs (asynchronous recalculation)
- Section 46 Realtime WebSockets (priority change events)
- Section 47 Persistent Notifications (escalation alerts)
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple, Set

from sqlalchemy.orm import Session
from sqlalchemy import desc, asc, or_, and_, func

from backend.db.models import (
    AssetModel,
    AssetPrioritizationPolicyModel,
    AssetPrioritySnapshotModel,
    IncidentModel,
    NotificationModel,
    InventoryOverrideModel,
    AuditLogModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.asset_prioritization import (
    PriorityBandEnum,
    PriorityDataQualityEnum,
    PriorityPolicyStatusEnum,
    PrioritizationFactorContribution,
    PriorityDataQualityReport,
    PriorityExplanationResponse,
    PrioritizedAssetItem,
    PrioritizedAssetSummary,
)
from backend.schemas.realtime import RealtimeEventTypeEnum, RealtimeResourceScopeEnum, RealtimeEvent
from backend.schemas.notification import NotificationTypeEnum, NotificationCategoryEnum, NotificationSeverityEnum
from backend.services.realtime_service import RealtimePublisher
from backend.services.notification_service import NotificationService

logger = logging.getLogger("cyberguard.services.asset_prioritization")


def emit_realtime_priority_event(
    workspace_id: str,
    event_type: str,
    resource_id: str,
    payload: Dict[str, Any],
) -> None:
    try:
        evt = RealtimeEvent(
            schema_version=1,
            event_id=generate_uuid(),
            sequence=1,
            event_type=event_type,
            resource_type=RealtimeResourceScopeEnum.ASSET.value,
            resource_id=resource_id,
            workspace_id=workspace_id,
            status="SUCCESS",
            message=f"Asset priority update: {event_type}",
            payload=payload,
            created_at=get_utc_now(),
        )
        RealtimePublisher._async_broadcast(evt)
    except Exception as e:
        logger.debug("Realtime priority event broadcast skipped: %s", e)


DEFAULT_POLICY_CONFIGURATION = {
    "name": "Default Operational Prioritization Policy",
    "description": "Standard balanced weights incorporating Unified Risk, Business Criticality, Attack Surface Exposure, and Active Incidents.",
    "weights": {
        "unified_security_risk": 0.40,
        "business_criticality": 0.25,
        "exposure_context": 0.15,
        "active_incidents": 0.10,
        "unmanaged_shadow_it": 0.05,
        "environment_tier": 0.05,
    },
    "criticality_points": {
        "CRITICAL": 100.0,
        "HIGH": 75.0,
        "MEDIUM": 40.0,
        "LOW": 10.0,
        "UNKNOWN": 35.0,  # Uncertainty buffer: unknown is NOT safe
    },
    "exposure_points": {
        "PUBLICLY_EXPOSED": 100.0,
        "INTERNALLY_REACHABLE": 40.0,
        "INTERNALLY_ONLY": 10.0,
        "UNKNOWN": 30.0,  # Uncertainty buffer
    },
    "environment_points": {
        "PRODUCTION": 100.0,
        "CORP": 50.0,
        "STAGING": 40.0,
        "DEVELOPMENT": 10.0,
        "LAB": 10.0,
        "UNKNOWN": 30.0,
    },
    "bands": {
        "P1": {"min_score": 80.0, "label": "CRITICAL"},
        "P2": {"min_score": 60.0, "label": "HIGH"},
        "P3": {"min_score": 35.0, "label": "MEDIUM"},
        "P4": {"min_score": 0.0, "label": "LOW"},
    },
    "staleness_threshold_hours": {
        "inventory": 720,  # 30 days
        "risk": 48,        # 2 days
        "exposure": 168,   # 7 days
    },
}


class AssetPrioritizationService:
    """
    Central operational engine for Section 64: Risk-Based Asset Prioritization.
    Calculates deterministic, versioned, explainable priority rankings without duplicating
    underlying risk, threat intel, or exposure scoring.
    """

    @classmethod
    def get_or_create_active_policy(
        cls, db: Session, workspace_id: str
    ) -> AssetPrioritizationPolicyModel:
        """
        Retrieves the currently active policy for the workspace, or creates the default policy v1.
        """
        policy = (
            db.query(AssetPrioritizationPolicyModel)
            .filter(
                AssetPrioritizationPolicyModel.workspace_id == workspace_id,
                AssetPrioritizationPolicyModel.status == PriorityPolicyStatusEnum.ACTIVE.value,
            )
            .order_by(desc(AssetPrioritizationPolicyModel.version))
            .first()
        )

        if not policy:
            policy = AssetPrioritizationPolicyModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                name="Default Operational Prioritization Policy",
                description="Authoritative default operational policy weighting risk, criticality, exposure, and incidents.",
                version=1,
                status=PriorityPolicyStatusEnum.ACTIVE.value,
                configuration_json=json.dumps(DEFAULT_POLICY_CONFIGURATION),
                created_by="SYSTEM",
                activated_at=get_utc_now(),
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
            logger.info("Created default active AssetPrioritizationPolicy v1 for workspace %s", workspace_id)

        return policy

    @classmethod
    def create_policy(
        cls,
        db: Session,
        workspace_id: str,
        name: str,
        configuration: Dict[str, Any],
        description: Optional[str] = None,
        created_by: str = "SYSTEM",
        status: str = "DRAFT",
    ) -> AssetPrioritizationPolicyModel:
        """
        Creates a new prioritization policy draft or active policy.
        """
        # Determine next version
        latest = (
            db.query(func.max(AssetPrioritizationPolicyModel.version))
            .filter(AssetPrioritizationPolicyModel.workspace_id == workspace_id)
            .scalar()
        )
        next_ver = (latest or 0) + 1

        policy = AssetPrioritizationPolicyModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            name=name,
            description=description,
            version=next_ver,
            status=status,
            configuration_json=json.dumps(configuration),
            created_by=created_by,
            activated_at=get_utc_now() if status == PriorityPolicyStatusEnum.ACTIVE.value else None,
        )

        if status == PriorityPolicyStatusEnum.ACTIVE.value:
            # Deactivate previous active policies
            db.query(AssetPrioritizationPolicyModel).filter(
                AssetPrioritizationPolicyModel.workspace_id == workspace_id,
                AssetPrioritizationPolicyModel.status == PriorityPolicyStatusEnum.ACTIVE.value,
            ).update(
                {
                    AssetPrioritizationPolicyModel.status: PriorityPolicyStatusEnum.ARCHIVED.value,
                    AssetPrioritizationPolicyModel.deactivated_at: get_utc_now(),
                }
            )

        db.add(policy)
        db.commit()
        db.refresh(policy)
        return policy

    @classmethod
    def activate_policy(
        cls, db: Session, workspace_id: str, policy_id: str
    ) -> AssetPrioritizationPolicyModel:
        """
        Activates a specific policy and archives any previously active policy.
        """
        target = (
            db.query(AssetPrioritizationPolicyModel)
            .filter(
                AssetPrioritizationPolicyModel.workspace_id == workspace_id,
                AssetPrioritizationPolicyModel.id == policy_id,
            )
            .first()
        )
        if not target:
            raise ValueError(f"Prioritization policy {policy_id} not found in workspace {workspace_id}")

        now = get_utc_now()
        # Archive existing active policies
        db.query(AssetPrioritizationPolicyModel).filter(
            AssetPrioritizationPolicyModel.workspace_id == workspace_id,
            AssetPrioritizationPolicyModel.status == PriorityPolicyStatusEnum.ACTIVE.value,
            AssetPrioritizationPolicyModel.id != policy_id,
        ).update(
            {
                AssetPrioritizationPolicyModel.status: PriorityPolicyStatusEnum.ARCHIVED.value,
                AssetPrioritizationPolicyModel.deactivated_at: now,
            }
        )

        target.status = PriorityPolicyStatusEnum.ACTIVE.value
        target.activated_at = now
        db.commit()
        db.refresh(target)

        # Broadcast realtime event
        emit_realtime_priority_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.ASSET_PRIORITY_POLICY_ACTIVATED.value,
            resource_id=target.id,
            payload={"policy_id": target.id, "name": target.name, "version": target.version},
        )

        return target

    @classmethod
    def calculate_asset_priority(
        cls,
        db: Session,
        asset: AssetModel,
        policy: Optional[AssetPrioritizationPolicyModel] = None,
        save_snapshot: bool = True,
    ) -> Tuple[AssetModel, Optional[AssetPrioritySnapshotModel]]:
        """
        Computes deterministic, explainable priority for an individual asset using authoritative signals.
        Prevents double-counting by consuming the Section 26 Unified Risk score as a single input.
        """
        workspace_id = asset.workspace_id
        if not policy:
            policy = cls.get_or_create_active_policy(db, workspace_id)

        cfg = policy.configuration_dict or DEFAULT_POLICY_CONFIGURATION
        weights = cfg.get("weights", DEFAULT_POLICY_CONFIGURATION["weights"])
        crit_pts = cfg.get("criticality_points", DEFAULT_POLICY_CONFIGURATION["criticality_points"])
        exp_pts = cfg.get("exposure_points", DEFAULT_POLICY_CONFIGURATION["exposure_points"])
        env_pts = cfg.get("environment_points", DEFAULT_POLICY_CONFIGURATION["environment_points"])
        bands_cfg = cfg.get("bands", DEFAULT_POLICY_CONFIGURATION["bands"])

        contributors: List[PrioritizationFactorContribution] = []
        issues: List[str] = []
        stale_sources: List[str] = []
        uncertain_sources: List[str] = []

        now = get_utc_now()
        previous_band = asset.priority_band or PriorityBandEnum.UNPRIORITIZED.value

        # ----------------------------------------------------------------------
        # 1. Authoritative Unified Security Risk (Section 26)
        # ----------------------------------------------------------------------
        weight_risk = weights.get("unified_security_risk", 0.40)
        risk_raw = asset.risk_score or 0.0
        risk_points = min(max(float(risk_raw), 0.0), 100.0)
        risk_weighted = risk_points * weight_risk

        risk_level_str = "HIGH" if risk_points >= 70.0 else ("MEDIUM" if risk_points >= 40.0 else "LOW")
        contributors.append(
            PrioritizationFactorContribution(
                factor="unified_security_risk",
                label="Unified Security Risk",
                value=round(risk_points, 1),
                points=round(risk_points, 1),
                weight=weight_risk,
                weighted_points=round(risk_weighted, 2),
                source="Section 26 Unified Risk Engine",
                contribution_level=risk_level_str,
                description=f"Authoritative security risk score of {round(risk_points, 1)} ({asset.risk_level})",
            )
        )

        # ----------------------------------------------------------------------
        # 2. Business Criticality (Section 63)
        # ----------------------------------------------------------------------
        weight_crit = weights.get("business_criticality", 0.25)
        crit_str = (asset.criticality or "UNKNOWN").upper()
        crit_points = crit_pts.get(crit_str, crit_pts.get("UNKNOWN", 35.0))
        crit_weighted = crit_points * weight_crit

        if crit_str == "UNKNOWN":
            uncertain_sources.append("criticality")
            issues.append("Business criticality is unassigned/unknown; applied 35pt uncertainty buffer")

        crit_contrib_level = "CRITICAL" if crit_str == "CRITICAL" else ("HIGH" if crit_str == "HIGH" else ("MEDIUM" if crit_str in ["MEDIUM", "UNKNOWN"] else "LOW"))
        contributors.append(
            PrioritizationFactorContribution(
                factor="business_criticality",
                label="Business Criticality",
                value=crit_str,
                points=round(crit_points, 1),
                weight=weight_crit,
                weighted_points=round(crit_weighted, 2),
                source="Section 63 Asset Inventory",
                contribution_level=crit_contrib_level,
                description=f"Asset holds business importance tier '{crit_str}'",
            )
        )

        # ----------------------------------------------------------------------
        # 3. Attack Surface Exposure Context (Section 62)
        # ----------------------------------------------------------------------
        weight_exp = weights.get("exposure_context", 0.15)
        exp_str = (asset.exposure_state or "UNKNOWN").upper()
        # If unknown exposure but active exposures exist, treat as publicly exposed
        if exp_str == "UNKNOWN" and asset.active_exposure_count > 0:
            exp_str = "PUBLICLY_EXPOSED"

        exp_points = exp_pts.get(exp_str, exp_pts.get("UNKNOWN", 30.0))
        exp_weighted = exp_points * weight_exp

        if exp_str == "UNKNOWN":
            uncertain_sources.append("exposure_state")
            issues.append("Attack surface exposure state is unverified; applied 30pt uncertainty buffer")

        exp_contrib_level = "HIGH" if exp_str == "PUBLICLY_EXPOSED" else ("MEDIUM" if exp_str in ["INTERNALLY_REACHABLE", "UNKNOWN"] else "LOW")
        contributors.append(
            PrioritizationFactorContribution(
                factor="exposure_context",
                label="Attack Surface Exposure",
                value=exp_str,
                points=round(exp_points, 1),
                weight=weight_exp,
                weighted_points=round(exp_weighted, 2),
                source="Section 62 Attack Surface Intelligence",
                contribution_level=exp_contrib_level,
                description=f"Reachable external attack surface condition: '{exp_str}'",
            )
        )

        # ----------------------------------------------------------------------
        # 4. Active Operational Incidents (Section 50/51)
        # ----------------------------------------------------------------------
        weight_inc = weights.get("active_incidents", 0.10)
        # Query open incidents in workspace related to this asset
        open_incidents_q = db.query(IncidentModel).filter(
            IncidentModel.workspace_id == workspace_id,
            IncidentModel.status.in_(["NEW", "OPEN", "ACKNOWLEDGED", "INVESTIGATING"]),
            or_(
                IncidentModel.title.ilike(f"%{asset.canonical_name}%"),
                IncidentModel.description.ilike(f"%{asset.canonical_name}%"),
                IncidentModel.title.ilike(f"%{asset.id}%"),
                IncidentModel.description.ilike(f"%{asset.id}%"),
            ),
        )
        open_incidents = open_incidents_q.all()
        inc_count = len(open_incidents)

        # Base incident points: 0 -> 0; 1 -> 60; 2 -> 85; 3+ -> 100
        if inc_count == 0:
            inc_points = 0.0
        elif inc_count == 1:
            inc_points = 60.0
        elif inc_count == 2:
            inc_points = 85.0
        else:
            inc_points = 100.0

        # Escalation bonus if any related incident breached or warning SLA
        has_sla_breach = any(inc.sla_status in ["BREACHED", "WARNING"] for inc in open_incidents)
        if has_sla_breach and inc_points > 0:
            inc_points = min(inc_points + 20.0, 100.0)

        inc_weighted = inc_points * weight_inc
        inc_contrib_level = "CRITICAL" if (inc_count > 0 and has_sla_breach) else ("HIGH" if inc_count >= 2 else ("MEDIUM" if inc_count == 1 else "NEGLIGIBLE"))
        contributors.append(
            PrioritizationFactorContribution(
                factor="active_incidents",
                label="Active Security Incidents",
                value=inc_count,
                points=round(inc_points, 1),
                weight=weight_inc,
                weighted_points=round(inc_weighted, 2),
                source="Section 50/51 Incident Management",
                contribution_level=inc_contrib_level,
                description=f"{inc_count} active open incident(s) currently affecting this asset"
                + (" (with active SLA urgency)" if has_sla_breach else ""),
            )
        )

        # ----------------------------------------------------------------------
        # 5. Management & Shadow IT Context (Section 63)
        # ----------------------------------------------------------------------
        weight_unmanaged = weights.get("unmanaged_shadow_it", 0.05)
        is_unmanaged_or_shadow = (not asset.is_managed) or (
            asset.ownership_status in ["UNASSIGNED", "UNKNOWN", "CONFLICTED"]
        )
        unmanaged_points = 100.0 if is_unmanaged_or_shadow else 0.0
        unmanaged_weighted = unmanaged_points * weight_unmanaged

        if is_unmanaged_or_shadow:
            unmanaged_desc = "Unmanaged or unassigned asset (Shadow IT / missing governance)"
        else:
            unmanaged_desc = "Managed enterprise asset with assigned ownership"

        contributors.append(
            PrioritizationFactorContribution(
                factor="unmanaged_shadow_it",
                label="Management & Governance",
                value="UNMANAGED" if is_unmanaged_or_shadow else "MANAGED",
                points=round(unmanaged_points, 1),
                weight=weight_unmanaged,
                weighted_points=round(unmanaged_weighted, 2),
                source="Section 63 Inventory Ownership",
                contribution_level="MEDIUM" if is_unmanaged_or_shadow else "LOW",
                description=unmanaged_desc,
            )
        )

        # ----------------------------------------------------------------------
        # 6. Environment Tier Context
        # ----------------------------------------------------------------------
        weight_env = weights.get("environment_tier", 0.05)
        env_str = (asset.environment or "UNKNOWN").upper()
        env_points = env_pts.get(env_str, env_pts.get("UNKNOWN", 30.0))
        env_weighted = env_points * weight_env

        contributors.append(
            PrioritizationFactorContribution(
                factor="environment_tier",
                label="Environment Tier",
                value=env_str,
                points=round(env_points, 1),
                weight=weight_env,
                weighted_points=round(env_weighted, 2),
                source="Section 63 Inventory Environment",
                contribution_level="MEDIUM" if env_str == "PRODUCTION" else "LOW",
                description=f"Operational environment: '{env_str}'",
            )
        )

        # ----------------------------------------------------------------------
        # Sum & Determine Priority Band
        # ----------------------------------------------------------------------
        total_score = sum(c.weighted_points for c in contributors)
        bounded_score = round(min(max(total_score, 0.0), 100.0), 1)

        # Evaluate priority band against policy thresholds
        p1_thresh = bands_cfg.get("P1", {}).get("min_score", 80.0)
        p2_thresh = bands_cfg.get("P2", {}).get("min_score", 60.0)
        p3_thresh = bands_cfg.get("P3", {}).get("min_score", 35.0)

        if bounded_score >= p1_thresh:
            calculated_band = PriorityBandEnum.P1.value
        elif bounded_score >= p2_thresh:
            calculated_band = PriorityBandEnum.P2.value
        elif bounded_score >= p3_thresh:
            calculated_band = PriorityBandEnum.P3.value
        else:
            calculated_band = PriorityBandEnum.P4.value

        # ----------------------------------------------------------------------
        # Data Quality & Staleness Evaluation
        # ----------------------------------------------------------------------
        staleness_cfg = cfg.get("staleness_threshold_hours", DEFAULT_POLICY_CONFIGURATION["staleness_threshold_hours"])
        inv_stale_hours = staleness_cfg.get("inventory", 720)

        if asset.last_seen_at:
            delta_hours = (now - asset.last_seen_at.replace(tzinfo=timezone.utc if asset.last_seen_at.tzinfo is None else asset.last_seen_at.tzinfo)).total_seconds() / 3600.0
            if delta_hours > inv_stale_hours or asset.is_stale:
                stale_sources.append("inventory")
                issues.append(f"Inventory observations stale (> {inv_stale_hours}h without confirmation)")

        if stale_sources:
            quality_status = PriorityDataQualityEnum.STALE.value
        elif issues:
            quality_status = PriorityDataQualityEnum.DEGRADED.value
        else:
            quality_status = PriorityDataQualityEnum.GOOD.value

        data_quality_report = PriorityDataQualityReport(
            status=quality_status,
            issues=issues,
            stale_sources=stale_sources,
            uncertain_sources=uncertain_sources,
        )

        # ----------------------------------------------------------------------
        # Evaluate Effective Priority (respecting active manual override)
        # ----------------------------------------------------------------------
        is_override = False
        override_priority = asset.priority_override
        override_reason = asset.priority_override_reason
        override_by = asset.priority_override_by

        if asset.priority_override:
            # Check expiry
            if asset.priority_override_expires_at:
                exp = asset.priority_override_expires_at
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if now > exp:
                    # Expired override
                    override_priority = None
                    asset.priority_override = None
                    asset.priority_override_reason = f"Expired at {exp.isoformat()}"
                else:
                    is_override = True
            else:
                is_override = True

        effective_band = override_priority if (is_override and override_priority) else calculated_band

        # ----------------------------------------------------------------------
        # Transition Type Evaluation
        # ----------------------------------------------------------------------
        band_ranks = {"P1": 4, "P2": 3, "P3": 2, "P4": 1, "UNPRIORITIZED": 0}
        prev_rank = band_ranks.get(previous_band, 0)
        curr_rank = band_ranks.get(effective_band, 0)

        if previous_band == PriorityBandEnum.UNPRIORITIZED.value:
            transition_type = "INITIAL"
        elif curr_rank > prev_rank:
            transition_type = "ESCALATED"
        elif curr_rank < prev_rank:
            transition_type = "DEESCALATED"
        elif is_override:
            transition_type = "OVERRIDDEN"
        else:
            transition_type = "UNCHANGED"

        # ----------------------------------------------------------------------
        # Build Explanation JSON
        # ----------------------------------------------------------------------
        explanation_data = {
            "priority_band": calculated_band,
            "priority_score": bounded_score,
            "effective_priority": effective_band,
            "is_overridden": is_override,
            "override_priority": override_priority,
            "contributors": [c.model_dump() for c in contributors],
            "data_quality": data_quality_report.model_dump(),
            "policy": {
                "id": policy.id,
                "name": policy.name,
                "version": policy.version,
            },
            "calculated_at": now.isoformat(),
        }

        # Update AssetModel
        asset.priority_band = calculated_band
        asset.priority_score = bounded_score
        asset.priority_calculated_at = now
        asset.priority_policy_id = policy.id
        asset.priority_policy_version = policy.version
        asset.priority_data_quality = quality_status
        asset.priority_explanation_json = json.dumps(explanation_data)

        # ----------------------------------------------------------------------
        # Persist Snapshot
        # ----------------------------------------------------------------------
        snapshot = None
        if save_snapshot:
            snapshot = AssetPrioritySnapshotModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                asset_id=asset.id,
                priority_band=calculated_band,
                priority_score=bounded_score,
                policy_id=policy.id,
                policy_version=policy.version,
                risk_score=risk_points,
                business_criticality=crit_str,
                exposure_state=exp_str,
                active_incident_count=inc_count,
                data_quality=quality_status,
                explanation_json=json.dumps(explanation_data),
                is_override=is_override,
                override_priority=override_priority,
                override_reason=override_reason,
                override_by=override_by,
                previous_priority_band=previous_band,
                transition_type=transition_type,
                calculated_at=now,
            )
            db.add(snapshot)

        db.commit()
        db.refresh(asset)
        if snapshot:
            db.refresh(snapshot)

        # ----------------------------------------------------------------------
        # Emit Realtime Events & Notifications
        # ----------------------------------------------------------------------
        if transition_type in ["INITIAL", "ESCALATED", "DEESCALATED", "OVERRIDDEN"]:
            event_type = (
                RealtimeEventTypeEnum.ASSET_PRIORITY_ESCALATED.value
                if transition_type == "ESCALATED"
                else (
                    RealtimeEventTypeEnum.ASSET_PRIORITY_DEESCALATED.value
                    if transition_type == "DEESCALATED"
                    else RealtimeEventTypeEnum.ASSET_PRIORITY_CHANGED.value
                )
            )
            emit_realtime_priority_event(
                workspace_id=workspace_id,
                event_type=event_type,
                resource_id=asset.id,
                payload={
                    "asset_id": asset.id,
                    "canonical_name": asset.canonical_name,
                    "effective_priority": effective_band,
                    "priority_score": bounded_score,
                    "previous_priority": previous_band,
                    "transition_type": transition_type,
                },
            )

            # Trigger notification if escalated to P1
            if effective_band == PriorityBandEnum.P1.value and transition_type == "ESCALATED":
                try:
                    notif_type = (
                        NotificationTypeEnum.CRITICAL_ASSET_PRIORITY_P1.value
                        if crit_str == "CRITICAL"
                        else NotificationTypeEnum.ASSET_PRIORITY_ESCALATED_P1.value
                    )
                    NotificationService.create_notification(
                        db=db,
                        workspace_id=workspace_id,
                        category=NotificationCategoryEnum.SECURITY_ALERT.value,
                        notification_type=notif_type,
                        severity=NotificationSeverityEnum.CRITICAL.value,
                        title=f"Asset Priority Escalation: {asset.display_name} escalated to P1",
                        message=f"Asset '{asset.canonical_name}' ({crit_str}, Risk: {round(risk_points, 1)}) reached Priority P1 ({bounded_score}).",
                        source_type="ASSET_PRIORITIZATION",
                        source_id=asset.id,
                        deduplication_key=f"prio_p1_{asset.id}_{now.strftime('%Y%m%d%H')}",
                        navigation_target=f"/assets?id={asset.id}",
                    )
                except Exception as e:
                    logger.warning("Failed to generate P1 priority notification: %s", e)

        return asset, snapshot

    @classmethod
    def apply_manual_override(
        cls,
        db: Session,
        workspace_id: str,
        asset_id: str,
        priority: str,
        reason: str,
        actor: str = "SYSTEM",
        expires_in_hours: Optional[int] = None,
    ) -> AssetModel:
        """
        Sets a manual priority override for an asset with full auditability.
        Preserves underlying calculated score and band.
        """
        asset = (
            db.query(AssetModel)
            .filter(AssetModel.workspace_id == workspace_id, AssetModel.id == asset_id)
            .first()
        )
        if not asset:
            raise ValueError(f"Asset {asset_id} not found in workspace {workspace_id}")

        priority_upper = priority.upper()
        if priority_upper not in [p.value for p in PriorityBandEnum if p != PriorityBandEnum.UNPRIORITIZED]:
            raise ValueError(f"Invalid priority band '{priority}'. Allowed: P1, P2, P3, P4")

        now = get_utc_now()
        expires_at = now + timedelta(hours=expires_in_hours) if expires_in_hours else None

        previous_effective = asset.effective_priority
        asset.priority_override = priority_upper
        asset.priority_override_reason = reason
        asset.priority_override_by = actor
        asset.priority_override_at = now
        asset.priority_override_expires_at = expires_at

        # Record audit override in inventory_overrides
        inv_override = InventoryOverrideModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            target_type="ASSET",
            target_id=asset.id,
            field_name="priority_override",
            previous_value=previous_effective,
            new_value=priority_upper,
            reason=reason,
            actor=actor,
        )
        db.add(inv_override)

        # Create audit snapshot
        policy = cls.get_or_create_active_policy(db, workspace_id)
        snapshot = AssetPrioritySnapshotModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            asset_id=asset.id,
            priority_band=asset.priority_band,
            priority_score=asset.priority_score,
            policy_id=policy.id,
            policy_version=policy.version,
            risk_score=asset.risk_score,
            business_criticality=asset.criticality,
            exposure_state=asset.exposure_state,
            active_incident_count=0,
            data_quality=asset.priority_data_quality,
            explanation_json=asset.priority_explanation_json,
            is_override=True,
            override_priority=priority_upper,
            override_reason=reason,
            override_by=actor,
            previous_priority_band=previous_effective,
            transition_type="OVERRIDDEN",
            calculated_at=now,
        )
        db.add(snapshot)

        db.commit()
        db.refresh(asset)

        # Realtime event
        emit_realtime_priority_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.ASSET_PRIORITY_OVERRIDE_APPLIED.value,
            resource_id=asset.id,
            payload={
                "asset_id": asset.id,
                "effective_priority": priority_upper,
                "reason": reason,
                "actor": actor,
            },
        )

        return asset

    @classmethod
    def remove_manual_override(
        cls, db: Session, workspace_id: str, asset_id: str, actor: str = "SYSTEM"
    ) -> AssetModel:
        """
        Removes an active manual priority override and restores the underlying calculated band.
        """
        asset = (
            db.query(AssetModel)
            .filter(AssetModel.workspace_id == workspace_id, AssetModel.id == asset_id)
            .first()
        )
        if not asset:
            raise ValueError(f"Asset {asset_id} not found in workspace {workspace_id}")

        previous_effective = asset.effective_priority
        asset.priority_override = None
        asset.priority_override_reason = None
        asset.priority_override_by = None
        asset.priority_override_at = None
        asset.priority_override_expires_at = None

        now = get_utc_now()
        # Record audit override removal
        inv_override = InventoryOverrideModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            target_type="ASSET",
            target_id=asset.id,
            field_name="priority_override",
            previous_value=previous_effective,
            new_value="REMOVED",
            reason=f"Override removed by {actor}",
            actor=actor,
        )
        db.add(inv_override)

        # Create snapshot
        policy = cls.get_or_create_active_policy(db, workspace_id)
        snapshot = AssetPrioritySnapshotModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            asset_id=asset.id,
            priority_band=asset.priority_band,
            priority_score=asset.priority_score,
            policy_id=policy.id,
            policy_version=policy.version,
            risk_score=asset.risk_score,
            business_criticality=asset.criticality,
            exposure_state=asset.exposure_state,
            active_incident_count=0,
            data_quality=asset.priority_data_quality,
            explanation_json=asset.priority_explanation_json,
            is_override=False,
            previous_priority_band=previous_effective,
            transition_type="OVERRIDE_REMOVED",
            calculated_at=now,
        )
        db.add(snapshot)

        db.commit()
        db.refresh(asset)

        # Realtime event
        emit_realtime_priority_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.ASSET_PRIORITY_OVERRIDE_REMOVED.value,
            resource_id=asset.id,
            payload={"asset_id": asset.id, "restored_priority": asset.priority_band},
        )

        return asset

    @classmethod
    def recalculate_workspace_priorities(
        cls,
        db: Session,
        workspace_id: str,
        asset_ids: Optional[List[str]] = None,
        actor: str = "SYSTEM",
    ) -> Dict[str, Any]:
        """
        Recalculates priorities across all or selected assets in the workspace.
        """
        policy = cls.get_or_create_active_policy(db, workspace_id)

        query = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id)
        if asset_ids:
            query = query.filter(AssetModel.id.in_(asset_ids))

        assets = query.all()

        p1_count = 0
        p2_count = 0
        p3_count = 0
        p4_count = 0
        escalated_count = 0
        deescalated_count = 0

        for asset in assets:
            prev_band = asset.effective_priority
            _, snapshot = cls.calculate_asset_priority(db, asset, policy=policy, save_snapshot=True)

            eff = asset.effective_priority
            if eff == PriorityBandEnum.P1.value:
                p1_count += 1
            elif eff == PriorityBandEnum.P2.value:
                p2_count += 1
            elif eff == PriorityBandEnum.P3.value:
                p3_count += 1
            else:
                p4_count += 1

            if snapshot and snapshot.transition_type == "ESCALATED":
                escalated_count += 1
            elif snapshot and snapshot.transition_type == "DEESCALATED":
                deescalated_count += 1

        logger.info(
            "Recalculated priorities for %d assets in workspace %s: P1=%d, P2=%d, P3=%d, P4=%d",
            len(assets),
            workspace_id,
            p1_count,
            p2_count,
            p3_count,
            p4_count,
        )

        return {
            "processed": len(assets),
            "p1_count": p1_count,
            "p2_count": p2_count,
            "p3_count": p3_count,
            "p4_count": p4_count,
            "escalated_count": escalated_count,
            "deescalated_count": deescalated_count,
            "policy_version": policy.version,
        }

    @classmethod
    def list_prioritized_assets(
        cls,
        db: Session,
        workspace_id: str,
        priority_band: Optional[str] = None,
        min_priority: Optional[str] = None,
        criticality: Optional[str] = None,
        exposure_state: Optional[str] = None,
        environment: Optional[str] = None,
        search: Optional[str] = None,
        is_overridden: Optional[bool] = None,
        sort_by: str = "priority_score",
        sort_desc: bool = True,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AssetModel], int, Dict[str, int]]:
        """
        Lists prioritized assets with server-side filters, search, and distribution metrics.
        """
        base_query = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id)

        # Filters
        if priority_band and priority_band != "ALL":
            base_query = base_query.filter(
                or_(
                    AssetModel.priority_override == priority_band,
                    and_(AssetModel.priority_override.is_(None), AssetModel.priority_band == priority_band),
                )
            )

        if min_priority and min_priority != "ALL":
            min_bands = {
                "P1": ["P1"],
                "P2": ["P1", "P2"],
                "P3": ["P1", "P2", "P3"],
                "P4": ["P1", "P2", "P3", "P4"],
            }.get(min_priority, [])
            if min_bands:
                base_query = base_query.filter(
                    or_(
                        AssetModel.priority_override.in_(min_bands),
                        and_(AssetModel.priority_override.is_(None), AssetModel.priority_band.in_(min_bands)),
                    )
                )

        if criticality and criticality != "ALL":
            base_query = base_query.filter(AssetModel.criticality == criticality)

        if exposure_state and exposure_state != "ALL":
            base_query = base_query.filter(AssetModel.exposure_state == exposure_state)

        if environment and environment != "ALL":
            base_query = base_query.filter(AssetModel.environment == environment)

        if is_overridden is True:
            base_query = base_query.filter(AssetModel.priority_override.isnot(None))
        elif is_overridden is False:
            base_query = base_query.filter(AssetModel.priority_override.is_(None))

        if search:
            search_pattern = f"%{search}%"
            base_query = base_query.filter(
                or_(
                    AssetModel.canonical_name.ilike(search_pattern),
                    AssetModel.display_name.ilike(search_pattern),
                    AssetModel.owner.ilike(search_pattern),
                    AssetModel.team.ilike(search_pattern),
                )
            )

        total = base_query.count()

        # Sorting
        sort_col = getattr(AssetModel, sort_by, AssetModel.priority_score)
        if sort_desc:
            base_query = base_query.order_by(desc(sort_col), desc(AssetModel.risk_score))
        else:
            base_query = base_query.order_by(asc(sort_col), asc(AssetModel.risk_score))

        items = base_query.offset(offset).limit(limit).all()

        # Distribution breakdown across workspace
        all_assets_q = db.query(AssetModel).filter(AssetModel.workspace_id == workspace_id)
        p1 = all_assets_q.filter(
            or_(
                AssetModel.priority_override == "P1",
                and_(AssetModel.priority_override.is_(None), AssetModel.priority_band == "P1"),
            )
        ).count()
        p2 = all_assets_q.filter(
            or_(
                AssetModel.priority_override == "P2",
                and_(AssetModel.priority_override.is_(None), AssetModel.priority_band == "P2"),
            )
        ).count()
        p3 = all_assets_q.filter(
            or_(
                AssetModel.priority_override == "P3",
                and_(AssetModel.priority_override.is_(None), AssetModel.priority_band == "P3"),
            )
        ).count()
        p4 = all_assets_q.filter(
            or_(
                AssetModel.priority_override == "P4",
                and_(AssetModel.priority_override.is_(None), AssetModel.priority_band == "P4"),
            )
        ).count()
        unp = all_assets_q.filter(
            AssetModel.priority_override.is_(None), AssetModel.priority_band == "UNPRIORITIZED"
        ).count()
        overridden = all_assets_q.filter(AssetModel.priority_override.isnot(None)).count()

        counts = {
            "p1_count": p1,
            "p2_count": p2,
            "p3_count": p3,
            "p4_count": p4,
            "unprioritized_count": unp,
            "overridden_count": overridden,
        }

        return items, total, counts

    @classmethod
    def get_asset_priority_explanation(
        cls, db: Session, workspace_id: str, asset_id: str
    ) -> PriorityExplanationResponse:
        """
        Retrieves or calculates the structured priority explanation for an asset.
        """
        asset = (
            db.query(AssetModel)
            .filter(AssetModel.workspace_id == workspace_id, AssetModel.id == asset_id)
            .first()
        )
        if not asset:
            raise ValueError(f"Asset {asset_id} not found in workspace {workspace_id}")

        # If not yet calculated, calculate now
        if not asset.priority_calculated_at or asset.priority_band == PriorityBandEnum.UNPRIORITIZED.value:
            asset, _ = cls.calculate_asset_priority(db, asset)

        expl = asset.priority_explanation_dict
        contributors_raw = expl.get("contributors", [])
        contributors = [PrioritizationFactorContribution(**c) for c in contributors_raw]

        dq_raw = expl.get("data_quality", {})
        data_quality = PriorityDataQualityReport(**dq_raw) if dq_raw else PriorityDataQualityReport(status=asset.priority_data_quality)

        policy_info = expl.get("policy", {})

        return PriorityExplanationResponse(
            asset_id=asset.id,
            canonical_name=asset.canonical_name,
            display_name=asset.display_name,
            asset_type=asset.asset_type,
            priority_band=asset.priority_band,
            priority_score=asset.priority_score,
            effective_priority=asset.effective_priority,
            is_overridden=bool(asset.priority_override),
            override_priority=asset.priority_override,
            override_reason=asset.priority_override_reason,
            override_by=asset.priority_override_by,
            override_at=asset.priority_override_at,
            override_expires_at=asset.priority_override_expires_at,
            contributors=contributors,
            data_quality=data_quality,
            policy_id=policy_info.get("id", asset.priority_policy_id),
            policy_name=policy_info.get("name", "Default Operational Prioritization Policy"),
            policy_version=policy_info.get("version", asset.priority_policy_version or 1),
            calculated_at=asset.priority_calculated_at,
        )

    @classmethod
    def get_asset_priority_history(
        cls, db: Session, workspace_id: str, asset_id: str, limit: int = 20
    ) -> List[AssetPrioritySnapshotModel]:
        """
        Retrieves the timeline of priority snapshot evaluations for an asset.
        """
        return (
            db.query(AssetPrioritySnapshotModel)
            .filter(
                AssetPrioritySnapshotModel.workspace_id == workspace_id,
                AssetPrioritySnapshotModel.asset_id == asset_id,
            )
            .order_by(desc(AssetPrioritySnapshotModel.calculated_at))
            .limit(limit)
            .all()
        )

    @classmethod
    def get_top_prioritized_assets(
        cls, db: Session, workspace_id: str, limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Retrieves top P1/P2 prioritized assets for the Section 44 SOC Overview dashboard.
        """
        assets = (
            db.query(AssetModel)
            .filter(
                AssetModel.workspace_id == workspace_id,
                or_(
                    AssetModel.priority_override.in_(["P1", "P2"]),
                    and_(
                        AssetModel.priority_override.is_(None),
                        AssetModel.priority_band.in_(["P1", "P2"]),
                    ),
                ),
            )
            .order_by(desc(AssetModel.priority_score), desc(AssetModel.risk_score))
            .limit(limit)
            .all()
        )

        results = []
        for a in assets:
            # Deterministic primary reason
            reasons = []
            if a.criticality == "CRITICAL":
                reasons.append("Critical business importance")
            if a.risk_score >= 70.0:
                reasons.append(f"High risk ({round(a.risk_score, 1)})")
            if a.exposure_state == "PUBLICLY_EXPOSED":
                reasons.append("Internet exposed")
            if not a.is_managed:
                reasons.append("Unmanaged shadow IT")
            primary_reason = ", ".join(reasons) if reasons else f"Priority score {round(a.priority_score, 1)}"

            results.append(
                {
                    "id": a.id,
                    "canonical_name": a.canonical_name,
                    "display_name": a.display_name,
                    "asset_type": a.asset_type,
                    "effective_priority": a.effective_priority,
                    "priority_score": a.priority_score,
                    "risk_score": a.risk_score,
                    "criticality": a.criticality,
                    "exposure_state": a.exposure_state,
                    "primary_reason": primary_reason,
                    "owner": a.owner,
                    "active_incidents": 0,
                }
            )

        return results
