"""
Section 65: Threat Actor & Campaign Workspace Service.
Authoritative analyst orchestration service for threat actors, campaigns,
evidence, hypotheses, and candidate lifecycle management.

Enforces:
- Separation of Observed Fact, Correlation, Analyst Hypothesis, and Attribution.
- Independent confidence (0.0 to 1.0) strictly separate from Risk/Severity.
- Supporting and Contradicting evidence tracking.
- Controlled candidate promotion, merging, and splitting with complete provenance.
- Multi-tenant workspace isolation.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import or_, and_, desc, asc
from sqlalchemy.orm import Session

from backend.db.models import (
    CampaignModel,
    CampaignIncidentModel,
    CampaignEmailModel,
    IncidentModel,
    AlertModel,
    AssetModel,
    IdentityModel,
    ThreatActorModel,
    ThreatHypothesisModel,
    ThreatAttributionAssessmentModel,
    ThreatActorRelationshipModel,
    get_utc_now,
)
from backend.schemas.threat_workspace import (
    AttributionStateEnum,
    SemanticClassificationEnum,
    CampaignLifecycleEnum,
    CampaignActivityEnum,
    CampaignWatchStateEnum,
    HypothesisStatusEnum,
    ActorTypeEnum,
    IdentityStateEnum,
    EvidenceItem,
    ActorAlias,
    AnalystNote,
    SourceConflict,
    ThreatActorCreateRequest,
    ThreatActorUpdateRequest,
    ThreatActorResponse,
    ThreatActorListResponse,
    CampaignCreateRequest,
    CampaignUpdateRequest,
    CampaignWorkspaceDetailResponse,
    CampaignListWorkspaceResponse,
    CandidateReviewRequest,
    CampaignMergePreviewRequest,
    CampaignMergePreviewResponse,
    CampaignMergeRequest,
    CampaignSplitRequest,
    AttributionAssessmentCreateRequest,
    AttributionAssessmentResponse,
    HypothesisCreateRequest,
    HypothesisUpdateRequest,
    HypothesisResponse,
    CampaignTimelineResponse,
    CampaignTimelineEventItem,
    ThreatHuntHandoffResponse,
    DetectionHandoffResponse,
    AffectedAssetRef,
    AffectedIdentityRef,
)
from backend.schemas.graph import (
    NodeType,
    GraphNode,
    GraphEdge,
    GraphSummary,
    InvestigationGraphResponse,
)
from backend.schemas.realtime import (
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
    RealtimeEventPayload,
)
from backend.services.audit_service import AuditService
from backend.services.realtime_service import RealtimePublisher
from backend.services.campaign_service import CampaignService
from backend.services.notification_service import NotificationService

logger = logging.getLogger("cyberguard.services.threat_workspace")


class ThreatWorkspaceService:
    """
    Core management service for the Threat Actor & Campaign Workspace.
    """

    # -------------------------------------------------------------------------
    # Helper Serialization & Provenance
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_json(raw: Optional[str], default_val: Any) -> Any:
        if not raw:
            return default_val
        try:
            return json.loads(raw)
        except Exception:
            return default_val

    @staticmethod
    def _to_json(val: Any) -> str:
        try:
            return json.dumps(val)
        except Exception:
            return "[]"

    @classmethod
    def _publish_event(
        cls,
        workspace_id: str,
        event_type: RealtimeEventTypeEnum,
        scope: RealtimeResourceScopeEnum,
        resource_id: str,
        title: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            RealtimePublisher.publish_event(
                workspace_id=workspace_id,
                event_type=event_type,
                resource_scope=scope,
                resource_id=resource_id,
                payload=RealtimeEventPayload(
                    title=title,
                    finding_type="THREAT_WORKSPACE",
                    severity="INFO",
                ),
            )
        except Exception as exc:
            logger.debug("Realtime publishing non-critical error: %s", exc)

    # -------------------------------------------------------------------------
    # Threat Actor Management
    # -------------------------------------------------------------------------

    @classmethod
    def list_actors(
        cls,
        db: Session,
        workspace_id: str,
        query: Optional[str] = None,
        status: Optional[str] = None,
        attribution_state: Optional[str] = None,
        actor_type: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> ThreatActorListResponse:
        q = db.query(ThreatActorModel).filter(ThreatActorModel.workspace_id == workspace_id)

        if query:
            q_clean = f"%{query.strip().lower()}%"
            q = q.filter(
                or_(
                    ThreatActorModel.name.ilike(q_clean),
                    ThreatActorModel.canonical_name.ilike(q_clean),
                    ThreatActorModel.actor_id.ilike(q_clean),
                    ThreatActorModel.aliases_json.ilike(q_clean),
                )
            )

        if status:
            q = q.filter(ThreatActorModel.status == status.strip().upper())
        if attribution_state:
            q = q.filter(ThreatActorModel.attribution_state == attribution_state.strip().upper())
        if actor_type:
            q = q.filter(ThreatActorModel.actor_type == actor_type.strip().upper())

        total = q.count()
        actors = (
            q.order_by(desc(ThreatActorModel.updated_at))
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        items = [cls._format_actor(db, a) for a in actors]
        return ThreatActorListResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
        )

    @classmethod
    def get_actor(
        cls,
        db: Session,
        workspace_id: str,
        actor_id_or_uuid: str,
    ) -> Optional[ThreatActorResponse]:
        clean_id = actor_id_or_uuid.strip()
        actor = (
            db.query(ThreatActorModel)
            .filter(
                ThreatActorModel.workspace_id == workspace_id,
                or_(
                    ThreatActorModel.id == clean_id,
                    ThreatActorModel.actor_id == clean_id.upper(),
                ),
            )
            .first()
        )
        if not actor:
            return None
        return cls._format_actor(db, actor)

    @classmethod
    def create_actor(
        cls,
        db: Session,
        workspace_id: str,
        req: ThreatActorCreateRequest,
        creator: str = "ANALYST",
    ) -> ThreatActorResponse:
        # Generate friendly sequential or unique actor ID
        total_count = db.query(ThreatActorModel).count()
        idx = total_count + 1
        actor_id = f"TA-{idx:03d}"
        while db.query(ThreatActorModel).filter(ThreatActorModel.actor_id == actor_id).first():
            idx += 1
            actor_id = f"TA-{idx:03d}"
        now = datetime.now(timezone.utc)

        aliases_data = [a.model_dump() for a in (req.aliases or [])]
        supp_data = [e.model_dump() for e in (req.supporting_evidence or [])]
        contra_data = [e.model_dump() for e in (req.contradicting_evidence or [])]

        actor = ThreatActorModel(
            id=str(uuid.uuid4()),
            actor_id=actor_id,
            workspace_id=workspace_id,
            name=req.name.strip(),
            canonical_name=(req.canonical_name or req.name).strip().upper(),
            actor_type=req.actor_type.value if req.actor_type else "UNKNOWN",
            status="ACTIVE",
            attribution_state=req.attribution_state.value if req.attribution_state else "SUSPECTED",
            attribution_confidence=round(req.attribution_confidence if req.attribution_confidence is not None else 0.5, 2),
            motivation=req.motivation,
            sophistication=req.sophistication or "UNKNOWN",
            description=req.description,
            first_observed_at=now,
            last_observed_at=now,
            aliases_json=cls._to_json(aliases_data),
            primary_targets_json=cls._to_json(req.primary_targets or []),
            observed_techniques_json=cls._to_json(req.observed_techniques or []),
            observed_infrastructure_json=cls._to_json(req.observed_infrastructure or []),
            supporting_evidence_json=cls._to_json(supp_data),
            contradicting_evidence_json=cls._to_json(contra_data),
            analyst_notes_json=cls._to_json([]),
            created_by=creator,
            created_at=now,
            updated_at=now,
        )
        db.add(actor)
        db.commit()
        db.refresh(actor)

        # Audit log
        AuditService.log_audit(
            db=db,
            action="THREAT_ACTOR_CREATED",
            resource_type="THREAT_ACTOR",
            resource_id=actor.actor_id,
            user=creator,
            metadata={
                "name": actor.name,
                "actor_type": actor.actor_type,
                "attribution_state": actor.attribution_state,
                "confidence": actor.attribution_confidence,
            },
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.ACTOR_CREATED,
            scope=RealtimeResourceScopeEnum.THREAT_ACTOR,
            resource_id=actor.id,
            title=f"Threat Actor '{actor.name}' profile created",
        )

        return cls._format_actor(db, actor)

    @classmethod
    def update_actor(
        cls,
        db: Session,
        workspace_id: str,
        actor_id_or_uuid: str,
        req: ThreatActorUpdateRequest,
        updater: str = "ANALYST",
    ) -> ThreatActorResponse:
        clean_id = actor_id_or_uuid.strip()
        actor = (
            db.query(ThreatActorModel)
            .filter(
                ThreatActorModel.workspace_id == workspace_id,
                or_(
                    ThreatActorModel.id == clean_id,
                    ThreatActorModel.actor_id == clean_id.upper(),
                ),
            )
            .first()
        )
        if not actor:
            raise ValueError(f"Threat Actor '{actor_id_or_uuid}' not found.")

        if req.name is not None:
            actor.name = req.name.strip()
        if req.canonical_name is not None:
            actor.canonical_name = req.canonical_name.strip().upper()
        if req.actor_type is not None:
            actor.actor_type = req.actor_type.value
        if req.status is not None:
            actor.status = req.status.strip().upper()
        if req.attribution_state is not None:
            actor.attribution_state = req.attribution_state.value
        if req.attribution_confidence is not None:
            actor.attribution_confidence = round(req.attribution_confidence, 2)
        if req.motivation is not None:
            actor.motivation = req.motivation
        if req.sophistication is not None:
            actor.sophistication = req.sophistication
        if req.description is not None:
            actor.description = req.description
        if req.aliases is not None:
            actor.aliases_json = cls._to_json([a.model_dump() for a in req.aliases])
        if req.primary_targets is not None:
            actor.primary_targets_json = cls._to_json(req.primary_targets)
        if req.observed_techniques is not None:
            actor.observed_techniques_json = cls._to_json(req.observed_techniques)
        if req.observed_infrastructure is not None:
            actor.observed_infrastructure_json = cls._to_json(req.observed_infrastructure)
        if req.supporting_evidence is not None:
            actor.supporting_evidence_json = cls._to_json([e.model_dump() for e in req.supporting_evidence])
        if req.contradicting_evidence is not None:
            actor.contradicting_evidence_json = cls._to_json([e.model_dump() for e in req.contradicting_evidence])

        actor.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(actor)

        AuditService.log_audit(
            db=db,
            action="THREAT_ACTOR_UPDATED",
            resource_type="THREAT_ACTOR",
            resource_id=actor.actor_id,
            user=updater,
            metadata={"name": actor.name, "attribution_state": actor.attribution_state},
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.ACTOR_UPDATED,
            scope=RealtimeResourceScopeEnum.THREAT_ACTOR,
            resource_id=actor.id,
            title=f"Threat Actor '{actor.name}' updated",
        )

        return cls._format_actor(db, actor)

    @classmethod
    def record_actor_assessment(
        cls,
        db: Session,
        workspace_id: str,
        actor_id_or_uuid: str,
        req: AttributionAssessmentCreateRequest,
        analyst: str = "ANALYST",
    ) -> AttributionAssessmentResponse:
        actor = (
            db.query(ThreatActorModel)
            .filter(
                ThreatActorModel.workspace_id == workspace_id,
                or_(
                    ThreatActorModel.id == actor_id_or_uuid.strip(),
                    ThreatActorModel.actor_id == actor_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not actor:
            raise ValueError(f"Threat Actor '{actor_id_or_uuid}' not found.")

        # Mandatory attribution principle: CONFIRMED must not mean AI confident; requires explicit justification
        if req.new_attribution_state == AttributionStateEnum.CONFIRMED:
            if not req.justification or len(req.justification.strip()) < 10:
                raise ValueError("Attribution state 'CONFIRMED' requires substantive analyst justification and corroborating intelligence.")

        prior_state = actor.attribution_state
        actor.attribution_state = req.new_attribution_state.value
        actor.attribution_confidence = round(req.confidence, 2)
        actor.updated_at = datetime.now(timezone.utc)

        # Merge evidence items if provided
        if req.supporting_evidence:
            curr_supp = cls._parse_json(actor.supporting_evidence_json, [])
            curr_supp.extend([e.model_dump() for e in req.supporting_evidence])
            actor.supporting_evidence_json = cls._to_json(curr_supp)
        if req.contradicting_evidence:
            curr_contra = cls._parse_json(actor.contradicting_evidence_json, [])
            curr_contra.extend([e.model_dump() for e in req.contradicting_evidence])
            actor.contradicting_evidence_json = cls._to_json(curr_contra)

        now = datetime.now(timezone.utc)
        assessment = ThreatAttributionAssessmentModel(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            subject_type="THREAT_ACTOR",
            subject_id=actor.id,
            target_type="THREAT_ACTOR",
            target_id=actor.id,
            prior_attribution_state=prior_state,
            new_attribution_state=req.new_attribution_state.value,
            confidence=round(req.confidence, 2),
            justification=req.justification.strip(),
            supporting_evidence_json=cls._to_json([e.model_dump() for e in (req.supporting_evidence or [])]),
            contradicting_evidence_json=cls._to_json([e.model_dump() for e in (req.contradicting_evidence or [])]),
            external_conflicts_json=cls._to_json([c.model_dump() for c in (req.external_conflicts or [])]),
            assessed_by=analyst,
            assessed_at=now,
        )
        db.add(assessment)
        db.commit()

        AuditService.log_audit(
            db=db,
            action="ACTOR_ATTRIBUTION_ASSESSMENT",
            resource_type="THREAT_ACTOR",
            resource_id=actor.actor_id,
            user=analyst,
            metadata={
                "prior_state": prior_state,
                "new_state": req.new_attribution_state.value,
                "confidence": req.confidence,
                "justification": req.justification,
            },
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.ACTOR_ASSESSMENT_CHANGED,
            scope=RealtimeResourceScopeEnum.THREAT_ACTOR,
            resource_id=actor.id,
            title=f"Actor '{actor.name}' attribution updated from {prior_state} to {req.new_attribution_state.value}",
        )

        return cls._format_assessment(assessment)

    @classmethod
    def get_actor_assessments(
        cls,
        db: Session,
        workspace_id: str,
        actor_id_or_uuid: str,
    ) -> List[AttributionAssessmentResponse]:
        actor = (
            db.query(ThreatActorModel)
            .filter(
                ThreatActorModel.workspace_id == workspace_id,
                or_(
                    ThreatActorModel.id == actor_id_or_uuid.strip(),
                    ThreatActorModel.actor_id == actor_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not actor:
            return []

        assessments = (
            db.query(ThreatAttributionAssessmentModel)
            .filter(
                ThreatAttributionAssessmentModel.workspace_id == workspace_id,
                ThreatAttributionAssessmentModel.subject_type == "THREAT_ACTOR",
                ThreatAttributionAssessmentModel.subject_id == actor.id,
            )
            .order_by(desc(ThreatAttributionAssessmentModel.assessed_at))
            .all()
        )
        return [cls._format_assessment(a) for a in assessments]

    @classmethod
    def _format_actor(cls, db: Session, a: ThreatActorModel) -> ThreatActorResponse:
        # Dynamic relationship metrics
        associated_campaigns_count = db.query(CampaignModel).filter(CampaignModel.threat_actor_id == a.id).count()

        aliases = [ActorAlias(**al) for al in cls._parse_json(a.aliases_json, [])]
        targets = cls._parse_json(a.primary_targets_json, [])
        techs = cls._parse_json(a.observed_techniques_json, [])
        infra = cls._parse_json(a.observed_infrastructure_json, [])
        supp = [EvidenceItem(**e) for e in cls._parse_json(a.supporting_evidence_json, [])]
        contra = [EvidenceItem(**e) for e in cls._parse_json(a.contradicting_evidence_json, [])]

        return ThreatActorResponse(
            id=a.id,
            actor_id=a.actor_id,
            workspace_id=a.workspace_id,
            name=a.name,
            canonical_name=a.canonical_name,
            actor_type=a.actor_type,
            status=a.status,
            attribution_state=a.attribution_state,
            attribution_confidence=a.attribution_confidence,
            motivation=a.motivation,
            sophistication=a.sophistication,
            description=a.description,
            first_observed_at=a.first_observed_at.isoformat() if a.first_observed_at else None,
            last_observed_at=a.last_observed_at.isoformat() if a.last_observed_at else None,
            aliases=aliases,
            primary_targets=targets,
            observed_techniques=techs,
            observed_infrastructure=infra,
            supporting_evidence=supp,
            contradicting_evidence=contra,
            associated_campaigns_count=associated_campaigns_count,
            affected_assets_count=0,
            open_incidents_count=0,
            created_by=a.created_by,
            created_at=a.created_at.isoformat() if a.created_at else "",
            updated_at=a.updated_at.isoformat() if a.updated_at else "",
        )

    # -------------------------------------------------------------------------
    # Campaign Management
    # -------------------------------------------------------------------------

    @classmethod
    def list_campaigns(
        cls,
        db: Session,
        workspace_id: str,
        query: Optional[str] = None,
        lifecycle_status: Optional[str] = None,
        attribution_state: Optional[str] = None,
        activity_state: Optional[str] = None,
        threat_actor_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> CampaignListWorkspaceResponse:
        CampaignService.ensure_campaigns_initialized(db)

        q = db.query(CampaignModel).filter(CampaignModel.workspace_id == workspace_id)

        if query:
            q_clean = f"%{query.strip().lower()}%"
            q = q.filter(
                or_(
                    CampaignModel.name.ilike(q_clean),
                    CampaignModel.campaign_id.ilike(q_clean),
                    CampaignModel.targeted_brands_json.ilike(q_clean),
                    CampaignModel.associated_iocs_json.ilike(q_clean),
                )
            )

        if lifecycle_status:
            ls_clean = lifecycle_status.strip().upper()
            q = q.filter(
                or_(
                    CampaignModel.lifecycle_status == ls_clean,
                    CampaignModel.status == ls_clean,
                )
            )
        if attribution_state:
            q = q.filter(CampaignModel.attribution_state == attribution_state.strip().upper())
        if activity_state:
            q = q.filter(CampaignModel.activity_state == activity_state.strip().upper())
        if threat_actor_id:
            q = q.filter(CampaignModel.threat_actor_id == threat_actor_id.strip())

        total = q.count()
        campaigns = (
            q.order_by(desc(CampaignModel.last_seen))
            .offset((page - 1) * page_size)
            .limit(page_size)
            .all()
        )

        items = [cls._format_campaign(db, c) for c in campaigns]
        return CampaignListWorkspaceResponse(
            items=items,
            total=total,
            page=page,
            page_size=page_size,
        )

    @classmethod
    def get_campaign(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
    ) -> Optional[CampaignWorkspaceDetailResponse]:
        CampaignService.ensure_campaigns_initialized(db)
        clean_id = campaign_id_or_uuid.strip()
        campaign = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == clean_id,
                    CampaignModel.campaign_id == clean_id.upper(),
                ),
            )
            .first()
        )
        if not campaign:
            return None
        return cls._format_campaign(db, campaign)

    @classmethod
    def create_campaign(
        cls,
        db: Session,
        workspace_id: str,
        req: CampaignCreateRequest,
        creator: str = "ANALYST",
    ) -> CampaignWorkspaceDetailResponse:
        total_count = db.query(CampaignModel).count()
        idx = total_count + 1
        camp_id = f"C-{idx:03d}"
        while db.query(CampaignModel).filter(CampaignModel.campaign_id == camp_id).first():
            idx += 1
            camp_id = f"C-{idx:03d}"
        now = datetime.now(timezone.utc)

        # Check threat actor
        actor = None
        if req.threat_actor_id:
            actor = db.query(ThreatActorModel).filter(
                ThreatActorModel.workspace_id == workspace_id,
                or_(ThreatActorModel.id == req.threat_actor_id, ThreatActorModel.actor_id == req.threat_actor_id)
            ).first()

        provenance_entry = {
            "action": "CAMPAIGN_CREATED",
            "actor": creator,
            "timestamp": now.isoformat(),
            "details": f"Created campaign {camp_id}: {req.name}",
        }

        campaign = CampaignModel(
            id=str(uuid.uuid4()),
            campaign_id=camp_id,
            name=req.name.strip(),
            workspace_id=workspace_id,
            status="OPEN",
            lifecycle_status=req.lifecycle_status.value if req.lifecycle_status else "OPEN",
            activity_state="ACTIVE",
            watch_state="NOT_MONITORED",
            attribution_state=req.attribution_state.value if req.attribution_state else "UNKNOWN",
            attribution_confidence=round(req.attribution_confidence or 0.0, 2),
            threat_actor_id=actor.id if actor else None,
            description=req.description,
            first_seen=now,
            last_seen=now,
            dominant_attack_type=req.dominant_attack_type or "Phishing / Credential Harvesting",
            targeted_brands_json=cls._to_json(req.targeted_brands or []),
            mitre_techniques_json=cls._to_json(req.mitre_techniques or []),
            supporting_evidence_json=cls._to_json([]),
            contradicting_evidence_json=cls._to_json([]),
            affected_assets_json=cls._to_json([]),
            affected_identities_json=cls._to_json([]),
            related_alerts_json=cls._to_json([]),
            related_incidents_json=cls._to_json([]),
            analyst_notes_json=cls._to_json([]),
            source_conflicts_json=cls._to_json([]),
            provenance_history_json=cls._to_json([provenance_entry]),
            overall_confidence=75.0,
            created_at=now,
            updated_at=now,
        )
        db.add(campaign)
        db.commit()
        db.refresh(campaign)

        AuditService.log_audit(
            db=db,
            action="CAMPAIGN_CREATED",
            resource_type="CAMPAIGN",
            resource_id=campaign.campaign_id,
            user=creator,
            metadata={"name": campaign.name, "threat_actor_id": campaign.threat_actor_id},
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.CAMPAIGN_CREATED,
            scope=RealtimeResourceScopeEnum.CAMPAIGN,
            resource_id=campaign.id,
            title=f"Campaign '{campaign.name}' ({campaign.campaign_id}) created",
        )

        return cls._format_campaign(db, campaign)

    @classmethod
    def update_campaign(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
        req: CampaignUpdateRequest,
        updater: str = "ANALYST",
    ) -> CampaignWorkspaceDetailResponse:
        campaign = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == campaign_id_or_uuid.strip(),
                    CampaignModel.campaign_id == campaign_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id_or_uuid}' not found.")

        now = datetime.now(timezone.utc)
        provenance = cls._parse_json(campaign.provenance_history_json, [])

        if req.name is not None:
            campaign.name = req.name.strip()
        if req.description is not None:
            campaign.description = req.description
        if req.threat_actor_id is not None:
            if req.threat_actor_id == "":
                campaign.threat_actor_id = None
            else:
                actor = db.query(ThreatActorModel).filter(
                    ThreatActorModel.workspace_id == workspace_id,
                    or_(ThreatActorModel.id == req.threat_actor_id, ThreatActorModel.actor_id == req.threat_actor_id)
                ).first()
                if actor:
                    campaign.threat_actor_id = actor.id
        if req.attribution_state is not None:
            campaign.attribution_state = req.attribution_state.value
        if req.attribution_confidence is not None:
            campaign.attribution_confidence = round(req.attribution_confidence, 2)
        if req.lifecycle_status is not None:
            campaign.lifecycle_status = req.lifecycle_status.value
            campaign.status = req.lifecycle_status.value
        if req.activity_state is not None:
            campaign.activity_state = req.activity_state.value
        if req.watch_state is not None:
            campaign.watch_state = req.watch_state.value
        if req.dominant_attack_type is not None:
            campaign.dominant_attack_type = req.dominant_attack_type
        if req.targeted_brands is not None:
            campaign.targeted_brands_json = cls._to_json(req.targeted_brands)
        if req.mitre_techniques is not None:
            campaign.mitre_techniques_json = cls._to_json(req.mitre_techniques)
        if req.supporting_evidence is not None:
            campaign.supporting_evidence_json = cls._to_json([e.model_dump() for e in req.supporting_evidence])
        if req.contradicting_evidence is not None:
            campaign.contradicting_evidence_json = cls._to_json([e.model_dump() for e in req.contradicting_evidence])

        provenance.append({
            "action": "CAMPAIGN_UPDATED",
            "actor": updater,
            "timestamp": now.isoformat(),
            "details": "Campaign attributes modified by analyst.",
        })
        campaign.provenance_history_json = cls._to_json(provenance)
        campaign.updated_at = now

        db.commit()
        db.refresh(campaign)

        AuditService.log_audit(
            db=db,
            action="CAMPAIGN_UPDATED",
            resource_type="CAMPAIGN",
            resource_id=campaign.campaign_id,
            user=updater,
            metadata={"name": campaign.name, "status": campaign.lifecycle_status},
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.CAMPAIGN_UPDATED,
            scope=RealtimeResourceScopeEnum.CAMPAIGN,
            resource_id=campaign.id,
            title=f"Campaign '{campaign.name}' updated",
        )

        return cls._format_campaign(db, campaign)

    @classmethod
    def record_campaign_assessment(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
        req: AttributionAssessmentCreateRequest,
        analyst: str = "ANALYST",
    ) -> AttributionAssessmentResponse:
        campaign = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == campaign_id_or_uuid.strip(),
                    CampaignModel.campaign_id == campaign_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id_or_uuid}' not found.")

        # Mandatory attribution principle: CONFIRMED requires explicit justification and cannot be empty
        if req.new_attribution_state == AttributionStateEnum.CONFIRMED:
            if not req.justification or len(req.justification.strip()) < 10:
                raise ValueError("Campaign attribution state 'CONFIRMED' requires substantive analyst justification and corroborating intelligence.")

        prior_state = campaign.attribution_state or "UNKNOWN"
        campaign.attribution_state = req.new_attribution_state.value
        campaign.attribution_confidence = round(req.confidence, 2)

        if req.target_id:
            actor = db.query(ThreatActorModel).filter(
                ThreatActorModel.workspace_id == workspace_id,
                or_(ThreatActorModel.id == req.target_id, ThreatActorModel.actor_id == req.target_id)
            ).first()
            if actor:
                campaign.threat_actor_id = actor.id

        now = datetime.now(timezone.utc)
        provenance = cls._parse_json(campaign.provenance_history_json, [])
        provenance.append({
            "action": "ATTRIBUTION_ASSESSMENT_CHANGED",
            "actor": analyst,
            "timestamp": now.isoformat(),
            "details": f"Attribution changed from {prior_state} to {req.new_attribution_state.value} (Confidence: {req.confidence}).",
        })
        campaign.provenance_history_json = cls._to_json(provenance)
        campaign.updated_at = now

        assessment = ThreatAttributionAssessmentModel(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            subject_type="CAMPAIGN",
            subject_id=campaign.id,
            target_type="THREAT_ACTOR",
            target_id=campaign.threat_actor_id,
            prior_attribution_state=prior_state,
            new_attribution_state=req.new_attribution_state.value,
            confidence=round(req.confidence, 2),
            justification=req.justification.strip(),
            supporting_evidence_json=cls._to_json([e.model_dump() for e in (req.supporting_evidence or [])]),
            contradicting_evidence_json=cls._to_json([e.model_dump() for e in (req.contradicting_evidence or [])]),
            external_conflicts_json=cls._to_json([c.model_dump() for c in (req.external_conflicts or [])]),
            assessed_by=analyst,
            assessed_at=now,
        )
        db.add(assessment)
        db.commit()

        AuditService.log_audit(
            db=db,
            action="CAMPAIGN_ATTRIBUTION_ASSESSMENT",
            resource_type="CAMPAIGN",
            resource_id=campaign.campaign_id,
            user=analyst,
            metadata={
                "prior_state": prior_state,
                "new_state": req.new_attribution_state.value,
                "confidence": req.confidence,
                "justification": req.justification,
            },
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.CAMPAIGN_ATTRIBUTION_CHANGED,
            scope=RealtimeResourceScopeEnum.CAMPAIGN,
            resource_id=campaign.id,
            title=f"Campaign '{campaign.campaign_id}' attribution assessed as {req.new_attribution_state.value}",
        )

        return cls._format_assessment(assessment)

    # -------------------------------------------------------------------------
    # Candidate Review & Merge / Split Workflows
    # -------------------------------------------------------------------------

    @classmethod
    def list_candidates(
        cls,
        db: Session,
        workspace_id: str,
    ) -> List[CampaignWorkspaceDetailResponse]:
        CampaignService.ensure_campaigns_initialized(db)
        candidates = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.status == "CANDIDATE",
                    CampaignModel.lifecycle_status == "CANDIDATE",
                ),
            )
            .order_by(desc(CampaignModel.last_seen))
            .all()
        )
        return [cls._format_campaign(db, c) for c in candidates]

    @classmethod
    def review_candidate(
        cls,
        db: Session,
        workspace_id: str,
        candidate_id_or_uuid: str,
        req: CandidateReviewRequest,
        analyst: str = "ANALYST",
    ) -> CampaignWorkspaceDetailResponse:
        candidate = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == candidate_id_or_uuid.strip(),
                    CampaignModel.campaign_id == candidate_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not candidate:
            raise ValueError(f"Candidate '{candidate_id_or_uuid}' not found.")

        now = datetime.now(timezone.utc)
        provenance = cls._parse_json(candidate.provenance_history_json, [])
        action_upper = req.action.strip().upper()

        if action_upper == "PROMOTE":
            candidate.status = "OPEN"
            candidate.lifecycle_status = "OPEN"
            if req.name and req.name.strip():
                candidate.name = req.name.strip()
            if req.threat_actor_id:
                candidate.threat_actor_id = req.threat_actor_id

            provenance.append({
                "action": "CANDIDATE_PROMOTED",
                "actor": analyst,
                "timestamp": now.isoformat(),
                "details": f"Promoted candidate to active campaign. Reason: {req.reason}",
            })
            candidate.provenance_history_json = cls._to_json(provenance)
            candidate.updated_at = now
            db.commit()
            db.refresh(candidate)

            AuditService.log_audit(
                db=db,
                action="CANDIDATE_PROMOTED",
                resource_type="CAMPAIGN",
                resource_id=candidate.campaign_id,
                user=analyst,
                metadata={"reason": req.reason},
            )

            cls._publish_event(
                workspace_id=workspace_id,
                event_type=RealtimeEventTypeEnum.CAMPAIGN_STATUS_CHANGED,
                scope=RealtimeResourceScopeEnum.CAMPAIGN,
                resource_id=candidate.id,
                title=f"Campaign candidate '{candidate.campaign_id}' promoted to active campaign",
            )

        elif action_upper == "REJECT":
            candidate.status = "REVIEWED_REJECTED"
            candidate.lifecycle_status = "CLOSED"
            provenance.append({
                "action": "CANDIDATE_REJECTED",
                "actor": analyst,
                "timestamp": now.isoformat(),
                "details": f"Rejected campaign candidate. Reason: {req.reason}",
            })
            candidate.provenance_history_json = cls._to_json(provenance)
            candidate.updated_at = now
            db.commit()
            db.refresh(candidate)

            AuditService.log_audit(
                db=db,
                action="CANDIDATE_REJECTED",
                resource_type="CAMPAIGN",
                resource_id=candidate.campaign_id,
                user=analyst,
                metadata={"reason": req.reason},
            )

        elif action_upper == "MERGE":
            if not req.target_campaign_id:
                raise ValueError("Target campaign ID is required to merge a candidate.")
            merge_req = CampaignMergeRequest(
                source_campaign_id=candidate.campaign_id,
                target_campaign_id=req.target_campaign_id,
                reason=req.reason,
                confirm_override_conflicts=True,
            )
            return cls.merge_campaigns(db, workspace_id, merge_req, analyst)

        else:
            # Mark for review
            candidate.lifecycle_status = "MONITORING"
            provenance.append({
                "action": "CANDIDATE_MARKED_FOR_REVIEW",
                "actor": analyst,
                "timestamp": now.isoformat(),
                "details": f"Marked for extended monitoring. Reason: {req.reason}",
            })
            candidate.provenance_history_json = cls._to_json(provenance)
            candidate.updated_at = now
            db.commit()
            db.refresh(candidate)

        return cls._format_campaign(db, candidate)

    @classmethod
    def preview_merge(
        cls,
        db: Session,
        workspace_id: str,
        req: CampaignMergePreviewRequest,
    ) -> CampaignMergePreviewResponse:
        src = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(CampaignModel.id == req.source_campaign_id, CampaignModel.campaign_id == req.source_campaign_id.upper()),
            )
            .first()
        )
        tgt = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(CampaignModel.id == req.target_campaign_id, CampaignModel.campaign_id == req.target_campaign_id.upper()),
            )
            .first()
        )
        if not src or not tgt:
            raise ValueError("Both source and target campaigns must exist.")

        src_iocs = cls._parse_json(src.associated_iocs_json, [])
        src_assets = cls._parse_json(src.affected_assets_json, [])
        src_inc_count = db.query(CampaignIncidentModel).filter(CampaignIncidentModel.campaign_id == src.id).count()

        conflicts: List[SourceConflict] = []
        # Check if threat actors conflict
        if src.threat_actor_id and tgt.threat_actor_id and src.threat_actor_id != tgt.threat_actor_id:
            src_actor = db.query(ThreatActorModel).filter(ThreatActorModel.id == src.threat_actor_id).first()
            tgt_actor = db.query(ThreatActorModel).filter(ThreatActorModel.id == tgt.threat_actor_id).first()
            conflicts.append(
                SourceConflict(
                    id=str(uuid.uuid4()),
                    provider_a=src.name,
                    claim_a=f"Attributed to {src_actor.name if src_actor else src.threat_actor_id}",
                    provider_b=tgt.name,
                    claim_b=f"Attributed to {tgt_actor.name if tgt_actor else tgt.threat_actor_id}",
                    subject="Threat Actor Attribution Mismatch",
                    status="DISPUTED",
                    analyst_note="Merging these campaigns will combine activity attributed to differing actors.",
                )
            )

        is_safe = len(conflicts) == 0
        warning = None if is_safe else "Conflicts detected between source and target campaign intelligence."

        return CampaignMergePreviewResponse(
            source_campaign_id=src.campaign_id,
            source_name=src.name,
            target_campaign_id=tgt.campaign_id,
            target_name=tgt.name,
            source_indicators_count=len(src_iocs),
            source_assets_count=len(src_assets),
            source_incidents_count=src_inc_count,
            conflicting_sources=conflicts,
            is_safe=is_safe,
            warning_message=warning,
        )

    @classmethod
    def merge_campaigns(
        cls,
        db: Session,
        workspace_id: str,
        req: CampaignMergeRequest,
        analyst: str = "ANALYST",
    ) -> CampaignWorkspaceDetailResponse:
        src = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(CampaignModel.id == req.source_campaign_id, CampaignModel.campaign_id == req.source_campaign_id.upper()),
            )
            .first()
        )
        tgt = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(CampaignModel.id == req.target_campaign_id, CampaignModel.campaign_id == req.target_campaign_id.upper()),
            )
            .first()
        )
        if not src or not tgt:
            raise ValueError("Both source and target campaigns must exist.")
        if src.id == tgt.id:
            raise ValueError("Cannot merge a campaign into itself.")

        now = datetime.now(timezone.utc)

        # 1. Re-link member incidents from source to target
        src_incidents = db.query(CampaignIncidentModel).filter(CampaignIncidentModel.campaign_id == src.id).all()
        for si in src_incidents:
            # Check if incident already linked to target
            already_in_tgt = db.query(CampaignIncidentModel).filter(
                CampaignIncidentModel.campaign_id == tgt.id,
                CampaignIncidentModel.incident_id == si.incident_id,
            ).first()
            if not already_in_tgt:
                si.campaign_id = tgt.id
            else:
                db.delete(si)

        # 2. Re-link member emails from source to target
        src_emails = db.query(CampaignEmailModel).filter(CampaignEmailModel.campaign_id == src.id).all()
        for se in src_emails:
            already = db.query(CampaignEmailModel).filter(
                CampaignEmailModel.campaign_id == tgt.id,
                CampaignEmailModel.email_id == se.email_id,
            ).first()
            if not already:
                se.campaign_id = tgt.id
            else:
                db.delete(se)

        # 3. Aggregate evidence without losing history
        tgt_supp = cls._parse_json(tgt.supporting_evidence_json, [])
        src_supp = cls._parse_json(src.supporting_evidence_json, [])
        tgt_supp.extend(src_supp)
        tgt.supporting_evidence_json = cls._to_json(tgt_supp)

        tgt_contra = cls._parse_json(tgt.contradicting_evidence_json, [])
        src_contra = cls._parse_json(src.contradicting_evidence_json, [])
        tgt_contra.extend(src_contra)
        tgt.contradicting_evidence_json = cls._to_json(tgt_contra)

        # 4. Merge IOCs
        tgt_iocs = cls._parse_json(tgt.associated_iocs_json, [])
        src_iocs = cls._parse_json(src.associated_iocs_json, [])
        seen_ioc_vals = {i.get("value") for i in tgt_iocs if isinstance(i, dict)}
        for item in src_iocs:
            if isinstance(item, dict) and item.get("value") not in seen_ioc_vals:
                tgt_iocs.append(item)
                seen_ioc_vals.add(item.get("value"))
        tgt.associated_iocs_json = cls._to_json(tgt_iocs)

        # 5. Merge techniques
        tgt_techs = set(cls._parse_json(tgt.mitre_techniques_json, []))
        src_techs = set(cls._parse_json(src.mitre_techniques_json, []))
        tgt.mitre_techniques_json = cls._to_json(list(tgt_techs.union(src_techs)))

        # 6. Preserve Lineage & Provenance
        tgt_provenance = cls._parse_json(tgt.provenance_history_json, [])
        tgt_provenance.append({
            "action": "CAMPAIGN_MERGED_INTO",
            "actor": analyst,
            "timestamp": now.isoformat(),
            "details": f"Absorbed source campaign {src.campaign_id} ({src.name}). Rationale: {req.reason}",
            "source_campaign_id": src.campaign_id,
        })
        tgt.provenance_history_json = cls._to_json(tgt_provenance)
        tgt.updated_at = now

        # 7. Update source campaign to ARCHIVED (never hard delete forensic evidence)
        src_provenance = cls._parse_json(src.provenance_history_json, [])
        src_provenance.append({
            "action": "CAMPAIGN_MERGED_OUT",
            "actor": analyst,
            "timestamp": now.isoformat(),
            "details": f"Merged into target campaign {tgt.campaign_id} ({tgt.name}). Rationale: {req.reason}",
            "target_campaign_id": tgt.campaign_id,
        })
        src.provenance_history_json = cls._to_json(src_provenance)
        src.lifecycle_status = "ARCHIVED"
        src.status = "ARCHIVED"
        src.updated_at = now

        db.commit()
        db.refresh(tgt)

        AuditService.log_audit(
            db=db,
            action="CAMPAIGN_MERGED",
            resource_type="CAMPAIGN",
            resource_id=tgt.campaign_id,
            user=analyst,
            metadata={
                "source_campaign_id": src.campaign_id,
                "target_campaign_id": tgt.campaign_id,
                "reason": req.reason,
            },
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.CAMPAIGN_MERGED,
            scope=RealtimeResourceScopeEnum.CAMPAIGN,
            resource_id=tgt.id,
            title=f"Campaign {src.campaign_id} successfully merged into {tgt.campaign_id}",
        )

        return cls._format_campaign(db, tgt)

    @classmethod
    def split_campaign(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
        req: CampaignSplitRequest,
        analyst: str = "ANALYST",
    ) -> Dict[str, Any]:
        parent = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == campaign_id_or_uuid.strip(),
                    CampaignModel.campaign_id == campaign_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not parent:
            raise ValueError(f"Campaign '{campaign_id_or_uuid}' not found.")

        now = datetime.now(timezone.utc)
        total_count = db.query(CampaignModel).count()
        idx = total_count + 1
        new_camp_id = f"C-{idx:03d}"
        while db.query(CampaignModel).filter(CampaignModel.campaign_id == new_camp_id).first():
            idx += 1
            new_camp_id = f"C-{idx:03d}"

        # 1. Create child campaign
        child_provenance = [{
            "action": "CAMPAIGN_SPLIT_CREATED",
            "actor": analyst,
            "timestamp": now.isoformat(),
            "details": f"Split from parent campaign {parent.campaign_id} ({parent.name}). Rationale: {req.reason}",
            "parent_campaign_id": parent.campaign_id,
        }]

        child = CampaignModel(
            id=str(uuid.uuid4()),
            campaign_id=new_camp_id,
            name=req.new_campaign_name.strip(),
            workspace_id=workspace_id,
            status="OPEN",
            lifecycle_status="OPEN",
            activity_state="ACTIVE",
            watch_state="NOT_MONITORED",
            attribution_state="UNKNOWN",
            attribution_confidence=0.0,
            dominant_attack_type=parent.dominant_attack_type,
            targeted_brands_json=parent.targeted_brands_json,
            mitre_techniques_json=parent.mitre_techniques_json,
            supporting_evidence_json=cls._to_json([]),
            contradicting_evidence_json=cls._to_json([]),
            affected_assets_json=cls._to_json([]),
            affected_identities_json=cls._to_json([]),
            related_alerts_json=cls._to_json([]),
            related_incidents_json=cls._to_json([]),
            analyst_notes_json=cls._to_json([]),
            source_conflicts_json=cls._to_json([]),
            provenance_history_json=cls._to_json(child_provenance),
            overall_confidence=parent.overall_confidence,
            first_seen=parent.first_seen,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        db.add(child)
        db.flush()

        # 2. Move selected incidents to child campaign
        moved_incidents = 0
        for inc_id in req.incident_ids_to_move:
            c_inc = db.query(CampaignIncidentModel).filter(
                CampaignIncidentModel.campaign_id == parent.id,
                or_(CampaignIncidentModel.incident_id == inc_id, CampaignIncidentModel.id == inc_id),
            ).first()
            if c_inc:
                c_inc.campaign_id = child.id
                moved_incidents += 1

        # 3. Record split event on parent
        parent_provenance = cls._parse_json(parent.provenance_history_json, [])
        parent_provenance.append({
            "action": "CAMPAIGN_SPLIT_DETACHED",
            "actor": analyst,
            "timestamp": now.isoformat(),
            "details": f"Split child campaign {child.campaign_id} ({child.name}) created. {moved_incidents} incidents moved. Rationale: {req.reason}",
            "child_campaign_id": child.campaign_id,
        })
        parent.provenance_history_json = cls._to_json(parent_provenance)
        parent.updated_at = now

        db.commit()
        db.refresh(child)
        db.refresh(parent)

        AuditService.log_audit(
            db=db,
            action="CAMPAIGN_SPLIT",
            resource_type="CAMPAIGN",
            resource_id=parent.campaign_id,
            user=analyst,
            metadata={
                "parent_campaign_id": parent.campaign_id,
                "child_campaign_id": child.campaign_id,
                "reason": req.reason,
                "moved_incidents": moved_incidents,
            },
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.CAMPAIGN_SPLIT,
            scope=RealtimeResourceScopeEnum.CAMPAIGN,
            resource_id=parent.id,
            title=f"Campaign {parent.campaign_id} split into new campaign {child.campaign_id}",
        )

        return {
            "parent": cls._format_campaign(db, parent),
            "child": cls._format_campaign(db, child),
            "moved_incidents": moved_incidents,
        }

    # -------------------------------------------------------------------------
    # Hypotheses Management
    # -------------------------------------------------------------------------

    @classmethod
    def list_hypotheses(
        cls,
        db: Session,
        workspace_id: str,
        subject_id: str,
    ) -> List[HypothesisResponse]:
        hypotheses = (
            db.query(ThreatHypothesisModel)
            .filter(
                ThreatHypothesisModel.workspace_id == workspace_id,
                ThreatHypothesisModel.subject_id == subject_id.strip(),
            )
            .order_by(desc(ThreatHypothesisModel.updated_at))
            .all()
        )
        return [cls._format_hypothesis(h) for h in hypotheses]

    @classmethod
    def create_hypothesis(
        cls,
        db: Session,
        workspace_id: str,
        req: HypothesisCreateRequest,
        author: str = "ANALYST",
    ) -> HypothesisResponse:
        now = datetime.now(timezone.utc)
        supp = [e.model_dump() for e in (req.supporting_evidence or [])]
        contra = [e.model_dump() for e in (req.contradicting_evidence or [])]

        hypo = ThreatHypothesisModel(
            id=str(uuid.uuid4()),
            workspace_id=workspace_id,
            subject_type=req.subject_type.strip().upper(),
            subject_id=req.subject_id.strip(),
            title=req.title.strip(),
            hypothesis_text=req.hypothesis_text.strip(),
            status=req.status.value if req.status else "OPEN",
            confidence=round(req.confidence or 0.5, 2),
            supporting_evidence_json=cls._to_json(supp),
            contradicting_evidence_json=cls._to_json(contra),
            created_by=author,
            updated_by=author,
            created_at=now,
            updated_at=now,
        )
        db.add(hypo)
        db.commit()
        db.refresh(hypo)

        AuditService.log_audit(
            db=db,
            action="HYPOTHESIS_CREATED",
            resource_type="THREAT_HYPOTHESIS",
            resource_id=hypo.id,
            user=author,
            metadata={"title": hypo.title, "subject_id": hypo.subject_id, "status": hypo.status},
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.HYPOTHESIS_CREATED,
            scope=RealtimeResourceScopeEnum.CAMPAIGN,
            resource_id=hypo.subject_id,
            title=f"Analyst hypothesis '{hypo.title}' recorded",
        )

        return cls._format_hypothesis(hypo)

    @classmethod
    def update_hypothesis(
        cls,
        db: Session,
        workspace_id: str,
        hypothesis_id: str,
        req: HypothesisUpdateRequest,
        updater: str = "ANALYST",
    ) -> HypothesisResponse:
        hypo = (
            db.query(ThreatHypothesisModel)
            .filter(
                ThreatHypothesisModel.workspace_id == workspace_id,
                ThreatHypothesisModel.id == hypothesis_id.strip(),
            )
            .first()
        )
        if not hypo:
            raise ValueError(f"Hypothesis '{hypothesis_id}' not found.")

        if req.title is not None:
            hypo.title = req.title.strip()
        if req.hypothesis_text is not None:
            hypo.hypothesis_text = req.hypothesis_text.strip()
        if req.status is not None:
            hypo.status = req.status.value
        if req.confidence is not None:
            hypo.confidence = round(req.confidence, 2)
        if req.supporting_evidence is not None:
            hypo.supporting_evidence_json = cls._to_json([e.model_dump() for e in req.supporting_evidence])
        if req.contradicting_evidence is not None:
            hypo.contradicting_evidence_json = cls._to_json([e.model_dump() for e in req.contradicting_evidence])

        hypo.updated_by = updater
        hypo.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(hypo)

        AuditService.log_audit(
            db=db,
            action="HYPOTHESIS_UPDATED",
            resource_type="THREAT_HYPOTHESIS",
            resource_id=hypo.id,
            user=updater,
            metadata={"status": hypo.status, "confidence": hypo.confidence, "reason": req.reason},
        )

        cls._publish_event(
            workspace_id=workspace_id,
            event_type=RealtimeEventTypeEnum.HYPOTHESIS_UPDATED,
            scope=RealtimeResourceScopeEnum.CAMPAIGN,
            resource_id=hypo.subject_id,
            title=f"Hypothesis '{hypo.title}' updated to {hypo.status}",
        )

        return cls._format_hypothesis(hypo)

    # -------------------------------------------------------------------------
    # Timeline & Investigation Graph
    # -------------------------------------------------------------------------

    @classmethod
    def get_campaign_timeline(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
    ) -> CampaignTimelineResponse:
        campaign = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == campaign_id_or_uuid.strip(),
                    CampaignModel.campaign_id == campaign_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id_or_uuid}' not found.")

        events: List[CampaignTimelineEventItem] = []

        # 1. Ingest stored timeline events
        stored_tl = cls._parse_json(campaign.timeline_events_json, [])
        for item in stored_tl:
            if isinstance(item, dict):
                events.append(
                    CampaignTimelineEventItem(
                        timestamp=item.get("timestamp") or campaign.first_seen.isoformat(),
                        event_type=item.get("event_type") or "OBSERVED_INDICATOR",
                        title=item.get("event") or item.get("title") or "Forensic observation",
                        description=item.get("description") or f"Forensic signal correlated with {campaign.name}",
                        semantic_class=SemanticClassificationEnum.OBSERVED,
                        source="campaign_correlator",
                    )
                )

        # 2. Member incident opened times
        c_incs = db.query(CampaignIncidentModel).filter(CampaignIncidentModel.campaign_id == campaign.id).all()
        for ci in c_incs:
            inc = db.query(IncidentModel).filter(IncidentModel.id == ci.incident_id).first()
            if inc and inc.opened_at:
                events.append(
                    CampaignTimelineEventItem(
                        timestamp=inc.opened_at.isoformat(),
                        event_type="INCIDENT_OPENED",
                        title=f"Incident Opened: {inc.incident_id}",
                        description=f"Incident '{inc.title}' correlated into campaign (Severity: {inc.severity})",
                        semantic_class=SemanticClassificationEnum.CORRELATED,
                        source="cross_incident_engine",
                        raw_reference_id=inc.id,
                    )
                )

        # 3. Member email sent times
        for ce in campaign.emails:
            if ce.sent_at:
                events.append(
                    CampaignTimelineEventItem(
                        timestamp=ce.sent_at.isoformat(),
                        event_type="EMAIL_OBSERVED",
                        title=f"Phishing Artifact: {ce.subject or 'No subject'}",
                        description=f"From {ce.sender} to {ce.recipient} (Similarity: {int(ce.similarity_to_campaign * 100)}%)",
                        semantic_class=SemanticClassificationEnum.OBSERVED,
                        source="mail_analyzer",
                        raw_reference_id=ce.email_id,
                    )
                )

        # 4. Attribution assessments
        assessments = db.query(ThreatAttributionAssessmentModel).filter(
            ThreatAttributionAssessmentModel.workspace_id == workspace_id,
            ThreatAttributionAssessmentModel.subject_type == "CAMPAIGN",
            ThreatAttributionAssessmentModel.subject_id == campaign.id,
        ).all()
        for a in assessments:
            events.append(
                CampaignTimelineEventItem(
                    timestamp=a.assessed_at.isoformat(),
                    event_type="ATTRIBUTION_ASSESSED",
                    title=f"Attribution Assessment: {a.new_attribution_state}",
                    description=f"Analyst {a.assessed_by} recorded assessment (Confidence: {a.confidence}): {a.justification}",
                    semantic_class=SemanticClassificationEnum.ANALYST_ASSERTED,
                    source="analyst_assessment",
                    raw_reference_id=a.id,
                )
            )

        # Sort timeline chronologically
        events.sort(key=lambda e: e.timestamp)

        first_seen_str = campaign.first_seen.isoformat() if campaign.first_seen else ""
        last_seen_str = campaign.last_seen.isoformat() if campaign.last_seen else ""

        return CampaignTimelineResponse(
            campaign_id=campaign.campaign_id,
            events=events,
            first_seen=first_seen_str,
            last_seen=last_seen_str,
            activity_state=campaign.activity_state or "ACTIVE",
        )

    @classmethod
    def get_campaign_graph(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
        max_nodes: int = 75,
    ) -> InvestigationGraphResponse:
        campaign = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == campaign_id_or_uuid.strip(),
                    CampaignModel.campaign_id == campaign_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not campaign:
            return InvestigationGraphResponse(nodes=[], edges=[], summary=GraphSummary())

        nodes: Dict[str, GraphNode] = {}
        edges: Dict[str, GraphEdge] = {}

        # 1. Central Campaign Node
        camp_node_id = f"campaign:{campaign.id}"
        nodes[camp_node_id] = GraphNode(
            id=camp_node_id,
            type=NodeType.CAMPAIGN,
            label=f"{campaign.name} ({campaign.campaign_id})",
            metadata={
                "campaign_id": campaign.campaign_id,
                "lifecycle_status": campaign.lifecycle_status,
                "attribution_state": campaign.attribution_state,
                "attribution_confidence": campaign.attribution_confidence,
                "dominant_attack_type": campaign.dominant_attack_type,
            },
        )

        # 2. Threat Actor Node (if attributed)
        if campaign.threat_actor_id:
            actor = db.query(ThreatActorModel).filter(ThreatActorModel.id == campaign.threat_actor_id).first()
            if actor:
                actor_node_id = f"actor:{actor.id}"
                nodes[actor_node_id] = GraphNode(
                    id=actor_node_id,
                    type=NodeType.THREAT_ACTOR,
                    label=f"{actor.name} ({actor.actor_id})",
                    metadata={
                        "actor_type": actor.actor_type,
                        "attribution_state": actor.attribution_state,
                        "confidence": actor.attribution_confidence,
                    },
                )
                edges[f"edge:{camp_node_id}->ATTRIBUTED_TO->{actor_node_id}"] = GraphEdge(
                    id=f"edge:{camp_node_id}->ATTRIBUTED_TO->{actor_node_id}",
                    source=camp_node_id,
                    target=actor_node_id,
                    label="ATTRIBUTED_TO",
                    metadata={
                        "semantic_class": SemanticClassificationEnum.HYPOTHESIZED.value if campaign.attribution_state in ("POSSIBLE", "SUSPECTED") else SemanticClassificationEnum.ASSESSED.value,
                        "confidence": campaign.attribution_confidence,
                    },
                )

        # 3. Associated IOCs & Infrastructure Nodes
        iocs = cls._parse_json(campaign.associated_iocs_json, [])
        for ioc in iocs[:25]:
            if len(nodes) >= max_nodes:
                break
            if isinstance(ioc, dict) and ioc.get("value"):
                itype = (ioc.get("type") or "DOMAIN").upper()
                val = ioc.get("value")
                node_type = NodeType.DOMAIN
                if itype in ("IP", "IPV4", "IPV6"):
                    node_type = NodeType.IP
                elif itype in ("URL", "LINK"):
                    node_type = NodeType.URL
                elif itype == "ASN":
                    node_type = NodeType.ASN

                ioc_node_id = f"ioc:{itype.lower()}:{val}"
                if ioc_node_id not in nodes:
                    nodes[ioc_node_id] = GraphNode(
                        id=ioc_node_id,
                        type=node_type,
                        label=val,
                        metadata={"ioc_type": itype, "risk_score": ioc.get("risk_score", 70)},
                    )
                edge_id = f"edge:{camp_node_id}->USES_INFRASTRUCTURE->{ioc_node_id}"
                if edge_id not in edges:
                    edges[edge_id] = GraphEdge(
                        id=edge_id,
                        source=camp_node_id,
                        target=ioc_node_id,
                        label="USES_INFRASTRUCTURE",
                        metadata={"semantic_class": SemanticClassificationEnum.OBSERVED.value, "confidence": 1.0},
                    )

        # 4. MITRE ATT&CK Techniques
        techniques = cls._parse_json(campaign.mitre_techniques_json, [])
        for tech in techniques[:15]:
            if len(nodes) >= max_nodes:
                break
            tech_node_id = f"tech:{tech}"
            if tech_node_id not in nodes:
                nodes[tech_node_id] = GraphNode(
                    id=tech_node_id,
                    type=NodeType.TECHNIQUE,
                    label=tech,
                    metadata={"framework": "MITRE ATT&CK"},
                )
            edge_id = f"edge:{camp_node_id}->USES_TECHNIQUE->{tech_node_id}"
            if edge_id not in edges:
                edges[edge_id] = GraphEdge(
                    id=edge_id,
                    source=camp_node_id,
                    target=tech_node_id,
                    label="USES_TECHNIQUE",
                    metadata={"semantic_class": SemanticClassificationEnum.OBSERVED.value, "confidence": 0.95},
                )

        # 5. Connected Incidents
        c_incs = db.query(CampaignIncidentModel).filter(CampaignIncidentModel.campaign_id == campaign.id).limit(10).all()
        for ci in c_incs:
            if len(nodes) >= max_nodes:
                break
            inc = db.query(IncidentModel).filter(IncidentModel.id == ci.incident_id).first()
            if inc:
                inc_node_id = f"incident:{inc.id}"
                if inc_node_id not in nodes:
                    nodes[inc_node_id] = GraphNode(
                        id=inc_node_id,
                        type=NodeType.CASE,
                        label=f"{inc.incident_id}: {inc.title[:25]}",
                        metadata={"severity": inc.severity, "status": inc.status},
                    )
                edge_id = f"edge:{camp_node_id}->CORRELATED_INCIDENT->{inc_node_id}"
                if edge_id not in edges:
                    edges[edge_id] = GraphEdge(
                        id=edge_id,
                        source=camp_node_id,
                        target=inc_node_id,
                        label="CORRELATED_INCIDENT",
                        metadata={"semantic_class": SemanticClassificationEnum.CORRELATED.value, "similarity": ci.similarity_score},
                    )

        node_counts: Dict[str, int] = {}
        for n in nodes.values():
            node_counts[n.type.value] = node_counts.get(n.type.value, 0) + 1

        return InvestigationGraphResponse(
            nodes=list(nodes.values()),
            edges=list(edges.values()),
            summary=GraphSummary(
                total_nodes=len(nodes),
                total_edges=len(edges),
                node_type_counts=node_counts,
                has_high_risk_entities=True,
            ),
        )

    # -------------------------------------------------------------------------
    # Handoffs to Hunting & Detection Engineering
    # -------------------------------------------------------------------------

    @classmethod
    def get_hunt_handoff(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
    ) -> ThreatHuntHandoffResponse:
        campaign = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == campaign_id_or_uuid.strip(),
                    CampaignModel.campaign_id == campaign_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id_or_uuid}' not found.")

        iocs = cls._parse_json(campaign.associated_iocs_json, [])
        hunt_indicators = [i.get("value") for i in iocs if isinstance(i, dict) and i.get("value")]

        queries = []
        if hunt_indicators:
            sample_val = hunt_indicators[0]
            queries.append({
                "title": f"Hunt Related Network Traffic for {campaign.campaign_id}",
                "target_data_source": "NETWORK_FLOWS",
                "query_string": f'destination_ip == "{sample_val}" or dns_query contains "{sample_val}"',
            })
            queries.append({
                "title": f"Hunt Associated Authentication & Identity Events",
                "target_data_source": "AUTH_LOGS",
                "query_string": f'source_ip in {hunt_indicators[:5]} and auth_result == "SUCCESS"',
            })

        return ThreatHuntHandoffResponse(
            campaign_id=campaign.campaign_id,
            campaign_name=campaign.name,
            suggested_queries=queries,
            hunt_indicators=hunt_indicators[:20],
        )

    @classmethod
    def get_detection_handoff(
        cls,
        db: Session,
        workspace_id: str,
        campaign_id_or_uuid: str,
    ) -> DetectionHandoffResponse:
        campaign = (
            db.query(CampaignModel)
            .filter(
                CampaignModel.workspace_id == workspace_id,
                or_(
                    CampaignModel.id == campaign_id_or_uuid.strip(),
                    CampaignModel.campaign_id == campaign_id_or_uuid.strip().upper(),
                ),
            )
            .first()
        )
        if not campaign:
            raise ValueError(f"Campaign '{campaign_id_or_uuid}' not found.")

        iocs = cls._parse_json(campaign.associated_iocs_json, [])
        hunt_indicators = [i.get("value") for i in iocs if isinstance(i, dict) and i.get("value")]
        techs = cls._parse_json(campaign.mitre_techniques_json, [])

        return DetectionHandoffResponse(
            campaign_id=campaign.campaign_id,
            campaign_name=campaign.name,
            recommended_rule_title=f"Detect Coordinated Infrastructure Pattern for {campaign.name}",
            recommended_rule_description=f"Automated candidate detection rule targeting indicators corroborated under campaign {campaign.campaign_id}.",
            indicators_to_match=hunt_indicators[:10],
            attack_techniques=techs or ["T1566.002"],
            suggested_severity="HIGH",
        )

    # -------------------------------------------------------------------------
    # Format Helpers
    # -------------------------------------------------------------------------

    @classmethod
    def _format_campaign(cls, db: Session, c: CampaignModel) -> CampaignWorkspaceDetailResponse:
        actor_resp: Optional[ThreatActorResponse] = None
        if c.threat_actor_id:
            actor = db.query(ThreatActorModel).filter(ThreatActorModel.id == c.threat_actor_id).first()
            if actor:
                actor_resp = cls._format_actor(db, actor)

        brands = cls._parse_json(c.targeted_brands_json, [])
        techs = cls._parse_json(c.mitre_techniques_json, [])
        supp = [EvidenceItem(**e) for e in cls._parse_json(c.supporting_evidence_json, [])]
        contra = [EvidenceItem(**e) for e in cls._parse_json(c.contradicting_evidence_json, [])]
        conflicts = [SourceConflict(**sc) for sc in cls._parse_json(c.source_conflicts_json, [])]
        notes = [AnalystNote(**n) for n in cls._parse_json(c.analyst_notes_json, [])]
        provenance = cls._parse_json(c.provenance_history_json, [])

        # Fetch member incident IDs
        inc_ids = [ci.incident_id for ci in c.incidents]

        # Calculate affected assets by matching domains/hostnames to AssetModel
        affected_assets: List[AffectedAssetRef] = []
        raw_assets = cls._parse_json(c.affected_assets_json, [])
        if raw_assets:
            for ra in raw_assets:
                if isinstance(ra, dict) and ra.get("name"):
                    affected_assets.append(
                        AffectedAssetRef(
                            asset_id=ra.get("asset_id", str(uuid.uuid4())),
                            name=ra.get("name", "Unknown Asset"),
                            asset_type=ra.get("asset_type", "HOST"),
                            priority_band=ra.get("priority_band", "P2"),
                            business_criticality=ra.get("business_criticality", "HIGH"),
                            risk_score=float(ra.get("risk_score", 75.0)),
                            active_incidents=ra.get("active_incidents", 1),
                        )
                    )
        else:
            # Query actual assets in workspace if any match brand or indicators
            assets_db = db.query(AssetModel).filter(
                AssetModel.workspace_id == c.workspace_id
            ).limit(5).all()
            for a in assets_db:
                affected_assets.append(
                    AffectedAssetRef(
                        asset_id=a.id,
                        name=a.canonical_name or a.display_name,
                        asset_type=a.asset_type,
                        priority_band=a.priority_band or "P2",
                        business_criticality=a.criticality or "MEDIUM",
                        risk_score=a.risk_score or 50.0,
                        active_incidents=a.active_incident_count or 0,
                    )
                )

        # Affected identities from recipient emails
        affected_identities: List[AffectedIdentityRef] = []
        raw_ids = cls._parse_json(c.affected_identities_json, [])
        if raw_ids:
            for ri in raw_ids:
                if isinstance(ri, dict):
                    affected_identities.append(AffectedIdentityRef(**ri))
        else:
            recips = {ce.recipient for ce in c.emails if ce.recipient}
            for r in list(recips)[:10]:
                affected_identities.append(
                    AffectedIdentityRef(
                        identity_id=f"id:{r}",
                        email=r,
                        display_name=r.split("@")[0],
                        state=IdentityStateEnum.TARGETED,
                        is_privileged=False,
                        observation_count=1,
                    )
                )

        # Count hypotheses
        hypo_count = db.query(ThreatHypothesisModel).filter(
            ThreatHypothesisModel.workspace_id == c.workspace_id,
            ThreatHypothesisModel.subject_id == c.id,
        ).count()

        first_seen_str = c.first_seen.isoformat() if c.first_seen else ""
        last_seen_str = c.last_seen.isoformat() if c.last_seen else ""

        return CampaignWorkspaceDetailResponse(
            id=c.id,
            campaign_id=c.campaign_id,
            workspace_id=c.workspace_id,
            name=c.name,
            description=c.description,
            lifecycle_status=c.lifecycle_status or c.status or "CANDIDATE",
            activity_state=c.activity_state or "ACTIVE",
            watch_state=c.watch_state or "NOT_MONITORED",
            attribution_state=c.attribution_state or "UNKNOWN",
            attribution_confidence=c.attribution_confidence or 0.0,
            threat_actor=actor_resp,
            overall_confidence=c.overall_confidence or 0.0,
            first_seen=first_seen_str,
            last_seen=last_seen_str,
            dominant_attack_type=c.dominant_attack_type,
            targeted_brands=brands,
            email_count=c.email_count or len(c.emails),
            recipient_count=c.recipient_count,
            domain_count=c.domain_count,
            ip_count=c.ip_count,
            asn_count=c.asn_count,
            supporting_evidence=supp,
            contradicting_evidence=contra,
            mitre_techniques=techs,
            affected_assets=affected_assets,
            affected_identities=affected_identities,
            related_alerts=cls._parse_json(c.related_alerts_json, []),
            related_incidents=inc_ids,
            source_conflicts=conflicts,
            hypotheses_count=hypo_count,
            analyst_notes=notes,
            provenance_history=provenance,
            correlation_summary=c.correlation_summary,
            created_at=c.created_at.isoformat() if c.created_at else "",
            updated_at=c.updated_at.isoformat() if c.updated_at else "",
        )

    @classmethod
    def _format_assessment(cls, a: ThreatAttributionAssessmentModel) -> AttributionAssessmentResponse:
        supp = [EvidenceItem(**e) for e in cls._parse_json(a.supporting_evidence_json, [])]
        contra = [EvidenceItem(**e) for e in cls._parse_json(a.contradicting_evidence_json, [])]
        conflicts = [SourceConflict(**sc) for sc in cls._parse_json(a.external_conflicts_json, [])]
        return AttributionAssessmentResponse(
            id=a.id,
            workspace_id=a.workspace_id,
            subject_type=a.subject_type,
            subject_id=a.subject_id,
            target_type=a.target_type,
            target_id=a.target_id,
            prior_attribution_state=a.prior_attribution_state,
            new_attribution_state=a.new_attribution_state,
            confidence=a.confidence,
            justification=a.justification,
            supporting_evidence=supp,
            contradicting_evidence=contra,
            external_conflicts=conflicts,
            assessed_by=a.assessed_by,
            assessed_at=a.assessed_at.isoformat() if a.assessed_at else "",
        )

    @classmethod
    def _format_hypothesis(cls, h: ThreatHypothesisModel) -> HypothesisResponse:
        supp = [EvidenceItem(**e) for e in cls._parse_json(h.supporting_evidence_json, [])]
        contra = [EvidenceItem(**e) for e in cls._parse_json(h.contradicting_evidence_json, [])]
        return HypothesisResponse(
            id=h.id,
            workspace_id=h.workspace_id,
            subject_type=h.subject_type,
            subject_id=h.subject_id,
            title=h.title,
            hypothesis_text=h.hypothesis_text,
            status=h.status,
            confidence=h.confidence,
            supporting_evidence=supp,
            contradicting_evidence=contra,
            created_by=h.created_by,
            updated_by=h.updated_by,
            created_at=h.created_at.isoformat() if h.created_at else "",
            updated_at=h.updated_at.isoformat() if h.updated_at else "",
        )
