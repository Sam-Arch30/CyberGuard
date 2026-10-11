"""
Section 67: Authoritative SOC Operational Case Management Service.
Coordinates security investigations, incidents, evidence, tasks, decisions, response actions, and final resolution.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any, Set
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc, asc
from fastapi import HTTPException, status

from backend.db.models import (
    CaseModel,
    CaseEmailModel,
    CaseNoteModel,
    CaseFindingModel,
    CaseTaskModel,
    IncidentModel,
    CampaignModel,
    AuditLogModel,
    EmailAnalysisModel,
)
from backend.schemas.case import (
    CaseCreateRequest,
    CaseUpdateRequest,
    CaseAssignRequest,
    CaseResolveRequest,
    CaseCloseRequest,
    CaseReopenRequest,
    CaseMergeRequest,
    CaseLinkRequest,
    CaseEmailCreateRequest,
    CaseNoteCreateRequest,
    CaseNoteUpdateRequest,
    CaseFindingCreateRequest,
    CaseTaskCreate,
    CaseTaskUpdate,
    CaseListItemResponse,
    CaseDetailResponse,
    CaseEmailResponse,
    CaseNoteResponse,
    CaseFindingResponse,
    CaseTaskResponse,
    AuditLogResponse,
    AggregatedIndicators,
    CaseTimelineEvent,
    CaseMetricsSummary,
    CaseStatus,
    CaseSeverity,
    CasePriority,
    CaseCategory,
    CaseClassification,
    CaseResolutionCode,
    TaskStatus,
    TaskPriority,
)
from backend.schemas.realtime import RealtimeEventTypeEnum, RealtimeResourceScopeEnum
from backend.services.audit_service import AuditService
from backend.services.realtime_service import RealtimePublisher


ALLOWED_STATE_TRANSITIONS: Dict[str, Set[str]] = {
    "NEW": {"OPEN", "IN_PROGRESS", "CANCELLED"},
    "OPEN": {"IN_PROGRESS", "PENDING", "ON_HOLD", "RESOLVED", "CANCELLED"},
    "IN_PROGRESS": {"PENDING", "ON_HOLD", "RESOLVED", "CANCELLED"},
    "PENDING": {"IN_PROGRESS", "RESOLVED", "CANCELLED"},
    "ON_HOLD": {"IN_PROGRESS", "RESOLVED", "CANCELLED"},
    "RESOLVED": {"CLOSED", "IN_PROGRESS"},
    "CLOSED": {"IN_PROGRESS"},
    "CANCELLED": {"OPEN", "IN_PROGRESS"},
}


class CaseService:
    """
    Authoritative Business Logic Service for SOC Operational Case Management.
    """

    @staticmethod
    def _normalize_status(val: Optional[str]) -> str:
        if not val:
            return "OPEN"
        v = val.strip().upper()
        mapping = {
            "OPEN": "OPEN",
            "INVESTIGATING": "IN_PROGRESS",
            "IN_PROGRESS": "IN_PROGRESS",
            "NEW": "NEW",
            "PENDING": "PENDING",
            "ON_HOLD": "ON_HOLD",
            "RESOLVED": "RESOLVED",
            "CLOSED": "CLOSED",
            "CANCELLED": "CANCELLED",
            "ESCALATED": "IN_PROGRESS",
        }
        return mapping.get(v, v)

    @staticmethod
    def _generate_case_number(db: Session, workspace_id: str = "default") -> str:
        """
        Generates readable collision-safe sequential case identifiers:
        CG-{YEAR}-{SEQUENCE:06d} (e.g. CG-2026-000001).
        """
        current_year = datetime.now(timezone.utc).year
        prefix = f"CG-{current_year}-"

        # Count existing cases across workspace and database
        last_case = (
            db.query(CaseModel)
            .filter(CaseModel.case_number.like(f"{prefix}%"))
            .order_by(desc(CaseModel.case_number))
            .first()
        )

        next_seq = 1
        if last_case:
            try:
                seq_part = last_case.case_number.split("-")[-1]
                next_seq = int(seq_part) + 1
            except (ValueError, IndexError):
                next_seq = db.query(CaseModel).count() + 1
        else:
            total_cases = db.query(CaseModel).count()
            next_seq = total_cases + 1

        # Safeguard against collision
        candidate = f"{prefix}{next_seq:06d}"
        while db.query(CaseModel).filter(CaseModel.case_number == candidate).first() is not None:
            next_seq += 1
            candidate = f"{prefix}{next_seq:06d}"

        return candidate

    @staticmethod
    def _log_audit(
        db: Session,
        case_id: str,
        action: str,
        details: str,
        metadata: Optional[Dict[str, Any]] = None,
        user: Optional[str] = "SOC Analyst",
        workspace_id: str = "default",
    ):
        """Records an immutable audit event in AuditLogModel."""
        meta = metadata or {}
        AuditService.log_audit(
            db=db,
            action=action,
            resource_type="case",
            resource_id=case_id,
            user=user or "SOC Analyst",
            metadata=meta,
            case_id=case_id,
            details=details,
        )

    @staticmethod
    def _emit_realtime(
        event_type: RealtimeEventTypeEnum,
        case: CaseModel,
        user: str = "SOC Analyst",
        details: Optional[Dict[str, Any]] = None,
    ):
        """Emits a Section 46 compliant real-time event to workspace subscribers."""
        try:
            import uuid
            from backend.schemas.realtime import RealtimeEvent

            payload = {
                "case_id": case.id,
                "case_number": case.case_number,
                "title": case.title,
                "status": case.status,
                "severity": case.severity,
                "priority": case.priority,
                "owner_id": case.owner_id,
                "team_id": case.team_id,
                "version": case.version,
                "updated_at": case.updated_at.isoformat() if case.updated_at else datetime.now(timezone.utc).isoformat(),
            }
            if details:
                payload.update(details)

            ev_str = event_type.value if hasattr(event_type, "value") else str(event_type)
            evt = RealtimeEvent(
                schema_version=1,
                event_id=str(uuid.uuid4()),
                sequence=1,
                event_type=ev_str,
                resource_type="CASE",
                resource_id=case.id,
                workspace_id=case.workspace_id,
                message=f"Case {case.case_number} {ev_str.lower().replace('_', ' ')}",
                payload=payload,
            )
            RealtimePublisher.publish(evt)
        except Exception:
            pass

    # -------------------------------------------------------------------------
    # Case CRUD
    # -------------------------------------------------------------------------

    @classmethod
    def create_case(
        cls,
        db: Session,
        request: CaseCreateRequest,
        workspace_id: str = "default",
        user: str = "SOC Analyst",
    ) -> CaseModel:
        """
        Creates a new operational case with collision-safe case number,
        tenant scoping, and audit provenance.
        """
        case_number = cls._generate_case_number(db, workspace_id=workspace_id)
        raw_status = getattr(request, "status", None)
        norm_status = cls._normalize_status(raw_status.value if hasattr(raw_status, "value") else (raw_status or "OPEN"))
        raw_sev = getattr(request, "severity", None)
        norm_sev = (raw_sev.value if hasattr(raw_sev, "value") else (raw_sev or "MEDIUM")).upper()
        raw_prio = getattr(request, "priority", None)
        norm_prio = raw_prio.value if hasattr(raw_prio, "value") else (raw_prio or "P3_MEDIUM")
        raw_cat = getattr(request, "category", None)
        norm_cat = raw_cat.value if hasattr(raw_cat, "value") else (raw_cat or "PHISHING")
        raw_class = getattr(request, "classification", None)
        norm_class = raw_class.value if hasattr(raw_class, "value") else (raw_class or "INTERNAL")

        now = datetime.now(timezone.utc)
        case = CaseModel(
            case_number=case_number,
            workspace_id=workspace_id,
            title=request.title.strip(),
            description=(request.description or "").strip(),
            severity=norm_sev,
            priority=norm_prio,
            status=norm_status,
            category=norm_cat,
            classification=norm_class,
            owner_id=request.owner_id,
            team_id=request.team_id,
            created_by=user,
            incident_id=request.incident_id,
            primary_investigation_id=request.primary_investigation_id,
            campaign_id=request.campaign_id,
            opened_at=now,
            tags_json=json.dumps(request.tags or []),
            custom_fields_json=json.dumps(request.custom_fields or {}),
            affected_assets_json=json.dumps(request.affected_assets or []),
            affected_identities_json=json.dumps(request.affected_identities or []),
            related_alerts_json=json.dumps(request.related_alerts or []),
            related_evidence_json=json.dumps(request.related_evidence or []),
            related_response_actions_json=json.dumps([]),
            version=1,
            created_at=now,
            updated_at=now,
        )
        db.add(case)
        db.flush()

        cls._log_audit(
            db,
            case_id=case.id,
            action="CASE_CREATED",
            details=f"Case {case.case_number} created with title '{case.title}' (Priority: {case.priority}, Severity: {case.severity}).",
            metadata={
                "case_number": case.case_number,
                "title": case.title,
                "priority": case.priority,
                "severity": case.severity,
                "status": case.status,
                "incident_id": case.incident_id,
                "primary_investigation_id": case.primary_investigation_id,
            },
            user=user,
            workspace_id=workspace_id,
        )

        # Attach initial email if specified
        if request.initial_email:
            cls.add_email_to_case(db, case_id=case.id, request=request.initial_email, workspace_id=workspace_id, user=user)

        db.commit()
        db.refresh(case)

        cls._emit_realtime(RealtimeEventTypeEnum.CASE_CREATED, case, user=user)
        return case

    @classmethod
    def get_case(cls, db: Session, case_identifier: str, workspace_id: Optional[str] = None) -> CaseModel:
        """
        Retrieves a case by UUID id or human-readable case_number, enforcing workspace isolation.
        """
        query = db.query(CaseModel).filter(
            or_(
                CaseModel.id == case_identifier,
                CaseModel.case_number == case_identifier,
            )
        )
        if workspace_id:
            query = query.filter(CaseModel.workspace_id == workspace_id)

        case = query.first()
        if not case:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Investigation case '{case_identifier}' was not found in workspace '{workspace_id or 'default'}'.",
            )
        return case

    @classmethod
    def list_cases(
        cls,
        db: Session,
        workspace_id: Optional[str] = None,
        status_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        priority_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        owner_id: Optional[str] = None,
        team_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        search_query: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[CaseListItemResponse], int]:
        """
        Lists and filters operational cases within the workspace.
        """
        query = db.query(CaseModel)
        if workspace_id:
            query = query.filter(CaseModel.workspace_id == workspace_id)

        if status_filter and status_filter.upper() != "ALL":
            norm = cls._normalize_status(status_filter)
            query = query.filter(CaseModel.status == norm)

        if severity_filter and severity_filter.upper() != "ALL":
            query = query.filter(CaseModel.severity == severity_filter.upper())

        if priority_filter and priority_filter.upper() != "ALL":
            query = query.filter(CaseModel.priority == priority_filter.upper())

        if category_filter and category_filter.upper() != "ALL":
            query = query.filter(CaseModel.category == category_filter.upper())

        if owner_id:
            query = query.filter(CaseModel.owner_id == owner_id)

        if team_id:
            query = query.filter(CaseModel.team_id == team_id)

        if incident_id:
            query = query.filter(CaseModel.incident_id == incident_id)

        if search_query and search_query.strip():
            term = f"%{search_query.strip().lower()}%"
            query = query.filter(
                or_(
                    CaseModel.title.ilike(term),
                    CaseModel.case_number.ilike(term),
                    CaseModel.description.ilike(term),
                    CaseModel.tags_json.ilike(term),
                )
            )

        total = query.count()
        cases = query.order_by(desc(CaseModel.updated_at)).offset(skip).limit(limit).all()

        responses = [cls._serialize_list_item(c) for c in cases]
        return responses, total

    @classmethod
    def get_case_detail(cls, db: Session, case_identifier: str, workspace_id: Optional[str] = None) -> CaseDetailResponse:
        """
        Returns the rich, authoritative case record including tasks, notes,
        findings, evidence references, and aggregated indicators.
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)

        # Aggregate indicators across all linked emails and findings
        domains: set = set()
        ips: set = set()
        urls: set = set()
        attachments: set = set()

        for ce in case.emails:
            if ce.indicators_json:
                try:
                    data = json.loads(ce.indicators_json)
                    for d in data.get("domains", []):
                        if d: domains.add(str(d).lower().strip())
                    for ip in data.get("ips", []):
                        if ip: ips.add(str(ip).strip())
                    for u in data.get("urls", []):
                        if u: urls.add(str(u).strip())
                    for a in data.get("attachments", []):
                        if a:
                            name = a.get("filename") if isinstance(a, dict) else str(a)
                            if name: attachments.add(name)
                except Exception:
                    pass

        agg = AggregatedIndicators(
            domains=sorted(list(domains)),
            ips=sorted(list(ips)),
            urls=sorted(list(urls)),
            attachments=sorted(list(attachments)),
        )

        tags = json.loads(case.tags_json) if case.tags_json else []
        custom_fields = json.loads(case.custom_fields_json) if case.custom_fields_json else {}
        affected_assets = json.loads(case.affected_assets_json) if case.affected_assets_json else []
        affected_identities = json.loads(case.affected_identities_json) if case.affected_identities_json else []
        related_alerts = json.loads(case.related_alerts_json) if case.related_alerts_json else []
        related_evidence = json.loads(case.related_evidence_json) if case.related_evidence_json else []
        related_response_actions = json.loads(case.related_response_actions_json) if case.related_response_actions_json else []

        tasks = [
            CaseTaskResponse(
                id=t.id,
                case_id=t.case_id,
                workspace_id=t.workspace_id,
                title=t.title,
                description=t.description,
                status=t.status,
                priority=t.priority,
                assignee_id=t.assignee_id,
                team_id=t.team_id,
                due_at=t.due_at,
                completed_at=t.completed_at,
                completed_by=t.completed_by,
                created_by=t.created_by,
                order_index=t.order_index,
                is_automated_recommendation=t.is_automated_recommendation,
                source_action_id=t.source_action_id,
                created_at=t.created_at,
                updated_at=t.updated_at,
            )
            for t in case.tasks
        ]

        notes = [
            CaseNoteResponse(
                id=n.id,
                case_id=n.case_id,
                author=n.author,
                note_text=n.note_text,
                visibility=getattr(n, "visibility", "ANALYST") or "ANALYST",
                created_at=n.created_at,
                updated_at=getattr(n, "updated_at", n.created_at),
            )
            for n in case.notes
        ]

        return CaseDetailResponse(
            id=case.id,
            case_number=case.case_number,
            workspace_id=case.workspace_id,
            title=case.title,
            description=case.description,
            severity=case.severity,
            priority=case.priority,
            status=case.status,
            category=case.category,
            classification=case.classification,
            owner_id=case.owner_id,
            team_id=case.team_id,
            created_by=case.created_by,
            incident_id=case.incident_id,
            primary_investigation_id=case.primary_investigation_id,
            campaign_id=case.campaign_id,
            sla_policy_id=case.sla_policy_id,
            sla_status=case.sla_status,
            next_sla_deadline=case.next_sla_deadline,
            opened_at=case.opened_at,
            resolved_at=case.resolved_at,
            resolved_by=case.resolved_by,
            resolution_code=case.resolution_code,
            resolution_summary=case.resolution_summary,
            closed_at=case.closed_at,
            closed_by=case.closed_by,
            closure_notes=case.closure_notes,
            reopened_at=case.reopened_at,
            reopened_by=case.reopened_by,
            reopen_reason=case.reopen_reason,
            duplicate_of_id=case.duplicate_of_id,
            merged_into_id=case.merged_into_id,
            tags=tags,
            custom_fields=custom_fields,
            affected_assets=affected_assets,
            affected_identities=affected_identities,
            related_alerts=related_alerts,
            related_evidence=related_evidence,
            related_response_actions=related_response_actions,
            version=case.version,
            created_at=case.created_at,
            updated_at=case.updated_at,
            emails=[CaseEmailResponse.model_validate(e) for e in case.emails],
            notes=notes,
            findings=[CaseFindingResponse.model_validate(f) for f in case.findings],
            tasks=tasks,
            audit_logs=[
                AuditLogResponse(
                    id=a.id,
                    case_id=case.id,
                    action=a.action,
                    details=a.details or "",
                    user=a.user or "SOC Analyst",
                    timestamp=a.timestamp,
                )
                for a in case.audit_logs
            ],
            aggregated_indicators=agg,
        )

    @classmethod
    def update_case(
        cls,
        db: Session,
        case_identifier: str,
        request: CaseUpdateRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseModel:
        """
        Updates case metadata with optimistic concurrency check,
        state machine validation, and audit tracking.
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)

        # Optimistic concurrency control check
        if request.expected_version is not None and request.expected_version != case.version:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Concurrent modification detected on Case {case.case_number}. Expected version {request.expected_version}, but current version is {case.version}. Please refresh and retry.",
            )

        has_changes = False

        if request.title is not None and request.title.strip() != case.title:
            cls._log_audit(db, case.id, "TITLE_UPDATED", f"Title updated to '{request.title.strip()}'.", user=user, workspace_id=case.workspace_id)
            case.title = request.title.strip()
            has_changes = True

        if request.description is not None and request.description != case.description:
            case.description = request.description
            has_changes = True

        if request.status is not None:
            raw_new = request.status.value if hasattr(request.status, "value") else str(request.status)
            new_st = cls._normalize_status(raw_new)
            if new_st != case.status:
                cls._validate_status_transition(case.status, new_st)
                old_st = case.status
                case.status = new_st
                cls._log_audit(
                    db,
                    case.id,
                    "CASE_STATUS_CHANGED",
                    f"Status updated from '{old_st}' to '{new_st}'.",
                    metadata={"case_number": case.case_number, "old_status": old_st, "new_status": new_st},
                    user=user,
                    workspace_id=case.workspace_id,
                )
                # Backward compatibility
                cls._log_audit(
                    db,
                    case.id,
                    "STATUS_CHANGED",
                    f"Status updated from '{old_st}' to '{new_st}'.",
                    metadata={"case_number": case.case_number, "old_status": old_st, "new_status": new_st},
                    user=user,
                    workspace_id=case.workspace_id,
                )
                has_changes = True

        if request.severity is not None:
            raw_sev = request.severity.value if hasattr(request.severity, "value") else str(request.severity)
            new_sev = raw_sev.upper()
            if new_sev != case.severity:
                old_sev = case.severity
                case.severity = new_sev
                cls._log_audit(
                    db,
                    case.id,
                    "SEVERITY_CHANGED",
                    f"Severity updated from '{old_sev}' to '{new_sev}'.",
                    metadata={"case_number": case.case_number, "old_severity": old_sev, "new_severity": new_sev},
                    user=user,
                    workspace_id=case.workspace_id,
                )
                has_changes = True

        if request.priority is not None:
            raw_prio = request.priority.value if hasattr(request.priority, "value") else str(request.priority)
            if raw_prio != case.priority:
                old_prio = case.priority
                case.priority = raw_prio
                cls._log_audit(
                    db,
                    case.id,
                    "PRIORITY_CHANGED",
                    f"Priority updated from '{old_prio}' to '{raw_prio}'.",
                    metadata={"case_number": case.case_number, "old_priority": old_prio, "new_priority": raw_prio},
                    user=user,
                    workspace_id=case.workspace_id,
                )
                has_changes = True

        if request.category is not None:
            raw_cat = request.category.value if hasattr(request.category, "value") else str(request.category)
            case.category = raw_cat
            has_changes = True

        if request.classification is not None:
            raw_class = request.classification.value if hasattr(request.classification, "value") else str(request.classification)
            case.classification = raw_class
            has_changes = True

        if request.owner_id is not None and request.owner_id != case.owner_id:
            old_owner = case.owner_id
            case.owner_id = request.owner_id
            cls._log_audit(
                db,
                case.id,
                "CASE_ASSIGNED",
                f"Case assigned to owner '{request.owner_id}'.",
                metadata={"case_number": case.case_number, "old_owner": old_owner, "new_owner": request.owner_id},
                user=user,
                workspace_id=case.workspace_id,
            )
            has_changes = True

        if request.team_id is not None and request.team_id != case.team_id:
            case.team_id = request.team_id
            has_changes = True

        if request.primary_investigation_id is not None:
            case.primary_investigation_id = request.primary_investigation_id
            has_changes = True

        if request.campaign_id is not None:
            case.campaign_id = request.campaign_id
            has_changes = True

        if request.tags is not None:
            case.tags_json = json.dumps(request.tags)
            has_changes = True

        if request.custom_fields is not None:
            case.custom_fields_json = json.dumps(request.custom_fields)
            has_changes = True

        if request.affected_assets is not None:
            case.affected_assets_json = json.dumps(request.affected_assets)
            has_changes = True

        if request.affected_identities is not None:
            case.affected_identities_json = json.dumps(request.affected_identities)
            has_changes = True

        if request.related_alerts is not None:
            case.related_alerts_json = json.dumps(request.related_alerts)
            has_changes = True

        if request.related_evidence is not None:
            case.related_evidence_json = json.dumps(request.related_evidence)
            has_changes = True

        if has_changes:
            case.version += 1
            case.updated_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(case)
            cls._emit_realtime(RealtimeEventTypeEnum.CASE_UPDATED, case, user=user)

        return case

    # -------------------------------------------------------------------------
    # State Machine: Resolve, Close, Reopen, Assign
    # -------------------------------------------------------------------------

    @classmethod
    def _validate_status_transition(cls, current_status: str, target_status: str):
        """Enforces authorized lifecycle state transitions."""
        curr = cls._normalize_status(current_status)
        targ = cls._normalize_status(target_status)
        if curr == targ:
            return

        allowed = ALLOWED_STATE_TRANSITIONS.get(curr, set())
        if targ not in allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid case status transition from '{curr}' to '{targ}'. Allowed transitions from '{curr}': {sorted(list(allowed))}.",
            )

    @classmethod
    def assign_case(
        cls,
        db: Session,
        case_identifier: str,
        request: CaseAssignRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseModel:
        """Assigns or reassigns case owner and team with audit traceability."""
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        old_owner = case.owner_id
        old_team = case.team_id

        case.owner_id = request.owner_id
        case.team_id = request.team_id
        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case.id,
            "CASE_ASSIGNED",
            f"Case assigned to owner '{request.owner_id}' (Team: '{request.team_id}'). Reason: {request.reason}",
            metadata={
                "case_number": case.case_number,
                "old_owner": old_owner,
                "new_owner": request.owner_id,
                "old_team": old_team,
                "new_team": request.team_id,
                "reason": request.reason,
            },
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(case)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_ASSIGNED, case, user=user, details={"reason": request.reason})
        return case

    @classmethod
    def resolve_case(
        cls,
        db: Session,
        case_identifier: str,
        request: CaseResolveRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseModel:
        """
        Resolves the operational case. The security matter is addressed,
        recording disposition code and resolution rationale.
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        cls._validate_status_transition(case.status, "RESOLVED")

        if not request.resolution_summary or len(request.resolution_summary.strip()) < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Resolution summary is required (minimum 5 characters) to explain findings and actions taken.",
            )

        now = datetime.now(timezone.utc)
        case.status = CaseStatus.RESOLVED.value
        case.resolution_code = request.resolution_code.value if hasattr(request.resolution_code, "value") else str(request.resolution_code)
        case.resolution_summary = request.resolution_summary.strip()
        case.resolved_at = now
        case.resolved_by = user
        if request.affected_identities:
            case.affected_identities_json = json.dumps(request.affected_identities)
        if request.tags:
            case.tags_json = json.dumps(request.tags)

        case.version += 1
        case.updated_at = now

        cls._log_audit(
            db,
            case.id,
            "CASE_RESOLVED",
            f"Case resolved with disposition '{case.resolution_code}': {case.resolution_summary}",
            metadata={
                "case_number": case.case_number,
                "resolution_code": case.resolution_code,
                "resolved_by": user,
            },
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(case)
        cls._emit_realtime(
            RealtimeEventTypeEnum.CASE_RESOLVED,
            case,
            user=user,
            details={"resolution_code": case.resolution_code, "resolved_by": user},
        )
        return case

    @classmethod
    def close_case(
        cls,
        db: Session,
        case_identifier: str,
        request: CaseCloseRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseModel:
        """
        Completes the final operational review and closes the case.
        Validates closure checklist (unresolved tasks, resolution presence).
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        cls._validate_status_transition(case.status, "CLOSED")

        # Validate task checklist
        open_tasks = [t for t in case.tasks if t.status in ("TODO", "IN_PROGRESS", "BLOCKED")]
        if open_tasks:
            if not request.force_close_tasks:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot close case: {len(open_tasks)} tasks remain open. Complete or cancel tasks first, or set 'force_close_tasks' to true.",
                )
            for t in open_tasks:
                t.status = "CANCELLED"
                t.updated_at = datetime.now(timezone.utc)

        now = datetime.now(timezone.utc)
        case.status = CaseStatus.CLOSED.value
        case.closed_at = now
        case.closed_by = user
        case.closure_notes = request.closure_notes.strip()
        case.version += 1
        case.updated_at = now

        cls._log_audit(
            db,
            case.id,
            "CASE_CLOSED",
            f"Case {case.case_number} closed by {user}. Notes: {case.closure_notes}",
            metadata={"case_number": case.case_number, "closed_by": user},
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(case)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_CLOSED, case, user=user)
        return case

    @classmethod
    def reopen_case(
        cls,
        db: Session,
        case_identifier: str,
        request: CaseReopenRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseModel:
        """
        Reopens a resolved or closed case with mandatory auditable justification.
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        cls._validate_status_transition(case.status, "IN_PROGRESS")

        if not request.reopen_reason or len(request.reopen_reason.strip()) < 5:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mandatory justification required to reopen case (minimum 5 characters).",
            )

        now = datetime.now(timezone.utc)
        prev_status = case.status
        case.status = CaseStatus.IN_PROGRESS.value
        case.reopened_at = now
        case.reopened_by = user
        case.reopen_reason = request.reopen_reason.strip()
        case.closed_at = None
        case.closed_by = None
        case.version += 1
        case.updated_at = now

        cls._log_audit(
            db,
            case.id,
            "CASE_REOPENED",
            f"Case {case.case_number} reopened from '{prev_status}' by {user}. Reason: {case.reopen_reason}",
            metadata={
                "case_number": case.case_number,
                "previous_status": prev_status,
                "reopened_by": user,
                "reopen_reason": case.reopen_reason,
            },
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(case)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_REOPENED, case, user=user, details={"reason": case.reopen_reason})
        return case

    @classmethod
    def merge_cases(
        cls,
        db: Session,
        target_case_identifier: str,
        request: CaseMergeRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseModel:
        """
        Safely merges one or more source cases into a target case.
        Preserves provenance: repoints tasks, notes, findings, and emails without evidence loss.
        Marks source cases as RESOLVED with resolution_code='DUPLICATE' and merged_into_id pointers.
        """
        target = cls.get_case(db, target_case_identifier, workspace_id=workspace_id)
        now = datetime.now(timezone.utc)

        merged_numbers = []
        for src_id in request.source_case_ids:
            if src_id in (target.id, target.case_number):
                continue
            src = cls.get_case(db, src_id, workspace_id=workspace_id)
            if src.workspace_id != target.workspace_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Cannot merge case {src.case_number} across workspaces.",
                )

            # Repoint tasks
            for task in src.tasks:
                task.case_id = target.id
                task.description = (task.description or "") + f" (Merged from {src.case_number})"

            # Repoint notes
            for note in src.notes:
                note.case_id = target.id
                note.note_text = f"[Merged from {src.case_number}] {note.note_text}"

            # Repoint findings
            for finding in src.findings:
                finding.case_id = target.id

            # Repoint emails (avoid duplicate emails)
            existing_email_ids = {e.email_id for e in target.emails}
            for em in src.emails:
                if em.email_id not in existing_email_ids:
                    em.case_id = target.id
                    existing_email_ids.add(em.email_id)

            # Mark source case as DUPLICATE merged into target
            src.status = CaseStatus.RESOLVED.value
            src.resolution_code = CaseResolutionCode.DUPLICATE.value
            src.resolution_summary = f"Merged into {target.case_number}. Reason: {request.reason}"
            src.merged_into_id = target.id
            src.duplicate_of_id = target.id
            src.resolved_at = now
            src.resolved_by = user
            src.version += 1
            src.updated_at = now

            cls._log_audit(
                db,
                src.id,
                "CASE_MERGED",
                f"Case {src.case_number} merged into {target.case_number}. Reason: {request.reason}",
                metadata={"merged_into_case_id": target.id, "target_case_number": target.case_number},
                user=user,
                workspace_id=src.workspace_id,
            )
            merged_numbers.append(src.case_number)

        target.version += 1
        target.updated_at = now

        cls._log_audit(
            db,
            target.id,
            "CASE_MERGED",
            f"Merged cases {merged_numbers} into {target.case_number}. Reason: {request.reason}",
            metadata={"source_cases": merged_numbers, "reason": request.reason},
            user=user,
            workspace_id=target.workspace_id,
        )

        db.commit()
        db.refresh(target)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_MERGED, target, user=user, details={"merged_sources": merged_numbers})
        return target

    # -------------------------------------------------------------------------
    # Tasks Management
    # -------------------------------------------------------------------------

    @classmethod
    def create_task(
        cls,
        db: Session,
        case_identifier: str,
        request: CaseTaskCreate,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseTaskResponse:
        """Creates an operational task within the case."""
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        now = datetime.now(timezone.utc)

        task = CaseTaskModel(
            case_id=case.id,
            workspace_id=case.workspace_id,
            title=request.title.strip(),
            description=request.description,
            status="TODO",
            priority=request.priority.value if hasattr(request.priority, "value") else (request.priority or "MEDIUM"),
            assignee_id=request.assignee_id,
            team_id=request.team_id,
            due_at=request.due_at,
            order_index=request.order_index or (len(case.tasks) + 1),
            is_automated_recommendation=bool(request.is_automated_recommendation),
            source_action_id=request.source_action_id,
            created_by=user,
            created_at=now,
            updated_at=now,
        )
        db.add(task)
        case.version += 1
        case.updated_at = now

        cls._log_audit(
            db,
            case.id,
            "CASE_TASK_CREATED",
            f"Task '{task.title}' added to case (Priority: {task.priority}).",
            metadata={"task_id": task.id, "title": task.title, "priority": task.priority},
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(task)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_TASK_CREATED, case, user=user, details={"task_id": task.id, "task_title": task.title})
        return CaseTaskResponse.model_validate(task)

    @classmethod
    def update_task(
        cls,
        db: Session,
        case_identifier: str,
        task_id: str,
        request: CaseTaskUpdate,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseTaskResponse:
        """Updates task status, assignment, or completion."""
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        task = db.query(CaseTaskModel).filter(CaseTaskModel.id == task_id, CaseTaskModel.case_id == case.id).first()
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' was not found in case.")

        now = datetime.now(timezone.utc)
        if request.title is not None:
            task.title = request.title.strip()
        if request.description is not None:
            task.description = request.description
        if request.priority is not None:
            task.priority = request.priority.value if hasattr(request.priority, "value") else str(request.priority)
        if request.assignee_id is not None:
            task.assignee_id = request.assignee_id
        if request.team_id is not None:
            task.team_id = request.team_id
        if request.due_at is not None:
            task.due_at = request.due_at
        if request.order_index is not None:
            task.order_index = request.order_index

        if request.status is not None:
            new_status = request.status.value if hasattr(request.status, "value") else str(request.status)
            task.status = new_status
            if new_status == "COMPLETED":
                task.completed_at = now
                task.completed_by = user
                cls._log_audit(
                    db,
                    case.id,
                    "CASE_TASK_COMPLETED",
                    f"Task '{task.title}' completed by {user}.",
                    metadata={"task_id": task.id, "title": task.title},
                    user=user,
                    workspace_id=case.workspace_id,
                )
            else:
                task.completed_at = None
                task.completed_by = None

        task.updated_at = now
        case.version += 1
        case.updated_at = now

        db.commit()
        db.refresh(task)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_TASK_UPDATED, case, user=user, details={"task_id": task.id, "status": task.status})
        return CaseTaskResponse.model_validate(task)

    @classmethod
    def delete_task(
        cls,
        db: Session,
        case_identifier: str,
        task_id: str,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ):
        """Removes a task from the case."""
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        task = db.query(CaseTaskModel).filter(CaseTaskModel.id == task_id, CaseTaskModel.case_id == case.id).first()
        if not task:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Task '{task_id}' was not found in case.")

        task_title = task.title
        db.delete(task)
        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case.id,
            "CASE_TASK_DELETED",
            f"Task '{task_title}' deleted by {user}.",
            metadata={"task_id": task_id, "title": task_title},
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()

    @classmethod
    def generate_tasks_from_investigation_gaps(
        cls,
        db: Session,
        case_identifier: str,
        gaps: List[Dict[str, Any]],
        workspace_id: Optional[str] = None,
        user: str = "Investigation Automation",
    ) -> List[CaseTaskResponse]:
        """
        Creates automated task recommendations from Section 66 investigation gaps.
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        created_tasks = []

        for gap in gaps:
            title = f"Resolve Gap: {gap.get('title', 'Missing Telemetry')}"
            desc = gap.get("remediation_recommendation") or gap.get("description") or "Investigate missing data source."
            task = CaseTaskModel(
                case_id=case.id,
                workspace_id=case.workspace_id,
                title=title[:250],
                description=desc,
                status="TODO",
                priority="HIGH" if gap.get("severity") in ("CRITICAL", "HIGH") else "MEDIUM",
                is_automated_recommendation=True,
                source_action_id=gap.get("category"),
                created_by=user,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(task)
            created_tasks.append(task)

        if created_tasks:
            case.version += 1
            case.updated_at = datetime.now(timezone.utc)
            db.commit()
            for t in created_tasks:
                db.refresh(t)

        return [CaseTaskResponse.model_validate(t) for t in created_tasks]

    # -------------------------------------------------------------------------
    # Multi-Entity Linking & Timeline
    # -------------------------------------------------------------------------

    @classmethod
    def link_entity(
        cls,
        db: Session,
        case_identifier: str,
        request: CaseLinkRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseDetailResponse:
        """
        Links an external entity (Alert, Incident, Investigation, Evidence, Campaign, Asset, Identity)
        without duplicating underlying objects.
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        etype = request.entity_type.upper().strip()
        eid = request.entity_id.strip()

        if etype == "INCIDENT":
            inc = db.query(IncidentModel).filter(IncidentModel.id == eid).first()
            if not inc:
                inc = db.query(IncidentModel).filter(IncidentModel.incident_number == eid).first()
            if not inc:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{eid}' not found.")
            case.incident_id = inc.id
            cls._log_audit(db, case.id, "INCIDENT_LINKED", f"Linked incident {inc.incident_number} to case.", user=user, workspace_id=case.workspace_id)

        elif etype == "INVESTIGATION":
            case.primary_investigation_id = eid
            cls._log_audit(db, case.id, "INVESTIGATION_LINKED", f"Linked investigation '{eid}' to case.", user=user, workspace_id=case.workspace_id)

        elif etype == "CAMPAIGN":
            camp = db.query(CampaignModel).filter(or_(CampaignModel.id == eid, CampaignModel.campaign_id == eid)).first()
            if not camp:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Campaign '{eid}' not found.")
            case.campaign_id = camp.id
            cls._log_audit(db, case.id, "CAMPAIGN_LINKED", f"Linked campaign '{camp.name}' to case.", user=user, workspace_id=case.workspace_id)

        elif etype == "ALERT":
            alerts = json.loads(case.related_alerts_json) if case.related_alerts_json else []
            if eid not in alerts:
                alerts.append(eid)
                case.related_alerts_json = json.dumps(alerts)
                cls._log_audit(db, case.id, "ALERT_LINKED", f"Linked alert '{eid}' to case.", user=user, workspace_id=case.workspace_id)

        elif etype == "EVIDENCE":
            ev = json.loads(case.related_evidence_json) if case.related_evidence_json else []
            if eid not in ev:
                ev.append(eid)
                case.related_evidence_json = json.dumps(ev)
                cls._log_audit(db, case.id, "EVIDENCE_LINKED", f"Linked evidence '{eid}' to case.", user=user, workspace_id=case.workspace_id)

        elif etype == "ASSET":
            assets = json.loads(case.affected_assets_json) if case.affected_assets_json else []
            if eid not in assets:
                assets.append(eid)
                case.affected_assets_json = json.dumps(assets)
                cls._log_audit(db, case.id, "ASSET_LINKED", f"Linked affected asset '{eid}' to case.", user=user, workspace_id=case.workspace_id)

        elif etype == "IDENTITY":
            idents = json.loads(case.affected_identities_json) if case.affected_identities_json else []
            if eid not in idents:
                idents.append(eid)
                case.affected_identities_json = json.dumps(idents)
                cls._log_audit(db, case.id, "IDENTITY_LINKED", f"Linked affected identity '{eid}' to case.", user=user, workspace_id=case.workspace_id)

        elif etype == "RESPONSE_ACTION":
            resp = json.loads(case.related_response_actions_json) if case.related_response_actions_json else []
            if eid not in resp:
                resp.append(eid)
                case.related_response_actions_json = json.dumps(resp)
                cls._log_audit(db, case.id, "RESPONSE_ACTION_LINKED", f"Linked response action '{eid}' to case.", user=user, workspace_id=case.workspace_id)

        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported entity type '{request.entity_type}'. Supported: ALERT, INCIDENT, INVESTIGATION, EVIDENCE, CAMPAIGN, ASSET, IDENTITY, RESPONSE_ACTION.",
            )

        case.version += 1
        case.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(case)

        cls._emit_realtime(RealtimeEventTypeEnum.CASE_UPDATED, case, user=user)
        return cls.get_case_detail(db, case.id, workspace_id=workspace_id)

    @classmethod
    def get_case_timeline(
        cls,
        db: Session,
        case_identifier: str,
        workspace_id: Optional[str] = None,
    ) -> List[CaseTimelineEvent]:
        """
        Synthesizes a unified operational timeline of all case milestones,
        audit logs, task completions, and linked investigation events.
        """
        case = cls.get_case(db, case_identifier, workspace_id=workspace_id)
        events: List[CaseTimelineEvent] = []

        # 1. Case Opened Milestone
        events.append(
            CaseTimelineEvent(
                id=f"evt-{case.id}-opened",
                timestamp=case.opened_at or case.created_at,
                event_type="CASE_OPENED",
                title=f"Case {case.case_number} Opened",
                description=f"Case initialized with title '{case.title}' (Priority: {case.priority}, Severity: {case.severity}).",
                actor=case.created_by or "SYSTEM",
                source="CASE",
            )
        )

        # 2. Audit Log Entries
        for al in case.audit_logs:
            events.append(
                CaseTimelineEvent(
                    id=f"audit-{al.id}",
                    timestamp=al.timestamp,
                    event_type=al.action,
                    title=al.action.replace("_", " ").title(),
                    description=al.details or "",
                    actor=al.user or "SOC Analyst",
                    source="AUDIT",
                )
            )

        # 3. Tasks Completed
        for t in case.tasks:
            if t.completed_at:
                events.append(
                    CaseTimelineEvent(
                        id=f"task-comp-{t.id}",
                        timestamp=t.completed_at,
                        event_type="TASK_COMPLETED",
                        title=f"Task Completed: {t.title}",
                        description=t.description or f"Operational task was completed by {t.completed_by or 'Analyst'}.",
                        actor=t.completed_by or "SOC Analyst",
                        source="TASK",
                    )
                )

        # 4. Case Resolved / Closed Milestones
        if case.resolved_at:
            events.append(
                CaseTimelineEvent(
                    id=f"evt-{case.id}-resolved",
                    timestamp=case.resolved_at,
                    event_type="CASE_RESOLVED",
                    title=f"Case Resolved ({case.resolution_code})",
                    description=case.resolution_summary or "Case was marked resolved by analyst.",
                    actor=case.resolved_by or "SOC Analyst",
                    source="CASE",
                )
            )

        if case.closed_at:
            events.append(
                CaseTimelineEvent(
                    id=f"evt-{case.id}-closed",
                    timestamp=case.closed_at,
                    event_type="CASE_CLOSED",
                    title="Case Closed",
                    description=case.closure_notes or "Operational case closed following final verification.",
                    actor=case.closed_by or "SOC Analyst",
                    source="CASE",
                )
            )

        if case.reopened_at:
            events.append(
                CaseTimelineEvent(
                    id=f"evt-{case.id}-reopened",
                    timestamp=case.reopened_at,
                    event_type="CASE_REOPENED",
                    title="Case Reopened",
                    description=case.reopen_reason or "Case was reopened for further investigation.",
                    actor=case.reopened_by or "SOC Analyst",
                    source="CASE",
                )
            )

        # Sort descending by timestamp
        events.sort(key=lambda x: x.timestamp, reverse=True)
        return events

    @classmethod
    def get_case_metrics(cls, db: Session, workspace_id: Optional[str] = None) -> CaseMetricsSummary:
        """
        Aggregates SOC overview metrics for cases within the workspace.
        """
        query = db.query(CaseModel)
        if workspace_id:
            query = query.filter(CaseModel.workspace_id == workspace_id)

        all_cases = query.all()
        total = len(all_cases)
        open_c = sum(1 for c in all_cases if c.status == "OPEN")
        in_prog = sum(1 for c in all_cases if c.status in ("IN_PROGRESS", "PENDING", "ON_HOLD"))
        resolved = sum(1 for c in all_cases if c.status == "RESOLVED")
        closed = sum(1 for c in all_cases if c.status == "CLOSED")
        critical = sum(1 for c in all_cases if c.severity == "CRITICAL" and c.status not in ("RESOLVED", "CLOSED", "CANCELLED"))
        high = sum(1 for c in all_cases if c.severity == "HIGH" and c.status not in ("RESOLVED", "CLOSED", "CANCELLED"))
        sla_breached = sum(1 for c in all_cases if c.sla_status == "BREACHED" and c.status not in ("RESOLVED", "CLOSED", "CANCELLED"))
        sla_warning = sum(1 for c in all_cases if c.sla_status == "WARNING" and c.status not in ("RESOLVED", "CLOSED", "CANCELLED"))
        unassigned = sum(1 for c in all_cases if not c.owner_id and c.status not in ("RESOLVED", "CLOSED", "CANCELLED"))

        # Overdue tasks
        now = datetime.now(timezone.utc)
        task_query = db.query(CaseTaskModel).filter(
            CaseTaskModel.status.in_(("TODO", "IN_PROGRESS")),
            CaseTaskModel.due_at.isnot(None),
            CaseTaskModel.due_at < now,
        )
        if workspace_id:
            task_query = task_query.filter(CaseTaskModel.workspace_id == workspace_id)
        overdue_tasks = task_query.count()

        return CaseMetricsSummary(
            total_cases=total,
            open_cases=open_c,
            in_progress_cases=in_prog,
            resolved_cases=resolved,
            closed_cases=closed,
            critical_cases=critical,
            high_cases=high,
            sla_breached_cases=sla_breached,
            sla_warning_cases=sla_warning,
            unassigned_cases=unassigned,
            overdue_tasks_count=overdue_tasks,
        )

    # -------------------------------------------------------------------------
    # Backward Compatibility Helpers
    # -------------------------------------------------------------------------

    @classmethod
    def add_email_to_case(
        cls,
        db: Session,
        case_id: str,
        request: CaseEmailCreateRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseEmailModel:
        """Assigns an analyzed email to a case, rejecting duplicates with 400 Bad Request."""
        case = cls.get_case(db, case_id, workspace_id=workspace_id)

        existing = (
            db.query(CaseEmailModel)
            .filter(
                CaseEmailModel.case_id == case.id,
                CaseEmailModel.email_id == request.email_id,
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Email '{request.email_id}' is already linked to this case.",
            )

        indicators_serialized = json.dumps(request.indicators or {})

        stored_analysis = (
            db.query(EmailAnalysisModel)
            .filter(
                or_(
                    EmailAnalysisModel.evidence_id == request.email_id,
                    EmailAnalysisModel.id == request.email_id,
                    EmailAnalysisModel.email_sha256 == request.email_id,
                )
            )
            .first()
        )

        if stored_analysis:
            real_subject = stored_analysis.subject
            real_sender = stored_analysis.sender
            real_threat_score = stored_analysis.threat_score
            real_severity = stored_analysis.severity
            real_sha256 = stored_analysis.email_sha256
            real_indicators = stored_analysis.indicators_json
        else:
            real_subject = request.subject or "Untitled Email"
            real_sender = request.sender or "unknown"
            real_threat_score = request.threat_score or 0
            real_severity = request.severity or "low"
            real_sha256 = request.email_sha256
            real_indicators = indicators_serialized

        case_email = CaseEmailModel(
            case_id=case.id,
            email_id=request.email_id,
            email_sha256=real_sha256,
            subject=real_subject,
            sender=real_sender,
            threat_score=real_threat_score,
            severity=real_severity,
            indicators_json=real_indicators,
            added_at=datetime.now(timezone.utc),
        )
        db.add(case_email)
        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case_id=case.id,
            action="EMAIL_ADDED_TO_CASE",
            details=f"Added email '{case_email.subject}' (Sender: {case_email.sender}, Score: {case_email.threat_score}) to case {case.case_number}.",
            metadata={
                "case_number": case.case_number,
                "email_id": case_email.email_id,
                "email_sha256": case_email.email_sha256,
                "subject": case_email.subject,
                "threat_score": case_email.threat_score,
            },
            user=user,
            workspace_id=case.workspace_id,
        )
        # Retain EMAIL_ADDED for backwards compatibility
        cls._log_audit(
            db,
            case_id=case.id,
            action="EMAIL_ADDED",
            details=f"Added email '{case_email.subject}' to case.",
            metadata={"case_number": case.case_number, "email_id": case_email.email_id},
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(case_email)
        return case_email

    @classmethod
    def remove_email_from_case(cls, db: Session, case_id: str, email_id: str, workspace_id: Optional[str] = None):
        """Detaches a linked email from a case."""
        case = cls.get_case(db, case_id, workspace_id=workspace_id)
        case_email = (
            db.query(CaseEmailModel)
            .filter(
                CaseEmailModel.case_id == case.id,
                or_(
                    CaseEmailModel.email_id == email_id,
                    CaseEmailModel.id == email_id,
                ),
            )
            .first()
        )
        if not case_email:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Email '{email_id}' is not linked to this case.")

        email_subject = case_email.subject
        db.delete(case_email)
        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case_id=case.id,
            action="EMAIL_REMOVED",
            details=f"Removed email '{email_subject}' from case.",
            metadata={"case_number": case.case_number, "email_id": email_id},
            workspace_id=case.workspace_id,
        )

        db.commit()

    @classmethod
    def add_note(
        cls,
        db: Session,
        case_id: str,
        request: CaseNoteCreateRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseNoteModel:
        """Adds an analyst note to the case."""
        case = cls.get_case(db, case_id, workspace_id=workspace_id)
        author = request.author or user or "SOC Analyst"

        note = CaseNoteModel(
            case_id=case.id,
            author=author,
            note_text=request.note_text.strip(),
            visibility=request.visibility or "ANALYST",
            edit_history_json=json.dumps([]),
            created_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc),
        )
        db.add(note)
        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case_id=case.id,
            action="NOTE_ADDED",
            details=f"Note added by {author}.",
            metadata={"case_number": case.case_number, "author": author, "note_id": note.id},
            user=author,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(note)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_NOTE_ADDED, case, user=author, details={"note_id": note.id})
        return note

    @classmethod
    def update_note(
        cls,
        db: Session,
        case_id: str,
        note_id: str,
        request: CaseNoteUpdateRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseNoteModel:
        """Edits an analyst note preserving audit history."""
        case = cls.get_case(db, case_id, workspace_id=workspace_id)
        note = db.query(CaseNoteModel).filter(CaseNoteModel.id == note_id, CaseNoteModel.case_id == case.id).first()
        if not note:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Note '{note_id}' was not found in case.")

        now = datetime.now(timezone.utc)
        history = json.loads(note.edit_history_json) if getattr(note, "edit_history_json", None) else []
        history.append({
            "previous_text": note.note_text,
            "edited_by": user,
            "edited_at": now.isoformat(),
        })

        note.edit_history_json = json.dumps(history)
        note.note_text = request.note_text.strip()
        if request.visibility:
            note.visibility = request.visibility
        note.updated_at = now
        case.version += 1
        case.updated_at = now

        cls._log_audit(
            db,
            case.id,
            "NOTE_EDITED",
            f"Note {note.id} updated by {user}.",
            metadata={"case_number": case.case_number, "note_id": note.id, "editor": user},
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(note)
        return note

    @classmethod
    def add_finding(
        cls,
        db: Session,
        case_id: str,
        request: CaseFindingCreateRequest,
        workspace_id: Optional[str] = None,
        user: str = "SOC Analyst",
    ) -> CaseFindingModel:
        """Adds a structured forensic finding to the case."""
        case = cls.get_case(db, case_id, workspace_id=workspace_id)

        norm_sev = request.severity.value if hasattr(request.severity, "value") else (request.severity or "medium")
        finding = CaseFindingModel(
            case_id=case.id,
            finding_type=request.finding_type,
            title=request.title.strip(),
            description=request.description.strip(),
            severity=norm_sev.lower(),
            created_at=datetime.now(timezone.utc),
        )
        db.add(finding)
        case.version += 1
        case.updated_at = datetime.now(timezone.utc)

        cls._log_audit(
            db,
            case.id,
            "FINDING_ADDED",
            f"Finding '{finding.title}' ({finding.finding_type}) flagged with severity '{finding.severity}'.",
            user=user,
            workspace_id=case.workspace_id,
        )

        db.commit()
        db.refresh(finding)
        cls._emit_realtime(RealtimeEventTypeEnum.CASE_FINDING_LINKED, case, user=user, details={"finding_id": finding.id, "title": finding.title})
        return finding

    @classmethod
    def _serialize_list_item(cls, c: CaseModel) -> CaseListItemResponse:
        tags = json.loads(c.tags_json) if c.tags_json else []
        tasks = c.tasks or []
        open_tasks = sum(1 for t in tasks if t.status in ("TODO", "IN_PROGRESS", "BLOCKED"))

        return CaseListItemResponse(
            id=c.id,
            case_number=c.case_number,
            workspace_id=c.workspace_id,
            title=c.title,
            description=c.description or "",
            severity=c.severity,
            priority=c.priority,
            status=c.status,
            category=c.category,
            classification=c.classification,
            owner_id=c.owner_id,
            team_id=c.team_id,
            incident_id=c.incident_id,
            primary_investigation_id=c.primary_investigation_id,
            campaign_id=c.campaign_id,
            sla_status=c.sla_status,
            next_sla_deadline=c.next_sla_deadline,
            opened_at=c.opened_at or c.created_at,
            resolved_at=c.resolved_at,
            closed_at=c.closed_at,
            created_at=c.created_at,
            updated_at=c.updated_at,
            email_count=len(c.emails),
            note_count=len(c.notes),
            finding_count=len(c.findings),
            task_count=len(tasks),
            open_task_count=open_tasks,
            version=c.version,
            tags=tags,
        )
