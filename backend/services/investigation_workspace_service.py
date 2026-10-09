"""
Service layer for Section 39: Investigation Workspace.
Aggregates the authoritative investigation shell, summary metrics, evidence browser,
truthful timeline events, and auditable status transitions.
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from backend.db.models import (
    AnalysisRunModel,
    AnalysisTaskModel,
    ArtifactModel,
    AuditLogModel,
    CaseModel,
    CaseEmailModel,
    CaseNoteModel,
    EvidenceModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    RelationshipModel,
    ResponseActionModel,
    ResponseRecommendationModel,
    ThreatEventModel,
    get_utc_now,
)
from backend.schemas.analysis_results import (
    FindingResultDetail,
    RiskHeaderSummary,
)
from backend.schemas.investigation_workspace import (
    AnalystNoteModel,
    InvestigationCountsModel,
    InvestigationEvidenceItem,
    InvestigationSummaryModel,
    InvestigationTimelineEventItem,
    InvestigationWorkspaceSummary,
)
from backend.services.analysis_orchestrator import AnalysisOrchestrator
from backend.services.analysis_results_aggregator import AnalysisResultsAggregator

logger = logging.getLogger("cyberguard.services.investigation_workspace_service")

VALID_STATUSES = {"OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"}

VALID_TRANSITIONS: Dict[str, set[str]] = {
    "OPEN": {"INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE"},
    "INVESTIGATING": {"CONTAINED", "RESOLVED", "CLOSED", "FALSE_POSITIVE", "OPEN"},
    "CONTAINED": {"RESOLVED", "CLOSED", "INVESTIGATING", "OPEN"},
    "RESOLVED": {"CLOSED", "INVESTIGATING", "OPEN"},
    "CLOSED": {"OPEN", "INVESTIGATING"},
    "FALSE_POSITIVE": {"OPEN", "INVESTIGATING"},
}


class InvestigationWorkspaceService:
    """
    Central orchestration service for Section 39 Investigation Workstation.
    """

    @classmethod
    def resolve_context(
        cls, db: Session, identifier: str
    ) -> Tuple[Optional[IncidentModel], Optional[AnalysisRunModel], Optional[ArtifactModel], Optional[CaseModel]]:
        """
        Robustly resolves an investigation's incident, analysis run, artifact, and legacy case.
        """
        clean_id = (identifier or "").strip()
        if not clean_id:
            return None, None, None, None

        # 1. Check if identifier is an Incident (by id or incident_number)
        incident = (
            db.query(IncidentModel)
            .filter((IncidentModel.id == clean_id) | (IncidentModel.incident_number == clean_id))
            .first()
        )

        # 2. Check if identifier is a Case (by id or case_number)
        case = (
            db.query(CaseModel)
            .filter((CaseModel.id == clean_id) | (CaseModel.case_number == clean_id))
            .first()
        )

        # 3. Resolve run using AnalysisOrchestrator
        run = AnalysisOrchestrator.resolve_run_for_investigation(db, clean_id)

        # 4. If we have a run, resolve artifact
        artifact = None
        if run:
            artifact = db.query(ArtifactModel).filter(ArtifactModel.id == run.artifact_id).first()

        # 5. If we have an incident but no run yet, find linked artifact via relationship
        if incident and not run:
            rel = (
                db.query(RelationshipModel)
                .filter(
                    RelationshipModel.source_type == "INCIDENT",
                    RelationshipModel.source_id == incident.id,
                    RelationshipModel.target_type == "ARTIFACT",
                )
                .first()
            )
            if rel:
                artifact = db.query(ArtifactModel).filter(ArtifactModel.id == rel.target_id).first()
                if artifact:
                    run = (
                        db.query(AnalysisRunModel)
                        .filter(AnalysisRunModel.artifact_id == artifact.id)
                        .order_by(AnalysisRunModel.started_at.desc())
                        .first()
                    )

        # 6. If we have a case, link to incident if not already linked
        if case and not incident:
            incident = db.query(IncidentModel).filter(IncidentModel.legacy_case_id == case.id).first()

        # 7. If we have run and artifact but no incident, find or create tracked IncidentModel
        if not incident and (run or artifact):
            # Check if incident exists via artifact relationship
            art_id = artifact.id if artifact else (run.artifact_id if run else None)
            if art_id:
                rel = (
                    db.query(RelationshipModel)
                    .filter(
                        RelationshipModel.target_type == "ARTIFACT",
                        RelationshipModel.target_id == art_id,
                        RelationshipModel.source_type == "INCIDENT",
                    )
                    .first()
                )
                if rel:
                    incident = db.query(IncidentModel).filter(IncidentModel.id == rel.source_id).first()

            # If still no incident, auto-instantiate a formal incident container
            if not incident and artifact:
                inc_num = f"INV-{datetime.utcnow().year}-{uuid.uuid4().hex[:6].upper()}"
                title = f"Investigation: {artifact.name}"
                incident = IncidentModel(
                    id=str(uuid.uuid4()),
                    incident_number=inc_num,
                    title=title,
                    description=f"Automated incident container for artifact {artifact.name}",
                    status="INVESTIGATING",
                    severity=run.overall_severity if (run and run.overall_severity) else "MEDIUM",
                    risk_score=run.overall_risk_score if (run and run.overall_risk_score is not None) else 0.0,
                    confidence=run.confidence if (run and run.confidence is not None) else 1.0,
                    legacy_case_id=case.id if case else None,
                )
                db.add(incident)
                db.flush()

                # Link relationship
                db.add(
                    RelationshipModel(
                        id=str(uuid.uuid4()),
                        source_type="INCIDENT",
                        source_id=incident.id,
                        relationship_type="INVESTIGATES_ARTIFACT",
                        target_type="ARTIFACT",
                        target_id=artifact.id,
                        confidence=1.0,
                        method="SYSTEM_AUTO_CREATION",
                    )
                )
                db.commit()

        # 8. Ensure case is resolved from incident.legacy_case_id or artifact
        if incident and incident.legacy_case_id and not case:
            case = db.query(CaseModel).filter(CaseModel.id == incident.legacy_case_id).first()
        if not case and artifact:
            ce = (
                db.query(CaseEmailModel)
                .filter(
                    (CaseEmailModel.email_id == artifact.id)
                    | (CaseEmailModel.email_sha256 == artifact.sha256)
                )
                .first()
            )
            if ce:
                case = db.query(CaseModel).filter(CaseModel.id == ce.case_id).first()

        return incident, run, artifact, case

    @classmethod
    def get_workspace_summary(cls, db: Session, identifier: str) -> Optional[InvestigationWorkspaceSummary]:
        """
        Compiles the complete 9-part workspace summary for the persistent investigation header & overview.
        """
        incident, run, artifact, case = cls.resolve_context(db, identifier)
        if not incident and not run and not artifact:
            return None

        # Resolve detailed analysis results
        results = None
        if run:
            results = AnalysisResultsAggregator.get_results_for_run(db, run.id)

        # 1. Investigation Identity
        inv_id = incident.id if incident else (run.id if run else identifier)
        inc_number = incident.incident_number if incident else (f"INV-{inv_id[:8].upper()}")
        title = (
            incident.title
            if (incident and incident.title)
            else (results.classification if (results and results.classification) else f"Investigation: {artifact.name if artifact else 'Security Incident'}")
        )
        status = incident.status if incident else (run.status.upper() if run else "OPEN")
        severity = incident.severity if incident else (run.overall_severity if (run and run.overall_severity) else "MEDIUM")

        inv_summary = InvestigationSummaryModel(
            investigation_id=inv_id,
            incident_number=inc_number,
            title=title,
            description=incident.description if incident else (results.executive_summary if results else None),
            status=status,
            severity=severity,
            risk_score=incident.risk_score if (incident and incident.risk_score is not None) else (run.overall_risk_score if run else None),
            confidence=incident.confidence if incident else (run.confidence if run else 1.0),
            opened_at=incident.opened_at if incident else (run.started_at if run else None),
            updated_at=incident.updated_at if incident else (run.completed_at if run else None),
            assigned_to=incident.assigned_to if incident else None,
            artifact_name=artifact.name if artifact else "artifact.bin",
            artifact_type=artifact.artifact_type if artifact else "UNKNOWN",
            artifact_id=artifact.id if artifact else (run.artifact_id if run else None),
            sha256=artifact.sha256 if artifact else None,
        )

        # 2. Risk Metrics
        if results and results.risk:
            risk = results.risk
        else:
            risk = RiskHeaderSummary(
                score=inv_summary.risk_score,
                level=inv_summary.severity,
                severity=inv_summary.severity,
                confidence=inv_summary.confidence,
                confidence_level="MODERATE",
                is_pending=False,
                status_label="Assessed",
            )

        # 3. Top Findings
        top_findings = results.top_findings if results else []

        # 4. Counts
        findings_count = len(top_findings)
        evidence_count = results.indicators_summary.total_count if results else 0
        indicators_count = results.indicators_summary.total_count if results else 0
        attack_paths_count = 1 if (results and results.attack_path_preview) else (len(incident.attack_paths) if incident else 0)
        legacy_actions_count = len(incident.response_actions) if incident else 0
        rec_count = db.query(ResponseRecommendationModel).filter(
            (ResponseRecommendationModel.scope_id == identifier) |
            (ResponseRecommendationModel.scope_id == inv_id) |
            (ResponseRecommendationModel.incident_id == (incident.id if incident else None))
        ).count()
        response_actions_count = max(legacy_actions_count, rec_count)

        # Query notes from case or audit logs
        notes: List[AnalystNoteModel] = []
        if case:
            for cn in case.notes:
                notes.append(
                    AnalystNoteModel(
                        id=cn.id,
                        author=cn.author or "SOC Analyst",
                        note_text=cn.note_text,
                        created_at=cn.created_at,
                    )
                )

        # 5. Attention Indicators
        attention_items: List[str] = []
        if risk.score and risk.score >= 70 and status in ("OPEN", "INVESTIGATING"):
            attention_items.append("High risk incident requiring active containment")
        if run and run.status == "PARTIAL":
            attention_items.append("Analysis execution partially complete; some analyzers timed out")
        if results and results.counter_evidence and len(results.counter_evidence) > 0:
            attention_items.append("Counter-evidence detected: review factors mitigating malicious intent")
        if results and results.contradictions and len(results.contradictions) > 0:
            attention_items.append("Conflicting evidence identified across detection engines")
        if response_actions_count > 0:
            attention_items.append(f"{response_actions_count} response playbooks proposed for review")

        timeline_events_count = 1 + len(notes) + findings_count

        counts = InvestigationCountsModel(
            findings_count=findings_count,
            evidence_count=max(evidence_count, 1),
            indicators_count=indicators_count,
            attack_paths_count=attack_paths_count,
            timeline_events_count=timeline_events_count,
            response_actions_count=response_actions_count,
            notes_count=len(notes),
        )

        return InvestigationWorkspaceSummary(
            investigation=inv_summary,
            risk=risk,
            classification=results.classification if results else "Security Investigation",
            executive_summary=results.executive_summary if results else "Investigation initialized and awaiting evidence analysis.",
            status=status,
            counts=counts,
            top_findings=top_findings[:5],
            attention_items=attention_items,
            analyst_notes=notes,
            last_updated=get_utc_now(),
        )

    @classmethod
    def update_status(
        cls,
        db: Session,
        identifier: str,
        new_status: str,
        reason: Optional[str] = None,
        analyst: str = "SOC Analyst",
    ) -> Optional[InvestigationWorkspaceSummary]:
        """
        Enforces state transition rules, updates incident/case, and logs audit record.
        """
        clean_status = (new_status or "").strip().upper()
        if clean_status not in VALID_STATUSES:
            raise ValueError(f"Invalid investigation status '{new_status}'. Allowed: {sorted(VALID_STATUSES)}")

        incident, run, artifact, case = cls.resolve_context(db, identifier)
        if not incident:
            return None

        current = incident.status.upper()
        if current != clean_status:
            allowed = VALID_TRANSITIONS.get(current, set())
            if clean_status not in allowed:
                raise ValueError(
                    f"Illegal status transition from '{current}' to '{clean_status}'. Allowed transitions: {sorted(allowed)}"
                )

            # Apply transition
            incident.status = clean_status
            incident.updated_at = get_utc_now()
            if clean_status in ("RESOLVED", "CLOSED"):
                incident.closed_at = get_utc_now()
            else:
                incident.closed_at = None

            # Also update legacy case if connected
            if case:
                case.status = clean_status.lower()
                case.updated_at = get_utc_now()

            # Record auditable log
            audit_id = str(uuid.uuid4())
            audit = AuditLogModel(
                id=audit_id,
                case_id=case.id if case else None,
                action="STATUS_CHANGE",
                user=analyst,
                details=str({
                    "previous_status": current,
                    "new_status": clean_status,
                    "reason": reason or "Analyst workflow transition",
                    "incident_id": incident.id,
                }),
                timestamp=get_utc_now(),
            )
            db.add(audit)
            db.commit()

        return cls.get_workspace_summary(db, identifier)

    @classmethod
    def add_note(
        cls,
        db: Session,
        identifier: str,
        note_text: str,
        author: str = "SOC Analyst",
    ) -> Optional[AnalystNoteModel]:
        """
        Appends an attributed, auditable analyst note to the investigation.
        """
        incident, run, artifact, case = cls.resolve_context(db, identifier)
        if not incident and not case:
            return None

        # Ensure a case exists to attach note
        if not case:
            case_num = f"CASE-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"
            case = CaseModel(
                id=str(uuid.uuid4()),
                case_number=case_num,
                title=incident.title if incident else "Investigation Case",
                status="open",
            )
            db.add(case)
            db.flush()
            if incident:
                incident.legacy_case_id = case.id
            if artifact:
                db.add(
                    CaseEmailModel(
                        id=str(uuid.uuid4()),
                        case_id=case.id,
                        email_id=artifact.id,
                        email_sha256=artifact.sha256,
                        subject=artifact.name,
                    )
                )

        note_id = str(uuid.uuid4())
        note = CaseNoteModel(
            id=note_id,
            case_id=case.id,
            author=author,
            note_text=note_text.strip(),
            created_at=get_utc_now(),
        )
        db.add(note)

        # Audit log
        db.add(
            AuditLogModel(
                id=str(uuid.uuid4()),
                case_id=case.id,
                action="NOTE_ADDED",
                user=author,
                details=str({"note_id": note_id, "preview": note_text[:100]}),
                timestamp=get_utc_now(),
            )
        )
        db.commit()

        return AnalystNoteModel(
            id=note.id,
            author=note.author,
            note_text=note.note_text,
            created_at=note.created_at,
        )

    @classmethod
    def get_evidence_list(cls, db: Session, identifier: str) -> List[InvestigationEvidenceItem]:
        """
        Returns all forensic evidence items, distinguishing immutable original files from derived signals.
        """
        incident, run, artifact, case = cls.resolve_context(db, identifier)
        items: List[InvestigationEvidenceItem] = []

        # 1. Original Artifact (Immutable)
        if artifact:
            items.append(
                InvestigationEvidenceItem(
                    id=artifact.id,
                    name=artifact.name,
                    evidence_type=artifact.artifact_type,
                    is_original=True,
                    sha256=artifact.sha256,
                    size_bytes=artifact.size,
                    source=artifact.source or "INGESTION_GATEWAY",
                    observed_at=artifact.created_at or get_utc_now(),
                    confidence=1.0,
                    details={
                        "mime_type": artifact.mime_type,
                        "storage_reference": artifact.storage_reference,
                        "parent_artifact_id": artifact.parent_artifact_id,
                    },
                )
            )

        # 2. Derived Evidence items from Findings
        if run:
            fe_records = (
                db.query(FindingEvidenceModel)
                .join(FindingModel, FindingEvidenceModel.finding_id == FindingModel.id)
                .filter(FindingModel.analysis_run_id == run.id)
                .all()
            )
            for fe in fe_records:
                items.append(
                    InvestigationEvidenceItem(
                        id=fe.id,
                        name=f"{fe.evidence_type}: {fe.key}",
                        evidence_type=fe.evidence_type,
                        is_original=False,
                        source=fe.source,
                        observed_at=fe.timestamp or get_utc_now(),
                        confidence=fe.confidence,
                        details={
                            "key": fe.key,
                            "value": AnalysisResultsAggregator.redact_sensitive_value(fe.value),
                            "finding_id": fe.finding_id,
                        },
                    )
                )

        return items

    @classmethod
    def get_timeline_events(cls, db: Session, identifier: str) -> List[InvestigationTimelineEventItem]:
        """
        Returns unified chronological events with timestamps and source provenance.
        """
        incident, run, artifact, case = cls.resolve_context(db, identifier)
        events: List[InvestigationTimelineEventItem] = []

        # Ingestion event
        if artifact:
            events.append(
                InvestigationTimelineEventItem(
                    id=f"evt-ingest-{artifact.id}",
                    timestamp=artifact.created_at or get_utc_now(),
                    event_type="ARTIFACT_INGESTION",
                    title="Forensic Evidence Ingested",
                    description=f"Artifact '{artifact.name}' ({artifact.artifact_type}) received and cryptographic SHA-256 fingerprint generated.",
                    severity="INFO",
                    source=artifact.source or "Gateway",
                    confidence=1.0,
                )
            )

        # Analysis run started
        if run and run.started_at:
            events.append(
                InvestigationTimelineEventItem(
                    id=f"evt-run-start-{run.id}",
                    timestamp=run.started_at,
                    event_type="ANALYSIS_STARTED",
                    title="Automated Analysis Orchestrated",
                    description=f"Pipeline version {run.pipeline_version} initiated analyzer DAG execution.",
                    severity="INFO",
                    source="AnalysisOrchestrator",
                    confidence=1.0,
                )
            )

        # Findings as analytical events
        if run:
            findings = db.query(FindingModel).filter(FindingModel.analysis_run_id == run.id).all()
            for f in findings:
                events.append(
                    InvestigationTimelineEventItem(
                        id=f"evt-finding-{f.id}",
                        timestamp=f.created_at or (run.started_at or get_utc_now()),
                        event_type="FINDING_DISCOVERED",
                        title=f.title,
                        description=f.description,
                        severity=f.severity.upper() if f.severity else "MEDIUM",
                        source=f.analyzer,
                        confidence=f.confidence or 1.0,
                    )
                )

        # Analysis run completed
        if run and run.completed_at:
            events.append(
                InvestigationTimelineEventItem(
                    id=f"evt-run-end-{run.id}",
                    timestamp=run.completed_at,
                    event_type="ANALYSIS_COMPLETED",
                    title="Pipeline Execution Concluded",
                    description=f"Risk evaluation finished with unified score {run.overall_risk_score:.0f}/100 ({run.overall_severity}).",
                    severity=run.overall_severity if run.overall_severity else "INFO",
                    source="UnifiedRiskEngine",
                    confidence=run.confidence or 1.0,
                )
            )

        # Threat events if incident exists
        if incident and incident.threat_events:
            for te in incident.threat_events:
                events.append(
                    InvestigationTimelineEventItem(
                        id=f"evt-threat-{te.id}",
                        timestamp=te.timestamp or get_utc_now(),
                        event_type="THREAT_EVENT",
                        title=te.summary or "Correlated Threat Event",
                        description=f"Threat event ({te.event_type}) correlated to active attack path.",
                        severity=te.severity.upper() if te.severity else "MEDIUM",
                        source="ThreatCorrelationEngine",
                        confidence=te.confidence or 1.0,
                    )
                )

        # Analyst notes as events
        if case and case.notes:
            for n in case.notes:
                events.append(
                    InvestigationTimelineEventItem(
                        id=f"evt-note-{n.id}",
                        timestamp=n.created_at,
                        event_type="ANALYST_NOTE",
                        title=f"Note by {n.author}",
                        description=n.note_text,
                        severity="INFO",
                        source="AnalystEntry",
                        confidence=1.0,
                    )
                )

        # Audit logs as events
        if case and case.audit_logs:
            for a in case.audit_logs:
                events.append(
                    InvestigationTimelineEventItem(
                        id=f"evt-audit-{a.id}",
                        timestamp=a.timestamp,
                        event_type="AUDIT_ACTION",
                        title=f"Workflow Action: {a.action}",
                        description=f"Action performed by {a.user or 'SOC Analyst'}.",
                        severity="INFO",
                        source="AuditLogger",
                        confidence=1.0,
                    )
                )

        # Sort chronologically ascending
        events.sort(key=lambda e: e.timestamp)
        return events
