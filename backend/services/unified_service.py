"""
Unified CyberGuard Service and Ingestion Adapter Layer.
Provides clean service interfaces for Artifacts, AnalysisRuns, Findings, Evidence,
Indicators, Entities, Relationships, Incidents, ThreatEvents, ResponseActions,
and ModelVersions. Future analyzers interact with this layer rather than direct ORM.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union

from sqlalchemy import or_, text
from sqlalchemy.orm import Session

from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    AttackEdgeModel,
    AttackPathModel,
    AttackStageModel,
    AuditEventModel,
    AuditLogModel,
    EntityModel,
    EvidenceItemModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    IndicatorModel,
    ModelVersionModel,
    RelationshipModel,
    ResponseActionModel,
    ThreatEventModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.unified import (
    AnalysisStatusEnum,
    AnalysisTriggerEnum,
    ArtifactTypeEnum,
    EntityTypeEnum,
    FindingMethodEnum,
    IncidentStatusEnum,
    IndicatorTypeEnum,
    ModelStatusEnum,
    RelationshipTypeEnum,
    ResponseStatusEnum,
    SeverityEnum,
    normalize_confidence,
    normalize_domain,
    normalize_email_address,
    normalize_hash,
    normalize_indicator,
    normalize_ip,
    normalize_risk_score,
    normalize_severity,
    normalize_url,
)

logger = logging.getLogger("cyberguard.unified")


# ============================================================================
# 1. ARTIFACT SERVICE
# ============================================================================

class ArtifactService:
    @staticmethod
    def create_or_get_artifact(
        db: Session,
        artifact_type: Union[ArtifactTypeEnum, str],
        name: str,
        source: str = "UPLOAD",
        mime_type: Optional[str] = None,
        size: Optional[int] = None,
        sha256: Optional[str] = None,
        sha1: Optional[str] = None,
        md5: Optional[str] = None,
        storage_reference: Optional[str] = None,
        parent_artifact_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ArtifactModel:
        """
        Creates or retrieves an existing Artifact.
        If a SHA-256 is provided and matches an existing record of the same type, returns the existing record.
        """
        clean_sha256 = sha256.strip().lower() if sha256 else None
        clean_type = artifact_type.value if isinstance(artifact_type, ArtifactTypeEnum) else str(artifact_type).upper()

        if clean_sha256:
            existing = (
                db.query(ArtifactModel)
                .filter(
                    ArtifactModel.artifact_type == clean_type,
                    ArtifactModel.sha256 == clean_sha256,
                )
                .first()
            )
            if existing:
                return existing

        now = get_utc_now()
        artifact = ArtifactModel(
            id=generate_uuid(),
            artifact_type=clean_type,
            name=name.strip()[:255],
            source=source.strip()[:100],
            mime_type=mime_type.strip()[:100] if mime_type else None,
            size=size if size is not None and size >= 0 else None,
            sha256=clean_sha256,
            sha1=sha1.strip().lower() if sha1 else None,
            md5=md5.strip().lower() if md5 else None,
            storage_reference=storage_reference,
            parent_artifact_id=parent_artifact_id,
            ingested_at=now,
            metadata_json=json.dumps(metadata or {}),
            created_at=now,
            updated_at=now,
        )
        db.add(artifact)
        db.commit()
        db.refresh(artifact)
        return artifact

    @staticmethod
    def get_artifact(db: Session, identifier: str) -> Optional[ArtifactModel]:
        """Looks up an artifact by UUID, SHA-256, or storage reference."""
        clean = identifier.strip()
        return (
            db.query(ArtifactModel)
            .filter(
                or_(
                    ArtifactModel.id == clean,
                    ArtifactModel.sha256 == clean.lower(),
                    ArtifactModel.storage_reference == clean,
                )
            )
            .first()
        )

    @staticmethod
    def list_artifacts(
        db: Session,
        artifact_type: Optional[str] = None,
        parent_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[ArtifactModel]:
        query = db.query(ArtifactModel)
        if artifact_type:
            query = query.filter(ArtifactModel.artifact_type == artifact_type.upper())
        if parent_id is not None:
            query = query.filter(ArtifactModel.parent_artifact_id == parent_id)
        return query.order_by(ArtifactModel.ingested_at.desc()).limit(limit).all()


# ============================================================================
# 2. ANALYSIS SERVICE
# ============================================================================

class AnalysisService:
    @staticmethod
    def create_analysis_run(
        db: Session,
        artifact_id: str,
        status: Union[AnalysisStatusEnum, str] = AnalysisStatusEnum.QUEUED,
        trigger: Union[AnalysisTriggerEnum, str] = AnalysisTriggerEnum.USER,
        pipeline_version: str = "1.0.0",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AnalysisRunModel:
        status_str = status.value if isinstance(status, AnalysisStatusEnum) else str(status).upper()
        trigger_str = trigger.value if isinstance(trigger, AnalysisTriggerEnum) else str(trigger).upper()

        run = AnalysisRunModel(
            id=generate_uuid(),
            artifact_id=artifact_id,
            status=status_str,
            started_at=get_utc_now(),
            trigger=trigger_str,
            pipeline_version=pipeline_version,
            metadata_json=json.dumps(metadata or {}),
            created_at=get_utc_now(),
        )
        db.add(run)
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def complete_analysis_run(
        db: Session,
        run_id: str,
        overall_risk_score: Optional[float] = None,
        overall_severity: Optional[Union[SeverityEnum, str]] = None,
        confidence: Optional[float] = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AnalysisRunModel:
        run = db.get(AnalysisRunModel, run_id)
        if not run:
            raise ValueError(f"AnalysisRun '{run_id}' not found.")

        run.status = AnalysisStatusEnum.COMPLETED.value
        run.completed_at = get_utc_now()
        run.overall_risk_score = normalize_risk_score(overall_risk_score)
        if overall_severity is not None:
            run.overall_severity = normalize_severity(overall_severity).value
        run.confidence = normalize_confidence(confidence)

        if metadata:
            curr = json.loads(run.metadata_json or "{}")
            curr.update(metadata)
            run.metadata_json = json.dumps(curr)

        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def fail_analysis_run(db: Session, run_id: str, error_message: str) -> AnalysisRunModel:
        run = db.get(AnalysisRunModel, run_id)
        if not run:
            raise ValueError(f"AnalysisRun '{run_id}' not found.")

        run.status = AnalysisStatusEnum.FAILED.value
        run.completed_at = get_utc_now()
        run.error = str(error_message)
        db.commit()
        db.refresh(run)
        return run

    @staticmethod
    def get_analysis_run(db: Session, run_id: str) -> Optional[AnalysisRunModel]:
        return db.get(AnalysisRunModel, run_id)

    @staticmethod
    def list_runs_for_artifact(db: Session, artifact_id: str) -> List[AnalysisRunModel]:
        return (
            db.query(AnalysisRunModel)
            .filter(AnalysisRunModel.artifact_id == artifact_id)
            .order_by(AnalysisRunModel.started_at.desc())
            .all()
        )


# ============================================================================
# 3. FINDING & EVIDENCE SERVICE
# ============================================================================

class FindingService:
    @staticmethod
    def create_finding(
        db: Session,
        analysis_run_id: str,
        analyzer: str,
        finding_type: str,
        title: str,
        description: str,
        severity: Union[SeverityEnum, str] = SeverityEnum.LOW,
        confidence: float = 1.0,
        risk_contribution: float = 0.0,
        method: Union[FindingMethodEnum, str] = FindingMethodEnum.RULE,
        model_version_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FindingModel:
        sev_val = normalize_severity(severity).value
        conf_val = normalize_confidence(confidence)
        risk_val = normalize_risk_score(risk_contribution) or 0.0
        method_str = method.value if isinstance(method, FindingMethodEnum) else str(method).upper()

        finding = FindingModel(
            id=generate_uuid(),
            analysis_run_id=analysis_run_id,
            analyzer=analyzer.strip()[:100],
            finding_type=finding_type.strip()[:100],
            title=title.strip()[:255],
            description=description,
            severity=sev_val,
            confidence=conf_val,
            risk_contribution=risk_val,
            method=method_str,
            model_version_id=model_version_id,
            rule_id=rule_id.strip()[:100] if rule_id else None,
            metadata_json=json.dumps(metadata or {}),
            created_at=get_utc_now(),
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        return finding

    @staticmethod
    def attach_evidence(
        db: Session,
        finding_id: str,
        evidence_type: str,
        source: str,
        key: str,
        value: Any,
        confidence: float = 1.0,
        artifact_id: Optional[str] = None,
        timestamp: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FindingEvidenceModel:
        str_val = value if isinstance(value, str) else json.dumps(value)
        evidence = FindingEvidenceModel(
            id=generate_uuid(),
            finding_id=finding_id,
            evidence_type=evidence_type.strip().upper()[:50],
            source=source.strip()[:100],
            key=key.strip()[:100],
            value=str_val,
            confidence=normalize_confidence(confidence),
            artifact_id=artifact_id,
            timestamp=timestamp or get_utc_now(),
            metadata_json=json.dumps(metadata or {}),
            created_at=get_utc_now(),
        )
        db.add(evidence)
        db.commit()
        db.refresh(evidence)
        return evidence

    @staticmethod
    def get_findings_for_run(db: Session, run_id: str) -> List[FindingModel]:
        return (
            db.query(FindingModel)
            .filter(FindingModel.analysis_run_id == run_id)
            .order_by(FindingModel.risk_contribution.desc(), FindingModel.created_at.asc())
            .all()
        )


# ============================================================================
# 4. INDICATOR SERVICE (NORMALIZATION & DEDUPLICATION)
# ============================================================================

class IndicatorService:
    @staticmethod
    def upsert_indicator(
        db: Session,
        indicator_type: Union[IndicatorTypeEnum, str],
        value: str,
        confidence: float = 1.0,
        reputation: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IndicatorModel:
        """
        Inserts a new indicator or updates last_seen/reputation of an existing indicator.
        Guarantees deduplication on (indicator_type, normalized_value).
        """
        raw_val, norm_val = normalize_indicator(indicator_type, value)
        type_str = indicator_type.value if isinstance(indicator_type, IndicatorTypeEnum) else str(indicator_type).upper()
        now = get_utc_now()
        conf_val = normalize_confidence(confidence)

        existing = (
            db.query(IndicatorModel)
            .filter(
                IndicatorModel.indicator_type == type_str,
                IndicatorModel.normalized_value == norm_val,
            )
            .first()
        )

        if existing:
            existing.last_seen = now
            if conf_val > existing.confidence:
                existing.confidence = conf_val
            if reputation:
                existing.reputation = reputation.strip().upper()
            if metadata:
                curr = json.loads(existing.metadata_json or "{}")
                curr.update(metadata)
                existing.metadata_json = json.dumps(curr)
            existing.updated_at = now
            db.commit()
            db.refresh(existing)
            return existing

        indicator = IndicatorModel(
            id=generate_uuid(),
            indicator_type=type_str,
            value=raw_val,
            normalized_value=norm_val,
            first_seen=now,
            last_seen=now,
            confidence=conf_val,
            reputation=reputation.strip().upper() if reputation else None,
            metadata_json=json.dumps(metadata or {}),
            created_at=now,
            updated_at=now,
        )
        db.add(indicator)
        db.commit()
        db.refresh(indicator)
        return indicator

    @staticmethod
    def get_indicator(
        db: Session, indicator_type: Union[IndicatorTypeEnum, str], value: str
    ) -> Optional[IndicatorModel]:
        _, norm_val = normalize_indicator(indicator_type, value)
        type_str = indicator_type.value if isinstance(indicator_type, IndicatorTypeEnum) else str(indicator_type).upper()
        return (
            db.query(IndicatorModel)
            .filter(
                IndicatorModel.indicator_type == type_str,
                IndicatorModel.normalized_value == norm_val,
            )
            .first()
        )


# ============================================================================
# 5. ENTITY SERVICE
# ============================================================================

class EntityService:
    @staticmethod
    def upsert_entity(
        db: Session,
        entity_type: Union[EntityTypeEnum, str],
        name: str,
        external_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> EntityModel:
        type_str = entity_type.value if isinstance(entity_type, EntityTypeEnum) else str(entity_type).upper()
        clean_name = name.strip()
        now = get_utc_now()

        existing = (
            db.query(EntityModel)
            .filter(
                EntityModel.entity_type == type_str,
                EntityModel.name == clean_name,
            )
            .first()
        )

        if existing:
            existing.last_seen = now
            if external_id and not existing.external_id:
                existing.external_id = external_id.strip()
            if attributes:
                curr = json.loads(existing.attributes_json or "{}")
                curr.update(attributes)
                existing.attributes_json = json.dumps(curr)
            existing.updated_at = now
            db.commit()
            db.refresh(existing)
            return existing

        entity = EntityModel(
            id=generate_uuid(),
            entity_type=type_str,
            name=clean_name,
            external_id=external_id.strip() if external_id else None,
            attributes_json=json.dumps(attributes or {}),
            first_seen=now,
            last_seen=now,
            created_at=now,
            updated_at=now,
        )
        db.add(entity)
        db.commit()
        db.refresh(entity)
        return entity


# ============================================================================
# 6. RELATIONSHIP SERVICE (SECURITY KNOWLEDGE GRAPH)
# ============================================================================

class RelationshipService:
    @staticmethod
    def create_relationship(
        db: Session,
        source_type: str,
        source_id: str,
        relationship_type: Union[RelationshipTypeEnum, str],
        target_type: str,
        target_id: str,
        confidence: float = 1.0,
        evidence_reference: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        method: str = "RULE",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RelationshipModel:
        rel_type_str = (
            relationship_type.value
            if isinstance(relationship_type, RelationshipTypeEnum)
            else str(relationship_type).upper()
        )
        now = get_utc_now()

        # Check existing edge
        existing = (
            db.query(RelationshipModel)
            .filter(
                RelationshipModel.relationship_type == rel_type_str,
                RelationshipModel.source_id == str(source_id),
                RelationshipModel.target_id == str(target_id),
            )
            .first()
        )
        if existing:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, normalize_confidence(confidence))
            existing.updated_at = now
            db.commit()
            db.refresh(existing)
            return existing

        rel = RelationshipModel(
            id=generate_uuid(),
            source_type=source_type.strip().upper(),
            source_id=str(source_id),
            relationship_type=rel_type_str,
            target_type=target_type.strip().upper(),
            target_id=str(target_id),
            confidence=normalize_confidence(confidence),
            first_seen=now,
            last_seen=now,
            evidence_reference=evidence_reference,
            analysis_run_id=analysis_run_id,
            method=method.strip().upper(),
            metadata_json=json.dumps(metadata or {}),
            created_at=now,
            updated_at=now,
        )
        db.add(rel)
        db.commit()
        db.refresh(rel)
        return rel

    @staticmethod
    def list_relationships(
        db: Session,
        source_id: Optional[str] = None,
        target_id: Optional[str] = None,
        relationship_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[RelationshipModel]:
        query = db.query(RelationshipModel)
        if source_id:
            query = query.filter(RelationshipModel.source_id == source_id)
        if target_id:
            query = query.filter(RelationshipModel.target_id == target_id)
        if relationship_type:
            query = query.filter(RelationshipModel.relationship_type == relationship_type.upper())
        return query.order_by(RelationshipModel.last_seen.desc()).limit(limit).all()


# ============================================================================
# 7. THREAT EVENT SERVICE
# ============================================================================

class ThreatEventService:
    @staticmethod
    def create_threat_event(
        db: Session,
        event_type: str,
        summary: str,
        severity: Union[SeverityEnum, str] = SeverityEnum.MEDIUM,
        risk_score: float = 0.0,
        confidence: float = 1.0,
        source_artifact_id: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        status: str = "OPEN",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ThreatEventModel:
        now = get_utc_now()
        event = ThreatEventModel(
            id=generate_uuid(),
            event_type=event_type.strip().lower(),
            timestamp=now,
            source_artifact_id=source_artifact_id,
            analysis_run_id=analysis_run_id,
            severity=normalize_severity(severity).value,
            risk_score=normalize_risk_score(risk_score) or 0.0,
            confidence=normalize_confidence(confidence),
            status=status.strip().upper(),
            summary=summary.strip(),
            incident_id=incident_id,
            metadata_json=json.dumps(metadata or {}),
            created_at=now,
            updated_at=now,
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        return event


# ============================================================================
# 8. INCIDENT SERVICE & RESPONSE ACTIONS
# ============================================================================

class IncidentService:
    @staticmethod
    def create_incident(
        db: Session,
        title: str,
        description: Optional[str] = None,
        severity: Union[SeverityEnum, str] = SeverityEnum.MEDIUM,
        risk_score: float = 0.0,
        confidence: float = 1.0,
        status: Union[IncidentStatusEnum, str] = IncidentStatusEnum.OPEN,
        assigned_to: Optional[str] = None,
        legacy_case_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> IncidentModel:
        now = get_utc_now()
        year = now.strftime("%Y")

        count = db.query(IncidentModel).count() + 1
        incident_number = f"INC-{year}-{count:06d}"

        # Guarantee unique incident_number if collisions occur
        while db.query(IncidentModel).filter(IncidentModel.incident_number == incident_number).first():
            count += 1
            incident_number = f"INC-{year}-{count:06d}"

        status_str = status.value if isinstance(status, IncidentStatusEnum) else str(status).upper()

        incident = IncidentModel(
            id=generate_uuid(),
            incident_number=incident_number,
            title=title.strip()[:255],
            description=description,
            status=status_str,
            severity=normalize_severity(severity).value,
            risk_score=normalize_risk_score(risk_score) or 0.0,
            confidence=normalize_confidence(confidence),
            opened_at=now,
            assigned_to=assigned_to.strip() if assigned_to else None,
            legacy_case_id=legacy_case_id,
            metadata_json=json.dumps(metadata or {}),
            created_at=now,
            updated_at=now,
        )
        db.add(incident)
        db.commit()
        db.refresh(incident)
        return incident

    @staticmethod
    def attach_threat_event(db: Session, incident_id: str, threat_event_id: str) -> ThreatEventModel:
        event = db.get(ThreatEventModel, threat_event_id)
        if not event:
            raise ValueError(f"ThreatEvent '{threat_event_id}' not found.")
        event.incident_id = incident_id
        event.updated_at = get_utc_now()
        db.commit()
        db.refresh(event)
        return event

    @staticmethod
    def create_response_action(
        db: Session,
        incident_id: str,
        action_type: str,
        description: str,
        priority: str = "MEDIUM",
        recommended_by: str = "CyberGuard Core",
        threat_event_id: Optional[str] = None,
        status: Union[ResponseStatusEnum, str] = ResponseStatusEnum.RECOMMENDED,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ResponseActionModel:
        status_str = status.value if isinstance(status, ResponseStatusEnum) else str(status).upper()
        action = ResponseActionModel(
            id=generate_uuid(),
            incident_id=incident_id,
            threat_event_id=threat_event_id,
            action_type=action_type.strip().upper()[:50],
            description=description.strip(),
            status=status_str,
            priority=priority.strip().upper()[:20],
            recommended_by=recommended_by.strip()[:100],
            created_at=get_utc_now(),
            metadata_json=json.dumps(metadata or {}),
        )
        db.add(action)
        db.commit()
        db.refresh(action)
        return action

    @staticmethod
    def get_incident(db: Session, identifier: str) -> Optional[IncidentModel]:
        clean = identifier.strip()
        return (
            db.query(IncidentModel)
            .filter(
                or_(
                    IncidentModel.id == clean,
                    IncidentModel.incident_number == clean.upper(),
                    IncidentModel.legacy_case_id == clean,
                )
            )
            .first()
        )


# ============================================================================
# 9. MODEL VERSION SERVICE
# ============================================================================

class ModelVersionService:
    @staticmethod
    def register_model_version(
        db: Session,
        model_name: str,
        model_type: str,
        version: str,
        provider: str,
        training_dataset_reference: Optional[str] = None,
        metrics: Optional[Dict[str, Any]] = None,
        status: Union[ModelStatusEnum, str] = ModelStatusEnum.ACTIVE,
        deployed_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ModelVersionModel:
        name_clean = model_name.strip()
        version_clean = version.strip()
        status_str = status.value if isinstance(status, ModelStatusEnum) else str(status).upper()

        existing = (
            db.query(ModelVersionModel)
            .filter(
                ModelVersionModel.model_name == name_clean,
                ModelVersionModel.version == version_clean,
            )
            .first()
        )
        if existing:
            return existing

        now = get_utc_now()
        mv = ModelVersionModel(
            id=generate_uuid(),
            model_name=name_clean,
            model_type=model_type.strip(),
            version=version_clean,
            provider=provider.strip(),
            training_dataset_reference=training_dataset_reference,
            metrics_json=json.dumps(metrics or {}),
            status=status_str,
            deployed_at=deployed_at or now,
            metadata_json=json.dumps(metadata or {}),
            created_at=now,
        )
        db.add(mv)
        db.commit()
        db.refresh(mv)
        return mv

    @staticmethod
    def get_model_version(db: Session, model_name: str, version: str) -> Optional[ModelVersionModel]:
        return (
            db.query(ModelVersionModel)
            .filter(
                ModelVersionModel.model_name == model_name.strip(),
                ModelVersionModel.version == version.strip(),
            )
            .first()
        )


# ============================================================================
# 10. UNIFIED INGESTION ADAPTER (LEGACY EML COMPATIBILITY)
# ============================================================================

class UnifiedIngestionAdapter:
    """
    Non-destructive bridge connecting existing EML analysis executions into the
    Unified CyberGuard Data Model:
    Email EML -> Artifact(EMAIL)
              -> AnalysisRun
              -> Findings (Rules, Heuristics, ML, Attribution)
              -> Evidence (Supporting observations)
              -> Indicators (Deduplicated IOCs)
              -> Relationships (Graph links)
              -> ThreatEvent / Incident
    """

    @classmethod
    def ingest_email_analysis(
        cls,
        db: Session,
        evidence_record: Any,
        analysis_result: Any,
        raw_sha256: str,
        content_bytes: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """
        Translates a completed EmailAnalysisResponse into canonical entities.
        Dual-writes safely alongside legacy tables without breaking any caller.
        """
        try:
            # 1. Register canonical Artifact for the Email
            filename = getattr(analysis_result, "original_filename", "email.eml") or "email.eml"
            file_size = getattr(evidence_record, "size", len(content_bytes) if content_bytes else 0)
            storage_ref = f"eml_store/{evidence_record.evidence_id}_{raw_sha256[:16]}.eml"

            email_artifact = ArtifactService.create_or_get_artifact(
                db=db,
                artifact_type=ArtifactTypeEnum.EMAIL,
                name=filename,
                source="UPLOAD",
                mime_type="message/rfc822",
                size=file_size,
                sha256=raw_sha256,
                storage_reference=storage_ref,
                metadata={
                    "evidence_id": evidence_record.evidence_id,
                    "uploader": getattr(evidence_record, "uploader", "SOC Analyst"),
                    "subject": getattr(analysis_result, "subject", "Untitled"),
                },
            )

            # 2. Register child Artifacts for attachments
            attachment_artifacts: List[Tuple[Any, ArtifactModel]] = []
            attachments = getattr(analysis_result, "attachments", []) or []
            for att in attachments:
                att_name = getattr(att, "filename", "unnamed_attachment")
                att_sha256 = getattr(att, "sha256", None)
                att_size = getattr(att, "size", None)
                att_mime = getattr(att, "mime_type", None) or getattr(att, "content_type", None)

                child_art = ArtifactService.create_or_get_artifact(
                    db=db,
                    artifact_type=ArtifactTypeEnum.ATTACHMENT,
                    name=att_name,
                    source="EML_EXTRACTION",
                    mime_type=att_mime,
                    size=att_size,
                    sha256=att_sha256,
                    parent_artifact_id=email_artifact.id,
                    metadata={"email_artifact_id": email_artifact.id},
                )
                attachment_artifacts.append((att, child_art))

            # 3. Create AnalysisRun
            ts_obj = getattr(analysis_result, "threat_score", None)
            score_val = ts_obj.score if ts_obj else 0.0
            sev_val = ts_obj.severity if ts_obj else "low"

            analysis_run = AnalysisService.create_analysis_run(
                db=db,
                artifact_id=email_artifact.id,
                status=AnalysisStatusEnum.RUNNING,
                trigger=AnalysisTriggerEnum.USER,
                pipeline_version="1.0.0",
                metadata={"evidence_id": evidence_record.evidence_id},
            )

            # Register standard ModelVersion records for model provenance
            nlp_mv = ModelVersionService.register_model_version(
                db=db,
                model_name="cyberguard-nlp-phishing-classifier",
                model_type="NLP_CLASSIFIER",
                version="1.0.0",
                provider="scikit-learn / TF-IDF Logistic Regression",
            )
            attr_mv = ModelVersionService.register_model_version(
                db=db,
                model_name="cyberguard-attribution-engine",
                model_type="ATTRIBUTION_ENGINE",
                version="1.0.0",
                provider="CyberGuard Probabilistic Infrastructure Heuristic",
            )

            # 4. Map Analyzers' Outputs to Findings & Evidence

            # 4a. Authentication & Alignment Finding
            auth = getattr(analysis_result, "authentication", None)
            if auth:
                spf_res = getattr(auth, "spf", None)
                dkim_res = getattr(auth, "dkim", None)
                dmarc_res = getattr(auth, "dmarc", None)
                align = getattr(auth, "alignment", None)

                spf_val = spf_res.result if spf_res else "neutral"
                dkim_val = dkim_res.result if dkim_res else "neutral"
                dmarc_val = dmarc_res.result if dmarc_res else "neutral"

                has_auth_fail = any(
                    r.lower() == "fail" for r in [spf_val, dkim_val, dmarc_val]
                )
                f_sev = SeverityEnum.HIGH if has_auth_fail else SeverityEnum.SAFE

                f_auth = FindingService.create_finding(
                    db=db,
                    analysis_run_id=analysis_run.id,
                    analyzer="AuthenticationAnalyzer",
                    finding_type="email_authentication",
                    title=f"Email Authentication Evaluation ({spf_val.upper()} SPF, {dkim_val.upper()} DKIM, {dmarc_val.upper()} DMARC)",
                    description=(
                        f"Forensic authentication checks: SPF={spf_val}, DKIM={dkim_val}, DMARC={dmarc_val}. "
                        f"Sender alignment: From={getattr(align, 'from_domain', 'N/A')}, "
                        f"Reply-To={getattr(align, 'reply_to_domain', 'N/A')}, "
                        f"Return-Path={getattr(align, 'return_path_domain', 'N/A')}."
                    ),
                    severity=f_sev,
                    confidence=1.0,
                    risk_contribution=25.0 if has_auth_fail else 0.0,
                    method=FindingMethodEnum.RULE,
                    rule_id="RULE-AUTH-RFC7489",
                )
                FindingService.attach_evidence(
                    db, f_auth.id, "SPF_RESULT", "SPF_VERIFIER", "result", spf_val, artifact_id=email_artifact.id
                )
                FindingService.attach_evidence(
                    db, f_auth.id, "DKIM_RESULT", "DKIM_VERIFIER", "result", dkim_val, artifact_id=email_artifact.id
                )
                FindingService.attach_evidence(
                    db, f_auth.id, "DMARC_RESULT", "DMARC_VERIFIER", "result", dmarc_val, artifact_id=email_artifact.id
                )

            # 4b. Lookalike Domains Findings
            lookalikes = getattr(analysis_result, "lookalike_domains", []) or []
            for lk in lookalikes:
                dom = getattr(lk, "domain", "")
                target = getattr(lk, "target_brand", "") or getattr(lk, "closest_brand", "")
                sim = getattr(lk, "similarity", 0.0) or getattr(lk, "confidence_score", 0.8)

                f_lk = FindingService.create_finding(
                    db=db,
                    analysis_run_id=analysis_run.id,
                    analyzer="LookalikeDetector",
                    finding_type="lookalike_impersonation",
                    title=f"Lookalike Domain Detected: {dom} targeting {target}",
                    description=f"Domain '{dom}' closely mimics genuine brand/domain '{target}' (similarity: {sim:.2f}).",
                    severity=SeverityEnum.HIGH,
                    confidence=normalize_confidence(sim),
                    risk_contribution=35.0,
                    method=FindingMethodEnum.HEURISTIC,
                    rule_id="HEUR-LOOKALIKE-LEVENSHTEIN",
                )
                FindingService.attach_evidence(
                    db, f_lk.id, "OBSERVED_DOMAIN", "LOOKALIKE_MATCHER", "domain", dom, artifact_id=email_artifact.id
                )
                FindingService.attach_evidence(
                    db, f_lk.id, "TARGET_BRAND", "LOOKALIKE_MATCHER", "brand", target, artifact_id=email_artifact.id
                )
                FindingService.attach_evidence(
                    db, f_lk.id, "SIMILARITY_RATIO", "LOOKALIKE_MATCHER", "similarity", sim, artifact_id=email_artifact.id
                )

            # 4c. NLP Phishing Classification Finding
            ml_pred = getattr(analysis_result, "ml_assessment", None)
            prob = getattr(analysis_result, "ml_phishing_probability", None)
            if ml_pred and prob is not None:
                prob_float = float(prob)
                is_phish = prob_float >= 0.5
                nlp_sev = (
                    SeverityEnum.CRITICAL
                    if prob_float >= 0.85
                    else SeverityEnum.HIGH
                    if prob_float >= 0.6
                    else SeverityEnum.SAFE
                )

                f_ml = FindingService.create_finding(
                    db=db,
                    analysis_run_id=analysis_run.id,
                    analyzer="NLPClassifier",
                    finding_type="nlp_intent_classification",
                    title=f"NLP Language Phishing Analysis ({prob_float*100:.1f}%)",
                    description=(
                        f"Machine learning model classified subject and body text with {prob_float*100:.1f}% phishing probability. "
                        f"Signals: urgency={getattr(ml_pred, 'urgency_cues', False)}, "
                        f"financial={getattr(ml_pred, 'financial_diversion', False)}, "
                        f"credential_harvesting={getattr(ml_pred, 'credential_harvesting', False)}."
                    ),
                    severity=nlp_sev,
                    confidence=normalize_confidence(prob_float),
                    risk_contribution=round(prob_float * 30.0, 2),
                    method=FindingMethodEnum.ML,
                    model_version_id=nlp_mv.id,
                )
                FindingService.attach_evidence(
                    db, f_ml.id, "ML_PROBABILITY", "NLP_MODEL", "phishing_probability", prob_float, artifact_id=email_artifact.id
                )

            # 4d. Suspicious URLs Findings
            urls = getattr(analysis_result, "urls", []) or []
            for u in urls:
                u_str = getattr(u, "url", str(u)) if not isinstance(u, str) else u
                u_score = getattr(u, "risk_score", 0.0) if not isinstance(u, str) else 0.0
                if u_score > 40.0:
                    f_url = FindingService.create_finding(
                        db=db,
                        analysis_run_id=analysis_run.id,
                        analyzer="URLAnalyzer",
                        finding_type="suspicious_url",
                        title=f"Suspicious URL Detected: {u_str[:60]}...",
                        description=f"Static analysis flagged URL '{u_str}' with elevated suspicion score ({u_score}).",
                        severity=SeverityEnum.HIGH if u_score >= 70 else SeverityEnum.MEDIUM,
                        confidence=normalize_confidence(u_score / 100.0),
                        risk_contribution=round(u_score * 0.25, 2),
                        method=FindingMethodEnum.HEURISTIC,
                        rule_id="HEUR-URL-STATIC",
                    )
                    FindingService.attach_evidence(
                        db, f_url.id, "OBSERVED_URL", "URL_ANALYZER", "url", u_str, artifact_id=email_artifact.id
                    )

            # 4e. Infrastructure Attribution Finding
            attr = getattr(analysis_result, "attribution", None)
            if attr:
                attr_ip = getattr(attr, "probable_origin_ip", None)
                attr_asn = getattr(attr, "probable_origin_asn", None)
                attr_country = getattr(attr, "probable_infrastructure_country", None)
                attr_conf = getattr(attr, "confidence_score", 50.0) / 100.0

                f_attr = FindingService.create_finding(
                    db=db,
                    analysis_run_id=analysis_run.id,
                    analyzer="AttributionEngine",
                    finding_type="infrastructure_attribution",
                    title=f"Infrastructure Attribution: {attr_ip or 'Unknown IP'} ({attr_country or 'Unknown'})",
                    description=(
                        f"Adversary origin infrastructure attributed to IP {attr_ip}, ASN {attr_asn}, "
                        f"Country {attr_country} with {attr_conf*100:.1f}% confidence."
                    ),
                    severity=SeverityEnum.MEDIUM,
                    confidence=normalize_confidence(attr_conf),
                    risk_contribution=15.0,
                    method=FindingMethodEnum.EXTERNAL_INTELLIGENCE,
                    model_version_id=attr_mv.id,
                )
                if attr_ip:
                    FindingService.attach_evidence(
                        db, f_attr.id, "ORIGIN_IP", "GEO_INTEL", "ip", attr_ip, artifact_id=email_artifact.id
                    )
                if attr_asn:
                    FindingService.attach_evidence(
                        db, f_attr.id, "ORIGIN_ASN", "BGP_INTEL", "asn", str(attr_asn), artifact_id=email_artifact.id
                    )

            # 5. Extract & Upsert Reusable Indicators (Deduplicated)
            # 5a. IPs
            ip_list = getattr(analysis_result, "ips", []) or []
            for ip in set(ip_list):
                if ip and len(ip.strip()) > 3:
                    IndicatorService.upsert_indicator(
                        db=db,
                        indicator_type=IndicatorTypeEnum.IP,
                        value=ip,
                        confidence=1.0,
                        metadata={"source_artifact": email_artifact.id},
                    )

            # 5b. Domains
            domain_list = getattr(analysis_result, "domains", []) or []
            for d in set(domain_list):
                if d and len(d.strip()) > 2:
                    IndicatorService.upsert_indicator(
                        db=db,
                        indicator_type=IndicatorTypeEnum.DOMAIN,
                        value=d,
                        confidence=1.0,
                        metadata={"source_artifact": email_artifact.id},
                    )

            # 5c. URLs
            for u in urls:
                u_str = getattr(u, "url", str(u)) if not isinstance(u, str) else u
                if u_str and "://" in u_str:
                    IndicatorService.upsert_indicator(
                        db=db,
                        indicator_type=IndicatorTypeEnum.URL,
                        value=u_str,
                        confidence=1.0,
                        metadata={"source_artifact": email_artifact.id},
                    )

            # 5d. Sender / Recipient Emails
            for em_field in ["sender", "from_header", "return_path", "reply_to"]:
                em_val = getattr(analysis_result, em_field, None)
                if em_val and "@" in str(em_val):
                    IndicatorService.upsert_indicator(
                        db=db,
                        indicator_type=IndicatorTypeEnum.EMAIL_ADDRESS,
                        value=str(em_val),
                        confidence=1.0,
                        metadata={"field": em_field, "source_artifact": email_artifact.id},
                    )

            # 5e. Attachment Hashes
            for _, child_art in attachment_artifacts:
                if child_art.sha256:
                    IndicatorService.upsert_indicator(
                        db=db,
                        indicator_type=IndicatorTypeEnum.FILE_HASH,
                        value=child_art.sha256,
                        confidence=1.0,
                        metadata={"filename": child_art.name, "parent_artifact": email_artifact.id},
                    )

            # 6. Establish Canonical Knowledge Graph Relationships
            # 6a. EMAIL CONTAINS ATTACHMENT
            for _, child_art in attachment_artifacts:
                RelationshipService.create_relationship(
                    db=db,
                    source_type="ARTIFACT",
                    source_id=email_artifact.id,
                    relationship_type=RelationshipTypeEnum.CONTAINS,
                    target_type="ARTIFACT",
                    target_id=child_art.id,
                    confidence=1.0,
                    analysis_run_id=analysis_run.id,
                    method="RULE",
                )

            # 6b. EMAIL REFERENCES URL
            for u in urls:
                u_str = getattr(u, "url", str(u)) if not isinstance(u, str) else u
                if u_str:
                    _, norm_url = normalize_indicator(IndicatorTypeEnum.URL, u_str)
                    RelationshipService.create_relationship(
                        db=db,
                        source_type="ARTIFACT",
                        source_id=email_artifact.id,
                        relationship_type=RelationshipTypeEnum.REFERENCES,
                        target_type="INDICATOR",
                        target_id=norm_url,
                        confidence=1.0,
                        analysis_run_id=analysis_run.id,
                        method="RULE",
                    )
                    # URL RESOLVES_TO DOMAIN
                    u_dom = getattr(u, "domain", None) if not isinstance(u, str) else None
                    if not u_dom and "://" in u_str:
                        u_dom = normalize_domain(u_str)
                    if u_dom:
                        RelationshipService.create_relationship(
                            db=db,
                            source_type="INDICATOR",
                            source_id=norm_url,
                            relationship_type=RelationshipTypeEnum.RESOLVES_TO,
                            target_type="INDICATOR",
                            target_id=normalize_domain(u_dom),
                            confidence=1.0,
                            analysis_run_id=analysis_run.id,
                            method="RULE",
                        )

            # 6c. EMAIL COMMUNICATES_WITH IP
            for ip in set(ip_list):
                if ip:
                    RelationshipService.create_relationship(
                        db=db,
                        source_type="ARTIFACT",
                        source_id=email_artifact.id,
                        relationship_type=RelationshipTypeEnum.COMMUNICATES_WITH,
                        target_type="INDICATOR",
                        target_id=normalize_ip(ip),
                        confidence=1.0,
                        analysis_run_id=analysis_run.id,
                        method="RULE",
                    )

            # 7. Complete AnalysisRun
            AnalysisService.complete_analysis_run(
                db=db,
                run_id=analysis_run.id,
                overall_risk_score=score_val,
                overall_severity=sev_val,
                confidence=1.0,
            )

            # 8. Normalized ThreatEvent Creation
            threat_event = None
            if score_val >= 25.0 or sev_val.lower() in ["medium", "high", "critical"]:
                summary_text = (
                    f"Suspicious email detected: '{getattr(analysis_result, 'subject', 'Untitled')}'. "
                    f"Threat score: {score_val:.1f} ({sev_val.upper()})."
                )
                threat_event = ThreatEventService.create_threat_event(
                    db=db,
                    event_type="phishing_attempt",
                    summary=summary_text,
                    severity=sev_val,
                    risk_score=score_val,
                    confidence=1.0,
                    source_artifact_id=email_artifact.id,
                    analysis_run_id=analysis_run.id,
                    metadata={"evidence_id": evidence_record.evidence_id},
                )

            return {
                "artifact_id": email_artifact.id,
                "analysis_run_id": analysis_run.id,
                "threat_event_id": threat_event.id if threat_event else None,
                "attachments_count": len(attachment_artifacts),
                "status": "success",
            }

        except Exception as exc:
            db.rollback()
            logger.error(f"Failed to dual-write canonical unified data model: {exc}", exc_info=True)
            return {"status": "error", "message": str(exc)}
