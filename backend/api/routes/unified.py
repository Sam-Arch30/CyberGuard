import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    ArtifactModel,
    AnalysisRunModel,
    FindingModel,
    IndicatorModel,
    RelationshipModel,
    IncidentModel,
    ThreatEventModel,
    ArtifactStorageRecordModel,
    IngestionRecordModel,
)
from backend.services.evidence_storage import (
    evidence_storage,
    StoragePathTraversalError,
    IntegrityStatus,
)
from backend.services.unified_service import (
    ArtifactService,
    AnalysisService,
    FindingService,
    IndicatorService,
    RelationshipService,
    IncidentService,
    StorageRecordService,
    IngestionService,
    StorageMaintenanceService,
    AuditService,
)
from backend.schemas.unified import ReanalyzeRequest

router = APIRouter(tags=["Unified Data Model"])



@router.get(
    "/api/unified/artifacts/{id}",
    summary="Get Artifact by ID or SHA-256",
    description="Returns the canonical Artifact entity including cryptographic hashes and storage references."
)
@router.get("/api/artifacts/{id}", include_in_schema=False)
def get_artifact_endpoint(id: str, db: Session = Depends(get_db)):
    artifact = ArtifactService.get_artifact(db, id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{id}' not found."
        )
    return {
        "id": artifact.id,
        "artifact_type": artifact.artifact_type,
        "name": artifact.name,
        "source": artifact.source,
        "mime_type": artifact.mime_type,
        "size": artifact.size,
        "sha256": artifact.sha256,
        "sha1": artifact.sha1,
        "md5": artifact.md5,
        "storage_reference": artifact.storage_reference,
        "parent_artifact_id": artifact.parent_artifact_id,
        "ingested_at": artifact.ingested_at.isoformat() if artifact.ingested_at else None,
        "metadata_json": artifact.metadata_json,
        "created_at": artifact.created_at.isoformat() if artifact.created_at else None,
    }


@router.get(
    "/api/unified/artifacts/{id}/analysis",
    summary="Get all AnalysisRuns for an Artifact",
    description="Returns chronological analysis pipeline execution runs for a given artifact."
)
@router.get("/api/artifacts/{id}/analysis", include_in_schema=False)
def get_artifact_analyses_endpoint(id: str, db: Session = Depends(get_db)):
    artifact = ArtifactService.get_artifact(db, id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{id}' not found."
        )
    runs = AnalysisService.list_runs_for_artifact(db, artifact.id)
    return [
        {
            "id": r.id,
            "artifact_id": r.artifact_id,
            "status": r.status,
            "trigger": r.trigger,
            "pipeline_version": r.pipeline_version,
            "overall_risk_score": r.overall_risk_score,
            "overall_severity": r.overall_severity,
            "confidence": r.confidence,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "error": r.error,
        }
        for r in runs
    ]


@router.get(
    "/api/unified/analysis/{id}/findings",
    summary="Get Findings and supporting Evidence for an AnalysisRun",
    description="Returns all analytical conclusions and their machine-readable evidence items."
)
@router.get("/api/analysis/{id}/findings", include_in_schema=False)
def get_analysis_findings_endpoint(id: str, db: Session = Depends(get_db)):
    run = AnalysisService.get_analysis_run(db, id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"AnalysisRun '{id}' not found."
        )
    findings = FindingService.get_findings_for_run(db, run.id)
    return [
        {
            "id": f.id,
            "analysis_run_id": f.analysis_run_id,
            "analyzer": f.analyzer,
            "finding_type": f.finding_type,
            "title": f.title,
            "description": f.description,
            "severity": f.severity,
            "confidence": f.confidence,
            "risk_contribution": f.risk_contribution,
            "method": f.method,
            "model_version_id": f.model_version_id,
            "rule_id": f.rule_id,
            "created_at": f.created_at.isoformat() if f.created_at else None,
            "evidence_items": [
                {
                    "id": ev.id,
                    "evidence_type": ev.evidence_type,
                    "source": ev.source,
                    "key": ev.key,
                    "value": ev.value,
                    "confidence": ev.confidence,
                    "artifact_id": ev.artifact_id,
                    "timestamp": ev.timestamp.isoformat() if ev.timestamp else None,
                }
                for ev in f.evidence_items
            ],
        }
        for f in findings
    ]


@router.get(
    "/api/unified/incidents/{id}",
    summary="Get Incident by ID or Incident Number",
    description="Returns incident details, related threat events, and proposed response actions."
)
@router.get("/api/incidents/{id}", include_in_schema=False)
def get_incident_endpoint(id: str, db: Session = Depends(get_db)):
    incident = IncidentService.get_incident(db, id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{id}' not found."
        )
    return {
        "id": incident.id,
        "incident_number": incident.incident_number,
        "title": incident.title,
        "description": incident.description,
        "status": incident.status,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "confidence": incident.confidence,
        "opened_at": incident.opened_at.isoformat() if incident.opened_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
        "assigned_to": incident.assigned_to,
        "legacy_case_id": incident.legacy_case_id,
        "threat_events": [
            {
                "id": te.id,
                "event_type": te.event_type,
                "summary": te.summary,
                "severity": te.severity,
                "risk_score": te.risk_score,
                "confidence": te.confidence,
                "status": te.status,
                "timestamp": te.timestamp.isoformat() if te.timestamp else None,
            }
            for te in incident.threat_events
        ],
        "response_actions": [
            {
                "id": ra.id,
                "action_type": ra.action_type,
                "description": ra.description,
                "status": ra.status,
                "priority": ra.priority,
                "recommended_by": ra.recommended_by,
                "approved_by": ra.approved_by,
                "created_at": ra.created_at.isoformat() if ra.created_at else None,
            }
            for ra in incident.response_actions
        ],
    }


@router.get(
    "/api/unified/indicators/{identifier}",
    summary="Get Indicator by normalized value or ID",
    description="Returns deduplicated canonical indicator with confidence, reputation, and timestamps."
)
def get_indicator_endpoint(
    identifier: str,
    indicator_type: Optional[str] = None,
    db: Session = Depends(get_db)
):
    clean = identifier.strip()
    query = db.query(IndicatorModel)
    if indicator_type:
        query = query.filter(IndicatorModel.indicator_type == indicator_type.upper())
    
    ind = query.filter(
        (IndicatorModel.id == clean) |
        (IndicatorModel.normalized_value == clean.lower()) |
        (IndicatorModel.value == clean)
    ).first()

    if not ind:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicator '{identifier}' not found."
        )
    return {
        "id": ind.id,
        "indicator_type": ind.indicator_type,
        "value": ind.value,
        "normalized_value": ind.normalized_value,
        "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
        "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
        "confidence": ind.confidence,
        "reputation": ind.reputation,
    }


@router.get(
    "/api/unified/relationships",
    summary="Query Knowledge Graph Relationships",
    description="Returns relationships filtered by source_id, target_id, or relationship_type."
)
def list_relationships_endpoint(
    source_id: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    relationship_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db)
):
    rels = RelationshipService.list_relationships(
        db, source_id=source_id, target_id=target_id, relationship_type=relationship_type, limit=limit
    )
    return [
        {
            "id": r.id,
            "source_type": r.source_type,
            "source_id": r.source_id,
            "relationship_type": r.relationship_type,
            "target_type": r.target_type,
            "target_id": r.target_id,
            "confidence": r.confidence,
            "first_seen": r.first_seen.isoformat() if r.first_seen else None,
            "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            "method": r.method,
        }
        for r in rels
    ]


# ============================================================================
# SECTION 3: PERSISTENT STORAGE, RETRIEVAL, INTEGRITY & RE-ANALYSIS ENDPOINTS
# ============================================================================

@router.get(
    "/api/unified/artifacts/{id}/download",
    summary="Download original immutable evidence file",
    description="Securely streams the raw forensic evidence without exposing backend filesystem paths."
)
@router.get("/api/artifacts/{id}/download", include_in_schema=False)
def download_artifact_endpoint(id: str, db: Session = Depends(get_db)):
    artifact = ArtifactService.get_artifact(db, id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{id}' not found."
        )

    storage_key = artifact.storage_reference
    if not storage_key and artifact.sha256:
        storage_key = f"artifacts/{artifact.sha256[:2]}/{artifact.sha256}/original"

    if not storage_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No storage reference associated with artifact '{id}'."
        )

    try:
        stream = evidence_storage.retrieve_stream(storage_key)
    except StoragePathTraversalError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid storage key detected."
        )
    except FileNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Forensic evidence file is missing from storage for artifact '{id}'."
        )

    safe_name = os.path.basename(artifact.name or "evidence.bin").replace('"', '')
    media_type = artifact.mime_type or "application/octet-stream"

    # Log chain of custody event
    AuditService.log_event(
        db=db,
        actor="API_USER",
        action="ARTIFACT_RETRIEVED",
        resource_type="ARTIFACT",
        resource_id=artifact.id,
        details={"name": safe_name, "storage_key": storage_key},
    )

    return StreamingResponse(
        stream,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{safe_name}"'}
    )


@router.get(
    "/api/unified/artifacts/{id}/integrity",
    summary="Verify cryptographic integrity of stored evidence",
    description="Computes SHA-256 over stored bytes and validates against canonical identity."
)
@router.get("/api/artifacts/{id}/integrity", include_in_schema=False)
def verify_artifact_integrity_endpoint(id: str, db: Session = Depends(get_db)):
    artifact = ArtifactService.get_artifact(db, id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{id}' not found."
        )

    storage_key = artifact.storage_reference or (f"artifacts/{artifact.sha256[:2]}/{artifact.sha256}/original" if artifact.sha256 else None)
    if not storage_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No storage key found for artifact '{id}'."
        )

    expected = artifact.sha256 or ""
    integ_status, actual_sha = evidence_storage.verify_integrity(storage_key, expected)

    StorageRecordService.update_integrity_status(
        db, artifact.id, integ_status.value, actual_sha
    )

    AuditService.log_event(
        db=db,
        actor="API_USER",
        action="ARTIFACT_INTEGRITY_VERIFIED",
        resource_type="ARTIFACT",
        resource_id=artifact.id,
        details={"status": integ_status.value, "expected": expected, "actual": actual_sha},
    )

    return {
        "artifact_id": artifact.id,
        "storage_key": storage_key,
        "expected_sha256": expected,
        "actual_sha256": actual_sha,
        "status": integ_status.value,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "details": "Integrity verified successfully" if integ_status.value == "VERIFIED" else f"Integrity status is {integ_status.value}",
    }


@router.post(
    "/api/unified/artifacts/{id}/reanalyze",
    summary="Re-analyze an existing Artifact",
    description="Retrieves persisted evidence, verifies integrity, and executes a new AnalysisRun without overwriting historical runs."
)
@router.post("/api/artifacts/{id}/reanalyze", include_in_schema=False)
def reanalyze_artifact_endpoint(
    id: str,
    req: Optional[ReanalyzeRequest] = None,
    db: Session = Depends(get_db)
):
    trigger = req.trigger if req else "REANALYSIS"
    pipeline_ver = req.pipeline_version if req else "1.1.0"
    force = req.force if req else False

    try:
        new_run = AnalysisService.reanalyze_artifact(
            db=db,
            artifact_id=id,
            pipeline_version=pipeline_ver,
            trigger=trigger,
            force=force,
        )
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Re-analysis failed: {str(e)}")

    return {
        "id": new_run.id,
        "artifact_id": new_run.artifact_id,
        "status": new_run.status,
        "trigger": new_run.trigger,
        "pipeline_version": new_run.pipeline_version,
        "overall_risk_score": new_run.overall_risk_score,
        "overall_severity": new_run.overall_severity,
        "confidence": new_run.confidence,
        "started_at": new_run.started_at.isoformat() if new_run.started_at else None,
        "completed_at": new_run.completed_at.isoformat() if new_run.completed_at else None,
        "findings_count": len(new_run.findings),
    }


@router.get(
    "/api/unified/artifacts/{id}/runs",
    summary="Get all historical AnalysisRuns for an Artifact",
    description="Returns chronological analysis pipeline execution runs."
)
def list_artifact_runs_endpoint(id: str, db: Session = Depends(get_db)):
    artifact = ArtifactService.get_artifact(db, id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{id}' not found."
        )
    runs = AnalysisService.list_runs_for_artifact(db, artifact.id)
    return [
        {
            "id": r.id,
            "artifact_id": r.artifact_id,
            "status": r.status,
            "trigger": r.trigger,
            "pipeline_version": r.pipeline_version,
            "overall_risk_score": r.overall_risk_score,
            "overall_severity": r.overall_severity,
            "confidence": r.confidence,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
            "findings_count": len(r.findings),
            "error": r.error,
        }
        for r in runs
    ]


@router.get(
    "/api/unified/artifacts/{id}/ingestions",
    summary="Get ingestion provenance records for an Artifact",
    description="Returns all submission/ingestion events associated with this artifact."
)
def list_artifact_ingestions_endpoint(id: str, db: Session = Depends(get_db)):
    artifact = ArtifactService.get_artifact(db, id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{id}' not found."
        )
    ingestions = IngestionService.list_ingestions(db, artifact.id)
    return [
        {
            "id": ing.id,
            "artifact_id": ing.artifact_id,
            "source": ing.source,
            "submitted_by": ing.submitted_by,
            "received_at": ing.received_at.isoformat() if ing.received_at else None,
            "original_filename": ing.original_filename,
            "request_id": ing.request_id,
            "status": ing.status,
            "context_json": ing.context_json,
        }
        for ing in ingestions
    ]


@router.get(
    "/api/unified/artifacts/{id}/storage",
    summary="Get storage physical records for an Artifact",
    description="Returns physical storage backend details, storage keys, and integrity status."
)
def list_artifact_storage_records_endpoint(id: str, db: Session = Depends(get_db)):
    artifact = ArtifactService.get_artifact(db, id)
    if not artifact:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Artifact '{id}' not found."
        )
    records = StorageRecordService.get_storage_records(db, artifact.id)
    return [
        {
            "id": rec.id,
            "artifact_id": rec.artifact_id,
            "storage_backend": rec.storage_backend,
            "storage_key": rec.storage_key,
            "sha256": rec.sha256,
            "size": rec.size,
            "mime_type": rec.mime_type,
            "original_filename": rec.original_filename,
            "stored_at": rec.stored_at.isoformat() if rec.stored_at else None,
            "verified_at": rec.verified_at.isoformat() if rec.verified_at else None,
            "integrity_status": rec.integrity_status,
            "retention_policy": rec.retention_policy,
        }
        for rec in records
    ]


@router.get(
    "/api/unified/maintenance/orphans",
    summary="Scan for storage orphans and missing evidence",
    description="Identifies database artifacts with missing files, untracked storage files, and stale temp staging."
)
def scan_orphans_endpoint(db: Session = Depends(get_db)):
    report = StorageMaintenanceService.scan_orphans(db)
    return report


@router.post(
    "/api/unified/maintenance/backfill",
    summary="Backfill legacy evidence into content-addressed storage",
    description="Migrates legacy eml_store evidence into content-addressed storage and registers unified models."
)
def backfill_legacy_endpoint(dry_run: bool = Query(True), db: Session = Depends(get_db)):
    result = StorageMaintenanceService.backfill_legacy_evidence(db, dry_run=dry_run)
    return result

