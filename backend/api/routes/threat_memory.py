"""
CyberGuard Threat Memory REST API Endpoints (Section 23).

Exposes routes for querying historical security intelligence, inspecting
provenance-aware observations, recording analyst decisions (verifications/false-positives),
retrieving related incidents/campaigns, building structured memory contexts,
and fetching operational statistics.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import (
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    ThreatMemoryDecisionModel,
)
from backend.schemas.threat_memory import (
    AnalystDecisionType,
    MemoryScope,
    MemoryStatus,
    MemoryType,
    ObservationClassification,
    ProvenanceType,
    ThreatMemoryContext,
    ThreatMemoryDecision,
    ThreatMemoryDecisionCreate,
    ThreatMemoryEntry,
    ThreatMemoryObservation,
    ThreatMemoryObservationCreate,
    ThreatMemoryStatsResponse,
)
from backend.services.threat_memory_service import ThreatMemoryService

router = APIRouter(tags=["Threat Memory"])


# ============================================================================
# 1. RETRIEVAL & CONTEXT ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/memory/lookup",
    response_model=Optional[ThreatMemoryEntry],
    summary="Exact lookup for an indicator or canonical key in Threat Memory",
)
def lookup_memory(
    canonical_key: Optional[str] = Query(None, description="Exact canonical key (e.g. DOMAIN:example.com)"),
    value: Optional[str] = Query(None, description="Raw observable value"),
    subject_type: Optional[MemoryType] = Query(None, description="Subject memory type"),
    workspace_id: str = Query("default", description="Workspace / tenant ID"),
    db: Session = Depends(get_db),
):
    """
    Performs deterministic lookup in Threat Memory with multi-tenant scope isolation.
    """
    if canonical_key:
        entry = ThreatMemoryService.lookup_by_key(db, workspace_id, canonical_key)
    elif value:
        entry = ThreatMemoryService.lookup_indicator(db, workspace_id, value, subject_type)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either canonical_key or value must be provided for lookup.",
        )

    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No Threat Memory entry found for the requested subject.",
        )

    # Convert attributes_json if necessary
    attrs = {}
    try:
        if entry.attributes_json:
            attrs = json.loads(entry.attributes_json)
    except Exception:
        pass

    return ThreatMemoryEntry(
        id=entry.id,
        workspace_id=entry.workspace_id,
        memory_type=entry.memory_type,
        subject_type=entry.subject_type,
        subject_id=entry.subject_id,
        canonical_key=entry.canonical_key,
        scope=entry.scope,
        status=entry.status,
        first_seen_at=entry.first_seen_at,
        last_seen_at=entry.last_seen_at,
        expires_at=entry.expires_at,
        observation_count=entry.observation_count,
        independent_source_count=entry.independent_source_count,
        incident_count=entry.incident_count,
        campaign_count=entry.campaign_count,
        confidence=entry.confidence,
        confidence_level=entry.confidence_level,
        provenance_type=entry.provenance_type,
        provenance_reference=entry.provenance_reference,
        summary=entry.summary,
        attributes=attrs,
        version=entry.version,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


@router.get(
    "/api/v1/memory/context",
    response_model=ThreatMemoryContext,
    summary="Build standardized ThreatMemoryContext with provenance, graph, and conflict evaluation",
)
def get_memory_context(
    canonical_key: Optional[str] = Query(None, description="Canonical key"),
    value: Optional[str] = Query(None, description="Raw observable value"),
    subject_type: Optional[MemoryType] = Query(None, description="Subject memory type"),
    workspace_id: str = Query("default", description="Workspace / tenant ID"),
    include_graph: bool = Query(True, description="Whether to include graph-linked infrastructure"),
    max_observations: int = Query(20, ge=1, le=100, description="Max observations to include"),
    db: Session = Depends(get_db),
):
    """
    Builds the complete ThreatMemoryContext.
    Maintains epistemic humility: CURRENT EVIDENCE > HISTORICAL MEMORY.
    """
    target = canonical_key or value
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either canonical_key or value must be specified.",
        )

    return ThreatMemoryService.build_threat_memory_context(
        db,
        workspace_id,
        value_or_key=target,
        subject_type=subject_type,
        include_graph=include_graph,
        max_observations=max_observations,
    )


@router.get(
    "/api/v1/memory/stats",
    response_model=ThreatMemoryStatsResponse,
    summary="Retrieve Threat Memory operational statistics",
)
def get_memory_stats(
    workspace_id: str = Query("default", description="Workspace ID"),
    db: Session = Depends(get_db),
):
    """
    Returns workspace operational counts for entries, observations, and decisions.
    """
    return ThreatMemoryService.get_memory_stats(db, workspace_id)


# ============================================================================
# 2. ENTRY DETAIL & LINEAGE ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/memory/{entry_id}",
    response_model=ThreatMemoryEntry,
    summary="Get Threat Memory entry by ID",
)
def get_memory_entry(
    entry_id: str,
    workspace_id: str = Query("default", description="Workspace ID"),
    db: Session = Depends(get_db),
):
    """
    Retrieves a Threat Memory entry by ID with workspace isolation.
    """
    entry = db.query(ThreatMemoryEntryModel).filter(
        ThreatMemoryEntryModel.id == entry_id,
        ThreatMemoryEntryModel.workspace_id == workspace_id,
    ).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat Memory entry not found.")

    attrs = {}
    try:
        if entry.attributes_json:
            attrs = json.loads(entry.attributes_json)
    except Exception:
        pass

    return ThreatMemoryEntry(
        id=entry.id,
        workspace_id=entry.workspace_id,
        memory_type=entry.memory_type,
        subject_type=entry.subject_type,
        subject_id=entry.subject_id,
        canonical_key=entry.canonical_key,
        scope=entry.scope,
        status=entry.status,
        first_seen_at=entry.first_seen_at,
        last_seen_at=entry.last_seen_at,
        expires_at=entry.expires_at,
        observation_count=entry.observation_count,
        independent_source_count=entry.independent_source_count,
        incident_count=entry.incident_count,
        campaign_count=entry.campaign_count,
        confidence=entry.confidence,
        confidence_level=entry.confidence_level,
        provenance_type=entry.provenance_type,
        provenance_reference=entry.provenance_reference,
        summary=entry.summary,
        attributes=attrs,
        version=entry.version,
        created_at=entry.created_at,
        updated_at=entry.updated_at,
    )


@router.get(
    "/api/v1/memory/{entry_id}/observations",
    response_model=List[ThreatMemoryObservation],
    summary="List observations for a Threat Memory entry",
)
def get_memory_observations(
    entry_id: str,
    workspace_id: str = Query("default", description="Workspace ID"),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """
    Returns individual observations demonstrating why CyberGuard remembers this subject.
    """
    obs_list = db.query(ThreatMemoryObservationModel).filter(
        ThreatMemoryObservationModel.memory_entry_id == entry_id,
        ThreatMemoryObservationModel.workspace_id == workspace_id,
    ).order_by(ThreatMemoryObservationModel.observed_at.desc()).limit(limit).all()

    results = []
    for o in obs_list:
        raw_ctx = {}
        try:
            if o.raw_context_json:
                raw_ctx = json.loads(o.raw_context_json)
        except Exception:
            pass
        results.append(
            ThreatMemoryObservation(
                id=o.id,
                memory_entry_id=o.memory_entry_id,
                workspace_id=o.workspace_id,
                source_type=o.source_type,
                source_id=o.source_id,
                investigation_id=o.investigation_id,
                incident_id=o.incident_id,
                campaign_id=o.campaign_id,
                observed_at=o.observed_at,
                observation_type=o.observation_type,
                classification=o.classification,
                severity=o.severity,
                confidence=o.confidence,
                evidence_reference=o.evidence_reference,
                analysis_run_id=o.analysis_run_id,
                detector_name=o.detector_name,
                detector_version=o.detector_version,
                is_analyst_verified=o.is_analyst_verified,
                verified_by=o.verified_by,
                raw_context=raw_ctx,
                created_at=o.created_at,
            )
        )
    return results


@router.get(
    "/api/v1/memory/{entry_id}/incidents",
    response_model=List[Dict[str, Any]],
    summary="List related historical incidents for a Threat Memory entry",
)
def get_memory_related_incidents(
    entry_id: str,
    workspace_id: str = Query("default", description="Workspace ID"),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    return ThreatMemoryService.get_related_incidents(db, workspace_id, entry_id, limit=limit)


@router.get(
    "/api/v1/memory/{entry_id}/campaigns",
    response_model=List[Dict[str, Any]],
    summary="List related historical campaigns for a Threat Memory entry",
)
def get_memory_related_campaigns(
    entry_id: str,
    workspace_id: str = Query("default", description="Workspace ID"),
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
):
    return ThreatMemoryService.get_related_campaigns(db, workspace_id, entry_id, limit=limit)


@router.get(
    "/api/v1/memory/{entry_id}/relationships",
    response_model=List[Dict[str, Any]],
    summary="List correlated infrastructure from the Security Knowledge Graph",
)
def get_memory_relationships(
    entry_id: str,
    workspace_id: str = Query("default", description="Workspace ID"),
    limit: int = Query(25, ge=1, le=100),
    db: Session = Depends(get_db),
):
    entry = db.query(ThreatMemoryEntryModel).filter(
        ThreatMemoryEntryModel.id == entry_id,
        ThreatMemoryEntryModel.workspace_id == workspace_id,
    ).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat Memory entry not found.")

    return ThreatMemoryService.get_related_infrastructure(db, workspace_id, entry.canonical_key, limit=limit)


@router.get(
    "/api/v1/memory/{entry_id}/history",
    response_model=Dict[str, Any],
    summary="Get full chronological progression and timeline for a Threat Memory entry",
)
def get_memory_history(
    entry_id: str,
    workspace_id: str = Query("default", description="Workspace ID"),
    db: Session = Depends(get_db),
):
    entry = db.query(ThreatMemoryEntryModel).filter(
        ThreatMemoryEntryModel.id == entry_id,
        ThreatMemoryEntryModel.workspace_id == workspace_id,
    ).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Threat Memory entry not found.")

    novelty_hist = ThreatMemoryService.get_novelty_progression(db, workspace_id, entry.canonical_key)
    behavioral_hist = ThreatMemoryService.get_behavioral_history(db, workspace_id, entry.canonical_key)
    incidents = ThreatMemoryService.get_related_incidents(db, workspace_id, entry.id)

    return {
        "canonical_key": entry.canonical_key,
        "first_seen_at": entry.first_seen_at.isoformat() if entry.first_seen_at else None,
        "last_seen_at": entry.last_seen_at.isoformat() if entry.last_seen_at else None,
        "observation_count": entry.observation_count,
        "independent_source_count": entry.independent_source_count,
        "novelty_progression": novelty_hist,
        "behavioral_history": behavioral_hist,
        "related_incidents": incidents,
    }


# ============================================================================
# 3. MUTATION ENDPOINTS (OBSERVATIONS & DECISIONS)
# ============================================================================

@router.post(
    "/api/v1/memory/observations",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Record an observation into Threat Memory",
)
def create_memory_observation(
    request: ThreatMemoryObservationCreate,
    db: Session = Depends(get_db),
):
    """
    Ingests an observation with eligibility filtering and poisoning protection.
    """
    try:
        entry, obs, is_new = ThreatMemoryService.record_observation(
            db,
            workspace_id=request.workspace_id,
            subject_type=request.subject_type,
            value=request.canonical_key,
            source_type=request.source_type,
            source_id=request.source_id,
            investigation_id=request.investigation_id,
            incident_id=request.incident_id,
            campaign_id=request.campaign_id,
            classification=request.classification,
            severity=request.severity,
            confidence=request.confidence,
            evidence_reference=request.evidence_reference,
            analysis_run_id=request.analysis_run_id,
            detector_name=request.detector_name,
            detector_version=request.detector_version or "1.0.0",
            is_analyst_verified=request.is_analyst_verified,
            verified_by=request.verified_by,
            observed_at=request.observed_at,
            raw_context=request.raw_context,
        )
        db.commit()
        return {
            "entry_id": entry.id,
            "observation_id": obs.id,
            "canonical_key": entry.canonical_key,
            "is_new_entry": is_new,
            "status": entry.status,
            "observation_count": entry.observation_count,
            "independent_source_count": entry.independent_source_count,
        }
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Observation recording failed: {exc}")


@router.post(
    "/api/v1/memory/decisions",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Record analyst validation, false-positive labeling, or suppression decision",
)
def create_memory_decision(
    request: ThreatMemoryDecisionCreate,
    db: Session = Depends(get_db),
):
    """
    Records an auditable analyst decision (VERIFIED_MALICIOUS, FALSE_POSITIVE, etc.)
    and promotes or suppresses the memory entry.
    """
    try:
        dec = ThreatMemoryService.record_analyst_decision(
            db,
            workspace_id=request.workspace_id,
            decision=request.decision,
            reason=request.reason,
            approved_by=request.approved_by,
            canonical_key=request.canonical_key,
            memory_entry_id=request.memory_entry_id,
            scope=request.scope,
            valid_days=30,
            evidence_ids=request.evidence_ids,
        )
        db.commit()
        return {
            "decision_id": dec.id,
            "memory_entry_id": dec.memory_entry_id,
            "decision": dec.decision,
            "approved_by": dec.approved_by,
            "valid_from": dec.valid_from.isoformat() if dec.valid_from else None,
            "valid_until": dec.valid_until.isoformat() if dec.valid_until else None,
        }
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Decision recording failed: {exc}")


class ThreatMemoryQuestionRequest(BaseModel):
    query_type: str = "HISTORICAL_LOOKUP"
    value: str
    workspace_id: str = "default"


@router.post(
    "/api/v1/memory/query",
    response_model=Dict[str, Any],
    summary="Query Threat Memory using natural language intent",
)
def query_memory_question(
    request: ThreatMemoryQuestionRequest,
    db: Session = Depends(get_db),
):
    """
    Exposes evidence-backed memory queries for Copilot and investigation triage:
    'Have we seen this domain before?', 'Was this file hash observed previously?'.
    """
    return ThreatMemoryService.answer_historical_question(
        db,
        workspace_id=request.workspace_id,
        question_intent=request.query_type,
        value=request.value,
    )
