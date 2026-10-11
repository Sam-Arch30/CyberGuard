"""
Section 61: REST API Routes for Cross-Source Correlation & Unified Entity Correlation.

Endpoints:
1. GET /api/v1/correlations/overview: Overview stats & health metrics
2. GET /api/v1/correlations: List correlations with multi-tenant filtering
3. GET /api/v1/correlations/{id}: Full progressive-disclosure correlation details
4. GET /api/v1/correlations/{id}/timeline: Chronological cross-source event timeline
5. GET /api/v1/correlations/{id}/explanation: "Why Correlated?" explainability facts
6. POST /api/v1/correlations/evaluate: Real-time on-demand evaluation
7. POST /api/v1/correlations/{id}/disposition: Analyst disposition (Confirm / Reject / Uncertain)
8. POST /api/v1/entities/resolve: Direct entity resolution with provenance
9. GET /api/v1/entities/resolution-history: Audit log of resolution decisions
10. GET /api/v1/entities/{id}/correlations: Correlations by entity
11. GET /api/v1/findings/{id}/correlations: Correlations by finding
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.cross_source_correlation import (
    CorrelationOverviewStats,
    CrossSourceCorrelationRead,
    CrossSourceCorrelationDetail,
    CorrelationTimelineItem,
    WhyCorrelatedExplanation,
    CorrelationDispositionRequest,
    CorrelationEvaluationRequest,
    EntityResolutionRequest,
    EntityResolutionResult,
    CorrelationTypeEnum,
    CorrelationStatusEnum,
)
from backend.services.cross_source_correlation_engine import CrossSourceCorrelationEngine
from backend.services.unified_entity_resolver import UnifiedEntityResolver

logger = logging.getLogger("cyberguard.api.cross_source_correlation")

router = APIRouter(prefix="/api/v1", tags=["Cross-Source Correlation"])


class CorrelationListResponse(BaseModel):
    items: List[CrossSourceCorrelationRead]
    total: int
    limit: int
    offset: int


class ResolutionHistoryItem(BaseModel):
    id: str
    workspace_id: str
    entity_type: str
    canonical_entity_id: str
    raw_identifier: str
    normalized_identifier: str
    resolution_method: str
    resolution_confidence: float
    status: str
    matched_attributes: Dict[str, Any]
    provenance: Dict[str, Any]
    created_at: str


class ResolutionHistoryResponse(BaseModel):
    items: List[ResolutionHistoryItem]
    total: int


# ============================================================================
# 1. OVERVIEW & METRICS
# ============================================================================

@router.get(
    "/correlations/overview",
    response_model=CorrelationOverviewStats,
    summary="Get cross-source correlation overview statistics",
)
def get_correlation_overview(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns platform-wide operational KPIs for cross-source threat correlations."""
    return CrossSourceCorrelationEngine.get_overview_stats(db, workspace_id=x_workspace_id)


# ============================================================================
# 2. LIST & SEARCH CORRELATIONS
# ============================================================================

@router.get(
    "/correlations",
    response_model=CorrelationListResponse,
    summary="List cross-source correlations with filtering",
)
def list_correlations(
    status: Optional[str] = Query(None, description="CANDIDATE, CORRELATED, PARTIALLY_CORRELATED, STALE, INVALIDATED, ARCHIVED"),
    correlation_type: Optional[str] = Query(None, description="Filter by correlation type"),
    severity: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
    min_confidence: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum confidence score"),
    search: Optional[str] = Query(None, description="Text search in title, number, or description"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Lists cross-source threat correlations with server-side pagination and multi-tenant scoping."""
    items, total = CrossSourceCorrelationEngine.list_correlations(
        db=db,
        workspace_id=x_workspace_id,
        status=status,
        correlation_type=correlation_type,
        severity=severity,
        min_confidence=min_confidence,
        search=search,
        limit=limit,
        offset=offset,
    )
    return CorrelationListResponse(items=items, total=total, limit=limit, offset=offset)


# ============================================================================
# 3. CORRELATION DETAILS, TIMELINE & EXPLANATION
# ============================================================================

@router.get(
    "/correlations/{correlation_id}",
    response_model=CrossSourceCorrelationDetail,
    summary="Get full correlation details",
)
def get_correlation_detail(
    correlation_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns complete progressive-disclosure details for a cross-source correlation."""
    detail = CrossSourceCorrelationEngine.get_correlation_detail(
        db=db, correlation_id=correlation_id, workspace_id=x_workspace_id
    )
    if not detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation '{correlation_id}' not found",
        )
    return detail


@router.get(
    "/correlations/{correlation_id}/timeline",
    response_model=List[CorrelationTimelineItem],
    summary="Get chronological timeline of correlated sequence",
)
def get_correlation_timeline(
    correlation_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns ordered multi-source timeline of observations comprising the correlation."""
    return CrossSourceCorrelationEngine.get_correlation_timeline(
        db=db, correlation_id=correlation_id, workspace_id=x_workspace_id
    )


@router.get(
    "/correlations/{correlation_id}/explanation",
    response_model=WhyCorrelatedExplanation,
    summary="Get 'Why Correlated?' explanation facts",
)
def get_why_correlated(
    correlation_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns structured reasoning, shared entities, indicators, and caveats explaining why events were correlated."""
    exp = CrossSourceCorrelationEngine.get_why_correlated(
        db=db, correlation_id=correlation_id, workspace_id=x_workspace_id
    )
    if not exp:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Correlation '{correlation_id}' not found",
        )
    return exp


# ============================================================================
# 4. EVALUATION & DISPOSITION
# ============================================================================

@router.post(
    "/correlations/evaluate",
    response_model=List[CrossSourceCorrelationRead],
    summary="Trigger real-time cross-source correlation evaluation",
)
def evaluate_correlation(
    req: CorrelationEvaluationRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Executes deterministic correlation evaluation across recent telemetry for an entity or finding."""
    target_ws = req.workspace_id or x_workspace_id
    window_s = float(req.correlation_window_minutes * 60)
    created = CrossSourceCorrelationEngine.evaluate_cross_source_correlation(
        db=db,
        workspace_id=target_ws,
        entity_id=req.entity_id,
        finding_id=req.finding_id,
        incident_id=req.incident_id,
        window_seconds=window_s,
    )
    db.commit()
    items: List[CrossSourceCorrelationRead] = []
    for r in created:
        items.append(CrossSourceCorrelationRead(
            id=r.id,
            workspace_id=r.workspace_id,
            correlation_number=r.correlation_number,
            correlation_type=CorrelationTypeEnum(r.correlation_type),
            title=r.title,
            description=r.description,
            status=CorrelationStatusEnum(r.status),
            confidence_score=r.confidence_score,
            confidence_level=r.confidence_level,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            severity=r.severity,
            first_observed_at=r.first_observed_at,
            last_observed_at=r.last_observed_at,
            time_window_seconds=r.time_window_seconds,
            parent_finding_id=r.parent_finding_id,
            alert_id=r.alert_id,
            incident_id=r.incident_id,
            campaign_id=r.campaign_id,
            explanation_summary=r.explanation_summary,
            member_count=len(r.members or []),
            sources=sorted(list({m.source_type for m in (r.members or [])})),
            entities=sorted(list({m.member_id for m in (r.members or []) if m.member_type == "ENTITY"})),
            analyst_disposition=r.analyst_disposition,
            created_at=r.created_at,
            updated_at=r.updated_at,
        ))
    return items


@router.post(
    "/correlations/{correlation_id}/disposition",
    response_model=CrossSourceCorrelationDetail,
    summary="Record analyst disposition on a correlation",
)
def record_disposition(
    correlation_id: str,
    req: CorrelationDispositionRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Allows an analyst to confirm, reject, or mark a correlation as uncertain with mandatory justification."""
    try:
        CrossSourceCorrelationEngine.record_disposition(
            db=db,
            correlation_id=correlation_id,
            req=req,
            workspace_id=x_workspace_id,
        )
        db.commit()
        detail = CrossSourceCorrelationEngine.get_correlation_detail(
            db=db, correlation_id=correlation_id, workspace_id=x_workspace_id
        )
        return detail
    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ============================================================================
# 5. UNIFIED ENTITY RESOLUTION ENDPOINTS
# ============================================================================

@router.post(
    "/entities/resolve",
    response_model=EntityResolutionResult,
    summary="Deterministically resolve an entity identifier",
)
def resolve_entity_identifier(
    req: EntityResolutionRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Resolves a raw identifier to an authoritative Knowledge Graph entity with provenance facts."""
    target_ws = req.workspace_id or x_workspace_id
    res = UnifiedEntityResolver.resolve_entity(
        db=db,
        entity_type=req.entity_type,
        raw_identifier=req.raw_identifier,
        workspace_id=target_ws,
        context=req.context,
        allow_fuzzy=req.allow_fuzzy,
    )
    db.commit()
    return res


@router.get(
    "/entities/resolution-history",
    response_model=ResolutionHistoryResponse,
    summary="Get audit log of entity resolution decisions",
)
def get_entity_resolution_history(
    entity_type: Optional[str] = Query(None),
    canonical_entity_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Queries immutable audit trail of entity resolution decisions."""
    records = UnifiedEntityResolver.get_resolution_history(
        db=db,
        workspace_id=x_workspace_id,
        entity_type=entity_type,
        canonical_entity_id=canonical_entity_id,
        limit=limit,
    )
    items = [
        ResolutionHistoryItem(
            id=r.id,
            workspace_id=r.workspace_id,
            entity_type=r.entity_type,
            canonical_entity_id=r.canonical_entity_id,
            raw_identifier=r.raw_identifier,
            normalized_identifier=r.normalized_identifier,
            resolution_method=r.resolution_method,
            resolution_confidence=r.resolution_confidence,
            status=r.status,
            matched_attributes=r.matched_attributes,
            provenance=r.provenance,
            created_at=r.created_at.isoformat(),
        )
        for r in records
    ]
    return ResolutionHistoryResponse(items=items, total=len(items))


@router.get(
    "/entities/{entity_id}/correlations",
    response_model=List[CrossSourceCorrelationRead],
    summary="Get correlations involving a specific entity",
)
def get_correlations_by_entity(
    entity_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns all cross-source threat correlations that include this entity as a member."""
    items, _ = CrossSourceCorrelationEngine.list_correlations(
        db=db, workspace_id=x_workspace_id, search=entity_id, limit=20
    )
    return items


@router.get(
    "/findings/{finding_id}/correlations",
    response_model=List[CrossSourceCorrelationRead],
    summary="Get correlations involving a specific finding",
)
def get_correlations_by_finding(
    finding_id: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
):
    """Returns cross-source threat correlations that reference this analytical finding."""
    items, _ = CrossSourceCorrelationEngine.list_correlations(
        db=db, workspace_id=x_workspace_id, search=finding_id, limit=20
    )
    return items
