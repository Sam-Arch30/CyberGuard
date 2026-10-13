"""
API Routes for Section 43: History & Search.
Unified Discovery, Global Search, and Cross-Investigation Indicator Intelligence.
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status as http_status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.search import (
    CrossInvestigationIndicatorResponse,
    SearchFacetsResponse,
    SearchResponse,
)
from backend.services.search_service import SearchService

router = APIRouter(prefix="/api/search", tags=["History & Search"])


@router.get(
    "",
    response_model=SearchResponse,
    summary="Unified Global Search",
    description="Unified discovery endpoint querying investigations, reports, indicators, evidence, findings, campaigns, and threat memory with deterministic ranking.",
)
def unified_search(
    q: str = Query(..., min_length=1, description="Search query string, indicator, ID, hash, or text keyword"),
    types: Optional[List[str]] = Query(None, description="Resource types to filter by (investigation, report, indicator, evidence, finding, campaign, threat_memory)"),
    risk: Optional[List[str]] = Query(None, description="Risk tiers (CRITICAL, HIGH, MEDIUM, LOW)"),
    severity: Optional[List[str]] = Query(None, description="Severity levels (CRITICAL, HIGH, MEDIUM, LOW)"),
    status: Optional[List[str]] = Query(None, description="Investigation or report statuses"),
    source: Optional[List[str]] = Query(None, description="Source types (EMAIL, URL, FILE, NETWORK, API)"),
    from_time: Optional[datetime] = Query(None, description="Filter records created on or after timestamp"),
    to_time: Optional[datetime] = Query(None, description="Filter records created on or before timestamp"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    try:
        return SearchService.search(
            db=db,
            query=q,
            resource_types=types,
            risk_filter=risk,
            severity_filter=severity,
            status_filter=status,
            source_filter=source,
            from_time=from_time,
            to_time=to_time,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Unified search execution failed.',
        )



@router.get(
    "/indicator/{value:path}",
    response_model=CrossInvestigationIndicatorResponse,
    summary="Cross-Investigation Indicator Lookup",
    description="Deep cross-investigation lookup for any observable IP, domain, URL, hash, or email, exposing exact investigation occurrences, historical Threat Memory, campaigns, and strict epistemic provenance.",
)
def indicator_lookup(
    value: str,
    db: Session = Depends(get_db),
):
    clean_val = value.strip()
    if not clean_val:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Indicator value cannot be empty.",
        )
    try:
        return SearchService.lookup_indicator(db=db, indicator_value=clean_val)
    except Exception as exc:
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Cross-investigation indicator lookup failed.',
        )
