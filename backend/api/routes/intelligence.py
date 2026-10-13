"""
Section 52: Threat Intelligence & External Intelligence Enrichment API Routes.
Provides sanitized, privacy-guarded indicator enrichment, provider configuration,
multi-source provenance, historical observation timelines, and asynchronous batch jobs.
Strictly safeguards API credentials, ensuring no secret keys or internal infrastructure details leak.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.ip_intelligence import GeolocationResponse, GeolocationStatusResponse
from backend.schemas.jobs import JobTypeEnum
from backend.schemas.threat_intelligence import (
    AggregatedIndicatorIntelligence,
    BatchEnrichmentRequest,
    BatchEnrichmentResponse,
    IndicatorEnrichmentRequest,
    IndicatorHistoryResponse,
    IndicatorTypeEnum,
    PrivacyPolicyClassificationResponse,
    ThreatIntelProviderConfigResponse,
    ThreatIntelProviderUpdateRequest,
)
from backend.services.background_job_service import BackgroundJobService
from backend.services.geolocation_service import global_geolocation_service
from backend.services.indicator_normalizer import IndicatorNormalizer
from backend.services.threat_intelligence_service import ThreatIntelligenceService

logger = logging.getLogger("cyberguard.intelligence_routes")
router = APIRouter(prefix="/api/intelligence", tags=["Threat Intelligence & Enrichment"])


# =============================================================================
# 1. Indicator Enrichment & Lookups
# =============================================================================

@router.get(
    "/indicator/{indicator_type}/{indicator_value:path}",
    response_model=AggregatedIndicatorIntelligence,
    summary="Query enriched threat intelligence for an observable indicator",
)
async def get_indicator_intelligence(
    indicator_type: str,
    indicator_value: str,
    force_refresh: bool = Query(False, description="Bypass cache and force fresh lookups"),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> AggregatedIndicatorIntelligence:
    """
    Retrieves normalized, multi-provider threat intelligence for an indicator.
    Enforces privacy policy: internal/private indicators (RFC1918 IPs, corporate hostnames, private URLs)
    are guarded and never leaked to external networks.
    """
    clean_val = unquote(indicator_value).strip()
    if not clean_val:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Indicator value cannot be empty.")

    try:
        svc = ThreatIntelligenceService()
        return await svc.enrich_indicator(
            db=db,
            raw_indicator=clean_val,
            indicator_type=indicator_type,
            workspace_id=x_workspace_id,
            force_refresh=force_refresh,
        )
    except Exception as exc:
        logger.error(f"Error enriching indicator '{clean_val}': {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Internal error enriching indicator.',
        )


@router.post(
    "/indicator/{indicator_type}/{indicator_value:path}/enrich",
    summary="Trigger on-demand indicator enrichment or submit background job",
)
async def enrich_indicator_action(
    indicator_type: str,
    indicator_value: str,
    req: IndicatorEnrichmentRequest = IndicatorEnrichmentRequest(),
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> Any:
    """
    Triggers enrichment. When sync=True, executes inline and returns intelligence immediately.
    When sync=False, enqueues an asynchronous Section 45 Background Job.
    """
    clean_val = unquote(indicator_value).strip()
    if not clean_val:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Indicator value cannot be empty.")

    if req.sync:
        svc = ThreatIntelligenceService()
        return await svc.enrich_indicator(
            db=db,
            raw_indicator=clean_val,
            indicator_type=indicator_type,
            workspace_id=x_workspace_id,
            force_refresh=req.force_refresh,
        )

    # Asynchronous Background Job Submission
    job = BackgroundJobService.submit_job(
        db=db,
        job_type=JobTypeEnum.INDICATOR_ENRICHMENT.value,
        workspace_id=x_workspace_id,
        payload={
            "indicator_value": clean_val,
            "indicator_type": indicator_type,
            "force_refresh": req.force_refresh,
        },
        resource_type="INDICATOR",
        resource_id=clean_val,
    )
    return {
        "status": "QUEUED",
        "job_id": job.id,
        "message": f"Enrichment job enqueued for indicator '{clean_val}'.",
    }


@router.post(
    "/indicator/{indicator_type}/{indicator_value:path}/refresh",
    response_model=AggregatedIndicatorIntelligence,
    summary="Force refresh intelligence from external providers bypassing cache",
)
async def refresh_indicator_intelligence(
    indicator_type: str,
    indicator_value: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> AggregatedIndicatorIntelligence:
    """Forces an immediate cache bypass and refreshes intelligence from configured providers."""
    clean_val = unquote(indicator_value).strip()
    svc = ThreatIntelligenceService()
    return await svc.enrich_indicator(
        db=db,
        raw_indicator=clean_val,
        indicator_type=indicator_type,
        workspace_id=x_workspace_id,
        force_refresh=True,
    )


@router.get(
    "/indicator/{indicator_type}/{indicator_value:path}/history",
    response_model=IndicatorHistoryResponse,
    summary="Retrieve chronological observation history across all providers",
)
def get_indicator_history(
    indicator_type: str,
    indicator_value: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> IndicatorHistoryResponse:
    """Retrieves point-in-time observation history for an indicator."""
    clean_val = unquote(indicator_value).strip()
    return ThreatIntelligenceService.get_indicator_history(
        db=db,
        workspace_id=x_workspace_id,
        indicator_type=indicator_type,
        normalized_value=clean_val,
    )


# =============================================================================
# 2. Batch Enrichment & Privacy Policy Inspection
# =============================================================================

@router.post(
    "/batch-enrich",
    response_model=BatchEnrichmentResponse,
    summary="Enrich a batch of observable indicators",
)
async def batch_enrich_indicators(
    req: BatchEnrichmentRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> BatchEnrichmentResponse:
    """Enriches multiple indicators with bounded concurrency."""
    svc = ThreatIntelligenceService()
    results: List[AggregatedIndicatorIntelligence] = []
    failures: List[Dict[str, Any]] = []

    for item in req.indicators:
        val = item.get("value")
        ind_type = item.get("type")
        if not val:
            continue
        try:
            res = await svc.enrich_indicator(
                db=db,
                raw_indicator=val,
                indicator_type=ind_type,
                workspace_id=x_workspace_id,
                force_refresh=req.force_refresh,
            )
            results.append(res)
        except Exception as e:
            failures.append({"indicator": val, "error": str(e)})

    return BatchEnrichmentResponse(
        total_requested=len(req.indicators),
        enriched_count=len(results),
        results=results,
        partial_failures=failures,
    )


@router.get(
    "/privacy/classify",
    response_model=PrivacyPolicyClassificationResponse,
    summary="Inspect privacy policy classification for an observable without querying providers",
)
def classify_indicator_privacy(
    value: str = Query(..., description="Observable indicator string"),
    type: Optional[str] = Query(None, description="Optional indicator type hint"),
) -> PrivacyPolicyClassificationResponse:
    """
    Evaluates privacy policy without triggering external lookups.
    Explains whether the indicator is PUBLIC, INTERNAL, or SENSITIVE.
    """
    norm = IndicatorNormalizer.normalize(value, type)
    allowed, reason = IndicatorNormalizer.is_external_lookup_allowed(norm)
    return PrivacyPolicyClassificationResponse(
        indicator_type=norm.type,
        raw_value=norm.raw_value,
        normalized_value=norm.normalized_value,
        privacy_scope=norm.privacy_scope,
        external_lookup_permitted=allowed,
        reason=reason,
    )


# =============================================================================
# 3. Provider Configuration & Health Management
# =============================================================================

@router.get(
    "/providers",
    response_model=List[ThreatIntelProviderConfigResponse],
    summary="List configured threat intelligence providers and their operational health",
)
def list_providers(
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> List[ThreatIntelProviderConfigResponse]:
    """Returns safe sanitized provider configurations without exposing credentials."""
    return ThreatIntelligenceService.get_provider_configs(db, x_workspace_id)


@router.put(
    "/providers/{provider_name}",
    response_model=ThreatIntelProviderConfigResponse,
    summary="Update provider settings, priority, or credentials",
)
def update_provider(
    provider_name: str,
    req: ThreatIntelProviderUpdateRequest,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> ThreatIntelProviderConfigResponse:
    """Updates provider priority, enablement, rate limit, or secret API key."""
    try:
        return ThreatIntelligenceService.update_provider_config(
            db=db,
            workspace_id=x_workspace_id,
            provider_name=provider_name,
            req=req,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/providers/{provider_name}/health",
    summary="Trigger live health check on a threat intelligence provider",
)
async def check_provider_health(
    provider_name: str,
    x_workspace_id: str = Header("default", alias="X-Workspace-ID"),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Verifies provider operational connectivity."""
    svc = ThreatIntelligenceService()
    provider_inst = svc.providers.get(provider_name)
    if not provider_inst:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Provider '{provider_name}' not found.")

    status_enum, message = await provider_inst.health_check()
    return {
        "provider": provider_name,
        "status": status_enum.value,
        "message": message,
        "capabilities": provider_inst.get_capabilities(),
    }


# =============================================================================
# 4. Backward Compatibility: Geolocation Endpoints
# =============================================================================

@router.get(
    "/geolocation/status",
    response_model=GeolocationStatusResponse,
    summary="Check safe geolocation configuration status",
)
async def get_geolocation_status() -> GeolocationStatusResponse:
    """Returns high-level status of the Geolocation Provider."""
    try:
        return global_geolocation_service.get_status()
    except Exception as exc:
        logger.error(f"Error checking geolocation status: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error retrieving geolocation provider status",
        )


@router.get(
    "/ip/{ip:path}/geolocation",
    response_model=GeolocationResponse,
    summary="Lookup sanitized IP geolocation telemetry",
)
async def get_ip_geolocation(ip: str) -> GeolocationResponse:
    """Resolves normalized geolocation intelligence for an IP address."""
    if not ip or not ip.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="IP address parameter cannot be empty.")
    try:
        return await global_geolocation_service.get_geolocation(ip.strip())
    except Exception as exc:
        logger.error(f"Unexpected error resolving geolocation for IP: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error resolving IP geolocation",
        )
