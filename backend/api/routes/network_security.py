"""
Network and Traffic Anomaly Security API Endpoints.
Provides routes for network telemetry ingestion, NetFlow/DNS batch analysis,
log uploads, artifact re-analysis, and engine configuration.
"""
from __future__ import annotations
from backend.services.upload_security import UploadSecurityService
from backend.services.structured_telemetry_parser import parse_structured_telemetry, validate_events

import csv
import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import ArtifactModel, EntityModel
from backend.schemas.unified import EntityTypeEnum
from backend.schemas.network_security import (
    NetworkConfigResponse,
    NetworkSecurityAnalysisResponse,
    DeviceNetworkProfile,
)
from backend.services.network_pipeline import global_network_pipeline

logger = logging.getLogger("cyberguard.api.network_security")

router = APIRouter(prefix="/api/network-security", tags=["Network Security"])


@router.get("/config", response_model=NetworkConfigResponse)
def get_network_security_config() -> NetworkConfigResponse:
    """
    Returns active configuration parameters, detection thresholds, and internal network CIDRs.
    """
    return global_network_pipeline.config


@router.post("/analyze-event", response_model=NetworkSecurityAnalysisResponse)
async def analyze_single_network_event(
    event_payload: Dict[str, Any],
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (generic_json, dns_log, netflow_json)"),
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Analyze a single network connection, flow, or DNS query event.
    """
    try:
        response = await global_network_pipeline.analyze_events(
            raw_events=[event_payload],
            db=db,
            provider_hint=provider_hint,
        )
        if response.events_analyzed_count == 0:
            raise HTTPException(status_code=422, detail="No usable telemetry events. Check provider fields and event format.")
        return response
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as e:
        logger.error(f"Error analyzing single network event: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Network analysis failed.',
        )


@router.post("/analyze-batch", response_model=NetworkSecurityAnalysisResponse)
async def analyze_batch_network_events(
    events: List[Dict[str, Any]],
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint"),
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Analyze a batch of network flow or DNS query records.
    """
    try:
        validate_events(events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    try:
        response = await global_network_pipeline.analyze_events(
            raw_events=events,
            db=db,
            provider_hint=provider_hint,
        )
        if response.events_analyzed_count == 0:
            raise HTTPException(status_code=422, detail="No usable telemetry events. Check provider fields and event format.")
        return response
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as e:
        logger.error(f"Error analyzing batch network events: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Batch network analysis failed.',
        )


@router.post("/upload-log", response_model=NetworkSecurityAnalysisResponse)
async def upload_network_log_file(
    file: UploadFile = File(...),
    provider_hint: Optional[str] = Query(None, description="Optional adapter hint (generic_json, generic_csv, dns_log, netflow_json)"),
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Upload and analyze network telemetry logs (JSON array, JSON lines, or CSV).
    """
    try:
        content_bytes = await UploadSecurityService.read_bounded_upload(file, max_bytes=50 * 1024 * 1024)
        try:
            raw_events = parse_structured_telemetry(content_bytes, file.filename or '', file.content_type or '')
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc))
        response = await global_network_pipeline.analyze_events(
            raw_events=raw_events,
            db=db,
            provider_hint=provider_hint,
        )
        if response.events_analyzed_count == 0:
            raise HTTPException(status_code=422, detail="No usable telemetry events. Check provider fields and event format.")
        return response
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as e:
        logger.error(f"Error analyzing uploaded network log: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Network log file analysis failed.',
        )


@router.post("/analyze-artifact/{artifact_id}", response_model=NetworkSecurityAnalysisResponse)
async def analyze_stored_network_artifact(
    artifact_id: str,
    db: Session = Depends(get_db),
) -> NetworkSecurityAnalysisResponse:
    """
    Re-analyze a stored NETWORK_LOG artifact directly from evidence storage.
    Creates a new independent AnalysisRunModel with full historical provenance.
    """
    try:
        return await global_network_pipeline.analyze_artifact(artifact_id=artifact_id, db=db)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as e:
        logger.error(f"Error re-analyzing network artifact {artifact_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Network artifact re-analysis failed.',
        )


@router.get("/devices/{device_id}/profile", response_model=DeviceNetworkProfile)
def get_device_network_profile(
    device_id: str,
    db: Session = Depends(get_db),
) -> DeviceNetworkProfile:
    """
    Returns baseline observed network telemetry for a host/device.
    """
    clean_id = device_id.strip()
    entity = db.query(EntityModel).filter(
        EntityModel.entity_type == EntityTypeEnum.DEVICE.value,
        EntityModel.name == clean_id,
    ).first()

    if not entity:
        return DeviceNetworkProfile(
            device_id=clean_id,
            total_connections_observed=0,
            known_destinations=[],
            known_ports=[],
            known_domains=[],
        )

    attrs = json.loads(entity.attributes_json or "{}")
    return DeviceNetworkProfile(
        device_id=clean_id,
        total_connections_observed=attrs.get("connections_count", 0),
        first_seen=entity.first_seen,
        last_seen=entity.last_seen,
        known_destinations=attrs.get("known_destinations", []),
        known_ports=attrs.get("known_ports", []),
        known_domains=attrs.get("known_domains", []),
        total_bytes_sent=attrs.get("bytes_sent", 0),
        total_bytes_received=attrs.get("bytes_received", 0),
    )
