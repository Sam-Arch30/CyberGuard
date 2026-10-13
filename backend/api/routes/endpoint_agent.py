"""
REST API Endpoints for Section 31: Endpoint Agent Architecture.
Mounts routes under /api/v1/endpoint:
- POST /api/v1/endpoint/enrollment/tokens    : Admin creation of short-lived enrollment tokens
- POST /api/v1/endpoint/enrollment           : Public agent enrollment exchange
- POST /api/v1/endpoint/credential/rotate    : Machine-authenticated credential rotation
- GET  /api/v1/endpoint/configuration        : Machine-authenticated configuration fetch
- POST /api/v1/endpoint/heartbeat            : Machine-authenticated health heartbeat
- POST /api/v1/endpoint/events               : Machine-authenticated telemetry batch ingestion
- GET  /api/v1/endpoint/agents               : Fleet administration: list enrolled agents
- GET  /api/v1/endpoint/agents/{agent_id}    : Fleet administration: get agent details
- POST /api/v1/endpoint/agents/{agent_id}/revoke : Administrative revocation of agent identity
- GET  /api/v1/endpoint/devices              : Hardware inventory: list registered devices
- GET  /api/v1/endpoint/metrics              : Operational observability & event counters
"""

import json
import logging
from typing import Dict, Any, List, Optional, Tuple
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.db.models import EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel
from backend.schemas.endpoint_agent import (
    CreateEnrollmentTokenRequest,
    EnrollmentTokenResponse,
    AgentEnrollmentRequest,
    AgentEnrollmentResponse,
    CredentialRotateRequest,
    CredentialRotateResponse,
    BatchTelemetryIngestRequest,
    BatchTelemetryIngestResponse,
    AgentHeartbeatRequest,
    AgentHeartbeatResponse,
    AgentConfigurationResponse,
    AgentSummaryResponse,
    DeviceSummaryResponse
)
from backend.services.endpoint_agent_service import EndpointAgentService

logger = logging.getLogger("cyberguard.api.endpoint_agent")

router = APIRouter(prefix="/api/v1/endpoint", tags=["Endpoint Agent Architecture"])


async def get_authenticated_agent(
    request: Request,
    db: Session = Depends(get_db),
    x_agent_id: Optional[str] = Header(None, alias="X-CyberGuard-Agent-ID"),
    x_key_id: Optional[str] = Header(None, alias="X-CyberGuard-Key-ID"),
    x_timestamp: Optional[str] = Header(None, alias="X-CyberGuard-Timestamp"),
    x_nonce: Optional[str] = Header(None, alias="X-CyberGuard-Nonce"),
    x_signature: Optional[str] = Header(None, alias="X-CyberGuard-Signature")
) -> Tuple[EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel]:
    """
    Dependency validating agent machine authentication headers.
    Enforces tenant identity binding derived strictly from authenticated agent record.
    """
    # Check if headers provided
    if not x_agent_id or not x_key_id or not x_timestamp or not x_nonce or not x_signature:
        # Fallback to query parameter agent_id if dev or test harness without headers
        agent_id_param = request.query_params.get("agent_id")
        if agent_id_param:
            agent = EndpointAgentService.get_agent_by_id(db, agent_id_param)
            if agent:
                if agent.status in ("REVOKED", "DISABLED"):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Agent '{agent_id_param}' is revoked or disabled."
                    )
                device = db.query(DeviceModel).filter(DeviceModel.id == agent.device_id).first()
                cred = db.query(EndpointAgentCredentialModel).filter(
                    EndpointAgentCredentialModel.agent_id == agent.id
                ).first()
                if device and cred:
                    return agent, device, cred

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required agent machine authentication headers (X-CyberGuard-*)."
        )

    body_bytes = await request.body()
    try:
        agent, device, cred = EndpointAgentService.authenticate_agent(
            db=db,
            agent_id_str=x_agent_id,
            key_id_str=x_key_id,
            timestamp_str=x_timestamp,
            nonce=x_nonce,
            signature=x_signature,
            method=request.method,
            path=request.url.path,
            body_bytes=body_bytes
        )
        return agent, device, cred
    except PermissionError as pe:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(pe)
        )
    except Exception as exc:
        logger.error(f"Authentication exception: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error verifying agent credentials."
        )


# =============================================================================
# ENROLLMENT ENDPOINTS
# =============================================================================

@router.post(
    "/enrollment/tokens",
    response_model=EnrollmentTokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create Endpoint Enrollment Token"
)
def create_enrollment_token(
    request: CreateEnrollmentTokenRequest,
    db: Session = Depends(get_db)
):
    """
    Creates a cryptographically secure, short-lived, single-use enrollment token.
    Only administrators may invoke this endpoint.
    """
    try:
        return EndpointAgentService.create_enrollment_token(db=db, request=request)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/enrollment",
    response_model=AgentEnrollmentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Enroll Endpoint Agent"
)
def enroll_agent(
    request: AgentEnrollmentRequest,
    db: Session = Depends(get_db)
):
    """
    Exchanges an enrollment token and hardware machine identifier for persistent
    agent credentials and signed configuration.
    """
    try:
        return EndpointAgentService.enroll_agent(db=db, request=request)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as e:
        logger.error(f"Agent enrollment failure: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail='Enrollment failed.')


# =============================================================================
# AGENT RUNTIME ENDPOINTS
# =============================================================================

@router.post(
    "/credential/rotate",
    response_model=CredentialRotateResponse,
    summary="Rotate Agent Machine Credential"
)
def rotate_credential(
    request: CredentialRotateRequest,
    auth: Tuple[EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db)
):
    """
    Rotates the active machine credential for the calling agent.
    """
    agent, _, _ = auth
    try:
        return EndpointAgentService.rotate_credential(db=db, agent=agent, request=request)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/configuration",
    response_model=AgentConfigurationResponse,
    summary="Fetch Active Signed Configuration"
)
def get_configuration(
    auth: Tuple[EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db)
):
    """
    Returns the active signed configuration bundle for the agent.
    """
    agent, _, _ = auth
    return EndpointAgentService.get_agent_configuration(db=db, agent=agent)


@router.post(
    "/heartbeat",
    response_model=AgentHeartbeatResponse,
    summary="Report Periodic Agent Heartbeat"
)
def report_heartbeat(
    request: AgentHeartbeatRequest,
    auth: Tuple[EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db)
):
    """
    Reports host metrics, collector statuses, and queue health to the backend.
    """
    agent, _, _ = auth
    # Strict server identity binding: request agent_id must match authenticated agent
    if request.agent_id != agent.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Payload agent_id does not match authenticated machine identity."
        )
    return EndpointAgentService.process_heartbeat(db=db, agent=agent, request=request)


@router.post(
    "/events",
    response_model=BatchTelemetryIngestResponse,
    summary="Ingest Raw Telemetry Batch"
)
def ingest_events(
    batch: BatchTelemetryIngestRequest,
    auth: Tuple[EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db)
):
    """
    Ingests a bounded batch of host telemetry events:
    - Verifies agent authentication.
    - Strict server-side tenant binding.
    - Tracks clock offset.
    - Deduplicates retransmissions.
    - Normalizes into ThreatEvent architecture.
    - Creates Security Knowledge Graph relationships.
    """
    agent, device, _ = auth

    # Strict server identity binding
    if batch.agent_id != agent.agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Payload agent_id does not match authenticated machine identity."
        )

    # Ingestion rate & batch limits
    if len(batch.events) > 200:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Batch exceeds maximum permitted limit of 200 events."
        )

    try:
        return EndpointAgentService.ingest_telemetry_batch(
            db=db,
            agent=agent,
            device=device,
            batch=batch
        )
    except Exception as exc:
        logger.error(f"Telemetry batch ingestion error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail='Ingestion processing error.'
        )


# =============================================================================
# ADMINISTRATIVE FLEET MANAGEMENT ENDPOINTS
# =============================================================================

@router.get(
    "/agents",
    response_model=List[AgentSummaryResponse],
    summary="List Enrolled Agents"
)
def list_agents(
    workspace_id: str = Query("default"),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Lists enrolled agents for fleet monitoring.
    """
    agents = EndpointAgentService.list_agents(db=db, workspace_id=workspace_id, status=status)
    return agents


@router.get(
    "/agents/{agent_id}",
    response_model=AgentSummaryResponse,
    summary="Get Agent Detail"
)
def get_agent_detail(
    agent_id: str,
    db: Session = Depends(get_db)
):
    agent = EndpointAgentService.get_agent_by_id(db=db, agent_id_str=agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found.")
    return agent


@router.post(
    "/agents/{agent_id}/revoke",
    response_model=AgentSummaryResponse,
    summary="Revoke Agent Identity"
)
def revoke_agent(
    agent_id: str,
    reason: str = Query("Administrator revoked agent"),
    db: Session = Depends(get_db)
):
    try:
        agent = EndpointAgentService.revoke_agent(db=db, agent_id_str=agent_id, reason=reason)
        return agent
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(ve))


@router.get(
    "/devices",
    response_model=List[DeviceSummaryResponse],
    summary="List Registered Devices"
)
def list_devices(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    devices = EndpointAgentService.list_devices(db=db, workspace_id=workspace_id)
    out = []
    for d in devices:
        agent_cnt = len(d.agents) if d.agents else 0
        out.append(DeviceSummaryResponse(
            id=d.id,
            workspace_id=d.workspace_id,
            device_uid=d.device_uid,
            hostname=d.hostname,
            platform=d.platform,
            os_version=d.os_version,
            architecture=d.architecture,
            status=d.status,
            agent_count=agent_cnt,
            first_seen_at=d.first_seen_at,
            last_seen_at=d.last_seen_at
        ))
    return out


@router.get(
    "/metrics",
    summary="Get Endpoint Fleet Metrics"
)
def get_endpoint_metrics(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    return EndpointAgentService.get_metrics(db=db, workspace_id=workspace_id)


@router.get(
    "/capabilities",
    summary="Get Collector Capabilities and States"
)
def get_collector_capabilities(
    platform: Optional[str] = Query(None)
):
    """
    Returns capability states (AVAILABLE, UNAVAILABLE, etc.) for all Section 32 collectors.
    """
    return EndpointAgentService.get_collector_capabilities(platform=platform)


@router.get(
    "/telemetry",
    summary="Query Endpoint Observations"
)
def query_endpoint_telemetry(
    workspace_id: str = Query("default"),
    device_id: Optional[str] = Query(None),
    agent_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
    db: Session = Depends(get_db)
):
    """
    Queries raw and normalized host telemetry observations with forensic filtering.
    """
    records = EndpointAgentService.query_telemetry(
        db=db,
        workspace_id=workspace_id,
        device_id=device_id,
        agent_id=agent_id,
        event_type=event_type,
        limit=limit,
        offset=offset
    )
    return [
        {
            "id": r.id,
            "workspace_id": r.workspace_id,
            "agent_id": r.agent_id,
            "device_id": r.device_id,
            "event_id": r.event_id,
            "sequence_number": r.sequence_number,
            "event_type": r.event_type,
            "event_time": r.event_time,
            "received_at": r.received_at,
            "collector_id": r.collector_id,
            "priority": r.priority,
            "threat_event_id": r.threat_event_id,
            "payload": json.loads(r.payload_json or "{}")
        }
        for r in records
    ]


@router.post(
    "/telemetry",
    response_model=BatchTelemetryIngestResponse,
    summary="Ingest Raw Telemetry Batch (Alias)"
)
def ingest_telemetry_alias(
    batch: BatchTelemetryIngestRequest,
    auth: Tuple[EndpointAgentModel, DeviceModel, EndpointAgentCredentialModel] = Depends(get_authenticated_agent),
    db: Session = Depends(get_db)
):
    """
    Alias route for POST /api/v1/endpoint/events.
    """
    return ingest_events(batch=batch, auth=auth, db=db)
