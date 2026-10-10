from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.services.dashboard_service import DashboardService
from backend.services.soc_dashboard_service import SocDashboardService
from backend.schemas.dashboard import (
    DashboardSummaryResponse,
    DashboardEmailListResponse
)
from backend.schemas.soc_overview import SocOverviewResponse

router = APIRouter(prefix="/api/dashboard", tags=["Analyst Dashboard"])


@router.get(
    "/overview",
    response_model=SocOverviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Get unified SOC Overview telemetry and priority queue",
    description="Returns Section 44 operational dashboard telemetry: Security Posture metrics, deterministic Priority Queue, Risk Distribution, Audit Activity, Threat Intelligence, and System/Fleet Health from authoritative persistent models."
)
def get_soc_overview(
    time_window: str = Query("30d", description="Time window for metric aggregation: 24h, 7d, 30d, all"),
    workspace_id: str = Query("default", description="Workspace tenant identifier"),
    limit_queue: int = Query(10, ge=1, le=50, description="Max priority queue items to return"),
    limit_activity: int = Query(15, ge=1, le=50, description="Max recent activity events to return"),
    db: Session = Depends(get_db)
):
    return SocDashboardService.get_overview(
        db=db,
        time_window=time_window,
        workspace_id=workspace_id,
        limit_queue=limit_queue,
        limit_activity=limit_activity,
    )



@router.get(
    "/summary",
    response_model=DashboardSummaryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get SOC analyst dashboard telemetry summary",
    description="Returns aggregated metrics, severity distribution, analysis trend, top suspicious domains, infrastructure countries, auth failure breakdown, recent cases, and recent email analyses based on real database records."
)
def get_dashboard_summary(
    days: int = Query(30, ge=1, le=365, description="Number of days to include in trend telemetry"),
    recent_limit: int = Query(5, ge=1, le=50, description="Max recent cases and emails to include"),
    db: Session = Depends(get_db)
):
    return DashboardService.get_summary(db=db, days=days, recent_limit=recent_limit)


@router.get(
    "/emails",
    response_model=DashboardEmailListResponse,
    status_code=status.HTTP_200_OK,
    summary="List analyzed emails with pagination",
    description="Returns paginated list of analyzed emails for SOC inspection."
)
def list_dashboard_emails(
    skip: int = Query(0, ge=0, description="Pagination offset"),
    limit: int = Query(20, ge=1, le=100, description="Page size"),
    db: Session = Depends(get_db)
):
    items, total = DashboardService.list_emails(db=db, skip=skip, limit=limit)
    return DashboardEmailListResponse(
        items=items,
        total=total,
        skip=skip,
        limit=limit
    )


@router.get(
    "/stream",
    summary="Stream SOC Overview Real-Time Telemetry (SSE - Section 46)",
    description="Provides real-time Server-Sent Events stream for SOC dashboard notifications, active analysis lifecycle events, and background job metrics in a tenant workspace.",
)
async def stream_dashboard_telemetry(
    workspace_id: str = Query("default", description="Workspace tenant identifier"),
    db: Session = Depends(get_db),
):
    import asyncio
    import json
    from fastapi.responses import StreamingResponse
    from backend.services.realtime_service import global_realtime_hub

    channel = f"workspace:{workspace_id.strip()}"

    async def event_generator():
        yield f"event: connected\ndata: {json.dumps({'workspace_id': workspace_id, 'channel': channel})}\n\n"

        queue = await global_realtime_hub.subscribe(channel)
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(queue.get(), timeout=15.0)
                    evt_type = msg.get("event_type") or "telemetry"
                    yield f"event: {str(evt_type).lower()}\ndata: {json.dumps(msg)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            await global_realtime_hub.unsubscribe(channel, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
