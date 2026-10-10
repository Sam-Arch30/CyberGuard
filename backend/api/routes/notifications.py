"""
Section 47: REST API Endpoints for Notifications & Alert Center.
Provides endpoints to list notifications, get fast unread counts, mark notifications read,
and acknowledge security alerts with strict workspace isolation.
"""
from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.notification import (
    NotificationListResponse,
    NotificationUnreadCountResponse,
    NotificationRead,
    NotificationAcknowledgeRequest,
)
from backend.services.notification_service import NotificationService

logger = logging.getLogger("cyberguard.api.notifications")

router = APIRouter(prefix="/api/notifications", tags=["Notifications & Alerts"])


@router.get(
    "",
    response_model=NotificationListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Notifications & Security Alerts",
    description="Returns paginated notifications and security alerts with category, status, and severity filters.",
)
def list_notifications(
    category: Optional[str] = Query(None, description="Filter: NOTIFICATION or SECURITY_ALERT"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter: UNREAD, READ, ACKNOWLEDGED"),
    severity: Optional[str] = Query(None, description="Filter: CRITICAL, HIGH, MEDIUM, LOW, INFO"),
    investigation_id: Optional[str] = Query(None, description="Filter by associated investigation ID"),
    limit: int = Query(30, ge=1, le=100, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    user_id = x_user.strip() if x_user else None

    return NotificationService.list_notifications(
        db=db,
        workspace_id=workspace,
        user_id=user_id,
        category=category,
        status=status_filter,
        severity=severity,
        investigation_id=investigation_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/unread-count",
    response_model=NotificationUnreadCountResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Unread Notifications Count",
    description="Returns efficient aggregate count of unread notifications and security alerts.",
)
def get_unread_count(
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    user_id = x_user.strip() if x_user else None

    return NotificationService.get_unread_count(
        db=db,
        workspace_id=workspace,
        user_id=user_id,
    )


@router.patch(
    "/{notification_id}/read",
    response_model=NotificationRead,
    status_code=status.HTTP_200_OK,
    summary="Mark Notification as Read",
    description="Marks a specific notification as READ and records timestamp.",
)
def mark_notification_read(
    notification_id: str,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    notif = NotificationService.mark_as_read(
        db=db,
        notification_id=notification_id,
        workspace_id=workspace,
    )
    if not notif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Notification '{notification_id}' not found in workspace.",
        )
    return notif


@router.post(
    "/read-all",
    status_code=status.HTTP_200_OK,
    summary="Mark All Notifications as Read",
    description="Batch marks all unread notifications in workspace as READ.",
)
def mark_all_notifications_read(
    category: Optional[str] = Query(None, description="Optional category filter: NOTIFICATION or SECURITY_ALERT"),
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    user_id = x_user.strip() if x_user else None

    count = NotificationService.mark_all_as_read(
        db=db,
        workspace_id=workspace,
        category=category,
        user_id=user_id,
    )
    return {
        "success": True,
        "count": count,
        "message": f"Marked {count} notifications as read.",
    }


@router.patch(
    "/{notification_id}/acknowledge",
    response_model=NotificationRead,
    status_code=status.HTTP_200_OK,
    summary="Acknowledge Security Alert",
    description="Acknowledges a security alert by analyst with timestamp and optional triage note.",
)
def acknowledge_security_alert(
    notification_id: str,
    body: Optional[NotificationAcknowledgeRequest] = None,
    x_workspace_id: Optional[str] = Header("default", alias="X-Workspace-ID"),
    x_user: Optional[str] = Header(None, alias="X-User"),
    workspace_id_query: Optional[str] = Query(None, alias="workspace_id"),
    db: Session = Depends(get_db),
):
    workspace = (workspace_id_query or x_workspace_id or "default").strip()
    analyst = (body.analyst_name if body and body.analyst_name else x_user) or "SOC Lead Analyst"
    note = body.note if body else None

    notif = NotificationService.acknowledge_alert(
        db=db,
        notification_id=notification_id,
        workspace_id=workspace,
        analyst_name=analyst,
        note=note,
    )
    if not notif:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security alert '{notification_id}' not found in workspace.",
        )
    return notif
