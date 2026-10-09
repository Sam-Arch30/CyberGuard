"""
FastAPI REST Routes for Section 30: LLM SOC Copilot.
Mounted under /api/v1/copilot.
Provides conversation management, grounded query processing,
context inspection, citations retrieval, and analyst feedback.
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.soc_copilot import (
    CreateConversationRequest,
    ConversationResponse,
    PostMessageRequest,
    MessageResponse,
    FeedbackRequest,
    FeedbackResponse,
    CopilotQueryRequest,
    CopilotCitation,
    CopilotModeEnum
)
from backend.services.soc_copilot_service import global_soc_copilot_service, SocCopilotService
from backend.db.models import SocCopilotMessageModel, SocCopilotConversationModel

router = APIRouter(prefix="/api/v1/copilot", tags=["Section 30: LLM SOC Copilot"])


@router.get(
    "/conversations",
    response_model=List[ConversationResponse],
    summary="List SOC Copilot Conversations"
)
def list_conversations(
    workspace_id: str = Query("default"),
    investigation_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=50),
    db: Session = Depends(get_db)
):
    convs = SocCopilotService.list_conversations(
        db=db,
        workspace_id=workspace_id,
        investigation_id=investigation_id,
        limit=limit
    )
    return [
        ConversationResponse(
            id=c.id,
            workspace_id=c.workspace_id,
            investigation_id=c.investigation_id,
            incident_id=c.incident_id,
            title=c.title,
            status=c.status,
            created_by=c.created_by,
            model_provider=c.model_provider,
            model_name=c.model_name,
            context_policy_version=c.context_policy_version,
            created_at=c.created_at,
            updated_at=c.updated_at,
            message_count=len(c.messages) if c.messages else 0
        )
        for c in convs
    ]


@router.post(
    "/conversations",
    response_model=ConversationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new SOC Copilot conversation"
)
def create_conversation(
    payload: CreateConversationRequest,
    db: Session = Depends(get_db)
):
    conv = SocCopilotService.create_conversation(
        db=db,
        workspace_id=payload.workspace_id,
        title=payload.title,
        investigation_id=payload.investigation_id,
        incident_id=payload.incident_id,
        model_provider=payload.model_provider,
        model_name=payload.model_name
    )
    return ConversationResponse(
        id=conv.id,
        workspace_id=conv.workspace_id,
        investigation_id=conv.investigation_id,
        incident_id=conv.incident_id,
        title=conv.title,
        status=conv.status,
        created_by=conv.created_by,
        model_provider=conv.model_provider,
        model_name=conv.model_name,
        context_policy_version=conv.context_policy_version,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
        message_count=0
    )


@router.get(
    "/conversations/{conversation_id}",
    response_model=ConversationResponse,
    summary="Get conversation details"
)
def get_conversation(
    conversation_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    conv = SocCopilotService.get_conversation(db, conversation_id, workspace_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found.")
    return ConversationResponse(
        id=conv.id,
        workspace_id=conv.workspace_id,
        investigation_id=conv.investigation_id,
        incident_id=conv.incident_id,
        title=conv.title,
        status=conv.status,
        created_by=conv.created_by,
        model_provider=conv.model_provider,
        model_name=conv.model_name,
        context_policy_version=conv.context_policy_version,
        created_at=conv.created_at,
        updated_at=conv.updated_at,
        message_count=len(conv.messages) if conv.messages else 0
    )


@router.get(
    "/conversations/{conversation_id}/messages",
    response_model=List[MessageResponse],
    summary="List messages in conversation"
)
def list_messages(
    conversation_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    conv = SocCopilotService.get_conversation(db, conversation_id, workspace_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found.")

    return [
        MessageResponse(
            id=m.id,
            conversation_id=m.conversation_id,
            role=m.role,
            content=m.content,
            message_type=m.message_type,
            context_snapshot_id=m.context_snapshot_id,
            model_provider=m.model_provider,
            model_name=m.model_name,
            prompt_version=m.prompt_version,
            claims=m.claims,
            citations=m.citations,
            uncertainties=m.uncertainties,
            hypotheses=m.hypotheses,
            next_steps=m.next_steps,
            tools_called=m.tools_called,
            latency_ms=m.latency_ms,
            created_at=m.created_at
        )
        for m in conv.messages
    ]


@router.post(
    "/conversations/{conversation_id}/messages",
    response_model=MessageResponse,
    summary="Post message and generate grounded Copilot response"
)
async def post_message_to_conversation(
    conversation_id: str,
    payload: PostMessageRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    try:
        assistant_msg = await global_soc_copilot_service.post_message(
            db=db,
            conversation_id=conversation_id,
            user_content=payload.content,
            mode=payload.mode,
            user_id=payload.user_id,
            workspace_id=workspace_id,
            target_scope_id=payload.target_scope_id or payload.investigation_id,
            email_payload=payload.email_payload
        )
        return MessageResponse(
            id=assistant_msg.id,
            conversation_id=assistant_msg.conversation_id,
            role=assistant_msg.role,
            content=assistant_msg.content,
            message_type=assistant_msg.message_type,
            context_snapshot_id=assistant_msg.context_snapshot_id,
            model_provider=assistant_msg.model_provider,
            model_name=assistant_msg.model_name,
            prompt_version=assistant_msg.prompt_version,
            claims=assistant_msg.claims,
            citations=assistant_msg.citations,
            uncertainties=assistant_msg.uncertainties,
            hypotheses=assistant_msg.hypotheses,
            next_steps=assistant_msg.next_steps,
            tools_called=assistant_msg.tools_called,
            latency_ms=assistant_msg.latency_ms,
            created_at=assistant_msg.created_at
        )
    except ValueError as val_err:
        raise HTTPException(status_code=404, detail=str(val_err))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Copilot query failed: {exc}")


@router.post(
    "/query",
    response_model=MessageResponse,
    summary="Standalone Copilot query (auto-creates conversation if omitted)"
)
async def query_copilot(
    payload: CopilotQueryRequest,
    db: Session = Depends(get_db)
):
    workspace_id = payload.workspace_id or "default"
    conv_id = payload.conversation_id

    if not conv_id:
        conv = SocCopilotService.create_conversation(
            db=db,
            workspace_id=workspace_id,
            investigation_id=payload.investigation_id,
            incident_id=payload.incident_id,
            title=f"Query: {payload.query[:30]}..."
        )
        conv_id = conv.id

    try:
        assistant_msg = await global_soc_copilot_service.post_message(
            db=db,
            conversation_id=conv_id,
            user_content=payload.query,
            mode=payload.mode,
            workspace_id=workspace_id,
            target_scope_id=payload.target_scope_id or payload.investigation_id,
            email_payload=payload.email_payload,
            compare_run_ids=payload.compare_run_ids
        )
        return MessageResponse(
            id=assistant_msg.id,
            conversation_id=assistant_msg.conversation_id,
            role=assistant_msg.role,
            content=assistant_msg.content,
            message_type=assistant_msg.message_type,
            context_snapshot_id=assistant_msg.context_snapshot_id,
            model_provider=assistant_msg.model_provider,
            model_name=assistant_msg.model_name,
            prompt_version=assistant_msg.prompt_version,
            claims=assistant_msg.claims,
            citations=assistant_msg.citations,
            uncertainties=assistant_msg.uncertainties,
            hypotheses=assistant_msg.hypotheses,
            next_steps=assistant_msg.next_steps,
            tools_called=assistant_msg.tools_called,
            latency_ms=assistant_msg.latency_ms,
            created_at=assistant_msg.created_at
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Copilot query failed: {exc}")


@router.get(
    "/context/{investigation_id}",
    summary="Inspect assembled context slice for an investigation"
)
def inspect_context(
    investigation_id: str,
    workspace_id: str = Query("default"),
    intent: str = Query("INCIDENT_SUMMARY"),
    db: Session = Depends(get_db)
):
    from backend.schemas.soc_copilot import IntentEnum
    try:
        chosen_intent = IntentEnum(intent)
    except Exception:
        chosen_intent = IntentEnum.INCIDENT_SUMMARY

    return SocCopilotService.assemble_grounded_context(
        db=db,
        workspace_id=workspace_id,
        intent=chosen_intent,
        target_scope_id=investigation_id
    )


@router.get(
    "/messages/{message_id}/citations",
    response_model=List[CopilotCitation],
    summary="Get verified citations for a Copilot message"
)
def get_message_citations(
    message_id: str,
    db: Session = Depends(get_db)
):
    msg = db.query(SocCopilotMessageModel).filter(SocCopilotMessageModel.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message not found.")
    return [CopilotCitation(**c) for c in msg.citations]


@router.post(
    "/messages/{message_id}/feedback",
    response_model=FeedbackResponse,
    summary="Submit analyst feedback for a message"
)
def submit_feedback(
    message_id: str,
    payload: FeedbackRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db)
):
    try:
        fb = SocCopilotService.record_feedback(
            db=db,
            message_id=message_id,
            rating=payload.rating,
            feedback_text=payload.feedback_text,
            claim_incorrect=payload.claim_incorrect,
            citation_incorrect=payload.citation_incorrect,
            insufficient_context=payload.insufficient_context,
            analyst_id=payload.analyst_id,
            workspace_id=workspace_id
        )
        return FeedbackResponse(
            id=fb.id,
            message_id=fb.message_id,
            conversation_id=fb.conversation_id,
            rating=fb.rating,
            analyst_id=fb.analyst_id,
            feedback_text=fb.feedback_text,
            created_at=fb.created_at
        )
    except ValueError as ve:
        raise HTTPException(status_code=404, detail=str(ve))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Feedback recording failed: {exc}")
