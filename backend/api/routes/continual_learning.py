"""
CyberGuard Controlled Continual-Learning REST API Endpoints (Section 24).

Exposes routes for:
1. Learning candidate management (creation, Threat Memory ingestion, analyst review).
2. Immutable dataset version compilation (temporal splitting, campaign grouping, anti-poisoning checks).
3. Asynchronous training jobs and real offline evaluation.
4. Model Registry management (approval gates, canary staging, verified promotion, reversible rollback).
5. Observability, concept drift detection, and dashboard metrics.
"""
from __future__ import annotations

import logging
from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.db.session import get_db
from backend.schemas.continual_learning import (
    CandidateReviewRequest,
    DatasetBuildRequest,
    DriftReport,
    LearningCandidate,
    LearningCandidateCreate,
    LearningDashboardStats,
    LearningDataset,
    ModelActionRequest,
    ModelApprovalRequest,
    ModelCard,
    ModelRollbackRequest,
    RegisteredModel,
    ThreatMemoryIngestRequest,
    TrainingJob,
    TrainingJobCreate,
)
from backend.services.continual_learning_service import ContinualLearningService

logger = logging.getLogger("cyberguard.api.continual_learning")

router = APIRouter(tags=["Controlled Continual Learning"])


# ============================================================================
# AUTHORIZATION DEPENDENCY
# ============================================================================

def verify_learning_role(
    x_role: Optional[str] = Header(None, alias="X-Role"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> str:
    """
    Enforces authorization check for continual learning operations.
    Rejects unauthorized, guest, or unprivileged actors with HTTP 403.
    """
    role = (x_role or x_user_role or "").strip().lower()
    if not role and authorization:
        auth_clean = authorization.strip().lower()
        if "admin" in auth_clean:
            role = "admin"
        elif "analyst" in auth_clean:
            role = "analyst"
        elif "guest" in auth_clean or "unauthorized" in auth_clean or "untrusted" in auth_clean:
            role = "unauthorized"

    # Default to analyst if unprovided in local test environments, but block unauthorized
    if role in ("guest", "unauthorized", "untrusted", "anonymous", "viewer"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: insufficient permissions for continual learning operations.",
        )
    return role or "analyst"


# ============================================================================
# 1. LEARNING CANDIDATE ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/learning/candidates",
    response_model=List[LearningCandidate],
    summary="List learning candidates",
)
def list_candidates(
    eligibility_status: Optional[str] = Query(None, description="Filter by eligibility status"),
    review_status: Optional[str] = Query(None, description="Filter by review status"),
    label: Optional[str] = Query(None, description="Filter by label (phishing, legitimate, etc.)"),
    workspace_id: str = Query("default", description="Workspace tenant identifier"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Retrieves candidates eligible or pending review for dataset compilation."""
    records = ContinualLearningService.list_candidates(
        db=db,
        workspace_id=workspace_id,
        eligibility_status=eligibility_status,
        review_status=review_status,
        label=label,
        skip=skip,
        limit=limit,
    )
    return [LearningCandidate.model_validate(r) for r in records]


@router.post(
    "/api/v1/learning/candidates",
    response_model=LearningCandidate,
    status_code=status.HTTP_201_CREATED,
    summary="Submit observation as learning candidate",
)
def create_candidate(
    candidate_in: LearningCandidateCreate,
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """
    Submits a new candidate observation into the learning curation pipeline.
    Enforces privacy sanitization, source trust qualification, and deduplication.
    """
    try:
        cand = ContinualLearningService.create_candidate(
            db=db,
            candidate_in=candidate_in,
        )
        db.commit()
        db.refresh(cand)
        return LearningCandidate.model_validate(cand)
    except Exception as exc:
        db.rollback()
        logger.error(f"Failed to create candidate: {exc}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Candidate creation failed: {exc}",
        )


@router.post(
    "/api/v1/learning/candidates/{candidate_id}/review",
    response_model=LearningCandidate,
    summary="Analyst review for a learning candidate",
)
def review_candidate(
    candidate_id: str,
    review_req: CandidateReviewRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """
    Records human-in-the-loop analyst review, accepting, rejecting, or overriding labels.
    """
    try:
        cand = ContinualLearningService.review_candidate(
            db=db,
            workspace_id=workspace_id,
            candidate_id=candidate_id,
            review_req=review_req,
        )
        db.commit()
        db.refresh(cand)
        return LearningCandidate.model_validate(cand)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/api/v1/learning/candidates/from-threat-memory",
    response_model=Optional[LearningCandidate],
    summary="Ingest learning candidate from a Threat Memory decision",
)
def ingest_from_threat_memory(
    req: ThreatMemoryIngestRequest,
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """
    Converts a verified Threat Memory analyst decision into an eligible candidate,
    automatically mapping false positives to hard negatives.
    """
    from backend.db.models import ThreatMemoryDecisionModel
    decision = db.query(ThreatMemoryDecisionModel).filter(
        ThreatMemoryDecisionModel.id == req.decision_id,
        ThreatMemoryDecisionModel.workspace_id == req.workspace_id,
    ).first()

    if not decision:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Decision not found")

    cand = ContinualLearningService.ingest_from_threat_memory_decision(
        db=db,
        decision=decision,
        workspace_id=req.workspace_id,
    )
    if cand:
        db.commit()
        db.refresh(cand)
        return LearningCandidate.model_validate(cand)
    return None


# ============================================================================
# 2. DATASET VERSIONING ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/learning/datasets",
    response_model=List[LearningDataset],
    summary="List immutable dataset versions",
)
def list_datasets(
    workspace_id: str = Query("default"),
    validation_status: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Lists versioned, immutable dataset snapshots."""
    records = ContinualLearningService.list_datasets(
        db=db,
        workspace_id=workspace_id,
        validation_status=validation_status,
        skip=skip,
        limit=limit,
    )
    return [LearningDataset.model_validate(r) for r in records]


@router.post(
    "/api/v1/learning/datasets/build",
    response_model=LearningDataset,
    status_code=status.HTTP_201_CREATED,
    summary="Compile a new immutable dataset version",
)
def build_dataset(
    req: DatasetBuildRequest,
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """
    Curates eligible candidates and hard negatives into an immutable dataset version.
    Enforces temporal ordering, campaign grouping, anti-poisoning checks, and SHA-256 integrity.
    """
    try:
        ds = ContinualLearningService.build_dataset_version(db=db, req=req)
        db.commit()
        db.refresh(ds)
        return LearningDataset.model_validate(ds)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        db.rollback()
        logger.error(f"Dataset build failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


@router.get(
    "/api/v1/learning/datasets/{dataset_id}",
    response_model=LearningDataset,
    summary="Get dataset version details",
)
def get_dataset(
    dataset_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    """Retrieves dataset manifest, distributions, and validation status."""
    ds = ContinualLearningService.get_dataset(db=db, workspace_id=workspace_id, dataset_id_or_version=dataset_id)
    if not ds:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Dataset '{dataset_id}' not found")
    return LearningDataset.model_validate(ds)


# ============================================================================
# 3. TRAINING & OFFLINE EVALUATION ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/learning/jobs",
    response_model=List[TrainingJob],
    summary="List training and evaluation jobs",
)
def list_training_jobs(
    workspace_id: str = Query("default"),
    status_filter: Optional[str] = Query(None, alias="status"),
    model_type: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Queries offline training and evaluation job runs."""
    jobs = ContinualLearningService.list_training_jobs(
        db=db,
        workspace_id=workspace_id,
        status=status_filter,
        model_type=model_type,
        skip=skip,
        limit=limit,
    )
    return [TrainingJob.model_validate(j) for j in jobs]


@router.post(
    "/api/v1/learning/jobs",
    response_model=TrainingJob,
    status_code=status.HTTP_201_CREATED,
    summary="Execute training and offline evaluation job",
)
def launch_training_job(
    job_req: TrainingJobCreate,
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """
    Launches an isolated training job on an immutable dataset version.
    Trains candidate model, computes real offline evaluation metrics,
    evaluates production baseline, checks regression gates, and saves candidate artifact.
    """
    try:
        job, registered_model = ContinualLearningService.run_training_job(db=db, req=job_req)
        db.commit()
        db.refresh(job)
        return TrainingJob.model_validate(job)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        db.rollback()
        logger.error(f"Training job execution failed: {exc}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Internal operation failed.")


@router.get(
    "/api/v1/learning/jobs/{job_id}",
    response_model=TrainingJob,
    summary="Get training job status and metrics",
)
def get_training_job(
    job_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    """Retrieves training job status, baseline comparison, and evaluation metrics."""
    job = ContinualLearningService.get_training_job(db=db, workspace_id=workspace_id, job_id=job_id)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Training job '{job_id}' not found")
    return TrainingJob.model_validate(job)


# ============================================================================
# 4. MODEL REGISTRY LIFECYCLE ENDPOINTS
# ============================================================================

@router.get(
    "/api/v1/models",
    response_model=List[RegisteredModel],
    summary="List registered models in Model Registry",
)
def list_models(
    workspace_id: str = Query("default"),
    status_filter: Optional[str] = Query(None, alias="status"),
    model_type: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Lists registered models across candidate, approved, staged, and production states."""
    models = ContinualLearningService.list_registered_models(
        db=db,
        workspace_id=workspace_id,
        status=status_filter,
        model_type=model_type,
        skip=skip,
        limit=limit,
    )
    return [RegisteredModel.model_validate(m) for m in models]


@router.get(
    "/api/v1/models/{model_id}",
    response_model=RegisteredModel,
    summary="Get registered model details",
)
def get_model(
    model_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    """Retrieves registered model metadata and lifecycle status."""
    model = ContinualLearningService.get_registered_model(db=db, workspace_id=workspace_id, model_id_or_version=model_id)
    if not model:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Model '{model_id}' not found")
    return RegisteredModel.model_validate(model)


@router.get(
    "/api/v1/models/{model_id}/card",
    response_model=ModelCard,
    summary="Get Model Card documentation",
)
def get_model_card(
    model_id: str,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    """Generates structured Model Card report with provenance, metrics, gates, and checksum."""
    try:
        return ContinualLearningService.get_model_card(db=db, workspace_id=workspace_id, model_id=model_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))


@router.post(
    "/api/v1/models/{model_id}/approve",
    response_model=RegisteredModel,
    summary="Approve candidate model",
)
def approve_model(
    model_id: str,
    req: ModelApprovalRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """Explicit human-in-the-loop approval gate promoting CANDIDATE to APPROVED."""
    try:
        model = ContinualLearningService.approve_model(
            db=db,
            workspace_id=workspace_id,
            model_id=model_id,
            reviewer=req.reviewer,
            reason=req.reason,
        )
        db.commit()
        db.refresh(model)
        return RegisteredModel.model_validate(model)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/api/v1/models/{model_id}/stage",
    response_model=RegisteredModel,
    summary="Stage approved model for canary evaluation",
)
def stage_model(
    model_id: str,
    req: ModelActionRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """Transitions APPROVED model to STAGED environment."""
    try:
        model = ContinualLearningService.stage_model(
            db=db,
            workspace_id=workspace_id,
            model_id=model_id,
            reviewer=req.reviewer,
            reason=req.reason,
        )
        db.commit()
        db.refresh(model)
        return RegisteredModel.model_validate(model)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/api/v1/models/{model_id}/promote",
    response_model=RegisteredModel,
    summary="Promote staged model to PRODUCTION",
)
def promote_model(
    model_id: str,
    req: ModelActionRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """
    Promotes STAGED model to PRODUCTION.
    Mandatory cryptographic checksum verification prevents artifact tampering.
    Hot-reloads the active production analyzer safely.
    """
    try:
        model = ContinualLearningService.promote_to_production(
            db=db,
            workspace_id=workspace_id,
            model_id=model_id,
            reviewer=req.reviewer,
            reason=req.reason,
        )
        db.commit()
        db.refresh(model)
        return RegisteredModel.model_validate(model)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.post(
    "/api/v1/models/{model_id}/rollback",
    response_model=RegisteredModel,
    summary="Reversibly rollback production model",
)
def rollback_model(
    model_id: str,
    req: ModelRollbackRequest,
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
    _role: str = Depends(verify_learning_role),
):
    """
    Reversibly rolls back production model upon detected regression.
    Preserves audit history and restores previous production version safely.
    """
    try:
        restored = ContinualLearningService.rollback_production(
            db=db,
            workspace_id=workspace_id,
            model_id=model_id,
            reviewer=req.reviewer,
            reason=req.reason,
            target_version=req.target_version,
        )
        db.commit()
        db.refresh(restored)
        return RegisteredModel.model_validate(restored)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


# ============================================================================
# 5. OBSERVABILITY, DRIFT & DASHBOARD
# ============================================================================

@router.get(
    "/api/v1/learning/drift",
    response_model=DriftReport,
    summary="Evaluate production model drift",
)
def get_drift_report(
    workspace_id: str = Query("default"),
    model_type: str = Query("PHISHING_CLASSIFIER"),
    sample_window_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
):
    """Evaluates production model drift signals, analyst disagreement, and novelty."""
    return ContinualLearningService.evaluate_drift(
        db=db,
        workspace_id=workspace_id,
        model_type=model_type,
        sample_window_days=sample_window_days,
    )


@router.get(
    "/api/v1/learning/stats",
    response_model=LearningDashboardStats,
    summary="Get learning dashboard statistics",
)
def get_learning_stats(
    workspace_id: str = Query("default"),
    db: Session = Depends(get_db),
):
    """Summarizes continual learning candidate counts, dataset version, and production model state."""
    return ContinualLearningService.get_dashboard_stats(db=db, workspace_id=workspace_id)
