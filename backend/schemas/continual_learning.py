"""
Controlled Continual-Learning Pipeline Schemas (Section 24).
Provides data contracts, lifecycle state enums, learning candidate models,
dataset versioning schemas, model registry contracts, evaluation metrics,
and regression gate definitions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from backend.services.log_sanitizer import sanitize_log_text


# ============================================================================
# 1. CONTROLLED ENUMS
# ============================================================================

class CandidateEligibilityStatus(str, Enum):
    ELIGIBLE = "ELIGIBLE"
    INELIGIBLE = "INELIGIBLE"
    EXCLUDED = "EXCLUDED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"


class CandidateReviewStatus(str, Enum):
    PENDING = "PENDING"
    REVIEWED = "REVIEWED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"


class LabelSource(str, Enum):
    ANALYST_VERIFIED = "ANALYST_VERIFIED"
    RULE_VERIFIED = "RULE_VERIFIED"
    MULTI_SOURCE_CORRELATED = "MULTI_SOURCE_CORRELATED"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    MODEL_PSEUDO_LABEL = "MODEL_PSEUDO_LABEL"
    SYSTEM_DERIVED = "SYSTEM_DERIVED"


class DatasetValidationStatus(str, Enum):
    COLLECTING = "COLLECTING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    ARCHIVED = "ARCHIVED"


class TrainingJobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    REJECTED = "REJECTED"


class ModelLifecycleStatus(str, Enum):
    CANDIDATE = "CANDIDATE"
    APPROVED = "APPROVED"
    STAGED = "STAGED"
    PRODUCTION = "PRODUCTION"
    ROLLED_BACK = "ROLLED_BACK"
    ARCHIVED = "ARCHIVED"
    REJECTED = "REJECTED"


# ============================================================================
# 2. PRIVACY & SANITIZATION HELPER
# ============================================================================

SENSITIVE_TOKENS = {
    "password", "secret", "token", "auth", "credential", "cookie",
    "api_key", "apikey", "bearer", "private_key", "session_key", "jwt"
}


def sanitize_training_payload(payload: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively redacts secrets and credentials from training candidate payloads
    before persistence or inclusion in datasets (Section 24 Privacy & Security).
    """
    if not payload or not isinstance(payload, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for k, v in payload.items():
        k_lower = str(k).lower()
        if any(sub in k_lower for sub in SENSITIVE_TOKENS):
            sanitized[k] = "[REDACTED_SECRET]"
            continue

        if isinstance(v, str):
            sanitized[k] = sanitize_log_text(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_training_payload(v)
        elif isinstance(v, list):
            clean_list = []
            for item in v:
                if isinstance(item, dict):
                    clean_list.append(sanitize_training_payload(item))
                elif isinstance(item, str):
                    clean_list.append(sanitize_log_text(item))
                else:
                    clean_list.append(item)
            sanitized[k] = clean_list
        else:
            sanitized[k] = v

    return sanitized


# ============================================================================
# 3. LEARNING CANDIDATE SCHEMAS
# ============================================================================

class LearningCandidateBase(BaseModel):
    source_type: str = Field(..., description="E.g. THREAT_MEMORY, INCIDENT, ANALYSIS_RUN, EXTERNAL_FEED")
    source_reference: str = Field(..., description="Identifier pointing to canonical record or memory observation")
    feature_reference: Optional[str] = Field(None, description="Feature vector reference or fingerprint")
    text_content: Optional[str] = Field(None, description="Raw text, subject+body, or representation (sanitized)")
    label: str = Field(..., description="Target label e.g. phishing, legitimate, malicious, benign")
    label_source: LabelSource = Field(default=LabelSource.ANALYST_VERIFIED)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    is_hard_negative: bool = Field(default=False, description="Flag indicating sample is a validated false positive / hard negative")
    incident_id: Optional[str] = None
    campaign_id: Optional[str] = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_payload: Dict[str, Any] = Field(default_factory=dict)


class LearningCandidateCreate(LearningCandidateBase):
    workspace_id: str = "default"


class CandidateReviewRequest(BaseModel):
    review_status: CandidateReviewStatus = CandidateReviewStatus.ACCEPTED
    reviewer: str = Field(..., description="Analyst identifier or role")
    reason: str = Field(..., min_length=3, description="Rationale for acceptance or exclusion")
    override_label: Optional[str] = None


class LearningCandidate(LearningCandidateBase):
    id: str
    workspace_id: str
    eligibility_status: CandidateEligibilityStatus
    ineligibility_reason: Optional[str] = None
    review_status: CandidateReviewStatus
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_reason: Optional[str] = None
    dataset_version: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ============================================================================
# 4. DATASET VERSIONING SCHEMAS
# ============================================================================

class DatasetBuildRequest(BaseModel):
    workspace_id: str = "default"
    feature_schema_version: str = "1.0.0"
    label_policy_version: str = "1.0.0"
    include_hard_negatives: bool = True
    max_samples: int = Field(default=2000, ge=10, le=50000)
    train_split_ratio: float = Field(default=0.70, ge=0.50, le=0.90)
    val_split_ratio: float = Field(default=0.15, ge=0.05, le=0.30)
    test_split_ratio: float = Field(default=0.15, ge=0.05, le=0.30)
    stratify_by_time: bool = Field(default=True, description="Strict temporal split preventing future lookahead leakage")
    group_by_campaign: bool = Field(default=True, description="Group by campaign/incident to avoid cross-split campaign leakage")


class LearningDataset(BaseModel):
    id: str
    workspace_id: str
    version: str = Field(..., description="Semantic dataset version e.g. D-001, D-025")
    feature_schema_version: str
    label_policy_version: str
    sample_count: int
    malicious_count: int
    benign_count: int
    hard_negative_count: int
    source_distribution: Dict[str, int] = Field(default_factory=dict)
    time_range_start: Optional[datetime] = None
    time_range_end: Optional[datetime] = None
    quality_score: float = 1.0
    validation_status: DatasetValidationStatus
    validation_errors: List[str] = Field(default_factory=list)
    manifest_checksum: str = Field(..., description="Cryptographic SHA-256 ensuring dataset immutability")
    created_by: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ============================================================================
# 5. TRAINING JOB & MODEL REGISTRY SCHEMAS
# ============================================================================

class TrainingJobCreate(BaseModel):
    workspace_id: str = "default"
    model_type: str = "PHISHING_CLASSIFIER"
    dataset_version: str
    training_config: Dict[str, Any] = Field(
        default_factory=lambda: {
            "max_features": 5000,
            "ngram_range": [1, 2],
            "C": 1.5,
            "class_weight": "balanced",
            "solver": "liblinear",
            "random_state": 42
        }
    )


class TrainingJob(BaseModel):
    id: str
    workspace_id: str
    model_type: str
    dataset_version: str
    status: TrainingJobStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    base_model_version: Optional[str] = None
    candidate_model_version: Optional[str] = None
    training_config: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ModelEvaluationMetrics(BaseModel):
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    false_negative_rate: float
    critical_threat_recall: float
    sample_count: int
    confusion_matrix: Dict[str, int] = Field(default_factory=dict)


class RegressionGateResult(BaseModel):
    gate_name: str
    passed: bool
    candidate_metric: float
    production_metric: float
    threshold: float
    message: str


class BaselineComparisonResult(BaseModel):
    passed_all_gates: bool
    candidate_metrics: ModelEvaluationMetrics
    production_metrics: Optional[ModelEvaluationMetrics] = None
    gates: List[RegressionGateResult] = Field(default_factory=list)
    recommendation: str


class ModelApprovalRequest(BaseModel):
    reviewer: str = Field(..., description="Analyst identifier")
    reason: str = Field(..., min_length=3, description="Approval rationale based on evaluation metrics")


class ModelActionRequest(BaseModel):
    reviewer: str = Field(..., description="Analyst or administrator identifier")
    reason: str = Field(..., min_length=3, description="Operational justification")


class ThreatMemoryIngestRequest(BaseModel):
    decision_id: str
    workspace_id: str = "default"


class ModelRollbackRequest(BaseModel):
    reviewer: str = Field(..., description="Analyst identifier")
    reason: str = Field(..., min_length=3, description="Rollback justification (e.g. production FPR spike)")
    target_version: Optional[str] = None


class RegisteredModel(BaseModel):
    id: str
    workspace_id: str
    model_type: str
    version: str
    dataset_version: str
    feature_schema_version: str
    training_job_id: Optional[str] = None
    status: ModelLifecycleStatus
    metrics: Dict[str, Any] = Field(default_factory=dict)
    baseline_comparison: Dict[str, Any] = Field(default_factory=dict)
    artifact_path: str
    artifact_checksum: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    staged_at: Optional[datetime] = None
    promoted_at: Optional[datetime] = None
    rolled_back_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ============================================================================
# 6. MODEL CARD & OBSERVABILITY SCHEMAS
# ============================================================================

class ModelCard(BaseModel):
    model_id: str
    model_type: str
    version: str
    status: ModelLifecycleStatus
    dataset_version: str
    feature_schema_version: str
    training_timestamp: Optional[datetime] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)
    baseline_comparison: Dict[str, Any] = Field(default_factory=dict)
    known_regressions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    approval_metadata: Dict[str, Any] = Field(default_factory=dict)
    checksum: str


class DriftReport(BaseModel):
    workspace_id: str
    model_type: str
    active_version: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sample_window_days: int = 30
    drift_detected: bool = False
    drift_signals: List[str] = Field(default_factory=list)
    false_positive_rate_trend: float = 0.0
    analyst_disagreement_rate: float = 0.0
    novel_pattern_rate: float = 0.0
    recommendation: str


class LearningDashboardStats(BaseModel):
    workspace_id: str
    total_candidates: int
    eligible_candidates: int
    pending_review_candidates: int
    hard_negatives: int
    total_datasets: int
    active_dataset_version: Optional[str] = None
    production_model_version: Optional[str] = None
    staged_model_version: Optional[str] = None
    total_training_jobs: int
    candidate_models_count: int
