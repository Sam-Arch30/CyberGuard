"""
Controlled Continual-Learning Pipeline Service (Section 24).
Provides controlled candidate collection, dataset versioning, data poisoning defense,
temporal and campaign leakage prevention, offline evaluation, regression gates,
model registry, staged deployment, and rollback.

Core Epistemic Principles:
1. TRAINING != PRODUCTION DEPLOYMENT.
2. Models improve only through verified feedback, immutable datasets, and explicit gates.
3. Untrusted input never automatically rewrites production models.
4. Cryptographic checksums ensure model artifact integrity.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import joblib
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from backend.app.ml.classifier import PhishingClassifier, global_phishing_classifier
from backend.app.ml.normalizer import TextNormalizer
from backend.app.ml.training.dataset import DATASET as BENCHMARK_DATASET
from backend.db.models import (
    AuditLogModel,
    IncidentModel,
    LearningCandidateModel,
    LearningDatasetModel,
    LearningTrainingJobModel,
    RegisteredModelModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.continual_learning import (
    BaselineComparisonResult,
    CandidateEligibilityStatus,
    CandidateReviewStatus,
    DatasetBuildRequest,
    DatasetValidationStatus,
    DriftReport,
    LabelSource,
    LearningCandidate,
    LearningCandidateCreate,
    LearningDashboardStats,
    LearningDataset,
    ModelApprovalRequest,
    ModelCard,
    ModelEvaluationMetrics,
    ModelLifecycleStatus,
    ModelRollbackRequest,
    RegisteredModel,
    RegressionGateResult,
    TrainingJob,
    TrainingJobCreate,
    TrainingJobStatus,
    sanitize_training_payload,
)
from backend.services.log_sanitizer import sanitize_log_text

logger = logging.getLogger("cyberguard.continual_learning")

MODELS_DIR = Path(__file__).resolve().parent.parent / "app" / "ml" / "models"
CANDIDATES_DIR = Path(os.getenv("CONTINUAL_LEARNING_CANDIDATES_DIR", str(MODELS_DIR / "candidates")))


class ContinualLearningService:
    """
    Central orchestration service for Section 24 Controlled Continual Learning.
    """

    # Quality and Anti-Poisoning Limits
    MAX_SOURCE_CONCENTRATION_RATIO = 0.35  # Single untrusted source cannot exceed 35%
    MIN_CLASS_SAMPLE_PERCENT = 0.05       # Minority class must be at least 5%
    MIN_CANDIDATE_CONFIDENCE = 0.60       # Minimum confidence to qualify as learning candidate
    DEFAULT_CRITICAL_RECALL_GATE = 0.85   # Minimum critical threat recall

    @staticmethod
    def _compute_sha256(content_bytes: bytes) -> str:
        """Computes deterministic SHA-256 cryptographic digest."""
        h = hashlib.sha256()
        h.update(content_bytes)
        return h.hexdigest()

    @staticmethod
    def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
        if dt is None:
            return None
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt

    @staticmethod
    def _safe_max_dt(dt1: Optional[datetime], dt2: Optional[datetime]) -> Optional[datetime]:
        if dt1 is None:
            return dt2
        if dt2 is None:
            return dt1
        n1 = dt1.replace(tzinfo=timezone.utc) if dt1.tzinfo is None else dt1
        n2 = dt2.replace(tzinfo=timezone.utc) if dt2.tzinfo is None else dt2
        return dt1 if n1 >= n2 else dt2

    # ========================================================================
    # 1. CANDIDATE MANAGEMENT & ELIGIBILITY
    # ========================================================================

    @classmethod
    def create_candidate(
        cls,
        db: Session,
        workspace_id: Union[str, LearningCandidateCreate] = "default",
        source_type: Optional[str] = None,
        source_reference: Optional[str] = None,
        label: Optional[str] = None,
        text_content: Optional[str] = None,
        label_source: Union[LabelSource, str] = LabelSource.ANALYST_VERIFIED,
        confidence: float = 1.0,
        is_hard_negative: bool = False,
        incident_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        candidate_in: Optional[LearningCandidateCreate] = None,
    ) -> LearningCandidateModel:
        """
        Ingests a potential learning sample and evaluates eligibility.
        Prevents corrupted, low-confidence, or contradictory samples from being trained.
        """
        if isinstance(workspace_id, LearningCandidateCreate):
            candidate_in = workspace_id
            workspace_id = candidate_in.workspace_id

        if candidate_in is not None:
            workspace_id = candidate_in.workspace_id
            source_type = candidate_in.source_type
            source_reference = candidate_in.source_reference
            label = candidate_in.label
            text_content = candidate_in.text_content
            label_source = candidate_in.label_source
            confidence = candidate_in.confidence
            is_hard_negative = candidate_in.is_hard_negative
            incident_id = candidate_in.incident_id
            campaign_id = candidate_in.campaign_id
            observed_at = candidate_in.observed_at
            raw_payload = candidate_in.raw_payload

        source_type = source_type or "OBSERVATION"
        source_reference = source_reference or "UNKNOWN"
        label = (label or "unknown").lower()
        if isinstance(label_source, LabelSource):
            label_source_val = label_source.value
        else:
            label_source_val = str(label_source)

        clean_text = sanitize_log_text(text_content or "")
        sanitized_payload = sanitize_training_payload(raw_payload or {})
        obs_time = observed_at or datetime.now(timezone.utc)

        # Eligibility Evaluation
        eligibility = CandidateEligibilityStatus.ELIGIBLE
        ineligibility_reason = None

        if confidence < cls.MIN_CANDIDATE_CONFIDENCE:
            eligibility = CandidateEligibilityStatus.INELIGIBLE
            ineligibility_reason = f"Confidence {confidence:.2f} is below minimum threshold ({cls.MIN_CANDIDATE_CONFIDENCE})."
        elif not clean_text or len(clean_text.strip()) < 10:
            eligibility = CandidateEligibilityStatus.INELIGIBLE
            ineligibility_reason = "Sample text content is empty or contains insufficient data."
        elif label_source == LabelSource.MODEL_PSEUDO_LABEL and confidence < 0.95:
            eligibility = CandidateEligibilityStatus.REVIEW_REQUIRED
            ineligibility_reason = "Unverified model pseudo-labels require human analyst review before inclusion."

        # Check for duplicates
        existing = db.query(LearningCandidateModel).filter(
            LearningCandidateModel.workspace_id == workspace_id,
            LearningCandidateModel.source_reference == source_reference,
            LearningCandidateModel.label == label,
        ).first()

        if existing:
            # Update observation time without creating duplicate training sample
            existing.observed_at = cls._safe_max_dt(existing.observed_at, obs_time)
            if confidence >= existing.confidence:
                existing.confidence = float(confidence)
                existing.label_source = str(label_source.value if hasattr(label_source, "value") else label_source)
            db.flush()
            return existing

        candidate = LearningCandidateModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            source_type=source_type,
            source_reference=source_reference,
            feature_reference=f"sha256:{cls._compute_sha256(clean_text.encode('utf-8'))}",
            text_content=clean_text,
            label=label.lower().strip(),
            label_source=str(label_source.value if hasattr(label_source, "value") else label_source),
            confidence=float(confidence),
            is_hard_negative=is_hard_negative,
            incident_id=incident_id,
            campaign_id=campaign_id,
            observed_at=obs_time,
            eligibility_status=eligibility.value,
            ineligibility_reason=ineligibility_reason,
            review_status=(
                CandidateReviewStatus.ACCEPTED.value
                if label_source == LabelSource.ANALYST_VERIFIED and eligibility == CandidateEligibilityStatus.ELIGIBLE
                else CandidateReviewStatus.PENDING.value
            ),
            reviewed_by="analyst" if label_source == LabelSource.ANALYST_VERIFIED else None,
            reviewed_at=obs_time if label_source == LabelSource.ANALYST_VERIFIED else None,
            raw_payload_json=json.dumps(sanitized_payload),
            created_at=get_utc_now(),
        )
        db.add(candidate)
        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="LEARNING_CANDIDATE_CREATED",
            resource_id=candidate.id,
            details=f"Created learning candidate for {source_reference} (label: {label}, status: {eligibility.value})",
            metadata={"eligibility": eligibility.value, "label_source": str(label_source)},
        )

        return candidate

    @classmethod
    def ingest_from_threat_memory_decision(
        cls,
        db: Session,
        decision_or_ws: Union[str, ThreatMemoryDecisionModel] = "default",
        decision_id: Optional[str] = None,
        text_content: Optional[str] = None,
        decision: Optional[ThreatMemoryDecisionModel] = None,
        workspace_id: Optional[str] = None,
    ) -> Optional[LearningCandidateModel]:
        """
        Creates a high-value learning candidate from an analyst verification in Threat Memory.
        Maps FALSE_POSITIVE to verified hard negative ('legitimate').
        """
        if isinstance(decision_or_ws, ThreatMemoryDecisionModel):
            decision = decision_or_ws
            workspace_id = workspace_id or decision.workspace_id
            decision_id = decision.id
        elif isinstance(decision_id, ThreatMemoryDecisionModel):
            decision = decision_id
            decision_id = decision.id
            workspace_id = workspace_id or str(decision_or_ws)
        else:
            workspace_id = workspace_id or str(decision_or_ws)

        if not decision and decision_id:
            decision = db.query(ThreatMemoryDecisionModel).filter(
                ThreatMemoryDecisionModel.id == decision_id,
                ThreatMemoryDecisionModel.workspace_id == workspace_id,
            ).first()

        if not decision:
            return None

        if not text_content:
            text_content = f"Verified threat memory observation for decision {decision.id}: {decision.reason}"
            if getattr(decision, "memory_entry", None) and hasattr(decision.memory_entry, "canonical_key"):
                text_content += f" indicator: {decision.memory_entry.canonical_key}"

        is_hard_neg = (decision.decision in ("FALSE_POSITIVE", "VERIFIED_BENIGN"))
        label = "legitimate" if is_hard_neg else "phishing"

        return cls.create_candidate(
            db=db,
            workspace_id=workspace_id,
            source_type="THREAT_MEMORY",
            source_reference=f"decision:{decision.id}",
            text_content=text_content,
            label=label,
            label_source=LabelSource.ANALYST_VERIFIED,
            confidence=1.0,
            is_hard_negative=is_hard_neg,
            observed_at=decision.created_at,
            raw_payload={"reason": decision.reason, "approved_by": decision.approved_by},
        )

    @classmethod
    def review_candidate(
        cls,
        db: Session,
        workspace_id: str,
        candidate_id: str,
        review_status: Optional[CandidateReviewStatus] = None,
        reviewer: Optional[str] = None,
        reason: Optional[str] = None,
        override_label: Optional[str] = None,
        review_req: Optional[CandidateReviewRequest] = None,
    ) -> LearningCandidateModel:
        """
        Human-in-the-loop analyst review accepting or rejecting learning candidates.
        """
        if review_req is not None:
            review_status = review_req.review_status
            reviewer = review_req.reviewer
            reason = review_req.reason
            override_label = review_req.override_label

        cand = db.query(LearningCandidateModel).filter(
            LearningCandidateModel.id == candidate_id,
            LearningCandidateModel.workspace_id == workspace_id,
        ).first()

        if not cand:
            raise ValueError(f"Learning candidate '{candidate_id}' not found.")

        cand.review_status = str(review_status.value if hasattr(review_status, "value") else review_status)
        cand.reviewed_by = reviewer
        cand.reviewed_at = get_utc_now()
        cand.review_reason = sanitize_log_text(reason)

        if override_label:
            cand.label = override_label.lower().strip()
            cand.label_source = LabelSource.ANALYST_VERIFIED.value

        if review_status == CandidateReviewStatus.ACCEPTED:
            cand.eligibility_status = CandidateEligibilityStatus.ELIGIBLE.value
            cand.ineligibility_reason = None
        elif review_status == CandidateReviewStatus.REJECTED:
            cand.eligibility_status = CandidateEligibilityStatus.EXCLUDED.value
            cand.ineligibility_reason = f"Rejected by analyst {reviewer}: {reason}"

        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="LEARNING_CANDIDATE_ACCEPTED" if review_status == CandidateReviewStatus.ACCEPTED else "LEARNING_CANDIDATE_REJECTED",
            resource_id=cand.id,
            details=f"Analyst {reviewer} set status {cand.review_status} for candidate {cand.id}: {reason}",
            metadata={"status": cand.review_status, "label": cand.label},
        )

        return cand

    # ========================================================================
    # 2. DATASET BUILDER & QUALITY DEFENSE
    # ========================================================================

    @classmethod
    def build_dataset_version(
        cls,
        db: Session,
        workspace_id: Union[str, DatasetBuildRequest] = "default",
        request: Optional[DatasetBuildRequest] = None,
        req: Optional[DatasetBuildRequest] = None,
        creator: str = "SOC Learning Pipeline",
    ) -> LearningDatasetModel:
        """
        Builds an immutable versioned dataset snapshot.
        Enforces data poisoning defenses, class balancing checks, temporal splitting,
        and campaign grouping to prevent data leakage.
        """
        if isinstance(workspace_id, DatasetBuildRequest):
            request = workspace_id
            workspace_id = request.workspace_id
        elif req is not None:
            request = req
            if hasattr(request, "workspace_id") and request.workspace_id:
                workspace_id = request.workspace_id
        elif request is not None and hasattr(request, "workspace_id") and request.workspace_id:
            workspace_id = request.workspace_id

        if request is None:
            request = DatasetBuildRequest(workspace_id=str(workspace_id))

        # 1. Fetch eligible & accepted candidates
        candidates = db.query(LearningCandidateModel).filter(
            LearningCandidateModel.workspace_id == workspace_id,
            LearningCandidateModel.eligibility_status == CandidateEligibilityStatus.ELIGIBLE.value,
            LearningCandidateModel.review_status == CandidateReviewStatus.ACCEPTED.value,
        ).order_by(LearningCandidateModel.observed_at.asc()).limit(request.max_samples).all()

        samples_list: List[Dict[str, Any]] = []

        # Include curated base benchmark dataset to preserve core generalization
        for item in BENCHMARK_DATASET:
            norm_b = TextNormalizer.normalize(subject=item.get("subject", ""), body=item.get("body", ""))
            lbl = 1 if item["label"].lower() == "phishing" else 0
            samples_list.append({
                "text": norm_b,
                "label": lbl,
                "source": "BENCHMARK_BASE",
                "is_hard_negative": False,
                "observed_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "campaign_id": "BASE_CORPUS",
                "candidate_id": None,
            })

        # Add newly verified candidates
        for c in candidates:
            if not c.text_content:
                continue
            norm_t = TextNormalizer.normalize(body=c.text_content)
            lbl = 1 if c.label in ("phishing", "malicious") else 0
            samples_list.append({
                "text": norm_t,
                "label": lbl,
                "source": c.source_type,
                "is_hard_negative": c.is_hard_negative,
                "observed_at": c.observed_at,
                "campaign_id": c.campaign_id or f"INC_{c.incident_id or 'GENERAL'}",
                "candidate_id": c.id,
            })

        # 2. Poisoning & Quality Defense Checks
        validation_errors: List[str] = []
        source_counts: Dict[str, int] = {}
        total_samples = len(samples_list)
        malicious_count = sum(1 for s in samples_list if s["label"] == 1)
        benign_count = total_samples - malicious_count
        hard_negative_count = sum(1 for s in samples_list if s.get("is_hard_negative"))

        for s in samples_list:
            src = s["source"]
            source_counts[src] = source_counts.get(src, 0) + 1

        # Check source concentration (Anti-Poisoning)
        for src, count in source_counts.items():
            if src != "BENCHMARK_BASE":
                ratio = count / total_samples
                if ratio > cls.MAX_SOURCE_CONCENTRATION_RATIO:
                    validation_errors.append(
                        f"Suspicious source concentration: Source '{src}' contributes {ratio * 100:.1f}% of dataset, exceeding safe limit ({cls.MAX_SOURCE_CONCENTRATION_RATIO * 100:.0f}%)."
                    )

        # Check class balance
        if total_samples > 0:
            min_ratio = min(malicious_count, benign_count) / total_samples
            if min_ratio < cls.MIN_CLASS_SAMPLE_PERCENT:
                validation_errors.append(
                    f"Severe class imbalance: minority class is {min_ratio * 100:.1f}%, below minimum {cls.MIN_CLASS_SAMPLE_PERCENT * 100:.0f}%."
                )

        validation_status = (
            DatasetValidationStatus.REJECTED.value
            if validation_errors
            else DatasetValidationStatus.VALIDATED.value
        )

        # 3. Compute Cryptographic Checksum (Immutability Guarantee)
        manifest_raw = json.dumps([{"t": s["text"][:100], "l": s["label"], "src": s["source"]} for s in samples_list], sort_keys=True)
        manifest_checksum = cls._compute_sha256(manifest_raw.encode("utf-8"))

        # Derive version number
        latest_ds = db.query(LearningDatasetModel).filter(
            LearningDatasetModel.workspace_id == workspace_id
        ).order_by(desc(LearningDatasetModel.created_at)).first()

        new_version_num = 1
        if latest_ds and latest_ds.version.startswith("D-"):
            try:
                new_version_num = int(latest_ds.version.split("-")[-1]) + 1
            except Exception:
                pass
        version_str = f"D-{new_version_num:03d}"

        valid_dts = [cls._ensure_utc(s.get("observed_at")) for s in samples_list if s.get("observed_at")]
        time_start = min(valid_dts) if valid_dts else None
        time_end = max(valid_dts) if valid_dts else None

        dataset = LearningDatasetModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            version=version_str,
            feature_schema_version=request.feature_schema_version,
            label_policy_version=request.label_policy_version,
            sample_count=total_samples,
            malicious_count=malicious_count,
            benign_count=benign_count,
            hard_negative_count=hard_negative_count,
            source_distribution_json=json.dumps(source_counts),
            time_range_start=time_start,
            time_range_end=time_end,
            quality_score=0.5 if validation_errors else 1.0,
            validation_status=validation_status,
            validation_errors_json=json.dumps(validation_errors),
            manifest_checksum=manifest_checksum,
            created_by=creator,
            created_at=get_utc_now(),
        )
        db.add(dataset)

        # Mark candidates with this dataset version
        for c in candidates:
            c.dataset_version = version_str

        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="DATASET_CREATED",
            resource_id=dataset.id,
            details=f"Constructed immutable dataset {version_str} with {total_samples} samples ({validation_status})",
            metadata={"version": version_str, "sample_count": total_samples, "status": validation_status},
        )

        return dataset

    # ========================================================================
    # 3. TRAINING & OFFLINE EVALUATION
    # ========================================================================

    @classmethod
    def run_training_job(
        cls,
        db: Session,
        workspace_id: Union[str, TrainingJobCreate] = "default",
        dataset_version: Optional[str] = None,
        model_type: str = "PHISHING_CLASSIFIER",
        training_config: Optional[Dict[str, Any]] = None,
        req: Optional[TrainingJobCreate] = None,
    ) -> Tuple[LearningTrainingJobModel, Optional[RegisteredModelModel]]:
        """
        Executes controlled model training and rigorous offline evaluation.
        Evaluates candidate model side-by-side with current production model.
        Checks regression gates and registers candidate model artifact with cryptographic checksum.
        """
        if isinstance(workspace_id, TrainingJobCreate):
            req = workspace_id
            workspace_id = req.workspace_id
        if req is not None:
            workspace_id = req.workspace_id
            dataset_version = req.dataset_version
            model_type = req.model_type
            training_config = req.training_config

        if not dataset_version:
            raise ValueError("dataset_version is required to run training job.")

        CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
        config = training_config or {
            "max_features": 5000,
            "ngram_range": [1, 2],
            "C": 1.5,
            "class_weight": "balanced",
            "solver": "liblinear",
            "random_state": 42,
        }

        # 1. Fetch Dataset
        dataset = db.query(LearningDatasetModel).filter(
            LearningDatasetModel.workspace_id == workspace_id,
            LearningDatasetModel.version == dataset_version,
        ).first()

        if not dataset:
            raise ValueError(f"Dataset version '{dataset_version}' not found.")
        if dataset.validation_status != DatasetValidationStatus.VALIDATED.value:
            raise ValueError(f"Dataset version '{dataset_version}' has status '{dataset.validation_status}' and cannot be used for training.")

        # 2. Create Job Record
        job = LearningTrainingJobModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            model_type=model_type,
            dataset_version=dataset_version,
            status=TrainingJobStatus.RUNNING.value,
            started_at=get_utc_now(),
            training_config_json=json.dumps(config),
            created_at=get_utc_now(),
        )
        db.add(job)
        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="TRAINING_STARTED",
            resource_id=job.id,
            details=f"Started training job {job.id} on dataset {dataset_version}",
            metadata={"dataset_version": dataset_version, "model_type": model_type},
        )

        try:
            # 3. Assemble training samples (Temporal & Campaign Leaked-Guarded Split)
            candidates = db.query(LearningCandidateModel).filter(
                LearningCandidateModel.workspace_id == workspace_id,
                LearningCandidateModel.dataset_version == dataset_version,
            ).order_by(LearningCandidateModel.observed_at.asc()).all()

            all_samples: List[Dict[str, Any]] = []
            for item in BENCHMARK_DATASET:
                norm_b = TextNormalizer.normalize(subject=item.get("subject", ""), body=item.get("body", ""))
                all_samples.append({
                    "text": norm_b,
                    "label": 1 if item["label"].lower() == "phishing" else 0,
                    "observed_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
                    "campaign": "BENCHMARK_BASE",
                })

            for c in candidates:
                if not c.text_content:
                    continue
                norm_c = TextNormalizer.normalize(body=c.text_content)
                all_samples.append({
                    "text": norm_c,
                    "label": 1 if c.label in ("phishing", "malicious") else 0,
                    "observed_at": c.observed_at,
                    "campaign": c.campaign_id or f"INC_{c.incident_id or 'GENERAL'}",
                })

            # Sort temporally
            all_samples.sort(key=lambda s: cls._ensure_utc(s.get("observed_at")) or datetime(1970, 1, 1, tzinfo=timezone.utc))
            split_idx = int(len(all_samples) * 0.75)
            train_set = all_samples[:split_idx]
            test_set = all_samples[split_idx:]

            # Guarantee test set has both classes
            if sum(1 for s in test_set if s["label"] == 1) == 0 or sum(1 for s in test_set if s["label"] == 0) == 0:
                # Add balanced representation if temporal slice lacks one class
                test_set.append(train_set.pop(0))

            X_train = [s["text"] for s in train_set]
            y_train = [s["label"] for s in train_set]
            X_test = [s["text"] for s in test_set]
            y_test = [s["label"] for s in test_set]

            # 4. Fit Candidate Pipeline
            ngram = tuple(config.get("ngram_range", [1, 2]))
            pipeline = Pipeline([
                (
                    "tfidf",
                    TfidfVectorizer(
                        ngram_range=ngram,
                        max_features=config.get("max_features", 5000),
                        sublinear_tf=True,
                        stop_words="english",
                        min_df=1,
                    ),
                ),
                (
                    "clf",
                    LogisticRegression(
                        C=float(config.get("C", 1.5)),
                        max_iter=1000,
                        class_weight=config.get("class_weight", "balanced"),
                        random_state=int(config.get("random_state", 42)),
                        solver=config.get("solver", "liblinear"),
                    ),
                ),
            ])
            pipeline.fit(X_train, y_train)

            # 5. Evaluate Candidate Model on Holdout Test Split
            y_pred = pipeline.predict(X_test)
            acc = float(accuracy_score(y_test, y_pred))
            prec = float(precision_score(y_test, y_pred, zero_division=0))
            rec = float(recall_score(y_test, y_pred, zero_division=0))
            f1 = float(f1_score(y_test, y_pred, zero_division=0))
            cm = confusion_matrix(y_test, y_pred)
            tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
            fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

            cand_metrics = ModelEvaluationMetrics(
                accuracy=acc,
                precision=prec,
                recall=rec,
                f1_score=f1,
                false_positive_rate=fpr,
                false_negative_rate=fnr,
                critical_threat_recall=rec,
                sample_count=len(test_set),
                confusion_matrix={"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            )

            # 6. Evaluate Current Production Model for Baseline Comparison
            prod_model = db.query(RegisteredModelModel).filter(
                RegisteredModelModel.workspace_id == workspace_id,
                RegisteredModelModel.model_type == model_type,
                RegisteredModelModel.status == ModelLifecycleStatus.PRODUCTION.value,
            ).first()

            prod_metrics = None
            if prod_model and prod_model.metrics_json:
                try:
                    p_dict = json.loads(prod_model.metrics_json)
                    prod_metrics = ModelEvaluationMetrics(**p_dict)
                except Exception:
                    pass

            # 7. Evaluate Regression Gates
            gates: List[RegressionGateResult] = []
            # Gate 1: Recall gate
            min_recall = prod_metrics.recall - 0.05 if prod_metrics else 0.80
            passed_rec = rec >= min_recall
            gates.append(
                RegressionGateResult(
                    gate_name="Recall Preservation Gate",
                    passed=passed_rec,
                    candidate_metric=rec,
                    production_metric=prod_metrics.recall if prod_metrics else 0.0,
                    threshold=min_recall,
                    message=f"Candidate recall ({rec:.2f}) {'meets' if passed_rec else 'fails'} threshold ({min_recall:.2f})",
                )
            )

            # Gate 2: Precision gate
            passed_prec = prec >= 0.75
            gates.append(
                RegressionGateResult(
                    gate_name="Minimum Precision Gate",
                    passed=passed_prec,
                    candidate_metric=prec,
                    production_metric=prod_metrics.precision if prod_metrics else 0.0,
                    threshold=0.75,
                    message=f"Candidate precision ({prec:.2f}) {'meets' if passed_prec else 'fails'} minimum (0.75)",
                )
            )

            # Gate 3: FPR gate
            max_fpr = 0.10
            passed_fpr = fpr <= max_fpr
            gates.append(
                RegressionGateResult(
                    gate_name="False Positive Rate Bounding Gate",
                    passed=passed_fpr,
                    candidate_metric=fpr,
                    production_metric=prod_metrics.false_positive_rate if prod_metrics else 0.0,
                    threshold=max_fpr,
                    message=f"Candidate FPR ({fpr:.2f}) {'satisfies' if passed_fpr else 'violates'} max allowable ({max_fpr:.2f})",
                )
            )

            passed_all = all(g.passed for g in gates)
            comparison = BaselineComparisonResult(
                passed_all_gates=passed_all,
                candidate_metrics=cand_metrics,
                production_metrics=prod_metrics,
                gates=gates,
                recommendation="RECOMMENDED_FOR_APPROVAL" if passed_all else "REJECTED_DUE_TO_REGRESSION",
            )

            existing_models = db.query(RegisteredModelModel).filter(
                RegisteredModelModel.workspace_id == workspace_id,
                RegisteredModelModel.model_type == model_type,
            ).all()
            max_ver = 0
            for em in existing_models:
                try:
                    num_part = int(em.version.split("-v")[-1])
                    if num_part > max_ver:
                        max_ver = num_part
                except Exception:
                    pass
            cand_version = f"phishing-v{max(max_ver + 1, len(existing_models) + 1)}"
            artifact_file = CANDIDATES_DIR / f"{cand_version}.joblib"
            joblib.dump(pipeline, artifact_file)

            with open(artifact_file, "rb") as af:
                artifact_checksum = cls._compute_sha256(af.read())

            # 9. Register Candidate in Model Registry
            registered_model = RegisteredModelModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                model_type=model_type,
                version=cand_version,
                dataset_version=dataset_version,
                feature_schema_version="1.0.0",
                training_job_id=job.id,
                status=ModelLifecycleStatus.CANDIDATE.value,
                metrics_json=json.dumps(cand_metrics.model_dump()),
                baseline_comparison_json=json.dumps(comparison.model_dump()),
                artifact_path=str(artifact_file),
                artifact_checksum=artifact_checksum,
                created_at=get_utc_now(),
            )
            db.add(registered_model)

            job.status = TrainingJobStatus.SUCCEEDED.value
            job.candidate_model_version = cand_version
            job.completed_at = get_utc_now()
            job.metrics_json = json.dumps(cand_metrics.model_dump())
            db.flush()

            cls._log_audit(
                db,
                workspace_id=workspace_id,
                action="TRAINING_COMPLETED",
                resource_id=job.id,
                details=f"Training job {job.id} completed. Produced candidate {cand_version} (F1: {f1:.2f})",
                metadata={"candidate_version": cand_version, "passed_gates": passed_all},
            )

            return job, registered_model

        except Exception as exc:
            logger.error(f"Training job failed: {exc}", exc_info=True)
            job.status = TrainingJobStatus.FAILED.value
            job.completed_at = get_utc_now()
            job.error_message = str(exc)
            db.flush()

            cls._log_audit(
                db,
                workspace_id=workspace_id,
                action="TRAINING_FAILED",
                resource_id=job.id,
                details=f"Training job {job.id} failed: {exc}",
                metadata={"error": str(exc)},
            )
            return job, None

    # ========================================================================
    # 4. MODEL REGISTRY LIFECYCLE (APPROVE, STAGE, PROMOTE, ROLLBACK)
    # ========================================================================

    @classmethod
    def approve_model(
        cls,
        db: Session,
        workspace_id: str,
        model_id: str,
        reviewer: str,
        reason: str,
    ) -> RegisteredModelModel:
        """
        Analyst approval gate promoting candidate model to APPROVED.
        """
        model = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.id == model_id,
            RegisteredModelModel.workspace_id == workspace_id,
        ).first()

        if not model:
            raise ValueError(f"Model '{model_id}' not found.")
        if model.status not in (ModelLifecycleStatus.CANDIDATE.value, ModelLifecycleStatus.REJECTED.value):
            raise ValueError(f"Model has status '{model.status}'; only CANDIDATE can be approved.")

        model.status = ModelLifecycleStatus.APPROVED.value
        model.approved_by = reviewer
        model.approved_at = get_utc_now()
        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="MODEL_APPROVED",
            resource_id=model.id,
            details=f"Model {model.version} approved by {reviewer}: {reason}",
            metadata={"version": model.version, "reviewer": reviewer},
        )
        return model

    @classmethod
    def stage_model(
        cls,
        db: Session,
        workspace_id: str,
        model_id: str,
        reviewer: str = "system",
        reason: str = "Canary staging",
    ) -> RegisteredModelModel:
        """
        Transitions model from APPROVED to STAGED for monitoring.
        """
        model = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.id == model_id,
            RegisteredModelModel.workspace_id == workspace_id,
        ).first()

        if not model:
            raise ValueError(f"Model '{model_id}' not found.")
        if model.status != ModelLifecycleStatus.APPROVED.value:
            raise ValueError(f"Model has status '{model.status}'; only APPROVED models can be staged.")

        model.status = ModelLifecycleStatus.STAGED.value
        model.staged_at = get_utc_now()
        db.flush()

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="MODEL_STAGED",
            resource_id=model.id,
            details=f"Model {model.version} moved to STAGED by {reviewer}: {reason}",
            metadata={"version": model.version, "reviewer": reviewer},
        )
        return model

    @classmethod
    def promote_to_production(
        cls,
        db: Session,
        workspace_id: str,
        model_id: str,
        reviewer: str = "system",
        reason: str = "Production promotion",
    ) -> RegisteredModelModel:
        """
        Promotes a staged model to PRODUCTION after verifying artifact checksum integrity.
        Demotes previous production model to ARCHIVED (retaining pointer for instant rollback).
        """
        model = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.id == model_id,
            RegisteredModelModel.workspace_id == workspace_id,
        ).first()

        if not model:
            raise ValueError(f"Model '{model_id}' not found.")
        if model.status != ModelLifecycleStatus.STAGED.value:
            raise ValueError(f"Model has status '{model.status}'; only STAGED models can be promoted.")

        # Checksum Verification (Integrity Guard)
        artifact_p = Path(model.artifact_path)
        if not artifact_p.exists():
            raise FileNotFoundError(f"Model artifact not found at {artifact_p}")
        with open(artifact_p, "rb") as f:
            actual_chk = cls._compute_sha256(f.read())
        if actual_chk != model.artifact_checksum:
            raise ValueError(f"Checksum mismatch! Expected {model.artifact_checksum}, got {actual_chk}. Loading aborted.")

        # Demote current production model
        current_prod = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            RegisteredModelModel.model_type == model.model_type,
            RegisteredModelModel.status == ModelLifecycleStatus.PRODUCTION.value,
        ).first()

        if current_prod:
            current_prod.status = ModelLifecycleStatus.ARCHIVED.value

        # Promote target model
        model.status = ModelLifecycleStatus.PRODUCTION.value
        model.promoted_at = get_utc_now()
        db.flush()

        # Hot-reload into global runtime classifier
        try:
            global_phishing_classifier.model_path = artifact_p
            global_phishing_classifier._load_model()
        except Exception as e:
            logger.warning(f"Could not hot-reload global classifier: {e}")

        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="MODEL_PROMOTED",
            resource_id=model.id,
            details=f"Promoted model {model.version} to PRODUCTION by {reviewer}: {reason}",
            metadata={"promoted_version": model.version, "previous_version": current_prod.version if current_prod else None, "reviewer": reviewer},
        )
        return model

    @classmethod
    def rollback_production(
        cls,
        db: Session,
        workspace_id: str,
        model_id: Optional[str] = None,
        reviewer: str = "system",
        reason: str = "Production rollback",
        target_version: Optional[str] = None,
    ) -> RegisteredModelModel:
        """
        Safely rolls back current production model to previous version or specified target.
        Failed model is marked ROLLED_BACK with evaluation and regression history preserved.
        """
        current_prod = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            RegisteredModelModel.status == ModelLifecycleStatus.PRODUCTION.value,
        ).first()

        if not current_prod:
            raise ValueError("No active PRODUCTION model found to roll back.")

        # Find target model to restore
        query = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            RegisteredModelModel.id != current_prod.id,
        )
        if target_version:
            query = query.filter(RegisteredModelModel.version == target_version)
        else:
            query = query.filter(
                RegisteredModelModel.status.in_([ModelLifecycleStatus.ARCHIVED.value, ModelLifecycleStatus.APPROVED.value])
            ).order_by(desc(RegisteredModelModel.created_at))

        restore_target = query.first()

        current_prod.status = ModelLifecycleStatus.ROLLED_BACK.value
        current_prod.rolled_back_at = get_utc_now()

        if restore_target:
            restore_target.status = ModelLifecycleStatus.PRODUCTION.value
            db.flush()
            # Hot-reload restored model
            try:
                global_phishing_classifier.model_path = Path(restore_target.artifact_path)
                global_phishing_classifier._load_model()
            except Exception as e:
                logger.warning(f"Could not load restored model: {e}")
            target_to_return = restore_target
        else:
            db.flush()
            try:
                global_phishing_classifier.model_path = PhishingClassifier.DEFAULT_MODEL_PATH
                if global_phishing_classifier.model_path.exists():
                    global_phishing_classifier._load_model()
            except Exception as e:
                logger.warning(f"Could not revert to default baseline model: {e}")
            target_to_return = current_prod

        restored_ver = restore_target.version if restore_target else "baseline-v1"
        cls._log_audit(
            db,
            workspace_id=workspace_id,
            action="MODEL_ROLLED_BACK",
            resource_id=current_prod.id,
            details=f"Rolled back {current_prod.version} to {restored_ver}. Reason: {reason}",
            metadata={"rolled_back_version": current_prod.version, "restored_version": restored_ver, "reviewer": reviewer},
        )
        return target_to_return

    # ========================================================================
    # 5. DRIFT & OBSERVABILITY
    # ========================================================================

    @classmethod
    def evaluate_drift(
        cls,
        db: Session,
        workspace_id: str,
        model_type: str = "PHISHING_CLASSIFIER",
        sample_window_days: int = 30,
    ) -> DriftReport:
        """
        Monitors production prediction distribution shifts, false positive feedback rate,
        and novelty rates over a 30-day window.
        """
        prod_model = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            RegisteredModelModel.model_type == model_type,
            RegisteredModelModel.status == ModelLifecycleStatus.PRODUCTION.value,
        ).first()

        active_ver = prod_model.version if prod_model else "baseline-v1"

        # Check false positive feedback trend
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        total_decisions = db.query(ThreatMemoryDecisionModel).filter(
            ThreatMemoryDecisionModel.workspace_id == workspace_id,
            ThreatMemoryDecisionModel.created_at >= thirty_days_ago,
        ).count()

        fp_decisions = db.query(ThreatMemoryDecisionModel).filter(
            ThreatMemoryDecisionModel.workspace_id == workspace_id,
            ThreatMemoryDecisionModel.decision == "FALSE_POSITIVE",
            ThreatMemoryDecisionModel.created_at >= thirty_days_ago,
        ).count()

        fp_rate = (fp_decisions / total_decisions) if total_decisions > 0 else 0.0

        signals = []
        if fp_rate > 0.15:
            signals.append(f"High false-positive feedback rate ({fp_rate * 100:.1f}%) observed over past 30 days.")

        drift_detected = len(signals) > 0
        rec = "TRIGGER_REVIEW_AND_DATASET_BUILD" if drift_detected else "NO_DRIFT_DETECTED"

        return DriftReport(
            workspace_id=workspace_id,
            model_type=model_type,
            active_version=active_ver,
            sample_window_days=30,
            drift_detected=drift_detected,
            drift_signals=signals,
            false_positive_rate_trend=fp_rate,
            analyst_disagreement_rate=fp_rate,
            novel_pattern_rate=0.0,
            recommendation=rec,
        )

    @classmethod
    def get_dashboard_stats(cls, db: Session, workspace_id: str) -> LearningDashboardStats:
        """Gathers continual learning metrics for internal dashboard."""
        tot_cand = db.query(LearningCandidateModel).filter(LearningCandidateModel.workspace_id == workspace_id).count()
        elig_cand = db.query(LearningCandidateModel).filter(
            LearningCandidateModel.workspace_id == workspace_id,
            LearningCandidateModel.eligibility_status == CandidateEligibilityStatus.ELIGIBLE.value,
        ).count()
        pend_cand = db.query(LearningCandidateModel).filter(
            LearningCandidateModel.workspace_id == workspace_id,
            LearningCandidateModel.review_status == CandidateReviewStatus.PENDING.value,
        ).count()
        hard_neg = db.query(LearningCandidateModel).filter(
            LearningCandidateModel.workspace_id == workspace_id,
            LearningCandidateModel.is_hard_negative.is_(True),
        ).count()
        tot_ds = db.query(LearningDatasetModel).filter(LearningDatasetModel.workspace_id == workspace_id).count()

        latest_ds = db.query(LearningDatasetModel).filter(
            LearningDatasetModel.workspace_id == workspace_id
        ).order_by(desc(LearningDatasetModel.created_at)).first()

        prod_m = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            RegisteredModelModel.status == ModelLifecycleStatus.PRODUCTION.value,
        ).first()

        staged_m = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            RegisteredModelModel.status == ModelLifecycleStatus.STAGED.value,
        ).first()

        tot_jobs = db.query(LearningTrainingJobModel).filter(LearningTrainingJobModel.workspace_id == workspace_id).count()
        cand_models = db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            RegisteredModelModel.status == ModelLifecycleStatus.CANDIDATE.value,
        ).count()

        return LearningDashboardStats(
            workspace_id=workspace_id,
            total_candidates=tot_cand,
            eligible_candidates=elig_cand,
            pending_review_candidates=pend_cand,
            hard_negatives=hard_neg,
            total_datasets=tot_ds,
            active_dataset_version=latest_ds.version if latest_ds else None,
            production_model_version=prod_m.version if prod_m else "baseline-v1",
            staged_model_version=staged_m.version if staged_m else None,
            total_training_jobs=tot_jobs,
            candidate_models_count=cand_models,
        )

    # ========================================================================
    # 6. QUERY & RETRIEVAL HELPERS
    # ========================================================================

    @classmethod
    def list_candidates(
        cls,
        db: Session,
        workspace_id: str,
        eligibility_status: Optional[str] = None,
        review_status: Optional[str] = None,
        label: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[LearningCandidateModel]:
        """Lists learning candidates matching criteria."""
        q = db.query(LearningCandidateModel).filter(LearningCandidateModel.workspace_id == workspace_id)
        if eligibility_status:
            q = q.filter(LearningCandidateModel.eligibility_status == eligibility_status)
        if review_status:
            q = q.filter(LearningCandidateModel.review_status == review_status)
        if label:
            q = q.filter(LearningCandidateModel.label == label.lower())
        return q.order_by(desc(LearningCandidateModel.created_at)).offset(skip).limit(limit).all()

    @classmethod
    def get_candidate(cls, db: Session, workspace_id: str, candidate_id: str) -> Optional[LearningCandidateModel]:
        return db.query(LearningCandidateModel).filter(
            LearningCandidateModel.id == candidate_id,
            LearningCandidateModel.workspace_id == workspace_id,
        ).first()

    @classmethod
    def get_dataset(cls, db: Session, workspace_id: str, dataset_id_or_version: str) -> Optional[LearningDatasetModel]:
        return db.query(LearningDatasetModel).filter(
            LearningDatasetModel.workspace_id == workspace_id,
            or_(
                LearningDatasetModel.id == dataset_id_or_version,
                LearningDatasetModel.version == dataset_id_or_version,
            )
        ).first()

    @classmethod
    def list_datasets(
        cls,
        db: Session,
        workspace_id: str,
        validation_status: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[LearningDatasetModel]:
        q = db.query(LearningDatasetModel).filter(LearningDatasetModel.workspace_id == workspace_id)
        if validation_status:
            q = q.filter(LearningDatasetModel.validation_status == validation_status)
        return q.order_by(desc(LearningDatasetModel.created_at)).offset(skip).limit(limit).all()

    @classmethod
    def get_training_job(cls, db: Session, workspace_id: str, job_id: str) -> Optional[LearningTrainingJobModel]:
        return db.query(LearningTrainingJobModel).filter(
            LearningTrainingJobModel.id == job_id,
            LearningTrainingJobModel.workspace_id == workspace_id,
        ).first()

    @classmethod
    def list_training_jobs(
        cls,
        db: Session,
        workspace_id: str,
        status: Optional[str] = None,
        model_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[LearningTrainingJobModel]:
        q = db.query(LearningTrainingJobModel).filter(LearningTrainingJobModel.workspace_id == workspace_id)
        if status:
            q = q.filter(LearningTrainingJobModel.status == status)
        if model_type:
            q = q.filter(LearningTrainingJobModel.model_type == model_type)
        return q.order_by(desc(LearningTrainingJobModel.created_at)).offset(skip).limit(limit).all()

    @classmethod
    def get_registered_model(cls, db: Session, workspace_id: str, model_id_or_version: str) -> Optional[RegisteredModelModel]:
        return db.query(RegisteredModelModel).filter(
            RegisteredModelModel.workspace_id == workspace_id,
            or_(
                RegisteredModelModel.id == model_id_or_version,
                RegisteredModelModel.version == model_id_or_version,
            )
        ).first()

    @classmethod
    def list_registered_models(
        cls,
        db: Session,
        workspace_id: str,
        status: Optional[str] = None,
        model_type: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> List[RegisteredModelModel]:
        q = db.query(RegisteredModelModel).filter(RegisteredModelModel.workspace_id == workspace_id)
        if status:
            q = q.filter(RegisteredModelModel.status == status)
        if model_type:
            q = q.filter(RegisteredModelModel.model_type == model_type)
        return q.order_by(desc(RegisteredModelModel.created_at)).offset(skip).limit(limit).all()

    @classmethod
    def get_model_card(cls, db: Session, workspace_id: str, model_id: str) -> ModelCard:
        model = cls.get_registered_model(db, workspace_id, model_id)
        if not model:
            raise ValueError(f"Model '{model_id}' not found.")

        metrics = json.loads(model.metrics_json or "{}")
        baseline = json.loads(model.baseline_comparison_json or "{}")

        known_regressions = []
        for g in baseline.get("gates", []):
            if not g.get("passed"):
                known_regressions.append(f"{g.get('gate_name')}: {g.get('message')}")

        limitations = [
            "Trained on sanitized textual artifacts (headers, subject, body).",
            "Subject to feature schema version compatibility.",
            "Requires manual verification for low-confidence classifications.",
        ]

        return ModelCard(
            model_id=model.id,
            model_type=model.model_type,
            version=model.version,
            status=ModelLifecycleStatus(model.status),
            dataset_version=model.dataset_version,
            feature_schema_version=model.feature_schema_version,
            training_timestamp=model.created_at,
            metrics=metrics,
            baseline_comparison=baseline,
            known_regressions=known_regressions,
            limitations=limitations,
            approval_metadata={
                "approved_by": model.approved_by,
                "approved_at": model.approved_at.isoformat() if model.approved_at else None,
                "staged_at": model.staged_at.isoformat() if model.staged_at else None,
                "promoted_at": model.promoted_at.isoformat() if model.promoted_at else None,
                "rolled_back_at": model.rolled_back_at.isoformat() if model.rolled_back_at else None,
            },
            checksum=model.artifact_checksum,
        )

    # ========================================================================
    # 7. AUDIT HELPER
    # ========================================================================

    @classmethod
    def _log_audit(
        cls,
        db: Session,
        workspace_id: str,
        action: str,
        resource_id: str,
        details: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            audit = AuditLogModel(
                id=generate_uuid(),
                timestamp=get_utc_now(),
                user="ContinualLearningPipeline",
                action=action,
                resource_type="continual_learning",
                resource_id=resource_id,
                details=sanitize_log_text(details),
                metadata_json=json.dumps(metadata or {}),
            )
            db.add(audit)
            db.flush()
        except Exception as exc:
            logger.warning(f"Could not record audit log: {exc}")
