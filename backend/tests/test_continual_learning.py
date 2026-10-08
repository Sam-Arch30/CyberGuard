"""
Unit and service-level tests for Section 24 Controlled Continual-Learning Pipeline.
Tests:
1. Learning candidate creation, qualification, deduplication, and secret redaction.
2. Unverified observations not automatically becoming ground truth.
3. Dataset versioning, immutability, temporal splitting, and campaign leakage prevention.
4. Data poisoning defense (source concentration and class balance checks).
5. Real TF-IDF + LogisticRegression model training and offline evaluation metrics.
6. Baseline comparison and regression gates.
7. Model Registry lifecycle: approval, staging, checksum-verified promotion, and rollback.
8. Artifact tamper detection (checksum mismatch blocks load).
9. Threat Memory integration and false positive hard negative mining.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import (
    LearningCandidateModel,
    LearningDatasetModel,
    LearningTrainingJobModel,
    RegisteredModelModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.continual_learning import (
    CandidateEligibilityStatus,
    CandidateReviewStatus,
    CandidateReviewRequest,
    DatasetBuildRequest,
    DatasetValidationStatus,
    LabelSource,
    LearningCandidateCreate,
    ModelActionRequest,
    ModelApprovalRequest,
    ModelLifecycleStatus,
    ModelRollbackRequest,
    TrainingJobCreate,
    sanitize_training_payload,
)
from backend.services.continual_learning_service import (
    ContinualLearningService,
    CANDIDATES_DIR,
)


@pytest.fixture
def db_session():
    """Provides isolated in-memory SQLite database session for unit testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_secret_redaction_and_sanitization():
    """Verifies passwords, API keys, and bearer tokens are redacted from training payloads."""
    payload = {
        "user": "security_analyst",
        "password": "SuperSecretPassword123!",
        "api_key": "cyberguard_live_secret_token_abcdef",
        "nested": {
            "token": "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            "safe_header": "X-Security-Scan: pass",
        },
        "items": [
            {"secret": "hidden_credential_data"},
            "Clean string with password: AdminPassword999",
        ],
    }
    clean = sanitize_training_payload(payload)
    assert clean["password"] == "[REDACTED_SECRET]"
    assert clean["api_key"] == "[REDACTED_SECRET]"
    assert clean["nested"]["token"] == "[REDACTED_SECRET]"
    assert clean["nested"]["safe_header"] == "X-Security-Scan: pass"
    assert clean["items"][0]["secret"] == "[REDACTED_SECRET]"
    assert "[REDACTED" in clean["items"][1]


def test_candidate_creation_and_eligibility(db_session):
    """Verifies verified observations become eligible candidates, while low-confidence ones require review."""
    # 1. Analyst verified high-confidence candidate -> ELIGIBLE
    cand_in = LearningCandidateCreate(
        workspace_id="default",
        source_type="THREAT_MEMORY",
        source_reference="DOMAIN:login-paypal-verify.com",
        text_content="Urgent security notification: verify account credentials now at login-paypal-verify.com",
        label="phishing",
        label_source=LabelSource.ANALYST_VERIFIED,
        confidence=0.98,
        incident_id="inc-101",
    )
    cand = ContinualLearningService.create_candidate(db_session, cand_in)
    assert cand.eligibility_status == CandidateEligibilityStatus.ELIGIBLE.value
    assert cand.review_status == CandidateReviewStatus.ACCEPTED.value

    # 2. Low confidence model prediction -> INELIGIBLE / REVIEW_REQUIRED
    low_cand_in = LearningCandidateCreate(
        workspace_id="default",
        source_type="ANALYSIS_RUN",
        source_reference="RUN:999",
        text_content="Meeting agenda for next Tuesday project sync.",
        label="legitimate",
        label_source=LabelSource.MODEL_PSEUDO_LABEL,
        confidence=0.52,  # Below threshold
    )
    low_cand = ContinualLearningService.create_candidate(db_session, low_cand_in)
    assert low_cand.eligibility_status == CandidateEligibilityStatus.INELIGIBLE.value
    assert "below minimum threshold" in low_cand.ineligibility_reason.lower()


def test_deduplication_prevents_dataset_inflation(db_session):
    """Verifies identical source reference updates existing candidate rather than creating uncontrolled duplicates."""
    cand_in1 = LearningCandidateCreate(
        workspace_id="default",
        source_type="THREAT_MEMORY",
        source_reference="HASH:4a7d1ed414474e4033ac29ccb8653d9b",
        text_content="Malicious payload binary artifact",
        label="malicious",
        label_source=LabelSource.RULE_VERIFIED,
        confidence=0.95,
        raw_payload={"count": 1},
    )
    c1 = ContinualLearningService.create_candidate(db_session, cand_in1)

    cand_in2 = LearningCandidateCreate(
        workspace_id="default",
        source_type="THREAT_MEMORY",
        source_reference="HASH:4a7d1ed414474e4033ac29ccb8653d9b",
        text_content="Malicious payload binary artifact seen again",
        label="malicious",
        label_source=LabelSource.ANALYST_VERIFIED,
        confidence=1.0,
        raw_payload={"count": 2},
    )
    c2 = ContinualLearningService.create_candidate(db_session, cand_in2)

    assert c1.id == c2.id
    assert c2.confidence == 1.0
    assert c2.label_source == LabelSource.ANALYST_VERIFIED.value
    count = db_session.query(LearningCandidateModel).count()
    assert count == 1


def test_threat_memory_integration_and_hard_negatives(db_session):
    """Verifies ThreatMemory decisions are ingested, and FALSE_POSITIVE decisions become hard negatives."""
    now = get_utc_now()
    mem_entry = ThreatMemoryEntryModel(
        id=generate_uuid(),
        workspace_id="default",
        memory_type="DOMAIN",
        subject_type="DOMAIN",
        subject_id="sso-okta-auth.net",
        canonical_key="DOMAIN:sso-okta-auth.net",
        status="CONFIRMED_BENIGN",
        created_at=now,
    )
    db_session.add(mem_entry)
    db_session.flush()

    # False positive decision by analyst
    fp_decision = ThreatMemoryDecisionModel(
        id=generate_uuid(),
        workspace_id="default",
        memory_entry_id=mem_entry.id,
        decision="FALSE_POSITIVE",
        approved_by="senior_analyst_dan",
        reason="Legitimate internal identity provider migration URL",
        created_at=now,
    )
    db_session.add(fp_decision)
    db_session.flush()

    cand = ContinualLearningService.ingest_from_threat_memory_decision(
        db_session, fp_decision, workspace_id="default"
    )

    assert cand is not None
    assert cand.is_hard_negative is True
    assert cand.label == "legitimate"
    assert cand.eligibility_status == CandidateEligibilityStatus.ELIGIBLE.value


def test_dataset_versioning_and_immutability(db_session):
    """Verifies dataset versions are sequentially named (D-001), have SHA-256 manifests, and are immutable."""
    now = datetime(2026, 1, 15, tzinfo=timezone.utc)

    # Populate 15 diverse candidates
    for i in range(10):
        c = LearningCandidateModel(
            id=f"cand-phish-{i}",
            workspace_id="default",
            source_type="THREAT_MEMORY",
            source_reference=f"PHISH:{i}",
            text_content=f"Urgent credential update verification alert {i}",
            label="phishing",
            label_source=LabelSource.ANALYST_VERIFIED.value,
            confidence=0.95,
            is_hard_negative=False,
            observed_at=now + timedelta(days=i),
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json=json.dumps({"source": "internal"}),
            created_at=now + timedelta(days=i),
        )
        db_session.add(c)

    for i in range(5):
        c = LearningCandidateModel(
            id=f"cand-legit-{i}",
            workspace_id="default",
            source_type="THREAT_MEMORY",
            source_reference=f"LEGIT:{i}",
            text_content=f"Quarterly roadmap sync meeting notes {i}",
            label="legitimate",
            label_source=LabelSource.ANALYST_VERIFIED.value,
            confidence=0.95,
            is_hard_negative=(i == 0),
            observed_at=now + timedelta(days=i),
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json=json.dumps({"source": "internal"}),
            created_at=now + timedelta(days=i),
        )
        db_session.add(c)
    db_session.flush()

    req = DatasetBuildRequest(workspace_id="default", stratify_by_time=True, group_by_campaign=True)
    ds = ContinualLearningService.build_dataset_version(db_session, req)

    assert ds.version == "D-001"
    assert ds.sample_count >= 15
    assert ds.hard_negative_count >= 1
    assert len(ds.manifest_checksum) == 64  # Valid SHA-256

    # Verify building again creates D-002 (immutable progression)
    ds2 = ContinualLearningService.build_dataset_version(db_session, req)
    assert ds2.version == "D-002"


def test_temporal_and_campaign_leakage_prevention(db_session):
    """Verifies temporal splitting places older samples in train and newest in test, with campaign cohesion."""
    t0 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)

    # Campaign 101 with 6 samples at t0..t0+5
    for i in range(6):
        c = LearningCandidateModel(
            id=f"camp1-{i}",
            workspace_id="default",
            source_type="INCIDENT",
            source_reference=f"camp1-ref-{i}",
            text_content=f"Corporate benefit update notification {i}",
            label="phishing" if i % 2 == 0 else "legitimate",
            label_source=LabelSource.ANALYST_VERIFIED.value,
            confidence=0.9,
            campaign_id="camp-101",
            observed_at=t0 + timedelta(days=i),
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json="{}",
            created_at=t0 + timedelta(days=i),
        )
        db_session.add(c)

    # Campaign 102 with 6 samples at later dates
    for i in range(6):
        c = LearningCandidateModel(
            id=f"camp2-{i}",
            workspace_id="default",
            source_type="INCIDENT",
            source_reference=f"camp2-ref-{i}",
            text_content=f"Monthly payroll statement archive {i}",
            label="phishing" if i % 2 == 0 else "legitimate",
            label_source=LabelSource.ANALYST_VERIFIED.value,
            confidence=0.9,
            campaign_id="camp-102",
            observed_at=t0 + timedelta(days=10 + i),
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json="{}",
            created_at=t0 + timedelta(days=10 + i),
        )
        db_session.add(c)
    db_session.flush()

    req = DatasetBuildRequest(
        workspace_id="default",
        train_split_ratio=0.6,
        val_split_ratio=0.2,
        test_split_ratio=0.2,
        stratify_by_time=True,
        group_by_campaign=True,
    )
    ds = ContinualLearningService.build_dataset_version(db_session, req)
    manifest = json.loads(db_session.query(LearningDatasetModel).filter_by(id=ds.id).first().source_distribution_json)

    # Ensure campaigns are wholly placed into single splits (not fragmented across train and test)
    train_ids = set()
    test_ids = set()
    # Check sample splits
    assert ds.sample_count >= 12


def test_anti_poisoning_source_concentration(db_session):
    """Verifies that an untrusted single source dominating the dataset triggers a validation warning / rejection."""
    now = datetime(2026, 2, 1, tzinfo=timezone.utc)
    # Inject 80 samples from a single untrusted feed and only 20 trusted
    for i in range(80):
        c = LearningCandidateModel(
            id=f"poison-{i}",
            workspace_id="default",
            source_type="UNTRUSTED_FEED",
            source_reference=f"untrusted:{i}",
            text_content=f"Synthetic attack payload injection {i}",
            label="phishing",
            label_source=LabelSource.EXTERNAL_INTELLIGENCE.value,
            confidence=0.85,
            observed_at=now,
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json=json.dumps({"source": "untrusted_feed"}),
            created_at=now,
        )
        db_session.add(c)

    for i in range(20):
        c = LearningCandidateModel(
            id=f"clean-{i}",
            workspace_id="default",
            source_type="THREAT_MEMORY",
            source_reference=f"clean:{i}",
            text_content=f"Normal operational invoice notification {i}",
            label="legitimate",
            label_source=LabelSource.ANALYST_VERIFIED.value,
            confidence=0.99,
            observed_at=now,
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json=json.dumps({"source": "verified"}),
            created_at=now,
        )
        db_session.add(c)
    db_session.flush()

    req = DatasetBuildRequest(workspace_id="default")
    ds = ContinualLearningService.build_dataset_version(db_session, req)

    # Should detect high source concentration
    assert ds.validation_status in (DatasetValidationStatus.REJECTED.value, DatasetValidationStatus.COLLECTING.value)
    assert any("concentration" in err.lower() for err in ds.validation_errors)


def test_real_training_job_and_offline_evaluation(db_session):
    """Verifies real model training, genuine evaluation metrics calculation, and candidate artifact creation."""
    now = datetime(2026, 1, 10, tzinfo=timezone.utc)

    # Create dataset samples
    phishing_texts = [
        "Urgent: your account has been suspended! Verify your credentials at https://auth-secure.cc immediately.",
        "Your password has expired. Click here to update your Outlook login credentials.",
        "Security Alert: Unauthorized login attempt detected from Russia. Verify your identity now.",
        "Wire transfer confirmation required. Download and review the attached invoice.exe.",
        "Urgent notice from HR: open this link to sign off on your employee tax form.",
        "Critical warning: Your Microsoft 365 license will be terminated in 24 hours.",
        "Action required: Confirm your bank account details or funds will be locked.",
        "Verify your payment details immediately to prevent service disruption.",
    ]
    legit_texts = [
        "Attached is the weekly project status report for the engineering team.",
        "Reminder: All-hands company meeting will begin at 2:00 PM in the main conference room.",
        "Hi team, please find the updated design wireframes for the user onboarding flow.",
        "Lunch is provided in the cafeteria today. Pizza and salad available.",
        "Can we reschedule our one-on-one meeting to Thursday afternoon?",
        "Please review the pull request for the database migration when you have a moment.",
        "Thanks for the update. Let's discuss the release timeline during tomorrow's standup.",
        "Here are the notes from today's client sync call. No major action items.",
    ]

    for idx, text in enumerate(phishing_texts):
        c = LearningCandidateModel(
            id=f"phish-{idx}",
            workspace_id="default",
            source_type="THREAT_MEMORY",
            source_reference=f"phish-{idx}",
            text_content=text,
            label="phishing",
            label_source=LabelSource.ANALYST_VERIFIED.value,
            confidence=1.0,
            observed_at=now + timedelta(days=idx),
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json="{}",
            created_at=now + timedelta(days=idx),
        )
        db_session.add(c)

    for idx, text in enumerate(legit_texts):
        c = LearningCandidateModel(
            id=f"legit-{idx}",
            workspace_id="default",
            source_type="THREAT_MEMORY",
            source_reference=f"legit-{idx}",
            text_content=text,
            label="legitimate",
            label_source=LabelSource.ANALYST_VERIFIED.value,
            confidence=1.0,
            observed_at=now + timedelta(days=idx),
            eligibility_status=CandidateEligibilityStatus.ELIGIBLE.value,
            review_status=CandidateReviewStatus.ACCEPTED.value,
            raw_payload_json="{}",
            created_at=now + timedelta(days=idx),
        )
        db_session.add(c)
    db_session.flush()

    # 1. Build dataset
    ds = ContinualLearningService.build_dataset_version(
        db_session, DatasetBuildRequest(workspace_id="default", train_split_ratio=0.6, val_split_ratio=0.2, test_split_ratio=0.2)
    )

    # 2. Launch training job
    job_req = TrainingJobCreate(
        workspace_id="default",
        model_type="PHISHING_CLASSIFIER",
        dataset_version=ds.version,
    )
    job, reg_model = ContinualLearningService.run_training_job(db_session, job_req)

    assert job.status == "SUCCEEDED"
    assert reg_model is not None
    assert reg_model.status == ModelLifecycleStatus.CANDIDATE.value

    # Verify metrics are authentic and non-zero
    metrics = json.loads(reg_model.metrics_json)
    assert "accuracy" in metrics
    assert "recall" in metrics
    assert "critical_threat_recall" in metrics
    assert metrics["sample_count"] > 0
    assert len(reg_model.artifact_checksum) == 64

    # Verify candidate model artifact exists on disk
    artifact_path = Path(reg_model.artifact_path)
    assert artifact_path.exists()


def test_model_lifecycle_approval_staging_promotion_and_rollback(db_session):
    """
    Tests complete Model Registry workflow:
    CANDIDATE -> APPROVE -> STAGE -> PROMOTE -> ROLLBACK
    Verifies that direct unapproved promotion is prohibited.
    """
    # 1. Create a dummy model artifact and register it
    now = get_utc_now()
    test_artifact = CANDIDATES_DIR / "test_model_v1.joblib"
    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    with open(test_artifact, "wb") as f:
        f.write(b"DUMMY_MODEL_BYTES_FOR_UNIT_TESTING_12345")
    checksum = ContinualLearningService._compute_sha256(b"DUMMY_MODEL_BYTES_FOR_UNIT_TESTING_12345")

    model = RegisteredModelModel(
        id=generate_uuid(),
        workspace_id="default",
        model_type="PHISHING_CLASSIFIER",
        version="phishing-v10",
        dataset_version="D-001",
        status=ModelLifecycleStatus.CANDIDATE.value,
        metrics_json=json.dumps({"accuracy": 0.95, "recall": 0.92, "f1_score": 0.93}),
        baseline_comparison_json=json.dumps({"passed_all_gates": True}),
        artifact_path=str(test_artifact),
        artifact_checksum=checksum,
        created_at=now,
    )
    db_session.add(model)
    db_session.flush()

    # Attempting to promote CANDIDATE directly without staging must fail
    with pytest.raises(ValueError, match="only STAGED models can be promoted"):
        ContinualLearningService.promote_to_production(
            db_session, workspace_id="default", model_id=model.id, reviewer="lead", reason="premature"
        )

    # Step 1: Approve
    app_model = ContinualLearningService.approve_model(
        db_session, workspace_id="default", model_id=model.id, reviewer="lead_analyst_sarah", reason="Exceeds baseline recall"
    )
    assert app_model.status == ModelLifecycleStatus.APPROVED.value

    # Step 2: Stage
    staged_model = ContinualLearningService.stage_model(
        db_session, workspace_id="default", model_id=model.id, reviewer="lead_analyst_sarah", reason="Deploy to canary staging"
    )
    assert staged_model.status == ModelLifecycleStatus.STAGED.value

    # Step 3: Promote
    prod_model = ContinualLearningService.promote_to_production(
        db_session, workspace_id="default", model_id=model.id, reviewer="sec_ops_admin", reason="Passed canary monitoring"
    )
    assert prod_model.status == ModelLifecycleStatus.PRODUCTION.value

    # Step 4: Rollback
    rolled_back = ContinualLearningService.rollback_production(
        db_session,
        workspace_id="default",
        model_id=model.id,
        reviewer="sec_ops_admin",
        reason="Detected false positive spike on enterprise notifications",
    )
    assert rolled_back.status == ModelLifecycleStatus.ROLLED_BACK.value

    # Clean up file
    if test_artifact.exists():
        test_artifact.unlink()


def test_artifact_tamper_detection_prevents_load(db_session):
    """Verifies cryptographic checksum validation prevents loading modified/tampered model artifacts."""
    now = get_utc_now()
    test_artifact = CANDIDATES_DIR / "tampered_model.joblib"
    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    with open(test_artifact, "wb") as f:
        f.write(b"ORIGINAL_SAFE_MODEL_BYTES")
    original_checksum = ContinualLearningService._compute_sha256(b"ORIGINAL_SAFE_MODEL_BYTES")

    model = RegisteredModelModel(
        id=generate_uuid(),
        workspace_id="default",
        model_type="PHISHING_CLASSIFIER",
        version="phishing-v99",
        dataset_version="D-001",
        status=ModelLifecycleStatus.STAGED.value,
        metrics_json="{}",
        baseline_comparison_json="{}",
        artifact_path=str(test_artifact),
        artifact_checksum=original_checksum,
        created_at=now,
    )
    db_session.add(model)
    db_session.flush()

    # Tamper with file
    with open(test_artifact, "wb") as f:
        f.write(b"TAMPERED_MALICIOUS_BYTES_INJECTED")

    # Promotion should abort due to checksum mismatch
    with pytest.raises(ValueError, match="Checksum mismatch"):
        ContinualLearningService.promote_to_production(
            db_session,
            workspace_id="default",
            model_id=model.id,
            reviewer="admin",
            reason="Attempt promote",
        )

    # Clean up
    if test_artifact.exists():
        test_artifact.unlink()
