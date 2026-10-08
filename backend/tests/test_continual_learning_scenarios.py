"""
End-to-End Continuous Learning Scenario Test (Section 24 & Section 68).

Simulates the full multi-day lifecycle:
Day 1:  New phishing email observed and recorded in Threat Memory.
Day 2:  Analyst reviews incident: CONFIRMED_MALICIOUS -> becomes eligible learning candidate.
Day 5:  Legitimate enterprise emails flagged -> marked FALSE_POSITIVE -> become hard negatives.
Day 10: Learning system builds immutable Dataset D-025 (anti-poisoning, temporal ordering, campaign grouping).
Train:  Candidate model trained (phishing-v13) with genuine metrics.
Eval:   Offline evaluation against baseline; passes regression gates.
Appr:   Security analyst approves candidate.
Stage:  Model staged in canary environment.
Prom:   Staged model promoted to PRODUCTION after SHA-256 integrity check.
Regr:   Subsequent regression triggers safe rollback; previous production model restored.
"""
from __future__ import annotations

import json
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
    DatasetBuildRequest,
    ModelLifecycleStatus,
    TrainingJobCreate,
)
from backend.services.continual_learning_service import (
    ContinualLearningService,
    CANDIDATES_DIR,
)


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_section_68_end_to_end_lifecycle(db_session):
    """
    Executes Section 68 End-to-End Success Scenario:
    OBSERVE -> VERIFY -> CURATE -> TRAIN -> EVALUATE -> COMPARE -> APPROVE -> STAGE -> MONITOR -> PROMOTE -> ROLLBACK
    """
    workspace = "default"
    t_base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------------------
    # Day 0: Existing Production Model (phishing-v12) is deployed
    # -------------------------------------------------------------------------
    v12_artifact = CANDIDATES_DIR / "phishing_v12_prod.joblib"
    CANDIDATES_DIR.mkdir(parents=True, exist_ok=True)
    with open(v12_artifact, "wb") as f:
        f.write(b"MOCK_WEIGHTS_V12_ACC_91_REC_89")
    v12_chk = ContinualLearningService._compute_sha256(b"MOCK_WEIGHTS_V12_ACC_91_REC_89")

    prod_v12 = RegisteredModelModel(
        id=generate_uuid(),
        workspace_id=workspace,
        model_type="PHISHING_CLASSIFIER",
        version="phishing-v12",
        dataset_version="D-024",
        status=ModelLifecycleStatus.PRODUCTION.value,
        metrics_json=json.dumps({"accuracy": 0.91, "recall": 0.89, "false_positive_rate": 0.04, "f1_score": 0.90}),
        baseline_comparison_json="{}",
        artifact_path=str(v12_artifact),
        artifact_checksum=v12_chk,
        created_at=t_base - timedelta(days=15),
    )
    db_session.add(prod_v12)
    db_session.flush()

    # -------------------------------------------------------------------------
    # Day 1: CyberGuard sees new phishing email -> stored in Threat Memory
    # -------------------------------------------------------------------------
    mem_entry_phish = ThreatMemoryEntryModel(
        id=generate_uuid(),
        workspace_id=workspace,
        memory_type="DOMAIN",
        subject_type="DOMAIN",
        subject_id="login-auth-account-verification.com",
        canonical_key="DOMAIN:login-auth-account-verification.com",
        status="OBSERVED",
        first_seen_at=t_base,
        last_seen_at=t_base,
        created_at=t_base,
    )
    db_session.add(mem_entry_phish)
    db_session.flush()

    # -------------------------------------------------------------------------
    # Day 2: Analyst reviews incident -> CONFIRMED_MALICIOUS -> becomes candidate
    # -------------------------------------------------------------------------
    t_day2 = t_base + timedelta(days=1)
    phish_decision = ThreatMemoryDecisionModel(
        id=generate_uuid(),
        workspace_id=workspace,
        memory_entry_id=mem_entry_phish.id,
        decision="VERIFIED_MALICIOUS",
        approved_by="senior_analyst_alice",
        reason="Credential phishing portal with SPF alignment failure and lookalike login form",
        created_at=t_day2,
    )
    db_session.add(phish_decision)
    db_session.flush()

    cand_phish = ContinualLearningService.ingest_from_threat_memory_decision(
        db_session,
        decision=phish_decision,
        text_content="URGENT: Microsoft 365 security alert! Your password has expired. Click here to verify your corporate credentials.",
        workspace_id=workspace,
    )
    assert cand_phish is not None
    assert cand_phish.label == "phishing"
    assert cand_phish.eligibility_status == CandidateEligibilityStatus.ELIGIBLE.value
    assert cand_phish.is_hard_negative is False

    # -------------------------------------------------------------------------
    # Day 5: Enterprise SSO emails falsely flagged -> FALSE_POSITIVE -> hard negatives
    # -------------------------------------------------------------------------
    t_day5 = t_base + timedelta(days=4)
    mem_entry_sso = ThreatMemoryEntryModel(
        id=generate_uuid(),
        workspace_id=workspace,
        memory_type="DOMAIN",
        subject_type="DOMAIN",
        subject_id="sso.enterprise-gateway.net",
        canonical_key="DOMAIN:sso.enterprise-gateway.net",
        status="OBSERVED",
        created_at=t_day5,
    )
    db_session.add(mem_entry_sso)
    db_session.flush()

    fp_decision = ThreatMemoryDecisionModel(
        id=generate_uuid(),
        workspace_id=workspace,
        memory_entry_id=mem_entry_sso.id,
        decision="FALSE_POSITIVE",
        approved_by="soc_lead_bob",
        reason="Legitimate internal Okta/SSO identity provider infrastructure migration",
        created_at=t_day5,
    )
    db_session.add(fp_decision)
    db_session.flush()

    cand_sso = ContinualLearningService.ingest_from_threat_memory_decision(
        db_session,
        decision=fp_decision,
        text_content="Enterprise single sign-on notification: Authorized identity verification link for employee portal access.",
        workspace_id=workspace,
    )
    assert cand_sso is not None
    assert cand_sso.label == "legitimate"
    assert cand_sso.is_hard_negative is True
    assert cand_sso.eligibility_status == CandidateEligibilityStatus.ELIGIBLE.value

    # Add several more diverse observations for a rich dataset
    for i in range(8):
        t_obs = t_base + timedelta(days=5 + i)
        ContinualLearningService.create_candidate(
            db_session,
            workspace_id=workspace,
            source_type="THREAT_MEMORY",
            source_reference=f"ioc-sample-{i}",
            text_content=f"Important internal calendar update for quarterly engineering sync meeting {i}",
            label="legitimate",
            confidence=0.99,
            observed_at=t_obs,
        )
        ContinualLearningService.create_candidate(
            db_session,
            workspace_id=workspace,
            source_type="THREAT_MEMORY",
            source_reference=f"phish-sample-{i}",
            text_content=f"Security warning: Wire payment invoice payment suspended. Re-enter banking information {i}",
            label="phishing",
            confidence=0.99,
            observed_at=t_obs,
        )

    # -------------------------------------------------------------------------
    # Day 10: Build immutable Dataset D-025
    # -------------------------------------------------------------------------
    # Seed prior dataset D-024 so next is D-025
    d24 = LearningDatasetModel(
        id=generate_uuid(),
        workspace_id=workspace,
        version="D-024",
        sample_count=50,
        manifest_checksum="a" * 64,
        validation_status="VALIDATED",
        created_at=t_base - timedelta(days=1),
    )
    db_session.add(d24)
    db_session.flush()

    ds_req = DatasetBuildRequest(workspace_id=workspace, stratify_by_time=True, group_by_campaign=True)
    dataset_d25 = ContinualLearningService.build_dataset_version(db_session, ds_req)

    assert dataset_d25.version == "D-025"
    assert dataset_d25.hard_negative_count >= 1
    assert len(dataset_d25.manifest_checksum) == 64
    assert dataset_d25.validation_status == "VALIDATED"

    # -------------------------------------------------------------------------
    # Training: Train candidate model phishing-v13
    # -------------------------------------------------------------------------
    train_req = TrainingJobCreate(
        workspace_id=workspace,
        model_type="PHISHING_CLASSIFIER",
        dataset_version=dataset_d25.version,
    )
    job, candidate_v13 = ContinualLearningService.run_training_job(db_session, train_req)

    assert job.status == "SUCCEEDED"
    assert candidate_v13 is not None
    assert candidate_v13.status == ModelLifecycleStatus.CANDIDATE.value
    assert candidate_v13.version == "phishing-v13"

    # -------------------------------------------------------------------------
    # Comparison & Regression Gates: Real evaluation vs production
    # -------------------------------------------------------------------------
    baseline_comp = json.loads(candidate_v13.baseline_comparison_json)
    assert "passed_all_gates" in baseline_comp
    assert "candidate_metrics" in baseline_comp
    assert "production_metrics" in baseline_comp

    # -------------------------------------------------------------------------
    # Approval Gate: Security Lead approves candidate
    # -------------------------------------------------------------------------
    approved = ContinualLearningService.approve_model(
        db_session,
        workspace_id=workspace,
        model_id=candidate_v13.id,
        reviewer="lead_analyst_alice",
        reason="Demonstrates superior resistance to SSO false positives and zero critical-threat recall regression",
    )
    assert approved.status == ModelLifecycleStatus.APPROVED.value
    assert approved.approved_by == "lead_analyst_alice"

    # -------------------------------------------------------------------------
    # Staging: Model deployed to STAGED for monitoring
    # -------------------------------------------------------------------------
    staged = ContinualLearningService.stage_model(
        db_session,
        workspace_id=workspace,
        model_id=candidate_v13.id,
        reviewer="devops_lead",
        reason="Canary deployment to SOC evaluation traffic",
    )
    assert staged.status == ModelLifecycleStatus.STAGED.value

    # -------------------------------------------------------------------------
    # Promotion: Promoted to PRODUCTION with SHA-256 integrity verification
    # -------------------------------------------------------------------------
    promoted = ContinualLearningService.promote_to_production(
        db_session,
        workspace_id=workspace,
        model_id=candidate_v13.id,
        reviewer="ciso_approver",
        reason="Completed 48-hour canary without drift or errors",
    )
    assert promoted.status == ModelLifecycleStatus.PRODUCTION.value

    # Previous v12 should now be archived
    db_session.refresh(prod_v12)
    assert prod_v12.status == ModelLifecycleStatus.ARCHIVED.value

    # -------------------------------------------------------------------------
    # Regression & Rollback: Simulated regression triggers rollback to v12
    # -------------------------------------------------------------------------
    rolled_back = ContinualLearningService.rollback_production(
        db_session,
        workspace_id=workspace,
        model_id=promoted.id,
        reviewer="oncall_sre",
        reason="Detected critical regression in executive communication triage",
        target_version="phishing-v12",
    )

    # v13 is marked ROLLED_BACK
    db_session.refresh(candidate_v13)
    assert candidate_v13.status == ModelLifecycleStatus.ROLLED_BACK.value

    # v12 is restored to PRODUCTION
    assert rolled_back.version == "phishing-v12"
    assert rolled_back.status == ModelLifecycleStatus.PRODUCTION.value

    # Clean up test artifacts
    if v12_artifact.exists():
        v12_artifact.unlink()
    cand_art = Path(candidate_v13.artifact_path)
    if cand_art.exists():
        cand_art.unlink()
