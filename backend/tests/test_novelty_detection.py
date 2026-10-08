"""
Unit and Integration Tests for Novelty & Emerging-Threat Detection Engine (Section 22).

Covers exact matching, structural similarity, sequence novelty, combination novelty,
retention boundaries, poisoning safeguards, contextual suppressions, privacy validation,
and emerging pattern recurrence lifecycle.
"""
import pytest
from datetime import datetime, timezone, timedelta
import json
import uuid
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import (
    IncidentModel,
    NoveltyAssessmentModel,
    PatternFingerprintModel,
    EmergingPatternCandidateModel,
    NoveltySuppressionRuleModel,
)
from backend.schemas.novelty_detection import (
    BehaviorFamiliarityMatrix,
    EmergingPatternStatus,
    NoveltyCategory,
    NoveltyEvaluationRequest,
    NoveltyLevel,
    NoveltySuppressionRule,
    validate_novelty_privacy,
)
from backend.services.novelty_fingerprinter import NoveltyFingerprinter
from backend.services.novelty_similarity import NoveltySimilarityService
from backend.services.novelty_detection_service import NoveltyDetectionService
from backend.config.novelty_config import DEFAULT_NOVELTY_CONFIG


@pytest.fixture
def db_session():
    """In-memory SQLite session with all models created."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


# ============================================================================
# 1. EXACT NOVELTY TESTS
# ============================================================================

def test_01_first_seen_domain_is_novel(db_session):
    """Never-before-seen domain pattern should evaluate to high novelty."""
    req = NoveltyEvaluationRequest(
        entity_type="DOMAIN",
        entity_id="never-seen-suspicious-fast-flux.xyz",
        novelty_type=NoveltyCategory.NOVEL_DOMAIN_PATTERN,
        attributes={"domain": "never-seen-suspicious-fast-flux.xyz", "is_ip": False},
    )
    res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
    assert res.assessment.novelty_score >= 0.90
    assert res.assessment.novelty_level == NoveltyLevel.VERY_HIGH
    assert res.assessment.historical_sample_count == 0
    assert "retained telemetry" in res.assessment.supporting_evidence[0]["description"]


def test_02_previously_seen_domain_is_known(db_session):
    """Evaluating the same domain pattern a second time evaluates to KNOWN."""
    req = NoveltyEvaluationRequest(
        entity_type="DOMAIN",
        entity_id="corp-portal.com",
        novelty_type=NoveltyCategory.NOVEL_DOMAIN_PATTERN,
        attributes={"domain": "corp-portal.com", "is_ip": False},
    )
    # First observation records it
    res1 = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
    assert res1.assessment.novelty_level == NoveltyLevel.VERY_HIGH

    # Second observation recognizes it
    res2 = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
    assert res2.assessment.novelty_score <= 0.05
    assert res2.assessment.novelty_level == NoveltyLevel.KNOWN
    assert res2.assessment.historical_sample_count >= 1


def test_03_first_seen_api_route_vs_existing(db_session):
    """First-seen API route should be evaluated as novel, while standard routes match."""
    # Seed standard route
    seed_req = NoveltyEvaluationRequest(
        entity_type="SERVICE",
        entity_id="user-service",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={"method": "GET", "path": "/api/v1/users/123", "resource_type": "users"},
    )
    NoveltyDetectionService.evaluate_pattern(session=db_session, request=seed_req)

    # Re-evaluate identical structure with different numeric ID (normalized to {id})
    same_req = NoveltyEvaluationRequest(
        entity_type="SERVICE",
        entity_id="user-service",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={"method": "GET", "path": "/api/v1/users/456", "resource_type": "users"},
    )
    same_res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=same_req)
    assert same_res.assessment.novelty_level == NoveltyLevel.KNOWN

    # Unseen privileged export route
    novel_req = NoveltyEvaluationRequest(
        entity_type="SERVICE",
        entity_id="user-service",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={"method": "POST", "path": "/api/admin/export/raw_dump", "resource_type": "admin_export", "is_privileged": True},
    )
    novel_res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=novel_req)
    assert novel_res.assessment.novelty_score >= 0.70
    assert novel_res.assessment.novelty_level in (NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH)


# ============================================================================
# 2. STRUCTURAL NOVELTY TESTS
# ============================================================================

def test_04_structural_url_similarity(db_session):
    """URLs with similar structure have lower novelty than completely alien structures."""
    # Seed base URL
    seed_req = NoveltyEvaluationRequest(
        entity_type="URL",
        entity_id="url1",
        novelty_type=NoveltyCategory.NOVEL_URL_STRUCTURE,
        attributes={"url": "https://company.test/login/sso", "param_keys": ["client_id", "redirect_uri"]},
    )
    NoveltyDetectionService.evaluate_pattern(session=db_session, request=seed_req)

    # Similar URL: same path depth, 1 shared param key
    sim_req = NoveltyEvaluationRequest(
        entity_type="URL",
        entity_id="url2",
        novelty_type=NoveltyCategory.NOVEL_URL_STRUCTURE,
        attributes={"url": "https://company.test/login/oauth", "param_keys": ["client_id", "response_type"]},
    )
    sim_res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=sim_req)
    # Similar structure has moderate similarity
    assert sim_res.assessment.similarity_score > 0.40
    assert sim_res.assessment.novelty_score < 0.70


# ============================================================================
# 3. SEQUENCE NOVELTY TESTS
# ============================================================================

def test_05_sequence_novelty_alignment(db_session):
    """Known event sequence matches; brand new transition sequence is flagged novel."""
    known_seq = ["AUTHENTICATION", "MFA_CHALLENGE", "API_REQUEST"]
    seed_req = NoveltyEvaluationRequest(
        entity_type="USER",
        entity_id="bob",
        novelty_type=NoveltyCategory.NOVEL_ATTACK_SEQUENCE,
        attributes={},
        event_sequence=known_seq,
    )
    NoveltyDetectionService.evaluate_pattern(session=db_session, request=seed_req)

    # Same sequence -> KNOWN
    same_res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=seed_req)
    assert same_res.assessment.novelty_level == NoveltyLevel.KNOWN

    # Unprecedented sequence -> novel
    alien_seq = ["AUTHENTICATION", "API_REQUEST", "DATA_ACCESS", "BULK_EXFILTRATION"]
    novel_req = NoveltyEvaluationRequest(
        entity_type="USER",
        entity_id="bob",
        novelty_type=NoveltyCategory.NOVEL_ATTACK_SEQUENCE,
        attributes={},
        event_sequence=alien_seq,
    )
    novel_res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=novel_req)
    assert novel_res.assessment.novelty_score > 0.40


# ============================================================================
# 4. COMBINATION NOVELTY TESTS
# ============================================================================

def test_06_multi_signal_combination_novelty(db_session):
    """Normal individual signals that combine into an unseen tuple evaluate as novel."""
    combo_req = NoveltyEvaluationRequest(
        entity_type="ACCOUNT",
        entity_id="alice",
        novelty_type=NoveltyCategory.NOVEL_EVENT_COMBINATION,
        attributes={
            "auth_method": "PASSWORD",
            "device": "NEW_MACBOOK",
            "source_network": "EXTERNAL_IP",
            "privilege": "ADMIN",
            "export_size": "LARGE",
        },
        is_entity_anomalous=True,
    )
    res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=combo_req)
    assert res.assessment.novelty_level in (NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH)
    # Verify 4-quadrant matrix
    assert res.assessment.behavior_familiarity_matrix == BehaviorFamiliarityMatrix.UNUSUAL_NOVEL


# ============================================================================
# 5. EMERGING PATTERN RECURRENCE LIFECYCLE
# ============================================================================

def test_07_emerging_pattern_recurrence_transition(db_session):
    """Recurring novel pattern across entities evolves from OBSERVED to EMERGING."""
    # First observation creates OBSERVED candidate
    req1 = NoveltyEvaluationRequest(
        entity_type="API_CLIENT",
        entity_id="client-01",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={"method": "PUT", "path": "/internal/debug/memory", "is_privileged": True},
    )
    res1 = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req1)
    assert res1.emerging_candidate is not None
    assert res1.emerging_candidate.status == EmergingPatternStatus.OBSERVED
    assert res1.emerging_candidate.observation_count == 1

    # Second observation on different entity advances candidate to EMERGING
    req2 = NoveltyEvaluationRequest(
        entity_type="API_CLIENT",
        entity_id="client-02",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={"method": "PUT", "path": "/internal/debug/memory", "is_privileged": True},
    )
    res2 = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req2)
    assert res2.emerging_candidate is not None
    assert res2.emerging_candidate.observation_count == 2
    assert res2.emerging_candidate.entity_count == 2
    assert res2.emerging_candidate.status == EmergingPatternStatus.EMERGING
    assert res2.emerging_candidate.recurrence_score >= 20.0


# ============================================================================
# 6. RETENTION WINDOW BOUNDARY
# ============================================================================

def test_08_retention_window_cutoff(db_session):
    """Patterns observed older than MAX_HISTORY_LOOKBACK_DAYS are not counted."""
    now = datetime.now(timezone.utc)
    # Insert old fingerprint 120 days ago (outside 90 day window)
    old_fp = PatternFingerprintModel(
        id=str(uuid.uuid4()),
        workspace_id="default",
        pattern_type=NoveltyCategory.NOVEL_DOMAIN_PATTERN.value,
        fingerprint_hash="test_old_hash",
        fingerprint_repr="DOMAIN:.test",
        attributes_json=json.dumps({"domain": "legacy.test"}),
        first_seen_at=now - timedelta(days=120),
        last_seen_at=now - timedelta(days=120),
        observation_count=50,
    )
    db_session.add(old_fp)
    db_session.commit()

    # Querying today evaluates against retained window (cutoff at 90 days)
    req = NoveltyEvaluationRequest(
        entity_type="DOMAIN",
        entity_id="new.test",
        novelty_type=NoveltyCategory.NOVEL_DOMAIN_PATTERN,
        attributes={"domain": "new.test"},
    )
    res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
    assert res.assessment.historical_sample_count == 0  # Old record excluded by retention boundary


# ============================================================================
# 7. POISONING SAFEGUARD
# ============================================================================

def test_09_poisoning_safeguard_excludes_malicious_telemetry(db_session):
    """Confirmed malicious or quarantined telemetry does not update benign baseline library."""
    req = NoveltyEvaluationRequest(
        entity_type="SERVICE",
        entity_id="vuln-service",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={
            "method": "POST",
            "path": "/api/exploit",
            "is_malicious": True,
            "quarantined": True,
        },
    )
    res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
    # The assessment notes the poisoning safeguard
    reasons = [e["type"] for e in res.assessment.contradicting_evidence]
    assert "POISONING_SAFEGUARD_ACTIVE" in reasons

    # Fingerprint was NOT saved into historical library
    fps = db_session.query(PatternFingerprintModel).filter(
        PatternFingerprintModel.pattern_type == NoveltyCategory.NOVEL_API_BEHAVIOR.value
    ).all()
    assert len(fps) == 0


# ============================================================================
# 8. CONTEXTUAL SUPPRESSION
# ============================================================================

def test_10_contextual_suppression_approved_rollout(db_session):
    """Contextual suppression rule prevents false positive alerts on approved changes."""
    # Register suppression rule for new SaaS rollout
    rule = NoveltySuppressionRule(
        id=str(uuid.uuid4()),
        workspace_id="default",
        pattern_type=NoveltyCategory.NOVEL_API_BEHAVIOR.value,
        entity_type="SERVICE",
        entity_id="crm-sync",
        reason="Approved Q4 SaaS Migration to New Hub",
        approved_by="CAB-Ticket-9912",
    )
    NoveltyDetectionService.register_suppression_rule(session=db_session, rule=rule)

    req = NoveltyEvaluationRequest(
        entity_type="SERVICE",
        entity_id="crm-sync",
        novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
        attributes={"method": "PATCH", "path": "/api/v2/contacts/sync"},
    )
    res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
    assert res.is_suppressed is True
    assert res.assessment.status.value == "SUPPRESSED"
    assert res.assessment.novelty_level == NoveltyLevel.KNOWN
    assert res.suppression_details["approved_by"] == "CAB-Ticket-9912"


# ============================================================================
# 9. PRIVACY SAFEGUARDS
# ============================================================================

def test_11_privacy_validation_forbids_credentials_and_secrets():
    """Privacy validation strictly rejects raw passwords, bearer tokens, or API keys."""
    with pytest.raises(ValueError, match="Privacy violation"):
        validate_novelty_privacy("password", "Secret123!")

    with pytest.raises(ValueError, match="Privacy violation"):
        validate_novelty_privacy("auth_header", "Bearer eyJhbGciOi...")

    with pytest.raises(ValueError, match="Privacy violation"):
        validate_novelty_privacy("api_key", "sk-live-999")

    # Safe attributes pass without error
    validate_novelty_privacy("resource_type", "users")
    validate_novelty_privacy("method", "GET")
    validate_novelty_privacy("direction", "OUTBOUND")
