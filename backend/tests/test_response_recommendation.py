"""
Unit tests for Section 28: Response Recommendation Engine.
Tests deterministic generation, approval boundaries, applicability filtering,
capability awareness, dependencies, conflicts, and audit logging.
"""

import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.models import (
    Base,
    ThreatEventModel,
    RiskAssessmentModel,
    ExplanationModel,
    ResponseRecommendationModel,
    ResponseCapabilityModel,
    AuditLogModel,
    generate_uuid,
    get_utc_now
)
from backend.services.response_recommendation_engine import ResponseRecommendationEngine
from backend.schemas.response_recommendation import (
    ActionTypeEnum,
    RecommendationPriorityEnum,
    RecommendationStatusEnum,
    ApplicabilityEnum,
    ReversibilityEnum,
    OperationalImpactEnum,
    CapabilityStateEnum
)


@pytest.fixture
def db_session():
    """Isolated in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def create_sample_threat_event(
    db,
    event_id: str = "EVT-TEST-01",
    score: float = 88.0,
    has_device: bool = False,
    has_ato: bool = False
) -> Tuple[ThreatEventModel, RiskAssessmentModel, ExplanationModel]:
    meta = {
        "sender": "attacker@micros0ft-update.com",
        "sender_domain": "micros0ft-update.com",
        "sender_ip": "198.51.100.44",
        "recipient": "victim_cfo@corp.com",
        "subject": "Urgent Security Verification",
        "urls": ["https://micros0ft-update.com/login/auth"],
        "domains": ["micros0ft-update.com"],
        "attachments": [{"filename": "invoice_update.docm", "sha256": "abcdef1234567890"}]
    }
    if has_device:
        meta["hostname"] = "WORKSTATION-CFO-01"
        meta["device_id"] = "DEV-9921"
    if has_ato:
        meta["session_id"] = "SESS-OAUTH-4411"

    event = ThreatEventModel(
        id=event_id,
        event_type="EMAIL_RECEIVED",
        severity="CRITICAL" if score >= 80 else "MEDIUM",
        status="PROCESSED",
        summary="Phishing attempt detected with lookalike domain.",
        source_artifact_id="MSG-001",
        analysis_run_id="RUN-01",
        metadata_json=json.dumps(meta),
        created_at=get_utc_now()
    )
    db.add(event)

    ra = RiskAssessmentModel(
        id=f"RA-{event_id}",
        workspace_id="default",
        scope_type="EVENT",
        scope_id=event_id,
        version=1,
        risk_score=score,
        risk_level="CRITICAL" if score >= 80 else "MEDIUM",
        severity="CRITICAL" if score >= 80 else "MEDIUM",
        confidence=0.92,
        confidence_level="VERY_HIGH",
        uncertainty_score=0.08,
        uncertainty="LOW",
        signals_json=json.dumps([
            {"category": "AUTH" if has_ato else "EMAIL", "evidence_refs": ["EV-01", "EV-02"]}
        ]),
        evidence_refs_json=json.dumps(["EV-01", "EV-02", "EV-03"])
    )
    db.add(ra)

    expl = ExplanationModel(
        id=f"EX-{event_id}",
        workspace_id="default",
        scope_type="EVENT",
        scope_id=event_id,
        explanation_version=1,
        risk_assessment_id=ra.id,
        summary="Grounded phishing and lookalike domain explanation.",
        explanation_units_json=json.dumps([
            {"id": "U-1", "claim": "Credential harvesting form detected", "claim_type": "URL", "evidence_refs": ["EV-01"]}
        ]),
        mitre_explanations_json=json.dumps([
            {"technique_id": "T1566.002", "technique_name": "Spearphishing Link"}
        ])
    )
    db.add(expl)
    db.commit()
    return event, ra, expl


from typing import Tuple


def test_recommendation_generation_deterministic(db_session):
    """Verifies that recommendation generation is deterministic and evidence-backed."""
    create_sample_threat_event(db_session, event_id="EVT-DET-01", score=88.0)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-DET-01",
        workspace_id="default"
    )

    assert len(recs) > 0
    # Must contain evidence preservation
    actions = [r.action_type for r in recs]
    assert ActionTypeEnum.PRESERVE_EMAIL.value in actions
    assert ActionTypeEnum.BLOCK_DOMAIN.value in actions
    assert ActionTypeEnum.REVIEW_EVIDENCE.value in actions

    # Same call returns identical recommendations without duplicates
    recs_again = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-DET-01",
        workspace_id="default"
    )
    assert len(recs_again) == len(recs)
    assert [r.id for r in recs_again] == [r.id for r in recs]


def test_consequential_actions_require_approval(db_session):
    """Consequential containment actions must NEVER bypass human approval."""
    create_sample_threat_event(db_session, event_id="EVT-APPR-01", score=92.0)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-APPR-01"
    )

    consequential_types = [
        ActionTypeEnum.BLOCK_DOMAIN.value,
        ActionTypeEnum.BLOCK_URL.value,
        ActionTypeEnum.QUARANTINE_FILE.value,
        ActionTypeEnum.ISOLATE_DEVICE.value,
        ActionTypeEnum.REVOKE_SESSION.value,
        ActionTypeEnum.FORCE_PASSWORD_RESET.value
    ]

    for r in recs:
        if r.action_type in consequential_types:
            assert r.approval_required is True, f"{r.action_type} must require approval"
            assert r.status == RecommendationStatusEnum.REVIEW_REQUIRED.value


def test_informational_actions_do_not_require_approval(db_session):
    """Non-consequential investigation & preservation actions do not block on approval."""
    create_sample_threat_event(db_session, event_id="EVT-INFO-01", score=75.0)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-INFO-01"
    )

    for r in recs:
        if r.action_type in [ActionTypeEnum.PRESERVE_EMAIL.value, ActionTypeEnum.REVIEW_EVIDENCE.value]:
            assert r.approval_required is False
            assert r.status == RecommendationStatusEnum.GENERATED.value


def test_applicability_suppresses_device_isolation_when_no_host(db_session):
    """When no endpoint is in evidence, ISOLATE_DEVICE must be marked NOT_APPLICABLE."""
    create_sample_threat_event(db_session, event_id="EVT-NOHOST-01", score=85.0, has_device=False)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-NOHOST-01"
    )

    isolate_rec = next((r for r in recs if r.action_type == ActionTypeEnum.ISOLATE_DEVICE.value), None)
    assert isolate_rec is not None
    assert isolate_rec.applicability == ApplicabilityEnum.NOT_APPLICABLE.value
    assert "No endpoint identity" in isolate_rec.applicability_reason


def test_applicability_allows_device_isolation_when_host_present(db_session):
    """When host is in evidence, ISOLATE_DEVICE is marked APPLICABLE with target."""
    create_sample_threat_event(db_session, event_id="EVT-HOST-01", score=85.0, has_device=True)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-HOST-01"
    )

    isolate_rec = next((r for r in recs if r.action_type == ActionTypeEnum.ISOLATE_DEVICE.value), None)
    assert isolate_rec is not None
    assert isolate_rec.applicability == ApplicabilityEnum.APPLICABLE.value
    entities = isolate_rec.affected_entities
    assert any(e.get("identifier") == "WORKSTATION-CFO-01" for e in entities)


def test_capability_awareness(db_session):
    """Engine respects registered capability states."""
    caps = ResponseRecommendationEngine.get_capabilities(db_session)
    assert ActionTypeEnum.ISOLATE_DEVICE.value in caps
    edr_cap = caps[ActionTypeEnum.ISOLATE_DEVICE.value]
    assert edr_cap.capability_state == CapabilityStateEnum.REQUIRES_CONFIGURATION.value


def test_recommendation_dependencies(db_session):
    """Quarantine file must depend on evidence preservation."""
    create_sample_threat_event(db_session, event_id="EVT-DEP-01", score=90.0)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-DEP-01"
    )

    quarantine = next((r for r in recs if r.action_type == ActionTypeEnum.QUARANTINE_FILE.value), None)
    preserve = next((r for r in recs if r.action_type == ActionTypeEnum.PRESERVE_ARTIFACT.value), None)

    if quarantine and preserve:
        assert preserve.id in quarantine.depends_on


def test_recommendation_confidence_separate_from_threat_confidence(db_session):
    """Threat confidence and recommendation confidence are mathematically distinct."""
    create_sample_threat_event(db_session, event_id="EVT-CONF-01", score=95.0, has_device=True)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-CONF-01"
    )

    # Threat confidence was 0.92
    isolate_rec = next(r for r in recs if r.action_type == ActionTypeEnum.ISOLATE_DEVICE.value)
    # Recommendation confidence is calibrated separately
    assert isolate_rec.confidence == 0.85


def test_expiration_and_supersession(db_session):
    """Regenerating recommendations supersedes older active recommendations."""
    create_sample_threat_event(db_session, event_id="EVT-SUP-01", score=60.0)
    recs_v1 = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-SUP-01"
    )
    v1_ids = [r.id for r in recs_v1]

    # Re-generate with force_regenerate=True
    recs_v2 = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-SUP-01",
        force_regenerate=True
    )

    # Check v1 status is SUPERSEDED
    old_recs = db_session.query(ResponseRecommendationModel).filter(
        ResponseRecommendationModel.id.in_(v1_ids)
    ).all()
    for o in old_recs:
        assert o.status == RecommendationStatusEnum.SUPERSEDED.value

    # Check v2 is active
    assert len(recs_v2) > 0
    assert all(r.status != RecommendationStatusEnum.SUPERSEDED.value for r in recs_v2)


def test_analyst_review_workflow(db_session):
    """Analyst review transitions recommendation to APPROVED and logs audit event."""
    create_sample_threat_event(db_session, event_id="EVT-REV-01", score=85.0)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-REV-01"
    )
    block_rec = next(r for r in recs if r.action_type == ActionTypeEnum.BLOCK_DOMAIN.value)
    assert block_rec.status == RecommendationStatusEnum.REVIEW_REQUIRED.value

    # Review approve
    updated = ResponseRecommendationEngine.review_recommendation(
        db=db_session,
        recommendation_id=block_rec.id,
        reviewer_id="analyst_jane",
        disposition="APPROVED",
        notes="Domain matches active typo-squatting campaign; authorized for DNS blocklist."
    )

    assert updated.status == RecommendationStatusEnum.APPROVED.value
    assert updated.reviewed_by == "analyst_jane"
    assert updated.status_reason == "Domain matches active typo-squatting campaign; authorized for DNS blocklist."

    # Audit log check
    audit = db_session.query(AuditLogModel).filter(
        AuditLogModel.action == "RECOMMENDATION_APPROVED",
        AuditLogModel.resource_id == block_rec.id
    ).first()
    assert audit is not None
    assert audit.user == "analyst_jane"


def test_analyst_review_reject(db_session):
    """Analyst review can reject a false positive recommendation."""
    create_sample_threat_event(db_session, event_id="EVT-REJ-01", score=65.0)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-REJ-01"
    )
    block_rec = next(r for r in recs if r.action_type == ActionTypeEnum.BLOCK_DOMAIN.value)

    rejected = ResponseRecommendationEngine.review_recommendation(
        db=db_session,
        recommendation_id=block_rec.id,
        reviewer_id="analyst_bob",
        disposition="REJECTED",
        notes="Domain is verified internal test subdomain."
    )
    assert rejected.status == RecommendationStatusEnum.REJECTED.value
    assert rejected.reviewed_by == "analyst_bob"


def test_reversibility_and_impact_classification(db_session):
    """Verifies that reversibility and impact classes are accurately assigned."""
    create_sample_threat_event(db_session, event_id="EVT-REVIMP-01", score=90.0, has_ato=True)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-REVIMP-01"
    )

    for r in recs:
        if r.action_type == ActionTypeEnum.REVOKE_SESSION.value:
            assert r.reversibility == ReversibilityEnum.REVERSIBLE.value
            assert r.impact == OperationalImpactEnum.MEDIUM.value
        elif r.action_type == ActionTypeEnum.FORCE_PASSWORD_RESET.value:
            assert r.reversibility == ReversibilityEnum.PARTIALLY_REVERSIBLE.value
            assert r.impact == OperationalImpactEnum.MEDIUM.value
        elif r.action_type == ActionTypeEnum.REVIEW_EVIDENCE.value:
            assert r.reversibility == ReversibilityEnum.REVERSIBLE.value
            assert r.impact == OperationalImpactEnum.NONE.value


def test_priority_ordering(db_session):
    """P0 and P1 recommendations precede P2 and P3."""
    create_sample_threat_event(db_session, event_id="EVT-ORDER-01", score=94.0, has_ato=True)
    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-ORDER-01"
    )

    priorities = [r.priority for r in recs]
    # Check that priority order is non-decreasing (e.g. P0 <= P1 <= P2)
    p_map = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    p_nums = [p_map[p] for p in priorities]
    assert p_nums == sorted(p_nums)


def test_end_to_end_scenario_52(db_session):
    """
    Deterministic synthetic test matching Section 52:
    - Email received with impersonation & credential harvesting URL
    - Recipient visits URL, unusual login occurs, privileged API activity follows
    - Risk: 94 / 100, CRITICAL, VERY_HIGH confidence
    - XAI: Multi-stage attack path
    - Response Recommendation Engine must derive:
      * P0 evidence preservation (email/URL/auth/API logs)
      * P0 session revocation consideration
      * P1 account/privileged review
      * P1 domain block consideration
      * P2 notifications / campaign correlation
    """
    create_sample_threat_event(
        db_session,
        event_id="EVT-SCENARIO-52",
        score=94.0,
        has_ato=True,
        has_device=True
    )

    recs = ResponseRecommendationEngine.generate_recommendations(
        db=db_session,
        scope_type="EVENT",
        scope_id="EVT-SCENARIO-52"
    )

    assert len(recs) >= 5

    action_types = [r.action_type for r in recs]

    # Verify P0 recommendations include evidence preservation and session revocation
    p0_recs = [r for r in recs if r.priority == RecommendationPriorityEnum.P0.value]
    p0_types = [r.action_type for r in p0_recs]
    assert any("PRESERVE" in t for t in p0_types), "Must have P0 preservation action"
    assert ActionTypeEnum.REVOKE_SESSION.value in p0_types, "Must have P0 session revocation action"

    # Verify P1 contains domain containment and credential/account actions
    p1_recs = [r for r in recs if r.priority == RecommendationPriorityEnum.P1.value]
    p1_types = [r.action_type for r in p1_recs]
    assert ActionTypeEnum.BLOCK_DOMAIN.value in p1_types or ActionTypeEnum.FORCE_PASSWORD_RESET.value in p1_types

    # Verify evidence references on consequential recommendations
    block_rec = next((r for r in recs if r.action_type == ActionTypeEnum.BLOCK_DOMAIN.value), None)
    if block_rec:
        assert len(block_rec.evidence_refs) > 0
        assert block_rec.approval_required is True

    # Verify affected entities are accurately tracked
    session_rec = next(r for r in recs if r.action_type == ActionTypeEnum.REVOKE_SESSION.value)
    assert any(e.get("identifier") in ["victim_cfo@corp.com", "SESS-OAUTH-4411"] for e in session_rec.affected_entities)

