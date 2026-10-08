"""
Synthetic End-to-End Scenarios for Novelty & Emerging-Threat Detection (Section 22).

Implements the three mandatory scenarios specified in Sections 43, 44, and 45 of CyberGuard Section 22:
1. API Sequence Novelty -> Recurring Novel Pattern -> Emerging Pattern Candidate (without false maliciousness)
2. Novel Network Behavior (Device -> new domain -> new IP -> new port)
3. Legitimate Novelty (Approved SaaS Rollout produces novelty without being classified as malicious)
"""
import pytest
from datetime import datetime, timezone
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
)
from backend.schemas.novelty_detection import (
    BehaviorFamiliarityMatrix,
    EmergingPatternStatus,
    NoveltyCategory,
    NoveltyEvaluationRequest,
    NoveltyLevel,
)
from backend.services.novelty_detection_service import NoveltyDetectionService


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
# SYNTHETIC SCENARIO 1: API Sequence Novelty -> Recurring -> Emerging
# ============================================================================

def test_synthetic_scenario_1_api_novelty_to_emerging(db_session):
    """
    Scenario 1 (Section 43):
    Historical telemetry: GET /profile, GET /orders, GET /orders/{id}.
    Observed new sequence: GET /profile -> GET /admin/export -> GET /bulk-download.
    CyberGuard identifies novel behavior, then repeats across incidents,
    evolving: NOVEL -> RECURRING NOVEL PATTERN -> EMERGING PATTERN without declaring MALICIOUS.
    """
    # 1. Establish historical known baseline routes
    historical_routes = [
        {"method": "GET", "path": "/profile", "resource": "profile"},
        {"method": "GET", "path": "/orders", "resource": "orders"},
        {"method": "GET", "path": "/orders/101", "resource": "orders"},
        {"method": "GET", "path": "/orders/102", "resource": "orders"},
    ]
    for r in historical_routes:
        req = NoveltyEvaluationRequest(
            entity_type="SERVICE",
            entity_id="core-api",
            novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
            attributes={"method": r["method"], "path": r["path"], "resource_type": r["resource"]},
        )
        NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)

    # 2. First observation of new sequence in Incident A
    inc_a_id = str(uuid.uuid4())
    obs_seq_1 = ["GET /profile", "GET /admin/export", "GET /bulk-download"]
    req_inc_a = NoveltyEvaluationRequest(
        workspace_id="default",
        incident_id=inc_a_id,
        entity_type="API_CLIENT",
        entity_id="client-alpha",
        novelty_type=NoveltyCategory.NOVEL_ATTACK_SEQUENCE,
        attributes={"client": "client-alpha"},
        event_sequence=obs_seq_1,
        is_entity_anomalous=False,
    )
    res_a = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req_inc_a)

    # Verifications for first occurrence:
    assert res_a.assessment.novelty_level in (NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH)
    assert res_a.assessment.novelty_score >= 0.70
    # Must NOT claim malicious or zero-day
    assert "malicious" not in res_a.assessment.threat_assessment_note.lower() or "not constitute" in res_a.assessment.threat_assessment_note.lower()
    assert res_a.emerging_candidate is not None
    assert res_a.emerging_candidate.status == EmergingPatternStatus.OBSERVED
    assert res_a.emerging_candidate.observation_count == 1

    # 3. Repeat pattern across synthetic Incident B with client-beta
    inc_b_id = str(uuid.uuid4())
    req_inc_b = NoveltyEvaluationRequest(
        workspace_id="default",
        incident_id=inc_b_id,
        entity_type="API_CLIENT",
        entity_id="client-beta",
        novelty_type=NoveltyCategory.NOVEL_ATTACK_SEQUENCE,
        attributes={"client": "client-beta"},
        event_sequence=obs_seq_1,
        is_entity_anomalous=False,
    )
    res_b = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req_inc_b)

    # Verifications for recurrence across incidents:
    assert res_b.emerging_candidate is not None
    assert res_b.emerging_candidate.observation_count == 2
    assert res_b.emerging_candidate.entity_count == 2
    assert res_b.emerging_candidate.incident_count == 2
    # Candidate evolved to EMERGING status
    assert res_b.emerging_candidate.status == EmergingPatternStatus.EMERGING
    assert res_b.emerging_candidate.recurrence_score >= 25.0
    # Epistemic humility: STILL not automatically declared MALICIOUS
    assert res_b.assessment.behavior_familiarity_matrix in (BehaviorFamiliarityMatrix.NORMAL_FAMILIAR, BehaviorFamiliarityMatrix.NORMAL_NOVEL)


# ============================================================================
# SYNTHETIC SCENARIO 2: Novel Network Behavior
# ============================================================================

def test_synthetic_scenario_2_novel_network_behavior(db_session):
    """
    Scenario 2 (Section 44):
    Historical: Device A communicates with api.example.test, cdn.example.test, dns.example.test.
    Observed: Device A -> new domain -> new IP -> new port -> repeated periodic connections.
    CyberGuard produces structured novelty evidence without jumping to malware conclusions.
    """
    # 1. Establish historical network destinations for Device A
    known_dests = ["api.example.test", "cdn.example.test", "dns.example.test"]
    for d in known_dests:
        req = NoveltyEvaluationRequest(
            entity_type="DEVICE",
            entity_id="device-workstation-01",
            novelty_type=NoveltyCategory.NOVEL_DOMAIN_PATTERN,
            attributes={"domain": d, "is_ip": False},
        )
        NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)

    # 2. Observed new network contact
    inc_id = str(uuid.uuid4())
    new_domain_req = NoveltyEvaluationRequest(
        incident_id=inc_id,
        entity_type="DEVICE",
        entity_id="device-workstation-01",
        novelty_type=NoveltyCategory.NOVEL_DOMAIN_PATTERN,
        attributes={"domain": "c2-fastflux-node.biz", "is_ip": False},
        is_entity_anomalous=True,
    )
    res_domain = NoveltyDetectionService.evaluate_pattern(session=db_session, request=new_domain_req)

    # Unprecedented port and volume bracket
    new_net_req = NoveltyEvaluationRequest(
        incident_id=inc_id,
        entity_type="DEVICE",
        entity_id="device-workstation-01",
        novelty_type=NoveltyCategory.NOVEL_NETWORK_BEHAVIOR,
        attributes={
            "destination_category": "EXTERNAL",
            "port": 4444,  # Non-standard high port
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "byte_volume": 2048,
        },
        is_entity_anomalous=True,
    )
    res_net = NoveltyDetectionService.evaluate_pattern(session=db_session, request=new_net_req)

    # Verify structured novelty findings generated
    assert res_domain.assessment.novelty_level in (NoveltyLevel.MODERATE, NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH)
    assert res_domain.assessment.novelty_score >= 0.50
    assert res_net.assessment.novelty_level in (NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH)
    assert res_net.assessment.behavior_familiarity_matrix == BehaviorFamiliarityMatrix.UNUSUAL_NOVEL

    # Verify epistemic boundaries
    assert "zero-day" not in res_net.assessment.threat_assessment_note.lower()
    assert "compromise" not in res_net.assessment.threat_assessment_note.lower() or "not constitute" in res_net.assessment.threat_assessment_note.lower()


# ============================================================================
# SYNTHETIC SCENARIO 3: Legitimate SaaS Rollout (Mandatory)
# ============================================================================

def test_synthetic_scenario_3_legitimate_saas_rollout(db_session):
    """
    Scenario 3 (Section 45 - Mandatory):
    Simulate company deploying a new legitimate SaaS application (e.g. Workday / Salesforce).
    Creates: new domains, new IPs, new API endpoints.
    CyberGuard detects novelty, but does NOT automatically classify it as malicious.
    """
    # 1. Company begins using new Workday enterprise endpoints
    new_saas_routes = [
        {"path": "/workday/v1/auth/saml", "method": "POST"},
        {"path": "/workday/v1/directory/sync", "method": "GET"},
        {"path": "/workday/v1/reports/payroll", "method": "GET"},
    ]

    assessments = []
    for r in new_saas_routes:
        req = NoveltyEvaluationRequest(
            entity_type="SERVICE",
            entity_id="enterprise-sso-gateway",
            novelty_type=NoveltyCategory.NOVEL_API_BEHAVIOR,
            attributes={"method": r["method"], "path": r["path"], "resource_type": "workday"},
            is_entity_anomalous=False,  # Legitimate organizational rollout, normal behavior
        )
        res = NoveltyDetectionService.evaluate_pattern(session=db_session, request=req)
        assessments.append(res.assessment)

    # 2. Initial SaaS introduction was completely novel in retained telemetry
    assert assessments[0].novelty_level in (NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH)
    assert assessments[0].behavior_familiarity_matrix == BehaviorFamiliarityMatrix.NORMAL_NOVEL

    # Subsequent Workday endpoints share structural similarity with learned Workday family
    assert assessments[1].novelty_level in (NoveltyLevel.MODERATE, NoveltyLevel.HIGH)

    # 3. CRITICAL TEST: For all endpoints in legitimate rollout, none are classified as malicious
    for a in assessments:
        # Categorized exclusively into benign NORMAL quadrants (NORMAL_NOVEL or NORMAL_FAMILIAR)
        assert a.behavior_familiarity_matrix in (BehaviorFamiliarityMatrix.NORMAL_NOVEL, BehaviorFamiliarityMatrix.NORMAL_FAMILIAR)
        # Threat disclaimer remains explicit
        assert "not constitute independent evidence of malicious compromise" in a.threat_assessment_note

