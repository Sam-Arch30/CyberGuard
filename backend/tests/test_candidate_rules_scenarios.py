"""
End-to-end scenario test for Section 25: Emerging Pattern & Candidate Rule Engine.

Executes the full Section 60 lifecycle:
1. Recurring novel URL structure observed across multiple investigations.
2. Section 22 produces EmergingPatternCandidate (EMERGING status).
3. Candidate Rule Engine synthesizes Candidate Rule CR-017 (STRUCTURAL generalization).
4. Candidate Rule undergoes historical backtesting against labeled and unlabeled events.
5. Analyst reviews quality report, limitations, and approves CR-017.
6. Rule is placed in STAGED shadow mode (evaluating incoming events with zero alert disruption).
7. Shadow mode validates low false positives; rule is promoted to ACTIVE production detection.
8. Active production rule evaluates incoming event, matches, and synthesizes ThreatEvent finding.
9. Security engineer tunes threshold: CR-017 v1 is superseded by CR-017 v2, preserving complete immutable lineage.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.db.session import Base
from backend.db.models import (
    CandidateRuleModel,
    CandidateRuleVersionModel,
    CandidateRuleExecutionModel,
    EmergingPatternCandidateModel,
    ThreatEventModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.candidate_rules import (
    CandidateRuleFromPatternRequest,
    DslOperator,
    GeneralizationLevel,
    RuleBacktestRequest,
    RuleCondition,
    RuleDefinition,
    RuleEditRequest,
    RuleLifecycleStatus,
    RuleReviewActionRequest,
    RuleScope,
    RuleSeverity,
    RuleType,
)
from backend.services.candidate_rule_service import CandidateRuleService


@pytest.fixture
def db_session():
    """Provides isolated in-memory SQLite database session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        yield session
    finally:
        session.close()


def test_section_60_end_to_end_candidate_rule_lifecycle(db_session):
    """
    Validates Section 60 contract:
    DISCOVER -> FORMALIZE -> VALIDATE -> HISTORICAL BACKTEST -> FALSE-POSITIVE ANALYSIS ->
    HUMAN REVIEW -> APPROVED -> STAGED (SHADOW) -> MONITOR -> ACTIVE -> TUNE / SUPERSEDE.
    """
    ws = "ws-sec60"

    # Step 1: Emerging Pattern Candidate discovered across 5 incidents
    pat = EmergingPatternCandidateModel(
        id="pat-e2e-01",
        workspace_id=ws,
        incident_id="inc-init",
        pattern_type="NOVEL_URL_STRUCTURE",
        fingerprint_hash="hash-url-login-brand",
        fingerprint_repr="path:login+brand:corp+redirect:true",
        novelty_score=0.95,
        recurrence_score=72.0,
        observation_count=18,
        entity_count=6,
        incident_count=5,
        status="EMERGING",
        supporting_evidence_json=json.dumps([
            {"domain": "login-corp-auth.com", "path": "/login/v2"},
            {"domain": "sso-corp-portal.net", "path": "/login/oauth"},
        ]),
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add(pat)
    db_session.commit()

    # Step 2: Synthesize Candidate Rule from Emerging Pattern
    synth_req = CandidateRuleFromPatternRequest(
        workspace_id=ws,
        pattern_candidate_id="pat-e2e-01",
        proposed_name="CR-017 Credential Harvesting URL Pattern",
        rule_type=RuleType.STRUCTURAL,
        generalization_level=GeneralizationLevel.STRUCTURAL,
        created_by="pattern_synthesizer",
    )
    candidate = CandidateRuleService.generate_candidate_from_pattern(db_session, synth_req)
    assert candidate.status == RuleLifecycleStatus.DISCOVERED.value
    assert candidate.version == "v1"
    assert candidate.complexity_score > 0.0

    # Step 3: Seed historical events for backtesting
    # 2 true positives (verified malicious)
    for i in range(2):
        te = ThreatEventModel(
            id=f"te-mal-{i}",
            incident_id=f"inc-hist-{i}",
            event_type="ACTIVE_URL_SCAN",
            severity="HIGH",
            confidence=0.90,
            summary=f"login-phish-{i}.com",
            metadata_json=json.dumps({"url": {"path": "/login/auth", "domain_similarity": 0.88}}),
            created_at=get_utc_now(),
        )
        mem = ThreatMemoryEntryModel(
            id=f"mem-mal-{i}",
            workspace_id=ws,
            canonical_key=f"login-phish-{i}.com",
            memory_type="DOMAIN",
            subject_type="DOMAIN",
            created_at=get_utc_now(),
        )
        db_session.add_all([te, mem])
        db_session.flush()

        dec = ThreatMemoryDecisionModel(
            id=f"dec-mal-{i}",
            workspace_id=ws,
            memory_entry_id=mem.id,
            decision="CONFIRMED_MALICIOUS",
            approved_by="analyst_1",
            reason="Confirmed campaign phish",
            created_at=get_utc_now(),
        )
        db_session.add(dec)

    db_session.commit()

    # Step 4: Run Historical Backtest
    backtest_req = RuleBacktestRequest(workspace_id=ws, lookback_days=60)
    evaluation = CandidateRuleService.backtest_candidate_rule(
        db_session, rule_id=candidate.id, workspace_id=ws, request=backtest_req
    )
    assert evaluation.historical_match_count >= 2
    assert evaluation.validated_positive_count >= 2
    assert evaluation.false_positive_count == 0
    assert evaluation.precision == 1.0
    assert candidate.status == RuleLifecycleStatus.TESTED.value

    # Step 5: Submit for review & approve
    CandidateRuleService.submit_for_review(db_session, rule_id=candidate.id, workspace_id=ws)
    assert candidate.status == RuleLifecycleStatus.REVIEW_REQUIRED.value

    approval_action = RuleReviewActionRequest(
        workspace_id=ws,
        reviewer="lead_detection_engineer",
        reason="Backtest demonstrated 100% precision across known campaign infrastructure.",
    )
    CandidateRuleService.approve_rule(db_session, rule_id=candidate.id, workspace_id=ws, request=approval_action)
    assert candidate.status == RuleLifecycleStatus.APPROVED.value

    # Step 6: Stage into shadow mode
    CandidateRuleService.stage_rule(db_session, rule_id=candidate.id, workspace_id=ws, request=approval_action)
    assert candidate.status == RuleLifecycleStatus.STAGED.value
    assert candidate.staged_at is not None

    # Step 7: Evaluate events in shadow mode (monitoring without alerting)
    shadow_ctx = {
        "event_id": "evt-shadow-101",
        "incident_id": "inc-live-01",
        "url": {"path": "/user/login", "domain_similarity": 0.89},
    }
    shadow_results = CandidateRuleService.evaluate_rules_for_event(
        db_session, workspace_id=ws, context=shadow_ctx, include_staged=True
    )
    assert len(shadow_results) == 1
    assert shadow_results[0].matched is True

    # Confirm telemetry record logged in SHADOW mode
    telemetry = db_session.query(CandidateRuleExecutionModel).filter(
        CandidateRuleExecutionModel.workspace_id == ws,
        CandidateRuleExecutionModel.mode == "SHADOW",
    ).first()
    assert telemetry is not None
    assert telemetry.matched is True

    # Confirm no production ThreatEvent was emitted in shadow mode
    prod_event = db_session.query(ThreatEventModel).filter(
        ThreatEventModel.incident_id == "inc-live-01",
    ).first()
    assert prod_event is None

    # Step 8: Promote to ACTIVE production detection
    activate_action = RuleReviewActionRequest(
        workspace_id=ws,
        reviewer="soc_manager",
        reason="Shadow mode telemetry clean. Zero false alarms observed.",
    )
    CandidateRuleService.activate_rule(db_session, rule_id=candidate.id, workspace_id=ws, request=activate_action)
    assert candidate.status == RuleLifecycleStatus.ACTIVE.value
    assert candidate.activated_at is not None

    # Step 9: Live evaluation under ACTIVE status triggers ThreatEvent
    live_ctx = {
        "event_id": "evt-live-202",
        "incident_id": "inc-active-02",
        "url": {"path": "/secure/login", "domain_similarity": 0.91},
    }
    live_results = CandidateRuleService.evaluate_rules_for_event(
        db_session, workspace_id=ws, context=live_ctx, include_staged=False
    )
    assert len(live_results) == 1
    assert live_results[0].matched is True

    # Active detection emitted a standardized ThreatEvent
    te_emitted = db_session.query(ThreatEventModel).filter(
        ThreatEventModel.incident_id == "inc-active-02",
    ).first()
    assert te_emitted is not None
    assert "CR-017" in te_emitted.summary
    assert te_emitted.severity == candidate.severity

    # Step 10: Tune rule threshold (v1 -> v2) with immutable provenance
    tuned_defn = RuleDefinition(
        logical_operator="AND",
        conditions=[
            RuleCondition(field="url.path", operator=DslOperator.CONTAINS, value="login"),
            RuleCondition(field="url.domain_similarity", operator=DslOperator.GREATER_THAN_OR_EQUAL, value=0.90),
        ],
    )
    edit_req = RuleEditRequest(
        workspace_id=ws,
        editor="detection_engineer",
        change_reason="Tighten domain similarity threshold from 0.85 to 0.90 to avoid near-lookalike false positives.",
        definition=tuned_defn,
        thresholds={"domain_similarity": 0.90},
    )
    tuned_candidate = CandidateRuleService.edit_rule(db_session, rule_id=candidate.id, workspace_id=ws, request=edit_req)

    assert tuned_candidate.version == "v2"
    assert tuned_candidate.status == RuleLifecycleStatus.DRAFT.value

    # Verify both v1 and v2 records exist in candidate_rule_versions
    all_versions = db_session.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.rule_id == candidate.id,
    ).order_by(CandidateRuleVersionModel.version.asc()).all()
    assert len(all_versions) == 2
    assert all_versions[0].version == "v1"
    assert all_versions[1].version == "v2"
    assert "0.90" in all_versions[1].change_reason
