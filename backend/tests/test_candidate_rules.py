"""
Unit and service-level tests for Section 25: Emerging Pattern & Candidate Rule Engine.

Validates:
1. Safe Rule DSL syntax validation and complexity scoring.
2. ReDoS / catastrophic backtracking rejection.
3. Canonical fingerprinting and deduplication (commutativity A AND B == B AND A).
4. Deterministic runtime operator evaluation (zero eval/exec).
5. Pattern-to-rule synthesis from EmergingPatternCandidate.
6. Ground-truth aware historical backtesting (unknowns NOT treated as true negatives).
7. Complete lifecycle state machine: DISCOVERED -> TESTED -> REVIEW_REQUIRED -> APPROVED -> STAGED -> ACTIVE.
8. Immutable versioning on rule edit (v1 preserved when creating v2).
9. Shadow mode execution vs active detection firing.
10. Rule disablement and retirement.
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
    CandidateRuleCreate,
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
from backend.services.candidate_rule_service import (
    CandidateRuleService,
    RuleDslValidator,
    RuleEvaluator,
    RuleNormalizer,
)


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


def test_dsl_validation_and_complexity():
    """Verifies operator syntax checking and complexity budget limits."""
    # Valid rule definition
    defn = RuleDefinition(
        logical_operator="AND",
        conditions=[
            RuleCondition(field="url.path", operator=DslOperator.CONTAINS, value="login"),
            RuleCondition(field="url.domain_similarity", operator=DslOperator.GREATER_THAN_OR_EQUAL, value=0.85),
            RuleCondition(field="email.spf_pass", operator=DslOperator.EQUALS, value=False),
        ],
    )
    valid, errors, complexity = RuleDslValidator.validate_definition(defn)
    assert valid is True
    assert len(errors) == 0
    assert complexity == 3.0

    # Rule exceeding condition count limit (>20)
    huge_conditions = [
        RuleCondition(field=f"field_{i}", operator=DslOperator.EQUALS, value=i)
        for i in range(25)
    ]
    huge_defn = RuleDefinition(conditions=huge_conditions)
    valid, errors, complexity = RuleDslValidator.validate_definition(huge_defn)
    assert valid is False
    assert any("exceeds maximum" in e for e in errors)


def test_redos_safety_rejection():
    """Verifies that dangerous catastrophic backtracking regex patterns are rejected."""
    dangerous_regexes = [
        "(a+)+",
        "([a-zA-Z]+)*",
        "(a|aa)+",
    ]
    for pattern in dangerous_regexes:
        defn = RuleDefinition(
            conditions=[
                RuleCondition(field="body_text", operator=DslOperator.REGEX, value=pattern),
            ],
        )
        valid, errors, complexity = RuleDslValidator.validate_definition(defn)
        assert valid is False
        assert any("catastrophic backtracking" in e.lower() for e in errors)


def test_rule_canonical_fingerprinting_deduplication():
    """Verifies that rule conditions are sorted canonically so A AND B == B AND A."""
    cond_a = RuleCondition(field="url.path", operator=DslOperator.CONTAINS, value="login")
    cond_b = RuleCondition(field="domain_similarity", operator=DslOperator.GREATER_THAN_OR_EQUAL, value=0.90)

    defn_1 = RuleDefinition(logical_operator="AND", conditions=[cond_a, cond_b])
    defn_2 = RuleDefinition(logical_operator="AND", conditions=[cond_b, cond_a])

    fp1 = RuleNormalizer.canonical_fingerprint(defn_1, RuleScope.URL, RuleType.STRUCTURAL)
    fp2 = RuleNormalizer.canonical_fingerprint(defn_2, RuleScope.URL, RuleType.STRUCTURAL)

    assert fp1 == fp2
    assert len(fp1) == 64


def test_rule_evaluator_operators():
    """Verifies safe operator dispatch for string, numeric, collection, and similarity checks."""
    context = {
        "url": {
            "path": "/auth/login/secure",
            "domain": "paypa1-verify.com",
            "similarity": 0.94,
        },
        "tags": ["phish", "credential_harvesting"],
        "failed_attempts": 6,
        "is_admin": False,
    }

    # Equality & comparison
    cond_gt = RuleCondition(field="url.similarity", operator=DslOperator.GREATER_THAN_OR_EQUAL, value=0.90)
    matched, _ = RuleEvaluator.evaluate_condition(cond_gt, context)
    assert matched is True

    cond_count = RuleCondition(field="failed_attempts", operator=DslOperator.GREATER_THAN, value=5)
    matched, _ = RuleEvaluator.evaluate_condition(cond_count, context)
    assert matched is True

    # Substring & collection
    cond_contains = RuleCondition(field="url.path", operator=DslOperator.CONTAINS, value="login")
    matched, _ = RuleEvaluator.evaluate_condition(cond_contains, context)
    assert matched is True

    cond_in = RuleCondition(field="tags", operator=DslOperator.CONTAINS, value="phish")
    matched, _ = RuleEvaluator.evaluate_condition(cond_in, context)
    assert matched is True

    # Similarity
    cond_sim = RuleCondition(field="url.domain", operator=DslOperator.SIMILARITY_GTE, value={"target": "paypal-verify", "threshold": 0.80})
    matched, _ = RuleEvaluator.evaluate_condition(cond_sim, {"url": {"domain": "paypa1-verify"}})
    assert matched is True

    # Missing field
    cond_missing = RuleCondition(field="non_existent.field", operator=DslOperator.EQUALS, value="xyz")
    matched, _ = RuleEvaluator.evaluate_condition(cond_missing, context)
    assert matched is False


def test_pattern_to_candidate_rule_synthesis(db_session):
    """Verifies EmergingPatternCandidate is synthesized into a generalized CandidateRuleModel."""
    # Seed EmergingPatternCandidate
    pat = EmergingPatternCandidateModel(
        id="pat-url-01",
        workspace_id="ws-test",
        incident_id="inc-100",
        pattern_type="NOVEL_URL_STRUCTURE",
        fingerprint_hash="abc123hash",
        fingerprint_repr="path:login+brand:bank+redirect:next",
        novelty_score=0.92,
        recurrence_score=65.0,
        observation_count=12,
        entity_count=4,
        incident_count=3,
        status="EMERGING",
        supporting_evidence_json=json.dumps([{"domain": "bank-portal.xyz"}]),
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add(pat)
    db_session.commit()

    req = CandidateRuleFromPatternRequest(
        workspace_id="ws-test",
        pattern_candidate_id="pat-url-01",
        proposed_name="Detect Credential Harvesting URL Pattern",
    )
    cand = CandidateRuleService.generate_candidate_from_pattern(db_session, req)

    assert cand is not None
    assert cand.id is not None
    assert cand.name == "Detect Credential Harvesting URL Pattern"
    assert cand.status == RuleLifecycleStatus.DISCOVERED.value
    assert cand.scope == RuleScope.URL.value
    assert cand.generalization_level == GeneralizationLevel.STRUCTURAL.value
    assert cand.version == "v1"

    # Verify initial version record
    v1 = db_session.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.rule_id == cand.id,
        CandidateRuleVersionModel.version == "v1",
    ).first()
    assert v1 is not None


def test_backtest_with_ground_truth_awareness(db_session):
    """Verifies backtesting distinguishes known malicious, known benign, and unlabeled unknowns."""
    # 1. Create candidate rule
    defn = RuleDefinition(
        logical_operator="AND",
        conditions=[
            RuleCondition(field="event_type", operator=DslOperator.EQUALS, value="CREDENTIAL_HARVEST_URL"),
        ],
    )
    cand = CandidateRuleModel(
        id="cr-test-01",
        workspace_id="ws-test",
        name="Credential Harvest Backtest Rule",
        rule_type="STRUCTURAL",
        status=RuleLifecycleStatus.DISCOVERED.value,
        definition_json=defn.model_dump_json(),
        thresholds_json="{}",
        scope="URL",
        severity="HIGH",
        confidence=0.85,
        generalization_level="STRUCTURAL",
        complexity_score=1.0,
        normalized_fingerprint="fp-backtest-01",
        version="v1",
        evaluation_summary_json="{}",
        created_by="analyst",
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add(cand)

    # 2. Seed ThreatEvents: 1 verified malicious, 1 verified benign, 1 unlabeled
    te_mal = ThreatEventModel(
        id="te-mal-01",
        incident_id="inc-01",
        event_type="CREDENTIAL_HARVEST_URL",
        severity="HIGH",
        confidence=0.95,
        summary="malicious-login.com",
        metadata_json=json.dumps({"source_component": "email_analyzer", "title": "malicious-login.com"}),
        created_at=get_utc_now(),
    )
    te_benign = ThreatEventModel(
        id="te-benign-01",
        incident_id="inc-02",
        event_type="CREDENTIAL_HARVEST_URL",
        severity="LOW",
        confidence=0.20,
        summary="legit-sso.com",
        metadata_json=json.dumps({"source_component": "email_analyzer", "title": "legit-sso.com"}),
        created_at=get_utc_now(),
    )
    te_unknown = ThreatEventModel(
        id="te-unk-01",
        incident_id="inc-03",
        event_type="CREDENTIAL_HARVEST_URL",
        severity="MEDIUM",
        confidence=0.60,
        summary="unverified-portal.net",
        metadata_json=json.dumps({"source_component": "email_analyzer", "title": "unverified-portal.net"}),
        created_at=get_utc_now(),
    )
    db_session.add_all([te_mal, te_benign, te_unknown])

    # 3. Seed Threat Memory decisions for ground truth
    mem_mal = ThreatMemoryEntryModel(
        id="mem-01",
        workspace_id="ws-test",
        canonical_key="malicious-login.com",
        memory_type="DOMAIN",
        subject_type="DOMAIN",
        created_at=get_utc_now(),
    )
    mem_ben = ThreatMemoryEntryModel(
        id="mem-02",
        workspace_id="ws-test",
        canonical_key="legit-sso.com",
        memory_type="DOMAIN",
        subject_type="DOMAIN",
        created_at=get_utc_now(),
    )
    db_session.add_all([mem_mal, mem_ben])
    db_session.flush()

    dec_mal = ThreatMemoryDecisionModel(
        id="dec-01",
        workspace_id="ws-test",
        memory_entry_id=mem_mal.id,
        decision="CONFIRMED_MALICIOUS",
        approved_by="lead_analyst",
        reason="Verified active phish",
        created_at=get_utc_now(),
    )
    dec_ben = ThreatMemoryDecisionModel(
        id="dec-02",
        workspace_id="ws-test",
        memory_entry_id=mem_ben.id,
        decision="CONFIRMED_BENIGN",
        approved_by="lead_analyst",
        reason="Authorized corporate migration",
        created_at=get_utc_now(),
    )
    db_session.add_all([dec_mal, dec_ben])
    db_session.commit()

    # 4. Run Backtest
    eval_res = CandidateRuleService.backtest_candidate_rule(
        db_session,
        rule_id="cr-test-01",
        workspace_id="ws-test",
        request=RuleBacktestRequest(workspace_id="ws-test", lookback_days=30),
    )

    assert eval_res.historical_match_count == 3
    assert eval_res.validated_positive_count == 1
    assert eval_res.false_positive_count == 1
    assert eval_res.unknown_count == 1  # Unlabeled event is not assumed true negative
    assert eval_res.precision == 0.5    # 1 TP / (1 TP + 1 FP)
    assert cand.status == RuleLifecycleStatus.TESTED.value


def test_rule_lifecycle_approval_staging_and_activation(db_session):
    """Verifies progression: TESTED -> REVIEW_REQUIRED -> APPROVED -> STAGED -> ACTIVE."""
    cand = CandidateRuleModel(
        id="cr-life-01",
        workspace_id="ws-life",
        name="Lifecycle Rule",
        rule_type="STRUCTURAL",
        status=RuleLifecycleStatus.TESTED.value,
        definition_json=json.dumps({"conditions": [{"field": "x", "operator": "eq", "value": 1}]}),
        thresholds_json="{}",
        scope="GLOBAL",
        severity="MEDIUM",
        confidence=0.8,
        generalization_level="STRUCTURAL",
        complexity_score=1.0,
        normalized_fingerprint="fp-life-01",
        version="v1",
        evaluation_summary_json="{}",
        created_by="analyst",
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add(cand)
    db_session.commit()

    # 1. Submit for review
    CandidateRuleService.submit_for_review(db_session, "cr-life-01", "ws-life")
    assert cand.status == RuleLifecycleStatus.REVIEW_REQUIRED.value

    # 2. Approve
    action = RuleReviewActionRequest(workspace_id="ws-life", reviewer="sec_lead", reason="Backtest passed")
    CandidateRuleService.approve_rule(db_session, "cr-life-01", "ws-life", action)
    assert cand.status == RuleLifecycleStatus.APPROVED.value
    assert cand.reviewed_by == "sec_lead"

    # 3. Stage into shadow mode
    CandidateRuleService.stage_rule(db_session, "cr-life-01", "ws-life", action)
    assert cand.status == RuleLifecycleStatus.STAGED.value
    assert cand.staged_at is not None

    # 4. Activate in production
    CandidateRuleService.activate_rule(db_session, "cr-life-01", "ws-life", action)
    assert cand.status == RuleLifecycleStatus.ACTIVE.value
    assert cand.activated_at is not None


def test_rule_editing_immutability(db_session):
    """Verifies editing creates an immutable new version (v1 -> v2) without mutating v1."""
    defn_v1 = RuleDefinition(
        logical_operator="AND",
        conditions=[RuleCondition(field="score", operator=DslOperator.GREATER_THAN, value=50)],
    )
    cand = CandidateRuleModel(
        id="cr-edit-01",
        workspace_id="ws-edit",
        name="Editable Rule",
        rule_type="BEHAVIORAL",
        status=RuleLifecycleStatus.APPROVED.value,
        definition_json=defn_v1.model_dump_json(),
        thresholds_json="{}",
        scope="GLOBAL",
        severity="MEDIUM",
        confidence=0.8,
        generalization_level="BEHAVIORAL",
        complexity_score=1.0,
        normalized_fingerprint="fp-v1",
        version="v1",
        evaluation_summary_json="{}",
        created_by="analyst",
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    v1_rec = CandidateRuleVersionModel(
        id="v1-rec-01",
        rule_id="cr-edit-01",
        version="v1",
        workspace_id="ws-edit",
        definition_json=defn_v1.model_dump_json(),
        thresholds_json="{}",
        evaluation_summary_json="{}",
        status="APPROVED",
        created_by="analyst",
        created_at=get_utc_now(),
    )
    db_session.add(cand)
    db_session.add(v1_rec)
    db_session.commit()

    # Edit: change threshold to 75
    defn_v2 = RuleDefinition(
        logical_operator="AND",
        conditions=[RuleCondition(field="score", operator=DslOperator.GREATER_THAN, value=75)],
    )
    edit_req = RuleEditRequest(
        workspace_id="ws-edit",
        editor="senior_engineer",
        change_reason="Raise threshold to reduce alert volume",
        definition=defn_v2,
        severity=RuleSeverity.HIGH,
    )
    updated = CandidateRuleService.edit_rule(db_session, "cr-edit-01", "ws-edit", edit_req)

    assert updated.version == "v2"
    assert updated.severity == "HIGH"
    assert updated.status == RuleLifecycleStatus.DRAFT.value

    # Verify v1 remains intact in version history
    versions = db_session.query(CandidateRuleVersionModel).filter(
        CandidateRuleVersionModel.rule_id == "cr-edit-01"
    ).all()
    assert len(versions) == 2
    ver_tags = {v.version for v in versions}
    assert "v1" in ver_tags
    assert "v2" in ver_tags


def test_shadow_mode_vs_active_detection(db_session):
    """Verifies STAGED rules log shadow telemetry without production ThreatEvents, whereas ACTIVE rules emit events."""
    # Staged rule
    cand_staged = CandidateRuleModel(
        id="cr-shadow-01",
        workspace_id="ws-exec",
        name="Staged Shadow Rule",
        rule_type="STRUCTURAL",
        status=RuleLifecycleStatus.STAGED.value,
        definition_json=json.dumps({"conditions": [{"field": "indicator", "operator": "eq", "value": "test_signal"}]}),
        thresholds_json="{}",
        scope="GLOBAL",
        severity="MEDIUM",
        confidence=0.8,
        generalization_level="STRUCTURAL",
        complexity_score=1.0,
        normalized_fingerprint="fp-shadow",
        version="v1",
        evaluation_summary_json="{}",
        created_by="analyst",
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    # Active rule
    cand_active = CandidateRuleModel(
        id="cr-prod-01",
        workspace_id="ws-exec",
        name="Active Prod Rule",
        rule_type="STRUCTURAL",
        status=RuleLifecycleStatus.ACTIVE.value,
        definition_json=json.dumps({"conditions": [{"field": "indicator", "operator": "eq", "value": "test_signal"}]}),
        thresholds_json="{}",
        scope="GLOBAL",
        severity="HIGH",
        confidence=0.9,
        generalization_level="STRUCTURAL",
        complexity_score=1.0,
        normalized_fingerprint="fp-prod",
        version="v1",
        evaluation_summary_json="{}",
        created_by="analyst",
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add_all([cand_staged, cand_active])
    db_session.commit()

    context = {
        "event_id": "evt-001",
        "incident_id": "inc-001",
        "indicator": "test_signal",
    }
    results = CandidateRuleService.evaluate_rules_for_event(
        db_session, workspace_id="ws-exec", context=context, include_staged=True
    )
    assert len(results) == 2

    # Check executions telemetry
    executions = db_session.query(CandidateRuleExecutionModel).filter(
        CandidateRuleExecutionModel.workspace_id == "ws-exec"
    ).all()
    assert len(executions) == 2
    modes = {e.mode for e in executions}
    assert "SHADOW" in modes
    assert "PRODUCTION" in modes

    # Active rule emitted a ThreatEvent in incident inc-001
    te = db_session.query(ThreatEventModel).filter(
        ThreatEventModel.incident_id == "inc-001",
    ).first()
    assert te is not None
    assert "Active Prod Rule" in te.summary


def test_rule_disable_and_retire(db_session):
    """Verifies active rule can be disabled or permanently retired."""
    cand = CandidateRuleModel(
        id="cr-retire-01",
        workspace_id="ws-retire",
        name="Rule To Retire",
        rule_type="STRUCTURAL",
        status=RuleLifecycleStatus.ACTIVE.value,
        definition_json="{}",
        thresholds_json="{}",
        scope="GLOBAL",
        severity="LOW",
        confidence=0.7,
        generalization_level="STRUCTURAL",
        complexity_score=1.0,
        normalized_fingerprint="fp-retire",
        version="v1",
        evaluation_summary_json="{}",
        created_by="analyst",
        created_at=get_utc_now(),
        updated_at=get_utc_now(),
    )
    db_session.add(cand)
    db_session.commit()

    # Disable
    action = RuleReviewActionRequest(workspace_id="ws-retire", reviewer="lead", reason="Spike in false positives")
    CandidateRuleService.disable_rule(db_session, "cr-retire-01", "ws-retire", action)
    assert cand.status == RuleLifecycleStatus.DISABLED.value

    # Retire
    action_retire = RuleReviewActionRequest(workspace_id="ws-retire", reviewer="lead", reason="Attack technique deprecated")
    CandidateRuleService.retire_rule(db_session, "cr-retire-01", "ws-retire", action_retire)
    assert cand.status == RuleLifecycleStatus.RETIRED.value
    assert cand.retired_at is not None
