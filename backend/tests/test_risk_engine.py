"""
Unit Tests for Section 26: Unified Risk Engine.

Tests:
1. Signal normalization across all semantic types and bounding to 0-100.
2. Separation of Risk, Severity, Confidence, Uncertainty.
3. Correlation grouping and diminishing returns discounting schedule [1.0, 0.4, 0.15, 0.05].
4. Genuine evidence independence across distinct families vs correlated signals.
5. Counter-evidence mitigation without blind zeroing of confirmed threats.
6. Contradictory signals raising uncertainty and penalizing confidence.
7. Novelty isolation: novelty alone produces 0 points; corroborating novelty adds points.
8. Threat Memory contextual contribution: fresh match adds points; expired match adds 0.
9. Attack Path continuity boost and MITRE technique corroboration.
10. Strict determinism: identical inputs produce identical results.
11. Reassessment immutability: v1 -> v2 creates new version and links parent.
12. Scope evaluation across EVENT, INVESTIGATION, and INCIDENT.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest

from backend.db.session import SessionLocal
from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    AttackPathModel,
    AttackStageModel,
    BehavioralDeviationModel,
    FindingModel,
    IncidentModel,
    RiskAssessmentModel,
    RiskSignalModel,
    ThreatEventModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.risk_engine import (
    ConfidenceLevel,
    EvidenceFamily,
    RiskLevel,
    RiskReassessRequest,
    RiskScope,
    RiskSeverityEnum,
    RiskSignalCreate,
    SignalDirection,
    SignalSemantics,
    UncertaintyLevel,
)
from backend.services.risk_engine_service import (
    CorrelationGrouper,
    RiskAggregator,
    RiskConfigurationManager,
    RiskEngineService,
    RiskMetricsCalculator,
    SignalNormalizer,
)


def test_01_signal_normalization_and_bounding():
    """Validates normalization of diverse signal semantic types to [0, 100]."""
    cfg = RiskConfigurationManager.load_active_config()

    # THREAT_SCORE
    s1 = SignalNormalizer.normalize_signal({"raw_score": 0.85, "semantics": SignalSemantics.THREAT_SCORE}, cfg)
    assert s1["normalized_score"] == 85.0

    s2 = SignalNormalizer.normalize_signal({"raw_score": 75.0, "semantics": SignalSemantics.THREAT_SCORE}, cfg)
    assert s2["normalized_score"] == 75.0

    # PROBABILITY
    s3 = SignalNormalizer.normalize_signal({"raw_score": 0.92, "semantics": SignalSemantics.PROBABILITY}, cfg)
    assert s3["normalized_score"] == 92.0

    # BOOLEAN_INDICATOR
    s4 = SignalNormalizer.normalize_signal({"raw_score": 1.0, "semantics": SignalSemantics.BOOLEAN_INDICATOR}, cfg)
    assert s4["normalized_score"] == 100.0

    s5 = SignalNormalizer.normalize_signal({"raw_score": 0.0, "semantics": SignalSemantics.BOOLEAN_INDICATOR}, cfg)
    assert s5["normalized_score"] == 0.0

    # SEVERITY
    s6 = SignalNormalizer.normalize_signal({"raw_score": 85.0, "semantics": SignalSemantics.SEVERITY}, cfg)
    assert s6["normalized_score"] == 100.0

    # Clamping out-of-bounds
    s7 = SignalNormalizer.normalize_signal({"raw_score": 150.0, "semantics": SignalSemantics.THREAT_SCORE}, cfg)
    assert s7["normalized_score"] == 100.0

    s8 = SignalNormalizer.normalize_signal({"raw_score": -10.0, "semantics": SignalSemantics.THREAT_SCORE}, cfg)
    assert s8["normalized_score"] == 0.0


def test_02_correlation_grouping_and_diminishing_returns():
    """
    Validates that multiple detectors analyzing the same underlying entity
    receive diminishing return multipliers [1.0, 0.40, 0.15, 0.05].
    """
    cfg = RiskConfigurationManager.load_active_config()

    signals = [
        {"signal_type": "URL_PHISH_1", "raw_score": 90.0, "reliability": 1.0, "correlation_group": "URL:login.example.com", "evidence_family": "URL"},
        {"signal_type": "URL_PHISH_2", "raw_score": 80.0, "reliability": 1.0, "correlation_group": "URL:login.example.com", "evidence_family": "URL"},
        {"signal_type": "URL_PHISH_3", "raw_score": 70.0, "reliability": 1.0, "correlation_group": "URL:login.example.com", "evidence_family": "URL"},
        {"signal_type": "URL_PHISH_4", "raw_score": 60.0, "reliability": 1.0, "correlation_group": "URL:login.example.com", "evidence_family": "URL"},
    ]

    normalized = [SignalNormalizer.normalize_signal(s, cfg) for s in signals]
    discounted, contradictions = CorrelationGrouper.group_and_discount(normalized, cfg)

    # Sort descending by contribution
    discounted.sort(key=lambda x: x["contribution"], reverse=True)

    # Rank 0: 90 * 1.0 = 90.0
    assert discounted[0]["correlation_rank"] == 0
    assert discounted[0]["contribution"] == 90.0

    # Rank 1: 80 * 0.40 = 32.0
    assert discounted[1]["correlation_rank"] == 1
    assert discounted[1]["contribution"] == 32.0

    # Rank 2: 70 * 0.15 = 10.5
    assert discounted[2]["correlation_rank"] == 2
    assert discounted[2]["contribution"] == 10.5

    # Rank 3: 60 * 0.05 = 3.0
    assert discounted[3]["correlation_rank"] == 3
    assert discounted[3]["contribution"] == 3.0

    # Four correlated signals total 135.5 before cap, rather than naive 300.0!
    total_group = sum(s["contribution"] for s in discounted)
    assert round(total_group, 1) == 135.5


def test_03_evidence_independence_vs_correlation():
    """
    Validates that genuine independent evidence (URL + FILE + AUTH) produces
    significantly higher multi-vector risk than repeated signals about the same entity.
    """
    cfg = RiskConfigurationManager.load_active_config()

    # Case A: 3 signals on the SAME URL
    correlated_signals = [
        {"signal_type": "URL_A", "raw_score": 80.0, "correlation_group": "URL:phish.com", "evidence_family": "URL"},
        {"signal_type": "URL_B", "raw_score": 80.0, "correlation_group": "URL:phish.com", "evidence_family": "URL"},
        {"signal_type": "URL_C", "raw_score": 80.0, "correlation_group": "URL:phish.com", "evidence_family": "URL"},
    ]
    res_correlated = RiskEngineService.evaluate_signals(correlated_signals, config=cfg)

    # Case B: 3 independent signals (URL + Malicious Attachment + Compromised Auth)
    independent_signals = [
        {"signal_type": "URL_A", "raw_score": 80.0, "correlation_group": "URL:phish.com", "evidence_family": "URL"},
        {"signal_type": "FILE_MACRO", "raw_score": 80.0, "correlation_group": "FILE:invoice.docm", "evidence_family": "FILE"},
        {"signal_type": "AUTH_SPRAY", "raw_score": 80.0, "correlation_group": "AUTH:victim@corp.com", "evidence_family": "AUTHENTICATION"},
    ]
    res_independent = RiskEngineService.evaluate_signals(independent_signals, config=cfg)

    # Correlated URL signals are capped by URL family cap (35.0)
    assert res_correlated["risk_score"] <= 35.0

    # Independent multi-vector signals combine asymptotically across families
    # Each family reaches near 35.0 cap -> 100 * (1 - (1-0.35)^3) = 100 * (1 - 0.274) = 72.5
    assert res_independent["risk_score"] > res_correlated["risk_score"]
    assert res_independent["risk_score"] >= 70.0
    assert res_independent["confidence"] > res_correlated["confidence"]


def test_04_counter_evidence_and_mitigation():
    """
    Validates that explicit counter-evidence reduces risk score, but does NOT
    blindly wipe out confirmed severe threats.
    """
    cfg = RiskConfigurationManager.load_active_config()

    # Base threat
    threat_only = [
        {"signal_type": "MALWARE_EXE", "raw_score": 90.0, "evidence_family": "FILE", "direction": "SUPPORTING"}
    ]
    res_base = RiskEngineService.evaluate_signals(threat_only, config=cfg)

    # Threat + Counter-evidence (e.g. corporate managed machine, valid DKIM)
    threat_with_counter = [
        {"signal_type": "MALWARE_EXE", "raw_score": 90.0, "evidence_family": "FILE", "direction": "SUPPORTING"},
        {"signal_type": "VALID_CRYPTO_DKIM", "raw_score": 50.0, "evidence_family": "CONTENT", "direction": "COUNTER"},
    ]
    res_counter = RiskEngineService.evaluate_signals(threat_with_counter, config=cfg)

    # Counter-evidence reduces score, but malware remains high risk
    assert res_counter["risk_score"] < res_base["risk_score"]
    assert res_counter["risk_score"] > 0.0  # Not blindly reduced to zero!


def test_05_contradictory_evidence_raises_uncertainty():
    """Validates that opposing signals within a group raise uncertainty and penalize confidence."""
    cfg = RiskConfigurationManager.load_active_config()

    contradictory_signals = [
        {"signal_type": "URL_REPUTATION_BAD", "raw_score": 80.0, "correlation_group": "URL:partner.com", "direction": "SUPPORTING", "evidence_family": "URL"},
        {"signal_type": "URL_REPUTATION_TRUSTED", "raw_score": 80.0, "correlation_group": "URL:partner.com", "direction": "COUNTER", "evidence_family": "URL"},
    ]
    res = RiskEngineService.evaluate_signals(contradictory_signals, config=cfg)

    assert len(res["contradictions"]) >= 1
    assert res["uncertainty_score"] >= 0.20
    assert len(res["uncertainty_factors"]) >= 1


def test_06_novelty_alone_never_equals_threat():
    """
    Critical requirement: High novelty alone must NOT produce high threat!
    Only novelty combined with existing threat signals can act as corroboration.
    """
    cfg = RiskConfigurationManager.load_active_config()

    # Isolated novel behavior (e.g. new employee uses new SaaS tool)
    novelty_isolated = [
        {"signal_type": "NOVEL_DOMAIN_VISIT", "raw_score": 0.95, "semantics": "NOVELTY", "evidence_family": "NOVELTY"}
    ]
    res_isolated = RiskEngineService.evaluate_signals(
        novelty_isolated,
        context_metadata={"novelty_score": 0.95},
        config=cfg,
    )
    # Isolated novelty produces 0 risk!
    assert res_isolated["risk_score"] == 0.0
    assert res_isolated["risk_level"] == RiskLevel.INFO

    # Corroborating novelty: Phishing link + novel infrastructure
    novelty_corroborated = [
        {"signal_type": "PHISHING_CRED_HARVEST", "raw_score": 85.0, "evidence_family": "URL"}
    ]
    res_corroborated = RiskEngineService.evaluate_signals(
        novelty_corroborated,
        context_metadata={"novelty_score": 0.95},
        config=cfg,
    )
    # Corroborating novelty receives modifier boost
    assert "novelty_corroboration_boost" in res_corroborated["contextual_factors"]
    assert res_corroborated["contextual_factors"]["novelty_corroboration_boost"] == 6.0


def test_07_threat_memory_and_attack_path_modifiers():
    """Validates that Threat Memory and Attack Path continuity contribute transparently."""
    cfg = RiskConfigurationManager.load_active_config()

    signals = [
        {"signal_type": "SUSPICIOUS_LOGIN", "raw_score": 70.0, "evidence_family": "AUTHENTICATION"}
    ]

    context = {
        "threat_memory_match": True,
        "threat_memory_status": "VERIFIED",
        "threat_memory_is_expired": False,
        "attack_path_confidence": 0.85,
        "attack_stage_count": 3,
        "mitre_supported_count": 2,
    }

    res = RiskEngineService.evaluate_signals(signals, context_metadata=context, config=cfg)

    assert "threat_memory_boost" in res["contextual_factors"]
    assert res["contextual_factors"]["threat_memory_boost"] == 8.0

    assert "attack_path_continuity_boost" in res["contextual_factors"]
    assert res["contextual_factors"]["attack_path_continuity_boost"] == 8.5  # 10.0 * 0.85

    assert "mitre_technique_boost" in res["contextual_factors"]
    assert res["contextual_factors"]["mitre_technique_boost"] == 8.0  # 2 * 4.0


def test_08_strict_determinism():
    """Validates that re-evaluating identical inputs yields 100% identical outputs."""
    cfg = RiskConfigurationManager.load_active_config()

    signals = [
        {"signal_type": "SIG_1", "raw_score": 78.5, "evidence_family": "URL"},
        {"signal_type": "SIG_2", "raw_score": 62.0, "evidence_family": "FILE"},
        {"signal_type": "SIG_3", "raw_score": 88.0, "evidence_family": "IDENTITY"},
    ]
    ctx = {"is_privileged_account": True, "novelty_score": 0.75}

    res_a = RiskEngineService.evaluate_signals(signals, context_metadata=ctx, config=cfg)
    res_b = RiskEngineService.evaluate_signals(signals, context_metadata=ctx, config=cfg)

    assert res_a["risk_score"] == res_b["risk_score"]
    assert res_a["confidence"] == res_b["confidence"]
    assert res_a["uncertainty_score"] == res_b["uncertainty_score"]
    assert res_a["severity"] == res_b["severity"]
    assert len(res_a["components"]) == len(res_b["components"])


def test_09_reassessment_immutability():
    """Validates that reassessment creates incremented version v(N+1) and links parent."""
    with SessionLocal() as db:
        now = get_utc_now()
        initial_assessment = RiskAssessmentModel(
            id=generate_uuid(),
            workspace_id="ws-reassess",
            scope_type="EVENT",
            scope_id="ev-reassess-1",
            risk_score=50.0,
            risk_level="MEDIUM",
            severity="MEDIUM",
            confidence=0.75,
            confidence_level="HIGH",
            uncertainty="LOW",
            uncertainty_score=0.15,
            version=1,
            status="CURRENT",
            signals_json=json.dumps([{"signal_type": "INIT", "raw_score": 50.0, "evidence_family": "URL"}]),
            components_json="[]",
            created_at=now,
            evaluated_at=now,
        )
        db.add(initial_assessment)
        db.commit()

        # Reassess with additional critical signal
        request = RiskReassessRequest(
            workspace_id="ws-reassess",
            reassessment_reason="Analyst discovered confirmed credential dump",
            additional_signals=[
                RiskSignalCreate(
                    signal_type="CREDENTIAL_EXPOSURE",
                    source_type="ANALYST_FEED",
                    detector_id="analyst_investigation",
                    evidence_family=EvidenceFamily.AUTHENTICATION,
                    raw_score=95.0,
                )
            ],
            context_metadata={"is_privileged_account": True},
        )

        v2 = RiskEngineService.reassess_assessment(
            db=db,
            assessment_id=initial_assessment.id,
            workspace_id="ws-reassess",
            request=request,
        )

        assert v2.version == 2
        assert v2.status == "CURRENT"
        assert v2.parent_assessment_id == initial_assessment.id
        assert v2.risk_score > initial_assessment.risk_score

        # Prior version is marked SUPERSEDED
        db.refresh(initial_assessment)
        assert initial_assessment.status == "SUPERSEDED"


def test_10_scope_evaluation_threat_event():
    """Validates end-to-end evaluation of an individual ThreatEventModel."""
    with SessionLocal() as db:
        now = get_utc_now()
        te = ThreatEventModel(
            id=generate_uuid(),
            event_type="phishing_url",
            summary="User clicked lookalike login URL",
            risk_score=60.0,
            severity="MEDIUM",
            confidence=0.80,
            metadata_json=json.dumps({"is_privileged_account": True}),
            created_at=now,
            updated_at=now,
        )
        db.add(te)
        db.commit()

        assessment = RiskEngineService.evaluate_threat_event(
            db=db,
            threat_event_id=te.id,
            workspace_id="ws-event-test",
        )

        assert assessment.scope_type == "EVENT"
        assert assessment.scope_id == te.id
        assert assessment.risk_score > 0.0

        # ThreatEvent was updated with assessment id
        db.refresh(te)
        assert te.risk_assessment_id == assessment.id
        assert te.risk_score == assessment.risk_score
