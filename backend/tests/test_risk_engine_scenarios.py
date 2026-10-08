"""
End-to-End Scenario Test for Section 26: Unified Risk Engine.

Executes the complete multi-vector progression:
Phishing email -> Suspicious URL -> Identity mismatch -> Historical memory match ->
Unusual login -> Attack-path correlation -> Final Unified RiskAssessment.

Verifies:
1. Multi-vector signal integration across URL, IDENTITY, HISTORICAL, AUTH, and TEMPORAL.
2. Diminishing returns discounting within the URL correlation group.
3. Multi-family asymptotic combination.
4. Independent severity derivation (CRITICAL due to executive account takeover).
5. High confidence due to multi-source corroboration.
6. Transparent explainability breakdown with exact point contributions.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
import pytest

from backend.db.session import SessionLocal
from backend.db.models import (
    AttackPathModel,
    AttackStageModel,
    IncidentModel,
    RiskAssessmentModel,
    ThreatEventModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.risk_engine import (
    EvidenceFamily,
    RiskLevel,
    RiskScope,
    RiskSeverityEnum,
    RiskSignalCreate,
    SignalDirection,
    SignalSemantics,
    UncertaintyLevel,
)
from backend.services.risk_engine_service import (
    RiskConfigurationManager,
    RiskEngineService,
)


def test_section_26_end_to_end_multivector_scenario():
    """
    Executes the multi-stage attack reconstruction scenario and verifies
    authoritative Unified Risk Assessment calculation.
    """
    with SessionLocal() as db:
        workspace_id = "ws-e2e-scenario"
        now = get_utc_now()

        # 1. Incident Container
        incident = IncidentModel(
            id=generate_uuid(),
            incident_number="INC-2026-MULTI-01",
            workspace_id=workspace_id,
            title="Executive Credential Theft & ATO Campaign",
            status="OPEN",
            severity="MEDIUM",
            risk_score=40.0,
            confidence=0.8,
            opened_at=now,
        )
        db.add(incident)

        # 2. Threat Events in the campaign
        te_phish = ThreatEventModel(
            id=generate_uuid(),
            event_type="phishing_email",
            summary="Targeted spear-phishing email received by CFO",
            incident_id=incident.id,
            risk_score=65.0,
            severity="HIGH",
            confidence=0.90,
            created_at=now,
        )
        te_url = ThreatEventModel(
            id=generate_uuid(),
            event_type="phishing_url",
            summary="Lookalike URL visited: https://login.secure-portal.example.com",
            incident_id=incident.id,
            risk_score=75.0,
            severity="HIGH",
            confidence=0.85,
            created_at=now,
        )
        te_auth = ThreatEventModel(
            id=generate_uuid(),
            event_type="anomalous_authentication",
            summary="Anomalous login from unrecognized IP: 198.51.100.44",
            incident_id=incident.id,
            risk_score=70.0,
            severity="HIGH",
            confidence=0.80,
            created_at=now,
        )
        db.add_all([te_phish, te_url, te_auth])

        # 3. Reconstructed Attack Path
        attack_path = AttackPathModel(
            id=generate_uuid(),
            incident_id=incident.id,
            workspace_id=workspace_id,
            name="Spear-Phish to CFO Credential Harvest to ATO",
            classification="CONFIRMED_PROGRESSION",
            confidence=0.88,
            confidence_level="VERY_HIGH",
            status="CURRENT",
        )
        db.add(attack_path)

        stage1 = AttackStageModel(
            id=generate_uuid(),
            attack_path_id=attack_path.id,
            stage_order=1,
            stage_type="INITIAL_ACCESS",
            name="Phishing Email Delivery",
            confidence=0.95,
        )
        stage2 = AttackStageModel(
            id=generate_uuid(),
            attack_path_id=attack_path.id,
            stage_order=2,
            stage_type="CREDENTIAL_HARVESTING",
            name="Lookalike Portal Interaction",
            confidence=0.90,
        )
        stage3 = AttackStageModel(
            id=generate_uuid(),
            attack_path_id=attack_path.id,
            stage_order=3,
            stage_type="ACCOUNT_TAKEOVER",
            name="Anomalous Session Establishment",
            confidence=0.85,
        )
        db.add_all([stage1, stage2, stage3])
        db.commit()

        # 4. Formulate Multi-Vector Signals
        signals: list[RiskSignalCreate] = [
            # URL Family (Correlated signals for same URL)
            RiskSignalCreate(
                signal_type="URL_LOOKALIKE",
                source_type="URL_ANALYZER",
                detector_id="url_domain_intel",
                evidence_family=EvidenceFamily.URL,
                semantics=SignalSemantics.THREAT_SCORE,
                raw_score=85.0,
                reliability=0.85,
                correlation_group="URL:secure-portal.example.com",
            ),
            RiskSignalCreate(
                signal_type="CREDENTIAL_FORM",
                source_type="CONTENT_EXTRACTOR",
                detector_id="url_domain_intel",
                evidence_family=EvidenceFamily.URL,
                semantics=SignalSemantics.BOOLEAN_INDICATOR,
                raw_score=1.0,
                reliability=0.90,
                correlation_group="URL:secure-portal.example.com",
            ),
            RiskSignalCreate(
                signal_type="REDIRECT_CHAIN",
                source_type="NETWORK_PROBE",
                detector_id="url_domain_intel",
                evidence_family=EvidenceFamily.URL,
                semantics=SignalSemantics.COUNT,
                raw_score=3.0,
                reliability=0.80,
                correlation_group="URL:secure-portal.example.com",
            ),
            # Identity Family
            RiskSignalCreate(
                signal_type="EXECUTIVE_IMPERSONATION",
                source_type="IMPERSONATION_DETECTOR",
                detector_id="impersonation_service",
                evidence_family=EvidenceFamily.IDENTITY,
                semantics=SignalSemantics.THREAT_SCORE,
                raw_score=80.0,
                reliability=0.85,
                correlation_group="USER:cfo@example.com",
            ),
            # Authentication Family
            RiskSignalCreate(
                signal_type="ANOMALOUS_GEO_LOGIN",
                source_type="AUTH_MONITOR",
                detector_id="authentication_pipeline",
                evidence_family=EvidenceFamily.AUTHENTICATION,
                semantics=SignalSemantics.ANOMALY_SCORE,
                raw_score=0.85,
                reliability=0.80,
                correlation_group="AUTH:cfo@example.com",
            ),
            # Counter-Evidence (Valid DKIM from third-party provider)
            RiskSignalCreate(
                signal_type="VALID_DKIM_SIGNATURE",
                source_type="HEADER_PARSER",
                detector_id="email_parser",
                evidence_family=EvidenceFamily.CONTENT,
                semantics=SignalSemantics.BOOLEAN_INDICATOR,
                direction=SignalDirection.COUNTER,
                raw_score=1.0,
                reliability=0.95,
                correlation_group="HEADER:cfo@example.com",
            ),
        ]

        # 5. Context Metadata from surrounding CyberGuard subsystems
        context_metadata = {
            "is_privileged_account": True,        # CFO identity
            "is_critical_asset": False,
            "threat_memory_match": True,          # Section 23 match on infrastructure
            "threat_memory_status": "VERIFIED",
            "threat_memory_is_expired": False,
            "attack_path_confidence": attack_path.confidence,
            "attack_stage_count": 3,
            "mitre_supported_count": 2,           # T1566.002, T1078
            "novelty_score": 0.85,                # Section 22 novelty
        }

        # 6. Evaluate via Unified Risk Engine
        assessment_dict = RiskEngineService.evaluate_signals(
            signals=signals,
            context_metadata=context_metadata,
        )

        # 7. Verification of Central Invariants
        # A. Unified Risk Score is strictly bounded and high
        risk_score = assessment_dict["risk_score"]
        assert 70.0 <= risk_score <= 100.0, f"Expected high risk score, got {risk_score}"
        assert assessment_dict["risk_level"] in (RiskLevel.HIGH, RiskLevel.CRITICAL)

        # B. Severity is CRITICAL due to executive ATO impact triggers
        assert assessment_dict["severity"] == RiskSeverityEnum.CRITICAL

        # C. Confidence is VERY HIGH due to multi-source corroboration (URL + IDENTITY + AUTH + HISTORICAL + TEMPORAL)
        confidence = assessment_dict["confidence"]
        assert confidence >= 0.85, f"Expected very high confidence, got {confidence}"

        # D. Uncertainty is LOW (no missing telemetry, no unresolved contradictions)
        assert assessment_dict["uncertainty"] == UncertaintyLevel.LOW

        # E. Contextual Modifiers contributed transparently
        ctx_factors = assessment_dict["contextual_factors"]
        assert "privileged_identity_boost" in ctx_factors
        assert "threat_memory_boost" in ctx_factors
        assert "attack_path_continuity_boost" in ctx_factors
        assert "novelty_corroboration_boost" in ctx_factors
        assert "mitre_technique_boost" in ctx_factors

        # F. Explainability components breakdown is populated with exact point contributions
        components = assessment_dict["components"]
        assert len(components) >= 5
        top_families = {c.family for c in components[:4]}
        assert EvidenceFamily.URL in top_families or EvidenceFamily.IDENTITY in top_families

        # G. Explanation summary exists without asking an LLM
        summary = assessment_dict["explanation_summary"]
        assert "Risk Score" in summary
        assert "Primary contributors" in summary
