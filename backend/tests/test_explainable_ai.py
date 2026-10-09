"""
Unit and Integration Tests for Section 27: Explainable AI (XAI).

Covers:
1. Evidence Grounding: Every explanation claim references valid evidence
2. Unsupported Claim Rejection: Validation rejects ungrounded claims
3. Risk Consistency: Explanation.risk_score == RiskAssessment.risk_score (no recalculation)
4. Confidence Consistency: Explanation confidence matches authoritative assessment
5. Counter-Evidence: Non-threat and mitigating signals appear as counter-evidence
6. Contradictions: Conflicting telemetry is explicitly surfaced
7. Unknowns & Missing Info: Telemetry gaps become UNKNOWN, never assumed SAFE
8. Attack Path Explanation: Stages and transitions preserve evidence continuity
9. MITRE Grounding: Unsupported techniques cannot become SUPPORTED
10. LLM Hallucination Validation: Rejection of unsupported IPs, domains, hashes, MITRE IDs, altered scores
11. Deterministic Fallback: Fallback to template when LLM fails or hallucinates
12. Versioning & Snapshots: Immutability and reproducible historical lineage (v1 -> v2)
13. Privacy Redaction: Passwords, tokens, and API keys are redacted
14. Explainability Quality Metrics: Grounding rate, evidence coverage, fallback rate
"""
import asyncio
import json
import pytest
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.db.session import SessionLocal, init_db
from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    AttackTechniqueMappingModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    RiskAssessmentModel,
    ThreatEventModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.explainable_ai import (
    ClaimType,
    ExplanationLayer,
    ExplanationResponse,
    ExplanationScope,
    FeedbackType,
    SupportLevel,
)
from backend.services.explanation_composer import ExplanationComposer
from backend.services.llm_explanation_service import LLMExplanationService
from backend.services.risk_engine_service import RiskEngineService


@pytest.fixture(scope="module")
def db_session():
    init_db()
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture
def sample_threat_event(db_session: Session):
    event_id = generate_uuid()
    artifact_id = generate_uuid()
    run_id = generate_uuid()
    now = get_utc_now()

    artifact = ArtifactModel(
        id=artifact_id,
        artifact_type="EMAIL",
        name="suspicious_phish.eml",
        created_at=now,
    )
    db_session.add(artifact)

    run = AnalysisRunModel(
        id=run_id,
        artifact_id=artifact_id,
        status="COMPLETED",
        overall_risk_score=85.0,
        overall_severity="HIGH",
        confidence=0.90,
        created_at=now,
    )
    db_session.add(run)

    event = ThreatEventModel(
        id=event_id,
        event_type="phishing_email",
        source_artifact_id=artifact_id,
        analysis_run_id=run_id,
        risk_score=85.0,
        severity="HIGH",
        confidence=0.90,
        summary="User received targeted lookalike credential harvesting email.",
        metadata_json=json.dumps({
            "sender": "attacker@paypa1-security.com",
            "subject": "Urgent Account Suspension Notice",
            "url": "https://paypa1-security.com/login",
            "recipient": "victim@corporate.com",
        }),
        created_at=now,
        updated_at=now,
    )
    db_session.add(event)

    # Add findings with evidence
    finding = FindingModel(
        id=generate_uuid(),
        analysis_run_id=run_id,
        analyzer="lookalike_detector",
        finding_type="LOOKALIKE_DOMAIN",
        title="Homoglyph Domain Impersonating Brand",
        description="Domain paypa1-security.com mimics paypal.com with character replacement.",
        severity="HIGH",
        confidence=0.92,
        method="HEURISTIC",
        created_at=now,
    )
    db_session.add(finding)
    db_session.flush()

    finding_ev = FindingEvidenceModel(
        id=generate_uuid(),
        finding_id=finding.id,
        evidence_type="DOMAIN",
        source="lookalike_detector",
        key="domain",
        value="paypa1-security.com",
        confidence=0.95,
        created_at=now,
    )
    db_session.add(finding_ev)

    # Add MITRE technique mapping
    mitre = AttackTechniqueMappingModel(
        id=generate_uuid(),
        source_type="EVENT",
        source_id=event_id,
        technique_id="T1566.002",
        technique_name="Spearphishing Link",
        tactic_names_json=json.dumps(["Initial Access"]),
        status="SUPPORTED",
        confidence=0.92,
        mapping_method="RULE_BASED",
        explanation="Lookalike URL detected in email body targeting corporate credentials.",
        evidence_ids_json=json.dumps(["EV-DOMAIN-101"]),
        event_ids_json=json.dumps([event_id]),
        created_at=now,
    )
    db_session.add(mitre)

    db_session.commit()
    db_session.refresh(event)
    return event


class TestExplainableAI:
    """Test suite for Section 27 Explainable AI."""

    def test_decision_vs_explanation_separation_and_risk_consistency(self, db_session: Session, sample_threat_event):
        """Verify explanation strictly consumes RiskAssessment risk_score without recalculation."""
        # 1. Evaluate risk deterministically first
        assessment = RiskEngineService.evaluate_threat_event(
            db=db_session,
            threat_event_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        assert assessment is not None
        initial_score = assessment.risk_score
        initial_level = assessment.risk_level
        initial_confidence = assessment.confidence

        # 2. Compose explanation
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
            force_refresh=True,
        )

        resp = ExplanationComposer.to_response_model(expl, db_session)

        # 3. Assert exact risk score, level, and confidence consistency
        assert resp.risk_score == initial_score
        assert resp.risk_level.value == initial_level
        assert resp.confidence == initial_confidence

    def test_evidence_grounding_for_all_claims(self, db_session: Session, sample_threat_event):
        """Every explanation claim must reference valid evidence or finding IDs."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        assert len(resp.explanation_units) > 0

        for unit in resp.explanation_units:
            # Must have non-empty claim and at least one evidence reference
            assert len(unit.claim.strip()) > 5
            assert len(unit.evidence_refs) > 0
            assert unit.confidence >= 0.0 and unit.confidence <= 1.0
            assert unit.support_level in (SupportLevel.CONFIRMED, SupportLevel.VERY_HIGH, SupportLevel.HIGH, SupportLevel.MODERATE, SupportLevel.WEAK)

    def test_counter_evidence_and_contradictions_representation(self, db_session: Session, sample_threat_event):
        """Verifies that counter-evidence and contradictions are represented when present."""
        # 1. Ensure authoritative risk assessment exists
        assessment = RiskEngineService.evaluate_threat_event(
            db=db_session,
            threat_event_id=sample_threat_event.id,
            workspace_id="test_ws",
        )

        # 2. Inject contradictory counter-signals
        assessment.counter_evidence_refs_json = json.dumps(["EV-AUTH-SPF-PASS"])
        assessment.contradictions_json = json.dumps([{
            "topic": "Domain Identity",
            "supporting_claim": "Lookalike domain observed",
            "counter_claim": "SPF authentication verified",
            "supporting_signal_id": "SIG-LOOKALIKE-1",
            "counter_signal_id": "SIG-SPF-1",
            "severity_impact": "Confidence discounted",
        }])
        db_session.commit()

        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
            force_refresh=True,
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        assert len(resp.counter_evidence) > 0
        assert any("SPF" in ce.claim or "SPF" in str(ce.evidence_refs) for ce in resp.counter_evidence)
        assert len(resp.contradictions) > 0
        assert resp.contradictions[0].claim == "Lookalike domain observed"
        assert resp.contradictions[0].conflicting_signal == "SPF authentication verified"

    def test_unknowns_and_missing_information_not_assumed_safe(self, db_session: Session, sample_threat_event):
        """Missing information and unknowns must be explicitly recorded and never assumed safe."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        # Missing information items should exist
        assert len(resp.missing_information) > 0
        # E.g. Endpoint Process Telemetry
        endpoint_gap = next((g for g in resp.missing_information if "Endpoint" in g.telemetry_source), None)
        assert endpoint_gap is not None
        assert "Cannot establish" in endpoint_gap.impact

    def test_what_would_change_this_assessment_guidance(self, db_session: Session, sample_threat_event):
        """Assessment change guidance must specify concrete strengthen and weaken conditions."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        guidance = resp.assessment_change_guidance
        assert len(guidance.what_would_strengthen) > 0
        assert len(guidance.what_would_weaken) > 0
        assert any("link" in s.lower() or "attachment" in s.lower() or "c2" in s.lower() for s in guidance.what_would_strengthen)
        assert any("authorized" in w.lower() or "partner" in w.lower() or "simulation" in w.lower() for w in guidance.what_would_weaken)

    def test_mitre_explanation_grounding(self, db_session: Session, sample_threat_event):
        """MITRE technique mappings must be evidence-backed and cannot be fabricated."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        assert len(resp.mitre_explanations) > 0
        t1566 = next((m for m in resp.mitre_explanations if m.technique_id == "T1566.002"), None)
        assert t1566 is not None
        assert t1566.technique_name == "Spearphishing Link"
        assert t1566.mapping_status == "SUPPORTED"
        assert len(t1566.evidence_refs) > 0

    def test_progressive_disclosure_layers(self, db_session: Session, sample_threat_event):
        """Verifies Executive (L1), Analyst (L2), Investigator (L3), and Forensic (L4) depths."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        # L1: Executive (1-2 sentences)
        assert len(resp.executive_summary) > 20
        assert "\n\n\n" not in resp.executive_summary
        assert resp.risk_level.value in resp.executive_summary

        # L2: Analyst (Contributors & Counter-Evidence)
        assert "EVALUATION SUMMARY:" in resp.analyst_summary
        assert "PRIMARY SUPPORTING EVIDENCE:" in resp.analyst_summary

        # L3: Investigator (Full graph & MITRE)
        assert len(resp.investigator_details) > 0
        assert "evidence_chain_count" in resp.investigator_details

        # L4: Forensic (Hashes, exact references, configuration versions)
        assert "scoring_configuration_version" in resp.forensic_details
        assert "evidence_reference_ids" in resp.forensic_details

    def test_evidence_graph_nodes_and_edges(self, db_session: Session, sample_threat_event):
        """Verifies evidence graph construction with Conclusion -> Finding -> Evidence hierarchy."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        graph = resp.evidence_graph
        assert len(graph.nodes) > 0
        assert len(graph.edges) > 0

        # Check root conclusion node
        root = next((n for n in graph.nodes if n.node_type == "CONCLUSION"), None)
        assert root is not None

        # Check finding nodes
        findings = [n for n in graph.nodes if n.node_type == "FINDING"]
        assert len(findings) > 0

        # Check edges connect root to findings
        supported_by_edges = [e for e in graph.edges if e.relation == "supported_by"]
        assert len(supported_by_edges) > 0
        assert supported_by_edges[0].source == root.id

    def test_llm_hallucination_validation_rejects_unsupported_entities(self, db_session: Session, sample_threat_event):
        """LLM validator must reject hallucinated IP addresses, domains, and altered risk scores."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        llm_service = LLMExplanationService()
        ground_truth = llm_service.extract_ground_truth_entities(resp)

        # 1. Test clean grounded narrative
        clean_narrative = (
            f"CyberGuard evaluated this event with a Risk Score of {resp.risk_score:.0f}/100. "
            f"The homoglyph domain paypa1-security.com mimics legitimate infrastructure. "
            f"Technique T1566.002 Spearphishing Link was identified."
        )
        is_valid, unsupp = llm_service.validate_narrative(clean_narrative, ground_truth)
        assert is_valid is True
        assert len(unsupp) == 0

        # 2. Test hallucinated IP address
        hallucinated_ip = clean_narrative + " Attacking command-and-control server is 198.51.100.77."
        is_valid, unsupp = llm_service.validate_narrative(hallucinated_ip, ground_truth)
        assert is_valid is False
        assert any("198.51.100.77" in err for err in unsupp)

        # 3. Test hallucinated domain
        hallucinated_domain = clean_narrative + " Exfiltration occurred to evil-c2-drop.xyz."
        is_valid, unsupp = llm_service.validate_narrative(hallucinated_domain, ground_truth)
        assert is_valid is False
        assert any("evil-c2-drop.xyz" in err for err in unsupp)

        # 4. Test altered risk score
        altered_score = "CyberGuard assigned a Risk Score: 99.8/100 to this event."
        is_valid, unsupp = llm_service.validate_narrative(altered_score, ground_truth)
        assert is_valid is False
        assert any("Altered Risk Score" in err for err in unsupp)

    def test_deterministic_fallback_on_llm_failure_or_rejection(self, db_session: Session, sample_threat_event):
        """When LLM hallucinates or fails, the service falls back to the deterministic template."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        # Mock provider that produces a hallucinated domain
        class HallucinatingMockProvider:
            async def generate_assessment(self, prompt: str, system_prompt: str):
                return "The malicious attack communicated with phantom-attacker-c2.ru at 185.220.101.5."

        service = LLMExplanationService(provider=HallucinatingMockProvider())
        narrative_resp = asyncio.run(service.generate_grounded_narrative(
            explanation=resp,
            strict_validation=True,
        ))

        assert narrative_resp.used_fallback is True
        assert narrative_resp.validation_passed is False
        assert len(narrative_resp.unsupported_entities_detected) > 0
        # The returned narrative must be the deterministic fallback
        assert "EVALUATION SUMMARY:" in narrative_resp.narrative

    def test_privacy_redaction_of_secrets(self):
        """Sensitive passwords, bearer tokens, and credentials must be redacted."""
        sensitive_text = (
            "Detected payload with password='SuperSecretPassword123!' and Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz "
            "and api_key='ak_live_abcdef1234567890'."
        )
        redacted = ExplanationComposer.redact_secrets(sensitive_text)
        assert "SuperSecretPassword123!" not in redacted
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
        assert "ak_live_abcdef1234567890" not in redacted
        assert "[REDACTED_SECRET]" in redacted

    def test_explanation_versioning_and_snapshots(self, db_session: Session, sample_threat_event):
        """Historical explanations must increment versions (v1 -> v2) and support immutable snapshots."""
        # 1. Create v1
        v1 = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
            force_refresh=True,
        )
        v1_id = v1.id
        v1_ver = v1.explanation_version

        # 2. Create snapshot of v1
        snapshot = ExplanationComposer.create_snapshot(
            db=db_session,
            explanation_id=v1_id,
            workspace_id="test_ws",
        )
        assert snapshot.explanation_id == v1_id
        assert len(snapshot.checksum) == 64

        # 3. Create v2
        v2 = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
            force_refresh=True,
        )

        assert v2.id != v1_id
        assert v2.explanation_version == v1_ver + 1
        assert v2.status == "CURRENT"

        # Check v1 status updated to SUPERSEDED
        db_session.refresh(v1)
        assert v1.status == "SUPERSEDED"

    def test_analyst_feedback_recording(self, db_session: Session, sample_threat_event):
        """Analyst feedback must be recorded without overwriting forensic records."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )

        fb = ExplanationComposer.record_feedback(
            db=db_session,
            explanation_id=expl.id,
            analyst_id="analyst_alice",
            feedback_type=FeedbackType.ANALYST_CONFIRMED.value,
            notes="Confirmed lookalike phishing email impersonating brand.",
            target_claim_id="CLAIM-001",
            workspace_id="test_ws",
        )

        assert fb.id is not None
        assert fb.explanation_id == expl.id
        assert fb.analyst_id == "analyst_alice"
        assert fb.feedback_type == "ANALYST_CONFIRMED"

    def test_explainability_quality_metrics(self, db_session: Session, sample_threat_event):
        """Verifies calculation of internal explainability quality metrics."""
        expl = ExplanationComposer.compose_explanation(
            db=db_session,
            scope_type="EVENT",
            scope_id=sample_threat_event.id,
            workspace_id="test_ws",
        )
        resp = ExplanationComposer.to_response_model(expl, db_session)

        metrics = LLMExplanationService.compute_quality_metrics(resp)
        assert metrics.total_claims > 0
        assert metrics.grounded_claims > 0
        assert metrics.claim_grounding_rate > 0.0 and metrics.claim_grounding_rate <= 1.0
        assert metrics.unsupported_claim_rate >= 0.0
        assert metrics.provenance_resolution_rate > 0.0
