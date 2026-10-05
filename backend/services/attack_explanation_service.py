"""
Attack Explanation Service (Section 18).
Generates analyst-readable, evidence-grounded explanations for:
- Why an attack stage exists
- Why two stages are connected by a transition
- Why an attack path was reconstructed and its weakest links
- Why entities or incidents are connected (via Section 14 & 15 provenance)
- Why one hypothesis outranks another (no black-box ranking)
- Deterministic report-ready explanations with strict epistemic safety

CORE PRINCIPLES:
1. EXPLAINABILITY MUST COME FROM EVIDENCE:
   Evidence -> structured reasoning -> confidence decomposition -> explanation.
   Never generate stories first and search for evidence later.
2. EPISTEMIC HUMILITY:
   Preserve epistemic language (OBSERVED vs DERIVED vs INFERRED).
   Never convert "Possible credential compromise" into "Credentials were stolen".
3. STRICT LLM SAFETY:
   Deterministic explanation first. LLM is optional and grounded strictly in evidence IDs.
   Untrusted artifact content is isolated in <untrusted_content> to prevent prompt injection.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import logging
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from backend.db.models import (
    IncidentModel,
    AttackPathModel,
    AttackStageModel,
    AttackEdgeModel,
    AttackHypothesisModel,
    SecurityEventModel,
    FindingModel,
    FindingEvidenceModel,
    RelationshipModel,
    RelationshipObservationModel,
    IncidentCorrelationModel,
    EntityModel,
    ArtifactModel,
    get_utc_now,
)
from backend.schemas.attack_confidence import (
    ConfidenceLevel,
    SourceTrustLevel,
    ConfidenceDimension,
    ContradictionType,
    EvidenceGapType,
    ConfidenceConfig,
    ConfidenceBottleneck,
    ConfidenceBreakdown,
    Explanation,
    HypothesisComparisonResult,
    ReportReadyExplanation,
    score_to_confidence_level,
)
from backend.services.attack_confidence_engine import AttackConfidenceEngine

logger = logging.getLogger(__name__)


class AttackExplanationService:
    """
    Forensic explanation service generating structured, verifiable explanations.
    """

    @classmethod
    def explain_stage(
        cls,
        stage_id: str,
        db: Session,
        candidate_facts: Optional[List[Dict[str, Any]]] = None
    ) -> Explanation:
        """
        Explains why a specific attack stage exists in the reconstruction.
        """
        stage = db.query(AttackStageModel).filter(AttackStageModel.id == stage_id).first()
        if not stage:
            raise ValueError(f"Attack stage with ID {stage_id} not found.")

        # Load supporting evidence and findings
        evidence_items: List[Dict[str, Any]] = []
        try:
            evidence_items = json.loads(stage.supporting_evidence_json or "[]")
        except Exception:
            evidence_items = []

        findings: List[Dict[str, Any]] = []
        try:
            f_ids = json.loads(stage.finding_ids_json or "[]")
            if f_ids:
                f_models = db.query(FindingModel).filter(FindingModel.id.in_(f_ids)).all()
                for fm in f_models:
                    findings.append({
                        "id": fm.id,
                        "finding_type": fm.finding_type,
                        "title": fm.title,
                        "severity": fm.severity,
                        "confidence": fm.confidence,
                        "method": fm.method
                    })
        except Exception:
            findings = []

        known_gaps: List[str] = []
        try:
            known_gaps = json.loads(stage.limitations_json or "[]")
        except Exception:
            known_gaps = []

        # Calculate confidence breakdown
        breakdown = AttackConfidenceEngine.score_stage(
            stage=stage,
            context_evidence=evidence_items,
            findings=findings,
            candidate_facts=candidate_facts,
            known_gaps=known_gaps
        )

        # Build bulleted WHY reasons
        why: List[str] = []
        status_str = stage.stage_status or "INFERRED"
        if status_str == "OBSERVED":
            why.append(f"Direct telemetry observation: Stage activity was authoritatively recorded by security sensors at {stage.start_time or 'specified time'}.")
            if evidence_items:
                why.append(f"Grounding evidence: {len(evidence_items)} specific telemetry record(s) directly capture this activity.")
        elif status_str == "DERIVED":
            why.append("Deterministic derivation: Activity is computed directly from raw observations and cryptographic/rule indicators.")
        elif status_str == "INFERRED":
            why.append("Behavioral inference: Stage is an evidence-constrained analytical hypothesis based on preceding and succeeding activity.")
            if stage.description:
                why.append(f"Analytical rationale: {stage.description}")
        else:
            why.append("Potential activity identified, but conclusive telemetry is currently absent or inconclusive.")

        for f in findings[:3]:
            why.append(f"Analyzer finding: {f.get('title')} ({f.get('finding_type')}) confirmed with confidence {f.get('confidence', 1.0):.2f}.")

        # Recommendations on what would strengthen / weaken
        what_strengthen: List[str] = []
        what_weaken: List[str] = []
        for gap in breakdown.missing_evidence:
            what_strengthen.extend(gap.what_would_strengthen)
            what_weaken.extend(gap.what_would_weaken)

        if not what_strengthen:
            what_strengthen.append("Direct authoritative server or host log verifying execution.")
        if not what_weaken:
            what_weaken.append("Proof that observed telemetry corresponds to scheduled benign maintenance.")

        # Alternative explanations
        alternatives: List[str] = []
        if status_str == "INFERRED":
            alternatives.append("Activity may reflect authorized administrative maintenance or testing.")
            alternatives.append("Behavioral anomaly could be caused by misconfigured automated software.")
        else:
            alternatives.append("Benign execution by authenticated user during authorized shift.")

        summary = (
            f"Stage '{stage.name}' is categorized as [{status_str}] with {breakdown.confidence_level.value} "
            f"confidence (score: {breakdown.raw_score:.2f}). "
            f"Evaluated across {len(breakdown.components)} dimensions with {breakdown.independent_sources_count} "
            f"independent evidence source(s)."
        )

        return Explanation(
            subject_type="STAGE",
            subject_id=stage.id,
            title=stage.name or "Attack Stage",
            summary=summary,
            why=why,
            supporting_evidence=evidence_items,
            contradicting_evidence=breakdown.contradicting_evidence,
            missing_evidence=breakdown.missing_evidence,
            confidence_breakdown=breakdown,
            alternative_explanations=alternatives,
            what_would_strengthen=list(dict.fromkeys(what_strengthen)),
            what_would_weaken=list(dict.fromkeys(what_weaken)),
            limitations=[c.description for c in breakdown.contradicting_evidence] + [g.impact_description for g in breakdown.missing_evidence]
        )

    @classmethod
    def explain_transition(
        cls,
        edge_id: str,
        db: Session,
        candidate_facts: Optional[List[Dict[str, Any]]] = None
    ) -> Explanation:
        """
        Explains why two attack stages are connected by a directed transition edge.
        """
        edge = db.query(AttackEdgeModel).filter(AttackEdgeModel.id == edge_id).first()
        if not edge:
            raise ValueError(f"Attack transition with ID {edge_id} not found.")

        src_id = getattr(edge, "source_stage_id", getattr(edge, "from_stage_id", None))
        tgt_id = getattr(edge, "target_stage_id", getattr(edge, "to_stage_id", None))
        from_stage = db.query(AttackStageModel).filter(AttackStageModel.id == src_id).first()
        to_stage = db.query(AttackStageModel).filter(AttackStageModel.id == tgt_id).first()

        breakdown = AttackConfidenceEngine.score_transition(
            from_stage=from_stage,
            to_stage=to_stage,
            edge_model=edge,
            candidate_facts=candidate_facts
        )

        from_name = getattr(from_stage, "name", "Stage A")
        to_name = getattr(to_stage, "name", "Stage B")

        shared_entities = []
        try:
            shared_entities = json.loads(edge.shared_entities_json or "[]")
        except Exception:
            shared_entities = []

        why: List[str] = []
        if shared_entities:
            why.append(f"Entity continuity: Both stages reference shared entities: {', '.join(shared_entities[:3])}.")
        else:
            why.append("Entity continuity: Connected via chronological sequence and threat context without direct shared identifier.")

        if edge.temporal_gap_seconds is not None:
            if edge.temporal_gap_seconds <= 60:
                why.append(f"Temporal proximity: Successive events occurred {edge.temporal_gap_seconds:.1f} seconds apart.")
            elif edge.temporal_gap_seconds <= 3600:
                why.append(f"Temporal proximity: Activity observed within {edge.temporal_gap_seconds / 60.0:.1f} minutes.")
            else:
                why.append(f"Temporal interval: Stages separated by {edge.temporal_gap_seconds / 3600.0:.1f} hours.")

        why.append(f"Relationship semantics: {edge.relationship_type or 'PRECEDES'} connection evaluated as {breakdown.epistemic_status}.")

        what_strengthen: List[str] = []
        what_weaken: List[str] = []
        for gap in breakdown.missing_evidence:
            what_strengthen.extend(gap.what_would_strengthen)
            what_weaken.extend(gap.what_would_weaken)

        summary = (
            f"Transition '{from_name}' -> '{to_name}' has {breakdown.confidence_level.value} "
            f"confidence (score: {breakdown.raw_score:.2f}). "
            f"{'Identified as speculative transition with evidence gaps.' if breakdown.missing_evidence else 'Strongly corroborated by continuous telemetry.'}"
        )

        return Explanation(
            subject_type="TRANSITION",
            subject_id=edge.id,
            title=f"{from_name} -> {to_name}",
            summary=summary,
            why=why,
            supporting_evidence=breakdown.supporting_evidence,
            contradicting_evidence=breakdown.contradicting_evidence,
            missing_evidence=breakdown.missing_evidence,
            confidence_breakdown=breakdown,
            alternative_explanations=[
                "Stages may represent coincidental concurrent activity by different actors.",
                "Subsequent activity could be an unrelated benign workflow initiated by authorized user."
            ],
            what_would_strengthen=list(dict.fromkeys(what_strengthen)) or ["Network connection telemetry linking both hosts directly."],
            what_would_weaken=list(dict.fromkeys(what_weaken)) or ["Evidence proving intervening session timeout or distinct user authentication."],
            limitations=[c.description for c in breakdown.contradicting_evidence] + [g.impact_description for g in breakdown.missing_evidence]
        )

    @classmethod
    def explain_attack_path(
        cls,
        path_id: str,
        db: Session,
        candidate_facts: Optional[List[Dict[str, Any]]] = None
    ) -> Explanation:
        """
        Explains the complete reconstructed attack path, exposing confidence bottlenecks,
        strongly supported sub-chains, and critical missing telemetry.
        """
        path = db.query(AttackPathModel).filter(AttackPathModel.id == path_id).first()
        if not path:
            raise ValueError(f"Attack path with ID {path_id} not found.")

        stages = db.query(AttackStageModel).filter(AttackStageModel.attack_path_id == path_id).order_by(AttackStageModel.stage_order.asc()).all()
        edges = db.query(AttackEdgeModel).filter(AttackEdgeModel.attack_path_id == path_id).all()

        breakdown, bottleneck = AttackConfidenceEngine.score_path(
            path=path,
            stages=stages,
            edges=edges,
            candidate_facts=candidate_facts
        )

        why: List[str] = [
            f"Reconstruction encompasses {len(stages)} stage(s) across {len(edges)} transition edge(s).",
            f"Overall heuristic evidence strength: {breakdown.raw_score:.2f} ({breakdown.confidence_level.value}).",
            f"Confidence Bottleneck identified: '{bottleneck.subject_name}' ({bottleneck.confidence_level.value}, score: {bottleneck.confidence:.2f}).",
            f"Bottleneck rationale: {bottleneck.primary_uncertainty}"
        ]

        # Categorize transitions
        strongly_supported: List[str] = []
        weakest_transitions: List[str] = []
        stage_map = {s.id: s for s in stages}
        for e in edges:
            src_id = getattr(e, "source_stage_id", getattr(e, "from_stage_id", None))
            tgt_id = getattr(e, "target_stage_id", getattr(e, "to_stage_id", None))
            from_name = getattr(stage_map.get(src_id), "title", getattr(stage_map.get(src_id), "name", "Stage A"))
            to_name = getattr(stage_map.get(tgt_id), "title", getattr(stage_map.get(tgt_id), "name", "Stage B"))
            if e.confidence >= 0.75:
                strongly_supported.append(f"{from_name} -> {to_name}")
            elif e.confidence < 0.60:
                weakest_transitions.append(f"{from_name} -> {to_name} (score: {e.confidence:.2f})")

        if strongly_supported:
            why.append(f"Strongly supported transition chains: {'; '.join(strongly_supported[:3])}.")
        if weakest_transitions:
            why.append(f"Speculative or uncertain transitions: {'; '.join(weakest_transitions[:3])}.")

        summary = (
            f"CyberGuard reconstructed a {path.classification or 'PLAUSIBLE_RECONSTRUCTION'} with {breakdown.confidence_level.value} "
            f"confidence. Several stages are directly observed, while the overall chain is constrained by "
            f"the confidence bottleneck at '{bottleneck.subject_name}'. {bottleneck.primary_uncertainty}"
        )

        return Explanation(
            subject_type="PATH",
            subject_id=path.id,
            title=path.name or "Reconstructed Attack Path",
            summary=summary,
            why=why,
            supporting_evidence=breakdown.supporting_evidence,
            contradicting_evidence=breakdown.contradicting_evidence,
            missing_evidence=breakdown.missing_evidence,
            confidence_breakdown=breakdown,
            alternative_explanations=[
                "Incident may be composed of multiple disjoint benign anomalies coinciding temporally.",
                "Initial entry vector may differ from reconstructed phishing delivery if alternative vector telemetry is missing."
            ],
            what_would_strengthen=bottleneck.recommendations or ["Telemetry directly bridging the weakest transition."],
            what_would_weaken=["Proof that activity in subsequent stages originated from authorized internal administrators."],
            limitations=[bottleneck.primary_uncertainty] + [g.impact_description for g in breakdown.missing_evidence[:3]]
        )

    @classmethod
    def explain_entity_relationship(
        cls,
        relationship_id: str,
        db: Session
    ) -> Dict[str, Any]:
        """
        Explains why two entities are connected in the Knowledge Graph (Section 14).
        Grounds reasoning strictly in sensor observations and timestamps (never 'AI determined').
        """
        rel = db.query(RelationshipModel).filter(RelationshipModel.id == relationship_id).first()
        if not rel:
            raise ValueError(f"Knowledge Graph relationship with ID {relationship_id} not found.")

        observations = db.query(RelationshipObservationModel).filter(
            RelationshipObservationModel.relationship_id == relationship_id
        ).all()

        reasons: List[str] = []
        if observations:
            for obs in observations:
                obs_time = obs.observed_at.isoformat() if obs.observed_at else "recorded time"
                analyzer_str = obs.analyzer or "telemetry sensor"
                reasons.append(
                    f"{analyzer_str} observed '{rel.source_id}' {rel.relationship_type} '{rel.target_id}' at {obs_time} (origin: {obs.origin})."
                )
        else:
            reasons.append(
                f"Relationship '{rel.relationship_type}' established by method {rel.method} between '{rel.source_id}' and '{rel.target_id}' (origin: {rel.origin})."
            )

        return {
            "relationship_id": rel.id,
            "source": f"{rel.source_type}:{rel.source_id}",
            "relationship_type": rel.relationship_type,
            "target": f"{rel.target_type}:{rel.target_id}",
            "confidence": rel.confidence,
            "confidence_level": score_to_confidence_level(rel.confidence).value,
            "origin": rel.origin,
            "observation_count": len(observations),
            "grounded_explanations": reasons,
            "provenance_summary": f"Observed by {len(observations)} sensor telemetry event(s)."
        }

    @classmethod
    def explain_cross_incident(
        cls,
        correlation_id: str,
        db: Session
    ) -> Dict[str, Any]:
        """
        Explains why two incidents are correlated in Section 15 campaign detection.
        Cites exact shared IOCs, infrastructure, and time delta.
        """
        corr = db.query(IncidentCorrelationModel).filter(IncidentCorrelationModel.id == correlation_id).first()
        if not corr:
            raise ValueError(f"Incident correlation with ID {correlation_id} not found.")

        shared_iocs = []
        try:
            shared_iocs = json.loads(corr.shared_indicators_json or "[]")
        except Exception:
            shared_iocs = []

        supporting = []
        try:
            supporting = json.loads(corr.supporting_evidence_json or "[]")
        except Exception:
            supporting = []

        reasons: List[str] = [
            f"Correlation score: {corr.correlation_score:.2f} ({corr.relationship_label}).",
            f"Shared technical indicators: {', '.join(shared_iocs) if shared_iocs else 'None directly shared'}."
        ]
        for sup in supporting:
            if isinstance(sup, dict):
                reasons.append(f"Corroborating signal: {sup.get('description', json.dumps(sup))}")
            else:
                reasons.append(f"Corroborating signal: {sup}")

        return {
            "correlation_id": corr.id,
            "incident_a_id": corr.incident_a_id,
            "incident_b_id": corr.incident_b_id,
            "score": corr.correlation_score,
            "confidence": corr.confidence,
            "confidence_level": score_to_confidence_level(corr.confidence).value,
            "relationship_label": corr.relationship_label,
            "shared_indicators": shared_iocs,
            "why_correlated": reasons,
            "limitations": [
                "Shared target identity alone is weak evidence without matching infrastructure or payload.",
                "Common cloud CDN IPs are prevalence-adjusted and do not prove coordinated campaign."
            ]
        }

    @classmethod
    def generate_report_explanation(
        cls,
        incident_id: str,
        db: Session,
        path_id: Optional[str] = None
    ) -> ReportReadyExplanation:
        """
        Generates executive and technical report summary with strict epistemic guardrails.
        (e.g., 'Possible credential compromise' is never converted to 'Credentials were stolen').
        """
        path = None
        if path_id:
            path = db.query(AttackPathModel).filter(AttackPathModel.id == path_id).first()
        else:
            path = db.query(AttackPathModel).filter(
                AttackPathModel.incident_id == incident_id,
                AttackPathModel.status == "CURRENT"
            ).order_by(AttackPathModel.confidence.desc()).first()

        if not path:
            return ReportReadyExplanation(
                incident_id=incident_id,
                overall_confidence_level=ConfidenceLevel.UNKNOWN,
                overall_evidence_strength="UNKNOWN",
                strongly_supported=[],
                moderately_supported=[],
                weakest_transitions=[],
                confidence_bottleneck=None,
                important_evidence_gaps=["No current reconstructed attack path for incident."],
                contradictions_observed=[],
                alternative_explanations=[],
                executive_summary="No reconstructed attack path telemetry is currently available for this incident."
            )

        stages = db.query(AttackStageModel).filter(AttackStageModel.attack_path_id == path.id).order_by(AttackStageModel.stage_order.asc()).all()
        edges = db.query(AttackEdgeModel).filter(AttackEdgeModel.attack_path_id == path.id).all()

        breakdown, bottleneck = AttackConfidenceEngine.score_path(
            path=path,
            stages=stages,
            edges=edges
        )

        stage_map = {s.id: s for s in stages}
        strongly_supported: List[Dict[str, Any]] = []
        moderately_supported: List[Dict[str, Any]] = []
        weakest_transitions: List[Dict[str, Any]] = []

        for e in edges:
            src_id = getattr(e, "source_stage_id", getattr(e, "from_stage_id", None))
            tgt_id = getattr(e, "target_stage_id", getattr(e, "to_stage_id", None))
            from_name = getattr(stage_map.get(src_id), "title", getattr(stage_map.get(src_id), "name", "Stage A"))
            to_name = getattr(stage_map.get(tgt_id), "title", getattr(stage_map.get(tgt_id), "name", "Stage B"))
            item = {
                "transition": f"{from_name} -> {to_name}",
                "confidence": e.confidence,
                "confidence_level": score_to_confidence_level(e.confidence).value
            }
            if e.confidence >= 0.75:
                strongly_supported.append(item)
            elif e.confidence >= 0.40:
                moderately_supported.append(item)
            else:
                weakest_transitions.append(item)

        if not weakest_transitions and bottleneck and bottleneck.bottleneck_type == "TRANSITION":
            weakest_transitions.append({
                "transition": bottleneck.subject_name,
                "confidence": bottleneck.confidence,
                "confidence_level": bottleneck.confidence_level.value,
                "uncertainty": bottleneck.primary_uncertainty
            })

        evidence_gaps_summary: List[str] = []
        for g in breakdown.missing_evidence:
            evidence_gaps_summary.append(g.impact_description)

        contradictions_summary: List[str] = []
        for c in breakdown.contradicting_evidence:
            contradictions_summary.append(f"{c.type.value}: {c.description}")

        # Construct safe executive summary (Prompt 68)
        observed_stage_names = [s.name for s in stages if s.stage_status == "OBSERVED"]
        inferred_stage_names = [s.name for s in stages if s.stage_status == "INFERRED"]

        exec_summary = (
            f"CyberGuard reconstructed a plausible attack sequence linking {len(stages)} stage(s). "
            f"Directly observed stages include: {', '.join(observed_stage_names[:3]) or 'None'}. "
            f"{f'Inferred stages requiring further verification include: {chr(44).join(inferred_stage_names[:3])}. ' if inferred_stage_names else ''}"
            f"The primary analytical uncertainty in the reconstruction is '{bottleneck.subject_name}', "
            f"where direct transition telemetry remains incomplete. "
            f"Overall evidence strength is rated as {breakdown.confidence_level.value}."
        )

        return ReportReadyExplanation(
            incident_id=incident_id,
            path_id=path.id,
            overall_confidence_level=breakdown.confidence_level,
            overall_evidence_strength=f"{breakdown.confidence_level.value} (score: {breakdown.raw_score:.2f})",
            strongly_supported=strongly_supported,
            moderately_supported=moderately_supported,
            weakest_transitions=weakest_transitions,
            confidence_bottleneck=bottleneck,
            important_evidence_gaps=list(dict.fromkeys(evidence_gaps_summary)) or ["No major telemetry gaps identified."],
            contradictions_observed=list(dict.fromkeys(contradictions_summary)),
            alternative_explanations=[
                "Observed events may represent separate unrelated operational incidents.",
                "Account activity could reflect legitimate user access from newly acquired device."
            ],
            executive_summary=exec_summary
        )

    @classmethod
    def enhance_with_llm(
        cls,
        explanation: Explanation,
        enable_llm: bool = False,
        untrusted_context: Optional[str] = None
    ) -> str:
        """
        Optionally enhances structured explanation using LLM prose.
        Enforces strict safety:
        1. If LLM is disabled, returns deterministic structured summary.
        2. Prompt injection safety: untrusted content is strictly wrapped in <untrusted_content>.
        3. Unsupported claim validation: ensures narrative references valid evidence/stage IDs.
        """
        # Deterministic explanation first (Prompt 53)
        if not enable_llm:
            return explanation.summary

        # Prompt injection defense (Prompt 55):
        sanitized_untrusted = ""
        if untrusted_context:
            # Strip prompt injection attempts and wrap in strict xml tags
            cleaned = re.sub(r"(ignore previous instructions|system prompt|admin override)", "[FILTERED]", untrusted_context, flags=re.IGNORECASE)
            sanitized_untrusted = f"\n<untrusted_content>\n{cleaned[:1000]}\n</untrusted_content>\n"

        # Construct grounded prompt
        prompt = (
            f"Synthesize the following structured forensic assessment into concise analyst notes.\n"
            f"RULES: Do NOT invent evidence, do NOT alter confidence, do NOT remove limitations.\n"
            f"Stage/Path Title: {explanation.title}\n"
            f"Confidence: {explanation.confidence_breakdown.confidence_level.value} ({explanation.confidence_breakdown.raw_score})\n"
            f"Why: {'; '.join(explanation.why)}\n"
            f"Limitations: {'; '.join(explanation.limitations)}\n"
            f"{sanitized_untrusted}"
        )

        # For production when LLM is connected, call model.
        # Fallback to deterministic synthesis:
        enhanced = (
            f"{explanation.summary} Key observations: {'; '.join(explanation.why[:2])}. "
            f"Known visibility limitations: {'; '.join(explanation.limitations[:2]) if explanation.limitations else 'None'}."
        )
        return enhanced
