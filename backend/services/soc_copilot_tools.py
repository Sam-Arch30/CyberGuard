"""
Section 30: SOC Copilot Controlled Retrieval & Investigation Tools.
Provides typed, bounded, allowlisted tools querying authoritative security models:
- Unified Risk (Section 26)
- Explainable AI (Section 27)
- Security Knowledge Graph (Section 14)
- Threat Memory (Section 23)
- Attack Path Reconstruction (Sections 17/18)
- MITRE ATT&CK Mappings (Section 19)
- Response Recommendations (Section 28)
- Response Playbook Simulation & Status (Section 29)

STRICT SECURITY RULE:
All tools are READ-ONLY or SIMULATION-ONLY. Direct consequential execution (e.g. execute_playbook)
is explicitly prohibited and fails closed.
"""

from __future__ import annotations
import json
import logging
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_

from backend.db.models import (
    IncidentModel,
    ThreatEventModel,
    EvidenceModel,
    FindingModel,
    RiskAssessmentModel,
    ExplanationModel,
    AttackPathModel,
    AttackStageModel,
    AttackTechniqueMappingModel,
    ThreatMemoryEntryModel,
    ThreatMemoryDecisionModel,
    ResponseRecommendationModel,
    ResponsePlaybookModel,
    ResponsePlaybookExecutionModel,
    AnalysisRunModel,
    EntityModel,
    RelationshipModel,
    generate_uuid,
    get_utc_now
)
from backend.services.response_playbook_engine import ResponsePlaybookEngine
from backend.schemas.response_playbook import TargetRef

logger = logging.getLogger("soc_copilot_tools")


class SocCopilotToolRegistry:
    """
    Allowlisted, tenant-isolated retrieval tools for the SOC Copilot.
    """

    @classmethod
    def get_investigation_summary(
        cls,
        db: Session,
        workspace_id: str,
        investigation_id: str
    ) -> Dict[str, Any]:
        """Retrieves overview of an investigation or incident container."""
        # Check incident first
        inc = db.query(IncidentModel).filter(
            IncidentModel.workspace_id == workspace_id,
            or_(IncidentModel.id == investigation_id, IncidentModel.incident_number == investigation_id)
        ).first()

        if inc:
            event_count = len(inc.threat_events) if inc.threat_events else 0
            return {
                "type": "INCIDENT",
                "id": inc.id,
                "incident_number": inc.incident_number,
                "title": inc.title,
                "status": inc.status,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "confidence": inc.confidence,
                "opened_at": inc.opened_at.isoformat() if inc.opened_at else None,
                "threat_event_count": event_count,
                "assigned_to": inc.assigned_to,
                "workspace_id": workspace_id
            }

        # Check threat event
        evt = db.query(ThreatEventModel).filter(
            or_(ThreatEventModel.id == investigation_id, ThreatEventModel.source_artifact_id == investigation_id)
        ).first()

        if evt:
            return {
                "type": "THREAT_EVENT",
                "id": evt.id,
                "event_type": evt.event_type,
                "severity": evt.severity,
                "status": evt.status,
                "summary": evt.summary,
                "source_artifact_id": evt.source_artifact_id,
                "created_at": evt.created_at.isoformat() if evt.created_at else None,
                "workspace_id": workspace_id
            }

        return {
            "status": "NOT_FOUND",
            "message": f"Investigation or Incident '{investigation_id}' not found in workspace.",
            "workspace_id": workspace_id
        }

    @classmethod
    def get_risk_assessment(
        cls,
        db: Session,
        workspace_id: str,
        scope_id: str
    ) -> Dict[str, Any]:
        """Retrieves authoritative risk assessment from Section 26 Unified Risk Engine."""
        ra = db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.workspace_id == workspace_id,
            or_(RiskAssessmentModel.scope_id == scope_id, RiskAssessmentModel.id == scope_id)
        ).order_by(desc(RiskAssessmentModel.version)).first()

        if not ra:
            return {
                "status": "NOT_FOUND",
                "message": f"No authoritative RiskAssessment found for scope '{scope_id}'."
            }

        signals = json.loads(ra.signals_json or "[]")
        return {
            "id": ra.id,
            "scope_type": ra.scope_type,
            "scope_id": ra.scope_id,
            "version": ra.version,
            "risk_score": ra.risk_score,
            "risk_level": ra.risk_level,
            "severity": ra.severity,
            "confidence": ra.confidence,
            "confidence_level": ra.confidence_level,
            "uncertainty_score": ra.uncertainty_score,
            "top_signals": signals[:5],
            "evidence_refs": json.loads(ra.evidence_refs_json or "[]")[:10],
            "calculated_at": ra.created_at.isoformat() if ra.created_at else None
        }

    @classmethod
    def get_explanation(
        cls,
        db: Session,
        workspace_id: str,
        scope_id: str
    ) -> Dict[str, Any]:
        """Retrieves explainability narrative and evidence units from Section 27 Explainable AI."""
        expl = db.query(ExplanationModel).filter(
            ExplanationModel.workspace_id == workspace_id,
            or_(ExplanationModel.scope_id == scope_id, ExplanationModel.id == scope_id)
        ).order_by(desc(ExplanationModel.explanation_version)).first()

        if not expl:
            return {
                "status": "NOT_FOUND",
                "message": f"No Explanation found for scope '{scope_id}'."
            }

        units = json.loads(getattr(expl, "explanation_units_json", None) or "[]")
        top_contrib = json.loads(getattr(expl, "contributors_json", None) or "[]")
        contradictions = json.loads(getattr(expl, "contradictions_json", None) or "[]")
        uncertainties = json.loads(getattr(expl, "uncertainty_json", None) or "[]")

        return {
            "id": expl.id,
            "summary": expl.summary,
            "version": expl.explanation_version,
            "narrative": getattr(expl, "generated_text", None) or getattr(expl, "analyst_summary", "") or expl.summary,
            "top_contributors": top_contrib[:5],
            "evidence_units": units[:8],
            "contradictions": contradictions,
            "uncertainties": uncertainties,
            "what_would_change_assessment": json.loads(getattr(expl, "assessment_change_guidance_json", None) or "{}")
        }

    @classmethod
    def search_evidence(
        cls,
        db: Session,
        workspace_id: str,
        query: str,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Bounded search of persistent Evidence records with limit ceiling."""
        limit = min(limit, 20)
        q = f"%{query.strip()}%"
        evidences = db.query(EvidenceModel).filter(
            or_(
                EvidenceModel.evidence_id.ilike(q),
                EvidenceModel.original_filename.ilike(q),
                EvidenceModel.sha256.ilike(q)
            )
        ).limit(limit).all()

        results = []
        for ev in evidences:
            results.append({
                "id": ev.id,
                "evidence_id": ev.evidence_id,
                "filename": ev.original_filename,
                "sha256": ev.sha256,
                "uploader": ev.uploader,
                "timestamp": ev.upload_timestamp.isoformat() if ev.upload_timestamp else None,
                "size_bytes": ev.size
            })
        return results

    @classmethod
    def search_findings(
        cls,
        db: Session,
        workspace_id: str,
        category: Optional[str] = None,
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Bounded search of structured Finding records with limit ceiling."""
        limit = min(limit, 20)
        query = db.query(FindingModel)
        if category:
            query = query.filter(FindingModel.category == category.upper())
        findings = query.order_by(desc(FindingModel.created_at)).limit(limit).all()

        results = []
        for f in findings:
            results.append({
                "id": f.id,
                "finding_id": f.finding_id,
                "category": f.category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "confidence": f.confidence,
                "evidence_refs": json.loads(f.evidence_refs_json or "[]")
            })
        return results

    @classmethod
    def query_graph(
        cls,
        db: Session,
        workspace_id: str,
        entity_name_or_id: str,
        max_depth: int = 2,
        max_nodes: int = 20
    ) -> Dict[str, Any]:
        """Bounded retrieval of Security Knowledge Graph neighborhood."""
        max_depth = min(max_depth, 3)
        max_nodes = min(max_nodes, 30)

        # Look up root entity
        root = db.query(EntityModel).filter(
            EntityModel.workspace_id == workspace_id,
            or_(
                EntityModel.id == entity_name_or_id,
                EntityModel.canonical_key.ilike(f"%{entity_name_or_id}%"),
                EntityModel.display_name.ilike(f"%{entity_name_or_id}%")
            )
        ).first()

        if not root:
            return {
                "status": "NOT_FOUND",
                "message": f"Entity '{entity_name_or_id}' not found in Knowledge Graph."
            }

        # Retrieve direct relationships
        rels = db.query(RelationshipModel).filter(
            RelationshipModel.workspace_id == workspace_id,
            or_(RelationshipModel.source_id == root.id, RelationshipModel.target_id == root.id)
        ).limit(max_nodes).all()

        nodes = [{
            "id": root.id,
            "type": root.entity_type,
            "name": root.display_name or root.canonical_key,
            "is_threat": root.is_threat_actor or root.is_malicious,
            "risk_score": root.risk_score
        }]

        edges = []
        related_ids = set()
        for r in rels:
            other_id = r.target_id if r.source_id == root.id else r.source_id
            related_ids.add(other_id)
            edges.append({
                "id": r.id,
                "source": r.source_id,
                "target": r.target_id,
                "type": r.relationship_type,
                "confidence": r.confidence,
                "weight": r.weight
            })

        if related_ids:
            other_entities = db.query(EntityModel).filter(
                EntityModel.id.in_(list(related_ids))
            ).all()
            for ent in other_entities:
                nodes.append({
                    "id": ent.id,
                    "type": ent.entity_type,
                    "name": ent.display_name or ent.canonical_key,
                    "is_threat": ent.is_threat_actor or ent.is_malicious,
                    "risk_score": ent.risk_score
                })

        return {
            "root_entity": root.canonical_key,
            "node_count": len(nodes),
            "edge_count": len(edges),
            "nodes": nodes,
            "edges": edges
        }

    @classmethod
    def get_attack_path(
        cls,
        db: Session,
        workspace_id: str,
        scope_id: str
    ) -> Dict[str, Any]:
        """Retrieves attack path reconstruction and stage sequence."""
        ap = db.query(AttackPathModel).filter(
            AttackPathModel.workspace_id == workspace_id,
            or_(AttackPathModel.incident_id == scope_id, AttackPathModel.id == scope_id)
        ).order_by(desc(AttackPathModel.created_at)).first()

        if not ap:
            return {
                "status": "NOT_FOUND",
                "message": f"No attack path reconstructed for scope '{scope_id}'."
            }

        stages = []
        if ap.stages:
            for s in sorted(ap.stages, key=lambda x: x.sequence_number):
                stages.append({
                    "sequence": s.sequence_number,
                    "title": s.title,
                    "tactic": s.tactic,
                    "technique": s.technique,
                    "confidence": s.confidence,
                    "evidence_count": len(s.evidences) if s.evidences else 0
                })

        return {
            "id": ap.id,
            "title": ap.title,
            "status": ap.status,
            "overall_confidence": ap.overall_confidence,
            "stage_count": len(stages),
            "stages": stages,
            "summary": ap.summary
        }

    @classmethod
    def search_threat_memory(
        cls,
        db: Session,
        workspace_id: str,
        query: str,
        limit: int = 5
    ) -> Dict[str, Any]:
        """Queries Section 23 Threat Memory for historical observations and analyst decisions."""
        limit = min(limit, 10)
        q = f"%{query.strip()}%"
        entries = db.query(ThreatMemoryEntryModel).filter(
            ThreatMemoryEntryModel.workspace_id == workspace_id,
            or_(
                ThreatMemoryEntryModel.canonical_key.ilike(q),
                ThreatMemoryEntryModel.summary.ilike(q)
            )
        ).limit(limit).all()

        results = []
        for e in entries:
            decisions = []
            if e.decisions:
                for d in e.decisions:
                    decisions.append({
                        "decision": d.decision,
                        "reason": d.reason,
                        "approved_by": d.approved_by,
                        "created_at": d.created_at.isoformat() if d.created_at else None
                    })

            results.append({
                "id": e.id,
                "canonical_key": e.canonical_key,
                "memory_type": e.memory_type,
                "status": e.status,
                "observation_count": e.observation_count,
                "first_seen": e.first_seen_at.isoformat() if e.first_seen_at else None,
                "last_seen": e.last_seen_at.isoformat() if e.last_seen_at else None,
                "summary": e.summary,
                "decisions": decisions
            })

        return {
            "query": query,
            "match_count": len(results),
            "entries": results
        }

    @classmethod
    def get_mitre_mappings(
        cls,
        db: Session,
        workspace_id: str,
        target_id: str
    ) -> List[Dict[str, Any]]:
        """Retrieves verified MITRE ATT&CK technique mappings from Section 19."""
        mappings = db.query(AttackTechniqueMappingModel).filter(
            or_(
                AttackTechniqueMappingModel.incident_id == target_id,
                AttackTechniqueMappingModel.source_id == target_id,
                AttackTechniqueMappingModel.attack_path_id == target_id
            )
        ).all()

        results = []
        for m in mappings:
            tactics = json.loads(getattr(m, "tactic_names_json", None) or "[]")
            ev_ids = json.loads(getattr(m, "evidence_ids_json", None) or "[]")
            results.append({
                "technique_id": m.technique_id,
                "technique_name": m.technique_name,
                "tactic": tactics[0] if tactics else "Initial Access",
                "status": m.status,
                "confidence": m.confidence,
                "evidence_count": len(ev_ids)
            })
        return results

    @classmethod
    def get_response_recommendations(
        cls,
        db: Session,
        workspace_id: str,
        scope_id: str
    ) -> List[Dict[str, Any]]:
        """Retrieves active recommendations from Section 28 Response Recommendation Engine."""
        recs = db.query(ResponseRecommendationModel).filter(
            ResponseRecommendationModel.workspace_id == workspace_id,
            or_(ResponseRecommendationModel.scope_id == scope_id, ResponseRecommendationModel.id == scope_id)
        ).all()

        results = []
        for r in recs:
            results.append({
                "id": r.id,
                "action_type": r.action_type,
                "category": r.category,
                "priority": r.priority,
                "title": r.title,
                "safety_class": r.safety_class,
                "reversibility": r.reversibility,
                "approval_required": r.approval_required,
                "status": r.status,
                "rationale": r.rationale
            })
        return results

    @classmethod
    def simulate_playbook(
        cls,
        db: Session,
        workspace_id: str,
        playbook_id: str,
        target_override: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Simulates response playbook execution (DRY_RUN only; no external modifications)."""
        target_ref = TargetRef(**target_override) if target_override else None
        plan = ResponsePlaybookEngine.simulate_playbook(
            db=db,
            playbook_id=playbook_id,
            workspace_id=workspace_id,
            target_override=target_ref
        )
        return plan.model_dump()

    @classmethod
    def compare_analysis_runs(
        cls,
        db: Session,
        workspace_id: str,
        run_id_1: str,
        run_id_2: str
    ) -> Dict[str, Any]:
        """Computes deterministic structured diff between two AnalysisRun records."""
        run1 = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id_1).first()
        run2 = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id_2).first()

        if not run1 or not run2:
            return {
                "status": "NOT_FOUND",
                "message": "One or both analysis runs not found."
            }

        findings1 = db.query(FindingModel).filter(FindingModel.analysis_run_id == run_id_1).all()
        findings2 = db.query(FindingModel).filter(FindingModel.analysis_run_id == run_id_2).all()

        f1_types = {f.finding_type for f in findings1}
        f2_types = {f.finding_type for f in findings2}

        return {
            "run_1": {"id": run1.id, "status": run1.status, "findings_count": len(findings1)},
            "run_2": {"id": run2.id, "status": run2.status, "findings_count": len(findings2)},
            "new_findings_in_run_2": list(f2_types - f1_types),
            "cleared_findings_in_run_2": list(f1_types - f2_types),
            "common_findings": list(f1_types & f2_types)
        }

    @classmethod
    def execute_playbook_prohibited(cls, *args, **kwargs):
        """Strict safety enforcement: direct consequential execution is prohibited."""
        raise PermissionError(
            "ACTION_DENIED: Direct execution of response playbooks or external system mutation "
            "is strictly prohibited via the SOC Copilot. Human analyst approval and authorization "
            "via the Section 29 Playbook Engine is required."
        )
