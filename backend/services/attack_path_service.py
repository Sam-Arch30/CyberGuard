"""
Service layer for Section 40: Interactive Attack Path.
Provides authoritative path-level projections of the Security Knowledge Graph,
Attack Reconstruction DAG, Confidence / Explainability models,
MITRE ATT&CK techniques, and Infrastructure Attribution context.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    AttackEdgeModel,
    AttackHypothesisModel,
    AttackPathModel,
    AttackStageModel,
    AttackTechniqueMappingModel,
    CaseModel,
    EntityModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    InfrastructureAttributionModel,
    RelationshipModel,
    SecurityEventModel,
    ThreatEventModel,
    get_utc_now,
)
from backend.schemas.attack_path_projection import (
    AttackAlternativeProjection,
    AttackContradictionProjection,
    AttackGapProjection,
    AttackPathDetailResponse,
    AttackStageProjection,
    AttackTransitionProjection,
)
from backend.schemas.attack_reconstruction import (
    AttackStageType,
    ReconstructionStatusEnum,
    StageStatusEnum,
    StageRelationshipType,
    calculate_confidence_level,
)
from backend.services.attack_reconstruction_engine import attack_reconstruction_engine
from backend.services.investigation_workspace_service import InvestigationWorkspaceService

logger = logging.getLogger("cyberguard.services.attack_path_service")


class AttackPathService:
    """
    Central service for querying, formatting, and synchronizing Interactive Attack Paths.
    Strictly follows the principle:
    - Path-level projection of existing backend Security Knowledge Graph & Reconstruction models.
    - Never calculates confidence or reconstructs paths in the frontend.
    - Rigorously distinguishes causal links from temporal correlations.
    """

    @classmethod
    def get_attack_path_detail(
        cls,
        db: Session,
        identifier: str,
        run_id: Optional[str] = None,
        force_reconstruct: bool = False,
        workspace_id: str = "default",
    ) -> Optional[AttackPathDetailResponse]:
        """
        Retrieves the complete evidence-backed AttackPath detail for an investigation.
        """
        incident, run, artifact, case = InvestigationWorkspaceService.resolve_context(db, identifier)
        if not incident and not run and not artifact and not case:
            return None

        # 1. Resolve Available Analysis Runs
        available_runs: List[Dict[str, Any]] = []
        target_artifact_id = artifact.id if artifact else (run.artifact_id if run else None)
        if target_artifact_id:
            runs_query = (
                db.query(AnalysisRunModel)
                .filter(AnalysisRunModel.artifact_id == target_artifact_id)
                .order_by(AnalysisRunModel.started_at.desc())
                .all()
            )
            for r in runs_query:
                is_curr = (run is not None and r.id == run.id) if not run_id else (r.id == run_id)
                available_runs.append({
                    "run_id": r.id,
                    "version": r.pipeline_version or "1.0",
                    "status": r.status,
                    "overall_risk_score": r.overall_risk_score,
                    "overall_severity": r.overall_severity,
                    "started_at": r.started_at.isoformat() if r.started_at else None,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "is_current": is_curr,
                })
        elif run:
            available_runs.append({
                "run_id": run.id,
                "version": run.pipeline_version or "1.0",
                "status": run.status,
                "overall_risk_score": run.overall_risk_score,
                "overall_severity": run.overall_severity,
                "started_at": run.started_at.isoformat() if run.started_at else None,
                "completed_at": run.completed_at.isoformat() if run.completed_at else None,
                "is_current": True,
            })

        active_run_id = run_id or (run.id if run else None)

        # 2. Query AttackPathModel
        path_model: Optional[AttackPathModel] = None
        if incident:
            path_query = (
                db.query(AttackPathModel)
                .filter(AttackPathModel.incident_id == incident.id)
                .order_by(
                    AttackPathModel.status == ReconstructionStatusEnum.CURRENT.value,
                    AttackPathModel.version.desc(),
                )
            )
            path_model = path_query.first()

            # If no path exists or force reconstruction requested, invoke existing engine
            if (not path_model or force_reconstruct) and incident.id:
                try:
                    reconstructed = attack_reconstruction_engine.reconstruct_incident(
                        db=db,
                        incident_id=incident.id,
                        workspace_id=workspace_id,
                        force_reanalysis=force_reconstruct,
                    )
                    if reconstructed and reconstructed.attack_path:
                        path_model = db.query(AttackPathModel).filter(
                            AttackPathModel.id == reconstructed.attack_path.id
                        ).first()
                except Exception as ex:
                    logger.warning("Auto-reconstruction failed for incident %s: %s", incident.id, ex)

        # 3. Handle Empty / Inconclusive State Truthfully
        if not path_model or not path_model.stages:
            return AttackPathDetailResponse(
                investigation_id=identifier,
                incident_number=incident.incident_number if incident else None,
                analysis_run_id=active_run_id,
                available_runs=available_runs,
                has_path=False,
                status="INCONCLUSIVE",
                status_rationale="CyberGuard does not currently have sufficient correlated telemetry to reconstruct a multi-stage attack path.",
                completeness_score=0.0,
                confidence=0.0,
                confidence_level="LOW",
                stages=[],
                transitions=[],
                gaps=[],
                contradictions=[],
                alternatives=[],
                mitre_techniques=[],
                infrastructure=[],
                timeline_events=[],
                total_evidence_count=0,
                total_findings_count=0,
                total_entities_count=0,
                limitations=[
                    "No contiguous attack sequence could be established from available events and findings.",
                    "Review raw findings, timeline events, or submit additional forensic artifacts to re-evaluate."
                ],
            )

        # 4. Project Stages
        stages_projections: List[AttackStageProjection] = []
        all_stage_entity_ids: Set[str] = set()
        all_stage_finding_ids: Set[str] = set()
        total_evidence = 0

        for s in path_model.stages:
            # Parse IDs
            ent_ids = json.loads(s.entity_ids_json) if s.entity_ids_json else []
            f_ids = json.loads(s.finding_ids_json) if s.finding_ids_json else []
            ev_ids = json.loads(s.evidence_ids_json) if s.evidence_ids_json else []
            ev_items = json.loads(s.supporting_evidence_json) if s.supporting_evidence_json else []
            contra_items = json.loads(s.contradicting_evidence_json) if s.contradicting_evidence_json else []
            limits = json.loads(s.limitations_json) if s.limitations_json else []

            all_stage_entity_ids.update(ent_ids)
            all_stage_finding_ids.update(f_ids)

            ev_count = max(len(ev_ids), len(ev_items))
            total_evidence += ev_count

            entities_detail: List[Dict[str, Any]] = []
            if ent_ids:
                found_ents = db.query(EntityModel).filter(EntityModel.id.in_(ent_ids[:10])).all()
                for fe in found_ents:
                    ent_attrs = {}
                    if fe.attributes_json:
                        try:
                            ent_attrs = json.loads(fe.attributes_json)
                        except Exception:
                            pass
                    entities_detail.append({
                        "id": fe.id,
                        "type": fe.entity_type,
                        "value": fe.name or fe.canonical_key or fe.id,
                        "risk_score": ent_attrs.get("risk_score", 0.0),
                    })

            findings_detail: List[Dict[str, Any]] = []
            if f_ids:
                found_findings = db.query(FindingModel).filter(FindingModel.id.in_(f_ids[:10])).all()
                for ff in found_findings:
                    findings_detail.append({
                        "id": ff.id,
                        "type": ff.finding_type,
                        "title": ff.title,
                        "severity": ff.severity,
                        "analyzer": ff.analyzer,
                        "confidence": ff.confidence,
                    })

            stages_projections.append(
                AttackStageProjection(
                    id=s.id,
                    stage_order=s.stage_order,
                    stage_type=s.stage_type,
                    stage_status=s.stage_status,
                    technique_id=s.technique_id,
                    tactic=s.tactic,
                    title=s.name,
                    description=s.description,
                    start_time=s.start_time,
                    end_time=s.end_time,
                    time_uncertainty="±30s" if s.stage_status == "INFERRED" else None,
                    confidence=s.confidence,
                    confidence_level=s.confidence_level or "HIGH",
                    entity_ids=ent_ids,
                    finding_ids=f_ids,
                    evidence_ids=ev_ids,
                    event_ids=json.loads(s.event_ids_json) if s.event_ids_json else [],
                    evidence_count=ev_count,
                    finding_count=len(f_ids),
                    supporting_evidence=ev_items,
                    contradicting_evidence=contra_items,
                    limitations=limits,
                    entities_detail=entities_detail,
                    findings_detail=findings_detail,
                )
            )

        # 5. Project Transitions (Edges) with Causal vs Temporal Rigor
        transitions_projections: List[AttackTransitionProjection] = []
        stage_title_map = {s.id: s.name for s in path_model.stages}

        for e in path_model.edges:
            rel_type = (e.relationship_type or "PRECEDES").upper()
            edge_st = (e.edge_status or "DERIVED").upper()
            src_name = stage_title_map.get(e.source_stage_id, "Prior Stage")
            tgt_name = stage_title_map.get(e.target_stage_id, "Subsequent Stage")

            gap_sec = e.temporal_gap_seconds
            gap_formatted: Optional[str] = None
            if gap_sec is not None:
                if gap_sec < 60:
                    gap_formatted = f"{int(gap_sec)}s"
                elif gap_sec < 3600:
                    m = int(gap_sec // 60)
                    s = int(gap_sec % 60)
                    gap_formatted = f"{m}m {s}s" if s > 0 else f"{m}m"
                else:
                    h = int(gap_sec // 3600)
                    m = int((gap_sec % 3600) // 60)
                    gap_formatted = f"{h}h {m}m"

            # Strict distinction: CAUSAL vs TEMPORAL
            is_causal = rel_type in ("CAUSES", "TRIGGERS") and edge_st in ("OBSERVED", "DERIVED")
            if is_causal:
                rel_label = "SUPPORTED CAUSAL LINK"
                rel_desc = f"Direct telemetry demonstrates that '{src_name}' initiated or triggered '{tgt_name}'."
            elif rel_type in ("TEMPORAL_LINK", "PRECEDES", "FOLLOWED_BY"):
                rel_label = "TEMPORAL ASSOCIATION"
                time_str = f" ({gap_formatted} interval)" if gap_formatted else ""
                rel_desc = f"'{tgt_name}' appeared after '{src_name}'{time_str}. Causal progression is temporally consistent but unproven."
            elif rel_type == "SHARES_ENTITY_WITH":
                rel_label = "ENTITY CORRELATION"
                rel_desc = f"Stages are linked by shared security entities; direct temporal sequencing is indirect."
            else:
                rel_label = "INFERRED TRANSITION"
                rel_desc = f"Hypothetical progression linking '{src_name}' to '{tgt_name}' based on behavioral patterns."

            shared_ents = json.loads(e.shared_entities_json) if e.shared_entities_json else []
            supp_ev = json.loads(e.supporting_evidence_json) if e.supporting_evidence_json else []
            contra_ev = json.loads(e.contradicting_evidence_json) if e.contradicting_evidence_json else []

            transitions_projections.append(
                AttackTransitionProjection(
                    id=e.id,
                    from_stage_id=e.source_stage_id,
                    to_stage_id=e.target_stage_id,
                    relationship_type=rel_type,
                    edge_status=edge_st,
                    is_causal=is_causal,
                    relationship_label=rel_label,
                    relationship_description=rel_desc,
                    temporal_gap_seconds=gap_sec,
                    temporal_gap_formatted=gap_formatted,
                    confidence=e.confidence,
                    confidence_level=e.confidence_level or "HIGH",
                    shared_entities=shared_ents,
                    supporting_evidence_count=len(supp_ev),
                    supporting_evidence=supp_ev,
                    contradicting_evidence=contra_ev,
                )
            )

        # 6. Project Evidence Gaps
        gaps_projections: List[AttackGapProjection] = []
        raw_gaps = json.loads(path_model.evidence_gaps_json) if path_model.evidence_gaps_json else []
        for i, g_str in enumerate(raw_gaps):
            gap_code = str(g_str).upper()
            if "NO_EVIDENCE_OF_URL_CLICK" in gap_code or "NO_URL_CLICK" in gap_code:
                gaps_projections.append(
                    AttackGapProjection(
                        id=f"gap-{i+1}",
                        category="MISSING_USER_INTERACTION",
                        title="Missing URL Click Telemetry",
                        description="Inbound lure contained a credential harvesting URL, but no proxy, DNS, or browser click telemetry was observed.",
                        impact="Progression from lure delivery to credential portal access remains unproven.",
                    )
                )
            elif "NO_PROCESS_TELEMETRY" in gap_code or "PROCESS" in gap_code:
                gaps_projections.append(
                    AttackGapProjection(
                        id=f"gap-{i+1}",
                        category="MISSING_ENDPOINT_TELEMETRY",
                        title="Missing Host Process Telemetry",
                        description="No endpoint detection and response (EDR) telemetry is available for the recipient device.",
                        impact="Host execution and downstream persistence cannot be verified directly.",
                    )
                )
            elif "NO_PROOF_OF_CREDENTIAL_THEFT" in gap_code or "CREDENTIAL" in gap_code:
                gaps_projections.append(
                    AttackGapProjection(
                        id=f"gap-{i+1}",
                        category="UNVERIFIED_COMPROMISE",
                        title="Unproven Credential Harvesting",
                        description="Communication with impersonation portal observed, but credential capture has not been confirmed in authentication logs.",
                        impact="Account takeover risk is inferred rather than directly observed.",
                    )
                )
            elif "NO_DIRECT_EXFILTRATION" in gap_code or "EXFILTRATION" in gap_code:
                gaps_projections.append(
                    AttackGapProjection(
                        id=f"gap-{i+1}",
                        category="MISSING_NETWORK_TELEMETRY",
                        title="Unconfirmed Data Exfiltration",
                        description="Suspicious external communication detected, but data exfiltration volume is not confirmed.",
                        impact="Impact assessment remains conservative.",
                    )
                )
            else:
                gaps_projections.append(
                    AttackGapProjection(
                        id=f"gap-{i+1}",
                        category="TELEMETRY_GAP",
                        title=g_str.replace("_", " ").title(),
                        description=f"Evidence gap identified during reconstruction: {g_str}.",
                        impact="Reduces overall confidence in sequential transitions.",
                    )
                )

        # 7. Project Contradictions
        contradictions_projections: List[AttackContradictionProjection] = []
        raw_contradictions = json.loads(path_model.contradicting_evidence_json) if path_model.contradicting_evidence_json else []
        for i, c_item in enumerate(raw_contradictions):
            if isinstance(c_item, dict):
                c_title = c_item.get("title", f"Contradiction #{i+1}")
                c_desc = c_item.get("description", c_item.get("explanation", "Conflicting telemetry observed."))
                c_ev = c_item.get("evidence", [c_item])
                c_impact = c_item.get("impact", "Reduces transition certainty.")
            else:
                c_title = f"Contradiction #{i+1}"
                c_desc = str(c_item)
                c_ev = []
                c_impact = "Reduces confidence in primary attack progression."

            contradictions_projections.append(
                AttackContradictionProjection(
                    id=f"contra-{i+1}",
                    title=c_title,
                    description=c_desc,
                    conflicting_evidence=c_ev if isinstance(c_ev, list) else [c_ev],
                    assessment_impact=c_impact,
                )
            )

        # 8. Project Alternative Hypotheses
        alternatives_projections: List[AttackAlternativeProjection] = []
        for h in path_model.hypotheses:
            h_st_ids = json.loads(h.stage_ids_json) if h.stage_ids_json else []
            h_supp = json.loads(h.supporting_evidence_json) if h.supporting_evidence_json else []
            h_contra = json.loads(h.contradicting_evidence_json) if h.contradicting_evidence_json else []
            h_miss = json.loads(h.missing_evidence_json) if h.missing_evidence_json else []

            alternatives_projections.append(
                AttackAlternativeProjection(
                    id=h.id,
                    title=h.title,
                    description=h.description,
                    status=h.status,
                    is_primary=h.is_primary,
                    stage_ids=h_st_ids,
                    confidence=h.confidence,
                    confidence_level=h.confidence_level or "MODERATE",
                    missing_evidence=h_miss,
                    supporting_evidence=h_supp,
                    contradicting_evidence=h_contra,
                )
            )

        # 9. Project MITRE ATT&CK Context
        mitre_techniques: List[Dict[str, Any]] = []
        mitre_mappings = (
            db.query(AttackTechniqueMappingModel)
            .filter(
                or_(
                    AttackTechniqueMappingModel.attack_path_id == path_model.id,
                    AttackTechniqueMappingModel.incident_id == (incident.id if incident else ""),
                )
            )
            .all()
        )
        seen_tech_ids: Set[str] = set()
        for mm in mitre_mappings:
            if mm.technique_id in seen_tech_ids:
                continue
            seen_tech_ids.add(mm.technique_id)
            mitre_techniques.append({
                "technique_id": mm.technique_id,
                "technique_name": mm.technique_name,
                "tactics": json.loads(mm.tactic_names_json) if mm.tactic_names_json else [],
                "status": mm.status,
                "confidence": mm.confidence,
                "confidence_level": mm.confidence_level,
                "explanation": mm.explanation,
                "evidence_count": len(json.loads(mm.evidence_ids_json)) if mm.evidence_ids_json else 0,
            })

        # Add any stage techniques not already in the mappings
        for s in path_model.stages:
            if s.technique_id and s.technique_id not in seen_tech_ids:
                seen_tech_ids.add(s.technique_id)
                mitre_techniques.append({
                    "technique_id": s.technique_id,
                    "technique_name": s.name,
                    "tactics": [s.tactic] if s.tactic else [],
                    "status": "SUPPORTED" if s.stage_status in ("OBSERVED", "DERIVED") else "PLAUSIBLE",
                    "confidence": s.confidence,
                    "confidence_level": s.confidence_level,
                    "explanation": s.description or "",
                    "evidence_count": len(json.loads(s.evidence_ids_json)) if s.evidence_ids_json else 1,
                })

        # 10. Project Infrastructure Context (Strictly No Human Attribution)
        infrastructure_projections: List[Dict[str, Any]] = []
        if incident:
            infra_records = (
                db.query(InfrastructureAttributionModel)
                .filter(InfrastructureAttributionModel.incident_id == incident.id)
                .all()
            )
            for inf in infra_records:
                infrastructure_projections.append({
                    "id": inf.id,
                    "origin_value": inf.origin_value,
                    "origin_type": inf.origin_type,  # e.g. IP, DOMAIN, ASN
                    "hypothesis_title": inf.hypothesis_title,
                    "hypothesis_type": inf.hypothesis_type,  # DEDICATED_THREAT_INFRASTRUCTURE, BULLETPROOF_HOSTING, COMPROMISED_LEGITIMATE
                    "status": inf.status,  # PROBABLE, PLAUSIBLE, INSUFFICIENT_EVIDENCE
                    "confidence_level": inf.confidence_level,
                    "confidence_score": inf.confidence_score,
                    "evidence_count": inf.evidence_count,
                    "limitations": json.loads(inf.limitations_json) if inf.limitations_json else [
                        "Identifies technical infrastructure only; does not establish human attacker identity."
                    ],
                })

        # 11. Synchronized Timeline Events
        raw_timeline = InvestigationWorkspaceService.get_timeline_events(db, identifier)
        timeline_events_projected: List[Dict[str, Any]] = []
        for te in raw_timeline:
            # Match timeline event to stage based on stage time bounds
            matched_stage_id: Optional[str] = None
            for sp in stages_projections:
                if sp.start_time and sp.end_time:
                    if sp.start_time <= te.timestamp <= sp.end_time:
                        matched_stage_id = sp.id
                        break
                elif sp.start_time and abs((te.timestamp - sp.start_time).total_seconds()) < 60:
                    matched_stage_id = sp.id
                    break

            timeline_events_projected.append({
                "id": te.id,
                "timestamp": te.timestamp.isoformat(),
                "event_type": te.event_type,
                "title": te.title,
                "description": te.description,
                "severity": te.severity,
                "source": te.source,
                "confidence": te.confidence,
                "matched_stage_id": matched_stage_id,
            })

        # 12. Determine Path Status Truthfully
        # Metadata
        meta_dict: Dict[str, Any] = {}
        if path_model.metadata_json:
            try:
                meta_dict = json.loads(path_model.metadata_json)
            except Exception:
                pass

        completeness = meta_dict.get("completeness_score", 0.0)
        if not completeness and stages_projections:
            obs_cnt = sum(1 for s in stages_projections if s.stage_status in ("OBSERVED", "DERIVED"))
            completeness = round(obs_cnt / len(stages_projections), 2)

        conf = path_model.confidence
        if completeness >= 0.85 and conf >= 0.80 and not contradictions_projections:
            path_status = "ESTABLISHED"
            status_rationale = "Reconstruction is supported by contiguous direct observations across all major stages with no significant contradictions."
        elif gaps_projections or completeness < 0.60:
            path_status = "PARTIAL"
            status_rationale = "Telemetry supports initial and intermediate stages, but intermediate execution transitions remain unconfirmed."
        elif any(s.stage_status == "INFERRED" for s in stages_projections):
            path_status = "SUPPORTED_HYPOTHESIS"
            status_rationale = "Plausible attack progression supported by circumstantial evidence and behavioral heuristics."
        elif conf < 0.40:
            path_status = "LOW_CONFIDENCE"
            status_rationale = "Sparse or conflicting telemetry yields low reconstruction certainty."
        else:
            path_status = "PARTIAL"
            status_rationale = "Partial progression observed."

        # Parse explainability json
        conf_breakdown = json.loads(path_model.confidence_breakdown_json) if path_model.confidence_breakdown_json else {}
        conf_bottleneck = json.loads(path_model.confidence_bottleneck_json) if path_model.confidence_bottleneck_json else None
        explanation = json.loads(path_model.explanation_json) if path_model.explanation_json else {}

        # Duration
        dur_sec: Optional[float] = None
        if path_model.start_time and path_model.end_time:
            dur_sec = max(0.0, (path_model.end_time - path_model.start_time).total_seconds())

        return AttackPathDetailResponse(
            investigation_id=identifier,
            incident_number=incident.incident_number if incident else None,
            analysis_run_id=active_run_id,
            available_runs=available_runs,
            has_path=True,
            path_id=path_model.id,
            name=path_model.name,
            classification=path_model.classification,
            status=path_status,
            status_rationale=status_rationale,
            completeness_score=completeness,
            confidence=conf,
            confidence_level=path_model.confidence_level or calculate_confidence_level(conf).value,
            confidence_components=conf_breakdown,
            confidence_bottleneck=conf_bottleneck,
            explanation=explanation,
            start_time=path_model.start_time,
            end_time=path_model.end_time,
            duration_seconds=dur_sec,
            version=path_model.version,
            engine_version=path_model.engine_version,
            rule_version=path_model.rule_version,
            generated_at=path_model.created_at,
            stages=stages_projections,
            transitions=transitions_projections,
            gaps=gaps_projections,
            contradictions=contradictions_projections,
            alternatives=alternatives_projections,
            mitre_techniques=mitre_techniques,
            infrastructure=infrastructure_projections,
            timeline_events=timeline_events_projected,
            total_evidence_count=total_evidence,
            total_findings_count=len(all_stage_finding_ids),
            total_entities_count=len(all_stage_entity_ids),
            limitations=[
                "Reconstruction is constrained to observed forensic artifacts and telemetry.",
                "Transitions marked as TEMPORAL ASSOCIATION indicate correlation without proven causality.",
                "Infrastructure entities indicate technical assets and must not be interpreted as human identities.",
            ],
        )
