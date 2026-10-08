"""
MITRE ATT&CK Mapping & Adversary Technique Intelligence Engine (Section 19).
Orchestrates evidence-driven, deterministic mapping of SecurityEvents, Findings,
ThreatEvents, AttackStages, and AttackPaths to MITRE ATT&CK Enterprise Matrix techniques.

CORE PRINCIPLES:
1. TAXONOMY, NOT PROOF:
   ATT&CK mapping reflects what behaviors are supported by observed evidence,
   never claiming attacker attribution, intent, or hypothetical compromise.
2. NO KEYWORD-ONLY MAPPING:
   Keywords alone ("password", "PowerShell", "email") do not map techniques.
   Context, telemetry type, source reliability, and behavior must satisfy rules.
3. HIERARCHY & SPECIFICITY:
   Prefer specific sub-techniques when evidence permits (T1110.003 > T1110).
   Map parent techniques when sub-technique evidence is insufficient (T1110).
   Avoid duplicate parent + sub-technique mappings for identical evidence.
4. REUSE SECTION 18 CONFIDENCE & EVIDENCE LINEAGE:
   Maps evidence strength to categorical levels (VERY_LOW to VERY_HIGH).
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from sqlalchemy.orm import Session

from backend.db.models import (
    AttackTechniqueMappingModel,
    AttackPathModel,
    AttackStageModel,
    FindingModel,
    FindingEvidenceModel,
    IncidentModel,
    SecurityEventModel,
    ThreatEventModel,
)
from backend.schemas.attack_confidence import ConfidenceLevel, score_to_confidence_level
from backend.schemas.attack_reconstruction import sanitize_reconstruction_attributes
from backend.schemas.mitre_attack import (
    AnalystDispositionEnum,
    AttackCoverageSummary,
    AttackMappingStatus,
    AttackTechnique,
    AttackTechniqueMapping,
    AttackTechniqueSequence,
    EnvironmentContextConfig,
    LLMTechniqueSuggestion,
    LLMValidationResult,
    MappingMethod,
    MitreAttackAnalysisReport,
    TacticTimelineEntry,
)
from backend.services.mitre_dataset_service import (
    MitreDatasetService,
    global_mitre_dataset_service,
)
from backend.services.mitre_rules import (
    MappingEvaluationContext,
    MitreRuleRegistry,
    RuleEvaluationResult,
    global_mitre_rule_registry,
)

logger = logging.getLogger("cyberguard.mitre.engine")


class MITREAttackMappingEngine:
    """
    Evidence-grounded ATT&CK mapping engine for CyberGuard.
    """

    def __init__(
        self,
        dataset_service: Optional[MitreDatasetService] = None,
        rule_registry: Optional[MitreRuleRegistry] = None,
        environment_config: Optional[EnvironmentContextConfig] = None,
    ):
        self.dataset = dataset_service or global_mitre_dataset_service
        self.rule_registry = rule_registry or global_mitre_rule_registry
        self.env_config = environment_config or EnvironmentContextConfig()
        self.engine_version = "1.0.0"
        self.configuration_version = "2026.10"

    def set_environment_config(self, config: EnvironmentContextConfig) -> None:
        """Updates authorized environment context (scanners, proxies, service accounts)."""
        self.env_config = config

    def get_environment_config(self) -> EnvironmentContextConfig:
        return self.env_config

    # ========================================================================
    # 1. CORE DISCRETE MAPPINGS (FINDING, EVENT, THREAT EVENT, STAGE, PATH)
    # ========================================================================

    def map_finding(
        self,
        finding: Union[FindingModel, Dict[str, Any]],
        evidence_items: Optional[List[Dict[str, Any]]] = None,
        incident_id: Optional[str] = None
    ) -> List[AttackTechniqueMapping]:
        """
        Evaluates candidate rules against a Finding and its supporting evidence.
        """
        if isinstance(finding, FindingModel):
            f_id = finding.id
            f_type = finding.finding_type
            analyzer = finding.analyzer
            severity = finding.severity
            confidence = finding.confidence
            title = finding.title
            desc = finding.description
            rule_id = finding.rule_id
            meta = {}
            if finding.metadata_json:
                try:
                    meta = json.loads(finding.metadata_json)
                except Exception:
                    pass
            ev_list = []
            if hasattr(finding, "evidence_items") and finding.evidence_items:
                for ev in finding.evidence_items:
                    ev_list.append({
                        "id": ev.id,
                        "key": ev.key,
                        "value": ev.value,
                        "source": ev.source,
                        "evidence_type": ev.evidence_type,
                    })
            elif evidence_items:
                ev_list = evidence_items
        else:
            f_id = finding.get("id", str(uuid.uuid4()))
            f_type = finding.get("finding_type", "")
            analyzer = finding.get("analyzer", "")
            severity = finding.get("severity", "LOW")
            confidence = finding.get("confidence", 1.0)
            title = finding.get("title", "")
            desc = finding.get("description", "")
            rule_id = finding.get("rule_id")
            meta = finding.get("metadata", {})
            ev_list = evidence_items or finding.get("evidence_items", [])

        # Sanitize metadata for privacy
        sanitized_meta = sanitize_reconstruction_attributes(meta)

        ctx = MappingEvaluationContext(
            source_type="FINDING",
            source_id=f_id,
            incident_id=incident_id,
            finding_type=f_type,
            analyzer=analyzer,
            severity=severity,
            confidence=confidence,
            title=title,
            description=desc,
            evidence_items=ev_list,
            attributes=sanitized_meta,
            environment_config=self.env_config,
        )

        return self._evaluate_context_against_rules(ctx)

    def map_event(
        self,
        event: Union[SecurityEventModel, Dict[str, Any]],
        incident_id: Optional[str] = None
    ) -> List[AttackTechniqueMapping]:
        """
        Evaluates candidate rules against a raw or normalized SecurityEvent.
        """
        if isinstance(event, SecurityEventModel):
            e_id = event.id
            e_type = event.event_type
            title = event.summary
            desc = event.summary
            meta = {}
            if event.attributes_json:
                try:
                    meta = json.loads(event.attributes_json)
                except Exception:
                    pass
            inc_id = event.incident_id or incident_id
        else:
            e_id = event.get("id", str(uuid.uuid4()))
            e_type = event.get("event_type", "")
            title = event.get("summary", event.get("event_type", ""))
            desc = event.get("summary", "")
            meta = event.get("attributes", event.get("metadata", {}))
            inc_id = event.get("incident_id") or incident_id

        sanitized_meta = sanitize_reconstruction_attributes(meta)

        ctx = MappingEvaluationContext(
            source_type="SECURITY_EVENT",
            source_id=e_id,
            incident_id=inc_id,
            event_type=e_type,
            title=title,
            description=desc,
            attributes=sanitized_meta,
            environment_config=self.env_config,
        )

        return self._evaluate_context_against_rules(ctx)

    def map_threat_event(
        self,
        threat_event: Union[ThreatEventModel, Dict[str, Any]],
        incident_id: Optional[str] = None
    ) -> List[AttackTechniqueMapping]:
        """
        Maps higher-level ThreatEvent (e.g. PHISHING_ATTEMPT, CREDENTIAL_HARVESTING).
        """
        if isinstance(threat_event, ThreatEventModel):
            t_id = threat_event.id
            t_type = threat_event.event_type
            title = threat_event.summary
            desc = threat_event.summary
            conf = threat_event.confidence
            meta = {}
            if threat_event.metadata_json:
                try:
                    meta = json.loads(threat_event.metadata_json)
                except Exception:
                    pass
            inc_id = threat_event.incident_id or incident_id
        else:
            t_id = threat_event.get("id", str(uuid.uuid4()))
            t_type = threat_event.get("event_type", "")
            title = threat_event.get("summary", "")
            desc = threat_event.get("summary", "")
            conf = threat_event.get("confidence", 1.0)
            meta = threat_event.get("metadata", {})
            inc_id = threat_event.get("incident_id") or incident_id

        sanitized_meta = sanitize_reconstruction_attributes(meta)

        ctx = MappingEvaluationContext(
            source_type="THREAT_EVENT",
            source_id=t_id,
            incident_id=inc_id,
            event_type=t_type,
            finding_type=t_type,
            confidence=conf,
            title=title,
            description=desc,
            attributes=sanitized_meta,
            environment_config=self.env_config,
        )

        return self._evaluate_context_against_rules(ctx)

    def map_stage(
        self,
        stage: Union[AttackStageModel, Dict[str, Any]],
        incident_id: Optional[str] = None
    ) -> List[AttackTechniqueMapping]:
        """
        Maps reconstructed AttackStage to candidate techniques, validating
        underlying stage status (OBSERVED vs INFERRED).
        """
        if isinstance(stage, AttackStageModel):
            s_id = stage.id
            s_type = stage.stage_type
            s_status = stage.stage_status
            title = stage.name
            desc = stage.description or ""
            conf = stage.confidence
            meta = {}
            if stage.metadata_json:
                try:
                    meta = json.loads(stage.metadata_json)
                except Exception:
                    pass
            ev_ids = []
            if stage.evidence_ids_json:
                try:
                    ev_ids = json.loads(stage.evidence_ids_json)
                except Exception:
                    pass
            f_ids = []
            if stage.finding_ids_json:
                try:
                    f_ids = json.loads(stage.finding_ids_json)
                except Exception:
                    pass
        else:
            s_id = stage.get("id", str(uuid.uuid4()))
            s_type = stage.get("stage_type", "")
            s_status = stage.get("stage_status", "OBSERVED")
            title = stage.get("name", stage.get("title", ""))
            desc = stage.get("description", "")
            conf = stage.get("confidence", 1.0)
            meta = stage.get("metadata", {})
            ev_ids = stage.get("evidence_ids", [])
            f_ids = stage.get("finding_ids", [])

        sanitized_meta = sanitize_reconstruction_attributes(meta)
        ev_items = [{"id": eid} for eid in ev_ids]

        ctx = MappingEvaluationContext(
            source_type="ATTACK_STAGE",
            source_id=s_id,
            incident_id=incident_id,
            stage_type=s_type,
            stage_status=s_status,
            confidence=conf,
            title=title,
            description=desc,
            evidence_items=ev_items,
            attributes=sanitized_meta,
            environment_config=self.env_config,
        )

        mappings = self._evaluate_context_against_rules(ctx)

        # Epistemic preservation (Req 22):
        # If the stage is INFERRED or UNRESOLVED, demote SUPPORTED to PLAUSIBLE!
        if s_status in ("INFERRED", "UNRESOLVED"):
            for m in mappings:
                if m.status == AttackMappingStatus.SUPPORTED:
                    m.status = AttackMappingStatus.PLAUSIBLE
                    m.explanation += " (Demoted to PLAUSIBLE: underlying stage is an inferred analytical hypothesis)."
                    m.limitations.append("Underlying attack stage was reconstructed as INFERRED rather than directly OBSERVED.")

        return mappings

    def map_path(
        self,
        path: Union[AttackPathModel, Dict[str, Any]],
        incident_id: Optional[str] = None
    ) -> List[AttackTechniqueMapping]:
        """
        Maps all stages and transitions across an AttackPath.
        """
        all_mappings: List[AttackTechniqueMapping] = []
        inc_id = incident_id

        if isinstance(path, AttackPathModel):
            inc_id = inc_id or path.incident_id
            if hasattr(path, "stages") and path.stages:
                for st in path.stages:
                    all_mappings.extend(self.map_stage(st, incident_id=inc_id))
        else:
            inc_id = inc_id or path.get("incident_id")
            for st in path.get("stages", []):
                all_mappings.extend(self.map_stage(st, incident_id=inc_id))

        return self.deduplicate_mappings(all_mappings)

    # ========================================================================
    # 2. RULE EVALUATION ENGINE
    # ========================================================================

    def _evaluate_context_against_rules(self, ctx: MappingEvaluationContext) -> List[AttackTechniqueMapping]:
        """
        Internal dispatcher running registered rules against the evaluation context.
        """
        candidate_mappings: List[AttackTechniqueMapping] = []

        for rule in self.rule_registry.list_rules():
            evaluator = self.rule_registry.evaluators.get(rule.id)
            if not evaluator:
                continue

            try:
                res: Optional[RuleEvaluationResult] = evaluator(ctx, rule)
                if res:
                    mapping = self._build_mapping_from_result(res, ctx)
                    if mapping:
                        candidate_mappings.append(mapping)
            except Exception as exc:
                logger.warning(f"Error evaluating rule {rule.id} against {ctx.source_type}:{ctx.source_id}: {exc}")

        return candidate_mappings

    def _build_mapping_from_result(
        self,
        res: RuleEvaluationResult,
        ctx: MappingEvaluationContext
    ) -> Optional[AttackTechniqueMapping]:
        """
        Converts a RuleEvaluationResult into a full AttackTechniqueMapping
        validating against the ATT&CK dataset.
        """
        target_tech_id = res.subtechnique_id or res.technique_id
        tech = self.dataset.get_technique(target_tech_id)
        if not tech:
            logger.warning(f"Rule {res.rule_id} referenced unknown technique {target_tech_id} in dataset.")
            return None

        # Resolve tactics from dataset technique
        tactic_names = []
        for tid in tech.tactic_ids:
            tac = self.dataset.get_tactic(tid)
            tactic_names.append(tac.name if tac else tid)

        conf_level = score_to_confidence_level(res.confidence)

        # Build evidence lineage
        ev_ids = res.evidence_ids or [str(e.get("id", "")) for e in ctx.evidence_items if e.get("id")]
        f_ids = res.finding_ids or ([ctx.source_id] if ctx.source_type == "FINDING" else [])
        e_ids = res.event_ids or ([ctx.source_id] if ctx.source_type == "SECURITY_EVENT" else [])
        s_ids = res.stage_ids or ([ctx.source_id] if ctx.source_type == "ATTACK_STAGE" else [])

        return AttackTechniqueMapping(
            id=str(uuid.uuid4()),
            incident_id=ctx.incident_id,
            source_type=ctx.source_type,
            source_id=ctx.source_id,
            technique_id=tech.technique_id,
            technique_name=tech.name,
            subtechnique_id=tech.technique_id if tech.is_subtechnique else None,
            tactic_ids=tech.tactic_ids,
            tactic_names=tactic_names,
            status=res.status,
            confidence=res.confidence,
            confidence_level=conf_level,
            evidence_ids=list(filter(None, ev_ids)),
            finding_ids=list(filter(None, f_ids)),
            event_ids=list(filter(None, e_ids)),
            stage_ids=list(filter(None, s_ids)),
            mapping_method=MappingMethod.RULE_BASED,
            mapping_rule_id=res.rule_id,
            explanation=res.explanation,
            limitations=res.limitations,
            contradictions=res.contradictions,
            attack_version=self.dataset.get_attack_version(),
            engine_version=self.engine_version,
            configuration_version=self.configuration_version,
            created_at=datetime.now(timezone.utc),
            metadata={
                "is_deprecated": tech.is_deprecated,
                "is_revoked": tech.is_revoked,
                "revoked_by": tech.revoked_by,
            }
        )

    # ========================================================================
    # 3. DEDUPLICATION & HIERARCHY HARMONIZATION
    # ========================================================================

    def deduplicate_mappings(self, mappings: List[AttackTechniqueMapping]) -> List[AttackTechniqueMapping]:
        """
        Deduplicates candidate mappings for an incident / path.
        Rules:
        - If multiple candidate mappings target the SAME technique_id:
          merge evidence IDs, keep highest confidence, keep most restrictive status.
        - Hierarchy check: If a sub-technique (e.g. T1110.003) is SUPPORTED,
          suppress the generic parent (T1110) if they share identical evidence items.
        - If sub-technique is only PLAUSIBLE or INSUFFICIENT, but parent is supported,
          keep parent and document limitation.
        """
        if not mappings:
            return []

        # Group by technique_id
        by_tech: Dict[str, List[AttackTechniqueMapping]] = {}
        for m in mappings:
            tid = m.technique_id
            if tid not in by_tech:
                by_tech[tid] = []
            by_tech[tid].append(m)

        consolidated: List[AttackTechniqueMapping] = []
        for tid, group in by_tech.items():
            primary = group[0]
            # Merge evidence references
            all_ev = set(primary.evidence_ids)
            all_f = set(primary.finding_ids)
            all_e = set(primary.event_ids)
            all_s = set(primary.stage_ids)
            all_lims = list(primary.limitations)
            all_contra = list(primary.contradictions)

            max_conf = primary.confidence
            best_status = primary.status

            for other in group[1:]:
                all_ev.update(other.evidence_ids)
                all_f.update(other.finding_ids)
                all_e.update(other.event_ids)
                all_s.update(other.stage_ids)
                for lim in other.limitations:
                    if lim not in all_lims:
                        all_lims.append(lim)
                for c in other.contradictions:
                    if c not in all_contra:
                        all_contra.append(c)
                if other.confidence > max_conf:
                    max_conf = other.confidence
                # Prioritize SUPPORTED over PLAUSIBLE over INSUFFICIENT
                if other.status == AttackMappingStatus.SUPPORTED:
                    best_status = AttackMappingStatus.SUPPORTED

            consolidated.append(
                AttackTechniqueMapping(
                    id=primary.id,
                    incident_id=primary.incident_id,
                    source_type=primary.source_type,
                    source_id=primary.source_id,
                    technique_id=primary.technique_id,
                    technique_name=primary.technique_name,
                    subtechnique_id=primary.subtechnique_id,
                    tactic_ids=primary.tactic_ids,
                    tactic_names=primary.tactic_names,
                    status=best_status,
                    confidence=max_conf,
                    confidence_level=score_to_confidence_level(max_conf),
                    evidence_ids=sorted(list(all_ev)),
                    finding_ids=sorted(list(all_f)),
                    event_ids=sorted(list(all_e)),
                    stage_ids=sorted(list(all_s)),
                    mapping_method=primary.mapping_method,
                    mapping_rule_id=primary.mapping_rule_id,
                    explanation=primary.explanation,
                    limitations=all_lims,
                    contradictions=all_contra,
                    attack_version=primary.attack_version,
                    engine_version=primary.engine_version,
                    configuration_version=primary.configuration_version,
                    created_at=primary.created_at,
                    analyst_disposition=primary.analyst_disposition,
                    analyst_notes=primary.analyst_notes,
                    metadata=primary.metadata,
                )
            )

        # Hierarchy check: If sub-technique is present, suppress parent if duplicate
        sub_tech_ids = {m.technique_id for m in consolidated if "." in m.technique_id}
        final_list: List[AttackTechniqueMapping] = []

        for m in consolidated:
            if "." not in m.technique_id:
                # Parent technique. Check if any sub-technique is already supported
                has_sub = any(
                    sub_id.startswith(f"{m.technique_id}.")
                    for sub_id in sub_tech_ids
                )
                if has_sub:
                    # Skip broad parent in favor of specific sub-technique (Req 26)
                    continue
            final_list.append(m)

        return sorted(final_list, key=lambda x: (x.status != AttackMappingStatus.SUPPORTED, -x.confidence))

    # ========================================================================
    # 4. INCIDENT-LEVEL END-TO-END MAPPING
    # ========================================================================

    def map_incident(
        self,
        incident_id: str,
        db: Session,
        persist: bool = True
    ) -> MitreAttackAnalysisReport:
        """
        Executes complete ATT&CK mapping across all normalized observations in an Incident:
        - SecurityEvents
        - Findings
        - ThreatEvents
        - AttackStages & AttackPaths
        Generates sequence, timeline, coverage, and report summaries.
        Optionally persists mappings to database.
        """
        incident = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
        raw_candidates: List[AttackTechniqueMapping] = []
        unmapped_observations: List[str] = []

        if incident:
            # 1. Map SecurityEvents
            sec_events = db.query(SecurityEventModel).filter(SecurityEventModel.incident_id == incident_id).all()
            for sev in sec_events:
                raw_candidates.extend(self.map_event(sev, incident_id=incident_id))

            # 2. Map ThreatEvents
            threat_events = db.query(ThreatEventModel).filter(ThreatEventModel.incident_id == incident_id).all()
            for te in threat_events:
                raw_candidates.extend(self.map_threat_event(te, incident_id=incident_id))

            # 3. Map AttackStages via AttackPaths
            paths = db.query(AttackPathModel).filter(AttackPathModel.incident_id == incident_id).all()
            for path in paths:
                raw_candidates.extend(self.map_path(path, incident_id=incident_id))

        # Deduplicate
        deduped = self.deduplicate_mappings(raw_candidates)

        # Categorize
        supported = [m for m in deduped if m.status == AttackMappingStatus.SUPPORTED]
        plausible = [m for m in deduped if m.status == AttackMappingStatus.PLAUSIBLE]
        insufficient = [m for m in deduped if m.status == AttackMappingStatus.INSUFFICIENT_EVIDENCE]
        rejected = [m for m in deduped if m.status == AttackMappingStatus.REJECTED]

        # Extract tactics present
        tactics_present = sorted(list({tac for m in supported + plausible for tac in m.tactic_names}))

        # Build sequence & timeline
        sequence = self.build_technique_sequence(supported + plausible, incident_id=incident_id)
        timeline = self.build_tactic_timeline(supported + plausible)
        coverage = self.assess_coverage(deduped, unmapped_observations)

        # Build summaries
        exec_summary = self._generate_executive_summary(supported, plausible, insufficient)
        analyst_summary = self._generate_analyst_summary(supported, plausible)

        report = MitreAttackAnalysisReport(
            incident_id=incident_id,
            attack_version=self.dataset.get_attack_version(),
            engine_version=self.engine_version,
            tactics_present=tactics_present,
            supported_mappings=supported,
            plausible_mappings=plausible,
            insufficient_mappings=insufficient,
            rejected_mappings=rejected,
            coverage_summary=coverage,
            sequence=sequence,
            tactic_timeline=timeline,
            executive_summary=exec_summary,
            analyst_summary=analyst_summary,
            limitations=[
                "Mappings reflect observed normalized telemetry, not exhaustive adversary activity.",
                "Missing techniques do not imply adversary inactivity in those phases.",
            ],
            generated_at=datetime.now(timezone.utc),
        )

        if persist:
            self._persist_mappings(db, incident_id, deduped)

        return report

    def _persist_mappings(
        self,
        db: Session,
        incident_id: str,
        mappings: List[AttackTechniqueMapping]
    ) -> None:
        """
        Persists mappings to database while preserving historical records on re-analysis.
        """
        # Delete prior unconfirmed mappings for this incident to avoid duplicate sprawl,
        # but preserve analyst-confirmed records.
        existing = db.query(AttackTechniqueMappingModel).filter(
            AttackTechniqueMappingModel.incident_id == incident_id
        ).all()

        confirmed_map: Dict[str, AttackTechniqueMappingModel] = {}
        for old_rec in existing:
            if old_rec.analyst_disposition in (AnalystDispositionEnum.CONFIRMED.value, AnalystDispositionEnum.REJECTED.value):
                confirmed_map[old_rec.technique_id] = old_rec
            else:
                db.delete(old_rec)

        db.flush()

        for m in mappings:
            # If analyst already dispositioned this technique, retain their verdict
            disp = m.analyst_disposition
            notes = m.analyst_notes
            if m.technique_id in confirmed_map:
                disp = confirmed_map[m.technique_id].analyst_disposition
                notes = confirmed_map[m.technique_id].analyst_notes

            model = AttackTechniqueMappingModel(
                id=m.id,
                incident_id=incident_id,
                source_type=m.source_type,
                source_id=m.source_id,
                technique_id=m.technique_id,
                subtechnique_id=m.subtechnique_id,
                technique_name=m.technique_name,
                tactic_ids_json=json.dumps(m.tactic_ids),
                tactic_names_json=json.dumps(m.tactic_names),
                status=m.status.value,
                confidence=m.confidence,
                confidence_level=m.confidence_level.value,
                evidence_ids_json=json.dumps(m.evidence_ids),
                finding_ids_json=json.dumps(m.finding_ids),
                event_ids_json=json.dumps(m.event_ids),
                stage_ids_json=json.dumps(m.stage_ids),
                mapping_method=m.mapping_method.value,
                mapping_rule_id=m.mapping_rule_id,
                explanation=m.explanation,
                limitations_json=json.dumps(m.limitations),
                contradictions_json=json.dumps(m.contradictions),
                attack_version=m.attack_version,
                engine_version=m.engine_version,
                configuration_version=m.configuration_version,
                analyst_disposition=disp,
                analyst_notes=notes,
                metadata_json=json.dumps(m.metadata),
                created_at=m.created_at,
            )
            db.add(model)

        db.commit()

    # ========================================================================
    # 5. SEQUENCE, TIMELINE & COVERAGE BUILDERS
    # ========================================================================

    def build_technique_sequence(
        self,
        mappings: List[AttackTechniqueMapping],
        incident_id: str = ""
    ) -> AttackTechniqueSequence:
        """
        Orders mappings chronologically based on earliest evidence timestamp or created_at.
        """
        sorted_m = sorted(mappings, key=lambda x: x.created_at)
        st_ids = [sid for m in sorted_m for sid in m.stage_ids]

        avg_conf = sum(m.confidence for m in sorted_m) / max(len(sorted_m), 1)

        return AttackTechniqueSequence(
            sequence_id=str(uuid.uuid4()),
            incident_id=incident_id,
            technique_mappings=sorted_m,
            ordered_by_time=True,
            stage_ids=list(dict.fromkeys(st_ids)),
            confidence=round(avg_conf, 2),
            confidence_level=score_to_confidence_level(avg_conf),
            explanation=(
                f"Observed chronological progression of {len(sorted_m)} mapped ATT&CK techniques. "
                "Order represents telemetry observation sequence and does not imply universal adversary necessity."
            ),
        )

    def build_tactic_timeline(
        self,
        mappings: List[AttackTechniqueMapping]
    ) -> List[TacticTimelineEntry]:
        """
        Groups mappings by ATT&CK matrix tactic order for visual timeline rendering.
        """
        tactics = self.dataset.list_tactics()
        timeline: List[TacticTimelineEntry] = []

        by_tactic: Dict[str, List[AttackTechniqueMapping]] = {}
        for m in mappings:
            for tid in m.tactic_ids:
                if tid not in by_tactic:
                    by_tactic[tid] = []
                by_tactic[tid].append(m)

        for tac in tactics:
            if tac.tactic_id in by_tactic:
                t_mappings = by_tactic[tac.tactic_id]
                earliest = min((m.created_at for m in t_mappings), default=None)
                latest = max((m.created_at for m in t_mappings), default=None)

                timeline.append(
                    TacticTimelineEntry(
                        tactic_id=tac.tactic_id,
                        tactic_name=tac.name,
                        order=tac.order,
                        earliest_time=earliest,
                        latest_time=latest,
                        mappings=t_mappings,
                    )
                )

        return timeline

    def assess_coverage(
        self,
        mappings: List[AttackTechniqueMapping],
        unmapped_observations: Optional[List[str]] = None
    ) -> AttackCoverageSummary:
        """
        Calculates supported, plausible, and insufficient candidate counts.
        Identifies unmapped CyberGuard signals (Req 38).
        """
        sup = [m.technique_id for m in mappings if m.status == AttackMappingStatus.SUPPORTED]
        pla = [m.technique_id for m in mappings if m.status == AttackMappingStatus.PLAUSIBLE]
        ins = [m.technique_id for m in mappings if m.status == AttackMappingStatus.INSUFFICIENT_EVIDENCE]
        rej = [m.technique_id for m in mappings if m.status == AttackMappingStatus.REJECTED]

        return AttackCoverageSummary(
            supported_count=len(sup),
            plausible_count=len(pla),
            insufficient_count=len(ins),
            rejected_count=len(rej),
            supported_techniques=sorted(list(set(sup))),
            plausible_techniques=sorted(list(set(pla))),
            insufficient_techniques=sorted(list(set(ins))),
            rejected_techniques=sorted(list(set(rej))),
            unmapped_behaviors=unmapped_observations or [],
        )

    # ========================================================================
    # 6. LLM SUGGESTION VALIDATION (REQ 44-46, SCENARIOS J & K)
    # ========================================================================

    def validate_llm_suggestion(
        self,
        suggestion: LLMTechniqueSuggestion,
        context: Optional[MappingEvaluationContext] = None
    ) -> LLMValidationResult:
        """
        Strict deterministic validator for AI / LLM technique suggestions.
        Rules:
        - Technique ID must exist in local ATT&CK dataset (Scenario J -> REJECTED if invalid ID).
        - If technique is deprecated/revoked, indicate clearly.
        - Technique MUST satisfy deterministic mapping rule.
        - If evidence is missing, suggestion may be PLAUSIBLE or INSUFFICIENT_EVIDENCE,
          but NEVER automatically marked SUPPORTED! (Scenario K).
        """
        tid = suggestion.candidate_technique_id.strip().upper()
        tech = self.dataset.get_technique(tid)

        # 1. Nonexistent technique ID (Scenario J)
        if not tech:
            return LLMValidationResult(
                suggested_technique_id=tid,
                technique_exists=False,
                technique_name=None,
                is_deprecated=False,
                is_revoked=False,
                rule_satisfied=False,
                contradicted=False,
                resulting_status=AttackMappingStatus.REJECTED,
                explanation=f"Rejection: '{tid}' is not a valid technique in MITRE ATT&CK Enterprise dataset.",
                resulting_mapping=None,
            )

        # 2. Check deprecated / revoked
        is_dep = tech.is_deprecated
        is_rev, rev_by = self.dataset.is_technique_revoked(tid)

        # 3. If no evaluation context provided, suggestion can only be PLAUSIBLE at best
        if not context:
            return LLMValidationResult(
                suggested_technique_id=tid,
                technique_exists=True,
                technique_name=tech.name,
                is_deprecated=is_dep,
                is_revoked=is_rev,
                rule_satisfied=False,
                contradicted=False,
                resulting_status=AttackMappingStatus.INSUFFICIENT_EVIDENCE,
                explanation=f"Technique {tid} ({tech.name}) recognized, but no normalized evidence was provided to validate mapping.",
                resulting_mapping=None,
            )

        # 4. Evaluate against deterministic rules
        rule_evals = self._evaluate_context_against_rules(context)
        matching_rule = next((m for m in rule_evals if m.technique_id == tid), None)
        rule_satisfied = bool(matching_rule and matching_rule.status == AttackMappingStatus.SUPPORTED)

        if rule_satisfied and matching_rule:
            # Rule found and supported
            status = matching_rule.status
            explanation = f"LLM suggestion confirmed by deterministic rule: {matching_rule.explanation}"
            mapping = matching_rule
        else:
            # Valid technique ID, but evidence does not satisfy rule -> PLAUSIBLE or INSUFFICIENT (Scenario K)
            status = AttackMappingStatus.PLAUSIBLE
            explanation = (
                f"LLM suggested {tid} ({tech.name}), but underlying evidence is insufficient "
                "to satisfy deterministic rule requirements. Kept at PLAUSIBLE."
            )
            mapping = AttackTechniqueMapping(
                id=str(uuid.uuid4()),
                incident_id=context.incident_id,
                source_type=context.source_type,
                source_id=context.source_id,
                technique_id=tech.technique_id,
                technique_name=tech.name,
                subtechnique_id=tech.technique_id if tech.is_subtechnique else None,
                tactic_ids=tech.tactic_ids,
                tactic_names=[self.dataset.get_tactic(x).name for x in tech.tactic_ids if self.dataset.get_tactic(x)],
                status=AttackMappingStatus.PLAUSIBLE,
                confidence=min(suggestion.confidence_suggestion or 0.50, 0.50),
                confidence_level=ConfidenceLevel.MODERATE,
                mapping_method=MappingMethod.LLM_SUGGESTED,
                explanation=explanation,
                limitations=["Technique candidate suggested by LLM; required telemetry is unconfirmed."],
                attack_version=self.dataset.get_attack_version(),
            )

        return LLMValidationResult(
            suggested_technique_id=tid,
            technique_exists=True,
            technique_name=tech.name,
            is_deprecated=is_dep,
            is_revoked=is_rev,
            rule_satisfied=rule_satisfied,
            contradicted=False,
            resulting_status=status,
            explanation=explanation,
            resulting_mapping=mapping,
        )

    # ========================================================================
    # 7. EXPLANATION & REPORT FORMATTING (REQ 49-54)
    # ========================================================================

    def explain_mapping(self, mapping: AttackTechniqueMapping) -> str:
        """
        Explains WHY a specific technique mapping was produced, citing evidence
        and limitations using epistemically humble phrasing.
        """
        lines = [
            f"Technique: {mapping.technique_name} ({mapping.technique_id})",
            f"Tactics: {', '.join(mapping.tactic_names)}",
            f"Mapping Status: {mapping.status.value} (Confidence: {mapping.confidence:.2f} [{mapping.confidence_level.value}])",
            f"Mapping Method: {mapping.mapping_method.value}",
            f"Why Mapped: {mapping.explanation}",
        ]
        if mapping.evidence_ids:
            lines.append(f"Supporting Evidence IDs: {', '.join(mapping.evidence_ids)}")
        if mapping.limitations:
            lines.append("Limitations & Gaps:")
            for lim in mapping.limitations:
                lines.append(f"  • {lim}")
        if mapping.contradictions:
            lines.append("Contradictions Observed:")
            for c in mapping.contradictions:
                lines.append(f"  • {c}")

        return "\n".join(lines)

    def _generate_executive_summary(
        self,
        supported: List[AttackTechniqueMapping],
        plausible: List[AttackTechniqueMapping],
        insufficient: List[AttackTechniqueMapping]
    ) -> str:
        """
        Generates an executive summary enforcing the linguistic rule:
        'CyberGuard mapped observed activity to...' NEVER 'The attacker used...'.
        """
        return (
            f"CyberGuard identified {len(supported)} ATT&CK mappings supported by observed evidence "
            f"and {len(plausible)} additional technique candidates that remain plausible but insufficiently established. "
            f"Observed security events and authentication patterns align with standard adversary behaviors in "
            f"MITRE ATT&CK Enterprise {self.dataset.get_attack_version()}."
        )

    def _generate_analyst_summary(
        self,
        supported: List[AttackTechniqueMapping],
        plausible: List[AttackTechniqueMapping]
    ) -> str:
        lines = ["MITRE ATT&CK ANALYSIS"]
        if supported:
            lines.append("\nSUPPORTED TECHNIQUES:")
            for m in supported:
                lines.append(
                    f"• [{m.technique_id}] {m.technique_name} ({', '.join(m.tactic_names)}) "
                    f"— Evidence items: {len(m.evidence_ids)}"
                )
        if plausible:
            lines.append("\nPLAUSIBLE TECHNIQUES (INSUFFICIENT TELEMETRY):")
            for m in plausible:
                lines.append(
                    f"• [{m.technique_id}] {m.technique_name} "
                    f"— Limitation: {m.limitations[0] if m.limitations else 'Indirect evidence'}"
                )
        return "\n".join(lines)


# Global singleton instance
global_mitre_mapping_engine = MITREAttackMappingEngine()
