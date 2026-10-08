"""
CyberGuard Threat Memory Service (Section 23).
Provides a persistent, provenance-aware security-memory and retrieval layer
over CyberGuard's canonical evidence, graph, incident, analysis, baseline, and novelty data.

Core Epistemic Principles:
1. CURRENT EVIDENCE > HISTORICAL MEMORY.
2. VERIFIED MEMORY > UNVERIFIED MEMORY.
3. EVIDENCE > LLM CLAIM.
4. Memory is contextual enrichment; it never automatically determines present truth.
5. Conflicting memory is preserved and surfaced explicitly, not overwritten.
6. Multi-tenant scope isolation is strictly enforced.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    AuditLogModel,
    BehavioralBaselineModel,
    BehavioralDeviationModel,
    CampaignModel,
    EmergingPatternCandidateModel,
    EntityModel,
    FindingModel,
    IncidentModel,
    IndicatorModel,
    NoveltyAssessmentModel,
    RelationshipModel,
    ResponseActionModel,
    ThreatMemoryDecisionModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
    ThreatMemoryRelationshipModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.threat_memory import (
    AnalystDecisionType,
    MemoryRelationshipType,
    MemoryScope,
    MemoryStatus,
    MemoryType,
    ObservationClassification,
    ProvenanceType,
    ThreatMemoryConflictSummary,
    ThreatMemoryContext,
    ThreatMemoryDecision,
    ThreatMemoryEntry,
    ThreatMemoryObservation,
    ThreatMemoryStatsResponse,
    canonicalize_memory_key,
    sanitize_memory_attributes,
)
from backend.services.log_sanitizer import sanitize_log_text

logger = logging.getLogger("cyberguard.threat_memory")


class ThreatMemoryService:
    """
    Central orchestration service for Section 23 Threat Memory.
    Enforces canonicalization, poisoning defense, observation deduplication,
    scope isolation, mixed-evidence preservation, and graceful degradation.
    """

    # Traversal and result bounding limits
    MAX_OBSERVATIONS_LIMIT = 50
    MAX_RELATED_INCIDENTS = 20
    MAX_RELATED_CAMPAIGNS = 10
    MAX_INFRASTRUCTURE_NODES = 25

    # ========================================================================
    # 1. CANONICALIZATION & ELIGIBILITY
    # ========================================================================

    @staticmethod
    def _safe_max_dt(dt1: Optional[datetime], dt2: Optional[datetime]) -> Optional[datetime]:
        if dt1 is None:
            return dt2
        if dt2 is None:
            return dt1
        n1 = dt1.replace(tzinfo=timezone.utc) if dt1.tzinfo is None else dt1
        n2 = dt2.replace(tzinfo=timezone.utc) if dt2.tzinfo is None else dt2
        return dt1 if n1 >= n2 else dt2

    @staticmethod
    def _safe_min_dt(dt1: Optional[datetime], dt2: Optional[datetime]) -> Optional[datetime]:
        if dt1 is None:
            return dt2
        if dt2 is None:
            return dt1
        n1 = dt1.replace(tzinfo=timezone.utc) if dt1.tzinfo is None else dt1
        n2 = dt2.replace(tzinfo=timezone.utc) if dt2.tzinfo is None else dt2
        return dt1 if n1 <= n2 else dt2

    @staticmethod
    def canonicalize(subject_type: Union[MemoryType, str], value: str) -> str:
        """
        Deterministic canonical key generation.
        """
        return canonicalize_memory_key(subject_type, value)

    @classmethod
    def is_eligible_for_memory(
        cls,
        subject_type: Union[MemoryType, str],
        value: str,
        confidence: float = 1.0,
    ) -> bool:
        """
        Eligibility filter: prevents ephemeral, empty, or unparseable inputs
        from creating permanent memory entries.
        """
        if not value or not str(value).strip():
            return False
        clean = str(value).strip()
        if len(clean) < 2:
            return False
        if clean.lower() in ("unknown", "null", "none", "n/a", "undefined"):
            return False
        if confidence < 0.2:
            return False
        return True

    # ========================================================================
    # 2. OBSERVATION INGESTION & POISONING PROTECTION
    # ========================================================================

    @classmethod
    def record_observation(
        cls,
        db: Session,
        workspace_id: str,
        subject_type: Union[MemoryType, str],
        value: str,
        source_type: str,
        source_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        classification: ObservationClassification = ObservationClassification.INCONCLUSIVE,
        severity: Optional[str] = None,
        confidence: float = 1.0,
        evidence_reference: Optional[str] = None,
        analysis_run_id: Optional[str] = None,
        detector_name: Optional[str] = None,
        detector_version: str = "1.0.0",
        is_analyst_verified: bool = False,
        verified_by: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        raw_context: Optional[Dict[str, Any]] = None,
        scope: MemoryScope = MemoryScope.ORGANIZATION,
    ) -> Tuple[ThreatMemoryEntryModel, ThreatMemoryObservationModel, bool]:
        """
        Records an observation with strict deduplication and poisoning protection.
        Returns: (entry, observation, is_new_entry)

        Poisoning Guard:
        - If the exact same source_id and investigation_id submits the observation repeatedly,
          it updates timestamps but DOES NOT increment independent_source_count.
        - Multiple observations from untrusted sources do NOT automatically promote to VERIFIED.
        """
        if not cls.is_eligible_for_memory(subject_type, value, confidence):
            raise ValueError(f"Subject '{value}' of type '{subject_type}' does not meet memory eligibility criteria.")

        canonical_key = cls.canonicalize(subject_type, value)
        obs_time = observed_at or datetime.now(timezone.utc)
        sanitized_context = sanitize_memory_attributes(raw_context or {})

        # 1. Lookup or create ThreatMemoryEntry
        entry = db.query(ThreatMemoryEntryModel).filter(
            ThreatMemoryEntryModel.workspace_id == workspace_id,
            ThreatMemoryEntryModel.canonical_key == canonical_key,
        ).first()

        is_new_entry = False
        if not entry:
            is_new_entry = True
            entry = ThreatMemoryEntryModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                memory_type=str(subject_type.value if hasattr(subject_type, "value") else subject_type),
                subject_type=str(subject_type.value if hasattr(subject_type, "value") else subject_type),
                canonical_key=canonical_key,
                scope=str(scope.value if hasattr(scope, "value") else scope),
                status=MemoryStatus.OBSERVED.value,
                first_seen_at=obs_time,
                last_seen_at=obs_time,
                observation_count=1,
                independent_source_count=1,
                incident_count=1 if incident_id else 0,
                campaign_count=1 if campaign_id else 0,
                confidence=float(confidence),
                confidence_level="HIGH" if confidence >= 0.8 else ("MEDIUM" if confidence >= 0.5 else "LOW"),
                provenance_type=(
                    ProvenanceType.ANALYST_VERIFIED.value
                    if is_analyst_verified
                    else (
                        ProvenanceType.EXTERNAL_INTELLIGENCE.value
                        if source_type == "EXTERNAL_FEED"
                        else ProvenanceType.DIRECT_OBSERVATION.value
                    )
                ),
                provenance_reference=evidence_reference or f"run:{analysis_run_id}" or f"inv:{investigation_id}",
                summary=f"Observed {canonical_key} via {detector_name or source_type}",
                attributes_json=json.dumps(sanitized_context),
                version="1.0.0",
                created_at=get_utc_now(),
                updated_at=get_utc_now(),
            )
            db.add(entry)
            db.flush()

            # Audit record
            cls._log_audit(
                db,
                workspace_id,
                action="MEMORY_CREATED",
                resource_id=entry.id,
                details=f"Created Threat Memory entry for {canonical_key}",
                metadata={"canonical_key": canonical_key, "source_type": source_type},
            )

        # 2. Check for duplicate observation to prevent inflation attack
        # A duplicate is an observation with the same memory_entry_id, investigation_id,
        # analysis_run_id, and source_id.
        existing_obs = None
        if investigation_id or analysis_run_id or source_id:
            query_filter = [ThreatMemoryObservationModel.memory_entry_id == entry.id]
            if investigation_id:
                query_filter.append(ThreatMemoryObservationModel.investigation_id == investigation_id)
            if analysis_run_id:
                query_filter.append(ThreatMemoryObservationModel.analysis_run_id == analysis_run_id)
            if source_id:
                query_filter.append(ThreatMemoryObservationModel.source_id == source_id)

            existing_obs = db.query(ThreatMemoryObservationModel).filter(*query_filter).first()

        if existing_obs:
            # Update observation timestamp without inflating independent counts
            existing_obs.observed_at = cls._safe_max_dt(existing_obs.observed_at, obs_time)
            if confidence > existing_obs.confidence:
                existing_obs.confidence = float(confidence)
            if is_analyst_verified:
                existing_obs.is_analyst_verified = True
                existing_obs.verified_by = verified_by

            entry.last_seen_at = cls._safe_max_dt(entry.last_seen_at, obs_time)
            entry.updated_at = get_utc_now()
            db.flush()
            return entry, existing_obs, False

        # 3. Create new independent observation
        obs = ThreatMemoryObservationModel(
            id=generate_uuid(),
            memory_entry_id=entry.id,
            workspace_id=workspace_id,
            source_type=source_type,
            source_id=source_id,
            investigation_id=investigation_id,
            incident_id=incident_id,
            campaign_id=campaign_id,
            observed_at=obs_time,
            observation_type="DETECTION",
            classification=str(classification.value if hasattr(classification, "value") else classification),
            severity=severity,
            confidence=float(confidence),
            evidence_reference=evidence_reference,
            analysis_run_id=analysis_run_id,
            detector_name=detector_name,
            detector_version=detector_version,
            is_analyst_verified=is_analyst_verified,
            verified_by=verified_by,
            raw_context_json=json.dumps(sanitized_context),
            created_at=get_utc_now(),
        )
        db.add(obs)
        db.flush()

        # 4. Update entry aggregate counters if not a new entry
        if not is_new_entry:
            entry.observation_count += 1
            entry.last_seen_at = cls._safe_max_dt(entry.last_seen_at, obs_time)

            # Calculate distinct independent sources
            distinct_sources = db.query(
                func.count(func.distinct(ThreatMemoryObservationModel.investigation_id))
            ).filter(ThreatMemoryObservationModel.memory_entry_id == entry.id).scalar() or 1
            entry.independent_source_count = max(entry.independent_source_count, distinct_sources)

            # Calculate distinct incidents
            distinct_incidents = db.query(
                func.count(func.distinct(ThreatMemoryObservationModel.incident_id))
            ).filter(
                ThreatMemoryObservationModel.memory_entry_id == entry.id,
                ThreatMemoryObservationModel.incident_id.isnot(None),
            ).scalar() or 0
            entry.incident_count = distinct_incidents

            # Calculate distinct campaigns
            distinct_campaigns = db.query(
                func.count(func.distinct(ThreatMemoryObservationModel.campaign_id))
            ).filter(
                ThreatMemoryObservationModel.memory_entry_id == entry.id,
                ThreatMemoryObservationModel.campaign_id.isnot(None),
            ).scalar() or 0
            entry.campaign_count = distinct_campaigns

            # Promotion Logic:
            # OBSERVED -> CORRELATED if multiple independent sources or incidents
            if entry.status == MemoryStatus.OBSERVED.value:
                if entry.independent_source_count >= 2 or entry.incident_count >= 2 or entry.campaign_count >= 1:
                    entry.status = MemoryStatus.CORRELATED.value
                    cls._log_audit(
                        db,
                        workspace_id,
                        action="MEMORY_PROMOTED",
                        resource_id=entry.id,
                        details=f"Promoted {canonical_key} from OBSERVED to CORRELATED",
                        metadata={"new_status": "CORRELATED", "source_count": entry.independent_source_count},
                    )

            if is_analyst_verified and entry.status != MemoryStatus.VERIFIED.value:
                entry.status = MemoryStatus.VERIFIED.value
                entry.provenance_type = ProvenanceType.ANALYST_VERIFIED.value

            entry.updated_at = get_utc_now()
            db.flush()

        cls._log_audit(
            db,
            workspace_id,
            action="MEMORY_OBSERVATION_ADDED",
            resource_id=entry.id,
            details=f"Added observation for {canonical_key} from {source_type}",
            metadata={"classification": str(classification), "investigation_id": investigation_id},
        )

        return entry, obs, is_new_entry

    # ========================================================================
    # 3. ANALYST DECISIONS & FALSE-POSITIVE MEMORY
    # ========================================================================

    @classmethod
    def record_analyst_decision(
        cls,
        db: Session,
        workspace_id: str,
        decision: Union[AnalystDecisionType, str],
        reason: str,
        approved_by: str,
        canonical_key: Optional[str] = None,
        memory_entry_id: Optional[str] = None,
        scope: MemoryScope = MemoryScope.ORGANIZATION,
        valid_days: Optional[int] = 30,
        evidence_ids: Optional[List[str]] = None,
    ) -> ThreatMemoryDecisionModel:
        """
        Records an auditable human analyst validation, false-positive verification,
        or suppression decision.
        """
        if not memory_entry_id and not canonical_key:
            raise ValueError("Either memory_entry_id or canonical_key must be specified.")

        entry = None
        if memory_entry_id:
            entry = db.query(ThreatMemoryEntryModel).filter(
                ThreatMemoryEntryModel.id == memory_entry_id,
                ThreatMemoryEntryModel.workspace_id == workspace_id,
            ).first()
        elif canonical_key:
            entry = db.query(ThreatMemoryEntryModel).filter(
                ThreatMemoryEntryModel.canonical_key == canonical_key,
                ThreatMemoryEntryModel.workspace_id == workspace_id,
            ).first()

        if not entry:
            raise ValueError(f"ThreatMemoryEntry not found for key={canonical_key} or id={memory_entry_id}")

        dec_str = str(decision.value if hasattr(decision, "value") else decision)
        now = datetime.now(timezone.utc)
        valid_until = now + timedelta(days=valid_days) if valid_days else None

        dec_record = ThreatMemoryDecisionModel(
            id=generate_uuid(),
            memory_entry_id=entry.id,
            workspace_id=workspace_id,
            decision=dec_str,
            reason=sanitize_log_text(reason),
            approved_by=approved_by,
            scope=str(scope.value if hasattr(scope, "value") else scope),
            valid_from=now,
            valid_until=valid_until,
            evidence_ids_json=json.dumps(evidence_ids or []),
            created_at=get_utc_now(),
        )
        db.add(dec_record)

        # Update entry status
        if dec_str in (AnalystDecisionType.VERIFIED_MALICIOUS.value, AnalystDecisionType.VERIFIED_BENIGN.value, AnalystDecisionType.FALSE_POSITIVE.value):
            entry.status = MemoryStatus.VERIFIED.value
            entry.provenance_type = ProvenanceType.ANALYST_VERIFIED.value
        elif dec_str in (AnalystDecisionType.SUPPRESSED.value,):
            entry.status = MemoryStatus.DISMISSED.value

        entry.updated_at = get_utc_now()
        db.flush()

        cls._log_audit(
            db,
            workspace_id,
            action="MEMORY_DECISION_RECORDED",
            resource_id=entry.id,
            details=f"Analyst {approved_by} recorded decision {dec_str} for {entry.canonical_key}: {reason}",
            metadata={"decision": dec_str, "approved_by": approved_by, "valid_until": str(valid_until)},
        )

        return dec_record

    # ========================================================================
    # 4. LOOKUP & RETRIEVAL
    # ========================================================================

    @classmethod
    def lookup_by_key(
        cls,
        db: Session,
        workspace_id: str,
        canonical_key: str,
        include_global: bool = True,
    ) -> Optional[ThreatMemoryEntryModel]:
        """
        Exact deterministic lookup with multi-tenant scope isolation.
        """
        query = db.query(ThreatMemoryEntryModel).filter(
            ThreatMemoryEntryModel.canonical_key == canonical_key
        )
        if include_global:
            query = query.filter(
                or_(
                    ThreatMemoryEntryModel.workspace_id == workspace_id,
                    ThreatMemoryEntryModel.scope == MemoryScope.GLOBAL.value,
                )
            )
        else:
            query = query.filter(ThreatMemoryEntryModel.workspace_id == workspace_id)

        return query.first()

    @classmethod
    def lookup_indicator(
        cls,
        db: Session,
        workspace_id: str,
        value: str,
        subject_type: Optional[Union[MemoryType, str]] = None,
    ) -> Optional[ThreatMemoryEntryModel]:
        """
        Looks up memory for a raw observable value by auto-canonicalizing it.
        """
        st = subject_type or MemoryType.INDICATOR
        # If subject_type not specified, try to infer
        if not subject_type:
            val_str = (value or "").strip()
            if "@" in val_str and "/" not in val_str:
                st = MemoryType.SENDER_PATTERN
            elif val_str.startswith("http://") or val_str.startswith("https://"):
                st = MemoryType.URL
            elif any(c in val_str for c in [":", "."]) and all(p.isdigit() or p == "" for p in val_str.split(".")):
                st = MemoryType.IP
            elif len(val_str) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in val_str):
                st = MemoryType.HASH
            elif "." in val_str and "/" not in val_str:
                st = MemoryType.DOMAIN

        canonical_key = cls.canonicalize(st, value)
        return cls.lookup_by_key(db, workspace_id, canonical_key)

    @classmethod
    def get_related_incidents(
        cls,
        db: Session,
        workspace_id: str,
        memory_entry_id: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves all historical incidents where this memory entry was observed.
        """
        obs_records = db.query(ThreatMemoryObservationModel).filter(
            ThreatMemoryObservationModel.memory_entry_id == memory_entry_id,
            ThreatMemoryObservationModel.incident_id.isnot(None),
        ).limit(cls.MAX_OBSERVATIONS_LIMIT).all()

        incident_ids = list({o.incident_id for o in obs_records if o.incident_id})
        if not incident_ids:
            return []

        incidents = db.query(IncidentModel).filter(
            IncidentModel.id.in_(incident_ids),
            IncidentModel.workspace_id == workspace_id,
        ).limit(limit).all()

        results = []
        for inc in incidents:
            results.append({
                "incident_id": inc.id,
                "incident_number": inc.incident_number,
                "title": inc.title,
                "status": inc.status,
                "severity": inc.severity,
                "risk_score": inc.risk_score,
                "opened_at": inc.opened_at.isoformat() if inc.opened_at else None,
            })
        return results

    @classmethod
    def get_related_campaigns(
        cls,
        db: Session,
        workspace_id: str,
        memory_entry_id: str,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves historical campaigns linked to this memory entry.
        """
        obs_records = db.query(ThreatMemoryObservationModel).filter(
            ThreatMemoryObservationModel.memory_entry_id == memory_entry_id,
            ThreatMemoryObservationModel.campaign_id.isnot(None),
        ).limit(cls.MAX_OBSERVATIONS_LIMIT).all()

        campaign_ids = list({o.campaign_id for o in obs_records if o.campaign_id})
        if not campaign_ids:
            return []

        campaigns = db.query(CampaignModel).filter(
            CampaignModel.id.in_(campaign_ids),
        ).limit(limit).all()

        results = []
        for c in campaigns:
            results.append({
                "id": c.id,
                "campaign_id": c.campaign_id,
                "name": c.name,
                "first_seen": c.first_seen.isoformat() if c.first_seen else None,
                "last_seen": c.last_seen.isoformat() if c.last_seen else None,
            })
        return results

    @classmethod
    def get_related_infrastructure(
        cls,
        db: Session,
        workspace_id: str,
        canonical_key: str,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """
        Traverses Section 14 Security Knowledge Graph relationships to retrieve
        correlated infrastructure (resolves_to, hosted_on, associated_with).
        """
        # Look for relationships where source_id or target_id matches canonical_key or its parts
        clean_key = canonical_key.split(":", 1)[-1] if ":" in canonical_key else canonical_key
        rels = db.query(RelationshipModel).filter(
            or_(
                RelationshipModel.source_id.in_([canonical_key, clean_key]),
                RelationshipModel.target_id.in_([canonical_key, clean_key]),
            ),
            or_(
                RelationshipModel.workspace_id == workspace_id,
                RelationshipModel.workspace_id.is_(None),
            ),
            RelationshipModel.status == "ACTIVE",
        ).limit(limit).all()

        results = []
        for r in rels:
            results.append({
                "relationship_type": r.relationship_type,
                "source_type": r.source_type,
                "source_id": r.source_id,
                "target_type": r.target_type,
                "target_id": r.target_id,
                "confidence": r.confidence,
                "origin": r.origin,
                "first_seen": r.first_seen.isoformat() if r.first_seen else None,
                "last_seen": r.last_seen.isoformat() if r.last_seen else None,
            })
        return results

    @classmethod
    def get_novelty_progression(
        cls,
        db: Session,
        workspace_id: str,
        canonical_key: str,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves Section 22 novelty assessment history to track pattern evolution:
        first-seen (novel) -> subsequent recurring observations.
        """
        clean_val = canonical_key.split(":", 1)[-1] if ":" in canonical_key else canonical_key
        assessments = db.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.workspace_id == workspace_id,
            or_(
                NoveltyAssessmentModel.entity_id == clean_val,
                NoveltyAssessmentModel.fingerprint_hash == clean_val,
            ),
        ).order_by(NoveltyAssessmentModel.created_at.asc()).limit(10).all()

        emerging = db.query(EmergingPatternCandidateModel).filter(
            EmergingPatternCandidateModel.workspace_id == workspace_id,
            EmergingPatternCandidateModel.fingerprint_hash == clean_val,
        ).first()

        progression = []
        for a in assessments:
            progression.append({
                "type": "NOVELTY_ASSESSMENT",
                "novelty_score": a.novelty_score,
                "novelty_level": a.novelty_level,
                "similarity_score": a.similarity_score,
                "historical_sample_count": a.historical_sample_count,
                "assessed_at": a.created_at.isoformat() if a.created_at else None,
            })

        if emerging:
            progression.append({
                "type": "EMERGING_PATTERN",
                "status": emerging.status,
                "observation_count": emerging.observation_count,
                "incident_count": emerging.incident_count,
                "recurrence_score": emerging.recurrence_score,
                "first_seen": emerging.first_seen.isoformat() if emerging.first_seen else None,
                "last_seen": emerging.last_seen.isoformat() if emerging.last_seen else None,
            })

        return progression

    @classmethod
    def get_behavioral_history(
        cls,
        db: Session,
        workspace_id: str,
        canonical_key: str,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves Section 21 Behavioral Baseline history for this entity.
        """
        clean_val = canonical_key.split(":", 1)[-1] if ":" in canonical_key else canonical_key
        baselines = db.query(BehavioralBaselineModel).filter(
            BehavioralBaselineModel.workspace_id == workspace_id,
            BehavioralBaselineModel.entity_id == clean_val,
        ).limit(5).all()

        results = []
        for b in baselines:
            results.append({
                "baseline_type": b.baseline_type,
                "sample_count": b.sample_count,
                "state": b.state,
                "first_learned": b.first_learned_at.isoformat() if b.first_learned_at else None,
                "last_updated": b.last_updated_at.isoformat() if b.last_updated_at else None,
            })
        return results

    @classmethod
    def get_response_history(
        cls,
        db: Session,
        workspace_id: str,
        incident_ids: List[str],
    ) -> List[Dict[str, Any]]:
        """
        Retrieves historical response actions and containment outcomes for linked incidents.
        """
        if not incident_ids:
            return []
        actions = db.query(ResponseActionModel).filter(
            ResponseActionModel.incident_id.in_(incident_ids),
        ).limit(10).all()

        results = []
        for a in actions:
            results.append({
                "id": a.id,
                "action_type": a.action_type,
                "status": a.status,
                "execution_summary": a.execution_summary,
                "incident_id": a.incident_id,
                "created_at": a.created_at.isoformat() if a.created_at else None,
            })
        return results

    # ========================================================================
    # 5. STANDARDIZED THREAT MEMORY CONTEXT BUILDER
    # ========================================================================

    @classmethod
    def build_threat_memory_context(
        cls,
        db: Session,
        workspace_id: str,
        value_or_key: str,
        subject_type: Optional[Union[MemoryType, str]] = None,
        include_graph: bool = True,
        max_observations: int = 20,
    ) -> ThreatMemoryContext:
        """
        Builds standardized ThreatMemoryContext with complete historical lineage,
        conflict evaluation, graph associations, and provenance.
        Gracefully degrades if memory lookup encounters an unexpected database error.
        """
        st = subject_type or MemoryType.INDICATOR
        canonical_key = (
            value_or_key
            if (isinstance(value_or_key, str) and ":" in value_or_key and value_or_key.split(":", 1)[0] in [
                "SHA256", "DOMAIN", "IP", "URL", "EMAIL", "CAMPAIGN", "CLUSTER", "FP"
            ])
            else cls.canonicalize(st, value_or_key)
        )

        try:
            entry = cls.lookup_by_key(db, workspace_id, canonical_key)
            if not entry:
                # No historical memory exists for this subject
                return ThreatMemoryContext(
                    canonical_key=canonical_key,
                    subject_type=str(st.value if hasattr(st, "value") else st),
                    memory_status=MemoryStatus.OBSERVED,
                    historical_context_available=True,
                    observation_count=0,
                    independent_source_count=0,
                    confidence=1.0,
                    confidence_level="UNKNOWN",
                    is_analyst_verified=False,
                    prior_observations=[],
                    limitations=[
                        "No prior historical observations exist in CyberGuard Threat Memory for this subject.",
                        "Current analysis must rely strictly on present forensic evidence.",
                    ],
                )

            # Retrieve prior observations
            obs_query = db.query(ThreatMemoryObservationModel).filter(
                ThreatMemoryObservationModel.memory_entry_id == entry.id,
            ).order_by(desc(ThreatMemoryObservationModel.observed_at)).limit(max_observations)
            obs_records = obs_query.all()

            pydantic_observations: List[ThreatMemoryObservation] = []
            malicious_count = 0
            benign_count = 0
            suspicious_count = 0
            inconclusive_count = 0

            for o in obs_records:
                cls_val = (o.classification or "").upper()
                if cls_val == "MALICIOUS":
                    malicious_count += 1
                elif cls_val == "BENIGN":
                    benign_count += 1
                elif cls_val == "SUSPICIOUS":
                    suspicious_count += 1
                else:
                    inconclusive_count += 1

                raw_ctx = {}
                try:
                    if o.raw_context_json:
                        raw_ctx = json.loads(o.raw_context_json)
                except Exception:
                    pass

                pydantic_observations.append(
                    ThreatMemoryObservation(
                        id=o.id,
                        memory_entry_id=o.memory_entry_id,
                        workspace_id=o.workspace_id,
                        source_type=o.source_type,
                        source_id=o.source_id,
                        investigation_id=o.investigation_id,
                        incident_id=o.incident_id,
                        campaign_id=o.campaign_id,
                        observed_at=o.observed_at,
                        observation_type=o.observation_type,
                        classification=ObservationClassification(o.classification) if o.classification in ObservationClassification._value2member_map_ else ObservationClassification.INCONCLUSIVE,
                        severity=o.severity,
                        confidence=o.confidence,
                        evidence_reference=o.evidence_reference,
                        analysis_run_id=o.analysis_run_id,
                        detector_name=o.detector_name,
                        detector_version=o.detector_version,
                        is_analyst_verified=o.is_analyst_verified,
                        verified_by=o.verified_by,
                        raw_context=raw_ctx,
                        created_at=o.created_at,
                    )
                )

            # Conflict Detection
            is_conflicted = (malicious_count > 0 and benign_count > 0)
            conflict_explanation = None
            if is_conflicted:
                conflict_explanation = (
                    f"Historical context is mixed. Observed malicious in {malicious_count} observations, "
                    f"benign in {benign_count} observations. Current classification requires fresh evidence."
                )

            # Analyst Decisions
            dec_records = db.query(ThreatMemoryDecisionModel).filter(
                ThreatMemoryDecisionModel.memory_entry_id == entry.id,
            ).order_by(desc(ThreatMemoryDecisionModel.created_at)).all()

            pydantic_decisions: List[ThreatMemoryDecision] = []
            is_analyst_verified = False
            verification_status = None
            for d in dec_records:
                ev_ids = []
                try:
                    if d.evidence_ids_json:
                        ev_ids = json.loads(d.evidence_ids_json)
                except Exception:
                    pass
                pydantic_decisions.append(
                    ThreatMemoryDecision(
                        id=d.id,
                        memory_entry_id=d.memory_entry_id,
                        workspace_id=d.workspace_id,
                        decision=AnalystDecisionType(d.decision) if d.decision in AnalystDecisionType._value2member_map_ else AnalystDecisionType.NEEDS_REVIEW,
                        reason=d.reason,
                        approved_by=d.approved_by,
                        scope=MemoryScope(d.scope) if d.scope in MemoryScope._value2member_map_ else MemoryScope.ORGANIZATION,
                        valid_from=d.valid_from,
                        valid_until=d.valid_until,
                        evidence_ids=ev_ids,
                        created_at=d.created_at,
                    )
                )
                if not is_analyst_verified:
                    is_analyst_verified = True
                    verification_status = d.decision

            # Graph & Related Data
            related_incidents = cls.get_related_incidents(db, workspace_id, entry.id, limit=cls.MAX_RELATED_INCIDENTS)
            related_campaigns = cls.get_related_campaigns(db, workspace_id, entry.id, limit=cls.MAX_RELATED_CAMPAIGNS)
            related_infra = cls.get_related_infrastructure(db, workspace_id, canonical_key, limit=cls.MAX_INFRASTRUCTURE_NODES) if include_graph else []
            novelty_history = cls.get_novelty_progression(db, workspace_id, canonical_key)
            behavioral_history = cls.get_behavioral_history(db, workspace_id, canonical_key)
            inc_ids = [inc["incident_id"] for inc in related_incidents if "incident_id" in inc]
            response_history = cls.get_response_history(db, workspace_id, inc_ids)

            # Provenance Chain
            provenance_chain = [
                {
                    "provenance_type": entry.provenance_type,
                    "reference": entry.provenance_reference,
                    "first_seen_at": entry.first_seen_at.isoformat() if entry.first_seen_at else None,
                    "last_seen_at": entry.last_seen_at.isoformat() if entry.last_seen_at else None,
                    "version": entry.version,
                }
            ]

            return ThreatMemoryContext(
                canonical_key=entry.canonical_key,
                subject_type=entry.subject_type,
                subject_id=entry.subject_id,
                memory_status=MemoryStatus(entry.status) if entry.status in MemoryStatus._value2member_map_ else MemoryStatus.OBSERVED,
                historical_context_available=True,
                observation_count=entry.observation_count,
                independent_source_count=entry.independent_source_count,
                first_seen_at=entry.first_seen_at,
                last_seen_at=entry.last_seen_at,
                confidence=entry.confidence,
                confidence_level=entry.confidence_level,
                is_analyst_verified=is_analyst_verified,
                verification_status=verification_status,
                prior_observations=pydantic_observations,
                related_incidents=related_incidents,
                related_campaigns=related_campaigns,
                related_infrastructure=related_infra,
                behavioral_history=behavioral_history,
                novelty_history=novelty_history,
                analyst_decisions=pydantic_decisions,
                response_history=response_history,
                conflict=ThreatMemoryConflictSummary(
                    is_conflicted=is_conflicted,
                    malicious_count=malicious_count,
                    benign_count=benign_count,
                    suspicious_count=suspicious_count,
                    inconclusive_count=inconclusive_count,
                    explanation=conflict_explanation,
                ),
                provenance_chain=provenance_chain,
            )

        except Exception as exc:
            logger.error(f"Threat Memory retrieval error for {canonical_key}: {exc}", exc_info=True)
            # Graceful degradation: return non-blocking context marked degraded
            return ThreatMemoryContext(
                canonical_key=canonical_key,
                subject_type=str(st.value if hasattr(st, "value") else st),
                memory_status=MemoryStatus.OBSERVED,
                historical_context_available=False,
                observation_count=0,
                independent_source_count=0,
                confidence=0.0,
                confidence_level="UNKNOWN",
                is_analyst_verified=False,
                prior_observations=[],
                limitations=[
                    "Threat Memory service was temporarily unavailable during retrieval.",
                    "Historical context could not be evaluated; proceeding strictly with present forensic evidence.",
                    "CURRENT EVIDENCE > HISTORICAL MEMORY.",
                ],
            )

    # ========================================================================
    # 6. ENRICHMENT FOR ANALYSIS ORCHESTRATION & COPILOT
    # ========================================================================

    @classmethod
    def enrich_analysis_with_memory(
        cls,
        db: Session,
        workspace_id: str,
        indicators: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Enriches analysis findings/indicators with historical Threat Memory context.
        Strictly preserves Principle 1: memory enriches context, but DOES NOT overwrite
        or bypass current detector findings.
        """
        enriched = []
        for ind in indicators:
            val = ind.get("value")
            ind_type = ind.get("type") or ind.get("indicator_type")
            if not val:
                continue

            mem_ctx = cls.build_threat_memory_context(
                db,
                workspace_id,
                value_or_key=val,
                subject_type=ind_type,
                include_graph=False,
                max_observations=5,
            )

            enrichment_summary = {
                "indicator_value": val,
                "canonical_key": mem_ctx.canonical_key,
                "historical_seen": mem_ctx.observation_count > 0,
                "observation_count": mem_ctx.observation_count,
                "incident_count": len(mem_ctx.related_incidents),
                "is_analyst_verified": mem_ctx.is_analyst_verified,
                "is_conflicted": mem_ctx.conflict.is_conflicted,
                "conflict_summary": mem_ctx.conflict.explanation,
                "verification_status": mem_ctx.verification_status,
                "first_seen_at": mem_ctx.first_seen_at.isoformat() if mem_ctx.first_seen_at else None,
                "last_seen_at": mem_ctx.last_seen_at.isoformat() if mem_ctx.last_seen_at else None,
            }
            enriched.append(enrichment_summary)
        return enriched

    @classmethod
    def answer_historical_question(
        cls,
        db: Session,
        workspace_id: str,
        question_intent: str,
        value: str,
    ) -> Dict[str, Any]:
        """
        Generates evidence-backed answers for historical Copilot questions:
        - 'Have we seen this domain before?'
        - 'Has this file hash appeared in another investigation?'
        - 'Was this sender previously associated with phishing?'
        - 'Was this pattern previously marked as a false positive?'
        """
        mem_ctx = cls.build_threat_memory_context(db, workspace_id, value)
        seen = mem_ctx.observation_count > 0

        answer_text = ""
        if not seen:
            answer_text = f"CyberGuard has no prior recorded observations for '{value}' in workspace '{workspace_id}'."
        else:
            first_seen_str = mem_ctx.first_seen_at.strftime("%Y-%m-%d") if mem_ctx.first_seen_at else "Unknown"
            last_seen_str = mem_ctx.last_seen_at.strftime("%Y-%m-%d") if mem_ctx.last_seen_at else "Unknown"
            inc_count = len(mem_ctx.related_incidents)

            answer_text = (
                f"Yes, '{value}' has been observed {mem_ctx.observation_count} time(s) across "
                f"{mem_ctx.independent_source_count} independent investigation(s) / source(s). "
                f"First seen: {first_seen_str}, Last seen: {last_seen_str}. "
                f"Associated with {inc_count} incident(s)."
            )

            if mem_ctx.conflict.is_conflicted:
                answer_text += f" Note: {mem_ctx.conflict.explanation}"
            elif mem_ctx.is_analyst_verified:
                answer_text += f" Analyst verified as: {mem_ctx.verification_status}."

        return {
            "query_value": value,
            "seen_before": seen,
            "observation_count": mem_ctx.observation_count,
            "answer": answer_text,
            "memory_context": mem_ctx.model_dump() if hasattr(mem_ctx, "model_dump") else mem_ctx.dict(),
        }

    # ========================================================================
    # 7. OBSERVABILITY / STATS
    # ========================================================================

    @classmethod
    def get_memory_stats(cls, db: Session, workspace_id: str) -> ThreatMemoryStatsResponse:
        """
        Gathers Threat Memory operational counters for the workspace.
        """
        total_entries = db.query(ThreatMemoryEntryModel).filter(
            ThreatMemoryEntryModel.workspace_id == workspace_id
        ).count()

        total_obs = db.query(ThreatMemoryObservationModel).filter(
            ThreatMemoryObservationModel.workspace_id == workspace_id
        ).count()

        total_verified = db.query(ThreatMemoryEntryModel).filter(
            ThreatMemoryEntryModel.workspace_id == workspace_id,
            ThreatMemoryEntryModel.status == MemoryStatus.VERIFIED.value,
        ).count()

        total_fps = db.query(ThreatMemoryDecisionModel).filter(
            ThreatMemoryDecisionModel.workspace_id == workspace_id,
            ThreatMemoryDecisionModel.decision == AnalystDecisionType.FALSE_POSITIVE.value,
        ).count()

        # by type
        by_type_rows = db.query(
            ThreatMemoryEntryModel.memory_type, func.count(ThreatMemoryEntryModel.id)
        ).filter(
            ThreatMemoryEntryModel.workspace_id == workspace_id
        ).group_by(ThreatMemoryEntryModel.memory_type).all()
        by_type = {r[0]: r[1] for r in by_type_rows}

        # by status
        by_status_rows = db.query(
            ThreatMemoryEntryModel.status, func.count(ThreatMemoryEntryModel.id)
        ).filter(
            ThreatMemoryEntryModel.workspace_id == workspace_id
        ).group_by(ThreatMemoryEntryModel.status).all()
        by_status = {r[0]: r[1] for r in by_status_rows}

        return ThreatMemoryStatsResponse(
            workspace_id=workspace_id,
            total_memory_entries=total_entries,
            total_observations=total_obs,
            total_verified_entries=total_verified,
            total_conflicted_entries=0,
            total_false_positive_records=total_fps,
            by_type=by_type,
            by_status=by_status,
        )

    # ========================================================================
    # 8. AUDIT LOGGING HELPER
    # ========================================================================

    @classmethod
    def _log_audit(
        cls,
        db: Session,
        workspace_id: str,
        action: str,
        resource_id: str,
        details: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Appends immutable audit record to audit_logs (Section 23 Auditability).
        """
        try:
            audit = AuditLogModel(
                id=generate_uuid(),
                timestamp=get_utc_now(),
                user="ThreatMemoryService",
                action=action,
                resource_type="threat_memory",
                resource_id=resource_id,
                details=sanitize_log_text(details),
                metadata_json=json.dumps(metadata or {}),
            )
            db.add(audit)
            db.flush()
        except Exception as exc:
            logger.warning(f"Failed to record audit log for {action}: {exc}")
