"""
Novelty Detection & Emerging-Threat Identification Service (Section 22).

Core orchestrator evaluating pattern novelty, structural similarity, event sequence
unfamiliarity, multi-signal combination novelty, and emerging pattern recurrence.
Provides strict retention-boundary reasoning, poisoning prevention, and epistemic humility.
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc

from backend.config.novelty_config import DEFAULT_NOVELTY_CONFIG, NoveltyEngineConfig
from backend.db.models import (
    EmergingPatternCandidateModel,
    IncidentModel,
    NoveltyAssessmentModel,
    NoveltySuppressionRuleModel,
    PatternFingerprintModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.novelty_detection import (
    AssessmentStatus,
    BehaviorFamiliarityMatrix,
    ComparisonMethod,
    EmergingPatternCandidate,
    EmergingPatternStatus,
    NoveltyAssessment,
    NoveltyCategory,
    NoveltyEvaluationRequest,
    NoveltyEvaluationResponse,
    NoveltyInvestigationSummary,
    NoveltyLevel,
    NoveltySuppressionRule,
    PatternFingerprint,
    validate_novelty_privacy,
)
from backend.services.novelty_fingerprinter import NoveltyFingerprinter
from backend.services.novelty_metrics import novelty_metrics
from backend.services.novelty_similarity import NoveltySimilarityService

logger = logging.getLogger("cyberguard.novelty_service")


class NoveltyDetectionService:
    """
    Main orchestration service for Section 22 Novelty & Emerging-Threat Detection.
    """

    @classmethod
    def check_suppression(
        cls,
        session: Session,
        workspace_id: str,
        novelty_type: str,
        entity_type: str,
        entity_id: str,
        fingerprint_hash: Optional[str] = None,
    ) -> Optional[NoveltySuppressionRuleModel]:
        """
        Checks whether an active, valid contextual suppression rule applies.
        """
        now = datetime.now(timezone.utc)
        rules = session.query(NoveltySuppressionRuleModel).filter(
            NoveltySuppressionRuleModel.workspace_id == workspace_id,
            NoveltySuppressionRuleModel.valid_from <= now,
        ).all()

        for r in rules:
            if r.valid_until and r.valid_until < now:
                continue

            # Check pattern type match
            if r.pattern_type and r.pattern_type != novelty_type:
                continue

            # Check entity match
            if r.entity_type and r.entity_type != entity_type:
                continue
            if r.entity_id and r.entity_id.strip().lower() != entity_id.strip().lower():
                continue

            # Check fingerprint hash match
            if r.fingerprint_hash and fingerprint_hash and r.fingerprint_hash != fingerprint_hash:
                continue

            return r

        return None

    @classmethod
    def evaluate_pattern(
        cls,
        session: Session,
        request: NoveltyEvaluationRequest,
        config: NoveltyEngineConfig = DEFAULT_NOVELTY_CONFIG,
    ) -> NoveltyEvaluationResponse:
        """
        Evaluates the novelty of an observed pattern against retained telemetry.
        """
        workspace_id = request.workspace_id or "default"
        norm_entity_type = request.entity_type.strip().upper()
        norm_entity_id = request.entity_id.strip().lower()
        now = datetime.now(timezone.utc)

        # 1. Generate Deterministic Fingerprint
        fp_hash = None
        fp_repr = None
        clean_attrs = {}

        if request.novelty_type == NoveltyCategory.NOVEL_API_BEHAVIOR:
            method = request.attributes.get("method", "GET")
            path = request.attributes.get("path") or request.attributes.get("route_template", "/")
            res = request.attributes.get("resource_type")
            is_priv = bool(request.attributes.get("is_privileged", False))
            auth_ctx = request.attributes.get("auth_context", "AUTHENTICATED")
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_api_route(
                method=method, path=path, resource_type=res, is_privileged=is_priv, auth_context=auth_ctx
            )

        elif request.novelty_type == NoveltyCategory.NOVEL_URL_STRUCTURE:
            url = request.attributes.get("url", "http://example.com/")
            host_type = request.attributes.get("hostname_type", "DOMAIN")
            params = request.attributes.get("param_keys")
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_url_structure(
                url=url, hostname_type=host_type, query_param_keys=params
            )

        elif request.novelty_type == NoveltyCategory.NOVEL_DOMAIN_PATTERN:
            domain = request.attributes.get("domain", "")
            is_ip = bool(request.attributes.get("is_ip", False))
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_domain_pattern(
                domain=domain, is_ip=is_ip
            )

        elif request.novelty_type == NoveltyCategory.NOVEL_NETWORK_BEHAVIOR:
            dest_cat = request.attributes.get("destination_category", "EXTERNAL")
            port = int(request.attributes.get("port", 443))
            proto = request.attributes.get("protocol", "TCP")
            dir_str = request.attributes.get("direction", "OUTBOUND")
            bytes_vol = int(request.attributes.get("byte_volume", 1024))
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_network_behavior(
                destination_category=dest_cat, port=port, protocol=proto, direction=dir_str, byte_volume=bytes_vol
            )

        elif request.novelty_type == NoveltyCategory.NOVEL_AUTHENTICATION_PATTERN:
            auth_m = request.attributes.get("auth_method", "PASSWORD")
            src_net = request.attributes.get("source_network_class", "CORPORATE")
            mfa = bool(request.attributes.get("is_mfa", False))
            dev_cat = request.attributes.get("device_category", "MANAGED_WORKSTATION")
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_auth_pattern(
                auth_method=auth_m, source_network_class=src_net, is_mfa=mfa, device_category=dev_cat
            )

        elif request.novelty_type in (NoveltyCategory.NOVEL_ATTACK_SEQUENCE, NoveltyCategory.NOVEL_EVENT_COMBINATION) and request.event_sequence:
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_event_sequence(request.event_sequence)

        elif request.novelty_type == NoveltyCategory.NOVEL_ENTITY_RELATIONSHIP:
            src_t = request.attributes.get("source_type", norm_entity_type)
            rel_t = request.attributes.get("relationship_type", "ASSOCIATED_WITH")
            tgt_t = request.attributes.get("target_type", "UNKNOWN")
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_relationship(src_t, rel_t, tgt_t)

        else:
            # Fallback multi-signal combination
            fp_hash, fp_repr, clean_attrs = NoveltyFingerprinter.fingerprint_combination_tuple(request.attributes)

        # 2. Check Contextual Suppression
        suppression = cls.check_suppression(
            session=session,
            workspace_id=workspace_id,
            novelty_type=request.novelty_type.value,
            entity_type=norm_entity_type,
            entity_id=norm_entity_id,
            fingerprint_hash=fp_hash,
        )

        # 3. Query Retained Historical Fingerprints
        lookback_cutoff = now - timedelta(days=config.MAX_HISTORY_LOOKBACK_DAYS)
        historical_records = session.query(PatternFingerprintModel).filter(
            PatternFingerprintModel.workspace_id == workspace_id,
            PatternFingerprintModel.pattern_type == request.novelty_type.value,
            PatternFingerprintModel.last_seen_at >= lookback_cutoff,
        ).order_by(desc(PatternFingerprintModel.observation_count)).limit(config.MAX_SIMILARITY_CANDIDATES).all()

        historical_candidates = []
        for rec in historical_records:
            try:
                cand_attrs = json.loads(rec.attributes_json)
            except Exception:
                cand_attrs = {}
            historical_candidates.append({
                "fingerprint_hash": rec.fingerprint_hash,
                "fingerprint_repr": rec.fingerprint_repr,
                "attributes": cand_attrs,
                "observation_count": rec.observation_count,
            })

        # 4. Evaluate Structural & Distance Similarity
        novelty_score, similarity_score, novelty_level, nearest_repr = NoveltySimilarityService.evaluate_candidates(
            observed_attrs=clean_attrs,
            historical_candidates=historical_candidates,
            config=config,
        )

        # Check for poisoning protection
        is_quarantined = bool(request.attributes.get("quarantined", False))
        is_malicious = bool(request.attributes.get("is_malicious", False))
        is_poisoned = is_quarantined or is_malicious

        # 5. Handle Suppression Downgrade
        is_suppressed = suppression is not None
        suppression_details = None
        if is_suppressed:
            suppression_details = {
                "rule_id": suppression.id,
                "reason": suppression.reason,
                "approved_by": suppression.approved_by,
            }
            # Downgrade novelty to KNOWN with audit notice
            novelty_score = min(novelty_score, 0.05)
            novelty_level = NoveltyLevel.KNOWN

        # 6. Build Behavior-Familiarity Matrix (Section 4)
        if request.is_entity_anomalous:
            matrix_quadrant = BehaviorFamiliarityMatrix.UNUSUAL_NOVEL if novelty_score >= config.THRESHOLD_LOW else BehaviorFamiliarityMatrix.UNUSUAL_FAMILIAR
        else:
            matrix_quadrant = BehaviorFamiliarityMatrix.NORMAL_NOVEL if novelty_score >= config.THRESHOLD_LOW else BehaviorFamiliarityMatrix.NORMAL_FAMILIAR

        # 7. Update Fingerprint Registry (Only if NOT poisoned and NOT suppressed)
        existing_fp = session.query(PatternFingerprintModel).filter(
            PatternFingerprintModel.workspace_id == workspace_id,
            PatternFingerprintModel.pattern_type == request.novelty_type.value,
            PatternFingerprintModel.fingerprint_hash == fp_hash,
        ).first()

        if not is_poisoned:
            if existing_fp:
                existing_fp.last_seen_at = now
                existing_fp.observation_count += 1
                session.flush()
            else:
                new_fp = PatternFingerprintModel(
                    id=str(uuid.uuid4()),
                    workspace_id=workspace_id,
                    pattern_type=request.novelty_type.value,
                    fingerprint_hash=fp_hash,
                    fingerprint_repr=fp_repr,
                    attributes_json=json.dumps(clean_attrs),
                    first_seen_at=now,
                    last_seen_at=now,
                    observation_count=1,
                    entity_count=1,
                    incident_count=1 if request.incident_id else 0,
                    is_suppressed=is_suppressed,
                    suppression_reason=suppression.reason if suppression else None,
                )
                session.add(new_fp)
                session.flush()

        # 8. Detect & Evolve Emerging Pattern Candidate
        emerging_candidate = None
        if not is_suppressed:
            existing_candidate = session.query(EmergingPatternCandidateModel).filter(
                EmergingPatternCandidateModel.workspace_id == workspace_id,
                EmergingPatternCandidateModel.fingerprint_hash == fp_hash,
            ).first()

            if existing_candidate:
                existing_candidate.last_seen = now
                existing_candidate.observation_count += 1
                existing_candidate.entity_count += 1
                if request.incident_id:
                    existing_candidate.incident_count += 1

                # Calculate Recurrence Score
                rec_score = min(
                    100.0,
                    (existing_candidate.observation_count * 10) * config.EMERGING_RECURRENCE_WEIGHT_FREQ
                    + (existing_candidate.entity_count * 20) * config.EMERGING_RECURRENCE_WEIGHT_ENTITIES
                    + (existing_candidate.incident_count * 25) * config.EMERGING_RECURRENCE_WEIGHT_INCIDENTS
                )
                existing_candidate.recurrence_score = round(rec_score, 2)

                # Auto-transition status if recurrence threshold reached
                if (
                    existing_candidate.status == EmergingPatternStatus.OBSERVED.value
                    and existing_candidate.observation_count >= config.EMERGING_MIN_OBSERVATIONS
                    and (existing_candidate.entity_count >= config.EMERGING_MIN_ENTITIES or existing_candidate.incident_count >= config.EMERGING_MIN_INCIDENTS)
                ):
                    existing_candidate.status = EmergingPatternStatus.EMERGING.value
                    novelty_metrics.record_emerging_pattern(is_new=False)

                session.flush()
                emerging_candidate = EmergingPatternCandidate(
                    id=existing_candidate.id,
                    workspace_id=existing_candidate.workspace_id,
                    incident_id=existing_candidate.incident_id,
                    pattern_type=existing_candidate.pattern_type,
                    fingerprint_hash=existing_candidate.fingerprint_hash,
                    fingerprint_repr=existing_candidate.fingerprint_repr,
                    similarity_cluster=existing_candidate.similarity_cluster,
                    novelty_score=existing_candidate.novelty_score,
                    recurrence_score=existing_candidate.recurrence_score,
                    first_seen=existing_candidate.first_seen,
                    last_seen=existing_candidate.last_seen,
                    observation_count=existing_candidate.observation_count,
                    entity_count=existing_candidate.entity_count,
                    incident_count=existing_candidate.incident_count,
                    supporting_evidence=json.loads(existing_candidate.supporting_evidence_json or "[]"),
                    status=EmergingPatternStatus(existing_candidate.status),
                    created_at=existing_candidate.created_at,
                    updated_at=existing_candidate.updated_at,
                )
            elif novelty_level in (NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH, NoveltyLevel.MODERATE):
                # Create initial candidate
                cand_id = str(uuid.uuid4())
                cand_evidence = [{
                    "observed_at": now.isoformat(),
                    "entity_type": norm_entity_type,
                    "entity_id": norm_entity_id,
                    "incident_id": request.incident_id,
                    "fingerprint": fp_repr,
                }]
                new_candidate_model = EmergingPatternCandidateModel(
                    id=cand_id,
                    workspace_id=workspace_id,
                    incident_id=request.incident_id,
                    pattern_type=request.novelty_type.value,
                    fingerprint_hash=fp_hash,
                    fingerprint_repr=fp_repr,
                    novelty_score=novelty_score,
                    recurrence_score=10.0,
                    first_seen=now,
                    last_seen=now,
                    observation_count=1,
                    entity_count=1,
                    incident_count=1 if request.incident_id else 0,
                    supporting_evidence_json=json.dumps(cand_evidence),
                    status=EmergingPatternStatus.OBSERVED.value,
                    created_at=now,
                    updated_at=now,
                )
                session.add(new_candidate_model)
                session.flush()
                novelty_metrics.record_emerging_pattern(is_new=True)

                emerging_candidate = EmergingPatternCandidate(
                    id=cand_id,
                    workspace_id=workspace_id,
                    incident_id=request.incident_id,
                    pattern_type=request.novelty_type.value,
                    fingerprint_hash=fp_hash,
                    fingerprint_repr=fp_repr,
                    novelty_score=novelty_score,
                    recurrence_score=10.0,
                    first_seen=now,
                    last_seen=now,
                    observation_count=1,
                    entity_count=1,
                    incident_count=1 if request.incident_id else 0,
                    supporting_evidence=cand_evidence,
                    status=EmergingPatternStatus.OBSERVED,
                    created_at=now,
                    updated_at=now,
                )

        # 9. Build Evidence & Limitations
        supporting_ev = []
        contradicting_ev = []
        limitations = [
            f"Evaluated against retained telemetry window ({config.MAX_HISTORY_LOOKBACK_DAYS} days). Historical patterns preceding this window were not evaluated.",
            "Novelty score reflects structural and feature distance, NOT malicious intent or compromise probability.",
        ]

        if novelty_level in (NoveltyLevel.HIGH, NoveltyLevel.VERY_HIGH):
            supporting_ev.append({
                "type": "RETAINED_HISTORY_ABSENCE",
                "description": f"Pattern not observed in retained telemetry during the previous {config.MAX_HISTORY_LOOKBACK_DAYS} days.",
                "fingerprint_repr": fp_repr,
                "similarity_to_nearest": similarity_score,
            })
        else:
            contradicting_ev.append({
                "type": "HISTORICAL_SIMILARITY",
                "description": f"Observed pattern closely matches existing retained pattern ({nearest_repr}).",
                "similarity_score": similarity_score,
            })

        if is_poisoned:
            contradicting_ev.append({
                "type": "POISONING_SAFEGUARD_ACTIVE",
                "description": "Observed activity has high-confidence malicious or quarantined flags; excluded from baseline familiar library.",
            })

        if is_suppressed:
            contradicting_ev.append({
                "type": "CONTEXTUAL_SUPPRESSION",
                "description": f"Pattern suppressed by rule approved by {suppression.approved_by}: {suppression.reason}",
            })

        # 10. Persist NoveltyAssessmentModel
        assessment_id = str(uuid.uuid4())
        assessment_model = NoveltyAssessmentModel(
            id=assessment_id,
            workspace_id=workspace_id,
            incident_id=request.incident_id,
            investigation_id=request.incident_id,
            entity_type=norm_entity_type,
            entity_id=norm_entity_id,
            novelty_type=request.novelty_type.value,
            novelty_score=novelty_score,
            novelty_level=novelty_level.value,
            similarity_score=similarity_score,
            historical_sample_count=len(historical_records),
            comparison_window=f"{config.MAX_HISTORY_LOOKBACK_DAYS}_DAYS",
            behavior_familiarity_matrix=matrix_quadrant.value,
            feature_version=config.FEATURE_VERSION,
            baseline_version=config.ENGINE_VERSION,
            status=AssessmentStatus.SUPPRESSED.value if is_suppressed else AssessmentStatus.ACTIVE.value,
            fingerprint_hash=fp_hash,
            fingerprint_repr=fp_repr,
            supporting_evidence_json=json.dumps(supporting_ev),
            contradicting_evidence_json=json.dumps(contradicting_ev),
            limitations_json=json.dumps(limitations),
            threat_assessment_note="Novelty represents technical unfamiliarity within retained telemetry and does not constitute independent evidence of malicious compromise.",
            engine_version=config.ENGINE_VERSION,
            created_at=now,
        )
        session.add(assessment_model)
        session.flush()

        novelty_metrics.record_assessment(is_novel=(novelty_score >= config.THRESHOLD_LOW))

        assessment = NoveltyAssessment(
            id=assessment_id,
            workspace_id=workspace_id,
            incident_id=request.incident_id,
            investigation_id=request.incident_id,
            entity_type=norm_entity_type,
            entity_id=norm_entity_id,
            novelty_type=request.novelty_type,
            novelty_score=novelty_score,
            novelty_level=novelty_level,
            similarity_score=similarity_score,
            historical_sample_count=len(historical_records),
            comparison_window=f"{config.MAX_HISTORY_LOOKBACK_DAYS}_DAYS",
            behavior_familiarity_matrix=matrix_quadrant,
            feature_version=config.FEATURE_VERSION,
            baseline_version=config.ENGINE_VERSION,
            status=AssessmentStatus.SUPPRESSED if is_suppressed else AssessmentStatus.ACTIVE,
            fingerprint_hash=fp_hash,
            fingerprint_repr=fp_repr,
            supporting_evidence=supporting_ev,
            contradicting_evidence=contradicting_ev,
            limitations=limitations,
            threat_assessment_note=assessment_model.threat_assessment_note,
            engine_version=config.ENGINE_VERSION,
            created_at=now,
        )

        return NoveltyEvaluationResponse(
            assessment=assessment,
            emerging_candidate=emerging_candidate,
            is_suppressed=is_suppressed,
            suppression_details=suppression_details,
        )

    # ------------------------------------------------------------------------
    # Investigation & Entity Query Methods
    # ------------------------------------------------------------------------
    @classmethod
    def get_investigation_novelty(
        cls,
        session: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> NoveltyInvestigationSummary:
        """Retrieves all novelty assessments and emerging pattern candidates for an incident."""
        records = session.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.workspace_id == workspace_id,
            NoveltyAssessmentModel.incident_id == incident_id,
        ).order_by(desc(NoveltyAssessmentModel.novelty_score)).all()

        assessments: List[NoveltyAssessment] = []
        high_novelty_count = 0
        novel_count = 0

        for r in records:
            a = cls._model_to_schema(r)
            assessments.append(a)
            if a.novelty_score >= 0.40:
                novel_count += 1
            if a.novelty_score >= 0.70:
                high_novelty_count += 1

        emerging_records = session.query(EmergingPatternCandidateModel).filter(
            EmergingPatternCandidateModel.workspace_id == workspace_id,
            EmergingPatternCandidateModel.incident_id == incident_id,
        ).all()

        emerging_patterns = [cls._candidate_model_to_schema(c) for c in emerging_records]

        return NoveltyInvestigationSummary(
            investigation_id=incident_id,
            incident_id=incident_id,
            total_assessments=len(assessments),
            novel_assessments_count=novel_count,
            high_novelty_count=high_novelty_count,
            assessments=assessments,
            emerging_patterns=emerging_patterns,
            limitations=[
                f"Evaluated against retained telemetry window ({DEFAULT_NOVELTY_CONFIG.MAX_HISTORY_LOOKBACK_DAYS} days).",
                "Novelty alone does not establish malicious intent or compromise.",
            ],
            retention_window=f"{DEFAULT_NOVELTY_CONFIG.MAX_HISTORY_LOOKBACK_DAYS}_DAYS",
        )

    @classmethod
    def get_investigation_patterns(
        cls,
        session: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> List[NoveltyAssessment]:
        """Retrieves structural pattern assessments for an incident."""
        records = session.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.workspace_id == workspace_id,
            NoveltyAssessmentModel.incident_id == incident_id,
            NoveltyAssessmentModel.novelty_type.in_([
                NoveltyCategory.NOVEL_API_BEHAVIOR.value,
                NoveltyCategory.NOVEL_URL_STRUCTURE.value,
                NoveltyCategory.NOVEL_DOMAIN_PATTERN.value,
                NoveltyCategory.NOVEL_AUTHENTICATION_PATTERN.value,
            ]),
        ).all()
        return [cls._model_to_schema(r) for r in records]

    @classmethod
    def get_investigation_sequences(
        cls,
        session: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> List[NoveltyAssessment]:
        """Retrieves sequence and combination novelty assessments for an incident."""
        records = session.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.workspace_id == workspace_id,
            NoveltyAssessmentModel.incident_id == incident_id,
            NoveltyAssessmentModel.novelty_type.in_([
                NoveltyCategory.NOVEL_ATTACK_SEQUENCE.value,
                NoveltyCategory.NOVEL_EVENT_COMBINATION.value,
            ]),
        ).all()
        return [cls._model_to_schema(r) for r in records]

    @classmethod
    def get_investigation_infrastructure(
        cls,
        session: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> List[NoveltyAssessment]:
        """Retrieves infrastructure and network novelty assessments for an incident."""
        records = session.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.workspace_id == workspace_id,
            NoveltyAssessmentModel.incident_id == incident_id,
            NoveltyAssessmentModel.novelty_type.in_([
                NoveltyCategory.NOVEL_NETWORK_BEHAVIOR.value,
                NoveltyCategory.NOVEL_INFRASTRUCTURE_RELATIONSHIP.value,
                NoveltyCategory.NOVEL_DOMAIN_PATTERN.value,
            ]),
        ).all()
        return [cls._model_to_schema(r) for r in records]

    @classmethod
    def get_investigation_emerging_patterns(
        cls,
        session: Session,
        incident_id: str,
        workspace_id: str = "default",
    ) -> List[EmergingPatternCandidate]:
        """Retrieves emerging pattern candidates for an incident."""
        records = session.query(EmergingPatternCandidateModel).filter(
            EmergingPatternCandidateModel.workspace_id == workspace_id,
            EmergingPatternCandidateModel.incident_id == incident_id,
        ).all()
        return [cls._candidate_model_to_schema(r) for r in records]

    @classmethod
    def get_entity_novelty(
        cls,
        session: Session,
        entity_id: str,
        workspace_id: str = "default",
    ) -> List[NoveltyAssessment]:
        """Retrieves all novelty assessments for a specific entity."""
        records = session.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.workspace_id == workspace_id,
            NoveltyAssessmentModel.entity_id == entity_id.strip().lower(),
        ).order_by(desc(NoveltyAssessmentModel.created_at)).all()
        return [cls._model_to_schema(r) for r in records]

    @classmethod
    def transition_emerging_pattern_status(
        cls,
        session: Session,
        pattern_id: str,
        actor: str,
        new_status: EmergingPatternStatus,
        reason: str,
        workspace_id: str = "default",
    ) -> EmergingPatternCandidate:
        """Transitions lifecycle state of an emerging pattern candidate with audit tracking."""
        record = session.query(EmergingPatternCandidateModel).filter(
            EmergingPatternCandidateModel.workspace_id == workspace_id,
            EmergingPatternCandidateModel.id == pattern_id,
        ).first()

        if not record:
            raise ValueError(f"Emerging pattern candidate {pattern_id} not found in workspace {workspace_id}")

        record.status = new_status.value
        record.updated_at = datetime.now(timezone.utc)

        # Append audit to supporting evidence
        ev_list = json.loads(record.supporting_evidence_json or "[]")
        ev_list.append({
            "action": "STATUS_TRANSITION",
            "actor": actor,
            "new_status": new_status.value,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        record.supporting_evidence_json = json.dumps(ev_list)
        session.flush()

        return cls._candidate_model_to_schema(record)

    @classmethod
    def register_suppression_rule(
        cls,
        session: Session,
        rule: NoveltySuppressionRule,
    ) -> NoveltySuppressionRuleModel:
        """Registers an auditable contextual exception rule suppressing benign novelty."""
        model = NoveltySuppressionRuleModel(
            id=rule.id,
            workspace_id=rule.workspace_id,
            pattern_type=rule.pattern_type,
            entity_type=rule.entity_type,
            entity_id=rule.entity_id,
            fingerprint_hash=rule.fingerprint_hash,
            reason=rule.reason,
            approved_by=rule.approved_by,
            valid_from=rule.valid_from,
            valid_until=rule.valid_until,
            created_at=datetime.now(timezone.utc),
        )
        session.add(model)
        session.flush()
        return model

    # ------------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------------
    @classmethod
    def _model_to_schema(cls, m: NoveltyAssessmentModel) -> NoveltyAssessment:
        return NoveltyAssessment(
            id=m.id,
            workspace_id=m.workspace_id,
            incident_id=m.incident_id,
            investigation_id=m.investigation_id,
            entity_type=m.entity_type,
            entity_id=m.entity_id,
            novelty_type=NoveltyCategory(m.novelty_type),
            novelty_score=m.novelty_score,
            novelty_level=NoveltyLevel(m.novelty_level),
            similarity_score=m.similarity_score,
            historical_sample_count=m.historical_sample_count,
            comparison_window=m.comparison_window,
            behavior_familiarity_matrix=BehaviorFamiliarityMatrix(m.behavior_familiarity_matrix),
            feature_version=m.feature_version,
            baseline_version=m.baseline_version,
            status=AssessmentStatus(m.status),
            fingerprint_hash=m.fingerprint_hash,
            fingerprint_repr=m.fingerprint_repr,
            supporting_evidence=json.loads(m.supporting_evidence_json or "[]"),
            contradicting_evidence=json.loads(m.contradicting_evidence_json or "[]"),
            limitations=json.loads(m.limitations_json or "[]"),
            threat_assessment_note=m.threat_assessment_note,
            engine_version=m.engine_version,
            created_at=m.created_at,
        )

    @classmethod
    def _candidate_model_to_schema(cls, m: EmergingPatternCandidateModel) -> EmergingPatternCandidate:
        return EmergingPatternCandidate(
            id=m.id,
            workspace_id=m.workspace_id,
            incident_id=m.incident_id,
            pattern_type=m.pattern_type,
            fingerprint_hash=m.fingerprint_hash,
            fingerprint_repr=m.fingerprint_repr,
            similarity_cluster=m.similarity_cluster,
            novelty_score=m.novelty_score,
            recurrence_score=m.recurrence_score,
            first_seen=m.first_seen,
            last_seen=m.last_seen,
            observation_count=m.observation_count,
            entity_count=m.entity_count,
            incident_count=m.incident_count,
            supporting_evidence=json.loads(m.supporting_evidence_json or "[]"),
            status=EmergingPatternStatus(m.status),
            created_at=m.created_at,
            updated_at=m.updated_at,
        )
