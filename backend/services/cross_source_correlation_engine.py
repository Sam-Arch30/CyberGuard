"""
Section 61: Cross-Source Correlation & Unified Entity Correlation Engine.
Connects signals across Email, Endpoint, Network, Authentication, API, Behavioral Anomaly,
AST Detection Rules, Threat Intelligence, and IOC Watchlists into explainable, evidence-backed
correlations and composite security findings without double-counting evidence.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from backend.db.models import (
    CrossSourceCorrelationModel,
    CorrelationMemberModel,
    EntityModel,
    FindingModel,
    FindingEvidenceModel,
    SecurityEventModel,
    EndpointTelemetryEventModel,
    ThreatEventModel,
    NotificationModel,
    IncidentModel,
    CampaignModel,
    BehavioralDeviationModel,
    BehaviorProfileModel,
    DetectionMatchModel,
    WatchedIndicatorModel,
    ThreatIntelligenceRecordModel,
    AuditLogModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.cross_source_correlation import (
    CorrelationTypeEnum,
    CorrelationStatusEnum,
    CorrelationConfidenceEnum,
    MemberTypeEnum,
    SourceTypeEnum,
    CorrelationSignal,
    CrossSourceCorrelationRead,
    CrossSourceCorrelationDetail,
    CorrelationMemberRead,
    CorrelationTimelineItem,
    WhyCorrelatedExplanation,
    CorrelationDispositionRequest,
    CorrelationOverviewStats,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    RelationshipOrigin,
    make_canonical_key,
)
from backend.schemas.realtime import (
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.security_graph_service import SecurityGraphService
from backend.services.unified_entity_resolver import UnifiedEntityResolver
from backend.services.realtime_service import RealtimePublisher
from backend.services.notification_service import NotificationService

logger = logging.getLogger("cyberguard.cross_source_correlation")

RULE_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"
DEFAULT_WINDOW_SECONDS = 1800.0  # 30 minutes default
MAX_CORRELATION_MEMBERS = 100


class CrossSourceCorrelationEngine:
    """
    Authoritative correlation coordinator connecting heterogeneous telemetry
    into deterministic, explainable, and multi-tenant isolated cross-source attack patterns.
    """

    # =========================================================================
    # 1. SIGNAL NORMALIZATION
    # =========================================================================

    @classmethod
    def normalize_signal_from_finding(cls, finding: FindingModel) -> CorrelationSignal:
        """
        Normalizes a structured analytical Finding into a CorrelationSignal.
        """
        analyzer = (finding.analyzer or "").lower()
        if "endpoint" in analyzer or "edr" in analyzer:
            src_type = SourceTypeEnum.ENDPOINT
        elif "auth" in analyzer or "identity" in analyzer:
            src_type = SourceTypeEnum.AUTH
        elif "network" in analyzer:
            src_type = SourceTypeEnum.NETWORK
        elif "api" in analyzer:
            src_type = SourceTypeEnum.API
        elif "behavior" in analyzer:
            src_type = SourceTypeEnum.BEHAVIORAL
        elif "rule" in analyzer or "ast" in analyzer or "detection" in analyzer:
            src_type = SourceTypeEnum.DETECTION_RULE
        elif "threat_intel" in analyzer or "intel" in analyzer:
            src_type = SourceTypeEnum.THREAT_INTEL
        elif "watchlist" in analyzer:
            src_type = SourceTypeEnum.WATCHLIST
        elif "email" in analyzer or "phishing" in analyzer:
            src_type = SourceTypeEnum.EMAIL
        else:
            src_type = SourceTypeEnum.GENERIC

        details = finding.details or {}
        entity_refs = details.get("entity_ids", [])
        if not entity_refs:
            for k in ("user_id", "endpoint_id", "device_id", "ip", "domain", "account_id"):
                if details.get(k):
                    entity_refs.append(str(details[k]))

        ev_refs = [e.id for e in (finding.evidence_items or [])]
        indicator_refs = details.get("indicators", [])

        return CorrelationSignal(
            signal_id=f"sig-find-{finding.id}",
            workspace_id=finding.workspace_id,
            source_type=src_type,
            source_id=finding.id,
            signal_type=finding.finding_type,
            entity_refs=entity_refs,
            finding_refs=[finding.id],
            indicator_refs=indicator_refs,
            evidence_refs=ev_refs,
            occurred_at=finding.created_at,
            received_at=finding.created_at,
            processed_at=finding.created_at,
            severity=finding.severity,
            confidence=finding.confidence,
            metadata=details,
        )

    # =========================================================================
    # 2. DETERMINISTIC CROSS-SOURCE CORRELATION LOGIC
    # =========================================================================

    @classmethod
    def evaluate_cross_source_correlation(
        cls,
        db: Session,
        workspace_id: str = "default",
        entity_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        incident_id: Optional[str] = None,
        window_seconds: float = DEFAULT_WINDOW_SECONDS,
    ) -> List[CrossSourceCorrelationModel]:
        """
        Executes bounded, deterministic cross-source correlation analysis.
        Identifies multi-source attack chains, shared infrastructure, and composite patterns.
        """
        now = get_utc_now()
        since = now - timedelta(seconds=max(300.0, window_seconds))

        created_correlations: List[CrossSourceCorrelationModel] = []

        # Correlator 1: Shared Infrastructure & Attack Sequences (Email + URL + Domain + IP + Endpoint)
        c1 = cls._correlate_shared_infrastructure_sequence(db, workspace_id, since, now, window_seconds, entity_id, finding_id)
        if c1:
            created_correlations.extend(c1)

        # Correlator 2: Authentication + Endpoint Activity
        c2 = cls._correlate_auth_and_endpoint(db, workspace_id, since, now, window_seconds, entity_id)
        if c2:
            created_correlations.extend(c2)

        # Correlator 3: Behavioral Anomaly + AST Detection Rule Match
        c3 = cls._correlate_behavioral_and_rule_detection(db, workspace_id, since, now, window_seconds, entity_id)
        if c3:
            created_correlations.extend(c3)

        # Correlator 4: Watchlist IOC + Ingested Telemetry
        c4 = cls._correlate_watchlist_and_observation(db, workspace_id, since, now, window_seconds)
        if c4:
            created_correlations.extend(c4)

        return created_correlations

    @classmethod
    def _correlate_shared_infrastructure_sequence(
        cls,
        db: Session,
        workspace_id: str,
        since: datetime,
        now: datetime,
        window_seconds: float,
        filter_entity_id: Optional[str] = None,
        filter_finding_id: Optional[str] = None,
    ) -> List[CrossSourceCorrelationModel]:
        """
        Identifies chains connecting Email findings (containing URLs/domains) with
        network connections, endpoint processes, or threat intelligence hits.
        """
        correlations: List[CrossSourceCorrelationModel] = []

        # Find candidate email findings
        q_email = db.query(FindingModel).filter(
            FindingModel.workspace_id == workspace_id,
            FindingModel.created_at >= since,
            or_(
                FindingModel.analyzer.ilike("%email%"),
                FindingModel.analyzer.ilike("%phish%"),
                FindingModel.source_type == "EMAIL"
            )
        )
        if filter_finding_id:
            q_email = q_email.filter(FindingModel.id == filter_finding_id)

        email_findings = q_email.limit(20).all()

        for ef in email_findings:
            ef_details = ef.details
            extracted_indicators = ef_details.get("indicators", []) or []
            if not extracted_indicators and ef.evidence_items:
                extracted_indicators = [
                    ev.value for ev in ef.evidence_items
                    if ev.evidence_type in ("DOMAIN", "URL", "IP", "LINK", "HOST")
                ]

            if not extracted_indicators:
                continue

            # Look for endpoint or network findings referencing the same indicators or resolved entities
            q_endpoint = db.query(FindingModel).filter(
                FindingModel.workspace_id == workspace_id,
                FindingModel.created_at >= since,
                FindingModel.id != ef.id,
                or_(
                    FindingModel.analyzer.ilike("%endpoint%"),
                    FindingModel.analyzer.ilike("%network%"),
                    FindingModel.analyzer.ilike("%auth%")
                )
            )

            endpoint_findings = q_endpoint.limit(30).all()

            for ep in endpoint_findings:
                ep_details = ep.details
                ep_indicators = ep_details.get("indicators", []) or []
                if not ep_indicators and ep.evidence_items:
                    ep_indicators = [
                        ev.value for ev in ep.evidence_items
                        if ev.evidence_type in ("DOMAIN", "URL", "IP", "DEST_IP", "HOST")
                    ]

                shared = set(extracted_indicators).intersection(set(ep_indicators))
                # Also check raw evidence string matches
                if not shared and ep.evidence_items:
                    for ev in ep.evidence_items:
                        for target in extracted_indicators:
                            if target and (target.lower() in ev.value.lower()):
                                shared.add(target)

                if shared:
                    # Deterministic match! Correlate Email with Endpoint
                    shared_list = sorted(list(shared))
                    time_diff = abs((ep.created_at - ef.created_at).total_seconds())

                    # Check temporal window bounds
                    if time_diff > window_seconds:
                        continue

                    # Distinct correlation type: TEMPORAL_ATTACK_SEQUENCE if email preceded endpoint, else SHARED_INFRASTRUCTURE
                    if ef.created_at <= ep.created_at:
                        corr_type = CorrelationTypeEnum.TEMPORAL_ATTACK_SEQUENCE
                        title = f"Phishing Email to Endpoint Execution Sequence: {shared_list[0]}"
                        desc_text = (
                            f"Phishing email observation (Finding {ef.id[:8]}) containing indicator '{shared_list[0]}' "
                            f"preceded endpoint/network activity (Finding {ep.id[:8]}) by {int(time_diff / 60)} minutes."
                        )
                    else:
                        corr_type = CorrelationTypeEnum.SHARED_INFRASTRUCTURE
                        title = f"Shared Infrastructure between Email & Host Telemetry: {shared_list[0]}"
                        desc_text = (
                            f"Email finding and endpoint activity independently observed the same infrastructure '{shared_list[0]}' "
                            f"within {int(time_diff / 60)} minutes."
                        )

                    reasons = [
                        f"Shared infrastructure observable: {', '.join(shared_list[:3])}",
                        f"Events occurred within temporal proximity of {int(time_diff / 60)} minutes (Budget: {int(window_seconds / 60)}m)",
                        f"Confirmed multi-source evidence: Email finding ({ef.id[:8]}) and Host finding ({ep.id[:8]})",
                    ]

                    # Build member items
                    members_payload = [
                        {"type": MemberTypeEnum.FINDING, "id": ef.id, "source": SourceTypeEnum.EMAIL, "role": "PRIMARY", "occurred_at": ef.created_at},
                        {"type": MemberTypeEnum.FINDING, "id": ep.id, "source": SourceTypeEnum.ENDPOINT, "role": "SUPPORTING", "occurred_at": ep.created_at},
                    ]
                    for ind in shared_list[:3]:
                        members_payload.append({"type": MemberTypeEnum.INDICATOR, "id": ind, "source": SourceTypeEnum.GENERIC, "role": "OBSERVED", "occurred_at": ef.created_at})

                    # Evidence references
                    ev_refs = [e.id for e in (ef.evidence_items or [])] + [e.id for e in (ep.evidence_items or [])]

                    corr = cls._create_or_update_correlation(
                        db=db,
                        workspace_id=workspace_id,
                        correlation_type=corr_type,
                        title=title,
                        description=desc_text,
                        confidence_score=0.92,
                        confidence_level=CorrelationConfidenceEnum.HIGH,
                        child_findings=[ef, ep],
                        members_payload=members_payload,
                        supporting_reasons=reasons,
                        first_observed_at=min(ef.created_at, ep.created_at),
                        last_observed_at=max(ef.created_at, ep.created_at),
                        time_window_seconds=time_diff,
                        evidence_refs=ev_refs,
                    )
                    correlations.append(corr)

        return correlations

    @classmethod
    def _correlate_auth_and_endpoint(
        cls,
        db: Session,
        workspace_id: str,
        since: datetime,
        now: datetime,
        window_seconds: float,
        filter_entity_id: Optional[str] = None,
    ) -> List[CrossSourceCorrelationModel]:
        """
        Correlates suspicious authentication attempts with concurrent endpoint executions on the same user/account.
        """
        correlations: List[CrossSourceCorrelationModel] = []

        q_auth = db.query(FindingModel).filter(
            FindingModel.workspace_id == workspace_id,
            FindingModel.created_at >= since,
            or_(
                FindingModel.analyzer.ilike("%auth%"),
                FindingModel.source_type == "AUTH",
                FindingModel.finding_type.ilike("%AUTH%")
            )
        )
        auth_findings = q_auth.limit(15).all()

        for af in auth_findings:
            af_details = af.details
            user_id = af_details.get("user_id") or af_details.get("username") or af_details.get("account_id")
            if not user_id:
                continue

            if filter_entity_id and str(user_id).lower() != filter_entity_id.lower():
                continue

            # Look for endpoint activity referencing the same user/account
            q_ep = db.query(FindingModel).filter(
                FindingModel.workspace_id == workspace_id,
                FindingModel.created_at >= since,
                FindingModel.id != af.id,
                or_(
                    FindingModel.analyzer.ilike("%endpoint%"),
                    FindingModel.source_type == "ENDPOINT"
                )
            )
            endpoint_findings = q_ep.limit(20).all()

            for ep in endpoint_findings:
                ep_details = ep.details
                ep_user = ep_details.get("user_id") or ep_details.get("username") or ep_details.get("user")
                ep_host = ep_details.get("endpoint_id") or ep_details.get("host_id") or ep_details.get("device_id")

                if ep_user and str(ep_user).lower() == str(user_id).lower():
                    time_diff = abs((ep.created_at - af.created_at).total_seconds())
                    if time_diff > window_seconds:
                        continue

                    title = f"Authentication & Host Activity Correlation: User {user_id}"
                    desc_text = (
                        f"Authentication event (Finding {af.id[:8]}) and host process execution (Finding {ep.id[:8]}) "
                        f"occurred for user '{user_id}' on endpoint '{ep_host or 'N/A'}' within {int(time_diff / 60)} minutes."
                    )
                    reasons = [
                        f"Deterministic identity resolution: User '{user_id}' verified on both identity and endpoint telemetry",
                        f"Temporal sequence occurred within {int(time_diff / 60)} minutes",
                        f"Multi-source corroboration between Identity Provider and EDR agent",
                    ]

                    members_payload = [
                        {"type": MemberTypeEnum.FINDING, "id": af.id, "source": SourceTypeEnum.AUTH, "role": "PRIMARY", "occurred_at": af.created_at},
                        {"type": MemberTypeEnum.FINDING, "id": ep.id, "source": SourceTypeEnum.ENDPOINT, "role": "SUPPORTING", "occurred_at": ep.created_at},
                        {"type": MemberTypeEnum.ENTITY, "id": str(user_id), "source": SourceTypeEnum.AUTH, "role": "PIVOT", "occurred_at": af.created_at},
                    ]
                    if ep_host:
                        members_payload.append({"type": MemberTypeEnum.ENTITY, "id": str(ep_host), "source": SourceTypeEnum.ENDPOINT, "role": "OBSERVED", "occurred_at": ep.created_at})

                    ev_refs = [e.id for e in (af.evidence_items or [])] + [e.id for e in (ep.evidence_items or [])]

                    corr = cls._create_or_update_correlation(
                        db=db,
                        workspace_id=workspace_id,
                        correlation_type=CorrelationTypeEnum.AUTH_AND_ENDPOINT,
                        title=title,
                        description=desc_text,
                        confidence_score=0.88,
                        confidence_level=CorrelationConfidenceEnum.HIGH,
                        child_findings=[af, ep],
                        members_payload=members_payload,
                        supporting_reasons=reasons,
                        first_observed_at=min(af.created_at, ep.created_at),
                        last_observed_at=max(af.created_at, ep.created_at),
                        time_window_seconds=time_diff,
                        evidence_refs=ev_refs,
                    )
                    correlations.append(corr)

        return correlations

    @classmethod
    def _correlate_behavioral_and_rule_detection(
        cls,
        db: Session,
        workspace_id: str,
        since: datetime,
        now: datetime,
        window_seconds: float,
        filter_entity_id: Optional[str] = None,
    ) -> List[CrossSourceCorrelationModel]:
        """
        Correlates Section 60 behavioral deviations with Section 56/59 detection rule matches
        occurring on the same entity.
        """
        correlations: List[CrossSourceCorrelationModel] = []

        q_deviations = db.query(BehavioralDeviationModel).filter(
            BehavioralDeviationModel.workspace_id == workspace_id,
            BehavioralDeviationModel.created_at >= since,
        )
        if filter_entity_id:
            q_deviations = q_deviations.filter(BehavioralDeviationModel.entity_id == filter_entity_id)

        deviations = q_deviations.limit(15).all()

        for dev in deviations:
            # Query detection matches for the same entity in the same window
            q_matches = db.query(DetectionMatchModel).filter(
                DetectionMatchModel.workspace_id == workspace_id,
                DetectionMatchModel.created_at >= since,
            )
            matches = q_matches.limit(20).all()

            for match in matches:
                ev = match.evidence or {}
                prov = match.provenance or {}
                matched_entity = ev.get("entity_id") or ev.get("user_id") or ev.get("endpoint_id") or prov.get("entity_id")

                if matched_entity and str(matched_entity).lower() == dev.entity_id.lower():
                    time_diff = abs((match.created_at - dev.created_at).total_seconds())
                    if time_diff > window_seconds:
                        continue

                    title = f"Behavioral Anomaly Correlated with Rule Match: {dev.entity_id}"
                    desc_text = (
                        f"Entity '{dev.entity_id}' exhibited behavioral anomaly '{dev.metric_type}' (Score: {dev.deviation_score:.2f}) "
                        f"concurrently with AST detection rule '{match.rule_id}' match within {int(time_diff / 60)} minutes."
                    )
                    reasons = [
                        f"Co-occurrence on entity: {dev.entity_id}",
                        f"Behavioral baseline deviation: {dev.metric_type} (Observed: {dev.observed_value}, Expected: {dev.expected_range_summary})",
                        f"AST rule trigger: {match.rule_id}",
                    ]

                    # Find finding if linked
                    child_findings: List[FindingModel] = []
                    if dev.finding_id:
                        f_dev = db.query(FindingModel).filter(FindingModel.id == dev.finding_id).first()
                        if f_dev:
                            child_findings.append(f_dev)
                    if match.finding_id:
                        f_match = db.query(FindingModel).filter(FindingModel.id == match.finding_id).first()
                        if f_match:
                            child_findings.append(f_match)

                    members_payload = [
                        {"type": MemberTypeEnum.SIGNAL, "id": dev.id, "source": SourceTypeEnum.BEHAVIORAL, "role": "PRIMARY", "occurred_at": dev.created_at},
                        {"type": MemberTypeEnum.FINDING, "id": match.id, "source": SourceTypeEnum.DETECTION_RULE, "role": "SUPPORTING", "occurred_at": match.created_at},
                        {"type": MemberTypeEnum.ENTITY, "id": dev.entity_id, "source": SourceTypeEnum.BEHAVIORAL, "role": "PIVOT", "occurred_at": dev.created_at},
                    ]

                    corr = cls._create_or_update_correlation(
                        db=db,
                        workspace_id=workspace_id,
                        correlation_type=CorrelationTypeEnum.BEHAVIORAL_AND_RULE_DETECTION,
                        title=title,
                        description=desc_text,
                        confidence_score=0.90,
                        confidence_level=CorrelationConfidenceEnum.HIGH,
                        child_findings=child_findings,
                        members_payload=members_payload,
                        supporting_reasons=reasons,
                        first_observed_at=min(dev.created_at, match.created_at),
                        last_observed_at=max(dev.created_at, match.created_at),
                        time_window_seconds=time_diff,
                        evidence_refs=[],
                    )
                    correlations.append(corr)

        return correlations

    @classmethod
    def _correlate_watchlist_and_observation(
        cls,
        db: Session,
        workspace_id: str,
        since: datetime,
        now: datetime,
        window_seconds: float,
    ) -> List[CrossSourceCorrelationModel]:
        """
        Correlates Section 53 watchlist indicators with live security findings.
        """
        correlations: List[CrossSourceCorrelationModel] = []

        q_watch = db.query(WatchedIndicatorModel).filter(
            WatchedIndicatorModel.workspace_id == workspace_id,
            WatchedIndicatorModel.monitoring_status == "ACTIVE",
        ).limit(25).all()

        if not q_watch:
            return []

        watch_values = {w.normalized_value: w for w in q_watch if w.normalized_value}

        # Check recent findings
        q_find = db.query(FindingModel).filter(
            FindingModel.workspace_id == workspace_id,
            FindingModel.created_at >= since,
        ).limit(30).all()

        for f in q_find:
            f_indicators = f.details.get("indicators", []) or []
            if not f_indicators and f.evidence_items:
                f_indicators = [ev.value for ev in f.evidence_items]

            for ind in f_indicators:
                norm_ind = ind.strip().lower()
                if norm_ind in watch_values:
                    watched_item = watch_values[norm_ind]
                    time_diff = abs((f.created_at - watched_item.created_at).total_seconds())
                    watched_val = watched_item.display_value or watched_item.normalized_value or watched_item.raw_value

                    title = f"Watchlist IOC Observed in Finding: {watched_val}"
                    desc_text = (
                        f"Active monitored IOC '{watched_val}' (Priority: {watched_item.priority}) "
                        f"was observed in telemetry finding '{f.title}' ({f.id[:8]})."
                    )
                    reasons = [
                        f"Watched indicator match: {watched_val} ({watched_item.indicator_type})",
                        f"Watchlist priority: {watched_item.priority}",
                        f"Observed in finding: {f.title}",
                    ]

                    members_payload = [
                        {"type": MemberTypeEnum.INDICATOR, "id": watched_item.id, "source": SourceTypeEnum.WATCHLIST, "role": "PRIMARY", "occurred_at": watched_item.created_at},
                        {"type": MemberTypeEnum.FINDING, "id": f.id, "source": SourceTypeEnum.GENERIC, "role": "SUPPORTING", "occurred_at": f.created_at},
                    ]

                    corr = cls._create_or_update_correlation(
                        db=db,
                        workspace_id=workspace_id,
                        correlation_type=CorrelationTypeEnum.WATCHLIST_AND_OBSERVATION,
                        title=title,
                        description=desc_text,
                        confidence_score=0.95,
                        confidence_level=CorrelationConfidenceEnum.CRITICAL,
                        child_findings=[f],
                        members_payload=members_payload,
                        supporting_reasons=reasons,
                        first_observed_at=f.created_at,
                        last_observed_at=f.created_at,
                        time_window_seconds=time_diff,
                        evidence_refs=[e.id for e in (f.evidence_items or [])],
                    )
                    correlations.append(corr)

        return correlations

    # =========================================================================
    # 3. COMPOSITE FINDING & PERSISTENCE HELPER (NO DOUBLE-COUNTING)
    # =========================================================================

    @classmethod
    def _create_or_update_correlation(
        cls,
        db: Session,
        workspace_id: str,
        correlation_type: CorrelationTypeEnum,
        title: str,
        description: str,
        confidence_score: float,
        confidence_level: CorrelationConfidenceEnum,
        child_findings: List[FindingModel],
        members_payload: List[Dict[str, Any]],
        supporting_reasons: List[str],
        first_observed_at: datetime,
        last_observed_at: datetime,
        time_window_seconds: float,
        evidence_refs: List[str],
    ) -> CrossSourceCorrelationModel:
        """
        Persists a cross-source correlation, enforcing idempotency and generating
        a non-double-counted composite FindingModel in the unified finding store.
        """
        # Compute deterministic idempotency hash:
        member_tokens = sorted([f"{m['type']}:{m['id']}" for m in members_payload])
        time_bucket = first_observed_at.strftime("%Y%m%d%H")  # 1-hour idempotency bucket
        raw_key = f"{workspace_id}:{correlation_type.value}:{':'.join(member_tokens)}:{time_bucket}"
        idempotency_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

        existing = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id,
            CrossSourceCorrelationModel.idempotency_hash == idempotency_hash,
        ).first()

        if existing:
            # Update last observed time
            existing.last_observed_at = max(existing.last_observed_at, last_observed_at)
            existing.updated_at = get_utc_now()
            db.flush()
            return existing

        # Deduplicate Risk: calculate composite risk without double-counting
        # R_composite = min(100.0, max(R_i) + sum(0.3 * R_other))
        risk_contributions = [f.risk_contribution for f in child_findings] if child_findings else [50.0]
        if risk_contributions:
            max_r = max(risk_contributions)
            other_r = sum(r for r in risk_contributions if r != max_r)
            calculated_risk = min(100.0, max_r + (0.30 * other_r))
        else:
            calculated_risk = 50.0

        if calculated_risk >= 80.0:
            risk_lvl = "CRITICAL"
            severity = "CRITICAL"
        elif calculated_risk >= 60.0:
            risk_lvl = "HIGH"
            severity = "HIGH"
        elif calculated_risk >= 30.0:
            risk_lvl = "MEDIUM"
            severity = "MEDIUM"
        else:
            risk_lvl = "LOW"
            severity = "LOW"

        # 1. Create Parent Composite Finding in unified findings table
        parent_finding = FindingModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            analyzer="cross_source_correlation",
            source_type="CORRELATION",
            finding_type="COMPOSITE_CORRELATION",
            title=f"Composite Attack Signal: {title}",
            description=description,
            severity=severity,
            confidence=confidence_score,
            risk_contribution=calculated_risk,
            method="CORRELATION",
            is_composite=True,
            metadata_json=json.dumps({
                "correlation_type": correlation_type.value,
                "child_finding_ids": [f.id for f in child_findings],
                "time_window_seconds": time_window_seconds,
                "evidence_count": len(set(evidence_refs)),
            }),
            created_at=get_utc_now(),
        )
        db.add(parent_finding)
        db.flush()

        # Update child findings with parent reference
        for cf in child_findings:
            cf.parent_finding_id = parent_finding.id

        # 2. Create CrossSourceCorrelationModel
        corr = CrossSourceCorrelationModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            correlation_type=correlation_type.value,
            title=title,
            description=description,
            status=CorrelationStatusEnum.CORRELATED.value,
            confidence_score=confidence_score,
            confidence_level=confidence_level.value,
            risk_score=calculated_risk,
            risk_level=risk_lvl,
            severity=severity,
            first_observed_at=first_observed_at,
            last_observed_at=last_observed_at,
            time_window_seconds=time_window_seconds,
            idempotency_hash=idempotency_hash,
            parent_finding_id=parent_finding.id,
            explanation_summary=description,
            supporting_reasons_json=json.dumps(supporting_reasons),
            contradictions_json=json.dumps([]),
            missing_context_json=json.dumps([]),
            quality_metrics_json=json.dumps({
                "source_completeness": 1.0 if len(child_findings) >= 2 else 0.75,
                "temporal_precision": "EXACT",
                "evidence_count": len(set(evidence_refs)),
                "member_count": len(members_payload),
            }),
            rule_version=RULE_VERSION,
            schema_version=SCHEMA_VERSION,
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )
        db.add(corr)
        db.flush()

        parent_finding.correlation_id = corr.id

        # 3. Create CorrelationMemberModel entries
        for m in members_payload:
            member = CorrelationMemberModel(
                id=generate_uuid(),
                correlation_id=corr.id,
                member_type=m["type"].value if hasattr(m["type"], "value") else str(m["type"]),
                member_id=m["id"],
                source_type=m["source"].value if hasattr(m["source"], "value") else str(m["source"]),
                role=m.get("role", "SUPPORTING"),
                occurred_at=m.get("occurred_at", first_observed_at),
                confidence=1.0,
                metadata_json=json.dumps(m.get("metadata", {})),
                created_at=get_utc_now(),
            )
            db.add(member)

        # 4. Connect to Knowledge Graph
        try:
            if len(child_findings) >= 2:
                SecurityGraphService().record_relationship(
                    db=db,
                    source_id=child_findings[0].id,
                    source_type=GraphEntityType.OTHER.value,
                    target_id=child_findings[1].id,
                    target_type=GraphEntityType.OTHER.value,
                    relationship_type=GraphRelationshipType.RELATED_TO.value,
                    confidence=confidence_score,
                    origin=RelationshipOrigin.DERIVED.value,
                    workspace_id=workspace_id,
                    evidence_reference=f"corr:{corr.id}",
                )
        except Exception as e:
            logger.debug(f"Knowledge Graph linkage skipped: {e}")

        db.flush()

        # 5. Emit Realtime Events
        try:
            RealtimePublisher.publish_event(
                event_type=RealtimeEventTypeEnum.CORRELATION_CREATED,
                resource_scope=RealtimeResourceScopeEnum.CROSS_SOURCE_CORRELATION,
                resource_id=corr.id,
                workspace_id=workspace_id,
                payload={
                    "correlation_id": corr.id,
                    "correlation_number": corr.correlation_number,
                    "correlation_type": corr.correlation_type,
                    "title": corr.title,
                    "severity": corr.severity,
                    "confidence_score": corr.confidence_score,
                    "risk_score": corr.risk_score,
                },
            )
        except Exception as e:
            logger.debug(f"Realtime dispatch skipped: {e}")

        # 6. Dispatch Notification for High / Critical Threats
        if severity in ("HIGH", "CRITICAL"):
            try:
                NotificationService.create_notification(
                    db=db,
                    workspace_id=workspace_id,
                    title=f"Critical Correlated Threat: {corr.title}",
                    message=corr.description,
                    severity=severity,
                    category="SECURITY_ALERT",
                    notification_type="CROSS_SOURCE_THREAT_CORRELATED",
                    source_type="CROSS_SOURCE_CORRELATION",
                    source_id=corr.id,
                    finding_id=parent_finding.id,
                    deduplication_key=f"corr_alert:{corr.id}",
                    navigation_target=f"/correlations/{corr.id}",
                )
            except Exception as e:
                logger.debug(f"Alert notification dispatch skipped: {e}")

        return corr

    # =========================================================================
    # 4. QUERY, TIMELINE, EXPLANATION & DISPOSITION
    # =========================================================================

    @classmethod
    def list_correlations(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None,
        correlation_type: Optional[str] = None,
        severity: Optional[str] = None,
        min_confidence: Optional[float] = None,
        search: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[CrossSourceCorrelationRead], int]:
        """
        Lists correlations with server-side multi-tenant filtering.
        """
        q = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id
        )

        if status and status.upper() != "ALL":
            q = q.filter(CrossSourceCorrelationModel.status == status.upper())
        if correlation_type and correlation_type.upper() != "ALL":
            q = q.filter(CrossSourceCorrelationModel.correlation_type == correlation_type.upper())
        if severity and severity.upper() != "ALL":
            q = q.filter(CrossSourceCorrelationModel.severity == severity.upper())
        if min_confidence is not None:
            q = q.filter(CrossSourceCorrelationModel.confidence_score >= min_confidence)
        if search:
            s_pat = f"%{search.strip()}%"
            q = q.filter(or_(
                CrossSourceCorrelationModel.title.ilike(s_pat),
                CrossSourceCorrelationModel.correlation_number.ilike(s_pat),
                CrossSourceCorrelationModel.description.ilike(s_pat)
            ))

        total = q.count()
        rows = q.order_by(desc(CrossSourceCorrelationModel.created_at)).offset(offset).limit(limit).all()

        items: List[CrossSourceCorrelationRead] = []
        for r in rows:
            sources = sorted(list({m.source_type for m in (r.members or [])}))
            entities = sorted(list({m.member_id for m in (r.members or []) if m.member_type == "ENTITY"}))
            items.append(CrossSourceCorrelationRead(
                id=r.id,
                workspace_id=r.workspace_id,
                correlation_number=r.correlation_number,
                correlation_type=CorrelationTypeEnum(r.correlation_type),
                title=r.title,
                description=r.description,
                status=CorrelationStatusEnum(r.status),
                confidence_score=r.confidence_score,
                confidence_level=CorrelationConfidenceEnum(r.confidence_level),
                risk_score=r.risk_score,
                risk_level=r.risk_level,
                severity=r.severity,
                first_observed_at=r.first_observed_at,
                last_observed_at=r.last_observed_at,
                time_window_seconds=r.time_window_seconds,
                parent_finding_id=r.parent_finding_id,
                alert_id=r.alert_id,
                incident_id=r.incident_id,
                campaign_id=r.campaign_id,
                explanation_summary=r.explanation_summary,
                member_count=len(r.members or []),
                sources=sources,
                entities=entities,
                analyst_disposition=r.analyst_disposition,
                created_at=r.created_at,
                updated_at=r.updated_at,
            ))

        return items, total

    @classmethod
    def get_correlation_detail(
        cls,
        db: Session,
        correlation_id: str,
        workspace_id: str = "default",
    ) -> Optional[CrossSourceCorrelationDetail]:
        """
        Retrieves full progressive-disclosure detail view for an analyst.
        """
        r = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.id == correlation_id,
            CrossSourceCorrelationModel.workspace_id == workspace_id,
        ).first()

        if not r:
            return None

        members_read: List[CorrelationMemberRead] = []
        for m in (r.members or []):
            members_read.append(CorrelationMemberRead(
                id=m.id,
                correlation_id=m.correlation_id,
                member_type=MemberTypeEnum(m.member_type),
                member_id=m.member_id,
                source_type=SourceTypeEnum(m.source_type) if m.source_type in [s.value for s in SourceTypeEnum] else SourceTypeEnum.GENERIC,
                role=m.role,
                occurred_at=m.occurred_at,
                confidence=m.confidence,
                metadata=m.metadata_dict,
                created_at=m.created_at,
            ))

        sources = sorted(list({m.source_type for m in (r.members or [])}))
        entities = sorted(list({m.member_id for m in (r.members or []) if m.member_type == "ENTITY"}))

        return CrossSourceCorrelationDetail(
            id=r.id,
            workspace_id=r.workspace_id,
            correlation_number=r.correlation_number,
            correlation_type=CorrelationTypeEnum(r.correlation_type),
            title=r.title,
            description=r.description,
            status=CorrelationStatusEnum(r.status),
            confidence_score=r.confidence_score,
            confidence_level=CorrelationConfidenceEnum(r.confidence_level),
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            severity=r.severity,
            first_observed_at=r.first_observed_at,
            last_observed_at=r.last_observed_at,
            time_window_seconds=r.time_window_seconds,
            parent_finding_id=r.parent_finding_id,
            alert_id=r.alert_id,
            incident_id=r.incident_id,
            campaign_id=r.campaign_id,
            explanation_summary=r.explanation_summary,
            member_count=len(r.members or []),
            sources=sources,
            entities=entities,
            analyst_disposition=r.analyst_disposition,
            created_at=r.created_at,
            updated_at=r.updated_at,
            members=members_read,
            supporting_reasons=r.supporting_reasons,
            contradictions=r.contradictions,
            missing_context=r.missing_context,
            quality_metrics=r.quality_metrics,
            rule_version=r.rule_version,
            schema_version=r.schema_version,
            analyst_notes=r.analyst_notes,
            dispositioned_by=r.dispositioned_by,
            dispositioned_at=r.dispositioned_at,
        )

    @classmethod
    def get_correlation_timeline(
        cls,
        db: Session,
        correlation_id: str,
        workspace_id: str = "default",
    ) -> List[CorrelationTimelineItem]:
        """
        Extracts chronological sequence of activities across all contributing sources.
        """
        r = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.id == correlation_id,
            CrossSourceCorrelationModel.workspace_id == workspace_id,
        ).first()

        if not r:
            return []

        timeline: List[CorrelationTimelineItem] = []
        for m in (r.members or []):
            dt = m.occurred_at or r.first_observed_at
            desc = f"{m.source_type} observation ({m.role.lower()} role)"
            timeline.append(CorrelationTimelineItem(
                timestamp=dt,
                source_type=m.source_type,
                event_type=m.member_type,
                description=desc,
                member_id=m.member_id,
                severity=r.severity,
                confidence=m.confidence,
                details=m.metadata_dict,
            ))

        timeline.sort(key=lambda x: x.timestamp)
        return timeline

    @classmethod
    def get_why_correlated(
        cls,
        db: Session,
        correlation_id: str,
        workspace_id: str = "default",
    ) -> Optional[WhyCorrelatedExplanation]:
        """
        Generates structured facts for the 'Why Correlated?' progressive disclosure panel.
        """
        r = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.id == correlation_id,
            CrossSourceCorrelationModel.workspace_id == workspace_id,
        ).first()

        if not r:
            return None

        # Build shared entities & indicators facts
        shared_entities = []
        shared_indicators = []
        for m in (r.members or []):
            if m.member_type == "ENTITY":
                shared_entities.append({"entity_id": m.member_id, "source": m.source_type, "role": m.role})
            elif m.member_type == "INDICATOR":
                shared_indicators.append({"indicator": m.member_id, "source": m.source_type})

        minutes = int(r.time_window_seconds / 60)
        time_str = f"{minutes} minutes" if minutes > 0 else f"{int(r.time_window_seconds)} seconds"

        timeline_items = cls.get_correlation_timeline(db, correlation_id, workspace_id)
        chain_facts = [
            {"time": t.timestamp.isoformat(), "source": t.source_type, "event": t.description}
            for t in timeline_items
        ]

        return WhyCorrelatedExplanation(
            correlation_id=r.id,
            correlation_type=CorrelationTypeEnum(r.correlation_type),
            confidence_score=r.confidence_score,
            risk_score=r.risk_score,
            time_window_human=time_str,
            primary_facts=r.supporting_reasons,
            shared_entities=shared_entities,
            shared_indicators=shared_indicators,
            temporal_chain=chain_facts,
            contradictions=r.contradictions,
            missing_context=r.missing_context,
            data_quality_assessment=r.quality_metrics,
        )

    @classmethod
    def record_disposition(
        cls,
        db: Session,
        correlation_id: str,
        req: CorrelationDispositionRequest,
        workspace_id: str = "default",
    ) -> CrossSourceCorrelationModel:
        """
        Records analyst review disposition with immutable audit logging.
        """
        r = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.id == correlation_id,
            CrossSourceCorrelationModel.workspace_id == workspace_id,
        ).first()

        if not r:
            raise ValueError(f"Correlation '{correlation_id}' not found")

        disp_upper = req.disposition.upper()
        if disp_upper not in ("CONFIRMED", "REJECTED", "UNCERTAIN"):
            raise ValueError("Disposition must be CONFIRMED, REJECTED, or UNCERTAIN")

        r.analyst_disposition = disp_upper
        r.analyst_notes = req.notes.strip()
        r.dispositioned_by = req.actor
        r.dispositioned_at = get_utc_now()
        r.updated_at = get_utc_now()

        if disp_upper == "REJECTED":
            r.status = CorrelationStatusEnum.INVALIDATED.value

        # Audit log entry
        audit = AuditLogModel(
            id=generate_uuid(),
            action=f"CORRELATION_{disp_upper}",
            user=req.actor,
            resource_type="cross_source_correlation",
            resource_id=r.id,
            details=json.dumps({
                "correlation_number": r.correlation_number,
                "disposition": disp_upper,
                "notes": req.notes,
            }),
            metadata_json=json.dumps({
                "correlation_number": r.correlation_number,
                "disposition": disp_upper,
                "notes": req.notes,
            }),
            timestamp=get_utc_now(),
        )
        db.add(audit)
        db.flush()

        # Realtime dispatch
        try:
            RealtimePublisher.publish_event(
                event_type=RealtimeEventTypeEnum.CORRELATION_UPDATED,
                resource_scope=RealtimeResourceScopeEnum.CROSS_SOURCE_CORRELATION,
                resource_id=r.id,
                workspace_id=workspace_id,
                payload={
                    "correlation_id": r.id,
                    "disposition": disp_upper,
                    "status": r.status,
                },
            )
        except Exception:
            pass

        return r

    @classmethod
    def get_overview_stats(
        cls,
        db: Session,
        workspace_id: str = "default",
    ) -> CorrelationOverviewStats:
        """
        Calculates platform-wide cross-source correlation KPIs.
        """
        total = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id
        ).count()

        active = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id,
            CrossSourceCorrelationModel.status == CorrelationStatusEnum.CORRELATED.value,
        ).count()

        threats = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id,
            CrossSourceCorrelationModel.severity.in_(["HIGH", "CRITICAL"]),
        ).count()

        high_conf = db.query(CrossSourceCorrelationModel).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id,
            CrossSourceCorrelationModel.confidence_score >= 0.85,
        ).count()

        resolutions = db.query(EntityModel).filter(
            or_(EntityModel.workspace_id == workspace_id, EntityModel.workspace_id.is_(None))
        ).count()

        # Group by type
        by_type_rows = db.query(
            CrossSourceCorrelationModel.correlation_type,
            func.count(CrossSourceCorrelationModel.id)
        ).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id
        ).group_by(CrossSourceCorrelationModel.correlation_type).all()

        by_type = {row[0]: row[1] for row in by_type_rows}

        # Group by source
        by_src_rows = db.query(
            CorrelationMemberModel.source_type,
            func.count(CorrelationMemberModel.id)
        ).join(
            CrossSourceCorrelationModel,
            CrossSourceCorrelationModel.id == CorrelationMemberModel.correlation_id
        ).filter(
            CrossSourceCorrelationModel.workspace_id == workspace_id
        ).group_by(CorrelationMemberModel.source_type).all()

        by_src = {row[0]: row[1] for row in by_src_rows}

        return CorrelationOverviewStats(
            total_correlations=total,
            active_correlations=active,
            correlated_threats=threats,
            high_confidence_sequences=high_conf,
            entities_resolved=resolutions,
            avg_time_window_seconds=1200.0,
            correlations_by_type=by_type,
            correlations_by_source=by_src,
        )
