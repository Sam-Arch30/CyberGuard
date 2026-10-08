"""
Probable Origin Infrastructure & Threat Infrastructure Attribution Engine (Section 20).
Analyzes technical network and hosting infrastructure connected to an investigation,
reconstructing origin hypotheses, hosting relationships, infrastructure clusters,
and historical associations without human attribution.

CORE FORENSIC PRINCIPLES:
1. NON-ATTRIBUTION: Never claims to identify human attackers, personal identities, physical locations, or legal ownership.
2. EVIDENCE-BASED: Explains technical association to observed infrastructure clusters, domains, IPs, and ASNs.
3. CAUTION: Shared hosting, CDNs, and cloud providers reduce attribution certainty.
4. INSUFFICIENT EVIDENCE: Inconclusive/insufficient evidence is a first-class valid outcome.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from backend.db.models import (
    IncidentModel,
    InfrastructureAttributionModel,
    InfrastructureAttributionEvidenceModel,
    InfrastructureClusterModel,
    ThreatEventModel,
    SecurityEventModel,
    FindingModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.attack_confidence import ConfidenceLevel
from backend.schemas.infrastructure_attribution import (
    OriginType,
    InfrastructureRole,
    InfrastructureDirection,
    AttributionStatus,
    AttributionHypothesisType,
    EvidenceFamily,
    SupportDirection,
    InfrastructureCandidate,
    InfrastructureCluster,
    InfrastructureTimelineEvent,
    InfrastructureAttribution,
    InfrastructureAttributionEvidence,
    InvestigationInfrastructureResponse,
    FORENSIC_INFRASTRUCTURE_DISCLAIMER,
)
from backend.services.infrastructure_candidate_generator import InfrastructureCandidateGenerator
from backend.services.infrastructure_clusterer import InfrastructureClusterer
from backend.services.infrastructure_temporal_analyzer import InfrastructureTemporalAnalyzer

logger = logging.getLogger("cyberguard.infrastructure_attribution_engine")


class InfrastructureAttributionEngine:
    """
    Main orchestration engine for Section 20 Threat Infrastructure Attribution.
    """

    ENGINE_VERSION = "1.0.0"

    def __init__(
        self,
        candidate_generator: Optional[InfrastructureCandidateGenerator] = None,
        clusterer: Optional[InfrastructureClusterer] = None,
        temporal_analyzer: Optional[InfrastructureTemporalAnalyzer] = None,
    ):
        self.candidate_generator = candidate_generator or InfrastructureCandidateGenerator()
        self.clusterer = clusterer or InfrastructureClusterer()
        self.temporal_analyzer = temporal_analyzer or InfrastructureTemporalAnalyzer()

    def analyze_incident_infrastructure(
        self,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
        persist: bool = True,
    ) -> InvestigationInfrastructureResponse:
        """
        Executes end-to-end infrastructure origin and attribution analysis for an incident.
        """
        incident = (
            db.query(IncidentModel)
            .filter(
                or_(
                    IncidentModel.id == incident_id,
                    IncidentModel.incident_number == incident_id,
                )
            )
            .first()
        )
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found.")

        # 1. Harvest and enrich observed and associated candidates
        observed_candidates, associated_candidates = self.candidate_generator.generate_candidates(
            db=db, incident=incident, workspace_id=workspace_id
        )
        all_candidates = observed_candidates + associated_candidates

        # 2. Construct infrastructure clusters
        clusters = self.clusterer.cluster_infrastructure(all_candidates, incident.id)

        # 3. Analyze temporal activity and migrations
        timeline = self.temporal_analyzer.analyze_timeline(db, incident, all_candidates)

        # 4. Rank candidates and formulate origin hypotheses
        ranked_candidates = self._rank_candidates(all_candidates)
        hypotheses, evidence_links = self._formulate_hypotheses(
            incident=incident,
            candidates=ranked_candidates,
            clusters=clusters,
            timeline=timeline,
        )

        primary_hypothesis = hypotheses[0] if hypotheses else None
        competing_hypotheses = hypotheses[1:] if len(hypotheses) > 1 else []

        # 5. Extract overarching limitations
        limitations = self._synthesize_limitations(
            candidates=ranked_candidates,
            clusters=clusters,
            primary_hypothesis=primary_hypothesis,
        )

        # 6. Generate neutral SOC summary
        summary = self._generate_executive_summary(
            incident=incident,
            primary_hypothesis=primary_hypothesis,
            clusters=clusters,
            observed_count=len(observed_candidates),
        )

        # 7. Persist results to DB if requested
        if persist:
            self._persist_assessment(
                db=db,
                incident=incident,
                workspace_id=workspace_id,
                hypotheses=hypotheses,
                evidence_links=evidence_links,
                clusters=clusters,
            )

        return InvestigationInfrastructureResponse(
            incident_id=incident.id,
            incident_number=incident.incident_number,
            workspace_id=workspace_id,
            observed_infrastructure=observed_candidates,
            associated_infrastructure=associated_candidates,
            clusters=clusters,
            primary_hypothesis=primary_hypothesis,
            competing_hypotheses=competing_hypotheses,
            timeline=timeline,
            evidence_links=evidence_links,
            limitations=limitations,
            summary=summary,
            disclaimer=FORENSIC_INFRASTRUCTURE_DISCLAIMER,
            created_at=datetime.now(timezone.utc),
        )

    def _rank_candidates(
        self, candidates: List[InfrastructureCandidate]
    ) -> List[InfrastructureCandidate]:
        """
        Ranks candidates based on evidence strength, unshared infrastructure specificity,
        historical reuse, and campaign correlation.
        """
        for c in candidates:
            score = 0.30  # Baseline prior

            # Positive weights
            if c.is_observed:
                score += 0.25
            if len(c.evidence_refs) >= 2:
                score += 0.15
            if c.historical_incident_ids:
                score += 0.20
            if c.campaign_ids:
                score += 0.25
            if not c.is_shared_infrastructure and not c.is_cloud_provider:
                score += 0.15

            # Penalties
            if c.is_cdn:
                score -= 0.30
                c.limitations.append("Endpoint is behind a Content Delivery Network (CDN) masking true origin")
            elif c.is_cloud_provider or c.is_shared_infrastructure:
                score -= 0.20
                c.limitations.append("Endpoint belongs to shared cloud/hosting infrastructure")

            if c.is_vpn_proxy_tor:
                score -= 0.20
                c.limitations.append("Endpoint is a known VPN, proxy, or Tor exit node")

            # Clamp between 0.05 and 0.95
            score = max(0.05, min(0.95, score))
            c.ranking_score = score
            c.confidence_score = score

            if score >= 0.80:
                c.confidence_level = ConfidenceLevel.VERY_HIGH
            elif score >= 0.60:
                c.confidence_level = ConfidenceLevel.HIGH
            elif score >= 0.40:
                c.confidence_level = ConfidenceLevel.MODERATE
            elif score >= 0.20:
                c.confidence_level = ConfidenceLevel.LOW
            else:
                c.confidence_level = ConfidenceLevel.VERY_LOW

        # Sort descending by score
        candidates.sort(key=lambda x: x.ranking_score, reverse=True)
        return candidates

    def _formulate_hypotheses(
        self,
        incident: IncidentModel,
        candidates: List[InfrastructureCandidate],
        clusters: List[InfrastructureCluster],
        timeline: List[InfrastructureTimelineEvent],
    ) -> Tuple[List[InfrastructureAttribution], List[InfrastructureAttributionEvidence]]:
        """
        Generates competing hypotheses (H1, H2, H3, H4) with itemized evidence links.
        """
        hypotheses: List[InfrastructureAttribution] = []
        evidence_links: List[InfrastructureAttributionEvidence] = []

        now = datetime.now(timezone.utc)

        # Case A: No viable candidates or only private/unroutable IPs
        if not candidates:
            h_insufficient = InfrastructureAttribution(
                id=f"ATTR-{incident.id[:8]}-H1",
                incident_id=incident.id,
                investigation_id=incident.legacy_case_id,
                subject_entity_id=None,
                origin_entity_id=None,
                origin_value="Insufficient Evidence",
                origin_type=OriginType.UNKNOWN,
                hypothesis_id="H1",
                hypothesis_type=AttributionHypothesisType.ORIGIN_INSUFFICIENT_EVIDENCE,
                hypothesis="CyberGuard could not establish a reliable infrastructure-origin hypothesis from the available evidence.",
                status=AttributionStatus.INSUFFICIENT_EVIDENCE,
                confidence_level=ConfidenceLevel.LOW,
                confidence_score=0.15,
                evidence_count=0,
                supporting_evidence_count=0,
                contradicting_evidence_count=0,
                limitations=[
                    "No public routable infrastructure endpoints observed in telemetry",
                    "Telemetry may be incomplete or masked by internal network hops",
                ],
                evidence_items=[],
                created_at=now,
                updated_at=now,
                engine_version=self.ENGINE_VERSION,
            )
            return [h_insufficient], []

        top_cand = candidates[0]

        # Hypothesis 1: Dedicated or Campaign-Linked Threat Infrastructure
        h1_id = f"ATTR-{incident.id[:8]}-H1"
        h1_evidence: List[InfrastructureAttributionEvidence] = []
        h1_limitations: List[str] = list(top_cand.limitations)
        h1_limitations.append("Observed infrastructure does not prove human ownership or identity")
        h1_limitations.append("IP geolocation represents server facility geography, not attacker location")

        origin_type = (
            OriginType.IP
            if top_cand.entity_type == "IP"
            else OriginType.DOMAIN
            if top_cand.entity_type == "DOMAIN"
            else OriginType.INFRASTRUCTURE_CLUSTER
        )

        origin_val = top_cand.value
        if clusters and clusters[0].confidence >= 0.70:
            origin_val = f"{top_cand.value} (associated with {clusters[0].name})"
            origin_type = OriginType.INFRASTRUCTURE_CLUSTER

        # Compile supporting evidence items
        ev_index = 1
        for ref in top_cand.evidence_refs:
            ev_link = InfrastructureAttributionEvidence(
                id=f"IAE-{incident.id[:8]}-{ev_index:03d}",
                attribution_id=h1_id,
                evidence_id=ref,
                source_entity_id=top_cand.canonical_key,
                target_entity_id=None,
                relationship_type="OBSERVED_IN_INCIDENT",
                evidence_family=EvidenceFamily.DIRECT_TELEMETRY,
                support_direction=SupportDirection.SUPPORTS,
                strength=0.9,
                explanation=f"Direct observation of {top_cand.value} in incident telemetry ({ref})",
                created_at=now,
            )
            ev_index += 1
            h1_evidence.append(ev_link)
            evidence_links.append(ev_link)

        if top_cand.historical_incident_ids:
            ev_link = InfrastructureAttributionEvidence(
                id=f"IAE-{incident.id[:8]}-{ev_index:03d}",
                attribution_id=h1_id,
                evidence_id=None,
                source_entity_id=top_cand.canonical_key,
                target_entity_id=None,
                relationship_type="SHARED_HISTORICAL_INCIDENTS",
                evidence_family=EvidenceFamily.HISTORICAL_INCIDENT,
                support_direction=SupportDirection.SUPPORTS,
                strength=0.85,
                explanation=f"Infrastructure node previously observed across {len(top_cand.historical_incident_ids)} prior investigations",
                created_at=now,
            )
            ev_index += 1
            h1_evidence.append(ev_link)
            evidence_links.append(ev_link)

        if top_cand.campaign_ids:
            ev_link = InfrastructureAttributionEvidence(
                id=f"IAE-{incident.id[:8]}-{ev_index:03d}",
                attribution_id=h1_id,
                evidence_id=None,
                source_entity_id=top_cand.canonical_key,
                target_entity_id=None,
                relationship_type="RELATED_TO_CAMPAIGN",
                evidence_family=EvidenceFamily.CAMPAIGN_CORRELATION,
                support_direction=SupportDirection.SUPPORTS,
                strength=0.95,
                explanation=f"Technical node matches threat campaign {top_cand.campaign_ids[0]}",
                created_at=now,
            )
            ev_index += 1
            h1_evidence.append(ev_link)
            evidence_links.append(ev_link)

        if top_cand.is_shared_infrastructure:
            ev_link = InfrastructureAttributionEvidence(
                id=f"IAE-{incident.id[:8]}-{ev_index:03d}",
                attribution_id=h1_id,
                evidence_id=None,
                source_entity_id=top_cand.canonical_key,
                target_entity_id=None,
                relationship_type="HOSTED_BY",
                evidence_family=EvidenceFamily.NETWORK_INTELLIGENCE,
                support_direction=SupportDirection.CONTRADICTS,
                strength=0.7,
                explanation=f"Candidate belongs to shared cloud or CDN infrastructure ({top_cand.hosting_provider or 'Shared Hosting'}), reducing origin specificity",
                created_at=now,
            )
            ev_index += 1
            h1_evidence.append(ev_link)
            evidence_links.append(ev_link)

        h1_supp = len([e for e in h1_evidence if e.support_direction == SupportDirection.SUPPORTS])
        h1_contra = len([e for e in h1_evidence if e.support_direction == SupportDirection.CONTRADICTS])

        h1_type = (
            AttributionHypothesisType.DEDICATED_THREAT_INFRASTRUCTURE
            if not top_cand.is_shared_infrastructure
            else AttributionHypothesisType.SHARED_INFRASTRUCTURE_PROXY
        )

        h1_title = (
            f"Probable technical origin associated with {origin_val} ({top_cand.hosting_provider or 'Observed Hosting'})"
            if not top_cand.is_shared_infrastructure
            else f"Activity routed through multi-tenant or shared infrastructure ({origin_val})"
        )

        h1 = InfrastructureAttribution(
            id=h1_id,
            incident_id=incident.id,
            investigation_id=incident.legacy_case_id,
            subject_entity_id=None,
            origin_entity_id=top_cand.id,
            origin_value=origin_val,
            origin_type=origin_type,
            hypothesis_id="H1",
            hypothesis_type=h1_type,
            hypothesis=h1_title,
            status=AttributionStatus.PROBABLE if top_cand.ranking_score >= 0.50 else AttributionStatus.PLAUSIBLE,
            confidence_level=top_cand.confidence_level,
            confidence_score=top_cand.ranking_score,
            evidence_count=len(h1_evidence),
            supporting_evidence_count=h1_supp,
            contradicting_evidence_count=h1_contra,
            limitations=h1_limitations,
            evidence_items=h1_evidence,
            created_at=now,
            updated_at=now,
            engine_version=self.ENGINE_VERSION,
        )
        hypotheses.append(h1)

        # Hypothesis 2: Compromised Legitimate Infrastructure
        h2_id = f"ATTR-{incident.id[:8]}-H2"
        h2 = InfrastructureAttribution(
            id=h2_id,
            incident_id=incident.id,
            investigation_id=incident.legacy_case_id,
            subject_entity_id=None,
            origin_entity_id=top_cand.id,
            origin_value=top_cand.value,
            origin_type=origin_type,
            hypothesis_id="H2",
            hypothesis_type=AttributionHypothesisType.COMPROMISED_HOSTING,
            hypothesis=f"Observed endpoint {top_cand.value} represents compromised legitimate third-party infrastructure",
            status=AttributionStatus.PLAUSIBLE,
            confidence_level=ConfidenceLevel.LOW if not top_cand.is_shared_infrastructure else ConfidenceLevel.MODERATE,
            confidence_score=0.35 if not top_cand.is_shared_infrastructure else 0.50,
            evidence_count=1,
            supporting_evidence_count=1,
            contradicting_evidence_count=0,
            limitations=[
                "No direct access to third-party web server logs to confirm unauthorized compromise",
                "Cannot conclusively differentiate adversary-purchased hosting from compromised legitimate hosting",
            ],
            evidence_items=[],
            created_at=now,
            updated_at=now,
            engine_version=self.ENGINE_VERSION,
        )
        hypotheses.append(h2)

        # Hypothesis 3: Shared Infrastructure / Intermediary
        if top_cand.is_shared_infrastructure or top_cand.is_vpn_proxy_tor:
            h3_id = f"ATTR-{incident.id[:8]}-H3"
            h3 = InfrastructureAttribution(
                id=h3_id,
                incident_id=incident.id,
                investigation_id=incident.legacy_case_id,
                subject_entity_id=None,
                origin_entity_id=top_cand.id,
                origin_value=top_cand.value,
                origin_type=OriginType.HOSTING_INFRASTRUCTURE,
                hypothesis_id="H3",
                hypothesis_type=AttributionHypothesisType.SHARED_INFRASTRUCTURE_PROXY,
                hypothesis=f"Observed endpoint {top_cand.value} is an intermediary, CDN, or shared proxy masking the true origin",
                status=AttributionStatus.PROBABLE,
                confidence_level=ConfidenceLevel.HIGH,
                confidence_score=0.75,
                evidence_count=1,
                supporting_evidence_count=1,
                contradicting_evidence_count=0,
                limitations=[
                    "Shared infrastructure prevents determining true origin without upstream provider cooperation",
                ],
                evidence_items=[],
                created_at=now,
                updated_at=now,
                engine_version=self.ENGINE_VERSION,
            )
            # If the candidate is shared, swap H3 to top hypothesis
            if top_cand.is_cdn:
                hypotheses.insert(0, h3)

        return hypotheses, evidence_links

    def _synthesize_limitations(
        self,
        candidates: List[InfrastructureCandidate],
        clusters: List[InfrastructureCluster],
        primary_hypothesis: Optional[InfrastructureAttribution],
    ) -> List[str]:
        """Synthesizes high-level investigation caveats and boundaries."""
        limits: List[str] = [
            "This assessment represents a technical infrastructure hypothesis and does not establish human identity or legal ownership.",
            "Observed IP geolocation reflects hosting facility network geography, not threat actor physical location.",
        ]
        has_shared = any(c.is_shared_infrastructure for c in candidates)
        if has_shared:
            limits.append("Observed infrastructure contains multi-tenant cloud or CDN endpoints, introducing origin ambiguity.")

        has_cdn = any(c.is_cdn for c in candidates)
        if has_cdn:
            limits.append("Content Delivery Network (CDN) layers mask upstream origin servers.")

        return limits

    def _generate_executive_summary(
        self,
        incident: IncidentModel,
        primary_hypothesis: Optional[InfrastructureAttribution],
        clusters: List[InfrastructureCluster],
        observed_count: int,
    ) -> str:
        """Constructs an evidence-grounded analyst narrative adhering strictly to non-attribution language."""
        if not primary_hypothesis or primary_hypothesis.hypothesis_type == AttributionHypothesisType.ORIGIN_INSUFFICIENT_EVIDENCE:
            return (
                f"CyberGuard evaluated technical telemetry for incident {incident.incident_number}. "
                "The available evidence is insufficient to establish a reliable infrastructure-origin hypothesis."
            )

        cluster_clause = (
            f"associating with {len(clusters)} infrastructure cluster(s)"
            if clusters
            else "without a broader multi-node cluster"
        )

        return (
            f"CyberGuard identified a probable technical infrastructure association for incident {incident.incident_number}. "
            f"The strongest observed infrastructure relationship points to {primary_hypothesis.origin_value} "
            f"({primary_hypothesis.confidence_level.value} confidence, {primary_hypothesis.confidence_score * 100:.1f}%), "
            f"evaluated across {observed_count} observed endpoints and {cluster_clause}. "
            f"This represents a technical infrastructure hypothesis based on normalized evidence and does not establish human attribution."
        )

    def _persist_assessment(
        self,
        db: Session,
        incident: IncidentModel,
        workspace_id: str,
        hypotheses: List[InfrastructureAttribution],
        evidence_links: List[InfrastructureAttributionEvidence],
        clusters: List[InfrastructureCluster],
    ) -> None:
        """Persists attribution models, evidence links, and clusters in the database."""
        # 1. Clear prior assessments for this incident to allow safe re-analysis
        db.query(InfrastructureAttributionModel).filter(
            InfrastructureAttributionModel.incident_id == incident.id
        ).delete()
        db.query(InfrastructureClusterModel).filter(
            InfrastructureClusterModel.incident_id == incident.id
        ).delete()

        # 2. Add clusters
        for cl in clusters:
            db_cl = InfrastructureClusterModel(
                id=generate_uuid(),
                cluster_id=cl.cluster_id,
                incident_id=incident.id,
                workspace_id=workspace_id,
                name=cl.name,
                members_json=json.dumps([m.model_dump() for m in cl.members]),
                relationship_types_json=json.dumps(cl.relationship_types),
                evidence_count=cl.evidence_count,
                incident_count=cl.incident_count,
                campaign_count=cl.campaign_count,
                supporting_signals_json=json.dumps(cl.supporting_signals),
                contradicting_signals_json=json.dumps(cl.contradicting_signals),
                confidence=cl.confidence,
                confidence_level=cl.confidence_level.value,
                created_at=get_utc_now(),
            )
            db.add(db_cl)

        # 3. Add hypotheses and evidence items
        for h in hypotheses:
            db_h = InfrastructureAttributionModel(
                id=h.id,
                incident_id=incident.id,
                investigation_id=h.investigation_id,
                workspace_id=workspace_id,
                subject_entity_id=h.subject_entity_id,
                origin_entity_id=h.origin_entity_id,
                origin_value=h.origin_value,
                origin_type=h.origin_type.value,
                hypothesis_id=h.hypothesis_id,
                hypothesis_type=h.hypothesis_type.value,
                hypothesis_title=h.hypothesis,
                status=h.status.value,
                confidence_score=h.confidence_score,
                confidence_level=h.confidence_level.value,
                evidence_count=h.evidence_count,
                supporting_evidence_count=h.supporting_evidence_count,
                contradicting_evidence_count=h.contradicting_evidence_count,
                limitations_json=json.dumps(h.limitations),
                metadata_json=json.dumps(h.metadata),
                engine_version=h.engine_version,
                created_at=h.created_at,
                updated_at=h.updated_at,
            )
            db.add(db_h)

            for ev in h.evidence_items:
                db_ev = InfrastructureAttributionEvidenceModel(
                    id=ev.id,
                    attribution_id=h.id,
                    evidence_id=ev.evidence_id,
                    relationship_id=ev.relationship_id,
                    source_entity_id=ev.source_entity_id,
                    target_entity_id=ev.target_entity_id,
                    relationship_type=ev.relationship_type,
                    evidence_family=ev.evidence_family.value,
                    support_direction=ev.support_direction.value,
                    strength=ev.strength,
                    explanation=ev.explanation,
                    created_at=ev.created_at,
                )
                db.add(db_ev)

        db.commit()


global_infrastructure_engine = InfrastructureAttributionEngine()
