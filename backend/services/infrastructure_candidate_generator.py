"""
Infrastructure Candidate Generator (Section 20).
Gathers, normalizes, and enriches observed and technically associated infrastructure
from investigation telemetry, artifacts, findings, threat events, and the Security Knowledge Graph.

STRICT BOUNDARIES:
1. Distinguishes observed source from observed destination; never labels endpoints as "attacker".
2. Bounded graph traversal (MAX_GRAPH_DEPTH, MAX_CANDIDATES) prevents graph explosion.
3. Reuses existing IPIntelligenceService, DNS, and ThreatIntelligenceService without live external dependencies.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    IncidentModel,
    ThreatEventModel,
    SecurityEventModel,
    FindingModel,
    FindingEvidenceModel,
    ArtifactModel,
    EntityModel,
    RelationshipModel,
    CampaignModel,
    IncidentCorrelationModel,
)
from backend.schemas.infrastructure_attribution import (
    InfrastructureCandidate,
    InfrastructureRole,
    InfrastructureDirection,
    ConfidenceLevel,
)
from backend.schemas.knowledge_graph import (
    GraphEntityType,
    GraphRelationshipType,
    make_canonical_key,
)
from backend.schemas.unified import normalize_ip, normalize_domain, normalize_url
from backend.services.relay_reconstructor import RelayReconstructorService
from backend.services.ip_cache import global_ip_cache
from backend.services.threat_intelligence_service import ThreatIntelligenceService

logger = logging.getLogger("cyberguard.infrastructure_candidate_generator")


# Known major cloud, hosting, CDN, and proxy ASNs and providers
KNOWN_SHARED_CLOUDS = {
    "AS16509": "Amazon AWS",
    "AS14618": "Amazon AWS",
    "AS8075": "Microsoft Azure",
    "AS15169": "Google Cloud",
    "AS396982": "Google Cloud",
    "AS13335": "Cloudflare",
    "AS20940": "Akamai Technologies",
    "AS54113": "Fastly",
    "AS16276": "OVH SAS",
    "AS24940": "Hetzner Online",
    "AS14061": "DigitalOcean",
    "AS63949": "Linode / Akamai",
}

KNOWN_SHARED_NAMESERVERS = {
    "cloudflare.com",
    "domaincontrol.com",
    "awsdns",
    "googledomains.com",
    "azure-dns",
    "registrar-servers.com",
    "name-services.com",
}


class InfrastructureCandidateGenerator:
    """
    Extracts, normalizes, and traverses infrastructure candidates for an incident.
    """

    MAX_GRAPH_DEPTH = 3
    MAX_CANDIDATES = 100
    MAX_RELATED_DOMAINS = 50
    MAX_RELATED_IPS = 50
    MAX_HISTORICAL_INCIDENTS = 20

    def __init__(
        self,
        max_graph_depth: int = MAX_GRAPH_DEPTH,
        max_candidates: int = MAX_CANDIDATES,
    ):
        self.max_graph_depth = max_graph_depth
        self.max_candidates = max_candidates

    def generate_candidates(
        self,
        db: Session,
        incident: IncidentModel,
        workspace_id: str = "default",
    ) -> Tuple[List[InfrastructureCandidate], List[InfrastructureCandidate]]:
        """
        Gathers observed and associated infrastructure candidates for an incident.
        Returns: (observed_candidates, associated_candidates)
        """
        observed_candidates: List[InfrastructureCandidate] = []
        observed_keys: Set[str] = set()

        # 1. Harvest directly observed infrastructure from SecurityEvents
        sec_events = (
            db.query(SecurityEventModel)
            .filter(SecurityEventModel.incident_id == incident.id)
            .all()
        )
        for se in sec_events:
            self._extract_from_security_event(se, observed_candidates, observed_keys)

        # 2. Harvest directly observed infrastructure from ThreatEvents
        threat_events = (
            db.query(ThreatEventModel)
            .filter(ThreatEventModel.incident_id == incident.id)
            .all()
        )
        for te in threat_events:
            self._extract_from_threat_event(te, observed_candidates, observed_keys)

        # 3. Harvest directly observed infrastructure from Findings & Evidence
        findings = (
            db.query(FindingModel)
            .join(ThreatEventModel, FindingModel.analysis_run_id == ThreatEventModel.analysis_run_id, isouter=True)
            .filter(
                or_(
                    ThreatEventModel.incident_id == incident.id,
                    FindingModel.id.in_(
                        db.query(FindingEvidenceModel.finding_id)
                        .filter(FindingEvidenceModel.incident_id == incident.id)
                    ) if hasattr(FindingEvidenceModel, "incident_id") else False
                )
            )
            .all()
        )
        for f in findings:
            self._extract_from_finding(f, observed_candidates, observed_keys)

        # 4. Traverse Security Knowledge Graph for associated infrastructure
        associated_candidates = self._traverse_associated_infrastructure(
            db, incident, observed_candidates, observed_keys, workspace_id
        )

        # 5. Enrich all candidates with ASN, hosting, shared provider, and historical incident info
        for c in observed_candidates + associated_candidates:
            self._enrich_candidate(db, c, incident.id, workspace_id)

        # Sort and limit candidates to prevent unbounded memory
        observed_candidates = observed_candidates[: self.max_candidates]
        associated_candidates = associated_candidates[: self.max_candidates]

        return observed_candidates, associated_candidates

    def _extract_from_security_event(
        self,
        se: SecurityEventModel,
        candidates: List[InfrastructureCandidate],
        seen_keys: Set[str],
    ) -> None:
        """Extracts IPs, domains, and endpoints from normalized SecurityEvent."""
        raw = {}
        payload = getattr(se, "attributes_json", None) or getattr(se, "raw_payload", None)
        if payload:
            try:
                raw = json.loads(payload) if isinstance(payload, str) else payload
            except Exception:
                raw = {}

        # Source IP (Ingress / Client)
        src_ip = raw.get("source_ip") or raw.get("src_ip") or raw.get("client_ip")
        if src_ip and isinstance(src_ip, str) and RelayReconstructorService.is_public_ip(src_ip):
            norm_ip = normalize_ip(src_ip)
            canon = make_canonical_key(GraphEntityType.IP, norm_ip)
            if canon not in seen_keys:
                seen_keys.add(canon)
                candidates.append(
                    InfrastructureCandidate(
                        id=f"cand-{norm_ip}",
                        entity_type="IP",
                        canonical_key=canon,
                        value=norm_ip,
                        role=InfrastructureRole.ORIGIN_CANDIDATE,
                        direction=InfrastructureDirection.OBSERVED_SOURCE,
                        is_observed=True,
                        is_direct=True,
                        first_seen=se.event_time,
                        last_seen=se.event_time,
                        evidence_refs=[se.id],
                    )
                )

        # Destination IP (Egress / Server)
        dst_ip = raw.get("destination_ip") or raw.get("dst_ip") or raw.get("server_ip")
        if dst_ip and isinstance(dst_ip, str) and RelayReconstructorService.is_public_ip(dst_ip):
            norm_ip = normalize_ip(dst_ip)
            canon = make_canonical_key(GraphEntityType.IP, norm_ip)
            if canon not in seen_keys:
                seen_keys.add(canon)
                candidates.append(
                    InfrastructureCandidate(
                        id=f"cand-{norm_ip}",
                        entity_type="IP",
                        canonical_key=canon,
                        value=norm_ip,
                        role=InfrastructureRole.COMMAND_INFRASTRUCTURE_CANDIDATE,
                        direction=InfrastructureDirection.OBSERVED_DESTINATION,
                        is_observed=True,
                        is_direct=True,
                        first_seen=se.event_time,
                        last_seen=se.event_time,
                        evidence_refs=[se.id],
                    )
                )

        # Domain / URL
        domain = raw.get("domain") or raw.get("host")
        if domain and isinstance(domain, str) and "." in domain:
            norm_dom = normalize_domain(domain)
            canon = make_canonical_key(GraphEntityType.DOMAIN, norm_dom)
            if canon not in seen_keys:
                seen_keys.add(canon)
                candidates.append(
                    InfrastructureCandidate(
                        id=f"cand-{norm_dom}",
                        entity_type="DOMAIN",
                        canonical_key=canon,
                        value=norm_dom,
                        role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
                        direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
                        is_observed=True,
                        is_direct=True,
                        first_seen=se.event_time,
                        last_seen=se.event_time,
                        evidence_refs=[se.id],
                    )
                )

    def _extract_from_threat_event(
        self,
        te: ThreatEventModel,
        candidates: List[InfrastructureCandidate],
        seen_keys: Set[str],
    ) -> None:
        """Extracts infrastructure entities from ThreatEvent summary and metadata."""
        meta = {}
        if te.metadata_json:
            try:
                meta = json.loads(te.metadata_json)
            except Exception:
                meta = {}

        ip = meta.get("ip") or meta.get("source_ip") or meta.get("destination_ip")
        if ip and isinstance(ip, str) and RelayReconstructorService.is_public_ip(ip):
            norm_ip = normalize_ip(ip)
            canon = make_canonical_key(GraphEntityType.IP, norm_ip)
            if canon not in seen_keys:
                seen_keys.add(canon)
                direction = (
                    InfrastructureDirection.OBSERVED_SOURCE
                    if "source" in str(meta).lower()
                    else InfrastructureDirection.OBSERVED_DESTINATION
                )
                candidates.append(
                    InfrastructureCandidate(
                        id=f"cand-{norm_ip}",
                        entity_type="IP",
                        canonical_key=canon,
                        value=norm_ip,
                        role=InfrastructureRole.ORIGIN_CANDIDATE if direction == InfrastructureDirection.OBSERVED_SOURCE else InfrastructureRole.HOSTING_INFRASTRUCTURE,
                        direction=direction,
                        is_observed=True,
                        is_direct=True,
                        first_seen=te.timestamp,
                        last_seen=te.timestamp,
                        evidence_refs=[te.id],
                    )
                )

        domain = meta.get("domain") or meta.get("sender_domain") or meta.get("url_domain")
        if domain and isinstance(domain, str) and "." in domain:
            norm_dom = normalize_domain(domain)
            canon = make_canonical_key(GraphEntityType.DOMAIN, norm_dom)
            if canon not in seen_keys:
                seen_keys.add(canon)
                candidates.append(
                    InfrastructureCandidate(
                        id=f"cand-{norm_dom}",
                        entity_type="DOMAIN",
                        canonical_key=canon,
                        value=norm_dom,
                        role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
                        direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
                        is_observed=True,
                        is_direct=True,
                        first_seen=te.timestamp,
                        last_seen=te.timestamp,
                        evidence_refs=[te.id],
                    )
                )

    def _extract_from_finding(
        self,
        f: FindingModel,
        candidates: List[InfrastructureCandidate],
        seen_keys: Set[str],
    ) -> None:
        """Extracts infrastructure from Finding details and metadata."""
        meta = {}
        payload = getattr(f, "metadata_json", None) or getattr(f, "details_json", None)
        if payload:
            try:
                meta = json.loads(payload)
            except Exception:
                meta = {}

        # Look for domain, IP, URL, mail relay
        for key in ("domain", "sender_domain", "target_domain", "lookalike_domain", "phishing_domain"):
            d = meta.get(key)
            if d and isinstance(d, str) and "." in d:
                norm_d = normalize_domain(d)
                canon = make_canonical_key(GraphEntityType.DOMAIN, norm_d)
                if canon not in seen_keys:
                    seen_keys.add(canon)
                    candidates.append(
                        InfrastructureCandidate(
                            id=f"cand-{norm_d}",
                            entity_type="DOMAIN",
                            canonical_key=canon,
                            value=norm_d,
                            role=InfrastructureRole.HOSTING_INFRASTRUCTURE,
                            direction=InfrastructureDirection.INFRASTRUCTURE_ENDPOINT,
                            is_observed=True,
                            is_direct=True,
                            first_seen=f.created_at,
                            last_seen=f.created_at,
                            evidence_refs=[f.id],
                        )
                    )

        for key in ("ip", "origin_ip", "relay_ip", "c2_ip", "resolved_ip"):
            ip_val = meta.get(key)
            if ip_val and isinstance(ip_val, str) and RelayReconstructorService.is_public_ip(ip_val):
                norm_ip = normalize_ip(ip_val)
                canon = make_canonical_key(GraphEntityType.IP, norm_ip)
                is_relay = "relay" in key.lower()
                if canon not in seen_keys:
                    seen_keys.add(canon)
                    candidates.append(
                        InfrastructureCandidate(
                            id=f"cand-{norm_ip}",
                            entity_type="IP",
                            canonical_key=canon,
                            value=norm_ip,
                            role=InfrastructureRole.MAIL_RELAY if is_relay else InfrastructureRole.ORIGIN_CANDIDATE,
                            direction=InfrastructureDirection.RELAY_INFRASTRUCTURE if is_relay else InfrastructureDirection.OBSERVED_SOURCE,
                            is_observed=True,
                            is_direct=True,
                            first_seen=f.created_at,
                            last_seen=f.created_at,
                            evidence_refs=[f.id],
                        )
                    )
                elif is_relay:
                    for cand in candidates:
                        if cand.canonical_key == canon:
                            cand.role = InfrastructureRole.MAIL_RELAY
                            cand.direction = InfrastructureDirection.RELAY_INFRASTRUCTURE
                            if f.id not in cand.evidence_refs:
                                cand.evidence_refs.append(f.id)
                            break

    def _traverse_associated_infrastructure(
        self,
        db: Session,
        incident: IncidentModel,
        observed: List[InfrastructureCandidate],
        observed_keys: Set[str],
        workspace_id: str,
    ) -> List[InfrastructureCandidate]:
        """
        Traverses Security Knowledge Graph from observed entities to find associated
        IPs, Domains, ASNs, Nameservers, and Certificates up to MAX_GRAPH_DEPTH.
        """
        associated: List[InfrastructureCandidate] = []
        visited_keys: Set[str] = set(observed_keys)
        frontier_keys: Set[str] = set(observed_keys)

        for depth in range(1, self.max_graph_depth + 1):
            if not frontier_keys or len(associated) >= self.max_candidates:
                break

            next_frontier: Set[str] = set()

            # Query relationships where source or target is in frontier
            edges = (
                db.query(RelationshipModel)
                .filter(
                    or_(
                        RelationshipModel.source_id.in_(list(frontier_keys)),
                        RelationshipModel.target_id.in_(list(frontier_keys)),
                    )
                )
                .limit(200)
                .all()
            )

            for edge in edges:
                other_id = edge.target_id if edge.source_id in frontier_keys else edge.source_id
                if other_id in visited_keys:
                    continue

                visited_keys.add(other_id)
                next_frontier.add(other_id)

                ent = db.query(EntityModel).filter(or_(EntityModel.id == other_id, EntityModel.canonical_key == other_id)).first()
                if ent:
                    ent_type = ent.entity_type
                    norm_val = ent.name
                    canon_key = ent.canonical_key or make_canonical_key(ent_type, norm_val)
                    first_seen = ent.first_seen
                    last_seen = ent.last_seen
                    ent_id = ent.id
                elif ":" in other_id:
                    parts = other_id.split(":", 1)
                    ent_type = parts[0].upper()
                    norm_val = parts[1]
                    canon_key = other_id
                    first_seen = None
                    last_seen = None
                    ent_id = f"ent-{other_id}"
                else:
                    continue

                if ent_type in ("IP", "DOMAIN", "ASN", "NAMESERVER", "CERTIFICATE", "NETWORK"):
                    role = InfrastructureRole.UNKNOWN
                    direction = InfrastructureDirection.INFRASTRUCTURE_ENDPOINT

                    if ent_type == "ASN":
                        role = InfrastructureRole.HOSTING_INFRASTRUCTURE
                    elif ent_type == "NAMESERVER":
                        role = InfrastructureRole.DNS_INFRASTRUCTURE
                    elif ent_type == "IP":
                        role = InfrastructureRole.HOSTING_INFRASTRUCTURE
                    elif ent_type == "DOMAIN":
                        role = InfrastructureRole.HOSTING_INFRASTRUCTURE

                    associated.append(
                        InfrastructureCandidate(
                            id=f"cand-assoc-{ent_id}",
                            entity_type=ent_type,
                            canonical_key=canon_key,
                            value=norm_val,
                            role=role,
                            direction=direction,
                            is_observed=False,
                            is_direct=False,
                            first_seen=first_seen,
                            last_seen=last_seen,
                            evidence_refs=[edge.id],
                        )
                    )

            frontier_keys = next_frontier

        return associated

    def _enrich_candidate(
        self,
        db: Session,
        candidate: InfrastructureCandidate,
        current_incident_id: str,
        workspace_id: str,
    ) -> None:
        """
        Enriches candidate with IP intelligence (ASN, cloud flags, country),
        historical incidents, and campaign associations.
        """
        if candidate.entity_type == "IP":
            ip_val = candidate.value
            cached_intel = global_ip_cache.get(ip_val)
            if cached_intel:
                candidate.asn = cached_intel.asn
                candidate.asn_org = cached_intel.asn_org or cached_intel.organization
                candidate.country = cached_intel.country
                candidate.country_code = cached_intel.country_code
                candidate.city = cached_intel.city
                candidate.hosting_provider = cached_intel.isp or cached_intel.organization
                candidate.is_shared_infrastructure = bool(cached_intel.is_hosting or cached_intel.is_proxy_vpn_tor)
                candidate.is_vpn_proxy_tor = bool(cached_intel.is_proxy_vpn_tor)

            # Check known cloud ASNs
            if candidate.asn and candidate.asn.upper() in KNOWN_SHARED_CLOUDS:
                candidate.is_cloud_provider = True
                candidate.is_shared_infrastructure = True
                candidate.hosting_provider = KNOWN_SHARED_CLOUDS[candidate.asn.upper()]
                if candidate.asn.upper() in ("AS13335", "AS20940", "AS54113"):
                    candidate.is_cdn = True

        elif candidate.entity_type == "DOMAIN":
            # Check if domain uses known generic CDN / nameserver
            dom_val = candidate.value.lower()
            if any(ns in dom_val for ns in KNOWN_SHARED_NAMESERVERS):
                candidate.is_shared_infrastructure = True

        # Query historical incidents sharing this exact value
        canon = candidate.canonical_key
        past_events = (
            db.query(ThreatEventModel.incident_id)
            .filter(
                ThreatEventModel.incident_id != current_incident_id,
                ThreatEventModel.incident_id.isnot(None),
                ThreatEventModel.metadata_json.like(f"%{candidate.value}%"),
            )
            .distinct()
            .limit(self.MAX_HISTORICAL_INCIDENTS)
            .all()
        )
        hist_inc_ids = [r[0] for r in past_events if r[0]]
        candidate.historical_incident_ids = list(set(hist_inc_ids))

        # Query campaign associations
        campaign_matches = (
            db.query(CampaignModel.id)
            .filter(
                or_(
                    CampaignModel.associated_iocs_json.like(f"%{candidate.value}%"),
                    CampaignModel.fingerprint_json.like(f"%{candidate.value}%"),
                )
            )
            .limit(10)
            .all()
        )
        candidate.campaign_ids = list(set([c[0] for c in campaign_matches if c[0]]))
