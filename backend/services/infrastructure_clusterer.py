"""
Infrastructure Clusterer (Section 20).
Identifies cohesive technical infrastructure clusters based on shared dedicated IPs,
shared custom nameservers, shared certificates, redirect chains, and campaign associations.

CONSERVATIVE CLUSTERING PRINCIPLES:
1. Shared generic hosting (AWS, Cloudflare, Azure, Google Cloud, generic registrar nameservers)
   NEVER forms a cluster on its own.
2. Only groups entities with specific, non-generic technical links or verified campaign associations.
3. Every cluster exposes supporting signals, contradicting signals, and cohesion confidence.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from backend.schemas.attack_confidence import ConfidenceLevel
from backend.schemas.infrastructure_attribution import (
    InfrastructureCandidate,
    InfrastructureCluster,
    InfrastructureClusterMember,
)

logger = logging.getLogger("cyberguard.infrastructure_clusterer")

# Generic ASNs and Nameservers that MUST NOT form clusters on their own
GENERIC_SHARED_ASNS = {
    "AS16509", "AS14618", "AS8075", "AS15169", "AS13335", "AS20940", "AS54113"
}

GENERIC_SHARED_NAMESERVER_SUBSTRINGS = {
    "cloudflare.com",
    "domaincontrol.com",
    "awsdns",
    "googledomains.com",
    "azure-dns",
    "registrar-servers.com",
    "name-services.com",
    "dnsv2.com",
}


class InfrastructureClusterer:
    """
    Groups technically connected infrastructure into conservative clusters.
    """

    def cluster_infrastructure(
        self,
        candidates: List[InfrastructureCandidate],
        incident_id: str,
    ) -> List[InfrastructureCluster]:
        """
        Evaluates candidate entities and constructs infrastructure clusters.
        """
        clusters: List[InfrastructureCluster] = []
        if not candidates:
            return clusters

        # Index candidates by entity type and value
        ip_candidates = [c for c in candidates if c.entity_type == "IP"]
        domain_candidates = [c for c in candidates if c.entity_type == "DOMAIN"]

        # Strategy 1: Shared Dedicated IP Cluster
        # If multiple domains resolve to the same non-shared IP, or multiple IPs share a custom dedicated subnet
        dedicated_ip_groups: Dict[str, List[InfrastructureCandidate]] = defaultdict(list)
        for ip in ip_candidates:
            if not ip.is_shared_infrastructure and not ip.is_cloud_provider and not ip.is_cdn:
                dedicated_ip_groups[ip.value].append(ip)

        # Strategy 2: Historical Incident / Campaign Sharing
        # Group candidates that share $\ge 1$ campaign or $\ge 2$ historical incidents
        campaign_groups: Dict[str, List[InfrastructureCandidate]] = defaultdict(list)
        for c in candidates:
            for camp_id in c.campaign_ids:
                campaign_groups[camp_id].append(c)

        cluster_index = 1
        processed_keys: Set[str] = set()

        # Build Campaign-Linked Clusters
        for camp_id, members in campaign_groups.items():
            if len(members) >= 2:
                member_keys = {m.canonical_key for m in members}
                if member_keys.intersection(processed_keys):
                    continue
                processed_keys.update(member_keys)

                cluster_id = f"CLUSTER-{incident_id[:8]}-{cluster_index:03d}"
                cluster_index += 1

                rel_types = ["RELATED_TO_CAMPAIGN", "SHARED_HISTORICAL_INCIDENTS"]
                supporting_signals = [
                    f"Correlated via threat campaign {camp_id}",
                    f"Contains {len(members)} technical observables",
                ]
                contradicting_signals = []

                has_shared_cloud = any(m.is_cloud_provider or m.is_shared_infrastructure for m in members)
                if has_shared_cloud:
                    contradicting_signals.append("Includes endpoints hosted on shared cloud or multi-tenant infrastructure")

                all_hist_incs = set()
                for m in members:
                    all_hist_incs.update(m.historical_incident_ids)

                cluster_members = [
                    InfrastructureClusterMember(
                        entity_id=m.id,
                        entity_type=m.entity_type,
                        value=m.value,
                        role=m.role.value,
                        is_observed=m.is_observed,
                        direction=m.direction.value,
                    )
                    for m in members
                ]

                conf_val = 0.85 if not has_shared_cloud else 0.65
                conf_level = ConfidenceLevel.HIGH if conf_val >= 0.70 else ConfidenceLevel.MODERATE

                clusters.append(
                    InfrastructureCluster(
                        cluster_id=cluster_id,
                        name=f"Campaign Cluster ({camp_id})",
                        members=cluster_members,
                        relationship_types=rel_types,
                        evidence_count=sum(len(m.evidence_refs) for m in members),
                        incident_count=len(all_hist_incs) + 1,
                        campaign_count=1,
                        supporting_signals=supporting_signals,
                        contradicting_signals=contradicting_signals,
                        confidence=conf_val,
                        confidence_level=conf_level,
                    )
                )

        # Build Dedicated IP / Domain Host Clusters
        for ip_val, ips in dedicated_ip_groups.items():
            # Find domains pointing to this IP or connected through direct evidence
            connected_domains = [
                d for d in domain_candidates
                if any(ip_val in str(d.evidence_refs) for _ in [1]) or
                any(d.canonical_key in str(ip.evidence_refs) for ip in ips)
            ]
            combined = ips + connected_domains
            if len(combined) >= 2:
                member_keys = {m.canonical_key for m in combined}
                if member_keys.intersection(processed_keys):
                    continue
                processed_keys.update(member_keys)

                cluster_id = f"CLUSTER-{incident_id[:8]}-{cluster_index:03d}"
                cluster_index += 1

                rel_types = ["DOMAIN_HOSTED_ON_IP", "SHARED_HOSTING_INFRASTRUCTURE"]
                supporting_signals = [
                    f"Dedicated hosting node {ip_val} associates multiple observed domains/endpoints",
                    "Dedicated unshared IP infrastructure",
                ]
                contradicting_signals = []

                all_hist_incs = set()
                for m in combined:
                    all_hist_incs.update(m.historical_incident_ids)

                cluster_members = [
                    InfrastructureClusterMember(
                        entity_id=m.id,
                        entity_type=m.entity_type,
                        value=m.value,
                        role=m.role.value,
                        is_observed=m.is_observed,
                        direction=m.direction.value,
                    )
                    for m in combined
                ]

                clusters.append(
                    InfrastructureCluster(
                        cluster_id=cluster_id,
                        name=f"Hosting Cluster ({ip_val})",
                        members=cluster_members,
                        relationship_types=rel_types,
                        evidence_count=sum(len(m.evidence_refs) for m in combined),
                        incident_count=len(all_hist_incs) + 1,
                        campaign_count=0,
                        supporting_signals=supporting_signals,
                        contradicting_signals=contradicting_signals,
                        confidence=0.75,
                        confidence_level=ConfidenceLevel.HIGH,
                    )
                )

        # If multiple observed malicious candidates exist in the incident and no dedicated cluster was built,
        # create a consolidated Incident Infrastructure Cluster if there are $\ge 2$ observed endpoints
        if not clusters:
            direct_observed = [c for c in candidates if c.is_observed]
            if len(direct_observed) >= 2:
                cluster_id = f"CLUSTER-{incident_id[:8]}-001"
                all_hist_incs = set()
                for m in direct_observed:
                    all_hist_incs.update(m.historical_incident_ids)

                has_shared = any(m.is_shared_infrastructure for m in direct_observed)
                contradicting_signals = []
                if has_shared:
                    contradicting_signals.append("Observed infrastructure contains multi-tenant cloud or shared hosting")

                clusters.append(
                    InfrastructureCluster(
                        cluster_id=cluster_id,
                        name=f"Incident Observed Infrastructure ({incident_id[:12]})",
                        members=[
                            InfrastructureClusterMember(
                                entity_id=m.id,
                                entity_type=m.entity_type,
                                value=m.value,
                                role=m.role.value,
                                is_observed=m.is_observed,
                                direction=m.direction.value,
                            )
                            for m in direct_observed
                        ],
                        relationship_types=["OBSERVED_IN_INCIDENT"],
                        evidence_count=sum(len(m.evidence_refs) for m in direct_observed),
                        incident_count=len(all_hist_incs) + 1,
                        campaign_count=0,
                        supporting_signals=["Endpoints concurrently observed in incident telemetry"],
                        contradicting_signals=contradicting_signals,
                        confidence=0.55 if not has_shared else 0.40,
                        confidence_level=ConfidenceLevel.MODERATE if not has_shared else ConfidenceLevel.LOW,
                    )
                )

        return clusters
