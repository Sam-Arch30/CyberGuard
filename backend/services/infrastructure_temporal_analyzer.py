"""
Infrastructure Temporal Analyzer (Section 20).
Analyzes chronological infrastructure activity, DNS resolution shifts, IP rotation,
and infrastructure migration without making unsupported maliciousness assumptions.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from backend.db.models import (
    IncidentModel,
    ThreatEventModel,
    SecurityEventModel,
    FindingModel,
    RelationshipModel,
)
from backend.schemas.infrastructure_attribution import (
    InfrastructureCandidate,
    InfrastructureTimelineEvent,
)

logger = logging.getLogger("cyberguard.infrastructure_temporal_analyzer")


class InfrastructureTemporalAnalyzer:
    """
    Synthesizes chronological timeline of infrastructure observations and detects migrations/rotations.
    """

    def analyze_timeline(
        self,
        db: Session,
        incident: IncidentModel,
        candidates: List[InfrastructureCandidate],
    ) -> List[InfrastructureTimelineEvent]:
        """
        Builds a chronological list of infrastructure events and detects potential migrations.
        """
        events: List[InfrastructureTimelineEvent] = []
        if not candidates:
            return events

        # 1. Harvest chronological observations from SecurityEventModel
        sec_events = (
            db.query(SecurityEventModel)
            .filter(SecurityEventModel.incident_id == incident.id)
            .order_by(SecurityEventModel.event_time.asc())
            .all()
        )
        for se in sec_events:
            payload_str = str(getattr(se, "attributes_json", None) or getattr(se, "raw_payload", None) or "")
            for c in candidates:
                if c.value in payload_str:
                    events.append(
                        InfrastructureTimelineEvent(
                            id=f"timeline-se-{se.id}-{c.value[:10]}",
                            timestamp=se.event_time,
                            event_type=se.event_type,
                            entity_value=c.value,
                            related_entity=None,
                            description=f"Observed in {se.event_type} event: {c.value} ({c.role.value})",
                            evidence_id=se.id,
                        )
                    )

        # 2. Harvest chronological observations from ThreatEventModel
        threat_events = (
            db.query(ThreatEventModel)
            .filter(ThreatEventModel.incident_id == incident.id)
            .order_by(ThreatEventModel.timestamp.asc())
            .all()
        )
        for te in threat_events:
            for c in candidates:
                if c.value in (te.metadata_json or "") or c.value in te.summary:
                    events.append(
                        InfrastructureTimelineEvent(
                            id=f"timeline-te-{te.id}-{c.value[:10]}",
                            timestamp=te.timestamp,
                            event_type=te.event_type,
                            entity_value=c.value,
                            related_entity=None,
                            description=f"ThreatEvent observation: {te.summary[:100]}",
                            evidence_id=te.id,
                        )
                    )

        # 3. Detect DNS / Hosting Migrations from Knowledge Graph relationships
        dns_edges = (
            db.query(RelationshipModel)
            .filter(
                RelationshipModel.relationship_type.in_(["RESOLVES_TO", "HOSTED_ON", "USES_NAMESERVER"])
            )
            .order_by(RelationshipModel.created_at.asc())
            .all()
        )
        domain_to_ips: Dict[str, List[Tuple[str, datetime]]] = {}
        for edge in dns_edges:
            if edge.relationship_type in ("RESOLVES_TO", "HOSTED_ON"):
                d_id = edge.source_id
                ip_id = edge.target_id
                t = edge.created_at or datetime.now(timezone.utc)
                if d_id not in domain_to_ips:
                    domain_to_ips[d_id] = []
                domain_to_ips[d_id].append((ip_id, t))

        for d_id, ip_history in domain_to_ips.items():
            if len(ip_history) >= 2:
                # Multiple IP resolutions detected across time
                prev_ip, prev_t = ip_history[0]
                for curr_ip, curr_t in ip_history[1:]:
                    if curr_ip != prev_ip:
                        events.append(
                            InfrastructureTimelineEvent(
                                id=f"timeline-mig-{d_id}-{curr_ip}",
                                timestamp=curr_t,
                                event_type="INFRASTRUCTURE_MIGRATION",
                                entity_value=d_id,
                                related_entity=curr_ip,
                                description=f"Observed infrastructure transition: {d_id} re-routed from {prev_ip} to {curr_ip}",
                                is_migration=True,
                                is_rotation=True,
                            )
                        )
                    prev_ip, prev_t = curr_ip, curr_t

        # Deduplicate and sort chronologically
        events.sort(key=lambda e: e.timestamp)
        seen_ids = set()
        deduped = []
        for e in events:
            if e.id not in seen_ids:
                seen_ids.add(e.id)
                deduped.append(e)

        return deduped
