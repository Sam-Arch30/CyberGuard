"""
Section 55: Advanced Threat Hunting & Investigation Pivots Service.
Coordinates controlled, evidence-driven pivots from suspicious objects into:
- Related objects (IPs, Domains, URLs, Hashes, Certificates, ASNs)
- Behavioral context (Emails, Endpoint Events, Network Telemetry)
- Infrastructure relationships & Attribution hypotheses
- Campaigns, Historical activity, Alerts, and Investigations
- Preserves provenance, timestamps, co-occurrence, and confidence.
- Never automates conclusions or fabricates attribution.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import and_, or_, desc, asc, func
from sqlalchemy.orm import Session

from backend.db.models import (
    get_utc_now,
    generate_uuid,
    IndicatorModel,
    AlertModel,
    FindingModel,
    ArtifactModel,
    EmailAnalysisModel,
    FindingEvidenceModel,
    ThreatIntelligenceRecordModel,
    WatchedIndicatorModel,
    WatchlistModel,
    IncidentModel,
    CaseModel,
    CampaignModel,
    CampaignIncidentModel,
    CampaignEmailModel,
    ThreatEventModel,
    EndpointTelemetryEventModel,
    RelationshipModel,
    RelationshipObservationModel,
    EntityModel,
    InfrastructureAttributionModel,
    InfrastructureAttributionEvidenceModel,
    PivotExecutionModel,
    HuntHypothesisModel,
)
from backend.schemas.hunting import (
    HuntQueryDefinition,
    HuntSourceEnum,
    QueryFilter,
    QueryOperatorEnum,
    TimePresetEnum,
)
from backend.schemas.pivots import (
    PivotCategoryEnum,
    PivotSourceTypeEnum,
    PivotTypeEnum,
    PivotCostClassEnum,
    PivotOriginEnum,
    EvidenceClassificationEnum,
    HypothesisStatusEnum,
    PivotDefinition,
    PivotRegistryResponse,
    PivotRequest,
    PivotResultItem,
    EntityFrequencyContext,
    PivotGraphNode,
    PivotGraphEdge,
    PivotResponse,
    AIPivotRecommendationItem,
    AIPivotRecommendationResponse,
    HypothesisRecordRequest,
    HypothesisResponse,
    PromoteToInvestigationRequest,
    PromoteToInvestigationResponse,
    PromoteToWatchlistRequest,
    PromoteToWatchlistResponse,
    PivotToHuntQueryRequest,
    PivotToHuntQueryResponse,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
    RealtimeEventPayload,
)
from backend.services.realtime_service import RealtimePublisher
from backend.services.security_graph_service import global_security_graph_service
from backend.services.watchlist_monitoring_service import WatchlistMonitoringService

logger = logging.getLogger("cyberguard.services.investigation_pivots")


class InvestigationPivotService:
    """
    Core engine powering Section 55: Advanced Threat Hunting & Investigation Pivots.
    """

    # =========================================================================
    # 1. Controlled Pivot Registry
    # =========================================================================

    PIVOT_REGISTRY: List[PivotDefinition] = [
        # Domain Pivots
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.RESOLVED_IPS,
            target_type=PivotSourceTypeEnum.IP,
            display_name="Resolved IP Addresses",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="RESOLVES_TO",
            description="DNS A/AAAA historical and active resolutions for this domain.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
            reverse_pivot_type=PivotTypeEnum.REVERSE_DNS_DOMAINS,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.ASSOCIATED_CERTIFICATES,
            target_type=PivotSourceTypeEnum.CERTIFICATE,
            display_name="SSL/TLS Certificates",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="PRESENTS_CERTIFICATE",
            description="SSL/TLS certificate fingerprints and SAN names associated with this domain.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
            reverse_pivot_type=PivotTypeEnum.SHARED_CERTIFICATE_DOMAINS,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.BELONGS_TO_ASN,
            target_type=PivotSourceTypeEnum.ASN,
            display_name="Hosting Autonomous System (ASN)",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="HOSTED_IN_ASN",
            description="BGP Autonomous System routing and network allocation.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
            reverse_pivot_type=PivotTypeEnum.ASN_INFRASTRUCTURE,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.NAMESERVERS,
            target_type=PivotSourceTypeEnum.DOMAIN,
            display_name="Authoritative Nameservers",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="DELEGATED_TO_NS",
            description="Authoritative DNS nameservers servicing this domain zone.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.RELATED_EMAILS,
            target_type=PivotSourceTypeEnum.EMAIL,
            display_name="Observed Phishing / Telemetry Emails",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="MENTIONED_IN_EMAIL",
            description="Ingested emails mentioning or originating from this domain.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.ENDPOINT_ACTIVITY,
            target_type=PivotSourceTypeEnum.DEVICE,
            display_name="Endpoint DNS / Connection Telemetry",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="QUERIED_FROM_ENDPOINT",
            description="Agent endpoint processes and devices issuing DNS queries or connections to this domain.",
            cost_class=PivotCostClassEnum.EXPENSIVE,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.RELATED_ALERTS,
            target_type=PivotSourceTypeEnum.ALERT,
            display_name="Correlated Security Alerts",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="TRIGGERED_ALERT",
            description="Security alerts and detections triggered by this domain.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.RELATED_INVESTIGATIONS,
            target_type=PivotSourceTypeEnum.INCIDENT,
            display_name="Linked Security Investigations",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="INVOLVED_IN_INVESTIGATION",
            description="Active or historical incident investigations involving this domain.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.ASSOCIATED_CAMPAIGNS,
            target_type=PivotSourceTypeEnum.CAMPAIGN,
            display_name="Associated Threat Campaigns",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="LINKED_TO_CAMPAIGN",
            description="Correlated multi-vector threat campaigns involving this infrastructure.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),

        # IP Pivots
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.REVERSE_DNS_DOMAINS,
            target_type=PivotSourceTypeEnum.DOMAIN,
            display_name="Hosted / Reverse DNS Domains",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="HOSTS_DOMAIN",
            description="Co-hosted domains and PTR records pointing to this IP.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
            reverse_pivot_type=PivotTypeEnum.RESOLVED_IPS,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.BELONGS_TO_ASN,
            target_type=PivotSourceTypeEnum.ASN,
            display_name="BGP Autonomous System (ASN)",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="ANNOUNCED_BY_ASN",
            description="Autonomous System number and hosting organization for this IP.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.ASSOCIATED_CERTIFICATES,
            target_type=PivotSourceTypeEnum.CERTIFICATE,
            display_name="SSL/TLS Certificates Presented",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="PRESENTS_CERTIFICATE",
            description="X.509 certificates presented on ports 443/8443 by this IP.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.SHARED_IP_DOMAINS,
            target_type=PivotSourceTypeEnum.DOMAIN,
            display_name="Co-Located Infrastructure Domains",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="SHARED_IP_INFRASTRUCTURE",
            description="Other known domains hosted on this exact IP address.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.RELATED_EMAILS,
            target_type=PivotSourceTypeEnum.EMAIL,
            display_name="Originating / Relay Emails",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="ORIGINATING_IP_FOR_EMAIL",
            description="Analyzed emails originating from or relayed through this IP.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.ENDPOINT_ACTIVITY,
            target_type=PivotSourceTypeEnum.DEVICE,
            display_name="Endpoint Outbound Network Connections",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="ENDPOINT_COMMUNICATED_WITH_IP",
            description="Managed endpoints that established network sockets with this IP.",
            cost_class=PivotCostClassEnum.EXPENSIVE,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.RELATED_ALERTS,
            target_type=PivotSourceTypeEnum.ALERT,
            display_name="Associated Security Alerts",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="TRIGGERED_ALERT",
            description="Alerts referencing this IP address.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.RELATED_INVESTIGATIONS,
            target_type=PivotSourceTypeEnum.INCIDENT,
            display_name="Involved Investigations",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="INVOLVED_IN_INVESTIGATION",
            description="Investigations in which this IP is listed as an indicator or target.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),

        # Certificate Pivots
        PivotDefinition(
            source_type=PivotSourceTypeEnum.CERTIFICATE,
            pivot_type=PivotTypeEnum.SHARED_CERTIFICATE_DOMAINS,
            target_type=PivotSourceTypeEnum.DOMAIN,
            display_name="Domains Sharing this Certificate",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="SHARED_SSL_CERTIFICATE",
            description="Other domains using the same SSL/TLS certificate fingerprint or Subject CN/SAN.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.CERTIFICATE,
            pivot_type=PivotTypeEnum.RESOLVED_IPS,
            target_type=PivotSourceTypeEnum.IP,
            display_name="IP Hosts Presenting Certificate",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="PRESENTED_BY_HOST",
            description="Server IPs observed serving this SSL/TLS certificate.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),

        # Hash Pivots
        PivotDefinition(
            source_type=PivotSourceTypeEnum.HASH,
            pivot_type=PivotTypeEnum.ARTIFACT_OBSERVATIONS,
            target_type=PivotSourceTypeEnum.ARTIFACT,
            display_name="Extracted / Analyzed Artifacts",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="HASH_OF_ARTIFACT",
            description="Raw forensic artifacts and payloads matching this hash.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.HASH,
            pivot_type=PivotTypeEnum.EMAIL_ATTACHMENTS,
            target_type=PivotSourceTypeEnum.EMAIL,
            display_name="Associated Phishing Attachments",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="ATTACHED_TO_EMAIL",
            description="Analyzed emails containing an attachment matching this hash.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.HASH,
            pivot_type=PivotTypeEnum.ENDPOINT_ACTIVITY,
            target_type=PivotSourceTypeEnum.DEVICE,
            display_name="Host Process Execution Events",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="EXECUTED_ON_DEVICE",
            description="Endpoint devices where binary or script matching this hash executed.",
            cost_class=PivotCostClassEnum.EXPENSIVE,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.HASH,
            pivot_type=PivotTypeEnum.RELATED_ALERTS,
            target_type=PivotSourceTypeEnum.ALERT,
            display_name="Malware Alerts",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="TRIGGERED_ALERT",
            description="Security alerts raised for this file hash.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),

        # Email Pivots
        PivotDefinition(
            source_type=PivotSourceTypeEnum.EMAIL,
            pivot_type=PivotTypeEnum.EMAIL_RECIPIENTS,
            target_type=PivotSourceTypeEnum.USER,
            display_name="Targeted Mailboxes / Users",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="SENT_TO_USER",
            description="Organizational recipients targeted by this message.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.EMAIL,
            pivot_type=PivotTypeEnum.EMAIL_ATTACHMENTS,
            target_type=PivotSourceTypeEnum.HASH,
            display_name="Message Attachments (Hashes)",
            category=PivotCategoryEnum.ACTIVITY,
            relationship_name="CONTAINS_ATTACHMENT",
            description="File attachment hashes extracted from this message.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.EMAIL,
            pivot_type=PivotTypeEnum.RESOLVED_IPS,
            target_type=PivotSourceTypeEnum.IP,
            display_name="Relay & Originating IPs",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="ORIGINATING_IP",
            description="Hop relay IPs and originating client IP in email headers.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.EMAIL,
            pivot_type=PivotTypeEnum.ASSOCIATED_CAMPAIGNS,
            target_type=PivotSourceTypeEnum.CAMPAIGN,
            display_name="Correlated Campaign Cluster",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="CLUSTERED_INTO_CAMPAIGN",
            description="Wider phishing cluster or impersonation campaign.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),

        # ASN Pivots
        PivotDefinition(
            source_type=PivotSourceTypeEnum.ASN,
            pivot_type=PivotTypeEnum.ASN_INFRASTRUCTURE,
            target_type=PivotSourceTypeEnum.IP,
            display_name="Observed IPs in this Autonomous System",
            category=PivotCategoryEnum.INFRASTRUCTURE,
            relationship_name="ROUTED_IN_ASN",
            description="Observed threat infrastructure IPs announced by this ASN.",
            cost_class=PivotCostClassEnum.NORMAL,
            is_multi_hop_capable=True,
        ),

        # Generic Security Knowledge Graph Pivots
        PivotDefinition(
            source_type=PivotSourceTypeEnum.DOMAIN,
            pivot_type=PivotTypeEnum.KNOWLEDGE_GRAPH_NEIGHBORS,
            target_type=PivotSourceTypeEnum.DOMAIN,
            display_name="Security Knowledge Graph Neighbors",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="GRAPH_RELATIONSHIP",
            description="Direct canonical multi-hop edges from the Security Knowledge Graph.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
        PivotDefinition(
            source_type=PivotSourceTypeEnum.IP,
            pivot_type=PivotTypeEnum.KNOWLEDGE_GRAPH_NEIGHBORS,
            target_type=PivotSourceTypeEnum.IP,
            display_name="Security Knowledge Graph Neighbors",
            category=PivotCategoryEnum.SECURITY,
            relationship_name="GRAPH_RELATIONSHIP",
            description="Direct canonical multi-hop edges from the Security Knowledge Graph.",
            cost_class=PivotCostClassEnum.FAST,
            is_multi_hop_capable=True,
        ),
    ]

    # =========================================================================
    # 2. Registry Retrieval & Request Validation
    # =========================================================================

    @classmethod
    def get_pivot_registry(cls, workspace_id: str = "default") -> PivotRegistryResponse:
        supported_types = sorted(list({p.source_type.value for p in cls.PIVOT_REGISTRY}))
        return PivotRegistryResponse(
            supported_source_types=supported_types,
            pivots=cls.PIVOT_REGISTRY,
            max_depth_allowed=3,
            max_results_allowed=200,
        )

    @classmethod
    def validate_pivot_request(cls, req: PivotRequest, workspace_id: str) -> Optional[PivotDefinition]:
        clean_val = req.source_value.strip()
        if not clean_val:
            raise ValueError("source_value must not be empty.")
        if req.depth < 1 or req.depth > 3:
            raise ValueError("Depth must be bounded between 1 and 3.")
        if req.limit < 1 or req.limit > 200:
            raise ValueError("Limit must be bounded between 1 and 200.")

        matching = [
            p for p in cls.PIVOT_REGISTRY
            if p.source_type == req.source_type and p.pivot_type == req.pivot_type
        ]
        if not matching:
            # Check if generic graph pivot is requested
            if req.pivot_type == PivotTypeEnum.KNOWLEDGE_GRAPH_NEIGHBORS:
                return PivotDefinition(
                    source_type=req.source_type,
                    pivot_type=PivotTypeEnum.KNOWLEDGE_GRAPH_NEIGHBORS,
                    target_type=req.source_type,
                    display_name="Knowledge Graph Neighbors",
                    category=PivotCategoryEnum.SECURITY,
                    relationship_name="CONNECTED_TO",
                    description="Generic Knowledge Graph traversal.",
                    cost_class=PivotCostClassEnum.FAST,
                )
            raise ValueError(
                f"Unsupported pivot '{req.pivot_type.value}' for source type '{req.source_type.value}'."
            )
        return matching[0]

    # =========================================================================
    # 3. Entity Frequency & Historical Context
    # =========================================================================

    @classmethod
    def get_entity_frequency_context(
        cls,
        db: Session,
        source_type: str,
        source_value: str,
        workspace_id: str = "default",
    ) -> EntityFrequencyContext:
        """
        Computes factual occurrence metrics across artifacts, investigations, alerts, and watchlists.
        Adheres to strict truthfulness: calculates from actual database rows without fabrication.
        """
        clean_val = source_value.strip().lower()
        now = get_utc_now()
        first_seen: Optional[datetime] = None
        last_seen: Optional[datetime] = None

        # 1. Check IndicatorModel
        ind = (
            db.query(IndicatorModel)
            .filter(IndicatorModel.normalized_value == clean_val)
            .first()
        )
        verdict = ind.reputation if ind and ind.reputation else None
        threat_score = ind.confidence if ind and ind.confidence is not None else None
        if ind:
            first_seen = ind.first_seen
            last_seen = ind.last_seen

        # 2. Check ThreatIntelligenceRecordModel
        ti = (
            db.query(ThreatIntelligenceRecordModel)
            .filter(
                ThreatIntelligenceRecordModel.normalized_value == clean_val,
                or_(ThreatIntelligenceRecordModel.workspace_id == workspace_id, ThreatIntelligenceRecordModel.workspace_id.is_(None)),
            )
            .first()
        )
        if ti:
            if not verdict and ti.verdict:
                verdict = ti.verdict
            if threat_score is None and ti.confidence is not None:
                threat_score = ti.confidence
            if ti.first_seen:
                first_seen = min(first_seen, ti.first_seen) if first_seen else ti.first_seen
            if ti.last_seen:
                last_seen = max(last_seen, ti.last_seen) if last_seen else ti.last_seen

        # 3. Artifact count (via Indicator occurrences or FindingEvidence)
        artifact_count = (
            db.query(func.count(FindingEvidenceModel.id))
            .filter(FindingEvidenceModel.value.ilike(f"%{clean_val}%"))
            .scalar()
            or 0
        )
        if artifact_count == 0:
            # Check EmailAnalysisModel
            email_hits = (
                db.query(func.count(EmailAnalysisModel.id))
                .filter(
                    or_(
                        EmailAnalysisModel.sender.ilike(f"%{clean_val}%"),
                        EmailAnalysisModel.domains_json.ilike(f"%{clean_val}%"),
                        EmailAnalysisModel.email_sha256 == clean_val,
                    )
                )
                .scalar()
                or 0
            )
            artifact_count = email_hits

        # 4. Investigation count (IncidentModel / CaseModel)
        investigation_count = (
            db.query(func.count(IncidentModel.id))
            .filter(
                or_(
                    IncidentModel.description.ilike(f"%{clean_val}%"),
                    IncidentModel.title.ilike(f"%{clean_val}%"),
                ),
                or_(IncidentModel.workspace_id == workspace_id, IncidentModel.workspace_id.is_(None)),
            )
            .scalar()
            or 0
        )

        # 5. Alert count (AlertModel)
        alert_count = (
            db.query(func.count(AlertModel.id))
            .filter(
                or_(
                    AlertModel.title.ilike(f"%{clean_val}%"),
                    AlertModel.message.ilike(f"%{clean_val}%"),
                ),
                or_(AlertModel.workspace_id == workspace_id, AlertModel.workspace_id.is_(None)),
            )
            .scalar()
            or 0
        )

        # 6. Active Watchlist monitoring status (WatchedIndicatorModel)
        is_monitored = (
            db.query(WatchedIndicatorModel)
            .filter(
                WatchedIndicatorModel.normalized_value == clean_val,
                WatchedIndicatorModel.monitoring_status == "ACTIVE",
                or_(WatchedIndicatorModel.workspace_id == workspace_id, WatchedIndicatorModel.workspace_id.is_(None)),
            )
            .first()
            is not None
        )

        days_span = 0
        if first_seen and last_seen:
            n_first = first_seen.replace(tzinfo=timezone.utc) if first_seen.tzinfo is None else first_seen
            n_last = last_seen.replace(tzinfo=timezone.utc) if last_seen.tzinfo is None else last_seen
            delta = n_last - n_first
            days_span = max(1, delta.days)

        return EntityFrequencyContext(
            source_type=source_type,
            source_value=source_value,
            first_seen=first_seen or now,
            last_seen=last_seen or now,
            observed_days_span=days_span,
            artifact_count=artifact_count,
            investigation_count=investigation_count,
            alert_count=alert_count,
            is_watchlist_monitored=is_monitored,
            reputation_verdict=verdict,
            threat_score=threat_score,
        )

    # =========================================================================
    # 4. Primary Pivot Execution
    # =========================================================================

    @classmethod
    def execute_pivot(
        cls,
        db: Session,
        req: PivotRequest,
        workspace_id: str = "default",
        user_id: str = "analyst",
    ) -> PivotResponse:
        """
        Executes bounded, multi-hop investigation pivot querying:
        1. Security Knowledge Graph canonical edges (Priority 1)
        2. Relational models fallback (Priority 2)
        3. Preserves evidence provenance without automated attribution.
        """
        start_t = time.time()
        pivot_def = cls.validate_pivot_request(req, workspace_id)
        clean_val = req.source_value.strip()

        # Emit Realtime PIVOT_STARTED event
        try:
            RealtimePublisher.publish_event(
                RealtimeEvent(
                    event_type=RealtimeEventTypeEnum.PIVOT_STARTED,
                    workspace_id=workspace_id,
                    resource_scope=RealtimeResourceScopeEnum.PIVOT,
                    resource_id=clean_val,
                    actor_id=user_id,
                    payload=RealtimeEventPayload(
                        title=f"Pivot started: {req.pivot_type.value} on {clean_val}",
                        analyzer="InvestigationPivotService",
                    ),
                )
            )
        except Exception as e:
            logger.debug("Realtime PIVOT_STARTED dispatch failed: %s", e)

        # 1. Fetch Frequency & Historical Context
        freq_ctx = cls.get_entity_frequency_context(
            db=db,
            source_type=req.source_type.value,
            source_value=clean_val,
            workspace_id=workspace_id,
        )

        items: List[PivotResultItem] = []
        graph_nodes: Dict[str, PivotGraphNode] = {}
        graph_edges: List[PivotGraphEdge] = []
        partial_failures: List[str] = []

        # Root node
        root_node_id = f"{req.source_type.value}:{clean_val}"
        graph_nodes[root_node_id] = PivotGraphNode(
            id=root_node_id,
            label=clean_val,
            entity_type=req.source_type.value,
            value=clean_val,
            is_root=True,
            hop_distance=0,
            verdict=freq_ctx.reputation_verdict,
            threat_score=freq_ctx.threat_score,
            metadata={"artifact_count": freq_ctx.artifact_count},
        )

        # 2. Execute Hop 1
        hop1_targets = cls._query_hop_edges(
            db=db,
            source_type=req.source_type,
            source_value=clean_val,
            pivot_type=req.pivot_type,
            limit=req.limit,
            workspace_id=workspace_id,
        )
        items.extend(hop1_targets)

        # Populate graph for Hop 1
        for it in hop1_targets:
            tgt_node_id = f"{it.target_type}:{it.target_value}"
            if tgt_node_id not in graph_nodes:
                graph_nodes[tgt_node_id] = PivotGraphNode(
                    id=tgt_node_id,
                    label=it.display_label,
                    entity_type=it.target_type,
                    value=it.target_value,
                    is_root=False,
                    hop_distance=1,
                    verdict=it.matched_context.get("verdict"),
                    metadata=it.matched_context,
                )
            edge_id = f"edge:{root_node_id}->{tgt_node_id}:{it.relationship_type}"
            graph_edges.append(
                PivotGraphEdge(
                    id=edge_id,
                    source=root_node_id,
                    target=tgt_node_id,
                    relationship=it.relationship_type,
                    label=it.relationship_type,
                    origin=it.origin,
                    confidence=it.confidence,
                    evidence_reference=it.evidence_reference,
                    provenance_explanation=it.relationship_description,
                )
            )

        # 3. Execute Multi-Hop (Depth 2 and 3) if requested
        if req.depth > 1 and hop1_targets:
            visited_values = {clean_val.lower()}
            current_level = hop1_targets[:10]  # Bound expansion branching to top 10 to avoid Cartesian explosion

            for current_hop in range(2, req.depth + 1):
                next_level: List[PivotResultItem] = []
                for parent_item in current_level:
                    parent_val = parent_item.target_value.strip()
                    if parent_val.lower() in visited_values:
                        continue
                    visited_values.add(parent_val.lower())

                    # Determine next logical pivot type
                    next_pivot_type = cls._infer_next_hop_pivot(parent_item.target_type)
                    if not next_pivot_type:
                        continue

                    try:
                        parent_src_enum = PivotSourceTypeEnum(parent_item.target_type)
                    except ValueError:
                        continue

                    sub_targets = cls._query_hop_edges(
                        db=db,
                        source_type=parent_src_enum,
                        source_value=parent_val,
                        pivot_type=next_pivot_type,
                        limit=15,
                        workspace_id=workspace_id,
                    )

                    parent_node_id = f"{parent_item.target_type}:{parent_val}"
                    for sub_it in sub_targets:
                        sub_node_id = f"{sub_it.target_type}:{sub_it.target_value}"
                        if sub_node_id not in graph_nodes and len(graph_nodes) < 100:
                            graph_nodes[sub_node_id] = PivotGraphNode(
                                id=sub_node_id,
                                label=sub_it.display_label,
                                entity_type=sub_it.target_type,
                                value=sub_it.target_value,
                                is_root=False,
                                hop_distance=current_hop,
                                verdict=sub_it.matched_context.get("verdict"),
                                metadata=sub_it.matched_context,
                            )
                        if len(graph_edges) < 200:
                            edge_id = f"edge:{parent_node_id}->{sub_node_id}:{sub_it.relationship_type}"
                            graph_edges.append(
                                PivotGraphEdge(
                                    id=edge_id,
                                    source=parent_node_id,
                                    target=sub_node_id,
                                    relationship=sub_it.relationship_type,
                                    label=sub_it.relationship_type,
                                    origin=sub_it.origin,
                                    confidence=sub_it.confidence,
                                    evidence_reference=sub_it.evidence_reference,
                                    provenance_explanation=sub_it.relationship_description,
                                )
                            )
                        next_level.append(sub_it)

                current_level = next_level

        duration_ms = round((time.time() - start_t) * 1000.0, 2)

        # 4. Record execution log in PivotExecutionModel
        exec_id = generate_uuid()
        try:
            exec_rec = PivotExecutionModel(
                id=exec_id,
                workspace_id=workspace_id,
                source_type=req.source_type.value,
                source_value=clean_val,
                pivot_type=req.pivot_type.value,
                execution_mode=req.execution_mode,
                status="SUCCEEDED",
                depth=req.depth,
                result_count=len(items),
                results_summary_json=json.dumps(
                    {
                        "target_count": len(items),
                        "node_count": len(graph_nodes),
                        "edge_count": len(graph_edges),
                    }
                ),
                duration_ms=duration_ms,
                executed_by=user_id,
                investigation_id=req.investigation_id,
                started_at=freq_ctx.first_seen or get_utc_now(),
                completed_at=get_utc_now(),
            )
            db.add(exec_rec)
            db.commit()
        except Exception as e:
            logger.warning("Failed to record pivot execution log: %s", e)
            db.rollback()

        # Emit Realtime PIVOT_COMPLETED event
        try:
            RealtimePublisher.publish_event(
                RealtimeEvent(
                    event_type=RealtimeEventTypeEnum.PIVOT_COMPLETED,
                    workspace_id=workspace_id,
                    resource_scope=RealtimeResourceScopeEnum.PIVOT,
                    resource_id=clean_val,
                    actor_id=user_id,
                    payload=RealtimeEventPayload(
                        title=f"Pivot completed: {len(items)} targets found",
                        analyzer="InvestigationPivotService",
                    ),
                )
            )
        except Exception as e:
            logger.debug("Realtime PIVOT_COMPLETED dispatch failed: %s", e)

        return PivotResponse(
            source_type=req.source_type.value,
            source_value=clean_val,
            pivot_type=req.pivot_type.value,
            depth=req.depth,
            execution_time_ms=duration_ms,
            total_results=len(items),
            truncated=len(items) >= req.limit,
            items=items[: req.limit],
            frequency_context=freq_ctx,
            graph_nodes=list(graph_nodes.values()),
            graph_edges=graph_edges,
            execution_id=exec_id,
            partial_failures=partial_failures,
        )

    # =========================================================================
    # 5. Core Edge Query Logic (Graph + Relational Models)
    # =========================================================================

    @classmethod
    def _query_hop_edges(
        cls,
        db: Session,
        source_type: PivotSourceTypeEnum,
        source_value: str,
        pivot_type: PivotTypeEnum,
        limit: int,
        workspace_id: str,
    ) -> List[PivotResultItem]:
        """
        Discovers related targets by checking:
        1. Canonical RelationshipModel rows (Security Knowledge Graph)
        2. Domain-specific models (ThreatIntelligence, EmailAnalysis, Artifacts, etc.)
        """
        clean_val = source_value.strip().lower()
        items: List[PivotResultItem] = []
        seen_targets: Set[str] = set()

        # Priority 1: Check canonical Knowledge Graph (RelationshipModel)
        try:
            rel_edges = (
                db.query(RelationshipModel)
                .filter(
                    or_(
                        and_(
                            RelationshipModel.source_type == source_type.value,
                            RelationshipModel.source_id.ilike(clean_val),
                        ),
                        and_(
                            RelationshipModel.target_type == source_type.value,
                            RelationshipModel.target_id.ilike(clean_val),
                        ),
                    ),
                    or_(RelationshipModel.workspace_id == workspace_id, RelationshipModel.workspace_id.is_(None)),
                )
                .limit(limit)
                .all()
            )

            for rel in rel_edges:
                is_source = rel.source_id.lower() == clean_val
                peer_type = rel.target_type if is_source else rel.source_type
                peer_val = rel.target_id if is_source else rel.source_id
                if peer_val.lower() in seen_targets:
                    continue
                seen_targets.add(peer_val.lower())

                items.append(
                    PivotResultItem(
                        id=f"kg:{rel.id}",
                        target_type=peer_type,
                        target_value=peer_val,
                        target_id=rel.id,
                        display_label=peer_val,
                        relationship_type=rel.relationship_type,
                        relationship_description=f"Observed {rel.relationship_type} in Security Knowledge Graph (Confidence: {int(rel.confidence * 100)}%).",
                        origin=rel.origin or "OBSERVED",
                        confidence=rel.confidence,
                        first_seen=rel.first_seen,
                        last_seen=rel.last_seen,
                        evidence_reference=rel.evidence_reference,
                        source_reference=f"Relationship #{rel.id[:8]}",
                        co_occurrence_count=1,
                        pivot_links={
                            "osint_url": f"/intelligence?q={peer_val}",
                            "graph_url": f"/graph?entity={peer_val}",
                        },
                    )
                )
        except Exception as e:
            logger.debug("Knowledge Graph edge lookup exception: %s", e)

        # Priority 2: Database Fallbacks per pivot type
        if pivot_type == PivotTypeEnum.RESOLVED_IPS:
            # Look up in ThreatIntelligenceRecordModel DNS / IP
            ti_records = (
                db.query(ThreatIntelligenceRecordModel)
                .filter(
                    ThreatIntelligenceRecordModel.normalized_value == clean_val,
                    or_(ThreatIntelligenceRecordModel.workspace_id == workspace_id, ThreatIntelligenceRecordModel.workspace_id.is_(None)),
                )
                .all()
            )
            for ti in ti_records:
                dns_attrs = {}
                if ti.normalized_data_json:
                    try:
                        dns_attrs = json.loads(ti.normalized_data_json)
                    except Exception:
                        pass
                # Extract resolutions
                resolutions = dns_attrs.get("resolved_ips", [])
                if not resolutions and dns_attrs.get("a_records"):
                    resolutions = dns_attrs.get("a_records")

                for ip_str in resolutions:
                    if ip_str.lower() in seen_targets:
                        continue
                    seen_targets.add(ip_str.lower())
                    items.append(
                        PivotResultItem(
                            id=f"ti:dns:{ip_str}",
                            target_type="IP",
                            target_value=ip_str,
                            display_label=ip_str,
                            relationship_type="RESOLVES_TO",
                            relationship_description=f"Domain {clean_val} resolved to IP {ip_str} in passive DNS intelligence.",
                            origin=PivotOriginEnum.EXTERNAL_INTELLIGENCE.value,
                            confidence=0.95,
                            first_seen=ti.first_seen,
                            last_seen=ti.last_seen,
                            source_reference=f"TI Record #{ti.id[:8]}",
                            co_occurrence_count=1,
                            pivot_links={"osint_url": f"/intelligence?q={ip_str}"},
                        )
                    )

        elif pivot_type in (PivotTypeEnum.REVERSE_DNS_DOMAINS, PivotTypeEnum.SHARED_IP_DOMAINS):
            # Look up other domains resolving to this IP in ThreatIntelligenceRecordModel
            ti_records = (
                db.query(ThreatIntelligenceRecordModel)
                .filter(
                    ThreatIntelligenceRecordModel.normalized_data_json.ilike(f"%{clean_val}%"),
                    ThreatIntelligenceRecordModel.indicator_type == "DOMAIN",
                    or_(ThreatIntelligenceRecordModel.workspace_id == workspace_id, ThreatIntelligenceRecordModel.workspace_id.is_(None)),
                )
                .limit(limit)
                .all()
            )
            for ti in ti_records:
                if ti.normalized_value.lower() in seen_targets or ti.normalized_value.lower() == clean_val:
                    continue
                seen_targets.add(ti.normalized_value.lower())
                items.append(
                    PivotResultItem(
                        id=f"ti:host:{ti.id}",
                        target_type="DOMAIN",
                        target_value=ti.normalized_value,
                        display_label=ti.normalized_value,
                        relationship_type="HOSTS_DOMAIN",
                        relationship_description=f"Shared infrastructure observed: domain {ti.normalized_value} co-hosted on IP {clean_val}.",
                        origin=PivotOriginEnum.EXTERNAL_INTELLIGENCE.value,
                        confidence=0.85,
                        first_seen=ti.first_seen,
                        last_seen=ti.last_seen,
                        source_reference=f"TI Record #{ti.id[:8]}",
                        matched_context={"verdict": ti.verdict},
                        pivot_links={"osint_url": f"/intelligence?q={ti.normalized_value}"},
                    )
                )

        elif pivot_type == PivotTypeEnum.BELONGS_TO_ASN:
            # Query ThreatIntelligenceRecordModel ASN metadata
            ti = (
                db.query(ThreatIntelligenceRecordModel)
                .filter(
                    ThreatIntelligenceRecordModel.normalized_value == clean_val,
                    or_(ThreatIntelligenceRecordModel.workspace_id == workspace_id, ThreatIntelligenceRecordModel.workspace_id.is_(None)),
                )
                .first()
            )
            if ti and ti.normalized_data_json:
                try:
                    payload = json.loads(ti.normalized_data_json)
                    asn_val = payload.get("asn") or payload.get("asn_number")
                    asn_name = payload.get("asn_name") or payload.get("organization") or "Unknown Carrier"
                    if asn_val:
                        asn_str = str(asn_val) if str(asn_val).startswith("AS") else f"AS{asn_val}"
                        if asn_str.lower() not in seen_targets:
                            seen_targets.add(asn_str.lower())
                            items.append(
                                PivotResultItem(
                                    id=f"asn:{asn_str}",
                                    target_type="ASN",
                                    target_value=asn_str,
                                    display_label=f"{asn_str} ({asn_name})",
                                    relationship_type="HOSTED_IN_ASN",
                                    relationship_description=f"IP/Domain {clean_val} is announced by BGP Autonomous System {asn_str} ({asn_name}).",
                                    origin=PivotOriginEnum.EXTERNAL_INTELLIGENCE.value,
                                    confidence=1.0,
                                    first_seen=ti.first_seen,
                                    last_seen=ti.last_seen,
                                    source_reference=f"BGP Telemetry for {clean_val}",
                                    matched_context={"carrier": asn_name},
                                )
                            )
                except Exception:
                    pass

        elif pivot_type in (PivotTypeEnum.ASSOCIATED_CERTIFICATES, PivotTypeEnum.SHARED_CERTIFICATE_DOMAINS):
            # Query certificate fingerprints in ThreatIntelligenceRecordModel
            ti_records = (
                db.query(ThreatIntelligenceRecordModel)
                .filter(
                    ThreatIntelligenceRecordModel.normalized_data_json.ilike(f"%{clean_val}%"),
                    or_(ThreatIntelligenceRecordModel.workspace_id == workspace_id, ThreatIntelligenceRecordModel.workspace_id.is_(None)),
                )
                .limit(limit)
                .all()
            )
            for ti in ti_records:
                if ti.normalized_value.lower() == clean_val:
                    # Extract certificates presented
                    try:
                        p = json.loads(ti.normalized_data_json or "{}")
                        certs = p.get("certificates", [])
                        for cert_obj in certs:
                            cert_sha = cert_obj.get("sha256") or cert_obj.get("fingerprint")
                            if cert_sha and cert_sha.lower() not in seen_targets:
                                seen_targets.add(cert_sha.lower())
                                items.append(
                                    PivotResultItem(
                                        id=f"cert:{cert_sha[:16]}",
                                        target_type="CERTIFICATE",
                                        target_value=cert_sha,
                                        display_label=f"Cert {cert_sha[:16]}... ({cert_obj.get('subject_cn', 'CN')})",
                                        relationship_type="PRESENTS_CERTIFICATE",
                                        relationship_description=f"Observed X.509 certificate with Subject CN '{cert_obj.get('subject_cn')}' on {clean_val}.",
                                        origin=PivotOriginEnum.EXTERNAL_INTELLIGENCE.value,
                                        confidence=0.9,
                                        first_seen=ti.first_seen,
                                        last_seen=ti.last_seen,
                                        matched_context=cert_obj,
                                    )
                                )
                    except Exception:
                        pass

                else:
                    # Shared certificate domain
                    if ti.normalized_value.lower() not in seen_targets:
                        seen_targets.add(ti.normalized_value.lower())
                        items.append(
                            PivotResultItem(
                                id=f"cert:shared:{ti.id}",
                                target_type="DOMAIN",
                                target_value=ti.normalized_value,
                                display_label=ti.normalized_value,
                                relationship_type="SHARED_SSL_CERTIFICATE",
                                relationship_description=f"Shared SSL/TLS certificate observed across domain {ti.normalized_value}.",
                                origin=PivotOriginEnum.EXTERNAL_INTELLIGENCE.value,
                                confidence=0.85,
                                first_seen=ti.first_seen,
                                last_seen=ti.last_seen,
                                source_reference=f"TI Certificate Correlation",
                                pivot_links={"osint_url": f"/intelligence?q={ti.normalized_value}"},
                            )
                        )

        elif pivot_type == PivotTypeEnum.RELATED_EMAILS:
            # Query EmailAnalysisModel where sender or domains match
            emails = (
                db.query(EmailAnalysisModel)
                .filter(
                    or_(
                        EmailAnalysisModel.sender.ilike(f"%{clean_val}%"),
                        EmailAnalysisModel.domains_json.ilike(f"%{clean_val}%"),
                        EmailAnalysisModel.indicators_json.ilike(f"%{clean_val}%"),
                    )
                )
                .order_by(EmailAnalysisModel.analyzed_at.desc())
                .limit(limit)
                .all()
            )
            for em in emails:
                if em.id in seen_targets:
                    continue
                seen_targets.add(em.id)
                items.append(
                    PivotResultItem(
                        id=f"em:{em.id}",
                        target_type="EMAIL",
                        target_value=em.id,
                        display_label=f"Email: {em.subject[:35] if em.subject else 'Untitled'}",
                        relationship_type="MENTIONED_IN_EMAIL",
                        relationship_description=f"Analyzed email from '{em.sender}' contained reference to {clean_val} (Threat Score: {int(em.threat_score)}).",
                        origin=PivotOriginEnum.OBSERVED.value,
                        confidence=1.0,
                        first_seen=em.analyzed_at,
                        last_seen=em.analyzed_at,
                        source_reference=f"Email Artifact #{em.id[:8]}",
                        matched_context={
                            "sender": em.sender,
                            "recipient": em.recipient,
                            "threat_score": em.threat_score,
                            "severity": em.severity,
                        },
                        pivot_links={"osint_url": f"/analyze?email_id={em.id}"},
                    )
                )

        elif pivot_type == PivotTypeEnum.ENDPOINT_ACTIVITY:
            # Query EndpointTelemetryEventModel
            ep_events = (
                db.query(EndpointTelemetryEventModel)
                .filter(
                    EndpointTelemetryEventModel.payload_json.ilike(f"%{clean_val}%"),
                    or_(EndpointTelemetryEventModel.workspace_id == workspace_id, EndpointTelemetryEventModel.workspace_id.is_(None)),
                )
                .order_by(EndpointTelemetryEventModel.event_time.desc())
                .limit(limit)
                .all()
            )
            for ep in ep_events:
                dev_val = ep.device_id or ep.agent_id
                if dev_val in seen_targets:
                    continue
                seen_targets.add(dev_val)
                items.append(
                    PivotResultItem(
                        id=f"ep:{ep.id}",
                        target_type="DEVICE",
                        target_value=dev_val,
                        display_label=f"Endpoint Device {dev_val[:12]} ({ep.event_type})",
                        relationship_type="QUERIED_FROM_ENDPOINT",
                        relationship_description=f"Endpoint telemetry event '{ep.event_type}' recorded activity involving {clean_val}.",
                        origin=PivotOriginEnum.OBSERVED.value,
                        confidence=0.95,
                        first_seen=ep.event_time,
                        last_seen=ep.event_time,
                        source_reference=f"Telemetry Event #{ep.event_id[:8]}",
                        matched_context={"event_type": ep.event_type, "priority": ep.priority},
                        pivot_links={"osint_url": f"/endpoint"},
                    )
                )

        elif pivot_type == PivotTypeEnum.RELATED_ALERTS:
            alerts = (
                db.query(AlertModel)
                .filter(
                    or_(
                        AlertModel.title.ilike(f"%{clean_val}%"),
                        AlertModel.message.ilike(f"%{clean_val}%"),
                    ),
                    or_(AlertModel.workspace_id == workspace_id, AlertModel.workspace_id.is_(None)),
                )
                .order_by(AlertModel.created_at.desc())
                .limit(limit)
                .all()
            )
            for alt in alerts:
                if alt.id in seen_targets:
                    continue
                seen_targets.add(alt.id)
                items.append(
                    PivotResultItem(
                        id=f"alt:{alt.id}",
                        target_type="ALERT",
                        target_value=alt.id,
                        display_label=f"Alert: {alt.title[:40]}",
                        relationship_type="TRIGGERED_ALERT",
                        relationship_description=f"Security alert '{alt.title}' ({alt.severity}) triggered by observable {clean_val}.",
                        origin=PivotOriginEnum.OBSERVED.value,
                        confidence=1.0,
                        first_seen=alt.created_at,
                        last_seen=alt.created_at,
                        source_reference=f"Alert #{alt.id[:8]}",
                        matched_context={"severity": alt.severity, "status": alt.status},
                        pivot_links={"osint_url": f"/alerts?selected={alt.id}"},
                    )
                )


        elif pivot_type == PivotTypeEnum.RELATED_INVESTIGATIONS:
            incidents = (
                db.query(IncidentModel)
                .filter(
                    or_(
                        IncidentModel.title.ilike(f"%{clean_val}%"),
                        IncidentModel.description.ilike(f"%{clean_val}%"),
                    ),
                    or_(IncidentModel.workspace_id == workspace_id, IncidentModel.workspace_id.is_(None)),
                )
                .order_by(IncidentModel.created_at.desc())
                .limit(limit)
                .all()
            )
            for inc in incidents:
                if inc.id in seen_targets:
                    continue
                seen_targets.add(inc.id)
                items.append(
                    PivotResultItem(
                        id=f"inc:{inc.id}",
                        target_type="INCIDENT",
                        target_value=inc.id,
                        display_label=f"Investigation: {inc.title[:40]}",
                        relationship_type="INVOLVED_IN_INVESTIGATION",
                        relationship_description=f"Active investigation '{inc.incident_number or inc.id[:8]}' lists {clean_val} as evidence.",
                        origin=PivotOriginEnum.OBSERVED.value,
                        confidence=1.0,
                        first_seen=inc.created_at,
                        last_seen=inc.updated_at,
                        source_reference=f"Investigation #{inc.incident_number or inc.id[:8]}",
                        matched_context={"severity": inc.severity, "status": inc.status},
                        pivot_links={"osint_url": f"/investigation/{inc.id}"},
                    )
                )

        elif pivot_type == PivotTypeEnum.ASSOCIATED_CAMPAIGNS:
            campaigns = (
                db.query(CampaignModel)
                .filter(
                    or_(
                        CampaignModel.name.ilike(f"%{clean_val}%"),
                        CampaignModel.description.ilike(f"%{clean_val}%"),
                    )
                )
                .limit(limit)
                .all()
            )
            for cmp in campaigns:
                if cmp.id in seen_targets:
                    continue
                seen_targets.add(cmp.id)
                items.append(
                    PivotResultItem(
                        id=f"cmp:{cmp.id}",
                        target_type="CAMPAIGN",
                        target_value=cmp.id,
                        display_label=f"Campaign: {cmp.name}",
                        relationship_type="LINKED_TO_CAMPAIGN",
                        relationship_description=f"Threat campaign '{cmp.name}' correlates multiple incidents linked to {clean_val}.",
                        origin=PivotOriginEnum.CORRELATED.value,
                        confidence=0.88,
                        first_seen=cmp.first_detected,
                        last_seen=cmp.last_activity,
                        source_reference=f"Campaign #{cmp.id[:8]}",
                        matched_context={"status": cmp.status, "threat_level": cmp.threat_level},
                        pivot_links={"osint_url": f"/campaigns"},
                    )
                )

        return items

    @classmethod
    def _infer_next_hop_pivot(cls, target_type: str) -> Optional[PivotTypeEnum]:
        """
        Determines the most insightful next pivot for a hop-2/hop-3 target.
        """
        t = target_type.upper()
        if t == "IP":
            return PivotTypeEnum.BELONGS_TO_ASN
        if t == "DOMAIN":
            return PivotTypeEnum.RESOLVED_IPS
        if t == "CERTIFICATE":
            return PivotTypeEnum.SHARED_CERTIFICATE_DOMAINS
        if t == "EMAIL":
            return PivotTypeEnum.EMAIL_ATTACHMENTS
        if t == "HASH":
            return PivotTypeEnum.ARTIFACT_OBSERVATIONS
        if t == "DEVICE":
            return PivotTypeEnum.ENDPOINT_ACTIVITY
        return None

    # =========================================================================
    # 6. AI-Assisted Pivot Recommendations
    # =========================================================================

    @classmethod
    def get_pivot_recommendations(
        cls,
        db: Session,
        source_type: str,
        source_value: str,
        workspace_id: str = "default",
    ) -> AIPivotRecommendationResponse:
        """
        Generates explainable, rule-backed suggestions for the next logical investigative pivot.
        Adheres to AI safety: only produces actionable recommendations with analytical rationale;
        never executes pivots directly without analyst approval.
        """
        clean_val = source_value.strip().lower()
        st = source_type.upper()
        recs: List[AIPivotRecommendationItem] = []

        if st == "DOMAIN":
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.RESOLVED_IPS,
                    display_name="Resolve Historical IP Addresses",
                    category=PivotCategoryEnum.INFRASTRUCTURE,
                    rationale=f"Passive DNS telemetry exists for domain '{clean_val}'. Resolving IPs maps hosting infrastructure and potential C2 servers.",
                    expected_yield="A/AAAA IP resolution history",
                    confidence=0.92,
                )
            )
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.ASSOCIATED_CERTIFICATES,
                    display_name="Check SSL/TLS Certificate Fingerprints",
                    category=PivotCategoryEnum.INFRASTRUCTURE,
                    rationale="Adversaries frequently reuse SSL/TLS certificates across phishing lookalike domains.",
                    expected_yield="X.509 SHA256 fingerprints & Subject CN",
                    confidence=0.88,
                )
            )
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.RELATED_EMAILS,
                    display_name="Search Ingested Phishing Emails",
                    category=PivotCategoryEnum.ACTIVITY,
                    rationale=f"Determine whether domain '{clean_val}' was observed in sender addresses, reply-to fields, or body links.",
                    expected_yield="Correlated email payloads & targeted users",
                    confidence=0.85,
                )
            )

        elif st == "IP":
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.REVERSE_DNS_DOMAINS,
                    display_name="Reverse DNS / Co-Hosted Domains",
                    category=PivotCategoryEnum.INFRASTRUCTURE,
                    rationale=f"IP '{clean_val}' may host additional phishing domains or malicious subdomains.",
                    expected_yield="Co-located domains & PTR records",
                    confidence=0.90,
                )
            )
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.BELONGS_TO_ASN,
                    display_name="Inspect Autonomous System (ASN)",
                    category=PivotCategoryEnum.INFRASTRUCTURE,
                    rationale="Determine the bulletproof hosting provider or cloud carrier routing this IP prefix.",
                    expected_yield="BGP ASN number & hosting organization",
                    confidence=0.95,
                )
            )
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.ENDPOINT_ACTIVITY,
                    display_name="Inspect Endpoint Sockets",
                    category=PivotCategoryEnum.ACTIVITY,
                    rationale="Identify corporate endpoints that established outbound socket connections to this address.",
                    expected_yield="Agent connection logs & process hashes",
                    confidence=0.82,
                )
            )

        elif st == "CERTIFICATE":
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.SHARED_CERTIFICATE_DOMAINS,
                    display_name="Discover Domains Sharing Certificate",
                    category=PivotCategoryEnum.INFRASTRUCTURE,
                    rationale="Certificate reuse is a high-fidelity indicator of shared attacker provisioning.",
                    expected_yield="Cluster of sibling malicious domains",
                    confidence=0.94,
                )
            )

        elif st == "HASH":
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.EMAIL_ATTACHMENTS,
                    display_name="Find Associated Emails",
                    category=PivotCategoryEnum.ACTIVITY,
                    rationale=f"Trace the initial delivery vector of payload '{clean_val[:12]}...'.",
                    expected_yield="Phishing messages delivering this attachment",
                    confidence=0.91,
                )
            )
            recs.append(
                AIPivotRecommendationItem(
                    pivot_type=PivotTypeEnum.ENDPOINT_ACTIVITY,
                    display_name="Query Host Execution Logs",
                    category=PivotCategoryEnum.ACTIVITY,
                    rationale="Verify whether any managed device executed this file hash.",
                    expected_yield="Host execution timeline & command line arguments",
                    confidence=0.87,
                )
            )

        return AIPivotRecommendationResponse(
            source_type=source_type,
            source_value=source_value,
            recommendations=recs,
        )

    # =========================================================================
    # 7. Analyst Hypothesis & Classification
    # =========================================================================

    @classmethod
    def record_hypothesis(
        cls,
        db: Session,
        req: HypothesisRecordRequest,
        workspace_id: str = "default",
        user_id: str = "analyst",
    ) -> HypothesisResponse:
        hypo = HuntHypothesisModel(
            id=generate_uuid(),
            workspace_id=workspace_id,
            investigation_id=req.investigation_id,
            title=req.title.strip(),
            hypothesis_text=req.hypothesis_text.strip(),
            source_observable=req.source_observable,
            status=req.status.value,
            supporting_items_json=json.dumps(req.supporting_items),
            contradicting_items_json=json.dumps(req.contradicting_items),
            neutral_items_json=json.dumps(req.neutral_items),
            analyst_notes=req.analyst_notes,
            created_by=user_id,
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )
        db.add(hypo)
        db.commit()
        db.refresh(hypo)

        return HypothesisResponse(
            id=hypo.id,
            workspace_id=hypo.workspace_id,
            investigation_id=hypo.investigation_id,
            title=hypo.title,
            hypothesis_text=hypo.hypothesis_text,
            status=hypo.status,
            source_observable=hypo.source_observable,
            supporting_count=len(req.supporting_items),
            contradicting_count=len(req.contradicting_items),
            neutral_count=len(req.neutral_items),
            supporting_items=req.supporting_items,
            contradicting_items=req.contradicting_items,
            neutral_items=req.neutral_items,
            analyst_notes=hypo.analyst_notes,
            created_by=hypo.created_by,
            created_at=hypo.created_at,
            updated_at=hypo.updated_at,
        )

    @classmethod
    def list_hypotheses(
        cls,
        db: Session,
        workspace_id: str = "default",
        investigation_id: Optional[str] = None,
    ) -> List[HypothesisResponse]:
        q = db.query(HuntHypothesisModel).filter(
            or_(HuntHypothesisModel.workspace_id == workspace_id, HuntHypothesisModel.workspace_id.is_(None))
        )
        if investigation_id:
            q = q.filter(HuntHypothesisModel.investigation_id == investigation_id)

        rows = q.order_by(HuntHypothesisModel.created_at.desc()).limit(50).all()
        res: List[HypothesisResponse] = []
        for h in rows:
            sup = json.loads(h.supporting_items_json or "[]")
            con = json.loads(h.contradicting_items_json or "[]")
            neu = json.loads(h.neutral_items_json or "[]")
            res.append(
                HypothesisResponse(
                    id=h.id,
                    workspace_id=h.workspace_id,
                    investigation_id=h.investigation_id,
                    title=h.title,
                    hypothesis_text=h.hypothesis_text,
                    status=h.status,
                    source_observable=h.source_observable,
                    supporting_count=len(sup),
                    contradicting_count=len(con),
                    neutral_count=len(neu),
                    supporting_items=sup,
                    contradicting_items=con,
                    neutral_items=neu,
                    analyst_notes=h.analyst_notes,
                    created_by=h.created_by,
                    created_at=h.created_at,
                    updated_at=h.updated_at,
                )
            )
        return res

    # =========================================================================
    # 8. Handoff Workflows (Investigation, Watchlist, Threat Hunting)
    # =========================================================================

    @classmethod
    def promote_to_investigation(
        cls,
        db: Session,
        req: PromoteToInvestigationRequest,
        workspace_id: str = "default",
        user_id: str = "analyst",
    ) -> PromoteToInvestigationResponse:
        """
        Promotes selected pivot items to an Investigation (IncidentModel).
        Records relationships without duplicating raw underlying evidence.
        """
        incident_id = req.investigation_id
        incident_num: Optional[str] = None

        if not incident_id:
            # Create a new IncidentModel
            inc_uuid = generate_uuid()
            now = get_utc_now()
            inc_title = req.title or f"Threat Hunt Pivot Investigation: {req.source_value}"
            incident = IncidentModel(
                id=inc_uuid,
                incident_number=f"INV-P-{int(time.time()) % 100000:05d}",
                title=inc_title,
                description=(
                    req.description
                    or f"Created from Threat Hunting Pivot ({req.pivot_type}) on observable '{req.source_value}'. "
                    f"Selected {len(req.selected_target_values)} correlated entities."
                ),
                severity=req.severity or "HIGH",
                status="INVESTIGATING",
                workspace_id=workspace_id,
                created_at=now,
                updated_at=now,
            )
            db.add(incident)
            db.flush()
            incident_id = incident.id
            incident_num = incident.incident_number
        else:
            inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
            if inc:
                incident_num = inc.incident_number

        # Create relationships linking incident to selected target observables
        created_count = 0
        now = get_utc_now()
        for tgt_val in req.selected_target_values:
            rel = RelationshipModel(
                id=generate_uuid(),
                source_type="INCIDENT",
                source_id=incident_id,
                relationship_type="INVOLVES_OBSERVABLE",
                target_type=req.source_type,
                target_id=tgt_val,
                confidence=0.9,
                origin="DERIVED",
                status="ACTIVE",
                workspace_id=workspace_id,
                first_seen=now,
                last_seen=now,
                evidence_reference=f"Threat Hunt Pivot: {req.pivot_type}",
                method="INVESTIGATION_PIVOT",
                created_at=now,
                updated_at=now,
            )
            db.add(rel)
            created_count += 1

        db.commit()

        return PromoteToInvestigationResponse(
            investigation_id=incident_id,
            created_relationships_count=created_count,
            incident_number=incident_num,
            message=f"Successfully linked {created_count} entities to Investigation {incident_num or incident_id[:8]}.",
        )

    @classmethod
    def promote_to_watchlist(
        cls,
        db: Session,
        req: PromoteToWatchlistRequest,
        workspace_id: str = "default",
        user_id: str = "analyst",
    ) -> PromoteToWatchlistResponse:
        """
        Adds selected pivot observables to Section 53 IOC Watchlist for continuous monitoring.
        """
        wl_id = req.watchlist_id
        if not wl_id:
            # Create a dedicated Threat Hunting watchlist
            name = req.watchlist_name or f"Pivot Watchlist - {datetime.now(timezone.utc).strftime('%b %d %H:%M')}"
            wl = WatchlistModel(
                id=generate_uuid(),
                name=name,
                description=f"Continuous threat monitoring for indicators identified via Investigation Pivots.",
                workspace_id=workspace_id,
                status="ACTIVE",
                metadata_json=json.dumps({"tags": ["threat_hunting", "pivot_findings"]}),
                created_by=user_id,
                created_at=get_utc_now(),
                updated_at=get_utc_now(),
            )
            db.add(wl)
            db.flush()
            wl_id = wl.id

        added_count = 0
        now = get_utc_now()
        for val in req.selected_target_values:
            clean_val = val.strip().lower()
            existing = (
                db.query(WatchedIndicatorModel)
                .filter(
                    WatchedIndicatorModel.watchlist_id == wl_id,
                    WatchedIndicatorModel.normalized_value == clean_val,
                )
                .first()
            )
            if not existing:
                w_item = WatchedIndicatorModel(
                    id=generate_uuid(),
                    watchlist_id=wl_id,
                    workspace_id=workspace_id,
                    indicator_type=req.target_type.upper(),
                    raw_value=val.strip(),
                    display_value=val.strip(),
                    normalized_value=clean_val,
                    monitoring_status="ACTIVE",
                    priority="HIGH",
                    created_by=user_id,
                    metadata_json=json.dumps({"added_reason": req.reason}),
                    created_at=now,
                    updated_at=now,
                )
                db.add(w_item)
                added_count += 1

        db.commit()

        return PromoteToWatchlistResponse(
            watchlist_id=wl_id,
            added_items_count=added_count,
            message=f"Successfully added {added_count} indicators to Watchlist #{wl_id[:8]}.",
        )

    @classmethod
    def pivot_to_hunt_query(
        cls,
        req: PivotToHuntQueryRequest,
    ) -> PivotToHuntQueryResponse:
        """
        Converts selected pivot values into a Section 54 HuntQueryDefinition
        enabling iterative analytical queries.
        """
        vals = [v.strip() for v in req.selected_target_values if v.strip()]
        field_name = "normalized_value" if req.target_type.upper() in ("IP", "DOMAIN", "URL", "HASH") else "id"
        source_name = HuntSourceEnum.INDICATORS

        if req.target_type.upper() == "ALERT":
            source_name = HuntSourceEnum.ALERTS
            field_name = "id"
        elif req.target_type.upper() == "INCIDENT":
            source_name = HuntSourceEnum.INCIDENTS
            field_name = "id"

        query_def = HuntQueryDefinition(
            data_source=source_name,
            filters=[
                QueryFilter(
                    field=field_name,
                    operator=QueryOperatorEnum.IN if len(vals) > 1 else QueryOperatorEnum.EQUALS,
                    value=vals if len(vals) > 1 else vals[0],
                )
            ],
            time_range={"preset": "7d"},
            limit=50,
            offset=0,
        )

        suggested_name = f"Threat Hunt: {len(vals)} Pivoted {req.target_type} Entities"
        return PivotToHuntQueryResponse(
            query_definition=query_def,
            suggested_hunt_name=suggested_name,
        )
