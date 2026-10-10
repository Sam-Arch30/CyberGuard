"""
Section 49: Alert Correlation & Incident Clustering Service.
Groups security alerts sharing infrastructure, identities, indicators, artifacts,
temporal proximity, campaigns, or graph edges into explainable, persisted Alert Clusters.
Strictly preserves tenant isolation and immutable audit trails.
"""
from __future__ import annotations

import json
import logging
import uuid
import re
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from sqlalchemy import desc, func, or_, and_
from sqlalchemy.orm import Session

from backend.db.models import (
    NotificationModel,
    FindingModel,
    FindingEvidenceModel,
    AnalysisRunModel,
    ArtifactModel,
    IncidentModel,
    CampaignModel,
    AuditLogModel,
    AlertClusterModel,
    AlertClusterMemberModel,
    get_utc_now,
)
from backend.schemas.alert_clusters import (
    ClusterStatusEnum,
    CorrelationSignalTypeEnum,
    CorrelationSignal,
    AlertClusterItemResponse,
    AlertClusterDetailResponse,
    AlertClusterMemberResponse,
    AlertClusterListResponse,
)
from backend.schemas.realtime import (
    RealtimeEvent,
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
)
from backend.services.audit_service import AuditService
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger("cyberguard.services.alert_correlation")

CORRELATION_VERSION = "1.0.0"
CORRELATION_THRESHOLD = 0.60

COMMON_INFRASTRUCTURE_DOMAINS = {
    "google.com", "microsoft.com", "cloudflare.com", "apple.com", "amazonaws.com",
    "github.com", "windows.com", "office.com", "live.com", "gmail.com",
    "yahoo.com", "outlook.com", "akamai.net", "fastly.net", "azure.com"
}
COMMON_INFRASTRUCTURE_IPS = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "127.0.0.1", "0.0.0.0"
}


class AlertCorrelationService:
    """
    Authoritative correlation engine grouping related security alerts into persistent clusters.
    """

    # =========================================================================
    # 1. CORRELATION EVALUATION & SCORING
    # =========================================================================

    @classmethod
    def extract_alert_features(cls, db: Session, alert: NotificationModel) -> Dict[str, Any]:
        """Extracts normalized correlation features from an alert, its finding, and evidence."""
        meta = {}
        if alert.metadata_json:
            try:
                meta = json.loads(alert.metadata_json)
            except Exception:
                meta = {}

        features = {
            "alert_id": alert.id,
            "workspace_id": alert.workspace_id,
            "created_at": alert.created_at,
            "user_id": alert.user_id or meta.get("user_id") or meta.get("recipient") or meta.get("user"),
            "sender": meta.get("sender"),
            "source_id": alert.source_id,
            "source_type": alert.source_type,
            "finding_id": alert.finding_id,
            "analysis_run_id": alert.analysis_run_id,
            "investigation_id": alert.investigation_id,
            "campaign_id": meta.get("campaign_id"),
            "endpoint_id": meta.get("endpoint_id") or meta.get("device_id"),
            "urls": set(),
            "domains": set(),
            "ips": set(),
            "hashes": set(),
        }

        # Extract indicators from metadata if present (supports scalar or list)
        raw_urls = meta.get("urls", [])
        if isinstance(raw_urls, str):
            raw_urls = [raw_urls]
        if meta.get("url") and isinstance(meta.get("url"), str):
            raw_urls = list(raw_urls) + [meta.get("url")]
        for u in raw_urls:
            if isinstance(u, str) and u.strip():
                features["urls"].add(u.strip().lower())
                domain = cls._extract_domain(u)
                if domain:
                    features["domains"].add(domain)

        raw_domains = meta.get("domains", [])
        if isinstance(raw_domains, str):
            raw_domains = [raw_domains]
        if meta.get("domain") and isinstance(meta.get("domain"), str):
            raw_domains = list(raw_domains) + [meta.get("domain")]
        for d in raw_domains:
            if isinstance(d, str) and d.strip():
                features["domains"].add(d.strip().lower())

        raw_ips = meta.get("ips", [])
        if isinstance(raw_ips, str):
            raw_ips = [raw_ips]
        if meta.get("ip") and isinstance(meta.get("ip"), str):
            raw_ips = list(raw_ips) + [meta.get("ip")]
        for ip in raw_ips:
            if isinstance(ip, str) and ip.strip():
                features["ips"].add(ip.strip())

        raw_hashes = meta.get("hashes", [])
        if isinstance(raw_hashes, str):
            raw_hashes = [raw_hashes]
        for h_key in ("hash", "sha256", "md5", "sha1"):
            if meta.get(h_key) and isinstance(meta.get(h_key), str):
                raw_hashes = list(raw_hashes) + [meta.get(h_key)]
        for h in raw_hashes:
            if isinstance(h, str) and h.strip():
                features["hashes"].add(h.strip().lower())

        # Extract from finding & evidence items
        if alert.finding_id:
            finding = db.query(FindingModel).filter(FindingModel.id == alert.finding_id).first()
            if finding:
                for ev in finding.evidence_items:
                    val = getattr(ev, "value", None) or getattr(ev, "indicator_value", "")
                    if not val:
                        continue
                    ev_type = (ev.evidence_type or "").upper()
                    if "URL" in ev_type:
                        features["urls"].add(val.strip().lower())
                        dom = cls._extract_domain(val)
                        if dom:
                            features["domains"].add(dom)
                    elif "DOMAIN" in ev_type:
                        features["domains"].add(val.strip().lower())
                    elif "IP" in ev_type:
                        features["ips"].add(val.strip())
                    elif "HASH" in ev_type or len(val) in (32, 40, 64):
                        features["hashes"].add(val.strip().lower())

        # Extract from analysis run artifact
        if alert.analysis_run_id:
            run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == alert.analysis_run_id).first()
            if run and run.artifact and run.artifact.sha256:
                features["hashes"].add(run.artifact.sha256.strip().lower())

        return features

    @classmethod
    def compare_alert_features(
        cls,
        f_a: Dict[str, Any],
        f_b: Dict[str, Any]
    ) -> Tuple[List[CorrelationSignal], float]:
        """
        Calculates pairwise correlation signals and normalized confidence score (0.0 - 1.0).
        Strictly prevents over-merging on common public infrastructure.
        """
        signals: List[CorrelationSignal] = []
        has_hard_signal = False

        # 1. Identity Signals
        if f_a["user_id"] and f_b["user_id"] and f_a["user_id"] == f_b["user_id"]:
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_USER.value,
                strength=0.85,
                description=f"Both alerts target user identity '{f_a['user_id']}'",
                matched_value=str(f_a["user_id"]),
            ))

        if f_a["sender"] and f_b["sender"] and f_a["sender"].lower() == f_b["sender"].lower():
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_SENDER.value,
                strength=0.75,
                description=f"Identical threat sender '{f_a['sender']}'",
                matched_value=str(f_a["sender"]),
            ))

        # 2. Indicator & Hash Signals (HARD SIGNALS)
        shared_hashes = f_a["hashes"].intersection(f_b["hashes"])
        if shared_hashes:
            h = next(iter(shared_hashes))
            has_hard_signal = True
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_ATTACHMENT_HASH.value,
                strength=0.98,
                description=f"Identical payload/attachment SHA256 digest: {h[:16]}...",
                matched_value=h,
            ))

        shared_urls = f_a["urls"].intersection(f_b["urls"])
        if shared_urls:
            u = next(iter(shared_urls))
            has_hard_signal = True
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_URL.value,
                strength=0.95,
                description=f"Exact shared malicious URL indicator: {u[:48]}...",
                matched_value=u,
            ))

        # 3. Infrastructure Signals (Filtered to avoid public CDN/Cloudflare false clustering)
        shared_domains = f_a["domains"].intersection(f_b["domains"])
        for d in shared_domains:
            if d in COMMON_INFRASTRUCTURE_DOMAINS:
                continue  # Skip generic public cloud / provider domains
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_DOMAIN.value,
                strength=0.85,
                description=f"Shared threat domain: '{d}'",
                matched_value=d,
            ))
            break

        shared_ips = f_a["ips"].intersection(f_b["ips"])
        for ip in shared_ips:
            if ip in COMMON_INFRASTRUCTURE_IPS:
                continue
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_IP.value,
                strength=0.70,
                description=f"Shared destination IP address: '{ip}'",
                matched_value=ip,
            ))
            break

        # 4. Pipeline & Artifact Provenance
        if f_a["analysis_run_id"] and f_a["analysis_run_id"] == f_b["analysis_run_id"]:
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_ANALYSIS_RUN.value,
                strength=0.90,
                description="Originating from the same automated analysis pipeline execution",
                matched_value=f_a["analysis_run_id"],
            ))

        # 5. Campaign Link (HARD SIGNAL)
        if f_a["campaign_id"] and f_a["campaign_id"] == f_b["campaign_id"]:
            has_hard_signal = True
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_CAMPAIGN.value,
                strength=0.95,
                description=f"Both alerts belong to correlated campaign '{f_a['campaign_id']}'",
                matched_value=f_a["campaign_id"],
            ))

        # 6. Investigation Link (HARD SIGNAL)
        if f_a["investigation_id"] and f_a["investigation_id"] == f_b["investigation_id"]:
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_INVESTIGATION.value,
                strength=0.92,
                description=f"Attached to common investigation '{f_a['investigation_id']}'",
                matched_value=f_a["investigation_id"],
            ))

        # 7. Endpoint Link
        if f_a["endpoint_id"] and f_a["endpoint_id"] == f_b["endpoint_id"]:
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.SAME_ENDPOINT.value,
                strength=0.85,
                description=f"Targeting common endpoint/device '{f_a['endpoint_id']}'",
                matched_value=f_a["endpoint_id"],
            ))

        # 8. Temporal Proximity
        dt = abs((f_a["created_at"] - f_b["created_at"]).total_seconds())
        if dt < 1800:  # < 30 minutes
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.TEMPORAL_PROXIMITY.value,
                strength=0.80,
                description=f"Occurred within {int(dt // 60)} minutes of each other",
                matched_value=f"{int(dt // 60)}m",
            ))
        elif dt < 7200:  # < 2 hours
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.TEMPORAL_PROXIMITY.value,
                strength=0.60,
                description=f"Occurred within {int(dt // 3600)} hours of each other",
                matched_value=f"{int(dt // 3600)}h",
            ))
        elif dt < 86400:  # < 24 hours
            signals.append(CorrelationSignal(
                type=CorrelationSignalTypeEnum.TEMPORAL_PROXIMITY.value,
                strength=0.35,
                description="Occurred within the same 24-hour incident window",
                matched_value="24h",
            ))

        # 9. Compute Overall Confidence
        if not signals:
            return [], 0.0

        # Disallow merging if only temporal proximity exists
        non_temporal_signals = [s for s in signals if s.type != CorrelationSignalTypeEnum.TEMPORAL_PROXIMITY.value]
        if not non_temporal_signals:
            return signals, 0.20

        max_strength = max(s.strength for s in signals)
        if has_hard_signal:
            final_score = max(0.85, max_strength)
        else:
            # Weighted cumulative score with asymptotic ceiling
            cumulative = sum(s.strength * 0.4 for s in signals)
            final_score = min(0.95, max_strength * 0.6 + cumulative * 0.4)

        return signals, round(final_score, 3)

    # =========================================================================
    # 2. CANDIDATE RETRIEVAL & CORRELATION ORCHESTRATION
    # =========================================================================

    @classmethod
    def correlate_alert(
        cls,
        db: Session,
        alert_id: str,
        workspace_id: str = "default",
        time_window_hours: int = 48,
        force_recluster: bool = False,
        triggered_by: Optional[str] = None,
    ) -> Optional[AlertClusterModel]:
        """
        Orchestrates bounded candidate retrieval, pairwise scoring, and cluster creation/update.
        Idempotent and safe for asynchronous background workers or live pipeline hooks.
        """
        target_alert = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.id == alert_id,
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
            )
            .first()
        )
        if not target_alert:
            return None

        # Check existing membership
        existing_member = (
            db.query(AlertClusterMemberModel)
            .filter(
                AlertClusterMemberModel.alert_id == alert_id,
                AlertClusterMemberModel.workspace_id == workspace_id,
            )
            .first()
        )
        if existing_member and not force_recluster:
            cluster = db.query(AlertClusterModel).filter(AlertClusterModel.id == existing_member.cluster_id).first()
            if cluster and cluster.status != "RESOLVED" and not cluster.merged_into_cluster_id:
                return cluster

        target_features = cls.extract_alert_features(db, target_alert)

        # Bounded candidate retrieval within temporal window (avoids O(N^2))
        min_time = target_alert.created_at - timedelta(hours=time_window_hours)
        max_time = target_alert.created_at + timedelta(hours=time_window_hours)

        candidate_alerts = (
            db.query(NotificationModel)
            .filter(
                NotificationModel.workspace_id == workspace_id,
                NotificationModel.category == "SECURITY_ALERT",
                NotificationModel.id != alert_id,
                NotificationModel.created_at >= min_time,
                NotificationModel.created_at <= max_time,
            )
            .order_by(desc(NotificationModel.created_at))
            .limit(50)  # Strict candidate bounding
            .all()
        )

        best_candidate: Optional[NotificationModel] = None
        best_signals: List[CorrelationSignal] = []
        best_confidence: float = 0.0

        for cand in candidate_alerts:
            cand_features = cls.extract_alert_features(db, cand)
            signals, conf = cls.compare_alert_features(target_features, cand_features)
            if conf >= CORRELATION_THRESHOLD and conf > best_confidence:
                best_confidence = conf
                best_signals = signals
                best_candidate = cand

        if not best_candidate or best_confidence < CORRELATION_THRESHOLD:
            # Alert remains unclustered
            return None

        # Determine if best candidate is already in an active cluster
        cand_membership = (
            db.query(AlertClusterMemberModel)
            .filter(
                AlertClusterMemberModel.alert_id == best_candidate.id,
                AlertClusterMemberModel.workspace_id == workspace_id,
            )
            .first()
        )

        cluster: Optional[AlertClusterModel] = None

        if cand_membership:
            cluster = (
                db.query(AlertClusterModel)
                .filter(
                    AlertClusterModel.id == cand_membership.cluster_id,
                    AlertClusterModel.workspace_id == workspace_id,
                )
                .first()
            )

        if cluster and not cluster.merged_into_cluster_id:
            # Attach to existing cluster
            cls._add_member_to_cluster(
                db=db,
                cluster=cluster,
                alert=target_alert,
                signals=best_signals,
                confidence=best_confidence,
                workspace_id=workspace_id,
            )
        else:
            # Create new AlertCluster containing both alerts
            cluster = cls._create_new_cluster(
                db=db,
                primary_alert=target_alert,
                peer_alert=best_candidate,
                signals=best_signals,
                confidence=best_confidence,
                workspace_id=workspace_id,
            )

        return cluster

    # =========================================================================
    # 3. CLUSTER MUTATION HELPERS
    # =========================================================================

    @classmethod
    def _create_new_cluster(
        cls,
        db: Session,
        primary_alert: NotificationModel,
        peer_alert: NotificationModel,
        signals: List[CorrelationSignal],
        confidence: float,
        workspace_id: str,
    ) -> AlertClusterModel:
        """Instantiates a new AlertCluster with two initial members."""
        cluster_id = str(uuid.uuid4())
        cluster_number = f"CLU-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

        # Generate descriptive title & summary
        title = f"Correlated Alert Group: {primary_alert.title}"
        summary = f"Clustered {primary_alert.notification_type} with {peer_alert.notification_type}. Primary correlation: {signals[0].description if signals else 'Shared observables'}."

        first_seen = min(primary_alert.created_at, peer_alert.created_at)
        last_seen = max(primary_alert.created_at, peer_alert.created_at)

        # Aggregate severity & risk deterministically
        sev = cls._aggregate_severity([primary_alert.severity, peer_alert.severity])
        risk = cls._aggregate_risk([
            cls._get_alert_risk(primary_alert),
            cls._get_alert_risk(peer_alert),
        ])

        inv_id = primary_alert.investigation_id or peer_alert.investigation_id

        cluster = AlertClusterModel(
            id=cluster_id,
            cluster_number=cluster_number,
            workspace_id=workspace_id,
            title=title,
            summary=summary,
            status=ClusterStatusEnum.OPEN.value,
            severity=sev,
            risk_score=risk,
            confidence=confidence,
            alert_count=2,
            primary_alert_id=primary_alert.id,
            investigation_id=inv_id,
            correlation_version=CORRELATION_VERSION,
            first_seen=first_seen,
            last_seen=last_seen,
            metadata_json=json.dumps({"initial_signals": [s.model_dump() for s in signals]}),
            created_at=get_utc_now(),
            updated_at=get_utc_now(),
        )
        db.add(cluster)
        db.flush()

        # Add member 1 (peer)
        m1 = AlertClusterMemberModel(
            id=str(uuid.uuid4()),
            cluster_id=cluster.id,
            alert_id=peer_alert.id,
            workspace_id=workspace_id,
            membership_confidence=1.0,
            correlation_reasons_json=json.dumps([s.model_dump() for s in signals]),
            correlation_version=CORRELATION_VERSION,
            created_at=get_utc_now(),
        )
        db.add(m1)

        # Add member 2 (primary)
        m2 = AlertClusterMemberModel(
            id=str(uuid.uuid4()),
            cluster_id=cluster.id,
            alert_id=primary_alert.id,
            workspace_id=workspace_id,
            membership_confidence=confidence,
            correlation_reasons_json=json.dumps([s.model_dump() for s in signals]),
            correlation_version=CORRELATION_VERSION,
            created_at=get_utc_now(),
        )
        db.add(m2)

        db.commit()
        db.refresh(cluster)

        AuditService.log_audit(
            db=db,
            action="ALERT_CLUSTER_CREATED",
            resource_type="alert_cluster",
            resource_id=cluster.id,
            user="CorrelationEngine",
            details=f"Created cluster {cluster_number} grouping {primary_alert.id[:8]} and {peer_alert.id[:8]} (conf={confidence:.2f}).",
        )

        cls._broadcast_cluster_event(cluster, RealtimeEventTypeEnum.ALERT_CLUSTER_CREATED.value)
        return cluster

    @classmethod
    def _add_member_to_cluster(
        cls,
        db: Session,
        cluster: AlertClusterModel,
        alert: NotificationModel,
        signals: List[CorrelationSignal],
        confidence: float,
        workspace_id: str,
    ) -> AlertClusterMemberModel:
        """Adds a new alert to an existing cluster, updating aggregate statistics."""
        # Check idempotency
        existing = (
            db.query(AlertClusterMemberModel)
            .filter(
                AlertClusterMemberModel.cluster_id == cluster.id,
                AlertClusterMemberModel.alert_id == alert.id,
            )
            .first()
        )
        if existing:
            return existing

        now = get_utc_now()
        member = AlertClusterMemberModel(
            id=str(uuid.uuid4()),
            cluster_id=cluster.id,
            alert_id=alert.id,
            workspace_id=workspace_id,
            membership_confidence=confidence,
            correlation_reasons_json=json.dumps([s.model_dump() for s in signals]),
            correlation_version=CORRELATION_VERSION,
            created_at=now,
        )
        db.add(member)
        db.flush()

        # Update cluster aggregates
        cluster.alert_count = db.query(AlertClusterMemberModel).filter(AlertClusterMemberModel.cluster_id == cluster.id).count()
        cluster.last_seen = max(cluster.last_seen, alert.created_at)
        if alert.investigation_id and not cluster.investigation_id:
            cluster.investigation_id = alert.investigation_id

        # Recalculate severity and risk
        members = db.query(AlertClusterMemberModel).filter(AlertClusterMemberModel.cluster_id == cluster.id).all()
        alerts = [m.alert for m in members if m.alert]
        cluster.severity = cls._aggregate_severity([a.severity for a in alerts])
        cluster.risk_score = cls._aggregate_risk([cls._get_alert_risk(a) for a in alerts])
        cluster.updated_at = now

        db.commit()
        db.refresh(cluster)

        AuditService.log_audit(
            db=db,
            action="ALERT_ADDED_TO_CLUSTER",
            resource_type="alert_cluster",
            resource_id=cluster.id,
            user="CorrelationEngine",
            details=f"Joined alert {alert.id[:8]} to cluster {cluster.cluster_number} (conf={confidence:.2f}).",
        )

        cls._broadcast_cluster_event(cluster, RealtimeEventTypeEnum.ALERT_ADDED_TO_CLUSTER.value)
        return member

    @classmethod
    def merge_clusters(
        cls,
        db: Session,
        target_cluster_id: str,
        source_cluster_id: str,
        workspace_id: str,
        analyst_name: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Optional[AlertClusterModel]:
        """Merges source_cluster into target_cluster, preserving audit history and provenance."""
        if target_cluster_id == source_cluster_id:
            return None

        target = db.query(AlertClusterModel).filter(
            AlertClusterModel.id == target_cluster_id,
            AlertClusterModel.workspace_id == workspace_id,
        ).first()

        source = db.query(AlertClusterModel).filter(
            AlertClusterModel.id == source_cluster_id,
            AlertClusterModel.workspace_id == workspace_id,
        ).first()

        if not target or not source:
            return None

        now = get_utc_now()
        analyst = analyst_name or "CorrelationEngine"

        # Re-parent all members of source into target
        for mem in source.members:
            # Check if alert already in target
            exists_in_target = db.query(AlertClusterMemberModel).filter(
                AlertClusterMemberModel.cluster_id == target.id,
                AlertClusterMemberModel.alert_id == mem.alert_id,
            ).first()
            if not exists_in_target:
                mem.cluster_id = target.id

        db.flush()

        source.status = ClusterStatusEnum.MERGED.value
        source.merged_into_cluster_id = target.id
        source.updated_at = now

        # Update target aggregates
        target.first_seen = min(target.first_seen, source.first_seen)
        target.last_seen = max(target.last_seen, source.last_seen)
        target.alert_count = db.query(AlertClusterMemberModel).filter(AlertClusterMemberModel.cluster_id == target.id).count()

        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if severity_rank.get(source.severity, 0) > severity_rank.get(target.severity, 0):
            target.severity = source.severity
        target.risk_score = max(target.risk_score, source.risk_score)
        target.confidence = max(target.confidence, source.confidence)
        target.updated_at = now

        db.commit()
        db.refresh(target)
        db.refresh(source)

        AuditService.log_audit(
            db=db,
            action="ALERT_CLUSTER_MERGED",
            resource_type="alert_cluster",
            resource_id=target.id,
            user=analyst,
            details=f"Merged cluster {source.cluster_number} into {target.cluster_number}. {reason or ''}".strip(),
        )

        cls._broadcast_cluster_event(target, RealtimeEventTypeEnum.ALERT_CLUSTER_MERGED.value)
        return target

    # =========================================================================
    # 4. QUERY & DETAIL ENDPOINTS
    # =========================================================================

    @classmethod
    def list_clusters(
        cls,
        db: Session,
        workspace_id: str = "default",
        status: Optional[str] = None,
        severity: Optional[str] = None,
        investigation_id: Optional[str] = None,
        campaign_id: Optional[str] = None,
        q: Optional[str] = None,
        limit: int = 25,
        offset: int = 0,
        sort_by: str = "severity_first",
    ) -> AlertClusterListResponse:
        """Retrieves paginated, filtered alert clusters."""
        query = db.query(AlertClusterModel).filter(
            AlertClusterModel.workspace_id == workspace_id,
            AlertClusterModel.merged_into_cluster_id.is_(None),  # Don't show superseded merged clusters
        )

        if status:
            statuses = [s.strip().upper() for s in status.split(",") if s.strip()]
            query = query.filter(AlertClusterModel.status.in_(statuses))

        if severity:
            sevs = [s.strip().upper() for s in severity.split(",") if s.strip()]
            query = query.filter(AlertClusterModel.severity.in_(sevs))

        if investigation_id:
            query = query.filter(AlertClusterModel.investigation_id == investigation_id.strip())

        if campaign_id:
            query = query.filter(AlertClusterModel.campaign_id == campaign_id.strip())

        if q and q.strip():
            term = f"%{q.strip().lower()}%"
            query = query.filter(
                or_(
                    func.lower(AlertClusterModel.title).like(term),
                    func.lower(AlertClusterModel.summary).like(term),
                    func.lower(AlertClusterModel.cluster_number).like(term),
                )
            )

        total = query.count()

        if sort_by == "newest":
            query = query.order_by(desc(AlertClusterModel.created_at))
        elif sort_by == "risk_desc":
            query = query.order_by(desc(AlertClusterModel.risk_score))
        elif sort_by == "alert_count":
            query = query.order_by(desc(AlertClusterModel.alert_count))
        else:
            query = query.order_by(desc(AlertClusterModel.updated_at))

        items = query.offset(offset).limit(limit).all()

        # Counts
        status_counts = dict(
            db.query(AlertClusterModel.status, func.count(AlertClusterModel.id))
            .filter(AlertClusterModel.workspace_id == workspace_id, AlertClusterModel.merged_into_cluster_id.is_(None))
            .group_by(AlertClusterModel.status)
            .all()
        )
        sev_counts = dict(
            db.query(AlertClusterModel.severity, func.count(AlertClusterModel.id))
            .filter(AlertClusterModel.workspace_id == workspace_id, AlertClusterModel.merged_into_cluster_id.is_(None))
            .group_by(AlertClusterModel.severity)
            .all()
        )

        return AlertClusterListResponse(
            items=[AlertClusterItemResponse.model_validate(c) for c in items],
            total=total,
            limit=limit,
            offset=offset,
            counts_by_status=status_counts,
            counts_by_severity=sev_counts,
        )

    @classmethod
    def get_cluster_detail(
        cls,
        db: Session,
        cluster_id: str,
        workspace_id: str = "default",
    ) -> Optional[AlertClusterDetailResponse]:
        """Retrieves full cluster record with member alerts, aggregated signals, timeline, and entities."""
        cluster = (
            db.query(AlertClusterModel)
            .filter(
                AlertClusterModel.id == cluster_id,
                AlertClusterModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not cluster:
            return None

        # Build members with summaries and signals
        members_resp: List[AlertClusterMemberResponse] = []
        all_signals: List[CorrelationSignal] = []
        entities: Dict[str, Set[str]] = {
            "users": set(),
            "domains": set(),
            "ips": set(),
            "urls": set(),
            "hashes": set(),
            "endpoints": set(),
        }
        timeline_events: List[Dict[str, Any]] = []

        for mem in cluster.members:
            signals_data = []
            if mem.correlation_reasons_json:
                try:
                    raw_sigs = json.loads(mem.correlation_reasons_json)
                    signals_data = [CorrelationSignal(**s) for s in raw_sigs]
                    all_signals.extend(signals_data)
                except Exception:
                    pass

            alert_summary = None
            if mem.alert:
                alert_summary = {
                    "id": mem.alert.id,
                    "title": mem.alert.title,
                    "severity": mem.alert.severity,
                    "status": mem.alert.status,
                    "alert_type": mem.alert.notification_type,
                    "risk_score": cls._get_alert_risk(mem.alert),
                    "created_at": mem.alert.created_at.isoformat(),
                    "source_type": mem.alert.source_type,
                }
                timeline_events.append({
                    "timestamp": mem.alert.created_at.isoformat(),
                    "title": mem.alert.title,
                    "severity": mem.alert.severity,
                    "alert_id": mem.alert.id,
                    "type": mem.alert.notification_type,
                })

                # Extract entities from alert
                feats = cls.extract_alert_features(db, mem.alert)
                if feats["user_id"]:
                    entities["users"].add(str(feats["user_id"]))
                if feats["sender"]:
                    entities["users"].add(str(feats["sender"]))
                entities["domains"].update(feats["domains"])
                entities["ips"].update(feats["ips"])
                entities["urls"].update(feats["urls"])
                entities["hashes"].update(feats["hashes"])
                if feats["endpoint_id"]:
                    entities["endpoints"].add(str(feats["endpoint_id"]))

            members_resp.append(AlertClusterMemberResponse(
                id=mem.id,
                alert_id=mem.alert_id,
                cluster_id=mem.cluster_id,
                workspace_id=mem.workspace_id,
                membership_confidence=mem.membership_confidence,
                signals=signals_data,
                alert_summary=alert_summary,
                created_at=mem.created_at,
            ))

        timeline_events.sort(key=lambda x: x["timestamp"])

        # Deduplicate signals
        unique_signals_map: Dict[str, CorrelationSignal] = {}
        for s in all_signals:
            k = f"{s.type}:{s.matched_value}"
            if k not in unique_signals_map or s.strength > unique_signals_map[k].strength:
                unique_signals_map[k] = s

        # Investigation detail
        inv_info = None
        if cluster.investigation_id:
            inc = db.query(IncidentModel).filter(IncidentModel.id == cluster.investigation_id).first()
            if inc:
                inv_info = {
                    "id": inc.id,
                    "incident_number": inc.incident_number,
                    "title": inc.title,
                    "status": inc.status,
                    "severity": inc.severity,
                    "risk_score": inc.risk_score,
                }

        # Audit logs for cluster
        activity_logs = (
            db.query(AuditLogModel)
            .filter(
                AuditLogModel.resource_type == "alert_cluster",
                AuditLogModel.resource_id == cluster.id,
            )
            .order_by(AuditLogModel.timestamp.asc())
            .all()
        )
        activity_list = [
            {
                "action": l.action,
                "timestamp": l.timestamp.isoformat(),
                "user": l.user,
                "details": l.details,
            }
            for l in activity_logs
        ]

        base_item = AlertClusterItemResponse.model_validate(cluster)

        return AlertClusterDetailResponse(
            **base_item.model_dump(),
            members=members_resp,
            aggregated_signals=list(unique_signals_map.values()),
            entities={k: sorted(list(v)) for k, v in entities.items()},
            affected_entities={k: sorted(list(v)) for k, v in entities.items()},
            timeline=timeline_events,
            investigation_detail=inv_info,
            campaign_detail=None,
            activity_log=activity_list,
        )

    @classmethod
    def get_alert_cluster(
        cls,
        db: Session,
        alert_id: str,
        workspace_id: str = "default",
    ) -> Optional[AlertClusterDetailResponse]:
        """Retrieves the active cluster associated with an alert."""
        mem = (
            db.query(AlertClusterMemberModel)
            .filter(
                AlertClusterMemberModel.alert_id == alert_id,
                AlertClusterMemberModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not mem:
            return None
        return cls.get_cluster_detail(db, mem.cluster_id, workspace_id)

    # =========================================================================
    # 5. INVESTIGATION LINKING & STATUS MUTATION
    # =========================================================================

    @classmethod
    def link_investigation(
        cls,
        db: Session,
        cluster_id: str,
        workspace_id: str = "default",
        investigation_id: Optional[str] = None,
        title: Optional[str] = None,
        analyst_name: Optional[str] = None,
        create_if_missing: bool = True,
        investigation_title: Optional[str] = None,
    ) -> Optional[AlertClusterDetailResponse]:
        """
        Connects an AlertCluster to an investigation.
        Creates a new IncidentModel if investigation_id is not specified.
        Updates all member alerts to reference this investigation.
        """
        cluster = (
            db.query(AlertClusterModel)
            .filter(
                AlertClusterModel.id == cluster_id,
                AlertClusterModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not cluster:
            return None

        analyst = analyst_name or "SOC Analyst"
        target_inv_id = investigation_id

        if not target_inv_id:
            # Create new incident / investigation container
            inc_id = str(uuid.uuid4())
            inc_num = f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:4].upper()}"
            inc = IncidentModel(
                id=inc_id,
                incident_number=inc_num,
                workspace_id=workspace_id,
                title=investigation_title or title or cluster.title,
                description=cluster.summary,
                status="OPEN",
                severity=cluster.severity,
                risk_score=cluster.risk_score,
                confidence=cluster.confidence,
                assigned_to=analyst,
                metadata_json=json.dumps({"originating_cluster_id": cluster.id}),
                created_at=get_utc_now(),
                updated_at=get_utc_now(),
            )
            db.add(inc)
            db.flush()
            target_inv_id = inc.id

        cluster.investigation_id = target_inv_id
        cluster.status = ClusterStatusEnum.INVESTIGATING.value
        cluster.updated_at = get_utc_now()

        # Update member alerts to link to investigation as well
        for m in cluster.members:
            if m.alert and not m.alert.investigation_id:
                m.alert.investigation_id = target_inv_id
                m.alert.status = "INVESTIGATING"

        db.commit()
        db.refresh(cluster)

        AuditService.log_audit(
            db=db,
            action="ALERT_CLUSTER_INVESTIGATION_LINKED",
            resource_type="alert_cluster",
            resource_id=cluster.id,
            user=analyst,
            details=f"Linked cluster {cluster.cluster_number} to investigation {target_inv_id}.",
        )

        cls._broadcast_cluster_event(cluster, RealtimeEventTypeEnum.ALERT_CLUSTER_INVESTIGATION_LINKED.value)
        return cls.get_cluster_detail(db, cluster.id, workspace_id)

    @classmethod
    def update_cluster_status(
        cls,
        db: Session,
        cluster_id: str,
        status: Optional[str] = None,
        workspace_id: str = "default",
        reason: Optional[str] = None,
        analyst_name: Optional[str] = None,
        new_status: Optional[str] = None,
    ) -> Optional[AlertClusterDetailResponse]:
        """Updates the status of an alert cluster and logs audit trail."""
        effective_status = (status or new_status or "").strip().upper()
        if not effective_status:
            return None

        cluster = (
            db.query(AlertClusterModel)
            .filter(
                AlertClusterModel.id == cluster_id,
                AlertClusterModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not cluster:
            return None

        clean_status = effective_status
        cluster.status = clean_status
        cluster.updated_at = get_utc_now()
        db.commit()
        db.refresh(cluster)

        analyst = analyst_name or "SOC Analyst"
        AuditService.log_audit(
            db=db,
            action="ALERT_CLUSTER_STATUS_CHANGED",
            resource_type="alert_cluster",
            resource_id=cluster.id,
            user=analyst,
            details=f"Cluster {cluster.cluster_number} status changed to {clean_status}. {reason or ''}".strip(),
        )

        cls._broadcast_cluster_event(cluster, RealtimeEventTypeEnum.ALERT_CLUSTER_UPDATED.value)
        return cls.get_cluster_detail(db, cluster.id, workspace_id)

    # =========================================================================
    # 6. INTERNAL UTILITIES
    # =========================================================================

    @staticmethod
    def _extract_domain(url_or_email: str) -> Optional[str]:
        """Extracts registrable second-level domain from URL or email address."""
        if not url_or_email:
            return None
        text = url_or_email.strip().lower()
        if "@" in text:
            return text.split("@")[-1].strip()
        match = re.search(r"https?://([^/:\s]+)", text)
        if match:
            host = match.group(1)
            parts = host.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
            return host
        if "." in text and "/" not in text:
            parts = text.split(".")
            if len(parts) >= 2:
                return ".".join(parts[-2:])
        return None

    @staticmethod
    def _get_alert_risk(alert: NotificationModel) -> float:
        """Extracts or infers risk score (0-100) from alert record."""
        if alert.metadata_json:
            try:
                m = json.loads(alert.metadata_json)
                if "risk_score" in m:
                    return float(m["risk_score"])
            except Exception:
                pass
        sev_map = {"CRITICAL": 90.0, "HIGH": 75.0, "MEDIUM": 50.0, "LOW": 25.0, "INFO": 10.0}
        return sev_map.get(alert.severity.upper(), 50.0)

    @staticmethod
    def _aggregate_severity(severities: List[str]) -> str:
        """Determines aggregate severity without artificial inflation."""
        sevs = [s.upper() for s in severities if s]
        if "CRITICAL" in sevs:
            return "CRITICAL"
        if "HIGH" in sevs:
            return "HIGH"
        if "MEDIUM" in sevs:
            return "MEDIUM"
        if "LOW" in sevs:
            return "LOW"
        return "INFO"

    @staticmethod
    def _aggregate_risk(risks: List[float]) -> float:
        """Computes deterministic cluster risk from member alerts."""
        if not risks:
            return 0.0
        max_r = max(risks)
        # Small boost for multi-alert clusters capped at 100
        boost = min(len(risks) - 1, 4) * 2.5
        return round(min(100.0, max_r + boost), 1)

    @classmethod
    def _broadcast_cluster_event(cls, cluster: AlertClusterModel, event_type: str) -> None:
        """Emits non-blocking Section 46 real-time SSE event."""
        try:
            evt = RealtimeEvent(
                schema_version=1,
                event_id=str(uuid.uuid4()),
                sequence=1,
                event_type=event_type,
                resource_type=RealtimeResourceScopeEnum.ALERT_CLUSTER.value,
                resource_id=cluster.id,
                workspace_id=cluster.workspace_id,
                investigation_id=cluster.investigation_id,
                status=cluster.status,
                message=f"Cluster {cluster.cluster_number} ({cluster.title}) updated",
                payload={
                    "cluster_id": cluster.id,
                    "cluster_number": cluster.cluster_number,
                    "severity": cluster.severity,
                    "risk_score": cluster.risk_score,
                    "alert_count": cluster.alert_count,
                    "title": cluster.title,
                },
                created_at=get_utc_now(),
            )
            RealtimePublisher._async_broadcast(evt)
        except Exception as e:
            logger.warning("Failed to broadcast alert cluster event: %s", e)
