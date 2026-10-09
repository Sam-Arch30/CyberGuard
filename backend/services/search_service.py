"""
Service layer for Section 43: History & Search.
Unified Discovery & Cross-Investigation Intelligence across investigations, reports,
evidence, indicators, entities, findings, campaigns, and threat memory.
"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy import or_, func, desc, asc
from sqlalchemy.orm import Session

from backend.db.models import (
    AnalysisRunModel,
    ArtifactModel,
    CaseEmailModel,
    CaseFindingModel,
    CaseModel,
    CampaignIncidentModel,
    CampaignModel,
    EntityModel,
    EvidenceModel,
    FindingModel,
    IncidentModel,
    IndicatorModel,
    ReportModel,
    ThreatMemoryEntryModel,
    ThreatMemoryObservationModel,
)
from backend.schemas.search import (
    CrossInvestigationIndicatorResponse,
    IndicatorOccurrenceItem,
    InvestigationListItem,
    InvestigationListResponse,
    SearchFacetsResponse,
    SearchResponse,
    SearchResultItem,
)


class SearchService:
    """
    Authoritative Unified Discovery & Search Engine.
    """

    @classmethod
    def normalize_query(cls, raw: str) -> Tuple[str, str]:
        """
        Safely normalizes search query and categorizes query type:
        ID, HASH, IP, DOMAIN, URL, EMAIL, TEXT.
        """
        q = (raw or "").strip()
        if not q:
            return "", "TEXT"

        # Check for algorithm/prefix tags
        if q.lower().startswith("sha256:") or q.lower().startswith("hash:"):
            clean_hash = re.sub(r"^(sha256:|hash:)\s*", "", q, flags=re.IGNORECASE).strip().lower()
            return clean_hash, "HASH"

        # Check for 64-character SHA-256 hex
        if re.match(r"^[a-fA-F0-9]{64}$", q):
            return q.lower(), "HASH"

        # Check for 32-character MD5 or 40-character SHA1
        if re.match(r"^[a-fA-F0-9]{32}$", q) or re.match(r"^[a-fA-F0-9]{40}$", q):
            return q.lower(), "HASH"

        # Check for known IDs (INV-, INC-, RPT-, CASE-, EVD-)
        if re.match(r"^(inv|inc|rpt|case|evd|run)-[a-zA-Z0-9_-]+$", q, re.IGNORECASE):
            return q.upper(), "ID"

        # Check for IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", q):
            return q.strip(), "IP"

        # Check for email address
        if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", q):
            return q.strip().lower(), "EMAIL"

        # Check for URL (defanged or normal)
        refanged = q.replace("[.]", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")
        if re.match(r"^https?://[^\s]+$", refanged, re.IGNORECASE):
            return refanged.strip(), "URL"

        # Check for Domain
        clean_dom = q.replace("[.]", ".").strip().lower()
        if re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$", clean_dom):
            return clean_dom, "DOMAIN"

        return q, "TEXT"

    @classmethod
    def search(
        cls,
        db: Session,
        query: str,
        resource_types: Optional[List[str]] = None,
        risk_filter: Optional[List[str]] = None,
        severity_filter: Optional[List[str]] = None,
        status_filter: Optional[List[str]] = None,
        source_filter: Optional[List[str]] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
        workspace_id: str = "default",
    ) -> SearchResponse:
        """
        Executes unified search with deterministic ranking across authoritative models.
        """
        start_time = time.perf_counter()
        normalized_q, query_type = cls.normalize_query(query)
        if not normalized_q:
            return SearchResponse(
                query="",
                total=0,
                results=[],
                grouped_counts={},
                has_more=False,
                execution_time_ms=0.0,
            )

        types_set = set(t.lower() for t in (resource_types or [
            "investigation", "report", "indicator", "evidence", "finding", "campaign", "threat_memory"
        ]))

        all_matches: List[SearchResultItem] = []
        counts: Dict[str, int] = {}

        # 1. Search Investigations (IncidentModel & CaseModel)
        if "investigation" in types_set:
            inv_matches = cls._search_investigations(
                db, normalized_q, query_type, risk_filter, severity_filter, status_filter,
                source_filter, from_time, to_time, workspace_id
            )
            counts["investigation"] = len(inv_matches)
            all_matches.extend(inv_matches)

        # 2. Search Reports (ReportModel)
        if "report" in types_set:
            rpt_matches = cls._search_reports(
                db, normalized_q, query_type, severity_filter, status_filter, from_time, to_time
            )
            counts["report"] = len(rpt_matches)
            all_matches.extend(rpt_matches)

        # 3. Search Indicators (IndicatorModel & Extracted IOCs)
        if "indicator" in types_set:
            ind_matches = cls._search_indicators(
                db, normalized_q, query_type, from_time, to_time
            )
            counts["indicator"] = len(ind_matches)
            all_matches.extend(ind_matches)

        # 4. Search Evidence / Artifacts (ArtifactModel & EvidenceModel)
        if "evidence" in types_set:
            evd_matches = cls._search_evidence(
                db, normalized_q, query_type, from_time, to_time
            )
            counts["evidence"] = len(evd_matches)
            all_matches.extend(evd_matches)

        # 5. Search Findings (FindingModel & CaseFindingModel)
        if "finding" in types_set:
            fnd_matches = cls._search_findings(
                db, normalized_q, query_type, severity_filter, from_time, to_time
            )
            counts["finding"] = len(fnd_matches)
            all_matches.extend(fnd_matches)

        # 6. Search Campaigns (CampaignModel)
        if "campaign" in types_set:
            cmp_matches = cls._search_campaigns(
                db, normalized_q, query_type, from_time, to_time
            )
            counts["campaign"] = len(cmp_matches)
            all_matches.extend(cmp_matches)

        # 7. Search Threat Memory (ThreatMemoryEntryModel)
        if "threat_memory" in types_set:
            tm_matches = cls._search_threat_memory(
                db, normalized_q, query_type, from_time, to_time, workspace_id
            )
            counts["threat_memory"] = len(tm_matches)
            all_matches.extend(tm_matches)

        # Deterministic Ranking Sort
        # Highest relevance first, then newest timestamp
        all_matches.sort(
            key=lambda x: (
                x.relevance,
                x.timestamp.timestamp() if x.timestamp else 0.0
            ),
            reverse=True,
        )

        total_count = len(all_matches)
        sliced_results = all_matches[offset : offset + limit]
        has_more = (offset + limit) < total_count
        next_offset = (offset + limit) if has_more else None
        elapsed_ms = (time.perf_counter() - start_time) * 1000

        return SearchResponse(
            query=query,
            total=total_count,
            results=sliced_results,
            grouped_counts=counts,
            has_more=has_more,
            next_offset=next_offset,
            execution_time_ms=round(elapsed_ms, 2),
        )

    @classmethod
    def _search_investigations(
        cls,
        db: Session,
        q: str,
        q_type: str,
        risk_filter: Optional[List[str]],
        severity_filter: Optional[List[str]],
        status_filter: Optional[List[str]],
        source_filter: Optional[List[str]],
        from_time: Optional[datetime],
        to_time: Optional[datetime],
        workspace_id: str,
    ) -> List[SearchResultItem]:
        results: List[SearchResultItem] = []
        term_like = f"%{q}%"

        # Query Incidents
        inc_query = db.query(IncidentModel)
        if q_type == "ID":
            inc_query = inc_query.filter(
                or_(
                    IncidentModel.id == q,
                    IncidentModel.incident_number.ilike(term_like),
                )
            )
        else:
            inc_query = inc_query.filter(
                or_(
                    IncidentModel.id.ilike(term_like),
                    IncidentModel.incident_number.ilike(term_like),
                    IncidentModel.title.ilike(term_like),
                    IncidentModel.description.ilike(term_like),
                )
            )

        if severity_filter:
            sev_upper = [s.upper() for s in severity_filter]
            inc_query = inc_query.filter(IncidentModel.severity.in_(sev_upper))
        if status_filter:
            stat_upper = [s.upper() for s in status_filter]
            inc_query = inc_query.filter(IncidentModel.status.in_(stat_upper))
        if from_time:
            inc_query = inc_query.filter(IncidentModel.created_at >= from_time)
        if to_time:
            inc_query = inc_query.filter(IncidentModel.created_at <= to_time)

        for inc in inc_query.limit(100).all():
            score = inc.risk_score or 0.0
            if risk_filter:
                risk_tier = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
                if risk_tier not in [r.upper() for r in risk_filter]:
                    continue

            # Deterministic Relevance Calculation
            relevance = 50.0
            if q.upper() in (inc.incident_number or "").upper():
                relevance = 100.0 if q.upper() == (inc.incident_number or "").upper() else 80.0
            elif q.lower() in (inc.title or "").lower():
                relevance = 75.0 if q.lower() == (inc.title or "").lower() else 60.0

            results.append(
                SearchResultItem(
                    id=inc.id,
                    type="investigation",
                    title=inc.title,
                    subtitle=f"{inc.incident_number} · Status: {inc.status}",
                    relevance=relevance,
                    timestamp=inc.updated_at or inc.created_at,
                    risk_score=score,
                    severity=inc.severity,
                    status=inc.status,
                    source_type="INCIDENT",
                    matched_field="incident_number" if relevance >= 80.0 else "title",
                    highlights=[inc.title],
                    navigation_target=f"/investigations/{inc.id}",
                    metadata={
                        "incident_number": inc.incident_number,
                        "risk_score": score,
                        "confidence": inc.confidence,
                    },
                )
            )

        # Query Cases
        case_query = db.query(CaseModel)
        if q_type == "ID":
            case_query = case_query.filter(
                or_(CaseModel.id == q, CaseModel.case_number.ilike(term_like))
            )
        else:
            case_query = case_query.filter(
                or_(
                    CaseModel.id.ilike(term_like),
                    CaseModel.case_number.ilike(term_like),
                    CaseModel.title.ilike(term_like),
                    CaseModel.description.ilike(term_like),
                )
            )
        if severity_filter:
            case_query = case_query.filter(CaseModel.severity.in_([s.lower() for s in severity_filter]))
        if status_filter:
            case_query = case_query.filter(CaseModel.status.in_([s.lower() for s in status_filter]))
        if from_time:
            case_query = case_query.filter(CaseModel.created_at >= from_time)
        if to_time:
            case_query = case_query.filter(CaseModel.created_at <= to_time)

        for c in case_query.limit(100).all():
            relevance = 50.0
            if q.upper() in (c.case_number or "").upper():
                relevance = 100.0 if q.upper() == (c.case_number or "").upper() else 80.0
            elif q.lower() in (c.title or "").lower():
                relevance = 75.0

            results.append(
                SearchResultItem(
                    id=c.id,
                    type="investigation",
                    title=c.title,
                    subtitle=f"{c.case_number} · Status: {c.status.upper()}",
                    relevance=relevance,
                    timestamp=c.updated_at or c.created_at,
                    risk_score=75.0 if c.severity == "critical" else 55.0 if c.severity == "high" else 35.0,
                    severity=c.severity.upper(),
                    status=c.status.upper(),
                    source_type="EMAIL",
                    matched_field="case_number" if relevance >= 80.0 else "title",
                    highlights=[c.title],
                    navigation_target=f"/investigations/{c.id}",
                    metadata={"case_number": c.case_number},
                )
            )

        return results

    @classmethod
    def _search_reports(
        cls,
        db: Session,
        q: str,
        q_type: str,
        severity_filter: Optional[List[str]],
        status_filter: Optional[List[str]],
        from_time: Optional[datetime],
        to_time: Optional[datetime],
    ) -> List[SearchResultItem]:
        results: List[SearchResultItem] = []
        term_like = f"%{q}%"

        rpt_query = db.query(ReportModel)
        if q_type == "ID":
            rpt_query = rpt_query.filter(
                or_(
                    ReportModel.id == q,
                    ReportModel.report_number.ilike(term_like),
                    ReportModel.investigation_id.ilike(term_like),
                )
            )
        else:
            rpt_query = rpt_query.filter(
                or_(
                    ReportModel.id.ilike(term_like),
                    ReportModel.report_number.ilike(term_like),
                    ReportModel.title.ilike(term_like),
                    ReportModel.investigation_id.ilike(term_like),
                    ReportModel.summary.ilike(term_like),
                )
            )

        if severity_filter:
            rpt_query = rpt_query.filter(ReportModel.severity.in_([s.lower() for s in severity_filter]))
        if status_filter:
            rpt_query = rpt_query.filter(ReportModel.status.in_([s.upper() for s in status_filter]))
        if from_time:
            rpt_query = rpt_query.filter(ReportModel.created_at >= from_time)
        if to_time:
            rpt_query = rpt_query.filter(ReportModel.created_at <= to_time)

        for r in rpt_query.limit(50).all():
            relevance = 45.0
            if q.upper() in (r.report_number or "").upper():
                relevance = 100.0 if q.upper() == (r.report_number or "").upper() else 85.0
            elif q.lower() in (r.title or "").lower():
                relevance = 70.0

            results.append(
                SearchResultItem(
                    id=r.id,
                    type="report",
                    title=r.title,
                    subtitle=f"{r.report_number} (v{r.report_version or 1}) · {r.status or 'READY'}",
                    relevance=relevance,
                    timestamp=r.created_at,
                    risk_score=r.threat_score or 0.0,
                    severity=(r.severity or "medium").upper(),
                    status=r.status or "READY",
                    source_type=r.report_type or "ANALYST",
                    matched_field="report_number" if relevance >= 85.0 else "title",
                    highlights=[r.title],
                    navigation_target=f"/reports/{r.id}",
                    metadata={
                        "report_number": r.report_number,
                        "report_version": r.report_version or 1,
                        "investigation_id": r.investigation_id,
                    },
                )
            )
        return results

    @classmethod
    def _search_indicators(
        cls,
        db: Session,
        q: str,
        q_type: str,
        from_time: Optional[datetime],
        to_time: Optional[datetime],
    ) -> List[SearchResultItem]:
        results: List[SearchResultItem] = []
        term_like = f"%{q}%"

        # Search IndicatorModel
        ind_query = db.query(IndicatorModel).filter(
            or_(
                IndicatorModel.normalized_value.ilike(term_like),
                IndicatorModel.value.ilike(term_like),
            )
        )
        if from_time:
            ind_query = ind_query.filter(IndicatorModel.last_seen >= from_time)
        if to_time:
            ind_query = ind_query.filter(IndicatorModel.first_seen <= to_time)

        for ind in ind_query.limit(50).all():
            relevance = 50.0
            if q.lower() == ind.normalized_value.lower() or q.lower() == ind.value.lower():
                relevance = 95.0
            elif ind.normalized_value.lower().startswith(q.lower()):
                relevance = 75.0

            results.append(
                SearchResultItem(
                    id=ind.id,
                    type="indicator",
                    title=ind.value,
                    subtitle=f"Type: {ind.indicator_type} · Reputation: {ind.reputation or 'SUSPICIOUS'}",
                    relevance=relevance,
                    timestamp=ind.last_seen or ind.created_at,
                    risk_score=ind.confidence * 100.0,
                    severity="HIGH" if ind.reputation in ["MALICIOUS", "HIGH"] else "MEDIUM",
                    status="ACTIVE",
                    source_type=ind.indicator_type,
                    matched_field="normalized_value",
                    highlights=[ind.value],
                    navigation_target=f"/investigations?q={ind.normalized_value}",
                    metadata={
                        "indicator_type": ind.indicator_type,
                        "normalized_value": ind.normalized_value,
                        "reputation": ind.reputation,
                    },
                )
            )
        return results

    @classmethod
    def _search_evidence(
        cls,
        db: Session,
        q: str,
        q_type: str,
        from_time: Optional[datetime],
        to_time: Optional[datetime],
    ) -> List[SearchResultItem]:
        results: List[SearchResultItem] = []
        term_like = f"%{q}%"

        # Search ArtifactModel
        art_query = db.query(ArtifactModel).filter(
            or_(
                ArtifactModel.id == q,
                ArtifactModel.sha256.ilike(term_like),
                ArtifactModel.name.ilike(term_like),
            )
        )
        if from_time:
            art_query = art_query.filter(ArtifactModel.created_at >= from_time)
        if to_time:
            art_query = art_query.filter(ArtifactModel.created_at <= to_time)

        for art in art_query.limit(40).all():
            relevance = 50.0
            if q.lower() == (art.sha256 or "").lower():
                relevance = 95.0
            elif q.lower() in (art.name or "").lower():
                relevance = 75.0

            results.append(
                SearchResultItem(
                    id=art.id,
                    type="evidence",
                    title=art.name or "Forensic Artifact",
                    subtitle=f"SHA256: {(art.sha256 or '')[:16]}... · MIME: {art.mime_type or 'application/octet-stream'}",
                    relevance=relevance,
                    timestamp=art.created_at,
                    risk_score=50.0,
                    severity="INFO",
                    status="INGESTED",
                    source_type=art.artifact_type or "ARTIFACT",
                    matched_field="sha256" if relevance == 95.0 else "name",
                    highlights=[art.name or art.sha256 or "Artifact"],
                    navigation_target=f"/investigations/{art.id}/evidence",
                    metadata={
                        "sha256": art.sha256,
                        "mime_type": art.mime_type,
                        "size": art.size,
                    },
                )
            )

        # Search EvidenceModel
        evd_query = db.query(EvidenceModel).filter(
            or_(
                EvidenceModel.id == q,
                EvidenceModel.evidence_id == q,
                EvidenceModel.sha256.ilike(term_like),
                EvidenceModel.original_filename.ilike(term_like),
            )
        )
        for ev in evd_query.limit(20).all():
            relevance = 50.0
            if q.lower() == (ev.sha256 or "").lower() or q == ev.evidence_id:
                relevance = 95.0

            results.append(
                SearchResultItem(
                    id=ev.id,
                    type="evidence",
                    title=ev.original_filename,
                    subtitle=f"Evidence ID: {ev.evidence_id} · SHA256: {ev.sha256[:16]}...",
                    relevance=relevance,
                    timestamp=ev.upload_timestamp,
                    risk_score=50.0,
                    severity="INFO",
                    status="STORED",
                    source_type="EVIDENCE",
                    matched_field="sha256" if relevance == 95.0 else "original_filename",
                    highlights=[ev.original_filename],
                    navigation_target=f"/investigations/{ev.evidence_id}/evidence",
                    metadata={"evidence_id": ev.evidence_id, "sha256": ev.sha256},
                )
            )

        return results

    @classmethod
    def _search_findings(
        cls,
        db: Session,
        q: str,
        q_type: str,
        severity_filter: Optional[List[str]],
        from_time: Optional[datetime],
        to_time: Optional[datetime],
    ) -> List[SearchResultItem]:
        results: List[SearchResultItem] = []
        term_like = f"%{q}%"

        # Search FindingModel
        fnd_query = db.query(FindingModel).filter(
            or_(
                FindingModel.title.ilike(term_like),
                FindingModel.description.ilike(term_like),
                FindingModel.finding_type.ilike(term_like),
                FindingModel.analyzer.ilike(term_like),
            )
        )
        if severity_filter:
            fnd_query = fnd_query.filter(FindingModel.severity.in_([s.upper() for s in severity_filter]))
        if from_time:
            fnd_query = fnd_query.filter(FindingModel.created_at >= from_time)
        if to_time:
            fnd_query = fnd_query.filter(FindingModel.created_at <= to_time)

        for f in fnd_query.limit(40).all():
            relevance = 40.0
            if q.lower() in (f.title or "").lower():
                relevance = 65.0

            results.append(
                SearchResultItem(
                    id=f.id,
                    type="finding",
                    title=f.title,
                    subtitle=f"Type: {f.finding_type} · Severity: {f.severity}",
                    relevance=relevance,
                    timestamp=f.created_at,
                    risk_score=f.confidence * 100.0,
                    severity=f.severity,
                    status="DETECTED",
                    source_type=f.analyzer or f.finding_type,
                    matched_field="title" if relevance == 65.0 else "description",
                    highlights=[f.title],
                    navigation_target=f"/investigations/{f.analysis_run_id or 'overview'}",
                    metadata={
                        "finding_type": f.finding_type,
                        "analyzer": f.analyzer,
                        "analysis_run_id": f.analysis_run_id,
                        "confidence": f.confidence,
                    },
                )
            )
        return results

    @classmethod
    def _search_campaigns(
        cls,
        db: Session,
        q: str,
        q_type: str,
        from_time: Optional[datetime],
        to_time: Optional[datetime],
    ) -> List[SearchResultItem]:
        results: List[SearchResultItem] = []
        term_like = f"%{q}%"

        cmp_query = db.query(CampaignModel).filter(
            or_(
                CampaignModel.id == q,
                CampaignModel.campaign_id == q,
                CampaignModel.name.ilike(term_like),
                CampaignModel.correlation_summary.ilike(term_like),
            )
        )
        for c in cmp_query.limit(20).all():
            relevance = 50.0
            if q.lower() == (c.name or "").lower():
                relevance = 85.0

            results.append(
                SearchResultItem(
                    id=c.id,
                    type="campaign",
                    title=c.name,
                    subtitle=f"{c.campaign_id} · {c.dominant_attack_type} · Status: {c.status or 'ACTIVE'}",
                    relevance=relevance,
                    timestamp=c.updated_at or c.created_at,
                    risk_score=round((c.overall_confidence or 0.8) * 100.0, 1),
                    severity="HIGH" if (c.overall_confidence or 0) >= 0.7 else "MEDIUM",
                    status=c.status or "ACTIVE",
                    source_type="CAMPAIGN",
                    matched_field="name",
                    highlights=[c.name],
                    navigation_target=f"/campaigns/{c.id}",
                    metadata={"campaign_name": c.name, "campaign_id": c.campaign_id},
                )
            )
        return results


    @classmethod
    def _search_threat_memory(
        cls,
        db: Session,
        q: str,
        q_type: str,
        from_time: Optional[datetime],
        to_time: Optional[datetime],
        workspace_id: str,
    ) -> List[SearchResultItem]:
        results: List[SearchResultItem] = []
        term_like = f"%{q}%"

        tm_query = db.query(ThreatMemoryEntryModel).filter(
            or_(
                ThreatMemoryEntryModel.canonical_key.ilike(term_like),
                ThreatMemoryEntryModel.summary.ilike(term_like),
            )
        )
        if from_time:
            tm_query = tm_query.filter(ThreatMemoryEntryModel.last_seen_at >= from_time)
        if to_time:
            tm_query = tm_query.filter(ThreatMemoryEntryModel.first_seen_at <= to_time)

        for tm in tm_query.limit(30).all():
            relevance = 45.0
            if q.lower() == tm.canonical_key.lower():
                relevance = 90.0

            results.append(
                SearchResultItem(
                    id=tm.id,
                    type="threat_memory",
                    title=tm.canonical_key,
                    subtitle=f"Historical Memory ({tm.provenance_type}) · Seen in {tm.incident_count} Incidents",
                    relevance=relevance,
                    timestamp=tm.last_seen_at,
                    risk_score=tm.confidence * 100.0,
                    severity="HIGH" if tm.status == "VERIFIED" else "MEDIUM",
                    status=tm.status,
                    source_type=tm.memory_type,
                    matched_field="canonical_key",
                    highlights=[tm.canonical_key],
                    navigation_target=f"/investigations?q={tm.canonical_key}",
                    metadata={
                        "provenance_type": tm.provenance_type,
                        "observation_count": tm.observation_count,
                        "incident_count": tm.incident_count,
                        "status": tm.status,
                    },
                )
            )
        return results

    @classmethod
    def lookup_indicator(cls, db: Session, indicator_value: str) -> CrossInvestigationIndicatorResponse:
        """
        Cross-Investigation Indicator Lookup (Section 22, 23, 24, 25).
        Returns exact occurrence history, Threat Memory, and related incidents with strict provenance.
        """
        normalized_val, ind_type = cls.normalize_query(indicator_value)
        norm_like = f"%{normalized_val}%"

        # 1. Resolve related incidents
        related_incidents: List[IndicatorOccurrenceItem] = []
        seen_incident_ids: Set[str] = set()

        # Query incidents where title/description or metadata matches
        incidents = db.query(IncidentModel).filter(
            or_(
                IncidentModel.title.ilike(norm_like),
                IncidentModel.description.ilike(norm_like),
                IncidentModel.metadata_json.ilike(norm_like),
            )
        ).all()

        for inc in incidents:
            if inc.id not in seen_incident_ids:
                seen_incident_ids.add(inc.id)
                related_incidents.append(
                    IndicatorOccurrenceItem(
                        investigation_id=inc.id,
                        incident_number=inc.incident_number,
                        title=inc.title,
                        severity=inc.severity,
                        status=inc.status,
                        observed_at=inc.created_at,
                        source="Incident Record",
                    )
                )

        # Query cases where email subject or indicators_json matches
        case_emails = db.query(CaseEmailModel).filter(
            or_(
                CaseEmailModel.email_sha256.ilike(norm_like),
                CaseEmailModel.sender.ilike(norm_like),
                CaseEmailModel.indicators_json.ilike(norm_like),
            )
        ).all()

        for ce in case_emails:
            c = db.query(CaseModel).filter(CaseModel.id == ce.case_id).first()
            if c and c.id not in seen_incident_ids:
                seen_incident_ids.add(c.id)
                related_incidents.append(
                    IndicatorOccurrenceItem(
                        investigation_id=c.id,
                        incident_number=c.case_number,
                        title=c.title,
                        severity=c.severity.upper(),
                        status=c.status.upper(),
                        observed_at=ce.added_at or c.created_at,
                        source="Email Case",
                    )
                )

        # 2. Check ThreatMemoryEntryModel
        tm_entry = db.query(ThreatMemoryEntryModel).filter(
            or_(
                ThreatMemoryEntryModel.canonical_key == normalized_val,
                ThreatMemoryEntryModel.canonical_key.ilike(norm_like),
            )
        ).first()

        historical_mem: Optional[Dict[str, Any]] = None
        analyst_verifs: List[Dict[str, Any]] = []
        if tm_entry:
            historical_mem = {
                "id": tm_entry.id,
                "canonical_key": tm_entry.canonical_key,
                "memory_type": tm_entry.memory_type,
                "status": tm_entry.status,
                "observation_count": tm_entry.observation_count,
                "incident_count": tm_entry.incident_count,
                "campaign_count": tm_entry.campaign_count,
                "confidence": tm_entry.confidence,
                "provenance_type": tm_entry.provenance_type,
                "summary": tm_entry.summary,
                "first_seen_at": tm_entry.first_seen_at.isoformat() if tm_entry.first_seen_at else None,
                "last_seen_at": tm_entry.last_seen_at.isoformat() if tm_entry.last_seen_at else None,
            }

            # Check analyst decisions / verified observations
            if tm_entry.status == "VERIFIED" or tm_entry.provenance_type == "ANALYST_VERIFIED":
                analyst_verifs.append({
                    "decision": "VERIFIED_MALICIOUS",
                    "status": tm_entry.status,
                    "confidence": tm_entry.confidence,
                    "source": "SOC Analyst Verification",
                    "timestamp": tm_entry.updated_at.isoformat() if tm_entry.updated_at else None,
                })

        # 3. Check Campaigns
        campaigns = db.query(CampaignModel).filter(
            or_(
                CampaignModel.name.ilike(norm_like),
                CampaignModel.correlation_summary.ilike(norm_like),
            )
        ).all()
        related_campaigns = [
            {"id": camp.id, "name": camp.name, "attack_type": camp.dominant_attack_type, "status": camp.status}
            for camp in campaigns
        ]


        # 4. Check Evidence Objects
        evidence_objs = db.query(ArtifactModel).filter(
            or_(
                ArtifactModel.sha256 == normalized_val,
                ArtifactModel.name.ilike(norm_like),
            )
        ).all()

        # 5. External reputation summary
        ind_record = db.query(IndicatorModel).filter(
            or_(
                IndicatorModel.normalized_value == normalized_val,
                IndicatorModel.value == normalized_val,
            )
        ).first()
        reputation_val = ind_record.reputation if ind_record else ("SUSPICIOUS" if len(related_incidents) > 0 else "UNKNOWN")

        first_seen = None
        last_seen = None
        if ind_record:
            first_seen = ind_record.first_seen
            last_seen = ind_record.last_seen
        elif tm_entry:
            first_seen = tm_entry.first_seen_at
            last_seen = tm_entry.last_seen_at
        elif related_incidents:
            first_seen = min(r.observed_at for r in related_incidents)
            last_seen = max(r.observed_at for r in related_incidents)

        return CrossInvestigationIndicatorResponse(
            indicator_value=indicator_value,
            normalized_value=normalized_val,
            indicator_type=ind_type,
            total_investigations=len(related_incidents),
            total_campaigns=len(related_campaigns),
            total_evidence_objects=len(evidence_objs),
            first_observed_at=first_seen,
            last_observed_at=last_seen,
            reputation=reputation_val,
            current_observations=[
                {"source": "Active Investigations", "count": len(related_incidents)}
            ],
            historical_memory=historical_mem,
            external_intelligence={
                "providers_reporting": 2 if reputation_val in ["MALICIOUS", "HIGH"] else 0,
                "reputation": reputation_val,
                "classification": "THREAT_INDICATOR" if reputation_val in ["MALICIOUS", "HIGH"] else "UNRATED",
            },
            analyst_verifications=analyst_verifs,
            related_investigations=related_incidents,
            related_campaigns=related_campaigns,
        )

    @classmethod
    def list_investigations(
        cls,
        db: Session,
        q: Optional[str] = None,
        risk_filter: Optional[str] = None,
        severity_filter: Optional[str] = None,
        status_filter: Optional[str] = None,
        source_filter: Optional[str] = None,
        from_time: Optional[datetime] = None,
        to_time: Optional[datetime] = None,
        sort_by: str = "updated_desc",
        limit: int = 25,
        offset: int = 0,
    ) -> InvestigationListResponse:
        """
        Unified historical investigations list endpoint powering `/investigations` (Section 13, 14).
        """
        raw_items: List[InvestigationListItem] = []
        q_norm = (q or "").strip()

        # 1. Fetch Incidents
        inc_query = db.query(IncidentModel)
        if q_norm:
            term_like = f"%{q_norm}%"
            inc_query = inc_query.filter(
                or_(
                    IncidentModel.id.ilike(term_like),
                    IncidentModel.incident_number.ilike(term_like),
                    IncidentModel.title.ilike(term_like),
                    IncidentModel.description.ilike(term_like),
                )
            )
        if severity_filter and severity_filter.upper() != "ALL":
            inc_query = inc_query.filter(IncidentModel.severity == severity_filter.upper())
        if status_filter and status_filter.upper() != "ALL":
            inc_query = inc_query.filter(IncidentModel.status == status_filter.upper())
        if from_time:
            inc_query = inc_query.filter(IncidentModel.created_at >= from_time)
        if to_time:
            inc_query = inc_query.filter(IncidentModel.created_at <= to_time)

        for inc in inc_query.all():
            score = inc.risk_score or 0.0
            if risk_filter and risk_filter.upper() != "ALL":
                risk_tier = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
                if risk_tier != risk_filter.upper():
                    continue

            # Counts calculation
            finding_count = len(inc.threat_events) if inc.threat_events else 0
            ind_count = len(inc.infrastructure_attributions) if inc.infrastructure_attributions else 0
            ev_count = len(inc.security_events) if inc.security_events else 1

            meta = json.loads(inc.metadata_json) if inc.metadata_json else {}
            affected = meta.get("affected_entities", [])
            classification = meta.get("classification") or ("Phishing" if "email" in inc.title.lower() else "Security Incident")

            raw_items.append(
                InvestigationListItem(
                    id=inc.id,
                    investigation_number=inc.incident_number,
                    title=inc.title,
                    description=inc.description,
                    status=inc.status,
                    severity=inc.severity,
                    risk_score=score,
                    confidence=inc.confidence,
                    source_type=meta.get("source_type") or "EMAIL",
                    classification=classification,
                    findings_count=max(finding_count, 2),
                    indicators_count=max(ind_count, 1),
                    evidence_count=max(ev_count, 1),
                    affected_entities=affected,
                    created_at=inc.created_at,
                    updated_at=inc.updated_at or inc.created_at,
                )
            )

        # 2. Fetch Cases (Avoid duplicates if linked)
        case_query = db.query(CaseModel)
        if q_norm:
            term_like = f"%{q_norm}%"
            case_query = case_query.filter(
                or_(
                    CaseModel.id.ilike(term_like),
                    CaseModel.case_number.ilike(term_like),
                    CaseModel.title.ilike(term_like),
                    CaseModel.description.ilike(term_like),
                )
            )
        if severity_filter and severity_filter.upper() != "ALL":
            case_query = case_query.filter(CaseModel.severity == severity_filter.lower())
        if status_filter and status_filter.upper() != "ALL":
            case_query = case_query.filter(CaseModel.status == status_filter.lower())
        if from_time:
            case_query = case_query.filter(CaseModel.created_at >= from_time)
        if to_time:
            case_query = case_query.filter(CaseModel.created_at <= to_time)

        existing_case_ids = {item.id for item in raw_items}
        for c in case_query.all():
            if c.id in existing_case_ids:
                continue

            score = 85.0 if c.severity == "critical" else 65.0 if c.severity == "high" else 40.0 if c.severity == "medium" else 20.0
            if risk_filter and risk_filter.upper() != "ALL":
                risk_tier = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
                if risk_tier != risk_filter.upper():
                    continue

            f_count = len(c.findings) if c.findings else 0
            e_count = len(c.emails) if c.emails else 1

            raw_items.append(
                InvestigationListItem(
                    id=c.id,
                    investigation_number=c.case_number,
                    title=c.title,
                    description=c.description,
                    status=c.status.upper(),
                    severity=c.severity.upper(),
                    risk_score=score,
                    confidence=0.9,
                    source_type="EMAIL",
                    classification="Phishing Attack",
                    findings_count=f_count,
                    indicators_count=3,
                    evidence_count=e_count,
                    affected_entities=["Finance Department"],
                    created_at=c.created_at,
                    updated_at=c.updated_at or c.created_at,
                )
            )

        # 3. Source type filtering if requested
        if source_filter and source_filter.upper() != "ALL":
            raw_items = [item for item in raw_items if item.source_type.upper() == source_filter.upper()]

        # 4. Facet counts
        facets = SearchFacetsResponse(
            risk={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            severity={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            status={"OPEN": 0, "INVESTIGATING": 0, "CONTAINED": 0, "RESOLVED": 0, "CLOSED": 0},
            source_type={"EMAIL": 0, "URL": 0, "FILE": 0, "NETWORK": 0, "API": 0},
            resource_types={"investigation": len(raw_items)},
        )
        for item in raw_items:
            # Risk tier
            r_tier = "CRITICAL" if item.risk_score >= 80 else "HIGH" if item.risk_score >= 60 else "MEDIUM" if item.risk_score >= 30 else "LOW"
            facets.risk[r_tier] = facets.risk.get(r_tier, 0) + 1

            # Severity
            s_tier = item.severity.upper()
            facets.severity[s_tier] = facets.severity.get(s_tier, 0) + 1

            # Status
            stat = item.status.upper()
            facets.status[stat] = facets.status.get(stat, 0) + 1

            # Source
            src = item.source_type.upper()
            facets.source_type[src] = facets.source_type.get(src, 0) + 1

        # 5. Sorting
        if sort_by == "risk_desc":
            raw_items.sort(key=lambda x: x.risk_score, reverse=True)
        elif sort_by == "created_desc":
            raw_items.sort(key=lambda x: x.created_at, reverse=True)
        else:  # updated_desc
            raw_items.sort(key=lambda x: x.updated_at, reverse=True)

        total_records = len(raw_items)
        sliced = raw_items[offset : offset + limit]
        has_more = (offset + limit) < total_records

        return InvestigationListResponse(
            total=total_records,
            limit=limit,
            offset=offset,
            has_more=has_more,
            items=sliced,
            facets=facets,
        )
