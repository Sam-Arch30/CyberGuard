import json
from collections import Counter
from datetime import datetime, timezone, timedelta
from typing import List, Tuple, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_

from backend.db.models import CaseModel, CaseEmailModel, EvidenceModel, AuditLogModel, EmailAnalysisModel, AnalysisPayloadModel
from backend.schemas.dashboard import (
    DashboardMetrics,
    SeverityDistributionItem,
    AnalysisTrendPoint,
    SuspiciousDomainItem,
    InfrastructureCountryItem,
    AuthFailureBreakdown,
    DashboardCaseItem,
    DashboardEmailItem,
    DashboardSummaryResponse
)


class DashboardService:
    @classmethod
    def sync_historical_records(cls, db: Session) -> None:
        """
        Synchronizes historical records from case_emails and evidence into email_analyses
        if email_analyses is currently empty. Ensures zero data loss for existing DB records.
        """
        existing_count = db.query(EmailAnalysisModel).count()
        if existing_count > 0:
            return

        case_emails = db.query(CaseEmailModel).all()
        seen_keys = set()

        for ce in case_emails:
            dedup_key = ce.email_sha256 or ce.email_id
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            domains = []
            countries = []
            ips = []
            if ce.indicators_json:
                try:
                    ind = json.loads(ce.indicators_json)
                    domains = ind.get("domains", [])
                    ips = ind.get("ips", [])
                    countries = ind.get("countries", [])
                except Exception:
                    pass

            # Only use countries actually present in indicators
            # Authentic SPF/DKIM/DMARC - leave as None if not evaluated
            spf = None
            dkim = None
            dmarc = None

            record = EmailAnalysisModel(
                evidence_id=ce.email_id if ce.email_id.startswith("EVD-") else None,
                email_sha256=ce.email_sha256,
                subject=ce.subject or "Untitled Email",
                sender=ce.sender or "unknown",
                threat_score=float(ce.threat_score or 0.0),
                severity=(ce.severity or "low").lower(),
                spf_result=spf,
                dkim_result=dkim,
                dmarc_result=dmarc,
                domains_json=json.dumps(domains),
                countries_json=json.dumps(countries),
                indicators_json=ce.indicators_json or "{}",
                analyzed_at=ce.added_at or datetime.now(timezone.utc)
            )
            db.add(record)

        if seen_keys:
            try:
                db.commit()
            except Exception:
                db.rollback()

    @classmethod
    def record_email_analysis(
        cls,
        db: Session,
        evidence_record: EvidenceModel,
        analysis_result,
        raw_sha256: str
    ) -> EmailAnalysisModel:
        """
        Records a newly analyzed email from /api/emails/analyze into email_analyses table.
        """
        score_val = float(analysis_result.threat_score.score if analysis_result.threat_score else 0.0)
        sev_val = str(analysis_result.threat_score.severity if analysis_result.threat_score else "low").lower()

        spf_res = None
        dkim_res = None
        dmarc_res = None
        if analysis_result.authentication:
            auth = analysis_result.authentication
            if auth.spf:
                spf_res = auth.spf.result
            if auth.dkim:
                dkim_res = auth.dkim.result
            if auth.dmarc:
                dmarc_res = auth.dmarc.result

        # Collect domains
        domain_set = set(analysis_result.domains or [])
        if analysis_result.lookalike_domains:
            for ld in analysis_result.lookalike_domains:
                if hasattr(ld, "domain") and ld.domain:
                    domain_set.add(ld.domain)
                elif isinstance(ld, dict) and ld.get("domain"):
                    domain_set.add(ld.get("domain"))

        # Collect countries from IP intelligence and relay hops
        country_set = set()
        if analysis_result.ip_intelligence:
            for ip, intel in analysis_result.ip_intelligence.items():
                if intel:
                    c = getattr(intel, "country", None) or (intel.get("country") if isinstance(intel, dict) else None)
                    if c and c != "Unknown":
                        country_set.add(c)

        relay = analysis_result.relay_analysis
        hops = (getattr(relay, "transmission_order_hops", None) or getattr(relay, "header_order_hops", None) or getattr(relay, "hops", None) or []) if relay else []
        for hop in hops:
            c = getattr(hop, "country", None) or (hop.get("country") if isinstance(hop, dict) else None)
            if c and c != "Unknown":
                country_set.add(c)

        indicators = {
            "domains": sorted(list(domain_set)),
            "countries": sorted(list(country_set)),
            "ips": analysis_result.ips or [],
            "urls": analysis_result.urls or []
        }

        analysis_row = EmailAnalysisModel(
            evidence_id=evidence_record.evidence_id,
            email_sha256=raw_sha256,
            subject=analysis_result.subject or "Untitled Email",
            sender=(getattr(analysis_result, "sender", None) or getattr(analysis_result, "from_header", None) or "unknown"),
            threat_score=score_val,
            severity=sev_val,
            spf_result=spf_res,
            dkim_result=dkim_res,
            dmarc_result=dmarc_res,
            domains_json=json.dumps(sorted(list(domain_set))),
            countries_json=json.dumps(sorted(list(country_set))),
            indicators_json=json.dumps(indicators),
            analyzed_at=evidence_record.upload_timestamp or datetime.now(timezone.utc)
        )
        db.add(analysis_row)
        try:
            db.commit()
            db.refresh(analysis_row)
        except Exception:
            db.rollback()

        return analysis_row

    @classmethod
    def get_summary(
        cls,
        db: Session,
        days: int = 30,
        recent_limit: int = 5
    ) -> DashboardSummaryResponse:
        """
        Aggregates SOC dashboard telemetry across cases, email analyses, and evidence.
        Uses real database telemetry and returns structured summaries.
        """
        cls.sync_historical_records(db)

        # 1. Top Metrics
        emails_query = db.query(EmailAnalysisModel)
        total_emails = emails_query.count()

        threats_detected = emails_query.filter(
            or_(
                EmailAnalysisModel.threat_score >= 50.0,
                EmailAnalysisModel.severity.in_(["medium", "high", "critical", "suspicious"])
            )
        ).count()

        critical_emails = emails_query.filter(
            or_(
                EmailAnalysisModel.threat_score >= 80.0,
                EmailAnalysisModel.severity == "critical"
            )
        ).count()

        open_cases = db.query(CaseModel).filter(
            CaseModel.status.in_(["open", "investigating", "escalated"])
        ).count()

        top_metrics = DashboardMetrics(
            emails_analyzed=total_emails,
            threats_detected=threats_detected,
            critical_emails=critical_emails,
            open_cases=open_cases
        )

        # 2. Threat Severity Distribution
        all_emails = emails_query.all()
        sev_counts: Counter = Counter()
        for em in all_emails:
            sev = (em.severity or "low").lower()
            if sev == "suspicious":
                sev = "medium"
            sev_counts[sev] += 1

        order = ["critical", "high", "medium", "low"]
        severity_dist = [
            SeverityDistributionItem(severity=k, count=sev_counts[k])
            for k in order if sev_counts[k] > 0
        ]
        # Include any other severities not in the standard 4
        for k, v in sev_counts.items():
            if k not in order and v > 0:
                severity_dist.append(SeverityDistributionItem(severity=k, count=v))

        # 3. Recent Analysis Trend
        # Group analyzed emails by date
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        trend_map = {}
        for em in all_emails:
            t = em.analyzed_at or datetime.now(timezone.utc)
            # Ensure timezone-aware comparison
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            if t >= cutoff_date:
                d_str = t.strftime("%Y-%m-%d")
                if d_str not in trend_map:
                    trend_map[d_str] = {"total": 0, "threats": 0}
                trend_map[d_str]["total"] += 1
                is_threat = (em.threat_score or 0) >= 50 or em.severity in ["medium", "high", "critical", "suspicious"]
                if is_threat:
                    trend_map[d_str]["threats"] += 1

        sorted_trend = sorted(trend_map.items(), key=lambda x: x[0])
        trend_points = [
            AnalysisTrendPoint(date=k, total=v["total"], threats=v["threats"])
            for k, v in sorted_trend
        ]

        # 4. Top Suspicious Domains
        domain_counts: Counter = Counter()
        for em in all_emails:
            if em.domains_json:
                try:
                    domains = json.loads(em.domains_json)
                    for d in domains:
                        clean_d = str(d).strip().lower()
                        if clean_d and "." in clean_d and not clean_d.endswith(".local"):
                            domain_counts[clean_d] += 1
                except Exception:
                    pass

        top_domains = [
            SuspiciousDomainItem(domain=d, count=c)
            for d, c in domain_counts.most_common(5)
        ]

        # 5. Top Observed Infrastructure Countries
        country_counts: Counter = Counter()
        for em in all_emails:
            if em.countries_json:
                try:
                    countries = json.loads(em.countries_json)
                    for c in countries:
                        clean_c = str(c).strip()
                        if clean_c and clean_c != "Unknown":
                            country_counts[clean_c] += 1
                except Exception:
                    pass

        top_countries = [
            InfrastructureCountryItem(country=c, count=cnt)
            for c, cnt in country_counts.most_common(5)
        ]

        # 6. Authentication Failure Breakdown
        spf_fails = 0
        dkim_fails = 0
        dmarc_fails = 0
        total_auth_checks = 0

        for em in all_emails:
            has_check = False
            if em.spf_result:
                has_check = True
                if str(em.spf_result).upper() in ["FAIL", "SOFTFAIL"]:
                    spf_fails += 1
            if em.dkim_result:
                has_check = True
                if str(em.dkim_result).upper() == "FAIL":
                    dkim_fails += 1
            if em.dmarc_result:
                has_check = True
                if str(em.dmarc_result).upper() == "FAIL":
                    dmarc_fails += 1
            if has_check:
                total_auth_checks += 1

        auth_breakdown = AuthFailureBreakdown(
            spf_failures=spf_fails,
            dkim_failures=dkim_fails,
            dmarc_failures=dmarc_fails,
            total_evaluated=total_auth_checks
        )

        # 7. Recent Investigations (Limit N)
        recent_cases_db = (
            db.query(CaseModel)
            .order_by(desc(CaseModel.updated_at))
            .limit(recent_limit)
            .all()
        )
        recent_cases = [
            DashboardCaseItem(
                id=c.id,
                case_number=c.case_number,
                title=c.title,
                severity=c.severity,
                status=c.status,
                emails_count=len(c.emails) if c.emails else 0,
                updated_at=c.updated_at.isoformat() if c.updated_at else datetime.now(timezone.utc).isoformat()
            )
            for c in recent_cases_db
        ]

        # 8. Recent Email Analyses (Limit N)
        recent_emails_db = (
            db.query(EmailAnalysisModel)
            .order_by(desc(EmailAnalysisModel.analyzed_at))
            .limit(recent_limit)
            .all()
        )
        recent_emails = []
        for em in recent_emails_db:
            orig_name = None
            if em.evidence_id:
                p_rec = db.query(AnalysisPayloadModel).filter(AnalysisPayloadModel.evidence_id == em.evidence_id).first()
                if p_rec and p_rec.analysis_json:
                    try:
                        orig_name = json.loads(p_rec.analysis_json).get("original_filename")
                    except Exception:
                        pass
            if not orig_name:
                orig_name = f"{(em.subject or 'evidence')[:25].strip().lower().replace(' ', '_')}.eml"
            recent_emails.append(DashboardEmailItem(
                id=em.id,
                evidence_id=em.evidence_id,
                sha256=em.email_sha256,
                subject=em.subject,
                sender=em.sender,
                threat_score=em.threat_score,
                severity=em.severity,
                timestamp=em.analyzed_at.isoformat() if em.analyzed_at else datetime.now(timezone.utc).isoformat(),
                has_eml_file=True,
                original_filename=orig_name
            ))

        return DashboardSummaryResponse(
            metrics=top_metrics,
            severity_distribution=severity_dist,
            analysis_trend=trend_points,
            top_suspicious_domains=top_domains,
            top_countries=top_countries,
            auth_failures=auth_breakdown,
            recent_cases=recent_cases,
            recent_emails=recent_emails
        )

    @classmethod
    def list_emails(
        cls,
        db: Session,
        skip: int = 0,
        limit: int = 20
    ) -> Tuple[List[DashboardEmailItem], int]:
        """
        Returns paginated list of email analyses and total count.
        """
        cls.sync_historical_records(db)
        query = db.query(EmailAnalysisModel)
        total = query.count()
        rows = (
            query.order_by(desc(EmailAnalysisModel.analyzed_at))
            .offset(skip)
            .limit(limit)
            .all()
        )
        items = []
        for em in rows:
            orig_name = None
            if em.evidence_id:
                p_rec = db.query(AnalysisPayloadModel).filter(AnalysisPayloadModel.evidence_id == em.evidence_id).first()
                if p_rec and p_rec.analysis_json:
                    try:
                        orig_name = json.loads(p_rec.analysis_json).get("original_filename")
                    except Exception:
                        pass
            if not orig_name:
                orig_name = f"{(em.subject or 'evidence')[:25].strip().lower().replace(' ', '_')}.eml"
            items.append(DashboardEmailItem(
                id=em.id,
                evidence_id=em.evidence_id,
                sha256=em.email_sha256,
                subject=em.subject,
                sender=em.sender,
                threat_score=em.threat_score,
                severity=em.severity,
                timestamp=em.analyzed_at.isoformat() if em.analyzed_at else datetime.now(timezone.utc).isoformat(),
                has_eml_file=True,
                original_filename=orig_name
            ))
        return items, total

