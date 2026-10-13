"""
Analysis Results Aggregator Service (Section 38).
Consolidates completed/partial analysis runs into structured progressive disclosure tiers:
- Level 1: Executive (Risk, Classification, Executive Summary, Why CyberGuard Thinks This, Next Steps)
- Level 2: Analyst (Top Findings, Indicators Summary, Counter-Evidence, Contradictions, Gaps, Novelty, Memory)
- Level 3: Investigator (Attack Path Preview, MITRE Preview, Infrastructure Attribution, Campaign Activity)
- Level 4: Forensic (Provenance, Model & Rule Versions, Run History, Raw Telemetry References)
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    AnalysisRunModel,
    AnalysisTaskModel,
    ArtifactModel,
    AttackPathModel,
    AttackStageModel,
    AttackTechniqueMappingModel,
    BehavioralDeviationModel,
    CampaignIncidentModel,
    CampaignModel,
    EvidenceModel,
    FindingEvidenceModel,
    FindingModel,
    IncidentModel,
    IndicatorModel,
    InfrastructureAttributionModel,
    NoveltyAssessmentModel,
    RelationshipModel,
    RiskAssessmentModel,
    ThreatEventModel,
    ThreatMemoryEntryModel,
    get_utc_now,
)
from backend.schemas.analysis_results import (
    AnalysisProvenance,
    AnalysisResultsResponse,
    AnalysisRunHistoryItem,
    ArtifactIdentity,
    AttachmentResultItem,
    AttackPathPreview,
    AttackStagePreview,
    BehavioralAnomalyItem,
    BehavioralSummary,
    CampaignActivityContext,
    ContradictionResultItem,
    CounterEvidenceResultItem,
    DigitalImpersonationSummary,
    DomainIndicator,
    EmailIndicator,
    EvidenceDetailResponse,
    FindingResultDetail,
    HashIndicator,
    IndicatorsSummary,
    InfrastructureAttributionPreview,
    IPIndicator,
    MITRETechniquePreview,
    NextStepRecommendation,
    NoveltySummary,
    RiskHeaderSummary,
    SupportingEvidencePreview,
    ThreatMemorySummary,
    UncertaintyAndGapsItem,
    URLIndicator,
    WhyCyberGuardThinksThisItem,
)

logger = logging.getLogger("cyberguard.services.analysis_results_aggregator")

# Severity sort priority helper
SEVERITY_ORDER = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "SAFE": 1,
    "INFO": 1,
    "UNKNOWN": 0,
}


class AnalysisResultsAggregator:
    """
    Centralized service compiling analysis runs into progressive disclosure response models.
    """

    @classmethod
    def redact_sensitive_value(cls, text: str) -> str:
        """Sanitizes API keys, authorization tokens, passwords, and secrets."""
        if not text:
            return ""
        s = str(text)
        s = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9\-._~+/]+=*", r"\1[REDACTED_TOKEN]", s)
        s = re.sub(r"(?i)(password[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", r"\1[REDACTED_PASSWORD]", s)
        s = re.sub(r"(?i)(api[_-]?key[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", r"\1[REDACTED_API_KEY]", s)
        s = re.sub(r"(?i)(secret[\"']?\s*[:=]\s*[\"']?)[^\"'\s,]+", r"\1[REDACTED_SECRET]", s)
        return s

    @classmethod
    def get_results_for_run(
        cls,
        db: Session,
        run_id: str,
        workspace_id: str = "default",
    ) -> Optional[AnalysisResultsResponse]:
        """
        Builds the complete AnalysisResultsResponse for a given analysis_run_id.
        """
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
        if not run:
            return None

        artifact = db.query(ArtifactModel).filter(ArtifactModel.id == run.artifact_id).first()

        # Find associated investigation / incident and evidence ID
        investigation_id = None
        evidence_id = None

        rel = db.query(RelationshipModel).filter(
            RelationshipModel.target_type == "ARTIFACT",
            RelationshipModel.target_id == run.artifact_id,
            RelationshipModel.source_type == "INCIDENT",
        ).first()
        if rel:
            investigation_id = rel.source_id

        if artifact and artifact.sha256:
            evd = db.query(EvidenceModel).filter(EvidenceModel.sha256 == artifact.sha256).first()
            if evd:
                evidence_id = evd.evidence_id

        # Query tasks and compute completeness
        tasks = db.query(AnalysisTaskModel).filter(
            AnalysisTaskModel.analysis_run_id == run.id
        ).order_by(AnalysisTaskModel.created_at).all()

        total_tasks = len(tasks)
        completed_tasks = sum(1 for t in tasks if t.status == "COMPLETED")
        failed_tasks = sum(1 for t in tasks if t.status == "FAILED")

        status = run.status.upper() if run.status else "RUNNING"
        completeness = "COMPLETE"
        completeness_msg = None

        if status == "FAILED":
            completeness = "DEGRADED"
            completeness_msg = run.error or "Analysis execution failed to complete all critical stages."
        elif status == "PARTIAL" or failed_tasks > 0:
            completeness = "PARTIAL"
            completeness_msg = f"{failed_tasks} of {total_tasks} analyzers encountered errors. Partial findings remain authoritative."
        elif status in ("INITIALIZING", "QUEUED", "RUNNING"):
            completeness = "IN_PROGRESS"
            completeness_msg = "Analyzers currently executing; results updating in real-time."

        # --------------------------------------------------------------------
        # 1. LEVEL 1: RISK & EXECUTIVE SUMMARY
        # --------------------------------------------------------------------
        risk_summary = cls._build_risk_summary(db, run, status)

        # Query all findings for this run
        findings = db.query(FindingModel).filter(
            FindingModel.analysis_run_id == run.id
        ).order_by(FindingModel.created_at.desc()).all()

        # Deterministic finding sort: severity priority -> risk contribution -> confidence
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity.upper() if f.severity else "LOW", 0),
                f.risk_contribution or 0.0,
                f.confidence or 0.0,
            ),
            reverse=True,
        )

        classification, exec_summary = cls._generate_executive_classification(run, artifact, sorted_findings)
        why_bullets = cls._build_why_cyberguard_thinks_this(sorted_findings, run, artifact)
        next_step = cls._build_next_step_recommendation(sorted_findings, run)
        media_assessment = None
        if artifact and artifact.artifact_type.upper() in ('IMAGE', 'AUDIO', 'VIDEO'):
            metadata = json.loads(run.metadata_json or '{}')
            state = metadata.get('processing_status', 'NOT_ANALYZED')
            media_assessment = metadata if 'processing_status' in metadata else {
                'processing_status': state, 'classification': 'INSUFFICIENT_EVIDENCE',
                'summary': 'No verified media-decoding result exists for this run.',
                'risk_score': 0, 'limitations': ['Legacy task completion is not proof of media decoding or authenticity.'],
                'detector_results': [], 'analysis_scope': 'Authenticity is unverified.'}
            if state != 'COMPLETED':
                completeness = 'PARTIAL' if completeness != 'IN_PROGRESS' else completeness
                status = 'PARTIAL' if status == 'COMPLETED' else status
                completeness_msg = 'Original evidence retained. Media analysis is incomplete: ' + state.replace('_', ' ').lower() + '.'
            classification = 'Media heuristic checks completed' if state == 'COMPLETED' else 'Media authenticity not assessed'
            exec_summary = media_assessment.get('summary', 'Authenticity is undetermined.') + ' These are heuristic observations, not a validated real/fake verdict.'
            next_step = NextStepRecommendation(action_title='Review original media and provenance',
                action_description='Inspect decoder status, limitations and independent source confirmation. Do not close the investigation from a zero signal score.',
                priority='REVIEW', target_route='/media-authenticity')

        # --------------------------------------------------------------------
        # 2. LEVEL 2: ANALYST FINDINGS & INDICATORS
        # --------------------------------------------------------------------
        top_findings_detail = [cls._format_finding_detail(f) for f in sorted_findings]
        indicators_summary = cls._build_indicators_summary(db, run, artifact, sorted_findings)
        counter_evidence = cls._build_counter_evidence(sorted_findings, run, artifact)
        contradictions = cls._build_contradictions(sorted_findings, run, artifact)
        uncertainty_gaps = cls._build_uncertainty_and_gaps(run, tasks, artifact)
        what_would_change = cls._build_what_would_change(sorted_findings, uncertainty_gaps)

        digital_impersonation = cls._extract_impersonation_summary(sorted_findings)
        behavioral_deviations = cls._query_behavioral_summary(db, investigation_id, workspace_id)
        novelty_summary = cls._query_novelty_summary(db, investigation_id, workspace_id)
        threat_memory_summary = cls._query_threat_memory_summary(db, artifact, workspace_id)

        # --------------------------------------------------------------------
        # 3. LEVEL 3: INVESTIGATOR CONTEXT
        # --------------------------------------------------------------------
        attack_path_preview = cls._query_attack_path_preview(db, investigation_id, run)
        mitre_preview = cls._query_mitre_preview(db, investigation_id, sorted_findings)
        infrastructure_preview = cls._query_infrastructure_preview(db, investigation_id, indicators_summary)
        campaign_context = cls._query_campaign_context(db, investigation_id)

        # --------------------------------------------------------------------
        # 4. LEVEL 4: FORENSIC & PROVENANCE
        # --------------------------------------------------------------------
        provenance = cls._build_provenance(run)
        run_history = cls._query_run_history(db, run)

        artifact_identity = ArtifactIdentity(
            id=artifact.id if artifact else run.artifact_id,
            name=artifact.name if artifact else "unknown",
            artifact_type=artifact.artifact_type if artifact else "FILE",
            size=(artifact.size or 0) if artifact else 0,
            sha256=artifact.sha256 if artifact else None,
            source=artifact.source if artifact else "UNKNOWN",
        )

        return AnalysisResultsResponse(
            run_id=run.id,
            investigation_id=investigation_id,
            evidence_id=evidence_id,
            artifact=artifact_identity,
            status=status,
            media_assessment=media_assessment,
            analysis_completeness=completeness,
            completeness_message=completeness_msg,
            total_tasks=total_tasks,
            completed_tasks=completed_tasks,
            failed_tasks=failed_tasks,
            risk=risk_summary,
            classification=classification,
            executive_summary=exec_summary,
            why_cyberguard_thinks_this=why_bullets,
            next_step_recommendation=next_step,
            top_findings=top_findings_detail,
            indicators_summary=indicators_summary,
            counter_evidence=counter_evidence,
            contradictions=contradictions,
            uncertainty_and_gaps=uncertainty_gaps,
            what_would_change_assessment=what_would_change,
            digital_impersonation=digital_impersonation,
            behavioral_deviations=behavioral_deviations,
            novelty=novelty_summary,
            threat_memory=threat_memory_summary,
            attack_path_preview=attack_path_preview,
            mitre_preview=mitre_preview,
            infrastructure_preview=infrastructure_preview,
            campaign_context=campaign_context,
            provenance=provenance,
            run_history=run_history,
            last_updated=run.completed_at or get_utc_now(),
        )

    # ========================================================================
    # HELPER COMPOSERS
    # ========================================================================

    @classmethod
    def _build_risk_summary(
        cls,
        db: Session,
        run: AnalysisRunModel,
        status: str,
    ) -> RiskHeaderSummary:
        """
        Extracts authoritative Section 26 metrics without frontend re-calculation.
        """
        # 1. Check if a formal RiskAssessmentModel exists for this run or investigation
        artifact = db.get(ArtifactModel, run.artifact_id)
        if artifact and artifact.artifact_type.upper() in ('IMAGE', 'AUDIO', 'VIDEO'):
            metadata = json.loads(run.metadata_json or '{}')
            processed = metadata.get('processing_status') == 'COMPLETED'
            return RiskHeaderSummary(score=metadata.get('risk_score') if processed else None,
                level='UNVERIFIED', severity='INFO', confidence=None, confidence_level='UNKNOWN',
                uncertainty='HIGH', is_pending=status in ('QUEUED', 'RUNNING'),
                status_label='Heuristic signals only; authenticity undetermined' if processed else 'Media authenticity not assessed')

        ra = db.query(RiskAssessmentModel).filter(
            or_(
                RiskAssessmentModel.analysis_run_id == run.id,
                RiskAssessmentModel.scope_id == run.id,
            )
        ).order_by(RiskAssessmentModel.version.desc()).first()

        if ra:
            score = ra.risk_score
            level = ra.risk_level.upper() if ra.risk_level else "UNKNOWN"
            severity = ra.severity.upper() if ra.severity else "LOW"
            conf = ra.confidence
            conf_level = ra.confidence_level.upper() if ra.confidence_level else "MODERATE"
            unc = ra.uncertainty.upper() if ra.uncertainty else "LOW"
            is_pending = False
            status_label = f"{level} Risk ({round(score, 1)} / 100)"
            return RiskHeaderSummary(
                score=score,
                level=level,
                severity=severity,
                confidence=conf,
                confidence_level=conf_level,
                uncertainty=unc,
                is_pending=is_pending,
                status_label=status_label,
            )

        # 2. Check run overall fields
        if run.overall_risk_score is not None:
            score = float(run.overall_risk_score)
            sev = run.overall_severity.upper() if run.overall_severity else "LOW"
            conf = run.confidence if run.confidence is not None else 0.0

            if score >= 80:
                level = "CRITICAL"
                conf_level = "VERY_HIGH"
            elif score >= 60:
                level = "HIGH"
                conf_level = "HIGH"
            elif score >= 35:
                level = "MEDIUM"
                conf_level = "MODERATE"
            elif score > 10:
                level = "LOW"
                conf_level = "MODERATE"
            else:
                level = "SAFE"
                conf_level = "HIGH"

            if conf == 0:
                level, conf_level = "UNKNOWN", "UNKNOWN"
            status_label = "Threat assessment incomplete" if conf == 0 else f"{level} Risk ({round(score, 1)} / 100)"
            return RiskHeaderSummary(
                score=score,
                level=level,
                severity=sev,
                confidence=conf,
                confidence_level=conf_level,
                uncertainty="HIGH" if conf == 0 else "LOW",
                is_pending=False,
                status_label=status_label,
            )

        # 3. Not calculated yet or running
        is_pending = status in ("INITIALIZING", "QUEUED", "RUNNING")
        return RiskHeaderSummary(
            score=None,
            level="UNKNOWN",
            severity="LOW",
            confidence=None,
            confidence_level="UNKNOWN",
            uncertainty="HIGH",
            is_pending=is_pending,
            status_label="Risk assessment pending" if is_pending else "Insufficient evidence",
        )

    @classmethod
    def _generate_executive_classification(
        cls,
        run: AnalysisRunModel,
        artifact: Optional[ArtifactModel],
        findings: List[FindingModel],
    ) -> Tuple[str, str]:
        """
        Produces concise, evidence-backed executive classification.
        Does not ask LLM during rendering; stays deterministic.
        """
        art_type = (artifact.artifact_type if artifact else "FILE").upper()
        if run.confidence == 0:
            return (
                "Threat assessment incomplete",
                "Available checks may identify references or file properties. These observations do not establish safety or a phishing verdict; assess indicators and review limitations.",
            )
        finding_types = [f.finding_type.upper() for f in findings]
        titles_lower = " ".join(f.title.lower() for f in findings)

        if any("CREDENTIAL" in ft or "PHISH" in ft for ft in finding_types) or "credential" in titles_lower:
            classification = "Likely credential phishing"
            exec_summary = "Observed indicators, deception headers, and harvested URLs are characteristic of credential collection targeting enterprise accounts."
        elif any("ATO" in ft or "TAKEOVER" in ft or "BURST" in ft for ft in finding_types):
            classification = "Potential account takeover activity"
            exec_summary = "Anomalous authentication bursts, geographic shifts, and unfamiliar device fingerprints indicate potential unauthorized account access."
        elif any("IMPERSONATION" in ft or "LOOKALIKE" in ft for ft in finding_types) or "lookalike" in titles_lower:
            classification = "Suspicious digital impersonation"
            exec_summary = "Identity headers and domain infrastructure demonstrate lookalike characteristics mimicking trusted organizational brands."
        elif any("MALWARE" in ft or "MACRO" in ft or "EXPLOIT" in ft for ft in finding_types):
            classification = "Potentially malicious attachment or executable"
            exec_summary = "Static structure anomalies, suspicious embedded routines, or known malware signatures detected in file container."
        elif art_type == "URL" and (run.overall_risk_score or 0) >= 60:
            classification = "High-risk suspicious URL / Web redirect"
            exec_summary = "Target endpoint exhibits suspicious redirect hops, poor domain reputation, or credential-harvesting page patterns."
        elif (run.overall_risk_score or 0) <= 20 and len(findings) == 0:
            classification = "Low risk / no malicious indicators detected"
            exec_summary = "Automated analysis completed without observing deceptive indicators, authentication anomalies, or malicious signatures."
        else:
            classification = f"Suspicious {art_type.lower()} artifact"
            exec_summary = f"Identified {len(findings)} suspicious finding(s) across telemetry analysis stages."

        return classification, exec_summary

    @classmethod
    def _build_why_cyberguard_thinks_this(
        cls,
        findings: List[FindingModel],
        run: AnalysisRunModel,
        artifact: Optional[ArtifactModel],
    ) -> List[WhyCyberGuardThinksThisItem]:
        """
        Extracts 3-5 structured assertions explaining the conclusion.
        Every substantive assertion is linked to structured findings/evidence.
        """
        items: List[WhyCyberGuardThinksThisItem] = []
        for i, f in enumerate(findings[:5], start=1):
            ev_items = getattr(f, "evidence_items", []) or []
            ev_refs = [e.id for e in ev_items]

            support = "HIGH"
            if f.confidence >= 0.90:
                support = "CONFIRMED" if f.severity in ("CRITICAL", "HIGH") else "VERY_HIGH"
            elif f.confidence < 0.70:
                support = "MODERATE"

            items.append(
                WhyCyberGuardThinksThisItem(
                    id=f"REASON-{i}",
                    claim=f.title,
                    support_level=support,
                    confidence=f.confidence,
                    evidence_count=len(ev_items),
                    evidence_refs=ev_refs,
                )
            )

        return items

    @classmethod
    def _build_next_step_recommendation(
        cls,
        findings: List[FindingModel],
        run: AnalysisRunModel,
    ) -> NextStepRecommendation:
        """
        Synthesizes the single most urgent, actionable next step for Level 1.
        """
        if run.confidence == 0:
            return NextStepRecommendation(
                action_title="Assess extracted indicators before resolving",
                action_description="URL references are observations, not phishing verdicts. Analyze destinations using the URL workflow and review unavailable analyzers.",
                priority="LOW", target_route="/detect",
            )
        sev = (run.overall_severity or "LOW").upper()
        top_sev = findings[0].severity.upper() if findings else sev

        if top_sev in ("CRITICAL", "HIGH"):
            return NextStepRecommendation(
                action_title="Review suspicious destination & isolate credentials",
                action_description="Block outbound access to identified credential-harvesting domains and check for authentication sessions initiated from related IP addresses.",
                priority="HIGH",
                target_route="/response",
            )
        elif top_sev == "MEDIUM":
            return NextStepRecommendation(
                action_title="Correlate sender infrastructure with historical telemetry",
                action_description="Check if other organizational mailboxes received similar communications and verify domain registration history.",
                priority="MEDIUM",
                target_route="/intelligence",
            )
        else:
            return NextStepRecommendation(
                action_title="Archive artifact and mark investigation resolved",
                action_description="Evidence demonstrates low threat risk; preserve findings in case archive for historical reference.",
                priority="LOW",
                target_route="/report",
            )

    @classmethod
    def _format_finding_detail(cls, f: FindingModel) -> FindingResultDetail:
        ev_items = getattr(f, "evidence_items", []) or []
        ev_previews = [
            SupportingEvidencePreview(
                id=e.id,
                evidence_type=e.evidence_type,
                source=e.source,
                key=e.key,
                value=cls.redact_sensitive_value(e.value),
                confidence=e.confidence,
                artifact_id=e.artifact_id,
                observed_at=e.timestamp,
            )
            for e in ev_items
        ]

        meta = {}
        try:
            meta = json.loads(f.metadata_json or "{}")
        except Exception:
            pass

        return FindingResultDetail(
            id=f.id,
            analyzer=f.analyzer,
            finding_type=f.finding_type,
            title=f.title,
            description=f.description,
            severity=f.severity.upper() if f.severity else "LOW",
            confidence=f.confidence or 1.0,
            risk_contribution=f.risk_contribution or 0.0,
            method=f.method or "RULE",
            rule_id=f.rule_id,
            observed_value=meta.get("observed_value") or meta.get("domain") or meta.get("url"),
            expected_value=meta.get("expected_value"),
            evidence_count=len(ev_previews),
            evidence_items=ev_previews,
            counter_evidence=meta.get("counter_evidence", []),
            metadata=meta,
        )

    @classmethod
    def _build_indicators_summary(
        cls,
        db: Session,
        run: AnalysisRunModel,
        artifact: Optional[ArtifactModel],
        findings: List[FindingModel],
    ) -> IndicatorsSummary:
        """
        Harvests observed domains, URLs, IPs, emails, and attachments without browser-side refetching.
        """
        summary = IndicatorsSummary()

        # Gather from FindingEvidence
        seen_domains = set()
        seen_urls = set()
        seen_ips = set()
        seen_emails = set()

        for f in findings:
            for ev in getattr(f, "evidence_items", []) or []:
                k = (ev.key or "").lower()
                v = (ev.value or "").strip()
                t = (ev.evidence_type or "").upper()

                if "domain" in k or t == "DOMAIN":
                    if v and v not in seen_domains:
                        seen_domains.add(v)
                        summary.domains.append(
                            DomainIndicator(
                                value=v,
                                severity=f.severity,
                                first_seen=ev.timestamp,
                                is_lookalike="lookalike" in f.title.lower(),
                            )
                        )
                elif "url" in k or t == "URL" or v.startswith("http://") or v.startswith("https://"):
                    if v and v not in seen_urls:
                        seen_urls.add(v)
                        summary.urls.append(
                            URLIndicator(
                                value=v,
                                severity=f.severity,
                                first_seen=ev.timestamp,
                                redirect_hops=None,
                                is_lookalike="lookalike" in f.title.lower(),
                                credential_harvesting="credential" in f.title.lower(),
                            )
                        )
                elif "ip" in k or t == "IP":
                    if v and v not in seen_ips:
                        seen_ips.add(v)
                        summary.ips.append(
                            IPIndicator(
                                value=v,
                                severity=f.severity,
                                first_seen=ev.timestamp,
                                country=None,
                                asn=None,
                            )
                        )
                elif "email" in k or "@" in v and not v.startswith("http"):
                    if v and v not in seen_emails:
                        seen_emails.add(v)
                        summary.emails.append(
                            EmailIndicator(
                                value=v,
                                severity=f.severity,
                                first_seen=ev.timestamp,
                                role="sender" if "from" in k else "recipient",
                            )
                        )

        # Artifact self-identity hash
        if artifact and artifact.sha256:
            summary.hashes.append(
                HashIndicator(
                    value=artifact.sha256,
                    algorithm="SHA-256",
                    severity="LOW",
                    first_seen=artifact.created_at,
                )
            )

        summary.total_count = (
            len(summary.domains)
            + len(summary.urls)
            + len(summary.ips)
            + len(summary.emails)
            + len(summary.hashes)
            + len(summary.attachments)
        )
        return summary

    @classmethod
    def _build_counter_evidence(
        cls,
        findings: List[FindingModel],
        run: AnalysisRunModel,
        artifact: Optional[ArtifactModel],
    ) -> List[CounterEvidenceResultItem]:
        """
        Identifies counter-evidence preventing confirmation bias.
        """
        items: List[CounterEvidenceResultItem] = []

        # Check for counter-evidence in findings metadata
        for f in findings:
            try:
                meta = json.loads(f.metadata_json or "{}")
                for ce in meta.get("counter_evidence", []):
                    items.append(
                        CounterEvidenceResultItem(
                            id=f"CE-{len(items)+1}",
                            title=ce if isinstance(ce, str) else ce.get("title", "Supporting Benign Indicator"),
                            description="Observed security attribute indicating legitimate infrastructure or benign behavior.",
                            source=f.analyzer,
                            strength="MODERATE",
                            impact="Reduces probability of automated spoofing",
                        )
                    )
            except Exception:
                pass

        return items

    @classmethod
    def _build_contradictions(
        cls,
        findings: List[FindingModel],
        run: AnalysisRunModel,
        artifact: Optional[ArtifactModel],
    ) -> List[ContradictionResultItem]:
        """
        Surfaces conflicting evidence without resolving it artificially in frontend.
        """
        items: List[ContradictionResultItem] = []

        has_auth_pass = any("pass" in f.title.lower() for f in findings)
        has_auth_fail = any("spf" in f.title.lower() or "dmarc" in f.title.lower() for f in findings)

        if has_auth_pass and has_auth_fail:
            items.append(
                ContradictionResultItem(
                    id="CONTRA-1",
                    topic="Authentication Alignment",
                    supporting_claim="Cryptographic DKIM signature matches the sending envelope domain.",
                    contradicting_claim="SPF alignment policy evaluation failed due to forwarding relay discrepancy.",
                    severity="MEDIUM",
                )
            )

        return items

    @classmethod
    def _build_uncertainty_and_gaps(
        cls,
        run: AnalysisRunModel,
        tasks: List[AnalysisTaskModel],
        artifact: Optional[ArtifactModel],
    ) -> List[UncertaintyAndGapsItem]:
        """
        Exposes important missing context or unreachable telemetry.
        """
        items: List[UncertaintyAndGapsItem] = []

        # Check failed or skipped tasks
        for t in tasks:
            if t.status == "FAILED":
                items.append(
                    UncertaintyAndGapsItem(
                        topic=t.title,
                        description=f"External provider or inspection routine was unavailable ({t.error or 'timeout'}).",
                        impact="This processing stage did not complete; review its limitation before relying on the assessment.",
                    )
                )

        return items

    @classmethod
    def _build_what_would_change(
        cls,
        findings: List[FindingModel],
        gaps: List[UncertaintyAndGapsItem],
    ) -> List[str]:
        """
        Actionable conditions derived from Explainable AI layer.
        """
        conditions = [f"Complete the unavailable check: {gap.topic}." for gap in gaps]
        conditions.extend(f"Independently verify the source evidence for: {finding.title}." for finding in findings[:3])
        return conditions

    @classmethod
    def _extract_impersonation_summary(
        cls,
        findings: List[FindingModel],
    ) -> Optional[DigitalImpersonationSummary]:
        for f in findings:
            if "impersonat" in f.title.lower() or "lookalike" in f.title.lower():
                try:
                    meta = json.loads(f.metadata_json or "{}")
                    return DigitalImpersonationSummary(
                        claimed_identity=meta.get("claimed_domain") or meta.get("claimed_brand") or "Executive / Corporate Domain",
                        observed_identity=meta.get("observed_domain") or f.title,
                        status="LOOKALIKE",
                        confidence=f.confidence,
                        similarity_score=meta.get("similarity_score", 0.88),
                        details=f.description,
                    )
                except Exception:
                    pass
        return None

    @classmethod
    def _query_behavioral_summary(
        cls,
        db: Session,
        investigation_id: Optional[str],
        workspace_id: str,
    ) -> Optional[BehavioralSummary]:
        if not investigation_id:
            return None
        devs = db.query(BehavioralDeviationModel).filter(
            BehavioralDeviationModel.workspace_id == workspace_id,
            BehavioralDeviationModel.investigation_id == investigation_id,
        ).all()
        if not devs:
            return None

        anomalies = [
            BehavioralAnomalyItem(
                metric=d.metric_type,
                status=d.status or "ANOMALY",
                deviation_score=d.deviation_score or 0.0,
                baseline_value=d.baseline_value,
                observed_value=d.observed_value,
            )
            for d in devs
        ]
        return BehavioralSummary(
            baseline_quality="HIGH" if len(devs) > 3 else "MODERATE",
            total_anomalies=len(anomalies),
            anomalies=anomalies,
        )

    @classmethod
    def _query_novelty_summary(
        cls,
        db: Session,
        investigation_id: Optional[str],
        workspace_id: str,
    ) -> Optional[NoveltySummary]:
        if not investigation_id:
            return None
        nov = db.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.workspace_id == workspace_id,
            NoveltyAssessmentModel.incident_id == investigation_id,
        ).order_by(NoveltyAssessmentModel.created_at.desc()).first()

        if nov:
            return NoveltySummary(
                novelty_score=nov.overall_novelty_score or 0.0,
                novelty_level=nov.novelty_level or "LOW",
                prior_observations_count=nov.prior_observations_count or 0,
                description=nov.summary or "Infrastructure patterns evaluated for historical frequency.",
            )
        return None

    @classmethod
    def _query_threat_memory_summary(
        cls,
        db: Session,
        artifact: Optional[ArtifactModel],
        workspace_id: str,
    ) -> Optional[ThreatMemorySummary]:
        if not artifact or not artifact.sha256:
            return None
        mem = db.query(ThreatMemoryEntryModel).filter(
            ThreatMemoryEntryModel.workspace_id == workspace_id,
            ThreatMemoryEntryModel.canonical_key.contains(artifact.sha256[:16]),
        ).first()

        if mem:
            return ThreatMemorySummary(
                previously_observed=True,
                total_observations=mem.observation_count or 1,
                verified_malicious=1 if mem.status == "VERIFIED" else 0,
                dismissed_count=1 if mem.status == "DISMISSED" else 0,
                notes=mem.summary,
            )
        return ThreatMemorySummary(
            previously_observed=False,
            total_observations=0,
            verified_malicious=0,
            dismissed_count=0,
            notes="No identical cryptographic fingerprints found in threat memory catalog.",
        )

    @classmethod
    def _query_attack_path_preview(
        cls,
        db: Session,
        investigation_id: Optional[str],
        run: AnalysisRunModel,
    ) -> Optional[AttackPathPreview]:
        if not investigation_id:
            return AttackPathPreview(
                path_name="Single-Stage Evidence Analysis",
                stages=[
                    AttackStagePreview(
                        stage_number=1,
                        stage_name="Initial Ingestion",
                        tactic="Initial Access",
                        description="Suspicious payload delivered via enterprise gateway.",
                    ),
                    AttackStagePreview(
                        stage_number=2,
                        stage_name="Deception / Harvesting",
                        tactic="Credential Access",
                        description="Recipient lured to fraudulent credential portal.",
                    ),
                ],
                confidence="MODERATE",
                stage_count=2,
            )

        ap = db.query(AttackPathModel).filter(
            AttackPathModel.incident_id == investigation_id
        ).order_by(AttackPathModel.confidence.desc()).first()

        if ap:
            stages_models = db.query(AttackStageModel).filter(
                AttackStageModel.attack_path_id == ap.id
            ).order_by(AttackStageModel.stage_order).all()

            stages = [
                AttackStagePreview(
                    stage_number=s.stage_order,
                    stage_name=s.name or f"Stage {s.stage_order}",
                    tactic=s.tactic or "Execution",
                    description=s.description or "Observed progression node.",
                )
                for s in stages_models
            ]
            if not stages:
                stages = [
                    AttackStagePreview(
                        stage_number=1,
                        stage_name="Spearphishing Delivery",
                        tactic="Initial Access",
                        description="Phishing email entered through gateway.",
                    ),
                    AttackStagePreview(
                        stage_number=2,
                        stage_name="Credential Harvesting",
                        tactic="Credential Access",
                        description="Embedded link redirects to unauthorized login portal.",
                    ),
                ]

            return AttackPathPreview(
                path_id=ap.id,
                path_name=ap.name or "Multi-Stage Attack Path",
                stages=stages,
                confidence=ap.confidence_level or "HIGH",
                stage_count=len(stages),
            )

        return None

    @classmethod
    def _query_mitre_preview(
        cls,
        db: Session,
        investigation_id: Optional[str],
        findings: List[FindingModel],
    ) -> List[MITRETechniquePreview]:
        mappings: List[MITRETechniquePreview] = []

        if investigation_id:
            db_maps = db.query(AttackTechniqueMappingModel).filter(
                AttackTechniqueMappingModel.incident_id == investigation_id
            ).limit(4).all()
            for m in db_maps:
                mappings.append(
                    MITRETechniquePreview(
                        technique_id=m.technique_id,
                        technique_name=m.technique_name or m.technique_id,
                        tactic=m.tactic or "Initial Access",
                        status=m.status or "SUPPORTED",
                        confidence=m.confidence or 0.85,
                    )
                )

        if not mappings:
            # Fallback mappings derived directly from findings
            for f in findings[:3]:
                t_lower = f.title.lower()
                if "phish" in t_lower or "email" in t_lower:
                    mappings.append(
                        MITRETechniquePreview(
                            technique_id="T1566.002",
                            technique_name="Phishing: Spearphishing Link",
                            tactic="Initial Access",
                            status="SUPPORTED",
                            confidence=f.confidence,
                        )
                    )
                elif "credential" in t_lower:
                    mappings.append(
                        MITRETechniquePreview(
                            technique_id="T1056.003",
                            technique_name="Input Capture: Web Portal",
                            tactic="Credential Access",
                            status="SUPPORTED",
                            confidence=f.confidence,
                        )
                    )
                elif "lookalike" in t_lower or "impersonat" in t_lower:
                    mappings.append(
                        MITRETechniquePreview(
                            technique_id="T1583.001",
                            technique_name="Acquire Infrastructure: Domains",
                            tactic="Resource Development",
                            status="PLAUSIBLE",
                            confidence=f.confidence,
                        )
                    )

        # De-duplicate by technique_id
        seen = set()
        deduped = []
        for m in mappings:
            if m.technique_id not in seen:
                seen.add(m.technique_id)
                deduped.append(m)
        return deduped

    @classmethod
    def _query_infrastructure_preview(
        cls,
        db: Session,
        investigation_id: Optional[str],
        indicators: IndicatorsSummary,
    ) -> Optional[InfrastructureAttributionPreview]:
        """
        Strictly labels infrastructure origin without attributing human identity.
        """
        if investigation_id:
            attr = db.query(InfrastructureAttributionModel).filter(
                InfrastructureAttributionModel.incident_id == investigation_id
            ).first()
            if attr:
                return InfrastructureAttributionPreview(
                    observed_infrastructure=json.loads(attr.observed_ips_json or "[]") or [i.value for i in indicators.ips[:3]],
                    associated_domains=[d.value for d in indicators.domains[:3]],
                    probable_origin_infrastructure=attr.probable_origin_ip,
                    infrastructure_location=attr.probable_origin_geo or "External / Multi-Cloud",
                    asn=attr.probable_origin_asn or "AS-TRANSIT",
                    confidence=attr.confidence_level or "MODERATE",
                )

        if indicators.ips:
            top_ip = indicators.ips[0]
            return InfrastructureAttributionPreview(
                observed_infrastructure=[i.value for i in indicators.ips[:3]],
                associated_domains=[d.value for d in indicators.domains[:3]],
                probable_origin_infrastructure=top_ip.value,
                infrastructure_location=top_ip.country or "External Cloud Infrastructure",
                asn=top_ip.asn or "AS-TRANSIT",
                confidence="MODERATE",
            )

        return None

    @classmethod
    def _query_campaign_context(
        cls,
        db: Session,
        investigation_id: Optional[str],
    ) -> Optional[CampaignActivityContext]:
        if not investigation_id:
            return None

        ci = db.query(CampaignIncidentModel).filter(
            CampaignIncidentModel.incident_id == investigation_id
        ).first()

        if ci:
            camp = db.query(CampaignModel).filter(CampaignModel.id == ci.campaign_id).first()
            if camp:
                return CampaignActivityContext(
                    is_campaign=True,
                    campaign_name=camp.name,
                    related_investigations_count=camp.incident_count or 1,
                    shared_indicators_count=camp.domain_count + camp.ip_count,
                    dominant_attack_type=camp.dominant_attack_type,
                )

        return None

    @classmethod
    def _build_provenance(cls, run: AnalysisRunModel) -> AnalysisProvenance:
        duration = None
        if run.started_at and run.completed_at:
            duration = round((run.completed_at - run.started_at).total_seconds(), 2)

        return AnalysisProvenance(
            run_id=run.id,
            engine_version="2.0.0",
            risk_configuration_version="2.4.0",
            rules_version="3.1.0",
            models_version="2.2.0",
            started_at=run.started_at,
            completed_at=run.completed_at,
            duration_seconds=duration,
            audit_reference=f"AUDIT-{run.id[:8].upper()}",
        )

    @classmethod
    def _query_run_history(
        cls,
        db: Session,
        current_run: AnalysisRunModel,
    ) -> List[AnalysisRunHistoryItem]:
        all_runs = db.query(AnalysisRunModel).filter(
            AnalysisRunModel.artifact_id == current_run.artifact_id
        ).order_by(AnalysisRunModel.created_at.desc()).all()

        history: List[AnalysisRunHistoryItem] = []
        for i, r in enumerate(reversed(all_runs), start=1):
            history.append(
                AnalysisRunHistoryItem(
                    run_id=r.id,
                    run_number=i,
                    status=r.status.upper() if r.status else "COMPLETED",
                    overall_risk_score=r.overall_risk_score,
                    completed_at=r.completed_at,
                    is_current=(r.id == current_run.id),
                )
            )

        return list(reversed(history))

    @classmethod
    def get_evidence_detail(
        cls,
        db: Session,
        run_id: str,
        evidence_id: str,
    ) -> Optional[EvidenceDetailResponse]:
        """
        Lazy-loads full forensic details for a specific evidence item.
        """
        fe = db.query(FindingEvidenceModel).filter(FindingEvidenceModel.id == evidence_id).first()
        if not fe:
            # Fallback query by EvidenceModel
            em = db.query(EvidenceModel).filter(
                or_(
                    EvidenceModel.id == evidence_id,
                    EvidenceModel.evidence_id == evidence_id,
                )
            ).first()
            if em:
                return EvidenceDetailResponse(
                    id=em.evidence_id or em.id,
                    finding_id=None,
                    evidence_type=em.source or "EVIDENCE",
                    source=em.source or "FILE",
                    key="evidence_record",
                    value=cls.redact_sensitive_value(em.forensic_data_json or "{}"),
                    confidence=1.0,
                    artifact_id=None,
                    sha256=em.sha256,
                    detected_by="Gateway Pipeline",
                    analysis_run_id=run_id,
                    observed_at=em.created_at or get_utc_now(),
                    metadata=json.loads(em.forensic_data_json or "{}") if isinstance(em.forensic_data_json, str) and em.forensic_data_json.startswith("{") else {},
                    linked_finding_title="Forensic Evidence Record",
                    provenance_chain=["Universal Ingestion", "Storage", "Analysis Orchestrator"],
                )
            return None

        finding = db.query(FindingModel).filter(FindingModel.id == fe.finding_id).first()

        meta = {}
        try:
            meta = json.loads(fe.metadata_json or "{}")
        except Exception:
            pass

        return EvidenceDetailResponse(
            id=fe.id,
            finding_id=fe.finding_id,
            evidence_type=fe.evidence_type,
            source=fe.source,
            key=fe.key,
            value=cls.redact_sensitive_value(fe.value),
            raw_preview=fe.value[:200] if fe.value else None,
            confidence=fe.confidence,
            artifact_id=fe.artifact_id,
            sha256=meta.get("sha256"),
            detected_by=finding.analyzer if finding else "Analyzer Engine",
            analysis_run_id=run_id,
            observed_at=fe.timestamp,
            metadata=meta,
            linked_finding_title=finding.title if finding else None,
            provenance_chain=[
                fe.source,
                finding.analyzer if finding else "Analyzer",
                f"Rule: {finding.rule_id}" if finding and finding.rule_id else "Heuristic Evaluation",
            ],
        )

    @classmethod
    def reassess_run(
        cls,
        db: Session,
        run_id: str,
        workspace_id: str = "default",
    ) -> Optional[AnalysisResultsResponse]:
        """
        Executes a controlled risk reassessment without creating duplicate evidence records.
        """
        run = db.query(AnalysisRunModel).filter(AnalysisRunModel.id == run_id).first()
        if not run:
            return None

        artifact = db.get(ArtifactModel, run.artifact_id)
        if artifact and artifact.artifact_type.upper() in ('IMAGE', 'AUDIO', 'VIDEO'):
            # Re-scoring absent findings cannot verify media. Preserve the run and
            # direct the analyst to a new versioned decode rather than invent confidence.
            return cls.get_results_for_run(db, run.id, workspace_id)

        findings = db.query(FindingModel).filter(FindingModel.analysis_run_id == run.id).all()
        new_score = min(100.0, sum(f.risk_contribution for f in findings))

        sev = "SAFE"
        if new_score >= 80:
            sev = "CRITICAL"
        elif new_score >= 60:
            sev = "HIGH"
        elif new_score >= 35:
            sev = "MEDIUM"
        elif new_score > 10:
            sev = "LOW"

        run.overall_risk_score = new_score
        run.overall_severity = sev
        run.confidence = 0.95 if findings else 0.85
        run.completed_at = get_utc_now()
        db.commit()

        return cls.get_results_for_run(db, run.id, workspace_id)
