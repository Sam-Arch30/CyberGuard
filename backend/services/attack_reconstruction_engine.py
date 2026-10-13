"""
AI Attack Reconstruction Engine Service (Section 17).
Performs evidence-constrained hypothesis generation across multi-telemetry security data.

CORE PRINCIPLE:
ATTACK RECONSTRUCTION IS EVIDENCE-CONSTRAINED HYPOTHESIS GENERATION, NOT STORY GENERATION.
The engine must NEVER invent missing telemetry to make a cleaner narrative.

GOLDEN RULE:
Every reconstructed stage and relationship MUST be categorized as strictly:
- OBSERVED (direct telemetry)
- DERIVED (deterministic interpretation)
- INFERRED (reasonable security hypothesis supported indirectly)
- UNRESOLVED (potential stage where evidence is absent)
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
import json
import logging
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from backend.db.models import (
    IncidentModel,
    AttackPathModel,
    AttackStageModel,
    AttackEdgeModel,
    AttackHypothesisModel,
    SecurityEventModel,
    FindingModel,
    FindingEvidenceModel,
    ThreatEventModel,
    EntityModel,
    RelationshipModel,
    ArtifactModel,
    AnalysisRunModel,
    TemporalSequenceCandidateModel,
    CampaignIncidentModel,
    NoveltyAssessmentModel,
    generate_uuid,
    get_utc_now,
)
from backend.schemas.attack_reconstruction import (
    StageStatusEnum,
    AttackStageType,
    StageRelationshipType,
    AttackPathClassification,
    ConfidenceLevel,
    ReconstructionStatusEnum,
    AnalystDispositionEnum,
    GAP_NO_URL_CLICK,
    GAP_NO_PROCESS_TELEMETRY,
    GAP_NO_CREDENTIAL_THEFT_PROOF,
    GAP_NO_EXFILTRATION_CONFIRMATION,
    GAP_NO_VICTIM_INTERACTION,
    GAP_UNKNOWN_PRECEDING,
    GAP_NO_FURTHER_TELEMETRY,
    sanitize_reconstruction_attributes,
    calculate_confidence_level,
    AttackStageSchema,
    AttackTransitionSchema,
    AttackHypothesisSchema,
    AttackPathSchema,
    ReconstructionContext,
    ReconstructIncidentRequest,
    AttackReconstructionResponse,
    HypothesesResponse,
    EvidenceGapsResponse,
    TransitionEvidenceResponse,
    AnalystFeedbackRequest,
)
from backend.schemas.temporal_correlation import SecurityEventType

logger = logging.getLogger("cyberguard.attack_reconstruction")


# ============================================================================
# KNOWN GENERIC INFRASTRUCTURE (Scenario E False-Positive Mitigation)
# ============================================================================
GENERIC_SHARED_INFRASTRUCTURE = {
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "127.0.0.1",
    "cloudflare.com", "fastly.com", "akamai.com", "amazonaws.com", "google.com"
}


class AttackReconstructionEngine:
    """
    Core Evidence-Driven Attack Reconstruction Engine.
    Orchestrates telemetry ingestion, candidate stage generation, DAG transition construction,
    evidence gap discovery, alternative hypothesis synthesis, and deterministic explanation.
    """

    ENGINE_VERSION = "1.0.0"
    RULE_VERSION = "1.0.0"

    MAX_STAGES_LIMIT = 50
    MAX_CANDIDATE_PATHS = 10
    MAX_DAG_DEPTH = 15

    # ------------------------------------------------------------------------
    # 1. CONTEXT LOADING (NO RAW RE-PARSING)
    # ------------------------------------------------------------------------
    @classmethod
    def load_context(cls, db: Session, incident_id: str, workspace_id: str = "default") -> Tuple[IncidentModel, Dict[str, Any]]:
        """
        Loads normalized incident telemetry from Sections 6–16 without re-parsing raw files.
        Enforces tenant workspace isolation.
        """
        incident = db.query(IncidentModel).filter(
            IncidentModel.id == incident_id,
            IncidentModel.workspace_id == workspace_id
        ).first()

        if not incident:
            raise ValueError(f"Incident {incident_id} not found in workspace {workspace_id}")

        # Fetch normalized security events
        security_events = db.query(SecurityEventModel).filter(
            SecurityEventModel.incident_id == incident_id,
            SecurityEventModel.workspace_id == workspace_id
        ).order_by(SecurityEventModel.event_time.asc()).all()

        # Fetch threat events
        threat_events = db.query(ThreatEventModel).filter(
            ThreatEventModel.incident_id == incident_id
        ).order_by(ThreatEventModel.created_at.asc()).all()

        # Fetch temporal sequences (Section 16)
        temporal_sequences = db.query(TemporalSequenceCandidateModel).filter(
            TemporalSequenceCandidateModel.incident_id == incident_id,
            TemporalSequenceCandidateModel.workspace_id == workspace_id
        ).all()

        # Fetch campaign memberships (Section 15)
        campaign_memberships = db.query(CampaignIncidentModel).filter(
            CampaignIncidentModel.incident_id == incident_id
        ).all()

        # Fetch novelty assessments (Section 22)
        novelty_assessments = db.query(NoveltyAssessmentModel).filter(
            NoveltyAssessmentModel.incident_id == incident_id,
            NoveltyAssessmentModel.workspace_id == workspace_id
        ).all()

        # Fetch findings linked via threat events or analysis runs
        finding_ids: Set[str] = set()
        for ev in security_events:
            if ev.finding_ids_json:
                try:
                    ids = json.loads(ev.finding_ids_json)
                    finding_ids.update(ids)
                except Exception:
                    pass
        for te in threat_events:
            if te.metadata_json:
                try:
                    meta = json.loads(te.metadata_json)
                    if "finding_id" in meta:
                        finding_ids.add(meta["finding_id"])
                    if "finding_ids" in meta:
                        finding_ids.update(meta["finding_ids"])
                except Exception:
                    pass

        findings: List[FindingModel] = []
        if finding_ids:
            findings = db.query(FindingModel).filter(FindingModel.id.in_(list(finding_ids))).all()

        # Also retrieve findings linked via analysis_run_ids
        analysis_run_ids: Set[str] = set()
        for ev in security_events:
            if ev.analysis_run_id:
                analysis_run_ids.add(ev.analysis_run_id)
        for te in threat_events:
            if te.analysis_run_id:
                analysis_run_ids.add(te.analysis_run_id)
        if analysis_run_ids:
            run_findings = db.query(FindingModel).filter(FindingModel.analysis_run_id.in_(list(analysis_run_ids))).all()
            existing_f_ids = {f.id for f in findings}
            for rf in run_findings:
                if rf.id not in existing_f_ids:
                    findings.append(rf)
                    existing_f_ids.add(rf.id)

        # Fetch entities
        entity_ids: Set[str] = set()
        for ev in security_events:
            if ev.entity_ids_json:
                try:
                    ids = json.loads(ev.entity_ids_json)
                    entity_ids.update(ids)
                except Exception:
                    pass
        entities: List[EntityModel] = []
        if entity_ids:
            entities = db.query(EntityModel).filter(EntityModel.id.in_(list(entity_ids))).all()

        # Fetch relationships
        relationships: List[RelationshipModel] = []
        if entity_ids:
            relationships = db.query(RelationshipModel).filter(
                or_(
                    RelationshipModel.source_id.in_(list(entity_ids)),
                    RelationshipModel.target_id.in_(list(entity_ids))
                )
            ).all()

        # Calculate time range
        earliest_dt: Optional[datetime] = None
        latest_dt: Optional[datetime] = None
        for ev in security_events:
            if earliest_dt is None or ev.event_time < earliest_dt:
                earliest_dt = ev.event_time
            if latest_dt is None or ev.event_time > latest_dt:
                latest_dt = ev.event_time

        telemetry = {
            "security_events": security_events,
            "threat_events": threat_events,
            "findings": findings,
            "entities": entities,
            "relationships": relationships,
            "temporal_sequences": temporal_sequences,
            "campaign_memberships": campaign_memberships,
            "novelty_assessments": novelty_assessments,
            "has_novel_sequence": any(
                getattr(a, "novelty_type", "") in ("NOVEL_ATTACK_SEQUENCE", "NOVEL_EVENT_COMBINATION")
                and float(getattr(a, "novelty_score", 0.0)) >= 0.70
                for a in novelty_assessments
            ),
            "time_range": {"start": earliest_dt, "end": latest_dt}
        }
        return incident, telemetry

    # ------------------------------------------------------------------------
    # 2. CANDIDATE STAGE BUILDER (STRICT OBSERVED / DERIVED / INFERRED)
    # ------------------------------------------------------------------------
    @classmethod
    def build_candidate_stages(cls, telemetry: Dict[str, Any]) -> List[AttackStageSchema]:
        """
        Builds candidate stages from normalized inputs without inventing missing telemetry.
        """
        security_events: List[SecurityEventModel] = telemetry.get("security_events", [])
        threat_events: List[ThreatEventModel] = telemetry.get("threat_events", [])
        findings: List[FindingModel] = telemetry.get("findings", [])
        entities: List[EntityModel] = telemetry.get("entities", [])
        relationships: List[RelationshipModel] = telemetry.get("relationships", [])

        stages: List[AttackStageSchema] = []

        # Track observed event types and payloads
        events_by_type: Dict[str, List[SecurityEventModel]] = {}
        for ev in security_events:
            events_by_type.setdefault(ev.event_type, []).append(ev)

        findings_by_type: Dict[str, List[FindingModel]] = {}
        for f in findings:
            findings_by_type.setdefault(f.finding_type, []).append(f)

        # --------------------------------------------------------------------
        # Stage 1: DELIVERY (Email Received)
        # --------------------------------------------------------------------
        email_events = events_by_type.get(SecurityEventType.EMAIL_RECEIVED.value, [])
        if email_events:
            earliest_email = email_events[0]
            stage_entities = cls._extract_entity_ids(email_events)
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.DELIVERY,
                    stage_status=StageStatusEnum.OBSERVED,
                    technique_id="T1566",
                    tactic="Initial Access",
                    title="Phishing Email Delivered" if (findings_by_type or threat_events) else "Email Delivered",
                    description=earliest_email.summary or "Inbound email received and delivered to target mailbox.",
                    start_time=earliest_email.event_time,
                    end_time=email_events[-1].event_time,
                    confidence=0.95,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=stage_entities,
                    event_ids=[e.id for e in email_events],
                    supporting_evidence=[
                        {"source": "security_events", "event_type": earliest_email.event_type, "timestamp": earliest_email.event_time.isoformat()}
                    ],
                    limitations=[]
                )
            )

        # --------------------------------------------------------------------
        # Stage 2: SOCIAL ENGINEERING (Phishing / Urgent Request Findings)
        # --------------------------------------------------------------------
        social_eng_findings = (
            findings_by_type.get("PHISHING_INDICATOR", []) +
            findings_by_type.get("CREDENTIAL_SOLICITATION", []) +
            findings_by_type.get("URGENT_REQUEST", []) +
            findings_by_type.get("LOOKALIKE_DOMAIN", []) +
            findings_by_type.get("DECEPTIVE_SENDER", []) +
            findings_by_type.get("SUSPICIOUS_EMAIL", [])
        )
        if social_eng_findings or any("PHISHING" in (te.threat_type or "") for te in threat_events):
            f_ids = [f.id for f in social_eng_findings]
            start_t = email_events[0].event_time if email_events else (social_eng_findings[0].created_at if social_eng_findings else None)
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.SOCIAL_ENGINEERING,
                    stage_status=StageStatusEnum.DERIVED,
                    technique_id="T1566.002",
                    tactic="Initial Access",
                    title="Social Engineering Attempt",
                    description="Deceptive email lure containing credential solicitation or urgent call to action.",
                    start_time=start_t,
                    end_time=start_t,
                    confidence=0.85,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=cls._extract_entity_ids(email_events),
                    finding_ids=f_ids,
                    supporting_evidence=[
                        {"finding_type": f.finding_type, "severity": f.severity, "title": f.title}
                        for f in social_eng_findings[:5]
                    ],
                    limitations=["Does not prove the recipient clicked links or entered credentials."]
                )
            )

        # --------------------------------------------------------------------
        # Stage 3: USER INTERACTION (Strictly requires direct telemetry)
        # --------------------------------------------------------------------
        url_accessed_events = events_by_type.get(SecurityEventType.URL_ACCESSED.value, [])
        if url_accessed_events:
            earliest_url_acc = url_accessed_events[0]
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.USER_INTERACTION,
                    stage_status=StageStatusEnum.OBSERVED,
                    technique_id="T1204.001",
                    tactic="Execution",
                    title="Observed User URL Interaction",
                    description="Verified endpoint or web proxy telemetry confirms navigation to lure URL.",
                    start_time=earliest_url_acc.event_time,
                    end_time=url_accessed_events[-1].event_time,
                    confidence=0.90,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=cls._extract_entity_ids(url_accessed_events),
                    event_ids=[e.id for e in url_accessed_events],
                    supporting_evidence=[
                        {"source": "proxy/endpoint_telemetry", "event_type": "URL_ACCESSED", "timestamp": earliest_url_acc.event_time.isoformat()}
                    ],
                    limitations=[]
                )
            )

        # --------------------------------------------------------------------
        # Stage 4: FILE ACTIVITY (Attachment Presence != Process Execution)
        # --------------------------------------------------------------------
        file_events = events_by_type.get(SecurityEventType.FILE_OBSERVED.value, []) + events_by_type.get(SecurityEventType.FILE_EXTRACTED.value, [])
        file_findings = findings_by_type.get("SUSPICIOUS_ATTACHMENT", []) + findings_by_type.get("MALICIOUS_FILE", [])
        if file_events or file_findings:
            f_start = file_events[0].event_time if file_events else (file_findings[0].created_at if file_findings else None)
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.FILE_ACTIVITY,
                    stage_status=StageStatusEnum.OBSERVED,
                    technique_id="T1204.002",
                    tactic="Execution",
                    title="Suspicious Attachment / File Present",
                    description="File observable identified in artifact or storage. Endpoint process execution is not observed.",
                    start_time=f_start,
                    end_time=f_start,
                    confidence=0.80,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=cls._extract_entity_ids(file_events),
                    event_ids=[e.id for e in file_events],
                    finding_ids=[f.id for f in file_findings],
                    supporting_evidence=[
                        {"file_event_count": len(file_events), "file_finding_count": len(file_findings)}
                    ],
                    limitations=["Presence of attachment does not prove malicious code execution on endpoint."]
                )
            )

        # --------------------------------------------------------------------
        # Stage 5: INFRASTRUCTURE CONTACT (DNS / Network Connection)
        # --------------------------------------------------------------------
        dns_events = events_by_type.get(SecurityEventType.DNS_QUERY.value, [])
        net_events = events_by_type.get(SecurityEventType.NETWORK_CONNECTION.value, [])
        infra_events = sorted(dns_events + net_events, key=lambda x: x.event_time)
        if infra_events:
            earliest_infra = infra_events[0]
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.INFRASTRUCTURE_CONTACT,
                    stage_status=StageStatusEnum.OBSERVED,
                    technique_id="T1071",
                    tactic="Command and Control",
                    title="Suspicious Infrastructure Contact",
                    description="Outbound network resolution or socket connection established to external infrastructure.",
                    start_time=earliest_infra.event_time,
                    end_time=infra_events[-1].event_time,
                    confidence=0.85,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=cls._extract_entity_ids(infra_events),
                    event_ids=[e.id for e in infra_events],
                    supporting_evidence=[
                        {"event_type": e.event_type, "timestamp": e.event_time.isoformat()}
                        for e in infra_events[:4]
                    ],
                    limitations=["Avoids labeling as Command and Control (C2) without confirmed persistent beacon telemetry."]
                )
            )

        # --------------------------------------------------------------------
        # Stage 6: CREDENTIAL ACTIVITY (Inferred Compromise from Auth Pattern)
        # --------------------------------------------------------------------
        auth_fail_events = events_by_type.get(SecurityEventType.AUTH_FAILURE.value, [])
        auth_succ_events = events_by_type.get(SecurityEventType.AUTH_SUCCESS.value, [])
        has_auth_anomalies = bool(
            findings_by_type.get("AUTHENTICATION_ANOMALY", []) or
            findings_by_type.get("ATO_SIGNAL", []) or
            (auth_fail_events and auth_succ_events)
        )
        if has_auth_anomalies and (email_events or social_eng_findings or auth_fail_events):
            c_start = auth_fail_events[0].event_time if auth_fail_events else (auth_succ_events[0].event_time if auth_succ_events else None)
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.CREDENTIAL_ACTIVITY,
                    stage_status=StageStatusEnum.INFERRED,
                    technique_id="T1078",
                    tactic="Credential Access",
                    title="Possible Credential Compromise",
                    description="Inferred credential compromise suggested by repeated auth failures preceding success or anomalous origin.",
                    start_time=c_start,
                    end_time=c_start,
                    confidence=0.65,
                    confidence_level=ConfidenceLevel.MODERATE,
                    entity_ids=cls._extract_entity_ids(auth_fail_events + auth_succ_events),
                    event_ids=[e.id for e in auth_fail_events],
                    finding_ids=[f.id for f in findings_by_type.get("AUTHENTICATION_ANOMALY", [])],
                    supporting_evidence=[
                        {"auth_failures": len(auth_fail_events), "auth_successes": len(auth_succ_events)}
                    ],
                    limitations=["Direct credential theft from lure cannot be conclusively proven from auth logs alone."]
                )
            )

        # --------------------------------------------------------------------
        # Stage 7: AUTHENTICATION (Observed Logon)
        # --------------------------------------------------------------------
        if auth_succ_events:
            earliest_auth = auth_succ_events[0]
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.AUTHENTICATION,
                    stage_status=StageStatusEnum.OBSERVED,
                    technique_id="T1078",
                    tactic="Initial Access",
                    title="Abnormal Authentication" if has_auth_anomalies else "Observed Authentication",
                    description="Successful authentication event recorded for target account.",
                    start_time=earliest_auth.event_time,
                    end_time=auth_succ_events[-1].event_time,
                    confidence=0.90,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=cls._extract_entity_ids(auth_succ_events),
                    event_ids=[e.id for e in auth_succ_events],
                    supporting_evidence=[
                        {"event_type": "AUTH_SUCCESS", "timestamp": earliest_auth.event_time.isoformat()}
                    ],
                    limitations=[]
                )
            )

        # --------------------------------------------------------------------
        # Stage 8: SESSION ESTABLISHMENT (Session Created)
        # --------------------------------------------------------------------
        session_events = events_by_type.get(SecurityEventType.SESSION_CREATED.value, []) + events_by_type.get(SecurityEventType.SESSION_ACTIVITY.value, [])
        if session_events:
            earliest_sess = session_events[0]
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.SESSION_ESTABLISHMENT,
                    stage_status=StageStatusEnum.OBSERVED,
                    technique_id="T1550",
                    tactic="Defense Evasion",
                    title="Session Established",
                    description="Session token or stateful session established following authentication.",
                    start_time=earliest_sess.event_time,
                    end_time=session_events[-1].event_time,
                    confidence=0.95,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=cls._extract_entity_ids(session_events),
                    event_ids=[e.id for e in session_events],
                    supporting_evidence=[
                        {"session_events_count": len(session_events), "earliest": earliest_sess.event_time.isoformat()}
                    ],
                    limitations=[]
                )
            )

        # --------------------------------------------------------------------
        # Stage 9: ENUMERATION / DISCOVERY (API Enumeration)
        # --------------------------------------------------------------------
        enum_events = events_by_type.get(SecurityEventType.API_ENUMERATION.value, [])
        enum_findings = findings_by_type.get("API_ENUMERATION", []) + findings_by_type.get("API_ABUSE", [])
        if enum_events or enum_findings:
            e_start = enum_events[0].event_time if enum_events else (enum_findings[0].created_at if enum_findings else None)
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.ENUMERATION,
                    stage_status=StageStatusEnum.DERIVED,
                    technique_id="T1087",
                    tactic="Discovery",
                    title="API Resource Enumeration",
                    description="Sequential or rapid traversal across API endpoints or internal resource identifiers.",
                    start_time=e_start,
                    end_time=enum_events[-1].event_time if enum_events else e_start,
                    confidence=0.80,
                    confidence_level=ConfidenceLevel.HIGH,
                    entity_ids=cls._extract_entity_ids(enum_events),
                    event_ids=[e.id for e in enum_events],
                    finding_ids=[f.id for f in enum_findings],
                    supporting_evidence=[
                        {"enum_event_count": len(enum_events), "enum_finding_count": len(enum_findings)}
                    ],
                    limitations=["High-volume API usage may also reflect legitimate automation or client retries."]
                )
            )

        # --------------------------------------------------------------------
        # Stage 10: COLLECTION (Bulk Resource Access)
        # --------------------------------------------------------------------
        bulk_events = events_by_type.get(SecurityEventType.BULK_RESOURCE_ACCESS.value, [])
        bulk_findings = findings_by_type.get("BULK_DATA_ACCESS", []) + findings_by_type.get("SENSITIVE_DATA_ACCESS", [])
        if bulk_events or bulk_findings:
            b_start = bulk_events[0].event_time if bulk_events else (bulk_findings[0].created_at if bulk_findings else None)
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.COLLECTION,
                    stage_status=StageStatusEnum.INFERRED,
                    technique_id="T1119",
                    tactic="Collection",
                    title="Possible Collection",
                    description="Unusual quantity of data records or resources retrieved in an abnormal access pattern.",
                    start_time=b_start,
                    end_time=bulk_events[-1].event_time if bulk_events else b_start,
                    confidence=0.70,
                    confidence_level=ConfidenceLevel.MODERATE,
                    entity_ids=cls._extract_entity_ids(bulk_events),
                    event_ids=[e.id for e in bulk_events],
                    finding_ids=[f.id for f in bulk_findings],
                    supporting_evidence=[
                        {"bulk_events": len(bulk_events), "findings": len(bulk_findings)}
                    ],
                    limitations=["Internal bulk retrieval does not establish that data was removed from organizational boundaries."]
                )
            )

        # --------------------------------------------------------------------
        # Stage 11: OUTBOUND TRANSFER / EXFILTRATION
        # --------------------------------------------------------------------
        exfil_events = events_by_type.get(SecurityEventType.HIGH_OUTBOUND_DATA_VOLUME.value, [])
        exfil_findings = findings_by_type.get("DATA_EXFILTRATION_SIGNAL", [])
        if exfil_events or exfil_findings:
            ex_start = exfil_events[0].event_time if exfil_events else (exfil_findings[0].created_at if exfil_findings else None)
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.OUTBOUND_TRANSFER,
                    stage_status=StageStatusEnum.INFERRED,
                    technique_id="T1048",
                    tactic="Exfiltration",
                    title="Possible Data Exfiltration",
                    description="Significant outbound volume transferred following resource collection.",
                    start_time=ex_start,
                    end_time=exfil_events[-1].event_time if exfil_events else ex_start,
                    confidence=0.65,
                    confidence_level=ConfidenceLevel.MODERATE,
                    entity_ids=cls._extract_entity_ids(exfil_events),
                    event_ids=[e.id for e in exfil_events],
                    finding_ids=[f.id for f in exfil_findings],
                    supporting_evidence=[
                        {"exfil_events": len(exfil_events), "findings": len(exfil_findings)}
                    ],
                    limitations=["Outbound volume does not prove stolen data without definitive packet payload capture."]
                )
            )

        # --------------------------------------------------------------------
        # Stage 12: IMPERSONATION / DEEPFAKE (Section 12 / 13)
        # --------------------------------------------------------------------
        impersonation_findings = (
            findings_by_type.get("EXECUTIVE_IMPERSONATION", []) +
            findings_by_type.get("DEEPFAKE_VOICE", []) +
            findings_by_type.get("SYNTHETIC_MEDIA", []) +
            findings_by_type.get("BRAND_IMPERSONATION", [])
        )
        if impersonation_findings:
            imp_start = impersonation_findings[0].created_at
            stages.append(
                AttackStageSchema(
                    id=str(uuid.uuid4()),
                    stage_order=len(stages) + 1,
                    stage_type=AttackStageType.IMPERSONATION,
                    stage_status=StageStatusEnum.DERIVED,
                    technique_id="T1656",
                    tactic="Initial Access",
                    title="Executive / Identity Impersonation Attempt",
                    description="Synthetic media or brand spoofing observed attempting identity masquerade.",
                    start_time=imp_start,
                    end_time=imp_start,
                    confidence=0.75,
                    confidence_level=ConfidenceLevel.HIGH,
                    finding_ids=[f.id for f in impersonation_findings],
                    supporting_evidence=[
                        {"finding": f.title, "severity": f.severity} for f in impersonation_findings[:3]
                    ],
                    limitations=["Does not infer successful deception or payment wire transfer without bank/action telemetry."]
                )
            )

        # Sort stages chronologically
        stages = sorted(stages, key=lambda s: (s.start_time or datetime.min.replace(tzinfo=timezone.utc), s.stage_order))
        for idx, s in enumerate(stages):
            s.stage_order = idx + 1

        return stages

    @classmethod
    def _extract_entity_ids(cls, events: List[SecurityEventModel]) -> List[str]:
        entity_set: Set[str] = set()
        for ev in events:
            if ev.entity_ids_json:
                try:
                    ids = json.loads(ev.entity_ids_json)
                    entity_set.update(ids)
                except Exception:
                    pass
        return list(entity_set)

    # ------------------------------------------------------------------------
    # 3. TRANSITION / EDGE BUILDER (DAG CONSTRUCTION)
    # ------------------------------------------------------------------------
    @classmethod
    def build_transitions(
        cls,
        stages: List[AttackStageSchema],
        telemetry: Dict[str, Any]
    ) -> List[AttackTransitionSchema]:
        """
        Builds conservative directed transition edges between stages in chronological order.
        Verifies entity continuity and filters out links based solely on generic cloud IPs.
        """
        transitions: List[AttackTransitionSchema] = []
        if len(stages) < 2:
            return transitions

        entities: List[EntityModel] = telemetry.get("entities", [])
        entity_lookup = {e.id: (e.canonical_key or e.name) for e in entities}

        for i in range(len(stages) - 1):
            src = stages[i]
            tgt = stages[i + 1]

            # Calculate temporal gap
            gap_seconds: Optional[float] = None
            if src.end_time and tgt.start_time:
                s_t = src.end_time.replace(tzinfo=timezone.utc) if src.end_time.tzinfo is None else src.end_time
                t_t = tgt.start_time.replace(tzinfo=timezone.utc) if tgt.start_time.tzinfo is None else tgt.start_time
                gap_seconds = max(0.0, (t_t - s_t).total_seconds())

            # Find shared entities
            shared_ids = set(src.entity_ids).intersection(set(tgt.entity_ids))
            shared_canonical = [entity_lookup.get(eid, eid) for eid in shared_ids]

            # Scenario E Check: Is the ONLY shared entity a generic infrastructure IP/domain?
            is_only_generic_ip = False
            if shared_canonical:
                is_only_generic_ip = all(any(gen in c.lower() for gen in GENERIC_SHARED_INFRASTRUCTURE) for c in shared_canonical)

            # Determine transition status and relationship
            edge_status = StageStatusEnum.DERIVED
            if src.stage_status == StageStatusEnum.OBSERVED and tgt.stage_status == StageStatusEnum.OBSERVED:
                # E.g. Auth Success -> Session Created in same continuous auth stream
                if (src.stage_type == AttackStageType.AUTHENTICATION and tgt.stage_type == AttackStageType.SESSION_ESTABLISHMENT) or \
                   (src.stage_type == AttackStageType.USER_INTERACTION and tgt.stage_type == AttackStageType.INFRASTRUCTURE_CONTACT):
                    edge_status = StageStatusEnum.OBSERVED
            elif src.stage_status == StageStatusEnum.INFERRED or tgt.stage_status == StageStatusEnum.INFERRED:
                edge_status = StageStatusEnum.INFERRED

            # Evaluate confidence
            confidence = 0.70
            if shared_canonical and not is_only_generic_ip:
                confidence += 0.20
            if gap_seconds is not None and gap_seconds < 1800:  # < 30 mins
                confidence += 0.05
            if is_only_generic_ip:
                confidence = max(0.20, confidence - 0.40)

            confidence = min(1.0, max(0.1, confidence))

            transitions.append(
                AttackTransitionSchema(
                    id=str(uuid.uuid4()),
                    from_stage_id=src.id,
                    to_stage_id=tgt.id,
                    relationship_type=StageRelationshipType.PRECEDES,
                    edge_status=edge_status,
                    temporal_gap_seconds=gap_seconds,
                    confidence=confidence,
                    confidence_level=calculate_confidence_level(confidence),
                    shared_entities=shared_canonical,
                    supporting_evidence=[
                        {"source_stage": src.stage_type.value, "target_stage": tgt.stage_type.value, "gap_seconds": gap_seconds}
                    ],
                    contradicting_evidence=[
                        {"reason": "Only link between stages is generic public infrastructure"}
                    ] if is_only_generic_ip else []
                )
            )

        return transitions

    # ------------------------------------------------------------------------
    # 4. CONTRADICTION & GAP DETECTOR
    # ------------------------------------------------------------------------
    @classmethod
    def detect_contradictions_and_gaps(
        cls,
        stages: List[AttackStageSchema],
        telemetry: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """
        Identifies contradicting telemetry (e.g. successful MFA, confirmed corporate VPN)
        and explicitly catalogs evidence gaps (missing telemetry).
        """
        contradictions: List[Dict[str, Any]] = []
        gaps: List[str] = []

        security_events: List[SecurityEventModel] = telemetry.get("security_events", [])
        stage_types = {s.stage_type for s in stages}

        # Contradiction checks
        for ev in security_events:
            if ev.event_type == SecurityEventType.MFA_EVENT.value:
                try:
                    attrs = json.loads(ev.attributes_json)
                    if attrs.get("mfa_result") in ("SUCCESS", "VERIFIED"):
                        contradictions.append({
                            "type": "LEGITIMATE_MFA_SUCCESS",
                            "description": "Legitimate multi-factor authentication was successfully verified.",
                            "penalty": 0.20,
                            "timestamp": ev.event_time.isoformat()
                        })
                except Exception:
                    pass
            if ev.event_type == SecurityEventType.AUTH_SUCCESS.value:
                try:
                    attrs = json.loads(ev.attributes_json)
                    if attrs.get("is_corporate_vpn") or attrs.get("network_zone") == "INTERNAL":
                        contradictions.append({
                            "type": "CORPORATE_NETWORK_SOURCE",
                            "description": "Logon originated from internal corporate VPN or managed network zone.",
                            "penalty": 0.15,
                            "timestamp": ev.event_time.isoformat()
                        })
                except Exception:
                    pass

        # Evidence Gap checks
        if AttackStageType.DELIVERY in stage_types or AttackStageType.SOCIAL_ENGINEERING in stage_types:
            if AttackStageType.USER_INTERACTION not in stage_types:
                gaps.append(GAP_NO_URL_CLICK)

        if AttackStageType.FILE_ACTIVITY in stage_types:
            if AttackStageType.EXECUTION not in stage_types:
                gaps.append(GAP_NO_PROCESS_TELEMETRY)

        if AttackStageType.CREDENTIAL_ACTIVITY in stage_types:
            gaps.append(GAP_NO_CREDENTIAL_THEFT_PROOF)

        if AttackStageType.OUTBOUND_TRANSFER in stage_types:
            gaps.append(GAP_NO_EXFILTRATION_CONFIRMATION)

        if AttackStageType.IMPERSONATION in stage_types:
            gaps.append(GAP_NO_VICTIM_INTERACTION)

        # Preceding / Terminal gaps
        if stages and stages[0].stage_type in (AttackStageType.AUTHENTICATION, AttackStageType.SESSION_ESTABLISHMENT, AttackStageType.ENUMERATION):
            gaps.append(GAP_UNKNOWN_PRECEDING)

        if stages and stages[-1].stage_type in (AttackStageType.ENUMERATION, AttackStageType.COLLECTION):
            gaps.append(GAP_NO_FURTHER_TELEMETRY)

        return contradictions, gaps

    # ------------------------------------------------------------------------
    # 5. ALTERNATIVE HYPOTHESIS GENERATOR & RANKER
    # ------------------------------------------------------------------------
    @classmethod
    def generate_and_rank_hypotheses(
        cls,
        incident_id: str,
        stages: List[AttackStageSchema],
        contradictions: List[Dict[str, Any]],
        gaps: List[str]
    ) -> List[AttackHypothesisSchema]:
        """
        Synthesizes primary and alternative hypotheses, ranking them using explainable evidence.
        Does NOT rely on LLM preference.
        """
        hypotheses: List[AttackHypothesisSchema] = []
        stage_ids = [s.id for s in stages]
        stage_types = {s.stage_type for s in stages}

        # Primary Hypothesis
        primary_confidence = 0.75
        if contradictions:
            primary_confidence -= 0.15 * len(contradictions)
        if gaps:
            primary_confidence -= 0.05 * len(gaps)
        primary_confidence = min(0.95, max(0.20, primary_confidence))

        hypotheses.append(
            AttackHypothesisSchema(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                title="Multi-Stage Attack Progression",
                description="Observed and derived events reflect a progressive adversary intrusion chain.",
                status="PLAUSIBLE",
                is_primary=True,
                stage_ids=stage_ids,
                confidence=primary_confidence,
                confidence_level=calculate_confidence_level(primary_confidence),
                supporting_evidence=[
                    {"stage_count": len(stages), "observed_stages": [s.stage_type.value for s in stages if s.stage_status == StageStatusEnum.OBSERVED]}
                ],
                contradicting_evidence=contradictions,
                missing_evidence=gaps
            )
        )

        # Alternative Hypothesis 1: Coincidental / Unrelated Events
        if (AttackStageType.DELIVERY in stage_types or AttackStageType.SOCIAL_ENGINEERING in stage_types) and \
           (AttackStageType.AUTHENTICATION in stage_types or AttackStageType.ENUMERATION in stage_types):
            alt1_conf = 0.35
            if GAP_NO_URL_CLICK in gaps:
                alt1_conf += 0.20
            if GAP_NO_CREDENTIAL_THEFT_PROOF in gaps:
                alt1_conf += 0.15
            alt1_conf = min(0.90, max(0.10, alt1_conf))

            hypotheses.append(
                AttackHypothesisSchema(
                    id=str(uuid.uuid4()),
                    incident_id=incident_id,
                    title="Coincidental Unrelated Incidents",
                    description="Initial phishing/delivery and subsequent account activity are independent, coincidental occurrences.",
                    status="PLAUSIBLE",
                    is_primary=False,
                    stage_ids=stage_ids,
                    confidence=alt1_conf,
                    confidence_level=calculate_confidence_level(alt1_conf),
                    supporting_evidence=[
                        {"reason": "No direct telemetry linking phishing delivery to credential theft or login"}
                    ],
                    contradicting_evidence=[
                        {"reason": "Close temporal proximity and common targeted account"}
                    ],
                    missing_evidence=[GAP_NO_URL_CLICK, GAP_NO_CREDENTIAL_THEFT_PROOF]
                )
            )

        # Alternative Hypothesis 2: Benign Automation / Legitimate Admin Activity
        if AttackStageType.ENUMERATION in stage_types or AttackStageType.COLLECTION in stage_types:
            alt2_conf = 0.30
            if any(c.get("type") == "LEGITIMATE_MFA_SUCCESS" for c in contradictions):
                alt2_conf += 0.30
            if any(c.get("type") == "CORPORATE_NETWORK_SOURCE" for c in contradictions):
                alt2_conf += 0.20
            alt2_conf = min(0.85, max(0.10, alt2_conf))

            hypotheses.append(
                AttackHypothesisSchema(
                    id=str(uuid.uuid4()),
                    incident_id=incident_id,
                    title="Authorized Administrative or Automated Scripting",
                    description="High-volume enumeration or bulk access reflects authorized scheduled reporting or IT administration.",
                    status="PLAUSIBLE",
                    is_primary=False,
                    stage_ids=stage_ids,
                    confidence=alt2_conf,
                    confidence_level=calculate_confidence_level(alt2_conf),
                    supporting_evidence=contradictions,
                    contradicting_evidence=[
                        {"reason": "High entropy, unexpected endpoint traversal, or failure prior to auth"}
                    ],
                    missing_evidence=[]
                )
            )

        # Sort hypotheses by confidence descending
        return sorted(hypotheses, key=lambda h: h.confidence, reverse=True)

    # ------------------------------------------------------------------------
    # 6. DETERMINISTIC RECONSTRUCTION PIPELINE & PERSISTENCE
    # ------------------------------------------------------------------------
    @classmethod
    def reconstruct_incident(
        cls,
        db: Session,
        incident_id: str,
        workspace_id: str = "default",
        force_reanalysis: bool = False,
        include_llm_summary: bool = False
    ) -> AttackReconstructionResponse:
        """
        Orchestrates full attack reconstruction pipeline:
        1. Loads normalized context
        2. Builds candidate stages
        3. Builds DAG transitions
        4. Detects contradictions and evidence gaps
        5. Synthesizes and ranks hypotheses
        6. Persists versioned AttackPath and models
        7. Produces deterministic explainable summary
        """
        # Check existing CURRENT attack path
        existing_path = db.query(AttackPathModel).filter(
            AttackPathModel.incident_id == incident_id,
            AttackPathModel.status == ReconstructionStatusEnum.CURRENT.value
        ).first()

        if existing_path and not force_reanalysis:
            return cls._hydrate_response_from_model(db, existing_path)

        # 1. Load context
        incident, telemetry = cls.load_context(db, incident_id, workspace_id)

        # 2. Build candidate stages
        stages = cls.build_candidate_stages(telemetry)

        # 3. Build transitions
        transitions = cls.build_transitions(stages, telemetry)

        # 4. Detect contradictions and gaps
        contradictions, gaps = cls.detect_contradictions_and_gaps(stages, telemetry)

        # 5. Generate and rank hypotheses
        hypotheses = cls.generate_and_rank_hypotheses(incident_id, stages, contradictions, gaps)

        # Calculate completeness score (ratio of OBSERVED / DERIVED stages to total stages)
        completeness = 0.0
        if stages:
            ev_count = sum(1 for s in stages if s.stage_status in (StageStatusEnum.OBSERVED, StageStatusEnum.DERIVED))
            completeness = round(ev_count / len(stages), 2)

        # Primary hypothesis determines path confidence
        primary_hyp = next((h for h in hypotheses if h.is_primary), hypotheses[0] if hypotheses else None)
        path_confidence = primary_hyp.confidence if primary_hyp else 0.50

        # Classification
        classification = AttackPathClassification.PLAUSIBLE_RECONSTRUCTION
        if completeness >= 0.85 and path_confidence >= 0.80 and not contradictions:
            classification = AttackPathClassification.STRONG_RECONSTRUCTION
        elif completeness < 0.50 or path_confidence < 0.40:
            classification = AttackPathClassification.PARTIAL_RECONSTRUCTION

        # Time range
        time_range = telemetry.get("time_range", {})
        start_t = time_range.get("start")
        end_t = time_range.get("end")

        # 6. Versioning: Supersede prior path if reanalyzing
        version = 1
        if existing_path:
            existing_path.status = ReconstructionStatusEnum.SUPERSEDED.value
            version = existing_path.version + 1
            db.flush()

        # Persist new AttackPathModel
        path_id = str(uuid.uuid4())
        path_model = AttackPathModel(
            id=path_id,
            incident_id=incident_id,
            workspace_id=workspace_id,
            name=f"Attack Reconstruction v{version}",
            description=f"Evidence-constrained reconstruction of incident {incident_id} ({len(stages)} stages).",
            classification=classification.value,
            confidence=path_confidence,
            status=ReconstructionStatusEnum.CURRENT.value,
            start_time=start_t,
            end_time=end_t,
            supporting_evidence_json=json.dumps(sanitize_reconstruction_attributes(primary_hyp.supporting_evidence if primary_hyp else [])),
            contradicting_evidence_json=json.dumps(sanitize_reconstruction_attributes(contradictions)),
            evidence_gaps_json=json.dumps(gaps),
            alternative_hypotheses_json=json.dumps([h.model_dump(mode="json") for h in hypotheses]),
            version=version,
            engine_version=cls.ENGINE_VERSION,
            rule_version=cls.RULE_VERSION,
            metadata_json=json.dumps({
                "completeness_score": completeness,
                "confidence_level": calculate_confidence_level(path_confidence).value
            }),
            created_at=get_utc_now(),
            updated_at=get_utc_now()
        )
        db.add(path_model)
        db.flush()

        # Persist stages
        stage_model_map: Dict[str, AttackStageModel] = {}
        for s in stages:
            sm = AttackStageModel(
                id=s.id,
                attack_path_id=path_id,
                stage_order=s.stage_order,
                stage_type=s.stage_type.value,
                stage_status=s.stage_status.value,
                technique_id=s.technique_id,
                tactic=s.tactic,
                name=s.title,
                description=s.description,
                status=s.status,
                start_time=s.start_time,
                end_time=s.end_time,
                confidence=s.confidence,
                entity_ids_json=json.dumps(s.entity_ids),
                event_ids_json=json.dumps(s.event_ids),
                finding_ids_json=json.dumps(s.finding_ids),
                evidence_ids_json=json.dumps(s.evidence_ids),
                relationship_ids_json=json.dumps(s.relationship_ids),
                supporting_evidence_json=json.dumps(sanitize_reconstruction_attributes(s.supporting_evidence)),
                contradicting_evidence_json=json.dumps(sanitize_reconstruction_attributes(s.contradicting_evidence)),
                limitations_json=json.dumps(s.limitations),
                metadata_json=json.dumps(sanitize_reconstruction_attributes(s.metadata)),
                created_at=get_utc_now()
            )
            db.add(sm)
            stage_model_map[s.id] = sm
        db.flush()

        # Persist edges
        for tr in transitions:
            em = AttackEdgeModel(
                id=tr.id,
                attack_path_id=path_id,
                source_stage_id=tr.from_stage_id,
                target_stage_id=tr.to_stage_id,
                relationship_type=tr.relationship_type.value,
                edge_status=tr.edge_status.value,
                temporal_gap_seconds=tr.temporal_gap_seconds,
                shared_entities_json=json.dumps(tr.shared_entities),
                supporting_evidence_json=json.dumps(sanitize_reconstruction_attributes(tr.supporting_evidence)),
                contradicting_evidence_json=json.dumps(sanitize_reconstruction_attributes(tr.contradicting_evidence)),
                confidence=tr.confidence,
                metadata_json=json.dumps(sanitize_reconstruction_attributes(tr.metadata)),
                created_at=get_utc_now()
            )
            db.add(em)
        db.flush()

        # Persist hypotheses
        for h in hypotheses:
            h.attack_path_id = path_id
            hm = AttackHypothesisModel(
                id=h.id,
                incident_id=incident_id,
                attack_path_id=path_id,
                workspace_id=workspace_id,
                title=h.title,
                description=h.description,
                status=h.status,
                is_primary=h.is_primary,
                stage_ids_json=json.dumps(h.stage_ids),
                confidence=h.confidence,
                supporting_evidence_json=json.dumps(sanitize_reconstruction_attributes(h.supporting_evidence)),
                contradicting_evidence_json=json.dumps(sanitize_reconstruction_attributes(h.contradicting_evidence)),
                missing_evidence_json=json.dumps(h.missing_evidence),
                metadata_json=json.dumps(sanitize_reconstruction_attributes(h.metadata)),
                created_at=get_utc_now(),
                updated_at=get_utc_now()
            )
            db.add(hm)

        # Build the response before commit expires the loaded telemetry and path.
        # Reading path attributes after commit otherwise reloads eager collections.
        # No response is returned unless the final transaction commits successfully.

        # Build schema response
        path_schema = AttackPathSchema(
            id=path_id,
            incident_id=incident_id,
            workspace_id=workspace_id,
            name=path_model.name,
            description=path_model.description,
            classification=classification,
            status=ReconstructionStatusEnum.CURRENT,
            confidence=path_confidence,
            confidence_level=calculate_confidence_level(path_confidence),
            completeness_score=completeness,
            start_time=start_t,
            end_time=end_t,
            stages=stages,
            transitions=transitions,
            supporting_evidence=primary_hyp.supporting_evidence if primary_hyp else [],
            contradicting_evidence=contradictions,
            evidence_gaps=gaps,
            alternative_hypotheses=hypotheses,
            limitations=[
                "Reconstruction reflects evidence-constrained hypotheses. Stages labeled INFERRED are not directly observed telemetry."
            ],
            version=version,
            engine_version=cls.ENGINE_VERSION,
            rule_version=cls.RULE_VERSION,
            created_at=path_model.created_at,
            updated_at=path_model.updated_at
        )

        ctx_summary = ReconstructionContext(
            incident_id=incident_id,
            workspace_id=workspace_id,
            time_range={"start": start_t, "end": end_t},
            artifact_count=len(telemetry.get("artifacts", [])),
            entity_count=len(telemetry.get("entities", [])),
            relationship_count=len(telemetry.get("relationships", [])),
            event_count=len(telemetry.get("security_events", [])),
            finding_count=len(telemetry.get("findings", [])),
            threat_event_count=len(telemetry.get("threat_events", [])),
            sequence_count=len(telemetry.get("temporal_sequences", [])),
            campaign_count=len(telemetry.get("campaign_memberships", [])),
            engine_version=cls.ENGINE_VERSION,
            configuration_version=cls.RULE_VERSION
        )

        response = AttackReconstructionResponse(
            attack_path=path_schema,
            stages=stages,
            transitions=transitions,
            supporting_evidence=primary_hyp.supporting_evidence if primary_hyp else [],
            contradicting_evidence=contradictions,
            evidence_gaps=gaps,
            alternative_hypotheses=hypotheses,
            confidence=path_confidence,
            confidence_level=calculate_confidence_level(path_confidence),
            limitations=path_schema.limitations,
            context=ctx_summary
        )
        db.commit()
        return response

    # ------------------------------------------------------------------------
    # 7. RESPONSE HYDRATION FROM DATABASE
    # ------------------------------------------------------------------------
    @classmethod
    def _hydrate_response_from_model(cls, db: Session, path_model: AttackPathModel) -> AttackReconstructionResponse:
        """Hydrates AttackReconstructionResponse from persisted database records."""
        stages: List[AttackStageSchema] = []
        for s in path_model.stages:
            stages.append(
                AttackStageSchema(
                    id=s.id,
                    stage_order=s.stage_order,
                    stage_type=AttackStageType(s.stage_type) if s.stage_type in AttackStageType.__members__ else AttackStageType.UNKNOWN_ACTIVITY,
                    stage_status=StageStatusEnum(s.stage_status) if s.stage_status in StageStatusEnum.__members__ else StageStatusEnum.OBSERVED,
                    technique_id=s.technique_id,
                    tactic=s.tactic,
                    title=s.name,
                    description=s.description,
                    status=s.status,
                    start_time=s.start_time,
                    end_time=s.end_time,
                    confidence=s.confidence,
                    confidence_level=calculate_confidence_level(s.confidence),
                    entity_ids=json.loads(s.entity_ids_json) if s.entity_ids_json else [],
                    event_ids=json.loads(s.event_ids_json) if s.event_ids_json else [],
                    finding_ids=json.loads(s.finding_ids_json) if s.finding_ids_json else [],
                    evidence_ids=json.loads(s.evidence_ids_json) if s.evidence_ids_json else [],
                    relationship_ids=json.loads(s.relationship_ids_json) if s.relationship_ids_json else [],
                    supporting_evidence=json.loads(s.supporting_evidence_json) if s.supporting_evidence_json else [],
                    contradicting_evidence=json.loads(s.contradicting_evidence_json) if s.contradicting_evidence_json else [],
                    limitations=json.loads(s.limitations_json) if s.limitations_json else [],
                    analyst_disposition=s.analyst_disposition,
                    analyst_notes=s.analyst_notes
                )
            )

        transitions: List[AttackTransitionSchema] = []
        for e in path_model.edges:
            transitions.append(
                AttackTransitionSchema(
                    id=e.id,
                    from_stage_id=e.source_stage_id,
                    to_stage_id=e.target_stage_id,
                    relationship_type=StageRelationshipType(e.relationship_type) if e.relationship_type in StageRelationshipType.__members__ else StageRelationshipType.PRECEDES,
                    edge_status=StageStatusEnum(e.edge_status) if e.edge_status in StageStatusEnum.__members__ else StageStatusEnum.DERIVED,
                    temporal_gap_seconds=e.temporal_gap_seconds,
                    confidence=e.confidence,
                    confidence_level=calculate_confidence_level(e.confidence),
                    shared_entities=json.loads(e.shared_entities_json) if e.shared_entities_json else [],
                    supporting_evidence=json.loads(e.supporting_evidence_json) if e.supporting_evidence_json else [],
                    contradicting_evidence=json.loads(e.contradicting_evidence_json) if e.contradicting_evidence_json else [],
                    analyst_disposition=e.analyst_disposition,
                    analyst_notes=e.analyst_notes
                )
            )

        hypotheses: List[AttackHypothesisSchema] = []
        for h in path_model.hypotheses:
            hypotheses.append(
                AttackHypothesisSchema(
                    id=h.id,
                    incident_id=h.incident_id,
                    attack_path_id=h.attack_path_id,
                    title=h.title,
                    description=h.description,
                    status=h.status,
                    is_primary=h.is_primary,
                    stage_ids=json.loads(h.stage_ids_json) if h.stage_ids_json else [],
                    confidence=h.confidence,
                    confidence_level=calculate_confidence_level(h.confidence),
                    supporting_evidence=json.loads(h.supporting_evidence_json) if h.supporting_evidence_json else [],
                    contradicting_evidence=json.loads(h.contradicting_evidence_json) if h.contradicting_evidence_json else [],
                    missing_evidence=json.loads(h.missing_evidence_json) if h.missing_evidence_json else [],
                    analyst_disposition=h.analyst_disposition,
                    analyst_notes=h.analyst_notes
                )
            )

        meta = {}
        if path_model.metadata_json:
            try:
                meta = json.loads(path_model.metadata_json)
            except Exception:
                pass

        supporting = json.loads(path_model.supporting_evidence_json) if path_model.supporting_evidence_json else []
        contradicting = json.loads(path_model.contradicting_evidence_json) if path_model.contradicting_evidence_json else []
        gaps = json.loads(path_model.evidence_gaps_json) if path_model.evidence_gaps_json else []

        path_schema = AttackPathSchema(
            id=path_model.id,
            incident_id=path_model.incident_id,
            workspace_id=path_model.workspace_id,
            name=path_model.name,
            description=path_model.description,
            classification=AttackPathClassification(path_model.classification) if path_model.classification in AttackPathClassification.__members__ else AttackPathClassification.PLAUSIBLE_RECONSTRUCTION,
            status=ReconstructionStatusEnum(path_model.status) if path_model.status in ReconstructionStatusEnum.__members__ else ReconstructionStatusEnum.CURRENT,
            confidence=path_model.confidence,
            confidence_level=calculate_confidence_level(path_model.confidence),
            completeness_score=meta.get("completeness_score", 0.0),
            start_time=path_model.start_time,
            end_time=path_model.end_time,
            stages=stages,
            transitions=transitions,
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            evidence_gaps=gaps,
            alternative_hypotheses=hypotheses,
            limitations=[
                "Reconstruction reflects evidence-constrained hypotheses. Stages labeled INFERRED are not directly observed telemetry."
            ],
            version=path_model.version,
            engine_version=path_model.engine_version,
            rule_version=path_model.rule_version,
            analyst_disposition=path_model.analyst_disposition,
            analyst_notes=path_model.analyst_notes,
            reviewed_by=path_model.reviewed_by,
            reviewed_at=path_model.reviewed_at,
            created_at=path_model.created_at,
            updated_at=path_model.updated_at
        )

        return AttackReconstructionResponse(
            attack_path=path_schema,
            stages=stages,
            transitions=transitions,
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            evidence_gaps=gaps,
            alternative_hypotheses=hypotheses,
            confidence=path_model.confidence,
            confidence_level=calculate_confidence_level(path_model.confidence),
            limitations=path_schema.limitations
        )

    # ------------------------------------------------------------------------
    # 8. ANALYST FEEDBACK LOGIC
    # ------------------------------------------------------------------------
    @classmethod
    def record_stage_feedback(
        cls,
        db: Session,
        stage_id: str,
        feedback: AnalystFeedbackRequest,
        workspace_id: str = "default"
    ) -> AttackStageSchema:
        """Records analyst feedback on a reconstructed attack stage."""
        stage = db.query(AttackStageModel).filter(AttackStageModel.id == stage_id).first()
        if not stage:
            raise ValueError(f"AttackStage {stage_id} not found")

        stage.analyst_disposition = feedback.disposition.value
        if feedback.notes:
            stage.analyst_notes = feedback.notes
        db.commit()
        db.refresh(stage)

        return AttackStageSchema(
            id=stage.id,
            stage_order=stage.stage_order,
            stage_type=AttackStageType(stage.stage_type) if stage.stage_type in AttackStageType.__members__ else AttackStageType.UNKNOWN_ACTIVITY,
            stage_status=StageStatusEnum(stage.stage_status) if stage.stage_status in StageStatusEnum.__members__ else StageStatusEnum.OBSERVED,
            title=stage.name,
            description=stage.description,
            status=stage.status,
            start_time=stage.start_time,
            end_time=stage.end_time,
            confidence=stage.confidence,
            confidence_level=calculate_confidence_level(stage.confidence),
            analyst_disposition=stage.analyst_disposition,
            analyst_notes=stage.analyst_notes
        )

    @classmethod
    def record_transition_feedback(
        cls,
        db: Session,
        edge_id: str,
        feedback: AnalystFeedbackRequest,
        workspace_id: str = "default"
    ) -> TransitionEvidenceResponse:
        """Records analyst feedback on an attack transition edge."""
        edge = db.query(AttackEdgeModel).filter(AttackEdgeModel.id == edge_id).first()
        if not edge:
            raise ValueError(f"AttackEdge {edge_id} not found")

        edge.analyst_disposition = feedback.disposition.value
        if feedback.notes:
            edge.analyst_notes = feedback.notes
        db.commit()
        db.refresh(edge)

        return TransitionEvidenceResponse(
            transition_id=edge.id,
            from_stage_id=edge.source_stage_id,
            to_stage_id=edge.target_stage_id,
            relationship_type=edge.relationship_type,
            edge_status=edge.edge_status,
            confidence=edge.confidence,
            confidence_level=calculate_confidence_level(edge.confidence),
            shared_entities=json.loads(edge.shared_entities_json) if edge.shared_entities_json else [],
            temporal_gap_seconds=edge.temporal_gap_seconds,
            supporting_evidence=json.loads(edge.supporting_evidence_json) if edge.supporting_evidence_json else [],
            contradicting_evidence=json.loads(edge.contradicting_evidence_json) if edge.contradicting_evidence_json else []
        )

    @classmethod
    def record_hypothesis_feedback(
        cls,
        db: Session,
        hypothesis_id: str,
        feedback: AnalystFeedbackRequest,
        workspace_id: str = "default"
    ) -> AttackHypothesisSchema:
        """Records analyst feedback on an attack hypothesis."""
        hyp = db.query(AttackHypothesisModel).filter(
            AttackHypothesisModel.id == hypothesis_id,
            AttackHypothesisModel.workspace_id == workspace_id
        ).first()
        if not hyp:
            raise ValueError(f"AttackHypothesis {hypothesis_id} not found in workspace {workspace_id}")

        hyp.analyst_disposition = feedback.disposition.value
        if feedback.notes:
            hyp.analyst_notes = feedback.notes
        db.commit()
        db.refresh(hyp)

        return AttackHypothesisSchema(
            id=hyp.id,
            incident_id=hyp.incident_id,
            attack_path_id=hyp.attack_path_id,
            title=hyp.title,
            description=hyp.description,
            status=hyp.status,
            is_primary=hyp.is_primary,
            stage_ids=json.loads(hyp.stage_ids_json) if hyp.stage_ids_json else [],
            confidence=hyp.confidence,
            confidence_level=calculate_confidence_level(hyp.confidence),
            supporting_evidence=json.loads(hyp.supporting_evidence_json) if hyp.supporting_evidence_json else [],
            contradicting_evidence=json.loads(hyp.contradicting_evidence_json) if hyp.contradicting_evidence_json else [],
            missing_evidence=json.loads(hyp.missing_evidence_json) if hyp.missing_evidence_json else [],
            analyst_disposition=hyp.analyst_disposition,
            analyst_notes=hyp.analyst_notes
        )


# Global Service Instance
attack_reconstruction_engine = AttackReconstructionEngine()
