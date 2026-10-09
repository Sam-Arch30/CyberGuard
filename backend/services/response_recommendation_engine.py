"""
Section 28: Response Recommendation Engine Service.
Transforms ThreatEvents, RiskAssessments, Explanations, Attack Paths, and Context
into structured, prioritized, actionable defensive recommendations.
Advisory only: Consequential execution belongs strictly behind human approval.
"""

import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.db.models import (
    ResponseRecommendationModel,
    ResponseCapabilityModel,
    RiskAssessmentModel,
    ExplanationModel,
    ThreatEventModel,
    IncidentModel,
    FindingModel,
    EvidenceModel,
    AuditLogModel,
    generate_uuid,
    get_utc_now
)
from backend.schemas.response_recommendation import (
    ActionCategoryEnum,
    ActionTypeEnum,
    RecommendationPriorityEnum,
    RecommendationUrgencyEnum,
    ApplicabilityEnum,
    ReversibilityEnum,
    OperationalImpactEnum,
    SafetyClassEnum,
    ExecutionModeEnum,
    RecommendationStatusEnum,
    CapabilityStateEnum,
    AffectedEntity,
    PrerequisiteItem,
    ConflictItem
)

logger = logging.getLogger(__name__)


# ============================================================================
# DEFAULT ENVIRONMENT CAPABILITIES REGISTRY
# ============================================================================

DEFAULT_CAPABILITIES = [
    {
        "action_type": ActionTypeEnum.BLOCK_DOMAIN.value,
        "provider": "Corporate DNS Sinkhole & Edge Firewall",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "DNS policy integration active."
    },
    {
        "action_type": ActionTypeEnum.BLOCK_URL.value,
        "provider": "Secure Web Gateway (SWG)",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "SWG URL filtering policy active."
    },
    {
        "action_type": ActionTypeEnum.BLOCK_IP.value,
        "provider": "Border Gateway & Perimeter Firewall",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Border ACL sync operational."
    },
    {
        "action_type": ActionTypeEnum.QUARANTINE_FILE.value,
        "provider": "Email Gateway & Host Quarantine Vault",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Quarantine storage available."
    },
    {
        "action_type": ActionTypeEnum.ISOLATE_DEVICE.value,
        "provider": "EDR Host Isolation Agent",
        "environment": "PRODUCTION",
        "enabled": False,
        "reversible": True,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.REQUIRES_CONFIGURATION.value,
        "state_reason": "No active EDR host-isolation connector registered for this workspace."
    },
    {
        "action_type": ActionTypeEnum.DISABLE_ACCOUNT.value,
        "provider": "Identity & Access Management (IAM)",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Active Directory / IdP API connected."
    },
    {
        "action_type": ActionTypeEnum.REVOKE_SESSION.value,
        "provider": "Identity Provider Session Manager",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "OAuth / SAML session revocation supported."
    },
    {
        "action_type": ActionTypeEnum.FORCE_PASSWORD_RESET.value,
        "provider": "Directory Service / Okta / Azure AD",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": False,
        "approval_required": True,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Temporary password issuance connector active."
    },
    {
        "action_type": ActionTypeEnum.REQUIRE_MFA_REAUTHENTICATION.value,
        "provider": "MFA Authenticator Gateway",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": False,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Step-up challenge API active."
    },
    {
        "action_type": ActionTypeEnum.PRESERVE_EMAIL.value,
        "provider": "CyberGuard Forensic Vault",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": False,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Immutable RFC 822 raw artifact storage online."
    },
    {
        "action_type": ActionTypeEnum.PRESERVE_ARTIFACT.value,
        "provider": "CyberGuard Forensic Object Storage",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": False,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "SHA-256 evidence vault operational."
    },
    {
        "action_type": ActionTypeEnum.PRESERVE_LOGS.value,
        "provider": "SIEM Cold Storage Archiver",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": False,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "SIEM audit freeze endpoint online."
    },
    {
        "action_type": ActionTypeEnum.NOTIFY_SECURITY_TEAM.value,
        "provider": "SOC Pager & Webhook Dispatch",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": True,
        "approval_required": False,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Webhook channels configured."
    },
    {
        "action_type": ActionTypeEnum.NOTIFY_USER.value,
        "provider": "Corporate Email Gateway",
        "environment": "PRODUCTION",
        "enabled": True,
        "reversible": False,
        "approval_required": False,
        "capability_state": CapabilityStateEnum.AVAILABLE.value,
        "state_reason": "Automated security advisory templates loaded."
    }
]


class ResponseRecommendationEngine:
    """
    Central recommendation engine for Section 28.
    Deterministic, evidence-backed, capability-aware, approval-bounded.
    """

    @classmethod
    def ensure_default_capabilities(cls, db: Session, workspace_id: str = "default") -> List[ResponseCapabilityModel]:
        """
        Seed default capabilities if not present.
        """
        existing = db.query(ResponseCapabilityModel).filter(
            ResponseCapabilityModel.workspace_id == workspace_id
        ).all()
        if existing:
            return existing

        created = []
        for cap in DEFAULT_CAPABILITIES:
            row = ResponseCapabilityModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                action_type=cap["action_type"],
                provider=cap["provider"],
                environment=cap["environment"],
                enabled=cap["enabled"],
                reversible=cap["reversible"],
                approval_required=cap["approval_required"],
                capability_state=cap["capability_state"],
                state_reason=cap["state_reason"],
                configuration_json="{}"
            )
            db.add(row)
            created.append(row)
        db.commit()
        return created

    @classmethod
    def get_capabilities(cls, db: Session, workspace_id: str = "default") -> Dict[str, ResponseCapabilityModel]:
        """
        Fetch capabilities indexed by action_type.
        """
        caps = cls.ensure_default_capabilities(db, workspace_id)
        return {c.action_type: c for c in caps}

    @classmethod
    def generate_recommendations(
        cls,
        db: Session,
        scope_type: str,
        scope_id: str,
        workspace_id: str = "default",
        force_regenerate: bool = False
    ) -> List[ResponseRecommendationModel]:
        """
        Primary entry point: Generates structured, prioritized recommendations.
        """
        # 1. Check existing recommendations
        if not force_regenerate:
            existing = db.query(ResponseRecommendationModel).filter(
                ResponseRecommendationModel.workspace_id == workspace_id,
                ResponseRecommendationModel.scope_type == scope_type,
                ResponseRecommendationModel.scope_id == scope_id,
                ResponseRecommendationModel.status.in_([
                    RecommendationStatusEnum.GENERATED.value,
                    RecommendationStatusEnum.REVIEW_REQUIRED.value,
                    RecommendationStatusEnum.APPROVED.value,
                    RecommendationStatusEnum.DEFERRED.value
                ])
            ).order_by(ResponseRecommendationModel.priority.asc(), ResponseRecommendationModel.created_at.asc()).all()
            if existing:
                return existing

        # 2. Look up authoritative risk assessment
        risk_assessment = db.query(RiskAssessmentModel).filter(
            RiskAssessmentModel.workspace_id == workspace_id,
            RiskAssessmentModel.scope_type == scope_type,
            RiskAssessmentModel.scope_id == scope_id
        ).order_by(desc(RiskAssessmentModel.version)).first()

        # 3. Look up structured explanation
        explanation = db.query(ExplanationModel).filter(
            ExplanationModel.workspace_id == workspace_id,
            ExplanationModel.scope_type == scope_type,
            ExplanationModel.scope_id == scope_id
        ).order_by(desc(ExplanationModel.explanation_version)).first()

        # 4. Look up underlying ThreatEvent or Incident
        threat_event = None
        incident = None
        if scope_type == "EVENT":
            threat_event = db.query(ThreatEventModel).filter(ThreatEventModel.id == scope_id).first()
        elif scope_type == "INCIDENT":
            incident = db.query(IncidentModel).filter(IncidentModel.id == scope_id).first()

        # 5. Extract environment capabilities
        capabilities = cls.get_capabilities(db, workspace_id)

        # 6. Extract raw entities and evidence tokens
        context_data = cls._extract_context(threat_event, incident, risk_assessment, explanation)

        # 7. Generate Candidate Recommendations
        candidates = cls._generate_candidates(context_data, capabilities, workspace_id, scope_type, scope_id)

        # 8. Deduplicate and merge candidates
        deduplicated = cls._deduplicate_candidates(candidates)

        # 9. Compute cross-dependencies and conflicts
        final_recommendations = cls._compute_dependencies_and_conflicts(deduplicated)

        # 10. Handle supersession if regenerating
        if force_regenerate:
            cls._supersede_prior_recommendations(db, workspace_id, scope_type, scope_id)

        # 11. Persist new recommendations
        persisted = []
        for rec in final_recommendations:
            db.add(rec)
            persisted.append(rec)
        db.commit()

        # 12. Record Audit Log for generation
        try:
            audit = AuditLogModel(
                id=generate_uuid(),
                action="RECOMMENDATION_CREATED",
                resource_type="response_recommendation",
                resource_id=scope_id,
                user="CyberGuard Response Engine",
                metadata_json=json.dumps({
                    "scope_type": scope_type,
                    "scope_id": scope_id,
                    "recommendations_count": len(persisted),
                    "p0_count": sum(1 for r in persisted if r.priority == "P0"),
                    "p1_count": sum(1 for r in persisted if r.priority == "P1")
                })
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            logger.warning(f"Could not write audit log for recommendations: {e}")

        return persisted

    # ========================================================================
    # CONTEXT EXTRACTION
    # ========================================================================

    @classmethod
    def _extract_context(
        cls,
        threat_event: Optional[ThreatEventModel],
        incident: Optional[IncidentModel],
        risk_assessment: Optional[RiskAssessmentModel],
        explanation: Optional[ExplanationModel]
    ) -> Dict[str, Any]:
        """
        Assembles all grounded inputs into a normalized inspection context.
        """
        ctx: Dict[str, Any] = {
            "threat_event_id": threat_event.id if threat_event else None,
            "incident_id": incident.id if incident else (threat_event.incident_id if threat_event else None),
            "risk_assessment_id": risk_assessment.id if risk_assessment else None,
            "explanation_id": explanation.id if explanation else None,
            "risk_score": risk_assessment.risk_score if risk_assessment else 50.0,
            "risk_level": risk_assessment.risk_level if risk_assessment else "MEDIUM",
            "severity": risk_assessment.severity if risk_assessment else "MEDIUM",
            "threat_confidence": risk_assessment.confidence if risk_assessment else 0.8,
            "threat_confidence_level": risk_assessment.confidence_level if risk_assessment else "HIGH",
            "accounts": [],
            "urls": [],
            "domains": [],
            "ips": [],
            "files": [],
            "devices": [],
            "sessions": [],
            "evidence_refs": [],
            "risk_refs": [],
            "mitre_refs": [],
            "attack_stages": [],
            "is_phishing": False,
            "is_ato": False,
            "is_malware": False,
            "is_network_threat": False,
            "is_api_abuse": False,
            "is_deepfake": False
        }

        # Ingest Risk Signals
        if risk_assessment:
            ctx["risk_refs"].append(risk_assessment.id)
            for sig in risk_assessment.signals:
                cat = (sig.category or "").upper()
                if "EMAIL" in cat or "PHISH" in cat:
                    ctx["is_phishing"] = True
                if "AUTH" in cat or "ATO" in cat or "IDENTITY" in cat:
                    ctx["is_ato"] = True
                if "FILE" in cat or "MALWARE" in cat:
                    ctx["is_malware"] = True
                if "NET" in cat:
                    ctx["is_network_threat"] = True
                if "API" in cat:
                    ctx["is_api_abuse"] = True
                if "MEDIA" in cat:
                    ctx["is_deepfake"] = True

                for ref in sig.evidence_refs:
                    if ref not in ctx["evidence_refs"]:
                        ctx["evidence_refs"].append(ref)

        # Ingest Explanation Units
        if explanation:
            for unit in explanation.explanation_units:
                ctype = unit.get("claim_type", "").upper()
                if "PHISH" in ctype or "URL" in ctype or "IDENTITY" in ctype:
                    ctx["is_phishing"] = True
                if "AUTH" in ctype or "BEHAVIOR" in ctype:
                    ctx["is_ato"] = True
                if "MALWARE" in ctype:
                    ctx["is_malware"] = True
                if "NETWORK" in ctype:
                    ctx["is_network_threat"] = True
                for r in unit.get("evidence_refs", []):
                    if r not in ctx["evidence_refs"]:
                        ctx["evidence_refs"].append(r)

            # Ingest MITRE
            for m in explanation.mitre_explanations:
                tid = m.get("technique_id")
                if tid and tid not in ctx["mitre_refs"]:
                    ctx["mitre_refs"].append(tid)

            # Ingest Attack Stages
            ap_data = explanation.attack_path_explanation
            if ap_data:
                ctx["attack_stages"] = ap_data.get("stage_sequence", [])

        # Ingest ThreatEvent metadata
        if threat_event:
            meta = json.loads(threat_event.metadata_json or "{}")
            # URLs
            for u in meta.get("urls", []) or meta.get("phishing_urls", []):
                u_str = u.get("url") if isinstance(u, dict) else str(u)
                if u_str and u_str not in ctx["urls"]:
                    ctx["urls"].append(u_str)
            # Domains
            for d in meta.get("lookalike_domains", []) or meta.get("domains", []):
                d_str = d.get("domain") if isinstance(d, dict) else str(d)
                if d_str and d_str not in ctx["domains"]:
                    ctx["domains"].append(d_str)
            if meta.get("sender_domain"):
                if meta["sender_domain"] not in ctx["domains"]:
                    ctx["domains"].append(meta["sender_domain"])
            # IPs
            for ip in meta.get("origin_ips", []) or meta.get("ips", []):
                ip_str = ip.get("ip") if isinstance(ip, dict) else str(ip)
                if ip_str and ip_str not in ctx["ips"]:
                    ctx["ips"].append(ip_str)
            if meta.get("sender_ip"):
                if meta["sender_ip"] not in ctx["ips"]:
                    ctx["ips"].append(meta["sender_ip"])
            # Files / Attachments
            for f in meta.get("attachments", []) or meta.get("files", []):
                f_name = f.get("filename") or f.get("name") if isinstance(f, dict) else str(f)
                f_hash = f.get("sha256") or f.get("hash") if isinstance(f, dict) else None
                ctx["files"].append({"filename": f_name, "sha256": f_hash})
            # Accounts
            for acc in [meta.get("recipient"), meta.get("target_user"), meta.get("username")]:
                if acc and acc not in ctx["accounts"]:
                    ctx["accounts"].append(acc)
            # Devices
            for dev in [meta.get("hostname"), meta.get("device_id"), meta.get("endpoint_id")]:
                if dev and dev not in ctx["devices"]:
                    ctx["devices"].append(dev)
            # Sessions
            for s in [meta.get("session_id"), meta.get("token_id")]:
                if s and s not in ctx["sessions"]:
                    ctx["sessions"].append(s)

        # Baseline flags if score is critical
        if ctx["risk_score"] >= 80:
            if not (ctx["is_phishing"] or ctx["is_ato"] or ctx["is_malware"] or ctx["is_network_threat"]):
                ctx["is_phishing"] = True  # Default to mail/phish if untagged

        return ctx

    # ========================================================================
    # CANDIDATE GENERATION
    # ========================================================================

    @classmethod
    def _generate_candidates(
        cls,
        ctx: Dict[str, Any],
        capabilities: Dict[str, ResponseCapabilityModel],
        workspace_id: str,
        scope_type: str,
        scope_id: str
    ) -> List[ResponseRecommendationModel]:
        """
        Generates raw candidate recommendations across all categories.
        """
        candidates: List[ResponseRecommendationModel] = []
        now = get_utc_now()
        is_critical = ctx["risk_score"] >= 80
        is_high = ctx["risk_score"] >= 50

        # Helper to create recommendation instances
        def build_rec(
            action_type: ActionTypeEnum,
            category: ActionCategoryEnum,
            title: str,
            description: str,
            rationale: str,
            priority: RecommendationPriorityEnum,
            urgency: RecommendationUrgencyEnum,
            expected_effect: str,
            reversibility: ReversibilityEnum,
            impact: OperationalImpactEnum,
            safety_class: SafetyClassEnum,
            approval_required: bool,
            affected_entities: List[Dict[str, Any]],
            prerequisites: List[Dict[str, Any]],
            confidence: float = 0.95,
            confidence_level: str = "VERY_HIGH",
            applicability: ApplicabilityEnum = ApplicabilityEnum.APPLICABLE,
            applicability_reason: str = "Prerequisites satisfied and targets identified in evidence.",
            ttl_hours: Optional[int] = None
        ) -> ResponseRecommendationModel:
            cap = capabilities.get(action_type.value)
            if cap:
                if applicability != ApplicabilityEnum.NOT_APPLICABLE:
                    if cap.capability_state == CapabilityStateEnum.UNAVAILABLE.value:
                        prerequisites.append({"name": "Capability Available", "description": f"Provider '{cap.provider}' is currently UNAVAILABLE.", "satisfied": False})
                    elif cap.capability_state == CapabilityStateEnum.REQUIRES_CONFIGURATION.value:
                        prerequisites.append({"name": "Capability Configured", "description": f"Provider '{cap.provider}' requires configuration before automated execution.", "satisfied": False})
                if cap.approval_required:
                    approval_required = True

            expires_at = (now + timedelta(hours=ttl_hours)) if ttl_hours else None

            rec = ResponseRecommendationModel(
                id=generate_uuid(),
                workspace_id=workspace_id,
                scope_type=scope_type,
                scope_id=scope_id,
                incident_id=ctx.get("incident_id"),
                threat_event_id=ctx.get("threat_event_id"),
                risk_assessment_id=ctx.get("risk_assessment_id"),
                explanation_id=ctx.get("explanation_id"),
                action_type=action_type.value,
                category=category.value,
                title=title,
                description=description,
                rationale=rationale,
                priority=priority.value,
                urgency=urgency.value,
                expected_effect=expected_effect,
                prerequisites_json=json.dumps(prerequisites),
                affected_entities_json=json.dumps(affected_entities),
                evidence_refs_json=json.dumps(ctx.get("evidence_refs", [])),
                risk_refs_json=json.dumps(ctx.get("risk_refs", [])),
                attack_path_refs_json=json.dumps([s.get("stage_id", "STAGE") for s in ctx.get("attack_stages", [])]),
                mitre_refs_json=json.dumps(ctx.get("mitre_refs", [])),
                confidence=confidence,
                confidence_level=confidence_level,
                applicability=applicability.value,
                applicability_reason=applicability_reason,
                reversibility=reversibility.value,
                impact=impact.value,
                approval_required=approval_required,
                safety_class=safety_class.value,
                execution_mode=ExecutionModeEnum.MANUAL.value,
                status=RecommendationStatusEnum.REVIEW_REQUIRED.value if approval_required else RecommendationStatusEnum.GENERATED.value,
                recommendation_version=1,
                created_at=now,
                updated_at=now,
                expires_at=expires_at
            )
            return rec

        # --------------------------------------------------------------------
        # 1. EVIDENCE PRESERVATION CANDIDATES
        # --------------------------------------------------------------------
        if ctx["is_phishing"] or scope_type == "EVENT":
            candidates.append(build_rec(
                action_type=ActionTypeEnum.PRESERVE_EMAIL,
                category=ActionCategoryEnum.EVIDENCE_PRESERVATION,
                title="Preserve original raw email message and cryptographic headers",
                description="Export and cryptographically seal RFC 822 email payload and transport headers into the tamper-proof forensic vault.",
                rationale="Active phishing investigations require immutable custody of DKIM, SPF, and received relay chains for legal defensibility and campaign correlation.",
                priority=RecommendationPriorityEnum.P0 if is_critical else RecommendationPriorityEnum.P1,
                urgency=RecommendationUrgencyEnum.IMMEDIATE,
                expected_effect="Freezes raw message payload in WORM storage; prevents accidental purge from mail client.",
                reversibility=ReversibilityEnum.REVERSIBLE,
                impact=OperationalImpactEnum.NONE,
                safety_class=SafetyClassEnum.INFORMATIONAL,
                approval_required=False,
                affected_entities=[{"entity_type": "EVENT", "identifier": scope_id, "role": "TARGET"}],
                prerequisites=[{"name": "Email Artifact Available", "description": "Raw message payload resides in cache or database.", "satisfied": True}]
            ))

        if ctx["files"]:
            for f in ctx["files"]:
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.PRESERVE_ARTIFACT,
                    category=ActionCategoryEnum.EVIDENCE_PRESERVATION,
                    title=f"Preserve suspicious attachment artifact '{f.get('filename')}'",
                    description=f"Store attachment binary and calculate SHA-256 hash ({f.get('sha256') or 'pending'}) in isolated malware vault.",
                    rationale="Prevents forensic loss before containment or sandboxing runs.",
                    priority=RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.IMMEDIATE,
                    expected_effect="Preserves byte-level fidelity for deep static and dynamic reverse engineering.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.NONE,
                    safety_class=SafetyClassEnum.INFORMATIONAL,
                    approval_required=False,
                    affected_entities=[{"entity_type": "FILE", "identifier": f.get("filename") or "attachment", "role": "TARGET"}],
                    prerequisites=[{"name": "Binary Available", "description": "Attachment binary captured.", "satisfied": True}]
                ))

        if ctx["is_ato"] or ctx["accounts"]:
            candidates.append(build_rec(
                action_type=ActionTypeEnum.PRESERVE_LOGS,
                category=ActionCategoryEnum.EVIDENCE_PRESERVATION,
                title="Freeze and preserve authentication audit telemetry",
                description="Preserve sign-in logs, MFA challenge records, and token issuance events across IdP and cloud directory.",
                rationale="Authentication events are subject to short retention windows and can be overwritten by subsequent logon attempts.",
                priority=RecommendationPriorityEnum.P1,
                urgency=RecommendationUrgencyEnum.URGENT,
                expected_effect="Retains complete sign-in sequence across anomalous IP addresses and user agents.",
                reversibility=ReversibilityEnum.REVERSIBLE,
                impact=OperationalImpactEnum.NONE,
                safety_class=SafetyClassEnum.INFORMATIONAL,
                approval_required=False,
                affected_entities=[{"entity_type": "ACCOUNT", "identifier": a, "role": "TARGET"} for a in ctx["accounts"]],
                prerequisites=[{"name": "IdP Access", "description": "Audit log provider active.", "satisfied": True}]
            ))

        # --------------------------------------------------------------------
        # 2. IMMEDIATE INVESTIGATION CANDIDATES
        # --------------------------------------------------------------------
        candidates.append(build_rec(
            action_type=ActionTypeEnum.REVIEW_EVIDENCE,
            category=ActionCategoryEnum.INVESTIGATION,
            title="Perform detailed analyst review of grounded evidence chain",
            description="Inspect the multi-stage evidence graph linking observed telemetry to detection findings and risk contributors.",
            rationale="Confirms signal fidelity and verifies absence of contradictory legitimate business justifications.",
            priority=RecommendationPriorityEnum.P1 if is_high else RecommendationPriorityEnum.P2,
            urgency=RecommendationUrgencyEnum.URGENT if is_high else RecommendationUrgencyEnum.NORMAL,
            expected_effect="Establishes analyst concurrence with automated CyberGuard findings.",
            reversibility=ReversibilityEnum.REVERSIBLE,
            impact=OperationalImpactEnum.NONE,
            safety_class=SafetyClassEnum.INFORMATIONAL,
            approval_required=False,
            affected_entities=[],
            prerequisites=[]
        ))

        if ctx["urls"]:
            for u in ctx["urls"]:
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.INSPECT_URL,
                    category=ActionCategoryEnum.INVESTIGATION,
                    title=f"Inspect destination structure and redirection for '{u[:40]}...'",
                    description="Analyze URL path, parameter obfuscation, login form tokens, and redirection hops.",
                    rationale="Detects credential harvesting forms and evasive open-redirect sequences without notifying adversary.",
                    priority=RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.URGENT,
                    expected_effect="Identifies final landing page and credential collection mechanisms.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.NONE,
                    safety_class=SafetyClassEnum.INFORMATIONAL,
                    approval_required=False,
                    affected_entities=[{"entity_type": "URL", "identifier": u, "role": "TARGET"}],
                    prerequisites=[{"name": "Normalized URL", "description": "URL structure parsed.", "satisfied": True}]
                ))

        if ctx["is_ato"]:
            candidates.append(build_rec(
                action_type=ActionTypeEnum.REVIEW_AUTHENTICATION,
                category=ActionCategoryEnum.INVESTIGATION,
                title="Audit recent authentication events and MFA registrations",
                description="Examine geographic velocity, ASN deviations, and recently registered authentication methods for the affected user.",
                rationale="Attacker may have registered backup FIDO2 or SMS MFA keys to maintain persistence.",
                priority=RecommendationPriorityEnum.P1,
                urgency=RecommendationUrgencyEnum.IMMEDIATE,
                expected_effect="Detects unauthorized MFA device registration or active session hijacking.",
                reversibility=ReversibilityEnum.REVERSIBLE,
                impact=OperationalImpactEnum.LOW,
                safety_class=SafetyClassEnum.INFORMATIONAL,
                approval_required=False,
                affected_entities=[{"entity_type": "ACCOUNT", "identifier": a, "role": "TARGET"} for a in ctx["accounts"]],
                prerequisites=[]
            ))

        # --------------------------------------------------------------------
        # 3. IDENTITY & CREDENTIAL PROTECTION CANDIDATES
        # --------------------------------------------------------------------
        if ctx["is_ato"] or (ctx["is_phishing"] and is_critical):
            for acc in ctx["accounts"]:
                # Revoke Session (P0/P1)
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.REVOKE_SESSION,
                    category=ActionCategoryEnum.IDENTITY_SECURITY,
                    title=f"Revoke all active sessions and refresh tokens for account '{acc}'",
                    description=f"Invalidate active OAuth tokens, browser cookies, and SSO sessions for {acc}.",
                    rationale="Prevents adversary from using stolen session tokens or persistence cookies while credentials are reset.",
                    priority=RecommendationPriorityEnum.P0 if is_critical else RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.IMMEDIATE,
                    expected_effect="Forces immediate termination of all active web and mobile client sessions.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.MEDIUM,
                    safety_class=SafetyClassEnum.REVERSIBLE,
                    approval_required=True,
                    affected_entities=[{"entity_type": "ACCOUNT", "identifier": acc, "role": "TARGET"}],
                    prerequisites=[{"name": "Account Identified", "description": "Target account validated.", "satisfied": True}],
                    ttl_hours=24
                ))

                # Force Password Reset
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.FORCE_PASSWORD_RESET,
                    category=ActionCategoryEnum.IDENTITY_SECURITY,
                    title=f"Require immediate password reset for targeted account '{acc}'",
                    description=f"Flag password as expired in IdP and require password change on next interactive sign-in for {acc}.",
                    rationale="Invalidates potentially compromised plaintext passwords or cached credentials.",
                    priority=RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.URGENT,
                    expected_effect="Blocks login attempts with current password; forces user to establish new credentials.",
                    reversibility=ReversibilityEnum.PARTIALLY_REVERSIBLE,
                    impact=OperationalImpactEnum.MEDIUM,
                    safety_class=SafetyClassEnum.HIGH_IMPACT,
                    approval_required=True,
                    affected_entities=[{"entity_type": "ACCOUNT", "identifier": acc, "role": "TARGET"}],
                    prerequisites=[{"name": "IAM Authority", "description": "Authorization permits password expiry.", "satisfied": True}]
                ))

                # Require MFA Re-authentication
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.REQUIRE_MFA_REAUTHENTICATION,
                    category=ActionCategoryEnum.IDENTITY_SECURITY,
                    title=f"Require MFA re-authentication for account '{acc}'",
                    description=f"Issue step-up MFA challenge requiring biometric or hardware security key authentication.",
                    rationale="Validates physical possession of authorized authenticator before allowing continued access.",
                    priority=RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.URGENT,
                    expected_effect="Prompts user for fresh MFA proof; denies access if adversary lacks hardware token.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.LOW,
                    safety_class=SafetyClassEnum.LOW_IMPACT,
                    approval_required=False,
                    affected_entities=[{"entity_type": "ACCOUNT", "identifier": acc, "role": "TARGET"}],
                    prerequisites=[]
                ))

        # --------------------------------------------------------------------
        # 4. CONTAINMENT CANDIDATES (Consequential: Approval Required)
        # --------------------------------------------------------------------
        if ctx["domains"]:
            for d in ctx["domains"]:
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.BLOCK_DOMAIN,
                    category=ActionCategoryEnum.CONTAINMENT,
                    title=f"Consider blocking suspicious lookalike domain '{d}' across organization",
                    description=f"Add domain '{d}' to DNS sinkhole and Secure Email Gateway quarantine policies.",
                    rationale="Domain exhibits lookalike impersonation or credential-harvesting indicators.",
                    priority=RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.URGENT,
                    expected_effect="Prevents internal resolution and drops inbound/outbound communication to the domain.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.MEDIUM,
                    safety_class=SafetyClassEnum.CONTAINMENT,
                    approval_required=True,
                    affected_entities=[{"entity_type": "DOMAIN", "identifier": d, "role": "TARGET"}],
                    prerequisites=[{"name": "Domain Normalized", "description": "FQDN validated.", "satisfied": True}]
                ))

        if ctx["urls"]:
            for u in ctx["urls"]:
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.BLOCK_URL,
                    category=ActionCategoryEnum.CONTAINMENT,
                    title=f"Consider blocking confirmed malicious URL in Web Proxy",
                    description=f"Add URL destination to corporate web gateway blocklist: {u[:60]}...",
                    rationale="Destructive link containing credential theft form or exploit payload.",
                    priority=RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.URGENT,
                    expected_effect="Renders URL unreachable for all corporate workstations and VPN clients.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.LOW,
                    safety_class=SafetyClassEnum.CONTAINMENT,
                    approval_required=True,
                    affected_entities=[{"entity_type": "URL", "identifier": u, "role": "TARGET"}],
                    prerequisites=[{"name": "URL Normalized", "description": "URL path verified.", "satisfied": True}]
                ))

        if ctx["files"]:
            for f in ctx["files"]:
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.QUARANTINE_FILE,
                    category=ActionCategoryEnum.CONTAINMENT,
                    title=f"Quarantine attachment artifact '{f.get('filename')}' across mailboxes",
                    description=f"Remove or quarantine attachment across all recipient inboxes matching SHA-256.",
                    rationale="Prevents other employees from opening the payload while analysis is finalized.",
                    priority=RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.IMMEDIATE,
                    expected_effect="Moves message/attachment to quarantine folder; prevents user access.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.LOW,
                    safety_class=SafetyClassEnum.CONTAINMENT,
                    approval_required=True,
                    affected_entities=[{"entity_type": "FILE", "identifier": f.get("filename") or "attachment", "role": "TARGET"}],
                    prerequisites=[{"name": "Mail Server Admin", "description": "Quarantine API permission granted.", "satisfied": True}]
                ))

        # Device Isolation (With explicit applicability check!)
        if ctx["devices"]:
            for dev in ctx["devices"]:
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.ISOLATE_DEVICE,
                    category=ActionCategoryEnum.CONTAINMENT,
                    title=f"Consider network isolation for affected host '{dev}'",
                    description=f"Sever network connectivity for device '{dev}', permitting telemetry exclusively to security console.",
                    rationale="Evidence indicates potential payload execution or lateral movement originating from host.",
                    priority=RecommendationPriorityEnum.P0 if is_critical else RecommendationPriorityEnum.P1,
                    urgency=RecommendationUrgencyEnum.IMMEDIATE,
                    expected_effect="Device cannot communicate with corporate LAN or external Internet.",
                    reversibility=ReversibilityEnum.REVERSIBLE,
                    impact=OperationalImpactEnum.HIGH,
                    safety_class=SafetyClassEnum.CONTAINMENT,
                    approval_required=True,
                    affected_entities=[{"entity_type": "DEVICE", "identifier": dev, "role": "TARGET"}],
                    prerequisites=[{"name": "EDR Agent Online", "description": "Host must report active heartbeat to EDR.", "satisfied": True}],
                    confidence=0.85,
                    confidence_level="HIGH"
                ))
        else:
            # Device isolation proposed but NOT APPLICABLE because no endpoint is identified!
            candidates.append(build_rec(
                action_type=ActionTypeEnum.ISOLATE_DEVICE,
                category=ActionCategoryEnum.CONTAINMENT,
                title="Consider host isolation for affected endpoint (Not Applicable: No Host Identified)",
                description="Network isolation cannot be targeted because no endpoint device is associated with this email/event.",
                rationale="Host isolation requires a known hostname or endpoint GUID.",
                priority=RecommendationPriorityEnum.P3,
                urgency=RecommendationUrgencyEnum.DEFERRED,
                expected_effect="None (Action suppressed due to missing endpoint identity).",
                reversibility=ReversibilityEnum.REVERSIBLE,
                impact=OperationalImpactEnum.NONE,
                safety_class=SafetyClassEnum.CONTAINMENT,
                approval_required=True,
                affected_entities=[],
                prerequisites=[{"name": "Endpoint Identity Identified", "description": "Host telemetry associated.", "satisfied": False}],
                applicability=ApplicabilityEnum.NOT_APPLICABLE,
                applicability_reason="No endpoint identity or hostname is associated with this investigation."
            ))

        # --------------------------------------------------------------------
        # 5. COMMUNICATION CANDIDATES
        # --------------------------------------------------------------------
        candidates.append(build_rec(
            action_type=ActionTypeEnum.NOTIFY_SECURITY_TEAM,
            category=ActionCategoryEnum.COMMUNICATION,
            title="Dispatch security incident alert to on-duty SOC response team",
            description="Send prioritized briefing to SOC channel with evidence graph summary and authoritative risk score.",
            rationale="Alerts analysts to review consequential recommendations and coordinate cross-functional containment.",
            priority=RecommendationPriorityEnum.P1 if is_high else RecommendationPriorityEnum.P2,
            urgency=RecommendationUrgencyEnum.IMMEDIATE if is_high else RecommendationUrgencyEnum.NORMAL,
            expected_effect="Notifies incident response team via established escalation webhooks.",
            reversibility=ReversibilityEnum.REVERSIBLE,
            impact=OperationalImpactEnum.LOW,
            safety_class=SafetyClassEnum.LOW_IMPACT,
            approval_required=False,
            affected_entities=[],
            prerequisites=[]
        ))

        if ctx["accounts"] and is_high:
            for acc in ctx["accounts"]:
                candidates.append(build_rec(
                    action_type=ActionTypeEnum.NOTIFY_USER,
                    category=ActionCategoryEnum.COMMUNICATION,
                    title=f"Notify targeted user '{acc}' regarding suspicious activity",
                    description=f"Send automated security warning to {acc} advising them not to interact with message links or provide credentials.",
                    rationale="Direct user notification reduces risk of secondary compromise while investigation proceeds.",
                    priority=RecommendationPriorityEnum.P2,
                    urgency=RecommendationUrgencyEnum.URGENT,
                    expected_effect="User is alerted to report any suspicious prompts or unexpected MFA requests.",
                    reversibility=ReversibilityEnum.PARTIALLY_REVERSIBLE,
                    impact=OperationalImpactEnum.LOW,
                    safety_class=SafetyClassEnum.LOW_IMPACT,
                    approval_required=False,
                    affected_entities=[{"entity_type": "ACCOUNT", "identifier": acc, "role": "TARGET"}],
                    prerequisites=[]
                ))

        # --------------------------------------------------------------------
        # 6. RECOVERY & FOLLOW-UP CANDIDATES
        # --------------------------------------------------------------------
        candidates.append(build_rec(
            action_type=ActionTypeEnum.CORRELATE_RELATED_EVENTS,
            category=ActionCategoryEnum.FOLLOW_UP,
            title="Search for related recipients and campaign indicators across enterprise",
            description="Query mail logs and endpoint telemetry for matching subject patterns, domain lookalikes, or infrastructure IPs.",
            rationale="Adversaries rarely target a single employee; correlation identifies lateral scope.",
            priority=RecommendationPriorityEnum.P2,
            urgency=RecommendationUrgencyEnum.NORMAL,
            expected_effect="Identifies all other users who received matching campaign lures.",
            reversibility=ReversibilityEnum.REVERSIBLE,
            impact=OperationalImpactEnum.NONE,
            safety_class=SafetyClassEnum.INFORMATIONAL,
            approval_required=False,
            affected_entities=[],
            prerequisites=[]
        ))

        return candidates

    # ========================================================================
    # DEDUPLICATION & MERGING
    # ========================================================================

    @classmethod
    def _deduplicate_candidates(
        cls,
        candidates: List[ResponseRecommendationModel]
    ) -> List[ResponseRecommendationModel]:
        """
        Deduplicates candidate recommendations sharing the same action_type and target entities.
        Aggregates evidence references.
        """
        seen: Dict[str, ResponseRecommendationModel] = {}
        for c in candidates:
            # Key based on action_type and affected entities
            entities_key = "-".join(sorted([e.get("identifier", "") for e in c.affected_entities]))
            key = f"{c.action_type}:{entities_key}"
            if key not in seen:
                seen[key] = c
            else:
                existing = seen[key]
                # Merge evidence refs
                merged_refs = list(set(existing.evidence_refs + c.evidence_refs))
                existing.evidence_refs_json = json.dumps(merged_refs)
                # Keep highest priority
                p_ranks = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
                if p_ranks.get(c.priority, 4) < p_ranks.get(existing.priority, 4):
                    existing.priority = c.priority
                    existing.urgency = c.urgency
        return list(seen.values())

    # ========================================================================
    # DEPENDENCY & CONFLICT ANALYSIS
    # ========================================================================

    @classmethod
    def _compute_dependencies_and_conflicts(
        cls,
        recommendations: List[ResponseRecommendationModel]
    ) -> List[ResponseRecommendationModel]:
        """
        Calculates execution dependencies and flags conflicting response actions.
        """
        by_action: Dict[str, ResponseRecommendationModel] = {r.action_type: r for r in recommendations}

        for r in recommendations:
            deps: List[str] = []
            conflicts: List[Dict[str, Any]] = []

            # Dependency Rule 1: Evidence preservation must precede destructive containment
            if r.action_type in [ActionTypeEnum.QUARANTINE_FILE.value, ActionTypeEnum.REMOVE_MALICIOUS_ARTIFACT.value]:
                if ActionTypeEnum.PRESERVE_ARTIFACT.value in by_action:
                    deps.append(by_action[ActionTypeEnum.PRESERVE_ARTIFACT.value].id)

            if r.action_type in [ActionTypeEnum.BLOCK_DOMAIN.value, ActionTypeEnum.BLOCK_URL.value]:
                if ActionTypeEnum.PRESERVE_EMAIL.value in by_action:
                    deps.append(by_action[ActionTypeEnum.PRESERVE_EMAIL.value].id)

            if r.action_type == ActionTypeEnum.ISOLATE_DEVICE.value:
                if ActionTypeEnum.REVIEW_ENDPOINT_TELEMETRY.value in by_action:
                    deps.append(by_action[ActionTypeEnum.REVIEW_ENDPOINT_TELEMETRY.value].id)

            if r.action_type == ActionTypeEnum.FORCE_PASSWORD_RESET.value:
                if ActionTypeEnum.REVOKE_SESSION.value in by_action:
                    deps.append(by_action[ActionTypeEnum.REVOKE_SESSION.value].id)

            # Conflict Rule: Disabling account conflicts with active monitoring / decoy observation
            if r.action_type == ActionTypeEnum.DISABLE_ACCOUNT.value:
                if ActionTypeEnum.REVIEW_AUTHENTICATION.value in by_action:
                    conflicts.append({
                        "conflicting_recommendation_id": by_action[ActionTypeEnum.REVIEW_AUTHENTICATION.value].id,
                        "conflicting_action_type": ActionTypeEnum.REVIEW_AUTHENTICATION.value,
                        "tradeoff_explanation": "Disabling the account immediately halts attacker progression, but terminates live behavioral observation of attacker TTPs."
                    })

            r.depends_on_json = json.dumps(deps)
            r.conflicts_with_json = json.dumps(conflicts)

        # Sort recommendations: P0 -> P1 -> P2 -> P3 -> P4, then by urgency
        p_ranks = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
        u_ranks = {"IMMEDIATE": 0, "URGENT": 1, "SOON": 2, "NORMAL": 3, "DEFERRED": 4}
        recommendations.sort(key=lambda x: (p_ranks.get(x.priority, 5), u_ranks.get(x.urgency, 5)))
        return recommendations

    # ========================================================================
    # SUPERSESSION & LIFECYCLE
    # ========================================================================

    @classmethod
    def _supersede_prior_recommendations(
        cls,
        db: Session,
        workspace_id: str,
        scope_type: str,
        scope_id: str
    ):
        """
        Marks active recommendations from prior generation as SUPERSEDED.
        """
        prior = db.query(ResponseRecommendationModel).filter(
            ResponseRecommendationModel.workspace_id == workspace_id,
            ResponseRecommendationModel.scope_type == scope_type,
            ResponseRecommendationModel.scope_id == scope_id,
            ResponseRecommendationModel.status.in_([
                RecommendationStatusEnum.GENERATED.value,
                RecommendationStatusEnum.REVIEW_REQUIRED.value
            ])
        ).all()
        for p in prior:
            p.status = RecommendationStatusEnum.SUPERSEDED.value
            p.status_reason = "Superseded by newly generated recommendation set."
            p.updated_at = get_utc_now()
        db.commit()

    @classmethod
    def review_recommendation(
        cls,
        db: Session,
        recommendation_id: str,
        reviewer_id: str,
        disposition: str,
        notes: str
    ) -> Optional[ResponseRecommendationModel]:
        """
        Processes human review of an advisory recommendation (APPROVED, REJECTED, DEFERRED).
        Strict safety: Does NOT execute the action. It marks the recommendation approved for future playbooks.
        """
        rec = db.query(ResponseRecommendationModel).filter(
            ResponseRecommendationModel.id == recommendation_id
        ).first()
        if not rec:
            return None

        disposition_upper = disposition.strip().upper()
        if disposition_upper not in [
            RecommendationStatusEnum.APPROVED.value,
            RecommendationStatusEnum.REJECTED.value,
            RecommendationStatusEnum.DEFERRED.value
        ]:
            raise ValueError(f"Invalid review disposition '{disposition}'")

        previous_status = rec.status
        rec.status = disposition_upper
        rec.reviewed_by = reviewer_id
        rec.reviewed_at = get_utc_now()
        rec.status_reason = notes.strip()
        rec.updated_at = get_utc_now()
        db.commit()
        db.refresh(rec)

        # Log immutable audit event
        try:
            audit = AuditLogModel(
                id=generate_uuid(),
                action=f"RECOMMENDATION_{disposition_upper}",
                resource_type="response_recommendation",
                resource_id=rec.id,
                user=reviewer_id,
                metadata_json=json.dumps({
                    "action_type": rec.action_type,
                    "previous_status": previous_status,
                    "new_status": disposition_upper,
                    "notes": notes,
                    "scope_type": rec.scope_type,
                    "scope_id": rec.scope_id
                })
            )
            db.add(audit)
            db.commit()
        except Exception as e:
            logger.warning(f"Failed to record audit log for recommendation review: {e}")

        return rec
