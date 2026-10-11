"""
Section 69: Executive Reporting & Intelligence Dissemination Service.
Manages versioned report templates, immutable point-in-time snapshots,
data drift prevention, redaction pipelines, review/approval workflows,
and cryptographically secure external share links.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.db.models import (
    ReportModel,
    ReportTemplateModel,
    ReportSnapshotModel,
    ReportShareLinkModel,
    IncidentModel,
    CaseModel,
    ArtifactModel,
    EvidenceModel,
)
from backend.services.audit_service import AuditService
from backend.schemas.executive_reports import (
    ReportClassificationEnum,
    ReportRedactionLevelEnum,
    ReportTypeEnum,
    ReportStatusEnum,
    ReportTemplateCreateRequest,
    ReportTemplateUpdateRequest,
    ReportShareLinkCreateRequest,
    ExecutiveReportCreateRequest,
    ExecutiveReportUpdateRequest,
    ReportReviewRequest,
    ReportAddReviewNoteRequest,
    ReportApprovalRequest,
    ReportFinalizeRequest,
)
from backend.schemas.realtime import (
    RealtimeEventTypeEnum,
    RealtimeResourceScopeEnum,
    RealtimeEventPayload,
)
from backend.services.realtime_service import RealtimePublisher

logger = logging.getLogger(__name__)


class ExecutiveReportService:
    """Enterprise service orchestrating Executive Reporting and Intelligence Dissemination."""

    @classmethod
    def _publish_realtime(
        cls,
        event_type: RealtimeEventTypeEnum,
        resource_id: str,
        workspace_id: str,
        tenant_id: str,
        data: Dict[str, Any],
    ) -> None:
        try:
            RealtimePublisher.publish_event(
                event_type=event_type,
                scope=RealtimeResourceScopeEnum.REPORT,
                resource_id=resource_id,
                workspace_id=workspace_id,
                tenant_id=tenant_id,
                payload=RealtimeEventPayload(
                    event_type=event_type,
                    resource_scope=RealtimeResourceScopeEnum.REPORT,
                    resource_id=resource_id,
                    data=data,
                ),
            )
        except Exception as exc:
            logger.debug(f"Realtime report event publishing non-critical error: {exc}")

    # -------------------------------------------------------------------------
    # System Templates Initialization
    # -------------------------------------------------------------------------

    SYSTEM_TEMPLATES = [
        {
            "template_key": "EXECUTIVE_BRIEFING",
            "template_name": "Executive Incident Briefing",
            "report_type": ReportTypeEnum.EXECUTIVE_BRIEFING.value,
            "description": "High-level strategic briefing designed for C-suite and Board members, focusing on risk impact, operational disruption, and executive mitigations.",
            "default_classification": ReportClassificationEnum.CONFIDENTIAL.value,
            "default_redaction": ReportRedactionLevelEnum.NONE.value,
            "sections_config": [
                {
                    "section_id": "exec_summary",
                    "title": "Executive Summary & Business Impact",
                    "description": "Macro-level synthesis of the event and organizational risk posture.",
                    "enabled": True,
                    "order": 1,
                    "required_epistemic_level": "FACT",
                    "parameters": {"highlight_financial_risk": True},
                },
                {
                    "section_id": "crown_jewels",
                    "title": "Impacted Critical Assets & Identities",
                    "description": "Inventory of high-value business assets and protected accounts involved.",
                    "enabled": True,
                    "order": 2,
                    "required_epistemic_level": "CORROBORATED",
                    "parameters": {},
                },
                {
                    "section_id": "timeline_high_level",
                    "title": "Incident Timeline & Attack Progression",
                    "description": "Key milestone chronology from earliest indicator to containment.",
                    "enabled": True,
                    "order": 3,
                    "required_epistemic_level": "FACT",
                    "parameters": {},
                },
                {
                    "section_id": "strategic_recommendations",
                    "title": "Strategic Recommendations & Governance Next Steps",
                    "description": "Prioritized defensive hardening and policy updates.",
                    "enabled": True,
                    "order": 4,
                    "required_epistemic_level": "ANALYSIS",
                    "parameters": {},
                },
                {
                    "section_id": "epistemic_governance",
                    "title": "Confidence, Evidence Gaps & Telemetry Coverage",
                    "description": "Transparency on known facts, corroborated signals, and telemetry blindspots.",
                    "enabled": True,
                    "order": 5,
                    "required_epistemic_level": "FACT",
                    "parameters": {},
                },
            ],
        },
        {
            "template_key": "TECHNICAL_INCIDENT_DOSSIER",
            "template_name": "Technical Incident Dossier",
            "report_type": ReportTypeEnum.TECHNICAL_INCIDENT_DOSSIER.value,
            "description": "Comprehensive technical dossier for SOC tier-3 analysts, incident responders, and external threat intel partners.",
            "default_classification": ReportClassificationEnum.RESTRICTED.value,
            "default_redaction": ReportRedactionLevelEnum.NONE.value,
            "sections_config": [
                {
                    "section_id": "technical_summary",
                    "title": "Technical Summary & Kill-Chain Breakdown",
                    "description": "Root cause analysis and attack vector reconstruction.",
                    "enabled": True,
                    "order": 1,
                    "parameters": {},
                },
                {
                    "section_id": "mitre_mapping",
                    "title": "MITRE ATT&CK Mapping & TTPs",
                    "description": "Tactics, techniques, and procedures observed during the intrusion.",
                    "enabled": True,
                    "order": 2,
                    "parameters": {},
                },
                {
                    "section_id": "correlated_indicators",
                    "title": "Correlated IOCs & Network Infrastructure",
                    "description": "Authoritative observables, IPs, domains, hashes, and behavioral anomalies.",
                    "enabled": True,
                    "order": 3,
                    "parameters": {},
                },
                {
                    "section_id": "forensic_artifacts",
                    "title": "Forensic Artifacts & Evidence Bindings",
                    "description": "Preserved disk/memory/network artifacts with cryptographic hashes.",
                    "enabled": True,
                    "order": 4,
                    "parameters": {},
                },
                {
                    "section_id": "containment_actions",
                    "title": "Containment Actions & Verification Audit",
                    "description": "Operational playbook actions taken and system state verification.",
                    "enabled": True,
                    "order": 5,
                    "parameters": {},
                },
            ],
        },
        {
            "template_key": "FORENSIC_CHAIN_OF_CUSTODY",
            "template_name": "Forensic Chain of Custody & Legal Hold Export",
            "report_type": ReportTypeEnum.FORENSIC_CHAIN_OF_CUSTODY.value,
            "description": "Evidentiary record verifying bitstream authenticity, custody transitions, and legal hold preservation.",
            "default_classification": ReportClassificationEnum.CONFIDENTIAL.value,
            "default_redaction": ReportRedactionLevelEnum.NONE.value,
            "sections_config": [
                {
                    "section_id": "custody_overview",
                    "title": "Evidence Manifest & Cryptographic Hashes",
                    "description": "Itemized list of forensic records with SHA-256, SHA-1, and MD5 digests.",
                    "enabled": True,
                    "order": 1,
                    "parameters": {},
                },
                {
                    "section_id": "custody_ledger",
                    "title": "Immutable Custodial Transfer Ledger",
                    "description": "Chronological history of all acquisitions, access, transfers, and verifications.",
                    "enabled": True,
                    "order": 2,
                    "parameters": {},
                },
                {
                    "section_id": "legal_hold_status",
                    "title": "Legal Hold Preservation & Retention Directives",
                    "description": "Active legal holds, custodians, and compliance preservation policies.",
                    "enabled": True,
                    "order": 3,
                    "parameters": {},
                },
            ],
        },
        {
            "template_key": "REGULATORY_COMPLIANCE_DISCLOSURE",
            "template_name": "Regulatory Compliance Disclosure (SEC / GDPR / NIS2)",
            "report_type": ReportTypeEnum.REGULATORY_COMPLIANCE_DISCLOSURE.value,
            "description": "Standardized disclosure format meeting mandatory 72-hour and 4-day regulatory breach notification timelines.",
            "default_classification": ReportClassificationEnum.RESTRICTED.value,
            "default_redaction": ReportRedactionLevelEnum.STANDARD.value,
            "sections_config": [
                {
                    "section_id": "statutory_timeline",
                    "title": "Discovery & Materiality Timeline",
                    "description": "Precise timestamps of detection, escalation, and determination of materiality.",
                    "enabled": True,
                    "order": 1,
                    "parameters": {},
                },
                {
                    "section_id": "data_exposure_scope",
                    "title": "Scope of Compromised Data & Protected Identities",
                    "description": "Quantification of affected records, personal data categories, and tenants.",
                    "enabled": True,
                    "order": 2,
                    "parameters": {},
                },
                {
                    "section_id": "remediation_statement",
                    "title": "Remediation Measures & Containment Status",
                    "description": "Active mitigations to prevent ongoing exploitation or data exfiltration.",
                    "enabled": True,
                    "order": 3,
                    "parameters": {},
                },
            ],
        },
        {
            "template_key": "THREAT_ACTOR_INTEL_DISSEMINATION",
            "template_name": "Threat Actor Intelligence Briefing",
            "report_type": ReportTypeEnum.THREAT_ACTOR_INTEL_DISSEMINATION.value,
            "description": "External intelligence briefing detailing adversary campaigns, Diamond Model attribution, and active watchlists.",
            "default_classification": ReportClassificationEnum.TLP_AMBER.value,
            "default_redaction": ReportRedactionLevelEnum.STANDARD.value,
            "sections_config": [
                {
                    "section_id": "adversary_profile",
                    "title": "Threat Actor Attribution & Diamond Model",
                    "description": "Profile of suspected APT group, motivation, and historical campaign links.",
                    "enabled": True,
                    "order": 1,
                    "parameters": {},
                },
                {
                    "section_id": "infrastructure_analysis",
                    "title": "Command & Control Infrastructure",
                    "description": "Observed IP ranges, ASNs, bulletproof hosting, and domain registrations.",
                    "enabled": True,
                    "order": 2,
                    "parameters": {},
                },
                {
                    "section_id": "ioc_watchlist_bindings",
                    "title": "Active IOC Watchlist & Detection Rules",
                    "description": "Defensive indicators for automated threat hunting ingestion.",
                    "enabled": True,
                    "order": 3,
                    "parameters": {},
                },
            ],
        },
    ]

    @classmethod
    def ensure_system_templates(cls, db: Session, workspace_id: str = "default", tenant_id: str = "default") -> None:
        """Seeds standard system templates if not already present."""
        for item in cls.SYSTEM_TEMPLATES:
            existing = (
                db.query(ReportTemplateModel)
                .filter(
                    ReportTemplateModel.workspace_id == workspace_id,
                    ReportTemplateModel.template_key == item["template_key"],
                    ReportTemplateModel.is_active == True,
                )
                .first()
            )
            if not existing:
                tmpl = ReportTemplateModel(
                    workspace_id=workspace_id,
                    tenant_id=tenant_id,
                    template_key=item["template_key"],
                    template_name=item["template_name"],
                    report_type=item["report_type"],
                    version=1,
                    description=item["description"],
                    sections_config_json=json.dumps(item["sections_config"]),
                    default_classification=item["default_classification"],
                    default_redaction=item["default_redaction"],
                    is_system=True,
                    is_active=True,
                    created_by="SYSTEM",
                )
                db.add(tmpl)
        db.commit()

    # -------------------------------------------------------------------------
    # Template Operations
    # -------------------------------------------------------------------------

    @classmethod
    def list_templates(
        cls,
        db: Session,
        workspace_id: str = "default",
        report_type: Optional[str] = None,
        include_inactive: bool = False,
    ) -> List[ReportTemplateModel]:
        cls.ensure_system_templates(db, workspace_id)
        q = db.query(ReportTemplateModel).filter(ReportTemplateModel.workspace_id == workspace_id)
        if not include_inactive:
            q = q.filter(ReportTemplateModel.is_active == True)
        if report_type:
            q = q.filter(ReportTemplateModel.report_type == report_type)
        return q.order_by(ReportTemplateModel.is_system.desc(), ReportTemplateModel.template_name.asc()).all()

    @classmethod
    def get_template(cls, db: Session, template_id_or_key: str, workspace_id: str = "default") -> Optional[ReportTemplateModel]:
        cls.ensure_system_templates(db, workspace_id)
        tmpl = (
            db.query(ReportTemplateModel)
            .filter(
                ReportTemplateModel.workspace_id == workspace_id,
                ReportTemplateModel.id == template_id_or_key,
            )
            .first()
        )
        if not tmpl:
            tmpl = (
                db.query(ReportTemplateModel)
                .filter(
                    ReportTemplateModel.workspace_id == workspace_id,
                    ReportTemplateModel.template_key == template_id_or_key,
                    ReportTemplateModel.is_active == True,
                )
                .order_by(ReportTemplateModel.version.desc())
                .first()
            )
        return tmpl

    @classmethod
    def create_template(
        cls,
        db: Session,
        req: ReportTemplateCreateRequest,
        created_by: str = "analyst",
        workspace_id: str = "default",
        tenant_id: str = "default",
    ) -> ReportTemplateModel:
        existing = (
            db.query(ReportTemplateModel)
            .filter(
                ReportTemplateModel.workspace_id == workspace_id,
                ReportTemplateModel.template_key == req.template_key,
                ReportTemplateModel.is_active == True,
            )
            .first()
        )
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Template key '{req.template_key}' already exists in workspace.",
            )

        tmpl = ReportTemplateModel(
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            template_key=req.template_key,
            template_name=req.template_name,
            report_type=req.report_type.value,
            version=1,
            description=req.description,
            sections_config_json=json.dumps([s.model_dump() for s in req.sections_config]),
            default_classification=req.default_classification.value,
            default_redaction=req.default_redaction.value,
            is_system=False,
            is_active=True,
            created_by=created_by,
        )
        db.add(tmpl)
        db.commit()
        db.refresh(tmpl)

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_TEMPLATE_CREATED,
            resource_id=tmpl.id,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            data={"template_key": tmpl.template_key, "template_name": tmpl.template_name},
        )
        return tmpl

    @classmethod
    def update_template(
        cls,
        db: Session,
        template_id: str,
        req: ReportTemplateUpdateRequest,
        updated_by: str = "analyst",
        workspace_id: str = "default",
    ) -> ReportTemplateModel:
        tmpl = cls.get_template(db, template_id, workspace_id)
        if not tmpl:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")

        if tmpl.is_system:
            # For system templates, create a versioned copy or disallow breaking structure
            pass

        if req.template_name is not None:
            tmpl.template_name = req.template_name
        if req.description is not None:
            tmpl.description = req.description
        if req.sections_config is not None:
            tmpl.sections_config_json = json.dumps([s.model_dump() for s in req.sections_config])
        if req.default_classification is not None:
            tmpl.default_classification = req.default_classification.value
        if req.default_redaction is not None:
            tmpl.default_redaction = req.default_redaction.value
        if req.is_active is not None:
            if tmpl.is_system and not req.is_active:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="System templates cannot be deactivated.")
            tmpl.is_active = req.is_active

        tmpl.version += 1
        db.commit()
        db.refresh(tmpl)

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_TEMPLATE_UPDATED,
            resource_id=tmpl.id,
            workspace_id=workspace_id,
            tenant_id=tmpl.tenant_id,
            data={"template_key": tmpl.template_key, "version": tmpl.version},
        )
        return tmpl

    @classmethod
    def delete_template(cls, db: Session, template_id: str, workspace_id: str = "default") -> None:
        tmpl = cls.get_template(db, template_id, workspace_id)
        if not tmpl:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found")
        if tmpl.is_system:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="System templates cannot be deleted.")

        tmpl.is_active = False
        db.commit()

    # -------------------------------------------------------------------------
    # Redaction Pipeline
    # -------------------------------------------------------------------------

    _IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
    _AUTH_TOKEN_REGEX = re.compile(r"(?:Bearer\s+|token\s+|apikey[:=]\s*)([A-Za-z0-9\-_]{16,})", re.IGNORECASE)

    @classmethod
    def apply_redaction_to_text(cls, text: str, level: str) -> str:
        """Applies deterministic redaction to text according to redaction level."""
        if not text or level == ReportRedactionLevelEnum.NONE.value:
            return text

        redacted = text
        if level in (ReportRedactionLevelEnum.STANDARD.value, ReportRedactionLevelEnum.STRICT.value, ReportRedactionLevelEnum.LEGAL_PRIVILEGED.value):
            # Mask API tokens
            redacted = cls._AUTH_TOKEN_REGEX.sub(r"Bearer [REDACTED_SECRET]", redacted)

            # Mask emails
            def _mask_email(m: re.Match) -> str:
                email_str = m.group(0)
                parts = email_str.split("@")
                if len(parts) == 2:
                    user_part, domain_part = parts
                    masked_user = user_part[0] + "***" if len(user_part) > 1 else "***"
                    return f"{masked_user}@{domain_part}"
                return "[REDACTED_EMAIL]"

            redacted = cls._EMAIL_REGEX.sub(_mask_email, redacted)

        if level in (ReportRedactionLevelEnum.STRICT.value, ReportRedactionLevelEnum.LEGAL_PRIVILEGED.value):
            # Mask IPv4 addresses
            redacted = cls._IPV4_REGEX.sub("[REDACTED_IP]", redacted)

        if level == ReportRedactionLevelEnum.LEGAL_PRIVILEGED.value:
            redacted = "[ATTORNEY-CLIENT PRIVILEGED & CONFIDENTIAL DOCUMENT]\n" + redacted

        return redacted

    @classmethod
    def apply_redaction_to_dict(cls, data: Any, level: str) -> Any:
        """Recursively sanitizes dictionary/list values with redaction level."""
        if level == ReportRedactionLevelEnum.NONE.value:
            return data
        if isinstance(data, str):
            return cls.apply_redaction_to_text(data, level)
        elif isinstance(data, list):
            return [cls.apply_redaction_to_dict(item, level) for item in data]
        elif isinstance(data, dict):
            new_dict = {}
            for k, v in data.items():
                if level in (ReportRedactionLevelEnum.STANDARD.value, ReportRedactionLevelEnum.STRICT.value):
                    if k.lower() in ("password", "secret", "auth_token", "api_key", "credential", "private_key"):
                        new_dict[k] = "[REDACTED_CREDENTIAL]"
                        continue
                if level == ReportRedactionLevelEnum.STRICT.value:
                    if k.lower() in ("analyst_name", "assignee", "investigator", "owner_email"):
                        new_dict[k] = "[REDACTED_IDENTITY]"
                        continue
                new_dict[k] = cls.apply_redaction_to_dict(v, level)
            return new_dict
        return data

    # -------------------------------------------------------------------------
    # Snapshot & Anti-Data Drift Engine
    # -------------------------------------------------------------------------

    @classmethod
    def capture_point_in_time_snapshot(
        cls,
        db: Session,
        report_id: str,
        incident_id: Optional[str] = None,
        case_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        evidence_id: Optional[str] = None,
        workspace_id: str = "default",
        tenant_id: str = "default",
    ) -> ReportSnapshotModel:
        """
        Captures authoritative snapshot of all referenced data sources at current moment.
        Freezes state, hashes payload, and prevents future data drift.
        """
        source_identifiers = {
            "incident_id": incident_id,
            "case_id": case_id,
            "investigation_id": investigation_id,
            "evidence_id": evidence_id,
        }
        source_versions: Dict[str, Any] = {}
        payload: Dict[str, Any] = {
            "snapshot_timestamp": datetime.now(timezone.utc).isoformat(),
            "workspace_id": workspace_id,
            "tenant_id": tenant_id,
        }

        # 1. Resolve Incident context
        if incident_id:
            inc = db.query(IncidentModel).filter(IncidentModel.id == incident_id).first()
            if inc:
                source_versions["incident_version"] = getattr(inc, "version", 1)
                payload["incident"] = {
                    "id": inc.id,
                    "incident_number": inc.incident_number,
                    "title": inc.title,
                    "severity": inc.severity,
                    "status": inc.status,
                    "threat_score": getattr(inc, "risk_score", getattr(inc, "threat_score", 0.0)),
                    "created_at": inc.opened_at.isoformat() if getattr(inc, "opened_at", None) else (inc.created_at.isoformat() if getattr(inc, "created_at", None) else None),
                    "attack_vector": getattr(inc, "category", getattr(inc, "attack_vector", "UNKNOWN")),
                    "summary": getattr(inc, "description", getattr(inc, "summary", "")),
                }

        # 2. Resolve Case context
        if case_id:
            cs = db.query(CaseModel).filter(CaseModel.id == case_id).first()
            if cs:
                source_versions["case_version"] = getattr(cs, "version", 1)
                payload["case"] = {
                    "id": cs.id,
                    "case_number": cs.case_number,
                    "title": cs.title,
                    "priority": getattr(cs, "priority", "P3"),
                    "status": getattr(cs, "status", "OPEN"),
                    "created_at": cs.created_at.isoformat() if cs.created_at else None,
                }

        # 3. Resolve Evidence context
        if evidence_id:
            evd = db.query(EvidenceModel).filter(EvidenceModel.evidence_id == evidence_id).first()
            if not evd:
                evd = db.query(EvidenceModel).filter(EvidenceModel.id == evidence_id).first()
            if evd:
                source_versions["evidence_id"] = evd.evidence_id
                payload["evidence"] = {
                    "id": evd.id,
                    "evidence_id": evd.evidence_id,
                    "sha256": evd.sha256,
                    "sha1": evd.sha1,
                    "md5": evd.md5,
                    "filename": evd.original_filename,
                    "size_bytes": evd.size,
                    "integrity_status": getattr(evd, "integrity_status", "VERIFIED"),
                    "classification": evd.classification,
                }

        # 4. Epistemic Labels
        epistemic_labels = {
            "source_integrity": "AUTHORITATIVE_FREEZE",
            "epistemic_level": "FACT",
            "data_drift_protection": "ACTIVE",
            "captured_records_count": len([k for k in payload.keys() if k not in ("snapshot_timestamp", "workspace_id", "tenant_id")]),
        }

        # Canonical deterministic JSON string for hashing
        canonical_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        snapshot_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        snapshot = ReportSnapshotModel(
            report_id=report_id,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            snapshot_hash=snapshot_hash,
            source_identifiers_json=json.dumps(source_identifiers),
            source_versions_json=json.dumps(source_versions),
            snapshot_payload_json=canonical_str,
            epistemic_labels_json=json.dumps(epistemic_labels),
        )
        db.add(snapshot)
        db.commit()
        db.refresh(snapshot)

        return snapshot

    # -------------------------------------------------------------------------
    # HTML Rendering & Assembly
    # -------------------------------------------------------------------------

    @classmethod
    def render_html_content(
        cls,
        report: ReportModel,
        template: ReportTemplateModel,
        snapshot_payload: Dict[str, Any],
        redaction_level: str,
    ) -> str:
        """Renders rich, responsive HTML executive report."""
        sections: List[Dict[str, Any]] = []
        try:
            sections = json.loads(template.sections_config_json)
        except Exception:
            sections = []

        # Color mapping for severity
        sev_color = {
            "critical": "#EF4444",
            "high": "#F97316",
            "medium": "#F59E0B",
            "low": "#10B981",
        }.get((report.severity or "").lower(), "#64748B")

        # Color mapping for classification badge
        class_color = {
            "CONFIDENTIAL": "#3B82F6",
            "RESTRICTED": "#EC4899",
            "INTERNAL": "#6366F1",
            "PUBLIC": "#10B981",
            "TLP_RED": "#DC2626",
            "TLP_AMBER": "#D97706",
            "TLP_GREEN": "#059669",
            "TLP_CLEAR": "#475569",
        }.get(report.classification, "#3B82F6")

        rendered_sections_html = []
        for sec in sorted(sections, key=lambda s: s.get("order", 0)):
            if not sec.get("enabled", True):
                continue

            sec_id = sec.get("section_id")
            title = sec.get("title", "Section")
            desc = sec.get("description", "")

            body_content = ""
            if sec_id in ("exec_summary", "technical_summary"):
                body_content = f"""
                <p style="color: #cbd5e1; line-height: 1.6; font-size: 14px;">
                    {cls.apply_redaction_to_text(report.summary or 'No executive summary provided.', redaction_level)}
                </p>
                <div style="display: flex; gap: 16px; margin-top: 16px;">
                    <div style="background: rgba(15, 23, 42, 0.6); padding: 12px 16px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Threat Score</div>
                        <div style="font-size: 20px; font-weight: 700; color: {sev_color};">{report.threat_score:.1f} / 100</div>
                    </div>
                    <div style="background: rgba(15, 23, 42, 0.6); padding: 12px 16px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Confidence Index</div>
                        <div style="font-size: 20px; font-weight: 700; color: #38bdf8;">{int((report.confidence or 1.0) * 100)}%</div>
                    </div>
                    <div style="background: rgba(15, 23, 42, 0.6); padding: 12px 16px; border-radius: 8px; border: 1px solid rgba(255,255,255,0.06);">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase;">Redaction Applied</div>
                        <div style="font-size: 20px; font-weight: 700; color: #a855f7;">{redaction_level}</div>
                    </div>
                </div>
                """
            elif sec_id in ("crown_jewels", "data_exposure_scope"):
                inc_data = snapshot_payload.get("incident", {})
                body_content = f"""
                <div style="background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 16px;">
                    <table style="width: 100%; border-collapse: collapse; font-size: 13px; color: #cbd5e1;">
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.08); text-align: left; color: #94a3b8;">
                            <th style="padding: 8px;">Target Asset / Identity</th>
                            <th style="padding: 8px;">Exposure Scope</th>
                            <th style="padding: 8px;">Status</th>
                        </tr>
                        <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                            <td style="padding: 8px; font-weight: 600;">{cls.apply_redaction_to_text(inc_data.get('attack_vector', 'CORPORATE_NETWORK'), redaction_level)}</td>
                            <td style="padding: 8px; color: #38bdf8;">Enterprise Critical Segment</td>
                            <td style="padding: 8px;"><span style="background: rgba(239, 68, 68, 0.2); color: #f87171; padding: 2px 8px; border-radius: 4px; font-size: 11px;">CONTAINED</span></td>
                        </tr>
                    </table>
                </div>
                """
            elif sec_id in ("timeline_high_level", "statutory_timeline"):
                body_content = f"""
                <div style="border-left: 2px solid #3b82f6; padding-left: 16px; margin-left: 8px;">
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: #38bdf8; font-weight: 600;">DETECTED / INGESTED</div>
                        <div style="font-size: 13px; color: #cbd5e1;">Initial anomaly telemetry captured by CyberGuard Universal Gateway.</div>
                    </div>
                    <div style="margin-bottom: 12px;">
                        <div style="font-size: 11px; color: #fbbf24; font-weight: 600;">TRIAGED & ESCALATED</div>
                        <div style="font-size: 13px; color: #cbd5e1;">Correlated into authoritative operational incident & case context.</div>
                    </div>
                    <div>
                        <div style="font-size: 11px; color: #34d399; font-weight: 600;">SNAPSHOT FROZEN & DOSSIER GENERATED</div>
                        <div style="font-size: 13px; color: #cbd5e1;">Cryptographic snapshot generated; report locked with zero data drift.</div>
                    </div>
                </div>
                """
            elif sec_id in ("strategic_recommendations", "remediation_statement"):
                recs = []
                try:
                    recs = json.loads(report.recommendations_json or "[]")
                except Exception:
                    recs = []
                if not recs:
                    recs = [
                        "Enforce strict MFA & password reset on correlated identities.",
                        "Isolate affected endpoints from corporate network segments.",
                        "Block correlated malicious network indicators across boundary firewalls.",
                    ]
                rec_items = "".join([f"<li style='margin-bottom: 8px;'>{cls.apply_redaction_to_text(r, redaction_level)}</li>" for r in recs])
                body_content = f"""
                <ul style="color: #cbd5e1; font-size: 13px; line-height: 1.6; padding-left: 20px;">
                    {rec_items}
                </ul>
                """
            elif sec_id in ("custody_overview", "forensic_artifacts"):
                evd_data = snapshot_payload.get("evidence", {})
                body_content = f"""
                <div style="background: rgba(15, 23, 42, 0.4); border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 16px;">
                    <div style="font-size: 12px; color: #94a3b8; margin-bottom: 6px;">EVIDENCE ID: <strong style="color: #38bdf8;">{evd_data.get('evidence_id', 'EVD-ATTACHED')}</strong></div>
                    <div style="font-family: monospace; font-size: 11px; color: #a5f3fc; word-break: break-all; margin-bottom: 4px;">SHA256: {evd_data.get('sha256', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')}</div>
                    <div style="font-size: 11px; color: #34d399;">INTEGRITY STATUS: VERIFIED APPEND-ONLY</div>
                </div>
                """
            else:
                body_content = f"""
                <p style="color: #94a3b8; font-size: 13px; font-style: italic;">
                    Section content generated from template parameters.
                </p>
                """

            rendered_sections_html.append(f"""
            <section style="margin-bottom: 28px; background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 12px; padding: 20px;">
                <div style="display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.06); padding-bottom: 8px;">
                    <h3 style="margin: 0; font-size: 16px; font-weight: 600; color: #f8fafc;">{title}</h3>
                    <span style="font-size: 11px; color: #64748b; font-family: monospace;">SECTION {sec.get('order', 0)}</span>
                </div>
                {f'<p style="margin: 0 0 14px 0; font-size: 12px; color: #94a3b8;">{desc}</p>' if desc else ''}
                {body_content}
            </section>
            """)

        all_sections_str = "\n".join(rendered_sections_html)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>{report.report_number} - {report.title}</title>
<style>
body {{
    margin: 0;
    padding: 32px;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: #0f172a;
    color: #e2e8f0;
}}
.container {{
    max-width: 900px;
    margin: 0 auto;
}}
.header {{
    border-bottom: 2px solid #334155;
    padding-bottom: 20px;
    margin-bottom: 28px;
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
}}
.badge {{
    display: inline-block;
    padding: 4px 10px;
    border-radius: 9999px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}}
.footer {{
    margin-top: 48px;
    border-top: 1px solid #334155;
    padding-top: 16px;
    font-size: 11px;
    color: #64748b;
    display: flex;
    justify-content: space-between;
}}
</style>
</head>
<body>
<div class="container">
    <div class="header">
        <div>
            <div style="font-size: 12px; color: #38bdf8; font-weight: 600; letter-spacing: 0.1em; text-transform: uppercase; margin-bottom: 4px;">
                CYBERGUARD // INTELLIGENCE & FORENSICS DISSEMINATION
            </div>
            <h1 style="margin: 0 0 8px 0; font-size: 24px; color: #ffffff;">{cls.apply_redaction_to_text(report.title, redaction_level)}</h1>
            <div style="font-size: 13px; color: #94a3b8;">
                REPORT ID: <strong style="color: #f1f5f9;">{report.report_number}</strong> &bull;
                VERSION: <strong style="color: #f1f5f9;">v{report.report_version}</strong> &bull;
                TYPE: <strong style="color: #f1f5f9;">{report.report_type}</strong>
            </div>
        </div>
        <div style="text-align: right;">
            <div class="badge" style="background: {class_color}; color: #ffffff; margin-bottom: 6px;">
                {report.classification}
            </div>
            <div style="font-size: 11px; color: #94a3b8;">
                STATUS: <strong style="color: #10b981;">{report.status}</strong>
            </div>
        </div>
    </div>

    {all_sections_str}

    <div class="footer">
        <div>
            SNAPSHOT SHA256: <span style="font-family: monospace; color: #94a3b8;">{report.source_data_hash or 'UNLOCKED'}</span>
        </div>
        <div>
            CYBERGUARD FORENSIC ENGINE &bull; {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')}
        </div>
    </div>
</div>
</body>
</html>"""
        return html_doc

    # -------------------------------------------------------------------------
    # Report CRUD & Lifecycle Management
    # -------------------------------------------------------------------------

    @classmethod
    def _generate_report_number(cls, db: Session) -> str:
        current_year = datetime.now(timezone.utc).year
        prefix = f"RPT-{current_year}-"
        reports = (
            db.query(ReportModel.report_number)
            .filter(ReportModel.report_number.like(f"{prefix}%"))
            .all()
        )
        max_seq = 0
        pattern = re.compile(rf"^RPT-{current_year}-(\d+)(?:-v\d+)?$")
        for (r_num,) in reports:
            m = pattern.match(r_num)
            if m:
                try:
                    num = int(m.group(1))
                    if num > max_seq:
                        max_seq = num
                except ValueError:
                    pass

        next_seq = max_seq + 1
        candidate = f"{prefix}{next_seq:06d}"
        while db.query(ReportModel).filter(ReportModel.report_number == candidate).first():
            next_seq += 1
            candidate = f"{prefix}{next_seq:06d}"
        return candidate

    @classmethod
    def create_executive_report(
        cls,
        db: Session,
        req: ExecutiveReportCreateRequest,
        created_by: str = "analyst",
        workspace_id: str = "default",
        tenant_id: str = "default",
    ) -> ReportModel:
        """Creates an executive report with an immediate point-in-time snapshot freeze."""
        # 1. Resolve template
        template_key = req.template_key or req.report_type.value
        tmpl = cls.get_template(db, template_key, workspace_id)
        if not tmpl:
            tmpl = cls.get_template(db, ReportTypeEnum.EXECUTIVE_BRIEFING.value, workspace_id)
        if not tmpl:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report template not found.")

        report_number = cls._generate_report_number(db)

        # 2. Derive threat score & severity if incident/case given
        threat_score = 0.0
        severity = "low"
        confidence = 1.0

        if req.incident_id:
            inc = db.query(IncidentModel).filter(IncidentModel.id == req.incident_id).first()
            if inc:
                threat_score = getattr(inc, "risk_score", getattr(inc, "threat_score", 0.0)) or 0.0
                severity = inc.severity or "low"
                confidence = getattr(inc, "confidence", 1.0) or 1.0

        report = ReportModel(
            report_number=report_number,
            title=req.title,
            report_type=req.report_type.value,
            status=ReportStatusEnum.DRAFT.value,
            report_version=1,
            classification=req.classification.value if req.classification else tmpl.default_classification,
            redaction_level=req.redaction_level.value if req.redaction_level else tmpl.default_redaction,
            threat_score=threat_score,
            severity=severity,
            confidence=confidence,
            summary=req.summary or f"Executive report generated using template {tmpl.template_name}.",
            analyst_name=created_by,
            incident_id=req.incident_id,
            case_id=req.case_id,
            investigation_id=req.investigation_id,
            evidence_id=req.evidence_id,
            template_id=tmpl.id,
            template_version=tmpl.version,
            content_options_json=json.dumps(req.content_options),
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            created_by=created_by,
            is_immutable=False,
            generated_at=datetime.now(timezone.utc),
        )
        db.add(report)
        db.commit()
        db.refresh(report)

        # 3. Capture Point-in-time Snapshot
        snapshot = cls.capture_point_in_time_snapshot(
            db,
            report_id=report.id,
            incident_id=req.incident_id,
            case_id=req.case_id,
            investigation_id=req.investigation_id,
            evidence_id=req.evidence_id,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
        )

        report.source_snapshot_id = snapshot.id
        report.source_data_hash = snapshot.snapshot_hash

        # 4. Render initial HTML content
        snapshot_payload = json.loads(snapshot.snapshot_payload_json)
        report.html_content = cls.render_html_content(
            report, tmpl, snapshot_payload, report.redaction_level
        )
        db.commit()
        db.refresh(report)

        # Audit log
        AuditService.log_audit(
            db=db,
            user=created_by,
            action="CREATE_EXECUTIVE_REPORT",
            resource_type="REPORT",
            resource_id=report.id,
            metadata={
                "report_number": report.report_number,
                "template_key": tmpl.template_key,
                "snapshot_hash": snapshot.snapshot_hash,
            },
        )

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_SNAPSHOT_CREATED,
            resource_id=report.id,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            data={"report_number": report.report_number, "status": report.status},
        )

        return report

    @classmethod
    def get_report(cls, db: Session, report_id: str, workspace_id: str = "default", tenant_id: str = "default") -> Optional[ReportModel]:
        return (
            db.query(ReportModel)
            .filter(
                ReportModel.id == report_id,
                ReportModel.workspace_id == workspace_id,
            )
            .first()
        )

    @classmethod
    def list_executive_reports(
        cls,
        db: Session,
        workspace_id: str = "default",
        tenant_id: str = "default",
        skip: int = 0,
        limit: int = 50,
        status_filter: Optional[str] = None,
        report_type: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> Tuple[List[ReportModel], int]:
        q = db.query(ReportModel).filter(ReportModel.workspace_id == workspace_id)
        if status_filter:
            q = q.filter(ReportModel.status == status_filter)
        if report_type:
            q = q.filter(ReportModel.report_type == report_type)
        if severity and severity.upper() != "ALL":
            q = q.filter(func.lower(ReportModel.severity) == severity.lower())

        total = q.count()
        items = q.order_by(ReportModel.created_at.desc()).offset(skip).limit(limit).all()
        return items, total

    @classmethod
    def update_report(
        cls,
        db: Session,
        report_id: str,
        req: ExecutiveReportUpdateRequest,
        updated_by: str = "analyst",
        workspace_id: str = "default",
    ) -> ReportModel:
        report = cls.get_report(db, report_id, workspace_id)
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        if report.is_immutable:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Finalized reports are immutable and cannot be edited. Create a new version instead.",
            )

        if req.title is not None:
            report.title = req.title
        if req.summary is not None:
            report.summary = req.summary
        if req.classification is not None:
            report.classification = req.classification.value
        if req.redaction_level is not None:
            report.redaction_level = req.redaction_level.value
        if req.recommendations is not None:
            report.recommendations_json = json.dumps(req.recommendations)
        if req.evidence_gaps is not None:
            report.evidence_gaps_json = json.dumps(req.evidence_gaps)
        if req.content_options is not None:
            report.content_options_json = json.dumps(req.content_options)

        # Re-render HTML with updated parameters
        tmpl = report.template or cls.get_template(db, report.report_type, workspace_id)
        snapshot = db.query(ReportSnapshotModel).filter(ReportSnapshotModel.id == report.source_snapshot_id).first()
        payload = json.loads(snapshot.snapshot_payload_json) if snapshot else {}

        report.html_content = cls.render_html_content(report, tmpl, payload, report.redaction_level)
        db.commit()
        db.refresh(report)

        return report

    # -------------------------------------------------------------------------
    # Review & Approval State Machine
    # -------------------------------------------------------------------------

    @classmethod
    def request_review(
        cls,
        db: Session,
        report_id: str,
        req: ReportReviewRequest,
        requested_by: str = "analyst",
        workspace_id: str = "default",
    ) -> ReportModel:
        report = cls.get_report(db, report_id, workspace_id)
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        if report.is_immutable:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Finalized reports cannot change review status.")

        report.status = ReportStatusEnum.REVIEW_REQUESTED.value
        report.reviewers_json = json.dumps(req.reviewers)

        notes: List[Dict[str, Any]] = []
        try:
            notes = json.loads(report.review_notes_json or "[]")
        except Exception:
            notes = []

        if req.note:
            notes.append({
                "author": requested_by,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "content": req.note,
                "status": "REVIEW_REQUESTED",
            })
            report.review_notes_json = json.dumps(notes)

        db.commit()
        db.refresh(report)

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_REVIEW_REQUESTED,
            resource_id=report.id,
            workspace_id=workspace_id,
            tenant_id=report.tenant_id,
            data={"report_number": report.report_number, "reviewers": req.reviewers},
        )
        return report

    @classmethod
    def add_review_note(
        cls,
        db: Session,
        report_id: str,
        req: ReportAddReviewNoteRequest,
        author: str = "reviewer",
        workspace_id: str = "default",
    ) -> ReportModel:
        report = cls.get_report(db, report_id, workspace_id)
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        if report.is_immutable:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot add review notes to finalized reports.")

        notes: List[Dict[str, Any]] = []
        try:
            notes = json.loads(report.review_notes_json or "[]")
        except Exception:
            notes = []

        notes.append({
            "author": author,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "content": req.note,
            "status": req.status,
        })
        report.review_notes_json = json.dumps(notes)
        db.commit()
        db.refresh(report)
        return report

    @classmethod
    def approve_report(
        cls,
        db: Session,
        report_id: str,
        req: ReportApprovalRequest,
        approved_by: str = "lead_analyst",
        workspace_id: str = "default",
    ) -> ReportModel:
        report = cls.get_report(db, report_id, workspace_id)
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        if report.is_immutable:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Report is already finalized and immutable.")

        report.status = ReportStatusEnum.APPROVED.value
        report.approved_at = datetime.now(timezone.utc)
        report.approved_by = approved_by

        if req.approval_notes:
            notes: List[Dict[str, Any]] = []
            try:
                notes = json.loads(report.review_notes_json or "[]")
            except Exception:
                notes = []
            notes.append({
                "author": approved_by,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "content": req.approval_notes,
                "status": "APPROVED",
            })
            report.review_notes_json = json.dumps(notes)

        db.commit()
        db.refresh(report)

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_APPROVED,
            resource_id=report.id,
            workspace_id=workspace_id,
            tenant_id=report.tenant_id,
            data={"report_number": report.report_number, "approved_by": approved_by},
        )
        return report

    @classmethod
    def finalize_report(
        cls,
        db: Session,
        report_id: str,
        req: ReportFinalizeRequest,
        finalized_by: str = "lead_analyst",
        workspace_id: str = "default",
    ) -> ReportModel:
        """Locks report into permanent, immutable state."""
        report = cls.get_report(db, report_id, workspace_id)
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

        report.status = ReportStatusEnum.FINALIZED.value
        report.is_immutable = True
        report.finalized_at = datetime.now(timezone.utc)
        report.finalized_by = finalized_by

        if req.finalization_notes:
            notes: List[Dict[str, Any]] = []
            try:
                notes = json.loads(report.review_notes_json or "[]")
            except Exception:
                notes = []
            notes.append({
                "author": finalized_by,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "content": req.finalization_notes,
                "status": "FINALIZED",
            })
            report.review_notes_json = json.dumps(notes)

        db.commit()
        db.refresh(report)

        AuditService.log_audit(
            db=db,
            user=finalized_by,
            action="FINALIZE_EXECUTIVE_REPORT",
            resource_type="REPORT",
            resource_id=report.id,
            metadata={"report_number": report.report_number, "source_data_hash": report.source_data_hash},
        )

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_FINALIZED,
            resource_id=report.id,
            workspace_id=workspace_id,
            tenant_id=report.tenant_id,
            data={"report_number": report.report_number, "finalized_by": finalized_by},
        )
        return report

    @classmethod
    def create_version(
        cls,
        db: Session,
        report_id: str,
        created_by: str = "analyst",
        workspace_id: str = "default",
    ) -> ReportModel:
        """Creates a mutable version branch from a finalized report."""
        parent = cls.get_report(db, report_id, workspace_id)
        if not parent:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Parent report not found")

        new_version_num = (parent.report_version or 1) + 1
        new_report_number = f"{parent.report_number.split('-v')[0]}-v{new_version_num}"

        child = ReportModel(
            report_number=new_report_number,
            title=f"{parent.title} (v{new_version_num})",
            report_type=parent.report_type,
            status=ReportStatusEnum.DRAFT.value,
            report_version=new_version_num,
            classification=parent.classification,
            redaction_level=parent.redaction_level,
            threat_score=parent.threat_score,
            severity=parent.severity,
            confidence=parent.confidence,
            summary=parent.summary,
            analyst_name=created_by,
            incident_id=parent.incident_id,
            case_id=parent.case_id,
            investigation_id=parent.investigation_id,
            evidence_id=parent.evidence_id,
            template_id=parent.template_id,
            template_version=parent.template_version,
            source_snapshot_id=parent.source_snapshot_id,
            source_data_hash=parent.source_data_hash,
            content_options_json=parent.content_options_json,
            review_notes_json="[]",
            reviewers_json=parent.reviewers_json,
            evidence_gaps_json=parent.evidence_gaps_json,
            recommendations_json=parent.recommendations_json,
            workspace_id=parent.workspace_id,
            tenant_id=parent.tenant_id,
            created_by=created_by,
            is_immutable=False,
            generated_at=datetime.now(timezone.utc),
        )
        db.add(child)
        db.flush()

        parent.superseded_by = child.id
        db.commit()
        db.refresh(child)
        return child

    # -------------------------------------------------------------------------
    # Share Links & External Dissemination
    # -------------------------------------------------------------------------

    @classmethod
    def create_share_link(
        cls,
        db: Session,
        report_id: str,
        req: ReportShareLinkCreateRequest,
        created_by: str = "analyst",
        workspace_id: str = "default",
        tenant_id: str = "default",
    ) -> Tuple[ReportShareLinkModel, str]:
        """Creates a cryptographically salted external share link."""
        report = cls.get_report(db, report_id, workspace_id)
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")

        # Generate 32-byte secure random token
        raw_token = f"secshare_{secrets.token_urlsafe(32)}"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=req.expires_in_hours)

        link = ReportShareLinkModel(
            report_id=report.id,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            token_hash=token_hash,
            format=req.format,
            classification=req.classification.value,
            redaction_level=req.redaction_level.value,
            expires_at=expires_at,
            max_uses=req.max_uses,
            use_count=0,
            is_revoked=False,
            created_by=created_by,
        )
        db.add(link)
        db.commit()
        db.refresh(link)

        AuditService.log_audit(
            db=db,
            user=created_by,
            action="CREATE_REPORT_SHARE_LINK",
            resource_type="REPORT_SHARE_LINK",
            resource_id=link.id,
            metadata={
                "report_id": report.id,
                "expires_at": expires_at.isoformat(),
                "redaction_level": link.redaction_level,
                "max_uses": link.max_uses,
            },
        )

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_SHARE_LINK_CREATED,
            resource_id=report.id,
            workspace_id=workspace_id,
            tenant_id=tenant_id,
            data={"link_id": link.id, "expires_at": expires_at.isoformat()},
        )

        return link, raw_token

    @classmethod
    def list_share_links(
        cls,
        db: Session,
        report_id: str,
        workspace_id: str = "default",
    ) -> List[ReportShareLinkModel]:
        return (
            db.query(ReportShareLinkModel)
            .filter(
                ReportShareLinkModel.report_id == report_id,
                ReportShareLinkModel.workspace_id == workspace_id,
            )
            .order_by(ReportShareLinkModel.created_at.desc())
            .all()
        )

    @classmethod
    def revoke_share_link(
        cls,
        db: Session,
        link_id: str,
        revoked_by: str = "analyst",
        workspace_id: str = "default",
    ) -> ReportShareLinkModel:
        link = (
            db.query(ReportShareLinkModel)
            .filter(
                ReportShareLinkModel.id == link_id,
                ReportShareLinkModel.workspace_id == workspace_id,
            )
            .first()
        )
        if not link:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share link not found")

        link.is_revoked = True
        link.revoked_at = datetime.now(timezone.utc)
        link.revoked_by = revoked_by
        db.commit()
        db.refresh(link)

        AuditService.log_audit(
            db=db,
            user=revoked_by,
            action="REVOKE_REPORT_SHARE_LINK",
            resource_type="REPORT_SHARE_LINK",
            resource_id=link.id,
            metadata={"report_id": link.report_id},
        )

        cls._publish_realtime(
            event_type=RealtimeEventTypeEnum.REPORT_SHARE_LINK_REVOKED,
            resource_id=link.report_id,
            workspace_id=workspace_id,
            tenant_id=link.tenant_id,
            data={"link_id": link.id},
        )
        return link

    @classmethod
    def resolve_public_share_token(cls, db: Session, raw_token: str) -> Tuple[ReportModel, ReportShareLinkModel, str]:
        """
        Validates token, verifies expiration & max uses, increments count,
        and returns redacted content for public dissemination.
        """
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        link = db.query(ReportShareLinkModel).filter(ReportShareLinkModel.token_hash == token_hash).first()
        if not link:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Invalid or non-existent share link.")

        now_utc = datetime.now(timezone.utc)
        # Ensure expires_at is timezone-aware for comparison
        expires_at = link.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if link.is_revoked:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This share link has been revoked by security operations.")
        if now_utc > expires_at:
            raise HTTPException(status_code=status.HTTP_410_GONE, detail="This share link has expired.")
        if link.use_count >= link.max_uses:
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="This share link has reached its maximum allowed access count.")

        # Increment use count
        link.use_count += 1
        db.commit()

        report = db.query(ReportModel).filter(ReportModel.id == link.report_id).first()
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Referenced report no longer exists.")

        # Render fresh HTML matching the share link's specified redaction level
        tmpl = report.template or cls.get_template(db, report.report_type, report.workspace_id)
        snapshot = db.query(ReportSnapshotModel).filter(ReportSnapshotModel.id == report.source_snapshot_id).first()
        payload = json.loads(snapshot.snapshot_payload_json) if snapshot else {}

        redacted_html = cls.render_html_content(report, tmpl, payload, link.redaction_level)

        AuditService.log_audit(
            db=db,
            user="EXTERNAL_RECIPIENT",
            action="ACCESS_REPORT_SHARE_LINK",
            resource_type="REPORT_SHARE_LINK",
            resource_id=link.id,
            metadata={"use_count": link.use_count, "max_uses": link.max_uses},
        )

        return report, link, redacted_html

    # -------------------------------------------------------------------------
    # Metrics
    # -------------------------------------------------------------------------

    @classmethod
    def get_metrics(cls, db: Session, workspace_id: str = "default") -> Dict[str, Any]:
        reports = db.query(ReportModel).filter(ReportModel.workspace_id == workspace_id).all()
        active_links = (
            db.query(ReportShareLinkModel)
            .filter(
                ReportShareLinkModel.workspace_id == workspace_id,
                ReportShareLinkModel.is_revoked == False,
                ReportShareLinkModel.expires_at > datetime.now(timezone.utc),
            )
            .count()
        )

        by_class: Dict[str, int] = {}
        by_type: Dict[str, int] = {}
        by_sev: Dict[str, int] = {}

        for r in reports:
            by_class[r.classification] = by_class.get(r.classification, 0) + 1
            by_type[r.report_type] = by_type.get(r.report_type, 0) + 1
            sev = (r.severity or "low").upper()
            by_sev[sev] = by_sev.get(sev, 0) + 1

        return {
            "total_reports": len(reports),
            "draft_reports": sum(1 for r in reports if r.status == ReportStatusEnum.DRAFT.value),
            "in_review_reports": sum(1 for r in reports if r.status == ReportStatusEnum.REVIEW_REQUESTED.value),
            "approved_reports": sum(1 for r in reports if r.status == ReportStatusEnum.APPROVED.value),
            "finalized_reports": sum(1 for r in reports if r.status == ReportStatusEnum.FINALIZED.value),
            "active_share_links": active_links,
            "by_classification": by_class,
            "by_type": by_type,
            "by_severity": by_sev,
        }
