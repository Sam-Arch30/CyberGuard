import json
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column,
    String,
    Text,
    Integer,
    Float,
    DateTime,
    ForeignKey,
    Index,
    Boolean
)
from sqlalchemy.orm import relationship, relationship as orm_relationship, synonym
from backend.db.session import Base


def generate_uuid(prefix: Optional[str] = None) -> str:
    return str(uuid.uuid4())


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_cluster_number() -> str:
    return f"CLU-{uuid.uuid4().hex[:8].upper()}"


def generate_incident_number() -> str:
    return f"INC-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"


class CaseModel(Base):
    """
    Section 67: Authoritative SOC Operational Case Management Container.
    Coordinates security investigations, incidents, evidence, tasks, decisions, response actions, and final resolution.
    """
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_number = Column(String(32), unique=True, nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    priority = Column(String(20), nullable=False, default="P3_MEDIUM", index=True)  # P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW
    status = Column(String(20), nullable=False, default="OPEN", index=True)  # NEW, OPEN, IN_PROGRESS, PENDING, ON_HOLD, RESOLVED, CLOSED, CANCELLED
    category = Column(String(50), nullable=False, default="PHISHING", index=True)  # PHISHING, ACCOUNT_TAKEOVER, MALWARE, etc.
    classification = Column(String(30), nullable=False, default="INTERNAL", index=True)  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    owner_id = Column(String(100), nullable=True, index=True)
    team_id = Column(String(64), nullable=True, index=True)
    created_by = Column(String(100), nullable=True, default="SYSTEM")
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    primary_investigation_id = Column(String(128), nullable=True, index=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    sla_policy_id = Column(String(36), nullable=True, index=True)
    sla_status = Column(String(30), nullable=False, default="HEALTHY", index=True)  # HEALTHY, WARNING, BREACHED, PAUSED, MET
    next_sla_deadline = Column(DateTime, nullable=True, index=True)
    opened_at = Column(DateTime, default=get_utc_now, nullable=False)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    resolution_code = Column(String(50), nullable=True, index=True)  # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_ACTIVITY, etc.
    resolution_summary = Column(Text, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    closed_by = Column(String(100), nullable=True)
    closure_notes = Column(Text, nullable=True)
    reopened_at = Column(DateTime, nullable=True)
    reopened_by = Column(String(100), nullable=True)
    reopen_reason = Column(Text, nullable=True)
    duplicate_of_id = Column(String(36), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    merged_into_id = Column(String(36), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    tags_json = Column(Text, default="[]", nullable=False)
    custom_fields_json = Column(Text, default="{}", nullable=False)
    affected_assets_json = Column(Text, default="[]", nullable=False)
    affected_identities_json = Column(Text, default="[]", nullable=False)
    related_alerts_json = Column(Text, default="[]", nullable=False)
    related_evidence_json = Column(Text, default="[]", nullable=False)
    related_response_actions_json = Column(Text, default="[]", nullable=False)
    version = Column(Integer, nullable=False, default=1)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    emails = relationship("CaseEmailModel", back_populates="case", cascade="all, delete-orphan", lazy="selectin")
    notes = relationship("CaseNoteModel", back_populates="case", cascade="all, delete-orphan", order_by="desc(CaseNoteModel.created_at)", lazy="selectin")
    findings = relationship("CaseFindingModel", back_populates="case", cascade="all, delete-orphan", order_by="desc(CaseFindingModel.created_at)", lazy="selectin")
    tasks = relationship("CaseTaskModel", back_populates="case", cascade="all, delete-orphan", order_by="asc(CaseTaskModel.order_index)", lazy="selectin")
    audit_logs = relationship("AuditLogModel", back_populates="case", cascade="all, delete-orphan", order_by="desc(AuditLogModel.timestamp)", lazy="selectin")
    incident = relationship("IncidentModel", foreign_keys=[incident_id], lazy="selectin")
    campaign = relationship("CampaignModel", foreign_keys=[campaign_id], lazy="selectin")

    __table_args__ = (
        Index("ix_cases_workspace_status", "workspace_id", "status"),
        Index("ix_cases_workspace_updated", "workspace_id", "updated_at"),
        Index("ix_cases_workspace_priority", "workspace_id", "priority"),
    )


class CaseTaskModel(Base):
    """
    Section 67: Operational Case Work Item / Task.
    Tracks investigation checklists, evidence verification, containment approval, and reporting steps.
    """
    __tablename__ = "case_tasks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="TODO", index=True)  # TODO, IN_PROGRESS, BLOCKED, COMPLETED, CANCELLED
    priority = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    assignee_id = Column(String(100), nullable=True, index=True)
    team_id = Column(String(64), nullable=True)
    due_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    completed_by = Column(String(100), nullable=True)
    created_by = Column(String(100), nullable=True, default="SOC Analyst")
    order_index = Column(Integer, nullable=False, default=0)
    is_automated_recommendation = Column(Boolean, default=False, nullable=False)
    source_action_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    case = relationship("CaseModel", back_populates="tasks")


class CaseEmailModel(Base):
    __tablename__ = "case_emails"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(128), nullable=False)
    email_sha256 = Column(String(64), nullable=True)
    subject = Column(String(255), nullable=True, default="Untitled Email")
    sender = Column(String(255), nullable=True, default="unknown")
    threat_score = Column(Float, nullable=True, default=0.0)
    severity = Column(String(20), nullable=True, default="low")
    indicators_json = Column(Text, nullable=True, default="{}")
    added_at = Column(DateTime, default=get_utc_now, nullable=False)

    # Relationships
    case = relationship("CaseModel", back_populates="emails")

    __table_args__ = (
        Index("ix_case_emails_case_id_email_id", "case_id", "email_id", unique=True),
    )


class CaseNoteModel(Base):
    __tablename__ = "case_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False, default="SOC Analyst")
    note_text = Column(Text, nullable=False)
    visibility = Column(String(30), nullable=False, default="ANALYST")  # ANALYST, TEAM, EXECUTIVE, CONFIDENTIAL
    edit_history_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    case = relationship("CaseModel", back_populates="notes")


class CaseFindingModel(Base):
    __tablename__ = "case_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_type = Column(String(50), nullable=False)  # e.g., lookalike_domain, credential_harvesting, spoofed_sender
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="medium")  # low, medium, high, critical
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    # Relationships
    case = relationship("CaseModel", back_populates="findings")


class EvidenceModel(Base):
    """
    Authoritative Forensic Evidence Record (Section 68).
    Represents an artifact or observation formally acquired, integrity-verified,
    and associated with an investigation or case with immutable provenance.
    """
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(64), unique=True, nullable=False, index=True)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)

    # Hashes & Cryptographic Integrity
    sha256 = Column(String(64), nullable=False, index=True)
    sha1 = Column(String(40), nullable=True)
    md5 = Column(String(32), nullable=True)
    hash_algorithm = Column(String(20), nullable=False, default="SHA-256")
    integrity_status = Column(String(30), nullable=False, default="VERIFIED", index=True)  # UNKNOWN, PENDING, VERIFIED, MISMATCH, UNAVAILABLE
    last_verified_at = Column(DateTime, nullable=True)
    last_verified_by = Column(String(100), nullable=True)

    # Artifact & Storage Metadata
    original_filename = Column(String(255), nullable=False)
    mime_type = Column(String(100), nullable=True)
    size = Column(Integer, nullable=False)
    size_bytes = Column(Integer, nullable=True)
    storage_reference = Column(String(500), nullable=True)

    # Provenance & Acquisition
    source_type = Column(String(50), nullable=False, default="EMAIL", index=True)  # EMAIL, FILE, ATTACHMENT, URL, ENDPOINT, NETWORK, MANUAL_UPLOAD, THREAT_INTEL
    source_reference = Column(String(255), nullable=True)
    collection_method = Column(String(50), nullable=False, default="INGESTION_GATEWAY")  # INGESTION_GATEWAY, MANUAL_UPLOAD, ENDPOINT_AGENT, API, CONNECTOR
    uploader = Column(String(100), nullable=True, default="SOC Analyst")
    collected_by = Column(String(100), nullable=True, default="SOC Analyst")
    upload_timestamp = Column(DateTime, default=get_utc_now, nullable=False)
    collected_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    received_at = Column(DateTime, default=get_utc_now, nullable=False)
    observed_at = Column(DateTime, nullable=True)

    # Classification & Lifecycle
    classification = Column(String(30), nullable=False, default="INTERNAL")  # PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED, SENSITIVE
    lifecycle_status = Column(String(30), nullable=False, default="VALID", index=True)  # REGISTERED, VALIDATING, VALID, INVALID, QUARANTINED, PRESERVED, RELEASED, RETIRED
    retention_policy = Column(String(50), nullable=False, default="INDEFINITE")  # INDEFINITE, 30_DAYS, 90_DAYS, 1_YEAR, LEGAL_HOLD
    preservation_status = Column(String(30), nullable=False, default="NORMAL", index=True)  # NORMAL, PRESERVED, ON_HOLD
    preservation_reason = Column(Text, nullable=True)
    preservation_actor = Column(String(100), nullable=True)
    preservation_timestamp = Column(DateTime, nullable=True)

    # Derivation & Provenance Lineage
    parent_evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    derivation_metadata_json = Column(Text, default="{}", nullable=False)

    # Metadata & Notes
    metadata_json = Column(Text, default="{}", nullable=False)
    forensic_notes_json = Column(Text, default="[]", nullable=False)
    evidence_gaps_json = Column(Text, default="[]", nullable=False)

    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    artifact = relationship("ArtifactModel")
    case = relationship("CaseModel")
    parent_evidence = relationship("EvidenceModel", remote_side=[id], backref="child_evidence")
    custody_events = relationship("EvidenceCustodyEventModel", back_populates="evidence", cascade="all, delete-orphan", order_by="EvidenceCustodyEventModel.timestamp")

    __table_args__ = (
        Index("ix_evidence_tenant_integrity", "tenant_id", "integrity_status"),
        Index("ix_evidence_tenant_source", "tenant_id", "source_type"),
        Index("ix_evidence_tenant_upload", "tenant_id", "upload_timestamp"),
    )


class EvidenceCustodyEventModel(Base):
    """
    Immutable Chain-of-Custody ledger entry (Section 68).
    Tracks every meaningful custody transition with authentication, timestamp,
    action, integrity digest, and non-repudiation audit trail.
    """
    __tablename__ = "evidence_custody_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    evidence_id = Column(String(36), ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # ACQUIRED, REGISTERED, TRANSFERRED, ACCESSED, COPIED, ANALYZED, EXPORTED, PRESERVED, RELEASED
    actor_id = Column(String(100), nullable=False, default="SOC Analyst")
    timestamp = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    source = Column(String(255), nullable=True)
    destination = Column(String(255), nullable=True)
    reason = Column(Text, nullable=True)
    integrity_hash = Column(String(64), nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    evidence = relationship("EvidenceModel", back_populates="custody_events")


from sqlalchemy import event


# Immutability enforcement for EvidenceCustodyEventModel: chain-of-custody records are strictly append-only
@event.listens_for(EvidenceCustodyEventModel, "before_update")
def _prevent_custody_event_update(mapper, connection, target):
    raise PermissionError("Chain-of-custody records are append-only and immutable. Modifications are prohibited.")


@event.listens_for(EvidenceCustodyEventModel, "before_delete")
def _prevent_custody_event_delete(mapper, connection, target):
    if getattr(connection, "_allow_custody_cleanup", False):
        return
    raise PermissionError("Chain-of-custody records are append-only and immutable. Deletions are prohibited.")


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    user = Column(String(100), nullable=True, default="SOC Analyst")
    action = Column(String(50), nullable=False, index=True)  # EMAIL_UPLOADED, ANALYSIS_STARTED, ANALYSIS_COMPLETED, CASE_CREATED, EMAIL_ADDED_TO_CASE, CASE_STATUS_CHANGED, NOTE_ADDED, REPORT_GENERATED
    resource_type = Column(String(50), nullable=False, default="case", index=True)
    resource_id = Column(String(128), nullable=False, default="", index=True)
    metadata_json = Column(Text, nullable=True, default="{}")
    request_id = Column(String(64), nullable=True, index=True)

    # Backwards compatibility fields
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    details = Column(Text, nullable=True, default="")

    # Relationships
    case = relationship("CaseModel", back_populates="audit_logs")


# Conceptual alias for the Unified CyberGuard Data Model
AuditEventModel = AuditLogModel


# Immutability enforcement: audit records are strictly append-only
from sqlalchemy import event


@event.listens_for(AuditLogModel, "before_update")
def _prevent_audit_log_update(mapper, connection, target):
    raise PermissionError("Audit log records are append-only and immutable. Modifications are prohibited.")


@event.listens_for(AuditLogModel, "before_delete")
def _prevent_audit_log_delete(mapper, connection, target):
    if getattr(connection, "_allow_audit_cleanup", False):
        return
    raise PermissionError("Audit log records are append-only and immutable. Deletions are prohibited.")


class ReportTemplateModel(Base):
    """
    Section 69: Versioned report template defining section composition,
    visual layout, ordering, classification defaults, and controlled data bindings.
    """
    __tablename__ = "report_templates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(128), nullable=False, default="default", index=True)
    tenant_id = Column(String(128), nullable=False, default="default", index=True)
    template_key = Column(String(64), nullable=False, index=True)
    template_name = Column(String(128), nullable=False)
    report_type = Column(String(64), nullable=False, index=True)
    version = Column(Integer, nullable=False, default=1)
    description = Column(Text, nullable=True)
    sections_config_json = Column(Text, nullable=False, default="[]")
    default_classification = Column(String(32), nullable=False, default="CONFIDENTIAL")
    default_redaction = Column(String(32), nullable=False, default="NONE")
    is_system = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True)
    created_by = Column(String(100), nullable=False, default="SYSTEM")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    reports = relationship("ReportModel", back_populates="template")

    __table_args__ = (
        Index("ix_rt_ws_key_ver", "workspace_id", "template_key", "version", unique=True),
    )


class ReportModel(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_number = Column(String(32), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id = Column(String(128), nullable=True)
    email_sha256 = Column(String(64), nullable=True, index=True)
    threat_score = Column(Float, nullable=True, default=0.0)
    severity = Column(String(20), nullable=True, default="low")
    analyst_name = Column(String(100), nullable=True, default="SOC Lead Analyst")
    summary = Column(Text, nullable=True)
    ai_summary_json = Column(Text, nullable=True, default=None)
    file_path = Column(String(255), nullable=True)
    file_size_bytes = Column(Integer, nullable=True, default=0)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    sha256 = Column(String(64), nullable=True, index=True)
    investigation_id = Column(String(128), nullable=True, index=True)
    report_type = Column(String(64), default="ANALYST", nullable=False)
    status = Column(String(32), default="READY", nullable=False)
    report_version = Column(Integer, default=1, nullable=False)
    classification = Column(String(32), default="CONFIDENTIAL", nullable=False)
    redaction_level = Column(String(32), default="NONE", nullable=False)
    confidence = Column(Float, nullable=True, default=1.0)
    content_options_json = Column(Text, nullable=True, default="{}")
    snapshot_data_json = Column(Text, nullable=True, default="{}")
    quality_check_json = Column(Text, nullable=True, default="{}")
    superseded_by = Column(String(36), nullable=True)
    workspace_id = Column(String(128), nullable=True, default="default", index=True)
    tenant_id = Column(String(128), nullable=False, default="default", index=True)
    format = Column(String(20), default="PDF", nullable=False)
    generator_version = Column(String(50), default="1.0.0", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    # Section 69 additions
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    template_id = Column(String(36), ForeignKey("report_templates.id", ondelete="SET NULL"), nullable=True, index=True)
    template_version = Column(Integer, nullable=False, default=1)
    source_snapshot_id = Column(String(36), nullable=True, index=True)
    created_by = Column(String(100), nullable=True, default="SOC Analyst")
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)
    generated_at = Column(DateTime, nullable=True)
    finalized_at = Column(DateTime, nullable=True)
    finalized_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approved_by = Column(String(100), nullable=True)
    review_notes_json = Column(Text, nullable=True, default="[]")
    reviewers_json = Column(Text, nullable=True, default="[]")
    evidence_gaps_json = Column(Text, nullable=True, default="[]")
    recommendations_json = Column(Text, nullable=True, default="[]")
    is_immutable = Column(Boolean, nullable=False, default=False)
    html_content = Column(Text, nullable=True)
    source_data_hash = Column(String(64), nullable=True)

    template = relationship("ReportTemplateModel", back_populates="reports", foreign_keys=[template_id])
    snapshots = relationship("ReportSnapshotModel", back_populates="report", cascade="all, delete-orphan")
    share_links = relationship("ReportShareLinkModel", back_populates="report", cascade="all, delete-orphan")


class ReportSnapshotModel(Base):
    """
    Section 69: Immutable point-in-time snapshot of evidence and investigation telemetry.
    Backs the report to guarantee repeatability, prevent data drift, and trace provenance.
    """
    __tablename__ = "report_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(128), nullable=False, default="default", index=True)
    tenant_id = Column(String(128), nullable=False, default="default", index=True)
    snapshot_hash = Column(String(64), nullable=False, index=True)
    source_identifiers_json = Column(Text, nullable=False, default="{}")
    source_versions_json = Column(Text, nullable=False, default="{}")
    snapshot_payload_json = Column(Text, nullable=False, default="{}")
    epistemic_labels_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    report = relationship("ReportModel", back_populates="snapshots")

    __table_args__ = (
        Index("ix_rs_ws_report", "workspace_id", "report_id"),
    )


class ReportShareLinkModel(Base):
    """
    Section 69: Cryptographically secure, time-bounded, revocable external share link for report artifacts.
    """
    __tablename__ = "report_share_links"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(128), nullable=False, default="default", index=True)
    tenant_id = Column(String(128), nullable=False, default="default", index=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    format = Column(String(20), nullable=False, default="PDF")
    classification = Column(String(32), nullable=False, default="CONFIDENTIAL")
    redaction_level = Column(String(32), nullable=False, default="STANDARD")
    expires_at = Column(DateTime, nullable=False)
    max_uses = Column(Integer, nullable=False, default=10)
    use_count = Column(Integer, nullable=False, default=0)
    is_revoked = Column(Boolean, nullable=False, default=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_by = Column(String(100), nullable=True)
    created_by = Column(String(100), nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    report = relationship("ReportModel", back_populates="share_links")

    __table_args__ = (
        Index("ix_rsl_ws_report", "workspace_id", "report_id"),
    )


class EmailAnalysisModel(Base):
    __tablename__ = "email_analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(64), nullable=True, index=True)
    email_sha256 = Column(String(64), nullable=True, index=True)
    subject = Column(String(255), nullable=True, default="Untitled Email")
    sender = Column(String(255), nullable=True, default="unknown")
    recipient = Column(String(255), nullable=True)
    threat_score = Column(Float, nullable=False, default=0.0)
    severity = Column(String(20), nullable=False, default="low", index=True)
    spf_result = Column(String(20), nullable=True)
    dkim_result = Column(String(20), nullable=True)
    dmarc_result = Column(String(20), nullable=True)
    domains_json = Column(Text, nullable=True, default="[]")
    countries_json = Column(Text, nullable=True, default="[]")
    indicators_json = Column(Text, nullable=True, default="{}")
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    sender_domain = Column(String(255), nullable=True, index=True)
    contains_login_url = Column(Boolean, default=False)
    url_count = Column(Integer, default=0)
    attachment_count = Column(Integer, default=0)
    threat_level = Column(String(30), nullable=True, default="UNKNOWN")
    analyzed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)


class CampaignModel(Base):
    __tablename__ = "campaigns"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    campaign_id = Column(String(32), unique=True, nullable=False, index=True)  # e.g., C-042
    name = Column(String(255), nullable=False)
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    email_count = Column(Integer, default=0, nullable=False)
    recipient_count = Column(Integer, default=0, nullable=False)
    sender_count = Column(Integer, default=0, nullable=False)
    domain_count = Column(Integer, default=0, nullable=False)
    ip_count = Column(Integer, default=0, nullable=False)
    asn_count = Column(Integer, default=0, nullable=False)
    overall_confidence = Column(Float, default=0.0, nullable=False)
    dominant_attack_type = Column(String(100), default="Phishing / Fraud", nullable=False)
    targeted_brands_json = Column(Text, default="[]", nullable=False)
    targeted_organizations_json = Column(Text, default="[]", nullable=False)
    fingerprint_json = Column(Text, default="{}", nullable=False)
    associated_iocs_json = Column(Text, default="[]", nullable=False)
    timeline_events_json = Column(Text, default="[]", nullable=False)
    status = Column(String(30), nullable=False, default="CANDIDATE", index=True)  # CANDIDATE, LIKELY_RELATED, REVIEWED_CONFIRMED, REVIEWED_REJECTED
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    engine_version = Column(String(32), nullable=False, default="2.0.0")
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    contradicting_evidence_json = Column(Text, default="[]", nullable=False)
    correlation_summary = Column(Text, nullable=True)
    threat_actor_id = Column(String(36), ForeignKey("threat_actors.id", ondelete="SET NULL"), nullable=True, index=True)
    attribution_state = Column(String(30), default="UNKNOWN", nullable=False, index=True)  # UNKNOWN, SUSPECTED, POSSIBLE, PROBABLE, ASSESSED, CONFIRMED, DISPUTED, REJECTED
    attribution_confidence = Column(Float, default=0.0, nullable=False)  # 0.0 - 1.0 distinct from risk
    lifecycle_status = Column(String(30), default="CANDIDATE", nullable=False, index=True)  # CANDIDATE, OPEN, ACTIVE, MONITORING, CONTAINED, INACTIVE, CLOSED, ARCHIVED
    activity_state = Column(String(30), default="ACTIVE", nullable=False)  # ACTIVE, QUIET, STALE, UNKNOWN
    watch_state = Column(String(30), default="NOT_MONITORED", nullable=False)  # MONITORED, NOT_MONITORED
    description = Column(Text, nullable=True)
    mitre_techniques_json = Column(Text, default="[]", nullable=False)  # e.g. ["T1566.001", "T1566.002"]
    affected_assets_json = Column(Text, default="[]", nullable=False)
    affected_identities_json = Column(Text, default="[]", nullable=False)
    related_alerts_json = Column(Text, default="[]", nullable=False)
    related_incidents_json = Column(Text, default="[]", nullable=False)
    analyst_notes_json = Column(Text, default="[]", nullable=False)
    source_conflicts_json = Column(Text, default="[]", nullable=False)
    provenance_history_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    emails = relationship("CampaignEmailModel", back_populates="campaign", cascade="all, delete-orphan", lazy="selectin")
    incidents = relationship("CampaignIncidentModel", back_populates="campaign", cascade="all, delete-orphan", lazy="selectin")
    threat_actor = relationship("ThreatActorModel", back_populates="campaigns", lazy="selectin")


class CampaignIncidentModel(Base):
    __tablename__ = "campaign_incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    similarity_score = Column(Float, default=0.0, nullable=False)
    membership_reasons_json = Column(Text, default="[]", nullable=False)
    status = Column(String(30), default="CANDIDATE", nullable=False)  # CANDIDATE, CONFIRMED, REJECTED
    added_at = Column(DateTime, default=get_utc_now, nullable=False)
    added_by = Column(String(100), default="AUTOMATED", nullable=False)

    # Relationships
    campaign = relationship("CampaignModel", back_populates="incidents")
    incident = relationship("IncidentModel")

    __table_args__ = (
        Index("ix_campaign_incidents_camp_inc", "campaign_id", "incident_id", unique=True),
    )


class CampaignEmailModel(Base):
    __tablename__ = "campaign_emails"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False, index=True)
    email_id = Column(String(128), nullable=False)
    email_sha256 = Column(String(64), nullable=True)
    subject = Column(String(255), nullable=True, default="Untitled Email")
    sender = Column(String(255), nullable=True, default="unknown")
    recipient = Column(String(255), nullable=True)
    sent_at = Column(DateTime, default=get_utc_now, nullable=False)
    similarity_to_campaign = Column(Float, default=0.0, nullable=False)
    category_scores_json = Column(Text, default="{}", nullable=False)
    correlation_reasons_json = Column(Text, default="[]", nullable=False)
    added_at = Column(DateTime, default=get_utc_now, nullable=False)

    # Relationships
    campaign = relationship("CampaignModel", back_populates="emails")

    __table_args__ = (
        Index("ix_campaign_emails_camp_email", "campaign_id", "email_id", unique=True),
    )


class AnalystDecisionModel(Base):
    __tablename__ = "analyst_decisions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id_a = Column(String(128), nullable=False, index=True)
    email_id_b = Column(String(128), nullable=False, index=True)
    decision = Column(String(50), nullable=False, index=True)  # unrelated, confirmed_related, assigned_campaign, added_to_case, escalated
    campaign_id = Column(String(64), nullable=True)
    case_id = Column(String(64), nullable=True)
    analyst = Column(String(100), nullable=False, default="SOC Analyst")
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_analyst_decisions_pair", "email_id_a", "email_id_b"),
    )


class CopilotAuditLogModel(Base):
    __tablename__ = "copilot_audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user = Column(String(100), nullable=False, default="SOC Analyst")
    query = Column(Text, nullable=False)
    mode = Column(String(32), nullable=False, default="email")  # email, case, campaign
    context_id = Column(String(128), nullable=True)
    evidence_ids_json = Column(Text, default="[]", nullable=False)
    confidence = Column(String(50), nullable=False, default="PROBABLE")
    model_identifier = Column(String(100), nullable=False, default="mailtrace-copilot-v1")
    timestamp = Column(DateTime, default=get_utc_now, nullable=False, index=True)


class AnalysisPayloadModel(Base):
    """
    Stores canonical full analysis JSON for an ingested email evidence record.
    Preserves complete forensic indicators and prevents fabrication on reload.
    """
    __tablename__ = "analysis_payloads"

    evidence_id = Column(String(128), primary_key=True)
    analysis_json = Column(Text, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)


# ============================================================================
# UNIFIED CYBERGUARD CANONICAL DATA MODEL (SECTION 2)
# ============================================================================

class ArtifactModel(Base):
    """
    Canonical representation of any ingested or extracted security artifact
    (e.g., EMAIL, FILE, ATTACHMENT, URL, DOMAIN, IP, IMAGE, AUDIO, LOG, etc.).
    """
    __tablename__ = "artifacts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_type = Column(String(50), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    source = Column(String(100), nullable=False, default="UPLOAD")
    mime_type = Column(String(100), nullable=True)
    size = Column(Integer, nullable=True)
    sha256 = Column(String(64), nullable=True, index=True)
    sha1 = Column(String(40), nullable=True)
    md5 = Column(String(32), nullable=True)
    storage_reference = Column(String(500), nullable=True)
    parent_artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    ingested_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Hierarchical tree: Email -> Attachment -> Extracted File
    parent_artifact = relationship("ArtifactModel", remote_side=[id], back_populates="child_artifacts")
    child_artifacts = relationship("ArtifactModel", back_populates="parent_artifact", cascade="all, delete-orphan")
    analysis_runs = relationship("AnalysisRunModel", back_populates="artifact", cascade="all, delete-orphan", lazy="selectin")
    threat_events = relationship("ThreatEventModel", back_populates="source_artifact")
    storage_records = relationship("ArtifactStorageRecordModel", back_populates="artifact", cascade="all, delete-orphan", lazy="selectin")
    ingestions = relationship("IngestionRecordModel", back_populates="artifact", cascade="all, delete-orphan", lazy="selectin")


class ArtifactStorageRecordModel(Base):
    """
    Physical storage and integrity tracking for an Artifact across storage backends
    (e.g., LOCAL, S3, GCS, AZURE). Tracks verified SHA-256 and retention policy.
    """
    __tablename__ = "artifact_storage_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True)
    storage_backend = Column(String(50), nullable=False, default="LOCAL", index=True)  # LOCAL, S3, GCS, AZURE
    storage_key = Column(String(500), nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    size = Column(Integer, nullable=False)
    mime_type = Column(String(100), nullable=True)
    original_filename = Column(String(255), nullable=True)
    stored_at = Column(DateTime, default=get_utc_now, nullable=False)
    verified_at = Column(DateTime, nullable=True)
    integrity_status = Column(String(30), nullable=False, default="UNVERIFIED", index=True)  # UNVERIFIED, VERIFIED, MISMATCH, MISSING
    retention_policy = Column(String(50), nullable=False, default="INDEFINITE")  # INDEFINITE, 30_DAYS, 90_DAYS, 1_YEAR, LEGAL_HOLD
    retain_until = Column(DateTime, nullable=True)
    legal_hold = Column(Boolean, default=False, nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    artifact = relationship("ArtifactModel", back_populates="storage_records")


class IngestionRecordModel(Base):
    """
    Tracks discrete ingestion events. Distinguishes immutable content identity (Artifact)
    from submission contexts (submitter, timestamp, request_id, source channel).
    """
    __tablename__ = "ingestions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True)
    source = Column(String(50), nullable=False, default="UPLOAD", index=True)  # UPLOAD, API, EMAIL_CONNECTOR, ENDPOINT_AGENT, SYSTEM, IMPORT, EXTRACTION, OTHER
    submitted_by = Column(String(100), nullable=True)
    received_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    original_filename = Column(String(255), nullable=True)
    request_id = Column(String(100), nullable=True, index=True)
    context_json = Column(Text, default="{}", nullable=False)
    status = Column(String(30), nullable=False, default="COMPLETED", index=True)  # RECEIVED, PROCESSING, COMPLETED, FAILED
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    artifact = relationship("ArtifactModel", back_populates="ingestions")


class AnalysisRunModel(Base):
    """
    Tracks an execution of the CyberGuard analysis pipeline against an Artifact.
    One artifact may have multiple analysis runs (re-analysis, different engines/triggers).
    """
    __tablename__ = "analysis_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="CASCADE"), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="QUEUED", index=True)  # QUEUED, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED
    started_at = Column(DateTime, default=get_utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    trigger = Column(String(50), nullable=False, default="USER")  # USER, AUTOMATIC, REANALYSIS, CORRELATION, SYSTEM
    pipeline_version = Column(String(50), nullable=False, default="1.0.0")
    overall_risk_score = Column(Float, nullable=True)
    overall_severity = Column(String(20), nullable=True, index=True)  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=True)  # 0.0 - 1.0
    error = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    artifact = relationship("ArtifactModel", back_populates="analysis_runs")
    findings = relationship("FindingModel", back_populates="analysis_run", cascade="all, delete-orphan", lazy="selectin")
    threat_events = relationship("ThreatEventModel", back_populates="analysis_run")
    tasks = relationship("AnalysisTaskModel", back_populates="analysis_run", cascade="all, delete-orphan", lazy="selectin", order_by="AnalysisTaskModel.created_at")
    events = relationship("AnalysisEventModel", back_populates="analysis_run", cascade="all, delete-orphan", lazy="selectin", order_by="AnalysisEventModel.timestamp")


class AnalysisTaskModel(Base):
    """
    Represents an atomic analyzer execution task within an AnalysisRun DAG (Section 37).
    """
    __tablename__ = "analysis_tasks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    analyzer_id = Column(String(100), nullable=False, index=True)
    task_type = Column(String(100), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="PENDING", index=True)  # PENDING, QUEUED, RUNNING, COMPLETED, SKIPPED, FAILED, BLOCKED, CANCELLED
    dependency_ids_json = Column(Text, default="[]", nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    progress = Column(Float, nullable=True)  # 0.0 - 100.0 or None
    message = Column(String(255), nullable=True)
    error = Column(Text, nullable=True)
    result_count = Column(Integer, default=0, nullable=False)
    version = Column(String(50), nullable=False, default="1.0.0")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    analysis_run = relationship("AnalysisRunModel", back_populates="tasks")
    events = relationship("AnalysisEventModel", back_populates="task")


class AnalysisEventModel(Base):
    """
    Live event log emitted during execution of an AnalysisRun (Section 37).
    """
    __tablename__ = "analysis_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    task_id = Column(String(36), ForeignKey("analysis_tasks.id", ondelete="SET NULL"), nullable=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # RUN_STARTED, TASK_STARTED, TASK_PROGRESS, TASK_COMPLETED, TASK_FAILED, FINDING_PRODUCED, RISK_ASSESSED, RUN_COMPLETED, RUN_FAILED, RUN_CANCELLED
    sequence = Column(Integer, nullable=False, default=1, index=True)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False)
    task_status = Column(String(30), nullable=True)
    message = Column(String(255), nullable=False)
    result_count = Column(Integer, default=0, nullable=False)
    error = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)

    analysis_run = relationship("AnalysisRunModel", back_populates="events")
    task = relationship("AnalysisTaskModel", back_populates="events")

    __table_args__ = (
        Index("ix_analysis_events_run_seq", "analysis_run_id", "sequence"),
    )


class ModelVersionModel(Base):
    """
    ML/LLM model version provenance metadata for findings and audits.
    """
    __tablename__ = "model_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    model_name = Column(String(100), nullable=False, index=True)
    model_type = Column(String(50), nullable=False, index=True)
    version = Column(String(50), nullable=False, index=True)
    provider = Column(String(100), nullable=False)
    training_dataset_reference = Column(String(255), nullable=True)
    metrics_json = Column(Text, default="{}", nullable=False)
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # CANDIDATE, VALIDATING, ACTIVE, RETIRED, REJECTED
    deployed_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_model_versions_name_version", "workspace_id", "model_name", "version", unique=True),
    )

    findings = relationship("FindingModel", back_populates="model_version")


class FindingModel(Base):
    """
    Represents an analytical conclusion or observation produced by an analyzer.
    Preserves exact provenance (rule, heuristic, ML, LLM, intelligence).
    """
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=True, index=True)
    analyzer = Column(String(100), nullable=False, default="detection_rules", index=True)
    source_type = Column(String(50), nullable=True, default="DETECTION_RULE", index=True)
    finding_type = Column(String(100), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="LOW", index=True)  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False, default=1.0)  # 0.0 - 1.0
    risk_contribution = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0
    method = Column(String(50), nullable=False, default="RULE", index=True)  # RULE, HEURISTIC, ML, LLM, EXTERNAL_INTELLIGENCE, STATISTICAL, GRAPH, MANUAL, HYBRID
    model_version_id = Column(String(36), ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id = Column(String(100), nullable=True, index=True)
    is_composite = Column(Boolean, default=False, nullable=False, index=True)
    parent_finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    correlation_id = Column(String(36), nullable=True, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    analysis_run = relationship("AnalysisRunModel", back_populates="findings")
    model_version = relationship("ModelVersionModel", back_populates="findings")
    evidence_items = relationship("FindingEvidenceModel", back_populates="finding", cascade="all, delete-orphan", lazy="selectin")
    parent_finding = relationship("FindingModel", remote_side=[id], foreign_keys=[parent_finding_id], backref="child_findings")

    @property
    def details(self) -> Dict[str, Any]:
        if not self.metadata_json:
            return {}
        try:
            return json.loads(self.metadata_json)
        except Exception:
            return {}

    @details.setter
    def details(self, val: Any) -> None:
        if isinstance(val, dict):
            self.metadata_json = json.dumps(val)
        elif isinstance(val, str):
            self.metadata_json = val
        else:
            self.metadata_json = json.dumps(val)


class FindingEvidenceModel(Base):
    """
    Machine-readable factual basis supporting a specific Finding.
    """
    __tablename__ = "finding_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_type = Column(String(50), nullable=False, index=True)
    source = Column(String(100), nullable=False)
    key = Column(String(100), nullable=False, index=True)
    value = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)
    artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    finding = relationship("FindingModel", back_populates="evidence_items")
    artifact = relationship("ArtifactModel")


# Convenient alias for finding evidence items
EvidenceItemModel = FindingEvidenceModel


class IndicatorModel(Base):
    """
    Canonical observable / IOC entity reusable across multiple analyses and investigations.
    Forensic raw format is preserved in value; deduplication operates on normalized_value.
    """
    __tablename__ = "indicators"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    indicator_type = Column(String(50), nullable=False, index=True)  # IP, DOMAIN, URL, EMAIL_ADDRESS, FILE_HASH, etc.
    value = Column(Text, nullable=False)  # Preserves raw forensic input
    normalized_value = Column(String(500), nullable=False, index=True)  # Canonical indexed value
    first_seen = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    reputation = Column(String(50), nullable=True, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_indicators_type_norm", "workspace_id", "indicator_type", "normalized_value", unique=True),
    )


class EntityModel(Base):
    """
    Higher-level organizational, identity, or infrastructure entity in investigations.
    """
    __tablename__ = "entities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    entity_type = Column(String(50), nullable=False, index=True)  # USER, ACCOUNT, DEVICE, HOST, ORGANIZATION, BRAND, etc.
    name = Column(String(255), nullable=False, index=True)
    external_id = Column(String(255), nullable=True, index=True)
    canonical_key = Column(String(500), nullable=True, index=True)
    workspace_id = Column(String(100), nullable=True, index=True)
    attributes_json = Column(Text, default="{}", nullable=False)
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_entities_type_key", "entity_type", "canonical_key"),
        Index("ix_entities_workspace", "workspace_id"),
    )


class RelationshipModel(Base):
    """
    Generic polymorphic relationship model powering the Security Knowledge Graph.
    Connects any source (Artifact, Indicator, Entity, Incident) to any target.
    """
    __tablename__ = "relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    source_type = Column(String(50), nullable=False, index=True)
    source_id = Column(String(128), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False, index=True)  # CONTAINS, REFERENCES, RESOLVES_TO, etc.
    target_type = Column(String(50), nullable=False, index=True)
    target_id = Column(String(128), nullable=False, index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    origin = Column(String(50), nullable=False, default="OBSERVED")  # OBSERVED, DERIVED, INFERRED, EXTERNAL_INTELLIGENCE
    status = Column(String(30), nullable=False, default="ACTIVE")  # ACTIVE, SUPERSEDED, RETRACTED
    workspace_id = Column(String(100), nullable=True, index=True)
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    evidence_reference = Column(String(255), nullable=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    method = Column(String(50), nullable=False, default="RULE")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    observations = relationship("RelationshipObservationModel", back_populates="canonical_relationship", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_rel_src", "source_type", "source_id"),
        Index("ix_rel_tgt", "target_type", "target_id"),
        Index("ix_rel_type_src_tgt", "relationship_type", "source_id", "target_id"),
        Index("ix_rel_workspace", "workspace_id"),
    )


class RelationshipObservationModel(Base):
    """
    Individual evidence-backed observation of a canonical relationship edge.
    Supports multiple observations over time for the same canonical relationship.
    """
    __tablename__ = "relationship_observations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    relationship_id = Column(String(36), ForeignKey("relationships.id", ondelete="CASCADE"), nullable=False, index=True)
    observed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    source_artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id = Column(String(36), ForeignKey("finding_evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    analyzer = Column(String(100), nullable=True)
    analyzer_version = Column(String(50), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    origin = Column(String(50), nullable=False, default="OBSERVED")
    attributes_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    canonical_relationship = orm_relationship("RelationshipModel", back_populates="observations")
    artifact = orm_relationship("ArtifactModel")
    analysis_run = orm_relationship("AnalysisRunModel")
    evidence = orm_relationship("FindingEvidenceModel")

    @property
    def relationship(self):
        return self.canonical_relationship

    @relationship.setter
    def relationship(self, value):
        self.canonical_relationship = value

    __table_args__ = (
        Index("ix_rel_obs_rel_obs_at", "relationship_id", "observed_at"),
    )



class IncidentModel(Base):
    """
    Unified incident container linking correlated ThreatEvents, ResponseActions, and AttackPaths.
    """
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_number = Column(String(32), unique=True, nullable=False, default=generate_incident_number, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="OPEN", index=True)  # NEW, OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE, DUPLICATE
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    priority = Column(String(20), nullable=False, default="P3_MEDIUM", index=True)  # P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW
    category = Column(String(50), nullable=False, default="OTHER", index=True)  # PHISHING, CREDENTIAL_COMPROMISE, MALWARE, etc.
    risk_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0
    confidence = Column(Float, nullable=False, default=1.0)  # 0.0 - 1.0
    opened_at = Column(DateTime, default=get_utc_now, nullable=False)
    first_seen_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    contained_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    assigned_to = Column(String(100), nullable=True)
    team_id = Column(String(64), nullable=True)
    legacy_case_id = Column(String(36), nullable=True, index=True)  # Pointer to legacy cases.id
    primary_alert_id = Column(String(36), nullable=True, index=True)
    primary_cluster_id = Column(String(36), nullable=True, index=True)
    investigation_id = Column(String(128), nullable=True, index=True)
    report_id = Column(String(36), nullable=True, index=True)
    created_by = Column(String(100), nullable=True, default="SYSTEM")
    resolved_by = Column(String(100), nullable=True)
    resolution_reason = Column(Text, nullable=True)
    duplicate_of_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    sla_policy_id = Column(String(36), nullable=True, index=True)
    escalation_level = Column(Integer, nullable=False, default=0, index=True)
    sla_status = Column(String(30), nullable=False, default="HEALTHY", index=True)  # HEALTHY, WARNING, BREACHED, PAUSED, EXEMPT, MET
    next_sla_deadline = Column(DateTime, nullable=True, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    threat_events = relationship("ThreatEventModel", back_populates="incident", lazy="select")
    response_actions = relationship("ResponseActionModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    attack_paths = relationship("AttackPathModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    attack_hypotheses = relationship("AttackHypothesisModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    security_events = relationship("SecurityEventModel", back_populates="incident", lazy="select")
    temporal_sequences = relationship("TemporalSequenceCandidateModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    attack_technique_mappings = relationship("AttackTechniqueMappingModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    infrastructure_attributions = relationship("InfrastructureAttributionModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    infrastructure_clusters = relationship("InfrastructureClusterModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    behavioral_deviations = relationship("BehavioralDeviationModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    novelty_assessments = relationship("NoveltyAssessmentModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")
    emerging_patterns = relationship("EmergingPatternCandidateModel", back_populates="incident", lazy="select")
    threat_memory_observations = relationship("ThreatMemoryObservationModel", back_populates="incident", lazy="select")
    risk_assessments = relationship("RiskAssessmentModel", back_populates="incident", foreign_keys="RiskAssessmentModel.incident_id", cascade="all, delete-orphan", lazy="select")
    device_correlations = relationship("DeviceIncidentCorrelationModel", back_populates="incident", cascade="all, delete-orphan", lazy="select")

    timeline_events = relationship("IncidentTimelineEventModel", back_populates="incident", cascade="all, delete-orphan", order_by="asc(IncidentTimelineEventModel.timestamp)", lazy="select")
    notes = relationship("IncidentNoteModel", back_populates="incident", cascade="all, delete-orphan", order_by="desc(IncidentNoteModel.created_at)", lazy="select")
    duplicate_of = relationship("IncidentModel", remote_side=[id], foreign_keys=[duplicate_of_id], lazy="select")
    sla_state = relationship("IncidentSLAStateModel", back_populates="incident", uselist=False, cascade="all, delete-orphan", lazy="select")
    workflow_executions = relationship("IncidentWorkflowExecutionModel", back_populates="incident", cascade="all, delete-orphan", order_by="desc(IncidentWorkflowExecutionModel.executed_at)", lazy="select")
    sla_pause_logs = relationship("IncidentSLAPauseLogModel", back_populates="incident", cascade="all, delete-orphan", order_by="desc(IncidentSLAPauseLogModel.timestamp)", lazy="select")

    __table_args__ = (
        Index("ix_incidents_workspace_status", "workspace_id", "status"),
        Index("ix_incidents_workspace_created", "workspace_id", "created_at"),
        Index("ix_incidents_workspace_severity", "workspace_id", "severity"),
    )


class IncidentTimelineEventModel(Base):
    """
    Chronological factual events linked to an incident case lifecycle.
    """
    __tablename__ = "incident_timeline_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type = Column(String(50), nullable=False, index=True)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    actor = Column(String(100), nullable=False, default="SYSTEM")
    source_type = Column(String(50), nullable=False, default="SYSTEM")
    source_id = Column(String(128), nullable=True)
    summary = Column(Text, nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)

    incident = relationship("IncidentModel", back_populates="timeline_events")


class IncidentNoteModel(Base):
    """
    Analyst case notes linked to an operational incident.
    """
    __tablename__ = "incident_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    author = Column(String(100), nullable=False, default="SOC Analyst")
    note_text = Column(Text, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="notes")


class IncidentCorrelationModel(Base):
    """
    Pairwise incident correlation record with structured supporting and contradicting evidence.
    """
    __tablename__ = "incident_correlations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    incident_a_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_b_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    correlation_score = Column(Float, nullable=False, default=0.0)
    confidence = Column(Float, nullable=False, default=1.0)
    relationship_label = Column(String(100), nullable=False, default="Inconclusive / No significant relationship")
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    contradicting_evidence_json = Column(Text, default="[]", nullable=False)
    feature_breakdown_json = Column(Text, default="{}", nullable=False)
    shared_indicators_json = Column(Text, default="[]", nullable=False)
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, CONFIRMED, REJECTED, SUPERSEDED
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)
    engine_version = Column(String(32), nullable=False, default="2.0.0")
    config_version = Column(String(32), nullable=False, default="2.0.0")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident_a = relationship("IncidentModel", foreign_keys=[incident_a_id])
    incident_b = relationship("IncidentModel", foreign_keys=[incident_b_id])

    __table_args__ = (
        Index("ix_inc_corr_pair", "workspace_id", "incident_a_id", "incident_b_id", unique=True),
        Index("ix_inc_corr_score", "workspace_id", "correlation_score"),
    )


class ThreatEventModel(Base):
    """
    Normalized security event (e.g. phishing attempt, malware delivery, credential harvesting).
    """
    __tablename__ = "threat_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_type = Column(String(100), nullable=False, index=True)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    source_artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    confidence = Column(Float, nullable=False, default=1.0)
    status = Column(String(30), nullable=False, default="OPEN", index=True)
    summary = Column(Text, nullable=False)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    risk_assessment_id = Column(String(36), ForeignKey("risk_assessments.id", ondelete="SET NULL", use_alter=True, name="fk_threat_events_risk_assessment"), nullable=True, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    source_artifact = relationship("ArtifactModel", back_populates="threat_events")
    analysis_run = relationship("AnalysisRunModel", back_populates="threat_events")
    incident = relationship("IncidentModel", back_populates="threat_events")
    response_actions = relationship("ResponseActionModel", back_populates="threat_event")
    risk_assessment = relationship("RiskAssessmentModel", foreign_keys=[risk_assessment_id])


class ResponseActionModel(Base):
    """
    Defensive remediation action proposed, pending, approved, or executed.
    """
    __tablename__ = "response_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_event_id = Column(String(36), ForeignKey("threat_events.id", ondelete="SET NULL"), nullable=True, index=True)
    action_type = Column(String(50), nullable=False, index=True)  # QUARANTINE_EMAIL, BLOCK_URL, BLOCK_DOMAIN, BLOCK_IP, etc.
    description = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="RECOMMENDED", index=True)  # RECOMMENDED, PENDING_APPROVAL, APPROVED, EXECUTING, COMPLETED, FAILED, REJECTED
    priority = Column(String(20), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    recommended_by = Column(String(100), nullable=False)
    approved_by = Column(String(100), nullable=True)
    executed_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    approved_at = Column(DateTime, nullable=True)
    executed_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)

    incident = relationship("IncidentModel", back_populates="response_actions")
    threat_event = relationship("ThreatEventModel", back_populates="response_actions")


# ============================================================================
# ATTACK PATH FOUNDATION MODELS (SECTION 2 PREPARATION)
# ============================================================================

class AttackPathModel(Base):
    """
    Represents a multi-stage attack path hypothesis or confirmed progression.
    Augmented in Section 17 for evidence-driven Attack Reconstruction.
    """
    __tablename__ = "attack_paths"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    classification = Column(String(50), nullable=False, default="PLAUSIBLE_RECONSTRUCTION")
    confidence = Column(Float, nullable=False, default=1.0)
    confidence_level = Column(String(30), nullable=False, default="MODERATE")
    status = Column(String(30), nullable=False, default="CURRENT", index=True)  # CURRENT, SUPERSEDED, INVALIDATED
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    contradicting_evidence_json = Column(Text, default="[]", nullable=False)
    evidence_gaps_json = Column(Text, default="[]", nullable=False)
    alternative_hypotheses_json = Column(Text, default="[]", nullable=False)
    confidence_breakdown_json = Column(Text, default="{}", nullable=False)
    explanation_json = Column(Text, default="{}", nullable=False)
    confidence_bottleneck_json = Column(Text, default="{}", nullable=False)
    version = Column(Integer, nullable=False, default=1)
    engine_version = Column(String(32), nullable=False, default="1.0.0")
    rule_version = Column(String(32), nullable=False, default="1.0.0")
    analyst_disposition = Column(String(50), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="attack_paths")
    stages = relationship("AttackStageModel", back_populates="attack_path", cascade="all, delete-orphan", order_by="AttackStageModel.stage_order", lazy="selectin")
    edges = relationship("AttackEdgeModel", back_populates="attack_path", cascade="all, delete-orphan", lazy="selectin")
    hypotheses = relationship("AttackHypothesisModel", back_populates="attack_path", cascade="all, delete-orphan", lazy="selectin")
    technique_mappings = relationship("AttackTechniqueMappingModel", back_populates="attack_path", lazy="selectin")


class AttackStageModel(Base):
    """
    Discrete node/stage in an AttackPath representing a specific reconstructed activity.
    Augmented in Section 17 & 18 with strict OBSERVED/DERIVED/INFERRED status, evidence bindings,
    and granular confidence/explainability breakdowns.
    """
    __tablename__ = "attack_stages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    attack_path_id = Column(String(36), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_order = Column(Integer, nullable=False, default=1)
    stage_type = Column(String(50), nullable=False, default="UNKNOWN_ACTIVITY", index=True)
    stage_status = Column(String(30), nullable=False, default="OBSERVED", index=True)  # OBSERVED, DERIVED, INFERRED, UNRESOLVED
    technique_id = Column(String(50), nullable=True, index=True)  # MITRE ATT&CK technique (e.g. T1566.002)
    tactic = Column(String(100), nullable=True)  # e.g. Initial Access
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="ACTIVE")
    start_time = Column(DateTime, nullable=True, index=True)
    end_time = Column(DateTime, nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    confidence_level = Column(String(30), nullable=False, default="HIGH")
    entity_ids_json = Column(Text, default="[]", nullable=False)
    event_ids_json = Column(Text, default="[]", nullable=False)
    finding_ids_json = Column(Text, default="[]", nullable=False)
    evidence_ids_json = Column(Text, default="[]", nullable=False)
    relationship_ids_json = Column(Text, default="[]", nullable=False)
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    contradicting_evidence_json = Column(Text, default="[]", nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    confidence_breakdown_json = Column(Text, default="{}", nullable=False)
    explanation_json = Column(Text, default="{}", nullable=False)
    analyst_disposition = Column(String(50), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    attack_path = relationship("AttackPathModel", back_populates="stages")


class AttackEdgeModel(Base):
    """
    Directed transition edge between AttackStages.
    Augmented in Section 17 & 18 with transition semantics, shared entities, evidence support,
    and granular transition confidence / explainability breakdowns.
    """
    __tablename__ = "attack_edges"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    attack_path_id = Column(String(36), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    source_stage_id = Column(String(36), ForeignKey("attack_stages.id", ondelete="CASCADE"), nullable=False)
    target_stage_id = Column(String(36), ForeignKey("attack_stages.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String(50), nullable=False, default="PRECEDES")
    edge_status = Column(String(30), nullable=False, default="DERIVED", index=True)  # OBSERVED, DERIVED, INFERRED
    temporal_gap_seconds = Column(Float, nullable=True)
    shared_entities_json = Column(Text, default="[]", nullable=False)
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    contradicting_evidence_json = Column(Text, default="[]", nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)
    confidence_level = Column(String(30), nullable=False, default="HIGH")
    confidence_breakdown_json = Column(Text, default="{}", nullable=False)
    explanation_json = Column(Text, default="{}", nullable=False)
    analyst_disposition = Column(String(50), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    attack_path = relationship("AttackPathModel", back_populates="edges")


class AttackHypothesisModel(Base):
    """
    Alternative or primary explainable hypothesis for attack reconstruction (Section 17 & 18).
    """
    __tablename__ = "attack_hypotheses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    attack_path_id = Column(String(36), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=True, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), nullable=False, default="PLAUSIBLE", index=True)  # ACTIVE, PLAUSIBLE, REJECTED, SUPERSEDED
    is_primary = Column(Boolean, nullable=False, default=False)
    stage_ids_json = Column(Text, default="[]", nullable=False)
    confidence = Column(Float, nullable=False, default=0.5)
    confidence_level = Column(String(30), nullable=False, default="MODERATE")
    confidence_breakdown_json = Column(Text, default="{}", nullable=False)
    explanation_json = Column(Text, default="{}", nullable=False)
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    contradicting_evidence_json = Column(Text, default="[]", nullable=False)
    missing_evidence_json = Column(Text, default="[]", nullable=False)
    analyst_disposition = Column(String(50), nullable=True)
    analyst_notes = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="attack_hypotheses")
    attack_path = relationship("AttackPathModel", back_populates="hypotheses")


class ProtectedIdentityModel(Base):
    """
    Authoritative reference identity profiles (organizations, brands, executives, institutions)
    used for digital impersonation comparison.
    """
    __tablename__ = "protected_identities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    display_name = Column(String(255), nullable=False, index=True)
    entity_type = Column(String(50), nullable=False, default="ORGANIZATION", index=True)  # ORGANIZATION, BRAND, INSTITUTION, EXECUTIVE, SERVICE
    source = Column(String(50), nullable=False, default="USER_CONFIGURED", index=True)  # USER_CONFIGURED, ORGANIZATION_CONFIGURED, SYSTEM_CONFIGURED, etc.
    verification_status = Column(String(30), nullable=False, default="VERIFIED", index=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    revision = Column(Integer, nullable=False, default=1)
    trusted_domains_json = Column(Text, default="[]", nullable=False)
    trusted_emails_json = Column(Text, default="[]", nullable=False)
    known_names_json = Column(Text, default="[]", nullable=False)
    known_roles_json = Column(Text, default="[]", nullable=False)
    known_brand_terms_json = Column(Text, default="[]", nullable=False)
    authorized_delegated_senders_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)


# ============================================================================
# TEMPORAL CORRELATION & EVENT SEQUENCING MODELS (SECTION 16)
# ============================================================================

class SecurityEventModel(Base):
    """
    Canonical normalized security event acting as an indexed temporal projection
    over multi-source evidence (Section 16).
    """
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    event_type = Column(String(100), nullable=False, index=True)
    event_time = Column(DateTime, nullable=False, index=True)  # Normalized UTC timestamp
    event_time_end = Column(DateTime, nullable=True)  # Optional end of interval
    event_time_precision = Column(String(30), nullable=False, default="SECOND")
    event_time_confidence = Column(Float, nullable=False, default=1.0)
    ingested_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    analyzed_at = Column(DateTime, nullable=True)
    source_type = Column(String(50), nullable=False, index=True)
    source_artifact_id = Column(String(36), ForeignKey("artifacts.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    entity_ids_json = Column(Text, default="[]", nullable=False)
    finding_ids_json = Column(Text, default="[]", nullable=False)
    threat_event_ids_json = Column(Text, default="[]", nullable=False)
    provider = Column(String(100), nullable=False, default="generic")
    adapter = Column(String(100), nullable=False, default="generic")
    adapter_version = Column(String(32), nullable=False, default="1.0.0")
    attributes_json = Column(Text, default="{}", nullable=False)
    timestamp_provenance_json = Column(Text, default="{}", nullable=False)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="security_events")
    source_artifact = relationship("ArtifactModel")
    analysis_run = relationship("AnalysisRunModel")

    __table_args__ = (
        Index("ix_sec_ev_inc_time", "incident_id", "event_time"),
        Index("ix_sec_ev_ws_time", "workspace_id", "event_time"),
        Index("ix_sec_ev_type_time", "event_type", "event_time"),
    )


class TemporalSequenceCandidateModel(Base):
    """
    Explainable multi-event temporal sequence candidate (Section 16).
    """
    __tablename__ = "temporal_sequences"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    event_ids_json = Column(Text, default="[]", nullable=False)
    rule_ids_json = Column(Text, default="[]", nullable=False)
    start_time = Column(DateTime, nullable=False, index=True)
    end_time = Column(DateTime, nullable=False, index=True)
    duration_seconds = Column(Float, nullable=False, default=0.0)
    shared_entities_json = Column(Text, default="[]", nullable=False)
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    conflicting_evidence_json = Column(Text, default="[]", nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    confidence = Column(Float, nullable=False, default=0.5)
    status = Column(String(50), nullable=False, default="OBSERVED_SEQUENCE", index=True)
    summary = Column(Text, nullable=False)
    engine_version = Column(String(32), nullable=False, default="1.0.0")
    rule_version = Column(String(32), nullable=False, default="1.0.0")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="temporal_sequences")

    __table_args__ = (
        Index("ix_temp_seq_inc_time", "incident_id", "start_time"),
        Index("ix_temp_seq_ws_status", "workspace_id", "status"),
    )


class AttackTechniqueMappingModel(Base):
    """
    Persisted evidence-grounded MITRE ATT&CK technique mapping.
    Maintains provenance back to source SecurityEvent, Finding, ThreatEvent,
    AttackStage, or AttackPath transition.
    """
    __tablename__ = "attack_technique_mappings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    attack_path_id = Column(String(36), ForeignKey("attack_paths.id", ondelete="SET NULL"), nullable=True, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    source_type = Column(String(50), nullable=False, index=True)
    source_id = Column(String(128), nullable=False, index=True)
    technique_id = Column(String(50), nullable=False, index=True)
    subtechnique_id = Column(String(50), nullable=True, index=True)
    technique_name = Column(String(255), nullable=False)
    tactic_ids_json = Column(Text, default="[]", nullable=False)
    tactic_names_json = Column(Text, default="[]", nullable=False)
    status = Column(String(30), nullable=False, default="SUPPORTED", index=True)  # SUPPORTED, PLAUSIBLE, INSUFFICIENT_EVIDENCE, REJECTED
    confidence = Column(Float, nullable=False, default=1.0)
    confidence_level = Column(String(30), nullable=False, default="HIGH")
    evidence_ids_json = Column(Text, default="[]", nullable=False)
    finding_ids_json = Column(Text, default="[]", nullable=False)
    event_ids_json = Column(Text, default="[]", nullable=False)
    stage_ids_json = Column(Text, default="[]", nullable=False)
    mapping_method = Column(String(50), nullable=False, default="RULE_BASED", index=True)
    mapping_rule_id = Column(String(100), nullable=True, index=True)
    explanation = Column(Text, nullable=False, default="")
    limitations_json = Column(Text, default="[]", nullable=False)
    contradictions_json = Column(Text, default="[]", nullable=False)
    attack_version = Column(String(32), nullable=False, default="v15.1", index=True)
    engine_version = Column(String(32), nullable=False, default="1.0.0")
    configuration_version = Column(String(32), nullable=False, default="2026.10")
    analyst_disposition = Column(String(50), nullable=True)  # CONFIRMED, REJECTED, NOT_APPLICABLE, MODIFIED, PENDING
    analyst_notes = Column(Text, nullable=True)
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="attack_technique_mappings")
    attack_path = relationship("AttackPathModel", back_populates="technique_mappings")

    __table_args__ = (
        Index("ix_atm_inc_status", "incident_id", "status"),
        Index("ix_atm_tech_status", "technique_id", "status"),
        Index("ix_atm_src", "source_type", "source_id"),
    )


class InfrastructureAttributionModel(Base):
    """
    Persisted technical infrastructure attribution hypothesis.
    Maintains origin hypothesis, confidence, limitations, and evidence links without human attribution.
    """
    __tablename__ = "infrastructure_attributions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    investigation_id = Column(String(36), nullable=True, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    subject_entity_id = Column(String(128), nullable=True, index=True)
    origin_entity_id = Column(String(128), nullable=True, index=True)
    origin_value = Column(String(255), nullable=False)
    origin_type = Column(String(50), nullable=False, default="UNKNOWN", index=True)
    hypothesis_id = Column(String(32), nullable=False, default="H1")
    hypothesis_type = Column(String(64), nullable=False, default="DEDICATED_THREAT_INFRASTRUCTURE", index=True)
    hypothesis_title = Column(String(255), nullable=False)
    status = Column(String(30), nullable=False, default="PROBABLE", index=True)  # PROBABLE, PLAUSIBLE, INSUFFICIENT_EVIDENCE, REJECTED
    confidence_score = Column(Float, nullable=False, default=0.5)
    confidence_level = Column(String(30), nullable=False, default="MODERATE")
    evidence_count = Column(Integer, nullable=False, default=0)
    supporting_evidence_count = Column(Integer, nullable=False, default=0)
    contradicting_evidence_count = Column(Integer, nullable=False, default=0)
    limitations_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    engine_version = Column(String(32), nullable=False, default="1.0.0")
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="infrastructure_attributions")
    evidence_items = relationship("InfrastructureAttributionEvidenceModel", back_populates="attribution", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_infra_attr_inc_status", "incident_id", "status"),
        Index("ix_infra_attr_origin", "origin_type", "origin_value"),
        Index("ix_infra_attr_ws", "workspace_id", "created_at"),
    )


class InfrastructureAttributionEvidenceModel(Base):
    """
    Forensic link connecting an attribution hypothesis to concrete telemetry, graph relationship, or artifact.
    """
    __tablename__ = "infrastructure_attribution_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    attribution_id = Column(String(36), ForeignKey("infrastructure_attributions.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(String(64), nullable=True, index=True)
    relationship_id = Column(String(64), nullable=True, index=True)
    source_entity_id = Column(String(128), nullable=False, index=True)
    target_entity_id = Column(String(128), nullable=True)
    relationship_type = Column(String(64), nullable=False)
    evidence_family = Column(String(64), nullable=False, index=True)  # DIRECT_TELEMETRY, DNS, etc.
    support_direction = Column(String(30), nullable=False, default="SUPPORTS")  # SUPPORTS, CONTRADICTS, NEUTRAL
    strength = Column(Float, nullable=False, default=1.0)
    explanation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    attribution = relationship("InfrastructureAttributionModel", back_populates="evidence_items")

    __table_args__ = (
        Index("ix_iae_attr_family", "attribution_id", "evidence_family"),
        Index("ix_iae_src_rel", "source_entity_id", "relationship_type"),
    )


class InfrastructureClusterModel(Base):
    """
    Persisted infrastructure cluster linking correlated domains, IPs, ASNs, and certificates.
    """
    __tablename__ = "infrastructure_clusters"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    cluster_id = Column(String(64), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(255), nullable=False)
    members_json = Column(Text, default="[]", nullable=False)
    relationship_types_json = Column(Text, default="[]", nullable=False)
    evidence_count = Column(Integer, nullable=False, default=0)
    incident_count = Column(Integer, nullable=False, default=0)
    campaign_count = Column(Integer, nullable=False, default=0)
    supporting_signals_json = Column(Text, default="[]", nullable=False)
    contradicting_signals_json = Column(Text, default="[]", nullable=False)
    confidence = Column(Float, nullable=False, default=0.5)
    confidence_level = Column(String(30), nullable=False, default="MODERATE")
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    incident = relationship("IncidentModel", back_populates="infrastructure_clusters")

    __table_args__ = (
        Index("ix_icm_inc_cluster", "incident_id", "cluster_id"),
        Index("ix_icm_ws_conf", "workspace_id", "confidence"),
    )


# ============================================================================
# BEHAVIORAL BASELINE & ANOMALY DETECTION MODELS (SECTION 21)
# ============================================================================

class BehavioralBaselineModel(Base):
    """
    Persisted entity-specific behavioral baseline model.
    Encapsulates robust statistical distributions, quality states, and version stamps.
    """
    __tablename__ = "behavioral_baselines"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    entity_type = Column(String(50), nullable=False, index=True)  # USER, ACCOUNT, DEVICE, SERVICE, API_CLIENT, etc.
    entity_id = Column(String(128), nullable=False, index=True)
    entity_category = Column(String(50), nullable=False, default="HUMAN_USER", index=True)  # HUMAN_USER, SERVICE_ACCOUNT, etc.
    metric_type = Column(String(64), nullable=False, index=True)
    metric_version = Column(String(32), nullable=False, default="1.0.0")
    window_type = Column(String(32), nullable=False, default="ROLLING_30D")
    window_start = Column(DateTime, nullable=True)
    window_end = Column(DateTime, nullable=True)
    sample_count = Column(Integer, nullable=False, default=0)
    valid_sample_count = Column(Integer, nullable=False, default=0)
    missing_sample_count = Column(Integer, nullable=False, default=0)

    # Robust statistics
    median_value = Column(Float, nullable=True)
    mean_value = Column(Float, nullable=True)
    std_dev = Column(Float, nullable=True)
    mad_value = Column(Float, nullable=True)
    min_value = Column(Float, nullable=True)
    max_value = Column(Float, nullable=True)
    percentiles_json = Column(Text, default="{}", nullable=False)

    # Categorical & temporal distributions
    distribution_json = Column(Text, default="{}", nullable=False)
    expected_range_summary = Column(String(255), default="", nullable=False)

    # Quality & State
    confidence_score = Column(Float, nullable=False, default=0.5)
    confidence_level = Column(String(30), nullable=False, default="MODERATE")
    quality_status = Column(String(30), nullable=False, default="INSUFFICIENT_HISTORY", index=True)
    learning_mode = Column(String(30), nullable=False, default="LEARNING", index=True)

    # Freeze & Control
    is_frozen = Column(Boolean, nullable=False, default=False)
    frozen_reason = Column(Text, nullable=True)
    frozen_by = Column(String(100), nullable=True)
    frozen_at = Column(DateTime, nullable=True)

    # Lineage & Versioning
    baseline_version = Column(String(32), nullable=False, default="1.0.0")
    feature_version = Column(String(32), nullable=False, default="1.0.0")
    calculation_method = Column(String(50), nullable=False, default="ROBUST_STATISTICS")
    configuration_version = Column(String(32), nullable=False, default="2026.10")
    source_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    deviations = relationship("BehavioralDeviationModel", back_populates="baseline", cascade="all, delete-orphan", lazy="selectin")
    audit_logs = relationship("BaselineAuditModel", back_populates="baseline", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_bb_entity_metric", "entity_type", "entity_id", "metric_type"),
        Index("ix_bb_ws_quality", "workspace_id", "quality_status"),
        Index("ix_bb_updated", "updated_at"),
    )


class BehavioralDeviationModel(Base):
    """
    Persisted behavioral deviation finding linking observed telemetry to established baseline.
    Represents objective statistical deviation without premature compromise verdicts.
    """
    __tablename__ = "behavioral_deviations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    baseline_id = Column(String(36), ForeignKey("behavioral_baselines.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    investigation_id = Column(String(36), nullable=True, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    entity_type = Column(String(50), nullable=False, index=True)
    entity_id = Column(String(128), nullable=False, index=True)
    metric_type = Column(String(64), nullable=False, index=True)
    observed_value = Column(String(255), nullable=False)
    expected_range_summary = Column(String(255), nullable=False, default="")
    deviation_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 1.0
    deviation_direction = Column(String(30), nullable=False, default="CHANGED")  # ABOVE_NORMAL, BELOW_NORMAL, NEW, MISSING, CHANGED
    severity_hint = Column(String(30), nullable=False, default="LOW")
    baseline_confidence = Column(Float, nullable=False, default=0.5)
    baseline_quality = Column(String(30), nullable=False, default="STABLE")
    evidence_ids_json = Column(Text, default="[]", nullable=False)
    explanation = Column(Text, nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_id = Column(String(36), nullable=True, index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    incident = relationship("IncidentModel", back_populates="behavioral_deviations")
    baseline = relationship("BehavioralBaselineModel", back_populates="deviations")

    __table_args__ = (
        Index("ix_bd_entity_time", "entity_type", "entity_id", "created_at"),
        Index("ix_bd_inc_metric", "incident_id", "metric_type"),
        Index("ix_bd_ws_dev", "workspace_id", "deviation_score"),
        Index("ix_bd_finding", "finding_id"),
    )


class BaselineAuditModel(Base):
    """
    Audit log record for baseline lifecycle operations (freeze, unfreeze, relearn, exceptions).
    """
    __tablename__ = "baseline_audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    baseline_id = Column(String(36), ForeignKey("behavioral_baselines.id", ondelete="CASCADE"), nullable=False, index=True)
    action = Column(String(50), nullable=False)  # FREEZE, UNFREEZE, RELEARN, EXCEPTION_ADDED, RECALCULATE
    actor = Column(String(100), nullable=False)
    reason = Column(Text, nullable=False)
    details_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    baseline = relationship("BehavioralBaselineModel", back_populates="audit_logs")

    __table_args__ = (
        Index("ix_bal_base_action", "baseline_id", "action"),
    )


class BehaviorProfileModel(Base):
    """
    Section 60: Entity-level behavioral profile managing long-term observation state,
    baseline versioning, active quality status, and anomaly summaries.
    """
    __tablename__ = "behavior_profiles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    entity_type = Column(String(50), nullable=False, index=True)  # USER, DEVICE, ENDPOINT, API_CLIENT, IP, DOMAIN, ACCOUNT, SERVICE
    entity_id = Column(String(128), nullable=False, index=True)
    entity_category = Column(String(50), nullable=False, default="HUMAN_USER", index=True)  # HUMAN_USER, SERVICE_ACCOUNT, ADMINISTRATOR, DEVICE, APPLICATION
    profile_status = Column(String(30), nullable=False, default="INSUFFICIENT_DATA", index=True)  # INSUFFICIENT_DATA, LEARNING, ACTIVE, STALE, DEGRADED, SUSPENDED
    sample_count = Column(Integer, nullable=False, default=0)
    first_observed_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_observed_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_anomaly_at = Column(DateTime, nullable=True)
    anomaly_count = Column(Integer, nullable=False, default=0)
    quality_status = Column(String(30), nullable=False, default="INSUFFICIENT_HISTORY", index=True)
    confidence_score = Column(Float, nullable=False, default=0.5)
    baseline_version = Column(String(32), nullable=False, default="1.0.0")
    feature_schema_version = Column(String(32), nullable=False, default="1.0.0")
    active_metrics_json = Column(Text, default="[]", nullable=False)
    top_deviations_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_bp_ws_entity", "workspace_id", "entity_type", "entity_id", unique=True),
        Index("ix_bp_ws_status", "workspace_id", "profile_status"),
        Index("ix_bp_ws_quality", "workspace_id", "quality_status"),
        Index("ix_bp_ws_updated", "workspace_id", "updated_at"),
    )


class BehaviorLearningQuarantineModel(Base):
    """
    Section 60: Learning quarantine protecting baselines against poisoning from suspicious
    or unverified observations before they are admitted into normal training sets.
    """
    __tablename__ = "behavior_learning_quarantines"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    entity_type = Column(String(50), nullable=False, index=True)
    entity_id = Column(String(128), nullable=False, index=True)
    metric_type = Column(String(64), nullable=False, index=True)
    observed_value = Column(String(255), nullable=False)
    event_id = Column(String(128), nullable=True, index=True)
    quarantine_reason = Column(String(255), nullable=False)  # HIGH_ANOMALY, UNVERIFIED_TELEMETRY, SUSPECTED_POISONING, SUSPICIOUS_BURST
    disposition = Column(String(30), nullable=False, default="PENDING", index=True)  # PENDING, APPROVED, REJECTED, EXPIRED
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)
    payload_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_blq_ws_entity", "workspace_id", "entity_type", "entity_id"),
        Index("ix_blq_ws_disp", "workspace_id", "disposition"),
        Index("ix_blq_ws_created", "workspace_id", "created_at"),
    )


# ============================================================================
# SECTION 22: NOVELTY DETECTION & EMERGING-THREAT IDENTIFICATION MODELS
# ============================================================================

class PatternFingerprintModel(Base):
    """
    Persisted pattern fingerprints powering exact match and historical structural similarity (Section 22).
    """
    __tablename__ = "pattern_fingerprints"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    pattern_type = Column(String(50), nullable=False, index=True)
    fingerprint_hash = Column(String(64), nullable=False, index=True)
    fingerprint_repr = Column(String(255), nullable=False)
    attributes_json = Column(Text, default="{}", nullable=False)
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    observation_count = Column(Integer, nullable=False, default=1)
    entity_count = Column(Integer, nullable=False, default=1)
    incident_count = Column(Integer, nullable=False, default=1)
    is_suppressed = Column(Boolean, nullable=False, default=False)
    suppression_reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_pf_ws_type_hash", "workspace_id", "pattern_type", "fingerprint_hash", unique=True),
        Index("ix_pf_ws_last_seen", "workspace_id", "last_seen_at"),
    )


class NoveltyAssessmentModel(Base):
    """
    Persisted novelty assessments evaluating pattern unfamiliarity in retained telemetry (Section 22).
    """
    __tablename__ = "novelty_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    investigation_id = Column(String(36), nullable=True, index=True)
    entity_type = Column(String(50), nullable=False, index=True)
    entity_id = Column(String(128), nullable=False, index=True)
    novelty_type = Column(String(50), nullable=False, index=True)
    novelty_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 1.0 relative distance
    novelty_level = Column(String(30), nullable=False, default="UNKNOWN")
    similarity_score = Column(Float, nullable=False, default=0.0)
    historical_sample_count = Column(Integer, nullable=False, default=0)
    comparison_window = Column(String(50), nullable=False, default="90_DAYS")
    behavior_familiarity_matrix = Column(String(50), nullable=False, default="NORMAL_NOVEL")
    feature_version = Column(String(32), nullable=False, default="1.0.0")
    baseline_version = Column(String(32), nullable=False, default="1.0.0")
    status = Column(String(30), nullable=False, default="ACTIVE")
    fingerprint_hash = Column(String(64), nullable=True, index=True)
    fingerprint_repr = Column(String(255), nullable=True)
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    contradicting_evidence_json = Column(Text, default="[]", nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    threat_assessment_note = Column(Text, nullable=True)
    engine_version = Column(String(32), nullable=False, default="1.0.0")
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    incident = relationship("IncidentModel", back_populates="novelty_assessments")

    __table_args__ = (
        Index("ix_na_ws_entity", "workspace_id", "entity_type", "entity_id"),
        Index("ix_na_inc_type", "incident_id", "novelty_type"),
        Index("ix_na_ws_score", "workspace_id", "novelty_score"),
    )


class EmergingPatternCandidateModel(Base):
    """
    Clusters of recurring novel patterns across multiple entities/incidents (Section 22).
    """
    __tablename__ = "emerging_pattern_candidates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    pattern_type = Column(String(50), nullable=False, index=True)
    fingerprint_hash = Column(String(64), nullable=False, index=True)
    fingerprint_repr = Column(String(255), nullable=False)
    similarity_cluster = Column(String(100), nullable=True)
    novelty_score = Column(Float, nullable=False, default=1.0)
    recurrence_score = Column(Float, nullable=False, default=0.0)
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    observation_count = Column(Integer, nullable=False, default=1)
    entity_count = Column(Integer, nullable=False, default=1)
    incident_count = Column(Integer, nullable=False, default=1)
    supporting_evidence_json = Column(Text, default="[]", nullable=False)
    status = Column(String(30), nullable=False, default="OBSERVED")  # OBSERVED, EMERGING, INVESTIGATING, VALIDATED, REJECTED, ARCHIVED
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="emerging_patterns")

    __table_args__ = (
        Index("ix_epc_ws_hash", "workspace_id", "fingerprint_hash", unique=True),
        Index("ix_epc_ws_status", "workspace_id", "status"),
        Index("ix_epc_recurrence", "workspace_id", "recurrence_score"),
    )


class NoveltySuppressionRuleModel(Base):
    """
    Auditable contextual exceptions suppressing benign novelty (Section 22).
    """
    __tablename__ = "novelty_suppression_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    pattern_type = Column(String(50), nullable=True, index=True)
    entity_type = Column(String(50), nullable=True)
    entity_id = Column(String(128), nullable=True)
    fingerprint_hash = Column(String(64), nullable=True, index=True)
    reason = Column(String(255), nullable=False)
    approved_by = Column(String(100), nullable=False)
    valid_from = Column(DateTime, default=get_utc_now, nullable=False)
    valid_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_nsr_ws_fp", "workspace_id", "fingerprint_hash"),
    )


# ============================================================================
# Section 23: Threat Memory Models
# ============================================================================

class ThreatMemoryEntryModel(Base):
    """
    Persistent security-memory projection retaining consolidated historical intelligence (Section 23).
    Acts as a queryable index/projection over canonical evidence without duplicating primary tables.
    """
    __tablename__ = "threat_memory_entries"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    memory_type = Column(String(50), nullable=False, index=True)  # INDICATOR, DOMAIN, IP, URL, HASH, CAMPAIGN, etc.
    subject_type = Column(String(50), nullable=False, index=True)
    subject_id = Column(String(128), nullable=True, index=True)
    canonical_key = Column(String(500), nullable=False, index=True)
    scope = Column(String(50), nullable=False, default="ORGANIZATION", index=True)  # GLOBAL, ORGANIZATION, INVESTIGATION
    status = Column(String(30), nullable=False, default="OBSERVED", index=True)  # OBSERVED, CORRELATED, VERIFIED, DISMISSED, EXPIRED, SUPERSEDED
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    observation_count = Column(Integer, nullable=False, default=1)
    independent_source_count = Column(Integer, nullable=False, default=1)
    incident_count = Column(Integer, nullable=False, default=0)
    campaign_count = Column(Integer, nullable=False, default=0)
    confidence = Column(Float, nullable=False, default=1.0)
    confidence_level = Column(String(20), nullable=False, default="MEDIUM")
    provenance_type = Column(String(50), nullable=False, default="DIRECT_OBSERVATION")  # DIRECT_OBSERVATION, ANALYST_VERIFIED, EXTERNAL_INTELLIGENCE, MODEL_DERIVED
    provenance_reference = Column(String(255), nullable=True)
    summary = Column(Text, nullable=True)
    attributes_json = Column(Text, default="{}", nullable=False)
    version = Column(String(32), nullable=False, default="1.0.0")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    observations = relationship("ThreatMemoryObservationModel", back_populates="memory_entry", cascade="all, delete-orphan", lazy="selectin")
    decisions = relationship("ThreatMemoryDecisionModel", back_populates="memory_entry", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_tme_ws_key", "workspace_id", "canonical_key", unique=True),
        Index("ix_tme_ws_type_key", "workspace_id", "memory_type", "canonical_key"),
        Index("ix_tme_ws_status", "workspace_id", "status"),
        Index("ix_tme_ws_seen", "workspace_id", "last_seen_at"),
    )


class ThreatMemoryObservationModel(Base):
    """
    Individual evidence-backed historical observation retained with strict provenance (Section 23).
    Answers: 'Why does CyberGuard remember this historical fact?'
    """
    __tablename__ = "threat_memory_observations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    memory_entry_id = Column(String(36), ForeignKey("threat_memory_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    source_type = Column(String(50), nullable=False, index=True)  # SECURITY_EVENT, FINDING, EVIDENCE, EXTERNAL_FEED, ARTIFACT
    source_id = Column(String(128), nullable=True, index=True)
    investigation_id = Column(String(36), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    observed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    observation_type = Column(String(50), nullable=False, default="DETECTION")
    classification = Column(String(30), nullable=False, default="INCONCLUSIVE", index=True)  # MALICIOUS, SUSPICIOUS, BENIGN, INCONCLUSIVE
    severity = Column(String(20), nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    evidence_reference = Column(String(255), nullable=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    detector_name = Column(String(100), nullable=True, index=True)
    detector_version = Column(String(32), nullable=False, default="1.0.0")
    is_analyst_verified = Column(Boolean, nullable=False, default=False)
    verified_by = Column(String(100), nullable=True)
    raw_context_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    memory_entry = relationship("ThreatMemoryEntryModel", back_populates="observations")
    incident = relationship("IncidentModel", back_populates="threat_memory_observations")

    __table_args__ = (
        Index("ix_tmo_entry_observed", "memory_entry_id", "observed_at"),
        Index("ix_tmo_ws_inv", "workspace_id", "investigation_id"),
        Index("ix_tmo_ws_inc", "workspace_id", "incident_id"),
    )


class ThreatMemoryDecisionModel(Base):
    """
    Durable human analyst validation, false-positive labeling, and suppression decisions (Section 23).
    VERIFIED_MALICIOUS, VERIFIED_BENIGN, FALSE_POSITIVE, NEEDS_REVIEW, SUPPRESSED, ESCALATED.
    """
    __tablename__ = "threat_memory_decisions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    memory_entry_id = Column(String(36), ForeignKey("threat_memory_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    decision = Column(String(50), nullable=False, index=True)
    reason = Column(String(500), nullable=False)
    approved_by = Column(String(100), nullable=False, index=True)
    scope = Column(String(50), nullable=False, default="ORGANIZATION")
    valid_from = Column(DateTime, default=get_utc_now, nullable=False)
    valid_until = Column(DateTime, nullable=True, index=True)
    evidence_ids_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    memory_entry = relationship("ThreatMemoryEntryModel", back_populates="decisions")

    __table_args__ = (
        Index("ix_tmd_entry_decision", "memory_entry_id", "decision"),
        Index("ix_tmd_ws_approved", "workspace_id", "approved_by"),
    )


class ThreatMemoryRelationshipModel(Base):
    """
    Cross-memory association edges (Section 23).
    Links historical entities, domains, IPs, campaigns, and false-positive patterns.
    """
    __tablename__ = "threat_memory_relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    source_memory_id = Column(String(36), ForeignKey("threat_memory_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    target_memory_id = Column(String(36), ForeignKey("threat_memory_entries.id", ondelete="CASCADE"), nullable=False, index=True)
    relationship_type = Column(String(50), nullable=False, index=True)  # ASSOCIATED_WITH, RESOLVES_TO, HOSTED_ON, PART_OF, etc.
    confidence = Column(Float, nullable=False, default=1.0)
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    evidence_references_json = Column(Text, default="[]", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    source_memory = relationship("ThreatMemoryEntryModel", foreign_keys=[source_memory_id])
    target_memory = relationship("ThreatMemoryEntryModel", foreign_keys=[target_memory_id])

    __table_args__ = (
        Index("ix_tmr_src_tgt", "source_memory_id", "target_memory_id", "relationship_type", unique=True),
        Index("ix_tmr_ws_type", "workspace_id", "relationship_type"),
    )


# ============================================================================
# Section 24: Controlled Continual-Learning Models
# ============================================================================

class LearningCandidateModel(Base):
    """
    Curated candidate for model learning derived from verified observations,
    hard negatives, and analyst feedback (Section 24).
    """
    __tablename__ = "learning_candidates"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    source_type = Column(String(50), nullable=False, index=True)  # THREAT_MEMORY, INCIDENT, ANALYSIS_RUN, EXTERNAL_FEED
    source_reference = Column(String(255), nullable=False, index=True)
    feature_reference = Column(String(255), nullable=True)
    text_content = Column(Text, nullable=True)
    label = Column(String(50), nullable=False, index=True)  # phishing, legitimate, etc.
    label_source = Column(String(50), nullable=False, index=True)  # ANALYST_VERIFIED, RULE_VERIFIED, etc.
    confidence = Column(Float, nullable=False, default=1.0)
    is_hard_negative = Column(Boolean, nullable=False, default=False)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    observed_at = Column(DateTime, default=get_utc_now, nullable=False)
    eligibility_status = Column(String(30), nullable=False, default="ELIGIBLE", index=True)  # ELIGIBLE, INELIGIBLE, EXCLUDED, REVIEW_REQUIRED
    ineligibility_reason = Column(String(255), nullable=True)
    review_status = Column(String(30), nullable=False, default="PENDING", index=True)  # PENDING, REVIEWED, ACCEPTED, REJECTED, DEFERRED
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_reason = Column(String(500), nullable=True)
    dataset_version = Column(String(50), nullable=True, index=True)
    raw_payload_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_lc_ws_elig", "workspace_id", "eligibility_status"),
        Index("ix_lc_ws_review", "workspace_id", "review_status"),
        Index("ix_lc_ws_dataset", "workspace_id", "dataset_version"),
    )

    @property
    def raw_payload(self) -> Dict[str, Any]:
        return json.loads(self.raw_payload_json or "{}")


class LearningDatasetModel(Base):
    """
    Immutable versioned training dataset snapshot with cryptographic integrity (Section 24).
    """
    __tablename__ = "learning_datasets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    version = Column(String(50), nullable=False, index=True)  # e.g. D-001, D-025
    feature_schema_version = Column(String(32), nullable=False, default="1.0.0")
    label_policy_version = Column(String(32), nullable=False, default="1.0.0")
    sample_count = Column(Integer, nullable=False, default=0)
    malicious_count = Column(Integer, nullable=False, default=0)
    benign_count = Column(Integer, nullable=False, default=0)
    hard_negative_count = Column(Integer, nullable=False, default=0)
    source_distribution_json = Column(Text, default="{}", nullable=False)
    time_range_start = Column(DateTime, nullable=True)
    time_range_end = Column(DateTime, nullable=True)
    quality_score = Column(Float, nullable=False, default=1.0)
    validation_status = Column(String(30), nullable=False, default="VALIDATED", index=True)  # COLLECTING, VALIDATED, REJECTED, ARCHIVED
    validation_errors_json = Column(Text, default="[]", nullable=False)
    manifest_checksum = Column(String(64), nullable=False)
    created_by = Column(String(100), nullable=False, default="system")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_ld_ws_ver", "workspace_id", "version", unique=True),
        Index("ix_ld_ws_status", "workspace_id", "validation_status"),
    )

    @property
    def source_distribution(self) -> Dict[str, Any]:
        return json.loads(self.source_distribution_json or "{}")

    @property
    def validation_errors(self) -> List[str]:
        return json.loads(self.validation_errors_json or "[]")


class LearningTrainingJobModel(Base):
    """
    Asynchronous training and offline evaluation job records (Section 24).
    """
    __tablename__ = "learning_training_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    model_type = Column(String(50), nullable=False, default="PHISHING_CLASSIFIER", index=True)
    dataset_version = Column(String(50), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="QUEUED", index=True)  # QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED, REJECTED
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    base_model_version = Column(String(50), nullable=True)
    candidate_model_version = Column(String(50), nullable=True)
    training_config_json = Column(Text, default="{}", nullable=False)
    metrics_json = Column(Text, default="{}", nullable=False)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_ltj_ws_status", "workspace_id", "status"),
        Index("ix_ltj_ws_dataset", "workspace_id", "dataset_version"),
    )

    @property
    def training_config(self) -> Dict[str, Any]:
        return json.loads(self.training_config_json or "{}")

    @property
    def metrics(self) -> Dict[str, Any]:
        return json.loads(self.metrics_json or "{}")


class RegisteredModelModel(Base):
    """
    Model Registry entry managing candidate, staged, and production model artifacts (Section 24).
    """
    __tablename__ = "registered_models"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    model_type = Column(String(50), nullable=False, default="PHISHING_CLASSIFIER", index=True)
    version = Column(String(50), nullable=False, index=True)  # e.g. phishing-v1, phishing-v13
    dataset_version = Column(String(50), nullable=False, index=True)
    feature_schema_version = Column(String(32), nullable=False, default="1.0.0")
    training_job_id = Column(String(36), nullable=True)
    status = Column(String(30), nullable=False, default="CANDIDATE", index=True)  # CANDIDATE, APPROVED, STAGED, PRODUCTION, ROLLED_BACK, ARCHIVED, REJECTED
    metrics_json = Column(Text, default="{}", nullable=False)
    baseline_comparison_json = Column(Text, default="{}", nullable=False)
    artifact_path = Column(String(500), nullable=False)
    artifact_checksum = Column(String(64), nullable=False)
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    staged_at = Column(DateTime, nullable=True)
    promoted_at = Column(DateTime, nullable=True)
    rolled_back_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_rm_ws_type_ver", "workspace_id", "model_type", "version", unique=True),
        Index("ix_rm_ws_status", "workspace_id", "model_type", "status"),
    )

    @property
    def metrics(self) -> Dict[str, Any]:
        return json.loads(self.metrics_json or "{}")

    @property
    def baseline_comparison(self) -> Dict[str, Any]:
        return json.loads(self.baseline_comparison_json or "{}")


# ============================================================================
# Section 25: Emerging Pattern & Candidate Rule Models
# ============================================================================

class CandidateRuleModel(Base):
    """
    Candidate detection rule synthesized from validated emerging patterns,
    correlations, Threat Memory, and proactive threat hunts (Section 25 & Section 56).
    """
    __tablename__ = "candidate_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    rule_identifier = Column(String(64), nullable=True, index=True)  # e.g. RULE-101, PHISH-001
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False, default="")
    rule_type = Column(String(50), nullable=False, default="STRUCTURAL", index=True)  # INDICATOR, STRUCTURAL, BEHAVIORAL, etc.
    category = Column(String(50), nullable=False, default="PHISHING", index=True)  # EMAIL, PHISHING, URL, DOMAIN, ATTACHMENT, IDENTITY, AUTHENTICATION, ENDPOINT, NETWORK, API, BEHAVIORAL, INFRASTRUCTURE, CAMPAIGN, CORRELATION, ANOMALY
    status = Column(String(30), nullable=False, default="DRAFT", index=True)  # DRAFT, CANDIDATE, VALIDATING, PENDING_REVIEW, APPROVED, STAGED, ACTIVE, DISABLED, DEPRECATED, ARCHIVED, REJECTED, DISCOVERED, TESTED, RETIRED, SUPERSEDED
    pattern_candidate_id = Column(String(36), ForeignKey("emerging_pattern_candidates.id", ondelete="SET NULL"), nullable=True, index=True)
    
    # Provenance tracking (Section 26 & Section 56)
    provenance_type = Column(String(50), nullable=False, default="ANALYST_CREATED", index=True)  # HUNT, INVESTIGATION, FINDING, THREAT_INTELLIGENCE, ANALYST_CREATED, SYSTEM_PROPOSED, CAMPAIGN, WATCHLIST
    provenance_id = Column(String(128), nullable=True, index=True)
    provenance_details_json = Column(Text, default="{}", nullable=False)
    source_memory_ids_json = Column(Text, default="[]", nullable=False)
    source_incident_ids_json = Column(Text, default="[]", nullable=False)

    # Rule definition & data dependencies
    definition_json = Column(Text, default="{}", nullable=False)
    data_sources_json = Column(Text, default="[]", nullable=False)
    thresholds_json = Column(Text, default="{}", nullable=False)
    time_window_seconds = Column(Integer, nullable=True)
    scope = Column(String(30), nullable=False, default="GLOBAL", index=True)  # EMAIL, URL, AUTH, NETWORK, API, FILE, MEDIA, GLOBAL
    severity = Column(String(20), nullable=False, default="MEDIUM")  # INFORMATIONAL, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False, default=0.8)
    generalization_level = Column(String(30), nullable=False, default="STRUCTURAL")  # EXACT, STRUCTURAL, BEHAVIORAL, etc.
    complexity_score = Column(Float, nullable=False, default=1.0)
    cost_class = Column(String(20), nullable=False, default="LOW", index=True)  # LOW, MEDIUM, HIGH, UNSUPPORTED
    normalized_fingerprint = Column(String(64), nullable=False, index=True)
    version = Column(String(20), nullable=False, default="v1", index=True)
    tags_json = Column(Text, default="[]", nullable=False)
    attack_techniques_json = Column(Text, default="[]", nullable=False)  # MITRE ATT&CK techniques e.g. ["T1566.002"]
    is_system_rule = Column(Boolean, nullable=False, default=False, index=True)

    # Lifecycle timestamps & audit
    evaluation_summary_json = Column(Text, default="{}", nullable=False)
    staged_at = Column(DateTime, nullable=True)
    activated_at = Column(DateTime, nullable=True)
    disabled_at = Column(DateTime, nullable=True)
    retired_at = Column(DateTime, nullable=True)
    created_by = Column(String(100), nullable=False, default="analyst")
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_reason = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Section 57: Detection Rule Management & Operational Control
    owner_id = Column(String(100), nullable=False, default="analyst", index=True)
    team_id = Column(String(100), nullable=True, index=True)
    last_editor_id = Column(String(100), nullable=True)
    deployment_state = Column(String(30), nullable=False, default="DRAFT", index=True)  # DRAFT, STAGING, PRODUCTION, DISABLED
    operational_health = Column(String(30), nullable=False, default="HEALTHY", index=True)  # HEALTHY, DEGRADED, FAILING, UNKNOWN
    health_reason = Column(String(500), nullable=True)
    health_updated_at = Column(DateTime, nullable=True)
    review_interval_days = Column(Integer, nullable=False, default=90)
    next_review_due = Column(DateTime, nullable=True, index=True)
    last_reviewed_at = Column(DateTime, nullable=True)
    dependencies_json = Column(Text, default="[]", nullable=False)
    collections_json = Column(Text, default="[]", nullable=False)
    replaced_by_rule_id = Column(String(36), ForeignKey("candidate_rules.id", ondelete="SET NULL"), nullable=True)
    last_matched_at = Column(DateTime, nullable=True, index=True)
    total_match_count = Column(Integer, nullable=False, default=0)

    # Section 58: Automated Detection Validation & Continuous Rule Quality
    last_validation_run_id = Column(String(36), nullable=True)
    validation_status = Column(String(30), nullable=False, default="NOT_RUN", index=True)  # NOT_RUN, QUEUED, RUNNING, PASS, PASS_WITH_WARNINGS, FAIL, BLOCKED, CANCELLED, TIMED_OUT, STALE
    validation_updated_at = Column(DateTime, nullable=True)

    versions = relationship("CandidateRuleVersionModel", back_populates="rule", cascade="all, delete-orphan", lazy="selectin", foreign_keys="[CandidateRuleVersionModel.rule_id]")
    executions = relationship("CandidateRuleExecutionModel", back_populates="rule", cascade="all, delete-orphan", lazy="selectin", foreign_keys="[CandidateRuleExecutionModel.rule_id]")
    suppressions = relationship("RuleSuppressionModel", back_populates="rule", cascade="all, delete-orphan", lazy="selectin", foreign_keys="[RuleSuppressionModel.rule_id]")
    validation_runs = relationship("DetectionValidationRunModel", back_populates="rule", cascade="all, delete-orphan", lazy="selectin", foreign_keys="[DetectionValidationRunModel.rule_id]")
    fixtures = relationship("DetectionRuleTestFixtureModel", back_populates="rule", cascade="all, delete-orphan", lazy="selectin", foreign_keys="[DetectionRuleTestFixtureModel.rule_id]")
    matches = relationship("DetectionMatchModel", back_populates="rule", cascade="all, delete-orphan", lazy="selectin", foreign_keys="[DetectionMatchModel.rule_id]")

    __table_args__ = (
        Index("ix_cr_ws_status", "workspace_id", "status"),
        Index("ix_cr_ws_scope", "workspace_id", "scope"),
        Index("ix_cr_ws_cat", "workspace_id", "category"),
        Index("ix_cr_ws_fp", "workspace_id", "normalized_fingerprint"),
        Index("ix_cr_ws_ident", "workspace_id", "rule_identifier"),
        Index("ix_cr_ws_depstate", "workspace_id", "deployment_state"),
        Index("ix_cr_ws_health", "workspace_id", "operational_health"),
        Index("ix_cr_ws_owner", "workspace_id", "owner_id"),
        Index("ix_cr_ws_valstatus", "workspace_id", "validation_status"),
    )

    @property
    def source_memory_ids(self) -> List[str]:
        return json.loads(self.source_memory_ids_json or "[]")

    @property
    def source_incident_ids(self) -> List[str]:
        return json.loads(self.source_incident_ids_json or "[]")

    @property
    def definition(self) -> Dict[str, Any]:
        return json.loads(self.definition_json or "{}")

    @definition.setter
    def definition(self, val: Any) -> None:
        self.definition_json = json.dumps(val) if isinstance(val, (dict, list)) else (val or "{}")

    @property
    def thresholds(self) -> Dict[str, Any]:
        return json.loads(self.thresholds_json or "{}")

    @property
    def evaluation_summary(self) -> Dict[str, Any]:
        return json.loads(self.evaluation_summary_json or "{}")

    @property
    def data_sources(self) -> List[str]:
        return json.loads(self.data_sources_json or "[]")

    @property
    def tags(self) -> List[str]:
        return json.loads(self.tags_json or "[]")

    @property
    def attack_techniques(self) -> List[str]:
        return json.loads(self.attack_techniques_json or "[]")

    @property
    def provenance_details(self) -> Dict[str, Any]:
        return json.loads(self.provenance_details_json or "{}")

    @property
    def dependencies(self) -> List[Dict[str, Any]]:
        return json.loads(self.dependencies_json or "[]")

    @property
    def collections(self) -> List[str]:
        return json.loads(self.collections_json or "[]")



class CandidateRuleVersionModel(Base):
    """
    Immutable version history for candidate and production detection rules (Section 25 & 56).
    """
    __tablename__ = "candidate_rule_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(36), ForeignKey("candidate_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    candidate_rule_id = synonym("rule_id")
    version = Column(String(20), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    definition_json = Column(Text, default="{}", nullable=False)
    data_sources_json = Column(Text, default="[]", nullable=False)
    thresholds_json = Column(Text, default="{}", nullable=False)
    diff_summary_json = Column(Text, default="{}", nullable=False)
    cost_class = Column(String(20), nullable=False, default="LOW")
    evaluation_summary_json = Column(Text, default="{}", nullable=False)
    status = Column(String(30), nullable=False, default="DRAFT")
    created_by = Column(String(100), nullable=False, default="analyst")
    reviewed_by = Column(String(100), nullable=True)
    change_reason = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    rule = relationship("CandidateRuleModel", back_populates="versions")

    __table_args__ = (
        Index("ix_crv_rule_ver", "rule_id", "version", unique=True),
    )

    @property
    def definition(self) -> Dict[str, Any]:
        return json.loads(self.definition_json or "{}")

    @definition.setter
    def definition(self, val: Any) -> None:
        self.definition_json = json.dumps(val) if isinstance(val, (dict, list)) else (val or "{}")

    @property
    def thresholds(self) -> Dict[str, Any]:
        return json.loads(self.thresholds_json or "{}")

    @property
    def evaluation_summary(self) -> Dict[str, Any]:
        return json.loads(self.evaluation_summary_json or "{}")

    @property
    def data_sources(self) -> List[str]:
        return json.loads(self.data_sources_json or "[]")

    @property
    def diff_summary(self) -> Dict[str, Any]:
        return json.loads(self.diff_summary_json or "{}")


class CandidateRuleExecutionModel(Base):
    """
    Telemetry log for candidate and active rule executions, backtests, and shadow evaluations (Section 25 & 56).
    """
    __tablename__ = "candidate_rule_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_id = Column(String(36), ForeignKey("candidate_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    candidate_rule_id = synonym("rule_id")
    rule_version = Column(String(20), nullable=False)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    mode = Column(String(20), nullable=False, default="SHADOW", index=True)  # SHADOW, PRODUCTION, BACKTEST
    matched = Column(Boolean, nullable=False, default=False, index=True)
    matched_conditions_json = Column(Text, default="[]", nullable=False)
    match_explanation_json = Column(Text, default="{}", nullable=False)
    detection_id = Column(String(64), nullable=True, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    event_id = Column(String(36), nullable=True, index=True)
    incident_id = Column(String(36), nullable=True, index=True)
    execution_time_ms = Column(Float, nullable=False, default=0.0)
    is_false_positive = Column(Boolean, nullable=True)
    feedback_reason = Column(String(255), nullable=True)
    disposition = Column(String(30), nullable=True, index=True)  # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN, EXPECTED_ACTIVITY, NEEDS_REVIEW
    disposition_by = Column(String(100), nullable=True)
    disposition_at = Column(DateTime, nullable=True)
    disposition_notes = Column(String(500), nullable=True)
    suppression_applied_id = Column(String(36), nullable=True)
    executed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    rule = relationship("CandidateRuleModel", back_populates="executions", foreign_keys=[rule_id])

    __table_args__ = (
        Index("ix_cre_ws_mode_matched", "workspace_id", "mode", "matched"),
        Index("ix_cre_executed_at", "executed_at"),
        Index("ix_cre_detection_id", "detection_id"),
        Index("ix_cre_disposition", "disposition"),
    )

    @property
    def matched_conditions(self) -> List[Dict[str, Any]]:
        return json.loads(self.matched_conditions_json or "[]")

    @property
    def match_explanation(self) -> Dict[str, Any]:
        return json.loads(self.match_explanation_json or "{}")


class RuleSuppressionModel(Base):
    """
    Section 57: Controlled suppression exception rule for detection rules.
    Allows time-bounded, scoped false-positive suppression without disabling rules.
    """
    __tablename__ = "rule_suppressions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    rule_id = Column(String(36), ForeignKey("candidate_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    reason = Column(String(500), nullable=False)
    scope_type = Column(String(50), nullable=False, default="ENTITY")  # ENTITY, FIELD, CONDITION, SOURCE, ENVIRONMENT, GLOBAL
    scope_target = Column(String(100), nullable=False)  # e.g. "sender_domain", "ip_address", "recipient", "subject"
    match_value = Column(String(255), nullable=False)  # e.g. "internal-scanner.corp", "10.0.0.1"
    match_operator = Column(String(30), nullable=False, default="EQUALS")  # EQUALS, CONTAINS, ENDS_WITH, REGEX
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    created_by = Column(String(100), nullable=False, default="analyst")
    approved_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    rule = relationship("CandidateRuleModel", back_populates="suppressions", foreign_keys=[rule_id])

    __table_args__ = (
        Index("ix_rs_ws_rule_active", "workspace_id", "rule_id", "is_active"),
        Index("ix_rs_expires_at", "expires_at"),
    )


# ============================================================================
# SECTION 58: AUTOMATED DETECTION VALIDATION & CONTINUOUS RULE QUALITY MODELS
# ============================================================================

class DetectionValidationRunModel(Base):
    """
    Section 58: Persistent validation run record for candidate and production detection rules.
    Tracks multi-dimensional validation lifecycle, baseline comparison, gate results, and freshness.
    """
    __tablename__ = "detection_validation_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    rule_id = Column(String(36), ForeignKey("candidate_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_version_id = Column(String(36), ForeignKey("candidate_rule_versions.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_version = Column(String(20), nullable=False, default="v1", index=True)
    validation_type = Column(String(50), nullable=False, default="FULL", index=True)  # FULL, STRUCTURAL, DEPENDENCY, DATA_COMPATIBILITY, EXECUTION, REGRESSION, PERFORMANCE, BEHAVIOR, FIXTURES, CONTINUOUS, GATE_CHECK
    status = Column(String(30), nullable=False, default="NOT_RUN", index=True)  # NOT_RUN, QUEUED, RUNNING, PASS, PASS_WITH_WARNINGS, FAIL, BLOCKED, CANCELLED, TIMED_OUT, STALE
    trigger_type = Column(String(50), nullable=False, default="MANUAL", index=True)  # MANUAL, SCHEDULED, CONTINUOUS, VERSION_CREATED, DEPLOYMENT_GATE, SCHEMA_CHANGE, DEPENDENCY_CHANGE, HEALTH_DEGRADED
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    requested_by = Column(String(100), nullable=False, default="analyst")
    executed_by = Column(String(100), nullable=True)
    job_id = Column(String(36), nullable=True, index=True)
    idempotency_key = Column(String(128), nullable=True, index=True)
    baseline_run_id = Column(String(36), ForeignKey("detection_validation_runs.id", ondelete="SET NULL"), nullable=True)
    baseline_rule_version = Column(String(20), nullable=True)
    data_window_start = Column(DateTime, nullable=True)
    data_window_end = Column(DateTime, nullable=True)
    is_stale = Column(Boolean, nullable=False, default=False, index=True)
    stale_reason = Column(String(255), nullable=True)
    summary_json = Column(Text, default="{}", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    rule = relationship("CandidateRuleModel", back_populates="validation_runs", foreign_keys=[rule_id])
    results = relationship("DetectionValidationResultModel", back_populates="run", cascade="all, delete-orphan", lazy="selectin", foreign_keys="[DetectionValidationResultModel.run_id]")

    __table_args__ = (
        Index("ix_dvr_ws_rule_status", "workspace_id", "rule_id", "status"),
        Index("ix_dvr_rule_ver", "rule_id", "rule_version"),
        Index("ix_dvr_created_at", "created_at"),
        Index("ix_dvr_idempotency", "workspace_id", "idempotency_key"),
    )

    @property
    def summary(self) -> Dict[str, Any]:
        return json.loads(self.summary_json or "{}")

    @property
    def metadata_dict(self) -> Dict[str, Any]:
        return json.loads(self.metadata_json or "{}")


class DetectionValidationResultModel(Base):
    """
    Section 58: Structured, evidence-backed individual validation check result.
    Covers STRUCTURAL, DEPENDENCY, DATA_COMPATIBILITY, EXECUTION, REGRESSION, PERFORMANCE, BEHAVIOR, FIXTURE, OPERATIONAL.
    """
    __tablename__ = "detection_validation_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    run_id = Column(String(36), ForeignKey("detection_validation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    rule_id = Column(String(36), nullable=False, index=True)
    category = Column(String(50), nullable=False, index=True)  # STRUCTURAL, DEPENDENCY, DATA_COMPATIBILITY, EXECUTION, REGRESSION, PERFORMANCE, BEHAVIOR, FIXTURE, OPERATIONAL
    status = Column(String(30), nullable=False, default="PASS", index=True)  # PASS, PASS_WITH_WARNINGS, FAIL, BLOCKED, NOT_RUN, SKIPPED
    severity = Column(String(20), nullable=False, default="INFO")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    code = Column(String(100), nullable=False, index=True)
    message = Column(String(500), nullable=False)
    observed_value_json = Column(Text, default="{}", nullable=False)
    expected_value_json = Column(Text, default="{}", nullable=False)
    baseline_value_json = Column(Text, default="{}", nullable=False)
    evidence_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    run = relationship("DetectionValidationRunModel", back_populates="results", foreign_keys=[run_id])

    __table_args__ = (
        Index("ix_dvres_run_category", "run_id", "category"),
        Index("ix_dvres_status", "status"),
    )

    @property
    def observed_value(self) -> Any:
        try:
            return json.loads(self.observed_value_json or "{}")
        except Exception:
            return {}

    @property
    def expected_value(self) -> Any:
        try:
            return json.loads(self.expected_value_json or "{}")
        except Exception:
            return {}

    @property
    def baseline_value(self) -> Any:
        try:
            return json.loads(self.baseline_value_json or "{}")
        except Exception:
            return {}

    @property
    def evidence(self) -> Any:
        try:
            return json.loads(self.evidence_json or "{}")
        except Exception:
            return {}


class DetectionRuleTestFixtureModel(Base):
    """
    Section 58: Controlled deterministic positive and negative test fixtures for detection rules.
    Enables reproducible continuous behavioral validation without fabricating synthetic production events.
    """
    __tablename__ = "detection_rule_fixtures"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    rule_id = Column(String(36), ForeignKey("candidate_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(String(500), nullable=False, default="")
    fixture_type = Column(String(20), nullable=False, default="POSITIVE", index=True)  # POSITIVE, NEGATIVE
    payload_json = Column(Text, default="{}", nullable=False)
    expected_match = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    last_run_at = Column(DateTime, nullable=True)
    last_result = Column(String(20), nullable=True)  # PASS, FAIL, BLOCKED
    last_error = Column(String(500), nullable=True)
    created_by = Column(String(100), nullable=False, default="analyst")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    rule = relationship("CandidateRuleModel", back_populates="fixtures", foreign_keys=[rule_id])

    __table_args__ = (
        Index("ix_drf_ws_rule_active", "workspace_id", "rule_id", "is_active"),
    )

    @property
    def payload(self) -> Dict[str, Any]:
        return json.loads(self.payload_json or "{}")


# ============================================================================
# UNIFIED RISK ENGINE MODELS (SECTION 26)
# ============================================================================

class RiskAssessmentModel(Base):
    """
    Centralized, deterministic, versioned risk-assessment layer (Section 26).
    Combines signals from all detection and intelligence systems into a unified
    reproducible assessment at EVENT, INVESTIGATION, or INCIDENT scopes.
    """
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    scope_type = Column(String(30), nullable=False, default="EVENT", index=True)  # EVENT, INVESTIGATION, INCIDENT, CAMPAIGN, ENTITY
    scope_id = Column(String(128), nullable=False, index=True)
    threat_event_id = Column(String(36), ForeignKey("threat_events.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(36), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    risk_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0
    risk_level = Column(String(20), nullable=False, default="INFO")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    severity = Column(String(20), nullable=False, default="MEDIUM")  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False, default=1.0)  # 0.0 - 1.0
    confidence_level = Column(String(20), nullable=False, default="HIGH")  # LOW, MODERATE, HIGH, VERY_HIGH
    uncertainty = Column(String(20), nullable=False, default="LOW")  # LOW, MEDIUM, HIGH
    uncertainty_score = Column(Float, nullable=False, default=0.0)
    version = Column(Integer, nullable=False, default=1)
    status = Column(String(30), nullable=False, default="CURRENT", index=True)  # CURRENT, SUPERSEDED, HISTORICAL
    parent_assessment_id = Column(String(36), ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True, index=True)
    aggregation_version = Column(String(32), nullable=False, default="1.0.0")
    configuration_version = Column(String(32), nullable=False, default="1.0.0")
    components_json = Column(Text, default="[]", nullable=False)
    signals_json = Column(Text, default="[]", nullable=False)
    evidence_refs_json = Column(Text, default="[]", nullable=False)
    counter_evidence_refs_json = Column(Text, default="[]", nullable=False)
    contradictions_json = Column(Text, default="[]", nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    contextual_factors_json = Column(Text, default="{}", nullable=False)
    explanation_summary = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=False, default="system")
    reassessment_reason = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    evaluated_at = Column(DateTime, default=get_utc_now, nullable=False)

    signals = relationship("RiskSignalModel", back_populates="assessment", cascade="all, delete-orphan", lazy="selectin")
    incident = relationship("IncidentModel", back_populates="risk_assessments", foreign_keys=[incident_id])
    analysis_run = relationship("AnalysisRunModel", foreign_keys=[analysis_run_id])
    parent_assessment = relationship("RiskAssessmentModel", remote_side=[id])
    explanations = relationship("ExplanationModel", back_populates="risk_assessment", cascade="all, delete-orphan", lazy="selectin")
    recommendations = relationship("ResponseRecommendationModel", back_populates="risk_assessment", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_ra_ws_scope", "workspace_id", "scope_type", "scope_id"),
        Index("ix_ra_score", "workspace_id", "risk_score"),
        Index("ix_ra_status", "workspace_id", "status"),
    )

    @property
    def components(self) -> List[Dict[str, Any]]:
        return json.loads(self.components_json or "[]")

    @property
    def raw_signals(self) -> List[Dict[str, Any]]:
        return json.loads(self.signals_json or "[]")

    @property
    def evidence_refs(self) -> List[str]:
        return json.loads(self.evidence_refs_json or "[]")

    @property
    def counter_evidence_refs(self) -> List[str]:
        return json.loads(self.counter_evidence_refs_json or "[]")

    @property
    def contradictions(self) -> List[Dict[str, Any]]:
        return json.loads(self.contradictions_json or "[]")

    @property
    def limitations(self) -> List[str]:
        return json.loads(self.limitations_json or "[]")

    @property
    def contextual_factors(self) -> Dict[str, Any]:
        return json.loads(self.contextual_factors_json or "{}")


class RiskSignalModel(Base):
    """
    Structured normalized risk signal input feeding into RiskAssessment (Section 26).
    Preserves exact origin, detector version, reliability factor, and correlation group.
    """
    __tablename__ = "risk_signals"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    assessment_id = Column(String(36), ForeignKey("risk_assessments.id", ondelete="CASCADE"), nullable=False, index=True)
    signal_type = Column(String(100), nullable=False, index=True)
    source_type = Column(String(50), nullable=False, index=True)
    detector_id = Column(String(100), nullable=False, index=True)
    detector_version = Column(String(50), nullable=False, default="1.0.0")
    evidence_family = Column(String(50), nullable=False, index=True)
    semantics = Column(String(50), nullable=False, default="THREAT_SCORE")
    direction = Column(String(30), nullable=False, default="SUPPORTING", index=True)  # SUPPORTING, COUNTER, CONTRADICTORY
    raw_score = Column(Float, nullable=False, default=0.0)
    normalized_score = Column(Float, nullable=False, default=0.0)
    reliability = Column(Float, nullable=False, default=1.0)
    weight = Column(Float, nullable=False, default=1.0)
    contribution = Column(Float, nullable=False, default=0.0)
    correlation_group = Column(String(255), nullable=True, index=True)
    evidence_refs_json = Column(Text, default="[]", nullable=False)
    provenance_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    assessment = relationship("RiskAssessmentModel", back_populates="signals")

    __table_args__ = (
        Index("ix_rs_fam_corr", "evidence_family", "correlation_group"),
    )

    @property
    def evidence_refs(self) -> List[str]:
        return json.loads(self.evidence_refs_json or "[]")

    @property
    def provenance(self) -> Dict[str, Any]:
        return json.loads(self.provenance_json or "{}")


class RiskConfigurationModel(Base):
    """
    Versioned, auditable risk configuration storage (Section 26).
    Enforces governance: changes require authorization and audit trail.
    """
    __tablename__ = "risk_configurations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    version = Column(String(32), nullable=False, index=True)
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, DRAFT, RETIRED
    thresholds_json = Column(Text, default="{}", nullable=False)
    confidence_levels_json = Column(Text, default="{}", nullable=False)
    uncertainty_levels_json = Column(Text, default="{}", nullable=False)
    family_caps_json = Column(Text, default="{}", nullable=False)
    family_weights_json = Column(Text, default="{}", nullable=False)
    correlation_discount_schedule_json = Column(Text, default="[]", nullable=False)
    reliability_defaults_json = Column(Text, default="{}", nullable=False)
    contextual_modifiers_json = Column(Text, default="{}", nullable=False)
    severity_rules_json = Column(Text, default="{}", nullable=False)
    created_by = Column(String(100), nullable=False, default="admin")
    description = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_rc_ws_ver", "workspace_id", "version", unique=True),
    )

    @property
    def thresholds(self) -> Dict[str, Any]:
        return json.loads(self.thresholds_json or "{}")

    @property
    def family_caps(self) -> Dict[str, Any]:
        return json.loads(self.family_caps_json or "{}")

    @property
    def family_weights(self) -> Dict[str, Any]:
        return json.loads(self.family_weights_json or "{}")

    @property
    def correlation_discount_schedule(self) -> List[float]:
        return json.loads(self.correlation_discount_schedule_json or "[]")

    @property
    def contextual_modifiers(self) -> Dict[str, Any]:
        return json.loads(self.contextual_modifiers_json or "{}")


# ============================================================================
# Section 27: Explainable AI (XAI) Models
# ============================================================================

class ExplanationModel(Base):
    """
    Centralized Explainable AI (XAI) model (Section 27).
    Converts CyberGuard's structured detection, intelligence, correlation, risk,
    and attack-reconstruction outputs into traceable, evidence-backed explanations.
    """
    __tablename__ = "explanations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    scope_type = Column(String(30), nullable=False, default="EVENT", index=True)  # EVENT, INVESTIGATION, INCIDENT, CAMPAIGN, ENTITY, ATTACK_PATH, STAGE
    scope_id = Column(String(128), nullable=False, index=True)
    risk_assessment_id = Column(String(36), ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    threat_event_id = Column(String(36), ForeignKey("threat_events.id", ondelete="SET NULL"), nullable=True, index=True)

    explanation_version = Column(Integer, nullable=False, default=1)
    status = Column(String(30), nullable=False, default="CURRENT", index=True)  # CURRENT, SUPERSEDED, ARCHIVED
    parent_explanation_id = Column(String(36), ForeignKey("explanations.id", ondelete="SET NULL"), nullable=True, index=True)

    # Narrative and summaries
    summary = Column(Text, nullable=False)
    executive_summary = Column(Text, nullable=True)
    analyst_summary = Column(Text, nullable=True)
    generated_text = Column(Text, nullable=True)

    # Structured explanation fields (JSON-encoded)
    conclusions_json = Column(Text, default="[]", nullable=False)
    explanation_units_json = Column(Text, default="[]", nullable=False)
    evidence_groups_json = Column(Text, default="[]", nullable=False)
    contributors_json = Column(Text, default="[]", nullable=False)
    counter_evidence_json = Column(Text, default="[]", nullable=False)
    contradictions_json = Column(Text, default="[]", nullable=False)
    uncertainty_json = Column(Text, default="[]", nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    missing_information_json = Column(Text, default="[]", nullable=False)
    causal_links_json = Column(Text, default="[]", nullable=False)
    detector_contributions_json = Column(Text, default="[]", nullable=False)
    model_contributions_json = Column(Text, default="[]", nullable=False)
    rule_contributions_json = Column(Text, default="[]", nullable=False)
    mitre_explanations_json = Column(Text, default="[]", nullable=False)
    attack_path_explanation_json = Column(Text, default="{}", nullable=False)
    novelty_explanation_json = Column(Text, default="{}", nullable=False)
    behavioral_explanation_json = Column(Text, default="{}", nullable=False)
    threat_memory_explanation_json = Column(Text, default="{}", nullable=False)
    assessment_change_guidance_json = Column(Text, default="{}", nullable=False)
    evidence_graph_json = Column(Text, default="{}", nullable=False)

    # Progressive disclosure levels
    investigator_details_json = Column(Text, default="{}", nullable=False)
    forensic_details_json = Column(Text, default="{}", nullable=False)

    # Quality, Validation & Provenance
    validation_status = Column(String(30), nullable=False, default="VALIDATED", index=True)  # VALIDATED, FALLBACK, REJECTED
    validation_details_json = Column(Text, default="{}", nullable=False)
    source_snapshot_json = Column(Text, default="{}", nullable=False)
    provenance_json = Column(Text, default="{}", nullable=False)

    created_by = Column(String(100), nullable=False, default="system")
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    risk_assessment = relationship("RiskAssessmentModel", back_populates="explanations")
    incident = relationship("IncidentModel", foreign_keys=[incident_id])
    threat_event = relationship("ThreatEventModel", foreign_keys=[threat_event_id])
    parent_explanation = relationship("ExplanationModel", remote_side=[id])
    snapshots = relationship("ExplanationSnapshotModel", back_populates="explanation", cascade="all, delete-orphan", lazy="selectin")
    feedbacks = relationship("ExplanationFeedbackModel", back_populates="explanation", cascade="all, delete-orphan", lazy="selectin")
    recommendations = relationship("ResponseRecommendationModel", back_populates="explanation", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_expl_ws_scope", "workspace_id", "scope_type", "scope_id"),
        Index("ix_expl_ws_status", "workspace_id", "status"),
        Index("ix_expl_ws_val", "workspace_id", "validation_status"),
    )

    @property
    def conclusions(self) -> List[Dict[str, Any]]:
        return json.loads(self.conclusions_json or "[]")

    @property
    def explanation_units(self) -> List[Dict[str, Any]]:
        return json.loads(self.explanation_units_json or "[]")

    @property
    def evidence_groups(self) -> List[Dict[str, Any]]:
        return json.loads(self.evidence_groups_json or "[]")

    @property
    def contributors(self) -> List[Dict[str, Any]]:
        return json.loads(self.contributors_json or "[]")

    @property
    def counter_evidence(self) -> List[Dict[str, Any]]:
        return json.loads(self.counter_evidence_json or "[]")

    @property
    def contradictions(self) -> List[Dict[str, Any]]:
        return json.loads(self.contradictions_json or "[]")

    @property
    def uncertainty(self) -> List[Dict[str, Any]]:
        return json.loads(self.uncertainty_json or "[]")

    @property
    def limitations(self) -> List[str]:
        return json.loads(self.limitations_json or "[]")

    @property
    def missing_information(self) -> List[Dict[str, Any]]:
        return json.loads(self.missing_information_json or "[]")

    @property
    def causal_links(self) -> List[Dict[str, Any]]:
        return json.loads(self.causal_links_json or "[]")

    @property
    def detector_contributions(self) -> List[Dict[str, Any]]:
        return json.loads(self.detector_contributions_json or "[]")

    @property
    def model_contributions(self) -> List[Dict[str, Any]]:
        return json.loads(self.model_contributions_json or "[]")

    @property
    def rule_contributions(self) -> List[Dict[str, Any]]:
        return json.loads(self.rule_contributions_json or "[]")

    @property
    def mitre_explanations(self) -> List[Dict[str, Any]]:
        return json.loads(self.mitre_explanations_json or "[]")

    @property
    def attack_path_explanation(self) -> Dict[str, Any]:
        return json.loads(self.attack_path_explanation_json or "{}")

    @property
    def novelty_explanation(self) -> Dict[str, Any]:
        return json.loads(self.novelty_explanation_json or "{}")

    @property
    def behavioral_explanation(self) -> Dict[str, Any]:
        return json.loads(self.behavioral_explanation_json or "{}")

    @property
    def threat_memory_explanation(self) -> Dict[str, Any]:
        return json.loads(self.threat_memory_explanation_json or "{}")

    @property
    def assessment_change_guidance(self) -> Dict[str, Any]:
        return json.loads(self.assessment_change_guidance_json or "{}")

    @property
    def evidence_graph(self) -> Dict[str, Any]:
        return json.loads(self.evidence_graph_json or "{}")

    @property
    def investigator_details(self) -> Dict[str, Any]:
        return json.loads(self.investigator_details_json or "{}")

    @property
    def forensic_details(self) -> Dict[str, Any]:
        return json.loads(self.forensic_details_json or "{}")

    @property
    def validation_details(self) -> Dict[str, Any]:
        return json.loads(self.validation_details_json or "{}")

    @property
    def source_snapshot(self) -> Dict[str, Any]:
        return json.loads(self.source_snapshot_json or "{}")

    @property
    def provenance(self) -> Dict[str, Any]:
        return json.loads(self.provenance_json or "{}")


class ExplanationSnapshotModel(Base):
    """
    Immutable historical snapshot of an explanation for audits and reports (Section 27).
    """
    __tablename__ = "explanation_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    explanation_id = Column(String(36), ForeignKey("explanations.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    scope_type = Column(String(30), nullable=False)
    scope_id = Column(String(128), nullable=False)
    assessment_version = Column(Integer, nullable=False, default=1)
    explanation_version = Column(Integer, nullable=False, default=1)

    evidence_snapshot_json = Column(Text, default="[]", nullable=False)
    risk_snapshot_json = Column(Text, default="{}", nullable=False)
    attack_path_snapshot_json = Column(Text, default="{}", nullable=False)
    model_versions_json = Column(Text, default="{}", nullable=False)
    rule_versions_json = Column(Text, default="{}", nullable=False)
    full_explanation_json = Column(Text, default="{}", nullable=False)
    checksum = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    explanation = relationship("ExplanationModel", back_populates="snapshots")

    __table_args__ = (
        Index("ix_es_ws_expl_ver", "workspace_id", "explanation_id", "explanation_version"),
    )

    @property
    def evidence_snapshot(self) -> List[Dict[str, Any]]:
        return json.loads(self.evidence_snapshot_json or "[]")

    @property
    def risk_snapshot(self) -> Dict[str, Any]:
        return json.loads(self.risk_snapshot_json or "{}")

    @property
    def full_explanation(self) -> Dict[str, Any]:
        return json.loads(self.full_explanation_json or "{}")


class ExplanationFeedbackModel(Base):
    """
    Structured human analyst feedback and corrections for explanations (Section 27).
    Preserves audit trail without silently modifying original forensic records.
    """
    __tablename__ = "explanation_feedbacks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    explanation_id = Column(String(36), ForeignKey("explanations.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    analyst_id = Column(String(100), nullable=False, index=True)
    feedback_type = Column(String(50), nullable=False, index=True)  # ANALYST_CONFIRMED, ANALYST_DISMISSED, ANALYST_CORRECTED, ANALYST_COMMENT
    target_claim_id = Column(String(64), nullable=True, index=True)
    notes = Column(Text, nullable=False)
    correction_payload_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    explanation = relationship("ExplanationModel", back_populates="feedbacks")

    __table_args__ = (
        Index("ix_ef_ws_type", "workspace_id", "feedback_type"),
    )

    @property
    def correction_payload(self) -> Dict[str, Any]:
        return json.loads(self.correction_payload_json or "{}")


# ============================================================================
# SECTION 28: RESPONSE RECOMMENDATION ENGINE MODELS
# ============================================================================

class ResponseRecommendationModel(Base):
    """
    Section 28: Response Recommendation Engine.
    Structured, prioritized, evidence-backed defensive action recommendations.
    Advisory only; consequential execution belongs strictly behind human approval.
    """
    __tablename__ = "response_recommendations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    scope_type = Column(String(30), nullable=False, default="EVENT", index=True)  # EVENT, INVESTIGATION, INCIDENT, CAMPAIGN, ENTITY, ATTACK_PATH
    scope_id = Column(String(128), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    threat_event_id = Column(String(36), ForeignKey("threat_events.id", ondelete="SET NULL"), nullable=True, index=True)
    risk_assessment_id = Column(String(36), ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True, index=True)
    explanation_id = Column(String(36), ForeignKey("explanations.id", ondelete="SET NULL"), nullable=True, index=True)

    action_type = Column(String(50), nullable=False, index=True)  # Controlled taxonomy (e.g., BLOCK_DOMAIN, REVOKE_SESSION)
    category = Column(String(40), nullable=False, default="INVESTIGATION", index=True)  # IMMEDIATE, CONTAINMENT, INVESTIGATION, EVIDENCE_PRESERVATION, IDENTITY_SECURITY, NETWORK_SECURITY, ENDPOINT_SECURITY, COMMUNICATION, RECOVERY, FOLLOW_UP
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    rationale = Column(Text, nullable=False)

    priority = Column(String(10), nullable=False, default="P2", index=True)  # P0, P1, P2, P3, P4
    urgency = Column(String(20), nullable=False, default="NORMAL", index=True)  # IMMEDIATE, URGENT, SOON, NORMAL, DEFERRED
    expected_effect = Column(Text, nullable=False)

    prerequisites_json = Column(Text, default="[]", nullable=False)
    affected_entities_json = Column(Text, default="[]", nullable=False)
    evidence_refs_json = Column(Text, default="[]", nullable=False)
    risk_refs_json = Column(Text, default="[]", nullable=False)
    attack_path_refs_json = Column(Text, default="[]", nullable=False)
    mitre_refs_json = Column(Text, default="[]", nullable=False)

    confidence = Column(Float, default=1.0, nullable=False)
    confidence_level = Column(String(20), default="HIGH", nullable=False)

    applicability = Column(String(30), default="APPLICABLE", nullable=False)  # APPLICABLE, NOT_APPLICABLE, UNKNOWN, NOT_READY
    applicability_reason = Column(Text, nullable=False, default="Prerequisites and targets validated.")

    reversibility = Column(String(30), default="REVERSIBLE", nullable=False)  # REVERSIBLE, PARTIALLY_REVERSIBLE, IRREVERSIBLE, UNKNOWN
    impact = Column(String(20), default="LOW", nullable=False)  # NONE, LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN

    approval_required = Column(Boolean, default=False, nullable=False)
    safety_class = Column(String(30), default="INFORMATIONAL", nullable=False)  # INFORMATIONAL, LOW_IMPACT, REVERSIBLE, CONTAINMENT, HIGH_IMPACT, DESTRUCTIVE
    execution_mode = Column(String(30), default="MANUAL", nullable=False)  # MANUAL, AUTOMATED_VIA_PLAYBOOK, HUMAN_IN_THE_LOOP

    status = Column(String(30), default="GENERATED", nullable=False, index=True)  # GENERATED, REVIEW_REQUIRED, APPROVED, REJECTED, EXPIRED, SUPERSEDED, DEFERRED
    status_reason = Column(Text, nullable=True)
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)

    recommendation_version = Column(Integer, default=1, nullable=False)
    superseded_by_id = Column(String(36), nullable=True)

    depends_on_json = Column(Text, default="[]", nullable=False)
    conflicts_with_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)

    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=True, index=True)

    # Relationships
    threat_event = relationship("ThreatEventModel", foreign_keys=[threat_event_id])
    incident = relationship("IncidentModel", foreign_keys=[incident_id])
    risk_assessment = relationship("RiskAssessmentModel", foreign_keys=[risk_assessment_id], back_populates="recommendations")
    explanation = relationship("ExplanationModel", foreign_keys=[explanation_id], back_populates="recommendations")

    __table_args__ = (
        Index("ix_rr_ws_scope", "workspace_id", "scope_type", "scope_id"),
        Index("ix_rr_status_priority", "workspace_id", "status", "priority"),
    )

    @property
    def prerequisites(self) -> List[Dict[str, Any]]:
        return json.loads(self.prerequisites_json or "[]")

    @property
    def affected_entities(self) -> List[Dict[str, Any]]:
        return json.loads(self.affected_entities_json or "[]")

    @property
    def evidence_refs(self) -> List[str]:
        return json.loads(self.evidence_refs_json or "[]")

    @property
    def risk_refs(self) -> List[str]:
        return json.loads(self.risk_refs_json or "[]")

    @property
    def attack_path_refs(self) -> List[str]:
        return json.loads(self.attack_path_refs_json or "[]")

    @property
    def mitre_refs(self) -> List[str]:
        return json.loads(self.mitre_refs_json or "[]")

    @property
    def depends_on(self) -> List[str]:
        return json.loads(self.depends_on_json or "[]")

    @property
    def conflicts_with(self) -> List[Dict[str, Any]]:
        return json.loads(self.conflicts_with_json or "[]")

    @property
    def metadata_payload(self) -> Dict[str, Any]:
        return json.loads(self.metadata_json or "{}")


class ResponseCapabilityModel(Base):
    """
    Section 28: Response Capability Registry.
    Tracks available environment capabilities, integration states, and approval policies.
    """
    __tablename__ = "response_capabilities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    action_type = Column(String(50), nullable=False, index=True)
    provider = Column(String(100), nullable=False)
    environment = Column(String(50), default="PRODUCTION", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    reversible = Column(Boolean, default=True, nullable=False)
    approval_required = Column(Boolean, default=True, nullable=False)
    capability_state = Column(String(30), default="AVAILABLE", nullable=False)  # AVAILABLE, UNAVAILABLE, UNKNOWN, DISABLED, REQUIRES_CONFIGURATION
    state_reason = Column(Text, nullable=True)
    configuration_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_rc_ws_action", "workspace_id", "action_type"),
    )

    @property
    def configuration(self) -> Dict[str, Any]:
        return json.loads(self.configuration_json or "{}")


# ============================================================================
# SECTION 29: RESPONSE PLAYBOOK MODELS
# ============================================================================

class ResponsePlaybookModel(Base):
    """
    Section 29: Response Playbook Domain Model.
    Immutable versioned workflow definition for executing controlled defensive actions.
    Distinguishes recommendation, playbook, approval, execution, and verification.
    """
    __tablename__ = "response_playbooks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    playbook_key = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)  # DRAFT, VALIDATING, READY, REVIEW_REQUIRED, APPROVED, STAGED, ACTIVE, PAUSED, DISABLED, RETIRED, SUPERSEDED
    trigger_type = Column(String(50), nullable=False, default="MANUAL", index=True)  # RECOMMENDATION_APPROVED, MANUAL, INCIDENT_SEVERITY
    scope_type = Column(String(30), nullable=False, default="EVENT")  # EVENT, INCIDENT, INVESTIGATION, CAMPAIGN
    severity_min = Column(String(20), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_min = Column(Float, nullable=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(128), nullable=True, index=True)
    source_recommendation_id = Column(String(36), ForeignKey("response_recommendations.id", ondelete="SET NULL"), nullable=True, index=True)

    target_selector_json = Column(Text, default="{}", nullable=False)
    approval_policy = Column(String(30), default="SINGLE_APPROVAL", nullable=False)  # NO_APPROVAL, SINGLE_APPROVAL, PRIVILEGED_APPROVAL, DUAL_APPROVAL
    execution_policy = Column(String(30), default="MANUAL", nullable=False)  # MANUAL, AUTOMATED_AFTER_APPROVAL, SIMULATE_ONLY
    timeout_seconds = Column(Integer, default=300, nullable=False)
    max_runtime_seconds = Column(Integer, default=600, nullable=False)

    parent_version = Column(Integer, nullable=True)
    change_summary = Column(Text, nullable=True)
    created_by = Column(String(100), default="system", nullable=False)
    updated_by = Column(String(100), default="system", nullable=False)
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    activated_at = Column(DateTime, nullable=True)
    retired_at = Column(DateTime, nullable=True)

    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    steps = relationship("ResponsePlaybookStepModel", back_populates="playbook", cascade="all, delete-orphan", order_by="ResponsePlaybookStepModel.sequence")
    executions = relationship("ResponsePlaybookExecutionModel", back_populates="playbook")
    incident = relationship("IncidentModel", foreign_keys=[incident_id])
    source_recommendation = relationship("ResponseRecommendationModel", foreign_keys=[source_recommendation_id])

    __table_args__ = (
        Index("ix_rpb_ws_key_ver", "workspace_id", "playbook_key", "version", unique=True),
        Index("ix_rpb_ws_status", "workspace_id", "status"),
    )

    @property
    def target_selector(self) -> Dict[str, Any]:
        return json.loads(self.target_selector_json or "{}")


class ResponsePlaybookStepModel(Base):
    """
    Section 29: Controlled Playbook Step Definition.
    Represents an allowlisted, typed step in a defensive response playbook.
    Arbitrary code/shell execution is prohibited.
    """
    __tablename__ = "response_playbook_steps"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    playbook_id = Column(String(36), ForeignKey("response_playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    step_key = Column(String(64), nullable=False, index=True)
    sequence = Column(Integer, nullable=False, default=1)
    step_type = Column(String(60), nullable=False, index=True)  # Controlled step taxonomy
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)

    parameters_json = Column(Text, default="{}", nullable=False)
    target_selector_json = Column(Text, default="{}", nullable=False)
    condition_json = Column(Text, default="{}", nullable=False)
    on_success = Column(String(50), default="CONTINUE", nullable=False)  # CONTINUE, COMPLETE, <step_key>
    on_failure = Column(String(50), default="FAIL", nullable=False)  # FAIL, ROLLBACK, CONTINUE_ON_FAILURE, ABORT

    timeout_seconds = Column(Integer, default=60, nullable=False)
    retry_policy_json = Column(Text, default="{}", nullable=False)
    requires_approval = Column(Boolean, default=False, nullable=False)
    approval_policy = Column(String(30), default="NO_APPROVAL", nullable=False)
    safety_class = Column(String(30), default="INFORMATIONAL", nullable=False)  # INFORMATIONAL, LOW_IMPACT, REVERSIBLE, CONTAINMENT, HIGH_IMPACT, DESTRUCTIVE
    verification_policy_json = Column(Text, default="{}", nullable=False)
    rollback_policy_json = Column(Text, default="{}", nullable=False)
    depends_on_json = Column(Text, default="[]", nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    playbook = relationship("ResponsePlaybookModel", back_populates="steps")

    __table_args__ = (
        Index("ix_rpbs_pb_seq", "playbook_id", "sequence"),
        Index("ix_rpbs_pb_key", "playbook_id", "step_key", unique=True),
    )

    @property
    def parameters(self) -> Dict[str, Any]:
        return json.loads(self.parameters_json or "{}")

    @property
    def target_selector(self) -> Dict[str, Any]:
        return json.loads(self.target_selector_json or "{}")

    @property
    def condition(self) -> Dict[str, Any]:
        return json.loads(self.condition_json or "{}")

    @property
    def retry_policy(self) -> Dict[str, Any]:
        return json.loads(self.retry_policy_json or "{}")

    @property
    def verification_policy(self) -> Dict[str, Any]:
        return json.loads(self.verification_policy_json or "{}")

    @property
    def rollback_policy(self) -> Dict[str, Any]:
        return json.loads(self.rollback_policy_json or "{}")

    @property
    def depends_on(self) -> List[str]:
        return json.loads(self.depends_on_json or "[]")


class ResponsePlaybookExecutionModel(Base):
    """
    Section 29: Persistent Playbook Execution Instance.
    Tracks live execution or dry-run simulation of an approved playbook.
    """
    __tablename__ = "response_playbook_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    playbook_id = Column(String(36), ForeignKey("response_playbooks.id", ondelete="CASCADE"), nullable=False, index=True)
    playbook_version = Column(Integer, nullable=False, default=1)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(128), nullable=True, index=True)
    source_recommendation_id = Column(String(36), ForeignKey("response_recommendations.id", ondelete="SET NULL"), nullable=True, index=True)

    trigger_source = Column(String(50), default="MANUAL", nullable=False)  # MANUAL, RECOMMENDATION, AUTOMATED
    mode = Column(String(20), default="LIVE", nullable=False)  # LIVE, DRY_RUN
    status = Column(String(30), default="PENDING", nullable=False, index=True)  # PENDING, VALIDATING, WAITING_FOR_APPROVAL, READY, RUNNING, PAUSED, COMPLETED, PARTIALLY_COMPLETED, FAILED, ROLLING_BACK, ROLLED_BACK, CANCELLED, EXPIRED

    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    requested_by = Column(String(100), nullable=False, default="system")
    approved_by = Column(String(100), nullable=True)
    current_step_key = Column(String(64), nullable=True)
    result_summary = Column(Text, nullable=False, default="")
    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)

    execution_context_json = Column(Text, default="{}", nullable=False)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    playbook = relationship("ResponsePlaybookModel", back_populates="executions")
    step_executions = relationship("ResponsePlaybookStepExecutionModel", back_populates="execution", cascade="all, delete-orphan", order_by="ResponsePlaybookStepExecutionModel.sequence")
    approvals = relationship("ResponsePlaybookApprovalModel", back_populates="execution", cascade="all, delete-orphan")
    incident = relationship("IncidentModel", foreign_keys=[incident_id])

    __table_args__ = (
        Index("ix_rpbe_ws_status", "workspace_id", "status"),
        Index("ix_rpbe_ws_pb", "workspace_id", "playbook_id"),
    )

    @property
    def execution_context(self) -> Dict[str, Any]:
        return json.loads(self.execution_context_json or "{}")


class ResponsePlaybookStepExecutionModel(Base):
    """
    Section 29: Immutable Step Execution Record.
    Records exact target snapshot, adapter used, verification outcome, and forensic evidence.
    """
    __tablename__ = "response_playbook_step_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    execution_id = Column(String(36), ForeignKey("response_playbook_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    step_id = Column(String(36), ForeignKey("response_playbook_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    step_key = Column(String(64), nullable=False)
    sequence = Column(Integer, nullable=False)

    target_snapshot_json = Column(Text, default="{}", nullable=False)
    status = Column(String(30), default="PENDING", nullable=False, index=True)  # PENDING, SKIPPED, RUNNING, COMPLETED, FAILED, ROLLED_BACK, ROLLBACK_FAILED, VERIFICATION_FAILED
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    attempt_count = Column(Integer, default=0, nullable=False)

    adapter = Column(String(100), nullable=False, default="")
    adapter_version = Column(String(30), nullable=False, default="1.0.0")
    input_summary_json = Column(Text, default="{}", nullable=False)  # Redacted of secrets
    output_summary_json = Column(Text, default="{}", nullable=False)
    verification_result_json = Column(Text, default="{}", nullable=False)

    error_code = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    evidence_refs_json = Column(Text, default="[]", nullable=False)
    audit_event_id = Column(String(36), nullable=True)
    idempotency_key = Column(String(128), nullable=True, index=True)

    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    # Relationships
    execution = relationship("ResponsePlaybookExecutionModel", back_populates="step_executions")
    step = relationship("ResponsePlaybookStepModel", foreign_keys=[step_id])

    __table_args__ = (
        Index("ix_rpbse_exec_seq", "execution_id", "sequence"),
    )

    @property
    def target_snapshot(self) -> Dict[str, Any]:
        return json.loads(self.target_snapshot_json or "{}")

    @property
    def input_summary(self) -> Dict[str, Any]:
        return json.loads(self.input_summary_json or "{}")

    @property
    def output_summary(self) -> Dict[str, Any]:
        return json.loads(self.output_summary_json or "{}")

    @property
    def verification_result(self) -> Dict[str, Any]:
        return json.loads(self.verification_result_json or "{}")

    @property
    def evidence_refs(self) -> List[str]:
        return json.loads(self.evidence_refs_json or "[]")


class ResponsePlaybookApprovalModel(Base):
    """
    Section 29: Scoped Human Approval Record.
    Binds approval strictly to: playbook version + execution + target + action scope.
    """
    __tablename__ = "response_playbook_approvals"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    execution_id = Column(String(36), ForeignKey("response_playbook_executions.id", ondelete="CASCADE"), nullable=False, index=True)
    step_id = Column(String(36), ForeignKey("response_playbook_steps.id", ondelete="SET NULL"), nullable=True, index=True)
    scope = Column(String(30), default="EXECUTION", nullable=False)  # EXECUTION, STEP
    decision = Column(String(30), default="PENDING", nullable=False, index=True)  # PENDING, APPROVED, REJECTED, DEFERRED, EXPIRED, CANCELLED

    requested_by = Column(String(100), nullable=False)
    approved_by = Column(String(100), nullable=True)
    reason = Column(Text, nullable=False, default="")

    target_snapshot_json = Column(Text, default="{}", nullable=False)
    authorization_context_json = Column(Text, default="{}", nullable=False)

    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    decided_at = Column(DateTime, nullable=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)

    # Relationships
    execution = relationship("ResponsePlaybookExecutionModel", back_populates="approvals")

    __table_args__ = (
        Index("ix_rpba_exec_dec", "execution_id", "decision"),
    )

    @property
    def target_snapshot(self) -> Dict[str, Any]:
        return json.loads(self.target_snapshot_json or "{}")

    @property
    def authorization_context(self) -> Dict[str, Any]:
        return json.loads(self.authorization_context_json or "{}")


class TargetLockModel(Base):
    """
    Section 29: Target Concurrency Lock.
    Prevents conflicting simultaneous executions against the same target entity.
    """
    __tablename__ = "response_target_locks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    target_type = Column(String(50), nullable=False, index=True)  # SESSION, ACCOUNT, DEVICE, DOMAIN, IP, URL
    target_id = Column(String(255), nullable=False, index=True)
    execution_id = Column(String(36), nullable=False, index=True)

    acquired_at = Column(DateTime, default=get_utc_now, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    released_at = Column(DateTime, nullable=True)
    active = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_rtl_ws_target_active", "workspace_id", "target_type", "target_id", "active"),
    )


# ============================================================================
# SECTION 30: LLM SOC COPILOT PERSISTENT DATA MODELS
# ============================================================================

class SocCopilotConversationModel(Base):
    """
    Section 30: LLM SOC Copilot Conversation.
    Persistent container for analyst multi-turn investigation dialogues.
    """
    __tablename__ = "soc_copilot_conversations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    investigation_id = Column(String(128), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False, default="New SOC Investigation Dialogue")
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, ARCHIVED, DELETED
    created_by = Column(String(100), nullable=False, default="analyst")
    model_provider = Column(String(50), nullable=False, default="mock")
    model_name = Column(String(100), nullable=False, default="cyberguard-copilot-v2")
    context_policy_version = Column(String(32), nullable=False, default="1.0.0")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    messages = relationship("SocCopilotMessageModel", back_populates="conversation", cascade="all, delete-orphan", order_by="SocCopilotMessageModel.created_at", lazy="selectin")
    snapshots = relationship("SocCopilotContextSnapshotModel", back_populates="conversation", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_scc_ws_status", "workspace_id", "status"),
        Index("ix_scc_ws_inv", "workspace_id", "investigation_id"),
        Index("ix_scc_ws_inc", "workspace_id", "incident_id"),
    )


class SocCopilotContextSnapshotModel(Base):
    """
    Section 30: Copilot Context Snapshot.
    Forensically immutable snapshot recording exactly what structured data the Copilot observed at response time.
    """
    __tablename__ = "soc_copilot_context_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    conversation_id = Column(String(36), ForeignKey("soc_copilot_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    scope = Column(String(30), nullable=False, default="INVESTIGATION", index=True)  # INCIDENT, INVESTIGATION, EVENT, CAMPAIGN, GLOBAL
    investigation_id = Column(String(128), nullable=True, index=True)
    incident_id = Column(String(36), nullable=True, index=True)
    context_version = Column(String(32), nullable=False, default="1.0.0")
    retrieved_entity_ids_json = Column(Text, default="[]", nullable=False)
    retrieved_evidence_ids_json = Column(Text, default="[]", nullable=False)
    retrieved_finding_ids_json = Column(Text, default="[]", nullable=False)
    risk_assessment_version = Column(Integer, nullable=True)
    attack_path_version = Column(String(32), nullable=True)
    explanation_version = Column(Integer, nullable=True)
    threat_memory_snapshot_json = Column(Text, default="{}", nullable=False)
    snapshot_data_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    # Relationships
    conversation = relationship("SocCopilotConversationModel", back_populates="snapshots")


class SocCopilotMessageModel(Base):
    """
    Section 30: LLM SOC Copilot Message.
    Stores dialogue messages, structured claims, citations, uncertainties, and next steps.
    """
    __tablename__ = "soc_copilot_messages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    conversation_id = Column(String(36), ForeignKey("soc_copilot_conversations.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String(20), nullable=False, index=True)  # USER, ASSISTANT, SYSTEM, TOOL
    content = Column(Text, nullable=False)
    message_type = Column(String(50), nullable=False, default="ANSWER", index=True)  # QUESTION, ANSWER, SUMMARY, EXPLANATION, INVESTIGATION_RESULT, RECOMMENDATION_SUMMARY, REPORT_DRAFT, ERROR
    context_snapshot_id = Column(String(36), ForeignKey("soc_copilot_context_snapshots.id", ondelete="SET NULL"), nullable=True, index=True)
    model_provider = Column(String(50), nullable=False, default="mock")
    model_name = Column(String(100), nullable=False, default="cyberguard-copilot-v2")
    prompt_version = Column(String(32), nullable=False, default="1.0.0")
    claims_json = Column(Text, default="[]", nullable=False)
    citations_json = Column(Text, default="[]", nullable=False)
    uncertainties_json = Column(Text, default="[]", nullable=False)
    hypotheses_json = Column(Text, default="[]", nullable=False)
    next_steps_json = Column(Text, default="[]", nullable=False)
    tools_called_json = Column(Text, default="[]", nullable=False)
    latency_ms = Column(Float, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    # Relationships
    conversation = relationship("SocCopilotConversationModel", back_populates="messages")
    context_snapshot = relationship("SocCopilotContextSnapshotModel")
    feedbacks = relationship("SocCopilotFeedbackModel", back_populates="message", cascade="all, delete-orphan", lazy="selectin")

    @property
    def claims(self) -> List[Dict[str, Any]]:
        return json.loads(self.claims_json or "[]")

    @property
    def citations(self) -> List[Dict[str, Any]]:
        return json.loads(self.citations_json or "[]")

    @property
    def uncertainties(self) -> List[str]:
        return json.loads(self.uncertainties_json or "[]")

    @property
    def hypotheses(self) -> List[str]:
        return json.loads(self.hypotheses_json or "[]")

    @property
    def next_steps(self) -> List[str]:
        return json.loads(self.next_steps_json or "[]")

    @property
    def tools_called(self) -> List[str]:
        return json.loads(self.tools_called_json or "[]")


class SocCopilotFeedbackModel(Base):
    """
    Section 30: Copilot Analyst Feedback.
    Auditable feedback on Copilot claims, citations, and answers without corrupting ground truth.
    """
    __tablename__ = "soc_copilot_feedback"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    message_id = Column(String(36), ForeignKey("soc_copilot_messages.id", ondelete="CASCADE"), nullable=False, index=True)
    conversation_id = Column(String(36), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    analyst_id = Column(String(100), nullable=False, default="analyst", index=True)
    rating = Column(String(30), nullable=False, index=True)  # HELPFUL, NOT_HELPFUL, INCORRECT, MISSING_EVIDENCE
    feedback_text = Column(Text, nullable=True)
    structured_feedback_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    message = relationship("SocCopilotMessageModel", back_populates="feedbacks")

    __table_args__ = (
        Index("ix_scf_ws_rating", "workspace_id", "rating"),
    )


# ============================================================================
# SECTION 31: ENDPOINT AGENT ARCHITECTURE MODELS
# ============================================================================

class DeviceModel(Base):
    """
    Section 31: Physical or Virtual Host Device Identity.
    Maintains a stable device identity distinct from replaceable EndpointAgent installations.
    """
    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    device_uid = Column(String(128), nullable=False, index=True)  # Hardware UUID / machine-id
    hostname = Column(String(255), nullable=False, index=True)
    platform = Column(String(32), nullable=False, index=True)  # macos, windows, linux
    os_version = Column(String(128), nullable=True)
    architecture = Column(String(64), nullable=True)  # x86_64, arm64, etc.
    manufacturer = Column(String(128), nullable=True)
    model = Column(String(128), nullable=True)
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE, OFFLINE, DECOMMISSIONED
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    agents = relationship("EndpointAgentModel", back_populates="device", cascade="all, delete-orphan", lazy="selectin")
    telemetry_events = relationship("EndpointTelemetryEventModel", back_populates="device", lazy="selectin")
    correlations = relationship("DeviceIncidentCorrelationModel", back_populates="device", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_devices_ws_uid", "workspace_id", "device_uid", unique=True),
        Index("ix_devices_ws_status", "workspace_id", "status"),
    )


class EndpointAgentModel(Base):
    """
    Section 31: Authorized Endpoint Telemetry Agent.
    Manages agent runtime identity, enrollment status, heartbeat, and versioning.
    """
    __tablename__ = "endpoint_agents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    agent_id = Column(String(64), nullable=False, index=True)  # AGT-XXXXXXXX
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    platform = Column(String(32), nullable=False, index=True)
    platform_version = Column(String(128), nullable=True)
    architecture = Column(String(64), nullable=True)
    agent_version = Column(String(32), nullable=False, default="1.0.0", index=True)
    status = Column(String(32), nullable=False, default="ENROLLING", index=True)  # ENROLLING, ACTIVE, DEGRADED, OFFLINE, REVOKED, DISABLED
    enrollment_state = Column(String(32), nullable=False, default="ENROLLED", index=True)  # ENROLLED, PENDING_VERIFICATION, REVOKED
    configuration_version = Column(String(32), nullable=False, default="1.0.0", index=True)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    last_heartbeat_at = Column(DateTime, nullable=True)
    last_event_time = Column(DateTime, nullable=True)
    clock_offset_ms = Column(Float, nullable=False, default=0.0)
    enrolled_at = Column(DateTime, default=get_utc_now, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revocation_reason = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    device = relationship("DeviceModel", back_populates="agents")
    credentials = relationship("EndpointAgentCredentialModel", back_populates="agent", cascade="all, delete-orphan", lazy="selectin")
    configurations = relationship("EndpointAgentConfigurationModel", back_populates="agent", lazy="selectin")
    heartbeats = relationship("EndpointAgentHeartbeatModel", back_populates="agent", cascade="all, delete-orphan", lazy="selectin")
    telemetry_events = relationship("EndpointTelemetryEventModel", back_populates="agent", lazy="selectin")

    __table_args__ = (
        Index("ix_ep_agents_ws_agent_id", "workspace_id", "agent_id", unique=True),
        Index("ix_ep_agents_status_seen", "status", "last_seen_at"),
    )


class EndpointEnrollmentTokenModel(Base):
    """
    Section 31: Cryptographically Secure Endpoint Enrollment Token.
    Short-lived, single-use, auditable, and revocable credential exchange token.
    """
    __tablename__ = "endpoint_enrollment_tokens"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    token_prefix = Column(String(16), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, index=True)  # SHA-256 of raw enrollment token
    description = Column(String(255), nullable=True)
    created_by = Column(String(100), nullable=False, default="admin")
    expires_at = Column(DateTime, nullable=False, index=True)
    max_uses = Column(Integer, nullable=False, default=1)
    use_count = Column(Integer, nullable=False, default=0)
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE, EXHAUSTED, EXPIRED, REVOKED
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_ep_tokens_ws_status", "workspace_id", "status"),
    )


class EndpointAgentCredentialModel(Base):
    """
    Section 31: Long-lived Agent Mutual Authentication Credential.
    Supports HMAC shared secret hash or public key verification with rotation lifecycle.
    """
    __tablename__ = "endpoint_agent_credentials"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    agent_id = Column(String(36), ForeignKey("endpoint_agents.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    credential_type = Column(String(32), nullable=False, default="HMAC_KEY", index=True)  # HMAC_KEY, BEARER_TOKEN, MTLS_CERT
    key_id = Column(String(64), nullable=False, index=True)
    secret_hash = Column(String(64), nullable=False)  # SHA-256 of credential secret
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE, ROTATED, EXPIRED, REVOKED
    expires_at = Column(DateTime, nullable=True)
    rotated_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    agent = relationship("EndpointAgentModel", back_populates="credentials")

    __table_args__ = (
        Index("ix_ep_cred_agent_status", "agent_id", "status"),
        Index("ix_ep_cred_key_id", "key_id", unique=True),
    )


class EndpointAgentConfigurationModel(Base):
    """
    Section 31: Versioned, Validated, and Signed Agent Configuration.
    Controls telemetry collectors, batching, buffer thresholds, and privacy redaction.
    """
    __tablename__ = "endpoint_agent_configurations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    configuration_id = Column(String(64), nullable=False, index=True)  # CFG-XXXX
    agent_id = Column(String(36), ForeignKey("endpoint_agents.id", ondelete="SET NULL"), nullable=True, index=True)
    version = Column(String(32), nullable=False, default="1.0.0", index=True)
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # DRAFT, VALIDATING, ACTIVE, SUPERSEDED, REVOKED
    collection_policy_json = Column(Text, default="{}", nullable=False)
    sampling_policy_json = Column(Text, default="{}", nullable=False)
    privacy_policy_json = Column(Text, default="{}", nullable=False)
    batch_size = Column(Integer, nullable=False, default=50)
    flush_interval_seconds = Column(Float, nullable=False, default=10.0)
    max_buffer_size_events = Column(Integer, nullable=False, default=5000)
    max_buffer_size_bytes = Column(Integer, nullable=False, default=20971520)  # 20MB
    server_endpoint = Column(String(500), nullable=False, default="/api/v1/endpoint")
    enabled_collectors_json = Column(Text, default="[]", nullable=False)
    signature = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    activated_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)

    agent = relationship("EndpointAgentModel", back_populates="configurations")

    __table_args__ = (
        Index("ix_ep_cfg_ws_ver", "workspace_id", "version"),
    )


class EndpointTelemetryEventModel(Base):
    """
    Section 31: Raw Endpoint Telemetry Event Evidence.
    Preserves raw host observations, client sequence numbers, timestamps, and provenance
    before feeding into the Universal Ingestion Gateway and ThreatEvent model.
    """
    __tablename__ = "endpoint_telemetry_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    agent_id = Column(String(36), ForeignKey("endpoint_agents.id", ondelete="CASCADE"), nullable=False, index=True)
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    event_id = Column(String(64), nullable=False, index=True)  # Client event UUID
    sequence_number = Column(Integer, nullable=False, index=True)
    event_type = Column(String(64), nullable=False, index=True)  # PROCESS, NETWORK, DNS, AUTHENTICATION, SYSTEM, FILE_METADATA, SECURITY_AUDIT
    event_time = Column(DateTime, nullable=False, index=True)  # Endpoint timestamp
    received_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)  # Backend timestamp
    collector_id = Column(String(64), nullable=False, index=True)
    collector_version = Column(String(32), nullable=False, default="1.0.0")
    configuration_version = Column(String(32), nullable=False, default="1.0.0")
    agent_version = Column(String(32), nullable=False, default="1.0.0")
    schema_version = Column(String(32), nullable=False, default="1.0.0")
    priority = Column(String(32), nullable=False, default="NORMAL", index=True)  # CRITICAL, HIGH, NORMAL, LOW
    threat_event_id = Column(String(36), ForeignKey("threat_events.id", ondelete="SET NULL"), nullable=True, index=True)
    payload_json = Column(Text, default="{}", nullable=False)
    integrity_hash = Column(String(64), nullable=True)
    status = Column(String(32), nullable=False, default="ACCEPTED", index=True)  # ACCEPTED, NORMALIZED, REJECTED, DUPLICATE
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    agent = relationship("EndpointAgentModel", back_populates="telemetry_events")
    device = relationship("DeviceModel", back_populates="telemetry_events")
    threat_event = relationship("ThreatEventModel", foreign_keys=[threat_event_id])

    __table_args__ = (
        Index("ix_ep_events_dedup", "agent_id", "sequence_number", "event_id", unique=True),
        Index("ix_ep_events_ws_type_time", "workspace_id", "event_type", "event_time"),
    )


class EndpointAgentHeartbeatModel(Base):
    """
    Section 31: Endpoint Agent Periodic Health & Metric Report.
    Audits collector health states, queue depth, buffer metrics, and host performance.
    """
    __tablename__ = "endpoint_agent_heartbeats"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    agent_id = Column(String(36), ForeignKey("endpoint_agents.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    health_state = Column(String(32), nullable=False, default="HEALTHY", index=True)  # HEALTHY, DEGRADED, OFFLINE, UNAUTHORIZED, MISCONFIGURED, BUFFER_PRESSURE, COLLECTOR_FAILURE
    collector_states_json = Column(Text, default="{}", nullable=False)
    buffer_events_count = Column(Integer, nullable=False, default=0)
    buffer_bytes = Column(Integer, nullable=False, default=0)
    cpu_usage_percent = Column(Float, nullable=False, default=0.0)
    memory_usage_mb = Column(Float, nullable=False, default=0.0)
    last_event_time = Column(DateTime, nullable=True)
    received_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    agent = relationship("EndpointAgentModel", back_populates="heartbeats")

    __table_args__ = (
        Index("ix_ep_hb_agent_time", "agent_id", "received_at"),
    )


# ============================================================================
# SECTION 33: DEVICE-TO-INCIDENT CORRELATION MODELS
# ============================================================================

class DeviceIncidentCorrelationModel(Base):
    """
    Section 33: Evidence-Backed Device-to-Incident Correlation.
    Maintains bidirectional, auditable, and versioned associations between
    managed endpoint devices and security incidents.
    """
    __tablename__ = "device_incident_correlations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    correlation_type = Column(String(64), nullable=False, index=True)  # DIRECT_IDENTIFIER, INDICATOR_MATCH, FILE_HASH_MATCH, DOMAIN_MATCH, IP_MATCH, USER_MATCH, TEMPORAL_SEQUENCE, GRAPH_PATH, MULTI_SIGNAL_CORRELATION, etc.
    correlation_score = Column(Float, nullable=False, default=0.0)      # 0.0 - 1.0 (strength)
    confidence = Column(Float, nullable=False, default=1.0)             # 0.0 - 1.0
    status = Column(String(32), nullable=False, default="OBSERVED", index=True)  # OBSERVED, RELATED, SUSPECTED, SUPPORTED, CONFIRMED, DISMISSED
    version = Column(Integer, nullable=False, default=1, index=True)
    is_current = Column(Boolean, nullable=False, default=True, index=True)
    first_observed_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_observed_at = Column(DateTime, default=get_utc_now, nullable=False)
    supporting_event_ids_json = Column(Text, default="[]", nullable=False)
    supporting_evidence_ids_json = Column(Text, default="[]", nullable=False)
    supporting_entity_ids_json = Column(Text, default="[]", nullable=False)
    supporting_relationship_ids_json = Column(Text, default="[]", nullable=False)
    matched_indicators_json = Column(Text, default="[]", nullable=False)
    matched_behaviors_json = Column(Text, default="[]", nullable=False)
    temporal_context_json = Column(Text, default="{}", nullable=False)
    reason_codes_json = Column(Text, default="[]", nullable=False)
    counter_evidence_json = Column(Text, default="[]", nullable=False)
    limitations_json = Column(Text, default="[]", nullable=False)
    structured_explanation_json = Column(Text, default="{}", nullable=False)
    correlation_engine_version = Column(String(32), nullable=False, default="1.0.0")
    reviewed_by = Column(String(100), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    device = relationship("DeviceModel", back_populates="correlations")
    incident = relationship("IncidentModel", back_populates="device_correlations")

    __table_args__ = (
        Index("ix_dev_inc_corr_lookup", "workspace_id", "device_id", "incident_id", "is_current"),
        Index("ix_dev_inc_corr_status", "workspace_id", "status"),
        Index("ix_dev_inc_corr_score", "workspace_id", "correlation_score"),
    )


# ============================================================================
# SECTION 45: PERSISTENT BACKGROUND JOBS & ASYNCHRONOUS ORCHESTRATION MODELS
# ============================================================================

class BackgroundJobModel(Base):
    """
    Section 45: Persistent Background Job Lifecycle Model.
    Tracks asynchronous execution state, leasing, idempotency, retry budgets,
    progress, stage milestones, and sanitized failure details for long-running operations.
    """
    __tablename__ = "background_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    job_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="QUEUED", index=True)
    priority = Column(String(20), nullable=False, default="NORMAL", index=True)  # CRITICAL, HIGH, NORMAL, LOW
    priority_weight = Column(Integer, nullable=False, default=2, index=True)      # CRITICAL=4, HIGH=3, NORMAL=2, LOW=1
    requested_by = Column(String(100), nullable=False, default="system")

    # Associated resources
    resource_type = Column(String(50), nullable=True, index=True)  # ARTIFACT, ANALYSIS_RUN, REPORT, INCIDENT, TELEMETRY, MAINTENANCE
    resource_id = Column(String(128), nullable=True, index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="SET NULL"), nullable=True, index=True)

    # Payload & references (Sanitized: NO raw secrets, passwords, or file bytes)
    payload_reference = Column(String(255), nullable=True)
    payload_json = Column(Text, default="{}", nullable=False)

    # Execution attempts and scheduling
    attempt_count = Column(Integer, nullable=False, default=0)
    max_attempts = Column(Integer, nullable=False, default=3)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    scheduled_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    heartbeat_at = Column(DateTime, nullable=True, index=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)
    timeout_seconds = Column(Integer, nullable=False, default=300)
    timeout_at = Column(DateTime, nullable=True, index=True)

    # Worker and lease tracking
    worker_id = Column(String(100), nullable=True, index=True)
    lease_expires_at = Column(DateTime, nullable=True, index=True)

    # Idempotency
    idempotency_key = Column(String(128), nullable=True, index=True)

    # Progress & stage reporting
    progress_percent = Column(Float, nullable=True)
    current_stage = Column(String(100), nullable=True)

    # Output & sanitized errors
    error_code = Column(String(64), nullable=True)
    sanitized_error_message = Column(Text, nullable=True)
    result_reference = Column(String(255), nullable=True)
    result_json = Column(Text, default="{}", nullable=False)

    events = relationship("BackgroundJobEventModel", back_populates="job", cascade="all, delete-orphan", lazy="selectin")
    analysis_run = relationship("AnalysisRunModel", foreign_keys=[analysis_run_id])
    report = relationship("ReportModel", foreign_keys=[report_id])

    @property
    def payload(self) -> Dict[str, Any]:
        try:
            return json.loads(self.payload_json or "{}")
        except Exception:
            return {}

    @property
    def result(self) -> Dict[str, Any]:
        try:
            return json.loads(self.result_json or "{}")
        except Exception:
            return {}

    __table_args__ = (
        Index("ix_bg_jobs_claim", "status", "scheduled_at", "priority_weight"),
        Index("ix_bg_jobs_ws_idemp", "workspace_id", "idempotency_key"),
        Index("ix_bg_jobs_ws_status", "workspace_id", "status"),
        Index("ix_bg_jobs_ws_type", "workspace_id", "job_type"),
        Index("ix_bg_jobs_heartbeat", "status", "heartbeat_at"),
    )


class BackgroundJobEventModel(Base):
    """
    Section 45: Auditable Background Job Event Stream.
    Tracks state transitions, progress milestones, heartbeats, and sanitized errors.
    """
    __tablename__ = "background_job_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    job_id = Column(String(36), ForeignKey("background_jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    event_type = Column(String(64), nullable=False, index=True)
    sequence = Column(Integer, nullable=False, default=1, index=True)
    stage = Column(String(100), nullable=True)
    progress_percent = Column(Float, nullable=True)
    message = Column(String(500), nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    job = relationship("BackgroundJobModel", back_populates="events")

    __table_args__ = (
        Index("ix_bg_job_events_order", "job_id", "timestamp"),
        Index("ix_bg_job_events_ws_type", "workspace_id", "event_type"),
        Index("ix_bg_job_events_seq", "job_id", "sequence"),
    )


class NotificationModel(Base):
    """
    Section 47: Persistent Notification & Security Alert Model.
    Distinguishes between user-facing notifications ('Something happened')
    and actionable security alerts ('Potential threat requires investigation/action').
    Tracks read/unread state, acknowledgement, authoritative provenance, and deduplication.
    """
    __tablename__ = "notifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    user_id = Column(String(100), nullable=True, index=True)

    category = Column(String(32), nullable=False, default="NOTIFICATION", index=True)  # NOTIFICATION, SECURITY_ALERT
    notification_type = Column(String(64), nullable=False, index=True)  # Controlled taxonomy
    severity = Column(String(20), nullable=False, default="INFO", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    status = Column(String(30), nullable=False, default="UNREAD", index=True)  # UNREAD, READ, ACKNOWLEDGED, DISMISSED

    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)

    # Authoritative Provenance & Navigation
    source_type = Column(String(50), nullable=False, default="FINDING", index=True)  # FINDING, ANALYSIS_RUN, REPORT, JOB, INVESTIGATION, INCIDENT
    source_id = Column(String(128), nullable=False, default=generate_uuid, index=True)
    investigation_id = Column(String(128), nullable=True, index=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    job_id = Column(String(36), ForeignKey("background_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    report_id = Column(String(36), ForeignKey("reports.id", ondelete="SET NULL"), nullable=True, index=True)
    navigation_target = Column(String(255), nullable=True)

    # Deduplication & Suppression
    deduplication_key = Column(String(190), nullable=False, default=generate_uuid, index=True)

    # Metadata & Explanations (sanitized JSON)
    metadata_json = Column(Text, default="{}", nullable=False)

    # Timestamps & Lifecycle
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    read_at = Column(DateTime, nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(100), nullable=True)

    # Section 48: Alert Triage & Disposition Lifecycle
    assigned_to = Column(String(100), nullable=True, index=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    resolution_reason = Column(Text, nullable=True)
    false_positive_reason = Column(Text, nullable=True)
    suppression_reason = Column(Text, nullable=True)
    suppression_scope = Column(String(50), nullable=True)  # THIS_ALERT, INDICATOR, PATTERN
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False, index=True)

    # Relationships
    analysis_run = relationship("AnalysisRunModel", foreign_keys=[analysis_run_id])
    finding = relationship("FindingModel", foreign_keys=[finding_id])
    job = relationship("BackgroundJobModel", foreign_keys=[job_id])
    report = relationship("ReportModel", foreign_keys=[report_id])

    __table_args__ = (
        Index("ix_notif_ws_status", "workspace_id", "status"),
        Index("ix_notif_ws_cat_status", "workspace_id", "category", "status"),
        Index("ix_notif_ws_dedup", "workspace_id", "deduplication_key"),
        Index("ix_notif_ws_created", "workspace_id", "created_at"),
        Index("ix_notif_ws_inv", "workspace_id", "investigation_id"),
        Index("ix_notif_ws_assign", "workspace_id", "assigned_to"),
        Index("ix_notif_ws_sev_status", "workspace_id", "severity", "status"),
    )


# Section 48: Unified Domain Model alias for Security Alerts
AlertModel = NotificationModel


# ============================================================================
# SECTION 49: ALERT CORRELATION & INCIDENT CLUSTERING MODELS
# ============================================================================

class AlertClusterModel(Base):
    """
    Section 49: Persisted Alert Cluster abstraction.
    Groups correlated security alerts that share infrastructure, identities,
    indicators, temporal proximity, campaigns, or attack-path graph relationships.
    """
    __tablename__ = "alert_clusters"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    cluster_number = Column(String(32), unique=True, nullable=False, default=generate_cluster_number, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="OPEN", index=True)  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE, SUPPRESSED
    severity = Column(String(20), nullable=False, default="HIGH", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0
    confidence = Column(Float, nullable=False, default=1.0)  # 0.0 - 1.0 (correlation confidence)
    alert_count = Column(Integer, nullable=False, default=1)
    primary_alert_id = Column(String(36), ForeignKey("notifications.id", ondelete="SET NULL"), nullable=True, index=True)
    investigation_id = Column(String(128), nullable=True, index=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    merged_into_cluster_id = Column(String(36), ForeignKey("alert_clusters.id", ondelete="SET NULL"), nullable=True, index=True)
    correlation_version = Column(String(32), nullable=False, default="1.0.0")
    first_seen = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    members = relationship("AlertClusterMemberModel", back_populates="cluster", cascade="all, delete-orphan", lazy="selectin")
    primary_alert = relationship("NotificationModel", foreign_keys=[primary_alert_id])
    campaign = relationship("CampaignModel", foreign_keys=[campaign_id])
    merged_into = relationship("AlertClusterModel", remote_side=[id], foreign_keys=[merged_into_cluster_id])

    __table_args__ = (
        Index("ix_clu_ws_status", "workspace_id", "status"),
        Index("ix_clu_ws_sev", "workspace_id", "severity"),
        Index("ix_clu_ws_inv", "workspace_id", "investigation_id"),
        Index("ix_clu_ws_camp", "workspace_id", "campaign_id"),
        Index("ix_clu_ws_updated", "workspace_id", "updated_at"),
    )


class AlertClusterMemberModel(Base):
    """
    Section 49: Explicit association between an Alert and an Alert Cluster.
    Contains membership confidence, structured correlation reasons, and versioning.
    """
    __tablename__ = "alert_cluster_members"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    cluster_id = Column(String(36), ForeignKey("alert_clusters.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_id = Column(String(36), ForeignKey("notifications.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    membership_confidence = Column(Float, nullable=False, default=1.0)
    correlation_reasons_json = Column(Text, default="[]", nullable=False)  # JSON array of structured SignalDetail dicts
    correlation_version = Column(String(32), nullable=False, default="1.0.0")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    cluster = relationship("AlertClusterModel", back_populates="members")
    alert = relationship("NotificationModel", foreign_keys=[alert_id])

    __table_args__ = (
        Index("ix_clu_mem_clu_alert", "cluster_id", "alert_id", unique=True),
        Index("ix_clu_mem_ws_alert", "workspace_id", "alert_id"),
    )


# ============================================================================
# SECTION 51: INCIDENT SLA, ESCALATION & ANALYST WORKFLOW AUTOMATION MODELS
# ============================================================================

class IncidentSLAPolicyModel(Base):
    """
    Section 51: Persistent Incident SLA Policy.
    Defines configurable acknowledgement, investigation, containment, and resolution
    target durations along with warning thresholds.
    """
    __tablename__ = "incident_sla_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="ANY", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO, ANY
    priority = Column(String(20), nullable=False, default="ANY", index=True)  # P1_CRITICAL, P2_HIGH, P3_MEDIUM, P4_LOW, ANY
    category = Column(String(50), nullable=False, default="ANY", index=True)  # PHISHING, MALWARE, etc. or ANY
    acknowledgement_target_minutes = Column(Integer, nullable=False, default=30)
    investigation_target_minutes = Column(Integer, nullable=False, default=60)
    containment_target_minutes = Column(Integer, nullable=False, default=120)
    resolution_target_minutes = Column(Integer, nullable=False, default=480)
    warning_threshold_pct = Column(Float, nullable=False, default=80.0)  # e.g. 80.0% of target
    escalation_policy_id = Column(String(36), nullable=True, index=True)
    is_default = Column(Boolean, nullable=False, default=False)
    status = Column(String(20), nullable=False, default="ACTIVE", index=True)  # DRAFT, ACTIVE, DISABLED, ARCHIVED
    version = Column(Integer, nullable=False, default=1)
    created_by = Column(String(100), default="SYSTEM")
    updated_by = Column(String(100), default="SYSTEM")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_sla_pol_ws_status", "workspace_id", "status"),
        Index("ix_sla_pol_ws_sev", "workspace_id", "severity"),
    )


class IncidentEscalationPolicyModel(Base):
    """
    Section 51: Persistent Escalation Policy abstraction.
    Groups ordered levels of escalation rules with loop cooldowns and max levels.
    """
    __tablename__ = "incident_escalation_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    cooldown_minutes = Column(Integer, nullable=False, default=15)
    max_escalation_level = Column(Integer, nullable=False, default=3)
    status = Column(String(20), nullable=False, default="ACTIVE", index=True)  # DRAFT, ACTIVE, DISABLED, ARCHIVED
    version = Column(Integer, nullable=False, default=1)
    created_by = Column(String(100), default="SYSTEM")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    rules = relationship("IncidentEscalationRuleModel", back_populates="policy", cascade="all, delete-orphan", order_by="asc(IncidentEscalationRuleModel.level)", lazy="selectin")

    __table_args__ = (
        Index("ix_esc_pol_ws_status", "workspace_id", "status"),
    )


class IncidentEscalationRuleModel(Base):
    """
    Section 51: Individual level / condition / action rule inside an Escalation Policy.
    """
    __tablename__ = "incident_escalation_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    policy_id = Column(String(36), ForeignKey("incident_escalation_policies.id", ondelete="CASCADE"), nullable=False, index=True)
    level = Column(Integer, nullable=False, default=1)  # 1, 2, 3
    condition_type = Column(String(50), nullable=False, default="SLA_BREACH")  # SLA_WARNING, SLA_BREACH, CRITICAL_UNACKNOWLEDGED, UNASSIGNED_TIMEOUT, PRIORITY_CRITICAL, REOPENED
    milestone = Column(String(30), nullable=False, default="ANY")  # ACKNOWLEDGEMENT, INVESTIGATION, CONTAINMENT, RESOLUTION, ANY
    action_type = Column(String(50), nullable=False, default="NOTIFY_TEAM")  # NOTIFY_OWNER, NOTIFY_TEAM, ASSIGN_TO_USER, ASSIGN_TO_TEAM, ESCALATE_PRIORITY, CREATE_TASK
    target_role = Column(String(50), nullable=True)  # "SOC Lead", "Security Manager"
    target_user = Column(String(100), nullable=True)  # Specific analyst or lead name
    target_team = Column(String(64), nullable=True)  # Specific team name/id
    escalate_priority_to = Column(String(20), nullable=True)  # P1_CRITICAL, P2_HIGH
    note_template = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    policy = relationship("IncidentEscalationPolicyModel", back_populates="rules")

    __table_args__ = (
        Index("ix_esc_rule_pol_lvl", "policy_id", "level"),
    )


class IncidentRoutingRuleModel(Base):
    """
    Section 51: Analyst & Team Routing Rules.
    Dispatches incoming or unassigned incidents using category, severity, and risk criteria.
    """
    __tablename__ = "incident_routing_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    priority_order = Column(Integer, nullable=False, default=10)
    category = Column(String(50), nullable=False, default="ANY")
    severity = Column(String(20), nullable=False, default="ANY")
    min_risk_score = Column(Float, nullable=False, default=0.0)
    routing_strategy = Column(String(30), nullable=False, default="ROUND_ROBIN")  # DIRECT_USER, ROUND_ROBIN, LEAST_LOADED, TEAM_QUEUE
    target_team_id = Column(String(64), nullable=True)
    target_user_id = Column(String(100), nullable=True)
    candidate_analysts_json = Column(Text, default="[]", nullable=False)  # JSON array of analyst usernames
    enabled = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_rout_ws_enabled_prio", "workspace_id", "enabled", "priority_order"),
    )


class IncidentSLAStateModel(Base):
    """
    Section 51: Authoritative persistent SLA state linked 1-to-1 with an Incident.
    Calculates elapsed times, milestone deadlines, pause duration, warnings, and breach markers.
    """
    __tablename__ = "incident_sla_states"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    policy_id = Column(String(36), nullable=True, index=True)
    policy_name = Column(String(100), nullable=True)
    policy_version = Column(Integer, nullable=False, default=1)
    escalation_policy_id = Column(String(36), nullable=True)

    # Acknowledgement Clock
    ack_target_minutes = Column(Integer, nullable=False, default=30)
    ack_deadline = Column(DateTime, nullable=True)
    ack_status = Column(String(20), nullable=False, default="NOT_STARTED")  # NOT_STARTED, RUNNING, MET, WARNING, BREACHED, PAUSED, EXEMPT
    ack_met_at = Column(DateTime, nullable=True)
    ack_warning_sent_at = Column(DateTime, nullable=True)
    ack_breached_at = Column(DateTime, nullable=True)

    # Investigation Clock
    inv_target_minutes = Column(Integer, nullable=False, default=60)
    inv_deadline = Column(DateTime, nullable=True)
    inv_status = Column(String(20), nullable=False, default="NOT_STARTED")
    inv_met_at = Column(DateTime, nullable=True)
    inv_warning_sent_at = Column(DateTime, nullable=True)
    inv_breached_at = Column(DateTime, nullable=True)

    # Containment Clock
    cont_target_minutes = Column(Integer, nullable=False, default=120)
    cont_deadline = Column(DateTime, nullable=True)
    cont_status = Column(String(20), nullable=False, default="NOT_STARTED")
    cont_met_at = Column(DateTime, nullable=True)
    cont_warning_sent_at = Column(DateTime, nullable=True)
    cont_breached_at = Column(DateTime, nullable=True)

    # Resolution Clock
    res_target_minutes = Column(Integer, nullable=False, default=480)
    res_deadline = Column(DateTime, nullable=True)
    res_status = Column(String(20), nullable=False, default="NOT_STARTED")
    res_met_at = Column(DateTime, nullable=True)
    res_warning_sent_at = Column(DateTime, nullable=True)
    res_breached_at = Column(DateTime, nullable=True)

    # Overall SLA status & Escalation Level
    overall_sla_status = Column(String(20), nullable=False, default="HEALTHY", index=True)  # HEALTHY, WARNING, BREACHED, PAUSED, EXEMPT, MET
    current_escalation_level = Column(Integer, nullable=False, default=0, index=True)
    last_escalated_at = Column(DateTime, nullable=True)
    last_escalation_reason = Column(Text, nullable=True)

    # Pausing State
    is_paused = Column(Boolean, nullable=False, default=False)
    paused_at = Column(DateTime, nullable=True)
    paused_by = Column(String(100), nullable=True)
    pause_reason = Column(Text, nullable=True)
    total_paused_seconds = Column(Integer, nullable=False, default=0)

    # Exemption State
    is_exempt = Column(Boolean, nullable=False, default=False)
    exempt_at = Column(DateTime, nullable=True)
    exempt_by = Column(String(100), nullable=True)
    exempt_reason = Column(Text, nullable=True)

    # High-Performance Deadline & Execution indexing
    next_sla_deadline = Column(DateTime, nullable=True, index=True)
    last_evaluated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="sla_state")

    __table_args__ = (
        Index("ix_sla_state_ws_status", "workspace_id", "overall_sla_status"),
        Index("ix_sla_state_next_dl", "workspace_id", "next_sla_deadline"),
    )


class IncidentWorkflowExecutionModel(Base):
    """
    Section 51: Idempotency log for workflow actions and escalation rule executions.
    Guarantees no duplicate execution of notifications, assignments, or escalations.
    """
    __tablename__ = "incident_workflow_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    execution_key = Column(String(190), unique=True, nullable=False, index=True)  # Deterministic idempotency key
    policy_id = Column(String(36), nullable=True)
    rule_id = Column(String(36), nullable=True)
    escalation_level = Column(Integer, nullable=False, default=0)
    action_type = Column(String(50), nullable=False)
    target = Column(String(100), nullable=True)
    status = Column(String(20), nullable=False, default="SUCCESS")  # SUCCESS, FAILED, SKIPPED
    executed_at = Column(DateTime, default=get_utc_now, nullable=False)
    details_json = Column(Text, default="{}", nullable=False)

    incident = relationship("IncidentModel", back_populates="workflow_executions")

    __table_args__ = (
        Index("ix_wf_exec_ws_inc", "workspace_id", "incident_id"),
        Index("ix_wf_exec_time", "workspace_id", "executed_at"),
    )


class IncidentSLAPauseLogModel(Base):
    """
    Section 51: Forensic audit trail of every SLA pause, resume, or exemption change.
    """
    __tablename__ = "incident_sla_pause_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    action = Column(String(20), nullable=False)  # PAUSE, RESUME, EXEMPT, UNEXEMPT
    actor = Column(String(100), nullable=False)
    reason = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=get_utc_now, nullable=False)
    paused_duration_seconds = Column(Integer, nullable=True)

    incident = relationship("IncidentModel", back_populates="sla_pause_logs")

    @property
    def active(self) -> bool:
        return self.action == "PAUSE"

    @property
    def paused_at(self):
        return self.timestamp if self.action == "PAUSE" else None

    @property
    def resumed_at(self):
        return self.timestamp if self.action == "RESUME" else None

    __table_args__ = (
        Index("ix_sla_pause_inc_time", "incident_id", "timestamp"),
    )


# ============================================================================
# Section 52: Threat Intelligence & External Intelligence Enrichment
# ============================================================================

class ThreatIntelligenceRecordModel(Base):
    """
    Section 52: Persistent Threat Intelligence Enrichment Record.
    Stores external or internal provider observations for observables (IP, DOMAIN, URL, HASH, EMAIL, ASN, etc.)
    with strict provenance, freshness, confidence, verdict, and multi-tenant scoping.
    """
    __tablename__ = "threat_intelligence_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    indicator_type = Column(String(50), nullable=False, index=True)  # IP, DOMAIN, URL, SHA256, SHA1, MD5, EMAIL, CERTIFICATE, ASN, HOSTNAME
    indicator_value = Column(Text, nullable=False)  # Raw observed value
    normalized_value = Column(String(500), nullable=False, index=True)  # Normalized canonical representation
    provider = Column(String(100), nullable=False, index=True)  # internal_memory, cyberguard_feed, virustotal, abuseipdb, alienvault
    provider_record_id = Column(String(255), nullable=True)
    verdict = Column(String(50), nullable=False, default="UNKNOWN", index=True)  # UNKNOWN, CLEAN, SUSPICIOUS, MALICIOUS, UNVERIFIED
    confidence = Column(Float, nullable=False, default=0.5)  # 0.0 - 1.0 (distinct from risk)
    severity = Column(String(20), nullable=False, default="NONE", index=True)  # NONE, LOW, MEDIUM, HIGH, CRITICAL
    threat_types_json = Column(Text, nullable=False, default="[]")  # e.g. ["Phishing", "Botnet C2", "Malware"]
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    observed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    retrieved_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    source_url = Column(String(1000), nullable=True)
    raw_reference = Column(Text, nullable=True)
    normalized_data_json = Column(Text, default="{}", nullable=False)
    evidence_id = Column(String(36), nullable=True, index=True)
    is_stale = Column(Boolean, default=False, nullable=False)
    privacy_scope = Column(String(20), default="PUBLIC", nullable=False)  # PUBLIC, PRIVATE, INTERNAL, SENSITIVE, UNKNOWN
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_ti_ws_type_norm_prov", "workspace_id", "indicator_type", "normalized_value", "provider"),
        Index("ix_ti_norm_val", "normalized_value"),
        Index("ix_ti_retrieved", "retrieved_at"),
    )


class ThreatIntelProviderConfigModel(Base):
    """
    Section 52: Threat Intelligence Provider Configuration & Operational State.
    Defines provider capabilities, priority ordering, rate-limiting, and credentials.
    """
    __tablename__ = "threat_intel_provider_configs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    provider_name = Column(String(100), nullable=False, index=True)
    display_name = Column(String(100), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100, nullable=False)  # 1 = highest priority
    supported_types_json = Column(Text, default="[]", nullable=False)  # JSON array of supported indicator types
    rate_limit_per_minute = Column(Integer, default=60, nullable=False)
    timeout_seconds = Column(Float, default=5.0, nullable=False)
    api_key_ciphertext = Column(Text, nullable=True)  # Encrypted/masked server-side key
    api_endpoint = Column(String(500), nullable=True)
    status = Column(String(30), default="HEALTHY", nullable=False)  # HEALTHY, DEGRADED, RATE_LIMITED, UNAVAILABLE, MISCONFIGURED
    last_health_check_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    capabilities_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_tip_ws_prov", "workspace_id", "provider_name", unique=True),
        Index("ix_tip_ws_priority", "workspace_id", "priority"),
    )


# ============================================================================
# Section 53: IOC Watchlists & Continuous Threat Monitoring
# ============================================================================

class WatchlistModel(Base):
    """
    Section 53: Persistent Analyst Watchlist.
    Logical collection of high-value indicators & entities monitored continuously.
    """
    __tablename__ = "watchlists"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(150), nullable=False, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, PAUSED, ARCHIVED
    priority = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    owner_user_id = Column(String(100), nullable=True)
    team_id = Column(String(64), nullable=True)
    check_interval_minutes = Column(Integer, nullable=False, default=60)  # 15, 60, 360, 720, 1440, 10080
    change_sensitivity = Column(String(20), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH
    alert_threshold = Column(String(20), nullable=False, default="HIGH")  # LOW, MEDIUM, HIGH, CRITICAL, NONE
    notify_on_change = Column(Boolean, nullable=False, default=True)
    cooldown_minutes = Column(Integer, nullable=False, default=360)
    last_monitored_at = Column(DateTime, nullable=True)
    next_monitoring_cycle_at = Column(DateTime, nullable=True, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_by = Column(String(100), nullable=False, default="system")
    updated_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    items = relationship("WatchedIndicatorModel", back_populates="watchlist", cascade="all, delete-orphan")
    runs = relationship("WatchlistMonitoringRunModel", back_populates="watchlist", cascade="all, delete-orphan")
    changes = relationship("IntelligenceChangeModel", back_populates="watchlist", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_wl_ws_status", "workspace_id", "status"),
        Index("ix_wl_ws_next_cycle", "workspace_id", "next_monitoring_cycle_at"),
        Index("ix_wl_ws_priority", "workspace_id", "priority"),
    )


class WatchedIndicatorModel(Base):
    """
    Section 53: Monitored Indicator item within a Watchlist.
    Maintains check schedules, execution history, and pointers to intelligence snapshots.
    """
    __tablename__ = "watched_indicators"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    watchlist_id = Column(String(36), ForeignKey("watchlists.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_id = Column(String(36), ForeignKey("indicators.id", ondelete="SET NULL"), nullable=True, index=True)
    indicator_type = Column(String(50), nullable=False, index=True)  # IP, DOMAIN, URL, SHA256, SHA1, MD5, EMAIL, CERTIFICATE, ASN, HOSTNAME
    raw_value = Column(Text, nullable=False)
    normalized_value = Column(String(500), nullable=False, index=True)
    display_value = Column(String(500), nullable=False)
    monitoring_status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, PAUSED, CHECKING, HEALTHY, STALE, DEGRADED, ERROR
    priority = Column(String(20), nullable=False, default="MEDIUM", index=True)
    first_watched_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_checked_at = Column(DateTime, nullable=True)
    next_check_at = Column(DateTime, nullable=True, index=True)
    last_successful_check_at = Column(DateTime, nullable=True)
    last_failed_check_at = Column(DateTime, nullable=True)
    last_change_detected_at = Column(DateTime, nullable=True)
    last_snapshot_id = Column(String(36), nullable=True)
    last_verdict = Column(String(50), nullable=False, default="UNKNOWN")  # UNKNOWN, CLEAN, SUSPICIOUS, MALICIOUS
    last_confidence = Column(Float, nullable=False, default=0.0)
    last_severity = Column(String(20), nullable=False, default="NONE")
    failure_count = Column(Integer, nullable=False, default=0)
    consecutive_failure_count = Column(Integer, nullable=False, default=0)
    last_error_message = Column(Text, nullable=True)
    source_incident_id = Column(String(36), nullable=True, index=True)
    source_investigation_id = Column(String(128), nullable=True, index=True)
    created_by = Column(String(100), nullable=False, default="system")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    watchlist = relationship("WatchlistModel", back_populates="items")
    snapshots = relationship("IntelligenceSnapshotModel", back_populates="watched_indicator", cascade="all, delete-orphan")
    changes = relationship("IntelligenceChangeModel", back_populates="watched_indicator", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_wi_ws_wl_norm", "workspace_id", "watchlist_id", "normalized_value", unique=True),
        Index("ix_wi_ws_status_next", "workspace_id", "monitoring_status", "next_check_at"),
    )


class IntelligenceSnapshotModel(Base):
    """
    Section 53: Point-in-time normalized threat intelligence snapshot.
    Stores deterministic fingerprint for material change comparison.
    """
    __tablename__ = "intelligence_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    watched_indicator_id = Column(String(36), ForeignKey("watched_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)
    normalized_value = Column(String(500), nullable=False, index=True)
    provider_consensus_verdict = Column(String(50), nullable=False, default="UNKNOWN")
    consensus_confidence = Column(Float, nullable=False, default=0.0)
    severity = Column(String(20), nullable=False, default="NONE")
    sources_count = Column(Integer, nullable=False, default=1)
    has_conflicts = Column(Boolean, nullable=False, default=False)
    threat_types_json = Column(Text, nullable=False, default="[]")
    normalized_data_json = Column(Text, nullable=False, default="{}")
    fingerprint = Column(String(64), nullable=False, index=True)  # SHA256 of material attributes
    retrieved_at = Column(DateTime, default=get_utc_now, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    watched_indicator = relationship("WatchedIndicatorModel", back_populates="snapshots")

    __table_args__ = (
        Index("ix_snap_wi_time", "watched_indicator_id", "created_at"),
        Index("ix_snap_norm_fp", "normalized_value", "fingerprint"),
    )


class IntelligenceChangeModel(Base):
    """
    Section 53: Record of detected material change between snapshots.
    Tracks previous vs current state, severity, explanation, and created alerts.
    """
    __tablename__ = "intelligence_changes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    watchlist_id = Column(String(36), ForeignKey("watchlists.id", ondelete="CASCADE"), nullable=False, index=True)
    watched_indicator_id = Column(String(36), ForeignKey("watched_indicators.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)
    normalized_value = Column(String(500), nullable=False, index=True)
    change_type = Column(String(50), nullable=False, index=True)  # NEWLY_MALICIOUS, NEWLY_SUSPICIOUS, BECAME_CLEAN, VERDICT_CHANGED, CONFIDENCE_CHANGED, SEVERITY_CHANGED, PROVIDER_CONFLICT_CHANGED, ASN_CHANGED, HOSTING_CHANGED, CAMPAIGN_ASSOCIATION_CHANGED
    change_severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    previous_snapshot_id = Column(String(36), nullable=True)
    current_snapshot_id = Column(String(36), nullable=True)
    previous_verdict = Column(String(50), nullable=True)
    current_verdict = Column(String(50), nullable=True)
    previous_confidence = Column(Float, nullable=True)
    current_confidence = Column(Float, nullable=True)
    previous_severity = Column(String(20), nullable=True)
    current_severity = Column(String(20), nullable=True)
    change_summary = Column(Text, nullable=False)
    change_details_json = Column(Text, default="{}", nullable=False)
    alert_id = Column(String(36), nullable=True, index=True)
    notification_id = Column(String(36), nullable=True, index=True)
    acknowledged = Column(Boolean, nullable=False, default=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(100), nullable=True)
    detected_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    watchlist = relationship("WatchlistModel", back_populates="changes")
    watched_indicator = relationship("WatchedIndicatorModel", back_populates="changes")

    __table_args__ = (
        Index("ix_ic_ws_wl_time", "workspace_id", "watchlist_id", "detected_at"),
        Index("ix_ic_wi_time", "watched_indicator_id", "detected_at"),
    )


class WatchlistMonitoringRunModel(Base):
    """
    Section 53: Audit log of watchlist monitoring execution cycles.
    """
    __tablename__ = "watchlist_monitoring_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    watchlist_id = Column(String(36), ForeignKey("watchlists.id", ondelete="CASCADE"), nullable=False, index=True)
    job_id = Column(String(36), nullable=True, index=True)
    trigger_type = Column(String(30), nullable=False, default="SCHEDULED")  # SCHEDULED, MANUAL, EVENT_DRIVEN
    status = Column(String(30), nullable=False, default="RUNNING")  # QUEUED, RUNNING, SUCCEEDED, PARTIALLY_SUCCEEDED, FAILED, CANCELLED
    items_due = Column(Integer, nullable=False, default=0)
    items_checked = Column(Integer, nullable=False, default=0)
    items_changed = Column(Integer, nullable=False, default=0)
    items_failed = Column(Integer, nullable=False, default=0)
    alerts_created = Column(Integer, nullable=False, default=0)
    notifications_created = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, default=get_utc_now, nullable=False)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    run_summary_json = Column(Text, default="{}", nullable=False)

    watchlist = relationship("WatchlistModel", back_populates="runs")

    __table_args__ = (
        Index("ix_wmr_ws_wl_time", "workspace_id", "watchlist_id", "started_at"),
    )


# ============================================================================
# Section 54: Threat Hunting Workspace & Query Engine Models
# ============================================================================

class SavedHuntModel(Base):
    """
    Section 54: Persistent Saved Threat Hunt Query Definition.
    Preserves analytical hypotheses, structured filter expressions, data source scope,
    and team visibility controls.
    """
    __tablename__ = "saved_hunts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=True)
    data_source = Column(String(64), nullable=False, default="indicators", index=True)
    query_definition_json = Column(Text, nullable=False, default="{}")
    hypothesis = Column(Text, nullable=True)
    tags_json = Column(Text, nullable=False, default="[]")
    owner_user_id = Column(String(100), nullable=True, index=True)
    team_id = Column(String(64), nullable=True)
    visibility = Column(String(30), nullable=False, default="TEAM", index=True)  # PRIVATE, TEAM, TENANT
    is_template = Column(Boolean, nullable=False, default=False, index=True)
    last_executed_at = Column(DateTime, nullable=True)
    last_result_count = Column(Integer, nullable=True)
    created_by = Column(String(100), nullable=False, default="system")
    updated_by = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    executions = relationship("HuntExecutionModel", back_populates="saved_hunt", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_sh_ws_source", "workspace_id", "data_source"),
        Index("ix_sh_ws_vis", "workspace_id", "visibility"),
        Index("ix_sh_ws_owner", "workspace_id", "owner_user_id"),
    )


class HuntExecutionModel(Base):
    """
    Section 54: Audit Log and Execution History for Threat Hunts.
    Captures exact query definition, result count, matched record IDs, performance duration,
    and links to Section 45 Background Jobs.
    """
    __tablename__ = "hunt_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    saved_hunt_id = Column(String(36), ForeignKey("saved_hunts.id", ondelete="SET NULL"), nullable=True, index=True)
    data_source = Column(String(64), nullable=False, default="indicators", index=True)
    query_definition_json = Column(Text, nullable=False, default="{}")
    execution_mode = Column(String(30), nullable=False, default="FAST")  # FAST, BACKGROUND
    status = Column(String(30), nullable=False, default="RUNNING", index=True)  # QUEUED, RUNNING, SUCCEEDED, PARTIALLY_SUCCEEDED, FAILED, CANCELLED
    result_count = Column(Integer, nullable=False, default=0)
    matched_record_ids_json = Column(Text, nullable=False, default="[]")
    results_summary_json = Column(Text, nullable=False, default="{}")
    duration_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    executed_by = Column(String(100), nullable=False, default="system")
    job_id = Column(String(36), nullable=True, index=True)
    started_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)

    saved_hunt = relationship("SavedHuntModel", back_populates="executions")

    __table_args__ = (
        Index("ix_he_ws_source_time", "workspace_id", "data_source", "started_at"),
        Index("ix_he_ws_status", "workspace_id", "status"),
        Index("ix_he_ws_saved", "workspace_id", "saved_hunt_id"),
    )


class PivotExecutionModel(Base):
    """
    Section 55: Persistent Execution Log for Advanced Threat Hunting Pivots.
    Records provenance, source observable, target relationship, multi-hop traversal depth,
    duration, and background job linkage.
    """
    __tablename__ = "pivot_executions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    source_type = Column(String(50), nullable=False, index=True)
    source_value = Column(String(500), nullable=False, index=True)
    pivot_type = Column(String(64), nullable=False, index=True)
    execution_mode = Column(String(30), nullable=False, default="FAST")  # FAST, BACKGROUND
    status = Column(String(30), nullable=False, default="SUCCEEDED", index=True)  # QUEUED, RUNNING, SUCCEEDED, FAILED, CANCELLED
    depth = Column(Integer, nullable=False, default=1)
    result_count = Column(Integer, nullable=False, default=0)
    results_summary_json = Column(Text, nullable=False, default="{}")
    duration_ms = Column(Float, nullable=False, default=0.0)
    job_id = Column(String(36), nullable=True, index=True)
    executed_by = Column(String(100), nullable=False, default="analyst")
    investigation_id = Column(String(36), nullable=True, index=True)
    error_message = Column(Text, nullable=True)
    started_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    completed_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("ix_pe_ws_src_type_val", "workspace_id", "source_type", "source_value"),
        Index("ix_pe_ws_pivot_status", "workspace_id", "pivot_type", "status"),
    )


class HuntHypothesisModel(Base):
    """
    Section 55: Structured Analyst Investigation Hypothesis & Evidence Classification.
    Allows analysts to test propositions across pivoted entities (e.g., shared C2 infrastructure)
    and categorize discovered relationships into supporting, contradicting, or neutral evidence.
    """
    __tablename__ = "hunt_hypotheses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    investigation_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), nullable=False)
    hypothesis_text = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="PROPOSED", index=True)  # PROPOSED, INVESTIGATING, CONFIRMED, DISPROVED, ABANDONED
    source_observable = Column(String(500), nullable=True)
    supporting_items_json = Column(Text, nullable=False, default="[]")
    contradicting_items_json = Column(Text, nullable=False, default="[]")
    neutral_items_json = Column(Text, nullable=False, default="[]")
    analyst_notes = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=False, default="analyst")
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_hh_ws_status", "workspace_id", "status"),
        Index("ix_hh_ws_inv", "workspace_id", "investigation_id"),
    )


class DetectionMatchModel(Base):
    """
    Section 59: Persistent First-Class Detection Match representation.
    Bridges detection rules to findings, risk scores, alerts, and investigations.
    """
    __tablename__ = "detection_matches"

    id = Column(String(64), primary_key=True, default=lambda: f"DET-{generate_uuid()[:12]}")
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    rule_id = Column(String(36), ForeignKey("candidate_rules.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_version = Column(String(20), nullable=False, index=True)
    event_id = Column(String(64), nullable=False, index=True)
    execution_id = Column(String(36), ForeignKey("candidate_rule_executions.id", ondelete="SET NULL"), nullable=True, index=True)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_id = Column(String(36), ForeignKey("notifications.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    mode = Column(String(20), nullable=False, default="PRODUCTION", index=True)  # PRODUCTION, SHADOW, REPLAY
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, SUPPRESSED, DISMISSED, INVESTIGATED
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    matched_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    matched_fields_json = Column(Text, default="[]", nullable=False)
    evidence_json = Column(Text, default="{}", nullable=False)
    provenance_json = Column(Text, default="{}", nullable=False)
    explanation_text = Column(Text, default="", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    rule = relationship("CandidateRuleModel", back_populates="matches", foreign_keys=[rule_id])
    execution = relationship("CandidateRuleExecutionModel", foreign_keys=[execution_id])
    finding = relationship("FindingModel", foreign_keys=[finding_id])
    alert = relationship("NotificationModel", foreign_keys=[alert_id])
    incident = relationship("IncidentModel", foreign_keys=[incident_id])

    __table_args__ = (
        Index("ix_dm_ws_matched_at", "workspace_id", "matched_at"),
        Index("ix_dm_rule_matched_at", "rule_id", "matched_at"),
        Index("ix_dm_event_ws", "workspace_id", "event_id"),
        Index("ix_dm_mode_status", "mode", "status"),
    )

    @property
    def matched_fields(self) -> List[str]:
        try:
            return json.loads(self.matched_fields_json or "[]")
        except Exception:
            return []

    @property
    def evidence(self) -> Dict[str, Any]:
        try:
            return json.loads(self.evidence_json or "{}")
        except Exception:
            return {}

    @property
    def provenance(self) -> Dict[str, Any]:
        try:
            return json.loads(self.provenance_json or "{}")
        except Exception:
            return {}


class DetectionDeadLetterModel(Base):
    """
    Section 59: Dead-Letter Event Repository for Unrecoverable or Poison Telemetry.
    Prevents silent event dropping while ensuring non-blocking pipeline operation.
    """
    __tablename__ = "detection_dead_letters"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    event_id = Column(String(64), nullable=False, index=True)
    source_type = Column(String(50), nullable=False, default="GENERIC", index=True)
    failure_stage = Column(String(50), nullable=False, default="NORMALIZATION", index=True)  # NORMALIZATION, APPLICABILITY, EVALUATION, DOWNSTREAM
    error_code = Column(String(100), nullable=False, index=True)
    error_message = Column(Text, nullable=False)
    attempt_count = Column(Integer, nullable=False, default=1)
    payload_json = Column(Text, default="{}", nullable=False)
    provenance_json = Column(Text, default="{}", nullable=False)
    resolved = Column(Boolean, default=False, nullable=False, index=True)
    resolved_by = Column(String(100), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_ddl_ws_stage", "workspace_id", "failure_stage"),
        Index("ix_ddl_ws_created", "workspace_id", "created_at"),
    )

    @property
    def payload(self) -> Dict[str, Any]:
        try:
            return json.loads(self.payload_json or "{}")
        except Exception:
            return {}

    @property
    def provenance(self) -> Dict[str, Any]:
        try:
            return json.loads(self.provenance_json or "{}")
        except Exception:
            return {}


# ============================================================================
# SECTION 61: CROSS-SOURCE CORRELATION & UNIFIED ENTITY CORRELATION MODELS
# ============================================================================

def generate_correlation_number() -> str:
    return f"CORR-{datetime.now(timezone.utc).year}-{uuid.uuid4().hex[:6].upper()}"


class CrossSourceCorrelationModel(Base):
    """
    Persisted Cross-Source Correlation instance connecting signals, entities, findings,
    and threat intelligence from disparate CyberGuard data sources (Section 61).
    """
    __tablename__ = "cross_source_correlations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    correlation_number = Column(String(32), unique=True, nullable=False, index=True, default=generate_correlation_number)
    correlation_type = Column(String(64), nullable=False, index=True)  # SAME_ENTITY, SHARED_INFRASTRUCTURE, TEMPORAL_ATTACK_SEQUENCE, etc.
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(32), nullable=False, default="CORRELATED", index=True)  # CANDIDATE, CORRELATED, PARTIALLY_CORRELATED, STALE, INVALIDATED, ARCHIVED
    confidence_score = Column(Float, nullable=False, default=0.85)  # 0.0 - 1.0 (Distinct from risk!)
    confidence_level = Column(String(20), nullable=False, default="HIGH", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0 (Calculated by Unified Risk Engine)
    risk_level = Column(String(20), nullable=False, default="LOW", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # LOW, MEDIUM, HIGH, CRITICAL
    first_observed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    last_observed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    time_window_seconds = Column(Float, nullable=False, default=1800.0)  # e.g. 30 minutes
    idempotency_hash = Column(String(64), nullable=False, index=True)  # sha256 to prevent duplicate creation
    parent_finding_id = Column(String(36), ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True)
    alert_id = Column(String(36), nullable=True, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    campaign_id = Column(String(36), ForeignKey("campaigns.id", ondelete="SET NULL"), nullable=True, index=True)
    explanation_summary = Column(Text, nullable=False)
    supporting_reasons_json = Column(Text, default="[]", nullable=False)
    contradictions_json = Column(Text, default="[]", nullable=False)
    missing_context_json = Column(Text, default="[]", nullable=False)
    quality_metrics_json = Column(Text, default="{}", nullable=False)
    rule_version = Column(String(32), nullable=False, default="1.0.0")
    schema_version = Column(String(32), nullable=False, default="1.0.0")
    analyst_disposition = Column(String(32), nullable=True, index=True)  # CONFIRMED, REJECTED, UNCERTAIN
    analyst_notes = Column(Text, nullable=True)
    dispositioned_by = Column(String(100), nullable=True)
    dispositioned_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    members = relationship("CorrelationMemberModel", back_populates="correlation", cascade="all, delete-orphan", lazy="selectin")
    parent_finding = relationship("FindingModel", foreign_keys=[parent_finding_id])
    incident = relationship("IncidentModel", foreign_keys=[incident_id])
    campaign = relationship("CampaignModel", foreign_keys=[campaign_id])

    __table_args__ = (
        Index("ix_csc_ws_type_status", "workspace_id", "correlation_type", "status"),
        Index("ix_csc_ws_idempotency", "workspace_id", "idempotency_hash", unique=True),
        Index("ix_csc_ws_created", "workspace_id", "created_at"),
    )

    @property
    def supporting_reasons(self) -> List[str]:
        try:
            return json.loads(self.supporting_reasons_json or "[]")
        except Exception:
            return []

    @property
    def contradictions(self) -> List[str]:
        try:
            return json.loads(self.contradictions_json or "[]")
        except Exception:
            return []

    @property
    def missing_context(self) -> List[str]:
        try:
            return json.loads(self.missing_context_json or "[]")
        except Exception:
            return []

    @property
    def quality_metrics(self) -> Dict[str, Any]:
        try:
            return json.loads(self.quality_metrics_json or "{}")
        except Exception:
            return {}


class CorrelationMemberModel(Base):
    """
    Normalized association between a Cross-Source Correlation and its constituent members
    (Entities, Findings, Alerts, Incidents, Indicators, Evidence items, Relationships, Signals) (Section 61).
    """
    __tablename__ = "correlation_members"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    correlation_id = Column(String(36), ForeignKey("cross_source_correlations.id", ondelete="CASCADE"), nullable=False, index=True)
    member_type = Column(String(32), nullable=False, index=True)  # ENTITY, FINDING, ALERT, INCIDENT, INDICATOR, EVIDENCE, RELATIONSHIP, SIGNAL
    member_id = Column(String(128), nullable=False, index=True)
    source_type = Column(String(50), nullable=False, default="GENERIC", index=True)  # EMAIL, ENDPOINT, NETWORK, AUTH, API, BEHAVIORAL, DETECTION_RULE, THREAT_INTEL, WATCHLIST
    role = Column(String(32), nullable=False, default="SUPPORTING", index=True)  # PRIMARY, SUPPORTING, PIVOT, OBSERVED
    occurred_at = Column(DateTime, nullable=True, index=True)
    confidence = Column(Float, nullable=False, default=1.0)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    correlation = relationship("CrossSourceCorrelationModel", back_populates="members")

    __table_args__ = (
        Index("ix_cm_corr_member", "correlation_id", "member_type", "member_id"),
        Index("ix_cm_member_type_id", "member_type", "member_id"),
    )

    @property
    def metadata_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.metadata_json or "{}")
        except Exception:
            return {}


class EntityResolutionRecordModel(Base):
    """
    Immutable audit record of a deterministic entity resolution decision
    mapping raw/external identifiers to canonical knowledge graph entities (Section 61).
    """
    __tablename__ = "entity_resolution_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    entity_type = Column(String(50), nullable=False, index=True)  # USER, ACCOUNT, DEVICE, ENDPOINT, IP, DOMAIN, URL, EMAIL, HASH, PROCESS, API_CLIENT
    canonical_entity_id = Column(String(128), nullable=False, index=True)
    raw_identifier = Column(Text, nullable=False)
    normalized_identifier = Column(String(500), nullable=False, index=True)
    resolution_method = Column(String(50), nullable=False, index=True)  # EXACT_ID, CANONICAL_NORMALIZATION, COMPOSITE_KEY, GRAPH_LINK, FUZZY_MATCH, UNRESOLVED
    resolution_confidence = Column(Float, nullable=False, default=1.0)
    status = Column(String(32), nullable=False, default="RESOLVED", index=True)  # RESOLVED, AMBIGUOUS, UNRESOLVED
    matched_attributes_json = Column(Text, default="{}", nullable=False)
    provenance_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_err_ws_type_norm", "workspace_id", "entity_type", "normalized_identifier"),
        Index("ix_err_ws_canonical", "workspace_id", "canonical_entity_id"),
    )

    @property
    def matched_attributes(self) -> Dict[str, Any]:
        try:
            return json.loads(self.matched_attributes_json or "{}")
        except Exception:
            return {}

    @property
    def provenance(self) -> Dict[str, Any]:
        try:
            return json.loads(self.provenance_json or "{}")
        except Exception:
            return {}


# ============================================================================
# SECTION 62: ATTACK SURFACE INTELLIGENCE MODELS
# ============================================================================

class AssetModel(Base):
    """
    Section 62: Normalized Asset representation.
    Tracks internal, external, and identity assets, their exposure state, ownership,
    criticality, and links to Knowledge Graph entities.
    """
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    asset_type = Column(String(50), nullable=False, index=True)  # DOMAIN, SUBDOMAIN, PUBLIC_IP, PRIVATE_IP, ENDPOINT, SERVER, DEVICE, APPLICATION, WEB_APPLICATION, API, SERVICE, CERTIFICATE, CLOUD_RESOURCE, EMAIL_INFRASTRUCTURE, IDENTITY, USER_ACCOUNT, SERVICE_ACCOUNT
    canonical_name = Column(String(500), nullable=False, index=True)  # Lowercased FQDN, standardized IP, device UID, user email
    display_name = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # DISCOVERED, ACTIVE, INACTIVE, STALE, RETIRED, UNKNOWN
    exposure_state = Column(String(32), nullable=False, default="UNKNOWN", index=True)  # PUBLICLY_EXPOSED, INTERNALLY_REACHABLE, INTERNALLY_ONLY, UNKNOWN
    criticality = Column(String(20), nullable=False, default="MEDIUM", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
    owner = Column(String(100), nullable=True)  # Owner name/email, "Unknown" if unassigned
    team = Column(String(100), nullable=True)
    business_unit = Column(String(100), nullable=True)
    environment = Column(String(32), nullable=False, default="UNKNOWN", index=True)  # PRODUCTION, STAGING, DEVELOPMENT, CORP, LAB, UNKNOWN
    ownership_confidence = Column(String(30), nullable=False, default="UNKNOWN")  # MANUAL, CMDB, DIRECTORY, ENDPOINT_AGENT, CLOUD_INVENTORY, DOMAIN_MAPPING, INFERENCE, UNKNOWN
    source = Column(String(50), nullable=False, default="INTERNAL_DISCOVERY", index=True)  # ENDPOINT_AGENT, EMAIL_ANALYSIS, URL_ANALYSIS, DOMAIN_ANALYSIS, NETWORK_TELEMETRY, API_TELEMETRY, AUTHENTICATION, THREAT_INTELLIGENCE, WATCHLIST, INVESTIGATION, THREAT_HUNT, MANUAL_ANALYST, EXTERNAL_DISCOVERY, INTERNAL_DISCOVERY
    external_id = Column(String(255), nullable=True, index=True)  # Pointer to DeviceModel.id, ProtectedIdentityModel.id, or external CMDB
    canonical_entity_id = Column(String(128), nullable=True, index=True)  # Pointer to Knowledge Graph EntityModel.id
    risk_score = Column(Float, nullable=False, default=0.0)  # Bounded risk from Unified Risk Engine (0.0 - 100.0)
    risk_level = Column(String(20), nullable=False, default="LOW")
    active_finding_count = Column(Integer, nullable=False, default=0)
    active_exposure_count = Column(Integer, nullable=False, default=0)
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    department = Column(String(100), nullable=True)
    ownership_status = Column(String(32), nullable=False, default="UNASSIGNED", index=True)  # ASSIGNED, UNASSIGNED, UNKNOWN, CONFLICTED, INFERRED
    classification = Column(String(50), nullable=True, index=True)  # SERVER, WORKSTATION, LAPTOP, MOBILE, DATABASE, APPLICATION, API, NETWORK_DEVICE, CLOUD_RESOURCE
    tags_json = Column(Text, default="[]", nullable=False)
    last_observed_at = Column(DateTime, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    is_managed = Column(Boolean, default=True, nullable=False, index=True)
    is_stale = Column(Boolean, default=False, nullable=False, index=True)
    last_scanned_at = Column(DateTime, nullable=True)
    last_analyzed_at = Column(DateTime, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)

    # Section 64: Risk-Based Asset Prioritization
    priority_band = Column(String(16), nullable=False, default="UNPRIORITIZED", index=True)  # P1, P2, P3, P4, UNPRIORITIZED
    priority_score = Column(Float, nullable=False, default=0.0, index=True)  # Bounded operational priority score (0.0 - 100.0)
    priority_calculated_at = Column(DateTime, nullable=True)
    priority_policy_id = Column(String(36), nullable=True)
    priority_policy_version = Column(Integer, nullable=True, default=1)
    priority_override = Column(String(16), nullable=True)  # P1, P2, P3, P4
    priority_override_reason = Column(Text, nullable=True)
    priority_override_by = Column(String(100), nullable=True)
    priority_override_at = Column(DateTime, nullable=True)
    priority_override_expires_at = Column(DateTime, nullable=True)
    priority_explanation_json = Column(Text, default="{}", nullable=False)
    priority_data_quality = Column(String(20), nullable=False, default="UNKNOWN", index=True)  # GOOD, DEGRADED, STALE, UNKNOWN

    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    exposures = relationship("ExposureModel", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")
    services = relationship("AssetServiceModel", back_populates="asset", cascade="all, delete-orphan", lazy="selectin")

    __table_args__ = (
        Index("ix_assets_ws_type_canon", "workspace_id", "asset_type", "canonical_name", unique=True),
        Index("ix_assets_ws_status_exp", "workspace_id", "status", "exposure_state"),
        Index("ix_assets_ws_crit_risk", "workspace_id", "criticality", "risk_score"),
        Index("ix_assets_ws_last_seen", "workspace_id", "last_seen_at"),
        Index("ix_assets_ws_own_stale", "workspace_id", "ownership_status", "is_stale"),
        Index("ix_assets_ws_prio", "workspace_id", "priority_band", "priority_score"),
    )

    @property
    def metadata_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.metadata_json or "{}")
        except Exception:
            return {}

    @property
    def tags_list(self) -> List[str]:
        try:
            return json.loads(self.tags_json or "[]")
        except Exception:
            return []

    @property
    def priority_explanation_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.priority_explanation_json or "{}")
        except Exception:
            return {}

    @property
    def effective_priority(self) -> str:
        if self.priority_override:
            if self.priority_override_expires_at:
                now = datetime.now(timezone.utc)
                exp = self.priority_override_expires_at
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                if now > exp:
                    return self.priority_band
            return self.priority_override
        return self.priority_band


class ExposureModel(Base):
    """
    Section 62: Actionable Asset Exposure representation.
    Tracks security exposures (public exposure, unknown assets, unmapped domains,
    unapproved ports, exposed APIs) separate from software vulnerabilities.
    """
    __tablename__ = "asset_exposures"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    exposure_type = Column(String(50), nullable=False, index=True)  # PUBLIC_ASSET, UNKNOWN_ASSET, UNKNOWN_SERVICE, EXPOSED_API, EXPOSED_IDENTITY, STALE_ASSET, UNMAPPED_DOMAIN, UNEXPECTED_ENDPOINT, UNAPPROVED_PORT, CERTIFICATE_EXPIRING
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="OPEN", index=True)  # OPEN, RESOLVED, ACCEPTED, SUPPRESSED, STALE, UNKNOWN
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(Float, nullable=False, default=1.0)
    remediation_guidance = Column(Text, nullable=True)
    evidence_refs_json = Column(Text, default="[]", nullable=False)
    source_refs_json = Column(Text, default="[]", nullable=False)
    risk_context_json = Column(Text, default="{}", nullable=False)
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    asset = relationship("AssetModel", back_populates="exposures")

    __table_args__ = (
        Index("ix_ae_ws_status_sev", "workspace_id", "status", "severity"),
        Index("ix_ae_ws_type", "workspace_id", "exposure_type"),
        Index("ix_ae_asset_type_status", "asset_id", "exposure_type", "status"),
    )

    @property
    def evidence_refs(self) -> List[str]:
        try:
            return json.loads(self.evidence_refs_json or "[]")
        except Exception:
            return []

    @property
    def source_refs(self) -> List[str]:
        try:
            return json.loads(self.source_refs_json or "[]")
        except Exception:
            return []

    @property
    def risk_context(self) -> Dict[str, Any]:
        try:
            return json.loads(self.risk_context_json or "{}")
        except Exception:
            return {}


class AssetServiceModel(Base):
    """
    Section 62: Network Service & Port observation associated with an asset.
    Preserves actual observed port, protocol, service banner, and exposure without speculation.
    """
    __tablename__ = "asset_services"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    port = Column(Integer, nullable=True, index=True)
    protocol = Column(String(20), nullable=False, default="TCP")  # TCP, UDP, ICMP
    service_name = Column(String(100), nullable=False, default="unknown", index=True)  # HTTP, HTTPS, SSH, SMTP, DNS, RDP, API, etc.
    service_version = Column(String(100), nullable=True)
    transport = Column(String(20), nullable=False, default="IP")
    exposure = Column(String(30), nullable=False, default="UNKNOWN", index=True)  # PUBLIC, INTERNAL, RESTRICTED, UNKNOWN
    source = Column(String(50), nullable=False, default="DISCOVERY")
    banner_snippet = Column(Text, nullable=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    asset = relationship("AssetModel", back_populates="services")

    __table_args__ = (
        Index("ix_as_asset_port_proto", "asset_id", "port", "protocol"),
        Index("ix_as_ws_service_exp", "workspace_id", "service_name", "exposure"),
    )

    @property
    def metadata_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.metadata_json or "{}")
        except Exception:
            return {}


class AttackSurfaceScopeModel(Base):
    """
    Section 62: Explicit, tenant-authorized attack surface discovery scope.
    Strictly controls which domains, CIDRs, IPs, or cloud accounts CyberGuard is authorized
    to evaluate, preventing uncontrolled internet scanning.
    """
    __tablename__ = "attack_surface_scopes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    scope_type = Column(String(30), nullable=False, index=True)  # DOMAIN, CIDR, IP, CLOUD_ACCOUNT, ASN
    target = Column(String(255), nullable=False, index=True)  # e.g. "company.example", "*.company.example", "203.0.113.0/24"
    is_authorized = Column(Boolean, nullable=False, default=True, index=True)
    description = Column(Text, default="", nullable=False)
    created_by = Column(String(100), nullable=False, default="system")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_ass_ws_target", "workspace_id", "target", unique=True),
    )


class AttackSurfaceSnapshotModel(Base):
    """
    Section 62: Periodic attack surface evaluation snapshot.
    Enables diff comparison (added assets, removed assets, new exposures, resolved exposures)
    between inspection cycles without losing historical evidence.
    """
    __tablename__ = "attack_surface_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    snapshot_name = Column(String(255), nullable=False)
    total_assets = Column(Integer, nullable=False, default=0)
    exposed_assets = Column(Integer, nullable=False, default=0)
    unknown_assets = Column(Integer, nullable=False, default=0)
    open_exposures = Column(Integer, nullable=False, default=0)
    critical_assets = Column(Integer, nullable=False, default=0)
    high_risk_assets = Column(Integer, nullable=False, default=0)
    assets_added = Column(Integer, nullable=False, default=0)
    assets_removed = Column(Integer, nullable=False, default=0)
    exposures_added = Column(Integer, nullable=False, default=0)
    exposures_resolved = Column(Integer, nullable=False, default=0)
    diff_summary_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_assnap_ws_time", "workspace_id", "created_at"),
    )

    @property
    def diff_summary(self) -> Dict[str, Any]:
        try:
            return json.loads(self.diff_summary_json or "{}")
        except Exception:
            return {}


# ============================================================================
# SECTION 63: ASSET & IDENTITY INVENTORY MODELS
# ============================================================================

class IdentityModel(Base):
    """
    Section 63: Authoritative Enterprise Identity & Account Representation.
    Tracks human users, accounts, service accounts, and API identities, their privileges,
    associated assets, manager/team lineage, and authentication freshness.
    """
    __tablename__ = "identities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    identity_type = Column(String(32), nullable=False, default="USER", index=True)  # USER, ACCOUNT, SERVICE_ACCOUNT, APPLICATION_IDENTITY, API_CLIENT
    canonical_identifier = Column(String(255), nullable=False, index=True)  # Lowercased email, UPN, directory username
    display_name = Column(String(255), nullable=False, index=True)
    email = Column(String(255), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)
    department = Column(String(100), nullable=True)
    team = Column(String(100), nullable=True)
    business_unit = Column(String(100), nullable=True)
    manager = Column(String(255), nullable=True)
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE, INACTIVE, DORMANT, SUSPENDED, RETIRED, UNKNOWN
    criticality = Column(String(20), nullable=False, default="MEDIUM", index=True)  # CRITICAL, HIGH, MEDIUM, LOW
    is_privileged = Column(Boolean, default=False, nullable=False, index=True)  # Administrator, high-privilege account
    is_service_account = Column(Boolean, default=False, nullable=False, index=True)
    is_orphaned = Column(Boolean, default=False, nullable=False, index=True)  # Missing known owner or application
    is_dormant = Column(Boolean, default=False, nullable=False, index=True)  # Inactive authentication > threshold
    source = Column(String(50), nullable=False, default="DIRECTORY", index=True)  # DIRECTORY, IDP, HR_SYSTEM, ENDPOINT_AGENT, CLOUD_IAM, MANUAL_ANALYST
    external_id = Column(String(255), nullable=True, index=True)  # Directory GUID, IdP object ID
    canonical_entity_id = Column(String(128), nullable=True, index=True)  # Link to Knowledge Graph EntityModel.id
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(20), nullable=False, default="LOW")
    first_seen_at = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    last_authenticated_at = Column(DateTime, nullable=True)
    last_sync_at = Column(DateTime, nullable=True)
    tags_json = Column(Text, default="[]", nullable=False)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_identities_ws_canon", "workspace_id", "canonical_identifier", unique=True),
        Index("ix_identities_ws_status_type", "workspace_id", "status", "identity_type"),
        Index("ix_identities_ws_priv_orph", "workspace_id", "is_privileged", "is_orphaned"),
    )

    @property
    def metadata_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.metadata_json or "{}")
        except Exception:
            return {}

    @property
    def tags_list(self) -> List[str]:
        try:
            return json.loads(self.tags_json or "[]")
        except Exception:
            return []


class InventorySourceModel(Base):
    """
    Section 63: Controlled Inventory Source Registry.
    Tracks authoritative systems (CMDB, IdP, Agent, Cloud) and their deterministic precedence weights.
    """
    __tablename__ = "inventory_sources"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    source_type = Column(String(32), nullable=False, index=True)  # DIRECTORY, CMDB, ENDPOINT_AGENT, CLOUD_PROVIDER, APPLICATION_REGISTRY, NETWORK_TELEMETRY, MANUAL
    name = Column(String(128), nullable=False)
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # ACTIVE, DEGRADED, OFFLINE, PAUSED
    authority_weight = Column(Integer, nullable=False, default=50)  # e.g., CMDB=100, Directory=80, Agent=60, Cloud=50, Network=40, Inferred=20
    sync_interval_seconds = Column(Integer, nullable=False, default=3600)
    last_sync_at = Column(DateTime, nullable=True)
    last_sync_status = Column(String(32), nullable=True)  # SUCCESS, PARTIAL, FAILED
    last_sync_record_count = Column(Integer, nullable=False, default=0)
    health_status = Column(String(32), nullable=False, default="HEALTHY")  # HEALTHY, DEGRADED, UNHEALTHY
    capabilities_json = Column(Text, default="[]", nullable=False)
    config_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_inv_sources_ws_type", "workspace_id", "source_type"),
    )

    @property
    def capabilities_list(self) -> List[str]:
        try:
            return json.loads(self.capabilities_json or "[]")
        except Exception:
            return []


class InventoryConflictModel(Base):
    """
    Section 63: Source Conflict Registry & Review Workspace.
    Tracks discrepancies between authoritative sources (e.g., CMDB owner vs Directory owner)
    with source authority justification and audit resolution state.
    """
    __tablename__ = "inventory_conflicts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    target_type = Column(String(32), nullable=False, index=True)  # ASSET, IDENTITY
    target_id = Column(String(36), nullable=False, index=True)
    target_canonical_name = Column(String(255), nullable=False, index=True)
    field_name = Column(String(64), nullable=False, index=True)  # owner, team, environment, criticality, status
    conflicting_values_json = Column(Text, default="[]", nullable=False)  # Array of {source, source_id, value, authority_weight, observed_at}
    resolved_value = Column(String(255), nullable=True)
    resolved_source = Column(String(64), nullable=True)
    resolution_reason = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="PENDING_REVIEW", index=True)  # AUTO_RESOLVED, PENDING_REVIEW, MANUALLY_RESOLVED, IGNORED
    resolved_by = Column(String(100), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_inv_conflicts_ws_status", "workspace_id", "status"),
        Index("ix_inv_conflicts_target", "target_type", "target_id"),
    )

    @property
    def conflicting_values_list(self) -> List[Dict[str, Any]]:
        try:
            return json.loads(self.conflicting_values_json or "[]")
        except Exception:
            return []


class InventoryOverrideModel(Base):
    """
    Section 63: Manual Analyst Metadata Overrides.
    Captures manual edits with full audit trail, preserving original source values.
    """
    __tablename__ = "inventory_overrides"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    target_type = Column(String(32), nullable=False, index=True)  # ASSET, IDENTITY
    target_id = Column(String(36), nullable=False, index=True)
    field_name = Column(String(64), nullable=False, index=True)
    previous_value = Column(String(255), nullable=True)
    new_value = Column(String(255), nullable=False)
    reason = Column(Text, nullable=True)
    actor = Column(String(100), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_inv_overrides_ws_target", "workspace_id", "target_type", "target_id"),
    )


# ============================================================================
# SECTION 64: RISK-BASED ASSET PRIORITIZATION MODELS
# ============================================================================

class AssetPrioritizationPolicyModel(Base):
    """
    Section 64: Versioned Operational Asset Prioritization Policy.
    Defines configurable, deterministic factor weights and thresholds for ranking assets.
    """
    __tablename__ = "asset_prioritization_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    version = Column(Integer, nullable=False, default=1)
    status = Column(String(20), nullable=False, default="ACTIVE", index=True)  # ACTIVE, DRAFT, DISABLED, ARCHIVED
    configuration_json = Column(Text, nullable=False)
    created_by = Column(String(100), nullable=False, default="SYSTEM")
    activated_at = Column(DateTime, nullable=True)
    deactivated_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_prio_pol_ws_status_ver", "workspace_id", "status", "version"),
    )

    @property
    def configuration_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.configuration_json or "{}")
        except Exception:
            return {}


class AssetPrioritySnapshotModel(Base):
    """
    Section 64: Immutable historical snapshot of an asset priority evaluation.
    Provides complete auditability of priority transitions and factor contributions.
    """
    __tablename__ = "asset_priority_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    priority_band = Column(String(16), nullable=False, index=True)  # P1, P2, P3, P4, UNPRIORITIZED
    priority_score = Column(Float, nullable=False, default=0.0)
    policy_id = Column(String(36), nullable=False, index=True)
    policy_version = Column(Integer, nullable=False, default=1)
    risk_score = Column(Float, nullable=False, default=0.0)
    business_criticality = Column(String(20), nullable=False, default="UNKNOWN")
    exposure_state = Column(String(32), nullable=False, default="UNKNOWN")
    active_incident_count = Column(Integer, nullable=False, default=0)
    data_quality = Column(String(20), nullable=False, default="UNKNOWN")  # GOOD, DEGRADED, STALE, UNKNOWN
    explanation_json = Column(Text, nullable=False, default="{}")
    is_override = Column(Boolean, default=False, nullable=False)
    override_priority = Column(String(16), nullable=True)
    override_reason = Column(Text, nullable=True)
    override_by = Column(String(100), nullable=True)
    previous_priority_band = Column(String(16), nullable=True)
    transition_type = Column(String(32), nullable=False, default="INITIAL")  # INITIAL, ESCALATED, DEESCALATED, UNCHANGED, OVERRIDDEN, EXPIRED
    calculated_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_prio_snap_ws_asset_time", "workspace_id", "asset_id", "calculated_at"),
    )

    @property
    def explanation_dict(self) -> Dict[str, Any]:
        try:
            return json.loads(self.explanation_json or "{}")
        except Exception:
            return {}


# =============================================================================
# Section 65: Threat Actor & Campaign Workspace Models
# =============================================================================

class ThreatActorModel(Base):
    """
    Section 65: Threat Actor Profile & Intelligence Entity.
    Represents suspected or known adversarial groups, clusters, or threat operators.
    Maintains aliases with provider provenance, explicit attribution states,
    confidence levels, motivation, sophistication, and observed technique mappings.
    """
    __tablename__ = "threat_actors"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    actor_id = Column(String(32), unique=True, nullable=False, index=True)  # e.g., TA-001, ACTOR-042
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(255), nullable=False, index=True)
    canonical_name = Column(String(255), nullable=False, index=True)
    actor_type = Column(String(50), nullable=False, default="UNKNOWN", index=True)  # NATION_STATE, CYBERCRIME, HACKTIVIST, INSIDER, OPPORTUNISTIC, UNKNOWN
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, MONITORING, DORMANT, RETIRED, UNKNOWN
    attribution_state = Column(String(30), nullable=False, default="SUSPECTED", index=True)  # UNKNOWN, SUSPECTED, POSSIBLE, PROBABLE, ASSESSED, CONFIRMED, DISPUTED, REJECTED
    attribution_confidence = Column(Float, nullable=False, default=0.5)  # 0.0 - 1.0 (strictly separate from risk/severity)
    motivation = Column(String(100), nullable=True)  # FINANCIAL, ESPIONAGE, SABOTAGE, CREDENTIAL_HARVESTING
    sophistication = Column(String(50), nullable=False, default="UNKNOWN")  # ADVANCED, INTERMEDIATE, COMMODITY, UNKNOWN
    description = Column(Text, nullable=True)
    first_observed_at = Column(DateTime, nullable=True, index=True)
    last_observed_at = Column(DateTime, nullable=True, index=True)
    aliases_json = Column(Text, nullable=False, default="[]")  # Array of {alias, source, source_record_id, observed_at, confidence}
    primary_targets_json = Column(Text, nullable=False, default="[]")  # Target sectors, regions, orgs
    observed_techniques_json = Column(Text, nullable=False, default="[]")  # MITRE ATT&CK technique IDs
    observed_infrastructure_json = Column(Text, nullable=False, default="[]")  # Known IPs, domains, ASNs
    supporting_evidence_json = Column(Text, nullable=False, default="[]")
    contradicting_evidence_json = Column(Text, nullable=False, default="[]")
    analyst_notes_json = Column(Text, nullable=False, default="[]")
    created_by = Column(String(100), nullable=False, default="ANALYST")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    campaigns = relationship("CampaignModel", back_populates="threat_actor", lazy="selectin")

    __table_args__ = (
        Index("ix_ta_ws_name", "workspace_id", "name"),
        Index("ix_ta_ws_status", "workspace_id", "status"),
        Index("ix_ta_ws_attr", "workspace_id", "attribution_state"),
    )


class ThreatHypothesisModel(Base):
    """
    Section 65: Analyst-Authored Threat Hypothesis.
    Explicitly tracks hypotheses separate from observed facts.
    Maintains hypothesis lifecycle (OPEN, SUPPORTED, WEAKENED, REJECTED, CONFIRMED)
    with supporting and contradicting evidence.
    """
    __tablename__ = "threat_hypotheses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    subject_type = Column(String(30), nullable=False, index=True)  # CAMPAIGN, THREAT_ACTOR, INFRASTRUCTURE
    subject_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    hypothesis_text = Column(Text, nullable=False)
    status = Column(String(30), nullable=False, default="OPEN", index=True)  # OPEN, SUPPORTED, WEAKENED, REJECTED, CONFIRMED
    confidence = Column(Float, nullable=False, default=0.5)  # 0.0 - 1.0
    supporting_evidence_json = Column(Text, nullable=False, default="[]")
    contradicting_evidence_json = Column(Text, nullable=False, default="[]")
    created_by = Column(String(100), nullable=False, default="ANALYST")
    updated_by = Column(String(100), nullable=False, default="ANALYST")
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_th_ws_subj", "workspace_id", "subject_type", "subject_id"),
        Index("ix_th_status", "status"),
    )


class ThreatAttributionAssessmentModel(Base):
    """
    Section 65: Attribution Assessment Audit Record.
    Immutable log capturing every state transition in threat actor or campaign attribution.
    Stores prior state, new state, analyst justification, supporting/contradicting evidence,
    and external intelligence conflicts.
    """
    __tablename__ = "threat_attribution_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    subject_type = Column(String(30), nullable=False, index=True)  # CAMPAIGN, THREAT_ACTOR
    subject_id = Column(String(64), nullable=False, index=True)
    target_type = Column(String(30), nullable=False)  # THREAT_ACTOR, UNKNOWN
    target_id = Column(String(64), nullable=True, index=True)
    prior_attribution_state = Column(String(30), nullable=False)
    new_attribution_state = Column(String(30), nullable=False)  # UNKNOWN, SUSPECTED, POSSIBLE, PROBABLE, ASSESSED, CONFIRMED, DISPUTED, REJECTED
    confidence = Column(Float, nullable=False, default=0.5)
    justification = Column(Text, nullable=False)
    supporting_evidence_json = Column(Text, nullable=False, default="[]")
    contradicting_evidence_json = Column(Text, nullable=False, default="[]")
    external_conflicts_json = Column(Text, nullable=False, default="[]")
    assessed_by = Column(String(100), nullable=False, default="ANALYST")
    assessed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_taa_ws_subj", "workspace_id", "subject_type", "subject_id"),
        Index("ix_taa_time", "assessed_at"),
    )


class ThreatActorRelationshipModel(Base):
    """
    Section 65: Threat Workspace Relationship with Semantic Classification.
    Enforces clear semantic classification (OBSERVED vs CORRELATED vs HYPOTHESIZED vs ASSESSED).
    Connects actors/campaigns to indicators, infrastructure, assets, identities, or techniques.
    """
    __tablename__ = "threat_actor_relationships"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    source_type = Column(String(30), nullable=False, index=True)  # THREAT_ACTOR, CAMPAIGN
    source_id = Column(String(64), nullable=False, index=True)
    target_type = Column(String(30), nullable=False, index=True)  # INDICATOR, INFRASTRUCTURE, TECHNIQUE, ASSET, IDENTITY, ALERT, INCIDENT
    target_id = Column(String(255), nullable=False, index=True)
    target_value = Column(String(500), nullable=False)
    relationship_type = Column(String(64), nullable=False)  # OPERATES_INFRASTRUCTURE, USES_TECHNIQUE, TARGETS_ASSET, TARGETS_IDENTITY, ASSOCIATED_IOC
    semantic_class = Column(String(30), nullable=False, default="OBSERVED", index=True)  # OBSERVED, CORRELATED, INFERRED, HYPOTHESIZED, ASSESSED, EXTERNAL_INTELLIGENCE, ANALYST_ASSERTED
    confidence = Column(Float, nullable=False, default=1.0)
    is_contradicting = Column(Boolean, nullable=False, default=False)
    evidence_summary = Column(Text, nullable=True)
    provenance_source = Column(String(100), nullable=False, default="INTERNAL_TELEMETRY")
    first_observed_at = Column(DateTime, nullable=True)
    last_observed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_tar_src", "workspace_id", "source_type", "source_id"),
        Index("ix_tar_tgt", "workspace_id", "target_type", "target_id"),
        Index("ix_tar_sem", "semantic_class"),
    )


# =============================================================================
# Section 66: Advanced Investigation Automation Models
# =============================================================================

class InvestigationAutomationRunModel(Base):
    """
    Section 66: Persistent record of an investigation automation execution.
    Represents an authorized, bounded execution of planned investigation steps
    for an authoritative investigation/incident.
    """
    __tablename__ = "investigation_automation_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    investigation_id = Column(String(64), nullable=False, index=True)
    trigger_type = Column(String(64), nullable=False, default="MANUAL_ANALYST", index=True)
    mode = Column(String(32), nullable=False, default="ASSISTED")  # MANUAL, ASSISTED, POLICY_AUTOMATIC
    template_name = Column(String(64), nullable=False, default="GENERAL_INCIDENT_INVESTIGATION")
    plan_version = Column(String(32), nullable=False, default="v1.0")
    status = Column(String(32), nullable=False, default="QUEUED", index=True)  # QUEUED, PLANNING, RUNNING, PARTIALLY_COMPLETED, WAITING_FOR_ANALYST, COMPLETED, FAILED, CANCELLED, TIMED_OUT
    budget_json = Column(Text, nullable=False, default="{}")  # max_steps, max_time_seconds, max_depth, max_entities, max_hunts
    visited_entities_json = Column(Text, nullable=False, default="[]")  # loop prevention tracking
    total_steps = Column(Integer, nullable=False, default=0)
    completed_steps = Column(Integer, nullable=False, default=0)
    failed_steps = Column(Integer, nullable=False, default=0)
    coverage_summary_json = Column(Text, nullable=False, default="{}")
    investigation_summary_json = Column(Text, nullable=False, default="{}")  # knowns, unknowns, assessment, next steps
    error_message = Column(Text, nullable=True)
    created_by = Column(String(100), nullable=False, default="SOC Analyst")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    steps = relationship("InvestigationAutomationStepModel", back_populates="run", cascade="all, delete-orphan", order_by="InvestigationAutomationStepModel.step_index")
    gaps = relationship("InvestigationGapModel", back_populates="run")

    __table_args__ = (
        Index("ix_iar_ws_inv", "workspace_id", "investigation_id"),
        Index("ix_iar_status", "status"),
    )


class InvestigationAutomationStepModel(Base):
    """
    Section 66: Discrete, bounded investigation step within an automation run.
    Contains explicit typed action, parameters, execution state, and output summary.
    """
    __tablename__ = "investigation_automation_steps"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    run_id = Column(String(36), ForeignKey("investigation_automation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    step_index = Column(Integer, nullable=False)
    action_id = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    cost_class = Column(String(32), nullable=False, default="NORMAL")  # FAST, NORMAL, EXPENSIVE, BACKGROUND
    approval_level = Column(String(32), nullable=False, default="READ_ONLY_AUTOMATIC")  # READ_ONLY_AUTOMATIC, READ_ONLY_APPROVAL_OPTIONAL, ANALYST_APPROVAL_REQUIRED, ADMIN_APPROVAL_REQUIRED, FORBIDDEN
    status = Column(String(32), nullable=False, default="QUEUED", index=True)  # QUEUED, WAITING_APPROVAL, RUNNING, COMPLETED, PARTIALLY_COMPLETED, FAILED, CANCELLED, SKIPPED
    input_params_json = Column(Text, nullable=False, default="{}")
    result_summary_json = Column(Text, nullable=False, default="{}")
    result_count = Column(Integer, nullable=False, default=0)
    warnings_json = Column(Text, nullable=False, default="[]")
    error_message = Column(Text, nullable=True)
    approved_by = Column(String(100), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=False, default=0)

    run = relationship("InvestigationAutomationRunModel", back_populates="steps")

    __table_args__ = (
        Index("ix_ias_run_idx", "run_id", "step_index"),
        Index("ix_ias_action", "action_id"),
    )


class InvestigationAutomationPolicyModel(Base):
    """
    Section 66: Controlled policy governing automated investigation triggers and allowed steps.
    """
    __tablename__ = "investigation_automation_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), nullable=False, default="ACTIVE", index=True)  # DRAFT, ACTIVE, DISABLED, ARCHIVED
    template_name = Column(String(64), nullable=False, default="GENERAL_INCIDENT_INVESTIGATION")
    trigger_conditions_json = Column(Text, nullable=False, default="{}")
    allowed_steps_json = Column(Text, nullable=False, default="[]")
    limits_json = Column(Text, nullable=False, default="{}")
    version = Column(String(32), nullable=False, default="1.0")
    created_by = Column(String(100), nullable=False, default="Security Admin")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_iap_ws_status", "workspace_id", "status"),
    )


class InvestigationGapModel(Base):
    """
    Section 66: Identified missing information or telemetry blindspot in an investigation.
    Represents an investigation gap (e.g. stale auth logs, missing endpoint data), not a malicious finding.
    """
    __tablename__ = "investigation_gaps"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    investigation_id = Column(String(64), nullable=False, index=True)
    run_id = Column(String(36), ForeignKey("investigation_automation_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    category = Column(String(64), nullable=False, index=True)  # TELEMETRY_MISSING, AUTHENTICATION_STALE, INTELLIGENCE_UNAVAILABLE, TEMPORAL_BLINDSPOT, UNRESOLVED_IDENTITY, ENDPOINT_OFFLINE
    severity = Column(String(32), nullable=False, default="MEDIUM")  # LOW, MEDIUM, HIGH, CRITICAL
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    remediation_recommendation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    run = relationship("InvestigationAutomationRunModel", back_populates="gaps")

    __table_args__ = (
        Index("ix_ig_ws_inv", "workspace_id", "investigation_id"),
        Index("ix_ig_cat_sev", "category", "severity"),
    )


# =============================================================================
# SECTION 70: SECURITY OPERATIONS AUTOMATION MODELS
# =============================================================================

class AutomationWorkflowModel(Base):
    """
    Section 70: Authoritative Security Operations Automation Workflow definition.
    Coordinates SOC playbooks, investigation actions, case management, and response tasks.
    """
    __tablename__ = "automation_workflows"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    workflow_type = Column(String(64), nullable=False, default="ALERT_TRIAGE", index=True)
    status = Column(String(32), nullable=False, default="DRAFT", index=True)  # DRAFT, VALIDATING, ACTIVE, PAUSED, DISABLED, ARCHIVED
    version = Column(Integer, nullable=False, default=1)
    owner_id = Column(String(100), nullable=False, default="SOC Analyst")
    team_id = Column(String(100), nullable=True)
    trigger_type = Column(String(64), nullable=False, index=True)
    trigger_config_json = Column(Text, nullable=False, default="{}")
    conditions_json = Column(Text, nullable=False, default="{}")
    actions_json = Column(Text, nullable=False, default="[]")
    approval_policy_json = Column(Text, nullable=False, default="{}")
    execution_limits_json = Column(Text, nullable=False, default="{}")
    is_active = Column(Boolean, nullable=False, default=False)
    created_by = Column(String(100), nullable=False, default="SOC Analyst")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    versions = relationship("AutomationWorkflowVersionModel", back_populates="workflow", cascade="all, delete-orphan", order_by="AutomationWorkflowVersionModel.version.desc()")
    runs = relationship("AutomationRunModel", back_populates="workflow")

    __table_args__ = (
        Index("ix_aw_ws_status", "workspace_id", "status"),
        Index("ix_aw_ws_trigger", "workspace_id", "trigger_type"),
    )


class AutomationWorkflowVersionModel(Base):
    """
    Section 70: Immutable snapshot of an activated workflow version.
    Ensures that active automation rules cannot be mutated in-place.
    """
    __tablename__ = "automation_workflow_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    workflow_id = Column(String(36), ForeignKey("automation_workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    version = Column(Integer, nullable=False)
    definition_json = Column(Text, nullable=False)  # Full serialized config of trigger, conditions, actions, limits
    status = Column(String(32), nullable=False, default="ACTIVE")
    change_summary = Column(Text, nullable=True)
    validated_at = Column(DateTime, nullable=True)
    created_by = Column(String(100), nullable=False, default="SOC Analyst")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    workflow = relationship("AutomationWorkflowModel", back_populates="versions")

    __table_args__ = (
        Index("ix_awv_wf_version", "workflow_id", "version", unique=True),
    )


class AutomationRunModel(Base):
    """
    Section 70: Execution record of an automated security operations workflow.
    Tracks end-to-end execution, steps, approval gates, failure classifications, and real metrics.
    """
    __tablename__ = "automation_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    workflow_id = Column(String(36), ForeignKey("automation_workflows.id", ondelete="SET NULL"), nullable=True, index=True)
    workflow_version = Column(Integer, nullable=False, default=1)
    status = Column(String(32), nullable=False, default="QUEUED", index=True)  # QUEUED, RUNNING, WAITING_FOR_APPROVAL, PAUSED, PARTIALLY_COMPLETED, COMPLETED, FAILED, CANCELLED, TIMED_OUT
    trigger_type = Column(String(64), nullable=False, index=True)
    trigger_resource_type = Column(String(64), nullable=True, index=True)
    trigger_resource_id = Column(String(64), nullable=True, index=True)
    trigger_payload_json = Column(Text, nullable=False, default="{}")
    execution_mode = Column(String(32), nullable=False, default="PRODUCTION")  # PRODUCTION, DRY_RUN, TEST, SIMULATION
    idempotency_key = Column(String(128), nullable=True, index=True)
    job_id = Column(String(64), nullable=True, index=True)
    parent_run_id = Column(String(36), nullable=True, index=True)
    recursion_depth = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    paused_at = Column(DateTime, nullable=True)
    timeout_at = Column(DateTime, nullable=True)
    current_step_index = Column(Integer, nullable=False, default=0)
    total_steps = Column(Integer, nullable=False, default=0)
    completed_steps = Column(Integer, nullable=False, default=0)
    failed_steps = Column(Integer, nullable=False, default=0)
    skipped_steps = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    failure_category = Column(String(64), nullable=True)  # VALIDATION_FAILURE, AUTHORIZATION_FAILURE, POLICY_DENIED, etc.
    budget_consumed_json = Column(Text, nullable=False, default="{}")
    output_summary_json = Column(Text, nullable=False, default="{}")
    explainability_trace_json = Column(Text, nullable=False, default="{}")
    created_by = Column(String(100), nullable=False, default="SYSTEM")
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    workflow = relationship("AutomationWorkflowModel", back_populates="runs")
    steps = relationship("AutomationRunStepModel", back_populates="run", cascade="all, delete-orphan", order_by="AutomationRunStepModel.step_index.asc()")
    approvals = relationship("AutomationApprovalRequestModel", back_populates="run", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_ar_ws_status", "workspace_id", "status"),
        Index("ix_ar_ws_trigger", "workspace_id", "trigger_resource_type", "trigger_resource_id"),
    )


class AutomationRunStepModel(Base):
    """
    Section 70: Discrete execution step within an automation run.
    Contains action parameters, risk classification, approval gates, verification results, and execution metrics.
    """
    __tablename__ = "automation_run_steps"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    run_id = Column(String(36), ForeignKey("automation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    step_index = Column(Integer, nullable=False)
    step_key = Column(String(64), nullable=False)
    action_id = Column(String(64), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING", index=True)  # PENDING, RUNNING, WAITING_FOR_APPROVAL, APPROVED, REJECTED, COMPLETED, PARTIALLY_COMPLETED, FAILED, SKIPPED, TIMED_OUT, POLICY_DENIED
    risk_classification = Column(String(32), nullable=False, default="LOW_IMPACT")  # READ_ONLY, LOW_IMPACT, MODERATE_IMPACT, HIGH_IMPACT, DESTRUCTIVE
    approval_level = Column(String(32), nullable=False, default="AUTOMATIC")  # AUTOMATIC, ANALYST_APPROVAL, SENIOR_ANALYST_APPROVAL, ADMIN_APPROVAL, FORBIDDEN
    requires_approval = Column(Boolean, nullable=False, default=False)
    approval_id = Column(String(36), nullable=True)
    approval_requested_at = Column(DateTime, nullable=True)
    approval_decision = Column(String(32), nullable=True)
    approved_by = Column(String(100), nullable=True)
    approved_at = Column(DateTime, nullable=True)
    approval_reason = Column(Text, nullable=True)
    approval_expires_at = Column(DateTime, nullable=True)
    input_params_json = Column(Text, nullable=False, default="{}")
    output_data_json = Column(Text, nullable=False, default="{}")
    verification_result_json = Column(Text, nullable=False, default="{}")
    verified_state = Column(Boolean, nullable=False, default=False)
    error_message = Column(Text, nullable=True)
    failure_category = Column(String(64), nullable=True)
    retry_count = Column(Integer, nullable=False, default=0)
    max_retries = Column(Integer, nullable=False, default=0)
    execution_duration_ms = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    run = relationship("AutomationRunModel", back_populates="steps")

    __table_args__ = (
        Index("ix_ars_run_idx", "run_id", "step_index"),
    )


class AutomationApprovalRequestModel(Base):
    """
    Section 70: Explicit human-in-the-loop approval gate for consequential actions.
    Enforces expiration, audit trails, and non-repudiation.
    """
    __tablename__ = "automation_approval_requests"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    run_id = Column(String(36), ForeignKey("automation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    step_id = Column(String(36), ForeignKey("automation_run_steps.id", ondelete="CASCADE"), nullable=False, index=True)
    action_id = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False, default="PENDING", index=True)  # PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED
    required_role = Column(String(64), nullable=False, default="analyst")
    requested_by = Column(String(100), nullable=False, default="SYSTEM")
    requested_at = Column(DateTime, default=get_utc_now, nullable=False)
    decision = Column(String(32), nullable=True)  # APPROVED, REJECTED
    decided_by = Column(String(100), nullable=True)
    decided_at = Column(DateTime, nullable=True)
    reason = Column(Text, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    action_payload_json = Column(Text, nullable=False, default="{}")
    context_summary_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    run = relationship("AutomationRunModel", back_populates="approvals")
    step = relationship("AutomationRunStepModel")

    __table_args__ = (
        Index("ix_aar_ws_status", "workspace_id", "status"),
    )


# =============================================================================
# SECTION 71: PLATFORM ADMINISTRATION & GOVERNANCE MODELS
# =============================================================================

class AdminUserModel(Base):
    """
    Section 71: Authoritative administrative user and account model.
    Maintains user identity, role, team affiliation, status, and permission scope.
    """
    __tablename__ = "admin_users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    username = Column(String(100), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    full_name = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="SOC_ANALYST", index=True)
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, DISABLED, INVITED, LOCKED, PENDING_VERIFICATION
    team_id = Column(String(36), nullable=True, index=True)
    is_platform_admin = Column(Boolean, nullable=False, default=False)
    custom_permissions_json = Column(Text, nullable=False, default="[]")
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_au_tenant_role", "tenant_id", "role"),
        Index("ix_au_tenant_status", "tenant_id", "status"),
    )


class AdminTeamModel(Base):
    """
    Section 71: Operational team and organizational structure model.
    Groups users into operational units (e.g. Tier 1 SOC, Threat Hunting Unit).
    """
    __tablename__ = "admin_teams"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    name = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=True)
    team_lead_id = Column(String(36), nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_at_tenant_name", "tenant_id", "name"),
    )


class AdminTenantModel(Base):
    """
    Section 71: Multi-tenant boundary and organizational entity model.
    Defines tenant status, retention schedules, plan tier, and operational parameters.
    """
    __tablename__ = "admin_tenants"

    id = Column(String(64), primary_key=True)  # Unique tenant identifier/slug (e.g. 'default', 'acme-corp')
    name = Column(String(150), nullable=False)
    status = Column(String(30), nullable=False, default="ACTIVE", index=True)  # ACTIVE, SUSPENDED, PROVISIONING, DISABLED
    plan_tier = Column(String(50), nullable=False, default="ENTERPRISE")  # COMMUNITY, STANDARD, ENTERPRISE
    retention_days = Column(Integer, nullable=False, default=90)
    configuration_json = Column(Text, nullable=False, default="{}")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)


class AdminSecurityPolicyModel(Base):
    """
    Section 71: Versioned security governance policy model.
    Controls authentication, session management, retention, role delegation, and external sharing.
    """
    __tablename__ = "admin_security_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    policy_type = Column(String(50), nullable=False, index=True)  # AUTHENTICATION, SESSION_MANAGEMENT, DATA_RETENTION, ROLE_DELEGATION, EXTERNAL_SHARING, API_ACCESS
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="DRAFT", index=True)  # DRAFT, VALIDATING, ACTIVE, DISABLED, ARCHIVED
    version = Column(Integer, nullable=False, default=1)
    rules_json = Column(Text, nullable=False, default="{}")
    created_by = Column(String(100), nullable=False, default="Security Admin")
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_asp_tenant_type_status", "tenant_id", "policy_type", "status"),
    )


class AdminSystemSettingModel(Base):
    """
    Section 71: Persistent system setting with optimistic concurrency and scope precedence.
    Enforces server-side typing, validation, and optimistic version checks.
    """
    __tablename__ = "admin_system_settings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(64), nullable=False, default="GLOBAL", index=True)  # 'GLOBAL' or specific tenant_id
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    key = Column(String(100), nullable=False, index=True)
    value_json = Column(Text, nullable=False, default="{}")
    category = Column(String(50), nullable=False, default="GENERAL", index=True)
    scope = Column(String(20), nullable=False, default="GLOBAL")  # GLOBAL, TENANT
    is_secret = Column(Boolean, nullable=False, default=False)
    version = Column(Integer, nullable=False, default=1)
    updated_by = Column(String(100), nullable=False, default="Platform Admin")
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_ass_tenant_key", "tenant_id", "key", unique=True),
    )


class AdminIntegrationConfigModel(Base):
    """
    Section 71: Controlled external integration registry and provider configuration model.
    Guarantees secrets are never returned in plaintext and provides health diagnostics.
    """
    __tablename__ = "admin_integration_configs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(64), nullable=False, default="default", index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    provider_name = Column(String(100), nullable=False, index=True)
    display_name = Column(String(150), nullable=False)
    category = Column(String(50), nullable=False, default="THREAT_INTEL", index=True)
    enabled = Column(Boolean, nullable=False, default=False, index=True)
    health_status = Column(String(30), nullable=False, default="UNCONFIGURED", index=True)  # HEALTHY, DEGRADED, UNCONFIGURED, ERROR
    endpoint_url = Column(String(500), nullable=True)
    credential_configured = Column(Boolean, nullable=False, default=False)
    credential_vault_key = Column(String(100), nullable=True)
    settings_json = Column(Text, nullable=False, default="{}")
    last_health_check_at = Column(DateTime, nullable=True)
    last_error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_aic_tenant_provider", "tenant_id", "provider_name", unique=True),
    )


class AdminFeatureControlModel(Base):
    """
    Section 71: Role-gated feature flags and capability controls.
    Enforces authorization requirements and multi-scope feature availability.
    """
    __tablename__ = "admin_feature_controls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    tenant_id = Column(String(64), nullable=False, default="GLOBAL", index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    feature_key = Column(String(100), nullable=False, index=True)
    display_name = Column(String(150), nullable=False)
    description = Column(Text, nullable=True)
    enabled = Column(Boolean, nullable=False, default=True, index=True)
    scope = Column(String(30), nullable=False, default="GLOBAL")  # GLOBAL, TENANT, ENVIRONMENT
    requires_role = Column(String(50), nullable=False, default="SOC_ANALYST")
    updated_by = Column(String(100), nullable=False, default="Platform Admin")
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_afc_tenant_feature", "tenant_id", "feature_key", unique=True),
    )
















