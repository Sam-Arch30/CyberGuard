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
from sqlalchemy.orm import relationship, relationship as orm_relationship
from backend.db.session import Base


def generate_uuid(prefix: Optional[str] = None) -> str:
    return str(uuid.uuid4())


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CaseModel(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_number = Column(String(32), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), nullable=False, default="low", index=True)
    status = Column(String(20), nullable=False, default="open", index=True)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    emails = relationship("CaseEmailModel", back_populates="case", cascade="all, delete-orphan", lazy="selectin")
    notes = relationship("CaseNoteModel", back_populates="case", cascade="all, delete-orphan", order_by="desc(CaseNoteModel.created_at)", lazy="selectin")
    findings = relationship("CaseFindingModel", back_populates="case", cascade="all, delete-orphan", order_by="desc(CaseFindingModel.created_at)", lazy="selectin")
    audit_logs = relationship("AuditLogModel", back_populates="case", cascade="all, delete-orphan", order_by="desc(AuditLogModel.timestamp)", lazy="selectin")


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
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

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
    __tablename__ = "evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(64), unique=True, nullable=False, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    original_filename = Column(String(255), nullable=False)
    upload_timestamp = Column(DateTime, default=get_utc_now, nullable=False)
    size = Column(Integer, nullable=False)
    uploader = Column(String(100), nullable=True, default="SOC Analyst")


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
    format = Column(String(20), default="PDF", nullable=False)
    generator_version = Column(String(50), default="1.0.0", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)


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
    analyzed_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)


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
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    emails = relationship("CampaignEmailModel", back_populates="campaign", cascade="all, delete-orphan", lazy="selectin")
    incidents = relationship("CampaignIncidentModel", back_populates="campaign", cascade="all, delete-orphan", lazy="selectin")


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
        Index("ix_model_versions_name_version", "model_name", "version", unique=True),
    )

    findings = relationship("FindingModel", back_populates="model_version")


class FindingModel(Base):
    """
    Represents an analytical conclusion or observation produced by an analyzer.
    Preserves exact provenance (rule, heuristic, ML, LLM, intelligence).
    """
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    analyzer = Column(String(100), nullable=False, index=True)
    finding_type = Column(String(100), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="LOW", index=True)  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    confidence = Column(Float, nullable=False, default=1.0)  # 0.0 - 1.0
    risk_contribution = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0
    method = Column(String(50), nullable=False, index=True)  # RULE, HEURISTIC, ML, LLM, EXTERNAL_INTELLIGENCE, STATISTICAL, GRAPH, MANUAL, HYBRID
    model_version_id = Column(String(36), ForeignKey("model_versions.id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id = Column(String(100), nullable=True, index=True)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    analysis_run = relationship("AnalysisRunModel", back_populates="findings")
    model_version = relationship("ModelVersionModel", back_populates="findings")
    evidence_items = relationship("FindingEvidenceModel", back_populates="finding", cascade="all, delete-orphan", lazy="selectin")


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
        Index("ix_indicators_type_norm", "indicator_type", "normalized_value", unique=True),
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
    incident_number = Column(String(32), unique=True, nullable=False, index=True)
    workspace_id = Column(String(64), nullable=False, default="default", index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="OPEN", index=True)  # OPEN, INVESTIGATING, CONTAINED, RESOLVED, CLOSED, FALSE_POSITIVE
    severity = Column(String(20), nullable=False, default="MEDIUM", index=True)  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    risk_score = Column(Float, nullable=False, default=0.0)  # 0.0 - 100.0
    confidence = Column(Float, nullable=False, default=1.0)  # 0.0 - 1.0
    opened_at = Column(DateTime, default=get_utc_now, nullable=False)
    closed_at = Column(DateTime, nullable=True)
    assigned_to = Column(String(100), nullable=True)
    legacy_case_id = Column(String(36), nullable=True, index=True)  # Pointer to legacy cases.id
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    threat_events = relationship("ThreatEventModel", back_populates="incident", lazy="selectin")
    response_actions = relationship("ResponseActionModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    attack_paths = relationship("AttackPathModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    attack_hypotheses = relationship("AttackHypothesisModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    security_events = relationship("SecurityEventModel", back_populates="incident", lazy="selectin")
    temporal_sequences = relationship("TemporalSequenceCandidateModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    attack_technique_mappings = relationship("AttackTechniqueMappingModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    infrastructure_attributions = relationship("InfrastructureAttributionModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    infrastructure_clusters = relationship("InfrastructureClusterModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    behavioral_deviations = relationship("BehavioralDeviationModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    novelty_assessments = relationship("NoveltyAssessmentModel", back_populates="incident", cascade="all, delete-orphan", lazy="selectin")
    emerging_patterns = relationship("EmergingPatternCandidateModel", back_populates="incident", lazy="selectin")
    threat_memory_observations = relationship("ThreatMemoryObservationModel", back_populates="incident", lazy="selectin")


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
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    source_artifact = relationship("ArtifactModel", back_populates="threat_events")
    analysis_run = relationship("AnalysisRunModel", back_populates="threat_events")
    incident = relationship("IncidentModel", back_populates="threat_events")
    response_actions = relationship("ResponseActionModel", back_populates="threat_event")


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
    created_at = Column(DateTime, default=get_utc_now, nullable=False, index=True)

    incident = relationship("IncidentModel", back_populates="behavioral_deviations")
    baseline = relationship("BehavioralBaselineModel", back_populates="deviations")

    __table_args__ = (
        Index("ix_bd_entity_time", "entity_type", "entity_id", "created_at"),
        Index("ix_bd_inc_metric", "incident_id", "metric_type"),
        Index("ix_bd_ws_dev", "workspace_id", "deviation_score"),
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









