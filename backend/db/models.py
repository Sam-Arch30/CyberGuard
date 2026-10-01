import uuid
from datetime import datetime, timezone
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
from sqlalchemy.orm import relationship
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
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    # Relationships
    emails = relationship("CampaignEmailModel", back_populates="campaign", cascade="all, delete-orphan", lazy="selectin")


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
    attributes_json = Column(Text, default="{}", nullable=False)
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)


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
    first_seen = Column(DateTime, default=get_utc_now, nullable=False)
    last_seen = Column(DateTime, default=get_utc_now, nullable=False)
    evidence_reference = Column(String(255), nullable=True)
    analysis_run_id = Column(String(36), ForeignKey("analysis_runs.id", ondelete="SET NULL"), nullable=True, index=True)
    method = Column(String(50), nullable=False, default="RULE")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    __table_args__ = (
        Index("ix_rel_src", "source_type", "source_id"),
        Index("ix_rel_tgt", "target_type", "target_id"),
        Index("ix_rel_type_src_tgt", "relationship_type", "source_id", "target_id"),
    )


class IncidentModel(Base):
    """
    Unified incident container linking correlated ThreatEvents, ResponseActions, and AttackPaths.
    """
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_number = Column(String(32), unique=True, nullable=False, index=True)
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
    """
    __tablename__ = "attack_paths"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    confidence = Column(Float, nullable=False, default=1.0)
    status = Column(String(30), nullable=False, default="HYPOTHESIS")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)
    updated_at = Column(DateTime, default=get_utc_now, onupdate=get_utc_now, nullable=False)

    incident = relationship("IncidentModel", back_populates="attack_paths")
    stages = relationship("AttackStageModel", back_populates="attack_path", cascade="all, delete-orphan", order_by="AttackStageModel.stage_order", lazy="selectin")
    edges = relationship("AttackEdgeModel", back_populates="attack_path", cascade="all, delete-orphan", lazy="selectin")


class AttackStageModel(Base):
    """
    Discrete node/stage in an AttackPath representing a specific TTP or kill-chain step.
    """
    __tablename__ = "attack_stages"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    attack_path_id = Column(String(36), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    stage_order = Column(Integer, nullable=False, default=1)
    technique_id = Column(String(50), nullable=True, index=True)  # MITRE ATT&CK technique (e.g. T1566.002)
    tactic = Column(String(100), nullable=True)  # e.g. Initial Access
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(30), nullable=False, default="SUSPECTED")
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    attack_path = relationship("AttackPathModel", back_populates="stages")


class AttackEdgeModel(Base):
    """
    Directed transition edge between AttackStages.
    """
    __tablename__ = "attack_edges"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    attack_path_id = Column(String(36), ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True)
    source_stage_id = Column(String(36), ForeignKey("attack_stages.id", ondelete="CASCADE"), nullable=False)
    target_stage_id = Column(String(36), ForeignKey("attack_stages.id", ondelete="CASCADE"), nullable=False)
    relationship_type = Column(String(50), nullable=False, default="LEADS_TO")
    confidence = Column(Float, nullable=False, default=1.0)
    metadata_json = Column(Text, default="{}", nullable=False)
    created_at = Column(DateTime, default=get_utc_now, nullable=False)

    attack_path = relationship("AttackPathModel", back_populates="edges")



