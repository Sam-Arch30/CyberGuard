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
    Index
)
from sqlalchemy.orm import relationship
from backend.db.session import Base


def generate_uuid() -> str:
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

    # Backwards compatibility fields
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=True, index=True)
    details = Column(Text, nullable=True, default="")

    # Relationships
    case = relationship("CaseModel", back_populates="audit_logs")


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


