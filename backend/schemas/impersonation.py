"""
Digital Impersonation Schemas & Identity Models (Section 12).
Defines IdentityClaim, ProtectedIdentityProfile, ImpersonationFinding,
ImpersonationAssessment, and associated forensic data models.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import model_validator, BaseModel, Field

from backend.schemas.unified import SeverityEnum, ArtifactTypeEnum


def generate_uuid() -> str:
    return str(uuid.uuid4())


class IdentityClaimTypeEnum(str, Enum):
    """Categorization of what type of entity is being claimed."""
    PERSON = "PERSON"
    ORGANIZATION = "ORGANIZATION"
    BRAND = "BRAND"
    INSTITUTION = "INSTITUTION"
    SERVICE = "SERVICE"
    ROLE = "ROLE"
    ACCOUNT = "ACCOUNT"
    OTHER = "OTHER"


class ReferenceSourceEnum(str, Enum):
    """Provenance source for an authoritative reference/protected identity."""
    USER_CONFIGURED = "USER_CONFIGURED"
    ORGANIZATION_CONFIGURED = "ORGANIZATION_CONFIGURED"
    SYSTEM_CONFIGURED = "SYSTEM_CONFIGURED"
    VERIFIED_INTERNAL_DIRECTORY = "VERIFIED_INTERNAL_DIRECTORY"
    VERIFIED_DOMAIN_CONFIGURATION = "VERIFIED_DOMAIN_CONFIGURATION"


class VerificationStatusEnum(str, Enum):
    """Status of reference identity verification."""
    VERIFIED = "VERIFIED"
    PENDING = "PENDING"
    UNVERIFIED = "UNVERIFIED"


class ComparisonOutcomeEnum(str, Enum):
    """Comparison result of a claim/observed entity against a reference identity."""
    MATCH = "MATCH"
    PARTIAL_MATCH = "PARTIAL_MATCH"
    MISMATCH = "MISMATCH"
    LOOKALIKE = "LOOKALIKE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNKNOWN = "UNKNOWN"


class ImpersonationClassificationEnum(str, Enum):
    """Overall assessment classification preserving epistemic modesty."""
    NO_IMPERSONATION_EVIDENCE = "NO_IMPERSONATION_EVIDENCE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    IMPERSONATION_SUSPECTED = "IMPERSONATION_SUSPECTED"
    STRONG_IMPERSONATION_INDICATORS = "STRONG_IMPERSONATION_INDICATORS"


class IdentityEvidenceCategoryEnum(str, Enum):
    """Taxonomy of evidence categories to avoid duplicate signal inflation."""
    NAME_IDENTITY = "NAME_IDENTITY"
    DOMAIN_IDENTITY = "DOMAIN_IDENTITY"
    EMAIL_IDENTITY = "EMAIL_IDENTITY"
    AUTHENTICATION_IDENTITY = "AUTHENTICATION_IDENTITY"
    WEBSITE_IDENTITY = "WEBSITE_IDENTITY"
    CONTENT_CONTEXT = "CONTENT_CONTEXT"
    BEHAVIORAL_CONTEXT = "BEHAVIORAL_CONTEXT"


class IdentityClaim(BaseModel):
    """
    Represents an identity claim extracted from an artifact (e.g. From display name,
    website title, or free text). An IdentityClaim is an observation in content,
    NOT an authoritative Entity assertion.
    """
    id: str = Field(default_factory=generate_uuid)
    claim_type: IdentityClaimTypeEnum
    claimed_name: str
    claimed_domain: Optional[str] = None
    claimed_email: Optional[str] = None
    claimed_organization: Optional[str] = None
    claimed_role: Optional[str] = None
    source_artifact_id: Optional[str] = None
    analysis_run_id: Optional[str] = None
    evidence_reference: Optional[str] = None
    confidence: float = 1.0
    text_span: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProtectedIdentityProfile(BaseModel):
    """
    Authoritative reference identity profile representing an organization, brand,
    executive, or institution that CyberGuard protects against impersonation.
    """
    id: str = Field(default_factory=generate_uuid)
    display_name: str
    entity_type: IdentityClaimTypeEnum = IdentityClaimTypeEnum.ORGANIZATION
    trusted_domains: List[str] = Field(default_factory=list)
    trusted_email_patterns: List[str] = Field(default_factory=list)
    trusted_sender_addresses: List[str] = Field(default_factory=list)
    known_names: List[str] = Field(default_factory=list)
    known_roles: List[str] = Field(default_factory=list)
    known_brand_terms: List[str] = Field(default_factory=list)
    authorized_delegated_senders: List[str] = Field(default_factory=list)
    source: ReferenceSourceEnum = ReferenceSourceEnum.USER_CONFIGURED
    verification_status: VerificationStatusEnum = VerificationStatusEnum.VERIFIED
    is_active: bool = True
    revision: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ImpersonationFindingEvidence(BaseModel):
    """Discrete factual item supporting or contradicting an impersonation finding."""
    category: IdentityEvidenceCategoryEnum
    source: str
    key: str
    value: str
    confidence: float = 1.0
    is_contradicting: bool = False
    notes: Optional[str] = None


class ImpersonationFinding(BaseModel):
    """
    Analytical observation or conclusion produced by the Digital Impersonation Engine.
    """
    finding_type: str
    title: str
    description: str
    severity: SeverityEnum = SeverityEnum.MEDIUM
    confidence: float = 1.0
    risk_contribution: float = 0.0
    rule_id: str
    rule_version: str = "1.0.0"
    category: IdentityEvidenceCategoryEnum
    target_identity_id: Optional[str] = None
    target_identity_name: Optional[str] = None
    evidence_items: List[ImpersonationFindingEvidence] = Field(default_factory=list)
    limitation: str = ""
    mitre_attack_ids: List[str] = Field(default_factory=list)


class ImpersonationAssessment(BaseModel):
    """
    Synthesized assessment of identity authenticity and impersonation likelihood.
    Separates supporting evidence from contradicting evidence.
    """
    classification: ImpersonationClassificationEnum
    confidence: float
    risk_score: float
    target_identity: Optional[str] = None
    target_identity_id: Optional[str] = None
    claims: List[IdentityClaim] = Field(default_factory=list)
    supporting_findings: List[ImpersonationFinding] = Field(default_factory=list)
    contradicting_findings: List[ImpersonationFinding] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    summary: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    profile_revisions_used: Dict[str, int] = Field(default_factory=dict)


# API Request / Response schemas

class CreateProtectedIdentityRequest(BaseModel):
    display_name: str
    entity_type: IdentityClaimTypeEnum = IdentityClaimTypeEnum.ORGANIZATION
    trusted_domains: List[str] = Field(default_factory=list)
    trusted_email_patterns: List[str] = Field(default_factory=list)
    trusted_sender_addresses: List[str] = Field(default_factory=list)
    known_names: List[str] = Field(default_factory=list)
    known_roles: List[str] = Field(default_factory=list)
    known_brand_terms: List[str] = Field(default_factory=list)
    authorized_delegated_senders: List[str] = Field(default_factory=list)
    source: ReferenceSourceEnum = ReferenceSourceEnum.USER_CONFIGURED
    verification_status: VerificationStatusEnum = VerificationStatusEnum.VERIFIED
    metadata: Dict[str, Any] = Field(default_factory=dict)


class UpdateProtectedIdentityRequest(BaseModel):
    display_name: Optional[str] = None
    entity_type: Optional[IdentityClaimTypeEnum] = None
    trusted_domains: Optional[List[str]] = None
    trusted_email_patterns: Optional[List[str]] = None
    trusted_sender_addresses: Optional[List[str]] = None
    known_names: Optional[List[str]] = None
    known_roles: Optional[List[str]] = None
    known_brand_terms: Optional[List[str]] = None
    authorized_delegated_senders: Optional[List[str]] = None
    is_active: Optional[bool] = None
    metadata: Optional[Dict[str, Any]] = None


class ImpersonationAnalysisRequest(BaseModel):
    @model_validator(mode="after")
    def validate_claim(self):
        from backend.services.identity_contract import normalize_email_claim
        if self.email_data is not None or self.artifact_type == ArtifactTypeEnum.EMAIL:
            self.email_data = normalize_email_claim(self.email_data or {})
        return self

    artifact_type: ArtifactTypeEnum = ArtifactTypeEnum.EMAIL
    email_data: Optional[Dict[str, Any]] = None
    url_data: Optional[Dict[str, Any]] = None
    website_data: Optional[Dict[str, Any]] = None
    target_identity_hint: Optional[str] = None
    artifact_id: Optional[str] = None


class ImpersonationAnalysisResponse(BaseModel):
    analysis_run_id: str
    artifact_id: Optional[str] = None
    assessment: ImpersonationAssessment
    entities_created: List[str] = Field(default_factory=list)
    relationships_created: List[str] = Field(default_factory=list)
    threat_events_created: List[str] = Field(default_factory=list)
