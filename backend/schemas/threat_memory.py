"""
Canonical Threat Memory Schemas (Section 23).
Provides data contracts, controlled enums, observation lineage models,
analyst decision records, and structured memory context aggregates.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, Field

from backend.schemas.unified import (
    normalize_confidence,
    normalize_domain,
    normalize_email_address,
    normalize_hash,
    normalize_ip,
    normalize_url,
)
from backend.services.log_sanitizer import sanitize_log_text


# ============================================================================
# 1. CONTROLLED ENUMS
# ============================================================================

class MemoryType(str, Enum):
    INDICATOR = "INDICATOR"
    DOMAIN = "DOMAIN"
    IP = "IP"
    URL = "URL"
    HASH = "HASH"
    SENDER_PATTERN = "SENDER_PATTERN"
    FILE_PATTERN = "FILE_PATTERN"
    IDENTITY_PATTERN = "IDENTITY_PATTERN"
    INFRASTRUCTURE_CLUSTER = "INFRASTRUCTURE_CLUSTER"
    CAMPAIGN = "CAMPAIGN"
    BEHAVIOR_PATTERN = "BEHAVIOR_PATTERN"
    ATTACK_SEQUENCE = "ATTACK_SEQUENCE"
    NOVEL_PATTERN = "NOVEL_PATTERN"
    FALSE_POSITIVE_PATTERN = "FALSE_POSITIVE_PATTERN"
    RESPONSE_OUTCOME = "RESPONSE_OUTCOME"
    THREAT_EVENT_PATTERN = "THREAT_EVENT_PATTERN"


class MemoryStatus(str, Enum):
    OBSERVED = "OBSERVED"
    CORRELATED = "CORRELATED"
    VERIFIED = "VERIFIED"
    DISMISSED = "DISMISSED"
    EXPIRED = "EXPIRED"
    SUPERSEDED = "SUPERSEDED"


class MemoryScope(str, Enum):
    GLOBAL = "GLOBAL"
    ORGANIZATION = "ORGANIZATION"
    ENVIRONMENT = "ENVIRONMENT"
    INVESTIGATION = "INVESTIGATION"
    ENTITY = "ENTITY"
    CAMPAIGN = "CAMPAIGN"


class ProvenanceType(str, Enum):
    DIRECT_OBSERVATION = "DIRECT_OBSERVATION"
    ANALYST_VERIFIED = "ANALYST_VERIFIED"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"
    MODEL_DERIVED = "MODEL_DERIVED"


class ObservationClassification(str, Enum):
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    BENIGN = "BENIGN"
    INCONCLUSIVE = "INCONCLUSIVE"


class AnalystDecisionType(str, Enum):
    VERIFIED_MALICIOUS = "VERIFIED_MALICIOUS"
    VERIFIED_BENIGN = "VERIFIED_BENIGN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    SUPPRESSED = "SUPPRESSED"
    ESCALATED = "ESCALATED"


class MemoryRelationshipType(str, Enum):
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    OBSERVED_IN = "OBSERVED_IN"
    PART_OF = "PART_OF"
    RELATED_TO = "RELATED_TO"
    RESOLVES_TO = "RESOLVES_TO"
    HOSTED_ON = "HOSTED_ON"
    USED_BY = "USED_BY"
    TARGETED = "TARGETED"
    SIMILAR_TO = "SIMILAR_TO"
    SEQUENCE_PRECEDES = "SEQUENCE_PRECEDES"
    SEQUENCE_FOLLOWS = "SEQUENCE_FOLLOWS"
    FALSE_POSITIVE_RELATED = "FALSE_POSITIVE_RELATED"
    RESPONSE_APPLIED_TO = "RESPONSE_APPLIED_TO"


# ============================================================================
# 2. PRIVACY & SANITIZATION UTILITIES
# ============================================================================

SENSITIVE_KEY_PATTERNS = {
    "password", "secret", "token", "auth", "credential", "cookie",
    "api_key", "apikey", "bearer", "private_key", "session_key", "jwt"
}


def sanitize_memory_attributes(attrs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively redacts raw passwords, tokens, cookies, auth headers, and secrets
    from memory attributes before persistence or serialization (Section 23 Privacy).
    """
    if not attrs or not isinstance(attrs, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for k, v in attrs.items():
        k_lower = str(k).lower()
        if any(sub in k_lower for sub in SENSITIVE_KEY_PATTERNS):
            sanitized[k] = "[REDACTED_SECRET]"
            continue

        if isinstance(v, str):
            sanitized[k] = sanitize_log_text(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_memory_attributes(v)
        elif isinstance(v, list):
            clean_list = []
            for item in v:
                if isinstance(item, dict):
                    clean_list.append(sanitize_memory_attributes(item))
                elif isinstance(item, str):
                    clean_list.append(sanitize_log_text(item))
                else:
                    clean_list.append(item)
            sanitized[k] = clean_list
        else:
            sanitized[k] = v

    return sanitized


def canonicalize_memory_key(subject_type: Union[MemoryType, str], value: str) -> str:
    """
    Produces deterministic canonical keys matching CyberGuard's canonical standards:
    - HASH: SHA256:<64 hex>
    - DOMAIN: DOMAIN:<normalized domain>
    - IP: IP:<normalized ip>
    - URL: URL:<canonical url>
    - SENDER/EMAIL: EMAIL:<normalized address>
    - CAMPAIGN: CAMPAIGN:<id>
    - FP/PATTERN: FP:<hash>
    - CLUSTER: CLUSTER:<id>
    """
    if hasattr(subject_type, "value"):
        st = str(subject_type.value).upper()
    else:
        st = str(subject_type).upper()
    if "." in st:
        st = st.split(".")[-1]

    val = (value or "").strip()

    # Strip existing recognized canonical prefix to avoid double-prefixing or colon truncation
    for prefix in ("DOMAIN:", "IP:", "URL:", "SHA256:", "EMAIL:", "CAMPAIGN:", "CLUSTER:", "FP:", "HASH:"):
        if val.upper().startswith(prefix):
            val = val[len(prefix):].strip()
            if st in ("INDICATOR", ""):
                st = prefix[:-1]
            break

    # If subject_type is generic or unspecific, infer from value format
    if st in ("INDICATOR", "", "NONE", "UNKNOWN"):
        if "@" in val and "/" not in val:
            st = "EMAIL"
        elif val.startswith("http://") or val.startswith("https://"):
            st = "URL"
        elif any(c in val for c in [":", "."]) and all(p.isdigit() or p == "" for p in val.split(".")):
            st = "IP"
        elif len(val) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in val):
            st = "HASH"
        elif "." in val and "/" not in val:
            st = "DOMAIN"

    if st in ("HASH", "FILE_HASH", "SHA256", "MD5", "SHA1"):
        norm_h = normalize_hash(val)
        return f"SHA256:{norm_h}" if not norm_h.startswith("SHA256:") else norm_h
    elif st in ("DOMAIN", "HOSTNAME", "FQDN"):
        return f"DOMAIN:{normalize_domain(val)}"
    elif st in ("IP", "IP_ADDRESS", "IPV4", "IPV6"):
        return f"IP:{normalize_ip(val)}"
    elif st == "URL":
        return f"URL:{normalize_url(val)}"
    elif st in ("EMAIL", "EMAIL_ADDRESS", "SENDER", "SENDER_PATTERN"):
        return f"EMAIL:{normalize_email_address(val)}"
    elif st in ("CAMPAIGN",):
        return f"CAMPAIGN:{val.upper()}"
    elif st in ("INFRASTRUCTURE_CLUSTER", "CLUSTER"):
        return f"CLUSTER:{val}"
    elif st in ("NOVEL_PATTERN", "BEHAVIOR_PATTERN", "FINGERPRINT", "FP"):
        clean_fp = re.sub(r"[^a-fA-F0-9]", "", val).lower()
        return f"FP:{clean_fp}" if clean_fp else f"FP:{val}"
    else:
        # Default deterministic key
        return f"{st}:{val.lower()}"


# ============================================================================
# 3. PYDANTIC SCHEMAS
# ============================================================================

class ThreatMemoryObservationBase(BaseModel):
    source_type: str = Field(..., description="E.g. SECURITY_EVENT, FINDING, EVIDENCE, EXTERNAL_FEED, ARTIFACT")
    source_id: Optional[str] = Field(None, description="Canonical ID of the original source object")
    investigation_id: Optional[str] = Field(None, description="Investigation ID where observation occurred")
    incident_id: Optional[str] = Field(None, description="Incident ID if associated with an incident")
    campaign_id: Optional[str] = Field(None, description="Campaign ID if correlated")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    observation_type: str = Field(default="DETECTION", description="Nature of observation")
    classification: ObservationClassification = Field(default=ObservationClassification.INCONCLUSIVE)
    severity: Optional[str] = Field(None, description="SAFE, LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_reference: Optional[str] = Field(None, description="Pointer to evidence item or artifact")
    analysis_run_id: Optional[str] = Field(None, description="Originating AnalysisRun ID")
    detector_name: Optional[str] = Field(None, description="Detector or pipeline name")
    detector_version: Optional[str] = Field(default="1.0.0", description="Detector version for reproducibility")
    is_analyst_verified: bool = Field(default=False)
    verified_by: Optional[str] = Field(None)
    raw_context: Dict[str, Any] = Field(default_factory=dict)


class ThreatMemoryObservationCreate(ThreatMemoryObservationBase):
    canonical_key: str
    subject_type: MemoryType = MemoryType.INDICATOR
    workspace_id: str = "default"


class ThreatMemoryObservation(ThreatMemoryObservationBase):
    id: str
    memory_entry_id: str
    workspace_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatMemoryDecisionBase(BaseModel):
    decision: AnalystDecisionType
    reason: str = Field(..., min_length=3, description="Analyst rationale for verification or suppression")
    approved_by: str = Field(..., description="Analyst identifier or service role")
    scope: MemoryScope = MemoryScope.ORGANIZATION
    valid_from: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    valid_until: Optional[datetime] = Field(None, description="Expiration date for time-bounded decisions")
    evidence_ids: List[str] = Field(default_factory=list)


class ThreatMemoryDecisionCreate(ThreatMemoryDecisionBase):
    canonical_key: Optional[str] = None
    memory_entry_id: Optional[str] = None
    workspace_id: str = "default"


class ThreatMemoryDecision(ThreatMemoryDecisionBase):
    id: str
    memory_entry_id: str
    workspace_id: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ThreatMemoryRelationshipBase(BaseModel):
    source_memory_id: str
    target_memory_id: str
    relationship_type: MemoryRelationshipType = MemoryRelationshipType.ASSOCIATED_WITH
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    evidence_references: List[str] = Field(default_factory=list)


class ThreatMemoryRelationship(ThreatMemoryRelationshipBase):
    id: str
    workspace_id: str
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class ThreatMemoryEntryBase(BaseModel):
    memory_type: MemoryType
    subject_type: str
    subject_id: Optional[str] = None
    canonical_key: str
    scope: MemoryScope = MemoryScope.ORGANIZATION
    status: MemoryStatus = MemoryStatus.OBSERVED
    first_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    observation_count: int = Field(default=1, ge=0)
    independent_source_count: int = Field(default=1, ge=0)
    incident_count: int = Field(default=0, ge=0)
    campaign_count: int = Field(default=0, ge=0)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    confidence_level: str = Field(default="MEDIUM")
    provenance_type: ProvenanceType = ProvenanceType.DIRECT_OBSERVATION
    provenance_reference: Optional[str] = None
    summary: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    version: str = Field(default="1.0.0")


class ThreatMemoryEntry(ThreatMemoryEntryBase):
    id: str
    workspace_id: str
    created_at: datetime
    updated_at: datetime
    observations: List[ThreatMemoryObservation] = Field(default_factory=list)
    decisions: List[ThreatMemoryDecision] = Field(default_factory=list)

    model_config = {"from_attributes": True}


# ============================================================================
# 4. MEMORY CONTEXT QUERY & RESPONSE AGGREGATES
# ============================================================================

class ThreatMemoryLookupRequest(BaseModel):
    canonical_key: Optional[str] = None
    value: Optional[str] = None
    subject_type: Optional[MemoryType] = None
    workspace_id: str = "default"
    include_graph: bool = True
    max_observations: int = Field(default=20, ge=1, le=100)


class ThreatMemoryConflictSummary(BaseModel):
    is_conflicted: bool = False
    malicious_count: int = 0
    benign_count: int = 0
    suspicious_count: int = 0
    inconclusive_count: int = 0
    explanation: Optional[str] = None


class ThreatMemoryContext(BaseModel):
    """
    Standardized ThreatMemoryContext consumed by Analysis Orchestrator,
    Copilot, Security Knowledge Graph, and Report Generation (Section 23).
    Strictly enforces: CURRENT EVIDENCE > HISTORICAL MEMORY.
    """
    canonical_key: str
    subject_type: str
    subject_id: Optional[str] = None
    memory_status: MemoryStatus = MemoryStatus.OBSERVED
    historical_context_available: bool = True
    observation_count: int = 0
    independent_source_count: int = 0
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    confidence: float = 1.0
    confidence_level: str = "MEDIUM"
    is_analyst_verified: bool = False
    verification_status: Optional[str] = None

    prior_observations: List[ThreatMemoryObservation] = Field(default_factory=list)
    historical_findings: List[Dict[str, Any]] = Field(default_factory=list)
    related_incidents: List[Dict[str, Any]] = Field(default_factory=list)
    related_campaigns: List[Dict[str, Any]] = Field(default_factory=list)
    related_infrastructure: List[Dict[str, Any]] = Field(default_factory=list)
    behavioral_history: List[Dict[str, Any]] = Field(default_factory=list)
    novelty_history: List[Dict[str, Any]] = Field(default_factory=list)
    analyst_decisions: List[ThreatMemoryDecision] = Field(default_factory=list)
    response_history: List[Dict[str, Any]] = Field(default_factory=list)
    similar_cases: List[Dict[str, Any]] = Field(default_factory=list)

    conflict: ThreatMemoryConflictSummary = Field(default_factory=ThreatMemoryConflictSummary)
    provenance_chain: List[Dict[str, Any]] = Field(default_factory=list)
    limitations: List[str] = Field(
        default_factory=lambda: [
            "Historical memory provides contextual enrichment and does not substitute for present forensic observation.",
            "CURRENT EVIDENCE > HISTORICAL MEMORY.",
            "Historical maliciousness is non-deterministic; fresh observation evidence is required."
        ]
    )


class ThreatMemoryStatsResponse(BaseModel):
    workspace_id: str
    total_memory_entries: int
    total_observations: int
    total_verified_entries: int
    total_conflicted_entries: int
    total_false_positive_records: int
    by_type: Dict[str, int] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
