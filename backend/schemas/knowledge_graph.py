"""
Canonical Security Knowledge Graph Schemas (Section 14).
Provides data contracts, controlled relationship vocabulary, canonical key generation,
attribute sanitization, edge observation models, and query schemas.
"""
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
# 1. CONTROLLED VOCABULARY & ENUMS
# ============================================================================

class GraphEntityType(str, Enum):
    EMAIL = "EMAIL"
    FILE = "FILE"
    HASH = "HASH"
    URL = "URL"
    DOMAIN = "DOMAIN"
    IP = "IP"
    USER = "USER"
    ACCOUNT = "ACCOUNT"
    DEVICE = "DEVICE"
    PROCESS = "PROCESS"
    SESSION = "SESSION"
    API_SERVICE = "API_SERVICE"
    API_RESOURCE = "API_RESOURCE"
    MEDIA = "MEDIA"
    IDENTITY = "IDENTITY"
    INCIDENT = "INCIDENT"
    CAMPAIGN = "CAMPAIGN"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    ASN = "ASN"
    CERTIFICATE = "CERTIFICATE"
    NAMESERVER = "NAMESERVER"
    NETWORK = "NETWORK"
    INFRASTRUCTURE_CLUSTER = "INFRASTRUCTURE_CLUSTER"
    BEHAVIORAL_BASELINE = "BEHAVIORAL_BASELINE"
    EMERGING_PATTERN = "EMERGING_PATTERN"
    OTHER = "OTHER"


class GraphRelationshipType(str, Enum):
    CONTAINS = "CONTAINS"
    REFERENCES = "REFERENCES"
    HAS_HOST = "HAS_HOST"
    RESOLVES_TO = "RESOLVES_TO"
    REDIRECTS_TO = "REDIRECTS_TO"
    CONNECTS_TO = "CONNECTS_TO"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    AUTHENTICATED_FROM = "AUTHENTICATED_FROM"
    USED_DEVICE = "USED_DEVICE"
    HAS_SESSION = "HAS_SESSION"
    ORIGINATED_FROM = "ORIGINATED_FROM"
    ACCESSED = "ACCESSED"
    BELONGS_TO = "BELONGS_TO"
    HAS_HASH = "HAS_HASH"
    EXTRACTED_FROM = "EXTRACTED_FROM"
    DERIVED_FROM = "DERIVED_FROM"
    CLAIMS_IDENTITY = "CLAIMS_IDENTITY"
    TARGETS = "TARGETS"
    LOOKALIKE_OF = "LOOKALIKE_OF"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    OBSERVED_IN = "OBSERVED_IN"
    RELATED_TO = "RELATED_TO"
    QUERIED_DNS = "QUERIED_DNS"
    SUBMITS_TO = "SUBMITS_TO"
    ROUTED_THROUGH = "ROUTED_THROUGH"
    USES_NAMESERVER = "USES_NAMESERVER"
    USES_MAIL_SERVER = "USES_MAIL_SERVER"
    HOSTED_BY = "HOSTED_BY"
    HOSTED_ON = "HOSTED_ON"
    SHARES_CERTIFICATE = "SHARES_CERTIFICATE"
    SHARES_NAMESERVER = "SHARES_NAMESERVER"
    SHARES_IP = "SHARES_IP"
    SHARES_ASN = "SHARES_ASN"
    RELATED_TO_DOMAIN = "RELATED_TO_DOMAIN"
    RELATED_TO_CAMPAIGN = "RELATED_TO_CAMPAIGN"
    HAS_BEHAVIOR_BASELINE = "HAS_BEHAVIOR_BASELINE"
    DEVIATES_FROM_BASELINE = "DEVIATES_FROM_BASELINE"
    EXHIBITS_NOVEL_PATTERN = "EXHIBITS_NOVEL_PATTERN"
    ASSOCIATED_WITH_NOVEL_PATTERN = "ASSOCIATED_WITH_NOVEL_PATTERN"
    OTHER = "OTHER"


class RelationshipOrigin(str, Enum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    INFERRED = "INFERRED"
    EXTERNAL_INTELLIGENCE = "EXTERNAL_INTELLIGENCE"


class RelationshipStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    RETRACTED = "RETRACTED"


# ============================================================================
# 2. CANONICAL KEY GENERATION & SANITIZATION UTILITIES
# ============================================================================

SENSITIVE_KEY_SUBSTRINGS = {
    "password", "secret", "token", "auth", "credential", "cookie",
    "api_key", "apikey", "bearer", "private_key", "session_key", "jwt"
}


def sanitize_graph_attributes(attrs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Recursively redacts raw passwords, tokens, cookies, auth headers, and secrets
    from graph node and edge attributes before persistence or serialization.
    """
    if not attrs or not isinstance(attrs, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for k, v in attrs.items():
        k_lower = str(k).lower()
        if any(sub in k_lower for sub in SENSITIVE_KEY_SUBSTRINGS):
            sanitized[k] = "[REDACTED]"
            continue

        if isinstance(v, str):
            sanitized[k] = sanitize_log_text(v)
        elif isinstance(v, dict):
            sanitized[k] = sanitize_graph_attributes(v)
        elif isinstance(v, list):
            clean_list = []
            for item in v:
                if isinstance(item, dict):
                    clean_list.append(sanitize_graph_attributes(item))
                elif isinstance(item, str):
                    clean_list.append(sanitize_log_text(item))
                else:
                    clean_list.append(item)
            sanitized[k] = clean_list
        else:
            sanitized[k] = v

    return sanitized


def make_canonical_key(
    entity_type: Union[GraphEntityType, str],
    value: str,
    context: Optional[str] = None
) -> str:
    """
    Produces deterministic, collision-resistant canonical keys across entity types.
    Strictly preserves tenant/provider context for non-globally-unique entities
    (Accounts, Users, Sessions, Devices, Processes).
    """
    type_str = (
        entity_type.value if isinstance(entity_type, GraphEntityType) else str(entity_type)
    ).upper()
    val = (value or "").strip()
    ctx = (context or "").strip()

    if type_str == "IP":
        return f"ip:{normalize_ip(val)}"
    elif type_str == "DOMAIN":
        return f"domain:{normalize_domain(val)}"
    elif type_str == "URL":
        return f"url:{normalize_url(val)}"
    elif type_str == "HASH":
        return f"hash:{normalize_hash(val)}"
    elif type_str == "EMAIL":
        return f"email:{val.lower()}"
    elif type_str in ("EMAIL_ADDRESS", "ADDRESS"):
        return f"email_addr:{normalize_email_address(val)}"
    elif type_str == "ACCOUNT":
        ctx_prefix = f"{ctx.lower()}:" if ctx else "global:"
        return f"account:{ctx_prefix}{val.lower()}"
    elif type_str == "USER":
        ctx_prefix = f"{ctx.lower()}:" if ctx else "global:"
        return f"user:{ctx_prefix}{val.lower()}"
    elif type_str == "DEVICE":
        ctx_prefix = f"{ctx.lower()}:" if ctx else "global:"
        return f"device:{ctx_prefix}{val}"
    elif type_str == "SESSION":
        ctx_prefix = f"{ctx.lower()}:" if ctx else "global:"
        return f"session:{ctx_prefix}{val}"
    elif type_str == "PROCESS":
        ctx_prefix = f"{ctx.lower()}:" if ctx else "global:"
        return f"process:{ctx_prefix}{val.lower()}"
    elif type_str == "API_SERVICE":
        return f"api_service:{val.lower()}"
    elif type_str == "API_RESOURCE":
        ctx_prefix = f"{ctx.lower()}:" if ctx else ""
        return f"api_resource:{ctx_prefix}{val.lower()}"
    elif type_str == "FILE":
        clean_hash = normalize_hash(val) if len(val) in (32, 40, 64) else val
        return f"file:{clean_hash}"
    elif type_str == "MEDIA":
        clean_hash = normalize_hash(val) if len(val) in (32, 40, 64) else val
        return f"media:{clean_hash}"
    elif type_str == "IDENTITY":
        return f"identity:{val.lower()}"
    elif type_str == "INCIDENT":
        return f"incident:{val.upper()}"
    elif type_str == "CAMPAIGN":
        return f"campaign:{val.lower()}"
    elif type_str == "ASN":
        clean_asn = val.upper() if val.upper().startswith("AS") else f"AS{val.upper()}"
        return f"asn:{clean_asn}"
    elif type_str == "CERTIFICATE":
        return f"cert:{val.lower()}"
    elif type_str == "NAMESERVER":
        return f"ns:{normalize_domain(val)}"
    elif type_str == "NETWORK":
        return f"network:{val.lower()}"
    elif type_str in ("INFRASTRUCTURE_CLUSTER", "CLUSTER"):
        return f"cluster:{val.lower()}"
    elif type_str in ("BEHAVIORAL_BASELINE", "BASELINE"):
        return f"baseline:{val.lower()}"
    else:
        return f"{type_str.lower()}:{val}"


# ============================================================================
# 3. PYDANTIC GRAPH CONTRACTS & RESPONSE SCHEMAS
# ============================================================================

class GraphNode(BaseModel):
    """Canonical representation of an entity node in the Security Knowledge Graph."""
    id: str = Field(..., description="Unique entity ID (UUID or canonical key)")
    type: str = Field(..., description="Entity category (e.g. IP, DOMAIN, URL, EMAIL, ACCOUNT, DEVICE)")
    canonical_key: str = Field(..., description="Deterministic canonical identity string")
    display_value: str = Field(..., description="Human-readable display title or name")
    first_seen: Optional[datetime] = Field(None, description="Earliest observation timestamp")
    last_seen: Optional[datetime] = Field(None, description="Most recent observation timestamp")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Redacted entity attributes")
    workspace_id: Optional[str] = Field(None, description="Tenant/workspace isolation scope")


class GraphEdge(BaseModel):
    """Directed canonical relationship edge in the Security Knowledge Graph."""
    id: str = Field(..., description="Relationship ID")
    source: str = Field(..., description="Source entity ID")
    target: str = Field(..., description="Target entity ID")
    type: str = Field(..., description="Relationship type from controlled vocabulary")
    origin: RelationshipOrigin = Field(RelationshipOrigin.OBSERVED, description="Edge origin classification")
    status: RelationshipStatus = Field(RelationshipStatus.ACTIVE, description="Active, Superseded, or Retracted")
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence in relationship existence")
    first_seen: Optional[datetime] = Field(None, description="First time relationship was observed")
    last_seen: Optional[datetime] = Field(None, description="Last time relationship was observed")
    observation_count: int = Field(1, description="Number of supporting observation records")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Redacted edge attributes")
    evidence_reference: Optional[str] = Field(None, description="Primary evidence reference pointer")
    workspace_id: Optional[str] = Field(None, description="Tenant/workspace isolation scope")


class RelationshipObservationResponse(BaseModel):
    """Individual evidence-backed observation of a relationship edge."""
    id: str = Field(..., description="Observation ID")
    relationship_id: str = Field(..., description="Parent canonical relationship ID")
    observed_at: datetime = Field(..., description="Observation timestamp")
    source_artifact_id: Optional[str] = Field(None, description="Artifact that produced this observation")
    analysis_run_id: Optional[str] = Field(None, description="AnalysisRun that produced this observation")
    evidence_id: Optional[str] = Field(None, description="Supporting FindingEvidence item ID")
    analyzer: Optional[str] = Field(None, description="Analyzer name")
    analyzer_version: Optional[str] = Field(None, description="Analyzer version")
    confidence: float = Field(1.0, description="Observation confidence score")
    origin: str = Field("OBSERVED", description="Observation origin")
    attributes: Dict[str, Any] = Field(default_factory=dict, description="Contextual observation attributes")


class EdgeEvidenceResponse(BaseModel):
    """Complete provenance and evidence disclosure answering 'WHY DOES THIS EDGE EXIST?'."""
    edge: GraphEdge
    observations: List[RelationshipObservationResponse] = Field(default_factory=list)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    threat_events: List[Dict[str, Any]] = Field(default_factory=list)
    source_entity: Optional[GraphNode] = None
    target_entity: Optional[GraphNode] = None
    explanation: str = Field(..., description="Human and machine-readable explanation of edge evidence")


class GraphSubgraphResponse(BaseModel):
    """Bounded subgraph payload (for neighborhoods, incident subgraphs, etc.)."""
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    total_nodes: int = Field(0)
    total_edges: int = Field(0)
    truncated: bool = Field(False, description="True if results were capped by max_nodes or max_edges limit")


class GraphPathResponse(BaseModel):
    """Bounded multi-hop path query result."""
    paths: List[List[GraphEdge]] = Field(default_factory=list, description="Sequences of edges forming paths")
    nodes: List[GraphNode] = Field(default_factory=list, description="Unique nodes involved in discovered paths")
    edges: List[GraphEdge] = Field(default_factory=list, description="Unique edges involved in discovered paths")
    depth: int = Field(0, description="Search depth reached")
    total_paths: int = Field(0, description="Count of paths discovered")
    provenance_summary: List[Dict[str, Any]] = Field(default_factory=list, description="Step-by-step path provenance")


class TimelineEventItem(BaseModel):
    """Entity-centric timeline entry."""
    id: str
    timestamp: datetime
    event_type: str
    description: str
    role: str
    relationship_type: Optional[str] = None
    peer_entity_id: Optional[str] = None
    peer_entity_type: Optional[str] = None
    peer_entity_key: Optional[str] = None
    origin: str = "OBSERVED"
    analyzer: Optional[str] = None
    confidence: float = 1.0
    artifact_id: Optional[str] = None
    incident_id: Optional[str] = None


class EntityTimelineResponse(BaseModel):
    """Entity-centric chronological timeline across observations and incidents."""
    entity_id: str
    canonical_key: str
    entity_type: str
    display_value: str
    total_events: int
    events: List[TimelineEventItem] = Field(default_factory=list)


class EntitySearchResponse(BaseModel):
    """Search results for entities."""
    entities: List[GraphNode] = Field(default_factory=list)
    total: int = 0


class GraphBuildRequest(BaseModel):
    """Request to process and ingest artifacts or analysis runs into the Knowledge Graph."""
    analysis_run_id: Optional[str] = None
    artifact_id: Optional[str] = None
    incident_id: Optional[str] = None
    workspace_id: Optional[str] = None


class GraphBuildResponse(BaseModel):
    """Result of graph construction operation."""
    entities_created: int = 0
    entities_updated: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    observations_created: int = 0
