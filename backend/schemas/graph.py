from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    EMAIL = "Email"
    EMAIL_ADDRESS = "Email Address"
    DOMAIN = "Domain"
    URL = "URL"
    IP = "IP"
    ASN = "ASN"
    ATTACHMENT = "Attachment"
    CASE = "Case"
    CAMPAIGN = "Campaign"
    COUNTRY = "Country"
    HASH = "Hash"


class GraphNode(BaseModel):
    """Represents a forensic entity node in the investigation relationship graph."""
    id: str = Field(..., description="Unique canonical identifier for the node (e.g. domain:example.com, ip:1.2.3.4)")
    type: NodeType = Field(..., description="Forensic entity category")
    label: str = Field(..., description="Human-readable display label")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Detailed forensic attributes, flags, and intelligence")


class GraphEdge(BaseModel):
    """Represents a directed relationship between two forensic entity nodes."""
    id: str = Field(..., description="Unique identifier for the edge (e.g. edge:source->LABEL->target)")
    source: str = Field(..., description="Source node id")
    target: str = Field(..., description="Target node id")
    label: str = Field(..., description="Semantic relationship type (e.g. SENT_FROM, CONTAINS_URL, RESOLVES_TO_IP)")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context or evidence for the edge")


class GraphSummary(BaseModel):
    """Summary counts and breakdown for the graph."""
    total_nodes: int = Field(0, description="Total number of nodes")
    total_edges: int = Field(0, description="Total number of edges")
    node_type_counts: Dict[str, int] = Field(default_factory=dict, description="Count of nodes per node type")
    has_high_risk_entities: bool = Field(False, description="Whether any critical/high-risk entities are present")


class InvestigationGraphResponse(BaseModel):
    """Complete investigation relationship graph payload."""
    nodes: List[GraphNode] = Field(default_factory=list, description="List of forensic entity nodes")
    edges: List[GraphEdge] = Field(default_factory=list, description="List of directed relationship edges")
    summary: GraphSummary = Field(default_factory=GraphSummary, description="Graph summary metadata")


class GraphFilterRequest(BaseModel):
    """Request payload for filtering investigation relationship graph elements."""
    graph: InvestigationGraphResponse = Field(..., description="Investigation relationship graph to filter")
    node_types: Optional[List[NodeType]] = Field(None, description="Allowed node types to retain")
    max_nodes: Optional[int] = Field(150, description="Maximum nodes to return to prevent graph overload")
