export type NodeType =
  | 'Email'
  | 'Email Address'
  | 'Domain'
  | 'URL'
  | 'IP'
  | 'ASN'
  | 'Attachment'
  | 'Case'
  | 'Campaign'
  | 'Country'
  | 'Hash';

export interface GraphNode {
  id: string;
  type: NodeType;
  label: string;
  metadata: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  metadata?: Record<string, any>;
}

export interface GraphSummary {
  total_nodes: number;
  total_edges: number;
  node_type_counts: Record<string, number>;
  has_high_risk_entities?: boolean;
}

export interface InvestigationGraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  summary: GraphSummary;
}

export interface GraphFilterState {
  allowedTypes: Set<NodeType>;
  searchTerm: string;
  highlightedNodeId: string | null;
}
