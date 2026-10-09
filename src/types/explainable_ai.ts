/**
 * TypeScript Interfaces for Section 27: Explainable AI (XAI).
 */

export type ExplanationScope =
  | 'EVENT'
  | 'INVESTIGATION'
  | 'INCIDENT'
  | 'CAMPAIGN'
  | 'ENTITY'
  | 'ATTACK_PATH'
  | 'STAGE';

export type ExplanationLayer =
  | 'EXECUTIVE'
  | 'ANALYST'
  | 'INVESTIGATOR'
  | 'FORENSIC';

export type SupportLevel =
  | 'CONFIRMED'
  | 'VERY_HIGH'
  | 'HIGH'
  | 'MODERATE'
  | 'WEAK'
  | 'CONTRADICTED';

export interface ExplanationUnit {
  id: string;
  claim: string;
  claim_type: string;
  support_level: SupportLevel;
  evidence_refs: string[];
  source_refs: string[];
  confidence: number;
  confidence_level: string;
  limitations: string[];
  explanation_order: number;
  provenance: Record<string, any>;
}

export interface EvidenceGroup {
  family: string;
  name: string;
  summary: string;
  claims: ExplanationUnit[];
  evidence_count: number;
  is_independent: boolean;
  correlation_group?: string;
}

export interface CounterEvidenceItem {
  claim: string;
  evidence_refs: string[];
  source: string;
  interpretation: string;
  mitigation_strength: string;
}

export interface ContradictionRecord {
  id: string;
  claim: string;
  conflicting_signal: string;
  evidence_refs: string[];
  severity: string;
  impact_on_confidence: string;
  resolution_status: string;
  resolution_notes?: string;
}

export interface UnknownItem {
  topic: string;
  unknown: string;
  reason: string;
  impact: string;
}

export interface MissingInformationItem {
  telemetry_source: string;
  description: string;
  impact: string;
  remedy?: string;
}

export interface DetectorContribution {
  detector_id: string;
  detector_name: string;
  detector_version: string;
  status: string;
  finding: string;
  evidence_refs: string[];
  contribution_points: number;
  is_independent: boolean;
}

export interface ModelContribution {
  model_name: string;
  model_version: string;
  feature_set: string[];
  output_label: string;
  confidence_label: string;
  calibrated_score?: number;
  evaluation_status: string;
}

export interface RuleContribution {
  rule_id: string;
  rule_name: string;
  rule_version: string;
  rule_type: string;
  matched_conditions: Record<string, any>[];
  evidence_refs: string[];
  evaluation_status: string;
}

export interface MITREExplanationItem {
  technique_id: string;
  technique_name: string;
  tactic: string;
  why_mapped: string;
  evidence_refs: string[];
  mapping_method: string;
  mapping_status: string;
  confidence: number;
}

export interface AttackPathExplanation {
  path_id?: string;
  stage_sequence: Record<string, any>[];
  evidence_continuity: string;
  weakest_transitions: Record<string, any>[];
  bottleneck_summary?: string;
}

export interface AssessmentChangeGuidance {
  what_would_strengthen: string[];
  what_would_weaken: string[];
}

export interface EvidenceGraphNode {
  id: string;
  label: string;
  node_type: string;
  category?: string;
  details: Record<string, any>;
}

export interface EvidenceGraphEdge {
  source: string;
  target: string;
  relation: string;
  evidence_ref?: string;
}

export interface EvidenceGraph {
  nodes: EvidenceGraphNode[];
  edges: EvidenceGraphEdge[];
}

export interface ExplanationResponse {
  id: string;
  workspace_id: string;
  scope_type: ExplanationScope;
  scope_id: string;
  explanation_version: number;
  risk_assessment_id?: string;
  threat_event_id?: string;
  incident_id?: string;

  risk_score: number;
  risk_level: string;
  severity: string;
  confidence: number;
  confidence_level: string;
  uncertainty: string;

  summary: string;
  executive_summary: string;
  analyst_summary: string;
  generated_text?: string;

  conclusions: Record<string, any>[];
  explanation_units: ExplanationUnit[];
  evidence_groups: EvidenceGroup[];
  contributors: Record<string, any>[];
  counter_evidence: CounterEvidenceItem[];
  contradictions: ContradictionRecord[];
  uncertainty_items: UnknownItem[];
  limitations: string[];
  missing_information: MissingInformationItem[];

  detector_contributions: DetectorContribution[];
  model_contributions: ModelContribution[];
  rule_contributions: RuleContribution[];
  mitre_explanations: MITREExplanationItem[];
  attack_path_explanation: AttackPathExplanation;
  assessment_change_guidance: AssessmentChangeGuidance;

  evidence_graph: EvidenceGraph;
  investigator_details: Record<string, any>;
  forensic_details: Record<string, any>;

  validation_status: string;
  provenance: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface ExplanationFeedbackCreate {
  analyst_id: string;
  feedback_type: string;
  target_claim_id?: string;
  notes: string;
  correction_payload?: Record<string, any>;
}
