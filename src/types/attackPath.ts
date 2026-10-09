/**
 * TypeScript Contracts for Section 40: Interactive Attack Path.
 * Mirrors backend Pydantic schemas in backend/schemas/attack_path_projection.py.
 */

export type AttackPathStatus =
  | 'ESTABLISHED'
  | 'PARTIAL'
  | 'SUPPORTED_HYPOTHESIS'
  | 'LOW_CONFIDENCE'
  | 'INCONCLUSIVE';

export type StageCertaintyStatus =
  | 'OBSERVED'
  | 'DERIVED'
  | 'INFERRED'
  | 'UNRESOLVED';

export type ConfidenceBand = 'VERY_HIGH' | 'HIGH' | 'MODERATE' | 'LOW';

export interface AttackStageProjection {
  id: string;
  stage_order: number;
  stage_type: string;
  stage_status: StageCertaintyStatus;
  technique_id?: string | null;
  tactic?: string | null;
  title: string;
  description?: string | null;
  start_time?: string | null;
  end_time?: string | null;
  time_uncertainty?: string | null;
  confidence: number;
  confidence_level: ConfidenceBand | string;
  entity_ids: string[];
  finding_ids: string[];
  evidence_ids: string[];
  event_ids: string[];
  evidence_count: number;
  finding_count: number;
  supporting_evidence: Array<Record<string, any>>;
  contradicting_evidence: Array<Record<string, any>>;
  limitations: string[];
  entities_detail: Array<{
    id: string;
    type: string;
    value: string;
    risk_score: number;
  }>;
  findings_detail: Array<{
    id: string;
    type: string;
    title: string;
    severity: string;
    analyzer: string;
    confidence: number;
  }>;
}

export interface AttackTransitionProjection {
  id: string;
  from_stage_id: string;
  to_stage_id: string;
  relationship_type: string;
  edge_status: StageCertaintyStatus;
  is_causal: boolean;
  relationship_label: string;
  relationship_description: string;
  temporal_gap_seconds?: number | null;
  temporal_gap_formatted?: string | null;
  confidence: number;
  confidence_level: ConfidenceBand | string;
  shared_entities: string[];
  supporting_evidence_count: number;
  supporting_evidence: Array<Record<string, any>>;
  contradicting_evidence: Array<Record<string, any>>;
}

export interface AttackGapProjection {
  id: string;
  category: string;
  title: string;
  description: string;
  affected_stage_ids: string[];
  impact: string;
}

export interface AttackContradictionProjection {
  id: string;
  title: string;
  description: string;
  conflicting_evidence: Array<Record<string, any>>;
  assessment_impact: string;
}

export interface AttackAlternativeProjection {
  id: string;
  title: string;
  description?: string | null;
  status: string;
  is_primary: boolean;
  stage_ids: string[];
  confidence: number;
  confidence_level: ConfidenceBand | string;
  missing_evidence: string[];
  supporting_evidence: Array<Record<string, any>>;
  contradicting_evidence: Array<Record<string, any>>;
}

export interface AttackPathAvailableRun {
  run_id: string;
  version: string;
  status: string;
  overall_risk_score?: number | null;
  overall_severity?: string | null;
  started_at?: string | null;
  completed_at?: string | null;
  is_current: boolean;
}

export interface AttackPathMitreTechnique {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  status: 'SUPPORTED' | 'PLAUSIBLE' | 'INSUFFICIENT' | 'REJECTED' | string;
  confidence: number;
  confidence_level: string;
  explanation: string;
  evidence_count: number;
}

export interface AttackPathInfrastructure {
  id: string;
  origin_value: string;
  origin_type: string;
  hypothesis_title: string;
  hypothesis_type: string;
  status: string;
  confidence_level: string;
  confidence_score: number;
  evidence_count: number;
  limitations: string[];
}

export interface AttackPathTimelineEvent {
  id: string;
  timestamp: string;
  event_type: string;
  title: string;
  description: string;
  severity: string;
  source: string;
  confidence: number;
  matched_stage_id?: string | null;
}

export interface AttackPathDetailResponse {
  investigation_id: string;
  incident_number?: string | null;
  analysis_run_id?: string | null;
  available_runs: AttackPathAvailableRun[];
  has_path: boolean;
  path_id?: string | null;
  name?: string | null;
  classification?: string | null;
  status: AttackPathStatus;
  status_rationale?: string | null;
  completeness_score: number;
  confidence: number;
  confidence_level: ConfidenceBand | string;
  confidence_components: Record<string, any>;
  confidence_bottleneck?: Record<string, any> | null;
  explanation: Record<string, any>;
  start_time?: string | null;
  end_time?: string | null;
  duration_seconds?: number | null;
  version: number;
  engine_version: string;
  rule_version: string;
  generated_at?: string | null;
  stages: AttackStageProjection[];
  transitions: AttackTransitionProjection[];
  gaps: AttackGapProjection[];
  contradictions: AttackContradictionProjection[];
  alternatives: AttackAlternativeProjection[];
  mitre_techniques: AttackPathMitreTechnique[];
  infrastructure: AttackPathInfrastructure[];
  timeline_events: AttackPathTimelineEvent[];
  total_evidence_count: number;
  total_findings_count: number;
  total_entities_count: number;
  limitations: string[];
}

export interface AttackPathFilterState {
  showObserved: boolean;
  showDerived: boolean;
  showInferred: boolean;
  minConfidence: number; // 0.0 - 1.0
  selectedTactic: string | 'ALL';
  selectedSource: string | 'ALL';
}
