export type ConfidenceLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'VERY HIGH';

export type EvidenceCategory =
  | 'confirmed_evidence'
  | 'probable_inference'
  | 'weak_hypothesis'
  | 'unavailable_information';

export type ConclusionType =
  | 'threat_classification'
  | 'infrastructure_attribution'
  | 'campaign_association'
  | 'geolocation'
  | 'lookalike_determination'
  | 'malicious_url'
  | 'nlp_classification'
  | 'attachment_risk';

export interface EvaluatedEvidence {
  evidence_id: string;
  source_module: string;
  statement: string;
  is_supporting: boolean;
  reliability: number;
  independence: number;
  recency_days?: number | null;
  specificity: number;
  consistency: number;
  raw_score_contribution: number;
  effective_weight: number;
  evidence_category: EvidenceCategory;
  independence_cluster?: string | null;
}

export interface ForensicConclusion {
  conclusion_id: string;
  type: ConclusionType;
  statement: string;
  confidence_score: number;
  confidence_level: ConfidenceLevel;
  supporting_evidence: EvaluatedEvidence[];
  conflicting_evidence: EvaluatedEvidence[];
  limitations: string[];
  source_modules: string[];
  generated_at: string;
  engine_version: string;
}

export interface EmailConfidenceResponse {
  email_id: string;
  conclusions: ForensicConclusion[];
  summary: {
    total_conclusions: number;
    highest_confidence_type?: string;
    has_conflicts: boolean;
    level_counts: Record<string, number>;
  };
  engine_version: string;
  evaluated_at: string;
}
