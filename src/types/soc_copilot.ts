/**
 * TypeScript Definitions for Section 30: LLM SOC Copilot.
 */

export type CopilotMode = 'ANALYST' | 'EXECUTIVE' | 'FORENSIC';

export type CopilotSemanticType =
  | 'OBSERVED_FACT'
  | 'INFERENCE'
  | 'HYPOTHESIS'
  | 'RECOMMENDATION'
  | 'ACTION_OPTION';

export type CopilotValidationStatus =
  | 'SUPPORTED'
  | 'PARTIALLY_SUPPORTED'
  | 'UNSUPPORTED'
  | 'UNCERTAIN';

export type CitationSourceType =
  | 'EVIDENCE'
  | 'FINDING'
  | 'THREAT_EVENT'
  | 'RISK_ASSESSMENT'
  | 'ATTACK_STAGE'
  | 'ATTACK_PATH'
  | 'MITRE_MAPPING'
  | 'THREAT_MEMORY'
  | 'RESPONSE_RECOMMENDATION'
  | 'ANALYSIS_RUN';

export interface CopilotCitation {
  citation_id: string;
  source_type: CitationSourceType;
  source_id: string;
  source_version?: string;
  claim_span?: string;
  confidence?: number;
  verified: boolean;
  details?: Record<string, any>;
}

export interface CopilotClaim {
  claim_text: string;
  semantic_type: CopilotSemanticType;
  validation_status: CopilotValidationStatus;
  supporting_evidence_ids: string[];
  notes?: string;
}

export interface ConversationResponse {
  id: string;
  workspace_id: string;
  investigation_id?: string;
  incident_id?: string;
  title: string;
  status: string;
  created_by: string;
  model_provider: string;
  model_name: string;
  context_policy_version: string;
  created_at: string;
  updated_at: string;
  message_count: number;
}

export interface SocMessageResponse {
  id: string;
  conversation_id: string;
  role: 'USER' | 'ASSISTANT' | 'SYSTEM' | 'TOOL';
  content: string;
  message_type: string;
  context_snapshot_id?: string;
  model_provider: string;
  model_name: string;
  prompt_version: string;
  claims: CopilotClaim[];
  citations: CopilotCitation[];
  uncertainties: string[];
  hypotheses: string[];
  next_steps: string[];
  tools_called: string[];
  latency_ms?: number;
  created_at: string;
}

export type FeedbackRating = 'HELPFUL' | 'NOT_HELPFUL' | 'INCORRECT' | 'MISSING_EVIDENCE';

export interface FeedbackSubmission {
  rating: FeedbackRating;
  feedback_text?: string;
  claim_incorrect?: boolean;
  citation_incorrect?: boolean;
  insufficient_context?: boolean;
  analyst_id?: string;
}
