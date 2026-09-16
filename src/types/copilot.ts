/**
 * Types for Evidence-Grounded Investigation Copilot in MailTraceAI.
 */

export type CopilotMode = 'email' | 'case' | 'campaign';

export type UncertaintyLevel =
  | 'CONFIRMED'
  | 'HIGH-CONFIDENCE INFERENCE'
  | 'PROBABLE'
  | 'LOW-CONFIDENCE HYPOTHESIS'
  | 'UNKNOWN';

export interface EvidenceReference {
  evidence_id: string;
  type: string;
  statement: string;
  source_module: string;
  reliability: number;
  confidence_category: string;
  raw_data?: Record<string, any>;
}

export type CopilotActionType =
  | 'view_evidence'
  | 'open_graph'
  | 'compare_emails'
  | 'add_to_case'
  | 'generate_report'
  | 'investigate_domain';

export interface CopilotAction {
  action_type: CopilotActionType;
  label: string;
  description?: string;
  params: Record<string, any>;
}

export interface SuggestedQuestion {
  question: string;
  category: string;
  mode: CopilotMode;
}

export interface CopilotQueryRequest {
  query: string;
  mode: CopilotMode;
  context_id?: string;
  email_payload?: Record<string, any>;
  include_timeline?: boolean;
  user?: string;
}

export interface CopilotQueryResponse {
  query: string;
  mode: CopilotMode;
  context_id?: string;
  assessment: string;
  reasoning_summary: string;
  confidence: UncertaintyLevel;
  evidence_refs: EvidenceReference[];
  suggested_actions: CopilotAction[];
  recommended_next_steps: string[];
  model: string;
  timestamp: string;
  audit_id?: string;
}

export interface CopilotMessage {
  id: string;
  sender: 'user' | 'copilot';
  text?: string;
  response?: CopilotQueryResponse;
  timestamp: string;
  isLoading?: boolean;
}

export interface CopilotAddToReportRequest {
  case_id?: string;
  report_id?: string;
  email_id?: string;
  query: string;
  summary_text: string;
  evidence_ids: string[];
  confidence: UncertaintyLevel;
  model: string;
  analyst_name: string;
}
