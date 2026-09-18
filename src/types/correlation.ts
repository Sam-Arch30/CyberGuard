export interface SharedIndicator {
  type: string;
  value: string;
  details?: string;
}

export interface MatchedSignalDetail {
  signal_name: string;
  weight: number;
  matched_values: string[];
  contribution: number;
}

export interface RelatedCaseItem {
  case_id: string;
  case_number: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
  status: 'open' | 'investigating' | 'resolved' | 'escalated' | string;
  correlation_score: number;
  relationship_label: string;
  shared_evidence_summary: string;
  shared_indicators: SharedIndicator[];
  matching_signals: Record<string, MatchedSignalDetail>;
}

export interface CorrelatedIngestedEmail {
  id: string;
  evidence_id: string;
  sha256?: string | null;
  original_filename?: string;
  subject: string;
  sender: string;
  recipient?: string | null;
  timestamp?: string;
  threat_score: number;
  severity: string;
  similarity_score: number;
  similarity_percentage: number;
  relationship_label: string;
  shared_evidence_summary: string;
  shared_indicators: SharedIndicator[];
  has_eml_file?: boolean;
}

export interface CampaignCorrelationResponse {
  related_cases: RelatedCaseItem[];
  correlation_score: number;
  relationship_label: string;
  shared_indicators: SharedIndicator[];
  correlated_emails?: CorrelatedIngestedEmail[];
}

