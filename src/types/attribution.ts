export interface EvidenceItem {
  evidence_type: string;
  observation: string;
  contribution: number;
  source: string;
  timestamp?: string;
}

export type AttributionConfidenceLevel = 'LOW' | 'MODERATE' | 'HIGH' | 'VERY HIGH' | string;

export interface AttributionResult {
  attribution_id: string;
  email_id?: string | null;
  case_id?: string | null;
  campaign_id?: string | null;

  probable_origin_ip?: string | null;
  probable_origin_asn?: string | null;
  probable_origin_provider?: string | null;
  probable_infrastructure_country?: string | null;

  confidence_score: number;
  confidence_level: AttributionConfidenceLevel;

  supporting_evidence: EvidenceItem[];
  conflicting_evidence: EvidenceItem[];

  related_domains: string[];
  related_ips: string[];
  related_campaigns: string[];

  analysis_timestamp: string;
  disclaimer: string;
}

export interface CaseAttributionResponse {
  case_id: string;
  case_number?: string | null;
  total_emails_analyzed: number;
  attribution: AttributionResult;
  per_email_attributions: AttributionResult[];
}

export interface CampaignAttributionResponse {
  campaign_id: string;
  campaign_name: string;
  related_case_count: number;
  attribution: AttributionResult;
  shared_infrastructure_summary: {
    unique_ips?: string[];
    unique_asns?: string[];
    unique_providers?: string[];
    unique_countries?: string[];
    unique_domains?: string[];
  };
}
