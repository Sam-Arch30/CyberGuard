/**
 * Section 52: Threat Intelligence & External Intelligence Enrichment TypeScript definitions.
 */

export type IndicatorType =
  | 'IP'
  | 'DOMAIN'
  | 'URL'
  | 'SHA256'
  | 'SHA1'
  | 'MD5'
  | 'EMAIL'
  | 'CERTIFICATE'
  | 'ASN'
  | 'HOSTNAME';

export type Verdict = 'UNKNOWN' | 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNVERIFIED';

export type Severity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type PrivacyScope = 'PUBLIC' | 'PRIVATE' | 'INTERNAL' | 'SENSITIVE' | 'UNKNOWN';

export type ProviderStatus = 'HEALTHY' | 'DEGRADED' | 'RATE_LIMITED' | 'UNAVAILABLE' | 'MISCONFIGURED';

export interface ProviderIntelligenceItem {
  provider: string;
  display_name: string;
  verdict: Verdict;
  confidence: number;
  severity: Severity;
  threat_types: string[];
  retrieved_at: string;
  observed_at?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  details?: string | null;
  source_url?: string | null;
  raw_reference?: string | null;
  attributes: Record<string, any>;
  is_stale: boolean;
}

export interface AggregatedIndicatorIntelligence {
  indicator_type: IndicatorType;
  raw_value: string;
  normalized_value: string;
  privacy_scope: PrivacyScope;
  overall_verdict: Verdict;
  consensus_confidence: number;
  overall_severity: Severity;
  total_sources_queried: number;
  verdict_breakdown: Record<string, number>;
  is_conflicting: boolean;
  conflict_summary?: string | null;
  threat_types: string[];
  is_stale: boolean;
  first_seen?: string | null;
  last_seen?: string | null;
  last_refreshed_at: string;
  providers_data: ProviderIntelligenceItem[];
  provenance: Record<string, any>;
  internal_memory_matched: boolean;
  associated_campaigns: string[];
  associated_threat_actors: string[];
}

export interface IndicatorObservationHistoryItem {
  timestamp: string;
  verdict: Verdict;
  confidence: number;
  provider: string;
  source_type: string;
  summary?: string | null;
  threat_types: string[];
}

export interface IndicatorHistoryResponse {
  indicator_type: IndicatorType;
  normalized_value: string;
  total_observations: number;
  history: IndicatorObservationHistoryItem[];
}

export interface ThreatIntelProviderConfig {
  id: string;
  workspace_id: string;
  provider_name: string;
  display_name: string;
  enabled: boolean;
  priority: number;
  supported_types: string[];
  rate_limit_per_minute: number;
  timeout_seconds: number;
  is_configured: boolean;
  status: ProviderStatus;
  last_health_check_at?: string | null;
  error_message?: string | null;
  capabilities: Record<string, any>;
}

export interface PrivacyPolicyClassification {
  indicator_type: IndicatorType;
  raw_value: string;
  normalized_value: string;
  privacy_scope: PrivacyScope;
  external_lookup_permitted: boolean;
  reason: string;
}
