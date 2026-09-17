export interface ProtocolResult {
  result?: 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'unknown' | string;
  details?: string;
}

export interface SenderAlignment {
  from_domain?: string;
  reply_to_domain?: string;
  return_path_domain?: string;
  reply_to_mismatch?: boolean;
  return_path_mismatch?: boolean;
}

export interface AuthenticationAnalysis {
  verification_type?: 'observed_header' | 'independent_validation' | string;
  verification_notice?: string;
  observed_header?: string;
  spf?: ProtocolResult;
  dkim?: ProtocolResult;
  dmarc?: ProtocolResult;
  alignment?: SenderAlignment;
}

export interface IPIndicator {
  value: string;
  version?: number;
  scope?: 'public' | 'private' | 'loopback' | 'link_local' | 'reserved' | 'unknown' | string;
  source?: string;
}

export interface DomainIndicator {
  value: string;
  source?: string;
}

export interface URLIndicator {
  value: string;
  source?: string;
}

export interface EmailAddressIndicator {
  value: string;
  source?: string;
}

import type { AttachmentStaticAnalysisResult } from './attachment';

export interface AttachmentIndicator {
  filename?: string;
  mime_type?: string;
  size?: number;
  sha256?: string;
  md5?: string;
  sha1?: string;
  static_analysis?: AttachmentStaticAnalysisResult;
}

export interface IndicatorsGroup {
  ips?: IPIndicator[];
  domains?: DomainIndicator[];
  urls?: URLIndicator[];
  email_addresses?: EmailAddressIndicator[];
  attachments?: AttachmentIndicator[];
}

export interface EmailAttachment {
  filename?: string;
  mime_type?: string;
  size?: number;
  sha256?: string;
  md5?: string;
  sha1?: string;
  static_analysis?: AttachmentStaticAnalysisResult;
}

export interface RelayHop {
  hop_number: number;
  from_host?: string;
  from_ip?: string;
  by_host?: string;
  by_ip?: string;
  protocol?: string;
  id?: string;
  recipient?: string;
  timestamp?: string;
  parser_confidence?: 'high' | 'medium' | 'low' | string;
  raw: string;
}

export interface EarliestObservableNode {
  earliest_observable_ip?: string;
  from_host?: string;
  confidence?: 'high' | 'medium' | 'low' | 'none' | string;
  reason?: string;
}

export interface RelayPathAnalysis {
  header_order_hops?: RelayHop[];
  transmission_order_hops?: RelayHop[];
  earliest_observable_node?: EarliestObservableNode;
  trust_notice?: string;
}

export interface IPIntelligence {
  ip: string;
  scope?: 'public' | 'private' | 'loopback' | 'link_local' | 'reserved' | 'unknown' | string;
  enrichment_available?: boolean;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  timezone?: string;
  asn?: string;
  asn_org?: string;
  isp?: string;
  organization?: string;
  is_hosting?: boolean;
  is_proxy_vpn_tor?: boolean;
  infrastructure_type?: string;
  error?: string;
}

export interface DNSRecords {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  txt: string[];
}

export interface DomainRegistration {
  registrar?: string;
  registration_date?: string;
  expiration_date?: string;
  nameservers: string[];
  status: string[];
  registration_source: string;
}

export interface LookalikeDetectionResult {
  domain: string;
  suspected_brand: string;
  brand_name: string;
  similarity: number;
  techniques: string[];
  confidence_label: string;
  details?: string;
}

export interface URLFeatures {
  scheme: string;
  hostname: string;
  registered_domain: string;
  subdomain: string;
  subdomain_count: number;
  port?: number;
  has_non_standard_port: boolean;
  path: string;
  path_length: number;
  query: string;
  query_length: number;
  total_length: number;
  is_ip_host: boolean;
  ip_version?: number;
  is_punycode: boolean;
  excessive_subdomains: boolean;
  has_credentials: boolean;
  suspicious_keywords: string[];
  has_percent_encoding: boolean;
  percent_encoding_count: number;
  unusual_char_density: boolean;
  is_shortener: boolean;
  display_link_mismatch: boolean;
  visible_text?: string;
  visible_text_domain?: string;
  lookalike?: LookalikeDetectionResult;
}

export interface URLAnalysisResult {
  url: string;
  domain: string;
  features: URLFeatures;
  observations: string[];
  suspicion_score: number;
  suspicion_level: 'low' | 'suspicious' | 'high';
  score_reasons: string[];
}

export interface ThreatSignalContribution {
  signal_id: string;
  category: string;
  name: string;
  description: string;
  why_it_matters?: string;
  raw_value?: any;
  normalized_value?: number;
  weight: number;
  contribution: number;
  direction: 'increase_risk' | 'decrease_risk';
  confidence: number;
  evidence_reference?: string;
  source: string;
}

export interface CategoryScoreBreakdown {
  category: string;
  display_name: string;
  risk_score: number;
  positive_signals_count: number;
  mitigating_signals_count: number;
  signals: ThreatSignalContribution[];
}

export interface ThreatScoreContribution {
  signal: string;
  label: string;
  points: number;
  evidence: string;
}

export interface PositiveEvidence {
  signal: string;
  label: string;
  evidence: string;
}

export interface ThreatScoreResult {
  score: number;
  severity: 'low' | 'suspicious' | 'high' | 'critical';
  risk_level?: 'LOW' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  confidence?: 'LOW' | 'MODERATE' | 'HIGH' | 'VERY HIGH';
  positive_contributions?: ThreatSignalContribution[];
  negative_contributions?: ThreatSignalContribution[];
  top_reasons?: string[];
  reasons: ThreatScoreContribution[];
  positive_evidence: PositiveEvidence[];
  summary: string;
  why_flagged?: string;
  category_breakdowns?: Record<string, CategoryScoreBreakdown>;
  model_version?: string;
  scoring_version?: string;
  audit_metadata?: {
    scoring_version?: string;
    weights_snapshot?: Record<string, number>;
    thresholds_snapshot?: Record<string, any>;
    timestamp?: string;
    evidence_ids?: string[];
    model_version?: string;
  };
}

export interface MLAssessmentResult {
  classification: 'phishing' | 'legitimate' | string;
  probability?: number | null;
  confidence?: 'high' | 'medium' | 'low' | 'none' | string;
  available?: boolean;
  top_features?: string[];
  model_name?: string;
  notice?: string;
}

export interface AIAnalystAssessment {
  summary: string;
  likely_attack_type: string;
  likely_objective: string;
  key_evidence: string[];
  recommended_actions: string[];
  limitations: string[];
  available: boolean;
  provider?: string;
  model?: string;
  model_name?: string;
  error?: string;
}

export interface DomainIntelligence {
  domain: string;
  punycode?: string;
  dns: DNSRecords;
  registration: DomainRegistration;
  domain_age_days?: number;
  newly_registered_domain?: boolean;
  is_resolvable: boolean;
  status_message?: string;
  lookalike?: LookalikeDetectionResult;
}

export interface InvestigationTimelineItem {
  id: string;
  timestamp: string;
  time_display: string;
  action: string;
  title: string;
  description?: string;
  user?: string;
  resource_type: string;
  resource_id: string;
  metadata?: Record<string, any>;
}

export interface InvestigationTimelineResponse {
  evidence_id?: string;
  sha256?: string;
  events: InvestigationTimelineItem[];
  total: number;
}

export interface EmailAnalysis {
  id?: string;
  evidence_id?: string;
  email_sha256?: string;
  original_filename?: string;
  upload_timestamp?: string;
  size?: number;
  uploader?: string;
  file_info?: {
    filename?: string;
    size_bytes?: number;
  };
  authentication?: AuthenticationAnalysis;
  relay_analysis?: RelayPathAnalysis;
  ip_intelligence?: Record<string, IPIntelligence>;
  domain_intelligence?: Record<string, DomainIntelligence>;
  lookalike_domains?: LookalikeDetectionResult[];
  url_analysis?: URLAnalysisResult[];
  threat_score?: ThreatScoreResult;
  ml_phishing_probability?: number | null;
  ml_assessment?: MLAssessmentResult;
  ai_analyst?: AIAnalystAssessment;
  investigation_graph?: import('./graph').InvestigationGraphData;
  attribution?: import('./attribution').AttributionResult;
  forensic_conclusions?: import('./confidence').ForensicConclusion[];
  indicators?: IndicatorsGroup;
  subject?: string;
  from?: string;
  to?: string;
  cc?: string;
  date?: string;
  reply_to?: string;
  return_path?: string;
  message_id?: string;
  received?: string[];
  authentication_results?: string;
  plain_text_body?: string;
  html_body?: string;
  raw_email?: string;
  urls?: string[];
  ips?: string[];
  domains?: string[];
  emails?: string[];
  attachments?: EmailAttachment[];
  hops?: any[];
  is_demo?: boolean;
  is_synthetic?: boolean;
}

export type ForensicTabType = 'overview' | 'copilot' | 'cross_investigation' | 'attribution' | 'graph' | 'map' | 'headers' | 'content' | 'indicators' | 'attachments' | 'raw';


