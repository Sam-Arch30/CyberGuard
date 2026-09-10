export interface InfrastructureFingerprint {
  origin_ip?: string | null;
  relay_ips: string[];
  asns: string[];
  hosting_providers: string[];
  nameservers: string[];
  mx_infrastructure: string[];
}

export interface DomainFingerprint {
  sender_domain?: string | null;
  reply_to_domain?: string | null;
  linked_domains: string[];
  registration_age_days?: number | null;
  registrars: string[];
  dns_characteristics: Record<string, any>;
  lookalike_targets: string[];
}

export interface UrlFingerprint {
  normalized_urls: string[];
  destination_domains: string[];
  redirect_chains: string[][];
  path_patterns: string[];
  query_parameter_keys: string[];
}

export interface EmailStructureFingerprint {
  subject_pattern: string;
  sender_naming_pattern: string;
  html_template_hash: string;
  header_patterns: Record<string, string>;
  attachment_names: string[];
  attachment_types: string[];
}

export interface ContentFingerprint {
  nlp_embeddings: Record<string, number>;
  phishing_intent: string;
  repeated_phrases: string[];
  targeted_organizations: string[];
  requested_actions: string[];
}

export interface AuthenticationFingerprint {
  spf_pattern: string;
  dkim_pattern: string;
  dmarc_pattern: string;
  alignment_status: Record<string, boolean>;
}

export interface AttachmentFingerprint {
  hashes: string[];
  fuzzy_hashes: string[];
  filenames: string[];
  mime_types: string[];
}

export interface CampaignFingerprint {
  infrastructure: InfrastructureFingerprint;
  domain: DomainFingerprint;
  url: UrlFingerprint;
  email_structure: EmailStructureFingerprint;
  content: ContentFingerprint;
  authentication: AuthenticationFingerprint;
  attachments: AttachmentFingerprint;
}

export interface CategoryScores {
  infrastructure_similarity: number;
  domain_similarity: number;
  url_similarity: number;
  content_similarity: number;
  template_similarity: number;
  authentication_similarity: number;
  attachment_similarity: number;
  overall_confidence: number;
  category_weights?: Record<string, number>;
  strongest_signals?: string[];
}

export interface CampaignTimelineEvent {
  id: string;
  timestamp: string;
  event_type: 'first_email' | 'new_domain' | 'infrastructure_change' | 'new_url' | 'victim_expansion' | string;
  title: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  indicators?: string[];
}

export interface CampaignIOC {
  type: 'ip' | 'domain' | 'url' | 'hash' | 'sender' | 'recipient' | string;
  value: string;
  first_seen: string;
  last_seen: string;
  confidence: number;
}

export interface CampaignClusterItem {
  campaign_id: string; // e.g. C-042
  name: string;
  first_seen: string;
  last_seen: string;
  email_count: number;
  recipient_count: number;
  sender_count: number;
  domain_count: number;
  ip_count: number;
  asn_count: number;
  overall_confidence: number;
  dominant_attack_type: string;
  targeted_brands: string[];
  targeted_organizations: string[];
  category_scores?: CategoryScores | null;
}

export interface CampaignDetail extends CampaignClusterItem {
  fingerprint: CampaignFingerprint;
  associated_iocs: CampaignIOC[];
  timeline: CampaignTimelineEvent[];
  emails: Array<{
    id: string;
    subject: string;
    sender: string;
    recipient?: string;
    date: string;
    threat_score?: number;
    similarity?: number;
    correlation_reasons?: string[];
  }>;
  infrastructure_summary: {
    origin_ip?: string | null;
    relay_ips?: string[];
    asns?: string[];
    hosting_providers?: string[];
    nameservers?: string[];
    mx_infrastructure?: string[];
  };
  domain_summary: {
    sender_domain?: string | null;
    reply_to_domain?: string | null;
    linked_domains?: string[];
    registrars?: string[];
    lookalike_targets?: string[];
  };
  url_summary: {
    normalized_urls?: string[];
    destination_domains?: string[];
    path_patterns?: string[];
    query_parameter_keys?: string[];
  };
  recipient_summary: {
    recipients?: string[];
    total?: number;
  };
}

export interface CampaignAlertData {
  is_campaign_detected: boolean;
  campaign_id?: string | null;
  campaign_name?: string | null;
  correlated_message_count?: number;
  overall_confidence?: number;
  message_alert?: string;
  alert_headline?: string;
  alert_subtext?: string;
  strongest_reasons?: string[];
  category_scores?: CategoryScores;
  first_seen?: string;
  last_seen?: string;
  dominant_attack_type?: string;
  targeted_brands?: string[];
}
