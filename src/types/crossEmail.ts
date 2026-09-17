import type { SharedIndicator } from './correlation';

export interface RelatedEmailItem {
  id: string;
  email_sha256?: string;
  subject: string;
  sender: string;
  recipient: string;
  received_time: string;
  threat_score: number;
  severity: string;
  campaign?: string;
  similarity: number;
  shared_indicators: SharedIndicator[];
  status: string;
  is_synthetic: boolean;
  correlation_reasons: string[];
}

export interface CrossEmailTimelineEvent {
  id: string;
  timestamp: string;
  time_display: string;
  event_type: 'email_delivered' | 'domain_registered' | 'redirect_identified' | 'ip_observed' | 'harvester_deployed' | string;
  title: string;
  description: string;
  related_emails: string[];
  indicators: string[];
  severity: 'low' | 'medium' | 'high' | 'critical' | string;
}

export interface CrossEmailAnalysisData {
  related_activity_detected: boolean;
  related_count: number;
  campaign_confidence?: number | null;
  campaign_id?: string | null;
  strongest_relationships: string[];
  related_emails: RelatedEmailItem[];
  timeline: CrossEmailTimelineEvent[];
  is_synthetic: boolean;
}

export interface ComparisonFieldItem {
  field_key: string;
  field_label: string;
  values: Record<string, any>;
  comparison_status: 'identical' | 'similar' | 'conflicting' | 'unique' | string;
  similarity_score?: number;
  explanation?: string;
}

export interface ComparisonCategory {
  category_id: string;
  category_title: string;
  items: ComparisonFieldItem[];
  category_alignment: string;
}

export interface ComparisonEmailMeta {
  id: string;
  subject: string;
  sender: string;
  recipient: string;
  threat_score: number;
  severity: string;
  received_time: string;
  is_synthetic: boolean;
}

export interface ComparisonMatrixData {
  emails: ComparisonEmailMeta[];
  categories: ComparisonCategory[];
  summary: {
    identical: number;
    similar: number;
    conflicting: number;
    unique: number;
  };
  overall_alignment_percentage: number;
}

export interface AnalystDecisionRecord {
  id: string;
  email_id_a: string;
  email_id_b: string;
  decision: string;
  campaign_id?: string;
  case_id?: string;
  analyst: string;
  notes?: string;
  created_at: string;
}
