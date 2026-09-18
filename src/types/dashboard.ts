export interface DashboardMetrics {
  emails_analyzed: number;
  threats_detected: number;
  critical_emails: number;
  open_cases: number;
}

export interface SeverityDistributionItem {
  severity: string;
  count: number;
}

export interface AnalysisTrendPoint {
  date: string;
  total: number;
  threats: number;
}

export interface SuspiciousDomainItem {
  domain: string;
  count: number;
}

export interface InfrastructureCountryItem {
  country: string;
  count: number;
}

export interface AuthFailureBreakdown {
  spf_failures: number;
  dkim_failures: number;
  dmarc_failures: number;
  total_evaluated: number;
}

export interface DashboardCaseItem {
  id: string;
  case_number: string;
  title: string;
  severity: string;
  status: string;
  emails_count: number;
  updated_at: string;
}

export interface DashboardEmailItem {
  id: string;
  evidence_id?: string | null;
  sha256?: string | null;
  subject: string;
  sender: string;
  threat_score: number;
  severity: string;
  timestamp: string;
  original_filename?: string;
  has_eml_file?: boolean;
}

export interface DashboardSummary {
  metrics: DashboardMetrics;
  severity_distribution: SeverityDistributionItem[];
  analysis_trend: AnalysisTrendPoint[];
  top_suspicious_domains: SuspiciousDomainItem[];
  top_countries: InfrastructureCountryItem[];
  auth_failures: AuthFailureBreakdown;
  recent_cases: DashboardCaseItem[];
  recent_emails: DashboardEmailItem[];
}
