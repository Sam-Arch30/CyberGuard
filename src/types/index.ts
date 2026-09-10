export type ThreatSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'LEGITIMATE';
export type ThreatCategory = 'BEC Fraud' | 'Executive Impersonation' | 'Credential Harvesting' | 'Phishing Link' | 'Malicious Attachment' | 'Display Name Spoof' | 'Legitimate';
export type CaseStatus = 'NEW' | 'UNDER_INVESTIGATION' | 'CONTAINED' | 'CLOSED' | 'ESCALATED';

export interface EmailHeaderHop {
  hopNumber: number;
  fromHost: string;
  fromIp: string;
  byHost: string;
  byIp: string;
  timestamp: string;
  delaySeconds: number;
  country: string;
  city: string;
  org: string;
  isOrigin?: boolean;
  isSuspicious?: boolean;
  notes?: string;
}

export interface SecurityProtocolStatus {
  spf: 'PASS' | 'FAIL' | 'NEUTRAL' | 'NONE';
  spfDetails: string;
  dkim: 'PASS' | 'FAIL' | 'NONE';
  dkimDetails: string;
  dmarc: 'PASS' | 'FAIL' | 'NONE';
  dmarcDetails: string;
  returnPathMatch: boolean;
  replyToMismatch: boolean;
}

export interface GeoLocationInfo {
  ip: string;
  country: string;
  countryCode: string;
  city: string;
  region: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  isVpn: boolean;
  isTor: boolean;
  isProxy: boolean;
  isDatacenter: boolean;
}

export interface ExtractedIOCs {
  ips: string[];
  domains: string[];
  urls: { url: string; domain: string; isObfuscated: boolean; riskScore: number }[];
  hashes: { filename: string; md5: string; sha256: string; isMalicious: boolean }[];
  emails: string[];
}

export interface EmailAnalysisData {
  id: string;
  subject: string;
  senderName: string;
  senderEmail: string;
  returnPath: string;
  replyTo: string;
  recipientEmail: string;
  timestamp: string;
  riskScore: number; // 0 to 100
  severity: ThreatSeverity;
  category: ThreatCategory;
  summary: string;
  nlpFlags: {
    urgencyCues: boolean;
    financialDiversionLanguage: boolean;
    credentialHarvestingKeywords: boolean;
    authorityImpersonation: boolean;
    nlpScore: number;
  };
  protocols: SecurityProtocolStatus;
  originGeo: GeoLocationInfo;
  hops: EmailHeaderHop[];
  iocs: ExtractedIOCs;
  rawHeaders: string;
  bodyText: string;
  campaignId?: string;
  campaignName?: string;
}

export interface InvestigationCase {
  id: string;
  caseNumber: string;
  title: string;
  severity: ThreatSeverity;
  status: CaseStatus;
  category: ThreatCategory;
  targetUser: string;
  targetDepartment: string;
  senderEmail: string;
  originIp: string;
  originCountry: string;
  fraudRiskScore: number;
  assignedAnalyst: string;
  createdAt: string;
  updatedAt: string;
  description: string;
  relatedEmailIds: string[];
  evidenceHashes: string[];
  chainOfCustody: {
    id: string;
    timestamp: string;
    action: string;
    actor: string;
    details: string;
    hash: string;
  }[];
}

export interface ThreatIntelligenceCluster {
  id: string;
  campaignName: string;
  threatActor: string;
  firstSeen: string;
  lastSeen: string;
  targetedSectors: string[];
  originCountries: string[];
  associatedDomains: string[];
  associatedIps: string[];
  activeIndicatorCount: number;
  riskLevel: ThreatSeverity;
  description: string;
}

export interface ForensicReport {
  id: string;
  reportNumber: string;
  title: string;
  type: 'Incident Response' | 'Law Enforcement Submittal' | 'Executive Threat Brief' | 'Compliance Audit';
  caseId: string;
  createdAt: string;
  analystName: string;
  status: 'Draft' | 'Approved' | 'Submitted';
  summary: string;
  evidenceCount: number;
  digitalSignature: string;
}

export interface SystemSettings {
  anonymizeTargetPII: boolean;
  maskEmailAddresses: boolean;
  retentionPeriodDays: number;
  autoEscalateThreshold: number;
  sha256ChainOfCustody: boolean;
  enableRealTimeAlerts: boolean;
  webhookUrl: string;
  allowedIpSubnets: string;
}

export * from './confidence';
export * from './attribution';
