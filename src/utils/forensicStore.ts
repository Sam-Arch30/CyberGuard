import type { EmailAnalysis } from '../types/forensic';
import { resolveEmailIndicators, resolveAttribution } from './indicatorHelper';
import { resolveConfidenceConclusions } from './confidenceResolver';

const STORAGE_KEY_PREFIX = 'mailtrace_forensic_';
const memoryStore = new Map<string, EmailAnalysis>();

export const MOCK_SAMPLE_ANALYSIS: EmailAnalysis = resolveEmailIndicators({
  id: 'sample-001',
  evidence_id: 'EVD-97D4B2E811',
  email_sha256: '97d4b2e811c7520e5e79603f9050d268159b360b9432df03d4083d8e57ef228a',
  original_filename: 'urgent_microsoft_verification.eml',
  upload_timestamp: '2026-09-07T05:12:00Z',
  size: 15420,
  uploader: 'SOC Analyst',
  subject: 'URGENT: Verify your Microsoft Account',
  from: 'Microsoft Security <security@micros0ft-example.com>',
  to: 'employee@company.com',
  cc: '',
  date: 'Sun, 7 Sep 2026 10:42:00 +0530',
  reply_to: 'support@example.net',
  return_path: 'bounce@example.net',
  message_id: '<abc123@example.com>',
  authentication_results: 'mx.company.com; dkim=fail header.i=@company.com; spf=fail (domain of bounce@example.net does not designate 203.0.113.25); dmarc=fail (p=reject)',
  authentication: {
    verification_type: 'observed_header',
    verification_notice: 'Observed authentication result from supplied headers (unverified by local mail server)',
    observed_header: 'mx.company.com; dkim=fail header.i=@company.com; spf=fail (domain of bounce@example.net does not designate 203.0.113.25); dmarc=fail (p=reject)',
    spf: { result: 'fail', details: 'spf=fail (domain of bounce@example.net does not designate 203.0.113.25)' },
    dkim: { result: 'fail', details: 'dkim=fail header.i=@company.com' },
    dmarc: { result: 'fail', details: 'dmarc=fail (p=reject dis=none)' },
    alignment: {
      from_domain: 'micros0ft-example.com',
      reply_to_domain: 'example.net',
      return_path_domain: 'example.net',
      reply_to_mismatch: true,
      return_path_mismatch: true
    }
  },
  received: [
    'from mail.example.net (203.0.113.25) by mx.company.com; Sun, 7 Sep 2026 10:42:01 +0530',
    'from smtp.example.org (198.51.100.12) by mail.example.net; Sun, 7 Sep 2026 10:41:59 +0530'
  ],
  plain_text_body: 'Your Microsoft account requires immediate verification. Please visit the secure link below to update your login credentials.\n\nLink: https://micros0ft-example.com/login\nShortlink: https://bit.ly/3sample-invoice',
  html_body: '<html><body><p>Your Microsoft account requires immediate verification.</p><p>Please update your credentials: <a href="http://evil-tracker.example/login">https://microsoft.com/security</a></p><p>Official link: <a href="https://micros0ft-example.com/login">https://micros0ft-example.com/login</a></p><p>Invoice: <a href="https://bit.ly/3sample-invoice">Invoice Details</a></p></body></html>',
  raw_email: `From: Microsoft Security <security@micros0ft-example.com>
To: employee@company.com
Subject: URGENT: Verify your Microsoft Account
Date: Sun, 7 Sep 2026 10:42:00 +0530
Reply-To: support@example.net
Return-Path: bounce@example.net
Message-ID: <abc123@example.com>
Authentication-Results: spf=fail; dkim=none; dmarc=fail
Received: from mail.example.net (203.0.113.25) by mx.company.com; Sun, 7 Sep 2026 10:42:01 +0530
Received: from smtp.example.org (198.51.100.12) by mail.example.net; Sun, 7 Sep 2026 10:41:59 +0530
Content-Type: multipart/mixed; boundary="BOUNDARY"

--BOUNDARY
Content-Type: text/plain; charset=utf-8

Your Microsoft account requires immediate verification.
Link: https://micros0ft-example.com/login

--BOUNDARY
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"

[PDF Attachment Bytes]
--BOUNDARY--`,
  indicators: {
    ips: [
      { value: '203.0.113.25', version: 4, scope: 'public', source: 'received_header_1' },
      { value: '198.51.100.12', version: 4, scope: 'public', source: 'received_header_2' }
    ],
    domains: [
      { value: 'micros0ft-example.com', source: 'url' },
      { value: 'example.net', source: 'reply_to' },
      { value: 'example.org', source: 'received_header' },
      { value: 'company.com', source: 'to' }
    ],
    urls: [
      { value: 'https://micros0ft-example.com/login', source: 'plain_text_body' },
      { value: 'http://evil-tracker.example/login', source: 'html_a_href' },
      { value: 'https://bit.ly/3sample-invoice', source: 'html_a_href' }
    ],
    email_addresses: [
      { value: 'security@micros0ft-example.com', source: 'header_from' },
      { value: 'employee@company.com', source: 'header_to' },
      { value: 'support@example.net', source: 'header_reply_to' },
      { value: 'bounce@example.net', source: 'header_return_path' }
    ],
    attachments: [
      {
        filename: 'invoice.pdf',
        mime_type: 'application/pdf',
        size: 241000,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        md5: 'd41d8cd98f00b204e9800998ecf8427e',
        sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
      }
    ]
  },
  urls: [
    'https://micros0ft-example.com/login',
    'http://evil-tracker.example/login',
    'https://bit.ly/3sample-invoice'
  ],
  ips: [
    '203.0.113.25',
    '198.51.100.12'
  ],
  domains: [
    'micros0ft-example.com',
    'example.net',
    'example.org',
    'company.com'
  ],
  emails: [
    'security@micros0ft-example.com',
    'employee@company.com',
    'support@example.net',
    'bounce@example.net'
  ],
  attachments: [
    {
      filename: 'invoice.pdf',
      mime_type: 'application/pdf',
      size: 241000,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    }
  ],
  domain_intelligence: {
    'micros0ft-example.com': {
      domain: 'micros0ft-example.com',
      dns: {
        a: ['203.0.113.88'],
        aaaa: [],
        mx: ['10 mail.micros0ft-example.com'],
        ns: ['ns1.shadow-dns.com', 'ns2.shadow-dns.com'],
        txt: ['v=spf1 include:spf.protection.outlook.com -all']
      },
      registration: {
        registrar: 'NameCheap, Inc.',
        registration_date: new Date(Date.now() - 18 * 86400000).toISOString(),
        expiration_date: new Date(Date.now() + 347 * 86400000).toISOString(),
        nameservers: ['ns1.shadow-dns.com', 'ns2.shadow-dns.com'],
        status: ['clientTransferProhibited'],
        registration_source: 'RDAP'
      },
      domain_age_days: 18,
      newly_registered_domain: true,
      is_resolvable: true,
      status_message: 'Active / Resolvable',
      lookalike: {
        domain: 'micros0ft-example.com',
        suspected_brand: 'microsoft.com',
        brand_name: 'Microsoft',
        similarity: 0.91,
        techniques: ['character_substitution', 'brand_keyword'],
        confidence_label: 'Potential brand impersonation',
        details: "Substitutes '0' for 'o' targeting Microsoft brand keyword"
      }
    },
    'company.com': {
      domain: 'company.com',
      dns: {
        a: ['198.51.100.10'],
        aaaa: [],
        mx: ['10 mx.company.com'],
        ns: ['ns1.company.com', 'ns2.company.com'],
        txt: ['v=spf1 ip4:198.51.100.10 -all']
      },
      registration: {
        registrar: 'MarkMonitor Inc.',
        registration_date: '1997-04-15T04:00:00Z',
        expiration_date: '2028-04-15T04:00:00Z',
        nameservers: ['ns1.company.com', 'ns2.company.com'],
        status: ['clientDeleteProhibited', 'clientTransferProhibited'],
        registration_source: 'RDAP'
      },
      domain_age_days: Math.floor((Date.now() - new Date('1997-04-15T04:00:00Z').getTime()) / 86400000),
      newly_registered_domain: false,
      is_resolvable: true,
      status_message: 'Active / Resolvable'
    },
    'example.net': {
      domain: 'example.net',
      dns: {
        a: ['93.184.216.34'],
        aaaa: ['2606:2800:220:1:248:1893:25c8:1946'],
        mx: ['0 .'],
        ns: ['a.iana-servers.net', 'b.iana-servers.net'],
        txt: ['v=spf1 -all']
      },
      registration: {
        registrar: 'Internet Assigned Numbers Authority',
        registration_date: '1995-07-10T04:00:00Z',
        expiration_date: '2027-07-09T04:00:00Z',
        nameservers: ['a.iana-servers.net', 'b.iana-servers.net'],
        status: ['serverDeleteProhibited', 'serverTransferProhibited'],
        registration_source: 'RDAP'
      },
      domain_age_days: Math.floor((Date.now() - new Date('1995-07-10T04:00:00Z').getTime()) / 86400000),
      newly_registered_domain: false,
      is_resolvable: true,
      status_message: 'Active / Resolvable'
    },
    'example.org': {
      domain: 'example.org',
      dns: {
        a: ['93.184.216.34'],
        aaaa: ['2606:2800:220:1:248:1893:25c8:1946'],
        mx: ['0 .'],
        ns: ['a.iana-servers.net', 'b.iana-servers.net'],
        txt: ['v=spf1 -all']
      },
      registration: {
        registrar: 'Internet Assigned Numbers Authority',
        registration_date: '1995-07-10T04:00:00Z',
        expiration_date: '2027-07-09T04:00:00Z',
        nameservers: ['a.iana-servers.net', 'b.iana-servers.net'],
        status: ['serverDeleteProhibited', 'serverTransferProhibited'],
        registration_source: 'RDAP'
      },
      domain_age_days: Math.floor((Date.now() - new Date('1995-07-10T04:00:00Z').getTime()) / 86400000),
      newly_registered_domain: false,
      is_resolvable: true,
      status_message: 'Active / Resolvable'
    }
  },
  ml_phishing_probability: 0.89,
  ml_assessment: {
    classification: 'phishing',
    probability: 0.89,
    confidence: 'high',
    available: true,
    top_features: ['httpurl', 'verify', 'password', 'update', 'account'],
    model_name: 'TF-IDF + Logistic Regression'
  },
  threat_score: {
    score: 82,
    severity: 'critical',
    risk_level: 'CRITICAL',
    confidence: 'VERY HIGH',
    summary: 'Email risk assessed as Critical (82/100) driven by 8 forensic signal(s): Brand impersonation (+18), Credential harvesting (+12), DMARC failure (+12), Link mismatch (+15), NLP phishing classifier (+10).',
    why_flagged: "This email was flagged with a Threat Score of 82/100 (CRITICAL) because it triggered 8 positive threat signal(s) across 6 analytical categories. Key forensic drivers: Potential brand impersonation (+18 pts); HTML link text and destination domain mismatch (+15 pts); DMARC authentication failed (+12 pts); Credential harvesting or urgent security language (+12 pts).",
    top_reasons: [
      'Potential brand impersonation detected (+18 pts)',
      'HTML link text and destination domain mismatch (+15 pts)',
      'DMARC authentication failed (+12 pts)',
      'Credential harvesting or urgent security language (+12 pts)'
    ],
    positive_contributions: [
      {
        signal_id: 'SIG-LOOK-001',
        category: 'lookalike_detection',
        name: 'Potential brand impersonation detected',
        description: "Substitutes '0' for 'o' targeting Microsoft brand keyword (micros0ft-example.com)",
        why_it_matters: 'Adversaries deploy visual lookalike domains to mislead recipients into believing the email originates from a trusted enterprise service provider.',
        raw_value: 'micros0ft-example.com',
        normalized_value: 0.94,
        weight: 18,
        contribution: 18,
        direction: 'increase_risk',
        confidence: 0.95,
        evidence_reference: 'micros0ft-example.com',
        source: 'Lookalike Domain Detector'
      },
      {
        signal_id: 'SIG-URLI-002',
        category: 'url_intelligence',
        name: 'HTML link text and destination domain mismatch',
        description: 'Anchor text displays microsoft.com but hyperlinks to evil-tracker.example',
        why_it_matters: 'Deceptive hyperlinks conceal the real destination server, bypassing human visual inspection and leading victims to phishing landing sites.',
        raw_value: 'evil-tracker.example',
        normalized_value: 1.0,
        weight: 15,
        contribution: 15,
        direction: 'increase_risk',
        confidence: 0.98,
        evidence_reference: 'evil-tracker.example',
        source: 'HTML Body Parser'
      },
      {
        signal_id: 'SIG-AUTH-003',
        category: 'authentication',
        name: 'DMARC authentication failed',
        description: 'DMARC policy evaluation failed: p=reject dis=none',
        why_it_matters: 'Indicates the sending IP lacks cryptographic or envelope authorization from the originating domain owner, a hallmark of sender spoofing.',
        raw_value: 'fail',
        normalized_value: 1.0,
        weight: 12,
        contribution: 12,
        direction: 'increase_risk',
        confidence: 1.0,
        evidence_reference: 'dmarc=fail (p=reject dis=none)',
        source: 'DMARC Alignment Engine'
      },
      {
        signal_id: 'SIG-EMAI-004',
        category: 'email_content',
        name: 'Credential harvesting or urgent security language',
        description: "Detected call-to-action pattern: 'update your login credentials'",
        why_it_matters: 'Social engineering prompts targeting account credentials create artificial urgency to induce hurried compliance before IT verification.',
        raw_value: 'update your login credentials',
        normalized_value: 0.9,
        weight: 12,
        contribution: 12,
        direction: 'increase_risk',
        confidence: 0.88,
        evidence_reference: 'update your login credentials',
        source: 'Content Keyword Risk Scanner'
      },
      {
        signal_id: 'SIG-EMAI-005',
        category: 'email_content',
        name: 'NLP phishing classifier flagged high suspicion',
        description: 'ML text classifier estimated 89% phishing probability based on language and phrasing patterns',
        why_it_matters: 'Statistical text classification corroborates psychological manipulation, deception, and phishing intent across the entire email body.',
        raw_value: 0.89,
        normalized_value: 0.89,
        weight: 10,
        contribution: 10,
        direction: 'increase_risk',
        confidence: 0.89,
        evidence_reference: 'TF-IDF Logistic Regression: 0.89 probability',
        source: 'Content ML Phishing Classifier'
      },
      {
        signal_id: 'SIG-DOMA-006',
        category: 'domain_intelligence',
        name: 'Newly registered domain (< 30 days old)',
        description: 'Domain micros0ft-example.com was registered 18 days ago',
        why_it_matters: 'Young domains lack established reputation and are frequently provisioned exclusively for short-lived phishing and malware campaigns.',
        raw_value: 18,
        normalized_value: 0.4,
        weight: 10,
        contribution: 10,
        direction: 'increase_risk',
        confidence: 0.92,
        evidence_reference: 'micros0ft-example.com (18 days old)',
        source: 'Domain Intelligence Subsystem'
      },
      {
        signal_id: 'SIG-AUTH-007',
        category: 'authentication',
        name: 'SPF authentication failed',
        description: 'SPF check failed: sending IP 203.0.113.25 is not authorized by bounce@example.net SPF record',
        why_it_matters: 'Permits unauthorized mail transfer agents to transmit messages purporting to originate from domains they do not control.',
        raw_value: 'fail',
        normalized_value: 1.0,
        weight: 8,
        contribution: 8,
        direction: 'increase_risk',
        confidence: 1.0,
        evidence_reference: 'spf=fail (IP 203.0.113.25 unauthorized)',
        source: 'Email Authentication Subsystem'
      },
      {
        signal_id: 'SIG-AUTH-008',
        category: 'authentication',
        name: 'DKIM signature verification failed',
        description: 'DKIM signature verification failed: header.i=@company.com',
        why_it_matters: 'Cryptographic tampering or absence of valid domain signing confirms the body or headers were altered in transit or unsigned.',
        raw_value: 'fail',
        normalized_value: 1.0,
        weight: 8,
        contribution: 8,
        direction: 'increase_risk',
        confidence: 1.0,
        evidence_reference: 'dkim=fail header.i=@company.com',
        source: 'Cryptographic Signature Validator'
      }
    ],
    negative_contributions: [
      {
        signal_id: 'SIG-MIT-001',
        category: 'domain_intelligence',
        name: 'Established Secondary Domain',
        description: 'example.org is 11,000+ days old and well-established',
        why_it_matters: 'Longstanding domains have verified operational history and lower probability of throwaway infrastructure abuse.',
        raw_value: 11000,
        normalized_value: 0.0,
        weight: -5,
        contribution: -5,
        direction: 'decrease_risk',
        confidence: 0.95,
        evidence_reference: 'example.org (11,000+ days old)',
        source: 'Domain Intelligence Subsystem'
      },
      {
        signal_id: 'SIG-MIT-002',
        category: 'attachments',
        name: 'Safe Non-Executable Attachments',
        description: 'No executable binaries or macro-enabled documents detected in attachment inventory',
        why_it_matters: 'Eliminates immediate endpoint binary execution risk from primary delivery payloads.',
        raw_value: 'clean_attachments',
        normalized_value: 0.0,
        weight: 0,
        contribution: 0,
        direction: 'decrease_risk',
        confidence: 0.9,
        evidence_reference: 'Attachment inventory verified',
        source: 'Attachment Risk Inspector'
      }
    ],
    category_breakdowns: {
      authentication: {
        category: 'authentication',
        display_name: 'Authentication Risk',
        risk_score: 28,
        positive_signals_count: 3,
        mitigating_signals_count: 0,
        signals: []
      },
      sender_identity: {
        category: 'sender_identity',
        display_name: 'Sender Identity Risk',
        risk_score: 0,
        positive_signals_count: 0,
        mitigating_signals_count: 0,
        signals: []
      },
      domain_intelligence: {
        category: 'domain_intelligence',
        display_name: 'Domain Risk',
        risk_score: 5,
        positive_signals_count: 1,
        mitigating_signals_count: 1,
        signals: []
      },
      lookalike_detection: {
        category: 'lookalike_detection',
        display_name: 'Lookalike Risk',
        risk_score: 18,
        positive_signals_count: 1,
        mitigating_signals_count: 0,
        signals: []
      },
      url_intelligence: {
        category: 'url_intelligence',
        display_name: 'URL Risk',
        risk_score: 15,
        positive_signals_count: 1,
        mitigating_signals_count: 0,
        signals: []
      },
      infrastructure: {
        category: 'infrastructure',
        display_name: 'Infrastructure Risk',
        risk_score: 0,
        positive_signals_count: 0,
        mitigating_signals_count: 0,
        signals: []
      },
      email_content: {
        category: 'email_content',
        display_name: 'Content Risk',
        risk_score: 22,
        positive_signals_count: 2,
        mitigating_signals_count: 0,
        signals: []
      },
      campaign_intelligence: {
        category: 'campaign_intelligence',
        display_name: 'Campaign Risk',
        risk_score: 0,
        positive_signals_count: 0,
        mitigating_signals_count: 0,
        signals: []
      },
      attachments: {
        category: 'attachments',
        display_name: 'Attachment Risk',
        risk_score: 0,
        positive_signals_count: 0,
        mitigating_signals_count: 1,
        signals: []
      }
    },
    reasons: [
      {
        signal: 'brand_impersonation',
        label: 'Potential brand impersonation detected',
        points: 18,
        evidence: "Substitutes '0' for 'o' targeting Microsoft brand keyword"
      },
      {
        signal: 'html_link_mismatch',
        label: 'HTML link text and destination domain mismatch',
        points: 15,
        evidence: 'Text shows microsoft.com but links to evil-tracker.example'
      },
      {
        signal: 'dmarc_fail',
        label: 'DMARC authentication failed',
        points: 12,
        evidence: 'dmarc=fail (p=reject dis=none)'
      },
      {
        signal: 'credential_request',
        label: 'Credential harvesting or urgent security language',
        points: 12,
        evidence: "Detected pattern: 'update your login credentials'"
      },
      {
        signal: 'ml_phishing_signal',
        label: 'NLP phishing classifier flagged high suspicion',
        points: 10,
        evidence: 'ML text classifier estimated 89% phishing probability based on language and phrasing patterns'
      },
      {
        signal: 'newly_registered_domain',
        label: 'Newly registered domain (< 30 days old)',
        points: 10,
        evidence: 'micros0ft-example.com registered 18 days ago'
      },
      {
        signal: 'spf_fail',
        label: 'SPF authentication failed',
        points: 8,
        evidence: 'spf=fail (domain of bounce@example.net does not designate 203.0.113.25)'
      },
      {
        signal: 'dkim_fail',
        label: 'DKIM signature verification failed',
        points: 8,
        evidence: 'dkim=fail header.i=@company.com'
      }
    ],
    positive_evidence: [],
    model_version: 'v1.0-tfidf-logistic',
    scoring_version: '2.0.0-explainable',
    audit_metadata: {
      scoring_version: '2.0.0-explainable',
      weights_snapshot: {
        brand_impersonation: 18,
        html_link_mismatch: 15,
        dmarc_fail: 12,
        credential_request: 12,
        ml_phishing_signal: 10,
        newly_registered_domain: 10,
        spf_fail: 8,
        dkim_fail: 8,
        trusted_sender_history: -5
      },
      thresholds_snapshot: {
        low: { min: 0, max: 24 },
        suspicious: { min: 25, max: 49 },
        high: { min: 50, max: 74 },
        critical: { min: 75, max: 100 }
      },
      timestamp: '2026-09-10T19:25:00Z',
      evidence_ids: [
        'SIG-LOOK-001',
        'SIG-URLI-002',
        'SIG-AUTH-003',
        'SIG-EMAI-004',
        'SIG-EMAI-005',
        'SIG-DOMA-006',
        'SIG-AUTH-007',
        'SIG-AUTH-008'
      ],
      model_version: 'v1.0-tfidf-logistic'
    }
  },
  ai_analyst: {
    summary: "Suspicious message exhibiting critical credential-harvesting indicators with severe sender spoofing, including failed DMARC and SPF checks alongside a deceptive lookalike domain.",
    likely_attack_type: "Credential Harvesting / Brand Impersonation Spear-Phishing",
    likely_objective: "Exfiltrate corporate Microsoft credentials via disguised credential-collection landing pages.",
    key_evidence: [
      "Failed DMARC (p=reject) and SPF authentication from sending IP 203.0.113.25",
      "Lookalike domain micros0ft-example.com imitating Microsoft (registered 18 days ago)",
      "HTML display anchor showing microsoft.com while pointing to evil-tracker.example",
      "NLP Phishing Classifier flagged high confidence (89% probability) for credential harvesting language",
      "Suspicious embedded shortened link (bit.ly/3sample-invoice)"
    ],
    recommended_actions: [
      "Block sending IP 203.0.113.25 and domain micros0ft-example.com on perimeter email gateway",
      "Revoke active sessions and force password resets for any recipient who accessed the link",
      "Search SIEM proxy/DNS telemetry for outbound HTTP requests to evil-tracker.example and bit.ly/3sample-invoice",
      "Purge matching message IDs from all internal Exchange/M365 mailboxes"
    ],
    limitations: [
      "Assessment is strictly derived from observed telemetry and headers; no dynamic sandbox detonation was executed on external URLs.",
      "Threat actor infrastructure may rotate dynamically across unobserved IP ranges."
    ],
    model_name: "Grounded Forensic Assistant (Local / Abstracted)",
    provider: "local-mock",
    available: true
  },
  attribution: {
    attribution_id: 'ATTR-97D4B2E8',
    email_id: 'sample-001',
    probable_origin_ip: '203.0.113.25',
    probable_origin_asn: 'AS64512',
    probable_origin_provider: 'Threat Hosting Corp',
    probable_infrastructure_country: 'United States',
    confidence_score: 78.0,
    confidence_level: 'HIGH',
    supporting_evidence: [
      {
        evidence_type: 'EARLIEST_UNTRUSTED_RELAY',
        observation: 'Earliest untrusted public sending infrastructure identified at IP 203.0.113.25 (mail.example.net).',
        contribution: 20.0,
        source: 'SMTP Relay Path Analysis',
        timestamp: '2026-09-07T05:12:01Z'
      },
      {
        evidence_type: 'DOMAIN_HOSTING_RELATIONSHIP',
        observation: "Suspicious domain 'micros0ft-example.com' directly resolves (A record) to probable sending IP 203.0.113.25.",
        contribution: 15.0,
        source: 'DNS Resolution Engine',
        timestamp: '2026-09-07T05:12:01Z'
      },
      {
        evidence_type: 'AUTHENTICATION_FAILURE_ALIGNMENT',
        observation: "SPF/DMARC authentication failed for sender 'micros0ft-example.com' from IP 203.0.113.25, indicating unauthorized sending infrastructure.",
        contribution: 10.0,
        source: 'Email Authentication Subsystem',
        timestamp: '2026-09-07T05:12:01Z'
      },
      {
        evidence_type: 'LOOKALIKE_INFRASTRUCTURE_OVERLAP',
        observation: "Brand lookalike domain 'micros0ft-example.com' shares hosting infrastructure (AS64512) with observed sending system.",
        contribution: 10.0,
        source: 'Lookalike Detection Engine',
        timestamp: '2026-09-07T05:12:01Z'
      },
      {
        evidence_type: 'HOSTING_PROVIDER_CONSISTENCY',
        observation: 'Probable origin IP 203.0.113.25 operates within cloud/datacenter hosting infrastructure (Threat Hosting Corp).',
        contribution: 10.0,
        source: 'IP Intelligence Infrastructure Classification',
        timestamp: '2026-09-07T05:12:01Z'
      }
    ],
    conflicting_evidence: [
      {
        evidence_type: 'ANONYMIZATION_INFRASTRUCTURE_DETECTED',
        observation: 'Sending infrastructure IP 203.0.113.25 is an identified anonymization proxy, VPN, or Tor exit node. Attribution points to proxy egress infrastructure rather than threat actor origin.',
        contribution: -20.0,
        source: 'IP Threat Intelligence',
        timestamp: '2026-09-07T05:12:01Z'
      }
    ],
    related_domains: ['micros0ft-example.com', 'example.net'],
    related_ips: ['203.0.113.25', '198.51.100.12'],
    related_campaigns: ['CASE-2026-000031'],
    analysis_timestamp: '2026-09-07T05:12:00Z',
    disclaimer: 'Location refers to observed network infrastructure and should not be interpreted as the physical location of the threat actor.'
  },
  investigation_graph: {
    nodes: [
      {
        id: 'email:sample-001',
        type: 'Email',
        label: 'Email: Urgent: Update Your Microsoft Account',
        metadata: { subject: 'Urgent: Update Your Microsoft Account', threat_score: 82, severity: 'critical', date: '2026-09-07T12:00:00Z' }
      },
      {
        id: 'email_addr:security@micros0ft-example.com',
        type: 'Email Address',
        label: 'security@micros0ft-example.com',
        metadata: { role: 'sender' }
      },
      {
        id: 'email_addr:employee@company.com',
        type: 'Email Address',
        label: 'employee@company.com',
        metadata: { role: 'recipient' }
      },
      {
        id: 'domain:micros0ft-example.com',
        type: 'Domain',
        label: 'micros0ft-example.com',
        metadata: {
          domain: 'micros0ft-example.com',
          is_lookalike: true,
          suspected_brand: 'microsoft.com',
          similarity: 0.91,
          domain_age_days: 18,
          newly_registered: true,
          registrar: 'NameCheap, Inc.'
        }
      },
      {
        id: 'domain:company.com',
        type: 'Domain',
        label: 'company.com',
        metadata: { domain: 'company.com', domain_age_days: 8700, newly_registered: false, registrar: 'Network Solutions' }
      },
      {
        id: 'domain:evil-tracker.example',
        type: 'Domain',
        label: 'evil-tracker.example',
        metadata: { domain: 'evil-tracker.example', newly_registered: true }
      },
      {
        id: 'domain:bit.ly',
        type: 'Domain',
        label: 'bit.ly',
        metadata: { domain: 'bit.ly', status_message: 'Shortener Service' }
      },
      {
        id: 'url:evil-tracker',
        type: 'URL',
        label: 'URL: hxxps://evil-tracker[.]example/track',
        metadata: {
          url: 'https://evil-tracker.example/track?id=987',
          defanged_url: 'hxxps://evil-tracker[.]example/track?id=987',
          suspicion_level: 'high',
          score_reasons: ['Destination domain mismatch with anchor text']
        }
      },
      {
        id: 'url:bitly-invoice',
        type: 'URL',
        label: 'URL: hxxps://bit[.]ly/3sample-invoice',
        metadata: {
          url: 'https://bit.ly/3sample-invoice',
          defanged_url: 'hxxps://bit[.]ly/3sample-invoice',
          suspicion_level: 'suspicious',
          score_reasons: ['Shortened link masking destination']
        }
      },
      {
        id: 'ip:203.0.113.25',
        type: 'IP',
        label: '203.0.113.25',
        metadata: { ip: '203.0.113.25', country: 'US', asn: 'AS64512', org: 'Threat Hosting Corp', is_proxy_vpn_tor: true }
      },
      {
        id: 'ip:198.51.100.12',
        type: 'IP',
        label: '198.51.100.12',
        metadata: { ip: '198.51.100.12', country: 'DE', asn: 'AS24940', org: 'Hetzner Online GmbH', is_proxy_vpn_tor: false }
      },
      {
        id: 'asn:AS64512',
        type: 'ASN',
        label: 'AS64512 (Threat Hosting)',
        metadata: { asn: 'AS64512', org: 'Threat Hosting Corp', country: 'US' }
      },
      {
        id: 'asn:AS24940',
        type: 'ASN',
        label: 'AS24940 (Hetzner Online)',
        metadata: { asn: 'AS24940', org: 'Hetzner Online GmbH', country: 'DE' }
      },
      {
        id: 'attachment:invoice-pdf',
        type: 'Attachment',
        label: 'invoice.pdf',
        metadata: { filename: 'invoice.pdf', mime_type: 'application/pdf', size_bytes: 241000, sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' }
      },
      {
        id: 'country:united_states',
        type: 'Country',
        label: 'United States',
        metadata: { country: 'United States', disclaimer: 'Location refers to observed network infrastructure' }
      }
    ],
    edges: [
      { id: 'edge:email:sample-001->ORIGIN_INFRASTRUCTURE->ip:203.0.113.25', source: 'email:sample-001', target: 'ip:203.0.113.25', label: 'ORIGIN_INFRASTRUCTURE' },
      { id: 'edge:ip:203.0.113.25->HOSTED_IN_COUNTRY->country:united_states', source: 'ip:203.0.113.25', target: 'country:united_states', label: 'HOSTED_IN_COUNTRY' },
      { id: 'edge:email:sample-001->SENT_FROM->email_addr:security@micros0ft-example.com', source: 'email:sample-001', target: 'email_addr:security@micros0ft-example.com', label: 'SENT_FROM' },
      { id: 'edge:email:sample-001->SENT_TO->email_addr:employee@company.com', source: 'email:sample-001', target: 'email_addr:employee@company.com', label: 'SENT_TO' },
      { id: 'edge:email_addr:security@micros0ft-example.com->BELONGS_TO_DOMAIN->domain:micros0ft-example.com', source: 'email_addr:security@micros0ft-example.com', target: 'domain:micros0ft-example.com', label: 'BELONGS_TO_DOMAIN' },
      { id: 'edge:email_addr:employee@company.com->BELONGS_TO_DOMAIN->domain:company.com', source: 'email_addr:employee@company.com', target: 'domain:company.com', label: 'BELONGS_TO_DOMAIN' },
      { id: 'edge:email:sample-001->CONTAINS_URL->url:evil-tracker', source: 'email:sample-001', target: 'url:evil-tracker', label: 'CONTAINS_URL' },
      { id: 'edge:email:sample-001->CONTAINS_URL->url:bitly-invoice', source: 'email:sample-001', target: 'url:bitly-invoice', label: 'CONTAINS_URL' },
      { id: 'edge:url:evil-tracker->RESOLVES_TO_DOMAIN->domain:evil-tracker.example', source: 'url:evil-tracker', target: 'domain:evil-tracker.example', label: 'RESOLVES_TO_DOMAIN' },
      { id: 'edge:url:bitly-invoice->RESOLVES_TO_DOMAIN->domain:bit.ly', source: 'url:bitly-invoice', target: 'domain:bit.ly', label: 'RESOLVES_TO_DOMAIN' },
      { id: 'edge:domain:micros0ft-example.com->RESOLVES_TO_IP->ip:203.0.113.25', source: 'domain:micros0ft-example.com', target: 'ip:203.0.113.25', label: 'RESOLVES_TO_IP' },
      { id: 'edge:email:sample-001->ROUTED_THROUGH->ip:203.0.113.25', source: 'email:sample-001', target: 'ip:203.0.113.25', label: 'ROUTED_THROUGH' },
      { id: 'edge:email:sample-001->ROUTED_THROUGH->ip:198.51.100.12', source: 'email:sample-001', target: 'ip:198.51.100.12', label: 'ROUTED_THROUGH' },
      { id: 'edge:ip:203.0.113.25->BELONGS_TO_ASN->asn:AS64512', source: 'ip:203.0.113.25', target: 'asn:AS64512', label: 'BELONGS_TO_ASN' },
      { id: 'edge:ip:198.51.100.12->BELONGS_TO_ASN->asn:AS24940', source: 'ip:198.51.100.12', target: 'asn:AS24940', label: 'BELONGS_TO_ASN' },
      { id: 'edge:email:sample-001->HAS_ATTACHMENT->attachment:invoice-pdf', source: 'email:sample-001', target: 'attachment:invoice-pdf', label: 'HAS_ATTACHMENT' }
    ],
    summary: {
      total_nodes: 14,
      total_edges: 14,
      node_type_counts: {
        'Email': 1,
        'Email Address': 2,
        'Domain': 4,
        'URL': 2,
        'IP': 2,
        'ASN': 2,
        'Attachment': 1
      },
      has_high_risk_entities: true
    }
  }
});

export const saveAnalysisResult = (id: string, data: EmailAnalysis): void => {
  const resolved = resolveEmailIndicators({ ...data, id });
  memoryStore.set(id, resolved);
  try {
    sessionStorage.setItem(STORAGE_KEY_PREFIX + id, JSON.stringify(resolved));
  } catch (e) {
    console.warn('Unable to persist analysis in sessionStorage', e);
  }
};

export const getAnalysisResult = (id: string): EmailAnalysis | null => {
  if (memoryStore.has(id)) {
    const item = resolveEmailIndicators(memoryStore.get(id)!);
    if (!item.attribution || !item.attribution.probable_origin_ip) {
      item.attribution = resolveAttribution(item);
    }
    if (!item.forensic_conclusions || item.forensic_conclusions.length === 0) {
      item.forensic_conclusions = resolveConfidenceConclusions(item);
    }
    return item;
  }
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY_PREFIX + id);
    if (raw) {
      const parsed = JSON.parse(raw);
      const resolved = resolveEmailIndicators(parsed);
      if (!resolved.attribution || !resolved.attribution.probable_origin_ip) {
        resolved.attribution = resolveAttribution(resolved);
      }
      if (!resolved.forensic_conclusions || resolved.forensic_conclusions.length === 0) {
        resolved.forensic_conclusions = resolveConfidenceConclusions(resolved);
      }
      memoryStore.set(id, resolved);
      return resolved;
    }
  } catch (e) {
    console.warn('Error reading analysis from sessionStorage', e);
  }

  if (id === 'sample-001' || id === 'latest' || id === 'demo') {
    if (!MOCK_SAMPLE_ANALYSIS.attribution || !MOCK_SAMPLE_ANALYSIS.attribution.probable_origin_ip) {
      MOCK_SAMPLE_ANALYSIS.attribution = resolveAttribution(MOCK_SAMPLE_ANALYSIS);
    }
    if (!MOCK_SAMPLE_ANALYSIS.forensic_conclusions || MOCK_SAMPLE_ANALYSIS.forensic_conclusions.length === 0) {
      MOCK_SAMPLE_ANALYSIS.forensic_conclusions = resolveConfidenceConclusions(MOCK_SAMPLE_ANALYSIS);
    }
    return MOCK_SAMPLE_ANALYSIS;
  }

  return null;
};
