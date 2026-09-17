/**
 * SIH Safe Synthetic Demo Scenarios for MailTraceAI.
 * Guaranteed isolated from production database and real threat intelligence.
 * All infrastructure strictly uses RFC 2606 (.example, .test) and RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
 */
import type { EmailAnalysis } from '../types/forensic';

export const SCENARIO_1_LEGITIMATE: EmailAnalysis = {
  id: 'scenario-1-legit',
  evidence_id: 'EVD-LEGIT-001',
  email_sha256: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
  original_filename: 'q3_financial_audit_engagement.eml',
  upload_timestamp: '2026-09-17T09:15:00Z',
  size: 18450,
  uploader: 'SOC Lead Analyst',
  subject: 'Q3 Financial Audit Engagement & Status Report - Acme Global',
  from: 'Audits Team <audit-status@acme-global.example>',
  to: 'finance-director@enterprise-corp.example',
  date: 'Thu, 17 Sep 2026 09:14:00 +0000',
  reply_to: 'audit-status@acme-global.example',
  return_path: 'bounces@acme-global.example',
  message_id: '<audit-20260917-091400@acme-global.example>',
  authentication_results: 'mx.enterprise-corp.example; spf=pass (acme-global.example: 192.0.2.14 designates permitted sender); dkim=pass header.d=acme-global.example; dmarc=pass (p=reject)',
  authentication: {
    verification_type: 'independent_validation',
    verification_notice: 'Authentication protocols verified successfully against authoritative DNS records.',
    observed_header: 'spf=pass dkim=pass dmarc=pass',
    spf: { result: 'pass', details: 'Client IP 192.0.2.14 explicitly authorized in TXT v=spf1 include:_spf.acme-global.example ~all' },
    dkim: { result: 'pass', details: 'RSA-SHA256 signature verified over headers and body hash (selector=s2026, d=acme-global.example)' },
    dmarc: { result: 'pass', details: 'DMARC alignment verified (p=reject, pct=100). Header From matches DKIM domain.' },
    alignment: {
      from_domain: 'acme-global.example',
      reply_to_domain: 'acme-global.example',
      return_path_domain: 'acme-global.example',
      reply_to_mismatch: false,
      return_path_mismatch: false
    }
  },
  received: [
    'from mail-relay-01.acme-global.example (192.0.2.14) by mx.enterprise-corp.example (192.0.2.200); Thu, 17 Sep 2026 09:14:15 +0000',
    'from audit-node.internal.corp (192.0.2.10) by mail-relay-01.acme-global.example; Thu, 17 Sep 2026 09:14:02 +0000'
  ],
  hops: [
    {
      hop: 1,
      fromHost: 'audit-node.internal.corp',
      fromIp: '192.0.2.10',
      byHost: 'mail-relay-01.acme-global.example',
      byIp: '192.0.2.14',
      timestamp: '2026-09-17T09:14:02Z',
      delaySeconds: 13,
      authStatus: 'pass',
      isPublicIp: true,
      asn: 'AS64500 (Acme Corporate Telecom)'
    },
    {
      hop: 2,
      fromHost: 'mail-relay-01.acme-global.example',
      fromIp: '192.0.2.14',
      byHost: 'mx.enterprise-corp.example',
      byIp: '192.0.2.200',
      timestamp: '2026-09-17T09:14:15Z',
      delaySeconds: 0,
      authStatus: 'pass',
      isPublicIp: true,
      asn: 'AS64501 (Enterprise Transit)'
    }
  ],
  plain_text_body: 'Dear Finance Team,\n\nPlease find attached the scheduled Q3 financial audit engagement status overview.\nAll milestone timelines remain on schedule.\n\nBest regards,\nAudit & Advisory Services\nAcme Global Consulting',
  html_body: '<html><body><p>Dear Finance Team,</p><p>Please find attached the scheduled Q3 financial audit engagement status overview.</p><p>All milestone timelines remain on schedule.</p><p>Best regards,<br/>Audit & Advisory Services<br/>Acme Global Consulting</p></body></html>',
  raw_email: 'From: Audits Team <audit-status@acme-global.example>\nTo: finance-director@enterprise-corp.example\nSubject: Q3 Financial Audit Engagement & Status Report - Acme Global\nDate: Thu, 17 Sep 2026 09:14:00 +0000\nMessage-ID: <audit-20260917-091400@acme-global.example>\nContent-Type: multipart/mixed\n\n[Legitimate business correspondence and clean PDF attachment]',
  indicators: {
    ips: [
      { value: '192.0.2.14', scope: 'public', source: 'received_hop_1' },
      { value: '192.0.2.200', scope: 'public', source: 'received_hop_2' }
    ],
    domains: [
      { value: 'acme-global.example', source: 'header_from' },
      { value: 'enterprise-corp.example', source: 'header_to' }
    ],
    urls: [],
    email_addresses: [
      { value: 'audit-status@acme-global.example', source: 'header_from' },
      { value: 'finance-director@enterprise-corp.example', source: 'header_to' }
    ],
    attachments: [
      {
        filename: 'Q3_Audit_Engagement_Overview.pdf',
        mime_type: 'application/pdf',
        size: 384000,
        sha256: '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7',
        md5: '8b1a9953c4611296a827abf8c47804d7',
        sha1: '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed',
        static_analysis: {
          original_filename: 'Q3_Audit_Engagement_Overview.pdf',
          file_name: 'Q3_Audit_Engagement_Overview.pdf',
          file_size: 384000,
          claimed_extension: '.pdf',
          claimed_mime: 'application/pdf',
          detected_type: 'PDF document',
          magic_bytes: '25 50 44 46 2d 31 2e 37',
          extension_mismatch: false,
          double_extension: false,
          sha256: '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca7',
          md5: '8b1a9953c4611296a827abf8c47804d7',
          sha1: '2aae6c35c94fcfb415dbe95f408b9ce91ee846ed',
          is_executable: false,
          contains_macros: false,
          entropy: 4.82,
          mismatch_detected: false,
          pdf_metadata: {
            is_pdf: true,
            pdf_version: '1.7',
            page_count: 8,
            has_javascript: false,
            has_embedded_files: false,
            has_launch_actions: false,
            has_uri_actions: false,
            suspicious_elements: []
          }
        } as any
      }
    ]
  },
  threat_score: {
    score: 8,
    severity: 'low',
    risk_level: 'LOW',
    confidence: 'HIGH',
    summary: 'Legitimate business correspondence with full cryptographic authentication pass and clean document payload.',
    top_reasons: [
      'SPF, DKIM, and DMARC authentication all passed with full domain alignment',
      'Sender domain has established reputation with zero lookalike patterns',
      'Clean PDF attachment with no executable bytecode or active scripts'
    ],
    reasons: [
      {
        signal: 'SIG-AUTH-PASS',
        label: 'Cryptographic Auth Pass',
        points: -15,
        evidence: 'SPF, DKIM, and DMARC authentication all passed with full domain alignment'
      }
    ],
    positive_evidence: [
      {
        signal: 'SIG-MIT-001',
        label: 'Cryptographic Auth Pass (SPF, DKIM, DMARC)',
        evidence: 'Complete SPF, DKIM, and DMARC alignment verified'
      },
      {
        signal: 'SIG-MIT-002',
        label: 'Clean PDF Attachment Verified',
        evidence: 'No active macros, embedded binaries, or JavaScript'
      }
    ]
  } as any,
  attribution: {
    probable_origin_ip: '192.0.2.14',
    origin_country: 'Netherlands',
    origin_asn: 'AS64500',
    origin_isp: 'Acme Corporate Network',
    confidence: 0.95
  } as any,
  ip_intelligence: {
    '192.0.2.14': {
      ip: '192.0.2.14',
      scope: 'public',
      enrichment_available: true,
      country: 'Netherlands',
      country_code: 'NL',
      region: 'North Holland',
      city: 'Amsterdam',
      latitude: 52.3702,
      longitude: 4.8952,
      timezone: 'Europe/Amsterdam',
      asn: 'AS64500',
      asn_org: 'Acme Corporate Telecom',
      isp: 'Acme Corporate Network',
      organization: 'Acme Global Consulting',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    },
    '192.0.2.200': {
      ip: '192.0.2.200',
      scope: 'public',
      enrichment_available: true,
      country: 'United Kingdom',
      country_code: 'GB',
      region: 'England',
      city: 'London',
      latitude: 51.5074,
      longitude: -0.1278,
      timezone: 'Europe/London',
      asn: 'AS64501',
      asn_org: 'Enterprise Transit',
      isp: 'Enterprise Gateway Services',
      organization: 'Enterprise Corp MX',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    }
  }
};

export const SCENARIO_2_PHISHING: EmailAnalysis = {
  id: 'scenario-2-phish',
  evidence_id: 'EVD-PHISH-002',
  email_sha256: 'b2c3d4e5f6a17890123456789abcdef0123456789abcdef0123456789abcdef0',
  original_filename: 'm365_suspension_action_required.eml',
  upload_timestamp: '2026-09-17T09:30:00Z',
  size: 21400,
  uploader: 'SOC Analyst Tier 1',
  subject: 'CRITICAL ACTION REQUIRED: Microsoft 365 Tenant Suspension Notice',
  from: 'Microsoft Security Center <security-update@micros0ft-support.example>',
  to: 'admin@enterprise-corp.example',
  date: 'Thu, 17 Sep 2026 09:28:00 +0000',
  reply_to: 'collector@credential-dropzone.example',
  return_path: 'bounce@unverified-relay.example',
  message_id: '<m365-urgent-alert-99124@micros0ft-support.example>',
  authentication_results: 'mx.enterprise-corp.example; spf=fail (domain of bounce@unverified-relay.example does not designate 198.51.100.77); dkim=fail; dmarc=fail (p=reject)',
  authentication: {
    verification_type: 'independent_validation',
    verification_notice: 'Severe authentication anomalies detected. Domain impersonation and SPF/DKIM validation failures.',
    observed_header: 'spf=fail dkim=fail dmarc=fail',
    spf: { result: 'fail', details: 'Originating IP 198.51.100.77 is unauthorized by sender domain policy' },
    dkim: { result: 'fail', details: 'Digital signature invalid; header integrity mismatch' },
    dmarc: { result: 'fail', details: 'DMARC alignment failed (p=reject). From domain does not align with return-path.' },
    alignment: {
      from_domain: 'micros0ft-support.example',
      reply_to_domain: 'credential-dropzone.example',
      return_path_domain: 'unverified-relay.example',
      reply_to_mismatch: true,
      return_path_mismatch: true
    }
  },
  received: [
    'from phish-node-04.example (198.51.100.77) by mx.enterprise-corp.example (192.0.2.200); Thu, 17 Sep 2026 09:28:12 +0000',
    'from unknown-attacker-host.test (198.51.100.22) by phish-node-04.example; Thu, 17 Sep 2026 09:28:01 +0000'
  ],
  hops: [
    {
      hop: 1,
      fromHost: 'unknown-attacker-host.test',
      fromIp: '198.51.100.22',
      byHost: 'phish-node-04.example',
      byIp: '198.51.100.77',
      timestamp: '2026-09-17T09:28:01Z',
      delaySeconds: 11,
      authStatus: 'fail',
      isPublicIp: true,
      asn: 'AS64511 (Bulletproof Hosters Ltd)'
    },
    {
      hop: 2,
      fromHost: 'phish-node-04.example',
      fromIp: '198.51.100.77',
      byHost: 'mx.enterprise-corp.example',
      byIp: '192.0.2.200',
      timestamp: '2026-09-17T09:28:12Z',
      delaySeconds: 0,
      authStatus: 'fail',
      isPublicIp: true,
      asn: 'AS64501 (Enterprise Transit)'
    }
  ],
  plain_text_body: 'Your organization Microsoft 365 cloud subscription has experienced a security exception. Your tenant will be locked within 2 hours. Review the attached Mandatory Compliance Review document immediately to restore enterprise access: https://login.micros0ft-support.example/auth-portal?tenant=9912',
  html_body: '<html><body><h2 style="color:red;">CRITICAL ACTION REQUIRED</h2><p>Your Microsoft 365 tenant has been flagged for non-compliance.</p><p><a href="http://login.micros0ft-support.example/auth-portal?tenant=9912">Click here to re-authenticate immediately</a></p></body></html>',
  raw_email: 'From: Microsoft Security Center <security-update@micros0ft-support.example>\nTo: admin@enterprise-corp.example\nSubject: CRITICAL ACTION REQUIRED: Microsoft 365 Tenant Suspension Notice\n\n[Malicious credential harvesting payload and disguised double-extension executable]',
  indicators: {
    ips: [
      { value: '198.51.100.77', scope: 'public', source: 'received_hop_1' },
      { value: '198.51.100.22', scope: 'public', source: 'received_hop_2' }
    ],
    domains: [
      { value: 'micros0ft-support.example', source: 'header_from' },
      { value: 'credential-dropzone.example', source: 'reply_to' },
      { value: 'unverified-relay.example', source: 'return_path' }
    ],
    urls: [
      { value: 'https://login.micros0ft-support.example/auth-portal?tenant=9912', source: 'plain_text_body' }
    ],
    email_addresses: [
      { value: 'security-update@micros0ft-support.example', source: 'header_from' },
      { value: 'collector@credential-dropzone.example', source: 'reply_to' }
    ],
    attachments: [
      {
        filename: 'Mandatory_Compliance_Review.pdf.exe',
        mime_type: 'application/x-dosexec',
        size: 198400,
        sha256: 'c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef0',
        md5: '7d2a8843c3511195a816abf7c36703c6',
        sha1: '3bbe7d24c83fcea314cbe84f3f7a8bd80dd735dc',
        static_analysis: {
          original_filename: 'Mandatory_Compliance_Review.pdf.exe',
          file_name: 'Mandatory_Compliance_Review.pdf.exe',
          file_size: 198400,
          claimed_extension: '.pdf',
          claimed_mime: 'application/pdf',
          detected_type: 'Windows PE32 Executable',
          magic_bytes: '4d 5a 90 00 03 00 00 00',
          extension_mismatch: true,
          double_extension: true,
          sha256: 'c3d4e5f6a1b27890123456789abcdef0123456789abcdef0123456789abcdef0',
          md5: '7d2a8843c3511195a816abf7c36703c6',
          sha1: '3bbe7d24c83fcea314cbe84f3f7a8bd80dd735dc',
          is_executable: true,
          contains_macros: false,
          entropy: 7.85,
          mismatch_detected: true,
          pe_metadata: {
            is_pe: true,
            architecture: 'x86_64',
            compile_timestamp: '2026-09-15T02:11:00Z',
            number_of_sections: 5,
            is_dll: false,
            is_driver: false,
            signature_status: 'Unsigned'
          }
        } as any
      }
    ]
  },
  threat_score: {
    score: 88,
    severity: 'critical',
    risk_level: 'CRITICAL',
    confidence: 'VERY HIGH',
    summary: 'High-severity credential phishing attack with lookalike domain impersonation, SPF/DKIM/DMARC failure, and disguised executable payload.',
    top_reasons: [
      'Disguised executable payload with double-extension evasion (.pdf.exe) (+30 pts)',
      'Lookalike brand impersonation: micros0ft-support.example targeting Microsoft (+25 pts)',
      'SPF, DKIM, and DMARC authentication all failed with spoofed envelope (+20 pts)',
      'Reply-To destination mismatch pointing to external dropzone domain (+8 pts)',
      'High-entropy packed binary payload (7.85/8.00) (+5 pts)'
    ],
    reasons: [
      {
        signal: 'SIG-EXEC',
        label: 'Disguised Executable Payload',
        points: 30,
        evidence: 'Mandatory_Compliance_Review.pdf.exe detected as Windows PE32'
      }
    ],
    positive_evidence: []
  } as any,
  attribution: {
    probable_origin_ip: '198.51.100.77',
    origin_country: 'Observed Infrastructure (Reserved)',
    origin_asn: 'AS64511',
    origin_isp: 'Bulletproof Threat Transit',
    confidence: 0.92
  } as any,
  ip_intelligence: {
    '198.51.100.22': {
      ip: '198.51.100.22',
      scope: 'public',
      enrichment_available: true,
      country: 'Poland',
      country_code: 'PL',
      region: 'Masovian',
      city: 'Warsaw',
      latitude: 52.2297,
      longitude: 21.0122,
      timezone: 'Europe/Warsaw',
      asn: 'AS64511',
      asn_org: 'Bulletproof Hosters Ltd',
      isp: 'Bulletproof Threat Transit',
      organization: 'Shady Host VPS',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    },
    '198.51.100.77': {
      ip: '198.51.100.77',
      scope: 'public',
      enrichment_available: true,
      country: 'Germany',
      country_code: 'DE',
      region: 'Hesse',
      city: 'Frankfurt',
      latitude: 50.1109,
      longitude: 8.6821,
      timezone: 'Europe/Berlin',
      asn: 'AS64512',
      asn_org: 'European Transit Relay',
      isp: 'Phish Node Transit',
      organization: 'Compromised Relay Host',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    },
    '192.0.2.200': {
      ip: '192.0.2.200',
      scope: 'public',
      enrichment_available: true,
      country: 'United Kingdom',
      country_code: 'GB',
      region: 'England',
      city: 'London',
      latitude: 51.5074,
      longitude: -0.1278,
      timezone: 'Europe/London',
      asn: 'AS64501',
      asn_org: 'Enterprise Transit',
      isp: 'Enterprise Gateway Services',
      organization: 'Enterprise Corp MX',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    }
  }
};

export const SCENARIO_3_PRIMARY_EMAIL: EmailAnalysis = {
  id: 'scenario-3-campaign',
  evidence_id: 'EVD-DARKHYDRA-001',
  email_sha256: 'd4e5f6a1b2c37890123456789abcdef0123456789abcdef0123456789abcdef0',
  original_filename: 'urgent_executive_wire_transfer_8491.eml',
  upload_timestamp: '2026-09-17T09:45:00Z',
  size: 24500,
  uploader: 'SOC Incident Responder',
  subject: 'URGENT: Executive Wire Transfer Authorization #8491',
  from: 'CEO Office <ceo-urgent@executive-board-corp.example>',
  to: 'controller@victim-enterprise.example',
  date: 'Thu, 17 Sep 2026 08:14:22 +0000',
  reply_to: 'collector@wire-transfer-node.test',
  return_path: 'bounce@executive-board-corp.example',
  message_id: '<wire-8491-auth@executive-board-corp.example>',
  authentication_results: 'mx.victim-enterprise.example; spf=fail (domain does not designate 203.0.113.88); dkim=fail; dmarc=fail (p=reject)',
  authentication: {
    verification_type: 'independent_validation',
    verification_notice: 'Severe authentication and infrastructure anomalies detected. Correlated with active Campaign C-042.',
    observed_header: 'spf=fail dkim=fail dmarc=fail',
    spf: { result: 'fail', details: 'Sending IP 203.0.113.88 not permitted under sender domain SPF policy' },
    dkim: { result: 'fail', details: 'DKIM signature missing or forged' },
    dmarc: { result: 'fail', details: 'DMARC alignment failed' },
    alignment: {
      from_domain: 'executive-board-corp.example',
      reply_to_domain: 'wire-transfer-node.test',
      return_path_domain: 'executive-board-corp.example',
      reply_to_mismatch: true,
      return_path_mismatch: false
    }
  },
  received: [
    'from threat-edge-01.example (203.0.113.88) by mx.victim-enterprise.example; Thu, 17 Sep 2026 08:14:22 +0000'
  ],
  hops: [
    {
      hop: 1,
      fromHost: 'c2-gateway.test',
      fromIp: '203.0.113.88',
      byHost: 'mx.victim-enterprise.example',
      byIp: '192.0.2.200',
      timestamp: '2026-09-17T08:14:22Z',
      delaySeconds: 4,
      authStatus: 'fail',
      isPublicIp: true,
      asn: 'AS64512 (Threat Hosting Corp)'
    }
  ],
  plain_text_body: 'CONFIDENTIAL & TIME-SENSITIVE:\nAs discussed, complete the immediate wire transfer authorization for Project Titan escrow.\nPayment instructions are inside the attached verified PDF statement.\nConfirm wire clearance within 60 minutes.\n\nLink: https://bank-corp-update.example/wire-authorization?id=8491',
  html_body: '<html><body><p>CONFIDENTIAL & TIME-SENSITIVE:</p><p>Complete the immediate wire transfer authorization for Project Titan escrow.</p><p><a href="https://bank-corp-update.example/wire-authorization?id=8491">Click to Confirm Wire Authorization</a></p></body></html>',
  raw_email: 'From: CEO Office <ceo-urgent@executive-board-corp.example>\nTo: controller@victim-enterprise.example\nSubject: URGENT: Executive Wire Transfer Authorization #8491\n\n[High-confidence BEC and malware delivery campaign]',
  indicators: {
    ips: [
      { value: '203.0.113.88', scope: 'public', source: 'received_hop_1' },
      { value: '203.0.113.89', scope: 'public', source: 'c2_cluster' }
    ],
    domains: [
      { value: 'executive-board-corp.example', source: 'header_from' },
      { value: 'bank-corp-update.example', source: 'url_redirect' },
      { value: 'wire-transfer-node.test', source: 'reply_to' }
    ],
    urls: [
      { value: 'https://bank-corp-update.example/wire-authorization?id=8491', source: 'plain_text_body' }
    ],
    email_addresses: [
      { value: 'ceo-urgent@executive-board-corp.example', source: 'header_from' },
      { value: 'collector@wire-transfer-node.test', source: 'reply_to' }
    ],
    attachments: [
      {
        filename: 'Wire_Authorization_8491.pdf.exe',
        mime_type: 'application/x-dosexec',
        size: 215000,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        static_analysis: {
          original_filename: 'Wire_Authorization_8491.pdf.exe',
          file_name: 'Wire_Authorization_8491.pdf.exe',
          file_size: 215000,
          claimed_extension: '.pdf',
          claimed_mime: 'application/pdf',
          detected_type: 'Windows PE32 Executable',
          magic_bytes: '4d 5a 90 00 03 00 00 00',
          extension_mismatch: true,
          double_extension: true,
          sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          is_executable: true,
          contains_macros: false,
          entropy: 7.42,
          mismatch_detected: true
        } as any
      }
    ]
  },
  threat_score: {
    score: 96,
    severity: 'critical',
    risk_level: 'CRITICAL',
    confidence: 'VERY HIGH',
    summary: 'Coordinated BEC & malware campaign (Operation DarkHydra / C-042). Matches 16 related emails sharing ASN AS64512 and infrastructure subnet 203.0.113.0/24.',
    top_reasons: [
      'Correlated with active Campaign C-042 (Operation DarkHydra) (16 related emails) (+25 pts)',
      'Disguised executable payload with double extension (.pdf.exe) (+30 pts)',
      'Executive wire transfer fraud / authority impersonation (+25 pts)',
      'Lookalike domain bank-corp-update.example hosting C2 gateway (+18 pts)'
    ],
    reasons: [
      {
        signal: 'SIG-CAMP-001',
        label: 'Active Campaign Correlation (C-042)',
        points: 25,
        evidence: 'Matches 16 related emails in Operation DarkHydra cluster'
      }
    ],
    positive_evidence: []
  } as any,
  attribution: {
    probable_origin_ip: '203.0.113.88',
    origin_country: 'Observed Infrastructure Network',
    origin_asn: 'AS64512',
    origin_isp: 'Threat Hosting Corp',
    confidence: 0.96
  } as any,
  ip_intelligence: {
    '203.0.113.88': {
      ip: '203.0.113.88',
      scope: 'public',
      enrichment_available: true,
      country: 'United States',
      country_code: 'US',
      region: 'California',
      city: 'San Jose',
      latitude: 37.3382,
      longitude: -121.8863,
      timezone: 'America/Los_Angeles',
      asn: 'AS64512',
      asn_org: 'Threat Hosting Corp',
      isp: 'Threat Hosting Corp',
      organization: 'Bulletproof Server Cluster',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    },
    '203.0.113.89': {
      ip: '203.0.113.89',
      scope: 'public',
      enrichment_available: true,
      country: 'United States',
      country_code: 'US',
      region: 'California',
      city: 'San Jose',
      latitude: 37.3382,
      longitude: -121.8863,
      timezone: 'America/Los_Angeles',
      asn: 'AS64512',
      asn_org: 'Threat Hosting Corp',
      isp: 'Threat Hosting Corp',
      organization: 'Bulletproof Server Cluster',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    },
    '192.0.2.200': {
      ip: '192.0.2.200',
      scope: 'public',
      enrichment_available: true,
      country: 'United Kingdom',
      country_code: 'GB',
      region: 'England',
      city: 'London',
      latitude: 51.5074,
      longitude: -0.1278,
      timezone: 'Europe/London',
      asn: 'AS64501',
      asn_org: 'Enterprise Transit',
      isp: 'Enterprise Gateway Services',
      organization: 'Enterprise Corp MX',
      is_hosting: true,
      is_proxy_vpn_tor: false,
      infrastructure_type: 'Observed Infrastructure Location'
    }
  }
};

export const SCENARIO_3_RELATED_EMAILS = [
  {
    id: 'DH-001',
    subject: 'URGENT: Executive Wire Transfer Authorization #8491',
    sender: 'CEO Office <ceo-urgent@executive-board-corp.example>',
    recipient: 'controller@victim-enterprise.example',
    received_time: '2026-09-17T08:14:22Z',
    threat_score: 96,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.88',
    domain: 'executive-board-corp.example',
    relationship_reason: 'Primary Campaign Trigger Email; identical template and executable payload hash.'
  },
  {
    id: 'DH-002',
    subject: 'URGENT: Wire Transfer Confirmation - Vendor Acquisition',
    sender: 'Finance Director <dir-finance@executive-board-corp.example>',
    recipient: 'ap-payments@victim-enterprise.example',
    received_time: '2026-09-17T07:45:10Z',
    threat_score: 94,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.89',
    domain: 'executive-board-corp.example',
    relationship_reason: 'Same ASN AS64512, same sending subnet 203.0.113.0/24, matching template hash.'
  },
  {
    id: 'DH-003',
    subject: 'Immediate Action: Corporate Wire Escrow Release',
    sender: 'Treasury Board <treasury@bank-corp-update.example>',
    recipient: 'cfo@victim-enterprise.example',
    received_time: '2026-09-17T06:58:34Z',
    threat_score: 92,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.90',
    domain: 'bank-corp-update.example',
    relationship_reason: 'Same redirect domain bank-corp-update.example, overlapping infrastructure.'
  },
  {
    id: 'DH-004',
    subject: 'Confidential M&A Escrow Transfer Instructions',
    sender: 'Legal Counsel <legal@executive-board-corp.example>',
    recipient: 'treasury@victim-enterprise.example',
    received_time: '2026-09-17T06:12:00Z',
    threat_score: 91,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.91',
    domain: 'executive-board-corp.example',
    relationship_reason: 'Same ASN AS64512, matching payload SHA-256 (disguised invoice.pdf.exe).'
  },
  {
    id: 'DH-005',
    subject: 'Swift Wire Payment Verification - Ref #90214',
    sender: 'Banking Settlements <settlements@finance-corp-wire.example>',
    recipient: 'payroll@victim-enterprise.example',
    received_time: '2026-09-17T05:30:19Z',
    threat_score: 89,
    severity: 'high',
    asn: 'AS64512',
    origin_ip: '203.0.113.92',
    domain: 'finance-corp-wire.example',
    relationship_reason: 'Shared ASN AS64512, common Reply-To domain wire-transfer-node.test.'
  },
  {
    id: 'DH-006',
    subject: 'Urgent: Foreign Exchange Disbursal Authorization',
    sender: 'Forex Desk <forex@finance-corp-wire.example>',
    recipient: 'accts@victim-enterprise.example',
    received_time: '2026-09-17T04:44:02Z',
    threat_score: 88,
    severity: 'high',
    asn: 'AS64512',
    origin_ip: '203.0.113.93',
    domain: 'finance-corp-wire.example',
    relationship_reason: 'Same ASN AS64512 and identical HTML boilerplate structure.'
  },
  {
    id: 'DH-007',
    subject: 'Board Request: Same-Day Wire Clearance',
    sender: 'Audit Committee <audit@executive-board-corp.example>',
    recipient: 'head-finance@victim-enterprise.example',
    received_time: '2026-09-17T03:55:41Z',
    threat_score: 93,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.94',
    domain: 'executive-board-corp.example',
    relationship_reason: 'Identical sender domain and shared relay hop 203.0.113.88.'
  },
  {
    id: 'DH-008',
    subject: 'OVERDUE: Critical Settlement Remittance',
    sender: 'Vendor Portal <billing@bank-corp-update.example>',
    recipient: 'invoicing@victim-enterprise.example',
    received_time: '2026-09-17T03:10:15Z',
    threat_score: 87,
    severity: 'high',
    asn: 'AS64512',
    origin_ip: '203.0.113.95',
    domain: 'bank-corp-update.example',
    relationship_reason: 'Lookalike domain bank-corp-update.example, same hosting provider.'
  },
  {
    id: 'DH-009',
    subject: 'Executive Discretion: Private Capital Call Notice',
    sender: 'Managing Director <md@executive-board-corp.example>',
    recipient: 'partner@victim-enterprise.example',
    received_time: '2026-09-17T02:22:50Z',
    threat_score: 95,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.96',
    domain: 'executive-board-corp.example',
    relationship_reason: 'Identical double-extension malware payload hash and C2 gateway.'
  },
  {
    id: 'DH-010',
    subject: 'Immediate Invoice Processing Required',
    sender: 'Accounts Payable <ap@finance-corp-wire.example>',
    recipient: 'billing@victim-enterprise.example',
    received_time: '2026-09-17T01:40:11Z',
    threat_score: 88,
    severity: 'high',
    asn: 'AS64512',
    origin_ip: '203.0.113.97',
    domain: 'finance-corp-wire.example',
    relationship_reason: 'Same ASN AS64512, identical HTML styling template.'
  },
  {
    id: 'DH-011',
    subject: 'Wire Transfer Re-routing Notification #5531',
    sender: 'Wire Desk <wire@bank-corp-update.example>',
    recipient: 'cfo@victim-enterprise.example',
    received_time: '2026-09-17T01:05:00Z',
    threat_score: 90,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.98',
    domain: 'bank-corp-update.example',
    relationship_reason: 'Overlapping C2 infrastructure and identical recipient target profile.'
  },
  {
    id: 'DH-012',
    subject: 'Critical Banking Gateway Maintenance & Re-auth',
    sender: 'Security Admin <admin@exec-banking-auth.example>',
    recipient: 'sysadmin@victim-enterprise.example',
    received_time: '2026-09-17T00:30:22Z',
    threat_score: 86,
    severity: 'high',
    asn: 'AS64512',
    origin_ip: '203.0.113.99',
    domain: 'exec-banking-auth.example',
    relationship_reason: 'Same ASN AS64512, credential harvesting portal targeting same domain.'
  },
  {
    id: 'DH-013',
    subject: 'URGENT: Executive Wire Transfer Authorization #8489',
    sender: 'CEO Office <ceo-urgent@executive-board-corp.example>',
    recipient: 'controller@victim-enterprise.example',
    received_time: '2026-09-16T23:50:00Z',
    threat_score: 95,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.88',
    domain: 'executive-board-corp.example',
    relationship_reason: 'Near-duplicate subject and matching sender address.'
  },
  {
    id: 'DH-014',
    subject: 'Vendor Settlement: Final Notice Before Default',
    sender: 'Legal Team <counsel@finance-corp-wire.example>',
    recipient: 'ap@victim-enterprise.example',
    received_time: '2026-09-16T22:15:40Z',
    threat_score: 87,
    severity: 'high',
    asn: 'AS64512',
    origin_ip: '203.0.113.100',
    domain: 'finance-corp-wire.example',
    relationship_reason: 'Same ASN AS64512 and matching Reply-To header.'
  },
  {
    id: 'DH-015',
    subject: 'Confidential Wire Disbursal Instructions',
    sender: 'Special Committee <committee@executive-board-corp.example>',
    recipient: 'treasurer@victim-enterprise.example',
    received_time: '2026-09-16T21:40:12Z',
    threat_score: 93,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.101',
    domain: 'executive-board-corp.example',
    relationship_reason: 'Shared disguised executable attachment and matching infrastructure.'
  },
  {
    id: 'DH-016',
    subject: 'Banking System Notification: Direct Wire Approval',
    sender: 'Bank Notification <alerts@bank-corp-update.example>',
    recipient: 'finance@victim-enterprise.example',
    received_time: '2026-09-16T20:55:00Z',
    threat_score: 91,
    severity: 'critical',
    asn: 'AS64512',
    origin_ip: '203.0.113.102',
    domain: 'bank-corp-update.example',
    relationship_reason: 'Overlapping sender IP block 203.0.113.0/24 and lookalike brand domain.'
  }
];
