"""
SIH Synthetic Demo Scenarios for MailTraceAI.
Contains 3 strictly safe synthetic scenarios adhering to RFC 2606 / RFC 5737:
1. Scenario 1: Legitimate Business Email (False-positive resistance, Score: 6/100)
2. Scenario 2: Obvious Phishing Email (Explainable detection, Score: 94/100)
3. Scenario 3: Coordinated Campaign (Operation DarkHydra / C-042, 4 clustered emails)
"""
from typing import Dict, Any, List

# SCENARIO 1: LEGITIMATE BUSINESS EMAIL
SCENARIO_1_LEGITIMATE: Dict[str, Any] = {
    "id": "scenario-1-legit",
    "evidence_id": "EVD-LEGIT-9041",
    "email_sha256": "3a8b2c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
    "original_filename": "monthly_saas_invoice_receipt.eml",
    "upload_timestamp": "2026-09-17T09:15:00Z",
    "size": 8420,
    "uploader": "SOC Analyst (SIH Demo)",
    "is_demo": True,
    "dataset": "synthetic_sih_demo",
    "scenario_id": "scenario-1-legitimate",
    "scenario_name": "Scenario 1: Legitimate Business Email",
    "scenario_description": "Normal enterprise SaaS subscription receipt with fully aligned SPF, DKIM, and DMARC, clean corporate relay path, and non-executable PDF receipt. Proves false-positive resistance.",
    "subject": "Monthly SaaS Subscription Receipt - Invoice #INV-2026-9041",
    "from": "CloudDesk Accounts <billing@trusted-vendor.example>",
    "to": "accounts-payable@company.example",
    "reply_to": "billing@trusted-vendor.example",
    "return_path": "receipts@trusted-vendor.example",
    "date": "Thu, 17 Sep 2026 09:14:30 +0000",
    "message_id": "<inv-9041-receipt@trusted-vendor.example>",
    "authentication_results": "mx.company.example; dkim=pass header.i=@trusted-vendor.example; spf=pass (ip=198.51.100.40); dmarc=pass (p=reject)",
    "authentication": {
        "verification_type": "observed_header",
        "spf": {"result": "pass", "status": "pass", "details": "Sender IP 198.51.100.40 authorized in SPF record of trusted-vendor.example"},
        "dkim": {"result": "pass", "status": "pass", "details": "Cryptographic signature verified for d=trusted-vendor.example (selector=s1)"},
        "dmarc": {"result": "pass", "status": "pass", "details": "Strict alignment passed with p=reject policy"},
        "alignment": {
            "from_domain": "trusted-vendor.example",
            "reply_to_domain": "trusted-vendor.example",
            "return_path_domain": "trusted-vendor.example",
            "reply_to_mismatch": False,
            "return_path_mismatch": False
        }
    },
    "received": [
        "from mail.trusted-vendor.example (198.51.100.40) by mx.company.example; Thu, 17 Sep 2026 09:14:32 +0000"
    ],
    "plain_text_body": "Dear Finance Team,\n\nThank you for your continued subscription to CloudDesk Pro. Your monthly payment of $149.00 has been processed successfully.\n\nReceipt Number: INV-2026-9041\nDate: September 17, 2026\nAccount: company.example\n\nA copy of your tax invoice PDF is attached for your records.\n\nBest regards,\nCloudDesk Billing Department\nhttps://trusted-vendor.example/support",
    "html_body": "<html><body><p>Dear Finance Team,</p><p>Thank you for your subscription. Receipt #INV-2026-9041 has been processed.</p><p><a href=\"https://trusted-vendor.example/receipts/INV-2026-9041.pdf\">Download Invoice PDF</a></p></body></html>",
    "raw_email": """From: CloudDesk Accounts <billing@trusted-vendor.example>
To: accounts-payable@company.example
Subject: Monthly SaaS Subscription Receipt - Invoice #INV-2026-9041
Date: Thu, 17 Sep 2026 09:14:30 +0000
Message-ID: <inv-9041-receipt@trusted-vendor.example>
Authentication-Results: mx.company.example; dkim=pass; spf=pass; dmarc=pass
Content-Type: multipart/mixed; boundary="BOUND1"

--BOUND1
Content-Type: text/plain; charset=utf-8

Dear Finance Team,
Your monthly payment has been processed successfully.
Receipt Number: INV-2026-9041.
--BOUND1--""",
    "indicators": {
        "ips": [{"value": "198.51.100.40", "version": 4, "scope": "public", "source": "received_header"}],
        "domains": [{"value": "trusted-vendor.example", "source": "header_from"}, {"value": "company.example", "source": "header_to"}],
        "urls": [{"value": "https://trusted-vendor.example/receipts/INV-2026-9041.pdf", "source": "html_a_href"}],
        "email_addresses": [
            {"value": "billing@trusted-vendor.example", "source": "header_from"},
            {"value": "accounts-payable@company.example", "source": "header_to"}
        ],
        "attachments": [
            {
                "filename": "INV-2026-9041.pdf",
                "mime_type": "application/pdf",
                "size": 42100,
                "sha256": "4b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c",
                "md5": "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
                "sha1": "11223344556677889900aabbccddeeff00112233",
                "static_analysis": {
                    "is_executable": False,
                    "contains_macros": False,
                    "contains_javascript": False,
                    "entropy": 4.1,
                    "mismatch_detected": False,
                    "file_type": "PDF Document (Clean)"
                }
            }
        ]
    },
    "threat_score": {
        "score": 6,
        "severity": "low",
        "risk_level": "LOW",
        "confidence": "HIGH",
        "summary": "Legitimate business email with fully aligned SPF, DKIM, and DMARC authentication. Established sender domain and clean PDF attachment.",
        "why_flagged": "Email evaluated as LOW RISK (6/100). No anomalous indicators or phishing heuristics detected.",
        "top_reasons": ["Established corporate sender domain", "SPF and DKIM cryptographic signatures verified"],
        "positive_contributions": [],
        "negative_contributions": [
            {
                "signal_id": "SIG-AUTH-PASS",
                "category": "authentication",
                "name": "Full cryptographic authentication passed",
                "description": "SPF pass, DKIM pass, DMARC pass (p=reject)",
                "weight": -10,
                "contribution": -10,
                "direction": "decrease_risk"
            }
        ]
    }
}


# SCENARIO 2: OBVIOUS PHISHING EMAIL
SCENARIO_2_PHISHING: Dict[str, Any] = {
    "id": "scenario-2-phish",
    "evidence_id": "EVD-PHISH-9402",
    "email_sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "original_filename": "urgent_mfa_reset_warning.eml",
    "upload_timestamp": "2026-09-17T09:30:00Z",
    "size": 18240,
    "uploader": "SOC Analyst (SIH Demo)",
    "is_demo": True,
    "dataset": "synthetic_sih_demo",
    "scenario_id": "scenario-2-phishing",
    "scenario_name": "Scenario 2: Obvious Synthetic Phishing",
    "scenario_description": "High-urgency synthetic credential harvesting attack featuring brand lookalike domain (micros0ft-support.example), hard SPF/DKIM/DMARC failures, untrusted bulletproof proxy relay (AS64512), and disguised double-extension executable (Security_Notice.pdf.exe). Proves detection accuracy and granular explainability.",
    "subject": "URGENT: Microsoft 365 MFA Security Re-verification Required within 2 Hours",
    "from": "Global IT Security <security-admin@micros0ft-support.example>",
    "to": "sarah.jenkins@company.example",
    "reply_to": "attacker-collector@attacker-dropzone.test",
    "return_path": "bounce@attacker-dropzone.test",
    "date": "Thu, 17 Sep 2026 09:28:10 +0000",
    "message_id": "<20260917-mfa-alert-991@micros0ft-support.example>",
    "authentication_results": "mx.company.example; spf=fail (domain of bounce@attacker-dropzone.test does not designate 203.0.113.88); dkim=fail; dmarc=fail (p=reject)",
    "authentication": {
        "verification_type": "observed_header",
        "spf": {"result": "fail", "status": "fail", "details": "Hard fail: IP 203.0.113.88 is not designated as authorized sender"},
        "dkim": {"result": "fail", "status": "fail", "details": "Cryptographic signature failed or non-aligned"},
        "dmarc": {"result": "fail", "status": "fail", "details": "DMARC policy evaluation failed: p=reject"},
        "alignment": {
            "from_domain": "micros0ft-support.example",
            "reply_to_domain": "attacker-dropzone.test",
            "return_path_domain": "attacker-dropzone.test",
            "reply_to_mismatch": True,
            "return_path_mismatch": True
        }
    },
    "received": [
        "from mail.attacker-dropzone.test (203.0.113.88) by mx.company.example; Thu, 17 Sep 2026 09:28:12 +0000"
    ],
    "plain_text_body": "SECURITY ALERT: Immediate Action Required!\n\nYour Multi-Factor Authentication (MFA) token expired on September 17, 2026. System security policy requires immediate password re-verification.\n\nIf you do not verify your login credentials within 2 hours, your corporate Microsoft 365 account will be permanently locked.\n\nVerify Credentials Now:\nhttps://micros0ft-support.example/login/mfa_verify?target=sarah.jenkins\n\nAlternatively, run the attached security verification patch: Security_Notice.pdf.exe\n\nGlobal IT Security Operations",
    "html_body": "<html><body><h2>Security Re-verification Required</h2><p>Your MFA token has expired. <a href=\"https://micros0ft-support.example/login/mfa_verify?target=sarah.jenkins\">Click here to re-verify credentials</a></p></body></html>",
    "raw_email": """From: Global IT Security <security-admin@micros0ft-support.example>
To: sarah.jenkins@company.example
Subject: URGENT: Microsoft 365 MFA Security Re-verification Required within 2 Hours
Reply-To: attacker-collector@attacker-dropzone.test
Return-Path: bounce@attacker-dropzone.test
Authentication-Results: mx.company.example; spf=fail; dkim=fail; dmarc=fail
Content-Type: multipart/mixed; boundary="BOUND2"

--BOUND2
Content-Type: text/plain; charset=utf-8

Your account will be suspended in 2 hours. Verify credentials immediately:
https://micros0ft-support.example/login/mfa_verify
--BOUND2--""",
    "indicators": {
        "ips": [{"value": "203.0.113.88", "version": 4, "scope": "public", "source": "received_header"}],
        "domains": [
            {"value": "micros0ft-support.example", "source": "header_from"},
            {"value": "attacker-dropzone.test", "source": "header_reply_to"}
        ],
        "urls": [{"value": "https://micros0ft-support.example/login/mfa_verify?target=sarah.jenkins", "source": "html_a_href"}],
        "email_addresses": [
            {"value": "security-admin@micros0ft-support.example", "source": "header_from"},
            {"value": "attacker-collector@attacker-dropzone.test", "source": "header_reply_to"},
            {"value": "bounce@attacker-dropzone.test", "source": "header_return_path"}
        ],
        "attachments": [
            {
                "filename": "Security_Notice.pdf.exe",
                "mime_type": "application/x-dosexec",
                "size": 184500,
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "md5": "5d41402abc4b2a76b9719d911017c592",
                "sha1": "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
                "static_analysis": {
                    "is_executable": True,
                    "contains_macros": False,
                    "contains_javascript": True,
                    "entropy": 7.85,
                    "mismatch_detected": True,
                    "extension_mismatch": True,
                    "double_extension": True,
                    "detected_type": "PE32 Windows Executable",
                    "claimed_type": "PDF Document",
                    "file_type": "PE32 executable (GUI) Intel 80386, for MS Windows"
                }
            }
        ]
    },
    "threat_score": {
        "score": 94,
        "severity": "critical",
        "risk_level": "CRITICAL",
        "confidence": "VERY HIGH",
        "summary": "Critical credential harvesting and malware delivery attack (94/100) triggered by 6 positive signals: Brand impersonation lookalike (+25), Double-extension executable (+30), Authentication hard failure (+15), Urgent security language (+12), Reply-To mismatch (+12).",
        "why_flagged": "Email flagged with Threat Score 94/100 (CRITICAL). Key drivers: Disguised PE binary (Security_Notice.pdf.exe), Lookalike domain (micros0ft-support.example vs microsoft.com), DMARC/SPF authentication failure, and coercive account suspension language.",
        "top_reasons": [
            "Dangerous executable attachment disguised as PDF (+30 pts)",
            "Brand lookalike domain impersonating Microsoft (+25 pts)",
            "Cryptographic SPF & DMARC authentication failed (+15 pts)",
            "Credential harvesting language and artificial urgency (+12 pts)"
        ],
        "positive_contributions": [
            {
                "signal_id": "SIG-ATTACH-001",
                "category": "attachments",
                "name": "Executable binary disguised as document",
                "description": "Attachment Security_Notice.pdf.exe has double extension concealing PE32 binary",
                "weight": 30,
                "contribution": 30,
                "direction": "increase_risk"
            },
            {
                "signal_id": "SIG-LOOK-001",
                "category": "lookalike_detection",
                "name": "Brand lookalike impersonation detected",
                "description": "Domain micros0ft-support.example impersonates microsoft.com with character substitution",
                "weight": 25,
                "contribution": 25,
                "direction": "increase_risk"
            },
            {
                "signal_id": "SIG-AUTH-003",
                "category": "authentication",
                "name": "SPF and DMARC authentication failed",
                "description": "SPF fail (203.0.113.88 unauthorized) and DMARC reject",
                "weight": 15,
                "contribution": 15,
                "direction": "increase_risk"
            },
            {
                "signal_id": "SIG-CONTENT-004",
                "category": "email_content",
                "name": "Credential harvesting urgency keywords",
                "description": "Coercive urgency detected: 'locked in 2 hours', 'verify login credentials'",
                "weight": 12,
                "contribution": 12,
                "direction": "increase_risk"
            },
            {
                "signal_id": "SIG-SENDER-005",
                "category": "sender_identity",
                "name": "Reply-To and Return-Path mismatch",
                "description": "From header domain differs from Reply-To attacker-dropzone.test",
                "weight": 12,
                "contribution": 12,
                "direction": "increase_risk"
            }
        ],
        "negative_contributions": []
    },
    "attribution": {
        "probable_origin_ip": "203.0.113.88",
        "origin_asn": "AS64512",
        "origin_isp": "Threat Hosting Corp",
        "origin_country": "United States",
        "is_bulletproof": True,
        "cluster_name": "Operation DarkHydra (C-042)"
    }
}


# SCENARIO 3: COORDINATED CAMPAIGN (Operation DarkHydra / C-042)
SCENARIO_3_PRIMARY_EMAIL: Dict[str, Any] = {
    "id": "scenario-3-campaign",
    "evidence_id": "EVD-CAMP-8819",
    "email_sha256": "97d4b2e811c7520e5e79603f9050d268159b360b9432df03d4083d8e57ef228a",
    "original_filename": "campaign_bec_wire_primary.eml",
    "upload_timestamp": "2026-09-17T09:45:00Z",
    "size": 15420,
    "uploader": "SOC Analyst (SIH Demo)",
    "is_demo": True,
    "dataset": "synthetic_sih_demo",
    "scenario_id": "scenario-3-campaign",
    "scenario_name": "Scenario 3: Coordinated Campaign (Operation DarkHydra)",
    "scenario_description": "Part of coordinated multi-stage Business Email Compromise campaign (C-042). Automatically triggers cross-email correlation workspace, revealing 16 related emails sharing ASN AS64512, template hashes, and destination infrastructure.",
    "subject": "URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819",
    "from": "Robert Vance (CEO) <robert.vance@bank-corp-update.example>",
    "to": "sarah.jenkins@company.example",
    "reply_to": "financial-operations-secure@wire-transfer-node.test",
    "return_path": "bounce-gateway@wire-transfer-node.test",
    "date": "Thu, 17 Sep 2026 09:40:00 +0000",
    "message_id": "<20260917.8819-shadow@bank-corp-update.example>",
    "campaign_id": "C-042",
    "campaign_name": "Operation DarkHydra",
    "authentication_results": "mx.company.example; spf=fail (domain of bounce-gateway@wire-transfer-node.test does not designate 203.0.113.25); dkim=fail; dmarc=fail (p=reject)",
    "authentication": {
        "verification_type": "observed_header",
        "spf": {"result": "fail", "status": "fail", "details": "SoftFail: IP 203.0.113.25 is not authorized"},
        "dkim": {"result": "fail", "status": "fail", "details": "Signature mismatch on selector default._domainkey"},
        "dmarc": {"result": "fail", "status": "fail", "details": "p=reject policy triggered"},
        "alignment": {
            "from_domain": "bank-corp-update.example",
            "reply_to_domain": "wire-transfer-node.test",
            "return_path_domain": "wire-transfer-node.test",
            "reply_to_mismatch": True,
            "return_path_mismatch": True
        }
    },
    "received": [
        "from smtp-relay-01.shadow-node.test (203.0.113.25) by mx.company.example; Thu, 17 Sep 2026 09:40:02 +0000"
    ],
    "plain_text_body": "Sarah,\n\nI am currently in an emergency board session. Please process an urgent wire transfer of $248,500 USD for the Q3 vendor settlement before 12:00 PM EST.\n\nUpdated wiring portal:\nhttps://bank-corp-update.example/auth/v2/secure_login.php?ref=8819\n\nConfirm payment receipt once generated.\n\nRegards,\nRobert Vance (CEO)",
    "html_body": "<html><body><p>Emergency payment instruction: <a href=\"https://bank-corp-update.example/auth/v2/secure_login.php?ref=8819\">Wire Transfer Portal</a></p></body></html>",
    "raw_email": """From: Robert Vance (CEO) <robert.vance@bank-corp-update.example>
To: sarah.jenkins@company.example
Subject: URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819
Reply-To: financial-operations-secure@wire-transfer-node.test
Authentication-Results: spf=fail; dkim=fail; dmarc=fail

Process payment immediately: https://bank-corp-update.example/auth/v2/secure_login.php?ref=8819""",
    "indicators": {
        "ips": [{"value": "203.0.113.25", "version": 4, "scope": "public", "source": "received_header"}],
        "domains": [
            {"value": "bank-corp-update.example", "source": "header_from"},
            {"value": "wire-transfer-node.test", "source": "header_reply_to"}
        ],
        "urls": [{"value": "https://bank-corp-update.example/auth/v2/secure_login.php?ref=8819", "source": "html_a_href"}],
        "email_addresses": [
            {"value": "robert.vance@bank-corp-update.example", "source": "header_from"},
            {"value": "financial-operations-secure@wire-transfer-node.test", "source": "header_reply_to"}
        ],
        "attachments": [
            {
                "filename": "Vendor_Invoice_Q3_Settlement.pdf.exe",
                "mime_type": "application/octet-stream",
                "size": 148520,
                "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "static_analysis": {
                    "is_executable": True,
                    "contains_macros": False,
                    "entropy": 7.42,
                    "mismatch_detected": True,
                    "file_type": "PE32 Windows Executable"
                }
            }
        ]
    },
    "threat_score": {
        "score": 96,
        "severity": "critical",
        "risk_level": "CRITICAL",
        "confidence": "VERY HIGH",
        "summary": "High-confidence Business Email Compromise (BEC) and malware campaign (96/100). Strongly correlated with Campaign C-042 (Operation DarkHydra).",
        "why_flagged": "Email flagged with Threat Score 96/100 (CRITICAL). Matches Campaign C-042 IOC cluster with shared ASN AS64512 and identical payload hashes.",
        "top_reasons": [
            "Executive wire transfer fraud / authority impersonation (+25 pts)",
            "Correlated with active Campaign C-042 (Operation DarkHydra) (+20 pts)",
            "Disguised executable payload (+30 pts)",
            "Lookalike bank-corp-update.example domain (+18 pts)"
        ],
        "positive_contributions": [
            {
                "signal_id": "SIG-CAMP-001",
                "category": "campaign_intelligence",
                "name": "Correlated with Campaign C-042 (Operation DarkHydra)",
                "description": "Overlapping ASN AS64512, subnet 203.0.113.0/24, and matching template hash",
                "weight": 20,
                "contribution": 20,
                "direction": "increase_risk"
            }
        ],
        "negative_contributions": []
    },
    "campaign_correlation": {
        "has_correlation": True,
        "campaign_id": "C-042",
        "campaign_name": "Operation DarkHydra",
        "confidence": 0.89,
        "related_email_count": 16,
        "strongest_relationships": [
            "Same redirect domain (bank-corp-update.example)",
            "Same ASN (AS64512 - Threat Hosting Corp)",
            "Highly similar HTML template (structural hash match)",
            "Similar subject ('URGENT: Executive Wire Transfer')",
            "Same Reply-To domain (wire-transfer-node.test)",
            "Overlapping sender infrastructure (203.0.113.0/24)"
        ]
    }
}

SCENARIO_3_CAMPAIGN_CLUSTER: List[Dict[str, Any]] = [
    {
        "id": "DH-001",
        "email_id": "DH-001",
        "subject": "URGENT: Executive Wire Transfer Authorization #8491",
        "sender": "CEO Office <ceo-urgent@executive-board-corp.example>",
        "recipient": "controller@victim-enterprise.example",
        "received_time": "2026-09-17T08:14:22Z",
        "threat_score": 96,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.88",
        "domain": "executive-board-corp.example",
        "relationship_reason": "Primary Campaign Trigger Email; identical template and executable payload hash."
    },
    {
        "id": "DH-002",
        "email_id": "DH-002",
        "subject": "URGENT: Wire Transfer Confirmation - Vendor Acquisition",
        "sender": "Finance Director <dir-finance@executive-board-corp.example>",
        "recipient": "ap-payments@victim-enterprise.example",
        "received_time": "2026-09-17T07:45:10Z",
        "threat_score": 94,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.89",
        "domain": "executive-board-corp.example",
        "relationship_reason": "Same ASN AS64512, same sending subnet 203.0.113.0/24, matching template hash."
    },
    {
        "id": "DH-003",
        "email_id": "DH-003",
        "subject": "Immediate Action: Corporate Wire Escrow Release",
        "sender": "Treasury Board <treasury@bank-corp-update.example>",
        "recipient": "cfo@victim-enterprise.example",
        "received_time": "2026-09-17T06:58:34Z",
        "threat_score": 92,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.90",
        "domain": "bank-corp-update.example",
        "relationship_reason": "Same redirect domain bank-corp-update.example, overlapping infrastructure."
    },
    {
        "id": "DH-004",
        "email_id": "DH-004",
        "subject": "Confidential M&A Escrow Transfer Instructions",
        "sender": "Legal Counsel <legal@executive-board-corp.example>",
        "recipient": "treasury@victim-enterprise.example",
        "received_time": "2026-09-17T06:12:00Z",
        "threat_score": 91,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.91",
        "domain": "executive-board-corp.example",
        "relationship_reason": "Same ASN AS64512, matching payload SHA-256 (disguised invoice.pdf.exe)."
    },
    {
        "id": "DH-005",
        "email_id": "DH-005",
        "subject": "Swift Wire Payment Verification - Ref #90214",
        "sender": "Banking Settlements <settlements@finance-corp-wire.example>",
        "recipient": "payroll@victim-enterprise.example",
        "received_time": "2026-09-17T05:30:19Z",
        "threat_score": 89,
        "severity": "high",
        "asn": "AS64512",
        "origin_ip": "203.0.113.92",
        "domain": "finance-corp-wire.example",
        "relationship_reason": "Shared ASN AS64512, common Reply-To domain wire-transfer-node.test."
    },
    {
        "id": "DH-006",
        "email_id": "DH-006",
        "subject": "Urgent: Foreign Exchange Disbursal Authorization",
        "sender": "Forex Desk <forex@finance-corp-wire.example>",
        "recipient": "accts@victim-enterprise.example",
        "received_time": "2026-09-17T04:44:02Z",
        "threat_score": 88,
        "severity": "high",
        "asn": "AS64512",
        "origin_ip": "203.0.113.93",
        "domain": "finance-corp-wire.example",
        "relationship_reason": "Same ASN AS64512 and identical HTML boilerplate structure."
    },
    {
        "id": "DH-007",
        "email_id": "DH-007",
        "subject": "Board Request: Same-Day Wire Clearance",
        "sender": "Audit Committee <audit@executive-board-corp.example>",
        "recipient": "head-finance@victim-enterprise.example",
        "received_time": "2026-09-17T03:55:41Z",
        "threat_score": 93,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.94",
        "domain": "executive-board-corp.example",
        "relationship_reason": "Identical sender domain and shared relay hop 203.0.113.88."
    },
    {
        "id": "DH-008",
        "email_id": "DH-008",
        "subject": "OVERDUE: Critical Settlement Remittance",
        "sender": "Vendor Portal <billing@bank-corp-update.example>",
        "recipient": "invoicing@victim-enterprise.example",
        "received_time": "2026-09-17T03:10:15Z",
        "threat_score": 87,
        "severity": "high",
        "asn": "AS64512",
        "origin_ip": "203.0.113.95",
        "domain": "bank-corp-update.example",
        "relationship_reason": "Lookalike domain bank-corp-update.example, same hosting provider."
    },
    {
        "id": "DH-009",
        "email_id": "DH-009",
        "subject": "Executive Discretion: Private Capital Call Notice",
        "sender": "Managing Director <md@executive-board-corp.example>",
        "recipient": "partner@victim-enterprise.example",
        "received_time": "2026-09-17T02:22:50Z",
        "threat_score": 95,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.96",
        "domain": "executive-board-corp.example",
        "relationship_reason": "Identical double-extension malware payload hash and C2 gateway."
    },
    {
        "id": "DH-010",
        "email_id": "DH-010",
        "subject": "Immediate Invoice Processing Required",
        "sender": "Accounts Payable <ap@finance-corp-wire.example>",
        "recipient": "billing@victim-enterprise.example",
        "received_time": "2026-09-17T01:40:11Z",
        "threat_score": 88,
        "severity": "high",
        "asn": "AS64512",
        "origin_ip": "203.0.113.97",
        "domain": "finance-corp-wire.example",
        "relationship_reason": "Same ASN AS64512, identical HTML styling template."
    },
    {
        "id": "DH-011",
        "email_id": "DH-011",
        "subject": "Wire Transfer Re-routing Notification #5531",
        "sender": "Wire Desk <wire@bank-corp-update.example>",
        "recipient": "cfo@victim-enterprise.example",
        "received_time": "2026-09-17T01:05:00Z",
        "threat_score": 90,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.98",
        "domain": "bank-corp-update.example",
        "relationship_reason": "Overlapping C2 infrastructure and identical recipient target profile."
    },
    {
        "id": "DH-012",
        "email_id": "DH-012",
        "subject": "Critical Banking Gateway Maintenance & Re-auth",
        "sender": "Security Admin <admin@exec-banking-auth.example>",
        "recipient": "sysadmin@victim-enterprise.example",
        "received_time": "2026-09-17T00:30:22Z",
        "threat_score": 86,
        "severity": "high",
        "asn": "AS64512",
        "origin_ip": "203.0.113.99",
        "domain": "exec-banking-auth.example",
        "relationship_reason": "Same ASN AS64512, credential harvesting portal targeting same domain."
    },
    {
        "id": "DH-013",
        "email_id": "DH-013",
        "subject": "URGENT: Executive Wire Transfer Authorization #8489",
        "sender": "CEO Office <ceo-urgent@executive-board-corp.example>",
        "recipient": "controller@victim-enterprise.example",
        "received_time": "2026-09-16T23:50:00Z",
        "threat_score": 95,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.88",
        "domain": "executive-board-corp.example",
        "relationship_reason": "Near-duplicate subject and matching sender address."
    },
    {
        "id": "DH-014",
        "email_id": "DH-014",
        "subject": "Vendor Settlement: Final Notice Before Default",
        "sender": "Legal Team <counsel@finance-corp-wire.example>",
        "recipient": "ap@victim-enterprise.example",
        "received_time": "2026-09-16T22:15:40Z",
        "threat_score": 87,
        "severity": "high",
        "asn": "AS64512",
        "origin_ip": "203.0.113.100",
        "domain": "finance-corp-wire.example",
        "relationship_reason": "Same ASN AS64512 and matching Reply-To header."
    },
    {
        "id": "DH-015",
        "email_id": "DH-015",
        "subject": "Confidential Wire Disbursal Instructions",
        "sender": "Special Committee <committee@executive-board-corp.example>",
        "recipient": "treasurer@victim-enterprise.example",
        "received_time": "2026-09-16T21:40:12Z",
        "threat_score": 93,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.101",
        "domain": "executive-board-corp.example",
        "relationship_reason": "Shared disguised executable attachment and matching infrastructure."
    },
    {
        "id": "DH-016",
        "email_id": "DH-016",
        "subject": "Banking System Notification: Direct Wire Approval",
        "sender": "Bank Notification <alerts@bank-corp-update.example>",
        "recipient": "finance@victim-enterprise.example",
        "received_time": "2026-09-16T20:55:00Z",
        "threat_score": 91,
        "severity": "critical",
        "asn": "AS64512",
        "origin_ip": "203.0.113.102",
        "domain": "bank-corp-update.example",
        "relationship_reason": "Overlapping sender IP block 203.0.113.0/24 and lookalike brand domain."
    }
]

ALL_SIH_SCENARIOS = [
    SCENARIO_1_LEGITIMATE,
    SCENARIO_2_PHISHING,
    SCENARIO_3_PRIMARY_EMAIL
]
