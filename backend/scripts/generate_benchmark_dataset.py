"""
Generates a comprehensive 60-sample labelled SAFE evaluation benchmark dataset for MailTraceAI.
Adheres strictly to RFC 2606 and RFC 5737 reserved names and IP subnets:
- IPs: 203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24
- Domains: .example, .test, .invalid, .internal
"""
import json
from pathlib import Path

DATASET_FILE = Path(__file__).resolve().parent.parent / "data" / "benchmark_dataset.json"

LEGITIMATE_TEMPLATES = [
    ("Monthly SaaS Subscription Receipt - Invoice #INV-2026-9041", "CloudDesk Accounts <billing@trusted-vendor.example>", "Thank you for your payment of $149.00. Invoice INV-2026-9041 is attached."),
    ("Weekly Engineering Sync & Sprint Retro Agenda", "Marcus Brody <m.brody@engineering.company.example>", "Team, please review the agenda for tomorrow's engineering sprint retro."),
    ("Annual Open Enrollment Benefits Confirmation", "HR Operations <benefits-service@company.example>", "Your benefits elections for fiscal year 2027 have been confirmed. No further action needed."),
    ("Customer Support Ticket #44102: Resolved", "Support Desk <support@saas-platform.example>", "Your inquiry regarding API rate limiting has been marked as resolved by our engineer."),
    ("Security Advisory: Scheduled Maintenance Window Sept 22", "IT Infrastructure <ops-announcements@company.example>", "Routine core router firmware updates will occur this Saturday between 02:00 and 04:00 UTC."),
    ("Q3 All-Hands Meeting Recording & Slide Deck", "Executive Office <all-hands@company.example>", "The recording of yesterday's executive town hall is now available on our internal portal."),
    ("Vendor Contract Renewal Approved - DocuSign Completed", "Legal Ops <contracts-bot@docusign-verified.example>", "All signers have completed the Vendor Master Services Agreement #V-2026-88."),
    ("Quarterly Team Offsite Location Poll", "Sarah Lin <s.lin@product.company.example>", "Please cast your vote for our Q4 team planning offsite location by end of week."),
    ("GitLab Enterprise: Merge Request #891 Approved", "GitLab Bot <notifications@git.company.internal>", "Merge request 'feat(auth): add rate limiting middleware' has been approved by senior reviewers."),
    ("Corporate Travel Expense Report #EX-992 Approved", "Finance Department <expenses@company.example>", "Your expense report for the cybersecurity conference in Chicago has been approved for reimbursement."),
    ("Daily Security Operations Center Incident Metrics Digest", "SOC Automated Reporting <soc-metrics@company.example>", "Here is the summary of security alerts triaged across endpoints over the past 24 hours."),
    ("AWS Cost & Usage Budget Threshold Alert: Normal", "Amazon Web Services <no-reply-aws@amazon.example>", "Your AWS account company-prod has utilized 68% of the forecasted monthly budget."),
    ("Office Supplies Requisition Order Placed", "Office Facilities <facilities@company.example>", "The stationery supplies requested for the 4th floor conference rooms have been ordered."),
    ("New Employee Onboarding Welcome: David Kim", "People Operations <people-team@company.example>", "Please join us in welcoming David Kim who joins the site reliability engineering team today."),
    ("IT Asset Verification: Annual Laptop Hardware Audit", "IT Helpdesk <servicedesk@company.example>", "Please complete the brief hardware serial number verification form on the internal IT portal."),
    ("Healthcare Provider Network Updates - Policy Year 2026", "Corporate Benefits <benefits-info@health-provider.example>", "Review the updated list of in-network primary care physicians and specialists."),
    ("Database Maintenance Completed: Replica Resync Finished", "Database Administration <dba-alerts@company.internal>", "PostgreSQL read-replica cluster failover testing was completed successfully with 0s downtime."),
    ("Vendor Payment Remittance Advice: Apex Consulting Ltd", "Treasury Operations <treasury@company.example>", "Remittance advice for electronic funds transfer in settlement of invoice APX-5519."),
    ("Facilities Notice: Annual Fire Alarm Testing This Friday", "Building Management <property-manager@commercial-office.example>", "Loud audible alarm sounders will be tested on Friday morning between 08:00 and 09:00."),
    ("Customer Survey: Your Feedback on MailTrace Integration", "Product Research <feedback@saas-analytics.example>", "We would love 2 minutes of your time to learn about your experience with our product."),
    ("Monthly 401(k) Retirement Account Contribution Statement", "Retirement Services <statements@retirement-fund.example>", "Your September retirement portfolio summary and contribution allocation is ready to view."),
    ("Internal Hackathon Registration: Sign Up Your Team", "Innovation Committee <hackathon@company.example>", "Registrations are now open for the 2026 Autumn Enterprise AI Hackathon."),
    ("Corporate Card Monthly Statement Available for Download", "Enterprise Card Services <corporatecard@commercial-bank.example>", "Your corporate procurement card statement ending in 4109 is available in the portal."),
    ("Software License Renewal Notice: IntelliJ IDEA Ultimate", "Procurement Operations <procurement@company.example>", "Developer IDE subscriptions have been renewed for the upcoming 12 months."),
    ("Office Catering Menu for Tomorrow's Client Briefing", "Guest Services <catering@company.example>", "Review the vegetarian and dietary meal options prepared for tomorrow's executive lunch."),
    ("Cybersecurity Awareness Training Module Completed", "Learning & Development <lms-platform@company.example>", "Congratulations! You have completed the annual phishing awareness module."),
    ("Data Privacy Compliance Review: Passed", "Governance, Risk & Compliance <grc-audit@company.example>", "The annual SOC 2 Type II audit readiness evaluation has concluded with zero non-conformities."),
    ("Team Standup Time Shift to 10:00 AM Starting Monday", "Project Management <pmo@company.example>", "Due to West Coast attendees, our daily engineering standup is shifting 30 minutes later."),
    ("Client Onboarding Kickoff Meeting Invitation", "Solutions Architecture <solutions@company.example>", "Invitation to technical kickoff call with the implementation lead at Client Corp."),
    ("Corporate Gym Membership Subsidy Enrollment Open", "Wellness Committee <wellness@company.example>", "Submit your fitness facility membership invoices to claim your quarterly wellness subsidy.")
]

MALICIOUS_TEMPLATES = [
    # 10 Credential Phishing
    ("URGENT: Microsoft 365 MFA Security Re-verification Required within 2 Hours", "Global IT Security <security-admin@micros0ft-support.example>", "Your MFA token expired today. Click to re-verify credentials immediately: https://micros0ft-support.example/login/mfa_verify", "credential_phishing"),
    ("DocuSign: Action Required - Sign Urgent Wire Transfer Authorization #991", "DocuSign Security Team <e-sign@docus1gn-verify.example>", "Review and electronically sign document: https://docus1gn-verify.example/sign/auth?id=991", "credential_phishing"),
    ("Google Workspace: Critical Security Notice - Unauthorized Access Detected", "Google Workspace Team <no-reply@g00gle-accounts-security.test>", "Sign in now to lock your account and verify your password: https://g00gle-accounts-security.test/security/checkpoint", "credential_phishing"),
    ("Action Required: Your Corporate Password Expires in 4 Hours", "IT Security Admin <admin@company-sso-portal-update.example>", "Re-authenticate credentials to prevent account suspension: https://company-sso-portal-update.example/sso/login", "credential_phishing"),
    ("PayPal Alert: Unusual Activity Detected - Account Restricted", "PayPal Security Center <service@paypa1-account-check.test>", "Confirm your identity and credit card numbers: https://paypa1-account-check.test/auth/verify", "credential_phishing"),
    ("Dropbox File Sharing: Important Confidential Document Shared With You", "Cloud File Share <notification@dr0pbox-direct-link.example>", "Access shared encrypted document: https://dr0pbox-direct-link.example/files/confidential_memo.html", "credential_phishing"),
    ("Adobe Acrobat: You received an encrypted PDF contract", "Adobe Cloud Services <contracts@ad0be-sign-portal.test>", "Log in with your corporate email password to decrypt document: https://ad0be-sign-portal.test/view/pdf", "credential_phishing"),
    ("HR Portal: Mandatory Employee Salary Structure Update Required", "HR Compensation <compensation@payroll-portal-verify.example>", "Confirm login to view updated compensation bands: https://payroll-portal-verify.example/auth/sso", "credential_phishing"),
    ("VPN Gateway Access: Re-verify Active Directory Certificate", "Network Administration <net-ops@remote-access-vpn-auth.example>", "Update expired VPN token and credentials: https://remote-access-vpn-auth.example/connect", "credential_phishing"),
    ("Zoom Video Communications: Missed Audio Meeting Recording", "Zoom Notifications <no-reply@z00m-meeting-transcripts.test>", "Sign in to play your recorded audio voicemail: https://z00m-meeting-transcripts.test/play?id=4921", "credential_phishing"),

    # 8 BEC Fraud
    ("URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819", "Robert Vance (CEO) <robert.vance@bank-corp-update.example>", "Sarah, please process an urgent wire transfer of $248,500 USD right away. Do not discuss with anyone.", "bec_fraud"),
    ("Strictly Confidential: Acquisition Escrow Funds Disbursement", "Executive Leadership <cfo.office@executive-corp-diversion.example>", "Process $412,000 disbursement to escrow node before 3:00 PM EST for Project Horizon.", "bec_fraud"),
    ("Vendor Banking Coordinate Update - Immediate Effect", "Accounts Receivable Dept <accounts@reputable-vendor-invoice.test>", "Please update our beneficiary bank account routing details for all pending invoice settlements.", "bec_fraud"),
    ("Immediate Task: Procurement of Client Appreciation Gift Cards", "Office of the Chief Executive <ceo-direct@executive-mail-portal.example>", "I need you to purchase twenty $200 Apple/Steam gift cards and reply with the scanned PIN codes.", "bec_fraud"),
    ("Urgent Payroll Direct Deposit Account Change Request", "Mark Reynolds (VP) <vp-reynolds@internal-hr-spoof.test>", "Please update my direct deposit bank routing number starting this Friday's payroll cycle.", "bec_fraud"),
    ("Emergency Tax Settlement Payment Notice", "Legal Counsel <counsel@tax-attorneys-settlement.example>", "Authorize emergency electronic funds transfer of $85,000 to prevent municipal lien enforcement.", "bec_fraud"),
    ("Overdue Settlement Wire Notification #8821", "Finance Director <finance-lead@bank-corp-update.example>", "Confirm wire receipt for settlement balance $180,000 sent via our secondary node.", "bec_fraud"),
    ("Project Zenith Emergency Settlement Confirmation #8820", "Executive Office <ceo-wire@bank-corp-update.example>", "Authorization confirmation for second tranche wire payment $310,000.", "bec_fraud"),

    # 7 Malware Delivery
    ("Outstanding Invoice Statement - Overdue Payment Reminder", "Billing Department <invoicing@overdue-collections-dept.example>", "Review the attached invoice: invoice_statement_2026.pdf.exe. Remit payment within 24 hours.", "malware_delivery"),
    ("Courier Delivery Notification: Package Delivery Attempt Failed", "Express Delivery Tracking <tracking@fast-courier-service.test>", "Download and open your digital parcel receipt: shipping_label_receipt.zip containing shipment.vbs.", "malware_delivery"),
    ("Scanned Multi-Function Office Printer Document #Scan-9081", "Xerox WorkCentre <printer-copier@office-scan-device.example>", "Attached is the document scanned from scanner tray: Scan_2026_09_17.pdf.exe.", "malware_delivery"),
    ("Purchase Order Confirmation & Delivery Manifest", "Supply Chain Logistics <orders@logistics-distributor.test>", "Attached is purchase order documentation with embedded macro payload: PO_990142.docm.", "malware_delivery"),
    ("Employee Resume Application: Senior Frontend Engineer", "Job Applicant <candidate.john.doe@free-webmail-relay.test>", "Please find my CV and portfolio project attached in archive: John_Doe_Resume_Portfolio.rar.", "malware_delivery"),
    ("Banking Security Patch Update: Immediate Installation", "IT Infrastructure Support <it-support@banking-patch-server.example>", "Execute the attached corporate security certificate: Root_Cert_Update_v2.exe.", "malware_delivery"),
    ("Urgent Subpoena Notice: Federal Legal Appearance", "Clerk of the Court <notice@district-court-legal.example>", "Open subpoena writ and case evidence: federal_subpoena_appearance.pdf.js.", "malware_delivery"),

    # 5 Brand Impersonation / Urgency
    ("Amazon Order Confirmation: 85-inch OLED TV Shipped", "Amazon Order Support <confirmations@amaz0n-orders-track.example>", "Thank you for purchasing $2,499.00 TV. If you did not place this order, cancel here immediately: https://amaz0n-orders-track.example/cancel", "brand_impersonation"),
    ("Apple ID Notice: Account Flagged for Suspicious Login in Russia", "Apple Support <security@appleid-icloud-verify.test>", "Your Apple account was accessed from Moscow. Unlock your account: https://appleid-icloud-verify.test/unlock", "brand_impersonation"),
    ("FedEx Freight: Shipment Damaged in Transit", "FedEx Express <freight@fedex-shipment-alert.example>", "Claim compensation for damaged cargo: https://fedex-shipment-alert.example/claims/view?tracking=9812", "brand_impersonation"),
    ("Netflix Membership Suspended: Billing Declined", "Netflix Customer Care <billing@netf1ix-update-center.test>", "Update your payment details within 24 hours to keep watching: https://netf1ix-update-center.test/re-bill", "brand_impersonation"),
    ("Bank of America: Debit Card Temporarily Deactivated", "Fraud Prevention Dept <fraud-alert@bofa-security-notice.example>", "Reactivate your checking card immediately: https://bofa-security-notice.example/reactivate/card", "brand_impersonation")
]


def generate_dataset():
    dataset = []
    sample_id = 1

    # Generate 30 Legitimate Emails
    for i, (subject, sender, body) in enumerate(LEGITIMATE_TEMPLATES):
        sender_email = sender.split("<")[1].rstrip(">") if "<" in sender else sender
        sender_domain = sender_email.split("@")[1]
        ip = f"198.51.100.{10 + (i % 80)}"

        entry = {
            "id": f"BENCH-{sample_id:03d}",
            "ground_truth": "legitimate",
            "category": "legitimate",
            "subject": subject,
            "from": sender,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "to": "employee@company.example",
            "date": f"Thu, 17 Sep 2026 {8 + (i // 5):02d}:{10 + (i * 3) % 50:02d}:00 +0000",
            "origin_ip": ip,
            "origin_asn": "AS64496",
            "body": body,
            "authentication": {
                "spf": "pass",
                "dkim": "pass",
                "dmarc": "pass",
                "spf_details": f"Sender IP {ip} authorized in SPF record",
                "dkim_details": f"Cryptographic signature verified for d={sender_domain}",
                "dmarc_details": "Strict alignment passed with p=reject policy"
            },
            "raw_headers": f"""From: {sender}
To: employee@company.example
Subject: {subject}
Date: Thu, 17 Sep 2026 09:00:00 +0000
Message-ID: <bench-{sample_id:03d}@{sender_domain}>
Received: from mail.{sender_domain} ({ip}) by mx.company.example; Thu, 17 Sep 2026 09:00:02 +0000
Authentication-Results: mx.company.example; spf=pass; dkim=pass; dmarc=pass
Return-Path: <service@{sender_domain}>
Reply-To: <service@{sender_domain}>""",
            "expected_threat_level": "low",
            "expected_threat_score": 8
        }
        dataset.append(entry)
        sample_id += 1

    # Generate 30 Malicious Emails
    for i, (subject, sender, body, category) in enumerate(MALICIOUS_TEMPLATES):
        sender_email = sender.split("<")[1].rstrip(">") if "<" in sender else sender
        sender_domain = sender_email.split("@")[1]
        ip = f"203.0.113.{20 + (i % 80)}"

        entry = {
            "id": f"BENCH-{sample_id:03d}",
            "ground_truth": "malicious",
            "category": category,
            "subject": subject,
            "from": sender,
            "sender_email": sender_email,
            "sender_domain": sender_domain,
            "to": "victim@company.example",
            "date": f"Thu, 17 Sep 2026 {10 + (i // 5):02d}:{15 + (i * 4) % 45:02d}:00 +0000",
            "origin_ip": ip,
            "origin_asn": "AS64512",
            "body": body,
            "authentication": {
                "spf": "fail",
                "dkim": "fail",
                "dmarc": "fail",
                "spf_details": f"Hard fail: IP {ip} not designated as authorized sender",
                "dkim_details": "Signature missing or non-aligned header mismatch",
                "dmarc_details": "p=reject policy triggered"
            },
            "raw_headers": f"""From: {sender}
To: victim@company.example
Subject: {subject}
Date: Thu, 17 Sep 2026 10:00:00 +0000
Message-ID: <bench-{sample_id:03d}-attack@{sender_domain}>
Received: from mail.threat-node.test ({ip}) by mx.company.example; Thu, 17 Sep 2026 10:00:02 +0000
Authentication-Results: mx.company.example; spf=fail; dkim=fail; dmarc=fail
Return-Path: <bounce@attacker-dropzone.test>
Reply-To: <collector@attacker-dropzone.test>""",
            "expected_threat_level": "critical" if category in ["malware_delivery", "bec_fraud"] else "high",
            "expected_threat_score": 92 if category == "malware_delivery" else 88
        }
        dataset.append(entry)
        sample_id += 1

    DATASET_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(DATASET_FILE, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"Generated {len(dataset)} benchmark evaluation samples at {DATASET_FILE}")
    print(f"  - Legitimate: 30")
    print(f"  - Malicious: 30 (10 Credential, 8 BEC, 7 Malware, 5 Brand Impersonation)")


if __name__ == "__main__":
    generate_dataset()
