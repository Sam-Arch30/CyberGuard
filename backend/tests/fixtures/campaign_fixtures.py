"""
Realistic Synthetic Fixtures for Campaign Fingerprinting & Correlation.
Covers 6 distinct tactical scenarios:
1. Same campaign, different sender addresses
2. Same campaign, rotating domains
3. Same campaign, rotating IPs
4. Unrelated emails using same cloud provider (AWS / Cloudflare)
5. Template reuse across different targets
6. Legitimate newsletters (benign controls)
"""

# Scenario 1: Same Campaign, Different Sender Addresses
FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_A = {
    "subject": "URGENT: Executive Wire Transfer Instructions - Settlement #8819",
    "from": "Robert Vance <ceo@bank-corp-update.com>",
    "reply_to": "wires@wire-transfer-node.ru",
    "ips": ["185.220.101.42"],
    "domains": ["bank-corp-update.com", "wire-transfer-node.ru"],
    "urls": ["https://bank-corp-update.com/auth/v2/secure_login.php?client=token1"],
    "html_body": "<div class='invoice-wrapper'><table class='wire-details'><tr><td>Immediate Wire Transfer Required</td></tr></table><a href='https://bank-corp-update.com/auth/v2/secure_login.php'>Confirm Wire</a></div>",
    "plain_text_body": "Please process the urgent executive wire transfer settlement immediately. Review payment details.",
    "brands": ["BankCorp"],
    "attachments": [{"filename": "invoice_8819.pdf.exe", "sha256": "aaaa" * 16, "mime_type": "application/x-dosexec"}]
}

FIXTURE_SAME_CAMPAIGN_DIFF_SENDER_B = {
    "subject": "URGENT: Executive Wire Transfer Authorization - Settlement #8820",
    "from": "Accounting Dept <accounting@bank-corp-update.com>",
    "reply_to": "wires@wire-transfer-node.ru",
    "ips": ["185.220.101.42"],
    "domains": ["bank-corp-update.com", "wire-transfer-node.ru"],
    "urls": ["https://bank-corp-update.com/auth/v2/secure_login.php?client=token2"],
    "html_body": "<div class='invoice-wrapper'><table class='wire-details'><tr><td>Immediate Wire Transfer Required</td></tr></table><a href='https://bank-corp-update.com/auth/v2/secure_login.php'>Confirm Wire</a></div>",
    "plain_text_body": "Please process the urgent executive wire transfer settlement immediately. Review payment details.",
    "brands": ["BankCorp"],
    "attachments": [{"filename": "invoice_8820.pdf.exe", "sha256": "aaaa" * 16, "mime_type": "application/x-dosexec"}]
}

# Scenario 2: Same Campaign, Rotating Domains
FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_A = {
    "subject": "Action Required: Verify Chase Commercial Account Access",
    "from": "Chase Security <alert@login-verify-chase.com>",
    "reply_to": "support@login-verify-chase.com",
    "ips": ["194.26.29.112"],
    "domains": ["login-verify-chase.com"],
    "urls": ["https://login-verify-chase.com/auth/sso/verify.php?session=active"],
    "html_body": "<div class='portal-box'><h2>Sign in to Chase Account</h2><form action='/verify'><input type='password' /></form></div>",
    "plain_text_body": "Your Chase account was flagged for suspicious activity. Verify your login credentials to restore access.",
    "brands": ["Chase"],
    "ip_intelligence": {"194.26.29.112": {"asn": "AS49281", "isp": "ShadowNode Hosting", "org": "Bulletproof VPS"}}
}

FIXTURE_SAME_CAMPAIGN_ROTATING_DOMAIN_B = {
    "subject": "Action Required: Verify Chase Commercial Account Access",
    "from": "Chase Online <security@security-alert-chase-online.org>",
    "reply_to": "support@security-alert-chase-online.org",
    "ips": ["194.26.29.112"],
    "domains": ["security-alert-chase-online.org"],
    "urls": ["https://security-alert-chase-online.org/auth/sso/verify.php?session=active"],
    "html_body": "<div class='portal-box'><h2>Sign in to Chase Account</h2><form action='/verify'><input type='password' /></form></div>",
    "plain_text_body": "Your Chase account was flagged for suspicious activity. Verify your login credentials to restore access.",
    "brands": ["Chase"],
    "ip_intelligence": {"194.26.29.112": {"asn": "AS49281", "isp": "ShadowNode Hosting", "org": "Bulletproof VPS"}}
}

# Scenario 3: Same Campaign, Rotating IPs
FIXTURE_SAME_CAMPAIGN_ROTATING_IP_A = {
    "subject": "Encrypted Secure Document Shared With You via OneDrive",
    "from": "Doc Share <shares@doc-share-portal.net>",
    "reply_to": "shares@doc-share-portal.net",
    "ips": ["194.26.29.112"],
    "domains": ["doc-share-portal.net"],
    "urls": ["https://doc-share-portal.net/view/encrypted_file.aspx"],
    "html_body": "<div class='doc-viewer'><p>A confidential document was shared with you.</p><a href='https://doc-share-portal.net/view/encrypted_file.aspx'>Open Document</a></div>",
    "plain_text_body": "You have received a protected document. Login to decrypt and access the file.",
    "domain_intelligence": {"doc-share-portal.net": {"dns": {"ns": ["ns1.shadow-dns.cc", "ns2.shadow-dns.cc"]}}}
}

FIXTURE_SAME_CAMPAIGN_ROTATING_IP_B = {
    "subject": "Encrypted Secure Document Shared With You via OneDrive",
    "from": "Doc Share Notification <shares@doc-share-portal.net>",
    "reply_to": "shares@doc-share-portal.net",
    "ips": ["194.26.29.115"],  # rotated IP in same subnet
    "domains": ["doc-share-portal.net"],
    "urls": ["https://doc-share-portal.net/view/encrypted_file.aspx"],
    "html_body": "<div class='doc-viewer'><p>A confidential document was shared with you.</p><a href='https://doc-share-portal.net/view/encrypted_file.aspx'>Open Document</a></div>",
    "plain_text_body": "You have received a protected document. Login to decrypt and access the file.",
    "domain_intelligence": {"doc-share-portal.net": {"dns": {"ns": ["ns1.shadow-dns.cc", "ns2.shadow-dns.cc"]}}}
}

# Scenario 4: Unrelated Emails Using Same Cloud Provider (AWS SES / Cloudflare)
FIXTURE_UNRELATED_AWS_EMAIL_A = {
    "subject": "Acme Corp Weekly Engineering Newsletter #42",
    "from": "Acme Team <newsletter@acme-corp.com>",
    "ips": ["54.240.8.1"],  # Amazon SES
    "domains": ["acme-corp.com"],
    "urls": ["https://acme-corp.com/blog/engineering-update"],
    "html_body": "<article><h1>Engineering Team Weekly</h1><p>Kubernetes cluster migration completed successfully.</p></article>",
    "plain_text_body": "Here is this week's engineering update on Kubernetes and backend microservices architecture.",
    "ip_intelligence": {"54.240.8.1": {"asn": "AS16509", "isp": "Amazon.com, Inc.", "org": "Amazon Data Services"}},
    "domain_intelligence": {"acme-corp.com": {"dns": {"ns": ["ns1.cloudflare.com", "ns2.cloudflare.com"]}}}
}

FIXTURE_UNRELATED_AWS_EMAIL_B = {
    "subject": "Your Online Order Receipt #99104 - Outdoor Gear Supply",
    "from": "Customer Support <support@outdoor-gear-store.com>",
    "ips": ["54.240.8.2"],  # Amazon SES
    "domains": ["outdoor-gear-store.com"],
    "urls": ["https://outdoor-gear-store.com/receipts/99104"],
    "html_body": "<div class='receipt'><h2>Thank you for your order</h2><p>Camping tent and hiking boots will ship tomorrow.</p></div>",
    "plain_text_body": "Thank you for shopping at Outdoor Gear. Your package has been confirmed and is being packed.",
    "ip_intelligence": {"54.240.8.2": {"asn": "AS16509", "isp": "Amazon.com, Inc.", "org": "Amazon Data Services"}},
    "domain_intelligence": {"outdoor-gear-store.com": {"dns": {"ns": ["ns3.cloudflare.com", "ns4.cloudflare.com"]}}}
}

# Scenario 5: Template Reuse Across Different Targets
FIXTURE_TEMPLATE_REUSE_TARGET_A = {
    "subject": "URGENT: Immediate Account Verification Required",
    "from": "Bank A Security <security@first-state-bank-auth.com>",
    "domains": ["first-state-bank-auth.com"],
    "ips": ["185.120.40.10"],
    "urls": ["https://first-state-bank-auth.com/portal/login.html"],
    "html_body": "<div class='phish-kit-container'><div class='header-banner-phish'><h1>Account Suspended Within 24 Hours</h1></div><div class='form-body-phish'><p>Verify your credentials to avoid permanent termination.</p><a class='btn-cta-phish' href='https://first-state-bank-auth.com/portal/login.html'>Verify Now</a></div></div>",
    "plain_text_body": "Immediate account verification required. Your account will be suspended within 24 hours if action is not taken.",
    "brands": ["First State Bank"]
}

FIXTURE_TEMPLATE_REUSE_TARGET_B = {
    "subject": "URGENT: Immediate Account Verification Required",
    "from": "Union Trust Security <security@union-trust-online-verify.net>",
    "domains": ["union-trust-online-verify.net"],
    "ips": ["185.120.40.12"],
    "urls": ["https://union-trust-online-verify.net/portal/login.html"],
    "html_body": "<div class='phish-kit-container'><div class='header-banner-phish'><h1>Account Suspended Within 24 Hours</h1></div><div class='form-body-phish'><p>Verify your credentials to avoid permanent termination.</p><a class='btn-cta-phish' href='https://union-trust-online-verify.net/portal/login.html'>Verify Now</a></div></div>",
    "plain_text_body": "Immediate account verification required. Your account will be suspended within 24 hours if action is not taken.",
    "brands": ["Union Trust"]
}

# Scenario 6: Legitimate Newsletters (Benign Controls)
FIXTURE_LEGIT_NEWSLETTER_A = {
    "subject": "Cybersecurity Weekly Digest - Zero-Day Trends & Defense",
    "from": "Threat Intel Weekly <digest@cybersec-weekly.com>",
    "domains": ["cybersec-weekly.com"],
    "ips": ["198.51.100.1"],
    "urls": ["https://cybersec-weekly.com/issues/104"],
    "html_body": "<article><h1>Weekly Cyber Roundup</h1><p>Analysis of latest vulnerabilities and patching guidance.</p></article>",
    "plain_text_body": "Read this week's analysis of zero-day vulnerabilities, supply chain risks, and proactive defense strategies.",
    "authentication": {"spf": {"result": "pass", "aligned": True}, "dkim": {"result": "pass", "aligned": True}}
}

FIXTURE_LEGIT_NEWSLETTER_B = {
    "subject": "Python Developer Monthly - AsyncIO & Performance Tips",
    "from": "Python Tips <newsletter@pydev-digest.org>",
    "domains": ["pydev-digest.org"],
    "ips": ["203.0.113.1"],
    "urls": ["https://pydev-digest.org/editions/55"],
    "html_body": "<article><h1>Python Performance Digest</h1><p>Tips on optimizing coroutines and memory profiling.</p></article>",
    "plain_text_body": "Learn how to write fast asynchronous Python code with proper profiling and memory management techniques.",
    "authentication": {"spf": {"result": "pass", "aligned": True}, "dkim": {"result": "pass", "aligned": True}}
}
