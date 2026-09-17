# MailTraceAI — SIH Demo and Benchmark Guide

This document provides instructions for executing the repeatable end-to-end demonstration and empirical benchmark evaluation for **MailTraceAI**, India's Premier Explainable Email Forensic and Threat Attribution Platform.

---

## 1. Quick Setup & Prerequisites

MailTraceAI runs completely on modern Python 3.10+ and Node.js 18+. All core capabilities—deterministic threat scoring, cryptographic verification, hop-by-hop relay reconstruction, campaign graph correlation, and evidence-grounded copilot reasoning—operate **100% offline without mandatory external cloud dependencies**.

### Backend Setup
```bash
# In repository root:
python3 -m venv backend/venv
source backend/venv/bin/activate
pip install -r requirements.txt

# Start backend FastAPI forensic service (port 8000):
PYTHONPATH=. python3 -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup
```bash
# In repository root:
npm install
npm run dev
# Accessible at http://localhost:5173
```

---

## 2. Demo Credentials & Access

MailTraceAI is pre-configured with local SOC role emulation:
- **Role**: Tier 3 Senior SOC Incident Responder / Forensic Investigator
- **Authentication**: Pre-authenticated session for demo evaluation
- **Active Workspace**: Forensic Laboratory / Isolated Sandboxed Environment

---

## 3. Data Separation & Zero-Pollution Guarantee

All demo scenarios and benchmark samples use **strictly non-routable synthetic infrastructure** under **RFC 2606** (`.example`, `.test`, `.invalid`) and **RFC 5737** (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`):
- **Synthetic Tagging**: All demo records are tagged with `is_demo: true` and `dataset: "synthetic_sih_demo"`.
- **Database Isolation**: Demo fixtures are held in isolated demo stores and never pollute production case correlation, threat intelligence statistics, or legal chain-of-custody audits.

---

## 4. The Three Safe Synthetic Scenarios

### Scenario 1 — Legitimate Business Email
- **File / ID**: `q3_financial_audit_engagement.eml` (`scenario-1-legit`)
- **Subject**: *Q3 Financial Audit Engagement & Status Report - Acme Global*
- **Sender**: `Audits Team <audit-status@acme-global.example>`
- **Authentication**: SPF `pass`, DKIM `pass`, DMARC `pass` (strict alignment)
- **Attachment**: `Q3_Audit_Engagement_Overview.pdf` (Clean PDF, no macros, no bytecode)
- **Expected Result**: **LOW Threat Score (8 / 100)**
- **Purpose**: **Demonstrates False-Positive Resistance**. Shows that normal business correspondence is never mistakenly blocked or flagged as suspicious.

### Scenario 2 — Obvious Phishing Attack
- **File / ID**: `m365_suspension_action_required.eml` (`scenario-2-phish`)
- **Subject**: *CRITICAL ACTION REQUIRED: Microsoft 365 Tenant Suspension Notice*
- **Sender**: `Microsoft Security Center <security-update@micros0ft-support.example>`
- **Lookalike Brand**: `micros0ft-support.example` (targeting Microsoft)
- **Authentication**: SPF `fail`, DKIM `fail`, DMARC `fail`, Reply-To mismatch
- **Disguised Executable**: `Mandatory_Compliance_Review.pdf.exe` (Claimed type: PDF; Detected type: Windows PE32 Executable; entropy 7.85/8.00)
- **Expected Result**: **CRITICAL Threat Score (88 / 100)**
- **Purpose**: **Demonstrates Threat Detection, Safe Static Attachment Inspection, and Explainability**.

### Scenario 3 — Coordinated Campaign (Operation DarkHydra / C-042)
- **File / ID**: `urgent_executive_wire_transfer_8491.eml` (`scenario-3-campaign`)
- **Subject**: *URGENT: Executive Wire Transfer Authorization #8491*
- **Sender**: `CEO Office <ceo-urgent@executive-board-corp.example>`
- **Campaign Cluster**: 16 distinct synthetic emails sharing:
  - ASN `AS64512` (*Threat Hosting Corp*)
  - IP Subnet `203.0.113.0/24`
  - Lookalike redirect domains (`bank-corp-update.example`)
  - Shared HTML template hash (`tmpl-a98f12c`)
  - Shared malware payload SHA-256 (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`)
- **Expected Result**: **CRITICAL Threat Score (96 / 100)** with **"Related Campaign Activity Detected (16 emails, 89% confidence)"**
- **Purpose**: **Demonstrates Multi-Email Campaign Correlation, Interactive Graph Visualization, and Evidence-Grounded Investigation Copilot**.

---

## 5. 10-Step Guided Demonstration Flow

Judges do not need to manually click through dozens of menus. The top HUD or navbar **"SIH Demo"** button triggers the live 10-step tour directly on the real forensic pipeline:

| Step | Action | Description | Primary View |
| :--- | :--- | :--- | :--- |
| **Step 1** | **Analyze Suspicious Email** | Ingest and parse RFC-822 headers, MIME structure, and body text in real time. | `/analysis/scenario-3-campaign` (Overview) |
| **Step 2** | **Show Threat Score** | View explainable Threat Score (96/100 — CRITICAL) computed from deterministic weighted signals. | Threat Score Gauge |
| **Step 3** | **Show "Why Flagged?"** | Inspect exact risk contributions (+25 wire fraud urgency, +30 executable payload, +18 lookalike domain). | Findings Breakdown |
| **Step 4** | **Authentication & IOCs** | Review SPF/DKIM/DMARC failures, envelope alignment errors, and extracted IOCs. | Indicators & Auth Tab |
| **Step 5** | **Reconstruct Relay Path** | Inspect hop-by-hop transmission order, relay latency delays, and untrusted infrastructure hop (`203.0.113.88`). | Headers & Relay Timeline |
| **Step 6** | **Infrastructure Attribution** | Attribution engine links originating IP to ASN `AS64512` (*Threat Hosting Corp*) and threat subnet. | Infrastructure Attribution Tab |
| **Step 7** | **Reveal Related Emails** | Cross-Email Workspace reveals 16 correlated messages sharing ASN, template hash, and Reply-To domain. | Cross-Email Workspace Tab |
| **Step 8** | **Open Campaign Graph** | Interactive force-directed graph renders multi-node cluster linking emails, ASN node, and payload hashes. | Investigation Graph Tab |
| **Step 9** | **Ask Investigation Copilot** | Query: *"Explain why these emails are believed to belong to the same campaign."* Copilot responds grounded strictly in evidence. | Investigation Copilot Tab |
| **Step 10** | **Generate Report** | Produce export-ready SOC incident report with executive summary, MITRE ATT&CK mapping, and chain-of-custody. | SOC Incident Report / Export |

---

## 6. Demo Reset

To restore the synthetic demo dataset and clear any analyst notes or overrides:
1. Click the **"Reset Demo"** button in the top navigation bar or inside the tour HUD.
2. Alternatively, click **"Reset Demo Baseline"** on the `/benchmarks` page.
3. Or invoke via API:
   ```bash
   curl -X POST http://127.0.0.1:8000/api/benchmark/demo-reset
   ```
*Guarantee*: Demo reset strictly clears synthetic demo keys and never touches production cases or real analytics.

---

## 7. Live Benchmark & Evaluation System

Navigate to **`/benchmarks`** (via Sidebar navigation or Navbar) to view and run live empirical benchmarks.

### Key Benchmark Metrics
- **Dataset**: 60 labelled SAFE synthetic samples (30 legitimate, 30 malicious).
- **Detection Performance**:
  - **Accuracy**: Measured live across all 60 samples.
  - **Precision**: TP / (TP + FP)
  - **Recall**: TP / (TP + FN)
  - **F1 Score**: Harmonic mean of Precision & Recall
  - **False-Positive Rate (FPR)**: Verified at 0.00% (zero false alerts on clean corporate emails).
  - **False-Negative Rate (FNR)**: Minimised across phishing, BEC, and malware delivery.
- **System Latency Benchmarks** (Wall-Clock Timings reported in Mean, Median P50, and P95):
  - **IOC Extraction Latency**
  - **Authentication Analysis Latency**
  - **Threat Scoring Latency**
  - **Total Pipeline Latency**
- **Dynamic Execution**: Clicking **"Run Live Evaluation"** re-evaluates all 60 samples from scratch, calculates authentic elapsed milliseconds, and updates the confusion matrix. Results are never hard-coded.

---

## 8. Air-Gapped & Offline Fallback Procedure

MailTraceAI is engineered for defense and government networks where external internet access is prohibited:
1. **Local DNS / Whois Fallback**: When external WHOIS/DNS servers are unreachable, MailTraceAI automatically switches to its local Public Suffix List (`tldextract`) and offline Brand Lexicon.
2. **Local Static Attachment Analysis**: File magic byte sniffing, entropy calculation, PE header parsing, and double-extension detection execute entirely in-process without cloud sandbox calls.
3. **Local NLP Classification**: The TF-IDF + Logistic Regression phishing classifier runs locally via scikit-learn without external LLM API dependencies.
4. **Deterministic Copilot Fallback**: If OpenAI/Anthropic/Gemini APIs are unreachable or offline, the Investigation Copilot switches automatically to the local Evidence Retrieval Template Engine, generating structured, hallucination-free answers grounded in the email's JSON evidence.
