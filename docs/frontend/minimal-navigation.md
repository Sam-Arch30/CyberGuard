# Section 35 — Minimal Navigation & Application Shell Architecture

This document details the minimal navigation architecture and standardized application shell implemented in Section 35 for **CYBERGUARD — AI Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System**.

---

## 1. Product Navigation Principle

CyberGuard is designed as a focused security investigation platform rather than a fragmented collection of disparate security tools.

```
                    CYBERGUARD
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
    Dashboard       Investigations      Reports
        │                │                │
        └────────────────┼────────────────┘
                         │
                      Settings
```

### Navigation ("Where Am I?") vs Workflow ("What Am I Doing?")
The primary distinction in Section 35 is between **Navigation** and **Investigation Workflow Stages**:

* **Navigation**: Answers *Where am I in the application?*
  * `Dashboard`
  * `Investigations`
  * `Reports`
  * `Settings`
* **Investigation Workflow Stages**: Answers *What am I doing with this security incident?*
  * `INGESTION` $\to$ `ANALYSIS` $\to$ `INVESTIGATION` $\to$ `RESPONSE` $\to$ `REPORT`

Specific capabilities—such as Email Analyzer, URL Analyzer, File Scanner, Threat Intelligence, MITRE Matrix, Attack Graph, Endpoint Sensors, and Network Telemetry—are **contextual tools within an investigation**, not permanent top-level sidebar destinations.

---

## 2. Core Information Architecture

```
Dashboard
│
├── Universal ingestion (Drop / Paste / Upload)
├── Recent investigations list
├── Active threats (DEFCON threat level & score)
└── System status
Investigations
│
├── Investigation list (/investigations)
│   ├── Severity filtering (Critical, High, Medium, Low, Safe)
│   ├── Search across subject, sender, and incident ID
│   └── Direct links to Incident Cases (/cases) & Ingestion History (/history)
└── Investigation workspace (/investigations/:id/:section)
    ├── Overview (Executive dossier & telemetry highlights)
    ├── Email Envelope (Header analysis, SPF/DKIM/DMARC alignment)
    ├── Payload & IOCs (Extracted links, file attachments, threat scoring)
    ├── OSINT & Infrastructure (WHOIS, ASN, GeoIP, lookalike domains)
    ├── Attack Path & Graph (Interactive Cytoscape graph & MITRE ATT&CK)
    └── Executive Dossier (Cryptographic chain of custody & report generation)
Reports
│
├── Report list (/reports)
└── Report detail (/reports/:reportId)
Settings
│
├── Appearance (/settings/appearance) — Calibrated theme engine & live preview
├── Detection (/settings/detection) — Risk score escalation thresholds
├── Integrations (/settings/integrations) — SIEM & alert webhook destinations
├── Agents (/settings/agents) — Endpoint telemetry sensor status & enrollment
└── Security (/settings/security) — PII masking, SHA-256 chain of custody, retention schedule
```

---

## 3. Application Shell (`<AppShell>`)

The application shell standardizes the layout, routing container, and telemetry context across the entire web application.

```
┌─────────────────────────────────────────────────────────────┐
│ CYBERGUARD       Dashboard                    ● System      │
├───────────────┬─────────────────────────────────────────────┤
│               │                                             │
│ Dashboard     │                                             │
│               │                                             │
│ Investigations│              PAGE CONTENT                   │
│               │         (Context-Aware Max Width)           │
│ Reports       │                                             │
│               │                                             │
│               │                                             │
│ ───────────── │                                             │
│ Settings      │                                             │
│ ● System OK   │                                             │
└───────────────┴─────────────────────────────────────────────┘
```

### Key Components

1. **`AppShell` (`src/components/layout/AppShell.tsx`)**:
   - Integrates `Sidebar`, `Topbar`, and main content viewport.
   - Embeds `AppShellErrorBoundary` using Section 34's `ErrorState` component to prevent route failures from crashing the shell.
   - Implements **Contextual Content Container Mode** (Section 43):
     - Standard pages (`/dashboard`, `/investigations`, `/reports`, `/settings`): `max-w-[1600px]` for readable typography and structured tables.
     - Investigation workspaces (`/investigations/:id/*`): `max-w-none` full-width mode to allocate maximum viewport area to interactive Cytoscape graphs, raw hex dumps, and multi-column telemetry.
   - Embeds the SIH Guided Tour HUD for zero-setup SOC evaluation.

2. **`Sidebar` (`src/components/layout/Sidebar.tsx`)**:
   - Visually quiet, typography-centered branding: `CYBERGUARD // AI THREAT DEFENSE`.
   - Permanent primary navigation: `Dashboard`, `Investigations`, `Reports`, and `Settings`.
   - Desktop collapsible state with local storage persistence (`cyberguard_sidebar_collapsed`).
   - Accessible tooltips on icon-only collapsed state with `placement="right"`.
   - Mobile responsive drawer with accessible backdrop and Escape key listener.
   - Real backend system health query (`/api/health`) and real enrolled agent count (`/api/v1/endpoint/agents`). Never displays hardcoded fake data.

3. **`Topbar` (`src/components/layout/Topbar.tsx`)**:
   - Responsive breadcrumb navigation (`Breadcrumbs.tsx`) auto-derived from route segments.
   - Contextual subtitle hierarchy indicating current SOC workspace.
   - Global indicator and hash search input linked directly to ingestion records.
   - Target switcher indicating currently active investigation subject and ID.
   - Real DEFCON threat ticker indicating active threat severity.
   - Section 34 theme selector with instant live preview.

4. **`Breadcrumbs` (`src/components/layout/Breadcrumbs.tsx`)**:
   - Semantic `<nav aria-label="Breadcrumb">` landmark.
   - Renders hierarchical trails such as:
     `Investigations / INV-2026-10492 / Analysis`
   - Automatically resolves human-readable section labels and short IDs.

5. **`InvestigationWorkflowNav` (`src/components/layout/InvestigationWorkflowNav.tsx`)**:
   - Renders the 5-stage lifecycle strip:
     `INGESTION → ANALYSIS → INVESTIGATION → RESPONSE → REPORT`
   - Visual state indicators: `COMPLETED`, `IN_PROGRESS`, `BLOCKED`, `UNAVAILABLE`.
   - Secondary sub-navigation tabs for investigation workspace inspection.

---

## 4. Route Inventory & Migration Map

| Route | Purpose | Status | Target Component | Notes |
|---|---|---|---|---|
| `/` | Application root | Redirect | `<Navigate to="/dashboard" />` | Canonical redirect |
| `/dashboard` | Primary SOC dashboard | **Canonical** | `<Dashboard />` | Ingestion, recent cases, system health |
| `/investigations` | Incident triage & dossiers | **Canonical** | `<InvestigationsListPage />` | Filterable list of active/stored investigations |
| `/investigations/:id` | Specific incident workspace | **Canonical** | `<InvestigationWorkspace />` | Defaults to overview section |
| `/investigations/:id/:section`| Section-specific view | **Canonical** | `<InvestigationWorkspace />` | overview, email, analysis, intelligence, investigation, report |
| `/investigations/:section` | Active session section view | **Canonical** | `<InvestigationWorkspace />` | Retains active investigated target |
| `/reports` | Forensic report catalog | **Canonical** | `<Reports />` | Evidentiary PDF generator & viewer |
| `/reports/:id` | Specific report view | **Canonical** | `<Reports />` | Direct deep-link to report dossier |
| `/settings` | Platform & SOC settings | **Canonical** | `<Settings />` | Structural settings root |
| `/settings/:tab` | Sub-tab settings | **Canonical** | `<Settings />` | appearance, detection, integrations, agents, security |
| `/investigate` | Legacy investigate route | Redirect | `<Navigate to="/investigations" />` | Backward compatible |
| `/investigate/:section` | Legacy section route | Compatibility | `<InvestigationWorkspace />` | Preserves existing URLs |
| `/investigate/:id/:section` | Legacy full route | Compatibility | `<InvestigationWorkspace />` | Preserves existing deep links |
| `/overview`, `/email`, `/analysis`, etc. | Top-level shortcuts | Compatibility | `<InvestigationWorkspace />` | Preserves existing hotkeys |
| `/analyze` | Universal Ingestion tool | Contextual Tool | `<AnalyzeEmail />` | Deep-link from Dashboard and Investigations |
| `/cases`, `/cases/:id` | Incident Cases & Detail | Contextual Tool | `<Cases />`, `<CaseDetail />` | Contextual investigation deep link |
| `/history` | Ingestion History | Contextual Tool | `<InvestigationHistory />` | Contextual investigation search |
| `/endpoints` | Endpoint Agent Manager | Contextual Tool | `<EndpointAgentView />` | Contextual device inspection |
| `/network-security` | Network Telemetry Tool | Contextual Tool | `<NetworkSecurityView />` | Contextual investigation tool |
| `/auth-security` | Identity & Auth Tool | Contextual Tool | `<AuthSecurityView />` | Contextual investigation tool |
| `/file-security` | File & Malware Sandbox | Contextual Tool | `<FileSecurityView />` | Contextual investigation tool |
| `/url-intelligence` | URL & Phishing Inspector | Contextual Tool | `<UrlSecurityView />` | Contextual investigation tool |
| `/campaigns` | Campaign Intelligence | Contextual Tool | `<CampaignIntelligence />` | Correlated campaign clustering |
| `/osint` | Threat OSINT Intelligence | Contextual Tool | `<ThreatIntelligence />` | Global feed lookup |
| `/access-denied` | 403 Access Restricted | **Canonical** | `<AccessDeniedPage />` | Minimal, non-leaking security guard |
| `*` | 404 Route Not Found | Fallback | `<NotFoundPage />` | Minimal, restrained error view |

---

## 5. Security & Access Control

- **Presentation vs Authorization**: Frontend navigation hiding is purely presentational. All underlying REST APIs (`/api/emails/*`, `/api/incidents/*`, `/api/reports/*`, `/api/v1/endpoint/*`) require server-side session authentication and authorization tokens.
- **Access Denied (403)**: Renders a minimal security view without disclosing internal server architecture, sensitive incident details, or resource metadata.
- **Not Found (404)**: Renders a restrained, professional view with a button returning the operator to `/dashboard`.

---

## 6. Theme & Responsive Design Integration

- **Theme Engine**: The application shell inherits Section 34 tokens across all four themes:
  - **Olive**: Classic tactical SOC dark theme (`#181c14`, `#9ea67e`).
  - **Sakura**: Soft forensic dark theme (`#1a1518`, `#d99cb1`).
  - **Paper**: High-contrast, clean legal light theme (`#f7f7f6`, `#324d3e`).
  - **Midnight**: Deep monochromatic navy theme (`#0c1017`, `#4a7bb0`).
- **Responsive Layout**:
  - Desktop ($\ge 1024\text{px}$): Persistent sidebar with collapsible toggle.
  - Mobile & Tablet ($< 1024\text{px}$): Off-canvas navigation drawer with backdrop, focus trapping, and Escape key dismissal.
