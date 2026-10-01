# Section 16 — URL, Domain & Website Intelligence Engine Architecture

## 1. Executive Summary & Target Architecture

Section 7 upgrades CyberGuard with a dedicated, explainable, and SSRF-defended **URL, Domain & Website Intelligence Engine**. The engine ingests URLs and domains directly from users, extracts them from emails and text artifacts, normalizes them using standards-aware parsers, and subjects them to a strict **Passive-First** evaluation pipeline. Outbound network interaction is isolated behind a centralized network safety gate (`SafeHttpClient`), preventing arbitrary HTTP fetches from accessing private, loopback, link-local, or cloud metadata endpoints.

```mermaid
flowchart TD
    subgraph Ingestion["Ingestion & Artifact Storage"]
        RawURL["Submitted or Extracted URL / Domain"]
        ArtSvc["Universal Ingestion Gateway / Storage"]
        RawURL --> ArtSvc
        ArtSvc --> URLArtifact["URL / Domain Artifact (Durable Storage)"]
    end

    subgraph Passive["Phase 1: Passive Analysis (Zero Network I/O)"]
        URLArtifact --> PassiveURL["PassiveURLAnalyzer"]
        PassiveURL --> SyntacticCheck["Syntax, Scheme & Userinfo Inspection"]
        PassiveURL --> IPHostCheck["IP-Literal Host & Port Verification"]
        PassiveURL --> StructCheck["Excessive Subdomains & Path Keywords"]
        PassiveURL --> DeceptiveCheck["Deceptive Subdomain Hierarchy & Punycode"]
    end

    subgraph DomainSec["Phase 2: Domain Infrastructure Intelligence"]
        SyntacticCheck --> ExtractedHost["Extracted Registrable Domain"]
        ExtractedHost --> DomainAnalyzer["DomainIntelligenceAnalyzer"]
        DomainAnalyzer --> LookalikeEng["Lookalike Impersonation Engine (Levenshtein & Homoglyphs)"]
        DomainAnalyzer --> DNSResolve["DNS Resolver (A, AAAA, MX, NS, TXT)"]
        DomainAnalyzer --> RDAPEng["RDAP / WHOIS Age & Redaction Service"]
        DomainAnalyzer --> ThreatIntel["Cached Threat Intelligence Engine"]
    end

    subgraph SafetyGate["Phase 3: Centralized Network Safety Gate"]
        DNSResolve --> SafeGate["SafeHttpClient Network Safety Gate"]
        SafeGate -- "Blocked IP / Internal / Loopback" --> BlockedFinding["CRITICAL: BLOCKED_INTERNAL_DESTINATION"]
        SafeGate -- "Active Inspection Disabled" --> PassiveComplete["ACTIVE_ANALYSIS_DISABLED (Clean Exit)"]
        SafeGate -- "Public IP & Allowed Scheme" --> ControlledFetch["Controlled Active HTTP Fetch"]
    end

    subgraph ActiveSec["Phase 4: Observational Website Inspection"]
        ControlledFetch --> RedirectLoop["Per-Hop SSRF Redirect Interceptor (Max 5)"]
        RedirectLoop --> TLSEvidence["TLS Certificate Handshake & SAN Inspection"]
        RedirectLoop --> StaticHTML["WebsiteInspector (Static HTML Parser)"]
        StaticHTML --> FormsCheck["Form Method & Password Field Detection"]
        StaticHTML --> CrossDomain["Cross-Domain Action Destination Check"]
        StaticHTML --> DownloadCheck["Download Reference Discovery (Zero Execution)"]
    end

    subgraph Persistence["Phase 5: Canonical Knowledge Graph Persistence"]
        BlockedFinding --> PersistModels["AnalysisRun, Findings, Evidence, Indicators, Relationships"]
        PassiveComplete --> PersistModels
        TLSEvidence --> PersistModels
        FormsCheck --> PersistModels
        CrossDomain --> PersistModels
        DownloadCheck --> PersistModels
        PersistModels --> SecurityGraph[("Security Knowledge Graph")]
    end
```

---

## 2. Passive-First URL Analysis

Every URL submitted to CyberGuard is analyzed **passively before any network request is initiated**. A URL produces structured forensic findings without sending packets to external networks.

### Implemented Signals & Heuristics
1. **Standards-Aware URL Decomposition**: Uses standard library `urllib.parse.urlsplit` to safely parse `scheme`, `netloc`, `path`, `query`, `fragment`, and `userinfo`.
2. **Embedded Userinfo / Credentials (`URL_USERINFO_PRESENT`)**: Detects username or password embedded in the authority segment (e.g. `http://admin:secret@malicious.test/`). Severity: `HIGH`.
3. **IP-Literal Hostnames (`IP_LITERAL_HOST`)**: Distinguishes IPv4 (`198.51.100.1`) and bracketed IPv6 (`[2001:db8::1]`) hostnames from registered domain names. Severity: `MEDIUM`.
4. **Non-Standard Network Ports (`NON_STANDARD_PORT`)**: Identifies ports other than 80 (HTTP) or 443 (HTTPS) (e.g. `:8080`, `:8443`, `:2082`, `:1337`). Severity: `LOW`.
5. **Excessive Subdomain Depth (`EXCESSIVE_SUBDOMAINS`)**: Flags hostnames containing $\ge 3$ subdomain labels (e.g. `a.b.c.evil.test`). Severity: `LOW`.
6. **Deceptive Subdomain Hierarchy (`DECEPTIVE_SUBDOMAIN_HIERARCHY`)**: Detects attacks where protected brand names appear as subdomain tokens before an unrelated registered base domain (e.g., `https://paypal.com.account-update.net/`). The engine correctly identifies `account-update.net` as the registrable domain and flags brand deception. Severity: `HIGH`.
7. **Punycode / IDN Host (`PUNYCODE_DOMAIN`)**: Identifies `xn--` encoded labels and resolves underlying Unicode representations. Severity: `LOW`.
8. **Suspicious Path Tokens (`SUSPICIOUS_PATH_TOKENS`)**: Identifies security-sensitive path segments (`login`, `admin`, `verify`, `account`, `banking`, `auth`, `password`). Severity: `LOW`.
9. **Suspicious Download Extension (`SUSPICIOUS_DOWNLOAD_EXTENSION`)**: Detects URLs targeting hazardous executables, scripts, or archives (`.exe`, `.scr`, `.bat`, `.apk`, `.msi`, `.iso`, `.dmg`, `.zip`). Severity: `HIGH`.
10. **Known URL Shortener (`KNOWN_URL_SHORTENER`)**: Identifies masking services (`bit.ly`, `tinyurl.com`, `t.co`, `cutt.ly`, etc.). Severity: `LOW`.
11. **Non-Web Schemes (`NON_HTTP_SCHEME`)**: Inspects non-HTTP schemes (`file:`, `javascript:`, `data:`, `ftp:`) statically without execution.

---

## 3. Domain Extraction & Public Suffix List (PSL)

Domain extraction uses `tldextract` to separate subdomains, registrable domain bases, and multi-part public suffixes:
- `https://secure.banking.service.co.uk/account` $\longrightarrow$ Registrable Domain: `service.co.uk`, Subdomain: `secure.banking`.
- `https://portal.health.gov.au/login` $\longrightarrow$ Registrable Domain: `health.gov.au`, Subdomain: `portal`.
- RFC-2606 test domains (`.test`, `.example`, `.invalid`, `.local`) are preserved without degradation.

---

## 4. IDN & Homoglyph Lookalike Engine

The engine identifies typosquatting and visual homoglyphs while preventing false positives against legitimate international domains:
1. **Leet-Speak & Character Substitutions**: Reverses digit substitutions (`0` $\rightarrow$ `o`, `1` $\rightarrow$ `l`, `3` $\rightarrow$ `e`, `5` $\rightarrow$ `s`, `@` $\rightarrow$ `a`).
2. **Unicode Homoglyphs**: Transliterates Cyrillic, Greek, and Latin full-width characters to standard Latin ASCII (e.g. Cyrillic `а` \u0430 $\rightarrow$ `a`).
3. **Contextual Reference Basis**: Lookalike comparisons require a legitimate reference domain. Domains are evaluated against protected targets (`paypal.com`, `microsoft.com`, `google.com`, `apple.com`, `amazon.com`, `chase.com`, `netflix.com`, etc.) or incident-specific brands.
4. **False-Positive Controls**: Benign international domains (e.g. `münchen.de`) and official brand domains are never flagged as impersonation.

---

## 5. DNS Infrastructure Intelligence & Knowledge Graph

DNS queries for A, AAAA, MX, NS, and TXT records populate security knowledge graph relationships:

```mermaid
graph LR
    URL["URL: https://sample-phish.test/login"] -- HAS_HOST --> DOM["Domain: sample-phish.test"]
    DOM -- RESOLVES_TO --> IP["IP: 198.51.100.50"]
    DOM -- MAIL_EXCHANGER --> MX["Domain: mail.sample-phish.test"]
    DOM -- USES_NAMESERVER --> NS["Domain: ns1.sample-phish.test"]
```

| Source Entity | Relationship Type | Target Entity | Confidence | Description |
|---|---|---|---|---|
| `URL` | `HAS_HOST` | `DOMAIN` | 1.0 | Maps URL to its authority host |
| `DOMAIN` | `RESOLVES_TO` | `IP` | 1.0 | Derived from DNS A and AAAA records |
| `DOMAIN` | `MAIL_EXCHANGER` | `DOMAIN` | 1.0 | Derived from DNS MX records |
| `DOMAIN` | `USES_NAMESERVER` | `DOMAIN` | 1.0 | Derived from DNS NS records |
| `URL` | `REDIRECTS_TO` | `URL` | 1.0 | Step-by-step HTTP redirection hops |
| `URL` | `SUBMITS_TO` | `URL` | 1.0 | Cross-domain form action targets |
| `URL` | `REFERENCES` | `URL` | 1.0 | Static script, favicon, and download candidates |

---

## 6. Centralized Network Safety & SSRF Defenses

Active website analysis is a major SSRF attack surface. CyberGuard strictly mandates that **no analyzer may issue outbound HTTP requests directly**. All active requests pass through `SafeHttpClient`.

### What CyberGuard Will Connect To
- Externally routable, public IPv4 and IPv6 addresses.
- HTTP (port 80) and HTTPS (port 443) destinations (or explicitly specified safe external non-standard ports).
- Destination domains whose **every** resolved IP address is verified as public and safe.

### What CyberGuard Will Refuse To Connect To
- **Loopback Networks**: `127.0.0.0/8`, `::1`, `localhost`.
- **Private Networks (RFC 1918 & ULA)**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `fd00::/8`.
- **Link-Local Networks**: `169.254.0.0/16`, `fe80::/10`.
- **Cloud Metadata Services**: `169.254.169.254`, `169.254.170.2`, `fd00:ec2::254`, `metadata.google.internal`, `metadata.internal`, `instance-data`.
- **Multicast & Reserved**: `224.0.0.0/4`, `ff00::/8`, `0.0.0.0/8`, `::`.
- **Carrier-Grade NAT (CGNAT)**: `100.64.0.0/10`.
- **Non-HTTP Schemes**: `file:`, `javascript:`, `data:`, `gopher:`, `ftp:`, `ssh:`.

### Step-by-Step Redirect Validation
Automatic HTTP client redirect following (`follow_redirects=True`) is **strictly forbidden**. Redirection is intercepted manually in a controlled loop:
1. HTTP 301/302/303/307/308 response intercepted.
2. `Location` header extracted and resolved against current URL via `urllib.parse.urljoin`.
3. Destination scheme validated (`http`/`https` only).
4. Destination host resolved and **every resolved IP re-verified against the SSRF safety gate**.
5. Hop index evaluated against `max_redirects` (default: 5).
6. Outbound request executed only if verified safe. Redirects to `127.0.0.1` or `169.254.169.254` are aborted with `BLOCKED_INTERNAL_DESTINATION`.

### DNS Preflight & Rebinding Limitations
- **Preflight Verification**: `resolve_and_verify_destination` queries system DNS and verifies that all returned records are safe public IPs before any connection is attempted.
- **Dual-Homed DNS**: Domains resolving to both a public IP and a private IP are rejected.
- **DNS Rebinding Consideration**: When using standard socket/HTTP stacks without low-level TCP connection IP pinning, an adversary who controls their authoritative DNS server could return a public IP during preflight and a private IP during connection establishment. In environments requiring strict rebinding immunity, DNS resolution should be directed through a local validating DNS proxy or destination socket pinning.

---

## 7. TLS Certificate & Registration Intelligence

1. **Safe TLS Inspection**: Establishes a read-only TLS handshake using the standard Mozilla CA bundle (`certifi.where()`). Extracts Subject Common Name, Organization, Issuer, Validity Dates, and Subject Alternative Names (SANs).
2. **Error Differentiation**: Differentiates between configuration errors and security events:
   - `EXPIRED_CERTIFICATE`: Certificate validity date expired.
   - `HOSTNAME_MISMATCH`: Certificate does not cover hostname.
   - `SELF_SIGNED_CERTIFICATE`: Subject matches Issuer without trusted root.
   - `TLS_CONNECTION_ERROR`: Handshake failure or protocol mismatch.
3. **Registration & Domain Age**: Queries RDAP (RFC 7480-7484) with WHOIS fallback. If registration date is within 30 days, generates `RECENTLY_REGISTERED_DOMAIN`. Redacted WHOIS/RDAP generates neutral `REGISTRATION_DATA_REDACTED` with `SAFE` severity.

---

## 8. Static HTML Analysis & Credential Harvesting

Web content retrieved by `SafeHttpClient` is parsed statically with standard library `HTMLParser`. **Zero JavaScript is executed; zero forms are submitted**.
- **Page Title & Meta Tags**: Statically extracted.
- **Password Input Detection (`PASSWORD_FIELD_DETECTED`)**: Flags `<input type="password">`.
- **Login Form Detection (`LOGIN_FORM_DETECTED`)**: Identifies interactive authentication forms.
- **Cross-Domain Form Action (`CROSS_DOMAIN_FORM_ACTION`)**: Discovers forms posting user credentials to unrelated third-party domains (e.g. host: `login.bank.test`, action: `https://evil-harvest.net/drop`). Creates `SUBMITS_TO` relationship.
- **Credential Harvesting Indicators (`CREDENTIAL_HARVESTING_INDICATORS`)**: Synthesized when password inputs coincide with brand impersonation or cross-domain form actions.
- **Discovered Downloads**: HTML references to executables or archives are extracted as candidate Indicators and linked via `REFERENCES` relationships without downloading payloads.

---

## 9. External Threat Intelligence & Caching

1. **Fact vs. Opinion Separation**: External provider verdicts (VirusTotal, AlienVault OTX, URLhaus) are preserved as distinct `THREAT_INTELLIGENCE` evidence records with timestamps, confidence, and provider provenance.
2. **In-Memory TTL Caching**: Results are cached with expiration timestamps (`expires_at`) to avoid redundant API consumption.
3. **Rate Limiting Handling**: When rate-limited, the engine reports `THREAT_INTEL_RATE_LIMITED` rather than treating missing data as benign.

---

## 10. Re-Analysis & Observation History

Re-analyzing an existing URL or domain artifact creates a new independent `AnalysisRunModel` record:
- Analysis #1: Target resolves to `198.51.100.10`.
- Analysis #2: Target resolves to `203.0.113.25`.
Both runs, findings, and evidence items remain durable in the database, allowing temporal infrastructure tracking and correlation.
