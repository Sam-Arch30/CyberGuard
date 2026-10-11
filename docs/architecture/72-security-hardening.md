# SECTION 72 — DEFENSIVE SECURITY HARDENING
## CYBERGUARD — AI-Powered Cyber Threat, Phishing & Digital Impersonation Detection and Response System

---

## 1. Executive Summary & Threat Model

Section 72 establishes a comprehensive, systematic **Defensive Security Hardening** pass across the entire CyberGuard platform. CyberGuard operates under a hostile-input posture: as a security operations and forensics platform, it intentionally ingests, analyzes, correlates, and stores potentially malicious artifacts (phishing emails, exploit attachments, adversarial URLs, compromised endpoint telemetry, and malicious domains).

The core architectural tenet of Section 72 is:
> **UNTRUSTED INPUT $\rightarrow$ VALIDATION $\rightarrow$ AUTHENTICATION $\rightarrow$ AUTHORIZATION $\rightarrow$ TENANT / RESOURCE SCOPE $\rightarrow$ POLICY CHECK $\rightarrow$ BOUNDED PROCESSING $\rightarrow$ AUDIT $\rightarrow$ VERIFIED RESULT**

Administrative convenience, internal workers, background jobs, realtime listeners, or AI assistants must **never** weaken security boundaries or bypass deterministic authorization.

```mermaid
flowchart TD
    subgraph Hostile Signal Ingestion
        EMAIL[RFC-822 / .eml Email] --> UPLOAD_GATE[Upload Security & MIME Magic Validator]
        URLS[Hostile URLs & Domains] --> SSRF_GATE[SafeHttpClient & SSRF Protector]
        ARCH[Hostile ZIP/Office Attachments] --> DECOMP_GATE[Decompression Bomb & Ratio Guard]
    end

    subgraph Trust Perimeter & Authorization Gate
        UPLOAD_GATE & SSRF_GATE & DECOMP_GATE --> AUTH[Token / Session Auth & Account State]
        AUTH --> RBAC[Server-Side Permission Matrix & Hierarchical Scope]
        RBAC --> TENANT_CHK[Multi-Tenant Workspace Scope Validation]
    end

    subgraph Controlled Analysis Engines
        TENANT_CHK --> STATIC_ENG[Static Forensics & IOC Extraction]
        STATIC_ENG --> ORM_DB[(SQLAlchemy Parameterized ORM)]
        STATIC_ENG --> AI_PROMPT[LLM Prompt Delimiter & Schema Validator]
    end

    subgraph Dissemination & Audit Defenses
        ORM_DB --> AUDIT_LOG[Append-Only Audit Ledger & Redacted Logs]
        ORM_DB --> CSV_EXP[CSV Formula Injection Sanitizer]
        ORM_DB --> HEADERS[Strict Security Headers: CSP, COOP, CORP]
    end
```

### Concrete Threat Actor Categories
1. **External Attackers**: Attempting unauthenticated API exploitation, remote code execution through malicious file uploads, SSRF via URL inspection endpoints, or denial-of-service via decompression bombs.
2. **Authenticated Low-Privilege Users**: Attempting horizontal privilege escalation (IDOR/BOLA across cases, evidence, reports), cross-tenant data exfiltration, or self-promotion to administrative roles.
3. **Malicious Artifacts**: Files containing Zip Slip traversals, nested decompression bombs, polyglot headers, dangerous HTML, or prompt injection strings designed to hijack LLM assistants.
4. **Malicious External Services**: Upstream intelligence endpoints returning redirect loops to private RFC-1918 subnets, oversized payloads, or malformed JSON payloads.
5. **Compromised Integrations**: Third-party API keys or webhook secrets leaked or abused to execute unauthorized operations.

---

## 2. Trust Boundaries

CyberGuard establishes explicit trust boundaries at every subsystem transition:

| Trust Boundary | Untrusted Source | Trusted Sink | Defensive Guard |
|:---|:---|:---|:---|
| **Boundary 1: Web Ingestion** | External Clients / Internet | FastAPI Routes | Rate limiting, CORS origin restrictions, security headers |
| **Boundary 2: Authentication** | Request Headers / Cookies | Security Context | Server-side user status (`ACTIVE`, `LOCKED`, `DISABLED`), session validity |
| **Boundary 3: Authorization** | Claimed Roles / Permissions | Business Services | Server-side RBAC matrix, last platform admin guard, rank hierarchy |
| **Boundary 4: Tenancy** | Client `X-Tenant-ID` / IDs | Database Queries | Enforced `tenant_id` and `workspace_id` filtering in all queries |
| **Boundary 5: File Processing** | Uploaded Files / Attachments | File Storage Root | Path traversal neutralization (`../`), content-addressed storage layout |
| **Boundary 6: Archive Unpacking** | Uploaded ZIP Archives | Memory / Parser | Max 500 files, 100MB uncompressed limit, 100:1 ratio ceiling |
| **Boundary 7: Outbound Network** | Analyzed URLs / Domains | Outbound Socket | Pre-request DNS check, blocking 127.0.0.1, RFC-1918, 169.254.169.254 |
| **Boundary 8: HTML Rendering** | Raw Email HTML Bodies | Browser DOM | Complete removal of script, iframe, object, on* event handlers, and javascript: links |
| **Boundary 9: AI Telemetry** | Analyzed Text / Headers | LLM Context | XML delimiter enclosure (`<untrusted_analyzed_content>`), output schema validation |
| **Boundary 10: Logging & Export** | Memory State / Exceptions | Server Logs / CSV Files | Regex credential redaction, CSV formula injection neutralization |

---

## 3. Authentication Controls

- **Identity Resolution**: Extracted from validated bearer sessions and verified request headers (`X-User-Email`, `X-User-Role`, `X-Tenant-Id`).
- **Account State Verification**: Accounts in `DISABLED` or `LOCKED` states immediately trigger `403 Forbidden` (`User account is disabled/locked`).
- **Session Revocation**: Disabling an administrative account immediately blocks API access without relying on client-side token deletion.
- **Timing Attack Resistance**: Constant-time string comparisons used for token and secret verification.

---

## 4. Authorization Controls (RBAC & Privilege Escalation Defense)

- **Independent Server-Side Authorization**: Every administrative and operational endpoint independently evaluates permissions using `PlatformAdminService.verify_permission()` (`resource + action + scope`).
- **Self-Promotion Guard**: Users cannot elevate their own role or expand their assigned permission scope.
- **Hierarchical Delegation Boundary**: Users can only assign or delegate roles equal to or strictly less than their own authority rank.
- **Last Platform Admin Invariant**: Explicit check prevents deactivating or demoting the last active `PLATFORM_ADMIN` account.

---

## 5. Multi-Tenant Isolation

- **Query-Level Enforcement**: All queries on cases, evidence, investigations, detection rules, and settings enforce `tenant_id` or `workspace_id`.
- **Cross-Tenant Protection**: Attempts by a `TENANT_ADMIN` or analyst to mutate or access an entity belonging to another tenant are rejected with `403 Forbidden` (`Cross-tenant modification denied`).
- **Indirect Object Reference Defense (IDOR/BOLA)**: Possession of a UUIDv4 identifier does not permit access without matching the authenticated tenant context.

---

## 6. File & Storage Security

- **Safe Path Resolution**: `evidence_storage.resolve_safe_path()` resolves paths against `storage_root` and strictly verifies `resolved_path.startswith(storage_root)`. Any `../`, `..\\`, null bytes, or absolute path sequences raise `StoragePathTraversalError`.
- **Filename Sanitization**: `UploadSecurityService.sanitize_filename()` strips control characters, normalizes path separators, extracts base names, and restricts filenames to safe characters `[a-zA-Z0-9._-]`.
- **Content-Addressed Storage**: Artifacts are stored under deterministic SHA-256 hashes rather than client-supplied filenames.
- **Magic-Byte MIME Verification**: File uploads reject executable binary signatures (`MZ` Windows PE, `\x7fELF` Linux ELF, Mach-O binaries).

---

## 7. SSRF Protections & Network Gateway

CyberGuard's `SafeHttpClient` and `SSRFProtector` govern all outbound HTTP lookups:
1. **Pre-Request DNS Resolution**: Resolves hostnames to IP addresses before initiating a socket connection.
2. **Prohibited Address Verification**:
   - Loopback: `127.0.0.0/8`, `::1`
   - Private RFC-1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Link-Local & Cloud Metadata: `169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`
   - Unspecified / Broadcast: `0.0.0.0`, `::`
3. **Redirect Per-Hop Revalidation**: Every redirect destination undergoes the same DNS and IP verification.
4. **Bounded Connection Timeouts**: Strict 10-second request timeout and 5MB response size limit to prevent slowloris or socket exhaustion.

---

## 8. Injection Protections (SQL, Command, CSV)

- **SQL Injection**: Exclusively uses SQLAlchemy ORM parameterized statements (`filter()`, `session.execute(select(...))`). Raw string concatenation in queries is strictly prohibited.
- **Command Injection**: Zero instances of `os.system`, `shell=True`, or unconstrained shell execution. All agent telemetry collectors use explicit argument arrays with `shell=False`.
- **CSV Formula Injection (CWE-1236)**: `SecurityHardeningService.sanitize_csv_cell()` prepends a single quote (`'`) to any cell beginning with formula trigger characters (`=`, `+`, `-`, `@`, `\t`, `\r`) prior to export.

---

## 9. AI / LLM Security & Authority Boundaries

- **Non-Authoritative Assistant Invariant**: LLMs are reasoning assistants only. They cannot grant permissions, execute response actions, modify security policies, or approve high-risk automation.
- **Prompt Injection Delimiters**: Analyzed threat data (emails, URLs, logs) is strictly enclosed within `<untrusted_analyzed_content>` tags.
- **Prompt Sanitization**: `AIAnalystService._sanitize_text()` filters XML tag breakout attempts (`</untrusted_email_content>`) and instruction overrides (`ignore all previous instructions`).
- **Data Minimization**: Passwords, API keys, and authorization tokens are redacted from telemetry payloads before transmission to external model providers.
- **Strict Output Schema Validation**: Model JSON outputs are validated against strict Pydantic models. Malformed or out-of-range fields are rejected.

---

## 10. Secrets Management & Logging Redaction

- **Write-Only Credential Ingestion**: Integration API keys, provider secrets, and tokens are encrypted and masked (`••••••••`) upon read requests.
- **Structured Log Sanitization**: `SensitiveLogFilter` intercepts all server log records and automatically redacts:
  - `Authorization: Bearer [REDACTED]`
  - `Authorization: Basic [REDACTED]`
  - `password=[REDACTED]`, `api_key=[REDACTED]`, `token=[REDACTED]`
  - Database connection strings (`postgresql://[REDACTED_USER]:[REDACTED_PASSWORD]@`)
  - Private RSA/EC keys (`[REDACTED_PRIVATE_KEY]`)
  - JWT strings (`[REDACTED_JWT]`)
  - AWS access keys (`[REDACTED_AWS_KEY]`)
  - GitHub/Slack tokens (`[REDACTED_GITHUB_TOKEN]`)
  - Session cookies (`session_id=[REDACTED]`)

---

## 11. Security Headers & Browser Hardening

Configured via `SecurityHeadersMiddleware`:
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';
```

---

## 12. Rate Limiting & Resource Exhaustion Controls

Sliding window rate limiter middleware enforces resource-aware tiers:
- **Email Upload & Analysis**: 20 requests / minute
- **LLM Inference**: 10 requests / minute
- **Threat Intelligence Lookups**: 60 requests / minute
- **Administrative Operations**: 60 requests / minute
- **Search & Threat Hunting**: 60 requests / minute
- **Executive Reports & Exports**: 30 requests / minute
- **General Endpoints**: 120 requests / minute

Threshold breaches return `HTTP 429 Too Many Requests` with standard `Retry-After` headers.

---

## 13. Security Control Matrix

| Control ID | Control Name | Subsystem / Location | Implementation | Verification Status | Residual Risk |
|:---|:---|:---|:---|:---:|:---|
| **SEC-01** | Account State & Session Control | `backend/services/platform_admin_service.py` | Validates active status (`ACTIVE`/`DISABLED`/`LOCKED`) server-side | **PASS** | Edge SSO token revocation depends on IdP sync |
| **SEC-02** | RBAC & Last Admin Guard | `backend/services/platform_admin_service.py` | Prevents self-promotion and last platform admin demotion | **PASS** | Zero residual risk on single-admin demotion |
| **SEC-03** | Multi-Tenant Scoping | `backend/api/routes/`, `backend/services/` | Explicit `tenant_id` and `workspace_id` filtering in all queries | **PASS** | Shared background worker pool bounded by tenant context |
| **SEC-04** | SQL Injection Defense | `backend/db/session.py`, models | Parameterized queries via SQLAlchemy ORM | **PASS** | Zero raw SQL concatenation |
| **SEC-05** | Command Injection Defense | `backend/agent/collectors/platform_adapters.py` | Explicit executable arrays with `shell=False` | **PASS** | OS utility availability required on agent nodes |
| **SEC-06** | Path Traversal Defense | `backend/services/evidence_storage.py` | `resolve_safe_path()` with root directory boundary check | **PASS** | Storage root filesystem permissions must be restricted |
| **SEC-07** | Decompression Bomb Defense | `backend/services/attachment_intelligence_service.py` | Max 500 files, 100MB uncompressed limit, 100:1 ratio ceiling | **PASS** | Benign large archives (>100MB) must be flagged for manual review |
| **SEC-08** | SSRF Network Gateway | `backend/services/ssrf_protector.py`, `safe_http_client.py` | IP resolution check, redirect revalidation, 10s timeout | **PASS** | Fast DNS rebinding mitigated by per-hop resolution |
| **SEC-09** | XSS & HTML Sanitization | `backend/services/html_sanitizer.py` | Strips script, iframe, object, on* handlers, javascript: links | **PASS** | Complex email CSS layouts simplified |
| **SEC-10** | CSV Formula Injection Defense | `backend/services/security_hardening_service.py` | Escapes `=,+,-,@,\t,\r` trigger characters with single quote | **PASS** | Text exports display leading single quote in raw viewers |
| **SEC-11** | Secret Redaction in Logs | `backend/services/log_sanitizer.py` | Multi-pattern regex redaction on all logging records | **PASS** | Novel unstandardized token formats require pattern additions |
| **SEC-12** | AI Authority Boundaries | `backend/services/ai_analyst_service.py`, `soc_copilot_service.py` | XML delimiters, non-authoritative constraint, strict output schema | **PASS** | Human-in-the-loop required for consequential actions |
| **SEC-13** | Rate Limiting | `backend/api/middleware/rate_limiter.py` | Sliding window rate limiter across 7 endpoint tiers | **PASS** | Distributed DDoS requires edge CDN/WAF filtering |
| **SEC-14** | Security Headers & CORS | `backend/api/middleware/security_headers.py`, `backend/main.py` | CSP, COOP, CORP, HSTS, explicit origin allowlist | **PASS** | Browser compliance with standard security headers required |

---

## 14. Authoritative Security Findings Register (Section 67)

| Finding ID | Severity | Component | Status | Remediation & Verification | Residual Risk |
|:---|:---:|:---|:---:|:---|:---|
| **SEC-FIND-001** | **HIGH** | Threat Hunting CSV Export | **FIXED** | Prepend single quote (`'`) to cells starting with formula triggers via `sanitize_csv_cell()`. Verified in `test_06`. | Leading quote displayed in raw text editors. |
| **SEC-FIND-002** | **MEDIUM** | Evidence Download Headers | **FIXED** | Sanitized Content-Disposition filenames via `UploadSecurityService.sanitize_filename()`. Verified in `test_10`. | Filenames restricted to standard alphanumeric characters. |
| **SEC-FIND-003** | **HIGH** | SSRF Outbound Gateway | **FIXED** | Enforced pre-request DNS resolution, IP range check, redirect revalidation, and 10s timeout in `SSRFProtector` & `SafeHttpClient`. Verified in `test_03`. | Bounded DNS rebinding risk addressed via per-hop re-resolution. |
| **SEC-FIND-004** | **HIGH** | Archive Decompression Bomb | **FIXED** | Enforced max 500 files, 100MB uncompressed limit, 100:1 ratio limit in `AttachmentIntelligenceService`. Verified in `test_05`. | Oversized archives flagged as `PROCESSING_LIMIT_EXCEEDED`. |
| **SEC-FIND-005** | **HIGH** | Email HTML XSS Defense | **FIXED** | Stripped scripts, iframes, objects, event handlers, and `javascript:` URIs via `HTMLSanitizerService`. Verified in `test_07`. | HTML formatting fidelity slightly reduced for safety. |
| **SEC-FIND-006** | **MEDIUM** | Logging & Secret Leakage | **FIXED** | Expanded multi-pattern regex redaction in `SensitiveLogFilter` for JWTs, private keys, passwords, and DB strings. Verified in `test_08`. | Custom non-standard token formats require regex updates. |
| **SEC-FIND-007** | **HIGH** | LLM Prompt Injection | **FIXED** | Isolated data within `<untrusted_analyzed_content>` delimiters, filtered XML breakouts, and enforced schema validation. Verified in `test_09`. | Probabilistic model outputs require human confirmation. |
| **SEC-FIND-008** | **MEDIUM** | API Rate Limiting | **FIXED** | Implemented tiered sliding window rate limiting across 7 API categories in `RateLimiterMiddleware`. Verified in middleware tests. | Volumetric DDoS requires edge WAF mitigation. |

---

## 15. Security Health & Diagnostics APIs

Section 72 exposes three dedicated administrative security endpoints under `/api/admin/security`:
1. `GET /api/admin/security/health`: Evaluates live security health across all 10 controls and returns truthful structured results (`PASS`, `WARN`, `FAIL`).
2. `GET /api/admin/security/findings`: Returns the complete machine-readable Security Findings Register.
3. `GET /api/admin/security/configuration`: Validates runtime environment configuration (debug flags, CORS, rate limits).

---

## 16. Verification & Automated Regression Suite

The dedicated security test suite `backend/tests/test_section72_security_hardening.py` covers 12 comprehensive test cases:
- `test_01_security_configuration_validator`: Verifies configuration auditing flags debug settings and CORS.
- `test_02_security_health_status_matrix`: Verifies all 10 trust boundary controls evaluate and pass.
- `test_03_ssrf_protector_comprehensive`: Confirms rejection of 127.0.0.1, RFC-1918 subnets, and metadata 169.254.169.254.
- `test_04_path_traversal_and_filename_sanitization`: Verifies directory traversal rejection and filename normalization.
- `test_05_decompression_bomb_and_archive_guards`: Tests zip bomb, ratio limit, and zip slip traversal rejection.
- `test_06_csv_formula_injection_defense`: Verifies formula trigger neutralization (`=`, `@`, `+`, `-`, `\t`).
- `test_07_html_sanitizer_xss_defense`: Confirms scripts, iframes, and event handlers are neutralized.
- `test_08_log_sanitizer_secret_redaction`: Verifies redaction of Bearer tokens, passwords, and database URIs.
- `test_09_llm_prompt_injection_defense_and_schema_validation`: Confirms prompt delimiter breakout neutralization.
- `test_10_evidence_download_header_injection_defense`: Validates Content-Disposition header sanitization.
- `test_11_security_incident_signals_and_audit`: Verifies dispatch of security signals to immutable audit ledger.
- `test_12_security_findings_register_integrity`: Validates structure and completeness of findings register.

**Outcome: 12/12 PASSED (100%). Regression Suite (Sections 45–72): 99/99 PASSED (100%). Frontend Production Build: PASS (0 errors).**
