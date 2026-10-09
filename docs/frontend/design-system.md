# CYBERGUARD Design System & Theme Engine Architecture
**Section 34 Specification • SOC-Grade Minimalist UI Foundation**

---

## 1. Design Principles

CyberGuard is a serious, professional cyber-defense and forensic investigation system. Its visual system has two distinct responsibilities:

1. **Application Chrome:**
   - **Quiet, consistent, minimal, low-contrast.**
   - Uses muted backgrounds, subtle borders, restrained typography, and compact layouts.
   - Avoids decorative distractions (no neon cyberpunk glows, no moving particles, no generic SaaS gradients).

2. **Security Information:**
   - **High-signal, clear, semantically consistent, immediately scannable.**
   - Strong colors and emphasis are strictly reserved for actual security meaning (threat severity, risk score, confidence, cryptographic status).
   - Never uses risk colors merely as decorative accents.

---

## 2. Calibrated Themes

CyberGuard supports four first-class themes with persistent user preference storage (`cyberguard_theme` with fallback `mailtrace_theme`) and system preference synchronization.

| Theme | Type | Identity & Character | Background | Surface | Accent | Primary Text |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Olive** | Dark *(Primary SOC)* | Serious, organic, technical, quiet graphite | `#090a08` | `#11130f` | `#7d9456` *(Muted Olive)* | `#e5e8e3` *(Warm off-white)* |
| **Sakura** | Light *(Porcelain)* | High-contrast, clean, soft pink accent | `#faf8f9` | `#ffffff` | `#c26382` *(Restrained Pink)* | `#16191f` *(Ink dark)* |
| **Paper** | Light *(Editorial)* | Forensic notebook, technical dossier, fine warm borders | `#f5f2e9` | `#fcfaf5` | `#725b44` *(Technical Umber)* | `#1a1917` *(Deep ink)* |
| **Midnight** | Dark *(Technical)* | Cool graphite, controlled electric cyan | `#0a0c10` | `#12151c` | `#2fa5c4` *(Electric Cyan)* | `#e6ecf2` *(Cool off-white)* |

### Theme Implementation
- All themes are implemented via pure CSS custom properties (`--color-background`, `--color-surface`, `--color-primary`, etc.) defined in `@theme` and `:root` / `[data-theme="*"]` in `src/index.css`.
- Theme switching updates the `data-theme` attribute and `dark` class on the `<html>` root element.
- Components consume semantic tokens and **never** perform runtime conditionals like `if (theme === 'olive')`.

---

## 3. Semantic Threat Colors (Theme-Independent)

Threat severity colors are strictly semantic. They are calibrated to maintain recognized meaning and WCAG AA contrast across both dark and light modes.

| Severity Tier | Semantic Meaning | Token Accent | Surface Token | Border Token |
| :--- | :--- | :--- | :--- | :--- |
| **CRITICAL** | Confirmed compromise, active exploitation, reverse shell | `--color-threat-critical` (`#ef4444`) | `--color-threat-critical-surface` | `--color-threat-critical-border` |
| **HIGH** | Lateral movement, credential dump attempt, malware payload | `--color-threat-high` (`#f97316`) | `--color-threat-high-surface` | `--color-threat-high-border` |
| **MEDIUM** | Suspicious anomaly, unverified binary, abnormal beacon | `--color-threat-medium` (`#f59e0b`) | `--color-threat-medium-surface` | `--color-threat-medium-border` |
| **LOW** | Policy aberration, low-risk telemetry tracking | `--color-threat-low` (`#10b981`) | `--color-threat-low-surface` | `--color-threat-low-border` |
| **SAFE** | Cryptographically authentic, verified benign, clean baseline | `--color-threat-safe` (`#22c55e`) | `--color-threat-safe-surface` | `--color-threat-safe-border` |
| **INFO** | Telemetry ingestion event, standard operating notice | `--color-threat-info` (`#3b82f6`) | `--color-threat-info-surface` | `--color-threat-info-border` |
| **UNKNOWN** | Insufficient observations, inconclusive data | `--color-threat-unknown` (`#64748b`) | `--color-threat-unknown-surface` | `--color-threat-unknown-border` |

> **Critical Rule:** Never convert missing or uncalibrated data into `SAFE` / green. Missing data must render as `UNKNOWN` / neutral.

---

## 4. Typography

CyberGuard prioritizes legibility, compactness, and numerical clarity:

- **Primary Sans Font:** `Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif`
  - Used for titles, body copy, descriptions, button labels, and general UI chrome.
- **Monospace Font:** `ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', monospace`
  - Used selectively for: IP addresses, hashes, domains, URLs, ports, event IDs, UUIDs, timestamps, technical metrics, and code snippets.
- **Hierarchy:**
  - `Display`: `text-2xl` to `text-3xl font-extrabold tracking-tight`
  - `Page Title`: `text-xl font-bold tracking-tight`
  - `Section Title`: `text-sm font-semibold tracking-normal`
  - `Card / Panel Title`: `text-xs font-mono font-bold uppercase tracking-wider`
  - `Body`: `text-xs sm:text-sm font-normal text-foreground`
  - `Secondary / Muted`: `text-xs font-normal text-foreground-muted`
  - `Metric / Readout`: `text-2xl font-extrabold font-mono text-foreground`

---

## 5. Spacing Scale

Tokens adhere to a strict 4px grid scale:

| Token | Size | Primary Usage |
| :--- | :--- | :--- |
| `space-1` | 4px | Micro padding, icon gaps, compact badge padding |
| `space-2` | 8px | Button padding-y, form control gap, badge gap |
| `space-3` | 12px | Compact panel padding, input padding-x |
| `space-4` | 16px | Standard card/panel padding, layout gap |
| `space-5` | 20px | Section margins, header heights |
| `space-6` | 24px | Major panel padding, modal dialog padding |
| `space-8` | 32px | Page section gaps |
| `space-12`| 48px | Top-level workspace offsets |

---

## 6. Borders and Elevation

CyberGuard prefers **fine, subtle borders** over heavy drop shadows:

- **Border Tokens:**
  - `--color-border-subtle`: Very fine partition lines (`border-border-subtle`)
  - `--color-border`: Standard card, input, and panel borders (`border-border`)
  - `--color-border-strong`: Active tab, focused element borders (`border-border-strong`)
  - `--color-focus`: High-visibility focus ring (`ring-1 ring-focus`)
- **Elevation Hierarchy:**
  - `flat`: `shadow-none` (default for panels, table rows, cards)
  - `subtle`: `shadow-xs` / `shadow-sm`
  - `card`: `shadow-card`
  - `overlay / popover`: `shadow-popover` (for dropdowns, modals, and detail drawers)

---

## 7. Border Radius

Restrained radius tokens prevent the interface from looking like a toy or floating pills:

- `rounded-control`: 6px (`0.375rem`) for buttons, inputs, selects, switches
- `rounded-card`: 10px (`0.625rem`) for panels, metric cards, table containers
- `rounded-badge`: 4px (`0.25rem`) for compact forensic badges and tags
- `rounded-full`: Reserved strictly for circular icon buttons, avatars, and status dots

---

## 8. Button System

All buttons support explicit variants and complete interactive states:

- **Variants:**
  - `primary`: Solid accent (`bg-primary text-primary-foreground`)
  - `secondary`: Neutral surface with border (`bg-surface-secondary border-border`)
  - `ghost`: Transparent hoverable surface
  - `danger`: Semantic destructive action (`bg-danger text-white`)
  - `quiet`: Borderless low-profile text button
- **States:** `default`, `hover`, `active` (with subtle click transform `btn-press`), `focus` (`ring-1 ring-focus`), `disabled` (`opacity-50 pointer-events-none`), `loading` (spinner + disabled).

---

## 9. Form Controls

All form controls follow accessible, high-signal patterns:

- `label`: Crisp, high-contrast, optional required indicator (`*`).
- `helperText` / `error`: Clean secondary explanation or semantic error message.
- `states`: `default`, `focused`, `disabled`, `read-only`.
- `Input`, `SearchInput`, `Select`, `Textarea`, `Checkbox`, `Switch`, `RadioGroup`.

---

## 10. Tables & Dense Forensic Mode

Security analysts frequently inspect hundreds of log events, network flows, or indicators. CyberGuard supports both **Standard** and **Dense** modes:

- **Standard Mode:** 44px row height, relaxed padding, optimized for dashboards.
- **Dense Mode:** 30px row height, reduced padding, monospace numerical readouts, optimized for forensic triage.
- Features: Sortable headers, row hover feedback, keyboard navigation, empty state, loading skeleton.

---

## 11. Security-Specific Primitives (`src/components/security/`)

| Primitive | Purpose | Key Props |
| :--- | :--- | :--- |
| `SeverityIndicator` | Displays standardized severity tier with pulse & icon | `severity`, `size`, `pulse`, `showText` |
| `ConfidenceIndicator` | Displays evidence calibration tier (visually secondary) | `tier`, `score`, `size`, `showPercentage` |
| `RiskBadge` | Semantic risk score + severity tag | `score`, `severity`, `variant`, `pulse` |
| `EvidenceCount` | Counter for supporting vs counter evidence | `total`, `supporting`, `refuting`, `variant` |
| `ThreatScore` | Tripartite score display (Risk Score, Severity, Confidence) | `score`, `severity`, `confidence`, `variant` |
| `EntityChip` | Monospace chip for IP, Host, User, Hash, Domain, Process | `type`, `value`, `copyable`, `truncateLength` |
| `IndicatorValue` | Specialized IOC display with defanging and reputation | `value`, `type`, `reputation`, `defang`, `copyable` |
| `Timestamp` | ISO 8601 UTC timestamp with relative time delta | `date`, `format`, `showRelative`, `copyable` |
| `SourceBadge` | Collector provenance tag (Sysmon, Auditd, CloudTrail, etc.) | `source`, `type`, `detector`, `version` |
| `TechnicalValue` | Monospace identifier with truncation, copy, and masking | `value`, `truncate`, `mask`, `copyable` |

---

## 12. Progressive Disclosure & Drawers

CyberGuard structures security intelligence hierarchically:

```
What happened? (Summary title & badge)
     ↓
How serious? (Risk score & severity indicator)
     ↓
Why? (Confidence & primary reasoning)
     ↓
Evidence (Supporting vs refuting telemetry)
     ↓
Technical Details (Raw payload, memory offset, hex dump)
```

- Components: `Accordion`, `Drawer`, `Modal`, `Panel` with collapsible sections.

---

## 13. Motion & Accessibility

- **Motion Tokens:**
  - Fast: `100ms ease-out`
  - Normal: `150ms ease-in-out`
  - Slow: `250ms cubic-bezier(0.16, 1, 0.3, 1)`
- **Reduced Motion:** Fully honors `@media (prefers-reduced-motion: reduce)` by disabling non-essential transitions and animations.
- **Accessibility (WCAG AA):**
  - All interactive elements possess explicit `focus-visible` styling (`ring-1 ring-focus outline-none`).
  - Screen reader labels (`aria-label`) on all icon-only buttons.
  - Threat indicators utilize **Icon + Text** rather than color alone to ensure accessibility for color-blind analysts.

---

## 14. Do's and Don'ts

| Practice | Do | Don't |
| :--- | :--- | :--- |
| **Color Usage** | Use semantic threat tokens (`threat-critical`, `threat-safe`) exclusively for security state. | Do NOT color random dashboard cards red/green/yellow for aesthetic variety. |
| **Theme Styling** | Use CSS variables (`var(--color-surface)`) or Tailwind theme classes (`bg-surface`). | Do NOT hardcode `#111111` or `#ffffff` inside component JSX. |
| **Missing Data** | Render `UNKNOWN` or `INSUFFICIENT DATA` in neutral gray. | Do NOT default missing data to green / `SAFE`. |
| **Risk Presentation**| Clearly distinguish Risk Score (0-100), Severity (CRITICAL-LOW), and Confidence. | Do NOT collapse all three metrics into a single ambiguous "score" number. |
| **Technical Strings** | Use `TechnicalValue` or `IndicatorValue` with monospace font and copy-to-clipboard. | Do NOT wrap long hashes or IP addresses haphazardly across multiple lines. |
| **Secrets Safety** | Mask credentials and tokens with `TechnicalValue mask={true}`. | Do NOT expose raw API keys, passwords, or session tokens in UI logs. |
