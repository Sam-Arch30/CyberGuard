import React, { useState } from 'react';
import {
  Link2,
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  Layers,
  Search,
} from 'lucide-react';
import { apiUrl } from '../utils/apiClient';

interface UrlAnalysisResult {
  url: string;
  normalized_url: string;
  domain: string;
  overall_risk_score: number;
  overall_severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  is_lookalike: boolean;
  targeted_brand?: string;
  is_punycode: boolean;
  domain_age_days?: number;
  is_newly_registered: boolean;
  redirect_hops_count: number;
  final_url?: string;
  findings: Array<{
    finding_type: string;
    title: string;
    description: string;
    severity: string;
    confidence: number;
  }>;
}

const PRESET_URLS = {
  homoglyph: {
    name: 'Punycode / Homoglyph Impersonation',
    url: 'https://xn--microsft-07a.com/auth/login',
    description: 'IDN punycode disguised domain impersonating Microsoft with cyrillic or lookalike glyphs.',
  },
  lookalike: {
    name: 'Brand Lookalike Phishing Link',
    url: 'https://paypal-security-verification.update-account.tk/signin',
    description: 'Suspicious free TLD (.tk) with multi-token subdomain targeting PayPal brand credentials.',
  },
  ip_url: {
    name: 'Raw IP Hostname Link',
    url: 'http://198.51.100.44:8080/secure/document.exe',
    description: 'Direct numeric IP address bypass link with non-standard HTTP port.',
  },
  clean: {
    name: 'Clean Authentic Corporate Domain',
    url: 'https://github.com/Sam-Arch30/CyberGuard',
    description: 'Legitimate HTTPS domain with established domain age and zero lookalike heuristics.',
  }
};

export const UrlSecurityView: React.FC = () => {
  const [selectedKey, setSelectedKey] = useState<keyof typeof PRESET_URLS>('homoglyph');
  const [inputUrl, setInputUrl] = useState<string>(PRESET_URLS.homoglyph.url);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSelectPreset = (key: keyof typeof PRESET_URLS) => {
    setSelectedKey(key);
    setInputUrl(PRESET_URLS[key].url);
    setResult(null);
    setErrorMsg(null);
  };

  const handleAnalyze = async () => {
    setIsAnalyzing(true);
    setErrorMsg(null);
    try {
      const res = await fetch(apiUrl('/api/urls/analyze'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: inputUrl }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `URL analysis failed with status ${res.status}`);
      }

      const data: UrlAnalysisResult = await res.json();
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'An error occurred during URL intelligence analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/10 text-red-500 border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/10 text-amber-500 border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/10 text-blue-500 border-blue-500/30';
      default:
        return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30';
    }
  };

  return (
    <div className="max-w-6xl w-full mx-auto py-6 px-4 space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Link2 className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                URL, Domain & Website Intelligence Engine
              </h1>
              <p className="text-xs text-foreground-muted font-mono">
                Section 7 — Homoglyphs, Lookalikes, Domain Age, Redirect Chains & Safe Static Website Triage
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-surface-secondary border border-border text-foreground-muted">
            SSRF Protection Guard
          </span>
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-primary/10 border border-primary/30 text-primary font-semibold">
            Section 7 Operational
          </span>
        </div>
      </div>

      {/* Preset Samples */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold uppercase text-foreground-subtle tracking-wider flex items-center gap-1.5">
            <Search className="w-3.5 h-3.5 text-primary" />
            Preset URL & Domain Scenarios
          </span>
          <span className="text-[11px] text-foreground-muted">Safe synthetic threat scenarios</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5">
          {(Object.keys(PRESET_URLS) as Array<keyof typeof PRESET_URLS>).map((key) => {
            const preset = PRESET_URLS[key];
            const isSelected = selectedKey === key;
            return (
              <button
                key={key}
                onClick={() => handleSelectPreset(key)}
                className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-primary/10 border-primary text-foreground shadow-xs'
                    : 'bg-surface-secondary/60 border-border hover:border-border-subtle text-foreground-muted hover:text-foreground'
                }`}
              >
                <div className="text-xs font-semibold">{preset.name}</div>
                <div className="text-[10px] text-foreground-muted truncate mt-0.5">{preset.description}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* URL Input Form */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <label className="text-xs font-mono text-foreground-muted block">Target URL or Domain</label>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={inputUrl}
            onChange={(e) => setInputUrl(e.target.value)}
            className="flex-1 font-mono text-xs px-3 py-2 rounded-lg bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
            placeholder="https://example.com/login"
          />
          <button
            onClick={() => handleSelectPreset(selectedKey)}
            className="px-3 py-2 text-xs rounded border border-border bg-surface hover:bg-surface-secondary text-foreground-muted transition-colors flex items-center gap-1 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset
          </button>
          <button
            onClick={handleAnalyze}
            disabled={isAnalyzing}
            className="px-4 py-2 text-xs font-semibold rounded bg-primary text-primary-foreground hover:bg-primary/90 transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            {isAnalyzing ? 'Inspecting Link...' : 'Inspect URL'}
          </button>
        </div>
      </div>

      {/* Error */}
      {errorMsg && (
        <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-5 animate-fadeIn">
          {/* Top KPI row */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Overall Severity</span>
              <div className={`text-xs font-bold px-2 py-0.5 rounded border inline-block ${getSeverityBadgeClass(result.overall_severity)}`}>
                {result.overall_severity}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Risk Score</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.overall_risk_score.toFixed(1)}<span className="text-xs text-foreground-muted">/100</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Extracted Domain</span>
              <div className="text-xs font-bold font-mono text-foreground truncate" title={result.domain}>
                {result.domain}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Lookalike Attack</span>
              <div className={`text-xs font-bold font-mono ${result.is_lookalike ? 'text-red-400' : 'text-emerald-400'}`}>
                {result.is_lookalike ? `YES (${result.targeted_brand})` : 'NO'}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Punycode (IDN)</span>
              <div className={`text-xs font-bold font-mono ${result.is_punycode ? 'text-amber-400' : 'text-foreground-muted'}`}>
                {result.is_punycode ? 'YES' : 'NO'}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Domain Age</span>
              <div className="text-xs font-bold font-mono text-foreground truncate">
                {result.domain_age_days ? `${result.domain_age_days} days` : 'UNKNOWN'}
              </div>
            </div>
          </div>

          {/* Lookalike Alert Banner */}
          {result.is_lookalike && (
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-400 flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 mt-0.5 shrink-0" />
              <div>
                <div className="font-bold text-sm">Targeted Brand Lookalike Impersonation Detected</div>
                <div className="text-xs opacity-90 mt-0.5">
                  Domain matches impersonation patterns targeting <strong className="underline uppercase">{result.targeted_brand}</strong> using typo-squatting, homoglyphs, or lookalike token permutation.
                </div>
              </div>
            </div>
          )}

          {/* Findings */}
          <div className="bg-surface rounded-card border border-border p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Layers className="w-4 h-4 text-primary" />
              URL & Infrastructure Findings ({result.findings.length})
            </h3>

            {result.findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-foreground-muted bg-surface-secondary/50 rounded-lg">
                No deceptive patterns, punycode tricks, or malicious infrastructure signals detected.
              </div>
            ) : (
              <div className="space-y-2.5">
                {result.findings.map((f, idx) => (
                  <div key={idx} className="p-3.5 rounded-lg bg-surface-secondary/60 border border-border space-y-1.5">
                    <div className="flex items-center space-x-2">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${getSeverityBadgeClass(f.severity)}`}>
                        {f.severity}
                      </span>
                      <span className="text-xs font-bold text-foreground">{f.title}</span>
                    </div>
                    <p className="text-xs text-foreground-muted leading-relaxed">
                      {f.description}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
