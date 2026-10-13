import { DetectorUpload } from '../components/analysis/DetectorUpload';
import { apiFetch } from '../utils/apiClient';
import React, { useState } from 'react';
import {
  KeyRound,
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  Fingerprint,
  Terminal,
  Layers,
} from 'lucide-react';
import { apiUrl, extractErrorMessage } from '../utils/apiClient';

interface FindingEvidence {
  key: string;
  value: string;
  source: string;
}

interface FindingItem {
  finding_type: string;
  title: string;
  description: string;
  severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  risk_contribution: number;
  category: string;
  target_account?: string;
  mitre_attack_ids?: string[];
  evidence_items?: FindingEvidence[];
}

interface AuthAnalysisResult {
  analysis_run_id: string;
  events_analyzed_count: number;
  accounts_targeted_count: number;
  unique_source_ips_count: number;
  overall_risk_score: number;
  overall_severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  classification: string;
  ato_suspected: boolean;
  findings: FindingItem[];
}

const PRESET_AUTH_SCENARIOS = {
  ato: {
    name: 'Account Takeover (ATO) Incident',
    description: '4 consecutive password failures followed immediately by successful login from an overseas IP with a new device.',
    events: [
      { user: 'cfo@cyberguard.internal', status: 'failure', ip: '198.51.100.99', device_name: 'Attacker-Kali', timestamp: '2026-10-02T10:00:00Z' },
      { user: 'cfo@cyberguard.internal', status: 'failure', ip: '198.51.100.99', device_name: 'Attacker-Kali', timestamp: '2026-10-02T10:01:00Z' },
      { user: 'cfo@cyberguard.internal', status: 'failure', ip: '198.51.100.99', device_name: 'Attacker-Kali', timestamp: '2026-10-02T10:02:00Z' },
      { user: 'cfo@cyberguard.internal', status: 'failure', ip: '198.51.100.99', device_name: 'Attacker-Kali', timestamp: '2026-10-02T10:03:00Z' },
      { user: 'cfo@cyberguard.internal', status: 'success', ip: '198.51.100.99', device_name: 'Attacker-Kali', latitude: 55.75, longitude: 37.61, city: 'Moscow', country: 'RU', timestamp: '2026-10-02T10:05:00Z' },
    ]
  },
  bruteforce: {
    name: 'Targeted Password Guessing (Brute Force)',
    description: 'Single external IP generating rapid sequential failures against administrator target.',
    events: Array.from({ length: 6 }).map((_, i) => ({
      user: 'admin@cyberguard.internal',
      status: 'failure',
      ip: '203.0.113.55',
      device_name: 'Python-Script',
      timestamp: new Date(Date.parse('2026-10-02T11:00:00Z') + i * 15000).toISOString(),
    }))
  },
  spray: {
    name: 'Distributed Password Spray',
    description: 'Horizontal spray attempting common passwords across 10 distinct employee accounts from 1 source.',
    events: Array.from({ length: 10 }).map((_, i) => ({
      user: `employee${i + 1}@cyberguard.internal`,
      status: 'failure',
      ip: '198.51.100.12',
      device_name: 'Sprayer-VM',
      timestamp: new Date(Date.parse('2026-10-02T11:30:00Z') + i * 30000).toISOString(),
    }))
  },
  mfa_fatigue: {
    name: 'MFA Fatigue & Repeated Rejections',
    description: 'User password correct but 4 successive push notifications rejected or timed out.',
    events: Array.from({ length: 4 }).map((_, i) => ({
      user: 'director@cyberguard.internal',
      status: 'mfa_failure',
      mfa_result: 'REJECTED',
      ip: '198.51.100.77',
      device_name: 'Unfamiliar-Mobile',
      timestamp: new Date(Date.parse('2026-10-02T11:45:00Z') + i * 20000).toISOString(),
    }))
  },
  legit: {
    name: 'Authorized Corporate Sign-In',
    description: 'Normal single-factor and MFA success from corporate enterprise laptop on local network.',
    events: [
      { user: 'alice@cyberguard.internal', status: 'success', mfa_result: 'SUCCESS', ip: '10.0.1.25', device_name: 'Corporate-MacBook-Pro', timestamp: '2026-10-02T09:00:00Z' }
    ]
  }
};

export const AuthSecurityView: React.FC = () => {
  const [selectedScenarioKey, setSelectedScenarioKey] = useState<keyof typeof PRESET_AUTH_SCENARIOS>('ato');
  const [customJson, setCustomJson] = useState<string>(
    JSON.stringify(PRESET_AUTH_SCENARIOS.ato.events, null, 2)
  );
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AuthAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleScenarioChange = (key: keyof typeof PRESET_AUTH_SCENARIOS) => {
    setSelectedScenarioKey(key);
    setCustomJson(JSON.stringify(PRESET_AUTH_SCENARIOS[key].events, null, 2));
    setResult(null);
    setErrorMsg(null);
  };

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    setErrorMsg(null);
    try {
      let eventsPayload;
      try {
        eventsPayload = JSON.parse(customJson);
        if (!Array.isArray(eventsPayload)) {
          eventsPayload = [eventsPayload];
        }
      } catch (err: any) {
        throw new Error(`Invalid JSON syntax in events input: ${err.message}`);
      }

      const res = await apiFetch(apiUrl('/api/auth-security/analyze-batch'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events: eventsPayload, provider_hint: 'generic' }),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Auth analysis request failed with status ${res.status}`);
      }

      const data: AuthAnalysisResult = await res.json();
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'An error occurred during authentication telemetry analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleUpload = async (file: File) => {
    setIsAnalyzing(true); setErrorMsg(null); setResult(null);
    try {
      const form = new FormData(); form.append('file', file);
      const response = await apiFetch(apiUrl('/api/auth-security/upload-log'), {method: 'POST', body: form});
      if (!response.ok) throw new Error(await extractErrorMessage(response));
      const data: AuthAnalysisResult = await response.json();
      if (!Number.isFinite(data.overall_risk_score) || !Array.isArray(data.findings)) throw new Error('Incomplete detector response.');
      setResult(data);
    } catch (error) {setErrorMsg(error instanceof Error ? error.message : 'Upload analysis failed.');}
    finally {setIsAnalyzing(false);}
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
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                Account & access analysis
              </h1>
              <p className="text-xs text-foreground-muted font-mono">
                Review authentication events for password attacks and unusual sign-in patterns.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-surface-secondary border border-border text-foreground-muted">
            SecretRedactor: Active
          </span>
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-primary/10 border border-primary/30 text-primary font-semibold">
            Rule-based checks
          </span>
        </div>
      </div>

      <DetectorUpload title="Upload authentication logs" description="Submit original telemetry directly to this detector and review the result below." accept=".json,.jsonl,.ndjson,.log,.txt" busy={isAnalyzing} onAnalyze={handleUpload} />

      {/* Preset Scenarios */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold uppercase text-foreground-subtle tracking-wider flex items-center gap-1.5">
            <Fingerprint className="w-3.5 h-3.5 text-primary" />
            Synthetic Authentication Threat Scenarios
          </span>
          <span className="text-[11px] text-foreground-muted">Safe, non-destructive audit telemetry</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {(Object.keys(PRESET_AUTH_SCENARIOS) as Array<keyof typeof PRESET_AUTH_SCENARIOS>).map((key) => {
            const sc = PRESET_AUTH_SCENARIOS[key];
            const isSelected = selectedScenarioKey === key;
            return (
              <button
                key={key}
                onClick={() => handleScenarioChange(key)}
                className={`p-2.5 rounded-lg border text-left transition-all cursor-pointer ${
                  isSelected
                    ? 'bg-primary/10 border-primary text-foreground shadow-xs'
                    : 'bg-surface-secondary/60 border-border hover:border-border-subtle text-foreground-muted hover:text-foreground'
                }`}
              >
                <div className="text-xs font-semibold">{sc.name}</div>
                <div className="text-[10px] text-foreground-muted truncate mt-0.5">{sc.description}</div>
              </button>
            );
          })}
        </div>
      </div>

      {/* JSON Editor */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold text-foreground flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-primary" />
            Authentication Telemetry Log Array (JSON)
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleScenarioChange(selectedScenarioKey)}
              className="px-2.5 py-1 text-xs rounded border border-border bg-surface hover:bg-surface-secondary text-foreground-muted transition-colors flex items-center gap-1 cursor-pointer"
            >
              <RotateCcw className="w-3 h-3" />
              Reset
            </button>
            <button
              onClick={handleRunAnalysis}
              disabled={isAnalyzing}
              className="px-4 py-1.5 text-xs font-semibold rounded bg-primary text-primary-foreground hover:bg-primary/90 transition-all flex items-center gap-1.5 cursor-pointer disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {isAnalyzing ? 'Evaluating Log...' : 'Run Authentication Analysis'}
            </button>
          </div>
        </div>

        <textarea
          value={customJson}
          onChange={(e) => setCustomJson(e.target.value)}
          rows={7}
          className="w-full font-mono text-xs p-3 rounded-lg bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary resize-y"
          placeholder="Paste array of auth event objects..."
        />
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
          {/* KPI row */}
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
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Analyzed Attempts</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.events_analyzed_count}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Target Accounts</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.accounts_targeted_count}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Source IPs</span>
              <div className="text-lg font-bold font-mono text-red-400">
                {result.unique_source_ips_count}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Account takeover</span>
              <div className="text-lg font-bold font-mono text-emerald-400">
                {result.ato_suspected ? 'Flagged' : 'Not flagged'}
              </div>
            </div>
          </div>

          {/* ATO Banner */}
          {result.ato_suspected && (
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-400 flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 mt-0.5 shrink-0" />
              <div>
                <div className="font-bold text-sm">Account Takeover (ATO) Incident Suspected</div>
                <div className="text-xs opacity-90 mt-0.5">
                  Multi-category corroboration confirmed: consecutive authentication failures followed by successful entry with new client hardware or rapid location change.
                </div>
              </div>
            </div>
          )}

          {/* Findings */}
          <div className="bg-surface rounded-card border border-border p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Layers className="w-4 h-4 text-primary" />
              Authentication Findings ({result.findings.length})
            </h3>

            {result.findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-foreground-muted bg-surface-secondary/50 rounded-lg">
                No anomalous authentication behavior or credential attack patterns detected.
              </div>
            ) : (
              <div className="space-y-3">
                {result.findings.map((f, idx) => (
                  <div key={idx} className="p-3.5 rounded-lg bg-surface-secondary/60 border border-border space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${getSeverityBadgeClass(f.severity)}`}>
                          {f.severity}
                        </span>
                        <span className="text-xs font-bold text-foreground">{f.title}</span>
                      </div>
                      <div className="flex items-center space-x-2 text-[11px] font-mono text-foreground-muted">
                        <span>Cat: {f.category}</span>
                        {f.mitre_attack_ids && f.mitre_attack_ids.length > 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-surface border border-border text-primary font-bold">
                            {f.mitre_attack_ids.join(', ')}
                          </span>
                        )}
                      </div>
                    </div>

                    <p className="text-xs text-foreground-muted leading-relaxed">
                      {f.description}
                    </p>

                    {f.evidence_items && f.evidence_items.length > 0 && (
                      <div className="pt-2 border-t border-border/40 grid grid-cols-2 sm:grid-cols-4 gap-2">
                        {f.evidence_items.map((evi, eIdx) => (
                          <div key={eIdx} className="text-[11px] font-mono bg-surface p-1.5 rounded border border-border/60">
                            <span className="text-foreground-subtle block text-[10px]">{evi.key}</span>
                            <span className="text-foreground font-semibold truncate block">{evi.value}</span>
                          </div>
                        ))}
                      </div>
                    )}
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
