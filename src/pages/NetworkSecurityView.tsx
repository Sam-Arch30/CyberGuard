import { DetectorUpload } from '../components/analysis/DetectorUpload';
import { apiFetch } from '../utils/apiClient';
import React, { useState } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Play,
  RotateCcw,
  Network,
  Radio,
  ArrowUpRight,
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
  target_destination?: string;
  target_device?: string;
  mitre_attack_ids?: string[];
  evidence_items?: FindingEvidence[];
}

interface NetworkAnalysisResult {
  analysis_run_id: string;
  events_analyzed_count: number;
  devices_observed_count: number;
  unique_destinations_count: number;
  total_bytes_sent: number;
  total_bytes_received: number;
  overall_risk_score: number;
  overall_severity: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  classification: string;
  suspicious_communication_detected: boolean;
  possible_exfiltration_detected: boolean;
  findings: FindingItem[];
}

const PRESET_SCENARIOS = {
  beaconing: {
    name: 'Beacon-Like C2 Periodic Flow',
    description: 'Source 10.0.1.10 establishes connections to external IP 203.0.113.88 at strict 60s intervals (low jitter CV).',
    events: [
      { src_ip: '10.0.1.10', dst_ip: '203.0.113.88', dst_port: 8443, protocol: 'TCP', bytes_sent: 1024, bytes_recv: 512, timestamp: '2026-10-02T12:00:00Z', device_id: 'workstation-17' },
      { src_ip: '10.0.1.10', dst_ip: '203.0.113.88', dst_port: 8443, protocol: 'TCP', bytes_sent: 1040, bytes_recv: 512, timestamp: '2026-10-02T12:01:00Z', device_id: 'workstation-17' },
      { src_ip: '10.0.1.10', dst_ip: '203.0.113.88', dst_port: 8443, protocol: 'TCP', bytes_sent: 1024, bytes_recv: 512, timestamp: '2026-10-02T12:02:01Z', device_id: 'workstation-17' },
      { src_ip: '10.0.1.10', dst_ip: '203.0.113.88', dst_port: 8443, protocol: 'TCP', bytes_sent: 1024, bytes_recv: 512, timestamp: '2026-10-02T12:03:00Z', device_id: 'workstation-17' },
      { src_ip: '10.0.1.10', dst_ip: '203.0.113.88', dst_port: 8443, protocol: 'TCP', bytes_sent: 1040, bytes_recv: 512, timestamp: '2026-10-02T12:04:00Z', device_id: 'workstation-17' },
      { src_ip: '10.0.1.10', dst_ip: '203.0.113.88', dst_port: 8443, protocol: 'TCP', bytes_sent: 1024, bytes_recv: 512, timestamp: '2026-10-02T12:05:01Z', device_id: 'workstation-17' },
    ]
  },
  scan: {
    name: 'Defensive Host Sweep & Port Scan',
    description: 'Internal workstation probing 16 consecutive ports across internal target subnet in under 60 seconds.',
    events: Array.from({ length: 16 }).map((_, i) => ({
      src_ip: '10.0.1.99',
      dst_ip: '10.0.2.15',
      dst_port: 1000 + i,
      protocol: 'TCP',
      status: 'FAILURE',
      timestamp: new Date(Date.parse('2026-10-02T12:00:00Z') + i * 2000).toISOString(),
      device_id: 'dev-lab-99',
    }))
  },
  exfiltration: {
    name: 'High Outbound Data Exfiltration',
    description: 'Finance laptop transferring 75 MB outbound to unfamiliar external IP with highly asymmetric upload ratios.',
    events: [
      {
        src_ip: '10.0.1.45',
        dst_ip: '198.51.100.89',
        dst_port: 443,
        protocol: 'TCP',
        bytes_sent: 78643200, // 75 MB
        bytes_recv: 52428,
        duration: 32.4,
        device_id: 'finance-laptop-45',
        timestamp: '2026-10-02T12:15:00Z',
      }
    ]
  },
  dns_tunneling: {
    name: 'DNS Tunneling & NXDOMAIN Storm',
    description: '16 high-entropy subdomain requests querying a single base domain with long chunk labels.',
    events: Array.from({ length: 16 }).map((_, i) => ({
      src_ip: '10.0.1.30',
      dns_query: `chunk-${i}-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0-payload.tunnel.corp-exfil.net`,
      query_type: 'TXT',
      response_code: i % 3 === 0 ? 'NXDOMAIN' : 'NOERROR',
      protocol: 'DNS',
      timestamp: new Date(Date.parse('2026-10-02T12:20:00Z') + i * 1500).toISOString(),
      device_id: 'host-eng-30',
    }))
  },
  benign: {
    name: 'Benign HTTPS Web Browsing',
    description: 'Standard authorized web browsing session to common content delivery network over TCP 443.',
    events: [
      { src_ip: '10.0.1.12', dst_ip: '93.184.216.34', dst_port: 443, protocol: 'HTTPS', bytes_sent: 4096, bytes_recv: 32768, duration: 4.2, timestamp: '2026-10-02T12:30:00Z', device_id: 'user-pc-12' },
      { src_ip: '10.0.1.12', dst_ip: '151.101.1.140', dst_port: 443, protocol: 'HTTPS', bytes_sent: 2048, bytes_recv: 16384, duration: 2.1, timestamp: '2026-10-02T12:30:15Z', device_id: 'user-pc-12' },
    ]
  }
};

export const NetworkSecurityView: React.FC = () => {
  const [selectedScenarioKey, setSelectedScenarioKey] = useState<keyof typeof PRESET_SCENARIOS>('beaconing');
  const [customJson, setCustomJson] = useState<string>(
    JSON.stringify(PRESET_SCENARIOS.beaconing.events, null, 2)
  );
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<NetworkAnalysisResult | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleScenarioChange = (key: keyof typeof PRESET_SCENARIOS) => {
    setSelectedScenarioKey(key);
    setCustomJson(JSON.stringify(PRESET_SCENARIOS[key].events, null, 2));
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

      const res = await apiFetch(apiUrl('/api/network-security/analyze-batch'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(eventsPayload),
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Analysis request failed with status ${res.status}`);
      }

      const data: NetworkAnalysisResult = await res.json();
      setResult(data);
    } catch (err: any) {
      setErrorMsg(err.message || 'An unexpected error occurred during network telemetry analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleUpload = async (file: File) => {
    setIsAnalyzing(true); setErrorMsg(null); setResult(null);
    try {
      const form = new FormData(); form.append('file', file);
      const response = await apiFetch(apiUrl('/api/network-security/upload-log'), {method: 'POST', body: form});
      if (!response.ok) throw new Error(await extractErrorMessage(response));
      const data: NetworkAnalysisResult = await response.json();
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
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-6">
        <div>
          <div className="flex items-center space-x-2.5">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
              <Network className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-foreground">
                Network activity analysis
              </h1>
              <p className="text-xs text-foreground-muted font-mono">
                Review submitted network telemetry for connection patterns and anomaly indicators.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-surface-secondary border border-border text-foreground-muted">
            Internal CIDRs: RFC1918 + ULA
          </span>
          <span className="text-[11px] font-mono px-2.5 py-1 rounded-badge bg-primary/10 border border-primary/30 text-primary font-semibold">
            Telemetry required
          </span>
        </div>
      </div>

      <DetectorUpload title="Upload network logs" description="Submit original telemetry directly to this detector and review the result below." accept=".json,.jsonl,.ndjson,.csv" busy={isAnalyzing} onAnalyze={handleUpload} />

      {/* Preset Scenario Selector */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold uppercase text-foreground-subtle tracking-wider flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-primary" />
            Synthetic Demonstration Telemetry Scenarios
          </span>
          <span className="text-[11px] text-foreground-muted">Safe, non-destructive telemetry</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5">
          {(Object.keys(PRESET_SCENARIOS) as Array<keyof typeof PRESET_SCENARIOS>).map((key) => {
            const sc = PRESET_SCENARIOS[key];
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

      {/* Input JSON Editor & Action Row */}
      <div className="bg-surface rounded-card border border-border p-4 space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-mono font-semibold text-foreground flex items-center gap-1.5">
            <Terminal className="w-3.5 h-3.5 text-primary" />
            Normalized Ingestion Telemetry Payload (JSON Array)
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
              {isAnalyzing ? 'Analyzing Telemetry...' : 'Analyze Network Telemetry'}
            </button>
          </div>
        </div>

        <textarea
          value={customJson}
          onChange={(e) => setCustomJson(e.target.value)}
          rows={7}
          className="w-full font-mono text-xs p-3 rounded-lg bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary resize-y"
          placeholder="Paste array of network flow objects..."
        />
      </div>

      {/* Error Banner */}
      {errorMsg && (
        <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-500 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Results Dashboard */}
      {result && (
        <div className="space-y-5 animate-fadeIn">
          {/* Top KPI Cards */}
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
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Analyzed Events</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.events_analyzed_count}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Devices / Hosts</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.devices_observed_count}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Destinations</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {result.unique_destinations_count}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface border border-border space-y-1">
              <span className="text-[10px] font-mono text-foreground-muted uppercase">Outbound Data</span>
              <div className="text-lg font-bold font-mono text-foreground">
                {(result.total_bytes_sent / (1024 * 1024)).toFixed(2)} <span className="text-xs text-foreground-muted">MB</span>
              </div>
            </div>
          </div>

          {/* Composite Alert Banners */}
          {result.suspicious_communication_detected && (
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/40 text-red-400 flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 mt-0.5 shrink-0" />
              <div>
                <div className="font-bold text-sm">Suspicious External Communication Corroborated</div>
                <div className="text-xs opacity-90 mt-0.5">
                  Multi-signal corroboration: periodic beaconing combined with threat intelligence indicator or new destination.
                </div>
              </div>
            </div>
          )}

          {result.possible_exfiltration_detected && (
            <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/40 text-amber-400 flex items-start gap-3">
              <ArrowUpRight className="w-5 h-5 mt-0.5 shrink-0" />
              <div>
                <div className="font-bold text-sm">Possible Data Exfiltration Pattern Detected</div>
                <div className="text-xs opacity-90 mt-0.5">
                  Large volume outbound transfer directed to an unfamiliar destination with significant traffic asymmetry.
                </div>
              </div>
            </div>
          )}

          {/* Findings List */}
          <div className="bg-surface rounded-card border border-border p-4 space-y-3">
            <h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Layers className="w-4 h-4 text-primary" />
              Evaluated Network Findings ({result.findings.length})
            </h3>

            {result.findings.length === 0 ? (
              <div className="p-6 text-center text-xs text-foreground-muted bg-surface-secondary/50 rounded-lg">
                No anomalous network patterns or policy violations detected in this batch.
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
