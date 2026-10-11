import React, { useState, useEffect } from 'react';
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Cpu,
  GitCommit,
  Play,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  XCircle,
  Zap,
} from 'lucide-react';
import type {
  PipelineMetrics,
  PipelineStatus,
  DetectionMatchItem,
  DeadLetterItem,
  PipelineExecutionResult,
  EventIngestPayload,
} from '../../types/detectionRules';
import { detectionRuleService } from '../../services/detectionRuleService';

const SAMPLE_PAYLOADS: Record<string, { source: string; event_type: string; payload: Record<string, any> }> = {
  powershell_c2: {
    source: 'ENDPOINT',
    event_type: 'ENDPOINT_EVENT',
    payload: {
      process_name: 'powershell.exe',
      command_line: 'powershell.exe -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAYwBwAEMAbABpAGUAbgB0AA==',
      parent_process: 'cmd.exe',
      user: 'Administrator',
      device_id: 'WS-CORP-FIN-09',
      destination_ip: '198.51.100.77',
      destination_port: 4444,
    },
  },
  credential_bruteforce: {
    source: 'AUTH',
    event_type: 'AUTH_EVENT',
    payload: {
      username: 'admin',
      auth_status: 'FAILURE',
      failure_count: 15,
      client_ip: '203.0.113.89',
      user_agent: 'Hydra-v9.2',
      target_service: 'SSH',
    },
  },
  phishing_payload: {
    source: 'EMAIL',
    event_type: 'EMAIL_EVENT',
    payload: {
      subject: 'URGENT: Verify Your Payroll Information Immediately',
      sender_email: 'security-notice@payro11-auth-center.com',
      sender_domain: 'payro11-auth-center.com',
      recipient: 'cfo@cyberguard-demo.corp',
      spf_status: 'FAIL',
      dmarc_status: 'FAIL',
      has_attachments: true,
      attachment_names: ['urgent_invoice_update.xlsm'],
      urls: ['http://login.payro11-auth-center.com/session/update'],
    },
  },
  c2_beaconing: {
    source: 'NETWORK',
    event_type: 'NETWORK_EVENT',
    payload: {
      source_ip: '10.0.4.150',
      destination_ip: '185.220.101.5',
      destination_port: 443,
      protocol: 'TLS',
      bytes_out: 489200,
      ja3_hash: '771,4865-4866-4867,0-23-65281-10-11-35-16,29-23-24,0',
      dns_query: 'update-svc-dyn.net',
    },
  },
};

export const UnifiedDetectionPipelineView: React.FC = () => {
  const [subTab, setSubTab] = useState<'sandbox' | 'matches' | 'trace' | 'replay' | 'dead-letters'>('sandbox');

  // Operational metrics & status
  const [status, setStatus] = useState<PipelineStatus | null>(null);
  const [metrics, setMetrics] = useState<PipelineMetrics | null>(null);
  const [loadingMetrics, setLoadingMetrics] = useState(false);

  // Sandbox state
  const [selectedPreset, setSelectedPreset] = useState<string>('powershell_c2');
  const [eventSource, setEventSource] = useState<string>('ENDPOINT');
  const [eventType, setEventType] = useState<string>('ENDPOINT_EVENT');
  const [payloadText, setPayloadText] = useState<string>(
    JSON.stringify(SAMPLE_PAYLOADS.powershell_c2.payload, null, 2)
  );
  const [pipelineMode, setPipelineMode] = useState<'PRODUCTION' | 'SHADOW'>('PRODUCTION');
  const [executingEvent, setExecutingEvent] = useState(false);
  const [executionResult, setExecutionResult] = useState<PipelineExecutionResult | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);

  // Matches state
  const [matches, setMatches] = useState<DetectionMatchItem[]>([]);
  const [loadingMatches, setLoadingMatches] = useState(false);
  const [selectedMatch, setSelectedMatch] = useState<DetectionMatchItem | null>(null);
  const [matchFilterSeverity, setMatchFilterSeverity] = useState<string>('ALL');
  const [matchFilterMode, setMatchFilterMode] = useState<string>('ALL');

  // Trace state
  const [traceEventId, setTraceEventId] = useState<string>('');
  const [loadingTrace, setLoadingTrace] = useState(false);
  const [traceData, setTraceData] = useState<any>(null);

  // Replay state
  const [replayMaxEvents, setReplayMaxEvents] = useState<number>(50);
  const [replaying, setReplaying] = useState(false);
  const [replayResult, setReplayResult] = useState<any>(null);

  // Dead-letters state
  const [deadLetters, setDeadLetters] = useState<DeadLetterItem[]>([]);
  const [loadingDeadLetters, setLoadingDeadLetters] = useState(false);
  const [retryingDlId, setRetryingDlId] = useState<string | null>(null);

  // Notification / Toast
  const [feedbackMsg, setFeedbackMsg] = useState<string | null>(null);
  const showFeedback = (msg: string) => {
    setFeedbackMsg(msg);
    setTimeout(() => setFeedbackMsg(null), 4000);
  };

  const loadPipelineMetrics = async () => {
    setLoadingMetrics(true);
    try {
      const [sData, mData] = await Promise.all([
        detectionRuleService.getPipelineStatus(),
        detectionRuleService.getPipelineMetrics(),
      ]);
      setStatus(sData);
      setMetrics(mData);
    } catch (err: any) {
      console.error('Failed to load pipeline telemetry:', err);
    } finally {
      setLoadingMetrics(false);
    }
  };

  const loadMatches = async () => {
    setLoadingMatches(true);
    try {
      const items = await detectionRuleService.listDetectionMatches({
        severity: matchFilterSeverity !== 'ALL' ? matchFilterSeverity : undefined,
        mode: matchFilterMode !== 'ALL' ? matchFilterMode : undefined,
        limit: 50,
      });
      setMatches(items);
    } catch (err: any) {
      console.error('Failed to load matches:', err);
    } finally {
      setLoadingMatches(false);
    }
  };

  const loadDeadLetters = async () => {
    setLoadingDeadLetters(true);
    try {
      const dls = await detectionRuleService.listDeadLetters();
      setDeadLetters(dls);
    } catch (err: any) {
      console.error('Failed to load dead letters:', err);
    } finally {
      setLoadingDeadLetters(false);
    }
  };

  useEffect(() => {
    loadPipelineMetrics();
  }, []);

  useEffect(() => {
    if (subTab === 'matches') {
      loadMatches();
    } else if (subTab === 'dead-letters') {
      loadDeadLetters();
    }
  }, [subTab, matchFilterSeverity, matchFilterMode]);

  const handleApplyPreset = (key: string) => {
    setSelectedPreset(key);
    const preset = SAMPLE_PAYLOADS[key];
    if (preset) {
      setEventSource(preset.source);
      setEventType(preset.event_type);
      setPayloadText(JSON.stringify(preset.payload, null, 2));
    }
  };

  const handleExecuteEvent = async () => {
    setExecutingEvent(true);
    setExecutionError(null);
    setExecutionResult(null);

    let parsedPayload: Record<string, any> = {};
    try {
      parsedPayload = JSON.parse(payloadText);
    } catch {
      setExecutionError('Invalid JSON format in event payload.');
      setExecutingEvent(false);
      return;
    }

    try {
      const payload: EventIngestPayload = {
        source: eventSource,
        event_type: eventType,
        payload: parsedPayload,
        mode: pipelineMode,
      };
      const result = await detectionRuleService.ingestEvent(payload);
      setExecutionResult(result);
      showFeedback(`Telemetry processed: ${result.matches_count} rule match(es) detected.`);
      loadPipelineMetrics();
    } catch (err: any) {
      setExecutionError(err.message || 'Pipeline evaluation failed.');
    } finally {
      setExecutingEvent(false);
    }
  };

  const handleInspectTrace = async (eventIdToTrace: string) => {
    if (!eventIdToTrace.trim()) return;
    setLoadingTrace(true);
    setTraceEventId(eventIdToTrace);
    try {
      const t = await detectionRuleService.getEventTrace(eventIdToTrace.trim());
      setTraceData(t);
      setSubTab('trace');
    } catch (err: any) {
      showFeedback(`Failed to load trace: ${err.message}`);
    } finally {
      setLoadingTrace(false);
    }
  };

  const handleRunReplay = async () => {
    setReplaying(true);
    setReplayResult(null);
    try {
      const res = await detectionRuleService.replayPipeline({
        max_events: replayMaxEvents,
      });
      setReplayResult(res);
      showFeedback(`Historical replay completed: ${res.total_events || 0} events evaluated.`);
      loadPipelineMetrics();
    } catch (err: any) {
      showFeedback(`Replay error: ${err.message}`);
    } finally {
      setReplaying(false);
    }
  };

  const handleRetryDeadLetter = async (id: string) => {
    setRetryingDlId(id);
    try {
      await detectionRuleService.retryDeadLetter(id);
      showFeedback('Dead-letter successfully re-evaluated.');
      loadDeadLetters();
      loadPipelineMetrics();
    } catch (err: any) {
      showFeedback(`Retry failed: ${err.message}`);
    } finally {
      setRetryingDlId(null);
    }
  };

  const getStatusBadge = (hStatus: string) => {
    switch (hStatus) {
      case 'HEALTHY':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <CheckCircle2 className="w-3 h-3 mr-1" />
            OPERATIONAL
          </span>
        );
      case 'DEGRADED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-3 h-3 mr-1" />
            DEGRADED
          </span>
        );
      case 'BACKLOGGED':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-purple-500/10 text-purple-400 border border-purple-500/20">
            <Clock className="w-3 h-3 mr-1" />
            BACKLOGGED
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <XCircle className="w-3 h-3 mr-1" />
            FAILING
          </span>
        );
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-rose-500/20 text-rose-400 border border-rose-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-yellow-500/20 text-yellow-400 border border-yellow-500/30">MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-bold rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">LOW</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* Toast feedback */}
      {feedbackMsg && (
        <div className="fixed bottom-6 right-6 z-50 bg-surface-secondary border border-primary/40 px-4 py-3 rounded-lg shadow-xl flex items-center space-x-2 text-foreground text-sm animate-fade-in">
          <Zap className="w-4 h-4 text-primary" />
          <span>{feedbackMsg}</span>
        </div>
      )}

      {/* Header & Pipeline Telemetry Bar */}
      <div className="bg-surface rounded-xl border border-border p-5 space-y-4 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-4">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Cpu className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-lg font-bold text-foreground">Unified Threat Detection Pipeline</h2>
                {getStatusBadge(metrics?.health_status || 'HEALTHY')}
                {status && (
                  <span className="text-[11px] font-mono text-foreground-muted ml-2">
                    Workers: {status.active_workers} | Queue: {status.queue_depth}
                  </span>
                )}
              </div>
              <p className="text-xs text-foreground-muted mt-0.5">
                Deterministic telemetry normalization, active rule resolution, AST evaluation, and finding/alert routing.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={loadPipelineMetrics}
              disabled={loadingMetrics}
              className="px-3 py-1.5 text-xs font-medium rounded-lg bg-surface-secondary border border-border text-foreground hover:bg-surface-hover transition-colors flex items-center space-x-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingMetrics ? 'animate-spin' : ''}`} />
              <span>Refresh Telemetry</span>
            </button>
          </div>
        </div>

        {/* Real Metrics Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3 pt-1">
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Ingested</span>
            <span className="text-lg font-bold font-mono text-foreground">{metrics?.events_received ?? 0}</span>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Processed</span>
            <span className="text-lg font-bold font-mono text-emerald-400">{metrics?.events_processed ?? 0}</span>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Rule Matches</span>
            <span className="text-lg font-bold font-mono text-primary">{metrics?.matches_created ?? 0}</span>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Findings</span>
            <span className="text-lg font-bold font-mono text-amber-400">{metrics?.findings_created ?? 0}</span>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Alerts</span>
            <span className="text-lg font-bold font-mono text-rose-400">{metrics?.alerts_created ?? 0}</span>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Errors</span>
            <span className="text-lg font-bold font-mono text-rose-400">{metrics?.errors_total ?? 0}</span>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Dead Letters</span>
            <span className="text-lg font-bold font-mono text-purple-400">{metrics?.dead_letters_total ?? 0}</span>
          </div>
          <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/60">
            <span className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider block">Avg Latency</span>
            <span className="text-lg font-bold font-mono text-cyan-400">{metrics?.avg_processing_latency_ms ? `${metrics.avg_processing_latency_ms}ms` : '0ms'}</span>
          </div>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex border-b border-border space-x-2">
        <button
          onClick={() => setSubTab('sandbox')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-colors flex items-center space-x-1.5 border-b-2 ${
            subTab === 'sandbox'
              ? 'border-primary text-primary bg-surface'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <Play className="w-3.5 h-3.5" />
          <span>Telemetry Evaluation Sandbox</span>
        </button>
        <button
          onClick={() => setSubTab('matches')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-colors flex items-center space-x-1.5 border-b-2 ${
            subTab === 'matches'
              ? 'border-primary text-primary bg-surface'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Detection Matches Stream</span>
        </button>
        <button
          onClick={() => setSubTab('trace')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-colors flex items-center space-x-1.5 border-b-2 ${
            subTab === 'trace'
              ? 'border-primary text-primary bg-surface'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <GitCommit className="w-3.5 h-3.5" />
          <span>End-to-End Trace Inspector</span>
        </button>
        <button
          onClick={() => setSubTab('replay')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-colors flex items-center space-x-1.5 border-b-2 ${
            subTab === 'replay'
              ? 'border-primary text-primary bg-surface'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Historical Replay</span>
        </button>
        <button
          onClick={() => setSubTab('dead-letters')}
          className={`px-4 py-2 text-xs font-semibold rounded-t-lg transition-colors flex items-center space-x-1.5 border-b-2 ${
            subTab === 'dead-letters'
              ? 'border-primary text-primary bg-surface'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <AlertOctagon className="w-3.5 h-3.5" />
          <span>Dead Letters</span>
          {metrics && metrics.dead_letters_total > 0 && (
            <span className="ml-1 px-1.5 py-0.2 rounded-full text-[10px] bg-purple-500/20 text-purple-400">
              {metrics.dead_letters_total}
            </span>
          )}
        </button>
      </div>

      {/* SUB-TAB 1: TELEMETRY EVALUATION SANDBOX */}
      {subTab === 'sandbox' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Ingestion Panel */}
          <div className="lg:col-span-5 bg-surface rounded-xl border border-border p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-foreground flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-primary" />
                <span>Telemetry Ingestion Console</span>
              </h3>
              <div className="flex items-center space-x-1">
                <span className="text-[11px] text-foreground-muted mr-1">Mode:</span>
                <button
                  type="button"
                  onClick={() => setPipelineMode('PRODUCTION')}
                  className={`px-2 py-0.5 text-[11px] font-medium rounded ${
                    pipelineMode === 'PRODUCTION'
                      ? 'bg-primary text-white'
                      : 'bg-surface-secondary text-foreground-muted'
                  }`}
                >
                  PRODUCTION
                </button>
                <button
                  type="button"
                  onClick={() => setPipelineMode('SHADOW')}
                  className={`px-2 py-0.5 text-[11px] font-medium rounded ${
                    pipelineMode === 'SHADOW'
                      ? 'bg-amber-500 text-white'
                      : 'bg-surface-secondary text-foreground-muted'
                  }`}
                >
                  SHADOW
                </button>
              </div>
            </div>

            {/* Presets */}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-foreground-muted">Threat Telemetry Preset</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => handleApplyPreset('powershell_c2')}
                  className={`p-2 rounded text-left text-xs transition-colors border ${
                    selectedPreset === 'powershell_c2'
                      ? 'bg-primary/10 border-primary text-primary'
                      : 'bg-surface-secondary border-border text-foreground hover:bg-surface-hover'
                  }`}
                >
                  <span className="font-semibold block">Suspicious PowerShell</span>
                  <span className="text-[10px] text-foreground-muted">Endpoint Process C2</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleApplyPreset('credential_bruteforce')}
                  className={`p-2 rounded text-left text-xs transition-colors border ${
                    selectedPreset === 'credential_bruteforce'
                      ? 'bg-primary/10 border-primary text-primary'
                      : 'bg-surface-secondary border-border text-foreground hover:bg-surface-hover'
                  }`}
                >
                  <span className="font-semibold block">Credential Burst</span>
                  <span className="text-[10px] text-foreground-muted">Auth Failure Spike</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleApplyPreset('phishing_payload')}
                  className={`p-2 rounded text-left text-xs transition-colors border ${
                    selectedPreset === 'phishing_payload'
                      ? 'bg-primary/10 border-primary text-primary'
                      : 'bg-surface-secondary border-border text-foreground hover:bg-surface-hover'
                  }`}
                >
                  <span className="font-semibold block">Phishing Ingress</span>
                  <span className="text-[10px] text-foreground-muted">SPF/DMARC Failure</span>
                </button>
                <button
                  type="button"
                  onClick={() => handleApplyPreset('c2_beaconing')}
                  className={`p-2 rounded text-left text-xs transition-colors border ${
                    selectedPreset === 'c2_beaconing'
                      ? 'bg-primary/10 border-primary text-primary'
                      : 'bg-surface-secondary border-border text-foreground hover:bg-surface-hover'
                  }`}
                >
                  <span className="font-semibold block">Tor C2 Beacon</span>
                  <span className="text-[10px] text-foreground-muted">TLS Network Exfil</span>
                </button>
              </div>
            </div>

            {/* Source & Event Type */}
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-medium text-foreground-muted block mb-1">Source Adapter</label>
                <select
                  value={eventSource}
                  onChange={(e) => setEventSource(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground"
                >
                  <option value="ENDPOINT">ENDPOINT</option>
                  <option value="EMAIL">EMAIL</option>
                  <option value="NETWORK">NETWORK</option>
                  <option value="AUTH">AUTH</option>
                  <option value="API">API</option>
                  <option value="GENERIC">GENERIC</option>
                </select>
              </div>
              <div>
                <label className="text-xs font-medium text-foreground-muted block mb-1">Event Schema</label>
                <input
                  type="text"
                  value={eventType}
                  onChange={(e) => setEventType(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-2.5 py-1.5 text-xs text-foreground font-mono"
                />
              </div>
            </div>

            {/* JSON Payload Editor */}
            <div className="space-y-1">
              <label className="text-xs font-medium text-foreground-muted flex justify-between">
                <span>Telemetry Payload (JSON)</span>
                <span className="text-[10px] text-foreground-muted">Bounded payload validation</span>
              </label>
              <textarea
                rows={10}
                value={payloadText}
                onChange={(e) => setPayloadText(e.target.value)}
                className="w-full bg-surface-secondary border border-border rounded-lg p-3 text-xs font-mono text-foreground focus:outline-none focus:border-primary"
              />
            </div>

            {executionError && (
              <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
                <XCircle className="w-4 h-4 shrink-0" />
                <span>{executionError}</span>
              </div>
            )}

            <button
              onClick={handleExecuteEvent}
              disabled={executingEvent}
              className="w-full py-2.5 rounded-lg bg-primary hover:bg-primary-hover text-white font-medium text-xs transition-colors flex items-center justify-center space-x-2 shadow-sm"
            >
              {executingEvent ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Evaluating Telemetry Through Pipeline...</span>
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  <span>Execute Pipeline Evaluation</span>
                </>
              )}
            </button>
          </div>

          {/* Results & Trace Output */}
          <div className="lg:col-span-7 bg-surface rounded-xl border border-border p-5 space-y-4">
            <h3 className="text-sm font-bold text-foreground flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-emerald-400" />
                <span>Execution Trace & Downstream Signals</span>
              </div>
              {executionResult && (
                <span className="text-xs font-mono text-cyan-400">
                  {executionResult.processing_duration_ms}ms total latency
                </span>
              )}
            </h3>

            {!executionResult && !executingEvent && (
              <div className="py-16 text-center border border-dashed border-border rounded-xl">
                <Terminal className="w-10 h-10 text-foreground-muted mx-auto mb-2 opacity-50" />
                <p className="text-xs text-foreground-muted">No telemetry executed in this session.</p>
                <p className="text-[11px] text-foreground-muted/70 mt-1">
                  Select a threat preset and click "Execute Pipeline Evaluation" to see deterministic rule matching.
                </p>
              </div>
            )}

            {executingEvent && (
              <div className="py-16 text-center border border-border rounded-xl space-y-3">
                <RefreshCw className="w-8 h-8 text-primary animate-spin mx-auto" />
                <p className="text-xs text-foreground font-medium">Running deterministic pipeline execution...</p>
                <p className="text-[11px] text-foreground-muted">
                  Normalizing schema → Selecting active rules → Evaluating AST logic → Persisting signals
                </p>
              </div>
            )}

            {executionResult && (
              <div className="space-y-4">
                {/* Result Summary Bar */}
                <div className="grid grid-cols-4 gap-2 p-3 bg-surface-secondary rounded-lg text-xs font-mono">
                  <div>
                    <span className="text-[10px] text-foreground-muted block">Applicable Rules</span>
                    <span className="font-bold text-foreground">{executionResult.applicable_rules_count}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-foreground-muted block">Evaluated</span>
                    <span className="font-bold text-foreground">{executionResult.evaluated_rules_count}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-foreground-muted block">Matches</span>
                    <span className="font-bold text-primary">{executionResult.matches_count}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-foreground-muted block">Suppressed</span>
                    <span className="font-bold text-amber-400">{executionResult.suppressed_count}</span>
                  </div>
                </div>

                {/* Normalized Event Entities & Provenance */}
                <div className="p-3 bg-surface-secondary/40 rounded-lg border border-border/80 space-y-2">
                  <span className="text-xs font-semibold text-foreground block">Extracted Entities & Indicators</span>
                  <div className="flex flex-wrap gap-1.5">
                    {executionResult.normalized_event.indicators.length > 0 ? (
                      executionResult.normalized_event.indicators.map((ind, i) => (
                        <span key={i} className="px-2 py-0.5 rounded text-[11px] font-mono bg-primary/10 text-primary border border-primary/20">
                          {ind}
                        </span>
                      ))
                    ) : (
                      <span className="text-[11px] text-foreground-muted">No explicit indicators extracted</span>
                    )}
                  </div>
                </div>

                {/* Evaluated Rules List */}
                <div className="space-y-2">
                  <span className="text-xs font-semibold text-foreground block">
                    Rule Evaluations ({executionResult.evaluations.length})
                  </span>

                  <div className="space-y-2 max-h-80 overflow-y-auto pr-1">
                    {executionResult.evaluations.map((ev, idx) => (
                      <div
                        key={idx}
                        className={`p-3 rounded-lg border text-xs space-y-1.5 transition-colors ${
                          ev.outcome === 'MATCH'
                            ? 'bg-emerald-500/5 border-emerald-500/30'
                            : ev.outcome === 'SUPPRESSED'
                            ? 'bg-amber-500/5 border-amber-500/30'
                            : 'bg-surface-secondary/30 border-border'
                        }`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="font-semibold text-foreground">{ev.rule_name}</span>
                            <span className="text-[10px] font-mono text-foreground-muted">v{ev.rule_version}</span>
                          </div>
                          <div className="flex items-center space-x-2">
                            {ev.outcome === 'MATCH' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400">
                                MATCH
                              </span>
                            )}
                            {ev.outcome === 'NO_MATCH' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-zinc-700 text-zinc-300">
                                NO_MATCH
                              </span>
                            )}
                            {ev.outcome === 'SUPPRESSED' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-amber-500/20 text-amber-400">
                                SUPPRESSED
                              </span>
                            )}
                            {ev.outcome === 'BLOCKED' && (
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-rose-500/20 text-rose-400">
                                BLOCKED (GATE)
                              </span>
                            )}
                            <span className="text-[10px] font-mono text-cyan-400">{ev.execution_duration_ms}ms</span>
                          </div>
                        </div>

                        {ev.explanation && (
                          <p className="text-[11px] text-foreground-muted">{ev.explanation}</p>
                        )}

                        {Object.keys(ev.matched_fields).length > 0 && (
                          <div className="p-2 rounded bg-surface border border-border/80 font-mono text-[10px] text-foreground-muted">
                            <span className="text-primary font-bold">Matched Fields: </span>
                            {JSON.stringify(ev.matched_fields)}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Downstream Actions */}
                <div className="p-3 bg-surface-secondary/60 rounded-lg border border-border flex items-center justify-between">
                  <div className="flex items-center space-x-4 text-xs">
                    <div>
                      <span className="text-foreground-muted">Findings Created: </span>
                      <span className="font-bold text-amber-400">{executionResult.findings_created}</span>
                    </div>
                    <div>
                      <span className="text-foreground-muted">Alerts Dispatched: </span>
                      <span className="font-bold text-rose-400">{executionResult.alerts_created}</span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleInspectTrace(executionResult.event_id)}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors flex items-center space-x-1"
                  >
                    <span>View Full Graph Trace</span>
                    <ArrowRight className="w-3 h-3" />
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* SUB-TAB 2: DETECTION MATCHES STREAM */}
      {subTab === 'matches' && (
        <div className="bg-surface rounded-xl border border-border p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <h3 className="text-sm font-bold text-foreground flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-primary" />
              <span>Deterministic Detection Matches</span>
            </h3>

            <div className="flex items-center space-x-2">
              <select
                value={matchFilterSeverity}
                onChange={(e) => setMatchFilterSeverity(e.target.value)}
                className="bg-surface-secondary border border-border rounded-lg px-2.5 py-1 text-xs text-foreground"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <select
                value={matchFilterMode}
                onChange={(e) => setMatchFilterMode(e.target.value)}
                className="bg-surface-secondary border border-border rounded-lg px-2.5 py-1 text-xs text-foreground"
              >
                <option value="ALL">All Modes</option>
                <option value="PRODUCTION">PRODUCTION</option>
                <option value="SHADOW">SHADOW</option>
                <option value="REPLAY">REPLAY</option>
              </select>

              <button
                onClick={loadMatches}
                className="p-1.5 rounded-lg bg-surface-secondary border border-border hover:bg-surface-hover text-foreground"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${loadingMatches ? 'animate-spin' : ''}`} />
              </button>
            </div>
          </div>

          {loadingMatches ? (
            <div className="py-12 text-center text-xs text-foreground-muted">Loading matches...</div>
          ) : matches.length === 0 ? (
            <div className="py-12 text-center text-xs text-foreground-muted border border-dashed border-border rounded-lg">
              0 detection matches found for current filter.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-foreground-muted font-medium">
                    <th className="py-2.5 px-3">Rule Name</th>
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Mode</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3">Matched At</th>
                    <th className="py-2.5 px-3">Finding</th>
                    <th className="py-2.5 px-3">Alert</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {matches.map((m) => (
                    <tr key={m.id} className="hover:bg-surface-secondary/40 transition-colors">
                      <td className="py-2.5 px-3 font-medium text-foreground">
                        {m.rule_name || m.rule_id}
                        <span className="text-[10px] font-mono text-foreground-muted ml-1.5">v{m.rule_version}</span>
                      </td>
                      <td className="py-2.5 px-3">{getSeverityBadge(m.severity)}</td>
                      <td className="py-2.5 px-3">
                        <span className="font-mono text-[11px] text-foreground-muted">{m.mode}</span>
                      </td>
                      <td className="py-2.5 px-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          m.status === 'MATCH' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                        }`}>
                          {m.status}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 font-mono text-foreground-muted text-[11px]">
                        {new Date(m.matched_at).toLocaleTimeString()}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px]">
                        {m.finding_id ? (
                          <span className="text-amber-400">Created</span>
                        ) : (
                          <span className="text-foreground-muted">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 font-mono text-[11px]">
                        {m.alert_id ? (
                          <span className="text-rose-400">Dispatched</span>
                        ) : (
                          <span className="text-foreground-muted">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => setSelectedMatch(m)}
                          className="px-2 py-1 rounded bg-surface-secondary border border-border hover:bg-surface-hover text-foreground text-[11px]"
                        >
                          Evidence
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Evidence Slide-over / Modal */}
          {selectedMatch && (
            <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
              <div className="bg-surface rounded-xl border border-border max-w-2xl w-full p-5 space-y-4 max-h-[85vh] overflow-y-auto">
                <div className="flex items-center justify-between border-b border-border pb-3">
                  <h4 className="text-sm font-bold text-foreground">
                    Detection Match Evidence: {selectedMatch.rule_name || selectedMatch.rule_id}
                  </h4>
                  <button
                    onClick={() => setSelectedMatch(null)}
                    className="p-1 rounded text-foreground-muted hover:text-foreground"
                  >
                    <XCircle className="w-5 h-5" />
                  </button>
                </div>

                <div className="space-y-3 text-xs">
                  <div>
                    <span className="font-semibold text-foreground-muted block mb-1">Human Explanation:</span>
                    <p className="p-3 bg-surface-secondary rounded-lg text-foreground font-sans">
                      {selectedMatch.explanation || 'No textual explanation recorded.'}
                    </p>
                  </div>

                  <div>
                    <span className="font-semibold text-foreground-muted block mb-1">Matched Fields:</span>
                    <pre className="p-3 bg-surface-secondary rounded-lg text-foreground font-mono text-[11px] overflow-x-auto">
                      {JSON.stringify(selectedMatch.matched_fields || {}, null, 2)}
                    </pre>
                  </div>

                  <div>
                    <span className="font-semibold text-foreground-muted block mb-1">Evidence Context:</span>
                    <pre className="p-3 bg-surface-secondary rounded-lg text-foreground font-mono text-[11px] overflow-x-auto">
                      {JSON.stringify(selectedMatch.evidence || {}, null, 2)}
                    </pre>
                  </div>

                  <div>
                    <span className="font-semibold text-foreground-muted block mb-1">Provenance Chain:</span>
                    <pre className="p-3 bg-surface-secondary rounded-lg text-foreground font-mono text-[11px] overflow-x-auto">
                      {JSON.stringify(selectedMatch.provenance || {}, null, 2)}
                    </pre>
                  </div>
                </div>

                <div className="border-t border-border pt-3 flex justify-end">
                  <button
                    onClick={() => setSelectedMatch(null)}
                    className="px-4 py-2 text-xs font-medium rounded-lg bg-surface-secondary border border-border text-foreground hover:bg-surface-hover"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 3: END-TO-END TRACE INSPECTOR */}
      {subTab === 'trace' && (
        <div className="bg-surface rounded-xl border border-border p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-bold text-foreground flex items-center space-x-2">
                <GitCommit className="w-4 h-4 text-primary" />
                <span>End-to-End Pipeline Trace Inspector</span>
              </h3>
              <p className="text-xs text-foreground-muted mt-0.5">
                Deterministic lifecycle: Telemetry → Normalization → Applicable Rules → Evaluator Outcome → Finding → Risk → Alert.
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <input
                type="text"
                placeholder="Enter event ID (e.g. evt-93...)"
                value={traceEventId}
                onChange={(e) => setTraceEventId(e.target.value)}
                className="bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-xs text-foreground font-mono w-64"
              />
              <button
                onClick={() => handleInspectTrace(traceEventId)}
                disabled={loadingTrace}
                className="px-3 py-1.5 text-xs font-medium rounded-lg bg-primary hover:bg-primary-hover text-white transition-colors"
              >
                {loadingTrace ? 'Tracing...' : 'Trace'}
              </button>
            </div>
          </div>

          {!traceData ? (
            <div className="py-16 text-center border border-dashed border-border rounded-xl">
              <Search className="w-8 h-8 text-foreground-muted mx-auto mb-2 opacity-50" />
              <p className="text-xs text-foreground-muted">Enter a Security Event ID above to inspect its execution trace.</p>
            </div>
          ) : (
            <div className="space-y-6 pt-2">
              {/* Stages Bar */}
              <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
                {traceData.stages?.map((st: any, i: number) => (
                  <div key={i} className="p-3 bg-surface-secondary rounded-lg border border-border space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-bold text-foreground">{st.stage}</span>
                      <span className={`text-[10px] font-semibold ${
                        st.status === 'COMPLETED' ? 'text-emerald-400' : 'text-zinc-400'
                      }`}>
                        {st.status}
                      </span>
                    </div>
                    <p className="text-[10px] text-foreground-muted leading-tight">{st.detail}</p>
                  </div>
                ))}
              </div>

              {/* Matched Rules in this event */}
              <div className="space-y-2">
                <h4 className="text-xs font-bold text-foreground">Detection Matches ({traceData.matches?.length || 0})</h4>
                <div className="space-y-2">
                  {traceData.matches?.map((m: any, idx: number) => (
                    <div key={idx} className="p-3 bg-surface-secondary/40 rounded-lg border border-border text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-foreground">{m.rule_id} (v{m.rule_version})</span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-rose-500/20 text-rose-400">
                          {m.severity}
                        </span>
                      </div>
                      <p className="text-[11px] text-foreground-muted">{m.explanation}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Linked Findings & Alerts */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-2">
                  <span className="text-xs font-bold text-foreground">Downstream Findings ({traceData.findings?.length || 0})</span>
                  {traceData.findings?.length === 0 ? (
                    <p className="text-[11px] text-foreground-muted">No findings generated.</p>
                  ) : (
                    traceData.findings.map((f: any, i: number) => (
                      <div key={i} className="p-2 rounded bg-surface border border-border text-xs flex justify-between items-center">
                        <span className="font-medium text-foreground">{f.title}</span>
                        <span className="text-amber-400 font-mono text-[10px]">{f.severity}</span>
                      </div>
                    ))
                  )}
                </div>

                <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-2">
                  <span className="text-xs font-bold text-foreground">Downstream Alerts ({traceData.alerts?.length || 0})</span>
                  {traceData.alerts?.length === 0 ? (
                    <p className="text-[11px] text-foreground-muted">No security alerts dispatched.</p>
                  ) : (
                    traceData.alerts.map((a: any, i: number) => (
                      <div key={i} className="p-2 rounded bg-surface border border-border text-xs flex justify-between items-center">
                        <span className="font-medium text-foreground">{a.title}</span>
                        <span className="text-rose-400 font-mono text-[10px]">{a.severity}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 4: HISTORICAL REPLAY */}
      {subTab === 'replay' && (
        <div className="bg-surface rounded-xl border border-border p-5 space-y-4 max-w-3xl">
          <div>
            <h3 className="text-sm font-bold text-foreground flex items-center space-x-2">
              <RotateCcw className="w-4 h-4 text-primary" />
              <span>Controlled Historical Event Replay</span>
            </h3>
            <p className="text-xs text-foreground-muted mt-1">
              Replay evaluates past security events against currently active detection rules in{' '}
              <span className="font-mono text-cyan-400 font-semibold">REPLAY</span> mode. Matches are logged for rule quality validation without producing production alerts or dispatching SOC notifications.
            </p>
          </div>

          <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg text-amber-300 text-xs flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 shrink-0 text-amber-400" />
            <span>
              Safe Sandboxed Replay: All generated matches will have status REPLAY and are fully excluded from active SOC queues.
            </span>
          </div>

          <div className="space-y-3 pt-2">
            <div>
              <label className="text-xs font-medium text-foreground-muted block mb-1">Max Events to Replay</label>
              <input
                type="number"
                min={1}
                max={500}
                value={replayMaxEvents}
                onChange={(e) => setReplayMaxEvents(parseInt(e.target.value) || 50)}
                className="w-40 bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-xs text-foreground font-mono"
              />
            </div>

            <button
              onClick={handleRunReplay}
              disabled={replaying}
              className="px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-white text-xs font-medium transition-colors flex items-center space-x-2"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${replaying ? 'animate-spin' : ''}`} />
              <span>{replaying ? 'Executing Replay...' : 'Start Historical Replay'}</span>
            </button>
          </div>

          {replayResult && (
            <div className="p-4 bg-surface-secondary rounded-lg border border-border space-y-2 text-xs">
              <span className="font-bold text-foreground block">Replay Execution Completed</span>
              <div className="grid grid-cols-3 gap-2 font-mono">
                <div>
                  <span className="text-foreground-muted text-[10px] block">Total Events Replayed</span>
                  <span className="text-foreground font-bold">{replayResult.total_events}</span>
                </div>
                <div>
                  <span className="text-foreground-muted text-[10px] block">Matches Detected</span>
                  <span className="text-primary font-bold">{replayResult.matched_events}</span>
                </div>
                <div>
                  <span className="text-foreground-muted text-[10px] block">Errors</span>
                  <span className="text-rose-400 font-bold">{replayResult.error_events}</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUB-TAB 5: DEAD LETTERS */}
      {subTab === 'dead-letters' && (
        <div className="bg-surface rounded-xl border border-border p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-foreground flex items-center space-x-2">
                <AlertOctagon className="w-4 h-4 text-purple-400" />
                <span>Dead-Letter Telemetry Queue</span>
              </h3>
              <p className="text-xs text-foreground-muted mt-0.5">
                Poison payloads, malformed telemetry, and unrecoverable pipeline processing errors isolated for administrator inspection.
              </p>
            </div>
            <button
              onClick={loadDeadLetters}
              className="p-1.5 rounded-lg bg-surface-secondary border border-border hover:bg-surface-hover text-foreground"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loadingDeadLetters ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {loadingDeadLetters ? (
            <div className="py-12 text-center text-xs text-foreground-muted">Loading dead letters...</div>
          ) : deadLetters.length === 0 ? (
            <div className="py-12 text-center text-xs text-foreground-muted border border-dashed border-border rounded-lg">
              0 dead-letter events in queue. All telemetry processed successfully.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-foreground-muted font-medium">
                    <th className="py-2.5 px-3">Event ID</th>
                    <th className="py-2.5 px-3">Source</th>
                    <th className="py-2.5 px-3">Failure Stage</th>
                    <th className="py-2.5 px-3">Error Code</th>
                    <th className="py-2.5 px-3">Message</th>
                    <th className="py-2.5 px-3">Attempts</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {deadLetters.map((dl) => (
                    <tr key={dl.id} className="hover:bg-surface-secondary/40 transition-colors">
                      <td className="py-2.5 px-3 font-mono text-[11px] text-foreground">{dl.event_id}</td>
                      <td className="py-2.5 px-3 font-semibold text-foreground">{dl.source_type}</td>
                      <td className="py-2.5 px-3 text-amber-400 font-mono text-[11px]">{dl.failure_stage}</td>
                      <td className="py-2.5 px-3 text-rose-400 font-mono text-[11px]">{dl.error_code}</td>
                      <td className="py-2.5 px-3 text-foreground-muted truncate max-w-xs">{dl.error_message}</td>
                      <td className="py-2.5 px-3 font-mono text-[11px] text-foreground">{dl.attempt_count}</td>
                      <td className="py-2.5 px-3 text-right">
                        <button
                          onClick={() => handleRetryDeadLetter(dl.id)}
                          disabled={retryingDlId === dl.id}
                          className="px-2.5 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 text-[11px] font-medium"
                        >
                          {retryingDlId === dl.id ? 'Retrying...' : 'Retry'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
