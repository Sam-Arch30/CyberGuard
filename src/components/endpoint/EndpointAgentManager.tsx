import React, { useState, useEffect } from 'react';
import {
  Shield,
  Laptop,
  CheckCircle2,
  Clock,
  Key,
  RefreshCw,
  Terminal,
  Copy,
  Check,
  ChevronRight,
  Info
} from 'lucide-react';

interface AgentSummary {
  id: string;
  agent_id: string;
  device_id: string;
  workspace_id: string;
  hostname: string;
  platform: string;
  platform_version?: string;
  architecture?: string;
  agent_version: string;
  status: 'ACTIVE' | 'DEGRADED' | 'OFFLINE' | 'REVOKED' | 'DISABLED';
  enrollment_state: string;
  configuration_version: string;
  last_seen_at: string;
  last_heartbeat_at?: string;
  clock_offset_ms: number;
  enrolled_at: string;
}

interface DeviceSummary {
  id: string;
  workspace_id: string;
  device_uid: string;
  hostname: string;
  platform: string;
  status: string;
  agent_count: number;
  last_seen_at: string;
}

interface FleetMetrics {
  agents_enrolled: number;
  agents_active: number;
  agents_degraded: number;
  agents_revoked: number;
  devices_total: number;
  events_received: number;
}

export const EndpointAgentManager: React.FC = () => {
  const [agents, setAgents] = useState<AgentSummary[]>([]);
  const [, setDevices] = useState<DeviceSummary[]>([]);
  const [metrics, setMetrics] = useState<FleetMetrics | null>(null);
  const [selectedAgent, setSelectedAgent] = useState<AgentSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [generatingToken, setGeneratingToken] = useState(false);
  const [generatedToken, setGeneratedToken] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);
  const [triggeringSynthetic, setTriggeringSynthetic] = useState(false);
  const [syntheticStatus, setSyntheticStatus] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [agentsRes, devicesRes, metricsRes] = await Promise.all([
        fetch('/api/v1/endpoint/agents').then(r => r.ok ? r.json() : []),
        fetch('/api/v1/endpoint/devices').then(r => r.ok ? r.json() : []),
        fetch('/api/v1/endpoint/metrics').then(r => r.ok ? r.json() : null)
      ]);
      setAgents(agentsRes);
      setDevices(devicesRes);
      setMetrics(metricsRes);
      if (agentsRes.length > 0 && !selectedAgent) {
        setSelectedAgent(agentsRes[0]);
      }
    } catch (err) {
      console.error('Failed to load endpoint telemetry agents:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateToken = async () => {
    try {
      setGeneratingToken(true);
      const res = await fetch('/api/v1/endpoint/enrollment/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workspace_id: 'default',
          description: 'Web Console Admin Enrollment',
          expires_in_minutes: 60,
          max_uses: 1
        })
      });
      if (res.ok) {
        const data = await res.json();
        setGeneratedToken(data.raw_token);
      }
    } catch (err) {
      console.error('Token generation error:', err);
    } finally {
      setGeneratingToken(false);
    }
  };

  const handleRevokeAgent = async (agentId: string) => {
    if (!window.confirm(`Revoke credentials and disable telemetry for agent ${agentId}?`)) {
      return;
    }
    try {
      const res = await fetch(`/api/v1/endpoint/agents/${agentId}/revoke?reason=AdminRevoked`, {
        method: 'POST'
      });
      if (res.ok) {
        fetchData();
        setSelectedAgent(null);
      }
    } catch (err) {
      console.error('Revocation error:', err);
    }
  };

  const handleRunSyntheticAgent = async () => {
    try {
      setTriggeringSynthetic(true);
      setSyntheticStatus('Generating safe synthetic telemetry (PROCESS, DNS, NETWORK, AUTH)...');

      // 1. Create short-lived token
      const tokRes = await fetch('/api/v1/endpoint/enrollment/tokens', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          workspace_id: 'default',
          description: 'Synthetic Test Harness',
          expires_in_minutes: 15,
          max_uses: 1
        })
      });
      const tokData = await tokRes.json();

      // 2. Enroll simulated test agent
      const enrollRes = await fetch('/api/v1/endpoint/enrollment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          enrollment_token: tokData.raw_token,
          device_uid: `SIM-MAC-${Date.now().toString().slice(-6)}`,
          hostname: 'demo-macbook-pro.local',
          platform: 'macos',
          os_version: 'macOS 15.1 (Sequoia)',
          architecture: 'arm64',
          agent_version: '1.0.0-demo'
        })
      });
      const enrollData = await enrollRes.json();

      // 3. Dispatch synthetic events batch
      const nowIso = new Date().toISOString();
      const eventsRes = await fetch('/api/v1/endpoint/events', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          agent_id: enrollData.agent_id,
          batch_id: `DEMO-BATCH-${Date.now()}`,
          timestamp: nowIso,
          events: [
            {
              event_id: `sim-proc-${Date.now()}`,
              sequence_number: 1,
              event_type: 'PROCESS',
              event_time: nowIso,
              collector_id: 'synthetic_collector',
              collector_version: '1.0.0',
              configuration_version: '1.0.0',
              agent_version: '1.0.0-demo',
              schema_version: '1.0.0',
              priority: 'NORMAL',
              payload: {
                process_name: 'curl',
                command_line: 'curl -s https://telemetry.internal.corp/health',
                pid: 8412,
                synthetic: true,
                badge: 'SIMULATED'
              }
            },
            {
              event_id: `sim-dns-${Date.now()}`,
              sequence_number: 2,
              event_type: 'DNS',
              event_time: nowIso,
              collector_id: 'synthetic_collector',
              collector_version: '1.0.0',
              configuration_version: '1.0.0',
              agent_version: '1.0.0-demo',
              schema_version: '1.0.0',
              priority: 'LOW',
              payload: {
                query_name: 'telemetry.internal.corp',
                query_type: 'A',
                answers: ['10.0.1.50'],
                synthetic: true,
                badge: 'SIMULATED'
              }
            }
          ]
        })
      });

      if (eventsRes.ok) {
        setSyntheticStatus('Simulated agent enrolled & telemetry normalized into ThreatEvents!');
        fetchData();
      }
    } catch (err: any) {
      setSyntheticStatus(`Error: ${err.message}`);
    } finally {
      setTriggeringSynthetic(false);
      setTimeout(() => setSyntheticStatus(null), 5000);
    }
  };

  const formatRelativeTime = (isoString?: string) => {
    if (!isoString) return 'Never';
    const diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (diff < 5) return 'just now';
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    return `${Math.floor(diff / 3600)}h ago`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-2xl font-bold tracking-tight text-foreground">Endpoint Agent Architecture</h1>
            <span className="px-2 py-0.5 text-xs font-semibold rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
              SECTION 31
            </span>
          </div>
          <p className="text-sm text-muted-foreground mt-1">
            Authorized host telemetry agents forwarding normalized events to the Universal Ingestion Gateway.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={fetchData}
            className="p-2 rounded-lg border border-border hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
            title="Refresh Fleet State"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={handleRunSyntheticAgent}
            disabled={triggeringSynthetic}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-50"
          >
            <Terminal className="w-3.5 h-3.5" />
            {triggeringSynthetic ? 'Running Test...' : 'Run Test Agent'}
          </button>
          <button
            onClick={handleCreateToken}
            disabled={generatingToken}
            className="flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <Key className="w-3.5 h-3.5" />
            Generate Token
          </button>
        </div>
      </div>

      {/* Synthetic Banner */}
      {syntheticStatus && (
        <div className="flex items-center gap-2 p-3 text-xs rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-300">
          <Info className="w-4 h-4 shrink-0" />
          <span>{syntheticStatus}</span>
        </div>
      )}

      {/* Fleet Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3 rounded-lg border border-border bg-card/50">
          <div className="text-xs text-muted-foreground">Enrolled Agents</div>
          <div className="text-xl font-bold mt-1 text-foreground">{metrics?.agents_enrolled ?? 0}</div>
        </div>
        <div className="p-3 rounded-lg border border-border bg-card/50">
          <div className="text-xs text-muted-foreground">Active</div>
          <div className="text-xl font-bold mt-1 text-emerald-400">{metrics?.agents_active ?? 0}</div>
        </div>
        <div className="p-3 rounded-lg border border-border bg-card/50">
          <div className="text-xs text-muted-foreground">Degraded</div>
          <div className="text-xl font-bold mt-1 text-amber-400">{metrics?.agents_degraded ?? 0}</div>
        </div>
        <div className="p-3 rounded-lg border border-border bg-card/50">
          <div className="text-xs text-muted-foreground">Revoked</div>
          <div className="text-xl font-bold mt-1 text-rose-400">{metrics?.agents_revoked ?? 0}</div>
        </div>
        <div className="p-3 rounded-lg border border-border bg-card/50">
          <div className="text-xs text-muted-foreground">Unique Devices</div>
          <div className="text-xl font-bold mt-1 text-foreground">{metrics?.devices_total ?? 0}</div>
        </div>
        <div className="p-3 rounded-lg border border-border bg-card/50">
          <div className="text-xs text-muted-foreground">Raw Telemetry Events</div>
          <div className="text-xl font-bold mt-1 text-cyan-400">{metrics?.events_received ?? 0}</div>
        </div>
      </div>

      {/* Generated Token Modal Overlay */}
      {generatedToken && (
        <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-500/5 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-amber-400 font-semibold text-sm">
              <Key className="w-4 h-4" />
              <span>One-Time Enrollment Token Created</span>
            </div>
            <button
              onClick={() => setGeneratedToken(null)}
              className="text-xs text-muted-foreground hover:text-foreground"
            >
              Dismiss
            </button>
          </div>
          <p className="text-xs text-muted-foreground">
            Provide this token to the endpoint installer. It is single-use, expires in 60 minutes, and will not be displayed again.
          </p>
          <div className="flex items-center gap-2 bg-background p-2 rounded-lg border border-border font-mono text-xs">
            <span className="flex-1 select-all break-all text-foreground">{generatedToken}</span>
            <button
              onClick={() => {
                navigator.clipboard.writeText(generatedToken);
                setCopiedToken(true);
                setTimeout(() => setCopiedToken(false), 2000);
              }}
              className="p-1.5 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
              title="Copy Token"
            >
              {copiedToken ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
            </button>
          </div>
        </div>
      )}

      {/* Main View: Split Agent List & Progressive Disclosure Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Enrolled Endpoints Compact List */}
        <div className="lg:col-span-5 space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground px-1">
            Enrolled Endpoints ({agents.length})
          </div>

          {agents.length === 0 ? (
            <div className="p-8 text-center rounded-xl border border-dashed border-border bg-card/30 text-muted-foreground">
              <Laptop className="w-8 h-8 mx-auto mb-2 opacity-40" />
              <p className="text-sm font-medium">No Endpoint Agents Enrolled</p>
              <p className="text-xs mt-1">Use "Run Test Agent" or "Generate Token" to enroll authorized hosts.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {agents.map(ag => {
                const isSelected = selectedAgent?.id === ag.id;
                const isDemo = ag.agent_version.includes('demo');

                return (
                  <div
                    key={ag.id}
                    onClick={() => setSelectedAgent(ag)}
                    className={`p-3 rounded-xl border transition-all cursor-pointer flex items-center justify-between ${
                      isSelected
                        ? 'border-cyan-500/50 bg-cyan-500/5 shadow-sm'
                        : 'border-border bg-card/60 hover:border-border/80 hover:bg-card'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className="w-8 h-8 rounded-lg bg-muted flex items-center justify-center shrink-0">
                        <Laptop className="w-4 h-4 text-foreground" />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm text-foreground truncate">{ag.hostname}</span>
                          {isDemo && (
                            <span className="px-1.5 py-0.2 text-[10px] font-bold rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                              SIMULATED
                            </span>
                          )}
                        </div>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                          <span>v{ag.agent_version}</span>
                          <span>•</span>
                          <span>{ag.platform}</span>
                          <span>•</span>
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {formatRelativeTime(ag.last_seen_at)}
                          </span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`px-2 py-0.5 text-xs font-semibold rounded ${
                          ag.status === 'ACTIVE'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : ag.status === 'DEGRADED'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                            : ag.status === 'REVOKED'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                            : 'bg-muted text-muted-foreground'
                        }`}
                      >
                        {ag.status}
                      </span>
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Progressive Disclosure Detail View */}
        <div className="lg:col-span-7">
          {selectedAgent ? (
            <div className="p-5 rounded-xl border border-border bg-card/60 space-y-6">
              {/* Detail Header */}
              <div className="flex items-start justify-between gap-4 pb-4 border-b border-border">
                <div>
                  <div className="flex items-center gap-2">
                    <h2 className="text-lg font-bold text-foreground">{selectedAgent.hostname}</h2>
                    <span
                      className={`px-2 py-0.5 text-xs font-semibold rounded ${
                        selectedAgent.status === 'ACTIVE'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      {selectedAgent.status}
                    </span>
                    {selectedAgent.agent_version.includes('demo') && (
                      <span className="px-1.5 py-0.2 text-[10px] font-bold rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">
                        SIMULATED / DEMO
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground mt-1 font-mono">{selectedAgent.agent_id}</p>
                </div>

                {selectedAgent.status !== 'REVOKED' && (
                  <button
                    onClick={() => handleRevokeAgent(selectedAgent.agent_id)}
                    className="px-2.5 py-1 text-xs font-medium rounded-lg border border-rose-500/30 text-rose-400 hover:bg-rose-500/10 transition-colors"
                  >
                    Revoke Agent
                  </button>
                )}
              </div>

              {/* Identity & Hardware Metadata */}
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                <div>
                  <div className="text-muted-foreground">Platform</div>
                  <div className="font-medium text-foreground mt-0.5 capitalize">{selectedAgent.platform}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">OS Version</div>
                  <div className="font-medium text-foreground mt-0.5">{selectedAgent.platform_version || 'N/A'}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Architecture</div>
                  <div className="font-medium text-foreground mt-0.5">{selectedAgent.architecture || 'Unknown'}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Agent Runtime</div>
                  <div className="font-medium text-foreground mt-0.5">v{selectedAgent.agent_version}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Config Version</div>
                  <div className="font-medium text-foreground mt-0.5">v{selectedAgent.configuration_version}</div>
                </div>
                <div>
                  <div className="text-muted-foreground">Clock Offset</div>
                  <div className="font-medium text-foreground mt-0.5">{selectedAgent.clock_offset_ms} ms</div>
                </div>
              </div>

              {/* Security Boundary Notice */}
              <div className="p-3 rounded-lg border border-border/80 bg-background/50 space-y-1">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-foreground">
                  <Shield className="w-3.5 h-3.5 text-cyan-400" />
                  <span>Security & Observation Boundary</span>
                </div>
                <p className="text-[11px] text-muted-foreground leading-relaxed">
                  CYBERGUARD endpoint agents run with strictly bounded user privileges. Remote arbitrary shells, command execution, and covert monitoring are strictly forbidden by architectural design.
                </p>
              </div>

              {/* Collector & Telemetry Status */}
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">
                  Active Collector Adapters
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                  <div className="p-2.5 rounded-lg border border-border bg-card flex items-center justify-between">
                    <span className="font-medium text-foreground">Process Collector</span>
                    <span className="flex items-center gap-1 text-emerald-400 text-[11px]">
                      <CheckCircle2 className="w-3 h-3" /> Active
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg border border-border bg-card flex items-center justify-between">
                    <span className="font-medium text-foreground">DNS & Network</span>
                    <span className="flex items-center gap-1 text-emerald-400 text-[11px]">
                      <CheckCircle2 className="w-3 h-3" /> Active
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg border border-border bg-card flex items-center justify-between">
                    <span className="font-medium text-foreground">Authentication Logs</span>
                    <span className="flex items-center gap-1 text-emerald-400 text-[11px]">
                      <CheckCircle2 className="w-3 h-3" /> Active
                    </span>
                  </div>
                  <div className="p-2.5 rounded-lg border border-border bg-card flex items-center justify-between">
                    <span className="font-medium text-foreground">File Metadata</span>
                    <span className="flex items-center gap-1 text-emerald-400 text-[11px]">
                      <CheckCircle2 className="w-3 h-3" /> Active
                    </span>
                  </div>
                </div>
              </div>

              {/* Timestamps */}
              <div className="text-[11px] text-muted-foreground pt-3 border-t border-border flex flex-wrap gap-4 justify-between">
                <div>Enrolled: {new Date(selectedAgent.enrolled_at).toLocaleString()}</div>
                <div>Last Seen: {new Date(selectedAgent.last_seen_at).toLocaleString()}</div>
              </div>
            </div>
          ) : (
            <div className="h-full flex items-center justify-center p-8 rounded-xl border border-dashed border-border text-muted-foreground text-sm">
              Select an endpoint agent on the left to view device identity, collectors, and health telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
