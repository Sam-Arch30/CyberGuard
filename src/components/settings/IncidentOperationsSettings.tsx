import React, { useState, useEffect, useCallback } from 'react';
import {
  Clock,
  ArrowUpRight,
  UserCheck,
  Plus,
  Play,
  RefreshCw,
  Sliders,
  Sparkles,
  X,
  AlertTriangle,
} from 'lucide-react';
import { SlaClientService } from '../../services/slaService';
import type {
  SLAPolicyResponse,
  EscalationPolicyResponse,
  EscalationRule,
  RoutingRuleResponse,
  SLAPolicySimulateRequest,
  SLAPolicySimulateResponse,
  CreateSLAPolicyRequest,
  IncidentSeverity,
  IncidentPriority,
  IncidentCategory,
} from '../../types';

export const IncidentOperationsSettings: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<'sla' | 'escalation' | 'routing' | 'simulate'>('sla');

  // Lists
  const [slaPolicies, setSlaPolicies] = useState<SLAPolicyResponse[]>([]);
  const [escalationPolicies, setEscalationPolicies] = useState<EscalationPolicyResponse[]>([]);
  const [routingRules, setRoutingRules] = useState<RoutingRuleResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Modals
  const [showCreateSlaModal, setShowCreateSlaModal] = useState<boolean>(false);
  const [newSlaName, setNewSlaName] = useState<string>('');
  const [newSlaSev, setNewSlaSev] = useState<string>('ALL');
  const [newSlaPrio, setNewSlaPrio] = useState<string>('ALL');
  const [newAckTarget, setNewAckTarget] = useState<number>(30);
  const [newInvTarget, setNewInvTarget] = useState<number>(60);
  const [newContTarget, setNewContTarget] = useState<number>(180);
  const [newResTarget, setNewResTarget] = useState<number>(720);
  const [newWarnPct, setNewWarnPct] = useState<number>(80);

  // Simulation State
  const [simSeverity, setSimSeverity] = useState<IncidentSeverity>('CRITICAL');
  const [simPriority, setSimPriority] = useState<IncidentPriority>('P1_CRITICAL');
  const [simCategory, setSimCategory] = useState<string>('RANSOMWARE');
  const [simElapsed, setSimElapsed] = useState<number>(35);
  const [simAcked, setSimAcked] = useState<boolean>(false);
  const [simContained, setSimContained] = useState<boolean>(false);
  const [simResolved, setSimResolved] = useState<boolean>(false);
  const [simResult, setSimResult] = useState<SLAPolicySimulateResponse | null>(null);
  const [simulating, setSimulating] = useState<boolean>(false);
  const [simError, setSimError] = useState<string | null>(null);

  // Load Policies
  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [slaRes, escRes, routeRes] = await Promise.all([
        SlaClientService.listSLAPolicies(),
        SlaClientService.listEscalationPolicies(),
        SlaClientService.listRoutingRules(),
      ]);
      setSlaPolicies(slaRes);
      setEscalationPolicies(escRes);
      setRoutingRules(routeRes as unknown as RoutingRuleResponse[]);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load policy configurations');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle Create SLA Policy
  const handleCreateSlaPolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSlaName.trim()) {
      alert('Policy name is required.');
      return;
    }
    try {
      const payload: CreateSLAPolicyRequest = {
        name: newSlaName.trim(),
        severity: newSlaSev === 'ALL' ? undefined : (newSlaSev as IncidentSeverity),
        priority: newSlaPrio === 'ALL' ? undefined : (newSlaPrio as IncidentPriority),
        acknowledgement_target_minutes: newAckTarget,
        investigation_target_minutes: newInvTarget,
        containment_target_minutes: newContTarget,
        resolution_target_minutes: newResTarget,
        warning_threshold_pct: newWarnPct,
        status: 'ACTIVE',
      };
      await SlaClientService.createSLAPolicy(payload);
      setShowCreateSlaModal(false);
      setNewSlaName('');
      await loadData();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to create SLA policy');
    }
  };

  // Run Simulation Dry-Run
  const handleRunSimulation = async () => {
    try {
      setSimulating(true);
      setSimError(null);
      const req: SLAPolicySimulateRequest = {
        severity: simSeverity,
        priority: simPriority,
        category: simCategory as IncidentCategory,
        risk_score: 80,
        unacknowledged_minutes: simAcked ? 0 : simElapsed,
        uncontained_minutes: simContained ? 0 : simElapsed,
        status: simResolved ? 'RESOLVED' : simContained ? 'CONTAINED' : simAcked ? 'INVESTIGATING' : 'NEW',
      };
      const res = await SlaClientService.simulateSLAPolicy(req);
      setSimResult(res);
    } catch (err: unknown) {
      setSimError(err instanceof Error ? err.message : 'Simulation dry-run failed');
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="p-5 bg-surface border border-border rounded-control shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Clock className="w-3.5 h-3.5 text-primary" />
            <span>SECTION 51 — INCIDENT WORKFLOW AUTOMATION &amp; SLA POLICIES</span>
          </div>
          <h2 className="text-lg font-bold text-foreground">
            Operational SLA Policies, Escalations &amp; Routing
          </h2>
          <p className="text-xs text-foreground-muted font-mono mt-0.5">
            Configure authoritative response timeframes, automated multi-tier escalation chains, intelligent analyst assignment, and dry-run policy simulations.
          </p>
        </div>

        <button
          type="button"
          onClick={loadData}
          disabled={loading}
          className="px-3 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface flex items-center space-x-1.5 cursor-pointer shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-primary' : ''}`} />
          <span>Refresh Policies</span>
        </button>
      </div>

      {error && (
        <div className="p-3 bg-danger-surface border border-danger-border rounded-control text-xs text-danger flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* 2. Sub-Tab Navigator */}
      <div className="flex items-center space-x-2 border-b border-border text-xs">
        <button
          type="button"
          onClick={() => setActiveSubTab('sla')}
          className={`pb-2 px-3 font-semibold transition-colors flex items-center space-x-1.5 cursor-pointer ${
            activeSubTab === 'sla'
              ? 'text-primary border-b-2 border-primary'
              : 'text-foreground-muted hover:text-foreground'
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          <span>SLA Policies ({slaPolicies.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('escalation')}
          className={`pb-2 px-3 font-semibold transition-colors flex items-center space-x-1.5 cursor-pointer ${
            activeSubTab === 'escalation'
              ? 'text-primary border-b-2 border-primary'
              : 'text-foreground-muted hover:text-foreground'
          }`}
        >
          <ArrowUpRight className="w-3.5 h-3.5" />
          <span>Escalation Policies ({escalationPolicies.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('routing')}
          className={`pb-2 px-3 font-semibold transition-colors flex items-center space-x-1.5 cursor-pointer ${
            activeSubTab === 'routing'
              ? 'text-primary border-b-2 border-primary'
              : 'text-foreground-muted hover:text-foreground'
          }`}
        >
          <UserCheck className="w-3.5 h-3.5" />
          <span>Analyst Routing ({routingRules.length})</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveSubTab('simulate')}
          className={`pb-2 px-3 font-semibold transition-colors flex items-center space-x-1.5 cursor-pointer ${
            activeSubTab === 'simulate'
              ? 'text-primary border-b-2 border-primary'
              : 'text-foreground-muted hover:text-foreground'
          }`}
        >
          <Sparkles className="w-3.5 h-3.5 text-primary" />
          <span>Dry-Run Policy Simulator</span>
        </button>
      </div>

      {/* 3. Sub-Tab Contents */}
      {activeSubTab === 'sla' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-foreground-muted">
              Authoritative policies define deterministic operational timeframes across Acknowledgement, Investigation, Containment, and Resolution.
            </span>
            <button
              type="button"
              onClick={() => setShowCreateSlaModal(true)}
              className="px-3 py-1.5 text-xs font-semibold text-white bg-primary hover:bg-primary-hover rounded-control flex items-center space-x-1.5 cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Create SLA Policy</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {slaPolicies.map((p) => {
              const isActive = p.status === 'ACTIVE';

              return (
                <div
                  key={p.id}
                  className="p-4 bg-surface border border-border rounded-control space-y-3 shadow-xs hover:border-border/80 transition-all"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <h4 className="text-sm font-bold text-foreground">{p.name}</h4>
                        <span
                          className={`text-[10px] font-mono px-1.5 py-0.2 rounded border font-semibold ${
                            isActive
                              ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                              : 'bg-surface-secondary text-foreground-muted border-border'
                          }`}
                        >
                          {p.status}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-foreground-muted block mt-0.5">
                        Scope: {p.severity || 'ANY SEVERITY'} · {p.priority || 'ANY PRIORITY'} · v{p.version}
                      </span>
                    </div>

                    <span className="text-[10px] font-mono text-foreground-muted">
                      Warn at: {p.warning_threshold_pct}%
                    </span>
                  </div>

                  {/* Milestones matrix */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-border font-mono text-xs">
                    <div className="p-2 bg-surface-secondary/40 rounded-xs border border-border">
                      <span className="text-[9px] uppercase text-foreground-muted block">Ack</span>
                      <span className="font-bold text-foreground">{p.acknowledgement_target_minutes}m</span>
                    </div>
                    <div className="p-2 bg-surface-secondary/40 rounded-xs border border-border">
                      <span className="text-[9px] uppercase text-foreground-muted block">Investigate</span>
                      <span className="font-bold text-foreground">{p.investigation_target_minutes}m</span>
                    </div>
                    <div className="p-2 bg-surface-secondary/40 rounded-xs border border-border">
                      <span className="text-[9px] uppercase text-foreground-muted block">Contain</span>
                      <span className="font-bold text-foreground">{p.containment_target_minutes}m</span>
                    </div>
                    <div className="p-2 bg-surface-secondary/40 rounded-xs border border-border">
                      <span className="text-[9px] uppercase text-foreground-muted block">Resolve</span>
                      <span className="font-bold text-foreground">{p.resolution_target_minutes}m</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {activeSubTab === 'escalation' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-foreground-muted">
              Multi-tier escalation rules guarantee loop prevention with maximum levels (L3), execution cooldowns, and deterministic idempotency keys.
            </span>
          </div>

          <div className="space-y-4">
            {escalationPolicies.map((ep) => (
              <div key={ep.id} className="p-4 bg-surface border border-border rounded-control space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <h4 className="text-sm font-bold text-foreground">{ep.name}</h4>
                    <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border bg-emerald-500/15 text-emerald-400 border-emerald-500/30">
                      ACTIVE
                    </span>
                  </div>

                  <span className="text-[10px] font-mono text-foreground-muted">
                    Max Level: L{ep.max_escalation_level} · Cooldown: {ep.cooldown_minutes}m
                  </span>
                </div>

                {/* Rules List */}
                <div className="space-y-2 pt-2 border-t border-border">
                  {ep.rules.map((r: EscalationRule) => (
                    <div
                      key={r.id}
                      className="p-2.5 bg-surface-secondary/50 rounded-control border border-border text-xs flex flex-wrap items-center justify-between gap-2"
                    >
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border font-bold text-primary">
                          L{r.level}
                        </span>
                        <span className="font-semibold text-foreground">
                          {r.condition_type.replace(/_/g, ' ')} Rule
                        </span>
                        <span className="text-[10px] font-mono text-foreground-muted">
                          (When: <strong>{r.condition_type}</strong>)
                        </span>
                      </div>

                      <div className="flex items-center space-x-3 text-[11px] font-mono">
                        <span className="text-rose-400 font-semibold">Action: {r.action_type}</span>
                        {r.target_role && (
                          <span className="text-foreground-muted">Target: {r.target_role}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeSubTab === 'routing' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="text-xs text-foreground-muted">
              Analyst routing automates incident assignment using telemetry signals without replacing authorative threat detection or risk scores.
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {routingRules.map((rr: any) => (
              <div key={rr.id} className="p-4 bg-surface border border-border rounded-control space-y-2 shadow-xs">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold text-foreground">{rr.name}</h4>
                  <span className="text-[10px] font-mono px-1.5 py-0.2 rounded border bg-purple-500/15 text-purple-400 border-purple-500/30">
                    {rr.strategy}
                  </span>
                </div>

                <div className="text-xs text-foreground-muted font-mono space-y-1">
                  <div>Scope: {rr.condition_category || 'ALL CATEGORIES'}</div>
                  <div>Severity: {rr.condition_severity || 'ANY SEVERITY'}</div>
                  <div className="text-foreground font-semibold">
                    Target: {rr.target_team || rr.target_user || 'Default SOC'}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {activeSubTab === 'simulate' && (
        <div className="space-y-6">
          <div className="p-4 bg-surface-secondary/40 border border-border rounded-control text-xs text-foreground-muted space-y-1">
            <span className="font-bold text-foreground flex items-center space-x-1.5">
              <Sparkles className="w-4 h-4 text-primary" />
              <span>Safe Dry-Run Policy Simulator (Non-Destructive)</span>
            </span>
            <p>
              Test and verify policy execution, milestone breach states, warning thresholds, and escalation triggers in a sandbox without altering live incidents or sending real notifications.
            </p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Input Form */}
            <div className="p-5 bg-surface border border-border rounded-control space-y-4 shadow-xs">
              <h3 className="text-sm font-bold text-foreground">Simulation Parameters</h3>

              <div className="grid grid-cols-2 gap-3 text-xs">
                <div>
                  <label className="font-semibold text-foreground block mb-1">Severity</label>
                  <select
                    value={simSeverity}
                    onChange={(e) => setSimSeverity(e.target.value as IncidentSeverity)}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <label className="font-semibold text-foreground block mb-1">Priority</label>
                  <select
                    value={simPriority}
                    onChange={(e) => setSimPriority(e.target.value as IncidentPriority)}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  >
                    <option value="P1_CRITICAL">P1 - Critical</option>
                    <option value="P2_HIGH">P2 - High</option>
                    <option value="P3_MEDIUM">P3 - Medium</option>
                    <option value="P4_LOW">P4 - Low</option>
                  </select>
                </div>
              </div>

              <div className="text-xs">
                <label className="font-semibold text-foreground block mb-1">Category</label>
                <select
                  value={simCategory}
                  onChange={(e) => setSimCategory(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                >
                  <option value="RANSOMWARE">Ransomware</option>
                  <option value="ACCOUNT_TAKEOVER">Account Takeover</option>
                  <option value="PHISHING">Phishing Attack</option>
                  <option value="DATA_EXFILTRATION">Data Exfiltration</option>
                  <option value="MALWARE">Malware Outbreak</option>
                </select>
              </div>

              <div className="text-xs">
                <label className="font-semibold text-foreground block mb-1">
                  Elapsed Time Since Creation: <strong>{simElapsed} minutes</strong>
                </label>
                <input
                  type="range"
                  min="0"
                  max="1440"
                  step="5"
                  value={simElapsed}
                  onChange={(e) => setSimElapsed(Number(e.target.value))}
                  className="w-full cursor-pointer accent-primary"
                />
              </div>

              <div className="space-y-2 pt-2 border-t border-border text-xs">
                <span className="font-semibold text-foreground block">Incident Milestone Flags</span>
                <div className="flex flex-wrap gap-4">
                  <label className="flex items-center space-x-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={simAcked}
                      onChange={(e) => setSimAcked(e.target.checked)}
                      className="rounded accent-primary"
                    />
                    <span>Is Acknowledged</span>
                  </label>

                  <label className="flex items-center space-x-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={simContained}
                      onChange={(e) => setSimContained(e.target.checked)}
                      className="rounded accent-primary"
                    />
                    <span>Is Contained</span>
                  </label>

                  <label className="flex items-center space-x-1.5 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={simResolved}
                      onChange={(e) => setSimResolved(e.target.checked)}
                      className="rounded accent-primary"
                    />
                    <span>Is Resolved</span>
                  </label>
                </div>
              </div>

              <button
                type="button"
                onClick={handleRunSimulation}
                disabled={simulating}
                className="w-full py-2 bg-primary hover:bg-primary-hover text-white font-semibold text-xs rounded-control flex items-center justify-center space-x-2 cursor-pointer shadow-xs transition-colors"
              >
                <Play className={`w-3.5 h-3.5 ${simulating ? 'animate-spin' : ''}`} />
                <span>{simulating ? 'Evaluating Policies...' : 'Execute Policy Dry-Run'}</span>
              </button>
            </div>

            {/* Results Panel */}
            <div className="p-5 bg-surface border border-border rounded-control space-y-4 shadow-xs">
              <h3 className="text-sm font-bold text-foreground">Simulation Output</h3>

              {simError && (
                <div className="p-3 bg-danger-surface border border-danger-border rounded-control text-xs text-danger">
                  {simError}
                </div>
              )}

              {!simResult && !simError ? (
                <div className="py-20 text-center text-foreground-muted space-y-1">
                  <Sliders className="w-8 h-8 text-foreground-muted/40 mx-auto" />
                  <p className="font-semibold text-foreground">No simulation executed yet</p>
                  <p className="text-xs">Adjust parameters and click Execute Dry-Run to observe evaluated milestones.</p>
                </div>
              ) : simResult ? (
                <div className="space-y-4 text-xs">
                  {/* Matched Policy & Overall State */}
                  <div className="p-3 bg-surface-secondary rounded-control border border-border space-y-1">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-[10px] text-foreground-muted uppercase">Matched Policy:</span>
                      <span className="font-bold text-foreground">{simResult.matched_policy_name}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-[10px] text-foreground-muted uppercase">Evaluated Status:</span>
                      <span
                        className={`font-mono text-xs font-bold px-1.5 py-0.2 rounded border ${
                          simResult.evaluated_sla_status === 'BREACHED'
                            ? 'bg-red-500/20 text-red-400 border-red-500/40'
                            : simResult.evaluated_sla_status === 'WARNING'
                            ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                            : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40'
                        }`}
                      >
                        {simResult.evaluated_sla_status}
                      </span>
                    </div>
                  </div>

                  {/* Milestones Output */}
                  <div className="space-y-2">
                    <span className="font-semibold text-foreground block">Milestone Evaluations</span>
                    <div className="grid grid-cols-2 gap-2 font-mono text-[11px]">
                      {Object.entries(simResult.milestone_states || {}).map(([name, state]: [string, any]) => (
                        <div key={name} className="p-2 bg-surface-secondary/40 rounded-xs border border-border flex justify-between">
                          <span className="capitalize">{name}:</span>
                          <span
                            className={
                              state.status === 'BREACHED'
                                ? 'text-red-400 font-bold'
                                : state.status === 'WARNING'
                                ? 'text-amber-400 font-bold'
                                : state.status === 'MET'
                                ? 'text-emerald-400'
                                : 'text-foreground'
                            }
                          >
                            {state.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Escalations Triggered */}
                  <div className="space-y-2 pt-2 border-t border-border">
                    <span className="font-semibold text-foreground block">
                      Escalations Triggered ({simResult.escalations_triggered?.length || 0})
                    </span>
                    {!simResult.escalations_triggered || simResult.escalations_triggered.length === 0 ? (
                      <span className="text-foreground-muted text-[11px]">No escalation rules triggered under current condition.</span>
                    ) : (
                      <div className="space-y-1.5">
                        {(simResult.escalations_triggered || []).map((esc: any, idx: number) => (
                          <div
                            key={idx}
                            className="p-2 bg-rose-500/10 border border-rose-500/25 rounded-xs text-[11px] font-mono text-rose-300 flex justify-between"
                          >
                            <span>Tier {esc.target_tier}: {esc.action}</span>
                            <span>{esc.target_recipient}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Routed Target */}
                  <div className="pt-2 border-t border-border flex justify-between text-xs font-mono">
                    <span className="text-foreground-muted">Simulated Assignee:</span>
                    <span className="font-bold text-primary">{simResult.target_assignee || 'Unassigned'}</span>
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        </div>
      )}

      {/* Create SLA Policy Modal */}
      {showCreateSlaModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-xs p-4 animate-in fade-in">
          <form
            onSubmit={handleCreateSlaPolicy}
            className="bg-surface border border-border rounded-control p-5 w-full max-w-lg space-y-4 shadow-2xl"
          >
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold text-foreground">Create New SLA Policy</h3>
              <button
                type="button"
                onClick={() => setShowCreateSlaModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="font-semibold text-foreground block mb-1">Policy Name</label>
                <input
                  type="text"
                  value={newSlaName}
                  onChange={(e) => setNewSlaName(e.target.value)}
                  placeholder="e.g., Enterprise Critical Tier Policy"
                  className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-semibold text-foreground block mb-1">Severity Match</label>
                  <select
                    value={newSlaSev}
                    onChange={(e) => setNewSlaSev(e.target.value)}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  >
                    <option value="ALL">ANY SEVERITY</option>
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <label className="font-semibold text-foreground block mb-1">Priority Match</label>
                  <select
                    value={newSlaPrio}
                    onChange={(e) => setNewSlaPrio(e.target.value)}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  >
                    <option value="ALL">ANY PRIORITY</option>
                    <option value="P1_CRITICAL">P1_CRITICAL</option>
                    <option value="P2_HIGH">P2_HIGH</option>
                    <option value="P3_MEDIUM">P3_MEDIUM</option>
                    <option value="P4_LOW">P4_LOW</option>
                  </select>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-semibold text-foreground block mb-1">
                    Acknowledgement (mins)
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={newAckTarget}
                    onChange={(e) => setNewAckTarget(Number(e.target.value))}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  />
                </div>
                <div>
                  <label className="font-semibold text-foreground block mb-1">
                    Investigation (mins)
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={newInvTarget}
                    onChange={(e) => setNewInvTarget(Number(e.target.value))}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="font-semibold text-foreground block mb-1">
                    Containment (mins)
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={newContTarget}
                    onChange={(e) => setNewContTarget(Number(e.target.value))}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  />
                </div>
                <div>
                  <label className="font-semibold text-foreground block mb-1">
                    Resolution (mins)
                  </label>
                  <input
                    type="number"
                    min="1"
                    value={newResTarget}
                    onChange={(e) => setNewResTarget(Number(e.target.value))}
                    className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                  />
                </div>
              </div>

              <div>
                <label className="font-semibold text-foreground block mb-1">
                  Warning Threshold (% of Target)
                </label>
                <input
                  type="number"
                  min="10"
                  max="95"
                  value={newWarnPct}
                  onChange={(e) => setNewWarnPct(Number(e.target.value))}
                  className="w-full bg-surface-secondary border border-border rounded-control px-2.5 py-1.5 text-foreground"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setShowCreateSlaModal(false)}
                className="px-3 py-1.5 text-xs text-foreground bg-surface border border-border rounded-control hover:bg-surface-secondary cursor-pointer"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-3 py-1.5 text-xs font-semibold text-white bg-primary hover:bg-primary-hover rounded-control cursor-pointer"
              >
                Save &amp; Activate Policy
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
