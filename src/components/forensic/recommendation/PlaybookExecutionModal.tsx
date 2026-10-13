import { apiFetch } from '../../../utils/apiClient';
import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  Play,
  CheckCircle2,
  AlertTriangle,
  Lock,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Check,
  Eye
} from 'lucide-react';
import type {
  ResponsePlaybook,
  SimulationPlan,
  ResponsePlaybookExecution
} from '../../../types/response_playbook';
import type { ResponseRecommendation } from '../../../types/response_recommendation';
import { apiUrl } from '../../../utils/apiClient';

interface PlaybookExecutionModalProps {
  playbook?: ResponsePlaybook | null;
  recommendation?: ResponseRecommendation | null;
  onClose: () => void;
  onExecutionCompleted?: (execution: ResponsePlaybookExecution) => void;
}

export const PlaybookExecutionModal: React.FC<PlaybookExecutionModalProps> = ({
  playbook: initialPlaybook,
  recommendation,
  onClose,
  onExecutionCompleted
}) => {
  const [playbook, setPlaybook] = useState<ResponsePlaybook | null>(initialPlaybook || null);
  const [loading, setLoading] = useState<boolean>(!initialPlaybook && !!recommendation);
  const [mode, setMode] = useState<'SIMULATION' | 'LIVE'>('SIMULATION');
  const [simulationPlan, setSimulationPlan] = useState<SimulationPlan | null>(null);
  const [execution, setExecution] = useState<ResponsePlaybookExecution | null>(null);
  const [executing, setExecuting] = useState<boolean>(false);
  const [approving, setApproving] = useState<boolean>(false);
  const [approvalReason, setApprovalReason] = useState<string>('');
  const [showApprovalBox, setShowApprovalBox] = useState<boolean>(false);
  const [expandedStepKey, setExpandedStepKey] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // If opened from a recommendation without a playbook, convert/fetch it
  useEffect(() => {
    if (!playbook && recommendation) {
      const loadOrConvertPlaybook = async () => {
        setLoading(true);
        setError(null);
        try {
          const res = await apiFetch(apiUrl(`/api/v1/playbooks/from-recommendation/${recommendation.id}`), {
            method: 'POST'
          });
          if (res.ok) {
            const pb: ResponsePlaybook = await res.json();
            setPlaybook(pb);
          } else {
            // Fallback: list existing playbooks to find match or default
            const listRes = await apiFetch(apiUrl('/api/v1/playbooks'));
            if (listRes.ok) {
              const list: ResponsePlaybook[] = await listRes.json();
              if (list.length > 0) setPlaybook(list[0]);
            }
          }
        } catch (err: any) {
          setError(err?.message || 'Failed to initialize response playbook');
        } finally {
          setLoading(false);
        }
      };
      loadOrConvertPlaybook();
    }
  }, [recommendation, playbook]);

  // Load simulation plan once playbook is available
  useEffect(() => {
    if (playbook) {
      handleSimulate();
    }
  }, [playbook]);

  const handleSimulate = async () => {
    if (!playbook) return;
    setError(null);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/playbooks/${playbook.id}/simulate`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      if (res.ok) {
        const plan: SimulationPlan = await res.json();
        setSimulationPlan(plan);
      } else {
        const err = await res.json().catch(() => ({ detail: 'Simulation failed' }));
        setError(err.detail || 'Simulation error');
      }
    } catch (err: any) {
      setError(err?.message || 'Simulation network error');
    }
  };

  const handleExecute = async (selectedMode: 'DRY_RUN' | 'LIVE') => {
    if (!playbook) return;
    setMode(selectedMode === 'DRY_RUN' ? 'SIMULATION' : 'LIVE');
    setExecuting(true);
    setError(null);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/playbooks/${playbook.id}/execute`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: selectedMode,
          requested_by: 'current_analyst'
        })
      });
      if (res.ok) {
        const exec: ResponsePlaybookExecution = await res.json();
        setExecution(exec);
        if (exec.status === 'WAITING_FOR_APPROVAL') {
          setShowApprovalBox(true);
        }
        if (onExecutionCompleted && exec.status === 'COMPLETED') {
          onExecutionCompleted(exec);
        }
      } else {
        const err = await res.json().catch(() => ({ detail: 'Execution request failed' }));
        setError(err.detail || 'Failed to start execution');
      }
    } catch (err: any) {
      setError(err?.message || 'Execution failed due to network error');
    } finally {
      setExecuting(false);
    }
  };

  const handleApprove = async () => {
    if (!execution) return;
    if (!approvalReason.trim()) {
      setError('An audit justification is mandatory to grant execution approval.');
      return;
    }
    setApproving(true);
    setError(null);
    try {
      const res = await apiFetch(apiUrl(`/api/v1/playbooks/executions/${execution.id}/approve`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          decision: 'APPROVED',
          approved_by: 'lead_analyst',
          reason: approvalReason.trim()
        })
      });
      if (res.ok) {
        setShowApprovalBox(false);
        // Refresh execution status
        const pollRes = await apiFetch(apiUrl(`/api/v1/playbooks/executions/${execution.id}`));
        if (pollRes.ok) {
          const updated: ResponsePlaybookExecution = await pollRes.json();
          setExecution(updated);
          if (onExecutionCompleted) onExecutionCompleted(updated);
        }
      } else {
        const err = await res.json().catch(() => ({ detail: 'Approval recording failed' }));
        setError(err.detail || 'Approval failed');
      }
    } catch (err: any) {
      setError(err?.message || 'Network error while recording approval');
    } finally {
      setApproving(false);
    }
  };

  const toggleStep = (stepKey: string) => {
    setExpandedStepKey(prev => prev === stepKey ? null : stepKey);
  };

  const getSafetyBadge = (safetyClass: string) => {
    switch (safetyClass) {
      case 'INFORMATIONAL':
      case 'LOW_IMPACT':
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">SAFE</span>;
      case 'REVERSIBLE':
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30">REVERSIBLE</span>;
      case 'CONTAINMENT':
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">CONTAINMENT</span>;
      default:
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">HIGH IMPACT</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1"><CheckCircle2 className="w-3 h-3" /> COMPLETED</span>;
      case 'WAITING_FOR_APPROVAL':
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1"><Lock className="w-3 h-3" /> APPROVAL REQUIRED</span>;
      case 'RUNNING':
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-blue-500/10 text-blue-400 border border-blue-500/30 flex items-center gap-1"><RefreshCw className="w-3 h-3 animate-spin" /> RUNNING</span>;
      case 'FAILED':
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30 flex items-center gap-1"><AlertTriangle className="w-3 h-3" /> FAILED</span>;
      default:
        return <span className="text-[10px] px-2 py-0.5 rounded font-mono font-semibold bg-surface-tertiary text-foreground-muted border border-border">{status}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex items-center justify-center bg-black/75 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="w-full max-w-3xl bg-surface border border-border rounded-xl shadow-2xl flex flex-col max-h-[92vh] overflow-hidden animate-in zoom-in-95 duration-200">
        
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-border bg-surface-secondary/40 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xs px-2 py-0.5 rounded font-mono font-bold bg-primary/20 text-primary border border-primary/30">
                  SECTION 29 PLAYBOOK
                </span>
                {playbook && (
                  <span className="text-xs px-2 py-0.5 rounded font-mono font-semibold bg-surface-tertiary text-foreground-muted border border-border">
                    v{playbook.version}
                  </span>
                )}
                {execution && getStatusBadge(execution.status)}
              </div>
              <h2 className="text-base font-bold text-foreground mt-1">
                {playbook ? playbook.name : 'Loading Response Playbook...'}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface-tertiary transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-5 flex-1">
          {error && (
            <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {loading ? (
            <div className="py-12 flex flex-col items-center justify-center space-y-3 text-foreground-muted font-mono text-xs">
              <RefreshCw className="w-6 h-6 animate-spin text-primary" />
              <span>Synthesizing verified defensive playbook from recommendation...</span>
            </div>
          ) : playbook ? (
            <>
              {/* Playbook Description & Policy Card */}
              <div className="p-3.5 rounded-lg border border-border bg-surface-secondary/20 space-y-2">
                <p className="text-xs text-foreground-muted leading-relaxed">
                  {playbook.description}
                </p>
                <div className="flex flex-wrap items-center gap-3 pt-1 text-[11px] font-mono text-foreground-muted">
                  <span>Policy: <strong className="text-foreground">{playbook.approval_policy}</strong></span>
                  <span>•</span>
                  <span>Execution: <strong className="text-foreground">{playbook.execution_policy}</strong></span>
                  <span>•</span>
                  <span>Timeout: <strong className="text-foreground">{playbook.timeout_seconds}s</strong></span>
                  {playbook.source_recommendation_id && (
                    <>
                      <span>•</span>
                      <span>Origin: <strong className="text-primary">{playbook.source_recommendation_id}</strong></span>
                    </>
                  )}
                </div>
              </div>

              {/* Approval Box if Waiting */}
              {showApprovalBox && (
                <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 space-y-3 animate-in fade-in duration-200">
                  <div className="flex items-center gap-2 text-amber-400 font-mono text-xs font-bold">
                    <Lock className="w-4 h-4" />
                    <span>HUMAN APPROVAL REQUIRED FOR CONSEQUENTIAL DEFENSIVE ACTION</span>
                  </div>
                  <p className="text-xs text-foreground-muted">
                    Execution has paused at a containment boundary step. Explicit human analyst sign-off is mandatory under CyberGuard strict zero-autonomous-destructive-action policy.
                  </p>
                  <div className="space-y-1">
                    <label className="text-[11px] font-mono text-foreground-muted">
                      Audit Justification Note:
                    </label>
                    <textarea
                      rows={2}
                      value={approvalReason}
                      onChange={(e) => setApprovalReason(e.target.value)}
                      placeholder="e.g. Authorized domain containment after reviewing active beaconing telemetry."
                      className="w-full p-2.5 rounded-lg bg-surface border border-border text-foreground text-xs font-sans placeholder:text-foreground-muted/50"
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={handleApprove}
                      disabled={approving || !approvalReason.trim()}
                      className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono font-bold text-xs flex items-center gap-1.5 transition-colors disabled:opacity-50"
                    >
                      {approving ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
                      Authorize & Resume Execution
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowApprovalBox(false)}
                      className="px-3 py-2 rounded-lg border border-border bg-surface text-foreground-muted hover:text-foreground font-mono text-xs transition-colors"
                    >
                      Dismiss Prompt
                    </button>
                  </div>
                </div>
              )}

              {/* Execution Plan / Step Progression */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                    {execution ? 'Execution Steps & Verification' : 'Controlled Steps & Safeguards'}
                  </h3>
                  <span className="text-[11px] font-mono text-foreground-muted">
                    {playbook.steps.length} sequential steps
                  </span>
                </div>

                <div className="space-y-2">
                  {playbook.steps.map((step) => {
                    const isExpanded = expandedStepKey === step.step_key;
                    const stepExec = execution?.step_executions?.find(s => s.step_key === step.step_key);
                    const simStep = simulationPlan?.steps?.find(s => s.step_key === step.step_key);

                    return (
                      <div
                        key={step.id || step.step_key}
                        className="rounded-lg border border-border bg-surface-secondary/20 overflow-hidden transition-all duration-150"
                      >
                        <div
                          onClick={() => toggleStep(step.step_key)}
                          className="p-3 flex items-center justify-between cursor-pointer hover:bg-surface-secondary/40 select-none"
                        >
                          <div className="flex items-center space-x-3">
                            <span className="w-6 h-6 rounded-full bg-surface-tertiary border border-border flex items-center justify-center font-mono text-xs font-bold text-foreground-muted">
                              {step.sequence}
                            </span>
                            <div>
                              <div className="flex items-center space-x-2">
                                <span className="font-mono text-xs font-bold text-foreground">
                                  {step.name}
                                </span>
                                {getSafetyBadge(step.safety_class)}
                                {step.requires_approval && (
                                  <span className="text-[9px] px-1.5 py-0.5 rounded font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                                    APPROVAL
                                  </span>
                                )}
                              </div>
                              <div className="text-[11px] text-foreground-muted mt-0.5 font-sans">
                                {step.description}
                              </div>
                            </div>
                          </div>

                          <div className="flex items-center space-x-2 shrink-0">
                            {stepExec ? (
                              getStatusBadge(stepExec.status)
                            ) : simStep ? (
                              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                                WOULD EXECUTE
                              </span>
                            ) : (
                              <span className="text-[10px] font-mono text-foreground-muted">READY</span>
                            )}
                            {isExpanded ? (
                              <ChevronUp className="w-4 h-4 text-foreground-muted" />
                            ) : (
                              <ChevronDown className="w-4 h-4 text-foreground-muted" />
                            )}
                          </div>
                        </div>

                        {/* Progressive Disclosure: Step Deep Dive */}
                        {isExpanded && (
                          <div className="p-3 border-t border-border/60 bg-surface/40 space-y-3 text-xs font-mono animate-in fade-in duration-150">
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                              <div>
                                <span className="text-foreground-muted">Action Type:</span>{' '}
                                <strong className="text-foreground">{step.step_type}</strong>
                              </div>
                              <div>
                                <span className="text-foreground-muted">Safety Class:</span>{' '}
                                <strong className="text-foreground">{step.safety_class}</strong>
                              </div>
                              <div>
                                <span className="text-foreground-muted">Verification Policy:</span>{' '}
                                <strong className="text-emerald-400">
                                  {step.verification_policy?.enabled ? step.verification_policy.expected_state : 'DISABLED'}
                                </strong>
                              </div>
                              <div>
                                <span className="text-foreground-muted">Rollback Reversibility:</span>{' '}
                                <strong className="text-blue-400">
                                  {step.rollback_policy?.reversibility || 'IRREVERSIBLE'}
                                </strong>
                              </div>
                            </div>

                            {/* Verification Result if executed */}
                            {stepExec?.verification_result && (
                              <div className="p-2 rounded bg-surface border border-border space-y-1">
                                <div className="text-[10px] text-emerald-400 font-bold flex items-center gap-1">
                                  <CheckCircle2 className="w-3 h-3" /> Defensive State Verified
                                </div>
                                <pre className="text-[10px] text-foreground-muted overflow-x-auto">
                                  {JSON.stringify(stepExec.verification_result, null, 2)}
                                </pre>
                              </div>
                            )}

                            {/* Step Output Summary if executed */}
                            {stepExec?.output_summary && (
                              <div className="p-2 rounded bg-surface border border-border space-y-1">
                                <div className="text-[10px] text-primary font-bold">Execution Output</div>
                                <pre className="text-[10px] text-foreground-muted overflow-x-auto">
                                  {JSON.stringify(stepExec.output_summary, null, 2)}
                                </pre>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Execution Summary / Result Card */}
              {execution?.result_summary && (
                <div className="p-3 rounded-lg border border-border bg-surface-secondary/40 space-y-1 text-xs font-mono">
                  <div className="font-bold text-foreground">Execution Result Summary:</div>
                  <div className="text-foreground-muted">{execution.result_summary}</div>
                </div>
              )}
            </>
          ) : null}
        </div>

        {/* Footer Actions */}
        <div className="p-4 border-t border-border bg-surface-secondary/40 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-[11px] font-mono text-foreground-muted flex items-center gap-2">
            <span>Mode:</span>
            <span className="font-bold text-primary">{mode === 'SIMULATION' ? 'DRY-RUN SIMULATION' : 'LIVE CONSTRAINED EXECUTION'}</span>
          </div>

          <div className="flex items-center gap-2 w-full sm:w-auto">
            <button
              type="button"
              onClick={() => handleExecute('DRY_RUN')}
              disabled={executing || !playbook}
              className="flex-1 sm:flex-none px-3.5 py-2 rounded-lg border border-primary/40 bg-primary/10 hover:bg-primary/20 text-primary font-mono font-bold text-xs transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              <Eye className="w-3.5 h-3.5" />
              Simulate Dry-Run
            </button>

            <button
              type="button"
              onClick={() => handleExecute('LIVE')}
              disabled={executing || !playbook}
              className="flex-1 sm:flex-none px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-bold text-xs transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
            >
              {executing ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
              Execute Playbook
            </button>
          </div>
        </div>

      </div>
    </div>
  );
};
