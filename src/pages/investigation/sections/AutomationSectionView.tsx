import React, { useState, useEffect, useCallback } from 'react';
import {
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  ShieldAlert,
  Loader2,
  Bot,
  Zap,
  ShieldCheck,
  PauseCircle,
  RefreshCw,
  Eye,
  Sliders,
  Sparkles,
  FileText,
  Radio,
} from 'lucide-react';
import { Button } from '../../../components/ui';
import { useInvestigation } from '../../../context/InvestigationContext';
import { investigationAutomationService } from '../../../services/investigationAutomationService';
import type {
  InvestigationAutomationRunRead,
  AutomationStepRead,
  InvestigationGapRead,
  AutomationTemplateDefinition,
  AutomationMode,
} from '../../../types/investigationAutomation';

export const AutomationSectionView: React.FC = () => {
  const { activeEmailId, workspaceSummary } = useInvestigation();
  const investigationId = activeEmailId || workspaceSummary?.investigation.investigation_id || '';

  const [runs, setRuns] = useState<InvestigationAutomationRunRead[]>([]);
  const [selectedRun, setSelectedRun] = useState<InvestigationAutomationRunRead | null>(null);
  const [templates, setTemplates] = useState<AutomationTemplateDefinition[]>([]);
  const [gaps, setGaps] = useState<InvestigationGapRead[]>([]);
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Modals & Drawers
  const [isNewRunModalOpen, setIsNewRunModalOpen] = useState(false);
  const [selectedTemplateName, setSelectedTemplateName] = useState('PHISHING_INVESTIGATION');
  const [selectedMode, setSelectedMode] = useState<AutomationMode>('ASSISTED');
  const [selectedStepDetail, setSelectedStepDetail] = useState<AutomationStepRead | null>(null);
  const [approvalReason, setApprovalReason] = useState('');

  const loadData = useCallback(async () => {
    if (!investigationId) return;
    setLoading(true);
    setError(null);
    try {
      const [runsList, tmplList, gapList] = await Promise.all([
        investigationAutomationService.listRuns(investigationId),
        investigationAutomationService.getTemplates(),
        investigationAutomationService.getGaps(investigationId),
      ]);
      setRuns(runsList);
      setTemplates(tmplList);
      setGaps(gapList);
      if (runsList.length > 0) {
        setSelectedRun(runsList[0]);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load investigation automation data');
    } finally {
      setLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Trigger New Run
  const handleTriggerRun = async () => {
    if (!investigationId) return;
    setActionLoading(true);
    try {
      const newRun = await investigationAutomationService.createAndExecuteRun(
        investigationId,
        {
          template_name: selectedTemplateName,
          mode: selectedMode,
        },
        false
      );
      setIsNewRunModalOpen(false);
      await loadData();
      setSelectedRun(newRun);
    } catch (err: any) {
      alert(`Execution failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  // Step Approval
  const handleApproveStep = async (stepIndex: number, approve: boolean) => {
    if (!selectedRun) return;
    setActionLoading(true);
    try {
      const updated = await investigationAutomationService.approveStep(
        selectedRun.id,
        stepIndex,
        { approve, reason: approvalReason },
        investigationId
      );
      setSelectedRun(updated);
      setApprovalReason('');
      await loadData();
    } catch (err: any) {
      alert(`Approval action failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  // Run Controls
  const handleCancelRun = async () => {
    if (!selectedRun) return;
    if (!confirm('Are you sure you want to cancel this automation run? All preserved evidence will remain intact.')) return;
    setActionLoading(true);
    try {
      const updated = await investigationAutomationService.cancelRun(selectedRun.id, investigationId);
      setSelectedRun(updated);
      await loadData();
    } catch (err: any) {
      alert(`Cancellation failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleResumeRun = async () => {
    if (!selectedRun) return;
    setActionLoading(true);
    try {
      const updated = await investigationAutomationService.resumeRun(selectedRun.id, investigationId);
      setSelectedRun(updated);
      await loadData();
    } catch (err: any) {
      alert(`Resume failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleRetryRun = async () => {
    if (!selectedRun) return;
    setActionLoading(true);
    try {
      const updated = await investigationAutomationService.retryRun(selectedRun.id, investigationId);
      setSelectedRun(updated);
      await loadData();
    } catch (err: any) {
      alert(`Retry failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3.5 h-3.5" /> Completed
          </span>
        );
      case 'PARTIALLY_COMPLETED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3.5 h-3.5" /> Partially Completed
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 animate-pulse">
            <Loader2 className="w-3.5 h-3.5 animate-spin" /> Running
          </span>
        );
      case 'WAITING_FOR_ANALYST':
      case 'WAITING_APPROVAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/50 animate-pulse">
            <Clock className="w-3.5 h-3.5" /> Waiting for Approval
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-red-500/10 text-red-400 border border-red-500/30">
            <XCircle className="w-3.5 h-3.5" /> Failed
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-surface-secondary text-foreground-muted border border-border">
            <PauseCircle className="w-3.5 h-3.5" /> Cancelled
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-surface-secondary text-foreground-muted border border-border">
            <Clock className="w-3.5 h-3.5" /> {status}
          </span>
        );
    }
  };

  const waitingStep = selectedRun?.steps?.find((s) => s.status === 'WAITING_APPROVAL');

  if (loading && !selectedRun) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-center">
        <Loader2 className="w-8 h-8 text-primary animate-spin mb-3" />
        <p className="text-sm font-mono text-foreground-muted">Loading investigation automation workflow...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 page-enter pb-12">
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-xs font-mono text-red-400 flex items-center justify-between">
          <span>Error loading automation data: {error}</span>
          <button onClick={() => setError(null)} className="text-foreground-muted hover:text-foreground">✕</button>
        </div>
      )}

      {/* 1. Header Bar with Controls */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-2xl bg-surface border border-border/80 shadow-sm">
        <div className="flex items-center gap-4">
          <div className="w-12 h-12 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <Bot className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h2 className="text-lg font-semibold text-foreground tracking-tight">Investigation Automation</h2>
              {selectedRun && getStatusBadge(selectedRun.status)}
              <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface-secondary text-foreground-muted border border-border">
                {selectedRun?.mode || 'ASSISTED'}
              </span>
            </div>
            <p className="text-xs text-foreground-muted mt-0.5">
              Deterministic, bounded workflow execution for rapid contextual enrichment, gap detection, and evidence correlation.
            </p>
          </div>
        </div>

        <div className="flex items-center flex-wrap gap-2.5">
          {runs.length > 1 && (
            <select
              value={selectedRun?.id || ''}
              onChange={(e) => {
                const r = runs.find((item) => item.id === e.target.value);
                if (r) setSelectedRun(r);
              }}
              className="bg-surface-secondary text-foreground text-xs font-mono rounded-lg px-3 py-2 border border-border focus:outline-none focus:border-primary"
            >
              {runs.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.template_name} ({r.status}) - {new Date(r.created_at).toLocaleTimeString()}
                </option>
              ))}
            </select>
          )}

          <Button
            variant="outline"
            size="sm"
            onClick={loadData}
            disabled={actionLoading}
            className="flex items-center gap-1.5 text-xs font-mono"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${actionLoading ? 'animate-spin' : ''}`} />
            Refresh
          </Button>

          {selectedRun?.status === 'WAITING_FOR_ANALYST' && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleResumeRun}
              disabled={actionLoading}
              className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 border-cyan-500/30"
            >
              <Play className="w-3.5 h-3.5" />
              Resume Run
            </Button>
          )}

          {selectedRun?.status === 'PARTIALLY_COMPLETED' && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleRetryRun}
              disabled={actionLoading}
              className="flex items-center gap-1.5 text-xs font-mono text-amber-400 border-amber-500/30"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              Retry Failed Steps
            </Button>
          )}

          {selectedRun?.status === 'RUNNING' && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleCancelRun}
              disabled={actionLoading}
              className="flex items-center gap-1.5 text-xs font-mono text-red-400 border-red-500/30"
            >
              <PauseCircle className="w-3.5 h-3.5" />
              Cancel Run
            </Button>
          )}

          <Button
            variant="primary"
            size="sm"
            onClick={() => setIsNewRunModalOpen(true)}
            disabled={actionLoading}
            className="flex items-center gap-1.5 text-xs font-mono"
          >
            <Zap className="w-3.5 h-3.5" />
            New Automation Run
          </Button>
        </div>
      </div>

      {/* 2. APPROVAL GATE BANNER (When action requires analyst sign-off) */}
      {waitingStep && (
        <div className="p-5 rounded-2xl bg-amber-500/10 border border-amber-500/40 animate-fadeIn">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-3.5">
              <div className="w-9 h-9 rounded-lg bg-amber-500/20 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                <AlertTriangle className="w-5 h-5 animate-pulse" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-semibold text-amber-300">
                    Analyst Approval Required: Step {waitingStep.step_index + 1} ({waitingStep.name})
                  </h4>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-500/20 text-amber-200 border border-amber-500/30">
                    {waitingStep.cost_class}
                  </span>
                </div>
                <p className="text-xs text-amber-200/80 mt-1">
                  This action is configured with elevated cost or query intensity. Execution is safely gated until an authorized analyst signs off.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-end md:self-center">
              <input
                type="text"
                placeholder="Optional sign-off reason / note..."
                value={approvalReason}
                onChange={(e) => setApprovalReason(e.target.value)}
                className="bg-surface text-xs font-mono px-3 py-1.5 rounded-lg border border-amber-500/30 text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-amber-400 w-56"
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleApproveStep(waitingStep.step_index, false)}
                disabled={actionLoading}
                className="text-xs font-mono text-red-400 border-red-500/30 hover:bg-red-500/10"
              >
                Reject & Skip
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => handleApproveStep(waitingStep.step_index, true)}
                disabled={actionLoading}
                className="text-xs font-mono bg-amber-500 hover:bg-amber-600 text-black border-amber-400"
              >
                Approve & Execute
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* 3. Main Grid: Stepper & Telemetry Coverage */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Step Visualizer */}
        <div className="lg:col-span-2 space-y-4">
          <div className="p-5 rounded-2xl bg-surface border border-border">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-semibold text-foreground">Execution Stepper</h3>
                <span className="text-xs font-mono text-foreground-muted">
                  ({selectedRun?.completed_steps || 0}/{selectedRun?.total_steps || 0} Steps)
                </span>
              </div>
              <div className="text-xs font-mono text-foreground-muted">
                Template: <span className="text-primary">{selectedRun?.template_name || 'None'}</span>
              </div>
            </div>

            {selectedRun?.steps && selectedRun.steps.length > 0 ? (
              <div className="space-y-3">
                {selectedRun.steps.map((step) => {
                  const isSelected = selectedStepDetail?.id === step.id;
                  return (
                    <div
                      key={step.id}
                      onClick={() => setSelectedStepDetail(step)}
                      className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
                        isSelected
                          ? 'bg-primary/5 border-primary shadow-sm'
                          : 'bg-surface-secondary/50 border-border hover:border-border-hover'
                      }`}
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-3">
                          <div className="w-6 h-6 rounded-full bg-surface border border-border flex items-center justify-center text-xs font-mono text-foreground-muted shrink-0">
                            {step.step_index + 1}
                          </div>
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold text-foreground">{step.name}</span>
                              <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-surface text-foreground-muted border border-border">
                                {step.action_id}
                              </span>
                            </div>
                            <div className="flex items-center gap-3 mt-1 text-[11px] font-mono text-foreground-muted">
                              <span>Cost: {step.cost_class}</span>
                              {step.duration_ms > 0 && <span>Duration: {step.duration_ms}ms</span>}
                              {step.result_count > 0 && <span>Results: {step.result_count} items</span>}
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-2">
                          {getStatusBadge(step.status)}
                          <Eye className="w-4 h-4 text-foreground-muted hover:text-primary transition-colors" />
                        </div>
                      </div>

                      {step.error_message && (
                        <div className="mt-2.5 p-2 rounded bg-red-500/10 border border-red-500/20 text-xs font-mono text-red-400">
                          Error: {step.error_message}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="py-12 text-center text-xs font-mono text-foreground-muted">
                No active automation steps in this run. Trigger a new run to begin.
              </div>
            )}
          </div>

          {/* Step Detail Inspector Drawer (Inline) */}
          {selectedStepDetail && (
            <div className="p-5 rounded-2xl bg-surface border border-primary/30 shadow-sm animate-fadeIn">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-primary" />
                  <h4 className="text-sm font-semibold text-foreground">
                    Step Inspector: {selectedStepDetail.name}
                  </h4>
                </div>
                <button
                  onClick={() => setSelectedStepDetail(null)}
                  className="text-xs font-mono text-foreground-muted hover:text-foreground"
                >
                  Close
                </button>
              </div>

              <div className="space-y-3 text-xs font-mono">
                <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-surface-secondary border border-border">
                  <div>
                    <span className="text-foreground-muted">Action ID:</span>{' '}
                    <span className="text-foreground">{selectedStepDetail.action_id}</span>
                  </div>
                  <div>
                    <span className="text-foreground-muted">Approval Level:</span>{' '}
                    <span className="text-foreground">{selectedStepDetail.approval_level}</span>
                  </div>
                  <div>
                    <span className="text-foreground-muted">Result Count:</span>{' '}
                    <span className="text-foreground">{selectedStepDetail.result_count}</span>
                  </div>
                  <div>
                    <span className="text-foreground-muted">Approved By:</span>{' '}
                    <span className="text-foreground">{selectedStepDetail.approved_by || 'Auto/System'}</span>
                  </div>
                </div>

                <div>
                  <div className="text-foreground-muted mb-1 font-semibold">Result Summary Payload:</div>
                  <pre className="p-3 rounded-lg bg-surface-secondary border border-border max-h-60 overflow-y-auto text-[11px] text-foreground leading-relaxed whitespace-pre-wrap">
                    {JSON.stringify(selectedStepDetail.result_summary, null, 2)}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right 1 Col: Telemetry Coverage & Blindspots */}
        <div className="space-y-6">
          {/* Telemetry Coverage Card */}
          <div className="p-5 rounded-2xl bg-surface border border-border">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-semibold text-foreground">Telemetry Coverage</h3>
              </div>
              <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
                {selectedRun?.coverage_summary?.coverage_score ?? 80}%
              </span>
            </div>

            <div className="space-y-2.5">
              {(
                selectedRun?.coverage_summary?.sources || [
                  { source: 'Email Telemetry', status: 'AVAILABLE', message: 'Headers, hops, and authentication verified' },
                  { source: 'Endpoint Agent', status: 'PARTIAL', message: 'Workstation agent reporting; DNS stream delayed' },
                  { source: 'Network Telemetry', status: 'AVAILABLE', message: 'Perimeter firewall flows correlated' },
                  { source: 'Identity & Auth', status: 'AVAILABLE', message: 'Directory accounts and VIP records resolved' },
                  { source: 'Cloud & API Audit', status: 'MISSING', message: 'Cloud trail logs not indexed for this timeframe' },
                  { source: 'Threat Intelligence', status: 'AVAILABLE', message: 'Cached reputation feeds active' },
                ]
              ).map((src: any, idx: number) => {
                let badgeClass = 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
                if (src.status === 'PARTIAL') badgeClass = 'text-amber-400 bg-amber-500/10 border-amber-500/30';
                if (src.status === 'MISSING') badgeClass = 'text-red-400 bg-red-500/10 border-red-500/30';

                return (
                  <div key={idx} className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-foreground">{src.source}</span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${badgeClass}`}>
                        {src.status}
                      </span>
                    </div>
                    <p className="text-[11px] text-foreground-muted leading-tight">{src.message}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Investigation Summary Synthesis */}
          {selectedRun?.investigation_summary && (
            <div className="p-5 rounded-2xl bg-surface border border-border">
              <div className="flex items-center gap-2 mb-3">
                <Sparkles className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-semibold text-foreground">AI Investigation Summary</h3>
              </div>
              <p className="text-xs text-foreground leading-relaxed mb-3">
                {selectedRun.investigation_summary.assessment_summary}
              </p>

              <div className="space-y-2">
                <div>
                  <div className="text-[11px] font-semibold text-emerald-400 uppercase tracking-wider mb-1 font-mono">
                    Observed Knowns ({selectedRun.investigation_summary.knowns?.length || 0})
                  </div>
                  <ul className="list-disc list-inside text-xs text-foreground-muted space-y-1">
                    {selectedRun.investigation_summary.knowns?.slice(0, 3).map((k, i) => (
                      <li key={i}>{k}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <div className="text-[11px] font-semibold text-amber-400 uppercase tracking-wider mb-1 font-mono">
                    Identified Unknowns ({selectedRun.investigation_summary.unknowns?.length || 0})
                  </div>
                  <ul className="list-disc list-inside text-xs text-foreground-muted space-y-1">
                    {selectedRun.investigation_summary.unknowns?.slice(0, 3).map((u, i) => (
                      <li key={i}>{u}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* 4. Investigation Gaps & Remediation Table */}
      <div className="p-5 rounded-2xl bg-surface border border-border">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-foreground">Identified Telemetry & Investigation Gaps</h3>
            <span className="px-2 py-0.5 rounded text-xs font-mono bg-amber-500/10 text-amber-400 border border-amber-500/30">
              {gaps.length} Gaps
            </span>
          </div>
          <span className="text-xs font-mono text-foreground-muted">
            Concrete blindspots identified during automated evaluation
          </span>
        </div>

        {gaps.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-surface-secondary text-foreground-muted font-mono uppercase text-[10px] border-b border-border">
                <tr>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">Category</th>
                  <th className="py-2.5 px-3">Gap Title</th>
                  <th className="py-2.5 px-3">Description</th>
                  <th className="py-2.5 px-3">Remediation Recommendation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border font-mono text-[11px]">
                {gaps.map((gap) => {
                  let sevClass = 'text-amber-400 bg-amber-500/10 border-amber-500/30';
                  if (gap.severity === 'CRITICAL' || gap.severity === 'HIGH') {
                    sevClass = 'text-red-400 bg-red-500/10 border-red-500/30';
                  }

                  return (
                    <tr key={gap.id} className="hover:bg-surface-secondary/30 transition-colors">
                      <td className="py-2.5 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sevClass}`}>
                          {gap.severity}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-foreground-muted">{gap.category}</td>
                      <td className="py-2.5 px-3 font-semibold text-foreground">{gap.title}</td>
                      <td className="py-2.5 px-3 text-foreground-muted max-w-xs truncate">{gap.description}</td>
                      <td className="py-2.5 px-3 text-primary max-w-xs truncate">
                        {gap.remediation_recommendation || 'Collect supplementary network and EDR logs'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="py-8 text-center text-xs font-mono text-foreground-muted">
            No telemetry gaps identified for this investigation. Full data scope verified.
          </div>
        )}
      </div>

      {/* 5. NEW AUTOMATION RUN MODAL */}
      {isNewRunModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-fadeIn">
          <div className="w-full max-w-2xl rounded-2xl bg-surface border border-border p-6 shadow-2xl space-y-5">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center gap-2.5">
                <Zap className="w-5 h-5 text-primary" />
                <h3 className="text-base font-semibold text-foreground">Launch Automated Investigation</h3>
              </div>
              <button
                onClick={() => setIsNewRunModalOpen(false)}
                className="text-foreground-muted hover:text-foreground text-sm font-mono"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <label className="text-xs font-mono text-foreground-muted block mb-2 font-semibold">
                  SELECT INVESTIGATION TEMPLATE
                </label>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {templates.map((tmpl) => {
                    const isSelected = selectedTemplateName === tmpl.template_name;
                    return (
                      <div
                        key={tmpl.template_name}
                        onClick={() => setSelectedTemplateName(tmpl.template_name)}
                        className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                          isSelected
                            ? 'bg-primary/10 border-primary ring-1 ring-primary'
                            : 'bg-surface-secondary/40 border-border hover:border-border-hover'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-semibold text-foreground">{tmpl.title}</span>
                          <span className="text-[10px] font-mono text-primary">{tmpl.steps.length} Steps</span>
                        </div>
                        <p className="text-[11px] text-foreground-muted leading-tight">{tmpl.description}</p>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div>
                <label className="text-xs font-mono text-foreground-muted block mb-2 font-semibold">
                  EXECUTION MODE
                </label>
                <div className="grid grid-cols-3 gap-3">
                  {(['ASSISTED', 'SEMI_AUTONOMOUS', 'SUPERVISED_AUTONOMOUS'] as AutomationMode[]).map((mode) => (
                    <button
                      key={mode}
                      type="button"
                      onClick={() => setSelectedMode(mode)}
                      className={`p-2.5 rounded-lg border text-xs font-mono transition-all text-center ${
                        selectedMode === mode
                          ? 'bg-primary/10 border-primary text-primary font-bold'
                          : 'bg-surface-secondary border-border text-foreground-muted hover:text-foreground'
                      }`}
                    >
                      {mode}
                    </button>
                  ))}
                </div>
              </div>

              <div className="p-3 rounded-lg bg-surface-secondary border border-border text-[11px] font-mono text-foreground-muted space-y-1">
                <div className="flex items-center gap-1.5 text-primary font-semibold">
                  <ShieldCheck className="w-3.5 h-3.5" /> Safety & Containment Guarantee
                </div>
                <div>All destructive actions are prohibited. Execution is bounded by maximum entity and time budgets.</div>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-border">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setIsNewRunModalOpen(false)}
                disabled={actionLoading}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleTriggerRun}
                disabled={actionLoading}
                className="flex items-center gap-1.5"
              >
                {actionLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Execute Run
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default AutomationSectionView;
