import React, { useState } from 'react';
import {
  Workflow,
  Play,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Layers,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import type {
  ResponsePlaybook,
  ResponsePlaybookSummary,
  ResponsePlaybookStep,
  SimulationPlan,
  ResponsePlaybookExecution
} from '../../../types/response_playbook';
import type { ResponseRecommendation } from '../../../types/response_recommendation';
import { responseWorkspaceService } from '../../../services/responseWorkspaceService';

interface PlaybookSectionProps {
  playbooks: (ResponsePlaybook | ResponsePlaybookSummary)[];
  recommendations: ResponseRecommendation[];
  investigationId: string;
  onRefresh: () => Promise<void>;
  onSelectExecution?: (execution: ResponsePlaybookExecution) => void;
}

export const PlaybookSection: React.FC<PlaybookSectionProps> = ({
  playbooks,
  recommendations,
  investigationId,
  onRefresh,
  onSelectExecution
}) => {
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string | null>(
    playbooks.length > 0 ? playbooks[0].id : null
  );
  const [detailedPlaybook, setDetailedPlaybook] = useState<ResponsePlaybook | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(false);


  // Simulation state
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationResult, setSimulationResult] = useState<SimulationPlan | null>(null);
  const [simulationError, setSimulationError] = useState<string | null>(null);

  // Execution state
  const [isExecuting, setIsExecuting] = useState(false);
  const [executionResult, setExecutionResult] = useState<ResponsePlaybookExecution | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);
  const [showLiveConfirmModal, setShowLiveConfirmModal] = useState(false);


  // Generate from recommendation state
  const [generatingFromRecId, setGeneratingFromRecId] = useState<string | null>(null);

  // Load detailed playbook on selection
  const handleSelectPlaybook = async (id: string) => {
    setSelectedPlaybookId(id);
    setSimulationResult(null);
    setSimulationError(null);
    setExecutionResult(null);
    setExecutionError(null);
    try {
      setIsLoadingDetail(true);
      const detail = await responseWorkspaceService.getPlaybook(id);
      setDetailedPlaybook(detail);
    } catch {
      // Fallback
    } finally {
      setIsLoadingDetail(false);
    }
  };

  // Initial load of first playbook detail if available
  React.useEffect(() => {
    if (selectedPlaybookId && !detailedPlaybook) {
      handleSelectPlaybook(selectedPlaybookId);
    }
  }, [selectedPlaybookId]);

  // Run dry-run simulation
  const handleRunSimulation = async (playbookId: string) => {
    try {
      setIsSimulating(true);
      setSimulationError(null);
      setSimulationResult(null);
      const sim = await responseWorkspaceService.simulatePlaybook(playbookId);
      setSimulationResult(sim);
    } catch (err: unknown) {
      setSimulationError(err instanceof Error ? err.message : 'Simulation failed');
    } finally {
      setIsSimulating(false);
    }
  };

  // Live execution confirmation
  const handleConfirmLiveExecution = async () => {
    if (!selectedPlaybookId) return;
    try {
      setIsExecuting(true);
      setExecutionError(null);
      const exec = await responseWorkspaceService.executePlaybook(
        selectedPlaybookId,
        'LIVE',
        'analyst@cyberguard.local',
        investigationId
      );
      setExecutionResult(exec);
      setShowLiveConfirmModal(false);
      await onRefresh();
      if (onSelectExecution) {
        onSelectExecution(exec);
      }
    } catch (err: unknown) {
      setExecutionError(err instanceof Error ? err.message : 'Execution failed');
    } finally {
      setIsExecuting(false);
    }
  };

  // Generate playbook from approved recommendation
  const handleGeneratePlaybook = async (recId: string) => {
    try {
      setGeneratingFromRecId(recId);
      const pb = await responseWorkspaceService.createPlaybookFromRecommendation(
        recId,
        'analyst@cyberguard.local'
      );
      await onRefresh();
      await handleSelectPlaybook(pb.id);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to generate playbook');
    } finally {
      setGeneratingFromRecId(null);
    }
  };

  const approvedWithoutPlaybook = recommendations.filter(
    (r) =>
      r.status === 'APPROVED' &&
      !playbooks.some(
        (p) => ('source_recommendation_id' in p && p.source_recommendation_id === r.id)
      )
  );

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-border">
        <div className="flex items-center gap-2.5">
          <Workflow className="w-5 h-5 text-primary" />
          <div>
            <h3 className="text-sm font-bold text-foreground tracking-tight">
              Defensive Response Playbooks (Section 29)
            </h3>
            <p className="text-xs text-muted-foreground">
              Multi-step deterministic workflows, dry-run simulations, and authorized execution adapters.
            </p>
          </div>
        </div>
        <span className="text-xs font-mono px-2 py-0.5 rounded bg-muted text-muted-foreground border border-border">
          {playbooks.length} Available Playbook{playbooks.length === 1 ? '' : 's'}
        </span>
      </div>

      {/* Conversion Banner: If approved recommendations exist without an active playbook */}
      {approvedWithoutPlaybook.length > 0 && (
        <div className="p-3 rounded-lg border border-primary/30 bg-primary/5 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <Sparkles className="w-4 h-4 text-primary flex-shrink-0" />
            <div className="text-xs">
              <span className="font-semibold text-foreground">
                {approvedWithoutPlaybook.length} Approved Recommendation{approvedWithoutPlaybook.length === 1 ? '' : 's'} Ready:
              </span>{' '}
              <span className="text-muted-foreground">
                Convert approved recommendation into an automated, validated execution playbook.
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {approvedWithoutPlaybook.slice(0, 2).map((rec) => (
              <button
                key={rec.id}
                onClick={() => handleGeneratePlaybook(rec.id)}
                disabled={generatingFromRecId === rec.id}
                className="px-2.5 py-1 text-xs font-bold bg-primary text-primary-foreground hover:bg-primary/90 rounded border border-primary/40 transition-colors flex items-center gap-1.5 disabled:opacity-50"
              >
                {generatingFromRecId === rec.id ? (
                  <span>Generating...</span>
                ) : (
                  <>
                    <span>Stage #{rec.id}</span>
                    <ArrowRight className="w-3 h-3" />
                  </>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Main Playbook Layout */}
      {playbooks.length === 0 ? (
        <div className="p-8 border border-border/80 border-dashed rounded-xl text-center bg-card/40 space-y-2">
          <Workflow className="w-8 h-8 text-muted-foreground mx-auto opacity-50" />
          <h4 className="text-sm font-semibold text-foreground">No Response Playbooks Staged</h4>
          <p className="text-xs text-muted-foreground max-w-md mx-auto">
            Playbooks are created when recommendations are approved or when specific security incidents
            escalate. Review and approve recommendations above to stage response workflows.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Playbook List (Column 1) */}
          <div className="lg:col-span-1 space-y-2">
            <div className="text-[11px] font-bold text-muted-foreground uppercase tracking-wider px-1">
              Staged Playbooks
            </div>
            {playbooks.map((pb) => {
              const isSelected = selectedPlaybookId === pb.id;
              return (
                <div
                  key={pb.id}
                  onClick={() => handleSelectPlaybook(pb.id)}
                  className={`p-3 rounded-lg border text-left cursor-pointer transition-all ${
                    isSelected
                      ? 'border-primary bg-primary/10 shadow-sm'
                      : 'border-border bg-card hover:bg-muted/40 hover:border-border/80'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-semibold">
                      v{pb.version}
                    </span>
                    <span
                      className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${
                        pb.status === 'READY' || pb.status === 'APPROVED'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : pb.status === 'REVIEW_REQUIRED'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : 'bg-muted text-muted-foreground border-border'
                      }`}
                    >
                      {pb.status}
                    </span>
                  </div>
                  <div className="text-xs font-bold text-foreground line-clamp-1">{pb.name}</div>
                  <p className="text-[11px] text-muted-foreground line-clamp-2 mt-1 leading-snug">
                    {pb.description}
                  </p>
                  <div className="flex items-center justify-between text-[10px] text-muted-foreground pt-2 mt-2 border-t border-border/60">
                    <span className="flex items-center gap-1 font-mono">
                      <Layers className="w-3 h-3" />
                      {'steps' in pb && Array.isArray(pb.steps) ? pb.steps.length : 'step_count' in pb ? (pb as any).step_count : 0} steps
                    </span>
                    <ChevronRight className="w-3 h-3 text-muted-foreground" />
                  </div>
                </div>
              );
            })}
          </div>

          {/* Playbook Inspector & Workflow Steps (Columns 2 & 3) */}
          <div className="lg:col-span-2 space-y-4">
            {isLoadingDetail ? (
              <div className="p-12 text-center border border-border rounded-xl bg-card">
                <div className="animate-spin w-6 h-6 border-2 border-primary border-t-transparent rounded-full mx-auto mb-2" />
                <span className="text-xs text-muted-foreground">Loading playbook definition...</span>
              </div>
            ) : detailedPlaybook ? (
              <div className="space-y-4">
                {/* Playbook Detail Card */}
                <div className="p-4 rounded-xl border border-border bg-card space-y-3 shadow-sm">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-xs font-mono font-bold text-primary">
                          {detailedPlaybook.playbook_key}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground">
                          Version {detailedPlaybook.version}
                        </span>
                        <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                          {detailedPlaybook.status}
                        </span>
                      </div>
                      <h4 className="text-sm font-bold text-foreground">{detailedPlaybook.name}</h4>
                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                        {detailedPlaybook.description}
                      </p>
                    </div>

                    {/* Operational Action Buttons */}
                    <div className="flex items-center gap-2 flex-shrink-0">
                      <button
                        onClick={() => handleRunSimulation(detailedPlaybook.id)}
                        disabled={isSimulating}
                        className="px-3 py-1.5 text-xs font-bold rounded-lg border border-border bg-background hover:bg-muted/60 text-foreground transition-all flex items-center gap-1.5 disabled:opacity-50 shadow-sm"
                        title="Simulate all steps and safety checks without performing any live actions"
                      >
                        <Play className="w-3.5 h-3.5 text-primary" />
                        <span>{isSimulating ? 'Simulating...' : 'Simulate Dry-Run'}</span>
                      </button>

                      <button
                        onClick={() => setShowLiveConfirmModal(true)}
                        disabled={isExecuting || detailedPlaybook.status === 'DISABLED'}
                        className="px-3 py-1.5 text-xs font-bold rounded-lg border border-emerald-500 bg-emerald-600 hover:bg-emerald-500 text-white transition-all flex items-center gap-1.5 shadow-sm disabled:opacity-50"
                        title="Authorize and execute deterministic playbook steps via configured adapters"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Execute Playbook</span>
                      </button>
                    </div>
                  </div>

                  {/* Playbook Policies Grid */}
                  <div className="grid grid-cols-3 gap-2 pt-2 border-t border-border/60 text-xs">
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">
                        Approval Policy
                      </span>
                      <span className="font-mono text-foreground font-semibold">
                        {detailedPlaybook.approval_policy}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">
                        Execution Policy
                      </span>
                      <span className="font-mono text-foreground font-semibold">
                        {detailedPlaybook.execution_policy}
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground uppercase font-semibold block">
                        Max Timeout
                      </span>
                      <span className="font-mono text-foreground">
                        {detailedPlaybook.timeout_seconds || 300}s
                      </span>
                    </div>
                  </div>
                </div>

                {/* Simulation Output Panel if available */}
                {simulationError && (
                  <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                    <span>Simulation Error: {simulationError}</span>
                  </div>
                )}

                {simulationResult && (
                  <div className="p-4 rounded-xl border border-primary/30 bg-primary/5 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                        <span className="text-xs font-bold text-foreground">
                          Dry-Run Simulation Plan #{simulationResult.playbook_key} v{simulationResult.playbook_version}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 font-bold">
                        SIMULATION COMPLETED — NO ACTION EXECUTED
                      </span>
                    </div>

                    <p className="text-xs text-muted-foreground leading-relaxed">
                      {simulationResult.summary}
                    </p>

                    {/* Step simulation breakdown */}
                    <div className="space-y-1.5 pt-1">
                      {simulationResult.steps.map((st) => (
                        <div
                          key={st.step_key}
                          className="flex items-center justify-between p-2 rounded bg-card/80 border border-border/80 text-xs"
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-[10px] text-muted-foreground">
                              0{st.sequence}
                            </span>
                            <span className="font-semibold text-foreground">{st.name}</span>
                            <span className="text-[10px] font-mono text-muted-foreground">
                              ({st.simulated_action})
                            </span>
                          </div>
                          <div className="flex items-center gap-2 text-[10px]">
                            <span
                              className={`px-1.5 py-0.2 rounded font-bold uppercase ${
                                st.capability_state === 'AVAILABLE'
                                  ? 'text-emerald-400'
                                  : 'text-amber-400'
                              }`}
                            >
                              {st.capability_state}
                            </span>
                            <span className="text-muted-foreground font-mono">
                              {st.rollback_available ? 'Rollback Ready' : 'One-Way'}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Execution Result Banner */}
                {executionError && (
                  <div className="p-3.5 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-300 text-xs flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                    <span>Execution Error: {executionError}</span>
                  </div>
                )}

                {executionResult && (
                  <div className="p-4 rounded-xl border border-emerald-500/40 bg-emerald-500/10 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2 text-emerald-400">
                        <CheckCircle2 className="w-4 h-4" />
                        <span className="text-xs font-bold">
                          Execution Request Registered: #{executionResult.id}
                        </span>
                      </div>
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                        STATUS: {executionResult.status}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Execution initiated in <strong>{executionResult.mode}</strong> mode by{' '}
                      <strong>{executionResult.requested_by}</strong>. State change recorded in immutable audit log.
                    </p>
                  </div>
                )}

                {/* Defined Steps List */}
                <div className="space-y-2">
                  <div className="text-[11px] font-bold text-muted-foreground uppercase tracking-wider">
                    Deterministic Playbook Steps ({detailedPlaybook.steps?.length || 0})
                  </div>

                  <div className="space-y-2">
                    {detailedPlaybook.steps?.map((step: ResponsePlaybookStep) => (
                      <div
                        key={step.id || step.step_key}
                        className="p-3.5 rounded-lg border border-border bg-card space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs font-bold text-primary">
                              STEP 0{step.sequence}
                            </span>
                            <span className="text-xs font-bold text-foreground">{step.name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border">
                              {step.step_type}
                            </span>
                            <span
                              className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                                step.safety_class === 'INFORMATIONAL'
                                  ? 'bg-blue-500/10 text-blue-400'
                                  : step.safety_class === 'LOW_IMPACT' || step.safety_class === 'REVERSIBLE'
                                  ? 'bg-emerald-500/10 text-emerald-400'
                                  : 'bg-amber-500/10 text-amber-400'
                              }`}
                            >
                              {step.safety_class}
                            </span>
                          </div>
                        </div>

                        <p className="text-xs text-muted-foreground leading-relaxed">
                          {step.description}
                        </p>

                        <div className="flex flex-wrap items-center gap-3 pt-2 border-t border-border/60 text-[11px] text-muted-foreground font-mono">
                          <div>
                            <span className="text-muted-foreground/70">Approval: </span>
                            <span className={step.requires_approval ? 'text-amber-400 font-bold' : 'text-foreground'}>
                              {step.requires_approval ? 'Required' : 'Pre-approved'}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground/70">Rollback: </span>
                            <span className={step.rollback_policy?.supports_rollback ? 'text-emerald-400' : 'text-muted-foreground'}>
                              {step.rollback_policy?.supports_rollback ? 'Supported' : 'None'}
                            </span>
                          </div>
                          <div>
                            <span className="text-muted-foreground/70">Verification: </span>
                            <span className={step.verification_policy?.enabled ? 'text-foreground' : 'text-muted-foreground'}>
                              {step.verification_policy?.enabled ? 'Enabled' : 'Disabled'}
                            </span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>
      )}

      {/* Confirmation Modal for Live Execution */}
      {showLiveConfirmModal && detailedPlaybook && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm"
          role="dialog"
          aria-modal="true"
        >
          <div className="w-full max-w-lg bg-card border border-border rounded-xl shadow-2xl p-5 space-y-4">
            <div className="flex items-center gap-3 text-amber-400">
              <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-foreground">Confirm Live Playbook Execution</h3>
                <p className="text-xs text-muted-foreground">
                  Playbook: {detailedPlaybook.name} (v{detailedPlaybook.version})
                </p>
              </div>
            </div>

            <p className="text-xs text-muted-foreground leading-relaxed">
              You are about to execute <strong>{detailedPlaybook.steps?.length || 0} defensive steps</strong>{' '}
              against configured target systems for Investigation #{investigationId}.
              This action will invoke registered security adapters. Ensure all prerequisites and approval
              policies have been verified.
            </p>

            <div className="p-3 rounded-lg bg-muted/40 border border-border text-xs space-y-1">
              <div className="text-[10px] uppercase font-bold text-muted-foreground">Actor Identification</div>
              <div className="font-mono font-bold text-foreground">analyst@cyberguard.local</div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setShowLiveConfirmModal(false)}
                disabled={isExecuting}
                className="px-3 py-1.5 text-xs text-foreground hover:bg-muted/60 border border-border rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleConfirmLiveExecution}
                disabled={isExecuting}
                className="px-4 py-1.5 text-xs font-bold rounded-lg border border-emerald-500 bg-emerald-600 hover:bg-emerald-500 text-white transition-all shadow-sm flex items-center gap-1.5 disabled:opacity-50"
              >
                {isExecuting ? 'Dispatching...' : 'Authorize & Execute'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
