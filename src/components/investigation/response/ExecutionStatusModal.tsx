import React from 'react';
import {
  Activity,
  Clock,
  AlertTriangle,
  ShieldCheck,
  X,
  Server,
  Terminal,
  FileText
} from 'lucide-react';

import type {
  ResponsePlaybookExecution,
  ResponsePlaybookStepExecution
} from '../../../types/response_playbook';

interface ExecutionStatusModalProps {
  isOpen: boolean;
  execution: ResponsePlaybookExecution | null;
  onClose: () => void;
}

export const ExecutionStatusModal: React.FC<ExecutionStatusModalProps> = ({
  isOpen,
  execution,
  onClose
}) => {
  if (!isOpen || !execution) return null;

  const isSuccess = execution.status === 'COMPLETED';
  const isFailed = execution.status === 'FAILED' || (execution.status as string) === 'ROLLBACK_FAILED';
  const isRunning = execution.status === 'RUNNING' || execution.status === 'PENDING';


  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-labelledby="execution-modal-title"
    >
      <div className="w-full max-w-2xl bg-card border border-border rounded-xl shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border bg-card">
          <div className="flex items-center gap-3">
            <div
              className={`p-2 rounded-lg border ${
                isSuccess
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : isFailed
                  ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                  : 'bg-primary/10 border-primary/30 text-primary'
              }`}
            >
              <Activity className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 id="execution-modal-title" className="text-base font-bold text-foreground">
                  Playbook Execution #{execution.id}
                </h2>
                <span
                  className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border uppercase ${
                    isSuccess
                      ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                      : isFailed
                      ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                      : isRunning
                      ? 'bg-amber-500/10 text-amber-400 border-amber-500/30 animate-pulse'
                      : 'bg-muted text-muted-foreground border-border'
                  }`}
                >
                  {execution.status}
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-muted text-muted-foreground border border-border">
                  {execution.mode}
                </span>
              </div>
              <p className="text-xs text-muted-foreground">
                Authoritative execution transcript & adapter verification records
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-muted-foreground hover:text-foreground rounded-md hover:bg-muted/50 transition-colors"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Metadata Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
            <div className="p-2.5 rounded-lg bg-muted/40 border border-border">
              <span className="text-[10px] text-muted-foreground uppercase font-bold block">
                Playbook
              </span>
              <span className="font-mono text-foreground font-semibold truncate block">
                {execution.playbook_id} (v{execution.playbook_version})
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-muted/40 border border-border">
              <span className="text-[10px] text-muted-foreground uppercase font-bold block">
                Actor
              </span>
              <span className="font-mono text-foreground truncate block">
                {execution.requested_by}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-muted/40 border border-border">
              <span className="text-[10px] text-muted-foreground uppercase font-bold block">
                Started
              </span>
              <span className="font-mono text-foreground text-[11px] truncate block">
                {new Date(execution.started_at).toLocaleTimeString()}
              </span>
            </div>
            <div className="p-2.5 rounded-lg bg-muted/40 border border-border">
              <span className="text-[10px] text-muted-foreground uppercase font-bold block">
                Completed
              </span>
              <span className="font-mono text-foreground text-[11px] truncate block">
                {execution.completed_at
                  ? new Date(execution.completed_at).toLocaleTimeString()
                  : 'In Progress'}
              </span>
            </div>
          </div>

          {/* Failure Callout if Execution Failed */}
          {isFailed && (
            <div className="p-4 rounded-xl border border-rose-500/40 bg-rose-500/10 space-y-2">
              <div className="flex items-center gap-2 text-rose-400 font-bold text-xs">
                <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                <span>Execution Failed — No Action Executed Successfully</span>
              </div>
              <p className="text-xs text-rose-200/90 leading-relaxed font-mono">
                {execution.error_message || execution.error_code || 'Adapter operation timed out or rejected request.'}
              </p>
              <div className="text-[11px] text-muted-foreground">
                Forensic recommendation: Verify endpoint agent connectivity and target reachability before retry.
              </div>
            </div>
          )}

          {/* Result Summary */}
          {execution.result_summary && (
            <div className="p-3.5 rounded-lg bg-muted/30 border border-border/80 text-xs space-y-1">
              <div className="text-[10px] font-bold text-muted-foreground uppercase">
                Result Summary
              </div>
              <p className="text-foreground leading-relaxed">{execution.result_summary}</p>
            </div>
          )}

          {/* Step Executions Timeline */}
          <div className="space-y-2">
            <div className="text-xs font-bold text-foreground uppercase tracking-wider flex items-center justify-between">
              <span>Step-by-Step Adapter Executions ({execution.step_executions?.length || 0})</span>
              <span className="text-[10px] font-mono text-muted-foreground">
                Total Steps: {execution.step_executions?.length || 0}
              </span>
            </div>

            {(!execution.step_executions || execution.step_executions.length === 0) ? (
              <div className="p-4 text-center border border-border rounded-lg text-xs text-muted-foreground">
                No step telemetry recorded yet.
              </div>
            ) : (
              <div className="space-y-2">
                {execution.step_executions.map((step: ResponsePlaybookStepExecution) => {
                  const isStepDone = step.status === 'COMPLETED';
                  const isStepFail = step.status === 'FAILED' || step.status === 'VERIFICATION_FAILED';
                  return (
                    <div
                      key={step.id || step.step_key}
                      className="p-3.5 rounded-lg border border-border bg-card space-y-2"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-primary">
                            0{step.sequence}
                          </span>
                          <span className="font-semibold text-xs text-foreground font-mono">
                            {step.step_key}
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span
                            className={`text-[10px] font-bold font-mono px-2 py-0.5 rounded border uppercase ${
                              isStepDone
                                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                                : isStepFail
                                ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                                : 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                            }`}
                          >
                            {step.status}
                          </span>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[11px] pt-1 text-muted-foreground">
                        <div className="flex items-center gap-1.5">
                          <Server className="w-3 h-3 text-muted-foreground/70" />
                          <span>Adapter:</span>
                          <span className="font-mono text-foreground font-medium truncate">
                            {step.adapter || 'simulated'}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3 text-muted-foreground/70" />
                          <span>Duration:</span>
                          <span className="font-mono text-foreground">
                            {step.started_at && step.completed_at
                              ? `${Math.max(
                                  1,
                                  Math.round(
                                    (new Date(step.completed_at).getTime() -
                                      new Date(step.started_at).getTime()) /
                                      1000
                                  )
                                )}s`
                              : 'Pending'}
                          </span>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <Terminal className="w-3 h-3 text-muted-foreground/70" />
                          <span>Attempts:</span>
                          <span className="font-mono text-foreground">{step.attempt_count || 1}</span>
                        </div>
                      </div>

                      {/* Error details if step failed */}
                      {step.error_message && (
                        <div className="p-2 rounded bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs font-mono">
                          {step.error_message}
                        </div>
                      )}

                      {/* Verification details if available */}
                      {step.verification_result && (
                        <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-[11px] flex items-center gap-2">
                          <ShieldCheck className="w-3.5 h-3.5 flex-shrink-0" />
                          <span>State Verification Confirmed by Adapter</span>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border bg-card flex items-center justify-between">
          <div className="text-[11px] text-muted-foreground font-mono flex items-center gap-1.5">
            <FileText className="w-3.5 h-3.5 text-primary" />
            <span>Audit Event logged to system ledger</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-foreground hover:bg-muted/60 border border-border rounded-lg transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
