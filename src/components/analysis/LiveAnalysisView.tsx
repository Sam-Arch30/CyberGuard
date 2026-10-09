import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  CheckCircle2,
  Loader2,
  Circle,
  AlertCircle,
  MinusCircle,
  Clock,
  Copy,
  Check,
  RotateCcw,
  XCircle,
  ArrowRight,
  Activity,
  ChevronDown,
  ChevronUp,
  Cpu,
  Layers,
  ShieldAlert,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import type {
  AnalysisRunLiveResponse,
  AnalysisTask,
  AnalysisEvent,
} from '../../types/analysis';
import { liveAnalysisService } from '../../services/liveAnalysisService';
import {
  Card,
  Button,
  LoadingState,
  ErrorState,
} from '../ui';
import {
  ThreatScore,
  SeverityIndicator,
  SourceBadge,
} from '../security';

const mapArtifactTypeToSource = (type?: string): string => {
  switch (type?.toUpperCase()) {
    case 'EMAIL':
      return 'Email Gateway';
    case 'URL':
    case 'DOMAIN':
    case 'IP':
      return 'Network / URL';
    case 'IMAGE':
    case 'MULTIMEDIA':
      return 'Media Forensics';
    case 'AUTH_LOG':
    case 'SYSTEM_LOG':
      return 'Identity & Access';
    case 'FILE':
    default:
      return 'File Ingestion';
  }
};

import { AnalysisResultsWorkstation } from './results/AnalysisResultsWorkstation';

interface LiveAnalysisViewProps {
  investigationId?: string;
  runId?: string;
  onOpenInvestigation?: () => void;
  defaultMode?: 'results' | 'dag';
}

export const LiveAnalysisView: React.FC<LiveAnalysisViewProps> = ({
  investigationId,
  runId: initialRunId,
  onOpenInvestigation,
  defaultMode,
}) => {
  const navigate = useNavigate();

  const [viewMode, setViewMode] = useState<'results' | 'dag'>(defaultMode || 'dag');
  const hasAutoSwitched = useRef<boolean>(false);
  const [analysisState, setAnalysisState] = useState<AnalysisRunLiveResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<boolean>(false);
  const [showTechnicalDetails, setShowTechnicalDetails] = useState<boolean>(false);
  const [expandedTasks, setExpandedTasks] = useState<Record<string, boolean>>({});
  const [cancelConfirmOpen, setCancelConfirmOpen] = useState<boolean>(false);

  const activeStreamCleanup = useRef<(() => void) | null>(null);
  const pollingTimer = useRef<number | null>(null);

  // Format real event timestamps (HH:MM:SS)
  const formatEventTime = (isoString?: string) => {
    if (!isoString) return '--:--:--';
    try {
      const d = new Date(isoString);
      return d.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch {
      return '--:--:--';
    }
  };

  // Copy SHA-256 hash
  const handleCopyHash = (hash?: string | null) => {
    if (!hash) return;
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  // Toggle task details
  const toggleTaskExpanded = (taskId: string) => {
    setExpandedTasks((prev) => ({ ...prev, [taskId]: !prev[taskId] }));
  };

  // Fetch analysis state from backend
  const fetchState = useCallback(async () => {
    try {
      let data: AnalysisRunLiveResponse;
      if (initialRunId) {
        data = await liveAnalysisService.getLiveAnalysis(initialRunId);
      } else if (investigationId) {
        data = await liveAnalysisService.getInvestigationLiveAnalysis(investigationId);
      } else {
        throw new Error('No investigation or analysis run identifier provided.');
      }
      setAnalysisState(data);
      if (!defaultMode && !hasAutoSwitched.current && ['COMPLETED', 'PARTIAL'].includes(data.status)) {
        hasAutoSwitched.current = true;
        setViewMode('results');
      }
      setError(null);
      return data;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to load analysis state.';
      setError(msg);
      return null;
    } finally {
      setLoading(false);
    }
  }, [initialRunId, investigationId, defaultMode]);

  // Handle SSE subscription and polling fallback
  useEffect(() => {
    let isMounted = true;

    const setupLiveTracking = async () => {
      const initial = await fetchState();
      if (!isMounted || !initial) return;

      const runId = initial.id;
      const isTerminal = ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes(initial.status);

      // Clean up previous listeners
      if (activeStreamCleanup.current) {
        activeStreamCleanup.current();
        activeStreamCleanup.current = null;
      }
      if (pollingTimer.current) {
        window.clearInterval(pollingTimer.current);
        pollingTimer.current = null;
      }

      if (!isTerminal) {
        // 1. Subscribe to SSE stream
        activeStreamCleanup.current = liveAnalysisService.subscribeLiveAnalysisStream(
          runId,
          (snapshot) => {
            if (isMounted) setAnalysisState(snapshot);
          },
          (eventPayload) => {
            if (isMounted && eventPayload) {
              // Refresh state on task progress/completion
              fetchState();
            }
          },
          (_terminalStatus) => {
            if (isMounted) {
              fetchState();
              if (pollingTimer.current) {
                window.clearInterval(pollingTimer.current);
                pollingTimer.current = null;
              }
            }
          },
          () => {
            // Polling fallback if SSE connection errors
            if (!pollingTimer.current && isMounted) {
              pollingTimer.current = window.setInterval(async () => {
                const refreshed = await fetchState();
                if (refreshed && ['COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes(refreshed.status)) {
                  if (pollingTimer.current) {
                    window.clearInterval(pollingTimer.current);
                    pollingTimer.current = null;
                  }
                }
              }, 2000);
            }
          }
        );
      }
    };

    setupLiveTracking();

    return () => {
      isMounted = false;
      if (activeStreamCleanup.current) {
        activeStreamCleanup.current();
        activeStreamCleanup.current = null;
      }
      if (pollingTimer.current) {
        window.clearInterval(pollingTimer.current);
        pollingTimer.current = null;
      }
    };
  }, [fetchState]);

  // User Action: Cancel Analysis
  const handleCancel = async () => {
    if (!analysisState) return;
    setActionLoading(true);
    try {
      const updated = await liveAnalysisService.cancelLiveAnalysis(analysisState.id);
      setAnalysisState(updated);
      setCancelConfirmOpen(false);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Cancellation failed.');
    } finally {
      setActionLoading(false);
    }
  };

  // User Action: Retry Analysis
  const handleRetry = async () => {
    if (!analysisState) return;
    setActionLoading(true);
    try {
      const updated = await liveAnalysisService.retryLiveAnalysis(analysisState.id);
      setAnalysisState(updated);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Retry failed.');
    } finally {
      setActionLoading(false);
    }
  };

  // User Action: Open Investigation
  const handleOpenInvestigation = () => {
    if (onOpenInvestigation) {
      onOpenInvestigation();
      return;
    }
    const targetId = analysisState?.investigation_id || investigationId || analysisState?.evidence_id || analysisState?.artifact_id;
    if (targetId) {
      navigate(`/investigations/${encodeURIComponent(targetId)}/overview`);
    } else {
      navigate('/investigations');
    }
  };

  if (loading) {
    return (
      <LoadingState
        message="Connecting to CyberGuard live analysis engine..."
        subtext="Verifying pipeline DAG state and event stream"
        fullHeight
      />
    );
  }

  if (error || !analysisState) {
    return (
      <ErrorState
        title="Live Analysis Unavailable"
        message={error || 'No analysis run is associated with this investigation.'}
        onRetry={fetchState}
        action={
          <Button
            size="sm"
            variant="outline"
            onClick={() => navigate('/dashboard')}
          >
            Return to Dashboard
          </Button>
        }
      />
    );
  }

  if (viewMode === 'results' && analysisState) {
    return (
      <AnalysisResultsWorkstation
        runId={analysisState.id}
        investigationId={investigationId}
        onToggleViewDAG={() => setViewMode('dag')}
      />
    );
  }

  const isRunning = analysisState.status === 'RUNNING' || analysisState.status === 'QUEUED';
  const isCompleted = analysisState.status === 'COMPLETED';
  const isPartial = analysisState.status === 'PARTIAL';
  const isFailed = analysisState.status === 'FAILED';
  const isCancelled = analysisState.status === 'CANCELLED';

  const sourceMapped = mapArtifactTypeToSource(analysisState.artifact_type);

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-16">
      {/* 1. MINIMAL HEADER CONTEXT */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center space-x-2 text-xs font-mono text-foreground-muted">
            <span>Investigation</span>
            <span>/</span>
            <span className="font-semibold text-foreground">
              {analysisState.investigation_id || investigationId || `RUN-${analysisState.id.slice(0, 8)}`}
            </span>
            <span>•</span>
            <span className="uppercase text-[10px] tracking-wider font-bold text-primary">Live Analysis</span>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-bold text-foreground truncate max-w-xl">
              {analysisState.artifact_name}
            </h1>
            <SourceBadge source={sourceMapped} size="sm" />
          </div>

          {/* Cryptographic SHA-256 Hash with Copy */}
          {analysisState.artifact_sha256 && (
            <div className="flex items-center space-x-2 text-xs font-mono text-foreground-muted pt-0.5">
              <span className="text-[11px] text-foreground-subtle">SHA-256:</span>
              <span className="text-[11px] font-mono select-all">
                {analysisState.artifact_sha256.slice(0, 16)}••••{analysisState.artifact_sha256.slice(-12)}
              </span>
              <button
                type="button"
                onClick={() => handleCopyHash(analysisState.artifact_sha256)}
                className="p-1 rounded hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                title="Copy full authoritative SHA-256 hash"
              >
                {copiedHash ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          )}
        </div>

        {/* Status Badge & Primary Action Controls */}
        <div className="flex items-center space-x-3 shrink-0">
          {isRunning && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-mono font-semibold animate-pulse">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>Analyzing Evidence...</span>
            </div>
          )}

          {isCompleted && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-success-surface border border-success-border text-success text-xs font-mono font-semibold">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Analysis Complete</span>
            </div>
          )}

          {isPartial && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-warning-surface border border-warning-border text-warning text-xs font-mono font-semibold">
              <AlertCircle className="w-3.5 h-3.5" />
              <span>Partially Completed</span>
            </div>
          )}

          {isFailed && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-danger-surface border border-danger-border text-danger text-xs font-mono font-semibold">
              <XCircle className="w-3.5 h-3.5" />
              <span>Analysis Failed</span>
            </div>
          )}

          {isCancelled && (
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground-muted text-xs font-mono font-semibold">
              <MinusCircle className="w-3.5 h-3.5" />
              <span>Cancelled</span>
            </div>
          )}

          {/* Primary Action Button */}
          {(isCompleted || isPartial) && (
            <>
              <Button
                variant="secondary"
                size="sm"
                onClick={() => setViewMode('results')}
                leftIcon={<ShieldAlert className="w-3.5 h-3.5 text-primary" />}
              >
                Forensic Results
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleOpenInvestigation}
                rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
              >
                Open Investigation
              </Button>
            </>
          )}

          {isRunning && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setCancelConfirmOpen(true)}
              disabled={actionLoading}
            >
              Cancel
            </Button>
          )}

          {(isFailed || isCancelled) && (
            <Button
              variant="secondary"
              size="sm"
              onClick={handleRetry}
              disabled={actionLoading}
              leftIcon={<RotateCcw className="w-3.5 h-3.5" />}
            >
              Retry Analysis
            </Button>
          )}
        </div>
      </div>

      {/* 2. TRUTHFUL PROGRESS / EXECUTION SUMMARY BAR */}
      <div className="bg-surface rounded-xl border border-border p-4 shadow-xs space-y-2">
        <div className="flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-foreground">Pipeline Execution:</span>
            <span className="text-foreground-muted">
              {analysisState.completed_tasks} of {analysisState.total_tasks} analyzers completed
            </span>
            {analysisState.failed_tasks > 0 && (
              <span className="text-danger font-bold">({analysisState.failed_tasks} failed)</span>
            )}
          </div>
          {typeof analysisState.progress === 'number' && (
            <span className="text-primary font-bold">{analysisState.progress}%</span>
          )}
        </div>

        {/* Progress Bar (Truthful 0-100 or indeterminate animation) */}
        <div className="w-full h-2 rounded-full bg-surface-secondary overflow-hidden">
          {typeof analysisState.progress === 'number' ? (
            <div
              className={`h-full transition-all duration-300 ${
                isCompleted ? 'bg-success' : isFailed ? 'bg-danger' : 'bg-primary'
              }`}
              style={{ width: `${Math.min(100, Math.max(0, analysisState.progress))}%` }}
            />
          ) : isRunning ? (
            <div className="h-full bg-primary/80 animate-pulse w-full" />
          ) : (
            <div className="h-full bg-surface-secondary w-full" />
          )}
        </div>
      </div>

      {/* 3. MAIN WORKSTATION GRID */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* LEFT COLUMN: TASK GRAPH DAG & FINDINGS PREVIEW (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          {/* A. CURRENTLY RUNNING ANALYZER HIGHLIGHT */}
          {isRunning && analysisState.current_task && (
            <Card className="border-primary/40 bg-primary/5 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-mono font-bold tracking-wider uppercase text-primary flex items-center space-x-1.5">
                  <Cpu className="w-3.5 h-3.5 animate-spin" />
                  <span>Currently Analyzing</span>
                </span>
                <span className="text-[11px] font-mono text-foreground-muted">
                  Analyzer: {analysisState.current_task.analyzer_id}
                </span>
              </div>
              <h2 className="text-sm font-bold text-foreground">
                {analysisState.current_task.title}
              </h2>
              {analysisState.current_task.description && (
                <p className="text-xs text-foreground-muted leading-relaxed">
                  {analysisState.current_task.description}
                </p>
              )}
            </Card>
          )}

          {/* B. TASK GRAPH DAG EXECUTION LIST */}
          <div className="bg-surface rounded-xl border border-border shadow-xs overflow-hidden">
            <div className="p-4 border-b border-border flex items-center justify-between bg-surface-secondary/40">
              <div className="flex items-center space-x-2">
                <Layers className="w-4 h-4 text-primary" />
                <h2 className="text-sm font-bold text-foreground">Analysis Task Graph (DAG)</h2>
              </div>
              <span className="text-xs font-mono text-foreground-muted">
                {analysisState.tasks.length} atomic analyzers
              </span>
            </div>

            <div className="divide-y divide-border">
              {analysisState.tasks.map((task: AnalysisTask) => {
                const isTaskExpanded = !!expandedTasks[task.id];
                const isTaskRunning = task.status === 'RUNNING';
                const isTaskCompleted = task.status === 'COMPLETED';
                const isTaskFailed = task.status === 'FAILED';
                const isTaskBlocked = task.status === 'BLOCKED' || task.status === 'SKIPPED';

                return (
                  <div
                    key={task.id}
                    className={`transition-colors ${
                      isTaskRunning ? 'bg-primary/5' : 'hover:bg-surface-secondary/40'
                    }`}
                  >
                    <div
                      onClick={() => toggleTaskExpanded(task.id)}
                      className="p-3.5 flex items-center justify-between gap-3 cursor-pointer select-none"
                    >
                      {/* Left: Status Icon & Title */}
                      <div className="flex items-center space-x-3 min-w-0">
                        {isTaskCompleted && (
                          <CheckCircle2 className="w-4 h-4 text-success shrink-0" />
                        )}
                        {isTaskRunning && (
                          <Loader2 className="w-4 h-4 text-primary animate-spin shrink-0" />
                        )}
                        {isTaskFailed && (
                          <AlertCircle className="w-4 h-4 text-danger shrink-0" />
                        )}
                        {isTaskBlocked && (
                          <MinusCircle className="w-4 h-4 text-foreground-subtle shrink-0" />
                        )}
                        {!isTaskCompleted && !isTaskRunning && !isTaskFailed && !isTaskBlocked && (
                          <Circle className="w-4 h-4 text-foreground-subtle shrink-0" />
                        )}

                        <div className="min-w-0">
                          <span
                            className={`text-xs font-semibold block truncate ${
                              isTaskRunning
                                ? 'text-primary'
                                : isTaskFailed
                                ? 'text-danger'
                                : 'text-foreground'
                            }`}
                          >
                            {task.title}
                          </span>
                          <span className="text-[11px] font-mono text-foreground-muted truncate block">
                            {task.message || task.description}
                          </span>
                        </div>
                      </div>

                      {/* Right: Duration, Result Count & Expand Toggle */}
                      <div className="flex items-center space-x-2 shrink-0 text-xs font-mono">
                        {task.result_count > 0 && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-surface-secondary border border-border text-foreground-muted">
                            {task.result_count} {task.result_count === 1 ? 'result' : 'results'}
                          </span>
                        )}
                        {typeof task.duration_seconds === 'number' && (
                          <span className="text-[11px] text-foreground-subtle">
                            {(task.duration_seconds * 1000).toFixed(0)}ms
                          </span>
                        )}
                        <span className="text-foreground-muted">
                          {isTaskExpanded ? (
                            <ChevronUp className="w-3.5 h-3.5" />
                          ) : (
                            <ChevronDown className="w-3.5 h-3.5" />
                          )}
                        </span>
                      </div>
                    </div>

                    {/* Expandable Task Metadata & Technical Details */}
                    {isTaskExpanded && (
                      <div className="px-10 pb-3 text-xs space-y-1.5 bg-surface-secondary/30 text-foreground-muted font-mono">
                        {task.description && (
                          <p className="text-[11px] leading-relaxed text-foreground-muted">
                            {task.description}
                          </p>
                        )}
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-[10px] pt-1">
                          <span>Task ID: {task.id}</span>
                          <span>Analyzer ID: {task.analyzer_id}</span>
                          <span>Version: {task.version}</span>
                          {task.error && <span className="text-danger">Error: {task.error}</span>}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* C. PRELIMINARY FINDINGS PREVIEW */}
          {analysisState.findings.length > 0 && (
            <div className="bg-surface rounded-xl border border-border shadow-xs p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <ShieldAlert className="w-4 h-4 text-warning" />
                  <h2 className="text-sm font-bold text-foreground">
                    Observed Findings ({analysisState.findings.length})
                  </h2>
                </div>
                <span className="text-[10px] font-mono text-foreground-muted">
                  Persisted to Knowledge Graph
                </span>
              </div>

              <div className="space-y-2">
                {analysisState.findings.map((f) => (
                  <div
                    key={f.id}
                    className="p-2.5 rounded-lg bg-surface-secondary/50 border border-border flex items-start justify-between gap-3 text-xs"
                  >
                    <div className="space-y-0.5 min-w-0">
                      <div className="flex items-center space-x-2">
                        <SeverityIndicator severity={f.severity} size="sm" showText />
                        <span className="font-semibold text-foreground truncate">{f.title}</span>
                      </div>
                      <span className="block text-[10px] font-mono text-foreground-muted">
                        Analyzer: {f.analyzer} • Confidence: {(f.confidence * 100).toFixed(0)}%
                      </span>
                    </div>

                    {f.risk_contribution > 0 && (
                      <span className="shrink-0 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-danger-surface text-danger border border-danger-border">
                        +{f.risk_contribution.toFixed(0)} pts
                      </span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT COLUMN: ACTIVITY STREAM & RISK ASSESSMENT (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* A. RISK ASSESSMENT SUMMARY */}
          <Card className="p-4 space-y-3">
            <span className="text-xs font-mono uppercase tracking-wider text-foreground-muted block font-bold">
              Risk Evaluation
            </span>

            {typeof analysisState.overall_risk_score === 'number' ? (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <ThreatScore
                    score={analysisState.overall_risk_score}
                    severity={analysisState.overall_severity || undefined}
                    confidenceScore={analysisState.confidence ?? undefined}
                    variant="card"
                  />
                </div>
                {typeof analysisState.confidence === 'number' && (
                  <div className="text-[11px] font-mono text-foreground-muted flex items-center justify-between pt-1 border-t border-border">
                    <span>Model Confidence</span>
                    <span className="font-bold">{(analysisState.confidence * 100).toFixed(0)}%</span>
                  </div>
                )}
              </div>
            ) : (
              <div className="p-3 rounded-lg bg-surface-secondary/60 border border-border text-center space-y-1">
                <Clock className="w-4 h-4 text-foreground-muted mx-auto animate-pulse" />
                <span className="text-xs font-mono text-foreground font-semibold block">
                  Risk Assessment Pending
                </span>
                <span className="text-[11px] text-foreground-muted block">
                  Awaiting completion of upstream heuristic and threat correlation analyzers
                </span>
              </div>
            )}
          </Card>

          {/* B. REAL-TIME ACTIVITY STREAM */}
          <div className="bg-surface rounded-xl border border-border shadow-xs p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-primary" />
                <h2 className="text-sm font-bold text-foreground">Analysis Activity Stream</h2>
              </div>
              {isRunning && (
                <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-primary/10 text-primary border border-primary/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-primary animate-ping mr-1" />
                  LIVE
                </span>
              )}
            </div>

            <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
              {analysisState.events.length === 0 ? (
                <div className="text-center py-6 text-xs text-foreground-muted font-mono">
                  No activity events recorded yet.
                </div>
              ) : (
                analysisState.events.map((evt: AnalysisEvent) => (
                  <div
                    key={evt.id}
                    className="p-2 rounded bg-surface-secondary/40 border border-border text-xs font-mono space-y-0.5"
                  >
                    <div className="flex items-center justify-between text-[10px] text-foreground-subtle">
                      <span>{formatEventTime(evt.timestamp)}</span>
                      <span className="uppercase text-[9px] font-semibold text-primary">
                        {evt.event_type.replace('_', ' ')}
                      </span>
                    </div>
                    <p className="text-[11px] text-foreground leading-snug">
                      {evt.message}
                    </p>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* C. TECHNICAL EXECUTION DETAILS (EXPANDABLE) */}
          <div className="bg-surface rounded-xl border border-border p-3 shadow-xs">
            <button
              type="button"
              onClick={() => setShowTechnicalDetails(!showTechnicalDetails)}
              className="w-full flex items-center justify-between text-xs font-mono text-foreground-muted hover:text-foreground transition-colors cursor-pointer select-none"
            >
              <span>Technical Analysis Metadata</span>
              <span>{showTechnicalDetails ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}</span>
            </button>

            {showTechnicalDetails && (
              <div className="pt-3 mt-2 border-t border-border space-y-1.5 text-[11px] font-mono text-foreground-muted">
                <div className="flex justify-between">
                  <span>Run ID:</span>
                  <span className="text-foreground select-all">{analysisState.id}</span>
                </div>
                <div className="flex justify-between">
                  <span>Pipeline Version:</span>
                  <span className="text-foreground">{analysisState.pipeline_version}</span>
                </div>
                <div className="flex justify-between">
                  <span>Trigger Mode:</span>
                  <span className="text-foreground">{analysisState.trigger}</span>
                </div>
                {analysisState.duration_seconds && (
                  <div className="flex justify-between">
                    <span>Duration:</span>
                    <span className="text-foreground">{analysisState.duration_seconds}s</span>
                  </div>
                )}
                {analysisState.previous_runs_count > 0 && (
                  <div className="flex justify-between">
                    <span>Historical Runs:</span>
                    <span className="text-foreground">{analysisState.previous_runs_count} prior runs</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 4. CANCEL CONFIRMATION MODAL */}
      {cancelConfirmOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-fadeIn">
          <div className="bg-surface rounded-xl border border-border shadow-xl max-w-md w-full p-5 space-y-4">
            <div className="flex items-center space-x-2 text-danger">
              <AlertCircle className="w-5 h-5" />
              <h3 className="text-sm font-bold text-foreground">Cancel Live Analysis?</h3>
            </div>
            <p className="text-xs text-foreground-muted leading-relaxed">
              Halting analysis will cancel currently running analyzers and mark this run as cancelled.
              Already persisted findings and evidence will remain intact.
            </p>
            <div className="flex items-center justify-end space-x-2 pt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCancelConfirmOpen(false)}
                disabled={actionLoading}
              >
                Continue Analyzing
              </Button>
              <Button
                variant="danger"
                size="sm"
                onClick={handleCancel}
                isLoading={actionLoading}
              >
                Yes, Cancel Analysis
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
