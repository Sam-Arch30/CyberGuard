import { MediaAnalysisPanel, type MediaAssessment } from '../../dashboard/MediaAnalysisPanel';
import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  AlertCircle,
  Clock,
  ArrowRight,
  ChevronDown,
  ChevronUp,
  Cpu,
  Sparkles,
  RefreshCw,
  Target,
  Link2,
  Globe,
  Paperclip,
  UserCheck,
  Eye,
  GitBranch,
  Scale,
  Compass,
  MapPin,
  Flame,
  Activity,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import {
  Card,
  Badge,
  Button,
  LoadingState,
  ErrorState,
} from '../../ui';
import {
  ThreatScore,
  SeverityIndicator,
  EvidenceCount,
} from '../../security';
import { analysisResultsService } from '../../../services/analysisResultsService';
import { RealtimeService } from '../../../services/realtimeService';
import type { RealtimeConnectionStatus } from '../../../types/realtime';
import { EvidenceDetailDrawer } from './EvidenceDetailDrawer';
import type {
  AnalysisResultsResponse,
  FindingResultDetail,
  SupportingEvidencePreview,
  DomainIndicator,
  URLIndicator,
  AttachmentResultItem,
} from '../../../types/analysisResults';

interface AnalysisResultsWorkstationProps {
  runId?: string;
  investigationId?: string;
  onToggleViewDAG?: () => void;
}

export const AnalysisResultsWorkstation: React.FC<AnalysisResultsWorkstationProps> = ({
  runId: initialRunId,
  investigationId,
  onToggleViewDAG,
}) => {
  const navigate = useNavigate();

  // Results State
  const [data, setData] = useState<AnalysisResultsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [reassessing, setReassessing] = useState<boolean>(false);
  const [connectionStatus, setConnectionStatus] = useState<RealtimeConnectionStatus>('DISCONNECTED');

  // Progressive Disclosure Expand States
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [expandedSections, setExpandedSections] = useState<{
    counterEvidence: boolean;
    contradictions: boolean;
    uncertainty: boolean;
    whatWouldChange: boolean;
    indicators: boolean;
    attackPath: boolean;
    mitre: boolean;
    infrastructure: boolean;
    behavioral: boolean;
    provenance: boolean;
  }>({
    counterEvidence: true,
    contradictions: true,
    uncertainty: true,
    whatWouldChange: true,
    indicators: false,
    attackPath: false,
    mitre: false,
    infrastructure: false,
    behavioral: false,
    provenance: false,
  });

  // Evidence Drawer State
  const [selectedEvidenceId, setSelectedEvidenceId] = useState<string | null>(null);
  const [evidencePreview, setEvidencePreview] = useState<SupportingEvidencePreview | null>(null);
  const [drawerOpen, setDrawerOpen] = useState<boolean>(false);

  // Load Aggregated Results
  const loadResults = useCallback(
    async (targetRunId?: string, silent: boolean = false) => {
      if (!silent) {
        setLoading(true);
        setError(null);
      }
      try {
        let res: AnalysisResultsResponse;
        if (targetRunId) {
          res = await analysisResultsService.getAnalysisResults(targetRunId);
        } else if (initialRunId) {
          res = await analysisResultsService.getAnalysisResults(initialRunId);
        } else if (investigationId) {
          res = await analysisResultsService.getInvestigationAnalysisResults(investigationId);
        } else {
          throw new Error('No valid run ID or investigation ID provided.');
        }
        setData(res);
      } catch (err: unknown) {
        if (!silent) {
          setError(err instanceof Error ? err.message : 'Failed to retrieve analysis results.');
        }
      } finally {
        if (!silent) {
          setLoading(false);
        }
      }
    },
    [initialRunId, investigationId]
  );

  useEffect(() => {
    loadResults();
  }, [loadResults]);

  // Section 46: Real-Time Updates Subscription
  useEffect(() => {
    if (!data?.run_id) return;
    const runId = data.run_id;

    const unsubscribe = RealtimeService.subscribe({
      url: `/api/analysis/${encodeURIComponent(runId)}/stream`,
      onEvent: (evt) => {
        // When findings persist, tasks progress, or analysis completes, silently refetch authoritative results
        if (
          [
            'FINDING_PERSISTED',
            'ANALYSIS_PROGRESS',
            'ANALYSIS_STAGE_COMPLETED',
            'ANALYSIS_COMPLETED',
            'ANALYSIS_PARTIAL',
            'ANALYZER_WARNING',
            'ANALYZER_DEGRADED',
          ].includes(evt.event_type)
        ) {
          loadResults(runId, true);
        }
      },
      onStatusChange: (st) => setConnectionStatus(st),
      onAuthoritativeRefetch: () => {
        loadResults(runId, true);
      },
      onTerminal: () => {
        loadResults(runId, true);
      },
    });

    return () => {
      unsubscribe();
    };
  }, [data?.run_id, loadResults]);

  // Handle Manual Reassessment
  const handleReassess = async () => {
    if (!data?.run_id) return;
    setReassessing(true);
    try {
      const refreshed = await analysisResultsService.reassessAnalysis(
        data.run_id,
        'Manual investigator-initiated risk reassessment'
      );
      setData(refreshed);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Risk reassessment failed.');
    } finally {
      setReassessing(false);
    }
  };

  // Toggle Finding Accordion
  const toggleFinding = (fId: string) => {
    setExpandedFindings((prev) => ({ ...prev, [fId]: !prev[fId] }));
  };

  // Open Evidence Drawer
  const openEvidenceDrawer = (evId: string, preview?: SupportingEvidencePreview) => {
    setSelectedEvidenceId(evId);
    setEvidencePreview(preview || null);
    setDrawerOpen(true);
  };

  // Toggle Generic Section
  const toggleSection = (section: keyof typeof expandedSections) => {
    setExpandedSections((prev) => ({ ...prev, [section]: !prev[section] }));
  };

  if (loading) {
    return (
      <LoadingState
        message="Aggregating verified analysis results..."
        subtext="Correlating findings, risk signals, and forensic provenance"
        fullHeight
      />
    );
  }

  if (error || !data) {
    return (
      <ErrorState
        title="Analysis Results Unavailable"
        message={error || 'Unable to load analysis conclusions for this investigation.'}
        onRetry={() => loadResults()}
        action={
          onToggleViewDAG && (
            <Button size="sm" variant="outline" onClick={onToggleViewDAG}>
              View Pipeline Tasks
            </Button>
          )
        }
      />
    );
  }

  const { risk, artifact } = data;
  if (['IMAGE', 'AUDIO', 'VIDEO'].includes(artifact.artifact_type)) {
    return <MediaAnalysisPanel key={data.run_id} artifact={{id: artifact.id, name: artifact.name}}
      initialAssessment={data.media_assessment as MediaAssessment | null}
      onAnalysisComplete={newRun => { void loadResults(newRun, true); }}/>
  }
  const isPartial = data.analysis_completeness === 'PARTIAL' || data.status === 'PARTIAL';
  const isDegraded = data.analysis_completeness === 'DEGRADED';

  return (
    <div className="cg-analysis-results space-y-6 pb-20 font-sans max-w-7xl mx-auto">
      {/* =========================================================================
          TOP BANNER: COMPLETENESS / RUN SELECTOR / ACTIONS
      ========================================================================= */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3 rounded-xl bg-surface border border-border shadow-xs text-xs font-mono">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-1.5">
            <span className="text-foreground-muted">Artifact:</span>
            <span className="font-semibold text-foreground">{artifact.name}</span>
            <Badge variant="outline" size="sm" className="text-[10px]">
              {artifact.artifact_type}
            </Badge>
          </div>

          <span className="text-border">|</span>

          <div className="flex items-center space-x-1.5">
            <span className="text-foreground-muted">Status:</span>
            {data.status === 'RUNNING' || data.status === 'QUEUED' ? (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-primary/10 text-primary border border-primary/30 animate-pulse">
                <RefreshCw className="w-3 h-3 mr-1 animate-spin" />
                ANALYSIS RUNNING ({data.completed_tasks}/{data.total_tasks} analyzers)
              </span>
            ) : isPartial ? (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-warning-surface text-warning border border-warning-border">
                <AlertTriangle className="w-3 h-3 mr-1" />
                PARTIAL RESULTS ({data.completed_tasks}/{data.total_tasks} analyzers)
              </span>
            ) : isDegraded ? (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-warning-surface text-warning border border-warning-border">
                <AlertCircle className="w-3 h-3 mr-1" />
                DEGRADED
              </span>
            ) : (
              <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-bold bg-success-surface text-success border border-success-border">
                <CheckCircle2 className="w-3 h-3 mr-1" />
                ANALYSIS COMPLETE
              </span>
            )}
          </div>
        </div>

        <div className="flex items-center space-x-2">
          {/* Real-time Connection Status Indicator */}
          <div
            className="flex items-center space-x-1.5 px-2 py-0.5 rounded text-[11px] font-mono border bg-surface-secondary border-border"
            title="Real-time SSE event stream connection state"
          >
            {connectionStatus === 'CONNECTED' && (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                <span className="text-foreground">● Live</span>
              </>
            )}
            {connectionStatus === 'RECONNECTING' && (
              <>
                <RefreshCw className="w-2.5 h-2.5 text-warning animate-spin" />
                <span className="text-warning">↻ Reconnecting</span>
              </>
            )}
            {connectionStatus === 'FALLBACK_POLLING' && (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-info" />
                <span className="text-foreground-muted">⚡ Polling</span>
              </>
            )}
            {connectionStatus === 'DISCONNECTED' && (
              <>
                <span className="w-1.5 h-1.5 rounded-full bg-foreground-muted/40" />
                <span className="text-foreground-muted">Idle</span>
              </>
            )}
          </div>

          {data.run_history.length > 1 && (
            <div className="flex items-center space-x-1 text-foreground-muted">
              <span>Run:</span>
              <select
                value={data.run_id}
                onChange={(e) => loadResults(e.target.value)}
                className="bg-surface-secondary border border-border rounded px-2 py-1 text-xs text-foreground cursor-pointer focus:outline-none"
                aria-label="Select Analysis Run"
              >
                {data.run_history.map((rh) => (
                  <option key={rh.run_id} value={rh.run_id}>
                    Run #{rh.run_number} ({rh.status}) {rh.is_current ? '• Current' : ''}
                  </option>
                ))}
              </select>
            </div>
          )}

          <Button
            size="sm"
            variant="outline"
            onClick={handleReassess}
            isLoading={reassessing}
            leftIcon={<RefreshCw className={`w-3.5 h-3.5 ${reassessing ? 'animate-spin' : ''}`} />}
            title="Request versioned risk reassessment"
          >
            Reassess
          </Button>

          {onToggleViewDAG && (
            <Button
              size="sm"
              variant="secondary"
              onClick={onToggleViewDAG}
              leftIcon={<Activity className="w-3.5 h-3.5 text-primary" />}
            >
              Processing details
            </Button>
          )}
        </div>
      </div>

      {/* Live Processing Notice (Preserves results while pipeline executes) */}
      {(data.status === 'RUNNING' || data.status === 'QUEUED') && (
        <div className="flex items-center justify-between p-3 rounded-xl bg-primary/5 border border-primary/20 text-xs font-mono">
          <div className="flex items-center space-x-2 text-primary font-medium">
            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
            <span>Analysis pipeline is actively executing ({data.completed_tasks} of {data.total_tasks} analyzers completed). New findings and risk updates will populate seamlessly.</span>
          </div>
          <span className="text-[10px] text-foreground-muted uppercase tracking-wider font-semibold">Live Analysis Active</span>
        </div>
      )}

      {/* PARTIAL RESULTS WARNING BANNER */}
      {isPartial && (
        <div className="p-3.5 rounded-xl bg-warning-surface/80 border border-warning-border flex items-start space-x-3 text-warning-foreground animate-fadeIn">
          <AlertTriangle className="w-4 h-4 text-warning shrink-0 mt-0.5" />
          <div className="text-xs space-y-0.5">
            <span className="font-bold text-foreground block font-mono">
              Analysis limitations
            </span>
            <p className="text-foreground-muted font-sans">
              {data.completeness_message ||
                `${data.failed_tasks} analysis tasks encountered errors or timeouts. Findings reflect all completed stages, but downstream correlators may have partial visibility.`}
            </p>
          </div>
        </div>
      )}

      {/* =========================================================================
          LEVEL 1: EXECUTIVE RESULT HERO (Risk + Classification + Why + Next Step)
      ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        {/* 1.1 RISK HEADER CARD (4 cols) */}
        <Card className="lg:col-span-4 p-5 flex flex-col justify-between space-y-4 border-primary/25 bg-surface/90 shadow-sm relative overflow-hidden">
          <div className="absolute top-0 right-0 transform translate-x-4 -translate-y-4 w-28 h-28 rounded-full bg-primary/5 blur-2xl pointer-events-none" />

          <div className="space-y-1">
            <div className="flex items-center justify-between">
              <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted font-bold">
                Unified Risk Assessment
              </span>
              <span className="text-[10px] font-mono text-foreground-subtle">
                Analysis result
              </span>
            </div>

            {risk.is_pending ? (
              <div className="py-6 text-center space-y-2">
                <Clock className="w-8 h-8 text-primary/60 mx-auto animate-pulse" />
                <span className="font-mono text-sm font-bold text-foreground block">
                  {risk.status_label}
                </span>
                <span className="text-xs text-foreground-muted font-sans block">
                  Analyzers still computing risk signals.
                </span>
              </div>
            ) : (
              <div className="py-2">
                <ThreatScore
                  score={risk.score}
                  severity={risk.severity}
                  confidence={risk.confidence_level}
                  confidenceScore={risk.confidence ?? undefined}
                  variant="card"
                />
              </div>
            )}
          </div>

          {/* EXPLICIT SEPARATION TOOLTIPS */}
          <div className="pt-3 border-t border-border grid grid-cols-3 gap-2 text-center font-mono">
            <div className="p-2 rounded-lg bg-surface-secondary/60 border border-border/80">
              <span className="text-[10px] text-foreground-subtle block uppercase">Risk</span>
              <span className="text-xs font-bold text-foreground">
                {risk.score !== null && risk.score !== undefined ? `${risk.score.toFixed(0)}/100` : '--'}
              </span>
            </div>

            <div className="p-2 rounded-lg bg-surface-secondary/60 border border-border/80">
              <span className="text-[10px] text-foreground-subtle block uppercase">Severity</span>
              <span className="text-xs font-bold text-foreground truncate block">
                {risk.severity}
              </span>
            </div>

            <div className="p-2 rounded-lg bg-surface-secondary/60 border border-border/80">
              <span className="text-[10px] text-foreground-subtle block uppercase">Confidence</span>
              <span className="text-xs font-bold text-foreground truncate block">
                {risk.confidence_level}
              </span>
            </div>
          </div>

          <div className="text-[10px] font-mono text-foreground-subtle flex items-center justify-between">
            <span>Freshness: {new Date(data.last_updated).toLocaleTimeString()}</span>
            <span>Uncertainty: {risk.uncertainty}</span>
          </div>
        </Card>

        {/* 1.2 EXECUTIVE SUMMARY & "WHY CYBERGUARD THINKS THIS" (8 cols) */}
        <Card className="lg:col-span-8 p-6 flex flex-col justify-between space-y-5 bg-surface shadow-sm">
          <div className="space-y-4">
            {/* CLASSIFICATION HEADER */}
            <div className="space-y-1">
              <span className="text-[11px] font-mono uppercase tracking-wider text-foreground-muted font-bold block">
                Threat assessment
              </span>
              <h2 className="text-xl font-bold text-foreground tracking-tight flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-primary shrink-0" />
                <span>{data.classification}</span>
              </h2>
              <p className="text-xs text-foreground-muted leading-relaxed font-sans pt-1">
                {data.executive_summary}
              </p>
            </div>

            {/* WHY CYBERGUARD THINKS THIS (EXPLAINABLE AI) */}
            <div className="space-y-2 pt-2 border-t border-border">
              <span className="text-xs font-mono font-bold text-foreground flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-primary" />
                Why CyberGuard thinks this
              </span>

              <div className="space-y-2">
                {data.why_cyberguard_thinks_this.length === 0 ? (
                  <div className="text-xs text-foreground-muted italic font-mono py-2">
                    Insufficient evidence to construct causal assertions.
                  </div>
                ) : (
                  data.why_cyberguard_thinks_this.map((item, idx) => (
                    <div
                      key={item.id || idx}
                      className="p-2.5 rounded-lg bg-surface-secondary/50 border border-border flex items-start justify-between gap-3 text-xs"
                    >
                      <div className="flex items-start space-x-2.5">
                        <span className="w-4 h-4 rounded-full bg-primary/10 text-primary flex items-center justify-center text-[10px] font-bold font-mono shrink-0 mt-0.5">
                          {idx + 1}
                        </span>
                        <div className="space-y-0.5">
                          <p className="text-foreground font-medium leading-relaxed">
                            {item.claim}
                          </p>
                          <div className="flex items-center space-x-2 text-[10px] font-mono text-foreground-muted">
                            <span>Support: {item.support_level}</span>
                            <span>•</span>
                            <span>Confidence: {(item.confidence * 100).toFixed(0)}%</span>
                          </div>
                        </div>
                      </div>

                      {item.evidence_refs && item.evidence_refs.length > 0 && (
                        <button
                          type="button"
                          onClick={() => openEvidenceDrawer(item.evidence_refs[0])}
                          className="shrink-0 inline-flex items-center space-x-1 px-2 py-1 rounded bg-surface hover:bg-surface-secondary border border-border text-[10px] font-mono text-primary cursor-pointer transition-colors"
                          title="Inspect supporting evidence"
                        >
                          <Eye className="w-3 h-3" />
                          <span>
                            {item.evidence_count} evidence
                          </span>
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* 1.3 RECOMMENDED NEXT STEP CTA */}
          <div className="p-3.5 rounded-xl bg-primary/5 border border-primary/20 flex flex-wrap items-center justify-between gap-3 font-sans">
            <div className="space-y-0.5">
              <span className="text-[10px] font-mono uppercase text-primary font-bold tracking-wider block">
                Recommended Action ({data.next_step_recommendation.priority} Priority)
              </span>
              <span className="text-xs font-bold text-foreground block">
                {data.next_step_recommendation.action_title}
              </span>
              <p className="text-[11px] text-foreground-muted leading-tight">
                {data.next_step_recommendation.action_description}
              </p>
            </div>

            {data.next_step_recommendation.target_route && (
              <Button
                size="sm"
                variant="primary"
                onClick={() => navigate(data.next_step_recommendation.target_route!)}
                rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
              >
                Proceed
              </Button>
            )}
          </div>
        </Card>
      </div>

      {/* =========================================================================
          LEVEL 2: ANALYST FINDINGS & INDICATOR SUMMARY
      ========================================================================= */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <ShieldAlert className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-bold font-mono text-foreground">
              Key Prioritized Findings ({data.top_findings.length})
            </h3>
          </div>
          <span className="text-[11px] font-mono text-foreground-muted">
            Sorted by Risk Contribution & Severity
          </span>
        </div>

        {data.top_findings.length === 0 ? (
          <div className="p-6 rounded-xl bg-surface border border-border text-center text-xs font-mono text-foreground-muted">
            No malicious or suspicious findings flagged by analyzers.
          </div>
        ) : (
          <div className="space-y-3">
            {data.top_findings.map((f: FindingResultDetail) => {
              const isExpanded = expandedFindings[f.id] || false;
              return (
                <div
                  key={f.id}
                  className="rounded-xl bg-surface border border-border shadow-xs overflow-hidden transition-all duration-150"
                >
                  {/* FINDING SUMMARY BAR (CLICK TO EXPAND) */}
                  <button
                    type="button"
                    onClick={() => toggleFinding(f.id)}
                    aria-expanded={isExpanded}
                    className="w-full p-4 flex items-center justify-between text-left hover:bg-surface-secondary/40 transition-colors cursor-pointer select-none"
                  >
                    <div className="flex items-center space-x-3.5 min-w-0 pr-2">
                      <SeverityIndicator severity={f.severity} size="sm" />

                      <div className="space-y-0.5 min-w-0">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-bold text-foreground font-sans truncate">
                            {f.title}
                          </span>
                          <span className="text-[10px] font-mono text-foreground-subtle hidden sm:inline">
                            [{f.analyzer}]
                          </span>
                        </div>
                        <p className="text-[11px] text-foreground-muted font-sans line-clamp-1">
                          {f.description}
                        </p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-3 shrink-0 font-mono text-xs">
                      {f.risk_contribution > 0 && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-danger-surface text-danger border border-danger-border">
                          +{f.risk_contribution.toFixed(0)} pts
                        </span>
                      )}

                      <span className="text-[11px] text-foreground-muted hidden md:inline">
                        Conf: {(f.confidence * 100).toFixed(0)}%
                      </span>

                      <EvidenceCount total={f.evidence_count} size="sm" />

                      <span className="text-foreground-muted">
                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                      </span>
                    </div>
                  </button>

                  {/* PROGRESSIVE DISCLOSURE: EXPANDED DETAILS */}
                  {isExpanded && (
                    <div className="p-4 bg-surface-secondary/30 border-t border-border space-y-4 text-xs font-mono animate-fadeIn">
                      {/* OBSERVED VS EXPECTED */}
                      {(f.observed_value || f.expected_value) && (
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-3 rounded-lg bg-surface border border-border">
                          {f.observed_value && (
                            <div className="space-y-1">
                              <span className="text-[10px] text-foreground-subtle uppercase block font-semibold">
                                Observed Value
                              </span>
                              <div className="p-2 rounded bg-surface-secondary/80 border border-border text-foreground break-all text-[11px]">
                                {f.observed_value}
                              </div>
                            </div>
                          )}
                          {f.expected_value && (
                            <div className="space-y-1">
                              <span className="text-[10px] text-foreground-subtle uppercase block font-semibold">
                                Expected / Baseline Value
                              </span>
                              <div className="p-2 rounded bg-surface-secondary/80 border border-border text-foreground break-all text-[11px]">
                                {f.expected_value}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* DETECTOR / RULE PROVENANCE */}
                      <div className="flex flex-wrap items-center gap-3 text-[11px] text-foreground-muted">
                        <span className="flex items-center gap-1">
                          <Cpu className="w-3 h-3 text-primary" />
                          Analyzer: <strong className="text-foreground">{f.analyzer}</strong>
                        </span>
                        <span>•</span>
                        <span>Method: {f.method}</span>
                        {f.rule_id && (
                          <>
                            <span>•</span>
                            <span>Rule: {f.rule_id}</span>
                          </>
                        )}
                        <span>•</span>
                        <span>Confidence: {(f.confidence * 100).toFixed(0)}%</span>
                      </div>

                      {/* SUPPORTING EVIDENCE LIST */}
                      {f.evidence_items.length > 0 && (
                        <div className="space-y-2 pt-2 border-t border-border/80">
                          <span className="text-[11px] font-semibold text-foreground uppercase tracking-wider block">
                            Supporting Forensic Evidence ({f.evidence_items.length})
                          </span>

                          <div className="space-y-1.5">
                            {f.evidence_items.map((ev) => (
                              <div
                                key={ev.id}
                                className="p-2 rounded-lg bg-surface border border-border flex items-center justify-between text-xs"
                              >
                                <div className="space-y-0.5 min-w-0 pr-2">
                                  <div className="flex items-center space-x-2">
                                    <Badge variant="outline" size="sm" className="text-[9px] uppercase">
                                      {ev.evidence_type}
                                    </Badge>
                                    <span className="text-[11px] font-semibold text-foreground truncate">
                                      {ev.key}
                                    </span>
                                  </div>
                                  <p className="text-[10px] text-foreground-muted truncate">
                                    {ev.value}
                                  </p>
                                </div>

                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={() => openEvidenceDrawer(ev.id, ev)}
                                  className="text-[10px] text-primary shrink-0 cursor-pointer"
                                  leftIcon={<Eye className="w-3 h-3" />}
                                >
                                  Inspect Evidence
                                </Button>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* COUNTER-EVIDENCE FOR THIS FINDING */}
                      {f.counter_evidence.length > 0 && (
                        <div className="p-2.5 rounded-lg bg-surface-secondary/70 border border-border text-[11px] space-y-1">
                          <span className="text-[10px] font-bold text-foreground uppercase tracking-wider block">
                            Specific Counter-Evidence
                          </span>
                          <ul className="list-disc list-inside text-foreground-muted space-y-0.5">
                            {f.counter_evidence.map((ce, i) => (
                              <li key={i}>{ce}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* =========================================================================
          LEVEL 2 & 3: FORENSIC COLLAPSIBLE TIERS (Indicators, Counter-Evidence, Contradictions, MITRE, Infra)
      ========================================================================= */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* LEFT COLUMN: INDICATORS & DIGITAL IMPERSONATION */}
        <div className="space-y-6">
          {/* 2.1 INDICATORS SUMMARY */}
          <Card className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Target className="w-4 h-4 text-primary" />
                <h4 className="text-xs font-bold font-mono text-foreground">
                  Extracted Indicators ({data.indicators_summary.total_count})
                </h4>
              </div>

              <button
                type="button"
                onClick={() => toggleSection('indicators')}
                className="text-foreground-muted hover:text-foreground text-xs font-mono cursor-pointer"
                aria-expanded={expandedSections.indicators}
              >
                {expandedSections.indicators ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
              </button>
            </div>

            {expandedSections.indicators && (
              <div className="space-y-3 text-xs font-mono pt-1">
                {/* INDICATOR TYPE COUNTS PILLS */}
                <div className="flex flex-wrap gap-2 text-[11px]">
                  <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                    {data.indicators_summary.domains.length} Domains
                  </span>
                  <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                    {data.indicators_summary.urls.length} URLs
                  </span>
                  <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                    {data.indicators_summary.ips.length} IPs
                  </span>
                  <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                    {data.indicators_summary.emails.length} Emails
                  </span>
                  <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                    {data.indicators_summary.hashes.length} Hashes
                  </span>
                  <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                    {data.indicators_summary.attachments.length} Files
                  </span>
                </div>

                {/* EXPANDED SAMPLES */}
                <div className="space-y-2 pt-2 border-t border-border">
                  {/* Domains */}
                  {data.indicators_summary.domains.map((d: DomainIndicator, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-surface-secondary/40 border border-border flex items-center justify-between text-[11px]"
                    >
                      <div className="flex items-center space-x-2 truncate pr-2">
                        <Globe className="w-3.5 h-3.5 text-primary shrink-0" />
                        <span className="text-foreground truncate select-all">{d.value}</span>
                        {d.is_lookalike && (
                          <Badge variant="danger" size="sm" className="text-[9px]">
                            Lookalike
                          </Badge>
                        )}
                      </div>
                      <SeverityIndicator severity={d.severity} size="sm" />
                    </div>
                  ))}

                  {/* URLs */}
                  {data.indicators_summary.urls.map((u: URLIndicator, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-surface-secondary/40 border border-border flex items-center justify-between text-[11px]"
                    >
                      <div className="flex items-center space-x-2 truncate pr-2">
                        <Link2 className="w-3.5 h-3.5 text-primary shrink-0" />
                        <span className="text-foreground truncate select-all">{u.value}</span>
                        {u.credential_harvesting && (
                          <Badge variant="danger" size="sm" className="text-[9px]">
                            Harvester
                          </Badge>
                        )}
                      </div>
                      <span className="text-[10px] text-foreground-muted shrink-0">
                        {u.redirect_hops == null ? 'Redirects not inspected' : `${u.redirect_hops} hops`}
                      </span>
                    </div>
                  ))}

                  {/* Attachments */}
                  {data.indicators_summary.attachments.map((a: AttachmentResultItem, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-surface-secondary/40 border border-border flex items-center justify-between text-[11px]"
                    >
                      <div className="flex items-center space-x-2 truncate pr-2">
                        <Paperclip className="w-3.5 h-3.5 text-primary shrink-0" />
                        <span className="text-foreground truncate">{a.filename}</span>
                        <span className="text-[10px] text-foreground-muted">({a.mime_type})</span>
                      </div>
                      <SeverityIndicator severity={a.severity} size="sm" />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>

          {/* 2.2 DIGITAL IMPERSONATION ASSESSMENT */}
          {data.digital_impersonation && (
            <Card className="p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-foreground flex items-center gap-1.5">
                  <UserCheck className="w-4 h-4 text-primary" />
                  Digital Impersonation Assessment
                </span>
                <Badge
                  variant={
                    data.digital_impersonation.status === 'LOOKALIKE' ||
                    data.digital_impersonation.status === 'MISMATCH'
                      ? 'danger'
                      : 'outline'
                  }
                  size="sm"
                  className="text-[10px]"
                >
                  {data.digital_impersonation.status}
                </Badge>
              </div>

              <div className="grid grid-cols-2 gap-2 p-2.5 rounded-lg bg-surface-secondary/50 border border-border text-[11px]">
                <div>
                  <span className="text-[10px] text-foreground-subtle block">Claimed Identity</span>
                  <span className="font-semibold text-foreground">
                    {data.digital_impersonation.claimed_identity}
                  </span>
                </div>
                <div>
                  <span className="text-[10px] text-foreground-subtle block">Observed Identity</span>
                  <span className="font-semibold text-foreground">
                    {data.digital_impersonation.observed_identity}
                  </span>
                </div>
              </div>

              {data.digital_impersonation.details && (
                <p className="text-[11px] text-foreground-muted font-sans leading-tight">
                  {data.digital_impersonation.details}
                </p>
              )}
            </Card>
          )}

          {/* 2.3 BEHAVIORAL & THREAT MEMORY CONTEXT */}
          {(data.behavioral_deviations || data.threat_memory) && (
            <Card className="p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-foreground flex items-center gap-1.5">
                  <Activity className="w-4 h-4 text-primary" />
                  Threat Memory & Behavioral Context
                </span>
              </div>

              {data.threat_memory && (
                <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border text-[11px] space-y-1">
                  <span className="text-[10px] text-foreground-subtle uppercase block font-semibold">
                    Historical Threat Memory
                  </span>
                  <div className="flex items-center space-x-3 text-foreground">
                    <span>Observed: {data.threat_memory.total_observations}x</span>
                    <span>•</span>
                    <span className="text-danger">Verified: {data.threat_memory.verified_malicious}</span>
                    <span>•</span>
                    <span>Dismissed: {data.threat_memory.dismissed_count}</span>
                  </div>
                </div>
              )}

              {data.behavioral_deviations && (
                <div className="space-y-1.5 pt-1">
                  <span className="text-[10px] text-foreground-subtle uppercase block font-semibold">
                    Behavioral Baselines (Quality: {data.behavioral_deviations.baseline_quality})
                  </span>
                  {data.behavioral_deviations.anomalies.map((anom, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between text-[11px] p-1.5 rounded bg-surface border border-border"
                    >
                      <span className="text-foreground">{anom.metric}</span>
                      <span className="text-warning font-semibold">{anom.status}</span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}
        </div>

        {/* RIGHT COLUMN: COUNTER-EVIDENCE, CONTRADICTIONS, MITRE, INFRASTRUCTURE */}
        <div className="space-y-6">
          {/* 2.4 COUNTER-EVIDENCE (PREVENTING CONFIRMATION BIAS) */}
          <Card className="p-4 space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Scale className="w-4 h-4 text-success" />
                <h4 className="text-xs font-bold font-mono text-foreground">
                  Counter-Evidence ({data.counter_evidence.length})
                </h4>
              </div>
              <span className="text-[10px] font-mono text-foreground-subtle">
                Prevents Confirmation Bias
              </span>
            </div>

            <div className="space-y-2 text-xs font-mono">
              {data.counter_evidence.length === 0 ? (
                <div className="text-[11px] text-foreground-muted italic py-1">
                  No benign counter-indicators identified.
                </div>
              ) : (
                data.counter_evidence.map((ce) => (
                  <div
                    key={ce.id}
                    className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-bold text-foreground">{ce.title}</span>
                      <span className="text-[10px] text-success font-semibold">{ce.strength}</span>
                    </div>
                    <p className="text-[11px] text-foreground-muted font-sans leading-tight">
                      {ce.description}
                    </p>
                  </div>
                ))
              )}
            </div>
          </Card>

          {/* 2.5 CONTRADICTIONS & UNCERTAINTY */}
          {(data.contradictions.length > 0 || data.uncertainty_and_gaps.length > 0) && (
            <Card className="p-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 text-warning">
                  <AlertCircle className="w-4 h-4" />
                  <h4 className="text-xs font-bold font-mono text-foreground">
                    Contradictions & Information Gaps
                  </h4>
                </div>
              </div>

              {data.contradictions.length > 0 && (
                <div className="space-y-2 text-xs font-mono">
                  <span className="text-[10px] uppercase text-foreground-subtle font-semibold block">
                    Conflicting Claims
                  </span>
                  {data.contradictions.map((c) => (
                    <div
                      key={c.id}
                      className="p-2.5 rounded-lg bg-warning-surface/50 border border-warning-border space-y-1 text-[11px]"
                    >
                      <span className="font-bold text-foreground block">{c.topic}</span>
                      <div className="text-foreground-muted space-y-0.5">
                        <p>✓ Supporting: {c.supporting_claim}</p>
                        <p className="text-warning">✗ Contradicting: {c.contradicting_claim}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {data.uncertainty_and_gaps.length > 0 && (
                <div className="space-y-1.5 text-xs font-mono pt-2 border-t border-border">
                  <span className="text-[10px] uppercase text-foreground-subtle font-semibold block">
                    Unavailable Information
                  </span>
                  {data.uncertainty_and_gaps.map((ug, idx) => (
                    <div key={idx} className="text-[11px] text-foreground-muted flex items-start gap-1.5">
                      <span className="text-foreground-subtle">•</span>
                      <span>
                        <strong className="text-foreground">{ug.topic}:</strong> {ug.description}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {data.what_would_change_assessment.length > 0 && (
                <div className="space-y-1 text-xs font-mono pt-2 border-t border-border">
                  <span className="text-[10px] uppercase text-foreground-subtle font-semibold block">
                    What could change this assessment?
                  </span>
                  {data.what_would_change_assessment.map((w, idx) => (
                    <div key={idx} className="text-[11px] text-foreground-muted flex items-start gap-1.5">
                      <span className="text-primary">•</span>
                      <span>{w}</span>
                    </div>
                  ))}
                </div>
              )}
            </Card>
          )}

          {/* 3.1 LEVEL 3: MITRE ATT&CK PREVIEW */}
          {data.mitre_preview.length > 0 && (
            <Card className="p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Flame className="w-4 h-4 text-primary" />
                  <h4 className="text-xs font-bold text-foreground">
                    MITRE ATT&CK Mapping ({data.mitre_preview.length})
                  </h4>
                </div>
                <span className="text-[10px] text-foreground-subtle">Sec 19 Preview</span>
              </div>

              <div className="space-y-1.5">
                {data.mitre_preview.map((m, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded-lg bg-surface-secondary/40 border border-border flex items-center justify-between text-[11px]"
                  >
                    <div className="space-y-0.5 truncate pr-2">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-primary">{m.technique_id}</span>
                        <span className="text-foreground truncate">{m.technique_name}</span>
                      </div>
                      <span className="text-[10px] text-foreground-muted block">{m.tactic}</span>
                    </div>

                    <Badge
                      variant={
                        m.status === 'SUPPORTED'
                          ? 'danger'
                          : m.status === 'PLAUSIBLE'
                          ? 'warning'
                          : 'outline'
                      }
                      size="sm"
                      className="text-[9px]"
                    >
                      {m.status}
                    </Badge>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* 3.2 LEVEL 3: INFRASTRUCTURE ATTRIBUTION */}
          {data.infrastructure_preview && (
            <Card className="p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Compass className="w-4 h-4 text-primary" />
                  <h4 className="text-xs font-bold text-foreground">Infrastructure Attribution</h4>
                </div>
                <Badge variant="outline" size="sm" className="text-[9px]">
                  Conf: {data.infrastructure_preview.confidence}
                </Badge>
              </div>

              <div className="space-y-2 text-[11px]">
                {data.infrastructure_preview.probable_origin_infrastructure && (
                  <div className="flex justify-between p-1.5 rounded bg-surface border border-border">
                    <span className="text-foreground-muted">Probable Origin:</span>
                    <span className="text-foreground font-semibold select-all">
                      {data.infrastructure_preview.probable_origin_infrastructure}
                    </span>
                  </div>
                )}

                {data.infrastructure_preview.infrastructure_location && (
                  <div className="flex justify-between p-1.5 rounded bg-surface border border-border">
                    <span className="text-foreground-muted">Infrastructure location:</span>
                    <span className="text-foreground flex items-center gap-1">
                      <MapPin className="w-3 h-3 text-primary" />
                      {data.infrastructure_preview.infrastructure_location}
                    </span>
                  </div>
                )}
              </div>
            </Card>
          )}

          {/* 3.3 LEVEL 3: ATTACK PATH PREVIEW */}
          {data.attack_path_preview && (
            <Card className="p-4 space-y-3 font-mono text-xs">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <GitBranch className="w-4 h-4 text-primary" />
                  <h4 className="text-xs font-bold text-foreground">
                    Attack Progression ({data.attack_path_preview.stage_count} stages)
                  </h4>
                </div>
                <Badge variant="outline" size="sm" className="text-[9px]">
                  Path Conf: {data.attack_path_preview.confidence}
                </Badge>
              </div>

              <div className="space-y-1.5">
                {data.attack_path_preview.stages.map((stg) => (
                  <div
                    key={stg.stage_number}
                    className="p-2 rounded bg-surface-secondary/40 border border-border flex items-center justify-between text-[11px]"
                  >
                    <div className="flex items-center space-x-2">
                      <span className="w-4 h-4 rounded-full bg-primary/10 text-primary flex items-center justify-center text-[9px] font-bold">
                        {stg.stage_number}
                      </span>
                      <span className="font-semibold text-foreground">{stg.stage_name}</span>
                    </div>
                    <span className="text-[10px] text-foreground-muted">{stg.tactic}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>
      </div>

      {/* =========================================================================
          LEVEL 4: FORENSIC PROVENANCE (DEFAULT COLLAPSED)
      ========================================================================= */}
      <Card className="p-4 space-y-3 font-mono text-xs">
        <button
          type="button"
          onClick={() => toggleSection('provenance')}
          className="w-full flex items-center justify-between text-left text-foreground-muted hover:text-foreground transition-colors cursor-pointer select-none"
          aria-expanded={expandedSections.provenance}
        >
          <div className="flex items-center space-x-2">
            <Cpu className="w-4 h-4 text-primary" />
            <span className="font-bold text-foreground">
              Level 4 — Forensic Provenance & Engine Audit
            </span>
          </div>
          <span>{expandedSections.provenance ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}</span>
        </button>

        {expandedSections.provenance && (
          <div className="pt-3 border-t border-border grid grid-cols-2 sm:grid-cols-4 gap-3 text-[11px] animate-fadeIn">
            <div className="p-2.5 rounded bg-surface-secondary/50 border border-border space-y-0.5">
              <span className="text-[10px] text-foreground-subtle block">Detection Engine</span>
              <span className="font-semibold text-foreground">{data.provenance.engine_version}</span>
            </div>

            <div className="p-2.5 rounded bg-surface-secondary/50 border border-border space-y-0.5">
              <span className="text-[10px] text-foreground-subtle block">Risk Config</span>
              <span className="font-semibold text-foreground">{data.provenance.risk_configuration_version}</span>
            </div>

            <div className="p-2.5 rounded bg-surface-secondary/50 border border-border space-y-0.5">
              <span className="text-[10px] text-foreground-subtle block">Rule Base</span>
              <span className="font-semibold text-foreground">{data.provenance.rules_version}</span>
            </div>

            <div className="p-2.5 rounded bg-surface-secondary/50 border border-border space-y-0.5">
              <span className="text-[10px] text-foreground-subtle block">Model Weights</span>
              <span className="font-semibold text-foreground">{data.provenance.models_version}</span>
            </div>

            {data.provenance.audit_reference && (
              <div className="col-span-full p-2.5 rounded bg-surface-secondary/50 border border-border text-[10px] text-foreground-muted flex justify-between select-all">
                <span>Audit Reference:</span>
                <span className="text-foreground">{data.provenance.audit_reference}</span>
              </div>
            )}
          </div>
        )}
      </Card>

      {/* =========================================================================
          REUSABLE EVIDENCE INSPECTION DRAWER (LEVEL 4 FORENSIC SURFACE)
      ========================================================================= */}
      <EvidenceDetailDrawer
        isOpen={drawerOpen}
        onClose={() => {
          setDrawerOpen(false);
          setSelectedEvidenceId(null);
          setEvidencePreview(null);
        }}
        runId={data.run_id}
        evidenceId={selectedEvidenceId}
        initialPreview={evidencePreview}
      />
    </div>
  );
};
