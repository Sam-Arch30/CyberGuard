import React, { useState, useEffect, useMemo, useCallback } from 'react';
import {
  GitBranch,
  ShieldAlert,
  Clock,
  AlertTriangle,
  RotateCcw,
} from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { Button, Badge, LoadingState } from '../../../components/ui';
import { attackPathService } from '../../../services/attackPathService';
import type {
  AttackPathDetailResponse,
  AttackPathFilterState,
} from '../../../types/attackPath';
import {
  AttackPathHeader,
  AttackStageCard,
  AttackTransitionEdge,
  AttackStageInspector,
  PathGapsAndContradictions,
  AlternativeHypothesesPanel,
  AttackPathTimelineSync,
  PathContextSummary,
  AttackPathToolbar,
  ConfidenceExplainModal,
} from '../../../components/attackPath';

const INITIAL_FILTERS: AttackPathFilterState = {
  showObserved: true,
  showDerived: true,
  showInferred: true,
  minConfidence: 0.0,
  selectedTactic: 'ALL',
  selectedSource: 'ALL',
};

export const AttackPathSectionView: React.FC = () => {
  const {
    activeEmailId,
    workspaceSummary,
    setSection,
    focusGraphNode,
    openCopilotDrawer,
  } = useInvestigation();

  const [pathData, setPathData] = useState<AttackPathDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [selectedRunId, setSelectedRunId] = useState<string | undefined>(undefined);
  const [selectedStageId, setSelectedStageId] = useState<string | null>(null);
  const [isConfidenceModalOpen, setIsConfidenceModalOpen] = useState<boolean>(false);

  // Filters state
  const [showFilters, setShowFilters] = useState<boolean>(false);
  const [filters, setFilters] = useState<AttackPathFilterState>(INITIAL_FILTERS);
  const [layoutMode, setLayoutMode] = useState<'vertical' | 'grid'>('vertical');

  // Load Attack Path Data from backend
  const fetchAttackPath = useCallback(
    async (forceReconstruct: boolean = false, runId?: string) => {
      const identifier = activeEmailId || workspaceSummary?.investigation?.investigation_id;
      if (!identifier) {
        setLoading(false);
        return;
      }

      try {
        if (forceReconstruct) {
          setIsRefreshing(true);
        } else {
          setLoading(true);
        }
        setError(null);

        const data = await attackPathService.getAttackPath(identifier, runId, forceReconstruct);
        setPathData(data);

        // Auto-select first stage if none selected or if previously selected is gone
        if (data.stages.length > 0) {
          setSelectedStageId((prev) => {
            const exists = data.stages.some((s) => s.id === prev);
            return exists ? prev : data.stages[0].id;
          });
        } else {
          setSelectedStageId(null);
        }
      } catch (err: any) {
        setError(err.message || 'Failed to load attack path reconstruction.');
      } finally {
        setLoading(false);
        setIsRefreshing(false);
      }
    },
    [activeEmailId, workspaceSummary?.investigation?.investigation_id]
  );

  useEffect(() => {
    fetchAttackPath(false, selectedRunId);
  }, [fetchAttackPath, selectedRunId]);

  // Derived filter calculations
  const tacticsList = useMemo(() => {
    if (!pathData?.stages) return [];
    const set = new Set<string>();
    pathData.stages.forEach((s) => {
      if (s.tactic) set.add(s.tactic);
    });
    return Array.from(set);
  }, [pathData?.stages]);

  const activeFilterCount = useMemo(() => {
    let count = 0;
    if (!filters.showObserved) count++;
    if (!filters.showDerived) count++;
    if (!filters.showInferred) count++;
    if (filters.minConfidence > 0) count++;
    if (filters.selectedTactic !== 'ALL') count++;
    return count;
  }, [filters]);

  const filteredStages = useMemo(() => {
    if (!pathData?.stages) return [];
    return pathData.stages.filter((s) => {
      if (!filters.showObserved && s.stage_status === 'OBSERVED') return false;
      if (!filters.showDerived && s.stage_status === 'DERIVED') return false;
      if (!filters.showInferred && s.stage_status === 'INFERRED') return false;
      if (s.confidence < filters.minConfidence) return false;
      if (filters.selectedTactic !== 'ALL' && s.tactic !== filters.selectedTactic) return false;
      return true;
    });
  }, [pathData?.stages, filters]);

  // Transitions corresponding to filtered stages
  const filteredTransitions = useMemo(() => {
    if (!pathData?.transitions) return [];
    const visibleStageIds = new Set(filteredStages.map((s) => s.id));
    return pathData.transitions.filter(
      (t) => visibleStageIds.has(t.from_stage_id) && visibleStageIds.has(t.to_stage_id)
    );
  }, [pathData?.transitions, filteredStages]);

  const selectedStage = useMemo(() => {
    if (!pathData?.stages || !selectedStageId) return null;
    return pathData.stages.find((s) => s.id === selectedStageId) || pathData.stages[0] || null;
  }, [pathData?.stages, selectedStageId]);

  // Navigation callbacks
  const handleViewInGraph = (nodeId?: string) => {
    if (nodeId) {
      focusGraphNode(nodeId);
    }
    setSection('graph');
  };

  const handleViewEvidence = () => {
    setSection('evidence');
  };

  const handleConsultCopilot = (prompt: string) => {
    openCopilotDrawer(prompt, selectedStage ? {
      type: 'ATTACK_STAGE',
      identifier: selectedStage.title,
      details: selectedStage.description || undefined,
    } : undefined);
  };

  // 1. Loading State
  if (loading && !pathData) {
    return (
      <div className="py-20 flex flex-col items-center justify-center space-y-4">
        <LoadingState
          title="Reconstructing Attack Path…"
          message="Analyzing temporal correlation, evaluating graph connectivity, and calculating evidence confidence bounds."
        />
      </div>
    );
  }

  // 2. Error State
  if (error && !pathData) {
    return (
      <div className="bg-surface border border-danger/30 rounded-xl p-8 max-w-lg mx-auto my-12 text-center space-y-4 shadow-xs">
        <div className="w-12 h-12 rounded-xl bg-danger/10 border border-danger/20 flex items-center justify-center mx-auto text-danger">
          <AlertTriangle className="w-6 h-6" />
        </div>
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-foreground font-sans">
            Failed to Load Attack Path
          </h3>
          <p className="text-xs text-foreground-muted font-mono leading-relaxed">
            {error}
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => fetchAttackPath(false, selectedRunId)}
          className="font-mono text-xs"
        >
          Retry Loading
        </Button>
      </div>
    );
  }

  // 3. Truthful No Data / Inconclusive State
  if (!pathData || !pathData.has_path || pathData.stages.length === 0) {
    return (
      <div className="bg-surface border border-border rounded-xl p-10 max-w-xl mx-auto my-8 text-center space-y-5 shadow-xs">
        <div className="w-12 h-12 rounded-xl bg-surface-secondary border border-border flex items-center justify-center mx-auto text-foreground-muted">
          <GitBranch className="w-6 h-6" />
        </div>
        <div className="space-y-1.5">
          <h2 className="text-base font-semibold text-foreground font-sans">
            No Reconstructable Attack Path
          </h2>
          <p className="text-xs text-foreground-muted font-mono leading-relaxed">
            {pathData?.status_rationale ||
              'CyberGuard does not currently have enough correlated telemetry to reconstruct a continuous multi-stage progression for this investigation.'}
          </p>
        </div>

        {/* Available Evidence Summary Callout */}
        <div className="p-3.5 rounded-lg bg-surface-secondary/60 border border-border text-xs font-mono text-foreground-muted text-left space-y-2">
          <div className="font-semibold text-foreground uppercase tracking-wider text-[10px]">
            Available Forensic Data:
          </div>
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="p-2 rounded bg-surface border border-border">
              <div className="text-sm font-bold text-foreground font-mono">
                {workspaceSummary?.counts?.findings_count || 0}
              </div>
              <div className="text-[10px] text-foreground-muted">Findings</div>
            </div>
            <div className="p-2 rounded bg-surface border border-border">
              <div className="text-sm font-bold text-foreground font-mono">
                {workspaceSummary?.counts?.evidence_count || 0}
              </div>
              <div className="text-[10px] text-foreground-muted">Evidence Items</div>
            </div>
            <div className="p-2 rounded bg-surface border border-border">
              <div className="text-sm font-bold text-foreground font-mono">
                {workspaceSummary?.counts?.timeline_events_count || 0}
              </div>
              <div className="text-[10px] text-foreground-muted">Timeline Events</div>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => setSection('analysis')}
            leftIcon={<ShieldAlert className="w-3.5 h-3.5" />}
            className="text-xs font-mono"
          >
            Review Findings
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => setSection('timeline')}
            leftIcon={<Clock className="w-3.5 h-3.5" />}
            className="text-xs font-mono"
          >
            Inspect Timeline
          </Button>
          <Button
            size="sm"
            variant="primary"
            disabled={isRefreshing}
            onClick={() => fetchAttackPath(true)}
            leftIcon={<RotateCcw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />}
            className="text-xs font-mono"
          >
            Force Reconstruct
          </Button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 1. Header Overview Banner */}
      <AttackPathHeader
        pathData={pathData}
        onRefresh={() => fetchAttackPath(true, selectedRunId)}
        isRefreshing={isRefreshing}
        onSelectRun={(runId) => setSelectedRunId(runId)}
        onOpenConfidenceModal={() => setIsConfidenceModalOpen(true)}
        showFilters={showFilters}
        onToggleFilters={() => setShowFilters(!showFilters)}
        activeFilterCount={activeFilterCount}
      />

      {/* 2. Optional Filter Toolbar */}
      {showFilters && (
        <AttackPathToolbar
          filters={filters}
          onFilterChange={(newF) => setFilters(newF)}
          onResetFilters={() => setFilters(INITIAL_FILTERS)}
          activeFilterCount={activeFilterCount}
          tacticsList={tacticsList}
          layoutMode={layoutMode}
          onLayoutModeChange={(m) => setLayoutMode(m)}
        />
      )}

      {/* 3. Primary Progression Canvas / Stage Sequence */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono uppercase font-bold text-foreground-muted tracking-wider">
              Reconstructed Sequence ({filteredStages.length} of {pathData.stages.length} Stages Visible)
            </span>
            {activeFilterCount > 0 && (
              <Badge variant="warning" size="xs" className="font-mono text-[9px]">
                Filtered
              </Badge>
            )}
          </div>
          <span className="text-[10px] font-mono text-foreground-muted hidden sm:inline">
            Click any stage to inspect evidence, provenance, and MITRE mapping
          </span>
        </div>

        {/* Layout Modes: Grid vs Vertical Sequence */}
        {layoutMode === 'grid' ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-3">
            {filteredStages.map((stage, idx) => (
              <AttackStageCard
                key={stage.id}
                stage={stage}
                index={idx}
                isSelected={selectedStageId === stage.id}
                onSelect={() => setSelectedStageId(stage.id)}
              />
            ))}
          </div>
        ) : (
          <div className="space-y-1 bg-surface-secondary/20 p-4 rounded-xl border border-border">
            {filteredStages.map((stage, idx) => {
              const transition = filteredTransitions.find((t) => t.from_stage_id === stage.id);
              return (
                <React.Fragment key={stage.id}>
                  <AttackStageCard
                    stage={stage}
                    index={idx}
                    isSelected={selectedStageId === stage.id}
                    onSelect={() => setSelectedStageId(stage.id)}
                  />
                  {transition && (
                    <AttackTransitionEdge
                      transition={transition}
                      sourceTitle={stage.title}
                      targetTitle={
                        filteredStages.find((s) => s.id === transition.to_stage_id)?.title || 'Next'
                      }
                    />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. Selected Stage Inspector Panel */}
      {selectedStage && (
        <AttackStageInspector
          stage={selectedStage}
          onViewInGraph={handleViewInGraph}
          onViewEvidence={handleViewEvidence}
          onConsultCopilot={handleConsultCopilot}
        />
      )}

      {/* 5. Forensic Gaps & Contradictions Panel */}
      <PathGapsAndContradictions
        gaps={pathData.gaps}
        contradictions={pathData.contradictions}
      />

      {/* 6. Alternative Hypotheses Panel */}
      <AlternativeHypothesesPanel
        alternatives={pathData.alternatives}
      />

      {/* 7. MITRE Matrix & Technical Infrastructure Summary */}
      <PathContextSummary
        mitreTechniques={pathData.mitre_techniques}
        infrastructure={pathData.infrastructure}
      />

      {/* 8. Synchronized Event-Time Timeline */}
      <AttackPathTimelineSync
        timelineEvents={pathData.timeline_events}
        selectedStageId={selectedStageId || undefined}
        onSelectStage={(stId) => setSelectedStageId(stId)}
      />

      {/* 9. Calibrated Confidence Explainability Modal */}
      <ConfidenceExplainModal
        isOpen={isConfidenceModalOpen}
        onClose={() => setIsConfidenceModalOpen(false)}
        pathData={pathData}
      />
    </div>
  );
};
