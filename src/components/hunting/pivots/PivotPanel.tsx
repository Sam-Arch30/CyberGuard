import React, { useState, useEffect } from 'react';
import {
  X,
  Compass,
  Share2,
  FileQuestion,
  Sparkles,
  AlertTriangle,
  Eye,
  Clock,
  CheckCircle,
} from 'lucide-react';
import type {
  PivotSourceType,
  PivotType,
  PivotDefinition,
  PivotResponse,
  PivotResultItem,
  EntityFrequencyContext,
  AIPivotRecommendationItem,
  PivotGraphNode,
  PivotHistoryStep,
  EvidenceClassification,
} from '../../../types/pivots';
import { pivotService } from '../../../services/pivotService';
import { PivotBreadcrumbs } from './PivotBreadcrumbs';
import { QuickPivotsBar } from './QuickPivotsBar';
import { PivotResultsList } from './PivotResultsList';
import { PivotGraphView } from './PivotGraphView';
import { AnalystHypothesisDrawer } from './AnalystHypothesisDrawer';
import { AIPivotRecommendations } from './AIPivotRecommendations';

interface PivotPanelProps {
  isOpen: boolean;
  onClose: () => void;
  initialSourceType: string;
  initialSourceValue: string;
  investigationId?: string;
  onHandoffToHunt?: (queryDef: any) => void;
}

export const PivotPanel: React.FC<PivotPanelProps> = ({
  isOpen,
  onClose,
  initialSourceType,
  initialSourceValue,
  investigationId,
  onHandoffToHunt,
}) => {
  // Active Target Entity
  const [currentSourceType, setCurrentSourceType] = useState<PivotSourceType>(
    (initialSourceType.toUpperCase() as PivotSourceType) || 'DOMAIN'
  );
  const [currentSourceValue, setCurrentSourceValue] = useState<string>(initialSourceValue);

  // Depth & Execution Mode
  const [depth, setDepth] = useState<number>(1);
  const [viewMode, setViewMode] = useState<'results' | 'graph' | 'hypothesis' | 'recommendations'>(
    'results'
  );

  // Pivot Registry & State
  const [registry, setRegistry] = useState<PivotDefinition[]>([]);
  const [activePivotType, setActivePivotType] = useState<PivotType | undefined>();
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [pivotResponse, setPivotResponse] = useState<PivotResponse | null>(null);
  const [frequencyContext, setFrequencyContext] = useState<EntityFrequencyContext | null>(null);
  const [recommendations, setRecommendations] = useState<AIPivotRecommendationItem[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Breadcrumbs Navigation Trail
  const [history, setHistory] = useState<PivotHistoryStep[]>([
    {
      source_type: (initialSourceType.toUpperCase() as PivotSourceType) || 'DOMAIN',
      source_value: initialSourceValue,
      timestamp: new Date().toISOString(),
    },
  ]);
  const [currentIndex, setCurrentIndex] = useState<number>(0);

  // Selections
  const [selectedItemIds, setSelectedItemIds] = useState<string[]>([]);

  // Hypothesis Evidence Buckets
  const [supportingItems, setSupportingItems] = useState<string[]>([]);
  const [contradictingItems, setContradictingItems] = useState<string[]>([]);
  const [neutralItems, setNeutralItems] = useState<string[]>([]);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  const loadRegistry = async () => {
    try {
      const reg = await pivotService.getRegistry();
      setRegistry(reg.pivots);
    } catch (err: any) {
      console.error('Failed to load pivot registry', err);
    }
  };

  const loadEntityContext = async (st: PivotSourceType, sv: string) => {
    try {
      const [freq, recs] = await Promise.all([
        pivotService.getFrequencyContext(st, sv).catch(() => null),
        pivotService.getRecommendations(st, sv).catch(() => null),
      ]);
      if (freq) setFrequencyContext(freq);
      if (recs) setRecommendations(recs.recommendations);
    } catch (err: any) {
      console.error('Failed to load entity context', err);
    }
  };

  // Initial registry & entity load
  useEffect(() => {
    loadRegistry();
  }, []);

  useEffect(() => {
    if (currentSourceValue) {
      loadEntityContext(currentSourceType, currentSourceValue);
    }
  }, [currentSourceType, currentSourceValue]);

  // Filter available pivots for active entity
  const availablePivots = registry.filter(
    (p) => p.source_type.toUpperCase() === currentSourceType.toUpperCase()
  );

  // Trigger pivot execution
  const executePivot = async (pType: PivotType, targetDepth: number = depth) => {
    setIsLoading(true);
    setErrorMessage(null);
    setActivePivotType(pType);
    setSelectedItemIds([]);

    try {
      const res = await pivotService.executePivot({
        source_type: currentSourceType,
        source_value: currentSourceValue,
        pivot_type: pType,
        depth: targetDepth,
        limit: 100,
        investigation_id: investigationId,
        execution_mode: 'FAST',
      });
      setPivotResponse(res);
      if (res.frequency_context) {
        setFrequencyContext(res.frequency_context);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Pivot execution failed');
    } finally {
      setIsLoading(false);
    }
  };

  // Hop to next entity in chain
  const handleHop = (targetType: string, targetValue: string, pType?: PivotType) => {
    const nextType = (targetType.toUpperCase() as PivotSourceType) || 'DOMAIN';
    const nextStep: PivotHistoryStep = {
      source_type: nextType,
      source_value: targetValue,
      pivot_type: pType,
      timestamp: new Date().toISOString(),
    };

    const newHistory = [...history.slice(0, currentIndex + 1), nextStep];
    setHistory(newHistory);
    setCurrentIndex(newHistory.length - 1);

    setCurrentSourceType(nextType);
    setCurrentSourceValue(targetValue);
    setPivotResponse(null);
    setActivePivotType(undefined);
    setSelectedItemIds([]);
    showToast(`Pivoted hop to ${nextType}: ${targetValue}`);
  };

  const handleHopResultItem = (item: PivotResultItem) => {
    handleHop(item.target_type, item.target_value, activePivotType);
  };

  const handleHopGraphNode = (node: PivotGraphNode) => {
    handleHop(node.entity_type, node.value, activePivotType);
  };

  // Breadcrumbs navigation
  const handleNavigateBreadcrumb = (index: number) => {
    const step = history[index];
    if (!step) return;
    setCurrentIndex(index);
    setCurrentSourceType(step.source_type);
    setCurrentSourceValue(step.source_value);
    setPivotResponse(null);
    setActivePivotType(step.pivot_type);
    setSelectedItemIds([]);
  };

  const handleResetBreadcrumbs = () => {
    const root = history[0];
    if (!root) return;
    setHistory([root]);
    setCurrentIndex(0);
    setCurrentSourceType(root.source_type);
    setCurrentSourceValue(root.source_value);
    setPivotResponse(null);
    setActivePivotType(undefined);
    setSelectedItemIds([]);
  };

  // Evidence Classification
  const handleClassifyEvidence = (item: PivotResultItem, classification: EvidenceClassification) => {
    const val = `${item.target_type}:${item.target_value} (${item.relationship_type})`;
    if (classification === 'SUPPORTING') {
      if (!supportingItems.includes(val)) setSupportingItems((prev) => [...prev, val]);
      setContradictingItems((prev) => prev.filter((i) => i !== val));
      setNeutralItems((prev) => prev.filter((i) => i !== val));
      showToast(`Classified as Supporting Evidence`);
    } else if (classification === 'CONTRADICTING') {
      if (!contradictingItems.includes(val)) setContradictingItems((prev) => [...prev, val]);
      setSupportingItems((prev) => prev.filter((i) => i !== val));
      setNeutralItems((prev) => prev.filter((i) => i !== val));
      showToast(`Classified as Contradicting Evidence`);
    } else {
      if (!neutralItems.includes(val)) setNeutralItems((prev) => [...prev, val]);
      setSupportingItems((prev) => prev.filter((i) => i !== val));
      setContradictingItems((prev) => prev.filter((i) => i !== val));
      showToast(`Classified as Neutral Context`);
    }
  };

  const handleRemoveEvidenceItem = (
    item: string,
    classification: 'SUPPORTING' | 'CONTRADICTING' | 'NEUTRAL'
  ) => {
    if (classification === 'SUPPORTING') setSupportingItems((p) => p.filter((x) => x !== item));
    if (classification === 'CONTRADICTING') setContradictingItems((p) => p.filter((x) => x !== item));
    if (classification === 'NEUTRAL') setNeutralItems((p) => p.filter((x) => x !== item));
  };

  // Promotion Workflows
  const handlePromoteInvestigation = async (items: PivotResultItem[]) => {
    try {
      const res = await pivotService.promoteToInvestigation({
        investigation_id: investigationId,
        selected_target_values: items.map((it) => it.target_value),
        source_value: currentSourceValue,
        source_type: currentSourceType,
        pivot_type: activePivotType || 'KNOWLEDGE_GRAPH_NEIGHBORS',
      });
      showToast(res.message);
    } catch (err: any) {
      setErrorMessage(err.message || 'Promotion to investigation failed');
    }
  };

  const handlePromoteWatchlist = async (items: PivotResultItem[]) => {
    try {
      const res = await pivotService.promoteToWatchlist({
        selected_target_values: items.map((it) => it.target_value),
        target_type: items[0]?.target_type || currentSourceType,
        reason: `Discovered during pivot analysis from ${currentSourceValue}`,
      });
      showToast(res.message);
    } catch (err: any) {
      setErrorMessage(err.message || 'Promotion to watchlist failed');
    }
  };

  const handlePivotToHunt = async (items: PivotResultItem[]) => {
    try {
      const res = await pivotService.pivotToHuntQuery({
        selected_target_values: items.map((it) => it.target_value),
        target_type: items[0]?.target_type || currentSourceType,
      });
      showToast(`Generated iterative hunt query`);
      if (onHandoffToHunt) {
        onHandoffToHunt(res.query_definition);
        onClose();
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to formulate hunt query');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in duration-150">
      <div className="bg-surface border border-border rounded-panel w-full max-w-6xl max-h-[92vh] flex flex-col shadow-2xl overflow-hidden">
        {/* 1. Header with Observable Identification & Controls */}
        <div className="px-5 py-3.5 bg-surface-secondary border-b border-border flex items-center justify-between">
          <div className="flex items-center space-x-3 min-w-0">
            <div className="p-2 rounded-control bg-primary/10 border border-primary/20 text-primary shrink-0">
              <Compass className="w-5 h-5" />
            </div>

            <div className="min-w-0">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 rounded-control bg-surface border border-border text-foreground-muted">
                  {currentSourceType}
                </span>
                <h3 className="text-sm font-mono font-bold text-foreground truncate select-all">
                  {currentSourceValue}
                </h3>
              </div>
              <div className="text-[11px] font-mono text-foreground-muted mt-0.5">
                Section 55 Advanced Threat Hunting & Investigation Pivots Workspace
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-3 shrink-0">
            {/* Depth Selector */}
            <div className="flex items-center space-x-1.5 text-xs font-mono bg-surface px-2.5 py-1 rounded-control border border-border">
              <span className="text-foreground-muted">Depth:</span>
              {[1, 2, 3].map((d) => (
                <button
                  key={d}
                  onClick={() => {
                    setDepth(d);
                    if (activePivotType) executePivot(activePivotType, d);
                  }}
                  className={`px-1.5 py-0.5 rounded-xs font-semibold cursor-pointer ${
                    depth === d
                      ? 'bg-primary text-white'
                      : 'text-foreground-muted hover:text-foreground'
                  }`}
                  title={`${d}-hop expansion`}
                >
                  {d}
                </button>
              ))}
            </div>

            <button
              onClick={onClose}
              className="p-1.5 text-foreground-muted hover:text-foreground rounded-control hover:bg-surface border border-transparent hover:border-border transition-colors cursor-pointer"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* 2. Breadcrumbs Navigation Trail */}
        <PivotBreadcrumbs
          history={history}
          currentIndex={currentIndex}
          onNavigate={handleNavigateBreadcrumb}
          onReset={handleResetBreadcrumbs}
        />

        {/* 3. Entity Frequency & Historical Metrics Banner */}
        {frequencyContext && (
          <div className="px-5 py-2 bg-surface/50 border-b border-border/80 flex items-center justify-between text-xs font-mono text-foreground-muted flex-wrap gap-2">
            <div className="flex items-center space-x-4 flex-wrap gap-y-1">
              {frequencyContext.first_seen && (
                <span className="flex items-center space-x-1">
                  <Clock className="w-3 h-3 text-primary" />
                  <span>First: {new Date(frequencyContext.first_seen).toLocaleDateString()}</span>
                </span>
              )}
              {frequencyContext.last_seen && (
                <span className="flex items-center space-x-1">
                  <Clock className="w-3 h-3 text-primary" />
                  <span>Last: {new Date(frequencyContext.last_seen).toLocaleDateString()}</span>
                </span>
              )}
              <span>Span: {frequencyContext.observed_days_span}d</span>
              <span>Artifacts: {frequencyContext.artifact_count}</span>
              <span>Alerts: {frequencyContext.alert_count}</span>
              <span>Investigations: {frequencyContext.investigation_count}</span>
            </div>

            <div className="flex items-center space-x-2">
              {frequencyContext.is_watchlist_monitored && (
                <span className="px-1.5 py-0.5 rounded-control text-[10px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20 flex items-center space-x-1">
                  <Eye className="w-3 h-3" />
                  <span>Monitored in Watchlist</span>
                </span>
              )}
              {frequencyContext.reputation_verdict && (
                <span
                  className={`px-1.5 py-0.5 rounded-control text-[10px] font-mono border ${
                    frequencyContext.reputation_verdict === 'MALICIOUS'
                      ? 'bg-threat-critical/15 text-threat-critical border-threat-critical/30'
                      : 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                  }`}
                >
                  {frequencyContext.reputation_verdict}
                </span>
              )}
            </div>
          </div>
        )}

        {/* 4. Quick Pivots Selection Bar */}
        <QuickPivotsBar
          availablePivots={availablePivots}
          activePivotType={activePivotType}
          onSelectPivot={(pt) => executePivot(pt)}
          isLoading={isLoading}
        />

        {/* 5. View Switcher Tabs */}
        <div className="px-5 py-2 bg-surface-secondary/40 border-b border-border flex items-center justify-between text-xs font-mono">
          <div className="flex items-center space-x-1">
            <button
              onClick={() => setViewMode('results')}
              className={`px-3 py-1 rounded-control transition-all cursor-pointer ${
                viewMode === 'results'
                  ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Pivot Results ({pivotResponse?.items?.length || 0})
            </button>
            <button
              onClick={() => setViewMode('graph')}
              className={`px-3 py-1 rounded-control transition-all cursor-pointer flex items-center space-x-1.5 ${
                viewMode === 'graph'
                  ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              <Share2 className="w-3 h-3 text-primary" />
              <span>Mini Graph ({pivotResponse?.graph_nodes?.length || 0} nodes)</span>
            </button>
            <button
              onClick={() => setViewMode('hypothesis')}
              className={`px-3 py-1 rounded-control transition-all cursor-pointer flex items-center space-x-1.5 ${
                viewMode === 'hypothesis'
                  ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              <FileQuestion className="w-3 h-3 text-primary" />
              <span>
                Hypothesis (
                {supportingItems.length + contradictingItems.length + neutralItems.length} evidence)
              </span>
            </button>
            <button
              onClick={() => setViewMode('recommendations')}
              className={`px-3 py-1 rounded-control transition-all cursor-pointer flex items-center space-x-1.5 ${
                viewMode === 'recommendations'
                  ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              <Sparkles className="w-3 h-3 text-primary" />
              <span>AI Guidance ({recommendations.length})</span>
            </button>
          </div>

          {pivotResponse && (
            <div className="text-[11px] text-foreground-muted font-mono">
              Executed in {pivotResponse.execution_time_ms}ms · Depth {pivotResponse.depth}
            </div>
          )}
        </div>

        {/* 6. Feedback Toast / Error Banner */}
        {errorMessage && (
          <div className="mx-5 my-2 p-2.5 bg-threat-critical/10 border border-threat-critical/30 rounded-control text-xs font-mono text-threat-critical flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
            <button
              onClick={() => setErrorMessage(null)}
              className="text-foreground-muted hover:text-foreground cursor-pointer"
            >
              ✕
            </button>
          </div>
        )}

        {toastMessage && (
          <div className="mx-5 my-2 p-2 bg-primary/10 border border-primary/20 rounded-control text-xs font-mono text-primary flex items-center space-x-2 animate-in fade-in">
            <CheckCircle className="w-3.5 h-3.5 shrink-0" />
            <span>{toastMessage}</span>
          </div>
        )}

        {/* 7. Scrollable Main Content Area */}
        <div className="flex-1 overflow-y-auto p-5 scrollbar-thin">
          {viewMode === 'results' && (
            <PivotResultsList
              items={pivotResponse?.items || []}
              selectedItemIds={selectedItemIds}
              onToggleSelect={(id) =>
                setSelectedItemIds((prev) =>
                  prev.includes(id) ? prev.filter((i) => i !== id) : [...prev, id]
                )
              }
              onSelectAll={() =>
                setSelectedItemIds((pivotResponse?.items || []).map((it: PivotResultItem) => it.id))
              }
              onClearSelection={() => setSelectedItemIds([])}
              onHopPivot={handleHopResultItem}
              onClassifyEvidence={handleClassifyEvidence}
              onPromoteInvestigation={handlePromoteInvestigation}
              onPromoteWatchlist={handlePromoteWatchlist}
              onPivotToHunt={handlePivotToHunt}
              isLoading={isLoading}
            />
          )}

          {viewMode === 'graph' && (
            <PivotGraphView
              nodes={pivotResponse?.graph_nodes || []}
              edges={pivotResponse?.graph_edges || []}
              onHopNode={handleHopGraphNode}
            />
          )}

          {viewMode === 'hypothesis' && (
            <AnalystHypothesisDrawer
              currentObservable={currentSourceValue}
              investigationId={investigationId}
              supportingItems={supportingItems}
              contradictingItems={contradictingItems}
              neutralItems={neutralItems}
              onRemoveItem={handleRemoveEvidenceItem}
              onSavedHypothesis={() => showToast('Hypothesis persisted')}
            />
          )}

          {viewMode === 'recommendations' && (
            <AIPivotRecommendations
              recommendations={recommendations}
              onSelectPivot={(pt) => {
                setViewMode('results');
                executePivot(pt);
              }}
              isLoading={isLoading}
            />
          )}
        </div>
      </div>
    </div>
  );
};
