import React, { useState, useEffect, useCallback } from 'react';
import {
  GitMerge,
  Search,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  FileCheck,
  Zap,
  Info,
  Shield,
} from 'lucide-react';
import type {
  CrossSourceCorrelationItem,
  CrossSourceCorrelationDetail,
  CorrelationTimelineItem,
  WhyCorrelatedExplanation,
  CorrelationOverviewStats,
  EntityResolutionResult,
  ResolutionHistoryItem,
  CorrelationConfidence,
  CorrelationStatus,
} from '../../types/correlation';
import { CrossSourceCorrelationService } from '../../services/crossSourceCorrelationService';
import {
  Button,
  Badge,
  Card,
  Modal,
  ModalHeader,
  ModalTitle,
  ModalBody,
  ModalFooter,
} from '../ui';
import { cn } from '../../utils/cn';

interface CrossSourceCorrelationViewProps {
  initialCorrelationId?: string;
}

export const CrossSourceCorrelationView: React.FC<CrossSourceCorrelationViewProps> = ({
  initialCorrelationId,
}) => {
  // Navigation / View Tabs
  const [activeTab, setActiveTab] = useState<'feed' | 'entity_resolver'>('feed');

  // Overview Stats
  const [overview, setOverview] = useState<CorrelationOverviewStats | null>(null);
  const [loadingOverview, setLoadingOverview] = useState(false);

  // List State
  const [correlations, setCorrelations] = useState<CrossSourceCorrelationItem[]>([]);
  const [totalCorrelations, setTotalCorrelations] = useState(0);
  const [loadingList, setLoadingList] = useState(false);
  const [listError, setListError] = useState<string | null>(null);

  // Filters
  const [filterType, setFilterType] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [filterConfidence, setFilterConfidence] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  // Selected Correlation & Detail Pane
  const [selectedId, setSelectedId] = useState<string | null>(initialCorrelationId || null);
  const [selectedDetail, setSelectedDetail] = useState<CrossSourceCorrelationDetail | null>(null);
  const [timelineItems, setTimelineItems] = useState<CorrelationTimelineItem[]>([]);
  const [explanation, setExplanation] = useState<WhyCorrelatedExplanation | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [detailTab, setDetailTab] = useState<'why' | 'timeline' | 'members' | 'risk'>('why');

  // Disposition Modal
  const [isDispositionModalOpen, setIsDispositionModalOpen] = useState(false);
  const [dispositionAction, setDispositionAction] = useState<'CONFIRMED' | 'REJECTED' | 'UNCERTAIN'>('CONFIRMED');
  const [dispositionNotes, setDispositionNotes] = useState('');
  const [submittingDisposition, setSubmittingDisposition] = useState(false);

  // Evaluation Modal
  const [isEvaluateModalOpen, setIsEvaluateModalOpen] = useState(false);
  const [evalWindowMinutes, setEvalWindowMinutes] = useState(30);
  const [evalEntityId, setEvalEntityId] = useState('');
  const [evalFindingId, setEvalFindingId] = useState('');
  const [evaluating, setEvaluating] = useState(false);

  // Entity Resolver Interactive Tool
  const [entityTypeInput, setEntityTypeInput] = useState('IP');
  const [rawIdentifierInput, setRawIdentifierInput] = useState('');
  const [resolvingEntity, setResolvingEntity] = useState(false);
  const [resolvedResult, setResolvedResult] = useState<EntityResolutionResult | null>(null);
  const [resolveError, setResolveError] = useState<string | null>(null);
  const [resolutionHistory, setResolutionHistory] = useState<ResolutionHistoryItem[]>([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

  // Load Overview
  const loadOverview = useCallback(async () => {
    try {
      setLoadingOverview(true);
      const res = await CrossSourceCorrelationService.getOverview();
      setOverview(res);
    } catch (err: any) {
      console.error('Failed to load overview:', err);
    } finally {
      setLoadingOverview(false);
    }
  }, []);

  // Load Correlation List
  const loadCorrelations = useCallback(async () => {
    try {
      setLoadingList(true);
      setListError(null);
      const params: any = { limit: 50, offset: 0 };
      if (filterType !== 'ALL') params.correlation_type = filterType;
      if (filterStatus !== 'ALL') params.status = filterStatus;
      if (filterConfidence !== 'ALL') params.confidence_level = filterConfidence;
      if (searchQuery.trim()) params.q = searchQuery.trim();

      const res = await CrossSourceCorrelationService.listCorrelations(params);
      setCorrelations(res.items);
      setTotalCorrelations(res.total);

      // Auto-select first item if none selected
      if (!selectedId && res.items.length > 0) {
        setSelectedId(res.items[0].id);
      }
    } catch (err: any) {
      setListError(err.message || 'Failed to load correlations');
    } finally {
      setLoadingList(false);
    }
  }, [filterType, filterStatus, filterConfidence, searchQuery, selectedId]);

  // Load Selected Correlation Detail
  const loadDetail = useCallback(async (id: string) => {
    try {
      setLoadingDetail(true);
      const [detail, tl, exp] = await Promise.all([
        CrossSourceCorrelationService.getCorrelationDetail(id),
        CrossSourceCorrelationService.getTimeline(id),
        CrossSourceCorrelationService.getExplanation(id),
      ]);
      setSelectedDetail(detail);
      setTimelineItems(tl);
      setExplanation(exp);
    } catch (err: any) {
      console.error('Failed to load correlation details:', err);
    } finally {
      setLoadingDetail(false);
    }
  }, []);

  // Load Resolution History
  const loadResolutionHistory = useCallback(async () => {
    try {
      setLoadingHistory(true);
      const res = await CrossSourceCorrelationService.getResolutionHistory({ limit: 25 });
      setResolutionHistory(res.items);
    } catch (err: any) {
      console.error('Failed to load resolution history:', err);
    } finally {
      setLoadingHistory(false);
    }
  }, []);

  useEffect(() => {
    loadOverview();
    loadCorrelations();
  }, [loadOverview, loadCorrelations]);

  useEffect(() => {
    if (selectedId) {
      loadDetail(selectedId);
    }
  }, [selectedId, loadDetail]);

  useEffect(() => {
    if (activeTab === 'entity_resolver') {
      loadResolutionHistory();
    }
  }, [activeTab, loadResolutionHistory]);

  // Handle Disposition Submit
  const handleDispositionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedId || !dispositionNotes.trim()) return;

    try {
      setSubmittingDisposition(true);
      await CrossSourceCorrelationService.recordDisposition(selectedId, {
        disposition: dispositionAction,
        notes: dispositionNotes.trim(),
        actor: 'SOC Analyst',
      });
      setIsDispositionModalOpen(false);
      setDispositionNotes('');
      // Reload current detail and list
      loadDetail(selectedId);
      loadCorrelations();
      loadOverview();
    } catch (err: any) {
      alert(`Error recording disposition: ${err.message}`);
    } finally {
      setSubmittingDisposition(false);
    }
  };

  // Handle Evaluate Trigger
  const handleEvaluateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setEvaluating(true);
      const res = await CrossSourceCorrelationService.evaluateCorrelation({
        correlation_window_minutes: evalWindowMinutes,
        entity_id: evalEntityId.trim() || undefined,
        finding_id: evalFindingId.trim() || undefined,
      });
      setIsEvaluateModalOpen(false);
      setEvalEntityId('');
      setEvalFindingId('');
      loadCorrelations();
      loadOverview();
      if (res.length > 0) {
        setSelectedId(res[0].id);
      }
    } catch (err: any) {
      alert(`Evaluation error: ${err.message}`);
    } finally {
      setEvaluating(false);
    }
  };

  // Handle Entity Resolution Submit
  const handleResolveEntity = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rawIdentifierInput.trim()) return;

    try {
      setResolvingEntity(true);
      setResolveError(null);
      const res = await CrossSourceCorrelationService.resolveEntity({
        entity_type: entityTypeInput,
        raw_identifier: rawIdentifierInput.trim(),
      });
      setResolvedResult(res);
      loadResolutionHistory();
    } catch (err: any) {
      setResolveError(err.message || 'Entity resolution failed');
      setResolvedResult(null);
    } finally {
      setResolvingEntity(false);
    }
  };

  // Helper badge styles
  const getConfidenceBadge = (level: CorrelationConfidence) => {
    switch (level) {
      case 'CERTAIN':
        return <Badge variant="success">Certain</Badge>;
      case 'HIGH':
        return <Badge variant="success">High Confidence</Badge>;
      case 'MEDIUM':
        return <Badge variant="warning">Medium Confidence</Badge>;
      default:
        return <Badge variant="outline">Low Confidence</Badge>;
    }
  };

  const getStatusBadge = (status: CorrelationStatus) => {
    switch (status) {
      case 'CORRELATED':
        return <Badge variant="success">Correlated</Badge>;
      case 'PARTIALLY_CORRELATED':
        return <Badge variant="warning">Partially Correlated</Badge>;
      case 'CANDIDATE':
        return <Badge variant="neutral">Candidate</Badge>;
      case 'INVALIDATED':
        return <Badge variant="danger">Invalidated</Badge>;
      case 'STALE':
        return <Badge variant="neutral">Stale</Badge>;
      default:
        return <Badge variant="outline">{status}</Badge>;
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return <Badge variant="danger">Critical</Badge>;
      case 'HIGH':
        return <Badge variant="danger">High</Badge>;
      case 'MEDIUM':
        return <Badge variant="warning">Medium</Badge>;
      case 'LOW':
        return <Badge variant="neutral">Low</Badge>;
      default:
        return <Badge variant="outline">{sev}</Badge>;
    }
  };

  return (
    <div className="flex flex-col h-full bg-background text-foreground overflow-hidden">
      {/* 1. TOP HEADER & WORKSPACE BANNER */}
      <div className="px-6 py-4 border-b border-border bg-surface shrink-0 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-control bg-primary-subtle text-primary border border-primary/20">
              <GitMerge className="w-5 h-5" />
            </div>
            <h1 className="text-xl font-bold tracking-tight">Cross-Source & Unified Entity Correlation</h1>
            <Badge variant="outline" className="font-mono text-xs">Section 61</Badge>
          </div>
          <p className="text-xs text-foreground-muted mt-1">
            Explainable multi-source signal fusion, bounded temporal correlation, deterministic entity resolution, and composite threat detection.
          </p>
        </div>

        <div className="flex items-center space-x-2 shrink-0">
          <div className="inline-flex rounded-control border border-border p-1 bg-surface-secondary text-xs font-medium">
            <button
              onClick={() => setActiveTab('feed')}
              className={cn(
                'px-3 py-1 rounded-control transition-colors cursor-pointer',
                activeTab === 'feed'
                  ? 'bg-surface text-foreground shadow-xs font-semibold'
                  : 'text-foreground-muted hover:text-foreground'
              )}
            >
              Correlations Feed
            </button>
            <button
              onClick={() => setActiveTab('entity_resolver')}
              className={cn(
                'px-3 py-1 rounded-control transition-colors cursor-pointer',
                activeTab === 'entity_resolver'
                  ? 'bg-surface text-foreground shadow-xs font-semibold'
                  : 'text-foreground-muted hover:text-foreground'
              )}
            >
              Entity Resolver Tool
            </button>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              loadOverview();
              loadCorrelations();
              if (selectedId) loadDetail(selectedId);
            }}
            title="Refresh Correlations"
          >
            <RefreshCw className={cn('w-3.5 h-3.5 mr-1.5', loadingList && 'animate-spin')} />
            Refresh
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => setIsEvaluateModalOpen(true)}
          >
            <Zap className="w-3.5 h-3.5 mr-1.5" />
            Evaluate Telemetry
          </Button>
        </div>
      </div>

      {/* 2. SOC KPI OVERVIEW CARDS */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-5 gap-3 p-4 px-6 border-b border-border bg-surface-secondary/40 shrink-0">
        <div className="p-3 bg-surface rounded-control border border-border">
          <div className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider">Active Correlations</div>
          <div className="text-xl font-bold text-foreground mt-0.5">
            {loadingOverview ? '...' : overview?.active_correlations ?? 0}
          </div>
          <div className="text-[10px] text-foreground-muted mt-0.5">Across all live streams</div>
        </div>

        <div className="p-3 bg-surface rounded-control border border-border">
          <div className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider">High Confidence</div>
          <div className="text-xl font-bold text-success mt-0.5">
            {loadingOverview ? '...' : overview?.high_confidence_count ?? 0}
          </div>
          <div className="text-[10px] text-foreground-muted mt-0.5">Score ≥ 0.85</div>
        </div>

        <div className="p-3 bg-surface rounded-control border border-border">
          <div className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider">Total Evaluated</div>
          <div className="text-xl font-bold text-foreground mt-0.5">
            {loadingOverview ? '...' : overview?.total_correlations ?? 0}
          </div>
          <div className="text-[10px] text-foreground-muted mt-0.5">Persisted correlation records</div>
        </div>

        <div className="p-3 bg-surface rounded-control border border-border">
          <div className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider">Avg Window</div>
          <div className="text-xl font-bold text-foreground mt-0.5">
            {loadingOverview ? '...' : `${overview?.avg_time_window_minutes ?? 0}m`}
          </div>
          <div className="text-[10px] text-foreground-muted mt-0.5">Bounded temporal interval</div>
        </div>

        <div className="p-3 bg-surface rounded-control border border-border col-span-2 sm:col-span-1">
          <div className="text-[11px] font-medium text-foreground-muted uppercase tracking-wider">Invalidated / Stale</div>
          <div className="text-xl font-bold text-foreground-muted mt-0.5">
            {loadingOverview ? '...' : overview?.invalidated_count ?? 0}
          </div>
          <div className="text-[10px] text-foreground-muted mt-0.5">Audit-preserved retractions</div>
        </div>
      </div>

      {/* 3. MAIN WORKSPACE CONTENT */}
      {activeTab === 'feed' ? (
        <div className="flex-1 flex flex-col md:flex-row min-h-0 overflow-hidden">
          {/* LEFT COLUMN: LIST & SEARCH */}
          <div className="w-full md:w-96 lg:w-[420px] border-r border-border flex flex-col bg-surface shrink-0 h-full">
            {/* Filter toolbar */}
            <div className="p-3 border-b border-border space-y-2 bg-surface">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-2.5 text-foreground-muted" />
                <input
                  type="text"
                  placeholder="Search correlations, entities, sources..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface-secondary border border-border rounded-control focus:outline-none focus:border-primary"
                />
              </div>

              <div className="grid grid-cols-3 gap-1.5 text-xs">
                <select
                  value={filterType}
                  onChange={(e) => setFilterType(e.target.value)}
                  className="bg-surface-secondary border border-border rounded-control px-2 py-1 text-xs text-foreground"
                >
                  <option value="ALL">All Types</option>
                  <option value="SHARED_INFRASTRUCTURE">Shared Infra</option>
                  <option value="TEMPORAL_ATTACK_SEQUENCE">Attack Sequence</option>
                  <option value="AUTH_AND_ENDPOINT">Auth + Endpoint</option>
                  <option value="BEHAVIORAL_AND_RULE_DETECTION">Behavior + Rule</option>
                  <option value="WATCHLIST_AND_OBSERVATION">Watchlist + Obs</option>
                </select>

                <select
                  value={filterStatus}
                  onChange={(e) => setFilterStatus(e.target.value)}
                  className="bg-surface-secondary border border-border rounded-control px-2 py-1 text-xs text-foreground"
                >
                  <option value="ALL">All Status</option>
                  <option value="CORRELATED">Correlated</option>
                  <option value="PARTIALLY_CORRELATED">Partial</option>
                  <option value="CANDIDATE">Candidate</option>
                  <option value="INVALIDATED">Invalidated</option>
                </select>

                <select
                  value={filterConfidence}
                  onChange={(e) => setFilterConfidence(e.target.value)}
                  className="bg-surface-secondary border border-border rounded-control px-2 py-1 text-xs text-foreground"
                >
                  <option value="ALL">All Confidence</option>
                  <option value="CERTAIN">Certain</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="text-[10px] text-foreground-muted px-1">
                Showing {correlations.length} of {totalCorrelations} records
              </div>
            </div>

            {/* Correlation List Items */}
            <div className="flex-1 overflow-y-auto divide-y divide-border">
              {loadingList && correlations.length === 0 ? (
                <div className="p-8 text-center text-xs text-foreground-muted">
                  <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2 text-primary" />
                  Loading correlations...
                </div>
              ) : listError ? (
                <div className="p-6 text-center text-xs text-danger">
                  <AlertTriangle className="w-5 h-5 mx-auto mb-2" />
                  {listError}
                </div>
              ) : correlations.length === 0 ? (
                <div className="p-8 text-center text-xs text-foreground-muted">
                  <GitMerge className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  No correlations matching active criteria.
                  <div className="mt-2">
                    <Button size="sm" variant="outline" onClick={() => setIsEvaluateModalOpen(true)}>
                      Evaluate Telemetry
                    </Button>
                  </div>
                </div>
              ) : (
                correlations.map((item) => {
                  const isSelected = item.id === selectedId;
                  return (
                    <div
                      key={item.id}
                      onClick={() => setSelectedId(item.id)}
                      className={cn(
                        'p-3.5 transition-colors cursor-pointer text-left',
                        isSelected
                          ? 'bg-primary-subtle/40 border-l-3 border-primary'
                          : 'hover:bg-surface-secondary/60'
                      )}
                    >
                      <div className="flex items-start justify-between gap-2">
                        <span className="font-mono text-[10px] text-foreground-muted uppercase">
                          {item.correlation_number}
                        </span>
                        <div className="flex items-center space-x-1 shrink-0">
                          {getConfidenceBadge(item.confidence_level)}
                          {getStatusBadge(item.status)}
                        </div>
                      </div>

                      <h4 className="text-xs font-semibold text-foreground mt-1 line-clamp-1">
                        {item.title}
                      </h4>

                      <p className="text-[11px] text-foreground-muted line-clamp-2 mt-1">
                        {item.description}
                      </p>

                      <div className="flex flex-wrap items-center gap-1.5 mt-2.5">
                        {getSeverityBadge(item.severity)}
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-control bg-surface-secondary border border-border text-foreground-muted">
                          Risk: {item.risk_score}
                        </span>
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-control bg-surface-secondary border border-border text-foreground-muted">
                          {item.member_count} signals
                        </span>
                        <span className="text-[10px] text-foreground-muted ml-auto">
                          {Math.round(item.time_window_seconds / 60)}m window
                        </span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* RIGHT COLUMN: ACTIVE DETAIL & PROGRESSIVE EXPLANATION */}
          <div className="flex-1 flex flex-col bg-background overflow-y-auto">
            {loadingDetail && !selectedDetail ? (
              <div className="flex-1 flex items-center justify-center p-8 text-xs text-foreground-muted">
                <RefreshCw className="w-6 h-6 animate-spin text-primary mr-2" />
                Loading correlation details & evidence graph...
              </div>
            ) : selectedDetail ? (
              <div className="p-6 space-y-6 max-w-5xl">
                {/* Header Card */}
                <div className="p-5 rounded-control bg-surface border border-border space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-3">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs font-bold text-primary">
                          {selectedDetail.correlation_number}
                        </span>
                        <Badge variant="outline">{selectedDetail.correlation_type}</Badge>
                        {getStatusBadge(selectedDetail.status)}
                      </div>
                      <h2 className="text-base font-bold text-foreground mt-1.5">
                        {selectedDetail.title}
                      </h2>
                    </div>

                    <div className="flex items-center space-x-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setIsDispositionModalOpen(true)}
                      >
                        <FileCheck className="w-3.5 h-3.5 mr-1.5" />
                        Analyst Disposition
                      </Button>
                    </div>
                  </div>

                  <p className="text-xs text-foreground leading-relaxed">
                    {selectedDetail.description}
                  </p>

                  {/* Summary Grid: Confidence vs Risk Separation */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 bg-surface-secondary/50 rounded-control border border-border text-xs">
                    <div>
                      <div className="text-[10px] font-medium text-foreground-muted uppercase">Correlation Confidence</div>
                      <div className="font-mono font-bold text-success text-sm mt-0.5">
                        {(selectedDetail.confidence_score * 100).toFixed(0)}% ({selectedDetail.confidence_level})
                      </div>
                      <div className="text-[10px] text-foreground-muted">Evidence strength</div>
                    </div>

                    <div>
                      <div className="text-[10px] font-medium text-foreground-muted uppercase">Threat Risk Score</div>
                      <div className="font-mono font-bold text-danger text-sm mt-0.5">
                        {selectedDetail.risk_score} / 100 ({selectedDetail.risk_level})
                      </div>
                      <div className="text-[10px] text-foreground-muted">Unified Risk Engine</div>
                    </div>

                    <div>
                      <div className="text-[10px] font-medium text-foreground-muted uppercase">Temporal Window</div>
                      <div className="font-mono font-bold text-foreground text-sm mt-0.5">
                        {Math.round(selectedDetail.time_window_seconds / 60)} minutes
                      </div>
                      <div className="text-[10px] text-foreground-muted">Bounded co-occurrence</div>
                    </div>

                    <div>
                      <div className="text-[10px] font-medium text-foreground-muted uppercase">Rule Engine Version</div>
                      <div className="font-mono font-bold text-foreground text-sm mt-0.5">
                        {selectedDetail.rule_version}
                      </div>
                      <div className="text-[10px] text-foreground-muted">Deterministic hash verified</div>
                    </div>
                  </div>

                  {/* Sources Badges */}
                  <div className="flex items-center space-x-2 pt-1 text-xs">
                    <span className="text-[11px] text-foreground-muted">Contributing Sources:</span>
                    <div className="flex flex-wrap gap-1">
                      {selectedDetail.sources.map((s) => (
                        <span
                          key={s}
                          className="px-2 py-0.5 rounded-control bg-surface-secondary border border-border text-[10px] font-mono text-foreground font-semibold"
                        >
                          {s}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Sub-tabs: Why Correlated / Timeline / Members / Risk */}
                <div className="border-b border-border flex items-center space-x-4 text-xs font-medium">
                  <button
                    onClick={() => setDetailTab('why')}
                    className={cn(
                      'pb-2.5 transition-colors cursor-pointer border-b-2',
                      detailTab === 'why'
                        ? 'border-primary text-primary font-bold'
                        : 'border-transparent text-foreground-muted hover:text-foreground'
                    )}
                  >
                    Why Correlated? (Explainability)
                  </button>

                  <button
                    onClick={() => setDetailTab('timeline')}
                    className={cn(
                      'pb-2.5 transition-colors cursor-pointer border-b-2',
                      detailTab === 'timeline'
                        ? 'border-primary text-primary font-bold'
                        : 'border-transparent text-foreground-muted hover:text-foreground'
                    )}
                  >
                    Chronological Timeline ({timelineItems.length})
                  </button>

                  <button
                    onClick={() => setDetailTab('members')}
                    className={cn(
                      'pb-2.5 transition-colors cursor-pointer border-b-2',
                      detailTab === 'members'
                        ? 'border-primary text-primary font-bold'
                        : 'border-transparent text-foreground-muted hover:text-foreground'
                    )}
                  >
                    Members & Evidence ({selectedDetail.members.length})
                  </button>

                  <button
                    onClick={() => setDetailTab('risk')}
                    className={cn(
                      'pb-2.5 transition-colors cursor-pointer border-b-2',
                      detailTab === 'risk'
                        ? 'border-primary text-primary font-bold'
                        : 'border-transparent text-foreground-muted hover:text-foreground'
                    )}
                  >
                    Composite Finding & Risk Lineage
                  </button>
                </div>

                {/* TAB 1: WHY CORRELATED? */}
                {detailTab === 'why' && (
                  <div className="space-y-4">
                    {/* Supporting Reasons */}
                    <Card className="p-4 space-y-3">
                      <div className="flex items-center space-x-2 text-xs font-bold text-foreground">
                        <CheckCircle2 className="w-4 h-4 text-success" />
                        <span>Supporting Correlation Evidence ({explanation?.supporting_reasons.length ?? 0})</span>
                      </div>
                      <div className="space-y-2">
                        {explanation?.supporting_reasons.map((r, i) => (
                          <div key={i} className="flex items-start space-x-2.5 text-xs text-foreground bg-surface-secondary/40 p-2.5 rounded-control border border-border">
                            <span className="text-success font-bold mt-0.5">✓</span>
                            <span>{r}</span>
                          </div>
                        ))}
                      </div>
                    </Card>

                    {/* Contradicting Evidence */}
                    <Card className="p-4 space-y-3">
                      <div className="flex items-center space-x-2 text-xs font-bold text-foreground">
                        <AlertTriangle className="w-4 h-4 text-warning" />
                        <span>Contradicting / Inconsistent Evidence</span>
                      </div>
                      {explanation && explanation.contradicting_evidence.length > 0 ? (
                        <div className="space-y-2">
                          {explanation.contradicting_evidence.map((c, i) => (
                            <div key={i} className="text-xs text-warning bg-warning-subtle/30 p-2.5 rounded-control border border-warning/30">
                              {c}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <div className="text-xs text-foreground-muted bg-surface-secondary/30 p-2.5 rounded-control border border-border">
                          No contradictory signals identified. All observed telemetry supports the correlated hypothesis.
                        </div>
                      )}
                    </Card>

                    {/* Missing Telemetry & Context Warning */}
                    <Card className="p-4 space-y-3 bg-surface">
                      <div className="flex items-center space-x-2 text-xs font-bold text-foreground">
                        <Info className="w-4 h-4 text-primary" />
                        <span>Missing Context & Telemetry Awareness</span>
                      </div>
                      <div className="p-3 rounded-control bg-primary-subtle/30 border border-primary/20 text-xs leading-relaxed">
                        <p className="font-semibold text-primary mb-1">
                          Security Assurance Guarantee:
                        </p>
                        Missing telemetry does NOT equal absence of malicious activity. If endpoint or network sensors are offline, CyberGuard explicitly treats context as unavailable rather than clean.
                      </div>
                    </Card>
                  </div>
                )}

                {/* TAB 2: CHRONOLOGICAL TIMELINE */}
                {detailTab === 'timeline' && (
                  <Card className="p-4 space-y-4">
                    <div className="flex items-center justify-between text-xs border-b border-border pb-2">
                      <span className="font-bold text-foreground">Sequential Event Sequence</span>
                      <span className="text-foreground-muted">Earliest to Latest</span>
                    </div>

                    <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-border">
                      {timelineItems.map((item, idx) => (
                        <div key={idx} className="relative group">
                          {/* Circle dot */}
                          <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-primary border-2 border-background" />

                          <div className="p-3 bg-surface-secondary/60 rounded-control border border-border space-y-1.5">
                            <div className="flex items-center justify-between text-[11px]">
                              <div className="flex items-center space-x-2">
                                <Badge variant="outline" className="font-mono text-[9px] uppercase">
                                  {item.source_type}
                                </Badge>
                                <span className="font-bold text-foreground">{item.role}</span>
                              </div>
                              <span className="font-mono text-foreground-muted">
                                +{Math.round(item.time_from_start_seconds / 60)}m ({new Date(item.timestamp).toLocaleTimeString()})
                              </span>
                            </div>

                            <p className="text-xs text-foreground">
                              {item.description}
                            </p>

                            <div className="text-[10px] font-mono text-foreground-muted">
                              Ref ID: {item.member_id}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>
                )}

                {/* TAB 3: MEMBERS & EVIDENCE */}
                {detailTab === 'members' && (
                  <Card className="p-4 space-y-4">
                    <div className="flex items-center justify-between text-xs border-b border-border pb-2">
                      <span className="font-bold text-foreground">Participating Members ({selectedDetail.members.length})</span>
                      <span className="text-foreground-muted">Immutable graph references</span>
                    </div>

                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs">
                        <thead>
                          <tr className="border-b border-border text-[10px] text-foreground-muted uppercase">
                            <th className="py-2 px-2">Type</th>
                            <th className="py-2 px-2">Source</th>
                            <th className="py-2 px-2">Role</th>
                            <th className="py-2 px-2">Member Ref</th>
                            <th className="py-2 px-2">Confidence</th>
                            <th className="py-2 px-2">Observed At</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {selectedDetail.members.map((m) => (
                            <tr key={m.id} className="hover:bg-surface-secondary/30">
                              <td className="py-2 px-2 font-mono text-[11px]">{m.member_type}</td>
                              <td className="py-2 px-2">
                                <span className="px-1.5 py-0.5 rounded-control bg-surface-secondary border border-border text-[10px] font-mono">
                                  {m.source_type}
                                </span>
                              </td>
                              <td className="py-2 px-2 font-semibold text-foreground">{m.role}</td>
                              <td className="py-2 px-2 font-mono text-[10px] text-foreground-muted truncate max-w-[200px]" title={m.member_id}>
                                {m.member_id}
                              </td>
                              <td className="py-2 px-2 font-mono">{(m.confidence_score * 100).toFixed(0)}%</td>
                              <td className="py-2 px-2 text-foreground-muted">
                                {m.occurred_at ? new Date(m.occurred_at).toLocaleTimeString() : 'N/A'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </Card>
                )}

                {/* TAB 4: RISK & DEDUPLICATION */}
                {detailTab === 'risk' && (
                  <Card className="p-4 space-y-4">
                    <div className="flex items-center space-x-2 text-xs font-bold text-foreground border-b border-border pb-2">
                      <Shield className="w-4 h-4 text-primary" />
                      <span>Unified Risk Engine & Evidence Lineage</span>
                    </div>

                    <div className="p-3 bg-surface-secondary/50 rounded-control border border-border space-y-2 text-xs">
                      <div className="font-semibold text-foreground">Evidence Deduplication Guarantee</div>
                      <p className="text-foreground-secondary leading-relaxed">
                        {explanation?.evidence_deduplication_summary ||
                          'The same underlying evidence is never double-counted. In accordance with Section 18, risk contributions are aggregated without multiplying correlated co-occurrences.'}
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="p-3 bg-surface-secondary/30 rounded-control border border-border space-y-1">
                        <span className="text-[10px] text-foreground-muted uppercase">Parent Composite Finding</span>
                        <div className="font-mono font-bold text-foreground">
                          {selectedDetail.parent_finding_id || 'Self-Correlated (No synthetic parent)'}
                        </div>
                      </div>

                      <div className="p-3 bg-surface-secondary/30 rounded-control border border-border space-y-1">
                        <span className="text-[10px] text-foreground-muted uppercase">Associated Alert ID</span>
                        <div className="font-mono font-bold text-foreground">
                          {selectedDetail.alert_id || 'Enriched Existing Alert'}
                        </div>
                      </div>
                    </div>
                  </Card>
                )}
              </div>
            ) : (
              <div className="flex-1 flex items-center justify-center p-8 text-xs text-foreground-muted">
                Select a correlation from the feed to view explainable evidence.
              </div>
            )}
          </div>
        </div>
      ) : (
        /* TAB 2: UNIFIED ENTITY RESOLVER TOOL & AUDIT LOG */
        <div className="flex-1 flex flex-col md:flex-row min-h-0 overflow-hidden bg-background">
          {/* Resolver Input Pane */}
          <div className="w-full md:w-96 p-6 border-r border-border bg-surface shrink-0 space-y-4">
            <div>
              <h3 className="text-sm font-bold text-foreground">Entity Resolution Inspector</h3>
              <p className="text-xs text-foreground-muted mt-1">
                Deterministically maps raw identifiers to authoritative Knowledge Graph entities with provenance facts.
              </p>
            </div>

            <form onSubmit={handleResolveEntity} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Entity Type</label>
                <select
                  value={entityTypeInput}
                  onChange={(e) => setEntityTypeInput(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-control p-2 text-xs text-foreground"
                >
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain Name</option>
                  <option value="URL">URL</option>
                  <option value="EMAIL">Email Address</option>
                  <option value="ENDPOINT">Endpoint / Device ID</option>
                  <option value="USER">User / Account ID</option>
                  <option value="HASH">File Hash (SHA256/MD5)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-foreground mb-1">Raw Identifier</label>
                <input
                  type="text"
                  placeholder="e.g. 194.26.29.15 or user@domain.com"
                  value={rawIdentifierInput}
                  onChange={(e) => setRawIdentifierInput(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-control p-2 text-xs text-foreground font-mono"
                  required
                />
              </div>

              <Button
                type="submit"
                variant="primary"
                size="sm"
                className="w-full"
                disabled={resolvingEntity}
              >
                {resolvingEntity ? 'Resolving...' : 'Resolve Deterministically'}
              </Button>
            </form>

            {/* Resolution Result Card */}
            {resolveError && (
              <div className="p-3 rounded-control bg-danger/10 border border-danger/20 text-xs text-danger">
                {resolveError}
              </div>
            )}

            {resolvedResult && (
              <Card className="p-4 space-y-3 bg-surface-secondary/40">
                <div className="flex items-center justify-between text-xs border-b border-border pb-2">
                  <span className="font-bold text-foreground">Resolution Output</span>
                  <Badge variant={resolvedResult.status === 'RESOLVED' ? 'success' : 'warning'}>
                    {resolvedResult.status}
                  </Badge>
                </div>

                <div className="space-y-2 text-xs">
                  <div>
                    <div className="text-[10px] text-foreground-muted uppercase">Canonical Entity ID</div>
                    <div className="font-mono text-xs text-primary font-bold break-all">
                      {resolvedResult.canonical_entity_id}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] text-foreground-muted uppercase">Normalized Identifier</div>
                    <div className="font-mono text-xs text-foreground break-all">
                      {resolvedResult.normalized_identifier}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] text-foreground-muted uppercase">Resolution Method</div>
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {resolvedResult.resolution_method}
                    </Badge>
                  </div>

                  <div>
                    <div className="text-[10px] text-foreground-muted uppercase">Resolution Confidence</div>
                    <div className="font-mono text-xs text-success font-bold">
                      {(resolvedResult.resolution_confidence * 100).toFixed(0)}%
                    </div>
                  </div>
                </div>
              </Card>
            )}
          </div>

          {/* Resolution History Audit Log Pane */}
          <div className="flex-1 p-6 overflow-y-auto space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-foreground">Resolution Provenance Audit Trail</h3>
                <p className="text-xs text-foreground-muted mt-0.5">
                  Immutable record of entity resolution decisions, preserving matched attributes and preventing ambiguous merges.
                </p>
              </div>
              <Button size="sm" variant="outline" onClick={loadResolutionHistory}>
                <RefreshCw className={cn('w-3.5 h-3.5 mr-1.5', loadingHistory && 'animate-spin')} />
                Refresh History
              </Button>
            </div>

            <Card className="p-4">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-border text-[10px] text-foreground-muted uppercase">
                      <th className="py-2 px-2">Type</th>
                      <th className="py-2 px-2">Raw Identifier</th>
                      <th className="py-2 px-2">Normalized</th>
                      <th className="py-2 px-2">Method</th>
                      <th className="py-2 px-2">Confidence</th>
                      <th className="py-2 px-2">Status</th>
                      <th className="py-2 px-2">Resolved At</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {resolutionHistory.map((item) => (
                      <tr key={item.id} className="hover:bg-surface-secondary/40">
                        <td className="py-2 px-2 font-mono">{item.entity_type}</td>
                        <td className="py-2 px-2 font-mono text-foreground-muted truncate max-w-[150px]">
                          {item.raw_identifier}
                        </td>
                        <td className="py-2 px-2 font-mono text-foreground truncate max-w-[150px]">
                          {item.normalized_identifier}
                        </td>
                        <td className="py-2 px-2">
                          <span className="px-1.5 py-0.5 rounded-control bg-surface-secondary border border-border text-[10px] font-mono">
                            {item.resolution_method}
                          </span>
                        </td>
                        <td className="py-2 px-2 font-mono">
                          {(item.resolution_confidence * 100).toFixed(0)}%
                        </td>
                        <td className="py-2 px-2">
                          <Badge variant={item.status === 'RESOLVED' ? 'success' : 'warning'} className="text-[10px]">
                            {item.status}
                          </Badge>
                        </td>
                        <td className="py-2 px-2 text-foreground-muted">
                          {new Date(item.created_at).toLocaleTimeString()}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          </div>
        </div>
      )}

      {/* MODAL 1: ANALYST DISPOSITION */}
      <Modal
        isOpen={isDispositionModalOpen}
        onClose={() => setIsDispositionModalOpen(false)}
      >
        <ModalHeader>
          <ModalTitle>Record Analyst Correlation Disposition</ModalTitle>
        </ModalHeader>
        <form onSubmit={handleDispositionSubmit}>
          <ModalBody className="space-y-4 text-xs">
            <div>
              <label className="block font-medium text-foreground mb-1">Disposition Verdict</label>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => setDispositionAction('CONFIRMED')}
                  className={cn(
                    'p-2.5 rounded-control border text-center font-semibold transition-colors cursor-pointer',
                    dispositionAction === 'CONFIRMED'
                      ? 'bg-success/15 border-success text-success'
                      : 'border-border text-foreground-muted hover:text-foreground'
                  )}
                >
                  Confirm
                </button>
                <button
                  type="button"
                  onClick={() => setDispositionAction('REJECTED')}
                  className={cn(
                    'p-2.5 rounded-control border text-center font-semibold transition-colors cursor-pointer',
                    dispositionAction === 'REJECTED'
                      ? 'bg-danger/15 border-danger text-danger'
                      : 'border-border text-foreground-muted hover:text-foreground'
                  )}
                >
                  Reject (Invalidate)
                </button>
                <button
                  type="button"
                  onClick={() => setDispositionAction('UNCERTAIN')}
                  className={cn(
                    'p-2.5 rounded-control border text-center font-semibold transition-colors cursor-pointer',
                    dispositionAction === 'UNCERTAIN'
                      ? 'bg-warning/15 border-warning text-warning'
                      : 'border-border text-foreground-muted hover:text-foreground'
                  )}
                >
                  Mark Uncertain
                </button>
              </div>
            </div>

            <div>
              <label className="block font-medium text-foreground mb-1">
                Mandatory Analytical Justification
              </label>
              <textarea
                rows={3}
                placeholder="State the forensic rationale for confirming or rejecting this correlation..."
                value={dispositionNotes}
                onChange={(e) => setDispositionNotes(e.target.value)}
                className="w-full bg-surface-secondary border border-border rounded-control p-2 text-xs text-foreground"
                required
              />
            </div>
          </ModalBody>
          <ModalFooter>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setIsDispositionModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={submittingDisposition || !dispositionNotes.trim()}
            >
              {submittingDisposition ? 'Recording...' : 'Submit Disposition'}
            </Button>
          </ModalFooter>
        </form>
      </Modal>

      {/* MODAL 2: EVALUATE TELEMETRY */}
      <Modal
        isOpen={isEvaluateModalOpen}
        onClose={() => setIsEvaluateModalOpen(false)}
      >
        <ModalHeader>
          <ModalTitle>Execute On-Demand Correlation Evaluation</ModalTitle>
        </ModalHeader>
        <form onSubmit={handleEvaluateSubmit}>
          <ModalBody className="space-y-4 text-xs">
            <div>
              <label className="block font-medium text-foreground mb-1">Bounded Correlation Window</label>
              <select
                value={evalWindowMinutes}
                onChange={(e) => setEvalWindowMinutes(Number(e.target.value))}
                className="w-full bg-surface-secondary border border-border rounded-control p-2 text-xs text-foreground"
              >
                <option value={5}>5 minutes (Near real-time bursts)</option>
                <option value={15}>15 minutes (Standard triage)</option>
                <option value={30}>30 minutes (Multi-stage attacks)</option>
                <option value={60}>1 hour (Lateral movement)</option>
                <option value={360}>6 hours (Extended campaign)</option>
                <option value={1440}>24 hours (Full day sweep)</option>
              </select>
            </div>

            <div>
              <label className="block font-medium text-foreground mb-1">Optional Entity ID Target</label>
              <input
                type="text"
                placeholder="e.g. host-prod-01 or user@example.com (Leave empty for workspace wide)"
                value={evalEntityId}
                onChange={(e) => setEvalEntityId(e.target.value)}
                className="w-full bg-surface-secondary border border-border rounded-control p-2 text-xs text-foreground font-mono"
              />
            </div>

            <div>
              <label className="block font-medium text-foreground mb-1">Optional Finding ID Target</label>
              <input
                type="text"
                placeholder="e.g. F-102 (Leave empty for all recent findings)"
                value={evalFindingId}
                onChange={(e) => setEvalFindingId(e.target.value)}
                className="w-full bg-surface-secondary border border-border rounded-control p-2 text-xs text-foreground font-mono"
              />
            </div>
          </ModalBody>
          <ModalFooter>
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setIsEvaluateModalOpen(false)}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={evaluating}
            >
              {evaluating ? 'Evaluating...' : 'Run Correlation Engine'}
            </Button>
          </ModalFooter>
        </form>
      </Modal>
    </div>
  );
};
