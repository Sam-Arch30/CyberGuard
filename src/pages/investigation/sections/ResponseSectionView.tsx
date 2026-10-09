import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams } from 'react-router-dom';
import {
  ShieldAlert,
  AlertTriangle,
  RotateCcw,
  Filter,
  ArrowUpDown,
  Search,
  Layers,
  Info
} from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { responseWorkspaceService } from '../../../services/responseWorkspaceService';
import type {
  ResponseRecommendation,
  ResponseCapability,
  ResponseWorkspaceOverview
} from '../../../types/response_recommendation';
import type {
  ResponsePlaybook,
  ResponsePlaybookSummary,
  ResponsePlaybookExecution
} from '../../../types/response_playbook';

// Section 41 Presentation Components
import { ResponseRiskSummary } from '../../../components/investigation/response/ResponseRiskSummary';
import { ResponseSummaryBar } from '../../../components/investigation/response/ResponseSummaryBar';
import { RecommendationCard } from '../../../components/investigation/response/RecommendationCard';
import { RecommendationInspectorModal } from '../../../components/investigation/response/RecommendationInspectorModal';
import { ActionApprovalModal } from '../../../components/investigation/response/ActionApprovalModal';
import { CapabilityRegistryModal } from '../../../components/investigation/response/CapabilityRegistryModal';
import { PlaybookSection } from '../../../components/investigation/response/PlaybookSection';
import { ExecutionStatusModal } from '../../../components/investigation/response/ExecutionStatusModal';
import { ActionHistoryTimeline } from '../../../components/investigation/response/ActionHistoryTimeline';

type WorkflowFilter = 'ALL' | 'REVIEW_REQUIRED' | 'APPROVED' | 'REJECTED' | 'DEFERRED';
type CategoryFilter = 'ALL' | 'CONTAINMENT' | 'IDENTITY_SECURITY' | 'NETWORK_SECURITY' | 'ENDPOINT_SECURITY' | 'EVIDENCE_PRESERVATION' | 'COMMUNICATION' | 'RECOVERY';
type SortOption = 'PRIORITY' | 'NEWEST' | 'OLDEST' | 'CONFIDENCE';

export const ResponseSectionView: React.FC = () => {
  const { id } = useParams<{ id?: string }>();
  const { activeEmail, activeEmailId, workspaceSummary, refreshWorkspaceSummary, setSection } = useInvestigation();

  const effectiveId = id || workspaceSummary?.investigation.investigation_id || activeEmailId || '';

  // Core Data State
  const [recommendations, setRecommendations] = useState<ResponseRecommendation[]>([]);
  const [overview, setOverview] = useState<ResponseWorkspaceOverview | null>(null);
  const [capabilities, setCapabilities] = useState<ResponseCapability[]>([]);
  const [playbooks, setPlaybooks] = useState<(ResponsePlaybook | ResponsePlaybookSummary)[]>([]);
  const [executions, setExecutions] = useState<ResponsePlaybookExecution[]>([]);

  // Loading & Error States
  const [loading, setLoading] = useState<boolean>(true);
  const [reloading, setReloading] = useState<boolean>(false);
  const [, setError] = useState<string | null>(null);

  // Filters & Sorting
  const [workflowFilter, setWorkflowFilter] = useState<WorkflowFilter>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('ALL');
  const [sortBy, setSortBy] = useState<SortOption>('PRIORITY');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Selected State & Modals
  const [inspectorRecommendation, setInspectorRecommendation] = useState<ResponseRecommendation | null>(null);
  const [approvalRecommendation, setApprovalRecommendation] = useState<ResponseRecommendation | null>(null);
  const [selectedExecution, setSelectedExecution] = useState<ResponsePlaybookExecution | null>(null);
  const [isCapabilityModalOpen, setIsCapabilityModalOpen] = useState<boolean>(false);

  // Load all response data
  const loadResponseWorkspace = useCallback(async (forceRefresh = false) => {
    if (!effectiveId) {
      setLoading(false);
      return;
    }

    try {
      if (forceRefresh) {
        setReloading(true);
      } else {
        setLoading(true);
      }
      setError(null);

      // 1. Fetch recommendations (or generate if needed)
      let recs: ResponseRecommendation[] = [];
      try {
        recs = await responseWorkspaceService.getRecommendationsByScope('INVESTIGATION', effectiveId);
        if (recs.length === 0) {
          recs = await responseWorkspaceService.generateRecommendations('INVESTIGATION', effectiveId, false);
        }
      } catch (recErr) {
        console.warn('Could not load scope recommendations directly:', recErr);
      }

      // 2. Fetch summary overview
      try {
        const sum = await responseWorkspaceService.getRecommendationsSummary('INVESTIGATION', effectiveId);
        setOverview(sum);
        if (recs.length === 0 && sum.recommendations && sum.recommendations.length > 0) {
          recs = sum.recommendations;
        }
      } catch (sumErr) {
        console.warn('Overview summary fetch warning:', sumErr);
      }
      setRecommendations(recs);

      // 3. Fetch capability registry
      try {
        const caps = await responseWorkspaceService.getCapabilities();
        setCapabilities(caps);
      } catch (capErr) {
        console.warn('Capabilities fetch warning:', capErr);
      }

      // 4. Fetch playbooks
      try {
        const pbs = await responseWorkspaceService.getPlaybooks(undefined, 'INVESTIGATION');
        setPlaybooks(pbs);
      } catch (pbErr) {
        console.warn('Playbooks fetch warning:', pbErr);
      }

      // 5. Fetch execution history
      try {
        const execs = await responseWorkspaceService.listExecutions(effectiveId);
        setExecutions(execs);
      } catch (execErr) {
        console.warn('Executions fetch warning:', execErr);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load response workspace data');
    } finally {
      setLoading(false);
      setReloading(false);
    }
  }, [effectiveId]);

  useEffect(() => {
    loadResponseWorkspace();
  }, [loadResponseWorkspace]);

  // Handle analyst review submission
  const handleReviewSubmit = async (req: {
    recommendation_id: string;
    status: 'APPROVED' | 'REJECTED' | 'DEFERRED';
    reviewer_id: string;
    reviewer_notes: string;
  }) => {
    try {
      if (req.status === 'APPROVED') {
        await responseWorkspaceService.approveRecommendation(
          req.recommendation_id,
          req.reviewer_notes,
          req.reviewer_id
        );
      } else if (req.status === 'REJECTED') {
        await responseWorkspaceService.rejectRecommendation(
          req.recommendation_id,
          req.reviewer_notes,
          req.reviewer_id
        );
      } else {
        await responseWorkspaceService.deferRecommendation(
          req.recommendation_id,
          req.reviewer_notes,
          req.reviewer_id
        );
      }
      await loadResponseWorkspace(true);
      await refreshWorkspaceSummary();
    } catch (err) {
      console.error('Failed to submit review:', err);
      throw err;
    }
  };

  // Check for stale recommendations compared to active analysis run
  const activeAnalysisRunId = (workspaceSummary as any)?.active_run?.id || activeEmail?.evidence_id || '';
  const staleRecommendations = useMemo(() => {
    if (!activeAnalysisRunId) return [];
    return recommendations.filter((r) => {
      const recRunId = (r as any).analysis_run_id || (r.metadata as any)?.analysis_run_id;
      return recRunId && recRunId !== activeAnalysisRunId;
    });
  }, [recommendations, activeAnalysisRunId]);

  // Filtered and sorted recommendations
  const filteredRecommendations = useMemo(() => {
    return recommendations
      .filter((rec) => {
        // Workflow Filter
        if (workflowFilter === 'REVIEW_REQUIRED') {
          if (rec.status !== 'GENERATED' && rec.status !== 'REVIEW_REQUIRED') return false;
        } else if (workflowFilter === 'APPROVED') {
          if (rec.status !== 'APPROVED') return false;
        } else if (workflowFilter === 'REJECTED') {
          if (rec.status !== 'REJECTED') return false;
        } else if (workflowFilter === 'DEFERRED') {
          if (rec.status !== 'DEFERRED') return false;
        }

        // Category Filter
        if (categoryFilter !== 'ALL' && rec.category !== categoryFilter) {
          return false;
        }

        // Search Query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const targetStr = rec.affected_entities?.[0]?.identifier || (rec as any).target_entity || '';
          const matches =
            rec.title.toLowerCase().includes(q) ||
            rec.description.toLowerCase().includes(q) ||
            targetStr.toLowerCase().includes(q) ||
            rec.rationale.toLowerCase().includes(q);
          if (!matches) return false;
        }

        return true;
      })
      .sort((a, b) => {
        if (sortBy === 'PRIORITY') {
          const pOrder: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 };
          const pA = pOrder[a.priority] ?? 99;
          const pB = pOrder[b.priority] ?? 99;
          return pA - pB;
        }
        if (sortBy === 'NEWEST') {
          return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
        }
        if (sortBy === 'OLDEST') {
          return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
        }
        if (sortBy === 'CONFIDENCE') {
          return (b.confidence || 0) - (a.confidence || 0);
        }
        return 0;
      });
  }, [recommendations, workflowFilter, categoryFilter, searchQuery, sortBy]);

  // Immediate Actions (P0 & P1) vs Standard Advisory
  const immediateActions = useMemo(() => {
    return filteredRecommendations.filter((r) => r.priority === 'P0' || r.priority === 'P1');
  }, [filteredRecommendations]);

  const standardActions = useMemo(() => {
    return filteredRecommendations.filter((r) => r.priority !== 'P0' && r.priority !== 'P1');
  }, [filteredRecommendations]);

  if (loading && !reloading) {
    return (
      <div className="p-12 text-center border border-border rounded-xl bg-card">
        <div className="animate-spin w-8 h-8 border-2 border-primary border-t-transparent rounded-full mx-auto mb-3" />
        <h3 className="text-sm font-bold text-foreground">Loading Response Workspace...</h3>
        <p className="text-xs text-muted-foreground mt-1">
          Grounded risk signals, capability registry, and defensive recommendations.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* 1. Response Summary Bar */}
      <ResponseSummaryBar
        overview={overview}
        recommendations={recommendations}
        loading={reloading}
        onRefresh={() => loadResponseWorkspace(true)}
        onOpenCapabilities={() => setIsCapabilityModalOpen(true)}
        lastUpdated={workspaceSummary?.last_updated}
      />

      {/* 2. Authoritative Risk Summary & Grounding Connection (Section 26 & 27) */}
      <ResponseRiskSummary
        summary={workspaceSummary}
        email={activeEmail}
        onNavigateToAnalysis={() => setSection('analysis')}
        onNavigateToAttackPath={() => setSection('attack-path')}
      />

      {/* 3. Stale Recommendations Callout if analysis run advanced */}
      {staleRecommendations.length > 0 && (
        <div className="p-4 rounded-xl border border-amber-500/40 bg-amber-500/10 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="text-xs space-y-1">
              <div className="font-bold text-amber-300">
                Stale Recommendations Detected ({staleRecommendations.length})
              </div>
              <p className="text-amber-200/90 leading-relaxed">
                These recommendations were evaluated against a previous analysis run.
                A newer analysis run (<code>{activeAnalysisRunId}</code>) is available.
                Re-evaluate recommendations to ensure grounding against the latest forensic telemetry.
              </p>
            </div>
          </div>
          <button
            onClick={() => loadResponseWorkspace(true)}
            className="px-3 py-1.5 text-xs font-bold bg-amber-600 hover:bg-amber-500 text-white rounded-lg transition-colors flex-shrink-0 flex items-center gap-1.5 shadow-sm"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Re-evaluate Now</span>
          </button>
        </div>
      )}

      {/* 4. Controls: Filters, Search, and Sort */}
      <div className="p-3.5 rounded-xl border border-border bg-card space-y-3">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
          {/* Search box */}
          <div className="relative flex-1 max-w-sm">
            <Search className="w-3.5 h-3.5 text-muted-foreground absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter actions by title, rationale, or target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full text-xs bg-background border border-border rounded-lg pl-8 pr-3 py-1.5 text-foreground placeholder:text-muted-foreground/60 focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>

          {/* Workflow Status Filter Tabs */}
          <div className="flex items-center gap-1 bg-muted/60 p-0.5 rounded-lg border border-border overflow-x-auto text-xs">
            {(['ALL', 'REVIEW_REQUIRED', 'APPROVED', 'REJECTED', 'DEFERRED'] as WorkflowFilter[]).map((wf) => (
              <button
                key={wf}
                onClick={() => setWorkflowFilter(wf)}
                className={`px-2.5 py-1 font-semibold rounded-md transition-all whitespace-nowrap ${
                  workflowFilter === wf
                    ? 'bg-card text-foreground shadow-xs font-bold'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                {wf === 'ALL'
                  ? `All (${recommendations.length})`
                  : wf === 'REVIEW_REQUIRED'
                  ? 'Review Required'
                  : wf === 'APPROVED'
                  ? 'Approved'
                  : wf === 'REJECTED'
                  ? 'Rejected'
                  : 'Deferred'}
              </button>
            ))}
          </div>
        </div>

        {/* Secondary Category & Sorting Controls */}
        <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border/60 text-xs">
          {/* Category Dropdown */}
          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-muted-foreground font-semibold">Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as CategoryFilter)}
              className="bg-background border border-border rounded px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono text-[11px]"
            >
              <option value="ALL">All Categories</option>
              <option value="CONTAINMENT">Containment</option>
              <option value="IDENTITY_SECURITY">Identity Security</option>
              <option value="NETWORK_SECURITY">Network Controls</option>
              <option value="ENDPOINT_SECURITY">Endpoint Defense</option>
              <option value="EVIDENCE_PRESERVATION">Evidence Preservation</option>
              <option value="COMMUNICATION">Incident Comms</option>
              <option value="RECOVERY">Remediation & Recovery</option>
            </select>
          </div>

          {/* Sort Dropdown */}
          <div className="flex items-center gap-2">
            <ArrowUpDown className="w-3.5 h-3.5 text-muted-foreground" />
            <span className="text-muted-foreground font-semibold">Sort By:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as SortOption)}
              className="bg-background border border-border rounded px-2 py-1 text-foreground focus:outline-none focus:ring-1 focus:ring-primary font-mono text-[11px]"
            >
              <option value="PRIORITY">Priority (P0 First)</option>
              <option value="NEWEST">Newest First</option>
              <option value="OLDEST">Oldest First</option>
              <option value="CONFIDENCE">Confidence Score</option>
            </select>
          </div>
        </div>
      </div>

      {/* 5. Recommendations List (Section 8, 9, 10, 40) */}
      <div className="space-y-6">
        {/* Immediate High-Priority Actions (P0 / P1) */}
        {immediateActions.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-rose-400" />
                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider">
                  Immediate Containment Actions ({immediateActions.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-muted-foreground">
                Critical & High Priority Defense Directives
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {immediateActions.map((rec) => (
                <RecommendationCard
                  key={rec.id}
                  recommendation={rec}
                  onInspect={(r) => setInspectorRecommendation(r)}
                  onApprove={(r) => setApprovalRecommendation(r)}
                  onReject={(r) => setApprovalRecommendation(r)}
                  onDefer={(r) => setApprovalRecommendation(r)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Standard Advisory Actions */}
        {standardActions.length > 0 && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="w-4 h-4 text-primary" />
                <h3 className="text-xs font-bold text-foreground uppercase tracking-wider">
                  Forensic & Remediation Advisory ({standardActions.length})
                </h3>
              </div>
              <span className="text-[10px] font-mono text-muted-foreground">
                Secondary Investigation & Recovery Actions
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {standardActions.map((rec) => (
                <RecommendationCard
                  key={rec.id}
                  recommendation={rec}
                  onInspect={(r) => setInspectorRecommendation(r)}
                  onApprove={(r) => setApprovalRecommendation(r)}
                  onReject={(r) => setApprovalRecommendation(r)}
                  onDefer={(r) => setApprovalRecommendation(r)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Empty State */}
        {filteredRecommendations.length === 0 && (
          <div className="p-8 border border-border/80 border-dashed rounded-xl text-center bg-card/40 space-y-2">
            <Info className="w-7 h-7 text-muted-foreground mx-auto opacity-50" />
            <h4 className="text-sm font-semibold text-foreground">No Recommendations Found</h4>
            <p className="text-xs text-muted-foreground max-w-md mx-auto">
              No recommendations match the current filters. Adjust your workflow status or category filter,
              or re-evaluate against new investigation telemetry.
            </p>
          </div>
        )}
      </div>

      {/* 6. Playbook Section (Section 25–30) */}
      <PlaybookSection
        playbooks={playbooks}
        recommendations={recommendations}
        investigationId={effectiveId}
        onRefresh={() => loadResponseWorkspace(true)}
        onSelectExecution={(exec) => setSelectedExecution(exec)}
      />

      {/* 7. Action & Audit History Timeline (Section 32, 33, 65) */}
      <ActionHistoryTimeline
        executions={executions}
        recommendations={recommendations}
        onSelectExecution={(exec) => setSelectedExecution(exec)}
        onSelectRecommendation={(rec) => setInspectorRecommendation(rec)}
      />

      {/* Modals & Inspection Drawers */}
      {/* 1. Authoritative Recommendation Inspector Modal */}
      <RecommendationInspectorModal
        isOpen={Boolean(inspectorRecommendation)}
        recommendation={inspectorRecommendation}
        onClose={() => setInspectorRecommendation(null)}
        onApprove={async (rec, notes) => {
          await handleReviewSubmit({
            recommendation_id: rec.id,
            status: 'APPROVED',
            reviewer_id: 'analyst@cyberguard.local',
            reviewer_notes: notes
          });
          setInspectorRecommendation(null);
        }}
        onReject={async (rec, notes) => {
          await handleReviewSubmit({
            recommendation_id: rec.id,
            status: 'REJECTED',
            reviewer_id: 'analyst@cyberguard.local',
            reviewer_notes: notes
          });
          setInspectorRecommendation(null);
        }}
        onDefer={async (rec, notes) => {
          await handleReviewSubmit({
            recommendation_id: rec.id,
            status: 'DEFERRED',
            reviewer_id: 'analyst@cyberguard.local',
            reviewer_notes: notes
          });
          setInspectorRecommendation(null);
        }}
        onNavigateToAttackPath={() => setSection('attack-path')}
        onNavigateToEvidence={() => setSection('evidence')}
      />

      {/* 2. Action Approval & Disposition Modal */}
      <ActionApprovalModal
        isOpen={Boolean(approvalRecommendation)}
        recommendation={approvalRecommendation}
        onClose={() => setApprovalRecommendation(null)}
        onSubmitReview={handleReviewSubmit}
      />

      {/* 3. Capability Registry Modal */}
      <CapabilityRegistryModal
        isOpen={isCapabilityModalOpen}
        capabilities={capabilities}
        onClose={() => setIsCapabilityModalOpen(false)}
      />

      {/* 4. Execution Status Modal */}
      <ExecutionStatusModal
        isOpen={Boolean(selectedExecution)}
        execution={selectedExecution}
        onClose={() => setSelectedExecution(null)}
      />
    </div>
  );
};

export default ResponseSectionView;
