import React, { useState, useEffect } from 'react';
import { ArrowLeft, Sparkles } from 'lucide-react';
import { useNavigate, useParams } from 'react-router-dom';
import { useInvestigation } from '../../context/InvestigationContext';
import { RealtimeService } from '../../services/realtimeService';
import type { RealtimeConnectionStatus } from '../../types/realtime';
import { ActiveInvestigationHeader } from '../../components/layout/ActiveInvestigationHeader';
import { InvestigationSummaryBar } from '../../components/investigation/InvestigationSummaryBar';
import { InvestigationNav } from '../../components/investigation/InvestigationNav';
import { InvestigationNotesDrawer } from '../../components/investigation/InvestigationNotesDrawer';
import { InvestigationAIDrawer } from '../../components/copilot/InvestigationAIDrawer';
import { LoadingState, ErrorState, Button } from '../../components/ui';

// Section Views for Section 39 Workspaces
import { OverviewSectionView } from './sections/OverviewSectionView';
import { AnalysisSectionView } from './sections/AnalysisSectionView';
import { AttackPathSectionView } from './sections/AttackPathSectionView';
import { GraphSectionView } from './sections/GraphSectionView';
import { TimelineSectionView } from './sections/TimelineSectionView';
import { EvidenceSectionView } from './sections/EvidenceSectionView';
import { IntelligenceSectionView } from './sections/IntelligenceSectionView';
import { ResponseSectionView } from './sections/ResponseSectionView';
import { ReportSectionView } from './sections/ReportSectionView';

// Backward-compatible sections
import { EmailSectionView } from './sections/EmailSectionView';
import { InvestigationSectionView } from './sections/InvestigationSectionView';
import { LiveAnalysisView } from '../../components/analysis/LiveAnalysisView';

import { CleanWorkspaceEmptyState } from './CleanWorkspaceEmptyState';

export const InvestigationWorkspace: React.FC = () => {
  const { id, section } = useParams<{ id?: string; section?: string }>();
  const {
    activeEmail,
    activeEmailId,
    workspaceSummary,
    loading,
    error,
    activeSection,
    reloadActiveEmail,
    refreshWorkspaceSummary,
    updateInvestigationStatus,
    addAnalystNote,
    isNotesDrawerOpen,
    openNotesDrawer,
    closeNotesDrawer,
    openCopilotDrawer,
    isCopilotDrawerOpen,
  } = useInvestigation();
  const navigate = useNavigate();

  const effectiveId = id || activeEmailId || workspaceSummary?.investigation.investigation_id;
  const isAnalysisRoute = section === 'analysis' || activeSection === 'analysis';
  const hasInvestigationData = Boolean(activeEmail || workspaceSummary);
  const [connectionStatus, setConnectionStatus] = useState<RealtimeConnectionStatus>('DISCONNECTED');

  // Section 46: Real-time event stream subscription for active investigation
  useEffect(() => {
    if (!effectiveId || effectiveId === 'analysis') return;

    const unsubscribe = RealtimeService.subscribe({
      url: `/api/investigations/${encodeURIComponent(effectiveId)}/stream`,
      onEvent: (evt) => {
        // When findings persist, analysis progresses/completes, or status transitions occur, refresh workspace summary
        if (
          [
            'FINDING_PERSISTED',
            'INDICATOR_DISCOVERED',
            'EVIDENCE_ADDED',
            'ANALYSIS_COMPLETED',
            'ANALYSIS_PARTIAL',
            'ANALYSIS_STAGE_COMPLETED',
            'REPORT_READY',
          ].includes(evt.event_type)
        ) {
          refreshWorkspaceSummary();
        }
      },
      onStatusChange: (status) => setConnectionStatus(status),
      onAuthoritativeRefetch: () => {
        refreshWorkspaceSummary();
      },
    });

    return () => {
      unsubscribe();
    };
  }, [effectiveId, refreshWorkspaceSummary]);

  if (!hasInvestigationData) {
    if (isAnalysisRoute && effectiveId && effectiveId !== 'analysis') {
      return (
        <div className="space-y-6 pb-16 page-enter relative">
          <LiveAnalysisView investigationId={effectiveId} />
        </div>
      );
    }
    if (loading) {
      return (
        <LoadingState
          message="Loading forensic investigation workspace..."
          subtext="Resolving investigation context and evidence graph"
          fullHeight
        />
      );
    }
    return <CleanWorkspaceEmptyState />;
  }

  if (error) {
    return (
      <ErrorState
        title="Investigation Record Not Found"
        message={error}
        onRetry={reloadActiveEmail}
        action={
          <Button
            size="sm"
            variant="primary"
            onClick={() => navigate('/analyze')}
            leftIcon={<ArrowLeft className="w-3.5 h-3.5" />}
          >
            Ingest New Email
          </Button>
        }
      />
    );
  }

  return (
    <div className="space-y-4 pb-16 page-enter relative">
      {/* 1. PERSISTENT ACTIVE INVESTIGATION CONTEXT HEADER (Forensic Telemetry) */}
      {activeEmail && <ActiveInvestigationHeader />}

      {/* 2. PERSISTENT INVESTIGATION SUMMARY BAR (Status, Score, Counts, Attention Items) */}
      <InvestigationSummaryBar
        summary={workspaceSummary}
        loading={loading}
        connectionStatus={connectionStatus}
        onStatusChange={updateInvestigationStatus}
        onOpenNotes={openNotesDrawer}
        onRefresh={refreshWorkspaceSummary}
      />

      {/* 3. CONTEXTUAL INVESTIGATION NAVIGATION (9 Canonical Workspaces) */}
      <InvestigationNav
        activeSection={activeSection}
        investigationId={effectiveId || ''}
        counts={workspaceSummary?.counts}
      />

      {/* 4. ACTIVE SECTION VIEW */}
      <div key={activeSection} className="page-enter">
        {activeSection === 'overview' && (
          <OverviewSectionView email={activeEmail} />
        )}
        {activeSection === 'analysis' && (
          activeEmail ? (
            <AnalysisSectionView email={activeEmail} />
          ) : effectiveId ? (
            <LiveAnalysisView investigationId={effectiveId} />
          ) : null
        )}
        {activeSection === 'attack-path' && (
          <AttackPathSectionView />
        )}
        {activeSection === 'graph' && (
          <GraphSectionView />
        )}
        {activeSection === 'timeline' && (
          <TimelineSectionView />
        )}
        {activeSection === 'evidence' && (
          <EvidenceSectionView />
        )}
        {activeSection === 'intelligence' && (
          activeEmail ? (
            <IntelligenceSectionView email={activeEmail} />
          ) : (
            <div className="bg-surface border border-border rounded-xl p-8 text-center text-xs font-mono text-foreground-muted">
              No threat intelligence telemetry available for this artifact.
            </div>
          )
        )}
        {activeSection === 'response' && (
          <ResponseSectionView />
        )}
        {activeSection === 'report' && (
          <ReportSectionView investigationId={effectiveId || ''} email={activeEmail || undefined} />
        )}

        {/* Backward-compatible legacy aliases */}
        {activeSection === 'email' && activeEmail && (
          <EmailSectionView email={activeEmail} />
        )}
        {activeSection === 'investigation' && activeEmail && (
          <InvestigationSectionView email={activeEmail} />
        )}
      </div>

      {/* 5. AUDITABLE ANALYST NOTES DRAWER */}
      <InvestigationNotesDrawer
        isOpen={isNotesDrawerOpen}
        onClose={closeNotesDrawer}
        notes={workspaceSummary?.analyst_notes || []}
        onAddNote={addAnalystNote}
        investigationId={effectiveId || ''}
      />

      {/* 6. CONTEXTUAL INVESTIGATION AI DRAWER */}
      <InvestigationAIDrawer />

      {/* 7. PERSISTENT FLOATING QUICK-ACCESS COPILOT BUTTON */}
      {!isCopilotDrawerOpen && (
        <div className="fixed bottom-6 right-6 z-40 animate-fadeIn">
          <button
            type="button"
            onClick={() => openCopilotDrawer()}
            className="group flex items-center space-x-2 px-3.5 py-2.5 rounded-full bg-surface hover:bg-surface-secondary text-primary shadow-lg border border-primary/35 hover:border-primary transition-all duration-150 cursor-pointer text-xs font-mono font-semibold"
            title="Open Investigation AI Copilot Drawer"
          >
            <Sparkles className="w-4 h-4 text-primary animate-pulse group-hover:scale-110 transition-transform" />
            <span>Ask Copilot</span>
          </button>
        </div>
      )}
    </div>
  );
};

export default InvestigationWorkspace;
