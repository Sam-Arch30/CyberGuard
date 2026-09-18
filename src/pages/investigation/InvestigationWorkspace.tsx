import React from 'react';
import { ArrowLeft, Sparkles } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useInvestigation } from '../../context/InvestigationContext';
import { ActiveInvestigationHeader } from '../../components/layout/ActiveInvestigationHeader';
import { InvestigationAIDrawer } from '../../components/copilot/InvestigationAIDrawer';
import { LoadingState, ErrorState, Button } from '../../components/ui';
import { OverviewSectionView } from './sections/OverviewSectionView';
import { EmailSectionView } from './sections/EmailSectionView';
import { AnalysisSectionView } from './sections/AnalysisSectionView';
import { IntelligenceSectionView } from './sections/IntelligenceSectionView';
import { InvestigationSectionView } from './sections/InvestigationSectionView';
import { ReportSectionView } from './sections/ReportSectionView';

import { CleanWorkspaceEmptyState } from './CleanWorkspaceEmptyState';

export const InvestigationWorkspace: React.FC = () => {
  const {
    activeEmail,
    loading,
    error,
    activeSection,
    reloadActiveEmail,
    openCopilotDrawer,
    isCopilotDrawerOpen
  } = useInvestigation();
  const navigate = useNavigate();

  if (!activeEmail) {
    if (loading) {
      return (
        <LoadingState
          message="Checking forensic workspace..."
          subtext="Verifying active email telemetry"
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
    <div className="space-y-6 pb-16 page-enter relative">
      {/* 1. PERSISTENT ACTIVE INVESTIGATION CONTEXT HEADER */}
      <ActiveInvestigationHeader />

      {/* 2. ACTIVE SECTION VIEW */}
      <div key={activeSection} className="page-enter">
        {activeSection === 'overview' && <OverviewSectionView email={activeEmail} />}
        {activeSection === 'email' && <EmailSectionView email={activeEmail} />}
        {activeSection === 'analysis' && <AnalysisSectionView email={activeEmail} />}
        {activeSection === 'intelligence' && <IntelligenceSectionView email={activeEmail} />}
        {activeSection === 'investigation' && <InvestigationSectionView email={activeEmail} />}
        {activeSection === 'report' && <ReportSectionView email={activeEmail} />}
      </div>

      {/* 3. CONTEXTUAL INVESTIGATION AI DRAWER */}
      <InvestigationAIDrawer />

      {/* 4. PERSISTENT FLOATING QUICK-ACCESS BUTTON (Accessible throughout workspace) */}
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
