import React from 'react';
import { Loader2, AlertCircle, ArrowLeft } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useInvestigation } from '../../context/InvestigationContext';
import { ActiveInvestigationHeader } from '../../components/layout/ActiveInvestigationHeader';
import { OverviewSectionView } from './sections/OverviewSectionView';
import { EmailSectionView } from './sections/EmailSectionView';
import { AnalysisSectionView } from './sections/AnalysisSectionView';
import { IntelligenceSectionView } from './sections/IntelligenceSectionView';
import { InvestigationSectionView } from './sections/InvestigationSectionView';
import { ReportSectionView } from './sections/ReportSectionView';

export const InvestigationWorkspace: React.FC = () => {
  const {
    activeEmail,
    loading,
    error,
    activeSection,
    reloadActiveEmail
  } = useInvestigation();
  const navigate = useNavigate();

  if (loading && !activeEmail) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
        <p className="text-xs font-mono text-foreground-muted">
          Loading investigation telemetry...
        </p>
      </div>
    );
  }

  if (error || !activeEmail) {
    return (
      <div className="max-w-xl mx-auto my-12 p-8 bg-surface rounded-xl border border-danger/40 text-center space-y-4 shadow-sm">
        <div className="p-3 bg-danger/10 rounded-full w-12 h-12 mx-auto flex items-center justify-center border border-danger/30 text-danger">
          <AlertCircle className="w-6 h-6" />
        </div>
        <h2 className="text-base font-bold text-foreground font-mono">
          Investigation Record Not Found
        </h2>
        <p className="text-xs font-mono text-foreground-muted">
          {error || 'Unable to locate forensic evidence for the requested ID.'}
        </p>
        <div className="pt-3 flex items-center justify-center gap-3">
          <button
            type="button"
            onClick={reloadActiveEmail}
            className="px-3.5 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono transition-colors cursor-pointer"
          >
            Retry Load
          </button>
          <button
            type="button"
            onClick={() => navigate('/analyze')}
            className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-semibold transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Ingest New Email</span>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-16 page-enter">
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
    </div>
  );
};

export default InvestigationWorkspace;
