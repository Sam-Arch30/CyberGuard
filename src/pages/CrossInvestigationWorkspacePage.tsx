import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import type { EmailAnalysis } from '../types/forensic';
import { getAnalysisResult } from '../utils/forensicStore';
import { resolveEmailIndicators } from '../utils/indicatorHelper';
import { CrossEmailWorkspace } from '../components/forensic/CrossEmailWorkspace';
import { GitMerge, ArrowLeft, Loader2, FolderLock } from 'lucide-react';

export const CrossInvestigationWorkspacePage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [email, setEmail] = useState<EmailAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    setLoading(true);
    const targetId = id || 'demo';
    const result = getAnalysisResult(targetId) || getAnalysisResult('sample-001') || getAnalysisResult('latest');
    if (result) {
      setEmail(resolveEmailIndicators(result));
    }
    setLoading(false);
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <Loader2 className="w-6 h-6 text-primary animate-spin" />
        <p className="text-xs font-mono text-foreground-muted">
          Loading Cross-Email Investigation Workspace...
        </p>
      </div>
    );
  }

  if (!email) {
    return (
      <div className="max-w-xl mx-auto my-12 p-8 bg-surface rounded-2xl border border-border text-center space-y-4">
        <GitMerge className="w-8 h-8 text-primary mx-auto opacity-70" />
        <h2 className="text-base font-bold text-foreground font-sans">No Investigation Active</h2>
        <p className="text-xs font-mono text-foreground-muted">
          Analyze an email or load the forensic demo dataset to launch cross-email correlation.
        </p>
        <button
          type="button"
          onClick={() => navigate('/analysis/demo')}
          className="px-4 py-2 rounded-xl bg-primary text-primary-foreground font-mono text-xs font-bold hover:bg-primary/90 transition-all cursor-pointer"
        >
          Load Demo Investigation
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6 pb-16">
      {/* Breadcrumb Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-2 border-b border-border">
        <div className="flex items-center space-x-3">
          <div className="w-10 h-10 rounded-xl bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <GitMerge className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h1 className="text-xl font-black font-sans text-foreground">
                Cross-Email Investigation Workspace
              </h1>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-danger/15 text-danger border border-danger/30">
                16 CORRELATED EMAILS
              </span>
            </div>
            <p className="text-xs font-mono text-foreground-muted mt-0.5">
              Multi-dimensional cross-message correlation, side-by-side comparison, and campaign infrastructure discovery.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            type="button"
            onClick={() => navigate(`/analysis/${email.id || 'demo'}`)}
            className="px-3.5 py-2 rounded-xl bg-surface border border-border text-foreground hover:bg-surface-secondary text-xs font-mono font-medium transition-all flex items-center space-x-2 cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to Email Forensics</span>
          </button>
          <button
            type="button"
            onClick={() => navigate('/campaigns/C-042')}
            className="px-3.5 py-2 rounded-xl bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 text-xs font-mono font-bold transition-all flex items-center space-x-2 cursor-pointer"
          >
            <FolderLock className="w-3.5 h-3.5" />
            <span>Campaign C-042</span>
          </button>
        </div>
      </div>

      {/* Primary Workspace */}
      <CrossEmailWorkspace
        email={email}
        onOpenEmail={(targetId) => navigate(`/analysis/${targetId}`)}
      />
    </div>
  );
};
