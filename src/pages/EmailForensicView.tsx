import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import type { EmailAnalysis, ForensicTabType } from '../types/forensic';
import { getAnalysisResult, saveAnalysisResult } from '../utils/forensicStore';
import { resolveEmailIndicators } from '../utils/indicatorHelper';
import { EmailSummaryHeader } from '../components/forensic/EmailSummaryHeader';
import { ForensicTabs } from '../components/forensic/ForensicTabs';
import { OverviewTab } from '../components/forensic/OverviewTab';
import { HeadersTab } from '../components/forensic/HeadersTab';
import { ContentTab } from '../components/forensic/ContentTab';
import { IndicatorsTab } from '../components/forensic/IndicatorsTab';
import { AttachmentsTab } from '../components/forensic/AttachmentsTab';
import { RawEmailTab } from '../components/forensic/RawEmailTab';
import { InvestigationGraphTab } from '../components/forensic/InvestigationGraphTab';
import { InvestigationMapTab } from '../components/forensic/InvestigationMapTab';
<<<<<<< Updated upstream
import { AlertCircle, ArrowLeft, Loader2 } from 'lucide-react';
=======
import { CrossEmailWorkspace } from '../components/forensic/CrossEmailWorkspace';
import { InvestigationCopilot } from '../components/copilot/InvestigationCopilot';
import { AlertCircle, ArrowLeft, Loader2, X } from 'lucide-react';
import { useDemoTour } from '../context/DemoTourContext';
import { api } from '../services/api';
>>>>>>> Stashed changes

export const EmailForensicView: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ForensicTabType>('overview');
<<<<<<< Updated upstream
=======
  const [focusedGraphNodeId, setFocusedGraphNodeId] = useState<string | null>(null);
  const [isCopilotDrawerOpen, setIsCopilotDrawerOpen] = useState<boolean>(false);

  useEffect(() => {
    if (activeTabOverride) {
      setActiveTab(activeTabOverride as ForensicTabType);
    }
  }, [activeTabOverride]);

  const handleFocusGraphNode = (nodeId: string) => {
    setFocusedGraphNodeId(nodeId);
    setActiveTab('graph');
  };
>>>>>>> Stashed changes

  useEffect(() => {
    setLoading(true);
    setError(null);

    const targetId = id || 'latest';
    const result = getAnalysisResult(targetId);

    if (result) {
      const resolved = resolveEmailIndicators(result);
      setAnalysis(resolved);

      // Dynamically fetch ML classification if not already cached
      const hasML = resolved.ml_phishing_probability !== undefined &&
                    resolved.ml_phishing_probability !== null &&
                    Boolean(resolved.ml_assessment);
      if (!hasML) {
        const textToAnalyze = resolved.plain_text_body || (resolved.html_body ? resolved.html_body.replace(/<[^>]+>/g, ' ') : '');
        if (resolved.subject || textToAnalyze) {
<<<<<<< Updated upstream
          fetch('http://localhost:8000/api/emails/ml-classify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              subject: resolved.subject || '',
              body: textToAnalyze || ''
            })
          })
            .then(res => (res.ok ? res.json() : null))
=======
          api.email.mlClassify(resolved.subject || '', textToAnalyze || '')
>>>>>>> Stashed changes
            .then(mlData => {
              if (mlData && mlData.available) {
                setAnalysis(prev => {
                  if (!prev) return prev;
                  const updated: EmailAnalysis = {
                    ...prev,
                    ml_phishing_probability: mlData.probability,
                    ml_assessment: mlData
                  };
                  saveAnalysisResult(targetId, updated);
                  return updated;
                });
              }
            })
            .catch(() => {});
        }
      }

      // Dynamically fetch AI Analyst assessment if not already cached
      if (!resolved.ai_analyst) {
<<<<<<< Updated upstream
        fetch('http://localhost:8000/api/emails/ai-analyst', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
=======
        api.email.aiAnalyst(resolved)
>>>>>>> Stashed changes
          .then(aiData => {
            if (aiData) {
              setAnalysis(prev => {
                if (!prev) return prev;
                const updated: EmailAnalysis = {
                  ...prev,
                  ai_analyst: aiData
                };
                saveAnalysisResult(targetId, updated);
                return updated;
              });
            }
          })
          .catch(() => {});
      }

<<<<<<< Updated upstream
      // Dynamically fetch Investigation Graph if not already cached
      if (!resolved.investigation_graph) {
        fetch('http://localhost:8000/api/emails/investigation-graph', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
=======
      // Dynamically fetch Attribution if not already cached
      if (!resolved.attribution) {
        api.attribution.evaluate(resolved)
          .then(attrData => {
            if (attrData) {
              setAnalysis(prev => {
                if (!prev) return prev;
                const updated: EmailAnalysis = {
                  ...prev,
                  attribution: attrData
                };
                saveAnalysisResult(targetId, updated);
                return updated;
              });
            }
          })
          .catch(() => {});
      }

      // Dynamically fetch Investigation Graph if not already cached
      if (!resolved.investigation_graph) {
        api.email.getInvestigationGraph(resolved)
>>>>>>> Stashed changes
          .then(graphData => {
            if (graphData && graphData.nodes) {
              setAnalysis(prev => {
                if (!prev) return prev;
                const updated: EmailAnalysis = {
                  ...prev,
                  investigation_graph: graphData
                };
                saveAnalysisResult(targetId, updated);
                return updated;
              });
            }
          })
          .catch(() => {});
      }
<<<<<<< Updated upstream
=======

      // Dynamically fetch Threat Score if not already cached
      if (!resolved.threat_score?.scoring_version || !resolved.threat_score?.audit_metadata) {
        api.email.calculateThreatScore(resolved)
          .then(scoreData => {
            if (scoreData) {
              setAnalysis(prev => {
                if (!prev) return prev;
                const updated: EmailAnalysis = {
                  ...prev,
                  threat_score: scoreData
                };
                saveAnalysisResult(targetId, updated);
                return updated;
              });
            }
          })
          .catch(() => {});
      }
      setLoading(false);
    } else if (targetId && targetId !== 'latest') {
      api.email.getAnalysis(targetId)
        .then(apiData => {
          const resolved = resolveEmailIndicators(apiData);
          saveAnalysisResult(targetId, resolved);
          setAnalysis(resolved);
          setLoading(false);
        })
        .catch(() => {
          setError(`Unable to load forensic analysis for email ID '${targetId}'.`);
          setLoading(false);
        });
>>>>>>> Stashed changes
    } else {
      setError('Unable to load the forensic analysis for this email.');
    }
    setLoading(false);
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <Loader2 className="w-6 h-6 text-primary animate-spin" />
        <p className="text-xs font-mono text-foreground-muted">
          Loading forensic evidence dossier...
        </p>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="max-w-xl mx-auto my-12 p-8 bg-surface rounded-card border border-danger-border text-center space-y-4 shadow-sm">
        <div className="p-3 bg-danger-surface rounded-full w-12 h-12 mx-auto flex items-center justify-center border border-danger-border">
          <AlertCircle className="w-5 h-5 text-danger" />
        </div>
        <h2 className="text-base font-bold text-foreground font-mono">
          Analysis Record Not Found
        </h2>
        <p className="text-xs font-mono text-foreground-muted">
          {error || 'Unable to load the forensic analysis for this email.'}
        </p>
        <div className="pt-3">
          <button
            type="button"
            onClick={() => navigate('/analyze')}
            className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-control bg-surface hover:bg-surface-secondary text-primary border border-border font-mono text-xs font-medium transition-colors btn-press cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Return to Ingestion Console</span>
          </button>
        </div>
      </div>
    );
  }

  const counts = {
    receivedHops: analysis.received?.length || 0,
    urls: analysis.urls?.length || 0,
    attachments: analysis.attachments?.length || analysis.indicators?.attachments?.length || 0,
  };

  return (
    <div className="space-y-4 pb-16 relative">
      {/* 1. FORENSIC COMMAND STRIP */}
      <EmailSummaryHeader
        email={analysis}
        onOpenCopilot={() => setIsCopilotDrawerOpen(true)}
      />

      {/* 2. GROUPED FORENSIC TABS WITH COPILOT DRAWER TOGGLE */}
      <ForensicTabs
        activeTab={activeTab}
        onTabChange={setActiveTab}
        counts={counts}
        onToggleCopilotDrawer={() => setIsCopilotDrawerOpen(!isCopilotDrawerOpen)}
        isCopilotDrawerOpen={isCopilotDrawerOpen}
      />

      {/* 3. ACTIVE TAB CONTENT WORKSPACE */}
      <div key={activeTab} className="page-enter">
        {activeTab === 'overview' && <OverviewTab email={analysis} />}
        {activeTab === 'graph' && <InvestigationGraphTab email={analysis} />}
        {activeTab === 'map' && <InvestigationMapTab email={analysis} />}
        {activeTab === 'headers' && <HeadersTab email={analysis} />}
        {activeTab === 'content' && <ContentTab email={analysis} />}
        {activeTab === 'indicators' && <IndicatorsTab email={analysis} />}
        {activeTab === 'attachments' && <AttachmentsTab email={analysis} />}
        {activeTab === 'raw' && <RawEmailTab email={analysis} />}
      </div>

      {/* 4. CONTEXTUAL COPILOT SLIDE-OVER DRAWER (ON DEMAND) */}
      {isCopilotDrawerOpen && (
        <div className="fixed inset-y-0 right-0 z-50 w-full sm:w-[480px] md:w-[540px] investigation-drawer flex flex-col bg-surface border-l border-border shadow-popover animate-in slide-in-from-right duration-200">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-surface-secondary/80">
            <span className="text-xs font-mono font-bold uppercase text-foreground">
              Investigation Copilot Assistant
            </span>
            <button
              type="button"
              onClick={() => setIsCopilotDrawerOpen(false)}
              className="p-1 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface border border-transparent hover:border-border cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          <div className="flex-1 overflow-y-auto p-3">
            <InvestigationCopilot
              mode="email"
              contextId={analysis.evidence_id || analysis.id || 'E-1042'}
              emailPayload={analysis}
              onOpenGraph={(params) => {
                setIsCopilotDrawerOpen(false);
                handleFocusGraphNode(params?.nodeId || '');
              }}
              onCompareEmails={() => {
                setIsCopilotDrawerOpen(false);
                setActiveTab('cross_investigation');
              }}
              onOpenEvidence={() => {
                setIsCopilotDrawerOpen(false);
                setActiveTab('overview');
              }}
              isCompact={true}
            />
          </div>
        </div>
      )}
    </div>
  );
};

export default EmailForensicView;
