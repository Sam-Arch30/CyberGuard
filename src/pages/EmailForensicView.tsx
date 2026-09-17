import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import type { EmailAnalysis, ForensicTabType } from '../types/forensic';
import { getAnalysisResult, saveAnalysisResult } from '../utils/forensicStore';
import { resolveEmailIndicators, resolveAttribution } from '../utils/indicatorHelper';
import { EmailSummaryHeader } from '../components/forensic/EmailSummaryHeader';
import { InfrastructureAttributionSection } from '../components/forensic/InfrastructureAttributionSection';
import { ForensicTabs } from '../components/forensic/ForensicTabs';
import { OverviewTab } from '../components/forensic/OverviewTab';
import { HeadersTab } from '../components/forensic/HeadersTab';
import { ContentTab } from '../components/forensic/ContentTab';
import { IndicatorsTab } from '../components/forensic/IndicatorsTab';
import { AttachmentsTab } from '../components/forensic/AttachmentsTab';
import { RawEmailTab } from '../components/forensic/RawEmailTab';
import { InvestigationGraphTab } from '../components/forensic/InvestigationGraphTab';
import { InvestigationMapTab } from '../components/forensic/InvestigationMapTab';
import { CrossEmailWorkspace } from '../components/forensic/CrossEmailWorkspace';
import { InvestigationCopilot } from '../components/copilot/InvestigationCopilot';
import { AlertCircle, ArrowLeft, Loader2 } from 'lucide-react';
import { useDemoTour } from '../context/DemoTourContext';

export const EmailForensicView: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { activeTabOverride } = useDemoTour();

  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<ForensicTabType>('overview');
  const [focusedGraphNodeId, setFocusedGraphNodeId] = useState<string | null>(null);

  useEffect(() => {
    if (activeTabOverride) {
      setActiveTab(activeTabOverride as ForensicTabType);
    }
  }, [activeTabOverride]);

  const handleFocusGraphNode = (nodeId: string) => {
    setFocusedGraphNodeId(nodeId);
    setActiveTab('graph');
  };

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
          fetch('/api/emails/ml-classify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              subject: resolved.subject || '',
              body: textToAnalyze || ''
            })
          })
            .then(res => (res.ok ? res.json() : null))
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
        fetch('/api/emails/ai-analyst', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
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

      // Dynamically fetch Attribution if not already cached
      if (!resolved.attribution) {
        fetch('/api/emails/attribution', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
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
        fetch('/api/emails/investigation-graph', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
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

      // Dynamically fetch Explainable Threat Score if not already cached with audit metadata
      if (!resolved.threat_score?.scoring_version || !resolved.threat_score?.audit_metadata) {
        fetch('/api/emails/calculate-threat-score', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(resolved)
        })
          .then(res => (res.ok ? res.json() : null))
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
      fetch(`/api/emails/${targetId}/analysis`)
        .then(res => {
          if (!res.ok) throw new Error('Not found');
          return res.json();
        })
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
    } else {
      setError('No emails analyzed yet. Upload or paste an email in the analysis console to begin.');
      setLoading(false);
    }
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <Loader2 className="w-6 h-6 text-primary animate-spin" />
        <p className="text-xs font-mono text-foreground-muted">
          Loading forensic evidence...
        </p>
      </div>
    );
  }

  if (error || !analysis) {
    return (
      <div className="max-w-xl mx-auto my-12 p-8 bg-surface rounded-xl border border-danger-border text-center space-y-4 shadow-sm">
        <div className="p-3 bg-danger-surface rounded-full w-12 h-12 mx-auto flex items-center justify-center border border-danger-border">
          <AlertCircle className="w-5 h-5 text-danger" />
        </div>
        <h2 className="text-base font-bold text-foreground font-mono">
          Analysis Not Found
        </h2>
        <p className="text-xs font-mono text-foreground-muted">
          {error || 'Unable to load the forensic analysis for this email.'}
        </p>
        <div className="pt-3">
          <button
            type="button"
            onClick={() => navigate('/analyze')}
            className="inline-flex items-center space-x-2 px-3.5 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary text-primary border border-border font-mono text-xs font-medium transition-colors btn-press cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Return to Analyze Email</span>
          </button>
        </div>
      </div>
    );
  }

  const counts = {
    receivedHops: analysis.received?.length || 0,
    urls: analysis.urls?.length || 0,
    attachments: analysis.attachments?.length || analysis.indicators?.attachments?.length || 0,
    relatedEmails: 16,
  };

  return (
    <div className="space-y-6 pb-16">
      {/* 1. EMAIL SUMMARY HEADER */}
      <EmailSummaryHeader email={analysis} />

      {/* 2. FORENSIC TABS */}
      <ForensicTabs
        activeTab={activeTab}
        onTabChange={setActiveTab}
        counts={counts}
      />

      {/* TAB CONTENT VIEWS */}
      <div key={activeTab} className="page-enter">
        {activeTab === 'overview' && (
          <OverviewTab
            email={analysis}
            onFocusGraphNode={handleFocusGraphNode}
            onOpenWorkspace={() => setActiveTab('cross_investigation')}
            onSelectEmail={(selected) => {
              setAnalysis(selected);
              if (selected.id) {
                navigate(`/analysis/${selected.id}`, { replace: true });
              }
            }}
          />
        )}
        {activeTab === 'copilot' && (
          <InvestigationCopilot
            mode="email"
            contextId={analysis.evidence_id || analysis.id || 'E-1042'}
            emailPayload={analysis}
            onOpenGraph={handleFocusGraphNode}
            onCompareEmails={() => setActiveTab('cross_investigation')}
            onOpenEvidence={() => setActiveTab('overview')}
            onSelectEmail={(selected) => {
              setAnalysis(selected);
              if (selected.id) {
                navigate(`/analysis/${selected.id}`, { replace: true });
              }
            }}
          />
        )}
        {activeTab === 'cross_investigation' && (
          <CrossEmailWorkspace
            email={analysis}
            onOpenEmail={(targetId) => {
              navigate(`/analysis/${targetId}`);
            }}
          />
        )}
        {activeTab === 'attribution' && (
          <div className="space-y-6">
            <InfrastructureAttributionSection
              attribution={analysis.attribution || resolveAttribution(analysis)}
              onFocusGraphNode={handleFocusGraphNode}
            />
          </div>
        )}
        {activeTab === 'graph' && (
          <InvestigationGraphTab email={analysis} focusNodeId={focusedGraphNodeId} />
        )}
        {activeTab === 'map' && <InvestigationMapTab email={analysis} />}
        {activeTab === 'headers' && <HeadersTab email={analysis} />}
        {activeTab === 'content' && <ContentTab email={analysis} />}
        {activeTab === 'indicators' && <IndicatorsTab email={analysis} />}
        {activeTab === 'attachments' && <AttachmentsTab email={analysis} />}
        {activeTab === 'raw' && <RawEmailTab email={analysis} />}
      </div>
    </div>
  );
};

export default EmailForensicView;
