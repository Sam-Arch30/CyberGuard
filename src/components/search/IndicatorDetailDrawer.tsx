import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  X,
  Globe,
  Server,
  Lock,
  Link as LinkIcon,
  Mail,
  Copy,
  Check,
  ExternalLink,
  Loader2,
  AlertCircle,
  Tag,
} from 'lucide-react';
import type { CrossInvestigationIndicatorResponse } from '../../types/search';
import { searchService } from '../../services/searchService';

interface IndicatorDetailDrawerProps {
  indicatorValue: string | null;
  onClose: () => void;
}

export const IndicatorDetailDrawer: React.FC<IndicatorDetailDrawerProps> = ({
  indicatorValue,
  onClose,
}) => {
  const navigate = useNavigate();
  const [data, setData] = useState<CrossInvestigationIndicatorResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'CURRENT' | 'HISTORICAL' | 'EXTERNAL' | 'ANALYST'>('CURRENT');

  useEffect(() => {
    if (!indicatorValue) {
      setData(null);
      return;
    }
    let isCancelled = false;
    setLoading(true);
    setError(null);

    searchService
      .lookupIndicator(indicatorValue)
      .then((res) => {
        if (!isCancelled) setData(res);
      })
      .catch((err) => {
        if (!isCancelled) setError(err?.message || 'Failed to lookup indicator history');
      })
      .finally(() => {
        if (!isCancelled) setLoading(false);
      });

    return () => {
      isCancelled = true;
    };
  }, [indicatorValue]);

  if (!indicatorValue) return null;

  const handleCopy = () => {
    navigator.clipboard.writeText(indicatorValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getIndicatorIcon = (type?: string) => {
    switch (type?.toUpperCase()) {
      case 'IP':
        return <Server className="w-4 h-4 text-primary" />;
      case 'DOMAIN':
        return <Globe className="w-4 h-4 text-primary" />;
      case 'URL':
        return <LinkIcon className="w-4 h-4 text-danger" />;
      case 'HASH':
      case 'FILE_HASH':
        return <Lock className="w-4 h-4 text-warning" />;
      case 'EMAIL':
      case 'EMAIL_ADDRESS':
        return <Mail className="w-4 h-4 text-primary" />;
      default:
        return <Tag className="w-4 h-4 text-primary" />;
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-xs flex justify-end animate-in fade-in duration-150">
      <div className="w-full max-w-xl bg-surface border-l border-border h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-border flex items-start justify-between gap-3 bg-surface-secondary/40">
          <div className="space-y-1 min-w-0">
            <div className="flex items-center space-x-2 text-[10px] font-mono font-bold text-primary uppercase tracking-wider">
              {getIndicatorIcon(data?.indicator_type)}
              <span>CROSS-INVESTIGATION INDICATOR INTELLIGENCE</span>
            </div>
            <div className="flex items-center space-x-2">
              <h3 className="text-base sm:text-lg font-bold font-mono text-foreground truncate select-all" title={indicatorValue}>
                {indicatorValue}
              </h3>
              <button
                type="button"
                onClick={handleCopy}
                className="p-1 rounded hover:bg-surface text-foreground-muted hover:text-foreground cursor-pointer shrink-0"
                title="Copy indicator value"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            {data && (
              <div className="flex items-center space-x-2 pt-0.5 text-xs font-mono">
                <span className="px-2 py-0.5 rounded bg-surface border border-border text-[10px] font-bold text-primary uppercase">
                  {data.indicator_type}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                  data.reputation === 'MALICIOUS' ? 'bg-danger/15 text-danger' :
                  data.reputation === 'SUSPICIOUS' ? 'bg-warning/15 text-warning' :
                  'bg-surface-secondary text-foreground-muted'
                }`}>
                  {data.reputation || 'SUSPICIOUS'}
                </span>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground cursor-pointer shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-5">
          {loading ? (
            <div className="p-12 text-center font-mono text-xs text-foreground-muted space-y-2">
              <Loader2 className="w-6 h-6 animate-spin mx-auto text-primary" />
              <p>Correlating indicator across investigations and Threat Memory...</p>
            </div>
          ) : error ? (
            <div className="p-4 rounded-xl bg-danger/10 border border-danger/30 text-xs font-mono text-danger space-y-1">
              <AlertCircle className="w-4 h-4 inline mr-1" />
              <span>{error}</span>
            </div>
          ) : !data ? null : (
            <>
              {/* Summary Metric Cards */}
              <div className="grid grid-cols-3 gap-2.5 font-mono text-xs">
                <div className="p-3 rounded-xl bg-surface-secondary border border-border space-y-0.5">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Investigations</span>
                  <span className="text-xl font-bold text-primary">{data.total_investigations}</span>
                  <span className="text-[9px] text-foreground-muted block">Linked incidents</span>
                </div>
                <div className="p-3 rounded-xl bg-surface-secondary border border-border space-y-0.5">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Campaigns</span>
                  <span className="text-xl font-bold text-warning">{data.total_campaigns}</span>
                  <span className="text-[9px] text-foreground-muted block">Cluster overlap</span>
                </div>
                <div className="p-3 rounded-xl bg-surface-secondary border border-border space-y-0.5">
                  <span className="text-[10px] uppercase text-foreground-muted block font-semibold">Evidence</span>
                  <span className="text-xl font-bold text-foreground">{data.total_evidence_objects}</span>
                  <span className="text-[9px] text-foreground-muted block">Artifact files</span>
                </div>
              </div>

              {/* Observation Chronology */}
              <div className="p-3 rounded-xl bg-surface-secondary/40 border border-border font-mono text-xs flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-foreground-muted uppercase font-bold block">First Observed</span>
                  <span className="text-foreground text-[11px]">
                    {data.first_observed_at ? new Date(data.first_observed_at).toLocaleDateString() : 'Active session'}
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-[10px] text-foreground-muted uppercase font-bold block">Last Observed</span>
                  <span className="text-foreground text-[11px]">
                    {data.last_observed_at ? new Date(data.last_observed_at).toLocaleDateString() : 'Active session'}
                  </span>
                </div>
              </div>

              {/* Provenance Tab Navigation (Section 25 Contract) */}
              <div className="space-y-3">
                <div className="flex items-center space-x-1 border-b border-border pb-1 overflow-x-auto text-[11px] font-mono">
                  <button
                    type="button"
                    onClick={() => setActiveTab('CURRENT')}
                    className={`px-3 py-1 rounded-md font-bold transition-all cursor-pointer ${
                      activeTab === 'CURRENT'
                        ? 'bg-primary/15 text-primary border border-primary/30'
                        : 'text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    Current Investigations ({data.related_investigations.length})
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('HISTORICAL')}
                    className={`px-3 py-1 rounded-md font-bold transition-all cursor-pointer ${
                      activeTab === 'HISTORICAL'
                        ? 'bg-primary/15 text-primary border border-primary/30'
                        : 'text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    Historical Memory
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('EXTERNAL')}
                    className={`px-3 py-1 rounded-md font-bold transition-all cursor-pointer ${
                      activeTab === 'EXTERNAL'
                        ? 'bg-primary/15 text-primary border border-primary/30'
                        : 'text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    External Intel
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('ANALYST')}
                    className={`px-3 py-1 rounded-md font-bold transition-all cursor-pointer ${
                      activeTab === 'ANALYST'
                        ? 'bg-primary/15 text-primary border border-primary/30'
                        : 'text-foreground-muted hover:text-foreground'
                    }`}
                  >
                    Analyst Verified ({data.analyst_verifications.length})
                  </button>
                </div>

                {/* Tab 1: Current Investigations */}
                {activeTab === 'CURRENT' && (
                  <div className="space-y-2 font-mono text-xs">
                    {data.related_investigations.length === 0 ? (
                      <p className="text-foreground-muted text-[11px] py-4 text-center">
                        No active investigations directly link this indicator.
                      </p>
                    ) : (
                      data.related_investigations.map((rel, idx) => (
                        <div
                          key={idx}
                          onClick={() => {
                            navigate(`/investigations/${rel.investigation_id}`);
                            onClose();
                          }}
                          className="p-3 rounded-xl bg-surface border border-border hover:border-primary/40 flex items-center justify-between gap-3 cursor-pointer transition-all shadow-xs"
                        >
                          <div className="min-w-0 space-y-0.5">
                            <div className="flex items-center space-x-2">
                              <span className="font-bold text-primary text-[11px]">{rel.incident_number}</span>
                              <span className={`px-1.5 py-0.2 rounded text-[9px] font-bold uppercase ${
                                rel.severity === 'CRITICAL' ? 'bg-danger/15 text-danger' :
                                rel.severity === 'HIGH' ? 'bg-warning/15 text-warning' :
                                'bg-surface-secondary text-foreground-muted'
                              }`}>
                                {rel.severity}
                              </span>
                            </div>
                            <div className="font-semibold text-foreground text-xs truncate font-sans">
                              {rel.title}
                            </div>
                            <div className="text-[10px] text-foreground-muted">
                              {new Date(rel.observed_at).toLocaleString()} · {rel.source}
                            </div>
                          </div>
                          <ExternalLink className="w-3.5 h-3.5 text-foreground-muted hover:text-primary shrink-0" />
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Tab 2: Historical Threat Memory */}
                {activeTab === 'HISTORICAL' && (
                  <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-3 font-mono text-xs">
                    {data.historical_memory ? (
                      <>
                        <div className="flex items-center justify-between border-b border-border pb-2">
                          <span className="font-bold text-foreground">Section 23 Threat Memory Record</span>
                          <span className="px-2 py-0.5 rounded bg-success/15 text-success font-bold text-[10px]">
                            {data.historical_memory.status}
                          </span>
                        </div>
                        <p className="text-[11px] text-foreground-muted leading-relaxed">
                          {data.historical_memory.summary || 'Historical correlation established across prior ingestion pipelines.'}
                        </p>
                        <div className="grid grid-cols-2 gap-2 text-[10px] text-foreground-muted pt-1">
                          <div>Provenance: <strong className="text-foreground">{data.historical_memory.provenance_type}</strong></div>
                          <div>Confidence: <strong className="text-primary">{Math.round((data.historical_memory.confidence || 1) * 100)}%</strong></div>
                        </div>
                      </>
                    ) : (
                      <p className="text-foreground-muted text-[11px] py-2 text-center">
                        No persistent Threat Memory entry recorded for this indicator.
                      </p>
                    )}
                  </div>
                )}

                {/* Tab 3: External Intelligence */}
                {activeTab === 'EXTERNAL' && (
                  <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-2 font-mono text-xs">
                    <span className="font-bold text-foreground block">OSINT & Reputation Telemetry</span>
                    <p className="text-[11px] text-foreground-muted leading-relaxed">
                      Reputation verdict evaluated as <strong className="text-warning">{data.reputation || 'SUSPICIOUS'}</strong> based on autonomous threat feeds and heuristic classifiers.
                    </p>
                    <div className="text-[10px] text-foreground-muted pt-1">
                      Providers reporting: <strong className="text-foreground">{data.external_intelligence?.providers_reporting ?? 1}</strong>
                    </div>
                  </div>
                )}

                {/* Tab 4: Analyst Verified */}
                {activeTab === 'ANALYST' && (
                  <div className="space-y-2 font-mono text-xs">
                    {data.analyst_verifications.length === 0 ? (
                      <p className="text-foreground-muted text-[11px] py-4 text-center">
                        No manual analyst verifications recorded for this indicator yet.
                      </p>
                    ) : (
                      data.analyst_verifications.map((v, i) => (
                        <div key={i} className="p-3 rounded-xl bg-surface border border-border space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="font-bold text-primary">{v.decision}</span>
                            <span className="text-[10px] text-foreground-muted">{v.timestamp || 'Recent'}</span>
                          </div>
                          <p className="text-[11px] text-foreground-muted">{v.source}</p>
                        </div>
                      ))
                    )}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
