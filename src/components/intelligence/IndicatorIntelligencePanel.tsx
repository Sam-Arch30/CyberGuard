import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Globe2,
  RefreshCw,
  Lock,
  ChevronDown,
  ChevronUp,
  History,
  Copy,
  Check,
  Sparkles,
  Eye,
} from 'lucide-react';
import type {
  AggregatedIndicatorIntelligence,
  IndicatorHistoryResponse,
} from '../../types/threatIntelligence';
import { threatIntelligenceService } from '../../services/threatIntelligenceService';
import { QuickWatchModal } from '../watchlists/QuickWatchModal';

interface IndicatorIntelligencePanelProps {
  intelligence: AggregatedIndicatorIntelligence;
  onRefresh?: (updated: AggregatedIndicatorIntelligence) => void;
  className?: string;
  defaultExpanded?: boolean;
}

export const IndicatorIntelligencePanel: React.FC<IndicatorIntelligencePanelProps> = ({
  intelligence,
  onRefresh,
  className = '',
  defaultExpanded = false,
}) => {
  const [data, setData] = useState<AggregatedIndicatorIntelligence>(intelligence);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  const [copied, setCopied] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [historyData, setHistoryData] = useState<IndicatorHistoryResponse | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [showWatchModal, setShowWatchModal] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(data.normalized_value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleRefresh = async () => {
    try {
      setIsRefreshing(true);
      const updated = await threatIntelligenceService.refreshIndicatorIntelligence(
        data.indicator_type,
        data.normalized_value
      );
      setData(updated);
      if (onRefresh) onRefresh(updated);
    } catch (err) {
      console.error('Error refreshing indicator intelligence:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleLoadHistory = async () => {
    try {
      setLoadingHistory(true);
      setShowHistory(true);
      const res = await threatIntelligenceService.getIndicatorHistory(
        data.indicator_type,
        data.normalized_value
      );
      setHistoryData(res);
    } catch (err) {
      console.error('Error loading history:', err);
    } finally {
      setLoadingHistory(false);
    }
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict.toUpperCase()) {
      case 'MALICIOUS':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-danger-surface text-danger border border-danger-border">
            <ShieldAlert className="w-3 h-3 mr-1" />
            MALICIOUS
          </span>
        );
      case 'SUSPICIOUS':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-warning-surface text-warning border border-warning-border">
            <AlertTriangle className="w-3 h-3 mr-1" />
            SUSPICIOUS
          </span>
        );
      case 'CLEAN':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-success-surface text-success border border-success-border">
            <ShieldCheck className="w-3 h-3 mr-1" />
            CLEAN
          </span>
        );
      case 'UNKNOWN':
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-surface-secondary text-foreground-muted border border-border">
            UNKNOWN
          </span>
        );
    }
  };

  const getPrivacyBadge = (scope: string) => {
    switch (scope.toUpperCase()) {
      case 'INTERNAL':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-warning-surface text-warning border border-warning-border" title="Internal / RFC-1918 address: External queries prohibited">
            <Lock className="w-2.5 h-2.5 mr-1" />
            INTERNAL (BLOCKED)
          </span>
        );
      case 'SENSITIVE':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-primary-surface text-primary border border-primary-border" title="PII / Sensitive indicator: External queries restricted">
            <Lock className="w-2.5 h-2.5 mr-1" />
            SENSITIVE PII
          </span>
        );
      case 'PUBLIC':
      default:
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary text-foreground-muted border border-border">
            <Globe2 className="w-2.5 h-2.5 mr-1" />
            PUBLIC
          </span>
        );
    }
  };

  return (
    <div className={`bg-surface border border-border rounded-xl p-4 space-y-3 font-sans transition-all ${className}`}>
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border pb-3">
        <div className="flex items-center space-x-2">
          <span className="px-1.5 py-0.5 rounded bg-surface-secondary text-[10px] font-mono font-semibold text-primary border border-border uppercase">
            {data.indicator_type}
          </span>
          <span className="font-mono text-xs font-bold text-foreground max-w-[260px] truncate" title={data.normalized_value}>
            {data.normalized_value}
          </span>
          <button
            onClick={handleCopy}
            className="p-1 text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
            title="Copy indicator"
          >
            {copied ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
          </button>
          {getPrivacyBadge(data.privacy_scope)}
        </div>

        <div className="flex items-center space-x-2">
          {getVerdictBadge(data.overall_verdict)}
          <button
            onClick={() => setShowWatchModal(true)}
            className="p-1.5 rounded-md bg-surface-secondary hover:bg-surface-secondary/80 text-foreground-muted hover:text-foreground border border-border transition-colors cursor-pointer"
            title="Continuously monitor in a Watchlist"
          >
            <Eye className="w-3.5 h-3.5 text-primary" />
          </button>
          <button
            onClick={handleRefresh}
            disabled={isRefreshing || data.privacy_scope === 'INTERNAL'}
            className="p-1.5 rounded-md bg-surface-secondary hover:bg-surface-secondary/80 text-foreground-muted hover:text-foreground border border-border transition-colors disabled:opacity-40 cursor-pointer"
            title="Force refresh intelligence from providers"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin text-primary' : ''}`} />
          </button>
        </div>
      </div>

      {/* Conflicting Intelligence Warning Banner */}
      {data.is_conflicting && (
        <div className="p-2.5 rounded-lg bg-warning-surface border border-warning-border flex items-start space-x-2 text-xs font-mono text-warning">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <div className="space-y-0.5">
            <span className="font-bold block">Conflicting External Intelligence Detected</span>
            <span className="text-[11px] block text-warning/90">{data.conflict_summary}</span>
          </div>
        </div>
      )}

      {/* Summary Metrics Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono bg-surface-secondary/40 p-2.5 rounded-lg border border-border/60">
        <div>
          <span className="text-[10px] text-foreground-muted block">Confidence:</span>
          <div className="flex items-center space-x-1.5 mt-0.5">
            <div className="w-12 h-1.5 bg-surface-secondary rounded-full overflow-hidden border border-border">
              <div
                className={`h-full ${
                  data.overall_verdict === 'MALICIOUS'
                    ? 'bg-danger'
                    : data.overall_verdict === 'SUSPICIOUS'
                    ? 'bg-warning'
                    : 'bg-primary'
                }`}
                style={{ width: `${Math.round(data.consensus_confidence * 100)}%` }}
              />
            </div>
            <span className="font-bold text-foreground">
              {Math.round(data.consensus_confidence * 100)}%
            </span>
          </div>
        </div>

        <div>
          <span className="text-[10px] text-foreground-muted block">Sources Queried:</span>
          <span className="font-bold text-foreground mt-0.5 block">
            {data.total_sources_queried} provider(s)
          </span>
        </div>

        <div>
          <span className="text-[10px] text-foreground-muted block">Last Refreshed:</span>
          <span className="text-[11px] text-foreground mt-0.5 block truncate" title={data.last_refreshed_at}>
            {new Date(data.last_refreshed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
          </span>
        </div>

        <div>
          <span className="text-[10px] text-foreground-muted block">Internal Memory:</span>
          <span className="mt-0.5 block">
            {data.internal_memory_matched ? (
              <span className="text-success font-semibold flex items-center">
                <Sparkles className="w-2.5 h-2.5 mr-1" /> Matched
              </span>
            ) : (
              <span className="text-foreground-muted">No historical entry</span>
            )}
          </span>
        </div>
      </div>

      {/* Threat Types / Tags */}
      {data.threat_types.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center">
          <span className="text-[10px] font-mono text-foreground-muted">Threat Associations:</span>
          {data.threat_types.map((tt, i) => (
            <span
              key={i}
              className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-danger-surface text-danger border border-danger-border"
            >
              {tt}
            </span>
          ))}
        </div>
      )}

      {/* Progressive Disclosure Toggle */}
      <div className="flex items-center justify-between pt-1 border-t border-border/50">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center space-x-1.5 text-xs font-mono text-primary hover:text-primary-hover font-semibold transition-colors cursor-pointer"
        >
          <span>{isExpanded ? 'Hide Provider Breakdown' : 'Show Provider Breakdown'}</span>
          {isExpanded ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
        </button>

        <button
          onClick={handleLoadHistory}
          className="flex items-center space-x-1 text-xs font-mono text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
        >
          <History className="w-3 h-3" />
          <span>Timeline History</span>
        </button>
      </div>

      {/* Expanded Provider Breakdown Details */}
      {isExpanded && (
        <div className="space-y-2 pt-2 border-t border-border/70 animate-in fade-in duration-200">
          <h4 className="text-[11px] font-mono font-bold text-foreground uppercase tracking-wider">
            Provider Breakdown ({data.providers_data.length})
          </h4>

          {data.providers_data.length === 0 ? (
            <div className="p-3 bg-surface-secondary/40 rounded border border-border text-center text-xs font-mono text-foreground-muted">
              No individual provider responses recorded.
            </div>
          ) : (
            <div className="space-y-2">
              {data.providers_data.map((prov, idx) => (
                <div
                  key={idx}
                  className="p-2.5 bg-surface-secondary/50 border border-border rounded-lg text-xs font-mono space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-foreground flex items-center space-x-1.5">
                      <span>{prov.display_name}</span>
                      <span className="text-[10px] font-normal text-foreground-muted">({prov.provider})</span>
                    </span>
                    <div className="flex items-center space-x-2">
                      {getVerdictBadge(prov.verdict)}
                      <span className="text-[11px] font-bold text-foreground">
                        {Math.round(prov.confidence * 100)}%
                      </span>
                    </div>
                  </div>

                  {prov.details && (
                    <p className="text-[11px] text-foreground-muted leading-relaxed">
                      {prov.details}
                    </p>
                  )}

                  <div className="flex items-center justify-between text-[10px] text-foreground-muted/80 pt-1">
                    <span>
                      Observed: {prov.observed_at ? new Date(prov.observed_at).toLocaleDateString() : 'Recent'}
                    </span>
                    <span>
                      Retrieved: {new Date(prov.retrieved_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Observation History Modal */}
      {showHistory && (
        <div className="fixed inset-0 z-50 bg-background/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-5 space-y-4 max-h-[85vh] overflow-y-auto shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2">
                <History className="w-4 h-4 text-primary" />
                <h3 className="font-sans font-bold text-sm text-foreground">
                  Observation Timeline: {data.normalized_value}
                </h3>
              </div>
              <button
                onClick={() => setShowHistory(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer text-sm font-bold"
              >
                ✕
              </button>
            </div>

            {loadingHistory ? (
              <div className="p-8 text-center text-xs font-mono text-foreground-muted">
                Loading historical observations...
              </div>
            ) : !historyData || historyData.history.length === 0 ? (
              <div className="p-6 text-center text-xs font-mono text-foreground-muted">
                No past historical observations recorded for this observable.
              </div>
            ) : (
              <div className="space-y-3">
                <div className="text-xs font-mono text-foreground-muted">
                  Total Observations: <strong>{historyData.total_observations}</strong>
                </div>
                <div className="border-l-2 border-border pl-3 space-y-3">
                  {historyData.history.map((h, i) => (
                    <div key={i} className="text-xs font-mono space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-foreground">{h.provider}</span>
                        {getVerdictBadge(h.verdict)}
                      </div>
                      <div className="text-[11px] text-foreground-muted">
                        {new Date(h.timestamp).toLocaleString()} ({h.source_type})
                      </div>
                      {h.summary && (
                        <p className="text-[11px] text-foreground-muted/90 bg-surface-secondary/40 p-1.5 rounded">
                          {h.summary}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Quick Watch Modal */}
      <QuickWatchModal
        isOpen={showWatchModal}
        onClose={() => setShowWatchModal(false)}
        indicatorValue={data.normalized_value}
        indicatorType={data.indicator_type}
      />
    </div>
  );
};
