import React, { useState } from 'react';
import {
  Link2,
  ShieldAlert,
  AlertTriangle,
  Layers,
  Search,
  Info
} from 'lucide-react';
import type { EmailAnalysis, URLAnalysisResult } from '../../types/forensic';
import { resolveConfidenceConclusions } from '../../utils/confidenceResolver';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { CopyButton } from './CopyButton';

interface URLAnalysisSectionProps {
  email: EmailAnalysis;
}

export const URLAnalysisSection: React.FC<URLAnalysisSectionProps> = ({ email }) => {
  const [filter, setFilter] = useState<'all' | 'suspicious' | 'mismatch' | 'shortener'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const conclusions =
    email.forensic_conclusions && email.forensic_conclusions.length > 0
      ? email.forensic_conclusions
      : resolveConfidenceConclusions(email);
  const urlConclusion = conclusions.find((c) => c.type === 'malicious_url');

  const urlList: URLAnalysisResult[] = email.url_analysis || [];

  // Filtered list
  const filteredUrls = urlList.filter(item => {
    // Search query
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchesUrl = item.url.toLowerCase().includes(q);
      const matchesDomain = item.domain.toLowerCase().includes(q);
      const matchesKw = item.features.suspicious_keywords.some(k => k.toLowerCase().includes(q));
      if (!matchesUrl && !matchesDomain && !matchesKw) return false;
    }

    // Category filter
    if (filter === 'suspicious') {
      return item.suspicion_score >= 25;
    }
    if (filter === 'mismatch') {
      return item.features.display_link_mismatch;
    }
    if (filter === 'shortener') {
      return item.features.is_shortener;
    }
    return true;
  });

  const mismatchCount = urlList.filter(u => u.features.display_link_mismatch).length;
  const suspiciousCount = urlList.filter(u => u.suspicion_score >= 25).length;
  const shortenerCount = urlList.filter(u => u.features.is_shortener).length;

  const getScoreBadge = (score: number, level: string) => {
    if (score >= 60 || level === 'high') {
      return {
        bg: 'bg-danger-surface border-danger-border text-danger',
        dot: 'bg-danger',
        label: 'High Suspicion'
      };
    }
    if (score >= 25 || level === 'suspicious') {
      return {
        bg: 'bg-warning-surface border-warning-border text-warning',
        dot: 'bg-warning',
        label: 'Suspicious'
      };
    }
    return {
      bg: 'bg-success-surface border-success-border text-success',
      dot: 'bg-success',
      label: 'Low Suspicion'
    };
  };

  return (
    <div className="bg-surface p-5 rounded-card border border-border space-y-4 shadow-sm">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border gap-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-1.5 rounded-control bg-primary/10 border border-primary/20 text-primary">
            <Link2 className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">
              Static URL Forensic Analysis ({urlList.length})
            </h3>
            <p className="text-[11px] text-foreground-muted">
              Non-invasive syntactic feature inspection. URLs remain non-clickable for security.
            </p>
          </div>
        </div>

        {/* Confidence & Safety Badges */}
        <div className="flex items-center space-x-2">
          {urlConclusion && (
            <ConfidenceBadge
              conclusion={urlConclusion}
              allConclusions={conclusions}
              size="sm"
            />
          )}
          <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-surface-secondary border border-border text-[10px] font-mono text-foreground-muted">
            <span className="w-1.5 h-1.5 rounded-full bg-primary" />
            <span>No external requests made</span>
          </div>
        </div>
      </div>

      {/* Metrics Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <div className="p-2.5 rounded-control border border-border bg-surface-secondary/50 flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-foreground-muted">Total Analyzed</span>
          <span className="text-lg font-mono font-bold text-foreground">{urlList.length}</span>
        </div>

        <div className={`p-2.5 rounded-control border flex flex-col justify-between ${
          mismatchCount > 0
            ? 'border-danger-border bg-danger-surface text-danger'
            : 'border-border bg-surface-secondary/50 text-foreground'
        }`}>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase">Link Mismatches</span>
            {mismatchCount > 0 && <ShieldAlert className="w-3.5 h-3.5 text-danger" />}
          </div>
          <span className="text-lg font-mono font-bold">{mismatchCount}</span>
        </div>

        <div className={`p-2.5 rounded-control border flex flex-col justify-between ${
          suspiciousCount > 0
            ? 'border-warning-border bg-warning-surface text-warning'
            : 'border-border bg-surface-secondary/50 text-foreground'
        }`}>
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase">Suspicious (Score &ge;25)</span>
            {suspiciousCount > 0 && <AlertTriangle className="w-3.5 h-3.5 text-warning" />}
          </div>
          <span className="text-lg font-mono font-bold">{suspiciousCount}</span>
        </div>

        <div className="p-2.5 rounded-control border border-border bg-surface-secondary/50 flex flex-col justify-between">
          <span className="text-[10px] font-mono uppercase text-foreground-muted">URL Shorteners</span>
          <span className="text-lg font-mono font-bold text-foreground">{shortenerCount}</span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-2.5 pt-1">
        <div className="flex flex-wrap items-center gap-1.5 w-full sm:w-auto">
          <button
            type="button"
            onClick={() => setFilter('all')}
            className={`px-3 py-1 rounded-control text-xs font-mono transition-colors cursor-pointer ${
              filter === 'all'
                ? 'bg-primary/10 border border-primary text-primary font-bold'
                : 'bg-surface-secondary border border-border text-foreground-muted hover:text-foreground'
            }`}
          >
            All ({urlList.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter('suspicious')}
            className={`px-3 py-1 rounded-control text-xs font-mono transition-colors cursor-pointer ${
              filter === 'suspicious'
                ? 'bg-warning-surface border border-warning-border text-warning font-bold'
                : 'bg-surface-secondary border border-border text-foreground-muted hover:text-foreground'
            }`}
          >
            Suspicious ({suspiciousCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter('mismatch')}
            className={`px-3 py-1 rounded-control text-xs font-mono transition-colors cursor-pointer ${
              filter === 'mismatch'
                ? 'bg-danger-surface border border-danger-border text-danger font-bold'
                : 'bg-surface-secondary border border-border text-foreground-muted hover:text-foreground'
            }`}
          >
            Link Mismatches ({mismatchCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter('shortener')}
            className={`px-3 py-1 rounded-control text-xs font-mono transition-colors cursor-pointer ${
              filter === 'shortener'
                ? 'bg-primary/10 border border-primary text-primary font-bold'
                : 'bg-surface-secondary border border-border text-foreground-muted hover:text-foreground'
            }`}
          >
            Shorteners ({shortenerCount})
          </button>
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-foreground-muted" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Filter URLs or domains..."
            className="w-full pl-8 pr-3 py-1 bg-surface-secondary border border-border rounded-control text-xs font-mono text-foreground placeholder:text-foreground-subtle focus:outline-none focus:border-primary"
          />
        </div>
      </div>

      {/* URL Cards List */}
      {filteredUrls.length === 0 ? (
        <div className="p-8 text-center rounded-card border border-border bg-surface-secondary/30">
          <p className="text-xs font-mono text-foreground-muted">
            {urlList.length === 0
              ? 'No URLs extracted from this email.'
              : 'No URLs match the selected filter criteria.'}
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {filteredUrls.map((item, idx) => {
            const badge = getScoreBadge(item.suspicion_score, item.suspicion_level);
            const { features } = item;

            return (
              <div
                key={idx}
                className={`p-4 rounded-card border transition-all ${
                  features.display_link_mismatch
                    ? 'border-danger-border/70 bg-danger-surface/20'
                    : item.suspicion_score >= 25
                    ? 'border-warning-border/70 bg-warning-surface/20'
                    : 'border-border bg-surface-secondary/40 hover:bg-surface-secondary/60'
                }`}
              >
                {/* Header Row: Domain, Score Gauge, Level */}
                <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-mono font-bold text-foreground">
                      {item.domain}
                    </span>
                    {features.registered_domain && features.registered_domain !== item.domain && (
                      <span className="text-[10px] font-mono text-foreground-muted">
                        (Apex: {features.registered_domain})
                      </span>
                    )}
                    {features.is_ip_host && (
                      <span className="px-1.5 py-0.5 rounded-control text-[10px] font-mono bg-warning-surface border border-warning-border text-warning">
                        IPv{features.ip_version} Direct IP
                      </span>
                    )}
                    {features.is_shortener && (
                      <span className="px-1.5 py-0.5 rounded-control text-[10px] font-mono bg-primary/10 border border-primary/30 text-primary">
                        Shortener
                      </span>
                    )}
                    {features.is_punycode && (
                      <span className="px-1.5 py-0.5 rounded-control text-[10px] font-mono bg-primary/10 border border-primary/30 text-primary">
                        Punycode
                      </span>
                    )}
                  </div>

                  <div className="flex items-center space-x-2">
                    {/* Static URL Score Badge */}
                    <div className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-full border text-xs font-mono font-bold ${badge.bg}`}>
                      <span className={`w-2 h-2 rounded-full ${badge.dot}`} />
                      <span>Score: {item.suspicion_score}/100</span>
                      <span className="text-[10px] opacity-80 font-normal">({badge.label})</span>
                    </div>
                  </div>
                </div>

                {/* HTML Display Link Mismatch Banner */}
                {features.display_link_mismatch && (
                  <div className="mt-3 p-3 rounded-control border border-danger-border bg-danger-surface text-danger flex items-start space-x-2.5">
                    <ShieldAlert className="w-4 h-4 text-danger shrink-0 mt-0.5" />
                    <div className="space-y-1">
                      <div className="text-xs font-mono font-bold text-danger">
                        HTML Display Link Mismatch Detected
                      </div>
                      <p className="text-xs font-mono text-foreground">
                        Visible text claimed <span className="font-bold underline text-foreground">{features.visible_text_domain || features.visible_text}</span>, but the actual destination points to <span className="font-bold underline text-danger">{item.domain}</span>.
                      </p>
                    </div>
                  </div>
                )}

                {/* Non-Clickable URL Presentation */}
                <div className="mt-3 p-3 rounded-control border border-border bg-surface flex items-center justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="text-[10px] font-mono uppercase text-foreground-muted mb-1">
                      Observed URL (Safe Non-Clickable View)
                    </div>
                    {/* Plain non-clickable select-all text */}
                    <span className="text-xs font-mono text-foreground select-all break-all select-text font-medium">
                      {item.url}
                    </span>
                  </div>
                  {/* Copy button only */}
                  <CopyButton text={item.url} label="Copy URL" />
                </div>

                {/* Features Grid */}
                <div className="mt-3 pt-3 border-t border-border">
                  <div className="text-[10px] font-mono uppercase text-foreground-muted mb-2 font-semibold">
                    Extracted Non-Invasive Features
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-2 text-xs font-mono">
                    <div className="p-2 rounded-control bg-surface-secondary border border-border">
                      <span className="text-foreground-muted block text-[10px]">Scheme</span>
                      <span className="text-foreground font-semibold">{features.scheme.toUpperCase()}</span>
                    </div>
                    <div className="p-2 rounded-control bg-surface-secondary border border-border">
                      <span className="text-foreground-muted block text-[10px]">Port</span>
                      <span className={features.has_non_standard_port ? 'text-warning font-semibold' : 'text-foreground'}>
                        {features.port !== null && features.port !== undefined ? features.port : 'Default'}
                        {features.has_non_standard_port ? ' (Non-std)' : ''}
                      </span>
                    </div>
                    <div className="p-2 rounded-control bg-surface-secondary border border-border">
                      <span className="text-foreground-muted block text-[10px]">Subdomain Count</span>
                      <span className={features.excessive_subdomains ? 'text-warning font-semibold' : 'text-foreground'}>
                        {features.subdomain_count} {features.excessive_subdomains ? '(High)' : ''}
                      </span>
                    </div>
                    <div className="p-2 rounded-control bg-surface-secondary border border-border">
                      <span className="text-foreground-muted block text-[10px]">Total Length</span>
                      <span className={features.total_length > 150 ? 'text-warning font-semibold' : 'text-foreground'}>
                        {features.total_length} chars
                      </span>
                    </div>
                    <div className="p-2 rounded-control bg-surface-secondary border border-border">
                      <span className="text-foreground-muted block text-[10px]">Path / Query Len</span>
                      <span className="text-foreground">
                        {features.path_length} / {features.query_length}
                      </span>
                    </div>
                    <div className="p-2 rounded-control bg-surface-secondary border border-border">
                      <span className="text-foreground-muted block text-[10px]">Percent Encoded</span>
                      <span className={features.percent_encoding_count >= 3 ? 'text-warning font-semibold' : 'text-foreground'}>
                        {features.percent_encoding_count > 0 ? `${features.percent_encoding_count} sequences` : 'None'}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Suspicious Keywords Pills */}
                {features.suspicious_keywords.length > 0 && (
                  <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
                    <span className="text-[10px] font-mono text-foreground-muted mr-1">Suspicious Keywords:</span>
                    {features.suspicious_keywords.map((kw, kwIdx) => (
                      <span
                        key={kwIdx}
                        className="px-2 py-0.5 rounded-control text-[11px] font-mono bg-warning-surface border border-warning-border text-warning"
                      >
                        {kw}
                      </span>
                    ))}
                  </div>
                )}

                {/* Lookalike Detection Finding if Present */}
                {features.lookalike && (
                  <div className="mt-2.5 p-2.5 rounded-control bg-warning-surface border border-warning-border flex items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <ShieldAlert className="w-3.5 h-3.5 text-warning shrink-0" />
                      <span className="text-xs font-mono text-warning font-semibold">
                        Potential {features.lookalike.brand_name} impersonation ({Math.round(features.lookalike.similarity * 100)}% match)
                      </span>
                    </div>
                    <div className="flex items-center space-x-1.5">
                      {features.lookalike.techniques.map((tech, tIdx) => (
                        <span key={tIdx} className="px-1.5 py-0.5 rounded-control text-[10px] font-mono bg-surface text-warning border border-warning-border">
                          {tech.replace(/_/g, ' ')}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Score Reasons & Observations */}
                {(item.score_reasons.length > 0 || item.observations.length > 0) && (
                  <div className="mt-3 pt-3 border-t border-border grid grid-cols-1 md:grid-cols-2 gap-3">
                    {/* Score Reasons */}
                    {item.score_reasons.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-[10px] font-mono uppercase text-foreground-muted font-semibold flex items-center space-x-1">
                          <Info className="w-3 h-3 text-primary" />
                          <span>Score Contributions</span>
                        </span>
                        <ul className="space-y-1">
                          {item.score_reasons.map((reason, rIdx) => (
                            <li key={rIdx} className="text-xs font-mono text-foreground flex items-center space-x-1.5">
                              <span className="w-1 h-1 rounded-full bg-primary shrink-0" />
                              <span>{reason}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {/* Observations */}
                    {item.observations.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-[10px] font-mono uppercase text-foreground-muted font-semibold flex items-center space-x-1">
                          <Layers className="w-3 h-3 text-primary" />
                          <span>Forensic Observations</span>
                        </span>
                        <ul className="space-y-1">
                          {item.observations.map((obs, oIdx) => (
                            <li key={oIdx} className="text-xs font-mono text-foreground-muted flex items-start space-x-1.5">
                              <span className="w-1 h-1 rounded-full bg-foreground-subtle shrink-0 mt-1.5" />
                              <span>{obs}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
