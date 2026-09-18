import React, { useState } from 'react';
import {
  Link2,
  ShieldAlert,
  AlertTriangle,
  Search
} from 'lucide-react';
import type { EmailAnalysis, URLAnalysisResult } from '../../types/forensic';
import { resolveConfidenceConclusions } from '../../utils/confidenceResolver';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { CopyButton } from './CopyButton';
import { StatusRow, DetailDrawer, MetadataRow, ExpandableSection } from '../common/progressive';

interface URLAnalysisSectionProps {
  email: EmailAnalysis;
}

const defang = (val?: string): string => {
  if (!val) return '';
  return val
    .replace(/\./g, '[.]')
    .replace(/http:\/\//g, 'hxxp://')
    .replace(/https:\/\//g, 'hxxps://');
};

export const URLAnalysisSection: React.FC<URLAnalysisSectionProps> = ({ email }) => {
  const [filter, setFilter] = useState<'all' | 'suspicious' | 'mismatch' | 'shortener'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedRawUrl, setSelectedRawUrl] = useState<URLAnalysisResult | null>(null);

  const conclusions =
    email.forensic_conclusions && email.forensic_conclusions.length > 0
      ? email.forensic_conclusions
      : resolveConfidenceConclusions(email);
  const urlConclusion = conclusions.find((c) => c.type === 'malicious_url');

  const urlList: URLAnalysisResult[] = email.url_analysis || [];

  // Filtered list
  const filteredUrls = urlList.filter(item => {
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      const matchesUrl = item.url.toLowerCase().includes(q);
      const matchesDomain = item.domain.toLowerCase().includes(q);
      const matchesKw = item.features.suspicious_keywords.some(k => k.toLowerCase().includes(q));
      if (!matchesUrl && !matchesDomain && !matchesKw) return false;
    }

    if (filter === 'suspicious') return item.suspicion_score >= 25;
    if (filter === 'mismatch') return item.features.display_link_mismatch;
    if (filter === 'shortener') return item.features.is_shortener;
    return true;
  });

  const mismatchCount = urlList.filter(u => u.features.display_link_mismatch).length;
  const suspiciousCount = urlList.filter(u => u.suspicion_score >= 25).length;
  const shortenerCount = urlList.filter(u => u.features.is_shortener).length;

  return (
    <div className="space-y-5">
      <ExpandableSection
        title={`Static URL Forensic Analysis (${urlList.length})`}
        subtitle="Non-invasive syntactic feature inspection. URLs remain non-clickable for security."
        icon={Link2}
        defaultExpanded={true}
        badge={
          <div className="flex items-center space-x-2">
            {urlConclusion && (
              <ConfidenceBadge
                conclusion={urlConclusion}
                allConclusions={conclusions}
                size="sm"
              />
            )}
            <span className="px-2 py-0.5 rounded-full bg-surface-secondary border border-border text-[10px] font-mono text-foreground-muted hidden sm:inline-block">
              Zero External Network Requests
            </span>
          </div>
        }
      >
        <div className="space-y-4">
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
                <span className="text-[10px] font-mono uppercase">Suspicious (&ge;25)</span>
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
              >
              </input>
            </div>
          </div>

          {/* Progressive URL Rows */}
          {filteredUrls.length === 0 ? (
            <div className="p-6 text-center rounded-xl border border-border bg-surface-secondary/30">
              <p className="text-xs font-mono text-foreground-muted">
                {urlList.length === 0
                  ? 'No URLs extracted from this email.'
                  : 'No URLs match the selected filter criteria.'}
              </p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {filteredUrls.map((item, idx) => {
                const { features } = item;
                const isCrit = item.suspicion_score >= 60;
                const isSusp = item.suspicion_score >= 25 || features.display_link_mismatch;
                const statusState = isCrit ? 'FAIL' : isSusp ? 'WARN' : 'PASS';
                const statusLabel = isCrit
                  ? `RISK ${item.suspicion_score}/100`
                  : isSusp
                  ? `SUSPICIOUS ${item.suspicion_score}/100`
                  : `CLEAN ${item.suspicion_score}/100`;

                return (
                  <StatusRow
                    key={idx}
                    title={defang(item.domain)}
                    status={statusState}
                    statusLabel={statusLabel}
                    subtitle={defang(item.url)}
                    defaultExpanded={false}
                    onViewRaw={() => setSelectedRawUrl(item)}
                    rawButtonLabel="View technical features"
                  >
                    <div className="space-y-2.5">
                      {/* Display Link Mismatch Banner */}
                      {features.display_link_mismatch && (
                        <div className="p-3 rounded-lg border border-danger-border bg-danger-surface text-danger flex items-start space-x-2 text-xs">
                          <ShieldAlert className="w-4 h-4 text-danger shrink-0 mt-0.5" />
                          <div>
                            <span className="font-bold block">Display Link Mismatch Detected</span>
                            <span>
                              Anchor text claimed <u>{features.visible_text_domain || features.visible_text}</u>, but the actual destination points to <u>{item.domain}</u>.
                            </span>
                          </div>
                        </div>
                      )}

                      {/* Safe Monospace URL */}
                      <div className="p-2.5 rounded-lg bg-surface border border-border flex items-center justify-between gap-2">
                        <div className="min-w-0 flex-1">
                          <span className="text-[10px] uppercase font-bold text-foreground-muted block mb-0.5">
                            Defanged Observed URL
                          </span>
                          <span className="text-xs font-mono text-foreground break-all select-all font-semibold">
                            {defang(item.url)}
                          </span>
                        </div>
                        <CopyButton text={item.url} label="Copy" className="shrink-0" />
                      </div>

                      {/* Key Explanation Metadata */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                        <MetadataRow label="Apex Domain" value={features.registered_domain || item.domain} />
                        <MetadataRow label="Scheme / Port" value={`${features.scheme.toUpperCase()} / ${features.port || 'Default'}${features.has_non_standard_port ? ' (Non-std)' : ''}`} />
                        <MetadataRow label="Subdomains" value={`${features.subdomain_count}${features.excessive_subdomains ? ' (High depth)' : ''}`} />
                        <MetadataRow label="Length / Encoded" value={`${features.total_length} chars / ${features.percent_encoding_count} encoded`} />
                      </div>

                      {/* Suspicious Keywords */}
                      {features.suspicious_keywords && features.suspicious_keywords.length > 0 && (
                        <div className="pt-1">
                          <span className="text-[10px] uppercase text-foreground-muted font-bold block mb-1">
                            Flagged Suspicious Keywords
                          </span>
                          <div className="flex flex-wrap gap-1">
                            {features.suspicious_keywords.map((kw, kIdx) => (
                              <span
                                key={kIdx}
                                className="px-2 py-0.5 rounded text-[10px] font-mono bg-warning-surface text-warning border border-warning-border font-semibold"
                              >
                                {kw}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </StatusRow>
                );
              })}
            </div>
          )}
        </div>
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawUrl && (
        <DetailDrawer
          isOpen={Boolean(selectedRawUrl)}
          onClose={() => setSelectedRawUrl(null)}
          title={`URL Technical Dossier — ${defang(selectedRawUrl.domain)}`}
          subtitle="Complete syntactic feature matrix and destination heuristics"
          data={{
            url: selectedRawUrl.url,
            defanged: defang(selectedRawUrl.url),
            domain: selectedRawUrl.domain,
            suspicion_score: selectedRawUrl.suspicion_score,
            suspicion_level: selectedRawUrl.suspicion_level,
            features: selectedRawUrl.features,
            observations: selectedRawUrl.observations,
            score_reasons: selectedRawUrl.score_reasons
          }}
          format="json"
        />
      )}
    </div>
  );
};
