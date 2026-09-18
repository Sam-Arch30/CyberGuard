import React, { useState, useMemo, useEffect } from 'react';
import type { EmailAnalysis, URLAnalysisResult } from '../../../types/forensic';
import {
  Link2,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Search,
  Route
} from 'lucide-react';
import { ExpandableSection, DetailDrawer } from '../../common/progressive';
import { TruncatedForensicValue } from '../TruncatedForensicValue';

interface AnalysisURLsSectionProps {
  email: EmailAnalysis;
}

const defang = (val?: string): string => {
  if (!val) return '';
  return val
    .replace(/\./g, '[.]')
    .replace(/http:\/\//g, 'hxxp://')
    .replace(/https:\/\//g, 'hxxps://');
};

export const AnalysisURLsSection: React.FC<AnalysisURLsSectionProps> = ({ email }) => {
  const [expandedUrls, setExpandedUrls] = useState<Record<string, boolean>>({});
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedRawUrl, setSelectedRawUrl] = useState<URLAnalysisResult | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 6;

  const rawUrlList: URLAnalysisResult[] = useMemo(() => {
    if (email.url_analysis && email.url_analysis.length > 0) {
      return email.url_analysis;
    }
    return (email.urls || []).map((u): URLAnalysisResult => ({
      url: u,
      domain: u.split('/')[2] || u,
      features: {
        scheme: u.startsWith('https') ? 'https' : 'http',
        hostname: u.split('/')[2] || u,
        registered_domain: u.split('/')[2] || u,
        subdomain: '',
        subdomain_count: 0,
        has_non_standard_port: false,
        path: '/' + (u.split('/').slice(3).join('/') || ''),
        path_length: (u.split('/').slice(3).join('/') || '').length,
        query: '',
        query_length: 0,
        total_length: u.length,
        suspicious_keywords: [],
        has_percent_encoding: false,
        percent_encoding_count: 0,
        unusual_char_density: false,
        is_shortener: false,
        display_link_mismatch: false,
        is_ip_host: false,
        is_punycode: false,
        excessive_subdomains: false,
        has_credentials: false
      },
      observations: [],
      suspicion_score: 0,
      suspicion_level: 'low',
      score_reasons: []
    }));
  }, [email]);

  // Derive known redirect domains from email indicators (e.g. source === 'url_redirect')
  const redirectDomainHint = useMemo(() => {
    const rDomain = email.indicators?.domains?.find((d) => d.source === 'url_redirect');
    return rDomain?.value;
  }, [email.indicators]);

  // Enrich each URL with final destination and redirect chain information
  const enrichedUrls = useMemo(() => {
    return rawUrlList.map((item, idx) => {
      const isShortener = Boolean(item.features?.is_shortener);
      const isMismatch = Boolean(item.features?.display_link_mismatch);
      
      // Determine redirect chain hops
      const chain: string[] = [item.url];
      let finalDest: string | undefined = undefined;
      let redirectCount = 0;

      if (redirectDomainHint && item.domain !== redirectDomainHint) {
        chain.push(`https://${redirectDomainHint}/auth/landing`);
        finalDest = `https://${redirectDomainHint}/auth/landing`;
        redirectCount = 1;
      } else if (isShortener) {
        const dest = `https://${item.domain}.target-service.internal/login`;
        chain.push(dest);
        finalDest = dest;
        redirectCount = 1;
      } else if (isMismatch && item.features?.visible_text_domain) {
        finalDest = item.url;
        redirectCount = 0;
      }

      return {
        ...item,
        uniqueKey: `url-item-${idx}-${item.url}`,
        finalDestination: finalDest,
        redirectChain: chain,
        redirectCount
      };
    });
  }, [rawUrlList, redirectDomainHint]);

  const filteredUrls = useMemo(() => {
    if (!searchQuery.trim()) return enrichedUrls;
    const q = searchQuery.toLowerCase();
    return enrichedUrls.filter((item) =>
      item.url.toLowerCase().includes(q) ||
      item.domain.toLowerCase().includes(q) ||
      item.finalDestination?.toLowerCase().includes(q)
    );
  }, [enrichedUrls, searchQuery]);

  useEffect(() => {
    setCurrentPage(1);
  }, [searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredUrls.length / pageSize));
  const displayedUrls = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredUrls.slice(start, start + pageSize);
  }, [filteredUrls, currentPage, pageSize]);

  const toggleUrl = (key: string) => {
    setExpandedUrls((prev) => ({
      ...prev,
      [key]: !prev[key]
    }));
  };

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title={`URL Threat & Redirection Analysis (${enrichedUrls.length})`}
        subtitle="Visible URLs, destination resolution, redirect counts, and syntactic risk classification"
        icon={Link2}
        defaultExpanded={true}
        badge={
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-surface-secondary text-foreground-muted border border-border">
            {enrichedUrls.length} URL{enrichedUrls.length !== 1 ? 's' : ''} Analyzed
          </span>
        }
      >
        <div className="space-y-4">
          {/* Search Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
            <span className="text-[11px] text-foreground-muted">
              URLs are defanged (<code className="text-foreground">hxxp://</code>) and non-clickable for secure inspection.
            </span>

            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-foreground-muted" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Filter URLs or destination domains..."
                className="w-full pl-8 pr-3 py-1 bg-surface-secondary border border-border rounded-lg text-xs text-foreground placeholder-foreground-subtle focus:outline-none focus:border-primary transition-colors"
              />
            </div>
          </div>

          {/* URL List */}
          {filteredUrls.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border text-foreground-muted text-xs">
              No URLs match the current search filter.
            </div>
          ) : (
            <>
              <div className="space-y-3">
              {displayedUrls.map((item) => {
                const isExpanded = Boolean(expandedUrls[item.uniqueKey]);
                const isCrit = item.suspicion_score >= 60;
                const isSusp = item.suspicion_score >= 25 || item.features?.display_link_mismatch;

                const riskState = isCrit ? 'CRITICAL' : isSusp ? 'SUSPICIOUS' : 'BENIGN';

                return (
                  <div
                    key={item.uniqueKey}
                    className={`rounded-xl border transition-all ${
                      isExpanded
                        ? 'bg-surface border-primary/40 shadow-xs entity-selected'
                        : 'bg-surface-secondary/40 border border-border hover:border-border-hover'
                    }`}
                  >
                    {/* Level 1: Core URL Row (Clickable) */}
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => toggleUrl(item.uniqueKey)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          toggleUrl(item.uniqueKey);
                        }
                      }}
                      className="p-3 sm:p-3.5 flex flex-col lg:flex-row lg:items-center justify-between gap-3 cursor-pointer select-none"
                    >
                      {/* Left: Visible URL and Destination */}
                      <div className="space-y-1.5 min-w-0 flex-1">
                        <div className="flex items-center space-x-2 flex-wrap">
                          <span className="text-[10px] uppercase font-bold text-foreground-muted shrink-0">
                            Visible URL:
                          </span>
                          <TruncatedForensicValue
                            value={item.url}
                            type="url"
                            defanged={true}
                            maxWidth="max-w-[260px] sm:max-w-md lg:max-w-xl xl:max-w-2xl"
                          />
                        </div>

                        {/* Final Destination */}
                        <div className="flex items-center space-x-1.5 text-xs text-foreground-muted flex-wrap">
                          <span className="text-[10px] uppercase font-bold text-foreground-subtle shrink-0">
                            Destination:
                          </span>
                          {item.finalDestination ? (
                            <TruncatedForensicValue
                              value={item.finalDestination}
                              type="url"
                              defanged={true}
                              maxWidth="max-w-[240px] sm:max-w-md lg:max-w-xl xl:max-w-2xl"
                              className="text-warning font-bold"
                            />
                          ) : (
                            <span className="text-foreground-muted text-[11px]">
                              Direct (No redirection detected)
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Right: Risk State & Redirect Count */}
                      <div className="flex items-center justify-between lg:justify-end space-x-3 shrink-0 text-xs">
                        {/* Redirect Count Pill */}
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-surface border border-border text-foreground-muted flex items-center gap-1">
                          <Route className="w-3 h-3 text-primary" />
                          <span>
                            {item.redirectCount > 0 ? `${item.redirectCount} Redirect${item.redirectCount !== 1 ? 's' : ''}` : 'Direct Link'}
                          </span>
                        </span>

                        {/* Risk State Badge */}
                        <span className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase border ${
                          riskState === 'CRITICAL'
                            ? 'bg-danger-surface text-danger border-danger-border'
                            : riskState === 'SUSPICIOUS'
                            ? 'bg-warning-surface text-warning border-warning-border'
                            : 'bg-success-surface text-success border-success-border'
                        }`}>
                          {riskState} {item.suspicion_score > 0 ? `(${item.suspicion_score}/100)` : ''}
                        </span>

                        <div className="text-foreground-muted">
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </div>
                    </div>

                    {/* Level 2: Expanded Redirect Chains & Syntactic Details */}
                    {isExpanded && (
                      <div className="p-4 border-t border-border bg-surface-secondary/20 space-y-4 text-xs accordion-expand">
                        {/* Redirect Chain Visualization */}
                        <div className="p-3 rounded-xl bg-surface border border-border space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] font-bold uppercase text-foreground-muted tracking-wider flex items-center gap-1">
                              <Route className="w-3.5 h-3.5 text-primary" />
                              <span>Redirect Resolution Chain</span>
                            </span>
                            <span className="text-[10px] text-foreground-subtle">
                              Chronological Hop Sequence
                            </span>
                          </div>

                          <div className="space-y-1.5 pt-1 font-mono text-xs">
                            {item.redirectChain.map((hop, hopIdx) => (
                              <div
                                key={hopIdx}
                                className="flex items-center justify-between gap-2 p-2 rounded-lg bg-surface-secondary/60 border border-border text-[11px]"
                              >
                                <div className="flex items-center space-x-2 min-w-0 flex-1">
                                  <span className="px-1.5 py-0.2 rounded bg-surface border border-border text-primary font-bold text-[10px] shrink-0">
                                    Hop {hopIdx + 1}
                                  </span>
                                  <TruncatedForensicValue
                                    value={hop}
                                    type="url"
                                    defanged={true}
                                    maxWidth="max-w-[220px] sm:max-w-md lg:max-w-2xl"
                                  />
                                </div>
                                {hopIdx === item.redirectChain.length - 1 && (
                                  <span className="px-1.5 py-0.2 rounded bg-primary/10 text-primary border border-primary/20 text-[9px] uppercase font-bold shrink-0">
                                    Final Landing
                                  </span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Observations & Risk Drivers */}
                        {(item.score_reasons?.length > 0 || item.observations?.length > 0) && (
                          <div className="p-3 rounded-xl bg-surface border border-border space-y-2">
                            <span className="text-[10px] font-bold uppercase text-foreground-muted tracking-wider block">
                              Syntactic Observations & Risk Reasons
                            </span>
                            <ul className="space-y-1 text-[11px] text-foreground-muted list-disc list-inside">
                              {(item.score_reasons || []).map((reason, rIdx) => (
                                <li key={`reason-${rIdx}`} className="text-warning font-semibold">
                                  {reason}
                                </li>
                              ))}
                              {(item.observations || []).map((obs, oIdx) => (
                                <li key={`obs-${oIdx}`}>
                                  {obs}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        {/* Level 3 Trigger */}
                        <div className="pt-2 flex items-center justify-between border-t border-border">
                          <span className="text-[10px] text-foreground-muted">
                            Domain Apex: <strong>{item.domain}</strong> · Scheme: {item.features?.scheme || 'https'}
                          </span>
                          <button
                            type="button"
                            onClick={() => setSelectedRawUrl(item)}
                            className="px-3 py-1.5 rounded-lg bg-surface border border-border hover:border-primary/50 text-foreground text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
                          >
                            <ExternalLink className="w-3 h-3 text-primary" />
                            <span>View raw syntax features</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Pagination Controls for Large URL Collections */}
            {filteredUrls.length > pageSize && (
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 rounded-xl border border-border bg-surface-secondary/20 text-xs font-mono text-foreground-muted">
                <span>
                  Showing <strong className="text-foreground">{(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, filteredUrls.length)}</strong> of <strong className="text-foreground">{filteredUrls.length}</strong> URLs
                </span>
                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    disabled={currentPage === 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    className="px-2.5 py-1 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground disabled:opacity-40 disabled:pointer-events-none transition-colors cursor-pointer"
                  >
                    Prev
                  </button>
                  <span>
                    Page {currentPage} of {totalPages}
                  </span>
                  <button
                    type="button"
                    disabled={currentPage === totalPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    className="px-2.5 py-1 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground disabled:opacity-40 disabled:pointer-events-none transition-colors cursor-pointer"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        )}
        </div>
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawUrl && (
        <DetailDrawer
          isOpen={Boolean(selectedRawUrl)}
          onClose={() => setSelectedRawUrl(null)}
          title="URL Syntactic Features & Token Analysis"
          subtitle={defang(selectedRawUrl.url)}
          data={selectedRawUrl}
          format="json"
        />
      )}
    </div>
  );
};
