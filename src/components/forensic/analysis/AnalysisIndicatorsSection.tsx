import React, { useState, useMemo, useEffect } from 'react';
import type { EmailAnalysis, IPIndicator, URLAnalysisResult } from '../../../types/forensic';
import {
  Target,
  Search,
  ExternalLink,
  ShieldAlert,
  Server,
  Globe,
  Link2,
  Mail,
  Paperclip,
  Filter,
  Sparkles
} from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { ExpandableSection, DetailDrawer } from '../../common/progressive';
import { CopyButton } from '../CopyButton';
import { TruncatedForensicValue } from '../TruncatedForensicValue';

interface AnalysisIndicatorsSectionProps {
  email: EmailAnalysis;
}

interface IOCItem {
  id: string;
  type: 'ip' | 'domain' | 'url' | 'email' | 'attachment';
  value: string;
  defangedValue: string;
  source: string;
  status: 'critical' | 'suspicious' | 'clean' | 'public' | 'private' | 'info';
  statusLabel: string;
  context?: string;
  metadata?: Record<string, any>;
}

const defang = (val: string): string => {
  return val
    .replace(/\./g, '[.]')
    .replace(/http:\/\//g, 'hxxp://')
    .replace(/https:\/\//g, 'hxxps://');
};

export const AnalysisIndicatorsSection: React.FC<AnalysisIndicatorsSectionProps> = ({ email }) => {
  const { openCopilotDrawer } = useInvestigation();
  const [selectedType, setSelectedType] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [onlySuspicious, setOnlySuspicious] = useState<boolean>(false);
  const [selectedIOC, setSelectedIOC] = useState<IOCItem | null>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const pageSize = 15;

  // Synthesize unified list of IOC items from email indicators
  const iocList = useMemo<IOCItem[]>(() => {
    const list: IOCItem[] = [];
    const indicators = email.indicators || {};

    // 1. IPs
    const ips: IPIndicator[] = indicators.ips && indicators.ips.length > 0
      ? indicators.ips
      : (email.ips || []).map((ip): IPIndicator => ({ value: ip, source: 'transmission' }));

    ips.forEach((ip, idx) => {
      const isEarliest = email.relay_analysis?.earliest_observable_node?.earliest_observable_ip === ip.value;
      const isPublic = ip.scope === 'public' || (!ip.scope && !ip.value.startsWith('192.168.') && !ip.value.startsWith('10.'));
      const ipIntel = email.ip_intelligence?.[ip.value];

      list.push({
        id: `ip-${idx}-${ip.value}`,
        type: 'ip',
        value: ip.value,
        defangedValue: defang(ip.value),
        source: ip.source ? `Header (${ip.source})` : isEarliest ? 'Earliest Origin Node' : 'Relay Header',
        status: isEarliest ? 'suspicious' : isPublic ? 'public' : 'clean',
        statusLabel: isEarliest ? 'Public Origin' : isPublic ? 'Public IP' : 'Internal IP',
        context: isEarliest ? 'Earliest observable public sending IP observed in Received chain.' : undefined,
        metadata: {
          ip: ip.value,
          scope: ip.scope || (isPublic ? 'public' : 'private'),
          is_earliest_sender: isEarliest,
          asn: ipIntel?.asn,
          asn_org: ipIntel?.asn_org,
          country: ipIntel?.country,
          city: ipIntel?.city,
          is_hosting: ipIntel?.is_hosting,
          is_proxy_vpn_tor: ipIntel?.is_proxy_vpn_tor
        }
      });
    });

    // 2. Domains
    const domains = indicators.domains && indicators.domains.length > 0
      ? indicators.domains
      : (email.domains || []).map((d) => ({ value: d, source: 'headers' }));

    domains.forEach((dom, idx) => {
      const isLookalike = (email.lookalike_domains || []).some(
        (l) => l.domain.toLowerCase() === dom.value.toLowerCase()
      );
      const lookalikeObj = (email.lookalike_domains || []).find(
        (l) => l.domain.toLowerCase() === dom.value.toLowerCase()
      );

      list.push({
        id: `domain-${idx}-${dom.value}`,
        type: 'domain',
        value: dom.value,
        defangedValue: defang(dom.value),
        source: dom.source ? `Source: ${dom.source}` : 'Extracted Domain',
        status: isLookalike ? 'critical' : 'clean',
        statusLabel: isLookalike ? 'Lookalike Spoof' : 'Standard Domain',
        context: isLookalike
          ? `Mimics target brand "${lookalikeObj?.brand_name || lookalikeObj?.suspected_brand}" via ${lookalikeObj?.techniques?.join(', ')}`
          : undefined,
        metadata: {
          domain: dom.value,
          lookalike_detected: isLookalike,
          lookalike_details: lookalikeObj,
          dns: email.domain_intelligence?.[dom.value]?.dns
        }
      });
    });

    // 3. URLs
    const urls: URLAnalysisResult[] = email.url_analysis && email.url_analysis.length > 0
      ? email.url_analysis
      : (email.urls || []).map((u): URLAnalysisResult => ({
          url: u,
          domain: u.split('/')[2] || u,
          suspicion_score: 0,
          suspicion_level: 'low',
          observations: [],
          score_reasons: [],
          features: {
            scheme: u.startsWith('https') ? 'https' : 'http',
            hostname: u.split('/')[2] || u,
            registered_domain: u.split('/')[2] || u,
            subdomain: '',
            subdomain_count: 0,
            has_non_standard_port: false,
            path: '',
            path_length: 0,
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
          }
        }));

    urls.forEach((u, idx) => {
      const isCrit = u.suspicion_score >= 60;
      const isSusp = u.suspicion_score >= 25 || u.features?.display_link_mismatch;

      list.push({
        id: `url-${idx}-${u.url}`,
        type: 'url',
        value: u.url,
        defangedValue: defang(u.url),
        source: u.features?.display_link_mismatch ? 'MIME HTML (Link Mismatch)' : 'Message Body Anchor',
        status: isCrit ? 'critical' : isSusp ? 'suspicious' : 'clean',
        statusLabel: isCrit
          ? `Risk ${u.suspicion_score}/100`
          : isSusp
          ? `Suspicious (${u.suspicion_score}/100)`
          : 'Clean URL',
        context: u.observations?.join(' · ') || (u.score_reasons?.join(' · ')),
        metadata: {
          url: u.url,
          domain: u.domain,
          suspicion_score: u.suspicion_score,
          reasons: u.score_reasons,
          observations: u.observations,
          features: u.features
        }
      });
    });

    // 4. Email Addresses
    const emails = indicators.email_addresses && indicators.email_addresses.length > 0
      ? indicators.email_addresses
      : (email.emails || []).map((em) => ({ value: em, source: 'envelope' }));

    emails.forEach((em, idx) => {
      const isReturnPath = email.return_path?.toLowerCase().includes(em.value.toLowerCase());
      const isReplyTo = email.reply_to?.toLowerCase().includes(em.value.toLowerCase());
      const hasMismatch = isReplyTo && email.authentication?.alignment?.reply_to_mismatch;

      list.push({
        id: `email-${idx}-${em.value}`,
        type: 'email',
        value: em.value,
        defangedValue: defang(em.value),
        source: isReplyTo ? 'Reply-To Header' : isReturnPath ? 'Return-Path Envelope' : (em.source || 'Header'),
        status: hasMismatch ? 'suspicious' : 'clean',
        statusLabel: hasMismatch ? 'Reply-To Mismatch' : 'Identity',
        context: hasMismatch ? 'Directs replies to a domain distinct from visible sender' : undefined,
        metadata: {
          address: em.value,
          source: em.source,
          is_reply_to: isReplyTo,
          is_return_path: isReturnPath
        }
      });
    });

    // 5. Attachments
    const attachments = indicators.attachments && indicators.attachments.length > 0
      ? indicators.attachments
      : (email.attachments || []).map((att) => ({
          filename: att.filename,
          mime_type: att.mime_type,
          size: att.size,
          sha256: att.sha256 || 'N/A',
          static_analysis: att.static_analysis
        }));

    attachments.forEach((att, idx) => {
      const isDangerous =
        att.filename?.match(/\.(exe|scr|bat|cmd|vbs|js|ps1|hta|iso|zip|rar)$/i) ||
        att.mime_type?.includes('executable') ||
        att.static_analysis?.extension_mismatch ||
        att.static_analysis?.double_extension ||
        att.static_analysis?.entropy_level === 'very_high';

      list.push({
        id: `attachment-${idx}-${att.filename || idx}`,
        type: 'attachment',
        value: att.filename || `attachment_${idx + 1}`,
        defangedValue: att.filename || `attachment_${idx + 1}`,
        source: 'MIME Multipart Boundary',
        status: isDangerous ? 'critical' : 'clean',
        statusLabel: isDangerous ? 'Risky Payload' : 'Document',
        context: att.sha256 && att.sha256 !== 'N/A' ? `SHA-256: ${att.sha256.slice(0, 16)}...` : undefined,
        metadata: {
          filename: att.filename,
          mime_type: att.mime_type,
          size: att.size,
          sha256: att.sha256,
          static_analysis: att.static_analysis
        }
      });
    });

    return list;
  }, [email]);

  // Filtered items
  const filteredList = useMemo(() => {
    return iocList.filter((item) => {
      if (selectedType !== 'all' && item.type !== selectedType) return false;
      if (onlySuspicious && item.status !== 'critical' && item.status !== 'suspicious') return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesVal = item.value.toLowerCase().includes(q);
        const matchesSource = item.source.toLowerCase().includes(q);
        const matchesContext = item.context?.toLowerCase().includes(q);
        if (!matchesVal && !matchesSource && !matchesContext) return false;
      }
      return true;
    });
  }, [iocList, selectedType, onlySuspicious, searchQuery]);

  // Reset pagination on filter changes
  useEffect(() => {
    setCurrentPage(1);
  }, [selectedType, onlySuspicious, searchQuery]);

  const totalPages = Math.max(1, Math.ceil(filteredList.length / pageSize));
  const displayedList = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredList.slice(start, start + pageSize);
  }, [filteredList, currentPage, pageSize]);

  const typeCounts = useMemo(() => {
    return {
      all: iocList.length,
      ip: iocList.filter((i) => i.type === 'ip').length,
      domain: iocList.filter((i) => i.type === 'domain').length,
      url: iocList.filter((i) => i.type === 'url').length,
      email: iocList.filter((i) => i.type === 'email').length,
      attachment: iocList.filter((i) => i.type === 'attachment').length
    };
  }, [iocList]);

  const getTypeIcon = (type: IOCItem['type']) => {
    switch (type) {
      case 'ip': return <Server className="w-3.5 h-3.5 text-primary" />;
      case 'domain': return <Globe className="w-3.5 h-3.5 text-primary" />;
      case 'url': return <Link2 className="w-3.5 h-3.5 text-primary" />;
      case 'email': return <Mail className="w-3.5 h-3.5 text-primary" />;
      case 'attachment': return <Paperclip className="w-3.5 h-3.5 text-primary" />;
    }
  };

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title={`Extracted Indicators of Compromise (${iocList.length})`}
        subtitle="Defanged network, host, and identity observables extracted across message envelope and body"
        icon={Target}
        defaultExpanded={true}
        badge={
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-surface-secondary text-foreground-muted border border-border">
            {filteredList.length} Observable{filteredList.length !== 1 ? 's' : ''}
          </span>
        }
      >
        <div className="space-y-4">
          {/* Controls: Type tabs, Search query, and Suspicious toggle */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
            {/* Filter Pills */}
            <div className="flex flex-wrap items-center gap-1.5">
              {(['all', 'ip', 'domain', 'url', 'email', 'attachment'] as const).map((t) => {
                const count = typeCounts[t];
                if (count === 0 && t !== 'all') return null;
                const label =
                  t === 'all'
                    ? 'All'
                    : t === 'ip'
                    ? 'IPs'
                    : t === 'domain'
                    ? 'Domains'
                    : t === 'url'
                    ? 'URLs'
                    : t === 'email'
                    ? 'Emails'
                    : 'Attachments';

                const isActive = selectedType === t;
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setSelectedType(t)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors cursor-pointer flex items-center space-x-1 ${
                      isActive
                        ? 'bg-primary text-primary-foreground font-bold shadow-xs'
                        : 'bg-surface-secondary/70 hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
                    }`}
                  >
                    <span>{label}</span>
                    <span className={`text-[10px] ${isActive ? 'text-primary-foreground/80' : 'text-foreground-subtle'}`}>
                      ({count})
                    </span>
                  </button>
                );
              })}
            </div>

            {/* Search and Suspicious Toggle */}
            <div className="flex items-center space-x-2">
              <div className="relative w-full sm:w-56">
                <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-foreground-muted" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter observables..."
                  className="w-full pl-8 pr-3 py-1 bg-surface-secondary border border-border rounded-lg text-xs text-foreground placeholder-foreground-subtle focus:outline-none focus:border-primary transition-colors"
                />
              </div>

              <button
                type="button"
                onClick={() => setOnlySuspicious(!onlySuspicious)}
                className={`px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center space-x-1 border transition-all cursor-pointer shrink-0 ${
                  onlySuspicious
                    ? 'bg-warning-surface text-warning border-warning-border font-bold'
                    : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground'
                }`}
              >
                <Filter className="w-3 h-3" />
                <span>Suspicious Only</span>
              </button>
            </div>
          </div>

          {/* Compact IOC Table */}
          {filteredList.length === 0 ? (
            <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border text-foreground-muted text-xs">
              No indicators match the selected filter criteria.
            </div>
          ) : (
            <div className="rounded-xl border border-border overflow-hidden bg-surface shadow-xs">
              {/* Tablet / Mobile Compact Card Rows (< md) */}
              <div className="md:hidden divide-y divide-border">
                {displayedList.map((ioc) => (
                  <div
                    key={`mob-${ioc.id}`}
                    onClick={() => setSelectedIOC(ioc)}
                    className={`p-3 space-y-2 cursor-pointer transition-colors ${
                      selectedIOC?.id === ioc.id ? 'bg-primary/10 entity-selected' : 'hover:bg-surface-secondary/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex items-center space-x-1.5 text-foreground-muted font-bold text-[11px] uppercase">
                        {getTypeIcon(ioc.type)}
                        <span>{ioc.type}</span>
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        ioc.status === 'critical'
                          ? 'bg-danger-surface text-danger border-danger-border'
                          : ioc.status === 'suspicious'
                          ? 'bg-warning-surface text-warning border-warning-border'
                          : ioc.status === 'public'
                          ? 'bg-primary/10 text-primary border-primary/20'
                          : 'bg-surface-secondary text-foreground-muted border-border'
                      }`}>
                        {ioc.statusLabel}
                      </span>
                    </div>

                    <div className="min-w-0">
                      <TruncatedForensicValue
                        value={ioc.value}
                        type={ioc.type}
                        defanged={true}
                        maxWidth="max-w-[260px] sm:max-w-md"
                      />
                    </div>

                    <div className="flex items-center justify-between pt-1 text-[11px] text-foreground-muted">
                      <span className="truncate max-w-[160px] text-foreground-subtle">{ioc.source}</span>
                      <div className="flex items-center space-x-2">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            openCopilotDrawer(
                              `Explain this ${ioc.type.toUpperCase()} observable: '${ioc.value}'. What is its reputation, forensic role, and threat context?`,
                              {
                                type: ioc.type.toUpperCase(),
                                identifier: ioc.value,
                                details: ioc.statusLabel
                              }
                            );
                          }}
                          className="px-1.5 py-0.5 rounded text-[10px] font-bold text-primary/80 hover:text-primary transition-colors flex items-center space-x-1 cursor-pointer"
                        >
                          <Sparkles className="w-3 h-3" />
                          <span>Ask AI</span>
                        </button>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedIOC(ioc);
                          }}
                          className="px-2 py-0.5 rounded text-[10px] font-bold text-primary hover:bg-primary/10 transition-colors flex items-center space-x-1 cursor-pointer"
                        >
                          <span>Inspect</span>
                          <ExternalLink className="w-2.5 h-2.5" />
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              {/* Desktop / Laptop Table (>= md) */}
              <div className="hidden md:block overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="bg-surface-secondary/60 border-b border-border text-[10px] uppercase font-bold text-foreground-muted tracking-wider">
                      <th className="py-2.5 px-3 w-28">Type</th>
                      <th className="py-2.5 px-3 min-w-[220px]">Indicator (Defanged)</th>
                      <th className="py-2.5 px-3">Context / Source</th>
                      <th className="py-2.5 px-3 w-32">Status</th>
                      <th className="py-2.5 px-3 text-right w-28">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {displayedList.map((ioc) => {
                      return (
                        <tr
                          key={ioc.id}
                          onClick={() => setSelectedIOC(ioc)}
                          className={`hover:bg-surface-secondary/50 transition-colors cursor-pointer group ${
                            selectedIOC?.id === ioc.id ? 'bg-primary/10 entity-selected' : ''
                          }`}
                        >
                          {/* Type */}
                          <td className="py-2 px-3 whitespace-nowrap">
                            <span className="flex items-center space-x-1.5 text-foreground-muted font-bold text-[11px] uppercase">
                              {getTypeIcon(ioc.type)}
                              <span>{ioc.type}</span>
                            </span>
                          </td>

                          {/* Indicator Value */}
                          <td className="py-2 px-3 min-w-0">
                            <TruncatedForensicValue
                              value={ioc.value}
                              type={ioc.type}
                              defanged={true}
                              maxWidth="max-w-[200px] lg:max-w-md"
                            />
                          </td>

                          {/* Source */}
                          <td className="py-2 px-3 text-foreground-muted text-[11px] truncate max-w-[200px]">
                            {ioc.source}
                          </td>

                          {/* Status */}
                          <td className="py-2 px-3 whitespace-nowrap">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                              ioc.status === 'critical'
                                ? 'bg-danger-surface text-danger border-danger-border'
                                : ioc.status === 'suspicious'
                                ? 'bg-warning-surface text-warning border-warning-border'
                                : ioc.status === 'public'
                                ? 'bg-primary/10 text-primary border-primary/20'
                                : 'bg-surface-secondary text-foreground-muted border-border'
                            }`}>
                              {ioc.statusLabel}
                            </span>
                          </td>

                          {/* Action */}
                          <td className="py-2 px-3 text-right whitespace-nowrap">
                            <div className="flex items-center justify-end space-x-1 ml-auto">
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  openCopilotDrawer(
                                    `Explain this ${ioc.type.toUpperCase()} observable: '${ioc.value}'. What is its reputation, forensic role, and threat context in this investigation?`,
                                    {
                                      type: ioc.type.toUpperCase(),
                                      identifier: ioc.value,
                                      details: ioc.statusLabel
                                    }
                                  );
                                }}
                                className="px-1.5 py-1 rounded text-[11px] font-bold text-primary/80 hover:text-primary hover:bg-primary/10 transition-colors flex items-center space-x-1 cursor-pointer"
                                title="Ask AI about this observable"
                              >
                                <Sparkles className="w-3 h-3" />
                                <span>Ask AI</span>
                              </button>
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setSelectedIOC(ioc);
                                }}
                                className="px-2 py-1 rounded text-[11px] font-bold text-primary hover:bg-primary/10 transition-colors flex items-center space-x-1 cursor-pointer"
                              >
                                <span>Inspect</span>
                                <ExternalLink className="w-3 h-3" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {/* Pagination Controls for Large Collections */}
              {filteredList.length > pageSize && (
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 border-t border-border bg-surface-secondary/20 text-xs font-mono text-foreground-muted">
                  <span>
                    Showing <strong className="text-foreground">{(currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, filteredList.length)}</strong> of <strong className="text-foreground">{filteredList.length}</strong> observables
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
            </div>
          )}
        </div>
      </ExpandableSection>

      {/* Contextual Drawer for Selected IOC */}
      {selectedIOC && (
        <DetailDrawer
          isOpen={Boolean(selectedIOC)}
          onClose={() => setSelectedIOC(null)}
          title={`IOC Forensic Context: ${selectedIOC.type.toUpperCase()}`}
          subtitle={selectedIOC.defangedValue}
          data={selectedIOC.metadata || selectedIOC}
          format="json"
        >
          <div className="space-y-4 font-mono text-xs pb-4 border-b border-border">
            <div className="p-3 rounded-xl bg-surface border border-border space-y-2">
              <span className="text-[10px] uppercase font-bold text-foreground-muted tracking-wider block">
                Observable Identity
              </span>
              <div className="flex items-center justify-between gap-2">
                <span className="font-bold text-foreground break-all select-all text-sm">
                  {selectedIOC.value}
                </span>
                <CopyButton text={selectedIOC.value} label="Copy Value" />
              </div>
              <div className="text-[11px] text-foreground-muted">
                Source: <strong>{selectedIOC.source}</strong>
              </div>
            </div>

            {selectedIOC.context && (
              <div className="p-3 rounded-xl bg-warning-surface/30 border border-warning-border text-foreground-muted space-y-1">
                <div className="flex items-center space-x-1.5 text-warning font-bold text-xs">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Detection Context</span>
                </div>
                <p className="text-[11px] leading-relaxed text-foreground">
                  {selectedIOC.context}
                </p>
              </div>
            )}

            {/* Contextual Ask AI Button inside Drawer */}
            <button
              type="button"
              onClick={() => {
                openCopilotDrawer(
                  `Explain this ${selectedIOC.type.toUpperCase()} observable: '${selectedIOC.value}'. What is its reputation, forensic role, and threat context?`,
                  {
                    type: selectedIOC.type.toUpperCase(),
                    identifier: selectedIOC.value,
                    details: selectedIOC.statusLabel
                  }
                );
              }}
              className="w-full py-2 rounded-xl bg-primary/10 hover:bg-primary/20 text-primary border border-primary/25 text-xs font-mono font-bold flex items-center justify-center space-x-1.5 transition-colors cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Ask AI About This Indicator</span>
            </button>
          </div>
        </DetailDrawer>
      )}
    </div>
  );
};
