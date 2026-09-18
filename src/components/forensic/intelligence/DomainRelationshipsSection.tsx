import React, { useState, useMemo } from 'react';
import {
  Globe,
  Server,
  Shield,
  ShieldAlert,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  CheckCircle2,
  XCircle
} from 'lucide-react';
import type { EmailAnalysis, DomainIntelligence } from '../../../types/forensic';
import { resolveDomainIntelligence } from '../../../utils/indicatorHelper';
import { CopyButton } from '../CopyButton';
import { DetailDrawer, MetadataRow } from '../../common/progressive';

interface DomainRelationshipsSectionProps {
  email: EmailAnalysis;
  onSelectIp?: (ip: string) => void;
  selectedDomainExternal?: string | null;
  onClearSelectedDomain?: () => void;
}

interface DomainEntityItem {
  domain: string;
  intel: DomainIntelligence;
  relationships: string[];
  isFromDomain: boolean;
  isReturnPath: boolean;
  isReplyTo: boolean;
  isUrlTarget: boolean;
  isIoc: boolean;
}

export const DomainRelationshipsSection: React.FC<DomainRelationshipsSectionProps> = ({
  email,
  onSelectIp,
  selectedDomainExternal,
  onClearSelectedDomain
}) => {
  const [filter, setFilter] = useState<'all' | 'lookalike' | 'header' | 'urls'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedDomains, setExpandedDomains] = useState<Record<string, boolean>>({});
  const [selectedRawDomain, setSelectedRawDomain] = useState<DomainIntelligence | null>(null);

  const domainIntelMap: Record<string, DomainIntelligence> = email.domain_intelligence || {};

  // Build domain entity items with explicit email relationships
  const domainEntities = useMemo(() => {
    const map = new Map<string, DomainEntityItem>();

    const fromDomain = email.authentication?.alignment?.from_domain?.toLowerCase() ||
      (email.from?.includes('@') ? email.from.split('@').pop()?.replace(/[>]/g, '').trim().toLowerCase() : undefined);

    const returnPathDomain = email.authentication?.alignment?.return_path_domain?.toLowerCase() ||
      (email.return_path?.includes('@') ? email.return_path.split('@').pop()?.replace(/[>]/g, '').trim().toLowerCase() : undefined);

    const replyToDomain = email.authentication?.alignment?.reply_to_domain?.toLowerCase() ||
      (email.reply_to?.includes('@') ? email.reply_to.split('@').pop()?.replace(/[>]/g, '').trim().toLowerCase() : undefined);

    // 1. From domain
    if (fromDomain) {
      const intel = resolveDomainIntelligence(fromDomain, domainIntelMap);
      map.set(fromDomain, {
        domain: fromDomain,
        intel,
        relationships: ['Header From (Sender)'],
        isFromDomain: true,
        isReturnPath: false,
        isReplyTo: false,
        isUrlTarget: false,
        isIoc: false
      });
    }

    // 2. Return-Path domain
    if (returnPathDomain) {
      const existing = map.get(returnPathDomain);
      if (existing) {
        existing.relationships.push('Return-Path (Envelope Bounce)');
        existing.isReturnPath = true;
      } else {
        const intel = resolveDomainIntelligence(returnPathDomain, domainIntelMap);
        map.set(returnPathDomain, {
          domain: returnPathDomain,
          intel,
          relationships: ['Return-Path (Envelope Bounce)'],
          isFromDomain: false,
          isReturnPath: true,
          isReplyTo: false,
          isUrlTarget: false,
          isIoc: false
        });
      }
    }

    // 3. Reply-To domain
    if (replyToDomain) {
      const existing = map.get(replyToDomain);
      if (existing) {
        existing.relationships.push('Reply-To Mailbox');
        existing.isReplyTo = true;
      } else {
        const intel = resolveDomainIntelligence(replyToDomain, domainIntelMap);
        map.set(replyToDomain, {
          domain: replyToDomain,
          intel,
          relationships: ['Reply-To Mailbox'],
          isFromDomain: false,
          isReturnPath: false,
          isReplyTo: true,
          isUrlTarget: false,
          isIoc: false
        });
      }
    }

    // 4. Body URLs / Links
    (email.url_analysis || []).forEach(u => {
      const dom = u.domain?.toLowerCase() || (u.features?.hostname || '').toLowerCase();
      if (dom) {
        const existing = map.get(dom);
        if (existing) {
          if (!existing.relationships.includes('Body URL / Link Target')) {
            existing.relationships.push('Body URL / Link Target');
            existing.isUrlTarget = true;
          }
        } else {
          const intel = resolveDomainIntelligence(dom, domainIntelMap);
          map.set(dom, {
            domain: dom,
            intel,
            relationships: ['Body URL / Link Target'],
            isFromDomain: false,
            isReturnPath: false,
            isReplyTo: false,
            isUrlTarget: true,
            isIoc: false
          });
        }
      }
    });

    // 5. Extracted indicator domains
    (email.indicators?.domains || []).forEach(d => {
      const dom = d.value.toLowerCase().trim();
      const existing = map.get(dom);
      if (existing) {
        if (!existing.relationships.includes('Extracted IOC')) {
          existing.relationships.push('Extracted IOC');
          existing.isIoc = true;
        }
      } else {
        const intel = resolveDomainIntelligence(dom, domainIntelMap);
        map.set(dom, {
          domain: dom,
          intel,
          relationships: ['Extracted IOC Indicator'],
          isFromDomain: false,
          isReturnPath: false,
          isReplyTo: false,
          isUrlTarget: false,
          isIoc: true
        });
      }
    });

    // 6. Any other domains in email.domains
    (email.domains || []).forEach(dStr => {
      const dom = dStr.toLowerCase().trim();
      if (!map.has(dom)) {
        const intel = resolveDomainIntelligence(dom, domainIntelMap);
        map.set(dom, {
          domain: dom,
          intel,
          relationships: ['Observed Domain Reference'],
          isFromDomain: false,
          isReturnPath: false,
          isReplyTo: false,
          isUrlTarget: false,
          isIoc: false
        });
      }
    });

    return Array.from(map.values());
  }, [email, domainIntelMap]);

  // Handle external selection
  React.useEffect(() => {
    if (selectedDomainExternal) {
      const match = domainEntities.find(d => d.domain.toLowerCase() === selectedDomainExternal.toLowerCase());
      if (match) {
        setExpandedDomains(prev => ({ ...prev, [match.domain]: true }));
      }
    }
  }, [selectedDomainExternal, domainEntities]);

  const toggleExpand = (domain: string) => {
    setExpandedDomains(prev => ({
      ...prev,
      [domain]: !prev[domain]
    }));
  };

  const formatDate = (isoStr?: string): string => {
    if (!isoStr) return 'Unavailable';
    try {
      const dt = new Date(isoStr);
      return dt.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  };

  const formatTechniqueName = (tech: string): string => {
    const map: Record<string, string> = {
      character_substitution: 'Character Substitution',
      brand_keyword: 'Brand Keyword',
      suspicious_subdomain_abuse: 'Subdomain Abuse',
      hyphenation: 'Hyphen Variation',
      added_affix: 'Added Prefix / Suffix',
      punycode: 'Punycode',
      unicode_homoglyphs: 'Unicode Homoglyphs',
      levenshtein_distance: 'Levenshtein Distance'
    };
    return map[tech] || tech.replace(/_/g, ' ');
  };

  // Filtered list
  const filteredDomains = useMemo(() => {
    return domainEntities.filter(item => {
      if (filter === 'lookalike' && !item.intel.lookalike) return false;
      if (filter === 'header' && !item.isFromDomain && !item.isReturnPath && !item.isReplyTo) return false;
      if (filter === 'urls' && !item.isUrlTarget) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchDomain = item.domain.toLowerCase().includes(q);
        const matchRegistrar = (item.intel.registration?.registrar || '').toLowerCase().includes(q);
        const matchBrand = (item.intel.lookalike?.brand_name || item.intel.lookalike?.suspected_brand || '').toLowerCase().includes(q);
        const matchRel = item.relationships.some(r => r.toLowerCase().includes(q));
        return matchDomain || matchRegistrar || matchBrand || matchRel;
      }
      return true;
    });
  }, [domainEntities, filter, searchQuery]);

  const lookalikeCount = domainEntities.filter(d => Boolean(d.intel.lookalike)).length;

  return (
    <div className="space-y-4">
      {/* Section Header with Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <Globe className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
              Domain Entities & Relationships ({domainEntities.length})
            </h3>
          </div>
          <p className="text-[11px] font-mono text-foreground-muted">
            Header sender, return-path envelope, link destinations, and authoritative DNS
          </p>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setFilter('all')}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
              filter === 'all'
                ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            All ({domainEntities.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter('header')}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
              filter === 'header'
                ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            Header / Envelope
          </button>
          <button
            type="button"
            onClick={() => setFilter('lookalike')}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
              filter === 'lookalike'
                ? 'bg-danger text-white font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            Lookalikes ({lookalikeCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter('urls')}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
              filter === 'urls'
                ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            URL Targets
          </button>
        </div>
      </div>

      {/* Search Input Bar */}
      <div className="relative">
        <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter domains by name, registrar, mimicked brand, or role..."
          className="w-full pl-9 pr-3 py-1.5 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
        />
      </div>

      {/* Domains List */}
      {filteredDomains.length === 0 ? (
        <div className="p-8 rounded-xl bg-surface-secondary/40 border border-border text-center text-foreground-muted font-mono text-xs">
          No domains matched the specified filter criteria.
        </div>
      ) : (
        <div className="space-y-3">
          {filteredDomains.map((entity) => {
            const isExpanded = Boolean(expandedDomains[entity.domain]);
            const intel = entity.intel;
            const lookalike = intel.lookalike;
            const isLookalike = Boolean(lookalike);
            const dns = intel.dns;
            const reg = intel.registration;

            // Related IPs: A and AAAA records
            const relatedIps = [...(dns?.a || []), ...(dns?.aaaa || [])];

            const ageDisplay = intel.domain_age_days !== undefined && intel.domain_age_days !== null
              ? `${intel.domain_age_days} days old`
              : 'Age unavailable';

            return (
              <div
                key={entity.domain}
                className={`rounded-xl border transition-all ${
                  selectedDomainExternal === entity.domain
                    ? 'border-primary ring-1 ring-primary/30 bg-surface entity-selected'
                    : 'bg-surface border-border hover:border-border-hover'
                } shadow-xs overflow-hidden`}
              >
                {/* Header Row (Clickable) */}
                <div
                  onClick={() => toggleExpand(entity.domain)}
                  className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-surface-secondary/40 transition-colors"
                >
                  <div className="space-y-1.5 min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        aria-label={isExpanded ? 'Collapse' : 'Expand'}
                        className="text-foreground-muted hover:text-foreground transition-transform"
                      >
                        {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      </button>

                      <span className="font-mono text-sm font-bold text-foreground">
                        {entity.domain}
                      </span>
                      <CopyButton text={entity.domain} label="Domain" />

                      {/* Lookalike Warning Badge */}
                      {isLookalike && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-danger/10 text-danger border border-danger/30 flex items-center gap-1">
                          <ShieldAlert className="w-3 h-3" />
                          LOOKALIKE ({Math.round(lookalike!.similarity * 100)}%)
                        </span>
                      )}

                      {/* Resolvability Badge */}
                      {intel.is_resolvable ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-success/10 text-success border border-success/30 flex items-center gap-1">
                          <CheckCircle2 className="w-3 h-3" /> ACTIVE / RESOLVING
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-danger/10 text-danger border border-danger/30 flex items-center gap-1">
                          <XCircle className="w-3 h-3" /> NXDOMAIN
                        </span>
                      )}

                      {intel.newly_registered_domain && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-warning/10 text-warning border border-warning/30">
                          NEW REGISTRATION
                        </span>
                      )}
                    </div>

                    {/* Subtitle: Relationship & Age */}
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs font-mono text-foreground-muted pl-6">
                      <span className="text-primary font-semibold">
                        {entity.relationships.join(' · ')}
                      </span>
                      <span className="text-foreground-subtle">•</span>
                      <span>{ageDisplay}</span>
                      {reg?.registrar && (
                        <>
                          <span className="text-foreground-subtle">•</span>
                          <span className="truncate max-w-[240px]">Registrar: {reg.registrar}</span>
                        </>
                      )}
                    </div>
                  </div>

                  {/* Actions on right */}
                  <div className="flex items-center space-x-2 pl-6 sm:pl-0 shrink-0">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedRawDomain(intel);
                      }}
                      className="px-2.5 py-1 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-[11px] font-mono text-foreground-muted hover:text-foreground transition-colors flex items-center space-x-1 cursor-pointer"
                    >
                      <span>Raw DNS</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                {/* Expanded Content (Progressive Disclosure) */}
                {isExpanded && (
                  <div className="p-4 border-t border-border bg-surface-secondary/20 space-y-4 text-xs font-mono accordion-expand">
                    {/* 1. Lookalike Impersonation Details (if applicable) */}
                    {lookalike && (
                      <div className="p-3.5 rounded-xl bg-danger/10 border border-danger/30 space-y-2">
                        <div className="flex items-center space-x-2 text-danger font-bold">
                          <ShieldAlert className="w-4 h-4" />
                          <span>Brand Impersonation Detection: {lookalike.brand_name}</span>
                        </div>
                        <p className="text-xs text-foreground leading-relaxed">
                          This domain mimics recognized brand <strong className="text-foreground font-bold font-mono">"{lookalike.suspected_brand || lookalike.brand_name}"</strong> with an evaluated visual similarity of <strong className="text-danger font-bold font-mono">{Math.round(lookalike.similarity * 100)}%</strong>.
                        </p>
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {lookalike.techniques.map((tech, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-danger/20 text-danger border border-danger/40"
                            >
                              {formatTechniqueName(tech)}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* 2. Registration Information (Only Backend-Returned Data) */}
                    <div className="p-3.5 rounded-xl bg-surface border border-border space-y-2.5">
                      <div className="flex items-center space-x-2 font-bold text-foreground">
                        <Shield className="w-4 h-4 text-primary" />
                        <span>Registration & WHOIS Timeline</span>
                      </div>

                      {reg && (reg.registrar || reg.registration_date) ? (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          <MetadataRow
                            label="Registrar"
                            value={reg.registrar || 'Not exposed by registrar'}
                          />
                          <MetadataRow
                            label="Domain Age"
                            value={ageDisplay}
                          />
                          <MetadataRow
                            label="Registration Date"
                            value={formatDate(reg.registration_date)}
                          />
                          <MetadataRow
                            label="Expiration Date"
                            value={formatDate(reg.expiration_date)}
                          />
                          {reg.nameservers && reg.nameservers.length > 0 && (
                            <div className="col-span-1 sm:col-span-2">
                              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">
                                Authoritative Nameservers:
                              </span>
                              <div className="flex flex-wrap gap-1 mt-1">
                                {reg.nameservers.map(ns => (
                                  <span key={ns} className="px-2 py-0.5 rounded bg-surface-secondary text-foreground text-[11px] border border-border">
                                    {ns}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <p className="text-xs text-foreground-muted italic">
                          Registration / WHOIS timeline was not returned by the backend DNS resolver for this domain.
                        </p>
                      )}
                    </div>

                    {/* 3. DNS Records (Only Backend-Returned Records) */}
                    <div className="p-3.5 rounded-xl bg-surface border border-border space-y-2.5">
                      <div className="flex items-center space-x-2 font-bold text-foreground">
                        <Server className="w-4 h-4 text-primary" />
                        <span>Authoritative DNS Records</span>
                      </div>

                      {dns && Object.values(dns).some(arr => Array.isArray(arr) && arr.length > 0) ? (
                        <div className="space-y-2">
                          {/* A Records */}
                          {dns.a && dns.a.length > 0 && (
                            <div>
                              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">
                                A Records (IPv4):
                              </span>
                              <div className="flex flex-wrap gap-1.5 mt-1">
                                {dns.a.map(ip => (
                                  <button
                                    key={ip}
                                    type="button"
                                    onClick={() => onSelectIp && onSelectIp(ip)}
                                    className="px-2.5 py-1 rounded bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 flex items-center space-x-1.5 cursor-pointer transition-colors"
                                  >
                                    <span>{ip}</span>
                                    <ExternalLink className="w-3 h-3" />
                                  </button>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* AAAA Records */}
                          {dns.aaaa && dns.aaaa.length > 0 && (
                            <div>
                              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">
                                AAAA Records (IPv6):
                              </span>
                              <div className="flex flex-wrap gap-1.5 mt-1">
                                {dns.aaaa.map(ip => (
                                  <span key={ip} className="px-2 py-0.5 rounded bg-surface-secondary text-foreground border border-border">
                                    {ip}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* MX Records */}
                          {dns.mx && dns.mx.length > 0 && (
                            <div>
                              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">
                                MX Records (Mail Exchangers):
                              </span>
                              <div className="flex flex-wrap gap-1.5 mt-1">
                                {dns.mx.map(mx => (
                                  <span key={mx} className="px-2 py-0.5 rounded bg-surface-secondary text-foreground border border-border">
                                    {mx}
                                  </span>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* TXT Records */}
                          {dns.txt && dns.txt.length > 0 && (
                            <div>
                              <span className="text-[10px] text-foreground-muted uppercase tracking-wider block">
                                TXT Records (SPF / DMARC / Site Verification):
                              </span>
                              <div className="space-y-1 mt-1">
                                {dns.txt.map((txt, idx) => (
                                  <div
                                    key={idx}
                                    className="p-2 rounded bg-surface-secondary text-foreground-muted text-[11px] font-mono break-all border border-border"
                                  >
                                    {txt}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ) : (
                        <p className="text-xs text-foreground-muted italic">
                          No active DNS records returned by authoritative query.
                        </p>
                      )}
                    </div>

                    {/* 4. Related IPs Linkage */}
                    {relatedIps.length > 0 && (
                      <div className="p-3.5 rounded-xl bg-surface border border-border space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
                            Related Infrastructure IPs:
                          </span>
                          <span className="text-[10px] text-primary">Click to inspect in drawer</span>
                        </div>
                        <div className="flex flex-wrap gap-1.5">
                          {relatedIps.map(ip => (
                            <button
                              key={ip}
                              type="button"
                              onClick={() => onSelectIp && onSelectIp(ip)}
                              className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-primary/10 hover:border-primary/40 text-foreground hover:text-primary border border-border text-xs flex items-center space-x-1.5 cursor-pointer transition-colors"
                            >
                              <span>{ip}</span>
                              <ExternalLink className="w-3 h-3" />
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* Level 3 Raw DNS & RDAP Drawer */}
      {selectedRawDomain && (
        <DetailDrawer
          isOpen={Boolean(selectedRawDomain)}
          onClose={() => {
            setSelectedRawDomain(null);
            if (onClearSelectedDomain) onClearSelectedDomain();
          }}
          title={`Domain Intelligence — ${selectedRawDomain.domain}`}
          subtitle="Authoritative DNS records and RDAP WHOIS telemetry"
          data={selectedRawDomain}
          format="json"
        />
      )}
    </div>
  );
};
