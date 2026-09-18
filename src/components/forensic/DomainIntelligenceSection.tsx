import React, { useState, useEffect } from 'react';
import { Globe, Server, Calendar, Shield, Clock, Info, AlertTriangle, ShieldAlert } from 'lucide-react';
import type { EmailAnalysis, DomainIntelligence } from '../../types/forensic';
import { resolveDomainIntelligence } from '../../utils/indicatorHelper';
import { resolveConfidenceConclusions } from '../../utils/confidenceResolver';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { CopyButton } from './CopyButton';
import { StatusRow, DetailDrawer, MetadataRow, ExpandableSection } from '../common/progressive';

interface DomainIntelligenceSectionProps {
  email: EmailAnalysis;
}

export const DomainIntelligenceSection: React.FC<DomainIntelligenceSectionProps> = ({ email }) => {
  const [filter, setFilter] = useState<'all' | 'lookalike' | 'new' | 'resolvable'>('all');
  const [liveDomainIntel, setLiveDomainIntel] = useState<Record<string, DomainIntelligence>>({});
  const [selectedRawDomain, setSelectedRawDomain] = useState<DomainIntelligence | null>(null);

  const conclusions =
    email.forensic_conclusions && email.forensic_conclusions.length > 0
      ? email.forensic_conclusions
      : resolveConfidenceConclusions(email);
  const lookalikeConclusion = conclusions.find((c) => c.type === 'lookalike_determination');

  // Gather unique domains
  const domainSet = new Set<string>();
  (email.indicators?.domains || []).forEach(d => domainSet.add(d.value.toLowerCase()));
  (email.domains || []).forEach(d => domainSet.add(d.toLowerCase()));
  if (email.authentication?.alignment?.from_domain) domainSet.add(email.authentication.alignment.from_domain.toLowerCase());
  if (email.authentication?.alignment?.reply_to_domain) domainSet.add(email.authentication.alignment.reply_to_domain.toLowerCase());
  if (email.authentication?.alignment?.return_path_domain) domainSet.add(email.authentication.alignment.return_path_domain.toLowerCase());

  const domainKey = Array.from(domainSet).sort().join(',');

  // Auto-enrich any domains missing registration or age via live backend API
  useEffect(() => {
    let isMounted = true;
    const initialMap = email.domain_intelligence || {};
    const domainsToFetch = domainKey ? domainKey.split(',').filter(Boolean) : [];

    domainsToFetch.forEach(async (dom) => {
      const existing = initialMap[dom];
      if (!existing || existing.domain_age_days === undefined || !existing.registration?.registration_date) {
        try {
          const resp = await fetch(`http://localhost:8000/api/emails/lookup-domain/${encodeURIComponent(dom)}`);
          if (resp.ok && isMounted) {
            const data: DomainIntelligence = await resp.json();
            setLiveDomainIntel(prev => {
              if (prev[dom]?.domain_age_days !== undefined) return prev;
              return { ...prev, [dom]: data };
            });
          }
        } catch {
          // Backend offline or unreachable, client fallback remains
        }
      }
    });

    return () => {
      isMounted = false;
    };
  }, [email.id, email.domain_intelligence, domainKey]);

  const domainIntelMap: Record<string, DomainIntelligence> = {
    ...(email.domain_intelligence || {}),
    ...liveDomainIntel
  };

  const domainList: DomainIntelligence[] = Array.from(domainSet).map(dom => {
    return resolveDomainIntelligence(dom, domainIntelMap);
  });

  const lookalikeCount = domainList.filter(d => d.lookalike).length;

  const filteredDomains = domainList.filter(d => {
    if (filter === 'lookalike') return Boolean(d.lookalike);
    if (filter === 'new') return Boolean(d.newly_registered_domain);
    if (filter === 'resolvable') return d.is_resolvable;
    return true;
  });

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

  return (
    <div className="space-y-6">
      {/* Security Notice */}
      <div className="p-4 rounded-xl bg-surface-secondary/70 border border-border flex items-start gap-3 backdrop-blur-sm shadow-xs">
        <Info className="w-5 h-5 text-primary shrink-0 mt-0.5" />
        <div className="text-xs leading-relaxed text-foreground-muted">
          <span className="font-semibold text-foreground">Domain Intelligence Safety Notice:</span>{' '}
          All domain intelligence is resolved strictly via server-side DNS queries and RDAP registration endpoints. Target web servers are never contacted.
        </div>
      </div>

      {/* Lookalike Findings Banner */}
      {lookalikeCount > 0 && (
        <div className="p-4 rounded-xl bg-danger-surface border border-danger-border flex items-start gap-3 backdrop-blur-sm shadow-xs">
          <AlertTriangle className="w-5 h-5 text-danger shrink-0 mt-0.5" />
          <div className="text-xs leading-relaxed text-foreground space-y-1">
            <div>
              <span className="font-bold text-danger uppercase tracking-wider">Potential Brand Impersonation Alert:</span>{' '}
              Found <strong className="text-danger font-bold">{lookalikeCount}</strong> domain{lookalikeCount !== 1 ? 's' : ''} exhibiting deceptive similarity or brand keyword abuse.
            </div>
            {lookalikeConclusion && (
              <div className="pt-1">
                <ConfidenceBadge conclusion={lookalikeConclusion} allConclusions={conclusions} size="sm" />
              </div>
            )}
          </div>
        </div>
      )}

      {/* Progressive Domains Section */}
      <ExpandableSection
        title={`Domain Infrastructure & Lookalike Heuristics (${filteredDomains.length})`}
        subtitle="Registration timelines, brand homoglyph checks, and authoritative DNS records"
        icon={Globe}
        defaultExpanded={true}
        actions={
          <div className="flex items-center gap-1 bg-surface-secondary p-1 rounded-control border border-border text-xs font-mono">
            <button
              onClick={() => setFilter('all')}
              className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                filter === 'all'
                  ? 'bg-surface text-foreground font-bold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              All ({domainList.length})
            </button>
            <button
              onClick={() => setFilter('lookalike')}
              className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                filter === 'lookalike'
                  ? 'bg-danger-surface text-danger font-bold border border-danger-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Lookalike ({lookalikeCount})
            </button>
            <button
              onClick={() => setFilter('new')}
              className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                filter === 'new'
                  ? 'bg-warning-surface text-warning font-bold border border-warning-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              New (&lt; 30d)
            </button>
            <button
              onClick={() => setFilter('resolvable')}
              className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                filter === 'resolvable'
                  ? 'bg-surface text-foreground font-bold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Resolvable
            </button>
          </div>
        }
      >
        {filteredDomains.length === 0 ? (
          <div className="p-8 rounded-xl bg-surface-secondary/40 border border-border text-center text-foreground-muted font-mono text-xs">
            No domains match the selected filter.
          </div>
        ) : (
          <div className="space-y-2.5">
            {filteredDomains.map(item => {
              const ageDisplay = item.domain_age_days !== undefined && item.domain_age_days !== null
                ? `${item.domain_age_days} days`
                : 'Registration age unavailable';

              const isLookalike = Boolean(item.lookalike);
              const statusState = isLookalike ? 'CRITICAL' : !item.is_resolvable ? 'FAIL' : item.newly_registered_domain ? 'WARN' : 'PASS';
              const statusLabel = isLookalike
                ? `IMPERSONATION (${Math.round(item.lookalike!.similarity * 100)}%)`
                : item.newly_registered_domain
                ? 'NEW REGISTRATION'
                : item.is_resolvable
                ? 'ACTIVE'
                : 'NXDOMAIN';

              const subtitle = isLookalike
                ? `Mimics "${item.lookalike!.suspected_brand || item.lookalike!.brand_name}" · ${ageDisplay}`
                : `${ageDisplay}${item.registration.registrar ? ` · ${item.registration.registrar}` : ''}`;

              return (
                <StatusRow
                  key={item.domain}
                  title={item.domain}
                  status={statusState}
                  statusLabel={statusLabel}
                  subtitle={subtitle}
                  defaultExpanded={false}
                  onViewRaw={() => setSelectedRawDomain(item)}
                  rawButtonLabel="View DNS records & RDAP"
                >
                  <div className="space-y-3">
                    {/* Lookalike Detailed Card */}
                    {item.lookalike && (
                      <div className="p-3.5 rounded-xl bg-danger-surface border border-danger-border space-y-2">
                        <div className="flex items-center space-x-2 text-danger font-bold text-xs">
                          <ShieldAlert className="w-4 h-4 text-danger" />
                          <span>Brand Impersonation Heuristics: {item.lookalike.brand_name}</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                          <div className="bg-surface p-2 rounded border border-border">
                            <span className="text-[10px] text-foreground-muted uppercase block">Observed Domain</span>
                            <span className="text-danger font-bold">{item.lookalike.domain}</span>
                          </div>
                          <div className="bg-surface p-2 rounded border border-border">
                            <span className="text-[10px] text-foreground-muted uppercase block">Target Brand Reference</span>
                            <span className="text-success font-bold">{item.lookalike.suspected_brand || item.lookalike.brand_name}</span>
                          </div>
                          <div className="bg-surface p-2 rounded border border-border">
                            <span className="text-[10px] text-foreground-muted uppercase block">Similarity Score</span>
                            <span className="text-warning font-bold">{Math.round(item.lookalike.similarity * 100)}% Match</span>
                          </div>
                        </div>
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {item.lookalike.techniques.map((tech, tIdx) => (
                            <span key={tIdx} className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-danger/10 text-danger border border-danger/30">
                              {formatTechniqueName(tech)}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Registration Details */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                      <MetadataRow
                        label="Domain Age"
                        value={
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3 text-primary" />
                            <span>{ageDisplay}</span>
                          </span>
                        }
                      />
                      <MetadataRow
                        label="Registrar"
                        value={
                          <span className="flex items-center gap-1">
                            <Shield className="w-3 h-3 text-primary" />
                            <span>{item.registration.registrar || 'Unavailable'}</span>
                          </span>
                        }
                      />
                      <MetadataRow
                        label="Registration Date"
                        value={
                          <span className="flex items-center gap-1">
                            <Calendar className="w-3 h-3 text-primary" />
                            <span>{formatDate(item.registration.registration_date)}</span>
                          </span>
                        }
                      />
                      <MetadataRow
                        label="Expiration Date"
                        value={
                          <span className="flex items-center gap-1">
                            <Calendar className="w-3 h-3 text-primary" />
                            <span>{formatDate(item.registration.expiration_date)}</span>
                          </span>
                        }
                      />
                    </div>

                    {/* DNS Records Snapshot */}
                    <div className="p-2.5 rounded-lg bg-surface border border-border flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                      <div className="flex items-center space-x-2">
                        <Server className="w-3.5 h-3.5 text-primary" />
                        <span className="font-bold text-foreground">Authoritative DNS Records:</span>
                      </div>
                      <div className="flex items-center space-x-2 text-[11px]">
                        <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                          {item.dns.a.length + item.dns.aaaa.length} A/AAAA
                        </span>
                        <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                          {item.dns.mx.length} MX
                        </span>
                        <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                          {item.dns.ns.length} NS
                        </span>
                        <span className="px-2 py-0.5 rounded bg-surface-secondary border border-border">
                          {item.dns.txt.length} TXT
                        </span>
                      </div>
                    </div>
                  </div>
                </StatusRow>
              );
            })}
          </div>
        )}
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawDomain && (
        <DetailDrawer
          isOpen={Boolean(selectedRawDomain)}
          onClose={() => setSelectedRawDomain(null)}
          title={`Domain Forensic Dossier — ${selectedRawDomain.domain}`}
          subtitle="DNS zone records, RDAP registration records, and lookalike metrics"
          data={{
            domain: selectedRawDomain.domain,
            punycode: selectedRawDomain.punycode,
            is_resolvable: selectedRawDomain.is_resolvable,
            domain_age_days: selectedRawDomain.domain_age_days,
            registration: selectedRawDomain.registration,
            dns_records: selectedRawDomain.dns,
            lookalike_determination: selectedRawDomain.lookalike
          }}
          format="json"
        >
          {/* Formatted DNS table inside drawer */}
          <div className="space-y-3 pb-3 border-b border-border font-mono text-xs">
            <h4 className="font-bold text-foreground uppercase tracking-wider text-[11px] flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-primary" />
              <span>Resolved DNS Answers</span>
            </h4>

            {/* A/AAAA */}
            <div className="space-y-1">
              <span className="text-[10px] text-foreground-muted uppercase font-bold">A / AAAA Records:</span>
              <div className="flex flex-wrap gap-1.5">
                {[...selectedRawDomain.dns.a, ...selectedRawDomain.dns.aaaa].map((ip, i) => (
                  <div key={i} className="flex items-center space-x-1.5 px-2 py-0.5 rounded bg-surface-secondary border border-border">
                    <span>{ip}</span>
                    <CopyButton text={ip} iconOnly />
                  </div>
                ))}
                {selectedRawDomain.dns.a.length === 0 && selectedRawDomain.dns.aaaa.length === 0 && (
                  <span className="text-foreground-subtle italic text-[11px]">No A records returned.</span>
                )}
              </div>
            </div>

            {/* MX */}
            <div className="space-y-1">
              <span className="text-[10px] text-foreground-muted uppercase font-bold">MX Mail Exchangers:</span>
              <div className="space-y-1">
                {selectedRawDomain.dns.mx.map((mx, i) => (
                  <div key={i} className="flex items-center justify-between p-1.5 rounded bg-surface-secondary border border-border">
                    <span className="break-all">{mx}</span>
                    <CopyButton text={mx} iconOnly />
                  </div>
                ))}
                {selectedRawDomain.dns.mx.length === 0 && (
                  <span className="text-foreground-subtle italic text-[11px]">No MX records returned.</span>
                )}
              </div>
            </div>

            {/* TXT */}
            <div className="space-y-1">
              <span className="text-[10px] text-foreground-muted uppercase font-bold">TXT Records (SPF, DKIM, DMARC, Verification):</span>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {selectedRawDomain.dns.txt.map((txt, i) => (
                  <div key={i} className="p-1.5 rounded bg-surface-secondary border border-border text-[11px] break-all select-all">
                    {txt}
                  </div>
                ))}
                {selectedRawDomain.dns.txt.length === 0 && (
                  <span className="text-foreground-subtle italic text-[11px]">No TXT records returned.</span>
                )}
              </div>
            </div>
          </div>
        </DetailDrawer>
      )}
    </div>
  );
};
