import React from 'react';
import {
  Server,
  Globe,
  MapPin,
  ShieldAlert,
  AlertTriangle,
  ArrowRight,
  Network
} from 'lucide-react';
import type { EmailAnalysis, IPIntelligence, DomainIntelligence } from '../../../types/forensic';
import { resolveIPIntelligence, resolveDomainIntelligence } from '../../../utils/indicatorHelper';

interface IntelligenceSummaryCardProps {
  email: EmailAnalysis;
  onSelectGroup: (group: 'infrastructure' | 'domains' | 'geography') => void;
}

export const IntelligenceSummaryCard: React.FC<IntelligenceSummaryCardProps> = ({
  email,
  onSelectGroup
}) => {
  // Collect all IPs
  const ipIntelMap: Record<string, IPIntelligence> = email.ip_intelligence || {};
  const ipSet = new Set<string>();
  (email.indicators?.ips || []).forEach(i => ipSet.add(i.value));
  (email.relay_analysis?.header_order_hops || []).forEach(h => {
    if (h.from_ip) ipSet.add(h.from_ip);
    if (h.by_ip) ipSet.add(h.by_ip);
  });
  if (email.ips) email.ips.forEach(ip => ipSet.add(ip));

  const allIps = Array.from(ipSet).map(ip => resolveIPIntelligence(ip, ipIntelMap));
  const publicIps = allIps.filter(i => i.scope === 'public');
  const privateIps = allIps.filter(i => i.scope === 'private');
  const suspiciousIps = allIps.filter(i => i.is_proxy_vpn_tor || (i.asn && i.asn.toLowerCase().includes('bulletproof')));

  // Collect all domains
  const domainIntelMap: Record<string, DomainIntelligence> = email.domain_intelligence || {};
  const domainSet = new Set<string>();
  (email.indicators?.domains || []).forEach(d => domainSet.add(d.value.toLowerCase()));
  (email.domains || []).forEach(d => domainSet.add(d.toLowerCase()));
  if (email.authentication?.alignment?.from_domain) domainSet.add(email.authentication.alignment.from_domain.toLowerCase());
  if (email.authentication?.alignment?.reply_to_domain) domainSet.add(email.authentication.alignment.reply_to_domain.toLowerCase());
  if (email.authentication?.alignment?.return_path_domain) domainSet.add(email.authentication.alignment.return_path_domain.toLowerCase());

  const allDomains = Array.from(domainSet).map(dom => resolveDomainIntelligence(dom, domainIntelMap));
  const lookalikeDomains = allDomains.filter(d => Boolean(d.lookalike));
  const newDomains = allDomains.filter(d => Boolean(d.newly_registered_domain));

  // ASNs
  const asns = new Set<string>();
  allIps.forEach(i => {
    if (i.asn) asns.add(i.asn);
  });

  // Countries
  const countries = new Set<string>();
  allIps.forEach(i => {
    if (i.country) countries.add(i.country);
  });

  // Earliest IP info
  const earliestIp = email.relay_analysis?.earliest_observable_node?.earliest_observable_ip;
  const earliestIpObj = earliestIp ? allIps.find(i => i.ip === earliestIp) : null;

  return (
    <div className="p-4 sm:p-5 rounded-xl bg-surface border border-border space-y-4 shadow-xs">
      {/* Header with Title & Jump Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
            <Network className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
                Infrastructure Investigation Workspace
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-primary/10 text-primary border border-primary/20">
                Cross-Entity Grounded
              </span>
            </div>
            <p className="text-[11px] font-mono text-foreground-muted">
              Correlated routing nodes, authoritative domains, and geolocated transmission infrastructure
            </p>
          </div>
        </div>

        {/* Quick-Jump Group Buttons */}
        <div className="flex items-center space-x-1.5 self-start sm:self-auto">
          <button
            type="button"
            onClick={() => onSelectGroup('infrastructure')}
            className="px-2.5 py-1 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-[11px] font-mono text-foreground-muted hover:text-foreground flex items-center space-x-1 transition-colors cursor-pointer"
          >
            <Server className="w-3 h-3 text-primary" />
            <span>IPs ({allIps.length})</span>
          </button>
          <button
            type="button"
            onClick={() => onSelectGroup('domains')}
            className="px-2.5 py-1 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-[11px] font-mono text-foreground-muted hover:text-foreground flex items-center space-x-1 transition-colors cursor-pointer"
          >
            <Globe className="w-3 h-3 text-primary" />
            <span>Domains ({allDomains.length})</span>
          </button>
          <button
            type="button"
            onClick={() => onSelectGroup('geography')}
            className="px-2.5 py-1 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-[11px] font-mono text-foreground-muted hover:text-foreground flex items-center space-x-1 transition-colors cursor-pointer"
          >
            <MapPin className="w-3 h-3 text-primary" />
            <span>Geography ({countries.size})</span>
          </button>
        </div>
      </div>

      {/* 3 Primary Metric Pillars */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {/* Pillar 1: Infrastructure */}
        <div
          onClick={() => onSelectGroup('infrastructure')}
          className="p-3.5 rounded-lg bg-surface-secondary/70 hover:bg-surface-secondary border border-border transition-all cursor-pointer space-y-2 group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider flex items-center gap-1.5">
              <Server className="w-3.5 h-3.5 text-primary" />
              Infrastructure Nodes
            </span>
            <span className="text-xs font-mono text-foreground-muted group-hover:text-primary transition-colors flex items-center gap-0.5">
              Inspect <ArrowRight className="w-3 h-3" />
            </span>
          </div>

          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-mono font-bold text-foreground">
              {allIps.length}
            </span>
            <span className="text-xs font-mono text-foreground-muted">
              ({publicIps.length} Public · {privateIps.length} Private)
            </span>
          </div>

          <div className="flex flex-wrap gap-1 pt-0.5">
            {suspiciousIps.length > 0 ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-danger/10 text-danger border border-danger/30 flex items-center gap-1">
                <AlertTriangle className="w-3 h-3 shrink-0" />
                {suspiciousIps.length} Suspicious / Proxy IP{suspiciousIps.length !== 1 ? 's' : ''}
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface text-foreground-subtle border border-border">
                {asns.size} Autonomous System{asns.size !== 1 ? 's' : ''}
              </span>
            )}
            {earliestIpObj && (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-warning/10 text-warning border border-warning/30 truncate max-w-[200px]">
                Origin: {earliestIpObj.ip}
              </span>
            )}
          </div>
        </div>

        {/* Pillar 2: Domains */}
        <div
          onClick={() => onSelectGroup('domains')}
          className="p-3.5 rounded-lg bg-surface-secondary/70 hover:bg-surface-secondary border border-border transition-all cursor-pointer space-y-2 group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-primary" />
              Observed Domains
            </span>
            <span className="text-xs font-mono text-foreground-muted group-hover:text-primary transition-colors flex items-center gap-0.5">
              Inspect <ArrowRight className="w-3 h-3" />
            </span>
          </div>

          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-mono font-bold text-foreground">
              {allDomains.length}
            </span>
            <span className="text-xs font-mono text-foreground-muted">
              Associated with message
            </span>
          </div>

          <div className="flex flex-wrap gap-1 pt-0.5">
            {lookalikeDomains.length > 0 ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-danger/10 text-danger border border-danger/30 flex items-center gap-1">
                <ShieldAlert className="w-3 h-3 shrink-0" />
                {lookalikeDomains.length} Lookalike Impersonation{lookalikeDomains.length !== 1 ? 's' : ''}
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-success/10 text-success border border-success/30">
                0 Impersonation Flags
              </span>
            )}
            {newDomains.length > 0 && (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-warning/10 text-warning border border-warning/30">
                {newDomains.length} New (&lt;30d)
              </span>
            )}
          </div>
        </div>

        {/* Pillar 3: Geography */}
        <div
          onClick={() => onSelectGroup('geography')}
          className="p-3.5 rounded-lg bg-surface-secondary/70 hover:bg-surface-secondary border border-border transition-all cursor-pointer space-y-2 group"
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider flex items-center gap-1.5">
              <MapPin className="w-3.5 h-3.5 text-primary" />
              Geographic Scope
            </span>
            <span className="text-xs font-mono text-foreground-muted group-hover:text-primary transition-colors flex items-center gap-0.5">
              Inspect <ArrowRight className="w-3 h-3" />
            </span>
          </div>

          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-mono font-bold text-foreground">
              {countries.size}
            </span>
            <span className="text-xs font-mono text-foreground-muted">
              Jurisdiction{countries.size !== 1 ? 's' : ''} crossed
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-1 pt-0.5 text-[10px] font-mono text-foreground-muted">
            {countries.size > 0 ? (
              Array.from(countries).slice(0, 3).map((country) => (
                <span
                  key={country}
                  className="px-2 py-0.5 rounded bg-surface text-foreground border border-border"
                >
                  {country}
                </span>
              ))
            ) : (
              <span className="px-2 py-0.5 rounded bg-surface text-foreground-subtle border border-border">
                Internal RFC 1918 Route
              </span>
            )}
            {countries.size > 3 && (
              <span className="text-foreground-muted">+{countries.size - 3} more</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
