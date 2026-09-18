import React, { useState, useMemo } from 'react';
import {
  Server,
  Cloud,
  Lock,
  MapPin,
  Search,
  ExternalLink,
  AlertTriangle,
  Sparkles
} from 'lucide-react';
import type { EmailAnalysis, IPIntelligence } from '../../../types/forensic';
import { useInvestigation } from '../../../context/InvestigationContext';
import { resolveIPIntelligence } from '../../../utils/indicatorHelper';
import { CopyButton } from '../CopyButton';
import { DetailDrawer, MetadataRow } from '../../common/progressive';

interface InfrastructureIPSectionProps {
  email: EmailAnalysis;
  onSelectDomain?: (domain: string) => void;
  selectedIpExternal?: string | null;
  onClearSelectedIp?: () => void;
}

interface IPEntityItem {
  ip: string;
  intel: IPIntelligence;
  role: string;
  isEarliest: boolean;
  isRelay: boolean;
  isIndicator: boolean;
  hopNumber?: number;
  relatedDomains: string[];
}

export const InfrastructureIPSection: React.FC<InfrastructureIPSectionProps> = ({
  email,
  onSelectDomain,
  selectedIpExternal,
  onClearSelectedIp
}) => {
  const { openCopilotDrawer } = useInvestigation();
  const [filter, setFilter] = useState<'all' | 'public' | 'private' | 'suspicious'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIpForDrawer, setSelectedIpForDrawer] = useState<IPEntityItem | null>(null);

  const ipIntelMap: Record<string, IPIntelligence> = email.ip_intelligence || {};
  const earliestIp = email.relay_analysis?.earliest_observable_node?.earliest_observable_ip;

  // Build mapped IP entities with their relationships to the email
  const ipEntities = useMemo(() => {
    const map = new Map<string, IPEntityItem>();

    // 1. Earliest origin node
    if (earliestIp) {
      const intel = resolveIPIntelligence(earliestIp, ipIntelMap);
      map.set(earliestIp, {
        ip: earliestIp,
        intel,
        role: 'Earliest Observable Origin Node',
        isEarliest: true,
        isRelay: true,
        isIndicator: false,
        hopNumber: 1,
        relatedDomains: []
      });
    }

    // 2. Relay hops
    const relayHops = email.relay_analysis?.transmission_order_hops || email.relay_analysis?.header_order_hops || [];
    relayHops.forEach((hop) => {
      if (hop.from_ip) {
        const ip = hop.from_ip.trim();
        const existing = map.get(ip);
        if (!existing) {
          const intel = resolveIPIntelligence(ip, ipIntelMap);
          map.set(ip, {
            ip,
            intel,
            role: `Relay Hop #${hop.hop_number || 1} (From: ${hop.from_host || 'Unknown'})`,
            isEarliest: ip === earliestIp,
            isRelay: true,
            isIndicator: false,
            hopNumber: hop.hop_number,
            relatedDomains: hop.from_host ? [hop.from_host] : []
          });
        } else if (hop.from_host && !existing.relatedDomains.includes(hop.from_host)) {
          existing.relatedDomains.push(hop.from_host);
        }
      }

      if (hop.by_ip) {
        const ip = hop.by_ip.trim();
        const existing = map.get(ip);
        if (!existing) {
          const intel = resolveIPIntelligence(ip, ipIntelMap);
          map.set(ip, {
            ip,
            intel,
            role: `Relay Node (Received by: ${hop.by_host || 'Gateway'})`,
            isEarliest: ip === earliestIp,
            isRelay: true,
            isIndicator: false,
            hopNumber: hop.hop_number,
            relatedDomains: hop.by_host ? [hop.by_host] : []
          });
        } else if (hop.by_host && !existing.relatedDomains.includes(hop.by_host)) {
          existing.relatedDomains.push(hop.by_host);
        }
      }
    });

    // 3. Extracted indicator IPs
    (email.indicators?.ips || []).forEach((indicator) => {
      const ip = indicator.value.trim();
      const existing = map.get(ip);
      if (!existing) {
        const intel = resolveIPIntelligence(ip, ipIntelMap);
        map.set(ip, {
          ip,
          intel,
          role: indicator.source ? `Extracted Indicator (${indicator.source})` : 'Extracted IOC Indicator',
          isEarliest: ip === earliestIp,
          isRelay: false,
          isIndicator: true,
          relatedDomains: []
        });
      } else {
        existing.isIndicator = true;
      }
    });

    // 4. Raw IP array
    (email.ips || []).forEach((ipStr) => {
      const ip = ipStr.trim();
      if (!map.has(ip)) {
        const intel = resolveIPIntelligence(ip, ipIntelMap);
        map.set(ip, {
          ip,
          intel,
          role: 'Observed Network Node',
          isEarliest: ip === earliestIp,
          isRelay: false,
          isIndicator: false,
          relatedDomains: []
        });
      }
    });

    // 5. Connect domain A/AAAA records to IPs
    const domainMap = email.domain_intelligence || {};
    Object.entries(domainMap).forEach(([dom, dIntel]) => {
      const resolvedIps = [...(dIntel.dns?.a || []), ...(dIntel.dns?.aaaa || [])];
      resolvedIps.forEach(ip => {
        const entity = map.get(ip);
        if (entity) {
          if (!entity.relatedDomains.includes(dom)) {
            entity.relatedDomains.push(dom);
          }
        }
      });
    });

    return Array.from(map.values());
  }, [email, earliestIp, ipIntelMap]);

  // Open drawer if selected externally
  React.useEffect(() => {
    if (selectedIpExternal) {
      const match = ipEntities.find(i => i.ip.toLowerCase() === selectedIpExternal.toLowerCase());
      if (match) {
        setSelectedIpForDrawer(match);
      }
    }
  }, [selectedIpExternal, ipEntities]);

  // Compute risk states for compact presentation
  const getRiskState = (entity: IPEntityItem): {
    badgeClass: string;
    label: string;
    severity: 'CRITICAL' | 'SUSPICIOUS' | 'BENIGN' | 'INFO';
  } => {
    const intel = entity.intel;
    if (intel.is_proxy_vpn_tor) {
      return {
        badgeClass: 'bg-danger/10 text-danger border-danger/30',
        label: 'PROXY / TOR',
        severity: 'CRITICAL'
      };
    }
    if (intel.asn && intel.asn.toLowerCase().includes('bulletproof')) {
      return {
        badgeClass: 'bg-danger/10 text-danger border-danger/30',
        label: 'HOSTILE ASN',
        severity: 'CRITICAL'
      };
    }
    if (entity.isEarliest && intel.is_hosting) {
      return {
        badgeClass: 'bg-warning/10 text-warning border-warning/30',
        label: 'HOSTING ORIGIN',
        severity: 'SUSPICIOUS'
      };
    }
    if (entity.isEarliest) {
      return {
        badgeClass: 'bg-warning/10 text-warning border-warning/30',
        label: 'ORIGIN HOP',
        severity: 'SUSPICIOUS'
      };
    }
    if (intel.scope === 'private') {
      return {
        badgeClass: 'bg-surface-secondary text-foreground-muted border-border',
        label: 'INTERNAL RFC 1918',
        severity: 'INFO'
      };
    }
    return {
      badgeClass: 'bg-success/10 text-success border-success/30',
      label: 'PUBLIC NODE',
      severity: 'BENIGN'
    };
  };

  // Filtered list
  const filteredEntities = useMemo(() => {
    return ipEntities.filter(entity => {
      const risk = getRiskState(entity);
      if (filter === 'public' && entity.intel.scope !== 'public') return false;
      if (filter === 'private' && entity.intel.scope !== 'private') return false;
      if (filter === 'suspicious' && (risk.severity !== 'CRITICAL' && risk.severity !== 'SUSPICIOUS')) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase().trim();
        const matchIp = entity.ip.toLowerCase().includes(q);
        const matchAsn = (entity.intel.asn || '').toLowerCase().includes(q);
        const matchOrg = (entity.intel.organization || entity.intel.isp || '').toLowerCase().includes(q);
        const matchCountry = (entity.intel.country || '').toLowerCase().includes(q);
        const matchRole = entity.role.toLowerCase().includes(q);
        return matchIp || matchAsn || matchOrg || matchCountry || matchRole;
      }
      return true;
    });
  }, [ipEntities, filter, searchQuery]);

  const suspiciousCount = ipEntities.filter(e => {
    const r = getRiskState(e);
    return r.severity === 'CRITICAL' || r.severity === 'SUSPICIOUS';
  }).length;

  return (
    <div className="space-y-4">
      {/* Section Header with Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <Server className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
              Infrastructure IP Entities ({ipEntities.length})
            </h3>
          </div>
          <p className="text-[11px] font-mono text-foreground-muted">
            All relevant routing nodes, transmission relays, and IOC indicators
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
            All ({ipEntities.length})
          </button>
          <button
            type="button"
            onClick={() => setFilter('public')}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
              filter === 'public'
                ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            Public ({ipEntities.filter(i => i.intel.scope === 'public').length})
          </button>
          <button
            type="button"
            onClick={() => setFilter('suspicious')}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
              filter === 'suspicious'
                ? 'bg-danger text-white font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            Suspicious ({suspiciousCount})
          </button>
          <button
            type="button"
            onClick={() => setFilter('private')}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-colors cursor-pointer ${
              filter === 'private'
                ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            Private ({ipEntities.filter(i => i.intel.scope === 'private').length})
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
          placeholder="Filter infrastructure IPs by address, ASN, ISP, or country..."
          className="w-full pl-9 pr-3 py-1.5 bg-surface-secondary border border-border rounded-lg text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
        />
      </div>

      {/* Compact Entity Cards / Table */}
      {filteredEntities.length === 0 ? (
        <div className="p-8 rounded-xl bg-surface-secondary/40 border border-border text-center text-foreground-muted font-mono text-xs">
          No IP addresses matched the specified filter criteria.
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-2.5">
          {filteredEntities.map((entity) => {
            const risk = getRiskState(entity);
            const intel = entity.intel;
            const isPrivate = intel.scope === 'private';
            const locationStr = isPrivate
              ? 'Private / RFC 1918 Address'
              : [intel.city, intel.country].filter(Boolean).join(', ') || 'Location Unspecified';
            const providerStr = intel.organization || intel.isp || intel.asn_org || (isPrivate ? 'Internal Local Network' : 'Unallocated ISP');

            return (
              <div
                key={entity.ip}
                onClick={() => setSelectedIpForDrawer(entity)}
                className={`p-3.5 rounded-xl border transition-all cursor-pointer group flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                  selectedIpExternal === entity.ip
                    ? 'bg-primary/5 border-primary shadow-xs ring-1 ring-primary/30 entity-selected'
                    : 'bg-surface hover:bg-surface-secondary/60 border-border hover:border-border-hover shadow-xs'
                }`}
              >
                {/* Left: IP, Copy, Role, Country, Provider */}
                <div className="space-y-1.5 min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-sm font-bold text-foreground group-hover:text-primary transition-colors">
                      {entity.ip}
                    </span>
                    <CopyButton text={entity.ip} label="IP" />

                    {/* Risk Badge */}
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${risk.badgeClass}`}>
                      {risk.label}
                    </span>

                    {/* Role Tag */}
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary text-foreground-subtle border border-border truncate max-w-[280px]">
                      {entity.role}
                    </span>
                  </div>

                  {/* Summary Line: Country & ASN/Provider */}
                  <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-mono text-foreground-muted">
                    <span className="flex items-center gap-1">
                      <MapPin className="w-3 h-3 text-primary shrink-0" />
                      <span>{locationStr}</span>
                    </span>

                    <span className="text-foreground-subtle">•</span>

                    <span className="flex items-center gap-1 truncate max-w-[340px]">
                      <Server className="w-3 h-3 text-primary shrink-0" />
                      <span>{intel.asn ? `${intel.asn} · ` : ''}{providerStr}</span>
                    </span>

                    {entity.relatedDomains.length > 0 && (
                      <>
                        <span className="text-foreground-subtle">•</span>
                        <span className="text-[11px] text-primary truncate max-w-[200px]">
                          Linked to: {entity.relatedDomains[0]}
                        </span>
                      </>
                    )}
                  </div>
                </div>

                {/* Right: Quick Flags & Action */}
                <div className="flex items-center space-x-2 shrink-0 self-end sm:self-center">
                  {intel.is_hosting && (
                    <span
                      title="Cloud / Datacenter Hosting"
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-primary/10 text-primary border border-primary/20 flex items-center gap-1"
                    >
                      <Cloud className="w-3 h-3" /> Hosting
                    </span>
                  )}
                  {intel.is_proxy_vpn_tor && (
                    <span
                      title="Known Anonymizer / Proxy"
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-danger/10 text-danger border border-danger/30 flex items-center gap-1"
                    >
                      <Lock className="w-3 h-3" /> VPN/Tor
                    </span>
                  )}

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      openCopilotDrawer(
                        `Explain infrastructure IP observable '${entity.ip}' (${entity.role}). What is its ASN reputation (${entity.intel.asn || 'N/A'}), hosting provider (${providerStr}), and risk level in this incident?`,
                        {
                          type: 'IP',
                          identifier: entity.ip,
                          details: `${entity.role} · ${entity.intel.asn || 'ASN'} ${providerStr}`
                        }
                      );
                    }}
                    className="px-2 py-1.5 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary border border-primary/25 text-xs font-mono font-semibold transition-colors flex items-center space-x-1 cursor-pointer"
                    title="Ask AI about this IP"
                  >
                    <Sparkles className="w-3 h-3" />
                    <span className="hidden sm:inline">Ask AI</span>
                  </button>

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedIpForDrawer(entity);
                    }}
                    className="px-3 py-1.5 rounded-lg bg-surface-secondary group-hover:bg-primary group-hover:text-primary-foreground border border-border text-xs font-mono text-foreground-muted transition-colors flex items-center space-x-1 cursor-pointer"
                  >
                    <span>Inspect</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Side DetailDrawer for Selected IP */}
      {selectedIpForDrawer && (
        <DetailDrawer
          isOpen={Boolean(selectedIpForDrawer)}
          onClose={() => {
            setSelectedIpForDrawer(null);
            if (onClearSelectedIp) onClearSelectedIp();
          }}
          title={`Infrastructure Intelligence — ${selectedIpForDrawer.ip}`}
          subtitle={`${selectedIpForDrawer.role} · ASN & BGP Route Telemetry`}
          data={selectedIpForDrawer.intel}
          format="json"
        >
          <div className="space-y-4 mb-4">
            {/* Callout Badge for Earliest Hop */}
            {selectedIpForDrawer.isEarliest && (
              <div className="p-3 rounded-lg bg-warning/10 border border-warning/30 flex items-start gap-2.5 text-xs font-mono text-warning">
                <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                <div>
                  <span className="font-bold">Earliest Observable Origin Node:</span>{' '}
                  This IP address represents the upstream boundary observed in RFC-5322 Received headers. It is the primary candidate for sender infrastructure attribution.
                </div>
              </div>
            )}

            {/* Structured Telemetry Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              <MetadataRow
                label="IP Address"
                value={
                  <span className="flex items-center gap-1.5 font-bold text-foreground">
                    {selectedIpForDrawer.ip}
                    <CopyButton text={selectedIpForDrawer.ip} label="IP" />
                  </span>
                }
              />
              <MetadataRow
                label="Routing Scope"
                value={selectedIpForDrawer.intel.scope === 'private' ? 'Private / RFC 1918' : 'Public Internet'}
              />
              <MetadataRow
                label="Autonomous System"
                value={selectedIpForDrawer.intel.asn || 'Unassigned / Private'}
              />
              <MetadataRow
                label="Organization / ISP"
                value={selectedIpForDrawer.intel.organization || selectedIpForDrawer.intel.isp || 'N/A'}
              />
              <MetadataRow
                label="Geographic Location"
                value={
                  <span className="flex items-center gap-1">
                    <MapPin className="w-3 h-3 text-primary shrink-0" />
                    <span>
                      {[selectedIpForDrawer.intel.city, selectedIpForDrawer.intel.region, selectedIpForDrawer.intel.country].filter(Boolean).join(', ') || 'N/A'}
                      {selectedIpForDrawer.intel.country_code ? ` (${selectedIpForDrawer.intel.country_code})` : ''}
                    </span>
                  </span>
                }
              />
              <MetadataRow
                label="Timezone"
                value={selectedIpForDrawer.intel.timezone || 'N/A'}
              />
              <MetadataRow
                label="Coordinates"
                value={
                  selectedIpForDrawer.intel.latitude && selectedIpForDrawer.intel.longitude
                    ? `${selectedIpForDrawer.intel.latitude.toFixed(4)}, ${selectedIpForDrawer.intel.longitude.toFixed(4)}`
                    : 'N/A'
                }
              />
              <MetadataRow
                label="Infrastructure Type"
                value={selectedIpForDrawer.intel.infrastructure_type || 'Observed Routing Node'}
              />
            </div>

            {/* Related Domains Pill links */}
            {selectedIpForDrawer.relatedDomains.length > 0 && (
              <div className="p-3 rounded-lg bg-surface border border-border space-y-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
                  Associated Domains & Hosts:
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {selectedIpForDrawer.relatedDomains.map((dom) => (
                    <button
                      key={dom}
                      type="button"
                      onClick={() => {
                        setSelectedIpForDrawer(null);
                        if (onSelectDomain) onSelectDomain(dom);
                      }}
                      className="px-2 py-0.5 rounded text-xs font-mono bg-primary/10 text-primary hover:bg-primary/20 border border-primary/30 flex items-center space-x-1 cursor-pointer transition-colors"
                    >
                      <span>{dom}</span>
                      <ExternalLink className="w-2.5 h-2.5" />
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Contextual Ask AI Button inside Drawer */}
            <button
              type="button"
              onClick={() => {
                openCopilotDrawer(
                  `Explain infrastructure IP '${selectedIpForDrawer.ip}' (${selectedIpForDrawer.role}). What is its ASN reputation (${selectedIpForDrawer.intel.asn || 'N/A'}), hosting provider (${selectedIpForDrawer.intel.organization || selectedIpForDrawer.intel.isp || 'N/A'}), and security implications?`,
                  {
                    type: 'IP',
                    identifier: selectedIpForDrawer.ip,
                    details: `${selectedIpForDrawer.role} · ${selectedIpForDrawer.intel.asn || 'ASN'}`
                  }
                );
              }}
              className="w-full py-2 rounded-xl bg-primary/10 hover:bg-primary/20 text-primary border border-primary/25 text-xs font-mono font-bold flex items-center justify-center space-x-1.5 transition-colors cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Ask AI About This IP Address</span>
            </button>
          </div>
        </DetailDrawer>
      )}
    </div>
  );
};
