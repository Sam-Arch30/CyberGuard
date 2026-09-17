import React, { useState } from 'react';
import { Globe, Server, Shield, MapPin, Info, Cloud, Lock, Cpu } from 'lucide-react';
import type { EmailAnalysis, IPIntelligence } from '../../types/forensic';
import { resolveIPIntelligence } from '../../utils/indicatorHelper';
import { resolveConfidenceConclusions } from '../../utils/confidenceResolver';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { LeafletMap, type MapLocation } from '../common/LeafletMap';

interface IPIntelligenceSectionProps {
  email: EmailAnalysis;
}

export const IPIntelligenceSection: React.FC<IPIntelligenceSectionProps> = ({ email }) => {
  const [selectedIpFilter, setSelectedIpFilter] = useState<'all' | 'public' | 'private'>('all');

  const conclusions =
    email.forensic_conclusions && email.forensic_conclusions.length > 0
      ? email.forensic_conclusions
      : resolveConfidenceConclusions(email);
  const geoConclusion = conclusions.find((c) => c.type === 'geolocation');

  const ipIntelMap: Record<string, IPIntelligence> = email.ip_intelligence || {};
  
  // Extract all unique IPs from indicators and relay path
  const ipSet = new Set<string>();
  (email.indicators?.ips || []).forEach(i => ipSet.add(i.value));
  (email.relay_analysis?.header_order_hops || []).forEach(h => {
    if (h.from_ip) ipSet.add(h.from_ip);
    if (h.by_ip) ipSet.add(h.by_ip);
  });
  if (email.ips) email.ips.forEach(ip => ipSet.add(ip));

  const earliestIp = email.relay_analysis?.earliest_observable_node?.earliest_observable_ip;

  const allIpList: IPIntelligence[] = Array.from(ipSet).map(ip => {
    return resolveIPIntelligence(ip, ipIntelMap);
  });

  const filteredIpList = allIpList.filter(item => {
    if (selectedIpFilter === 'public') return item.scope === 'public';
    if (selectedIpFilter === 'private') return item.scope === 'private';
    return true;
  });

  const mapLocations: MapLocation[] = allIpList
    .filter(item => item.scope !== 'private' && item.latitude !== undefined && item.longitude !== undefined)
    .map(item => ({
      ip: item.ip,
      latitude: item.latitude!,
      longitude: item.longitude!,
      country: item.country,
      city: item.city,
      asn: item.asn,
      organization: item.organization || item.isp || item.asn_org,
      isEarliest: item.ip === earliestIp
    }));

  return (
    <div className="space-y-6">
      {/* Privacy Notice Banner */}
      <div className="p-4 rounded-xl bg-surface-secondary/70 border border-border flex items-start gap-3 backdrop-blur-sm shadow-xs">
        <Info className="w-5 h-5 text-primary shrink-0 mt-0.5" />
        <div className="text-xs leading-relaxed text-foreground-muted">
          <span className="font-semibold text-foreground">Observed Infrastructure Notice:</span>{' '}
          IP geolocation estimates infrastructure location and does not establish the physical location or identity of the sender.
        </div>
      </div>

      {/* Interactive Infrastructure Map */}
      <div className="bg-surface rounded-card border border-border p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-semibold text-foreground flex items-center gap-2">
                Observed Infrastructure Map
                <span className="text-xs px-2 py-0.5 rounded-full bg-primary/10 border border-primary/20 text-primary font-normal">
                  {mapLocations.length} Geolocated Node{mapLocations.length !== 1 ? 's' : ''}
                </span>
              </h3>
              <p className="text-xs text-foreground-muted">Visual mapping of public IP routing nodes and email server infrastructure</p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
            {geoConclusion && (
              <ConfidenceBadge
                conclusion={geoConclusion}
                allConclusions={conclusions}
                size="sm"
              />
            )}
            <div className="flex items-center gap-1 bg-surface-secondary p-1 rounded-control border border-border text-xs font-mono">
              <button
                onClick={() => setSelectedIpFilter('all')}
                className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
                  selectedIpFilter === 'all' ? 'bg-surface text-foreground font-bold border border-border shadow-xs' : 'text-foreground-muted hover:text-foreground'
                }`}
              >
              All ({allIpList.length})
            </button>
            <button
              onClick={() => setSelectedIpFilter('public')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
                selectedIpFilter === 'public' ? 'bg-surface text-foreground font-bold border border-border shadow-xs' : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Public ({allIpList.filter(i => i.scope === 'public').length})
            </button>
            <button
              onClick={() => setSelectedIpFilter('private')}
              className={`px-3 py-1.5 rounded-lg font-medium transition-colors cursor-pointer ${
                selectedIpFilter === 'private' ? 'bg-surface text-foreground font-bold border border-border shadow-xs' : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Private ({allIpList.filter(i => i.scope === 'private').length})
            </button>
          </div>
        </div>
      </div>

        {/* Leaflet Map component */}
        <LeafletMap locations={mapLocations} height="340px" />
      </div>

      {/* IP Intelligence Cards Grid */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-foreground uppercase tracking-wider flex items-center gap-2">
            <Server className="w-4 h-4 text-primary" />
            Enriched IP Infrastructure Cards ({filteredIpList.length})
          </h3>
        </div>

        {filteredIpList.length === 0 ? (
          <div className="p-8 rounded-xl bg-surface-secondary/40 border border-border text-center text-foreground-muted font-mono text-xs">
            No IP addresses match the selected filter.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredIpList.map(item => {
              const isEarliest = item.ip === earliestIp;
              const isPrivate = item.scope === 'private';

              return (
                <div
                  key={item.ip}
                  className={`p-5 rounded-xl border transition-all duration-200 ${
                    isEarliest
                      ? 'bg-surface border-2 border-warning/50 shadow-sm'
                      : isPrivate
                      ? 'bg-surface-secondary/40 border border-border'
                      : 'bg-surface border border-border hover:border-primary/40 shadow-xs'
                  }`}
                >
                  {/* Card Header */}
                  <div className="flex items-start justify-between gap-3 mb-4 pb-3 border-b border-border">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-base font-bold text-foreground tracking-wide">
                          {item.ip}
                        </span>
                        {isEarliest && (
                          <span className="px-2 py-0.5 text-[10px] font-bold uppercase rounded-full bg-warning/15 border border-warning/40 text-warning tracking-wider">
                            Earliest Hop Node
                          </span>
                        )}
                        <span
                          className={`px-2 py-0.5 text-[10px] font-semibold rounded-full border ${
                            isPrivate
                              ? 'bg-surface-secondary text-foreground-muted border-border'
                              : 'bg-primary/10 text-primary border-primary/20'
                          }`}
                        >
                          {item.scope === 'private' ? 'Private / Reserved' : 'Public IP'}
                        </span>
                      </div>
                      <p className="text-xs text-foreground-muted flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 text-foreground-subtle" />
                        {item.infrastructure_type || (isPrivate ? 'Internal infrastructure' : 'Observed infrastructure node')}
                      </p>
                    </div>

                    {/* Infrastructure Badges */}
                    <div className="flex flex-col items-end gap-1.5">
                      {item.is_hosting && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-primary/10 border border-primary/20 text-primary">
                          <Cloud className="w-3 h-3" /> Hosting / Cloud
                        </span>
                      )}
                      {item.is_proxy_vpn_tor && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-danger/10 border border-danger/30 text-danger">
                          <Lock className="w-3 h-3" /> Proxy / VPN / Tor
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Details Grid */}
                  {isPrivate ? (
                    <div className="p-3.5 rounded-xl bg-surface border border-border text-xs text-foreground-muted space-y-1">
                      <div className="font-semibold text-foreground flex items-center gap-1.5">
                        <Shield className="w-3.5 h-3.5 text-foreground-subtle" />
                        Private / Non-Routable Address
                      </div>
                      <p className="text-foreground-muted text-[11px] leading-relaxed">
                        This IP address belongs to RFC 1918, loopback, CGNAT, or local link space. It is not queried against public IP geolocation databases.
                      </p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div className="bg-surface-secondary/50 p-2.5 rounded-lg border border-border">
                        <span className="text-foreground-muted text-[10px] uppercase font-semibold block mb-0.5">Country</span>
                        <div className="font-medium text-foreground flex items-center gap-1.5">
                          <MapPin className="w-3.5 h-3.5 text-primary" />
                          {item.country || 'Unknown'} {item.country_code ? `(${item.country_code})` : ''}
                        </div>
                      </div>

                      <div className="bg-surface-secondary/50 p-2.5 rounded-lg border border-border">
                        <span className="text-foreground-muted text-[10px] uppercase font-semibold block mb-0.5">Region / City</span>
                        <div className="font-medium text-foreground">
                          {[item.city, item.region].filter(Boolean).join(', ') || 'N/A'}
                        </div>
                      </div>

                      <div className="bg-surface-secondary/50 p-2.5 rounded-lg border border-border">
                        <span className="text-foreground-muted text-[10px] uppercase font-semibold block mb-0.5">ASN</span>
                        <div className="font-mono font-semibold text-primary">
                          {item.asn || 'N/A'}
                        </div>
                      </div>

                      <div className="bg-surface-secondary/50 p-2.5 rounded-lg border border-border">
                        <span className="text-foreground-muted text-[10px] uppercase font-semibold block mb-0.5">Timezone</span>
                        <div className="font-medium text-foreground">
                          {item.timezone || 'N/A'}
                        </div>
                      </div>

                      <div className="col-span-2 bg-surface-secondary/50 p-2.5 rounded-lg border border-border">
                        <span className="text-foreground-muted text-[10px] uppercase font-semibold block mb-0.5">Provider / Organization</span>
                        <div className="font-medium text-foreground truncate">
                          {item.organization || item.isp || item.asn_org || 'N/A'}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Geolocation Notice Footer */}
                  <div className="mt-4 pt-2.5 border-t border-border flex items-center justify-between text-[11px] text-foreground-muted">
                    <span>Observed infrastructure location</span>
                    {item.latitude && item.longitude && (
                      <span className="font-mono text-foreground-muted text-[10px]">
                        {item.latitude.toFixed(4)}, {item.longitude.toFixed(4)}
                      </span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
