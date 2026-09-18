import React, { useState } from 'react';
import { Globe, Server, Info, Cloud, Lock, MapPin } from 'lucide-react';
import type { EmailAnalysis, IPIntelligence } from '../../types/forensic';
import { resolveIPIntelligence } from '../../utils/indicatorHelper';
import { resolveConfidenceConclusions } from '../../utils/confidenceResolver';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import { LeafletMap, type MapLocation } from '../common/LeafletMap';
import { StatusRow, DetailDrawer, MetadataRow, ExpandableSection } from '../common/progressive';

interface IPIntelligenceSectionProps {
  email: EmailAnalysis;
}

export const IPIntelligenceSection: React.FC<IPIntelligenceSectionProps> = ({ email }) => {
  const [selectedIpFilter, setSelectedIpFilter] = useState<'all' | 'public' | 'private'>('all');
  const [selectedRawIp, setSelectedRawIp] = useState<IPIntelligence | null>(null);

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
      <ExpandableSection
        title="Observed Infrastructure Map"
        subtitle="Visual mapping of public IP routing nodes and email server infrastructure"
        icon={Globe}
        defaultExpanded={true}
        badge={
          <div className="flex items-center space-x-2">
            <span className="text-xs px-2 py-0.5 rounded-full bg-primary/10 border border-primary/20 text-primary font-normal">
              {mapLocations.length} Geolocated Node{mapLocations.length !== 1 ? 's' : ''}
            </span>
            {geoConclusion && (
              <ConfidenceBadge
                conclusion={geoConclusion}
                allConclusions={conclusions}
                size="sm"
              />
            )}
          </div>
        }
      >
        <LeafletMap locations={mapLocations} height="340px" />
      </ExpandableSection>

      {/* Progressive IP Cards */}
      <ExpandableSection
        title={`Enriched IP Infrastructure Nodes (${filteredIpList.length})`}
        subtitle="Autonomous system routing, provider attribution, and proxy/hosting detection"
        icon={Server}
        defaultExpanded={true}
        actions={
          <div className="flex items-center gap-1 bg-surface-secondary p-1 rounded-control border border-border text-xs font-mono">
            <button
              onClick={() => setSelectedIpFilter('all')}
              className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                selectedIpFilter === 'all'
                  ? 'bg-surface text-foreground font-bold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              All ({allIpList.length})
            </button>
            <button
              onClick={() => setSelectedIpFilter('public')}
              className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                selectedIpFilter === 'public'
                  ? 'bg-surface text-foreground font-bold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Public ({allIpList.filter(i => i.scope === 'public').length})
            </button>
            <button
              onClick={() => setSelectedIpFilter('private')}
              className={`px-3 py-1 rounded-lg font-medium transition-colors cursor-pointer ${
                selectedIpFilter === 'private'
                  ? 'bg-surface text-foreground font-bold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              Private ({allIpList.filter(i => i.scope === 'private').length})
            </button>
          </div>
        }
      >
        {filteredIpList.length === 0 ? (
          <div className="p-8 rounded-xl bg-surface-secondary/40 border border-border text-center text-foreground-muted font-mono text-xs">
            No IP addresses match the selected filter.
          </div>
        ) : (
          <div className="space-y-2.5">
            {filteredIpList.map(item => {
              const isEarliest = item.ip === earliestIp;
              const isPrivate = item.scope === 'private';

              const statusState = item.is_proxy_vpn_tor
                ? 'FAIL'
                : item.is_hosting
                ? 'WARN'
                : isPrivate
                ? 'NONE'
                : isEarliest
                ? 'WARN'
                : 'PASS';

              const statusLabel = item.is_proxy_vpn_tor
                ? 'PROXY / VPN'
                : isPrivate
                ? 'PRIVATE / RFC 1918'
                : isEarliest
                ? 'EARLIEST HOP'
                : 'PUBLIC IP';

              const locationDesc = [item.city, item.country].filter(Boolean).join(', ') ||
                (isPrivate ? 'Internal non-routable address' : 'Observed routing node');

              return (
                <StatusRow
                  key={item.ip}
                  title={item.ip}
                  status={statusState}
                  statusLabel={statusLabel}
                  subtitle={`${locationDesc}${item.asn ? ` · ${item.asn}` : ''}`}
                  defaultExpanded={false}
                  onViewRaw={() => setSelectedRawIp(item)}
                  rawButtonLabel="View technical RDAP & BGP"
                >
                  <div className="space-y-2.5">
                    {/* Flags */}
                    <div className="flex flex-wrap gap-2">
                      {isEarliest && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-warning-surface text-warning border border-warning-border">
                          Earliest Observable Origin Node
                        </span>
                      )}
                      {item.is_hosting && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-primary/10 text-primary border border-primary/20 flex items-center gap-1">
                          <Cloud className="w-3 h-3" /> Hosting / Cloud Infrastructure
                        </span>
                      )}
                      {item.is_proxy_vpn_tor && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-danger-surface text-danger border border-danger-border flex items-center gap-1">
                          <Lock className="w-3 h-3" /> Proxy / VPN / Anonymizer
                        </span>
                      )}
                    </div>

                    {isPrivate ? (
                      <p className="text-xs font-mono text-foreground-muted">
                        This IP address belongs to RFC 1918, loopback, CGNAT, or local link space. It is not queried against public IP geolocation databases.
                      </p>
                    ) : (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                        <MetadataRow
                          label="Location"
                          value={
                            <span className="flex items-center gap-1">
                              <MapPin className="w-3 h-3 text-primary shrink-0" />
                              <span>{item.country || 'Unknown'} {item.country_code ? `(${item.country_code})` : ''} · {[item.city, item.region].filter(Boolean).join(', ') || 'N/A'}</span>
                            </span>
                          }
                        />
                        <MetadataRow label="ASN" value={item.asn || 'N/A'} />
                        <MetadataRow label="Organization / ISP" value={item.organization || item.isp || item.asn_org || 'N/A'} />
                        <MetadataRow label="Timezone" value={item.timezone || 'N/A'} />
                        <MetadataRow label="Coordinates" value={item.latitude && item.longitude ? `${item.latitude.toFixed(4)}, ${item.longitude.toFixed(4)}` : 'N/A'} />
                        <MetadataRow label="Infrastructure Type" value={item.infrastructure_type || 'Observed public node'} />
                      </div>
                    )}
                  </div>
                </StatusRow>
              );
            })}
          </div>
        )}
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawIp && (
        <DetailDrawer
          isOpen={Boolean(selectedRawIp)}
          onClose={() => setSelectedRawIp(null)}
          title={`IP Technical Intelligence — ${selectedRawIp.ip}`}
          subtitle="RDAP registration, BGP autonomous routing, and geolocation payload"
          data={selectedRawIp}
          format="json"
        />
      )}
    </div>
  );
};
