import React, { useState, useMemo } from 'react';
import {
  MapPin,
  Globe,
  Info,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Server,
  ArrowRight
} from 'lucide-react';
import type { EmailAnalysis, IPIntelligence } from '../../../types/forensic';
import { resolveIPIntelligence } from '../../../utils/indicatorHelper';
import { LeafletMap, type MapLocation } from '../../common/LeafletMap';
import { CopyButton } from '../CopyButton';

interface GeographicSummarySectionProps {
  email: EmailAnalysis;
  onSelectIp?: (ip: string) => void;
}

export const GeographicSummarySection: React.FC<GeographicSummarySectionProps> = ({
  email,
  onSelectIp
}) => {
  const [isMapOpen, setIsMapOpen] = useState(false);

  const ipIntelMap: Record<string, IPIntelligence> = email.ip_intelligence || {};
  const earliestIp = email.relay_analysis?.earliest_observable_node?.earliest_observable_ip;

  // Build geolocated nodes from relay path and indicators
  const { geolocatedNodes, mapLocations, originNode, transitNodes, destinationNode } = useMemo(() => {
    const relayHops = email.relay_analysis?.transmission_order_hops || email.relay_analysis?.header_order_hops || [];
    const orderedIpList: { ip: string; role: string; isEarliest: boolean; hopNumber?: number }[] = [];
    const seenIps = new Set<string>();

    // 1. Relay transmission order
    relayHops.forEach((hop, idx) => {
      if (hop.from_ip && !seenIps.has(hop.from_ip)) {
        seenIps.add(hop.from_ip);
        orderedIpList.push({
          ip: hop.from_ip,
          role: hop.from_ip === earliestIp ? 'Origin Infrastructure Hop' : `Relay Transit #${idx + 1}`,
          isEarliest: hop.from_ip === earliestIp,
          hopNumber: hop.hop_number
        });
      }
      if (hop.by_ip && !seenIps.has(hop.by_ip)) {
        seenIps.add(hop.by_ip);
        orderedIpList.push({
          ip: hop.by_ip,
          role: idx === relayHops.length - 1 ? 'Recipient MX Gateway' : `Relay Gateway #${idx + 1}`,
          isEarliest: hop.by_ip === earliestIp,
          hopNumber: hop.hop_number
        });
      }
    });

    // 2. Any remaining indicator IPs
    (email.indicators?.ips || []).forEach(i => {
      if (!seenIps.has(i.value)) {
        seenIps.add(i.value);
        orderedIpList.push({
          ip: i.value,
          role: 'Extracted Indicator IP',
          isEarliest: i.value === earliestIp
        });
      }
    });

    // Resolve intel
    const nodes = orderedIpList.map(item => {
      const intel = resolveIPIntelligence(item.ip, ipIntelMap);
      return {
        ...item,
        intel
      };
    });

    // Filter to valid coordinates
    const geoNodes = nodes.filter(
      n => n.intel.scope !== 'private' && typeof n.intel.latitude === 'number' && typeof n.intel.longitude === 'number'
    );

    const locations: MapLocation[] = geoNodes.map(n => ({
      ip: n.ip,
      latitude: n.intel.latitude!,
      longitude: n.intel.longitude!,
      country: n.intel.country,
      city: n.intel.city,
      asn: n.intel.asn,
      organization: n.intel.organization || n.intel.isp || n.intel.asn_org,
      isEarliest: n.isEarliest
    }));

    const origin = geoNodes.find(n => n.isEarliest) || geoNodes[0] || null;
    const dest = geoNodes.length > 1 ? geoNodes[geoNodes.length - 1] : null;
    const transit = geoNodes.filter(n => n !== origin && n !== dest);

    return {
      geolocatedNodes: geoNodes,
      mapLocations: locations,
      originNode: origin,
      transitNodes: transit,
      destinationNode: dest
    };
  }, [email, ipIntelMap, earliestIp]);

  // Unique countries
  const countries = useMemo(() => {
    const list: string[] = [];
    geolocatedNodes.forEach(n => {
      if (n.intel.country && !list.includes(n.intel.country)) {
        list.push(n.intel.country);
      }
    });
    return list;
  }, [geolocatedNodes]);

  return (
    <div className="space-y-4">
      {/* Section Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <MapPin className="w-4 h-4 text-primary" />
            <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
              Geographic Routing & Infrastructure Trace
            </h3>
          </div>
          <p className="text-[11px] font-mono text-foreground-muted">
            Observed transit path, cross-border jurisdictions, and infrastructure coordinates
          </p>
        </div>

        {/* Prominent "Open Map" Action */}
        <button
          type="button"
          onClick={() => setIsMapOpen(!isMapOpen)}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold flex items-center space-x-1.5 transition-all cursor-pointer ${
            isMapOpen
              ? 'bg-surface-secondary text-foreground border border-border shadow-xs'
              : 'bg-primary hover:bg-primary-hover text-primary-foreground shadow-xs'
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>{isMapOpen ? 'Close Map View' : `Open Map (${mapLocations.length} Nodes)`}</span>
          {isMapOpen ? <ChevronUp className="w-3.5 h-3.5 ml-1" /> : <ChevronDown className="w-3.5 h-3.5 ml-1" />}
        </button>
      </div>

      {/* Mandatory Infrastructure Geolocation Notice */}
      <div className="p-3.5 rounded-xl bg-surface-secondary/70 border border-border flex items-start gap-3 backdrop-blur-sm shadow-xs">
        <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <div className="text-xs font-mono leading-relaxed text-foreground-muted">
          <span className="font-bold text-foreground">Infrastructure Geolocation Notice:</span>{' '}
          IP geolocation represents physical and autonomous infrastructure locations (data centers, cloud hosts, routing relays) and does not establish the physical location or identity of the human sender.
        </div>
      </div>

      {/* Compact Geographic Summary Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Origin Infrastructure */}
        <div className="p-3.5 rounded-xl bg-surface border border-border space-y-1.5 shadow-xs">
          <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
            Origin Infrastructure Node
          </span>
          {originNode ? (
            <div className="space-y-1">
              <div className="text-sm font-mono font-bold text-foreground flex items-center justify-between">
                <span>{originNode.intel.country || 'Unspecified'}</span>
                <span className="text-xs font-normal text-foreground-muted">{originNode.intel.city || 'N/A'}</span>
              </div>
              <div className="text-[11px] font-mono text-warning flex items-center justify-between">
                <span className="truncate max-w-[150px]">{originNode.ip}</span>
                <button
                  type="button"
                  onClick={() => onSelectIp && onSelectIp(originNode.ip)}
                  className="text-primary hover:underline flex items-center gap-0.5 cursor-pointer"
                >
                  <span>Inspect</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </button>
              </div>
              <div className="text-[10px] font-mono text-foreground-muted truncate">
                {originNode.intel.organization || originNode.intel.asn || 'Public Node'}
              </div>
            </div>
          ) : (
            <p className="text-xs font-mono text-foreground-muted italic">Internal network origin</p>
          )}
        </div>

        {/* Intermediate Transit */}
        <div className="p-3.5 rounded-xl bg-surface border border-border space-y-1.5 shadow-xs">
          <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
            Intermediate Relay Transit
          </span>
          <div className="text-sm font-mono font-bold text-foreground">
            {transitNodes.length} Relay Node{transitNodes.length !== 1 ? 's' : ''}
          </div>
          <div className="text-[11px] font-mono text-foreground-muted">
            {transitNodes.length > 0
              ? Array.from(new Set(transitNodes.map(n => n.intel.country).filter(Boolean))).join(', ')
              : 'Direct connection to MX'}
          </div>
          <div className="text-[10px] font-mono text-foreground-subtle">
            Verified header transit trace
          </div>
        </div>

        {/* Destination MX Infrastructure */}
        <div className="p-3.5 rounded-xl bg-surface border border-border space-y-1.5 shadow-xs">
          <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
            Destination MX Gateway
          </span>
          {destinationNode ? (
            <div className="space-y-1">
              <div className="text-sm font-mono font-bold text-foreground flex items-center justify-between">
                <span>{destinationNode.intel.country || 'Recipient Host'}</span>
                <span className="text-xs font-normal text-foreground-muted">{destinationNode.intel.city || 'N/A'}</span>
              </div>
              <div className="text-[11px] font-mono text-foreground-muted flex items-center justify-between">
                <span className="truncate max-w-[150px]">{destinationNode.ip}</span>
                <button
                  type="button"
                  onClick={() => onSelectIp && onSelectIp(destinationNode.ip)}
                  className="text-primary hover:underline flex items-center gap-0.5 cursor-pointer"
                >
                  <span>Inspect</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </button>
              </div>
              <div className="text-[10px] font-mono text-foreground-subtle truncate">
                {destinationNode.intel.organization || 'Inbound Mail Server'}
              </div>
            </div>
          ) : (
            <p className="text-xs font-mono text-foreground-muted italic">Internal relay destination</p>
          )}
        </div>

        {/* Cross-Border Jurisdictions */}
        <div className="p-3.5 rounded-xl bg-surface border border-border space-y-1.5 shadow-xs">
          <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
            Jurisdictions Traversed
          </span>
          <div className="text-sm font-mono font-bold text-foreground">
            {countries.length} Country{countries.length !== 1 ? 'ies' : ''}
          </div>
          <div className="text-[11px] font-mono text-foreground-muted truncate">
            {countries.join(' → ') || 'Local / RFC 1918'}
          </div>
          <div className="text-[10px] font-mono text-primary">
            {countries.length > 1 ? 'Cross-Border Transmission' : 'Domestic / Single Zone'}
          </div>
        </div>
      </div>

      {/* Chronological Transit Flow Bar */}
      {countries.length > 0 && (
        <div className="p-3.5 rounded-xl bg-surface border border-border space-y-2 shadow-xs">
          <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
            Observed Infrastructure Transit Sequence:
          </span>
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            {geolocatedNodes.map((node, idx) => (
              <React.Fragment key={node.ip}>
                <button
                  type="button"
                  onClick={() => onSelectIp && onSelectIp(node.ip)}
                  className={`px-3 py-1.5 rounded-lg border text-left transition-all cursor-pointer flex items-center space-x-2 ${
                    node.isEarliest
                      ? 'bg-warning/10 border-warning/40 text-warning hover:bg-warning/20'
                      : 'bg-surface-secondary border-border text-foreground hover:border-primary/40'
                  }`}
                >
                  <span className="font-bold">{node.intel.country || 'Node'}</span>
                  <span className="text-[10px] text-foreground-muted">({node.intel.city || node.ip})</span>
                  {node.isEarliest && (
                    <span className="text-[9px] px-1 py-0.2 rounded bg-warning text-black font-bold">
                      ORIGIN
                    </span>
                  )}
                </button>

                {idx < geolocatedNodes.length - 1 && (
                  <ArrowRight className="w-3.5 h-3.5 text-foreground-subtle shrink-0" />
                )}
              </React.Fragment>
            ))}
          </div>
        </div>
      )}

      {/* Expandable Leaflet Map Container */}
      {isMapOpen && (
        <div className="rounded-xl border border-border bg-surface p-4 space-y-3 shadow-xs animate-in fade-in duration-200">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="font-bold text-foreground flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-primary" />
              Interactive Geospatial Infrastructure Map
            </span>
            <span className="text-[11px] text-foreground-muted">
              Click node markers to view coordinates & details
            </span>
          </div>

          <LeafletMap locations={mapLocations} height="360px" />
        </div>
      )}

      {/* Geolocated Nodes Table */}
      <div className="rounded-xl border border-border bg-surface overflow-hidden shadow-xs">
        <div className="px-4 py-3 border-b border-border flex items-center justify-between">
          <span className="text-xs font-mono font-bold uppercase text-foreground flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-primary" />
            Geolocated Routing Nodes ({geolocatedNodes.length})
          </span>
          <span className="text-[11px] font-mono text-foreground-muted">
            Click Inspect to view IP side drawer
          </span>
        </div>

        {geolocatedNodes.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-foreground-muted">
            No public IP addresses with valid geolocation coordinates were observed in headers.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-surface-secondary/70 border-b border-border text-[10px] uppercase text-foreground-muted">
                <tr>
                  <th className="px-3.5 py-2.5">IP Address</th>
                  <th className="px-3.5 py-2.5">Role</th>
                  <th className="px-3.5 py-2.5">Location</th>
                  <th className="px-3.5 py-2.5">Autonomous System / Provider</th>
                  <th className="px-3.5 py-2.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {geolocatedNodes.map(node => (
                  <tr
                    key={node.ip}
                    className="hover:bg-surface-secondary/40 transition-colors"
                  >
                    <td className="px-3.5 py-2.5 font-bold text-foreground whitespace-nowrap">
                      <div className="flex items-center space-x-1.5">
                        <span>{node.ip}</span>
                        <CopyButton text={node.ip} label="IP" />
                      </div>
                    </td>
                    <td className="px-3.5 py-2.5 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-semibold ${
                        node.isEarliest
                          ? 'bg-warning/10 text-warning border border-warning/30'
                          : 'bg-surface-secondary text-foreground-subtle border border-border'
                      }`}>
                        {node.role}
                      </span>
                    </td>
                    <td className="px-3.5 py-2.5 text-foreground whitespace-nowrap">
                      {[node.intel.city, node.intel.country].filter(Boolean).join(', ') || 'N/A'}
                    </td>
                    <td className="px-3.5 py-2.5 text-foreground-muted truncate max-w-[240px]">
                      {node.intel.asn ? `${node.intel.asn} · ` : ''}
                      {node.intel.organization || node.intel.isp || 'N/A'}
                    </td>
                    <td className="px-3.5 py-2.5 text-right whitespace-nowrap">
                      <button
                        type="button"
                        onClick={() => onSelectIp && onSelectIp(node.ip)}
                        className="px-2.5 py-1 rounded bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 text-[11px] font-mono inline-flex items-center space-x-1 cursor-pointer transition-colors"
                      >
                        <span>Inspect IP</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
