import React, { useState, useMemo } from 'react';
import type { RelayPathAnalysis, RelayHop, IPIntelligence } from '../../../types/forensic';
import {
  GitCommit,
  ArrowRight,
  Globe,
  Clock,
  Server,
  Building,
  ExternalLink,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { ExpandableSection, DetailDrawer, MetadataRow } from '../../common/progressive';
import { TruncatedForensicValue } from '../TruncatedForensicValue';

interface EmailRelaySubsectionProps {
  relayAnalysis?: RelayPathAnalysis;
  ipIntelligence?: Record<string, IPIntelligence>;
  rawReceived?: string[];
}

const parseDelay = (currentTs?: string, prevTs?: string): { text: string; isInstant: boolean } => {
  if (!prevTs || !currentTs) return { text: 'Initial Origin', isInstant: true };
  const tCurrent = new Date(currentTs).getTime();
  const tPrev = new Date(prevTs).getTime();
  if (isNaN(tCurrent) || isNaN(tPrev)) return { text: 'N/A', isInstant: false };
  const diffSec = (tCurrent - tPrev) / 1000;
  if (diffSec < 0) return { text: 'Clock skew detected', isInstant: false };
  if (diffSec < 1) return { text: '< 1s delay', isInstant: true };
  if (diffSec < 60) return { text: `+${diffSec.toFixed(1)}s delay`, isInstant: false };
  if (diffSec < 3600) {
    const mins = Math.floor(diffSec / 60);
    const secs = Math.round(diffSec % 60);
    return { text: `+${mins}m ${secs}s delay`, isInstant: false };
  }
  const hours = Math.floor(diffSec / 3600);
  const mins = Math.round((diffSec % 3600) / 60);
  return { text: `+${hours}h ${mins}m delay`, isInstant: false };
};

const getRoleTitle = (index: number, total: number): string => {
  if (total === 1) return 'Direct Delivery';
  if (index === 0) return 'Sender';
  if (index === total - 1) return 'Recipient MX';
  if (index === 1 && total > 2) return 'Mail Server';
  return `Relay`;
};

export const EmailRelaySubsection: React.FC<EmailRelaySubsectionProps> = ({
  relayAnalysis,
  ipIntelligence = {},
  rawReceived = []
}) => {
  const [expandedHopIndices, setExpandedHopIndices] = useState<Record<number, boolean>>({});
  const [selectedRawHop, setSelectedRawHop] = useState<RelayHop | null>(null);

  // Transmission order: Chronological sequence from sender origin to recipient mail server
  const hops = useMemo(() => {
    if (relayAnalysis?.transmission_order_hops && relayAnalysis.transmission_order_hops.length > 0) {
      return relayAnalysis.transmission_order_hops;
    }
    // Fallback: reverse raw Received headers
    if (rawReceived && rawReceived.length > 0) {
      return [...rawReceived].reverse().map((raw, idx): RelayHop => ({
        hop_number: idx + 1,
        raw,
        from_host: raw.match(/from\s+([^\s;()]+)/i)?.[1],
        from_ip: raw.match(/\[([0-9a-fA-F:.]+)\]/)?.[1],
        by_host: raw.match(/by\s+([^\s;()]+)/i)?.[1],
        by_ip: undefined,
        protocol: 'ESMTPS',
        parser_confidence: 'medium',
        timestamp: raw.split(';').pop()?.trim()
      }));
    }
    return [];
  }, [relayAnalysis, rawReceived]);

  const toggleHop = (idx: number) => {
    setExpandedHopIndices((prev) => ({
      ...prev,
      [idx]: !prev[idx]
    }));
  };

  const expandAll = () => {
    const all: Record<number, boolean> = {};
    hops.forEach((_, idx) => (all[idx] = true));
    setExpandedHopIndices(all);
  };

  const collapseAll = () => {
    setExpandedHopIndices({});
  };

  return (
    <div className="space-y-4 font-mono">
      <ExpandableSection
        title="Email Relay Path"
        subtitle="Chronological hop reconstruction from sender origin to recipient MX gateway"
        icon={GitCommit}
        defaultExpanded={true}
        badge={
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-primary/10 text-primary border border-primary/20 flex items-center gap-1">
            <span>{hops.length} Chronological Hop{hops.length !== 1 ? 's' : ''}</span>
          </span>
        }
        actions={
          hops.length > 0 ? (
            <div className="flex items-center space-x-2 text-[11px]">
              <button
                type="button"
                onClick={expandAll}
                className="text-primary hover:underline font-semibold cursor-pointer"
              >
                Expand all
              </button>
              <span className="text-border">|</span>
              <button
                type="button"
                onClick={collapseAll}
                className="text-foreground-muted hover:text-foreground font-semibold cursor-pointer"
              >
                Collapse all
              </button>
            </div>
          ) : undefined
        }
      >
        {hops.length === 0 ? (
          <div className="p-6 text-center rounded-xl bg-surface-secondary/40 border border-border text-foreground-muted text-xs">
            No Received header hops present in this email envelope.
          </div>
        ) : (
          <div className="space-y-5">
            {/* 1. SIMPLIFIED CHRONOLOGICAL RELAY PATH VISUALIZATION */}
            <div className="p-4 rounded-xl bg-surface-secondary/40 border border-border space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-bold uppercase text-foreground-muted tracking-wider flex items-center gap-1.5">
                  <Server className="w-3.5 h-3.5 text-primary" />
                  <span>Simplified Chronological Relay Path</span>
                </span>
                <span className="text-[10px] text-foreground-muted">
                  Sender → Mail Server → Relay → Recipient MX
                </span>
              </div>

              {/* Horizontal Pipeline */}
              <div className="overflow-x-auto pb-1.5 scrollbar-thin -mx-1 px-1">
                <div className="flex items-center gap-2 min-w-max pt-1">
                  {hops.map((hop, idx) => {
                    const role = getRoleTitle(idx, hops.length);
                    const isOrigin = idx === 0;
                    const isDestination = idx === hops.length - 1;
                    const activeIp = hop.from_ip || hop.by_ip;
                    const geo = activeIp ? ipIntelligence[activeIp] : undefined;
                    const isExpanded = Boolean(expandedHopIndices[idx]);

                    return (
                      <React.Fragment key={`pipeline-step-${idx}`}>
                        <button
                          type="button"
                          onClick={() => toggleHop(idx)}
                          className={`group p-2.5 rounded-xl border text-left transition-all cursor-pointer flex flex-col min-w-[140px] sm:min-w-[160px] max-w-[220px] ${
                            isExpanded
                              ? 'bg-primary/10 border-primary shadow-xs ring-1 ring-primary/20'
                              : isOrigin
                                ? 'bg-warning-surface/30 border-warning-border/80 hover:border-warning'
                                : isDestination
                                  ? 'bg-success-surface/30 border-success-border/80 hover:border-success'
                                  : 'bg-surface border-border hover:border-primary/50'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className={`text-[10px] font-bold uppercase tracking-wider ${
                              isOrigin ? 'text-warning' : isDestination ? 'text-success' : 'text-primary'
                            }`}>
                              {role}
                            </span>
                            <span className="text-[9px] text-foreground-muted">
                              Hop #{idx + 1}
                            </span>
                          </div>

                          <span className="font-bold text-foreground text-xs truncate block" title={hop.from_host || hop.from_ip || 'Origin Node'}>
                            {hop.from_host || hop.from_ip || 'Origin Node'}
                          </span>

                          <div className="flex items-center space-x-1.5 text-[10px] text-foreground-muted mt-1 truncate">
                            {geo?.country_code && (
                              <span className="font-mono text-foreground font-semibold">
                                {geo.country_code}
                              </span>
                            )}
                            <span className="truncate">{hop.from_ip || 'No IP'}</span>
                          </div>
                        </button>

                        {idx < hops.length - 1 && (
                          <div className="flex items-center justify-center text-foreground-subtle shrink-0 px-0.5">
                            <ArrowRight className="w-4 h-4" />
                          </div>
                        )}
                      </React.Fragment>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* 2. DETAILED CHRONOLOGICAL HOP ROWS */}
            <div className="space-y-3">
              {hops.map((hop, idx) => {
                const role = getRoleTitle(idx, hops.length);
                const isOrigin = idx === 0;
                const isDestination = idx === hops.length - 1;
                const isExpanded = Boolean(expandedHopIndices[idx]);

                const prevHop = idx > 0 ? hops[idx - 1] : undefined;
                const delayInfo = parseDelay(hop.timestamp, prevHop?.timestamp);

                const activeIp = hop.from_ip || hop.by_ip;
                const geo = activeIp ? ipIntelligence[activeIp] : undefined;

                return (
                  <div
                    key={`relay-hop-card-${idx}`}
                    className={`rounded-xl border transition-all ${
                      isExpanded
                        ? 'bg-surface border-primary/40 shadow-xs'
                        : 'bg-surface-secondary/40 border-border hover:border-border-hover'
                    }`}
                  >
                    {/* Header Row (Clickable) */}
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => toggleHop(idx)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          toggleHop(idx);
                        }
                      }}
                      className="p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 cursor-pointer select-none"
                    >
                      <div className="flex items-start sm:items-center space-x-3 min-w-0">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider shrink-0 border ${
                          isOrigin
                            ? 'bg-warning-surface text-warning border-warning-border'
                            : isDestination
                              ? 'bg-success-surface text-success border-success-border'
                              : 'bg-surface text-foreground-muted border-border'
                        }`}>
                          {role} (Hop {idx + 1})
                        </span>

                        <div className="min-w-0 flex-1">
                          <div className="flex items-center space-x-2 flex-wrap">
                            <TruncatedForensicValue
                              value={hop.from_host || hop.from_ip || 'Unspecified Host'}
                              type={hop.from_ip ? 'ip' : 'domain'}
                              maxWidth="max-w-[150px] sm:max-w-[220px] md:max-w-xs"
                            />
                            <ArrowRight className="w-3 h-3 text-foreground-muted shrink-0" />
                            <TruncatedForensicValue
                              value={hop.by_host || hop.by_ip || 'Recipient System'}
                              type={hop.by_ip ? 'ip' : 'domain'}
                              maxWidth="max-w-[150px] sm:max-w-[220px] md:max-w-xs"
                            />
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center justify-between sm:justify-end space-x-3 shrink-0 text-xs">
                        {/* Delay Badge */}
                        <div className="flex items-center space-x-1 text-foreground-muted text-[11px]">
                          <Clock className="w-3 h-3 text-primary shrink-0" />
                          <span>{delayInfo.text}</span>
                        </div>

                        {/* Geolocation Mini */}
                        {geo && (
                          <div className="flex items-center space-x-1 text-[11px] text-foreground-muted">
                            <Globe className="w-3 h-3 text-primary shrink-0" />
                            <span>{geo.city ? `${geo.city}, ` : ''}{geo.country || geo.country_code || 'Geo'}</span>
                          </div>
                        )}

                        <div className="text-foreground-muted">
                          {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </div>
                      </div>
                    </div>

                    {/* Expanded Technical Details */}
                    {isExpanded && (
                      <div className="p-4 border-t border-border bg-surface-secondary/20 space-y-4 text-xs animate-in fade-in duration-150">
                        {/* Hostname & IP Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                          {/* Sending Side (From) */}
                          <div className="p-3 rounded-xl bg-surface border border-border space-y-2">
                            <span className="text-[10px] font-bold uppercase text-foreground-muted tracking-wider block">
                              Sending Node (From)
                            </span>
                            <MetadataRow
                              label="Hostname"
                              value={hop.from_host || 'None specified'}
                              allowCopy={Boolean(hop.from_host)}
                            />
                            <MetadataRow
                              label="IP Address"
                              value={hop.from_ip || 'None detected'}
                              allowCopy={Boolean(hop.from_ip)}
                            />
                          </div>

                          {/* Receiving Side (By) */}
                          <div className="p-3 rounded-xl bg-surface border border-border space-y-2">
                            <span className="text-[10px] font-bold uppercase text-foreground-muted tracking-wider block">
                              Receiving Server (By)
                            </span>
                            <MetadataRow
                              label="Hostname"
                              value={hop.by_host || 'None specified'}
                              allowCopy={Boolean(hop.by_host)}
                            />
                            <MetadataRow
                              label="IP Address"
                              value={hop.by_ip || 'None detected'}
                              allowCopy={Boolean(hop.by_ip)}
                            />
                          </div>
                        </div>

                        {/* Timing, Delay, & Geolocation Grid */}
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                          <div className="p-3 rounded-xl bg-surface border border-border space-y-1.5">
                            <span className="text-[10px] font-bold uppercase text-foreground-muted tracking-wider flex items-center gap-1">
                              <Clock className="w-3 h-3 text-primary" />
                              <span>Timestamp & Latency</span>
                            </span>
                            <div className="text-foreground text-[11px] font-bold break-all">
                              {hop.timestamp || 'Not recorded'}
                            </div>
                            <div className="text-[11px] text-primary">
                              Inter-hop latency: <strong>{delayInfo.text}</strong>
                            </div>
                          </div>

                          <div className="p-3 rounded-xl bg-surface border border-border space-y-1.5">
                            <span className="text-[10px] font-bold uppercase text-foreground-muted tracking-wider flex items-center gap-1">
                              <Globe className="w-3 h-3 text-primary" />
                              <span>Geolocation</span>
                            </span>
                            <div className="text-foreground text-[11px] font-bold">
                              {geo?.country ? `${geo.country} (${geo.country_code || ''})` : 'Geolocation lookup unavailable'}
                            </div>
                            <div className="text-[11px] text-foreground-muted">
                              {geo?.city ? `City: ${geo.city}${geo.region ? `, ${geo.region}` : ''}` : 'Regional data unmapped'}
                            </div>
                          </div>

                          <div className="p-3 rounded-xl bg-surface border border-border space-y-1.5">
                            <span className="text-[10px] font-bold uppercase text-foreground-muted tracking-wider flex items-center gap-1">
                              <Building className="w-3 h-3 text-primary" />
                              <span>Associated Intelligence</span>
                            </span>
                            <div className="text-foreground text-[11px] font-bold truncate" title={geo?.asn_org || geo?.asn || 'ASN unknown'}>
                              {geo?.asn ? `${geo.asn} · ${geo.asn_org || ''}` : 'No ASN listed'}
                            </div>
                            <div className="flex items-center gap-1.5 flex-wrap pt-0.5">
                              {geo?.is_hosting && (
                                <span className="px-1.5 py-0.5 rounded text-[9px] bg-warning-surface text-warning border border-warning-border font-bold">
                                  Hosting / Datacenter
                                </span>
                              )}
                              {geo?.is_proxy_vpn_tor && (
                                <span className="px-1.5 py-0.5 rounded text-[9px] bg-danger-surface text-danger border border-danger-border font-bold">
                                  VPN / Tor / Proxy
                                </span>
                              )}
                              {!geo?.is_hosting && !geo?.is_proxy_vpn_tor && (
                                <span className="text-[10px] text-foreground-muted">
                                  {geo?.isp || 'Standard MTA Infrastructure'}
                                </span>
                              )}
                            </div>
                          </div>
                        </div>

                        {/* Level 3 Raw Received Header Action */}
                        <div className="pt-2 flex items-center justify-between border-t border-border">
                          <span className="text-[10px] text-foreground-muted">
                            Protocol: {hop.protocol || 'ESMTPS'} · Parser confidence: {hop.parser_confidence || 'High'}
                          </span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedRawHop(hop);
                            }}
                            className="px-3 py-1.5 rounded-lg bg-surface border border-border hover:border-primary/50 text-foreground text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
                          >
                            <ExternalLink className="w-3 h-3 text-primary" />
                            <span>View raw Received header</span>
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawHop && (
        <DetailDrawer
          isOpen={Boolean(selectedRawHop)}
          onClose={() => setSelectedRawHop(null)}
          title={`Hop #${selectedRawHop.hop_number} Technical RFC-822 Trace`}
          subtitle="Verbatim Received header string and parsed routing tokens"
          data={{
            hop_number: selectedRawHop.hop_number,
            from_host: selectedRawHop.from_host,
            from_ip: selectedRawHop.from_ip,
            by_host: selectedRawHop.by_host,
            by_ip: selectedRawHop.by_ip,
            protocol: selectedRawHop.protocol,
            timestamp: selectedRawHop.timestamp,
            raw_received_header: selectedRawHop.raw
          }}
          format="json"
        >
          {selectedRawHop.raw && (
            <div className="space-y-1.5 pb-3 border-b border-border font-mono text-xs">
              <span className="text-[10px] text-foreground-muted uppercase font-bold block">
                Literal Received Header String:
              </span>
              <pre className="p-3 rounded-lg bg-neutral-950 text-neutral-200 text-[11px] whitespace-pre-wrap break-all select-all">
                {selectedRawHop.raw}
              </pre>
            </div>
          )}
        </DetailDrawer>
      )}
    </div>
  );
};
