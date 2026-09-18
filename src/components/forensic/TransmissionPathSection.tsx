import React, { useState } from 'react';
import type { RelayPathAnalysis, RelayHop } from '../../types/forensic';
import {
  GitCommit,
  Info,
  Radio,
  FileText,
  Network
} from 'lucide-react';
import { StatusRow, DetailDrawer, MetadataRow, ExpandableSection } from '../common/progressive';

interface TransmissionPathSectionProps {
  relayAnalysis?: RelayPathAnalysis;
}

export const TransmissionPathSection: React.FC<TransmissionPathSectionProps> = ({ relayAnalysis }) => {
  const [viewMode, setViewMode] = useState<'transmission' | 'header'>('transmission');
  const [selectedRawHop, setSelectedRawHop] = useState<RelayHop | null>(null);

  const headerHops = relayAnalysis?.header_order_hops || [];
  const transmissionHops = relayAnalysis?.transmission_order_hops || [];
  const activeHops = viewMode === 'transmission' ? transmissionHops : headerHops;
  const earliestNode = relayAnalysis?.earliest_observable_node;

  const getNodeRoleLabel = (index: number, total: number, mode: 'transmission' | 'header') => {
    if (mode === 'transmission') {
      if (index === 0) return 'Sender Origin Infrastructure';
      if (index === total - 1) return 'Recipient Gateway';
      return `Relay Node #${index + 1}`;
    } else {
      if (index === 0) return 'Recipient Gateway';
      if (index === total - 1) return 'Sender Origin Infrastructure';
      return `Upstream Relay #${index + 1}`;
    }
  };

  return (
    <div className="space-y-5 font-mono">
      {/* Earliest Observable Origin Card */}
      {earliestNode && (
        <div className="p-4 rounded-xl bg-surface-secondary/50 border border-border space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-foreground uppercase tracking-wider">
              Earliest Observable Sender Infrastructure
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-warning-surface text-warning border border-warning-border">
              Confidence: {earliestNode.confidence || 'Calibrated'}
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 text-xs">
            <MetadataRow label="Earliest Observable IP" value={earliestNode.earliest_observable_ip || 'None detected'} />
            <MetadataRow label="Associated Host" value={earliestNode.from_host || 'Unknown host'} />
          </div>

          <p className="text-[11px] text-foreground-muted font-sans pt-1">
            <strong className="text-foreground">Analysis Note: </strong>
            {earliestNode.reason || 'Initial public sending IP observed in email headers.'}
          </p>
        </div>
      )}

      {/* Forensic Trust Notice */}
      <div className="flex items-start space-x-2.5 p-3.5 rounded-xl bg-surface-secondary/70 border border-border text-xs text-foreground-muted leading-relaxed font-sans">
        <Info className="w-4 h-4 text-primary shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-foreground block font-mono text-[11px]">
            Relay Header Trust Hierarchy
          </span>
          <span className="text-foreground-muted text-[11px]">
            {relayAnalysis?.trust_notice ||
              'Headers nearest the recipient mail infrastructure provide stronger evidentiary guarantee than upstream headers, which may be forged by prior nodes.'}
          </span>
        </div>
      </div>

      {/* Main Progressive Relay Path Section */}
      <ExpandableSection
        title="Email Relay Transmission Path"
        subtitle="Reconstructed Received header chain and routing infrastructure analysis"
        icon={GitCommit}
        defaultExpanded={true}
        badge={
          <span className="px-2 py-0.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-normal">
            {activeHops.length} Hop{activeHops.length !== 1 ? 's' : ''} Reconstructed
          </span>
        }
        actions={
          <div className="flex items-center bg-surface-secondary p-1 rounded-control border border-border">
            <button
              type="button"
              onClick={() => setViewMode('transmission')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1.5 cursor-pointer ${
                viewMode === 'transmission'
                  ? 'bg-surface text-foreground border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              <Radio className="w-3.5 h-3.5" />
              <span>Transmission Order</span>
            </button>
            <button
              type="button"
              onClick={() => setViewMode('header')}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center space-x-1.5 cursor-pointer ${
                viewMode === 'header'
                  ? 'bg-surface text-foreground border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground'
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              <span>Header Order</span>
            </button>
          </div>
        }
      >
        {activeHops.length === 0 ? (
          <div className="p-6 text-center rounded-xl bg-surface-secondary/40 border border-border text-foreground-muted text-xs">
            No Received header hops present in this email.
          </div>
        ) : (
          <div className="space-y-2.5">
            {activeHops.map((hop: RelayHop, idx: number) => {
              const roleLabel = getNodeRoleLabel(idx, activeHops.length, viewMode);
              const isOrigin = (viewMode === 'transmission' && idx === 0) || (viewMode === 'header' && idx === activeHops.length - 1);
              const isRecipient = (viewMode === 'transmission' && idx === activeHops.length - 1) || (viewMode === 'header' && idx === 0);

              const statusState = isOrigin ? 'WARN' : isRecipient ? 'PASS' : 'INFO';
              const statusLabel = isOrigin ? 'ORIGIN' : isRecipient ? 'GATEWAY' : `HOP #${hop.hop_number}`;

              const fromDisplay = hop.from_host || hop.from_ip || 'Unspecified Host';
              const byDisplay = hop.by_host || hop.by_ip || 'Recipient Mail System';

              return (
                <StatusRow
                  key={`${viewMode}-hop-${hop.hop_number}`}
                  title={`Hop #${hop.hop_number}: ${fromDisplay} → ${byDisplay}`}
                  status={statusState}
                  statusLabel={statusLabel}
                  subtitle={`${roleLabel}${hop.protocol ? ` · Protocol: ${hop.protocol}` : ''}${hop.timestamp ? ` · ${hop.timestamp}` : ''}`}
                  defaultExpanded={false}
                  onViewRaw={() => setSelectedRawHop(hop)}
                  rawButtonLabel="View raw Received header"
                >
                  <div className="space-y-2.5 text-xs font-mono">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <div className="p-2.5 rounded-lg bg-surface border border-border space-y-1">
                        <span className="text-[10px] text-foreground-muted uppercase font-bold block">
                          Sending Infrastructure (From)
                        </span>
                        <div className="text-foreground font-bold break-all">
                          {hop.from_host || 'Unspecified Host'}
                        </div>
                        <div className="flex items-center space-x-1.5 text-primary text-[11px]">
                          <Network className="w-3 h-3 text-foreground-subtle shrink-0" />
                          <span>IP: {hop.from_ip || 'No IP in header'}</span>
                        </div>
                      </div>

                      <div className="p-2.5 rounded-lg bg-surface border border-border space-y-1">
                        <span className="text-[10px] text-foreground-muted uppercase font-bold block">
                          Receiving Server (By)
                        </span>
                        <div className="text-foreground font-bold break-all">
                          {hop.by_host || 'Unspecified Host'}
                        </div>
                        <div className="flex items-center space-x-1.5 text-primary text-[11px]">
                          <Network className="w-3 h-3 text-foreground-subtle shrink-0" />
                          <span>IP: {hop.by_ip || 'No IP in header'}</span>
                        </div>
                      </div>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                      <MetadataRow label="Parser Confidence" value={hop.parser_confidence || 'High'} />
                      <MetadataRow label="Envelope Recipient" value={hop.recipient || 'N/A'} />
                      <MetadataRow label="Queue / Message ID" value={hop.id || 'N/A'} />
                    </div>
                  </div>
                </StatusRow>
              );
            })}
          </div>
        )}
      </ExpandableSection>

      {/* Level 3 Raw Drawer */}
      {selectedRawHop && (
        <DetailDrawer
          isOpen={Boolean(selectedRawHop)}
          onClose={() => setSelectedRawHop(null)}
          title={`Hop #${selectedRawHop.hop_number} Technical Header Trace`}
          subtitle="Verbatim Received RFC-822 header content and parser tokens"
          data={{
            hop_number: selectedRawHop.hop_number,
            from_host: selectedRawHop.from_host,
            from_ip: selectedRawHop.from_ip,
            by_host: selectedRawHop.by_host,
            by_ip: selectedRawHop.by_ip,
            protocol: selectedRawHop.protocol,
            timestamp: selectedRawHop.timestamp,
            recipient: selectedRawHop.recipient,
            id: selectedRawHop.id,
            parser_confidence: selectedRawHop.parser_confidence,
            raw_header: selectedRawHop.raw
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
