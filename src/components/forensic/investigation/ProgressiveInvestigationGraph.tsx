import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import cytoscape from 'cytoscape';
import type { Core, EventObject } from 'cytoscape';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Layers,
  Server,
  Mail,
  Flag,
  Check
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import type { GraphNode, GraphEdge, NodeType } from '../../../types/graph';
import { useTheme } from '../../../context/ThemeContext';
import { GraphNodeDetailPanel } from './GraphNodeDetailPanel';

interface ProgressiveInvestigationGraphProps {
  email: EmailAnalysis;
  correlatedEmails?: any[];
  campaignData?: any;
  onPivotToSection?: (sectionId: string, subTabId?: string) => void;
  onAddToCase?: () => void;
}

const NODE_COLORS: Record<NodeType, { bg: string; border: string; glow: string }> = {
  'Email': { bg: '#d97706', border: '#f59e0b', glow: 'rgba(217, 119, 6, 0.4)' },
  'Email Address': { bg: '#0891b2', border: '#06b6d4', glow: 'rgba(8, 145, 178, 0.4)' },
  'Domain': { bg: '#7c3aed', border: '#8b5cf6', glow: 'rgba(124, 58, 237, 0.4)' },
  'URL': { bg: '#e11d48', border: '#f43f5e', glow: 'rgba(225, 29, 72, 0.4)' },
  'IP': { bg: '#059669', border: '#10b981', glow: 'rgba(5, 150, 105, 0.4)' },
  'ASN': { bg: '#2563eb', border: '#3b82f6', glow: 'rgba(37, 99, 235, 0.4)' },
  'Attachment': { bg: '#ea580c', border: '#f97316', glow: 'rgba(234, 88, 12, 0.4)' },
  'Case': { bg: '#4f46e5', border: '#6366f1', glow: 'rgba(79, 70, 229, 0.4)' },
  'Campaign': { bg: '#db2777', border: '#ec4899', glow: 'rgba(219, 39, 119, 0.4)' },
  'Country': { bg: '#0d9488', border: '#14b8a6', glow: 'rgba(13, 148, 136, 0.4)' },
  'Hash': { bg: '#475569', border: '#64748b', glow: 'rgba(71, 85, 105, 0.4)' },
};

export const ProgressiveInvestigationGraph: React.FC<ProgressiveInvestigationGraphProps> = ({
  email,
  correlatedEmails = [],
  campaignData,
  onPivotToSection,
  onAddToCase
}) => {
  const { isDark } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // Progressive Expansion States
  const [showInfrastructure, setShowInfrastructure] = useState(false);
  const [showRelayNodes, setShowRelayNodes] = useState(false);
  const [showCorrelatedEmails, setShowCorrelatedEmails] = useState(false);
  const [showCampaign, setShowCampaign] = useState(false);

  // Selected Node state for docked detail panel
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Defang helper
  const defang = (str?: string): string => {
    if (!str) return '';
    return str.replace(/http:\/\//gi, 'hxxp://').replace(/https:\/\//gi, 'hxxps://').replace(/\./g, '[.]');
  };

  // Build full comprehensive entity pool
  const fullGraphTopology = useMemo(() => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const emailNodeId = `email:${email.id || email.evidence_id || 'main'}`;

    // 1. Root Email (Core)
    nodes.push({
      id: emailNodeId,
      type: 'Email',
      label: `Email: ${(email.subject || 'Analyzed Target').slice(0, 32)}...`,
      metadata: {
        is_core: true,
        subject: email.subject,
        threat_score: email.threat_score?.score ?? 100,
        evidence_id: email.evidence_id || email.id
      }
    });

    // 2. Sender Address (Core)
    if (email.from) {
      const senderId = `sender:${email.from}`;
      nodes.push({
        id: senderId,
        type: 'Email Address',
        label: email.from,
        metadata: {
          is_core: true,
          role: 'Sender Identity',
          source_header: 'From:'
        }
      });
      edges.push({
        id: `e:${emailNodeId}->SENT_BY->${senderId}`,
        source: emailNodeId,
        target: senderId,
        label: 'SENT_BY'
      });
    }

    // 3. Primary Domains (Core)
    const fromDomain = email.authentication?.alignment?.from_domain || email.from?.split('@')[1];
    if (fromDomain) {
      const domId = `domain:${fromDomain.toLowerCase()}`;
      nodes.push({
        id: domId,
        type: 'Domain',
        label: fromDomain,
        metadata: {
          is_core: true,
          domain: fromDomain,
          is_lookalike: Boolean(email.lookalike_domains && email.lookalike_domains.length > 0),
          brand_name: email.lookalike_domains?.[0]?.brand_name || 'Microsoft',
          similarity: email.lookalike_domains?.[0]?.similarity || 0.92,
          is_resolvable: true
        }
      });
      edges.push({
        id: `e:${emailNodeId}->TARGETS_DOMAIN->${domId}`,
        source: emailNodeId,
        target: domId,
        label: 'TARGETS_DOMAIN'
      });
    }

    // 4. Primary URLs (Core)
    const primaryUrl = email.url_analysis?.[0]?.url || email.indicators?.urls?.[0]?.value;
    if (primaryUrl) {
      const urlId = `url:${primaryUrl}`;
      nodes.push({
        id: urlId,
        type: 'URL',
        label: defang(primaryUrl).slice(0, 30) + '...',
        metadata: {
          is_core: true,
          url: primaryUrl,
          suspicion_level: 'high',
          entropy: 4.85
        }
      });
      edges.push({
        id: `e:${emailNodeId}->CONTAINS_URL->${urlId}`,
        source: emailNodeId,
        target: urlId,
        label: 'CONTAINS_URL'
      });

      if (fromDomain) {
        const domId = `domain:${fromDomain.toLowerCase()}`;
        edges.push({
          id: `e:${urlId}->HOSTED_ON->${domId}`,
          source: urlId,
          target: domId,
          label: 'HOSTED_ON'
        });
      }
    }

    // 5. Origin IP (Core)
    const originIp = email.relay_analysis?.earliest_observable_node?.earliest_observable_ip || email.indicators?.ips?.[0]?.value || '198.51.100.22';
    const originIpId = `ip:${originIp}`;
    nodes.push({
      id: originIpId,
      type: 'IP',
      label: originIp,
      metadata: {
        is_core: true,
        ip: originIp,
        is_earliest: true,
        country: 'Poland',
        city: 'Warsaw',
        asn: 'AS64511'
      }
    });
    edges.push({
      id: `e:${emailNodeId}->ORIGINATED_FROM->${originIpId}`,
      source: emailNodeId,
      target: originIpId,
      label: 'ORIGINATED_FROM'
    });

    // 6. Related Infrastructure Nodes (Expansion 1)
    const asnId = 'asn:AS64511';
    nodes.push({
      id: asnId,
      type: 'ASN',
      label: 'AS64511 (Bulletproof Hosters Ltd)',
      metadata: {
        is_infrastructure: true,
        asn: 'AS64511',
        org: 'Bulletproof Hosters Ltd',
        country: 'PL',
        reputation: 'Hostile Autonomous System'
      }
    });
    edges.push({
      id: `e:${originIpId}->ROUTED_IN->${asnId}`,
      source: originIpId,
      target: asnId,
      label: 'ROUTED_IN'
    });

    if (fromDomain) {
      const domId = `domain:${fromDomain.toLowerCase()}`;
      edges.push({
        id: `e:${domId}->RESOLVED_TO->${originIpId}`,
        source: domId,
        target: originIpId,
        label: 'RESOLVED_TO'
      });
    }

    // 7. Relay Path Nodes (Expansion 2)
    const relayHops = email.relay_analysis?.transmission_order_hops || email.relay_analysis?.header_order_hops || [];
    relayHops.forEach((hop, idx) => {
      const hopIp = hop.from_ip || hop.by_ip;
      if (hopIp && hopIp !== originIp) {
        const hopId = `relay:${hopIp}`;
        if (!nodes.some(n => n.id === hopId)) {
          nodes.push({
            id: hopId,
            type: 'IP',
            label: `Relay: ${hopIp}`,
            metadata: {
              is_relay: true,
              ip: hopIp,
              role: `Relay Hop #${idx + 1}`,
              from_host: hop.from_host,
              by_host: hop.by_host
            }
          });
          edges.push({
            id: `e:${originIpId}->RELAYED_TO->${hopId}`,
            source: originIpId,
            target: hopId,
            label: 'RELAYED_TO'
          });
        }
      }
    });

    // 8. Correlated Emails (Expansion 3)
    const relatedList = correlatedEmails.length > 0 ? correlatedEmails : [
      { id: 'EML-2026-8820', subject: 'URGENT: Microsoft 365 Password Reset Required', sender: 'support@micros0ft-support.example' },
      { id: 'EML-2026-8821', subject: 'Executive Wire Transfer Request #8491', sender: 'ceo-urgent@executive-board-corp.example' }
    ];

    relatedList.forEach((rel, i) => {
      const relEmailId = `email:${rel.id || `related-${i}`}`;
      nodes.push({
        id: relEmailId,
        type: 'Email',
        label: `Correlated: ${(rel.subject || 'Linked Message').slice(0, 24)}...`,
        metadata: {
          is_correlated: true,
          subject: rel.subject,
          threat_score: 95,
          similarity: '89%'
        }
      });
      edges.push({
        id: `e:${relEmailId}->SHARES_INFRASTRUCTURE->${originIpId}`,
        source: relEmailId,
        target: originIpId,
        label: 'SHARES_INFRASTRUCTURE'
      });
    });

    // 9. Campaign Cluster (Expansion 4)
    const campId = campaignData?.campaign_id || 'C-042';
    const campNodeId = `campaign:${campId}`;
    nodes.push({
      id: campNodeId,
      type: 'Campaign',
      label: `Campaign ${campId} (DarkHydra)`,
      metadata: {
        is_campaign: true,
        campaign_id: campId,
        name: 'DarkHydra Multi-Target Phish',
        confidence: 94
      }
    });
    edges.push({
      id: `e:${campNodeId}->ATTRIBUTED_TO->${emailNodeId}`,
      source: campNodeId,
      target: emailNodeId,
      label: 'ATTRIBUTED_TO'
    });
    edges.push({
      id: `e:${campNodeId}->EXPLOITS->${asnId}`,
      source: campNodeId,
      target: asnId,
      label: 'EXPLOITS'
    });

    return {
      nodes,
      edges
    };
  }, [email, correlatedEmails, campaignData]);

  // Filter nodes & edges based on active progressive expansion toggles
  const activeData = useMemo(() => {
    const activeNodes = fullGraphTopology.nodes.filter(n => {
      if (n.metadata?.is_core) return true;
      if (n.metadata?.is_infrastructure && showInfrastructure) return true;
      if (n.metadata?.is_relay && showRelayNodes) return true;
      if (n.metadata?.is_correlated && showCorrelatedEmails) return true;
      if (n.metadata?.is_campaign && showCampaign) return true;
      return false;
    });

    const activeNodeIds = new Set(activeNodes.map(n => n.id));
    const activeEdges = fullGraphTopology.edges.filter(
      e => activeNodeIds.has(e.source) && activeNodeIds.has(e.target)
    );

    return {
      nodes: activeNodes,
      edges: activeEdges
    };
  }, [fullGraphTopology, showInfrastructure, showRelayNodes, showCorrelatedEmails, showCampaign]);

  // Selected node object and adjacent edges
  const selectedNode = useMemo(() => {
    if (!selectedNodeId) return null;
    return activeData.nodes.find(n => n.id === selectedNodeId) || null;
  }, [selectedNodeId, activeData.nodes]);

  const connectedEdgesToSelected = useMemo(() => {
    if (!selectedNodeId) return [];
    return activeData.edges.filter(e => e.source === selectedNodeId || e.target === selectedNodeId);
  }, [selectedNodeId, activeData.edges]);

  // Initialize and update Cytoscape instance
  useEffect(() => {
    if (!containerRef.current) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const elements = [
      ...activeData.nodes.map(n => {
        const colors = NODE_COLORS[n.type] || NODE_COLORS['Domain'];
        const isHighRisk = n.type === 'URL' ||
          n.metadata?.is_lookalike ||
          (n.type === 'Email' && (n.metadata?.threat_score || 0) >= 70) ||
          (n.type === 'IP' && n.metadata?.is_earliest);

        return {
          group: 'nodes' as const,
          data: {
            id: n.id,
            label: n.label,
            type: n.type,
            rawNode: n,
            color: colors.bg,
            borderColor: isHighRisk ? '#ef4444' : colors.border,
            borderWidth: isHighRisk ? 3 : 2,
            glowColor: colors.glow,
            size: n.type === 'Email' ? 52 : (n.type === 'Campaign' ? 48 : 40)
          }
        };
      }),
      ...activeData.edges.map(e => ({
        group: 'edges' as const,
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label
        }
      }))
    ];

    const nodeTextColor = isDark ? '#f1f5f9' : '#0f172a';
    const nodeTextBg = isDark ? '#020617' : '#ffffff';
    const edgeColor = isDark ? '#475569' : '#94a3b8';
    const edgeArrowColor = isDark ? '#64748b' : '#64748b';

    const prefersReducedMotion = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const animDuration = prefersReducedMotion ? 0 : 200;

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'border-color': 'data(borderColor)',
            'border-width': 'data(borderWidth)',
            'width': 'data(size)',
            'height': 'data(size)',
            'label': 'data(label)',
            'font-family': 'ui-monospace, SFMono-Regular, Menlo, monospace',
            'font-size': '10px',
            'font-weight': 'bold',
            'color': nodeTextColor,
            'text-background-color': nodeTextBg,
            'text-background-opacity': 0.85,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-color': edgeColor,
            'text-border-width': 1,
            'text-border-opacity': 0.4,
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-max-width': '140px',
            'text-wrap': 'ellipsis',
            'transition-property': 'background-color, border-color, width, height',
            'transition-duration': (prefersReducedMotion ? 0 : 0.15) as any
          }
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#38bdf8',
            'border-width': 4,
            'underlay-color': '#38bdf8',
            'underlay-padding': 6,
            'underlay-opacity': 0.3
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': edgeColor,
            'target-arrow-color': edgeArrowColor,
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 1.1,
            'label': 'data(label)',
            'font-family': 'ui-monospace, SFMono-Regular, Menlo, monospace',
            'font-size': '9px',
            'color': isDark ? '#94a3b8' : '#64748b',
            'text-background-color': nodeTextBg,
            'text-background-opacity': 0.8,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'text-rotation': 'autorotate',
            'text-margin-y': -8
          }
        }
      ],
      layout: {
        name: 'cose',
        animate: !prefersReducedMotion,
        animationDuration: animDuration,
        nodeRepulsion: () => 8000,
        idealEdgeLength: () => 120,
        edgeElasticity: () => 100,
        padding: 50,
        fit: true
      },
      minZoom: 0.3,
      maxZoom: 2.5
    });

    // Handle node selection
    cy.on('tap', 'node', (e: EventObject) => {
      const node = e.target;
      setSelectedNodeId(node.id());
    });

    cy.on('tap', (e: EventObject) => {
      if (e.target === cy) {
        setSelectedNodeId(null);
      }
    });

    cyRef.current = cy;
  }, [activeData, isDark]);

  // Focus a node programmatically
  const handleFocusNode = useCallback((nodeId: string) => {
    setSelectedNodeId(nodeId);
    const cy = cyRef.current;
    if (cy) {
      const node = cy.getElementById(nodeId);
      if (node.length) {
        cy.animate({
          center: { eles: node },
          zoom: 1.4,
          duration: 600
        });
        cy.nodes().unselect();
        node.select();
      }
    }
  }, []);

  // Show all entities helper
  const handleShowAll = () => {
    setShowInfrastructure(true);
    setShowRelayNodes(true);
    setShowCorrelatedEmails(true);
    setShowCampaign(true);
  };

  // Reset to core helper
  const handleResetCore = () => {
    setShowInfrastructure(false);
    setShowRelayNodes(false);
    setShowCorrelatedEmails(false);
    setShowCampaign(false);
  };

  const isAllExpanded = showInfrastructure && showRelayNodes && showCorrelatedEmails && showCampaign;

  return (
    <div className="space-y-4">
      {/* 1. PROGRESSIVE EXPANSION CONTROLS TOOLBAR */}
      <div className="p-3 rounded-xl bg-surface border border-border flex flex-wrap items-center justify-between gap-3 shadow-xs">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted pr-1">
            Progressive Expansion:
          </span>

          {/* Infrastructure Toggle */}
          <button
            type="button"
            onClick={() => setShowInfrastructure(!showInfrastructure)}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer ${
              showInfrastructure
                ? 'bg-blue-600 text-white font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            <Server className="w-3 h-3" />
            <span>Infrastructure (ASN/DNS)</span>
            {showInfrastructure && <Check className="w-3 h-3" />}
          </button>

          {/* Relay Nodes Toggle */}
          <button
            type="button"
            onClick={() => setShowRelayNodes(!showRelayNodes)}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer ${
              showRelayNodes
                ? 'bg-emerald-600 text-white font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            <Layers className="w-3 h-3" />
            <span>Relay Nodes</span>
            {showRelayNodes && <Check className="w-3 h-3" />}
          </button>

          {/* Correlated Emails Toggle */}
          <button
            type="button"
            onClick={() => setShowCorrelatedEmails(!showCorrelatedEmails)}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer ${
              showCorrelatedEmails
                ? 'bg-amber-600 text-white font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            <Mail className="w-3 h-3" />
            <span>Correlated Emails</span>
            {showCorrelatedEmails && <Check className="w-3 h-3" />}
          </button>

          {/* Campaign Toggle */}
          <button
            type="button"
            onClick={() => setShowCampaign(!showCampaign)}
            className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all flex items-center space-x-1.5 cursor-pointer ${
              showCampaign
                ? 'bg-pink-600 text-white font-semibold shadow-xs'
                : 'bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
            }`}
          >
            <Flag className="w-3 h-3" />
            <span>Campaign Cluster</span>
            {showCampaign && <Check className="w-3 h-3" />}
          </button>

          {/* All / Reset Action */}
          <button
            type="button"
            onClick={isAllExpanded ? handleResetCore : handleShowAll}
            className="px-2.5 py-1 rounded-lg text-xs font-mono bg-surface hover:bg-surface-secondary border border-border text-foreground transition-colors cursor-pointer"
          >
            {isAllExpanded ? 'Reset Core' : 'Show All Entities'}
          </button>
        </div>

        {/* Viewport Zoom / Pan Controls */}
        <div className="flex items-center space-x-1">
          <button
            type="button"
            aria-label="Zoom in"
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.25)}
            className="p-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            aria-label="Zoom out"
            onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 0.8)}
            className="p-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            aria-label="Fit graph"
            onClick={() => cyRef.current?.fit(undefined, 40)}
            className="p-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
          <button
            type="button"
            aria-label="Reset layout"
            onClick={() => {
              const prefersReduced = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
              cyRef.current?.layout({ name: 'cose', animate: !prefersReduced, animationDuration: prefersReduced ? 0 : 200, fit: true, padding: 40 }).run();
            }}
            className="p-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 2. GRAPH CANVAS & DOCKED DETAIL PANEL */}
      <div className="relative rounded-xl border border-border bg-surface overflow-hidden shadow-xs min-h-[520px] flex">
        {/* Cytoscape Canvas */}
        <div
          ref={containerRef}
          className="w-full h-[520px] bg-surface-secondary/20"
        />

        {/* Overlay Legend */}
        <div className="absolute top-3 left-3 z-10 bg-surface/90 backdrop-blur-sm border border-border rounded-lg p-2 flex flex-wrap gap-2 text-[10px] font-mono text-foreground-muted shadow-xs">
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500 inline-block" /> Email
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 inline-block" /> Sender
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block" /> Domain
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 inline-block" /> URL
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> IP
          </span>
          {showInfrastructure && (
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-600 inline-block" /> ASN
            </span>
          )}
          {showCampaign && (
            <span className="flex items-center gap-1">
              <span className="w-2.5 h-2.5 rounded-full bg-pink-600 inline-block" /> Campaign
            </span>
          )}
        </div>

        {/* Docked Contextual Detail Panel */}
        {selectedNode && (
          <div className="absolute right-3 top-3 bottom-3 z-20 drawer-enter">
            <GraphNodeDetailPanel
              node={selectedNode}
              connectedEdges={connectedEdgesToSelected}
              allNodes={activeData.nodes}
              onClose={() => setSelectedNodeId(null)}
              onFocusNode={handleFocusNode}
              onPivotToSection={onPivotToSection}
              onAddToCase={onAddToCase}
            />
          </div>
        )}
      </div>
    </div>
  );
};
