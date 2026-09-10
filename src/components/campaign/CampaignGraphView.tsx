import React, { useEffect, useRef, useState, useMemo } from 'react';
import cytoscape from 'cytoscape';
import type { Core, EventObject } from 'cytoscape';
import type { CampaignDetail } from '../../types/campaign';
import type { GraphNode, GraphEdge, NodeType } from '../../types/graph';
import { useTheme } from '../../context/ThemeContext';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Layers,
  X,
  Copy,
  Check
} from 'lucide-react';

interface CampaignGraphViewProps {
  campaign: CampaignDetail;
  className?: string;
}

const NODE_COLORS: Record<string, { bg: string; border: string; text: string; lightBg: string }> = {
  'Campaign': { bg: '#db2777', border: '#ec4899', text: '#fce7f3', lightBg: 'bg-pink-500/15 text-pink-700 dark:text-pink-300 border-pink-500/30' },
  'Email': { bg: '#d97706', border: '#f59e0b', text: '#fef3c7', lightBg: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30' },
  'Domain': { bg: '#7c3aed', border: '#8b5cf6', text: '#ede9fe', lightBg: 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30' },
  'IP': { bg: '#059669', border: '#10b981', text: '#d1fae5', lightBg: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' },
  'URL': { bg: '#e11d48', border: '#f43f5e', text: '#ffe4e6', lightBg: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30' },
  'Email Address': { bg: '#0891b2', border: '#06b6d4', text: '#cffafe', lightBg: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30' }
};

export const CampaignGraphView: React.FC<CampaignGraphViewProps> = ({ campaign, className = '' }) => {
  const { isDark } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const [layoutName, setLayoutName] = useState<'concentric' | 'cose' | 'breadthfirst' | 'circle'>('concentric');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  const ALL_TYPES: NodeType[] = ['Campaign', 'Email', 'Domain', 'IP', 'URL', 'Email Address'];
  const [selectedTypes, setSelectedTypes] = useState<Set<NodeType>>(new Set(ALL_TYPES));

  // Construct graph elements connecting Campaign to Emails, Domains, IPs, URLs, Recipients
  const graphElements = useMemo(() => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const seenNodeIds = new Set<string>();

    const campId = campaign.campaign_id;
    const campNodeId = `campaign:${campId}`;

    // 1. Central Campaign Node
    nodes.push({
      id: campNodeId,
      type: 'Campaign',
      label: `Campaign ${campId}: ${campaign.name.slice(0, 30)}`,
      metadata: {
        campaign_id: campId,
        confidence: campaign.overall_confidence,
        attack_type: campaign.dominant_attack_type,
        first_seen: campaign.first_seen,
        last_seen: campaign.last_seen
      }
    });
    seenNodeIds.add(campNodeId);

    // 2. Emails (Campaign -> Email)
    for (const em of campaign.emails.slice(0, 10)) {
      const eNodeId = `email:${em.id}`;
      if (!seenNodeIds.has(eNodeId)) {
        seenNodeIds.add(eNodeId);
        nodes.push({
          id: eNodeId,
          type: 'Email',
          label: `Email: ${em.subject.slice(0, 25)}...`,
          metadata: { id: em.id, subject: em.subject, sender: em.sender, date: em.date }
        });
        edges.push({
          id: `edge:${campNodeId}->INCLUDES_EMAIL->${eNodeId}`,
          source: campNodeId,
          target: eNodeId,
          label: 'INCLUDES_EMAIL'
        });
      }
    }

    // 3. Domains (Campaign -> Domain)
    const doms = new Set<string>([
      ...(campaign.domain_summary?.linked_domains || []),
      ...(campaign.domain_summary?.sender_domain ? [campaign.domain_summary.sender_domain] : []),
      ...(campaign.domain_summary?.reply_to_domain ? [campaign.domain_summary.reply_to_domain] : [])
    ]);
    for (const d of Array.from(doms).slice(0, 10)) {
      if (!d) continue;
      const dNodeId = `domain:${d}`;
      if (!seenNodeIds.has(dNodeId)) {
        seenNodeIds.add(dNodeId);
        nodes.push({
          id: dNodeId,
          type: 'Domain',
          label: d,
          metadata: { domain: d }
        });
        edges.push({
          id: `edge:${campNodeId}->UTILIZES_DOMAIN->${dNodeId}`,
          source: campNodeId,
          target: dNodeId,
          label: 'UTILIZES_DOMAIN'
        });
      }
    }

    // 4. IPs (Campaign -> IP)
    const ips = new Set<string>([
      ...(campaign.infrastructure_summary?.origin_ip ? [campaign.infrastructure_summary.origin_ip] : []),
      ...(campaign.infrastructure_summary?.relay_ips || [])
    ]);
    for (const ip of Array.from(ips).slice(0, 8)) {
      if (!ip) continue;
      const ipNodeId = `ip:${ip}`;
      if (!seenNodeIds.has(ipNodeId)) {
        seenNodeIds.add(ipNodeId);
        nodes.push({
          id: ipNodeId,
          type: 'IP',
          label: ip,
          metadata: { ip }
        });
        edges.push({
          id: `edge:${campNodeId}->HOSTED_ON_IP->${ipNodeId}`,
          source: campNodeId,
          target: ipNodeId,
          label: 'HOSTED_ON_IP'
        });
      }
    }

    // 5. URLs (Campaign -> URL)
    const urls = campaign.url_summary?.normalized_urls || [];
    for (const u of urls.slice(0, 8)) {
      if (!u) continue;
      const uHash = u.slice(-10);
      const uNodeId = `url:${uHash}`;
      if (!seenNodeIds.has(uNodeId)) {
        seenNodeIds.add(uNodeId);
        const defanged = u.replace(/http:\/\//gi, 'hxxp://').replace(/https:\/\//gi, 'hxxps://').replace(/\./g, '[.]');
        nodes.push({
          id: uNodeId,
          type: 'URL',
          label: `URL: ${defanged.slice(0, 25)}...`,
          metadata: { url: u, defanged }
        });
        edges.push({
          id: `edge:${campNodeId}->DEPLOYS_URL->${uNodeId}`,
          source: campNodeId,
          target: uNodeId,
          label: 'DEPLOYS_URL'
        });
      }
    }

    // 6. Recipients (Campaign -> Recipient)
    const rcpts = campaign.recipient_summary?.recipients || [];
    for (const r of rcpts.slice(0, 8)) {
      if (!r || !r.includes('@')) continue;
      const rNodeId = `email_addr:${r}`;
      if (!seenNodeIds.has(rNodeId)) {
        seenNodeIds.add(rNodeId);
        nodes.push({
          id: rNodeId,
          type: 'Email Address',
          label: r,
          metadata: { recipient: r, role: 'victim_target' }
        });
        edges.push({
          id: `edge:${campNodeId}->TARGETS_RECIPIENT->${rNodeId}`,
          source: campNodeId,
          target: rNodeId,
          label: 'TARGETS_RECIPIENT'
        });
      }
    }

    return { nodes, edges };
  }, [campaign]);

  // Cytoscape initialization
  useEffect(() => {
    if (!containerRef.current) return;

    const filteredNodes = graphElements.nodes.filter(n => selectedTypes.has(n.type));
    const allowedNodeIds = new Set(filteredNodes.map(n => n.id));
    const filteredEdges = graphElements.edges.filter(e => allowedNodeIds.has(e.source) && allowedNodeIds.has(e.target));

    const cyElements = [
      ...filteredNodes.map(n => {
        const colors = NODE_COLORS[n.type] || NODE_COLORS['Domain'];
        const isCamp = n.type === 'Campaign';
        return {
          group: 'nodes' as const,
          data: {
            id: n.id,
            label: n.label,
            type: n.type,
            rawNode: n,
            color: colors.bg,
            borderColor: colors.border,
            textColor: isDark ? '#f8fafc' : '#0f172a',
            nodeSize: isCamp ? 52 : 36
          }
        };
      }),
      ...filteredEdges.map(e => ({
        group: 'edges' as const,
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          edgeColor: isDark ? '#475569' : '#cbd5e1',
          labelColor: isDark ? '#94a3b8' : '#64748b'
        }
      }))
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: cyElements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'border-width': 2.5,
            'border-color': 'data(borderColor)',
            'width': 'data(nodeSize)',
            'height': 'data(nodeSize)',
            'label': 'data(label)',
            'color': 'data(textColor)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-background-opacity': isDark ? 0.8 : 0.9,
            'text-background-color': isDark ? '#090d16' : '#ffffff',
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-width': 1,
            'text-border-color': isDark ? '#1e293b' : '#e2e8f0',
            'text-max-width': '120px',
            'text-wrap': 'ellipsis'
          }
        },
        {
          selector: 'node[type = "Campaign"]',
          style: {
            'font-weight': 'bold',
            'font-size': '11px',
            'border-width': 4
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 1.8,
            'line-color': 'data(edgeColor)',
            'target-arrow-color': 'data(edgeColor)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.9,
            'label': 'data(label)',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '8px',
            'color': 'data(labelColor)',
            'text-background-opacity': isDark ? 0.75 : 0.85,
            'text-background-color': isDark ? '#090d16' : '#ffffff',
            'text-background-padding': '2px',
            'text-rotation': 'autorotate'
          }
        },
        {
          selector: ':selected',
          style: {
            'border-width': 4,
            'border-color': '#f59e0b',
            'overlay-opacity': 0.2,
            'overlay-color': '#f59e0b'
          }
        }
      ],
      layout: {
        name: layoutName,
        animate: true,
        animationDuration: 400,
        padding: 50,
        ...(layoutName === 'concentric' ? {
          concentric: (node: any) => (node.data('type') === 'Campaign' ? 5 : 1),
          levelWidth: () => 1
        } : {})
      }
    });

    cy.on('tap', 'node', (evt: EventObject) => {
      const raw = evt.target.data('rawNode') as GraphNode;
      setSelectedNode(raw);
    });

    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        setSelectedNode(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [graphElements, selectedTypes, layoutName, isDark]);

  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 40);

  const toggleType = (t: NodeType) => {
    const next = new Set(selectedTypes);
    if (next.has(t)) {
      if (next.size > 1) next.delete(t);
    } else {
      next.add(t);
    }
    setSelectedTypes(next);
  };

  const copyVal = (v: string) => {
    navigator.clipboard.writeText(v);
    setCopiedText(v);
    setTimeout(() => setCopiedText(null), 2000);
  };

  return (
    <div className={`relative bg-surface rounded-2xl border border-border overflow-hidden ${className}`}>
      {/* Top Controls Toolbar */}
      <div className="p-3 bg-surface-secondary/70 border-b border-border flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center space-x-1">
          <span className="text-[11px] text-foreground-muted uppercase mr-2 font-semibold">Entity Filter:</span>
          {ALL_TYPES.map(type => {
            const isSelected = selectedTypes.has(type);
            const color = NODE_COLORS[type] || NODE_COLORS['Domain'];
            return (
              <button
                key={type}
                type="button"
                onClick={() => toggleType(type)}
                className={`px-2.5 py-1 rounded-md text-[11px] transition-all flex items-center space-x-1.5 cursor-pointer border ${
                  isSelected
                    ? `${color.lightBg} font-bold shadow-xs`
                    : 'bg-surface/50 border-border text-foreground-muted opacity-50'
                }`}
              >
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color.bg }} />
                <span>{type}</span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center space-x-2">
          {/* Layout Selector */}
          <div className="flex items-center space-x-1 bg-surface px-2 py-1 rounded-lg border border-border">
            <Layers className="w-3.5 h-3.5 text-foreground-muted" />
            <select
              value={layoutName}
              onChange={e => setLayoutName(e.target.value as any)}
              className="bg-transparent text-foreground text-xs font-mono outline-none cursor-pointer"
            >
              <option value="concentric">Concentric Layout</option>
              <option value="cose">Force Directed (CoSE)</option>
              <option value="breadthfirst">Hierarchical</option>
              <option value="circle">Circular</option>
            </select>
          </div>

          <div className="flex items-center space-x-1">
            <button
              type="button"
              onClick={handleZoomIn}
              className="p-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground transition-colors"
              title="Zoom In"
            >
              <ZoomIn className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={handleZoomOut}
              className="p-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground transition-colors"
              title="Zoom Out"
            >
              <ZoomOut className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={handleFit}
              className="p-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground transition-colors"
              title="Fit to Screen"
            >
              <Maximize2 className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Graph Canvas */}
      <div className="relative h-[620px] w-full bg-surface-secondary/20">
        <div ref={containerRef} className="w-full h-full" />

        {/* Selected Node Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 bg-surface/95 backdrop-blur-md rounded-xl border border-border p-4 shadow-xl text-xs font-mono space-y-3 z-30 animate-in fade-in slide-in-from-right-3 duration-150">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2">
                <span
                  className="w-2.5 h-2.5 rounded-full"
                  style={{ backgroundColor: (NODE_COLORS[selectedNode.type] || NODE_COLORS['Domain']).bg }}
                />
                <span className="font-bold uppercase text-foreground">{selectedNode.type} Node</span>
              </div>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="p-1 text-foreground-muted hover:text-foreground transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div>
              <span className="text-[10px] text-foreground-muted uppercase block">Label:</span>
              <span className="font-semibold text-foreground break-all">{selectedNode.label}</span>
            </div>

            <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
              <span className="text-[10px] text-foreground-muted uppercase block">Metadata Attributes:</span>
              {Object.entries(selectedNode.metadata || {}).map(([k, v]) => (
                <div key={k} className="p-1.5 bg-surface-secondary rounded border border-border/70 text-[11px] flex justify-between gap-2">
                  <span className="text-foreground-muted">{k}:</span>
                  <span className="text-foreground font-semibold truncate max-w-[140px]">{String(v)}</span>
                </div>
              ))}
            </div>

            <button
              type="button"
              onClick={() => copyVal(selectedNode.label)}
              className="w-full py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-primary font-mono text-xs flex items-center justify-center space-x-1.5 transition-colors cursor-pointer"
            >
              {copiedText === selectedNode.label ? (
                <>
                  <Check className="w-3.5 h-3.5 text-success" />
                  <span>COPIED</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  <span>COPY NODE IDENTIFIER</span>
                </>
              )}
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
