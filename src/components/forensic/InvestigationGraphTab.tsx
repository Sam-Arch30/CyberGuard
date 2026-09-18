import React, { useEffect, useRef, useState, useMemo } from 'react';
import cytoscape from 'cytoscape';
import type { Core, EventObject } from 'cytoscape';
import type { EmailAnalysis } from '../../types/forensic';
import type { GraphNode, GraphEdge, NodeType, InvestigationGraphData } from '../../types/graph';
import { useTheme } from '../../context/ThemeContext';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  RotateCcw,
  Layers,
  X,
  Copy,
  Check,
  ShieldAlert,
  AlertTriangle,
  Mail,
  AtSign,
  Globe,
  Link as LinkIcon,
  Server,
  Cloud,
  Paperclip,
  Briefcase,
  Flag,
  Share2,
  RefreshCw,
  Hash
} from 'lucide-react';

interface InvestigationGraphTabProps {
  email: EmailAnalysis;
  focusNodeId?: string | null;
}

const NODE_TYPE_COLORS: Record<NodeType, { bg: string; border: string; text: string; lightBg: string }> = {
  'Email': { bg: '#d97706', border: '#f59e0b', text: '#fef3c7', lightBg: 'bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30' },
  'Email Address': { bg: '#0891b2', border: '#06b6d4', text: '#cffafe', lightBg: 'bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30' },
  'Domain': { bg: '#7c3aed', border: '#8b5cf6', text: '#ede9fe', lightBg: 'bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30' },
  'URL': { bg: '#e11d48', border: '#f43f5e', text: '#ffe4e6', lightBg: 'bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30' },
  'IP': { bg: '#059669', border: '#10b981', text: '#d1fae5', lightBg: 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30' },
  'ASN': { bg: '#2563eb', border: '#3b82f6', text: '#dbeafe', lightBg: 'bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30' },
  'Attachment': { bg: '#ea580c', border: '#f97316', text: '#ffedd5', lightBg: 'bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30' },
  'Case': { bg: '#4f46e5', border: '#6366f1', text: '#e0e7ff', lightBg: 'bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30' },
  'Campaign': { bg: '#db2777', border: '#ec4899', text: '#fce7f3', lightBg: 'bg-pink-500/15 text-pink-700 dark:text-pink-300 border-pink-500/30' },
  'Country': { bg: '#0d9488', border: '#14b8a6', text: '#ccfbf1', lightBg: 'bg-teal-500/15 text-teal-700 dark:text-teal-300 border-teal-500/30' },
  'Hash': { bg: '#475569', border: '#64748b', text: '#f8fafc', lightBg: 'bg-slate-500/15 text-slate-700 dark:text-slate-300 border-slate-500/30' },
};

const getNodeIcon = (type: NodeType) => {
  switch (type) {
    case 'Email': return <Mail className="w-3.5 h-3.5" />;
    case 'Email Address': return <AtSign className="w-3.5 h-3.5" />;
    case 'Domain': return <Globe className="w-3.5 h-3.5" />;
    case 'URL': return <LinkIcon className="w-3.5 h-3.5" />;
    case 'IP': return <Server className="w-3.5 h-3.5" />;
    case 'ASN': return <Cloud className="w-3.5 h-3.5" />;
    case 'Attachment': return <Paperclip className="w-3.5 h-3.5" />;
    case 'Case': return <Briefcase className="w-3.5 h-3.5" />;
    case 'Campaign': return <Flag className="w-3.5 h-3.5" />;
    case 'Country': return <Globe className="w-3.5 h-3.5" />;
    case 'Hash': return <Hash className="w-3.5 h-3.5" />;
    default: return <Share2 className="w-3.5 h-3.5" />;
  }
};

export const InvestigationGraphTab: React.FC<InvestigationGraphTabProps> = ({ email, focusNodeId }) => {
  const { isDark } = useTheme();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  // Graph Data State
  const [graphData, setGraphData] = useState<InvestigationGraphData | null>(email.investigation_graph || null);
  const [loading, setLoading] = useState<boolean>(!email.investigation_graph);

  // Filter State
  const ALL_NODE_TYPES: NodeType[] = [
    'Email', 'Email Address', 'Domain', 'URL', 'IP', 'ASN', 'Attachment', 'Case', 'Campaign', 'Country', 'Hash'
  ];
  const [selectedTypes, setSelectedTypes] = useState<Set<NodeType>>(new Set(ALL_NODE_TYPES));

  // Layout State
  const [layoutName, setLayoutName] = useState<'cose' | 'concentric' | 'breadthfirst' | 'circle'>('cose');

  // Selected Node Side Panel
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Defang helper for security: URLs are strictly never clickable
  const defangUrl = (url: string) => {
    if (!url) return '';
    return url.replace(/http:\/\//gi, 'hxxp://').replace(/https:\/\//gi, 'hxxps://').replace(/\./g, '[.]');
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Fetch or construct graph if not already populated
  useEffect(() => {
    if (email.investigation_graph) {
      setGraphData(email.investigation_graph);
      setLoading(false);
      return;
    }

    setLoading(true);
    fetch('http://localhost:8000/api/emails/investigation-graph', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(email)
    })
      .then(res => (res.ok ? res.json() : null))
      .then(data => {
        if (data && data.nodes) {
          setGraphData(data);
        } else {
          // Fallback client-side generation
          setGraphData(buildClientFallbackGraph(email));
        }
      })
      .catch(() => {
        setGraphData(buildClientFallbackGraph(email));
      })
      .finally(() => {
        setLoading(false);
      });
  }, [email]);

  // Client-side fallback if backend API is not responding
  const buildClientFallbackGraph = (em: EmailAnalysis): InvestigationGraphData => {
    const nodes: GraphNode[] = [];
    const edges: GraphEdge[] = [];
    const emailNodeId = `email:${em.id || 'main'}`;

    nodes.push({
      id: emailNodeId,
      type: 'Email',
      label: `Email: ${(em.subject || 'Analyzed Email').slice(0, 35)}...`,
      metadata: { subject: em.subject, threat_score: em.threat_score?.score }
    });

    if (em.from) {
      const fromId = `email_addr:${em.from}`;
      nodes.push({ id: fromId, type: 'Email Address', label: em.from, metadata: { role: 'sender' } });
      edges.push({ id: `edge:${emailNodeId}->SENT_FROM->${fromId}`, source: emailNodeId, target: fromId, label: 'SENT_FROM' });
    }

    (em.urls || []).slice(0, 8).forEach((u, i) => {
      const urlId = `url:${i}`;
      nodes.push({ id: urlId, type: 'URL', label: defangUrl(u).slice(0, 30), metadata: { url: u } });
      edges.push({ id: `edge:${emailNodeId}->CONTAINS_URL->${urlId}`, source: emailNodeId, target: urlId, label: 'CONTAINS_URL' });
    });

    (em.domains || []).slice(0, 6).forEach((d) => {
      const domId = `domain:${d}`;
      nodes.push({ id: domId, type: 'Domain', label: d, metadata: { domain: d } });
    });

    (em.ips || []).slice(0, 5).forEach((ip) => {
      const ipId = `ip:${ip}`;
      nodes.push({ id: ipId, type: 'IP', label: ip, metadata: { ip } });
      edges.push({ id: `edge:${emailNodeId}->ROUTED_THROUGH->${ipId}`, source: emailNodeId, target: ipId, label: 'ROUTED_THROUGH' });
    });

    return {
      nodes,
      edges,
      summary: { total_nodes: nodes.length, total_edges: edges.length, node_type_counts: {} }
    };
  };

  // Filtered nodes and edges
  const filteredData = useMemo(() => {
    if (!graphData) return { nodes: [], edges: [] };
    const validNodes = graphData.nodes.filter(n => selectedTypes.has(n.type));
    const validNodeIds = new Set(validNodes.map(n => n.id));
    const validEdges = graphData.edges.filter(e => validNodeIds.has(e.source) && validNodeIds.has(e.target));
    return { nodes: validNodes, edges: validEdges };
  }, [graphData, selectedTypes]);

  // Compute node counts per type
  const typeCounts = useMemo(() => {
    const counts: Partial<Record<NodeType, number>> = {};
    if (!graphData) return counts;
    for (const n of graphData.nodes) {
      counts[n.type] = (counts[n.type] || 0) + 1;
    }
    return counts;
  }, [graphData]);

  // Initialize and update Cytoscape
  useEffect(() => {
    if (!containerRef.current || !filteredData.nodes.length) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cyElements = [
      ...filteredData.nodes.map(n => {
        const colors = NODE_TYPE_COLORS[n.type] || NODE_TYPE_COLORS['Domain'];
        const isHighRisk = n.metadata?.is_lookalike ||
                           n.metadata?.suspicion_level === 'high' ||
                           n.metadata?.is_dangerous_extension ||
                           (n.type === 'Email' && (n.metadata?.threat_score || 0) >= 70);

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
            borderStyle: isHighRisk ? 'solid' : 'solid',
            size: n.type === 'Email' ? 52 : (n.type === 'Domain' || n.type === 'IP' ? 44 : 38)
          }
        };
      }),
      ...filteredData.edges.map(e => ({
        group: 'edges' as const,
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label,
          rawEdge: e
        }
      }))
    ];

    const nodeTextColor = isDark ? '#f1f5f9' : '#0f172a';
    const nodeTextBg = isDark ? '#020617' : '#ffffff';
    const nodeTextBorder = isDark ? '#1e293b' : '#cbd5e1';
    const edgeLineColor = isDark ? '#334155' : '#cbd5e1';
    const edgeArrowColor = isDark ? '#64748b' : '#94a3b8';
    const edgeTextColor = isDark ? '#94a3b8' : '#475569';
    const edgeTextBg = isDark ? '#020617' : '#ffffff';

    const cy = cytoscape({
      container: containerRef.current,
      elements: cyElements,
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
            'color': nodeTextColor,
            'font-family': 'monospace',
            'font-size': '11px',
            'font-weight': 'bold',
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-background-color': nodeTextBg,
            'text-background-opacity': 0.88,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-border-color': nodeTextBorder,
            'text-border-width': 1,
            'text-border-opacity': 0.8,
            'text-max-width': '120px',
            'text-wrap': 'ellipsis'
          }
        },
        {
          selector: 'edge',
          style: {
            'width': 2,
            'line-color': edgeLineColor,
            'target-arrow-color': edgeArrowColor,
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.9,
            'label': 'data(label)',
            'font-family': 'monospace',
            'font-size': '8px',
            'color': edgeTextColor,
            'text-rotation': 'autorotate',
            'text-background-color': edgeTextBg,
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'text-background-shape': 'roundrectangle',
            'text-margin-y': -4
          }
        },
        {
          selector: ':selected',
          style: {
            'border-color': '#06b6d4',
            'border-width': 4,
            'underlay-color': '#06b6d4',
            'underlay-padding': 6,
            'underlay-opacity': 0.35
          }
        },
        {
          selector: '.highlighted-node',
          style: {
            'border-color': '#06b6d4',
            'border-width': 4,
            'underlay-color': '#06b6d4',
            'underlay-padding': 6,
            'underlay-opacity': 0.35
          }
        },
        {
          selector: '.highlighted-edge',
          style: {
            'line-color': '#06b6d4',
            'target-arrow-color': '#06b6d4',
            'width': 3.5
          }
        },
        {
          selector: '.dimmed',
          style: {
            'opacity': 0.25
          }
        }
      ],
      layout: getLayoutConfig(layoutName),
      minZoom: 0.2,
      maxZoom: 3.5,
      wheelSensitivity: 0.25
    });

    // Node selection event handler
    cy.on('tap', 'node', (evt: EventObject) => {
      const node = evt.target;
      const raw = node.data('rawNode') as GraphNode;
      setSelectedNode(raw);

      // Highlight 1-hop connected neighborhood
      cy.elements().removeClass('highlighted-node highlighted-edge dimmed');
      const neighborhood = node.neighborhood().add(node);
      cy.elements().not(neighborhood).addClass('dimmed');
      node.addClass('highlighted-node');
      node.connectedEdges().addClass('highlighted-edge');
    });

    // Background tap resets selection
    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        setSelectedNode(null);
        cy.elements().removeClass('highlighted-node highlighted-edge dimmed');
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [filteredData, layoutName, isDark]);

  // Focus specific node from Attribution or navigation
  useEffect(() => {
    if (!cyRef.current || !focusNodeId) return;
    const cy = cyRef.current;
    const targetNode = cy.$id(focusNodeId);
    if (targetNode && targetNode.length > 0) {
      targetNode.select();
      const raw = targetNode.data('rawNode') as GraphNode;
      if (raw) setSelectedNode(raw);

      cy.elements().removeClass('highlighted-node highlighted-edge dimmed');
      const neighborhood = targetNode.neighborhood().add(targetNode);
      cy.elements().not(neighborhood).addClass('dimmed');
      targetNode.addClass('highlighted-node');
      targetNode.connectedEdges().addClass('highlighted-edge');

      cy.animate({
        center: { eles: targetNode },
        zoom: 1.4,
        duration: 400
      });
    }
  }, [focusNodeId, filteredData]);

  function getLayoutConfig(name: string) {
    const prefersReduced = typeof window !== 'undefined' && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const duration = prefersReduced ? 0 : 200;
    const animate = !prefersReduced;

    switch (name) {
      case 'concentric':
        return {
          name: 'concentric',
          concentric: (node: any) => {
            const type = node.data('type');
            if (type === 'Email') return 5;
            if (type === 'Email Address' || type === 'Attachment') return 4;
            if (type === 'Domain' || type === 'URL') return 3;
            if (type === 'IP') return 2;
            return 1;
          },
          levelWidth: () => 1,
          padding: 40,
          animate,
          animationDuration: duration
        };
      case 'breadthfirst':
        return {
          name: 'breadthfirst',
          directed: true,
          padding: 40,
          spacingFactor: 1.25,
          animate,
          animationDuration: duration
        };
      case 'circle':
        return {
          name: 'circle',
          padding: 40,
          animate,
          animationDuration: duration
        };
      case 'cose':
      default:
        return {
          name: 'cose',
          animate,
          animationDuration: duration,
          nodeRepulsion: () => 8500,
          idealEdgeLength: () => 90,
          edgeElasticity: () => 100,
          gravity: 0.2,
          padding: 40,
          numIter: 1000
        };
    }
  }

  // Zoom / Pan controls
  const handleZoomIn = () => cyRef.current?.zoom(cyRef.current.zoom() * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom(cyRef.current.zoom() * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 40);
  const handleReset = () => {
    cyRef.current?.reset();
    cyRef.current?.fit(undefined, 40);
    setSelectedNode(null);
    cyRef.current?.elements().removeClass('highlighted-node highlighted-edge dimmed');
  };

  // Filter toggling
  const toggleType = (t: NodeType) => {
    setSelectedTypes(prev => {
      const next = new Set(prev);
      if (next.has(t)) {
        next.delete(t);
      } else {
        next.add(t);
      }
      return next;
    });
  };

  const selectAllTypes = () => setSelectedTypes(new Set(ALL_NODE_TYPES));
  const clearAllTypes = () => setSelectedTypes(new Set(['Email']));

  // Compute connected nodes for side panel
  const connectedInfo = useMemo(() => {
    if (!selectedNode || !graphData) return { incoming: [], outgoing: [] };
    const incoming = graphData.edges
      .filter(e => e.target === selectedNode.id)
      .map(e => {
        const srcNode = graphData.nodes.find(n => n.id === e.source);
        return { edge: e, node: srcNode };
      })
      .filter(item => item.node !== undefined);

    const outgoing = graphData.edges
      .filter(e => e.source === selectedNode.id)
      .map(e => {
        const tgtNode = graphData.nodes.find(n => n.id === e.target);
        return { edge: e, node: tgtNode };
      })
      .filter(item => item.node !== undefined);

    return { incoming, outgoing };
  }, [selectedNode, graphData]);

  const focusNodeInCanvas = (nodeId: string) => {
    if (!cyRef.current) return;
    const cyNode = cyRef.current.getElementById(nodeId);
    if (cyNode && cyNode.length) {
      cyRef.current.animate({
        center: { eles: cyNode },
        zoom: 1.5,
        duration: 400
      });
      const raw = cyNode.data('rawNode') as GraphNode;
      setSelectedNode(raw);

      cyRef.current.elements().removeClass('highlighted-node highlighted-edge dimmed');
      const neighborhood = cyNode.neighborhood().add(cyNode);
      cyRef.current.elements().not(neighborhood).addClass('dimmed');
      cyNode.addClass('highlighted-node');
      cyNode.connectedEdges().addClass('highlighted-edge');
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[500px] space-y-4 rounded-card border border-border bg-surface shadow-sm">
        <RefreshCw className="w-8 h-8 text-primary animate-spin" />
        <p className="text-sm font-mono text-foreground-muted">Reconstructing investigation relationship graph...</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* 1. CONTROLS & FILTER BAR */}
      <div className="p-4 rounded-card border border-border bg-surface shadow-sm space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 rounded-control bg-primary/10 border border-primary/20 text-primary">
              <Share2 className="w-4 h-4" />
            </div>
            <div>
              <h3 className="text-sm font-bold font-mono text-foreground flex items-center space-x-2">
                <span>Investigation Relationship Graph</span>
                <span className="px-2 py-0.5 rounded-full text-[10px] bg-surface-secondary text-foreground-muted border border-border">
                  {filteredData.nodes.length} Nodes · {filteredData.edges.length} Edges
                </span>
              </h3>
              <p className="text-[11px] font-mono text-foreground-muted">
                Visualizing multi-entity forensic relationships with force-directed physics.
              </p>
            </div>
          </div>

          {/* Canvas Viewport Controls */}
          <div className="flex items-center space-x-1.5 bg-surface-secondary p-1.5 rounded-control border border-border">
            <select
              value={layoutName}
              onChange={e => setLayoutName(e.target.value as any)}
              className="bg-surface text-foreground font-mono text-xs px-2.5 py-1.5 rounded-control border border-border focus:outline-none focus:border-primary mr-2 cursor-pointer"
              title="Graph Layout"
            >
              <option value="cose">Force-Directed (COSE)</option>
              <option value="concentric">Concentric Radial</option>
              <option value="breadthfirst">Tree Hierarchy</option>
              <option value="circle">Circle Cluster</option>
            </select>

            <button
              type="button"
              onClick={handleZoomIn}
              className="p-1.5 rounded-control bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border transition-colors cursor-pointer"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleZoomOut}
              className="p-1.5 rounded-control bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border transition-colors cursor-pointer"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleFit}
              className="p-1.5 rounded-control bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border transition-colors cursor-pointer"
              title="Fit to Screen"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              type="button"
              onClick={handleReset}
              className="p-1.5 rounded-control bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border transition-colors cursor-pointer"
              title="Reset Layout & View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Node Type Filter Chips */}
        <div className="flex flex-wrap items-center gap-1.5 pt-2 border-t border-border">
          <span className="text-[11px] font-mono text-foreground-muted mr-1 flex items-center space-x-1">
            <Layers className="w-3 h-3" />
            <span>Filter Entity Types:</span>
          </span>

          {ALL_NODE_TYPES.map(type => {
            const count = typeCounts[type] || 0;
            const isSelected = selectedTypes.has(type);
            const colors = NODE_TYPE_COLORS[type];

            return (
              <button
                key={type}
                type="button"
                onClick={() => toggleType(type)}
                className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-control text-[11px] font-mono transition-all border cursor-pointer ${
                  isSelected
                    ? `${colors.lightBg} shadow-xs font-semibold`
                    : 'bg-surface-secondary/60 text-foreground-subtle border-border hover:bg-surface-secondary hover:text-foreground-muted'
                }`}
              >
                {getNodeIcon(type)}
                <span>{type}</span>
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${isSelected ? 'bg-surface/70' : 'bg-surface-secondary'}`}>
                  {count}
                </span>
              </button>
            );
          })}

          <div className="ml-auto flex items-center space-x-2 text-[10px] font-mono">
            <button type="button" onClick={selectAllTypes} className="text-primary hover:underline cursor-pointer">Select All</button>
            <span className="text-foreground-subtle">|</span>
            <button type="button" onClick={clearAllTypes} className="text-foreground-muted hover:underline cursor-pointer">Reset</button>
          </div>
        </div>
      </div>

      {/* 2. MAIN GRAPH CANVAS & SIDE PANEL */}
      <div className="relative w-full h-[620px] rounded-card border border-border bg-surface-secondary/20 shadow-sm overflow-hidden">
        {/* Cytoscape Canvas Container */}
        <div ref={containerRef} className="w-full h-full cursor-grab active:cursor-grabbing" />

        {/* Empty State Overlay */}
        {filteredData.nodes.length === 0 && (
          <div className="absolute inset-0 flex flex-col items-center justify-center p-6 bg-surface/85 backdrop-blur-md text-center space-y-3">
            <AlertTriangle className="w-8 h-8 text-warning" />
            <p className="text-sm font-mono text-foreground">
              {!graphData?.nodes?.length
                ? 'No relationships discovered for this investigation.'
                : 'No nodes match the selected entity filters.'}
            </p>
            {Boolean(graphData?.nodes?.length) && (
              <button
                type="button"
                onClick={selectAllTypes}
                className="px-3 py-1.5 rounded-control bg-primary/10 border border-primary text-primary font-mono text-xs cursor-pointer"
              >
                Reset Filters
              </button>
            )}
          </div>
        )}

        {/* Legend Overlay (Bottom Left) */}
        <div className="absolute bottom-3 left-3 bg-surface/95 border border-border rounded-control p-2.5 backdrop-blur-md pointer-events-auto shadow-md flex flex-wrap gap-2 max-w-sm text-[10px] font-mono text-foreground-muted">
          <div className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-full bg-amber-500" /><span>Email</span></div>
          <div className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-full bg-cyan-500" /><span>Address</span></div>
          <div className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-full bg-purple-500" /><span>Domain</span></div>
          <div className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-full bg-rose-500" /><span>URL</span></div>
          <div className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /><span>IP</span></div>
          <div className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" /><span>ASN</span></div>
          <div className="flex items-center space-x-1"><span className="w-2.5 h-2.5 rounded-full bg-orange-500" /><span>Attachment</span></div>
        </div>

        {/* 3. ENTITY INFORMATION SIDE PANEL (Right Drawer) */}
        {selectedNode && (
          <div className="absolute top-0 right-0 w-84 sm:w-96 h-full bg-surface/95 border-l border-border backdrop-blur-md shadow-xl p-5 overflow-y-auto space-y-4 z-20 animate-in slide-in-from-right duration-200">
            {/* Header */}
            <div className="flex items-start justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <span className={`p-1.5 rounded-control border text-xs font-mono font-bold flex items-center space-x-1 ${NODE_TYPE_COLORS[selectedNode.type]?.lightBg}`}>
                  {getNodeIcon(selectedNode.type)}
                  <span>{selectedNode.type}</span>
                </span>
              </div>
              <button
                type="button"
                onClick={() => {
                  setSelectedNode(null);
                  cyRef.current?.elements().removeClass('highlighted-node highlighted-edge dimmed');
                }}
                className="p-1 rounded-control hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
                title="Close"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Label / Identifier */}
            <div className="space-y-1">
              <label className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider">Entity Identifier</label>
              <div className="p-2.5 rounded-control bg-surface-secondary border border-border font-mono text-xs text-foreground break-all flex items-start justify-between gap-2">
                <span>{selectedNode.label}</span>
                <button
                  type="button"
                  onClick={() => copyToClipboard(selectedNode.label)}
                  className="text-foreground-muted hover:text-primary p-1 flex-shrink-0 cursor-pointer"
                  title="Copy"
                >
                  {copiedText === selectedNode.label ? <Check className="w-3.5 h-3.5 text-success" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
              <div className="text-[10px] font-mono text-foreground-subtle">ID: {selectedNode.id}</div>
            </div>

            {/* Security Notice for URLs (Strictly Non-Clickable) */}
            {selectedNode.type === 'URL' && (
              <div className="p-3 rounded-control bg-danger-surface border border-danger-border space-y-2">
                <div className="flex items-center space-x-1.5 text-danger text-xs font-mono font-bold">
                  <ShieldAlert className="w-4 h-4" />
                  <span>Defanged Security Mode</span>
                </div>
                <p className="text-[11px] font-mono text-danger/80">
                  URLs are defanged to prevent accidental execution or browser navigation.
                </p>
                <div className="p-2 rounded-control bg-surface border border-danger-border/50 font-mono text-[11px] text-danger break-all select-all">
                  <code>{defangUrl(selectedNode.metadata?.url || selectedNode.label)}</code>
                </div>
                {selectedNode.metadata?.suspicion_level && (
                  <div className="flex items-center justify-between text-xs font-mono pt-1">
                    <span className="text-foreground-muted">Suspicion Level:</span>
                    <span className={`px-2 py-0.5 rounded font-bold uppercase text-[10px] ${
                      selectedNode.metadata.suspicion_level === 'high' ? 'bg-danger/20 text-danger border border-danger/40' : 'bg-surface-secondary text-foreground-muted'
                    }`}>
                      {selectedNode.metadata.suspicion_level}
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* Entity Specific Metadata Cards */}
            {selectedNode.type === 'Domain' && (
              <div className="space-y-2 text-xs font-mono">
                <div className="p-3 rounded-control bg-surface-secondary border border-border space-y-1.5">
                  <div className="flex justify-between"><span className="text-foreground-muted">Domain:</span><span className="text-foreground font-bold">{selectedNode.metadata?.domain || selectedNode.label}</span></div>
                  {selectedNode.metadata?.registrar && (
                    <div className="flex justify-between"><span className="text-foreground-muted">Registrar:</span><span className="text-foreground">{selectedNode.metadata.registrar}</span></div>
                  )}
                  {typeof selectedNode.metadata?.domain_age_days === 'number' && (
                    <div className="flex justify-between"><span className="text-foreground-muted">Domain Age:</span><span className="text-foreground">{selectedNode.metadata.domain_age_days} days</span></div>
                  )}
                  {selectedNode.metadata?.newly_registered && (
                    <div className="p-1.5 rounded-control bg-warning-surface border border-warning-border text-warning text-[10px] text-center font-bold">
                      Newly Registered Domain (&lt; 30 days)
                    </div>
                  )}
                  {selectedNode.metadata?.is_lookalike && (
                    <div className="p-2 rounded-control bg-danger-surface border border-danger-border space-y-1 text-danger text-[11px]">
                      <div className="font-bold flex items-center space-x-1 text-danger">
                        <AlertTriangle className="w-3.5 h-3.5" />
                        <span>Impersonation Finding</span>
                      </div>
                      <div>Target Brand: <strong>{selectedNode.metadata?.suspected_brand}</strong></div>
                      <div>Similarity: {(selectedNode.metadata?.similarity * 100).toFixed(0)}%</div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {selectedNode.type === 'IP' && (
              <div className="p-3 rounded-control bg-surface-secondary border border-border space-y-1.5 text-xs font-mono">
                <div className="flex justify-between"><span className="text-foreground-muted">IP Address:</span><span className="text-success font-bold">{selectedNode.metadata?.ip || selectedNode.label}</span></div>
                {selectedNode.metadata?.country && (
                  <div className="flex justify-between"><span className="text-foreground-muted">Country:</span><span className="text-foreground">{selectedNode.metadata.country}</span></div>
                )}
                {selectedNode.metadata?.asn && (
                  <div className="flex justify-between"><span className="text-foreground-muted">ASN:</span><span className="text-primary font-bold">{selectedNode.metadata.asn}</span></div>
                )}
                {selectedNode.metadata?.org && (
                  <div className="flex justify-between"><span className="text-foreground-muted">Organization:</span><span className="text-foreground">{selectedNode.metadata.org}</span></div>
                )}
                {selectedNode.metadata?.is_proxy_vpn_tor && (
                  <div className="p-1 rounded-control bg-danger-surface text-danger border border-danger-border text-[10px] text-center font-bold">
                    VPN / Proxy / Tor Infrastructure
                  </div>
                )}
              </div>
            )}

            {selectedNode.type === 'Attachment' && (
              <div className="p-3 rounded-control bg-surface-secondary border border-border space-y-1.5 text-xs font-mono">
                <div className="flex justify-between"><span className="text-foreground-muted">Filename:</span><span className="text-foreground font-bold">{selectedNode.metadata?.filename || selectedNode.label}</span></div>
                {selectedNode.metadata?.mime_type && (
                  <div className="flex justify-between"><span className="text-foreground-muted">MIME:</span><span className="text-foreground">{selectedNode.metadata.mime_type}</span></div>
                )}
                {selectedNode.metadata?.size_bytes !== undefined && (
                  <div className="flex justify-between"><span className="text-foreground-muted">Size:</span><span className="text-foreground">{Math.round(selectedNode.metadata.size_bytes / 1024)} KB</span></div>
                )}
                {selectedNode.metadata?.sha256 && (
                  <div className="space-y-1 pt-1">
                    <span className="text-foreground-muted text-[10px]">SHA-256:</span>
                    <div className="p-1.5 rounded-control bg-surface border border-border text-[10px] break-all select-all text-foreground">
                      {selectedNode.metadata.sha256}
                    </div>
                  </div>
                )}
                {selectedNode.metadata?.is_dangerous_extension && (
                  <div className="p-1.5 rounded-control bg-danger-surface text-danger border border-danger-border text-[10px] text-center font-bold">
                    Executable / High-Risk File Extension
                  </div>
                )}
              </div>
            )}

            {selectedNode.type === 'Email' && (
              <div className="p-3 rounded-control bg-surface-secondary border border-border space-y-1.5 text-xs font-mono">
                <div className="flex justify-between"><span className="text-foreground-muted">Subject:</span><span className="text-foreground font-bold truncate max-w-[200px]">{selectedNode.metadata?.subject}</span></div>
                {selectedNode.metadata?.threat_score !== undefined && (
                  <div className="flex justify-between"><span className="text-foreground-muted">Threat Score:</span><span className="text-warning font-bold">{selectedNode.metadata.threat_score}/100</span></div>
                )}
                {selectedNode.metadata?.severity && (
                  <div className="flex justify-between"><span className="text-foreground-muted">Severity:</span><span className="uppercase text-foreground font-semibold">{selectedNode.metadata.severity}</span></div>
                )}
                {selectedNode.metadata?.ml_probability !== undefined && selectedNode.metadata?.ml_probability !== null && (
                  <div className="flex justify-between"><span className="text-foreground-muted">ML Phish Prob:</span><span className="text-primary">{Math.round(selectedNode.metadata.ml_probability * 100)}%</span></div>
                )}
              </div>
            )}

            {/* Connected Relationships List */}
            <div className="space-y-2 pt-2 border-t border-border">
              <h4 className="text-[11px] font-mono text-foreground font-bold uppercase tracking-wider flex items-center space-x-1.5">
                <Share2 className="w-3.5 h-3.5 text-primary" />
                <span>Connected Forensic Links ({connectedInfo.outgoing.length + connectedInfo.incoming.length})</span>
              </h4>

              <div className="space-y-1.5 max-h-48 overflow-y-auto pr-1">
                {connectedInfo.outgoing.map(({ edge, node }) => (
                  <div
                    key={edge.id}
                    onClick={() => node && focusNodeInCanvas(node.id)}
                    className="p-2 rounded-control bg-surface-secondary hover:bg-surface border border-border cursor-pointer transition-colors space-y-0.5 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-primary font-bold">{edge.label} →</span>
                      <span className="text-foreground-subtle">{node?.type}</span>
                    </div>
                    <div className="text-foreground truncate font-semibold">{node?.label}</div>
                  </div>
                ))}

                {connectedInfo.incoming.map(({ edge, node }) => (
                  <div
                    key={edge.id}
                    onClick={() => node && focusNodeInCanvas(node.id)}
                    className="p-2 rounded-control bg-surface-secondary hover:bg-surface border border-border cursor-pointer transition-colors space-y-0.5 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between text-[10px]">
                      <span className="text-primary font-bold">← {edge.label}</span>
                      <span className="text-foreground-subtle">{node?.type}</span>
                    </div>
                    <div className="text-foreground truncate font-semibold">{node?.label}</div>
                  </div>
                ))}

                {!connectedInfo.outgoing.length && !connectedInfo.incoming.length && (
                  <p className="text-[11px] font-mono text-foreground-muted italic">No connected links for this node.</p>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
