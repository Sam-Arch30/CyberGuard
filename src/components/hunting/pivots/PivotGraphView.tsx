import React, { useState, useMemo } from 'react';
import {
  ZoomIn,
  ZoomOut,
  RotateCcw,
  GitFork,
  Share2,
  Shield,
} from 'lucide-react';
import type { PivotGraphNode, PivotGraphEdge } from '../../../types/pivots';

interface PivotGraphViewProps {
  nodes: PivotGraphNode[];
  edges: PivotGraphEdge[];
  onHopNode: (node: PivotGraphNode) => void;
}

export const PivotGraphView: React.FC<PivotGraphViewProps> = ({
  nodes,
  edges,
  onHopNode,
}) => {
  const [zoom, setZoom] = useState(1);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  // Layout calculation (deterministic radial layout based on hop_distance)
  const layout = useMemo(() => {
    const width = 800;
    const height = 500;
    const centerX = width / 2;
    const centerY = height / 2;

    const rootNode = nodes.find((n) => n.is_root) || nodes[0];
    const positions: Record<string, { x: number; y: number }> = {};

    if (rootNode) {
      positions[rootNode.id] = { x: centerX, y: centerY };
    }

    // Group non-root nodes by hop_distance
    const hopGroups: Record<number, PivotGraphNode[]> = {};
    nodes.forEach((n) => {
      if (n.id === rootNode?.id) return;
      const hop = n.hop_distance || 1;
      if (!hopGroups[hop]) hopGroups[hop] = [];
      hopGroups[hop].push(n);
    });

    // Arrange each hop in a ring
    Object.entries(hopGroups).forEach(([hopStr, group]) => {
      const hop = Number(hopStr);
      const radius = 120 + (hop - 1) * 90;
      const angleStep = (2 * Math.PI) / group.length;

      group.forEach((node, i) => {
        const angle = i * angleStep;
        positions[node.id] = {
          x: centerX + radius * Math.cos(angle),
          y: centerY + radius * Math.sin(angle),
        };
      });
    });

    return { width, height, positions };
  }, [nodes]);

  const selectedNode = useMemo(() => {
    return nodes.find((n) => n.id === selectedNodeId) || null;
  }, [nodes, selectedNodeId]);

  const getNodeColor = (node: PivotGraphNode) => {
    if (node.is_root) return '#3b82f6'; // Primary blue
    if (node.verdict === 'MALICIOUS') return '#ef4444'; // Threat critical
    if (node.entity_type === 'IP') return '#06b6d4'; // Cyan
    if (node.entity_type === 'DOMAIN') return '#8b5cf6'; // Purple
    if (node.entity_type === 'CERTIFICATE') return '#f59e0b'; // Amber
    if (node.entity_type === 'ASN') return '#10b981'; // Emerald
    return '#64748b'; // Slate
  };

  return (
    <div className="relative bg-surface border border-border rounded-panel overflow-hidden shadow-xs h-[520px] flex flex-col">
      {/* 1. Header controls */}
      <div className="flex items-center justify-between px-3 py-2 bg-surface-secondary/80 border-b border-border text-xs z-10">
        <div className="flex items-center space-x-2 font-mono text-foreground-muted">
          <Share2 className="w-3.5 h-3.5 text-primary" />
          <span>Pivot Graph:</span>
          <span className="font-semibold text-foreground">{nodes.length} Nodes</span>
          <span>·</span>
          <span className="font-semibold text-foreground">{edges.length} Edges</span>
        </div>

        <div className="flex items-center space-x-1">
          <button
            onClick={() => setZoom((z) => Math.min(z + 0.15, 2))}
            className="p-1 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground cursor-pointer"
            title="Zoom In"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom((z) => Math.max(z - 0.15, 0.5))}
            className="p-1 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground cursor-pointer"
            title="Zoom Out"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => setZoom(1)}
            className="p-1 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground cursor-pointer"
            title="Reset Zoom"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* 2. Interactive SVG Canvas */}
      <div className="flex-1 overflow-hidden relative cursor-grab active:cursor-grabbing bg-radial from-surface-secondary/20 to-surface">
        <svg
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          className="w-full h-full transition-transform duration-100 ease-out"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center center' }}
        >
          <defs>
            <marker
              id="arrow"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="5"
              markerHeight="5"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 9 5 L 0 9 z" fill="rgba(148, 163, 184, 0.6)" />
            </marker>
          </defs>

          {/* Render Edges */}
          {edges.map((edge) => {
            const p1 = layout.positions[edge.source];
            const p2 = layout.positions[edge.target];
            if (!p1 || !p2) return null;

            const midX = (p1.x + p2.x) / 2;
            const midY = (p1.y + p2.y) / 2;

            return (
              <g key={edge.id} className="opacity-70 hover:opacity-100 transition-opacity">
                <line
                  x1={p1.x}
                  y1={p1.y}
                  x2={p2.x}
                  y2={p2.y}
                  stroke="rgba(148, 163, 184, 0.4)"
                  strokeWidth={1.5}
                  markerEnd="url(#arrow)"
                />
                <text
                  x={midX}
                  y={midY - 4}
                  fill="#94a3b8"
                  fontSize="8"
                  fontFamily="monospace"
                  textAnchor="middle"
                  className="pointer-events-none select-none bg-surface"
                >
                  {edge.relationship.toLowerCase()}
                </text>
              </g>
            );
          })}

          {/* Render Nodes */}
          {nodes.map((node) => {
            const pos = layout.positions[node.id];
            if (!pos) return null;
            const isSelected = selectedNodeId === node.id;
            const nodeColor = getNodeColor(node);

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNodeId(node.id)}
                className="cursor-pointer group"
              >
                {/* Glow ring if root or selected */}
                {(node.is_root || isSelected) && (
                  <circle
                    r={node.is_root ? 24 : 20}
                    fill="none"
                    stroke={nodeColor}
                    strokeWidth={2}
                    strokeDasharray={node.is_root ? 'none' : '3,3'}
                    className="animate-pulse opacity-50"
                  />
                )}

                <circle
                  r={node.is_root ? 18 : 14}
                  fill="#1e293b"
                  stroke={nodeColor}
                  strokeWidth={isSelected ? 3 : 2}
                  className="transition-all group-hover:scale-110"
                />

                <text
                  textAnchor="middle"
                  dy=".3em"
                  fill="#f8fafc"
                  fontSize={node.is_root ? '9' : '8'}
                  fontFamily="monospace"
                  fontWeight="bold"
                  className="pointer-events-none select-none"
                >
                  {node.entity_type.slice(0, 3)}
                </text>

                {/* Node Label Below */}
                <text
                  textAnchor="middle"
                  dy="2.4em"
                  fill="#cbd5e1"
                  fontSize="9"
                  fontFamily="monospace"
                  className="pointer-events-none select-none drop-shadow-sm font-medium"
                >
                  {node.value.length > 16 ? `${node.value.slice(0, 14)}…` : node.value}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* 3. Selected Node Inspection Card Overlay */}
      {selectedNode && (
        <div className="absolute bottom-3 left-3 right-3 p-3 bg-surface/95 backdrop-blur-xs border border-border rounded-panel flex items-center justify-between shadow-lg text-xs font-mono animate-in fade-in slide-in-from-bottom-2 z-20">
          <div className="flex items-center space-x-3 min-w-0 flex-1">
            <div className="p-2 rounded-control bg-primary/10 border border-primary/20 shrink-0">
              <Shield className="w-4 h-4 text-primary" />
            </div>

            <div className="min-w-0 flex-1">
              <div className="flex items-center space-x-2">
                <span className="text-[10px] uppercase font-bold text-foreground-muted px-1.5 py-0.2 bg-surface-secondary border border-border rounded-xs">
                  {selectedNode.entity_type}
                </span>
                <span className="font-semibold text-foreground truncate">{selectedNode.value}</span>
                {selectedNode.is_root && (
                  <span className="text-[9px] px-1.5 py-0.2 rounded-xs bg-primary text-white font-bold">
                    ROOT
                  </span>
                )}
                {selectedNode.hop_distance > 0 && (
                  <span className="text-[9px] text-foreground-muted">
                    Hop {selectedNode.hop_distance}
                  </span>
                )}
              </div>

              <div className="text-[11px] text-foreground-muted mt-0.5">
                {selectedNode.verdict ? `Verdict: ${selectedNode.verdict}` : 'Observable'}
                {selectedNode.threat_score !== undefined && ` · Score: ${selectedNode.threat_score}`}
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0 ml-3">
            {!selectedNode.is_root && (
              <button
                onClick={() => onHopNode(selectedNode)}
                className="px-2.5 py-1.5 text-xs font-medium text-white bg-primary hover:bg-primary/90 rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs transition-colors"
                title="Pivot from this node as the new root"
              >
                <GitFork className="w-3.5 h-3.5" />
                <span>Pivot From Node</span>
              </button>
            )}
            <button
              onClick={() => setSelectedNodeId(null)}
              className="p-1 text-foreground-muted hover:text-foreground rounded-control hover:bg-surface-secondary cursor-pointer"
            >
              ✕
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
