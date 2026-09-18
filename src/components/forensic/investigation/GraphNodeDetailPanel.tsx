import React from 'react';
import {
  X,
  Mail,
  AtSign,
  Globe,
  Link as LinkIcon,
  Server,
  Cloud,
  Paperclip,
  Briefcase,
  Flag,
  ShieldAlert,
  AlertTriangle,
  ExternalLink,
  ArrowRight,
  Database,
  Sparkles
} from 'lucide-react';
import type { GraphNode, GraphEdge, NodeType } from '../../../types/graph';
import { useInvestigation } from '../../../context/InvestigationContext';
import { CopyButton } from '../CopyButton';

interface GraphNodeDetailPanelProps {
  node: GraphNode;
  connectedEdges: GraphEdge[];
  allNodes: GraphNode[];
  onClose: () => void;
  onFocusNode: (nodeId: string) => void;
  onPivotToSection?: (sectionId: string, subTabId?: string) => void;
  onAddToCase?: () => void;
}

const getNodeIcon = (type: NodeType) => {
  switch (type) {
    case 'Email': return <Mail className="w-4 h-4 text-amber-500" />;
    case 'Email Address': return <AtSign className="w-4 h-4 text-cyan-500" />;
    case 'Domain': return <Globe className="w-4 h-4 text-purple-500" />;
    case 'URL': return <LinkIcon className="w-4 h-4 text-rose-500" />;
    case 'IP': return <Server className="w-4 h-4 text-emerald-500" />;
    case 'ASN': return <Cloud className="w-4 h-4 text-blue-500" />;
    case 'Attachment': return <Paperclip className="w-4 h-4 text-orange-500" />;
    case 'Case': return <Briefcase className="w-4 h-4 text-indigo-500" />;
    case 'Campaign': return <Flag className="w-4 h-4 text-pink-500" />;
    default: return <Database className="w-4 h-4 text-slate-400" />;
  }
};

const getNodeTypeBadge = (type: NodeType) => {
  switch (type) {
    case 'Email': return 'bg-amber-500/10 text-amber-500 border-amber-500/30';
    case 'Email Address': return 'bg-cyan-500/10 text-cyan-500 border-cyan-500/30';
    case 'Domain': return 'bg-purple-500/10 text-purple-500 border-purple-500/30';
    case 'URL': return 'bg-rose-500/10 text-rose-500 border-rose-500/30';
    case 'IP': return 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30';
    case 'ASN': return 'bg-blue-500/10 text-blue-500 border-blue-500/30';
    case 'Attachment': return 'bg-orange-500/10 text-orange-500 border-orange-500/30';
    case 'Case': return 'bg-indigo-500/10 text-indigo-500 border-indigo-500/30';
    case 'Campaign': return 'bg-pink-500/10 text-pink-500 border-pink-500/30';
    default: return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
  }
};

export const GraphNodeDetailPanel: React.FC<GraphNodeDetailPanelProps> = ({
  node,
  connectedEdges,
  allNodes,
  onClose,
  onFocusNode,
  onPivotToSection,
  onAddToCase
}) => {
  const { openCopilotDrawer } = useInvestigation();
  const meta = node.metadata || {};

  // Build connected adjacent entities
  const adjacentEntities = connectedEdges.map((edge) => {
    const isSource = edge.source === node.id;
    const neighborId = isSource ? edge.target : edge.source;
    const neighbor = allNodes.find((n) => n.id === neighborId);
    return {
      edgeId: edge.id,
      label: edge.label,
      direction: isSource ? 'outgoing' : 'incoming',
      neighbor
    };
  }).filter((item) => Boolean(item.neighbor));

  // Determine evidence source
  const getEvidenceSource = (): string => {
    if (meta.evidence_source) return meta.evidence_source;
    if (meta.source_header) return `RFC-5322 ${meta.source_header} header`;
    switch (node.type) {
      case 'Email':
        return 'Analyzed RFC-822 email evidence file';
      case 'Email Address':
        return meta.role ? `Sender envelope (${meta.role})` : 'RFC-5322 From/Reply-To header';
      case 'Domain':
        return meta.source ? `Extracted via ${meta.source}` : 'Header alignment & link host';
      case 'URL':
        return 'Extracted from HTML anchor href / plain text';
      case 'IP':
        return meta.is_earliest ? 'RFC-5322 Received header hop 1 (earliest origin)' : 'Relay transmission hop';
      case 'ASN':
        return 'Autonomous System BGP routing table lookup';
      case 'Campaign':
        return 'Multi-indicator fingerprint clustering algorithm';
      default:
        return 'Forensic parser indicator extraction';
    }
  };

  // Determine risk presentation
  const getRiskInfo = () => {
    if (node.type === 'Email') {
      const score = meta.threat_score ?? 100;
      return (
        <div className="p-3 rounded-lg bg-danger/10 border border-danger/30 space-y-1">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono font-bold text-danger">Threat Score: {score}/100</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-bold bg-danger text-white">
              {score >= 70 ? 'CRITICAL RISK' : 'MODERATE'}
            </span>
          </div>
          <p className="text-[11px] font-mono text-foreground-muted">
            {meta.subject ? `Target message: "${meta.subject}"` : 'Active threat telemetry grounded.'}
          </p>
        </div>
      );
    }

    if (node.type === 'Domain') {
      if (meta.is_lookalike || meta.lookalike) {
        const sim = meta.similarity ? Math.round(meta.similarity * 100) : 92;
        const brand = meta.brand_name || meta.suspected_brand || 'Recognized Brand';
        return (
          <div className="p-3 rounded-lg bg-danger/10 border border-danger/30 space-y-1">
            <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-danger">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Brand Impersonation ({sim}% Match)</span>
            </div>
            <p className="text-[11px] font-mono text-foreground-muted">
              Mimics legitimate brand <strong className="text-foreground">"{brand}"</strong> using character substitution or typosquatting.
            </p>
          </div>
        );
      }
      return (
        <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-1">
          <span className="text-xs font-mono font-bold text-foreground">Domain Reputation</span>
          <p className="text-[11px] font-mono text-foreground-muted">
            {meta.is_resolvable ? 'Domain resolves via authoritative nameservers' : 'Observed domain indicator'}
          </p>
        </div>
      );
    }

    if (node.type === 'IP') {
      if (meta.is_proxy_vpn_tor || (meta.asn && meta.asn.toLowerCase().includes('bulletproof'))) {
        return (
          <div className="p-3 rounded-lg bg-danger/10 border border-danger/30 space-y-1">
            <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-danger">
              <ShieldAlert className="w-3.5 h-3.5" />
              <span>Hostile / Bulletproof Infrastructure</span>
            </div>
            <p className="text-[11px] font-mono text-foreground-muted">
              Attributed to hostile ASN hosting or anonymizer infrastructure.
            </p>
          </div>
        );
      }
      return (
        <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-1">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="font-bold text-foreground">
              {meta.country ? `${meta.country} (${meta.city || 'Regional'})` : 'Routing Node'}
            </span>
            <span className="text-foreground-muted">{meta.asn || 'Public Node'}</span>
          </div>
          <p className="text-[11px] font-mono text-foreground-muted">
            {meta.is_earliest ? 'Earliest observable origin node in relay headers.' : 'Intermediate transmission relay.'}
          </p>
        </div>
      );
    }

    if (node.type === 'URL') {
      return (
        <div className="p-3 rounded-lg bg-danger/10 border border-danger/30 space-y-1">
          <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-danger">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>Credential Harvester Lure</span>
          </div>
          <p className="text-[11px] font-mono text-foreground-muted">
            Observed landing endpoint flagged for credential harvesting and brand impersonation.
          </p>
        </div>
      );
    }

    if (node.type === 'Campaign') {
      return (
        <div className="p-3 rounded-lg bg-pink-500/10 border border-pink-500/30 space-y-1">
          <div className="flex items-center space-x-1.5 text-xs font-mono font-bold text-pink-500">
            <Flag className="w-3.5 h-3.5" />
            <span>Coordinated Campaign Cluster</span>
          </div>
          <p className="text-[11px] font-mono text-foreground-muted">
            Correlated across multiple enterprise targets sharing infrastructure and lure patterns.
          </p>
        </div>
      );
    }

    return null;
  };

  return (
    <div className="w-full sm:w-80 lg:w-96 rounded-xl border border-border bg-surface p-4 flex flex-col space-y-4 shadow-md max-h-[600px] overflow-y-auto animate-in slide-in-from-right-4 duration-200">
      {/* Header */}
      <div className="flex items-start justify-between gap-2 pb-3 border-b border-border">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex items-center gap-1 ${getNodeTypeBadge(node.type)}`}>
              {getNodeIcon(node.type)}
              <span>{node.type.toUpperCase()}</span>
            </span>
          </div>
          <h4 className="text-xs font-mono font-bold text-foreground break-all" title={node.label}>
            {node.label}
          </h4>
        </div>

        <button
          type="button"
          onClick={onClose}
          aria-label="Close panel"
          className="text-foreground-muted hover:text-foreground p-1 rounded hover:bg-surface-secondary transition-colors cursor-pointer"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      {/* Verbatim Identifier */}
      <div className="space-y-1">
        <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
          Identifier:
        </span>
        <div className="p-2 rounded bg-surface-secondary border border-border flex items-center justify-between gap-2">
          <span className="text-xs font-mono text-foreground break-all select-all">
            {node.metadata?.url || node.metadata?.domain || node.metadata?.ip || node.label}
          </span>
          <CopyButton
            text={node.metadata?.url || node.metadata?.domain || node.metadata?.ip || node.label}
            label="ID"
          />
        </div>
      </div>

      {/* Relevant Risk Information */}
      <div className="space-y-1">
        <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
          Risk Assessment:
        </span>
        {getRiskInfo()}
      </div>

      {/* Evidence Source */}
      <div className="space-y-1">
        <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
          Evidence Source:
        </span>
        <div className="p-2.5 rounded bg-surface-secondary border border-border text-xs font-mono text-foreground">
          {getEvidenceSource()}
        </div>
      </div>

      {/* Connected Entities */}
      <div className="space-y-1.5">
        <div className="flex items-center justify-between">
          <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
            Connected Entities ({adjacentEntities.length}):
          </span>
          <span className="text-[10px] font-mono text-foreground-subtle">
            Click to focus node
          </span>
        </div>

        {adjacentEntities.length === 0 ? (
          <p className="text-xs font-mono text-foreground-muted italic">
            No adjacent connections in current graph view.
          </p>
        ) : (
          <div className="space-y-1 max-h-40 overflow-y-auto pr-1">
            {adjacentEntities.map((item, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => item.neighbor && onFocusNode(item.neighbor.id)}
                className="w-full p-2 rounded bg-surface-secondary/70 hover:bg-surface-secondary border border-border text-left transition-colors cursor-pointer flex items-center justify-between gap-2 group"
              >
                <div className="min-w-0 flex-1">
                  <span className="text-[9px] font-mono font-bold uppercase tracking-wider text-primary block truncate">
                    {item.label}
                  </span>
                  <span className="text-xs font-mono text-foreground truncate block group-hover:text-primary transition-colors">
                    {item.neighbor?.label || 'Node'}
                  </span>
                </div>
                <ArrowRight className="w-3.5 h-3.5 text-foreground-muted group-hover:text-primary transition-colors shrink-0" />
              </button>
            ))}
          </div>
        )}
      </div>

      {/* Investigation Actions */}
      <div className="pt-2 border-t border-border space-y-2">
        <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block">
          Investigation Actions:
        </span>

        <div className="grid grid-cols-1 gap-1.5">
          {/* Ask AI Contextual Action */}
          <button
            type="button"
            onClick={() => {
              const identifier = node.metadata?.url || node.metadata?.domain || node.metadata?.ip || node.label;
              openCopilotDrawer(
                `Explain entity [${node.type}] '${identifier}' and how it relates to the attack vectors in this email investigation.`,
                {
                  type: node.type,
                  identifier: identifier,
                  details: node.label
                }
              );
            }}
            className="w-full px-3 py-1.5 rounded-lg bg-primary/10 hover:bg-primary/20 text-primary border border-primary/25 font-mono text-xs font-semibold transition-colors flex items-center justify-center space-x-1.5 cursor-pointer"
            title="Ask AI Copilot about this entity"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Ask AI About This Entity</span>
          </button>
          {node.type === 'IP' && onPivotToSection && (
            <button
              type="button"
              onClick={() => onPivotToSection('intelligence', 'infrastructure')}
              className="w-full px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold transition-colors flex items-center justify-center space-x-1.5 cursor-pointer"
            >
              <span>Pivot to IP Intelligence</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          )}

          {node.type === 'Domain' && onPivotToSection && (
            <button
              type="button"
              onClick={() => onPivotToSection('intelligence', 'domains')}
              className="w-full px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold transition-colors flex items-center justify-center space-x-1.5 cursor-pointer"
            >
              <span>Inspect Domain in Intelligence</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          )}

          {node.type === 'URL' && onPivotToSection && (
            <button
              type="button"
              onClick={() => onPivotToSection('analysis', 'urls')}
              className="w-full px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono text-xs font-bold transition-colors flex items-center justify-center space-x-1.5 cursor-pointer"
            >
              <span>Inspect URL Redirection Chain</span>
              <ExternalLink className="w-3 h-3" />
            </button>
          )}

          {onAddToCase && (
            <button
              type="button"
              onClick={onAddToCase}
              className="w-full px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs transition-colors flex items-center justify-center space-x-1.5 cursor-pointer"
            >
              <span>Associate with Case</span>
              <Briefcase className="w-3 h-3 text-indigo-400" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
