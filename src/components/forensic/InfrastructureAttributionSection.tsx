import React, { useState } from 'react';
import type { AttributionResult, EvidenceItem } from '../../types/attribution';
import type { ForensicConclusion } from '../../types/confidence';
import { ConfidenceBadge } from '../common/ConfidenceBadge';
import {
  Server,
  Globe,
  Network,
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Copy,
  Check,
  ExternalLink,
  Clock
} from 'lucide-react';

interface InfrastructureAttributionSectionProps {
  attribution?: AttributionResult;
  conclusions?: ForensicConclusion[];
  onFocusGraphNode?: (nodeId: string) => void;
}

export const InfrastructureAttributionSection: React.FC<InfrastructureAttributionSectionProps> = ({
  attribution,
  conclusions = [],
  onFocusGraphNode
}) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [showSupporting, setShowSupporting] = useState<boolean>(true);
  const [showConflicting, setShowConflicting] = useState<boolean>(true);
  const attrConclusion = conclusions.find((c) => c.type === 'infrastructure_attribution');

  if (!attribution) return null;

  const {
    probable_origin_ip,
    probable_origin_asn,
    probable_origin_provider,
    probable_infrastructure_country,
    confidence_score,
    confidence_level,
    supporting_evidence,
    conflicting_evidence,
    related_domains,
    related_ips,
    related_campaigns,
    analysis_timestamp,
    disclaimer
  } = attribution;

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const getConfidenceLevelStyle = (level: string) => {
    switch (level?.toUpperCase()) {
      case 'VERY HIGH':
        return {
          badge: 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/30',
          bar: 'bg-emerald-500',
          indicator: 'text-emerald-500',
          label: 'VERY HIGH'
        };
      case 'HIGH':
        return {
          badge: 'bg-purple-500/10 text-purple-600 dark:text-purple-400 border-purple-500/30',
          bar: 'bg-purple-500',
          indicator: 'text-purple-500',
          label: 'HIGH'
        };
      case 'MODERATE':
        return {
          badge: 'bg-blue-500/10 text-blue-600 dark:text-blue-400 border-blue-500/30',
          bar: 'bg-blue-500',
          indicator: 'text-blue-500',
          label: 'MODERATE'
        };
      case 'LOW':
      default:
        return {
          badge: 'bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30',
          bar: 'bg-amber-500',
          indicator: 'text-amber-500',
          label: 'LOW'
        };
    }
  };

  const levelStyle = getConfidenceLevelStyle(confidence_level);

  return (
    <div className="bg-surface rounded-card border border-border overflow-hidden shadow-xs space-y-0">
      {/* Header Banner */}
      <div className="px-5 py-4 border-b border-border bg-surface-secondary/40 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
                Probabilistic Threat Attribution Engine
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-secondary border border-border text-foreground-muted">
                Section 21
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs font-mono text-foreground-muted mt-0.5">
              <span>Explainable infrastructure attribution & campaign correlation</span>
              {analysis_timestamp && (
                <span className="text-[11px] text-foreground-muted/80">
                  • Evaluated {new Date(analysis_timestamp).toLocaleTimeString()}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Confidence Tier Badge */}
        <div className="flex items-center space-x-3">
          <div className="text-right">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block mb-1">
              Attribution Confidence
            </span>
            <ConfidenceBadge
              conclusion={attrConclusion}
              allConclusions={conclusions}
              score={confidence_score}
              level={confidence_level}
              size="lg"
            />
          </div>
        </div>
      </div>

      {/* Mandatory Physical Attribution Disclaimer Banner */}
      <div className="px-5 py-3 bg-amber-500/10 dark:bg-amber-950/30 border-b border-amber-500/20 flex items-start space-x-3 text-amber-800 dark:text-amber-200">
        <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
        <div className="text-xs font-mono leading-relaxed">
          <span className="font-bold">FORENSIC ATTRIBUTION NOTICE: </span>
          {disclaimer || "Location refers to observed network infrastructure and should not be interpreted as the physical location of the threat actor."}
        </div>
      </div>

      {/* Main Grid: Probable Origin Infrastructure Cards */}
      <div className="p-5 space-y-6">
        <div>
          <h4 className="text-xs font-mono font-bold text-foreground-muted uppercase tracking-wider mb-3 flex items-center space-x-2">
            <Server className="w-3.5 h-3.5 text-primary" />
            <span>Probable Origin Infrastructure</span>
          </h4>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* 1. Probable Origin IP */}
            <div className="p-4 bg-surface-secondary/50 rounded-control border border-border space-y-2 hover:border-primary/40 transition-colors">
              <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                Origin IP
              </span>
              <div className="flex items-center justify-between">
                <span className="text-sm font-mono font-bold text-foreground truncate">
                  {probable_origin_ip || 'Unknown'}
                </span>
                {probable_origin_ip && (
                  <div className="flex items-center space-x-1 shrink-0 ml-2">
                    <button
                      type="button"
                      onClick={() => copyToClipboard(probable_origin_ip, 'ip')}
                      className="p-1 text-foreground-muted hover:text-foreground rounded transition-colors"
                      title="Copy IP"
                    >
                      {copiedKey === 'ip' ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                    </button>
                    {onFocusGraphNode && (
                      <button
                        type="button"
                        onClick={() => onFocusGraphNode(`ip:${probable_origin_ip}`)}
                        className="p-1 text-primary hover:text-primary-hover rounded transition-colors"
                        title="Focus in Graph"
                      >
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                )}
              </div>
              <p className="text-[11px] font-mono text-foreground-muted">
                {probable_origin_ip ? 'Earliest untrusted sending relay' : 'No public IP observed in headers'}
              </p>
            </div>

            {/* 2. Autonomous System (ASN) */}
            <div className="p-4 bg-surface-secondary/50 rounded-control border border-border space-y-2 hover:border-primary/40 transition-colors">
              <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                Autonomous System
              </span>
              <div className="flex items-center justify-between">
                <span className="text-sm font-mono font-bold text-foreground truncate">
                  {probable_origin_asn || 'Unknown'}
                </span>
                {probable_origin_asn && (
                  <div className="flex items-center space-x-1 shrink-0 ml-2">
                    <button
                      type="button"
                      onClick={() => copyToClipboard(probable_origin_asn, 'asn')}
                      className="p-1 text-foreground-muted hover:text-foreground rounded transition-colors"
                      title="Copy ASN"
                    >
                      {copiedKey === 'asn' ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                    </button>
                    {onFocusGraphNode && (
                      <button
                        type="button"
                        onClick={() => onFocusGraphNode(`asn:${probable_origin_asn}`)}
                        className="p-1 text-primary hover:text-primary-hover rounded transition-colors"
                        title="Focus in Graph"
                      >
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                )}
              </div>
              <p className="text-[11px] font-mono text-foreground-muted truncate">
                {probable_origin_provider || 'BGP Routing Authority'}
              </p>
            </div>

            {/* 3. Hosting Provider / ISP */}
            <div className="p-4 bg-surface-secondary/50 rounded-control border border-border space-y-2 hover:border-primary/40 transition-colors">
              <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                Hosting Provider / ISP
              </span>
              <div className="flex items-center justify-between">
                <span className="text-sm font-mono font-bold text-foreground truncate" title={probable_origin_provider || 'Unknown'}>
                  {probable_origin_provider || 'Unknown Provider'}
                </span>
                {probable_origin_provider && (
                  <button
                    type="button"
                    onClick={() => copyToClipboard(probable_origin_provider, 'provider')}
                    className="p-1 text-foreground-muted hover:text-foreground rounded transition-colors shrink-0 ml-2"
                    title="Copy Provider"
                  >
                    {copiedKey === 'provider' ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                  </button>
                )}
              </div>
              <p className="text-[11px] font-mono text-foreground-muted truncate">
                Infrastructure operator
              </p>
            </div>

            {/* 4. Infrastructure Location */}
            <div className="p-4 bg-surface-secondary/50 rounded-control border border-border space-y-2 hover:border-primary/40 transition-colors">
              <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
                Infrastructure Country
              </span>
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-1.5 truncate">
                  <Globe className="w-3.5 h-3.5 text-info shrink-0" />
                  <span className="text-sm font-mono font-bold text-foreground truncate">
                    {probable_infrastructure_country || 'Unknown'}
                  </span>
                </div>
                {probable_infrastructure_country && onFocusGraphNode && (
                  <button
                    type="button"
                    onClick={() => {
                      const slug = probable_infrastructure_country.toLowerCase().replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
                      onFocusGraphNode(`country:${slug}`);
                    }}
                    className="p-1 text-primary hover:text-primary-hover rounded transition-colors shrink-0 ml-2"
                    title="Focus in Graph"
                  >
                    <ExternalLink className="w-3 h-3" />
                  </button>
                )}
              </div>
              <p className="text-[10px] font-mono text-foreground-muted truncate">
                Network routing jurisdiction
              </p>
            </div>
          </div>
        </div>

        {/* Confidence Gauge Bar */}
        <div className="p-4 bg-surface-secondary/30 rounded-control border border-border space-y-2">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-foreground-muted">Confidence Engine Contribution Weighting</span>
            <span className="font-bold text-foreground">{confidence_score}% — {confidence_level}</span>
          </div>
          <div className="w-full bg-surface-secondary h-2.5 rounded-full overflow-hidden border border-border">
            <div
              className={`h-full transition-all duration-500 ${levelStyle.bar}`}
              style={{ width: `${Math.max(4, Math.min(100, confidence_score))}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] font-mono text-foreground-muted pt-0.5">
            <span>0% LOW (0-39)</span>
            <span>40% MODERATE (40-69)</span>
            <span>70% HIGH (70-84)</span>
            <span>85%+ VERY HIGH</span>
          </div>
        </div>

        {/* Expandable Section 1: Supporting Evidence */}
        <div className="border border-border rounded-control overflow-hidden">
          <button
            type="button"
            onClick={() => setShowSupporting(!showSupporting)}
            className="w-full px-4 py-3 bg-surface-secondary/40 hover:bg-surface-secondary/60 flex items-center justify-between transition-colors cursor-pointer"
          >
            <div className="flex items-center space-x-2.5">
              <CheckCircle2 className="w-4 h-4 text-emerald-500" />
              <span className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                Supporting Evidence ({supporting_evidence?.length || 0})
              </span>
            </div>
            <div className="flex items-center space-x-2 text-foreground-muted">
              <span className="text-[11px] font-mono">
                {showSupporting ? 'Collapse' : 'Expand'}
              </span>
              {showSupporting ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {showSupporting && (
            <div className="p-4 space-y-2.5 bg-surface border-t border-border">
              {supporting_evidence && supporting_evidence.length > 0 ? (
                supporting_evidence.map((item: EvidenceItem, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 bg-emerald-500/5 dark:bg-emerald-950/15 border border-emerald-500/20 rounded-lg flex flex-col sm:flex-row sm:items-start justify-between gap-2.5"
                  >
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 font-bold border border-emerald-500/30">
                          {item.evidence_type}
                        </span>
                        <span className="text-[10px] font-mono text-foreground-muted">
                          Source: {item.source}
                        </span>
                      </div>
                      <p className="text-xs font-mono text-foreground leading-relaxed">
                        {item.observation}
                      </p>
                    </div>

                    <div className="shrink-0 flex items-center sm:flex-col sm:items-end gap-1.5">
                      <span className="text-xs font-mono font-bold text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                        +{item.contribution} pts
                      </span>
                      {item.timestamp && (
                        <span className="text-[10px] font-mono text-foreground-muted flex items-center space-x-1">
                          <Clock className="w-2.5 h-2.5" />
                          <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                        </span>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs font-mono text-foreground-muted py-2 text-center">
                  No positive supporting signals observed for this message.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Expandable Section 2: Conflicting Evidence */}
        <div className="border border-border rounded-control overflow-hidden">
          <button
            type="button"
            onClick={() => setShowConflicting(!showConflicting)}
            className="w-full px-4 py-3 bg-surface-secondary/40 hover:bg-surface-secondary/60 flex items-center justify-between transition-colors cursor-pointer"
          >
            <div className="flex items-center space-x-2.5">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <span className="text-xs font-mono font-bold text-foreground uppercase tracking-wider">
                Conflicting / Cautionary Evidence ({conflicting_evidence?.length || 0})
              </span>
            </div>
            <div className="flex items-center space-x-2 text-foreground-muted">
              <span className="text-[11px] font-mono">
                {showConflicting ? 'Collapse' : 'Expand'}
              </span>
              {showConflicting ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </div>
          </button>

          {showConflicting && (
            <div className="p-4 space-y-2.5 bg-surface border-t border-border">
              {conflicting_evidence && conflicting_evidence.length > 0 ? (
                conflicting_evidence.map((item: EvidenceItem, idx: number) => (
                  <div
                    key={idx}
                    className="p-3 bg-amber-500/5 dark:bg-amber-950/15 border border-amber-500/20 rounded-lg flex flex-col sm:flex-row sm:items-start justify-between gap-2.5"
                  >
                    <div className="space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/15 text-amber-700 dark:text-amber-300 font-bold border border-amber-500/30">
                          {item.evidence_type}
                        </span>
                        <span className="text-[10px] font-mono text-foreground-muted">
                          Source: {item.source}
                        </span>
                      </div>
                      <p className="text-xs font-mono text-foreground leading-relaxed">
                        {item.observation}
                      </p>
                    </div>

                    <div className="shrink-0 flex items-center sm:flex-col sm:items-end gap-1.5">
                      <span className="text-xs font-mono font-bold text-amber-600 dark:text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                        {item.contribution} pts
                      </span>
                      {item.timestamp && (
                        <span className="text-[10px] font-mono text-foreground-muted flex items-center space-x-1">
                          <Clock className="w-2.5 h-2.5" />
                          <span>{new Date(item.timestamp).toLocaleTimeString()}</span>
                        </span>
                      )}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs font-mono text-foreground-muted py-2 text-center">
                  No conflicting or anonymizing indicators identified.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Related Infrastructure Tags */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          {/* Related Domains */}
          <div className="p-3.5 bg-surface-secondary/40 rounded-control border border-border space-y-2">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
              Related Domains ({related_domains?.length || 0})
            </span>
            <div className="flex flex-wrap gap-1.5">
              {related_domains && related_domains.length > 0 ? (
                related_domains.slice(0, 6).map((dom, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => onFocusGraphNode && onFocusGraphNode(`domain:${dom}`)}
                    className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface border border-border hover:border-primary text-foreground hover:text-primary transition-colors flex items-center space-x-1"
                  >
                    <span>{dom}</span>
                    {onFocusGraphNode && <ExternalLink className="w-2.5 h-2.5" />}
                  </button>
                ))
              ) : (
                <span className="text-xs font-mono text-foreground-muted">None observed</span>
              )}
            </div>
          </div>

          {/* Related IPs */}
          <div className="p-3.5 bg-surface-secondary/40 rounded-control border border-border space-y-2">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
              Observed Infrastructure IPs ({related_ips?.length || 0})
            </span>
            <div className="flex flex-wrap gap-1.5">
              {related_ips && related_ips.length > 0 ? (
                related_ips.slice(0, 6).map((ip, i) => (
                  <button
                    key={i}
                    type="button"
                    onClick={() => onFocusGraphNode && onFocusGraphNode(`ip:${ip}`)}
                    className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface border border-border hover:border-primary text-foreground hover:text-primary transition-colors flex items-center space-x-1"
                  >
                    <span>{ip}</span>
                    {onFocusGraphNode && <ExternalLink className="w-2.5 h-2.5" />}
                  </button>
                ))
              ) : (
                <span className="text-xs font-mono text-foreground-muted">None observed</span>
              )}
            </div>
          </div>

          {/* Related Campaigns */}
          <div className="p-3.5 bg-surface-secondary/40 rounded-control border border-border space-y-2">
            <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block">
              Related Campaigns / Cases ({related_campaigns?.length || 0})
            </span>
            <div className="flex flex-wrap gap-1.5">
              {related_campaigns && related_campaigns.length > 0 ? (
                related_campaigns.slice(0, 5).map((camp, i) => {
                  const slug = camp.toLowerCase().replace(/[^a-zA-Z0-9]+/g, '_').replace(/^_+|_+$/g, '');
                  return (
                    <button
                      key={i}
                      type="button"
                      onClick={() => onFocusGraphNode && onFocusGraphNode(`campaign:${slug}`)}
                      className="text-[11px] font-mono px-2 py-0.5 rounded bg-surface border border-border hover:border-primary text-foreground hover:text-primary transition-colors flex items-center space-x-1"
                    >
                      <span>{camp}</span>
                      {onFocusGraphNode && <ExternalLink className="w-2.5 h-2.5" />}
                    </button>
                  );
                })
              ) : (
                <span className="text-xs font-mono text-foreground-muted">No historical campaign link</span>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
