import React from 'react';
import {
  Share2,
  Mail,
  Globe,
  Server,
  ShieldAlert,
  CheckCircle2,
  Network
} from 'lucide-react';
import type { EmailAnalysis } from '../../../types/forensic';
import type { CampaignAlertData } from '../../../types/campaign';

interface InvestigationRelationshipSummaryProps {
  email: EmailAnalysis;
  campaignAlert?: CampaignAlertData | null;
  visibleNodeCount: number;
  totalNodeCount: number;
  onResetGraph?: () => void;
}

export const InvestigationRelationshipSummary: React.FC<InvestigationRelationshipSummaryProps> = ({
  email,
  campaignAlert,
  visibleNodeCount,
  totalNodeCount,
  onResetGraph
}) => {
  const fromDomain = email.authentication?.alignment?.from_domain || email.from?.split('@')[1];
  const urlCount = email.url_analysis?.length || email.indicators?.urls?.length || 0;
  const ipCount = email.indicators?.ips?.length || email.ips?.length || 0;
  const domainCount = email.indicators?.domains?.length || email.domains?.length || 0;

  const isCampaignDetected = Boolean(campaignAlert?.is_campaign_detected);

  return (
    <div className="p-4 sm:p-5 rounded-xl bg-surface border border-border space-y-4 shadow-xs">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border">
        <div className="flex items-center space-x-2.5">
          <div className="w-8 h-8 rounded-lg bg-primary/10 text-primary flex items-center justify-center border border-primary/20">
            <Share2 className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
                Progressive Relationship Graph
              </h3>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-primary/10 text-primary border border-primary/20">
                Entity Topology
              </span>
            </div>
            <p className="text-[11px] font-mono text-foreground-muted">
              Explore how sender identity, infrastructure, domains, links, and campaigns interconnect
            </p>
          </div>
        </div>

        {/* Graph Density Pill */}
        <div className="flex items-center space-x-2 self-start sm:self-auto">
          <span className="text-xs font-mono text-foreground-muted">
            Displaying <strong className="text-foreground">{visibleNodeCount}</strong> of <strong className="text-foreground">{totalNodeCount}</strong> entities
          </span>
          {visibleNodeCount < totalNodeCount && onResetGraph && (
            <button
              type="button"
              onClick={onResetGraph}
              className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
            >
              Reset Core
            </button>
          )}
        </div>
      </div>

      {/* Summary Metrics Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
        {/* Metric 1: Root Sender */}
        <div className="p-3 rounded-lg bg-surface-secondary/70 border border-border space-y-1">
          <span className="text-[10px] text-foreground-muted uppercase tracking-wider flex items-center gap-1">
            <Mail className="w-3 h-3 text-amber-500" />
            Root Sender
          </span>
          <div className="font-bold text-foreground truncate" title={email.from}>
            {email.from || 'Unspecified'}
          </div>
          <div className="text-[10px] text-foreground-muted truncate">
            Domain: {fromDomain || 'N/A'}
          </div>
        </div>

        {/* Metric 2: Primary Domains & URLs */}
        <div className="p-3 rounded-lg bg-surface-secondary/70 border border-border space-y-1">
          <span className="text-[10px] text-foreground-muted uppercase tracking-wider flex items-center gap-1">
            <Globe className="w-3 h-3 text-purple-500" />
            Domains & URLs
          </span>
          <div className="font-bold text-foreground">
            {domainCount} Domains · {urlCount} URLs
          </div>
          <div className="text-[10px] text-foreground-muted truncate">
            {email.lookalike_domains && email.lookalike_domains.length > 0
              ? `${email.lookalike_domains.length} Lookalike domain flagged`
              : 'Direct links inspected'}
          </div>
        </div>

        {/* Metric 3: Infrastructure IPs */}
        <div className="p-3 rounded-lg bg-surface-secondary/70 border border-border space-y-1">
          <span className="text-[10px] text-foreground-muted uppercase tracking-wider flex items-center gap-1">
            <Server className="w-3 h-3 text-emerald-500" />
            Origin Infrastructure
          </span>
          <div className="font-bold text-foreground">
            {ipCount} Observed IP{ipCount !== 1 ? 's' : ''}
          </div>
          <div className="text-[10px] text-foreground-muted truncate">
            {email.relay_analysis?.earliest_observable_node?.earliest_observable_ip
              ? `Origin: ${email.relay_analysis.earliest_observable_node.earliest_observable_ip}`
              : 'Direct connection'}
          </div>
        </div>

        {/* Metric 4: Campaign Correlation */}
        <div className="p-3 rounded-lg bg-surface-secondary/70 border border-border space-y-1">
          <span className="text-[10px] text-foreground-muted uppercase tracking-wider flex items-center gap-1">
            <Network className="w-3 h-3 text-pink-500" />
            Campaign Status
          </span>
          <div className="font-bold text-foreground flex items-center gap-1.5 truncate">
            {isCampaignDetected ? (
              <>
                <ShieldAlert className="w-3.5 h-3.5 text-danger shrink-0" />
                <span className="text-danger truncate">{campaignAlert?.campaign_id || 'Cluster Active'}</span>
              </>
            ) : (
              <>
                <CheckCircle2 className="w-3.5 h-3.5 text-success shrink-0" />
                <span className="text-success">Single Incident</span>
              </>
            )}
          </div>
          <div className="text-[10px] text-foreground-muted truncate">
            {isCampaignDetected
              ? `${campaignAlert?.correlated_message_count || 2} correlated messages`
              : 'No external campaign match'}
          </div>
        </div>
      </div>
    </div>
  );
};
