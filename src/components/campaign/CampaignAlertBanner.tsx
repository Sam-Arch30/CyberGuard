import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ChevronRight,
  ChevronDown,
  ChevronUp,
  Server,
  Globe,
  Link as LinkIcon,
  Layers,
  FileText,
  Activity
} from 'lucide-react';
import type { CampaignAlertData } from '../../types/campaign';

interface CampaignAlertBannerProps {
  alertData?: CampaignAlertData | null;
  onViewCampaign?: (campaignId: string) => void;
  className?: string;
}

export const CampaignAlertBanner: React.FC<CampaignAlertBannerProps> = ({
  alertData,
  onViewCampaign,
  className = ''
}) => {
  const navigate = useNavigate();
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  if (!alertData || !alertData.is_campaign_detected || !alertData.campaign_id) {
    return null;
  }

  const campaignId = alertData.campaign_id;
  const messageCount = alertData.correlated_message_count || 0;
  const confidence = alertData.overall_confidence !== undefined ? Math.round(alertData.overall_confidence) : 0;
  const reasons = alertData.strongest_reasons || [];
  const catScores = alertData.category_scores || null;

  const handleNavigate = () => {
    if (onViewCampaign) {
      onViewCampaign(campaignId);
    } else {
      navigate(`/campaigns/${campaignId}`);
    }
  };

  return (
    <div
      className={`rounded-2xl border-2 border-warning/50 bg-gradient-to-r from-warning/15 via-surface to-warning/10 p-5 shadow-lg relative overflow-hidden transition-all duration-200 ${className}`}
    >
      {/* Background ambient glow */}
      <div className="absolute -top-16 -right-16 w-48 h-48 bg-warning/20 rounded-full blur-3xl pointer-events-none" />

      <div className="flex flex-col space-y-4 relative z-10">
        {/* Top Header Row */}
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-warning/20">
          <div className="flex items-center space-x-3.5">
            <div className="relative flex-shrink-0">
              <div className="w-10 h-10 rounded-xl bg-warning/20 border border-warning/40 flex items-center justify-center text-warning shadow-xs">
                <ShieldAlert className="w-6 h-6 animate-pulse" />
              </div>
              <div className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-danger ring-2 ring-surface animate-ping" />
            </div>

            <div>
              <div className="flex items-center space-x-2.5">
                <span className="px-2 py-0.5 rounded-md bg-danger text-danger-foreground text-[10px] font-mono font-bold uppercase tracking-wider">
                  TACTICAL CORRELATION
                </span>
                <span className="text-xs font-mono font-bold text-warning uppercase tracking-wider">
                  {campaignId ? `Campaign ${campaignId} Detected` : 'Campaign Detected'}
                </span>
              </div>
              <h2 className="text-base font-extrabold text-foreground font-sans tracking-tight mt-0.5">
                Potential campaign detected
              </h2>
            </div>
          </div>

          <div className="flex items-center space-x-2 self-start md:self-auto">
            <button
              type="button"
              onClick={handleNavigate}
              className="px-3.5 py-1.5 rounded-lg bg-warning hover:bg-warning-hover text-warning-foreground font-mono font-bold text-xs tracking-wider transition-all btn-press shadow-sm flex items-center space-x-1.5 cursor-pointer"
            >
              <span>OPEN CAMPAIGN INTELLIGENCE</span>
              <ChevronRight className="w-4 h-4" />
            </button>

            <button
              type="button"
              onClick={() => setIsExpanded(!isExpanded)}
              className="p-1.5 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-border transition-colors"
              title={isExpanded ? 'Collapse Alert' : 'Expand Alert Details'}
            >
              {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Primary Message Alert */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs font-mono">
          <p className="text-foreground font-medium flex items-center space-x-2">
            <Activity className="w-4 h-4 text-warning shrink-0" />
            <span>
              This email shares infrastructure or behavioral characteristics with{' '}
              <strong className="text-warning underline decoration-warning/50 underline-offset-2">
                {messageCount} previously analyzed messages
              </strong>
              .
            </span>
          </p>

          <div className="flex items-center space-x-2 shrink-0">
            <span className="text-[11px] text-foreground-muted uppercase font-mono">Overall Confidence:</span>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-bold bg-warning/20 border border-warning/40 text-warning">
              {confidence}%
            </span>
          </div>
        </div>

        {/* Expanded Details: Category Scores & Strongest Correlation Reasons */}
        {isExpanded && (
          <div className="space-y-3.5 pt-2 border-t border-warning/15 animate-in fade-in duration-150">
            {/* Category Similarity Grid */}
            {catScores && (
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
                <div className="p-2.5 rounded-xl bg-surface border border-border/80 text-center space-y-1">
                  <div className="flex items-center justify-center space-x-1 text-[10px] font-mono text-foreground-muted uppercase">
                    <Server className="w-3 h-3 text-primary" />
                    <span>Infrastructure</span>
                  </div>
                  <div className="text-sm font-bold font-mono text-primary">
                    {Math.round(catScores.infrastructure_similarity)}%
                  </div>
                  <div className="w-full bg-surface-secondary h-1 rounded-full overflow-hidden">
                    <div
                      className="bg-primary h-full rounded-full transition-all"
                      style={{ width: `${Math.min(100, catScores.infrastructure_similarity)}%` }}
                    />
                  </div>
                </div>

                <div className="p-2.5 rounded-xl bg-surface border border-border/80 text-center space-y-1">
                  <div className="flex items-center justify-center space-x-1 text-[10px] font-mono text-foreground-muted uppercase">
                    <Globe className="w-3 h-3 text-info" />
                    <span>Domain</span>
                  </div>
                  <div className="text-sm font-bold font-mono text-info">
                    {Math.round(catScores.domain_similarity)}%
                  </div>
                  <div className="w-full bg-surface-secondary h-1 rounded-full overflow-hidden">
                    <div
                      className="bg-info h-full rounded-full transition-all"
                      style={{ width: `${Math.min(100, catScores.domain_similarity)}%` }}
                    />
                  </div>
                </div>

                <div className="p-2.5 rounded-xl bg-surface border border-border/80 text-center space-y-1">
                  <div className="flex items-center justify-center space-x-1 text-[10px] font-mono text-foreground-muted uppercase">
                    <LinkIcon className="w-3 h-3 text-danger" />
                    <span>URL Lure</span>
                  </div>
                  <div className="text-sm font-bold font-mono text-danger">
                    {Math.round(catScores.url_similarity)}%
                  </div>
                  <div className="w-full bg-surface-secondary h-1 rounded-full overflow-hidden">
                    <div
                      className="bg-danger h-full rounded-full transition-all"
                      style={{ width: `${Math.min(100, catScores.url_similarity)}%` }}
                    />
                  </div>
                </div>

                <div className="p-2.5 rounded-xl bg-surface border border-border/80 text-center space-y-1">
                  <div className="flex items-center justify-center space-x-1 text-[10px] font-mono text-foreground-muted uppercase">
                    <FileText className="w-3 h-3 text-warning" />
                    <span>Content Intent</span>
                  </div>
                  <div className="text-sm font-bold font-mono text-warning">
                    {Math.round(catScores.content_similarity)}%
                  </div>
                  <div className="w-full bg-surface-secondary h-1 rounded-full overflow-hidden">
                    <div
                      className="bg-warning h-full rounded-full transition-all"
                      style={{ width: `${Math.min(100, catScores.content_similarity)}%` }}
                    />
                  </div>
                </div>

                <div className="p-2.5 rounded-xl bg-surface border border-border/80 text-center space-y-1 col-span-2 sm:col-span-1">
                  <div className="flex items-center justify-center space-x-1 text-[10px] font-mono text-foreground-muted uppercase">
                    <Layers className="w-3 h-3 text-emerald-400" />
                    <span>Template SimHash</span>
                  </div>
                  <div className="text-sm font-bold font-mono text-emerald-400">
                    {Math.round(catScores.template_similarity)}%
                  </div>
                  <div className="w-full bg-surface-secondary h-1 rounded-full overflow-hidden">
                    <div
                      className="bg-emerald-400 h-full rounded-full transition-all"
                      style={{ width: `${Math.min(100, catScores.template_similarity)}%` }}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Strongest Correlation Reasons List */}
            <div className="space-y-1.5">
              <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted block font-semibold">
                Strongest Correlation Reasons:
              </span>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {reasons.map((reason, idx) => (
                  <div
                    key={idx}
                    className="px-3 py-2 rounded-lg bg-surface border border-border/70 text-xs font-mono text-foreground flex items-start space-x-2"
                  >
                    <span className="w-2 h-2 rounded-full bg-warning shrink-0 mt-1" />
                    <span className="leading-snug">{reason}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
