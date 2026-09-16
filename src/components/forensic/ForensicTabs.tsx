import React from 'react';
import type { ForensicTabType } from '../../types/forensic';
import { LayoutDashboard, FileText, Code, Target, Paperclip, Terminal, Share2, MapPin, Network, GitMerge, Sparkles } from 'lucide-react';

interface ForensicTabsProps {
  activeTab: ForensicTabType;
  onTabChange: (tab: ForensicTabType) => void;
  counts: {
    receivedHops: number;
    urls: number;
    attachments: number;
    relatedEmails?: number;
  };
}

export const ForensicTabs: React.FC<ForensicTabsProps> = ({
  activeTab,
  onTabChange,
  counts
}) => {
  const tabs: { id: ForensicTabType; label: string; icon: React.ReactNode; badge?: number | string; badgeColor?: string }[] = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-3.5 h-3.5" /> },
    {
      id: 'copilot',
      label: 'Investigation Copilot',
      icon: <Sparkles className="w-3.5 h-3.5 text-primary" />,
      badge: 'AI',
      badgeColor: 'text-primary bg-primary/15 border-primary/30 font-bold'
    },
    {
      id: 'cross_investigation',
      label: 'Cross-Email Workspace',
      icon: <GitMerge className="w-3.5 h-3.5" />,
      badge: counts.relatedEmails ?? 16,
      badgeColor: 'text-danger bg-danger/15 border-danger/30'
    },
    { id: 'attribution', label: 'Infrastructure Attribution', icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'graph', label: 'Investigation Graph', icon: <Share2 className="w-3.5 h-3.5" /> },
    { id: 'map', label: 'Investigation Map', icon: <MapPin className="w-3.5 h-3.5" /> },
    { id: 'headers', label: 'Headers', icon: <FileText className="w-3.5 h-3.5" />, badge: counts.receivedHops },
    { id: 'content', label: 'Content', icon: <Code className="w-3.5 h-3.5" /> },
    { id: 'indicators', label: 'Indicators', icon: <Target className="w-3.5 h-3.5" />, badge: counts.urls },
    { id: 'attachments', label: 'Attachments', icon: <Paperclip className="w-3.5 h-3.5" />, badge: counts.attachments },
    { id: 'raw', label: 'Raw Email', icon: <Terminal className="w-3.5 h-3.5" /> },
  ];

  return (
    <div className="flex flex-wrap items-center gap-1 p-1 bg-surface-secondary/70 rounded-control border border-border">
      {tabs.map((tab) => {
        const isActive = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            onClick={() => onTabChange(tab.id)}
            className={`flex items-center space-x-2 px-3 py-2 rounded-control text-xs font-mono transition-all cursor-pointer ${
              isActive
                ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                : 'text-foreground-muted hover:text-foreground hover:bg-surface/50 border border-transparent'
            }`}
          >
            <span className={isActive ? 'text-primary' : 'text-foreground-muted'}>
              {tab.icon}
            </span>
            <span>{tab.label}</span>
            {typeof tab.badge === 'number' && (
              <span
                className={`ml-1 px-1.5 py-0.2 rounded-control text-[10px] font-mono border ${
                  tab.badgeColor || (isActive
                    ? 'bg-surface-secondary text-foreground border-border font-bold'
                    : 'bg-surface-secondary/60 text-foreground-muted border-border/60')
                }`}
              >
                {tab.badge}
              </span>
            )}
          </button>
        );
      })}
    </div>
  );
};
