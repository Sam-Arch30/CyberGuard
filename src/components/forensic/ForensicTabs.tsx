import React from 'react';
import type { ForensicTabType } from '../../types/forensic';
<<<<<<< Updated upstream
import { LayoutDashboard, FileText, Code, Target, Paperclip, Terminal, Share2, MapPin } from 'lucide-react';
=======
import {
  LayoutDashboard,
  FileText,
  Code,
  Target,
  Paperclip,
  Terminal,
  Share2,
  MapPin,
  Network,
  GitMerge,
  Sparkles
} from 'lucide-react';
>>>>>>> Stashed changes

interface ForensicTabsProps {
  activeTab: ForensicTabType;
  onTabChange: (tab: ForensicTabType) => void;
  counts: {
    receivedHops: number;
    urls: number;
    attachments: number;
  };
  onToggleCopilotDrawer?: () => void;
  isCopilotDrawerOpen?: boolean;
}

export const ForensicTabs: React.FC<ForensicTabsProps> = ({
  activeTab,
  onTabChange,
  counts,
  onToggleCopilotDrawer,
  isCopilotDrawerOpen
}) => {
  const tabs: { id: ForensicTabType; label: string; icon: React.ReactNode; badge?: number }[] = [
    { id: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-3.5 h-3.5" /> },
<<<<<<< Updated upstream
    { id: 'graph', label: 'Investigation Graph', icon: <Share2 className="w-3.5 h-3.5" /> },
    { id: 'map', label: 'Investigation Map', icon: <MapPin className="w-3.5 h-3.5" /> },
    { id: 'headers', label: 'Headers', icon: <FileText className="w-3.5 h-3.5" />, badge: counts.receivedHops },
=======
    { id: 'headers', label: 'Headers & Relays', icon: <FileText className="w-3.5 h-3.5" />, badge: counts.receivedHops },
>>>>>>> Stashed changes
    { id: 'content', label: 'Content', icon: <Code className="w-3.5 h-3.5" /> },
    { id: 'indicators', label: 'Indicators', icon: <Target className="w-3.5 h-3.5" />, badge: counts.urls },
    { id: 'attachments', label: 'Attachments', icon: <Paperclip className="w-3.5 h-3.5" />, badge: counts.attachments },
    { id: 'graph', label: 'Investigation Graph', icon: <Share2 className="w-3.5 h-3.5" /> },
    { id: 'map', label: 'GeoTrace Map', icon: <MapPin className="w-3.5 h-3.5" /> },
    { id: 'attribution', label: 'Attribution', icon: <Network className="w-3.5 h-3.5" /> },
    { id: 'cross_investigation', label: 'Cross-Email Pivot', icon: <GitMerge className="w-3.5 h-3.5" /> },
    { id: 'raw', label: 'Raw RFC-822', icon: <Terminal className="w-3.5 h-3.5" /> },
    { id: 'copilot', label: 'Copilot Workbench', icon: <Sparkles className="w-3.5 h-3.5 text-primary" />, badge: 'AI' },
  ];

  return (
<<<<<<< Updated upstream
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
                  isActive
                    ? 'bg-surface-secondary text-foreground border-border font-bold'
                    : 'bg-surface-secondary/60 text-foreground-muted border-border/60'
                }`}
              >
                {tab.badge}
=======
    <div className="flex items-center justify-between gap-2 p-1 bg-surface-secondary/70 rounded-control border border-border">
      <div className="flex flex-wrap items-center gap-1">
        {tabs.map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control text-xs font-mono transition-all cursor-pointer ${
                isActive
                  ? 'bg-surface text-foreground font-semibold border border-border shadow-xs'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface/50 border border-transparent'
              }`}
            >
              <span className={isActive ? 'text-primary' : 'text-foreground-muted'}>
                {tab.icon}
>>>>>>> Stashed changes
              </span>
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span
                  className={`ml-1 px-1 rounded text-[10px] font-mono border ${
                    tab.badge === 'AI'
                      ? 'bg-primary-subtle text-primary border-primary/30 font-bold'
                      : isActive
                      ? 'bg-surface-secondary text-foreground border-border font-bold'
                      : 'bg-surface-secondary/60 text-foreground-muted border-border/60'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {onToggleCopilotDrawer && (
        <button
          type="button"
          onClick={onToggleCopilotDrawer}
          className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control text-xs font-mono font-medium transition-colors cursor-pointer border ${
            isCopilotDrawerOpen
              ? 'bg-primary text-primary-foreground border-primary shadow-xs'
              : 'bg-surface text-foreground hover:bg-surface-secondary border-border'
          }`}
          title="Toggle Contextual Copilot Drawer"
        >
          <Sparkles className="w-3.5 h-3.5 text-primary" />
          <span className="hidden sm:inline">Copilot Drawer</span>
        </button>
      )}
    </div>
  );
};
