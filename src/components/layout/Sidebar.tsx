import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  FolderLock,
  Globe2,
  FileText,
  Sliders,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
<<<<<<< Updated upstream
  Radio,
  Zap,
  Palette
=======
  Palette,
  Network,
  GitMerge,
  BarChart3,
  Clock,
  ShieldAlert,
  Inbox
>>>>>>> Stashed changes
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

interface SidebarProps {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed: externalCollapsed,
  onToggleCollapse: externalToggle
}) => {
  const [internalCollapsed, setInternalCollapsed] = useState(false);
  const isCollapsed = externalCollapsed !== undefined ? externalCollapsed : internalCollapsed;
  const toggleCollapse = externalToggle || (() => setInternalCollapsed(!internalCollapsed));

  const { themeMeta } = useTheme();

  // Guided Investigation Workflow Steps
  const workflowItems = [
    {
      step: '01',
      name: 'Ingest Email',
      path: '/analyze',
      icon: Inbox,
      description: 'Upload .eml or raw text'
    },
    {
<<<<<<< Updated upstream
      name: 'Forensic View',
      path: '/analysis/demo',
      icon: FileText,
      badge: 'EVIDENCE'
    },
    {
      name: 'Investigations',
      path: '/cases',
      icon: FolderLock,
      badge: '3 Active'
    },
    {
      name: 'Threat Intelligence',
      path: '/intelligence',
      icon: Globe2,
      badge: undefined
=======
      step: '02',
      name: 'Triage Queue',
      path: '/history',
      icon: Clock,
      description: 'Prioritize analyzed emails'
    },
    {
      step: '03',
      name: 'Forensic Deep Dive',
      path: '/analysis/demo',
      icon: ShieldAlert,
      description: 'Header, relay & IOC analysis'
    },
    {
      step: '04',
      name: 'Cross-Correlation',
      path: '/cross-investigation',
      icon: GitMerge,
      description: 'Multi-message pivot & overlap'
    },
    {
      step: '05',
      name: 'Campaign Intelligence',
      path: '/campaigns',
      icon: Network,
      description: 'Threat actor clusters'
    },
    {
      step: '06',
      name: 'Incident Cases',
      path: '/cases',
      icon: FolderLock,
      description: 'Evidence & findings tracking'
>>>>>>> Stashed changes
    },
    {
      step: '07',
      name: 'Forensic Reports',
      path: '/reports',
      icon: FileText,
      description: 'Audit-ready court PDFs'
    }
  ];

  // Secondary Tools & Platform Overview
  const platformItems = [
    {
      name: 'SOC Telemetry',
      path: '/',
      icon: LayoutDashboard,
    },
    {
<<<<<<< Updated upstream
      name: 'Settings',
=======
      name: 'OSINT Threat Intel',
      path: '/intelligence',
      icon: Globe2,
    },
    {
      name: 'Model Benchmark',
      path: '/benchmarks',
      icon: BarChart3,
    },
    {
      name: 'System Settings',
>>>>>>> Stashed changes
      path: '/settings',
      icon: Sliders,
    }
  ];

  return (
    <aside
      className={`fixed top-0 left-0 bottom-0 z-40 bg-sidebar-bg border-r border-sidebar-border transition-all duration-250 flex flex-col justify-between select-none ${
        isCollapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Top Header Logo */}
      <div className="flex-1 overflow-y-auto">
        <div className="h-16 px-4 flex items-center justify-between border-b border-sidebar-border sticky top-0 bg-sidebar-bg/95 backdrop-blur-xs z-10">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="relative flex-shrink-0">
              <div className="w-8 h-8 rounded-control bg-surface border border-border flex items-center justify-center text-primary shadow-xs">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-success ring-2 ring-sidebar-bg" />
            </div>

            {!isCollapsed && (
              <div className="flex flex-col min-w-0">
                <span className="font-sans font-bold text-xs tracking-tight text-foreground truncate">
                  MailTrace AI
                </span>
                <span className="text-[10px] font-mono text-foreground-muted tracking-wider uppercase truncate">
                  Enterprise SOC
                </span>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={toggleCollapse}
            className="p-1 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent hover:border-border transition-colors cursor-pointer"
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
            aria-label={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {isCollapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
          </button>
        </div>

        {/* Workflow Section Header */}
        {!isCollapsed ? (
          <div className="px-4 pt-4 pb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-foreground-subtle flex items-center justify-between">
            <span>Investigation Lifecycle</span>
          </div>
        ) : (
          <div className="my-2 border-b border-sidebar-border" />
        )}

        {/* Primary Investigation Workflow Navigation */}
        <nav className="px-2.5 space-y-0.5">
          {workflowItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center justify-between px-2.5 py-1.5 rounded-control text-xs font-medium transition-all group ${
                    isActive
                      ? 'bg-primary-subtle text-primary border border-primary/30 font-semibold shadow-xs'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
                  }`
                }
                title={isCollapsed ? `${item.step}. ${item.name}` : undefined}
              >
                <div className="flex items-center space-x-2.5 min-w-0">
                  <Icon className="w-3.5 h-3.5 flex-shrink-0 group-hover:text-primary transition-colors" />
                  {!isCollapsed && (
                    <div className="flex flex-col min-w-0">
                      <span className="truncate leading-snug">{item.name}</span>
                    </div>
                  )}
                </div>

                {!isCollapsed && (
                  <span className="text-[9px] font-mono px-1 rounded bg-surface/70 border border-border text-foreground-subtle">
                    {item.step}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Secondary Platform Tools Header */}
        {!isCollapsed ? (
          <div className="px-4 pt-5 pb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-foreground-subtle">
            <span>Platform Tools</span>
          </div>
        ) : (
          <div className="my-3 border-b border-sidebar-border" />
        )}

        {/* Secondary Navigation */}
        <nav className="px-2.5 space-y-0.5 pb-4">
          {platformItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center space-x-2.5 px-2.5 py-1.5 rounded-control text-xs font-medium transition-all group ${
                    isActive
                      ? 'bg-primary-subtle text-primary border border-primary/30 font-semibold'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
                  }`
                }
                title={isCollapsed ? item.name : undefined}
              >
                <Icon className="w-3.5 h-3.5 flex-shrink-0 group-hover:text-primary transition-colors" />
                {!isCollapsed && <span className="truncate">{item.name}</span>}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Profile / Theme Footer */}
      <div className="p-3 border-t border-sidebar-border bg-sidebar-bg">
        {!isCollapsed ? (
          <div className="flex items-center justify-between p-2 rounded-control bg-surface border border-border">
            <div className="flex items-center space-x-2 min-w-0">
              <div className="w-6 h-6 rounded bg-surface-secondary border border-border flex items-center justify-center text-[10px] font-mono font-semibold text-primary">
                SOC
              </div>
              <div className="flex flex-col min-w-0">
                <span className="text-[11px] font-medium text-foreground truncate">Analyst Console</span>
                <span className="text-[9px] font-mono text-success truncate">Connected</span>
              </div>
            </div>

            <div
              className="flex items-center space-x-1 px-1.5 py-0.5 rounded text-[10px] font-mono text-foreground-muted bg-surface-secondary border border-border"
              title={`Active Theme: ${themeMeta.name}`}
            >
              <Palette className="w-2.5 h-2.5 text-primary" />
              <span className="capitalize">{themeMeta.id}</span>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center">
            <div className="w-7 h-7 rounded bg-surface border border-border flex items-center justify-center text-[10px] font-mono font-semibold text-primary">
              SOC
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
