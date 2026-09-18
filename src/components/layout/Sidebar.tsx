import React, { useState } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  Compass,
  FileText,
  Cpu,
  Globe2,
  FolderLock,
  FileCheck,
  Plus,
  Clock,
  BarChart3,
  Briefcase,
  Layers,
  Sliders,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  Palette
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useInvestigation } from '../../context/InvestigationContext';

interface SidebarProps {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed: externalCollapsed,
  onToggleCollapse: externalToggle,
  mobileOpen = false,
  onCloseMobile
}) => {
  const [internalCollapsed, setInternalCollapsed] = useState(false);
  const isCollapsed = externalCollapsed !== undefined ? externalCollapsed : internalCollapsed;
  const toggleCollapse = externalToggle || (() => setInternalCollapsed(!internalCollapsed));

  const { themeMeta } = useTheme();
  const { activeEmailId, activeSection } = useInvestigation();
  const location = useLocation();

  // 1. PRIMARY INVESTIGATION AREAS (The core 6 sections)
  const primaryInvestigationAreas = [
    {
      step: '01',
      id: 'overview',
      name: 'Overview',
      path: activeEmailId ? `/investigate/${activeEmailId}/overview` : '/overview',
      matchPrefixes: ['/overview', `/investigate/${activeEmailId}/overview`, '/investigate/overview'],
      icon: Compass,
      description: 'Threat score & major findings'
    },
    {
      step: '02',
      id: 'email',
      name: 'Email',
      path: activeEmailId ? `/investigate/${activeEmailId}/email` : '/email',
      matchPrefixes: ['/email', `/investigate/${activeEmailId}/email`, '/investigate/email'],
      icon: FileText,
      description: 'Headers, auth & relay trace'
    },
    {
      step: '03',
      id: 'analysis',
      name: 'Analysis',
      path: activeEmailId ? `/investigate/${activeEmailId}/analysis` : '/analysis',
      matchPrefixes: ['/analysis', `/investigate/${activeEmailId}/analysis`, '/investigate/analysis'],
      icon: Cpu,
      description: 'IOCs, URLs, lookalikes & NLP'
    },
    {
      step: '04',
      id: 'intelligence',
      name: 'Intelligence',
      path: activeEmailId ? `/investigate/${activeEmailId}/intelligence` : '/intelligence',
      matchPrefixes: ['/intelligence', `/investigate/${activeEmailId}/intelligence`, '/investigate/intelligence'],
      icon: Globe2,
      description: 'IP & domain intel, map & ASN'
    },
    {
      step: '05',
      id: 'investigation',
      name: 'Investigation',
      path: activeEmailId ? `/investigate/${activeEmailId}/investigation` : '/investigation',
      matchPrefixes: ['/investigation', `/investigate/${activeEmailId}/investigation`, '/investigate/investigation', '/cross-investigation', '/campaigns'],
      icon: FolderLock,
      description: 'Graph, campaigns & copilot'
    },
    {
      step: '06',
      id: 'report',
      name: 'Report',
      path: activeEmailId ? `/investigate/${activeEmailId}/report` : '/report',
      matchPrefixes: ['/report', `/investigate/${activeEmailId}/report`, '/investigate/report', '/reports'],
      icon: FileCheck,
      description: 'Executive briefing & PDF export'
    }
  ];

  // 2. SECONDARY PLATFORM & INTAKE TOOLS
  const platformTools = [
    {
      name: 'Ingest Email',
      path: '/analyze',
      icon: Plus,
      badge: 'INTAKE'
    },
    {
      name: 'Ingested .EML History',
      path: '/history',
      icon: Clock,
      badge: undefined
    },
    {
      name: 'SOC Telemetry',
      path: '/dashboard',
      icon: BarChart3,
      badge: undefined
    },
    {
      name: 'Incident Cases',
      path: '/cases',
      icon: Briefcase,
      badge: undefined
    },
    {
      name: 'Evaluation Benchmark',
      path: '/benchmarks',
      icon: Layers,
      badge: 'SAFE'
    },
    {
      name: 'System Settings',
      path: '/settings',
      icon: Sliders,
      badge: undefined
    }
  ];

  const isAreaActive = (area: typeof primaryInvestigationAreas[0]) => {
    return activeSection === area.id || area.matchPrefixes.some(p => location.pathname === p || location.pathname.startsWith(p + '/'));
  };

  return (
    <>
      {/* Mobile Drawer Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-xs md:hidden animate-in fade-in duration-150"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 z-50 md:z-40 bg-sidebar-bg border-r border-sidebar-border transition-all duration-200 flex flex-col justify-between select-none ${
          mobileOpen ? 'left-0 w-64 shadow-2xl' : '-left-64 md:left-0'
        } ${
          isCollapsed ? 'md:w-20' : 'md:w-64'
        }`}
      >
      <div className="flex-1 overflow-y-auto">
        {/* Top Header Logo */}
        <div className="h-16 px-4 flex items-center justify-between border-b border-sidebar-border sticky top-0 bg-sidebar-bg/95 backdrop-blur-xs z-10">
          <NavLink to={activeEmailId ? `/investigate/${activeEmailId}/overview` : '/'} className="flex items-center space-x-3 overflow-hidden group cursor-pointer">
            <div className="relative flex-shrink-0">
              <div className="w-8 h-8 rounded-control bg-surface border border-border flex items-center justify-center text-primary shadow-xs group-hover:border-primary/50 transition-colors">
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
                  Forensic Suite
                </span>
              </div>
            )}
          </NavLink>

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

        {/* Primary Investigation Section Header */}
        {!isCollapsed ? (
          <div className="px-4 pt-4 pb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-foreground-subtle flex items-center justify-between">
            <span>Investigation Lifecycle</span>
            <span className="text-[9px] px-1.5 py-0.2 rounded bg-primary/10 text-primary font-bold">
              6 STAGES
            </span>
          </div>
        ) : (
          <div className="my-2 border-b border-sidebar-border" />
        )}

        {/* Primary 6-Area Navigation */}
        <nav className="px-2 space-y-0.5">
          {primaryInvestigationAreas.map((item) => {
            const Icon = item.icon;
            const active = isAreaActive(item);
            return (
              <NavLink
                key={item.id}
                to={item.path}
                className={`flex items-center justify-between px-2.5 py-2 rounded-control text-xs font-medium transition-all group ${
                  active
                    ? 'bg-primary/10 text-primary font-semibold border-l-2 border-primary pl-2'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border-l-2 border-transparent'
                }`}
                title={isCollapsed ? `${item.step}. ${item.name}` : item.description}
              >
                <div className="flex items-center space-x-2.5 min-w-0">
                  <Icon className={`w-4 h-4 flex-shrink-0 transition-colors ${active ? 'text-primary' : 'group-hover:text-primary'}`} />
                  {!isCollapsed && (
                    <div className="flex flex-col min-w-0">
                      <span className="truncate leading-snug">{item.name}</span>
                    </div>
                  )}
                </div>

                {!isCollapsed && (
                  <span
                    className={`text-[9px] font-mono px-1 rounded ${
                      active
                        ? 'bg-primary/20 text-primary font-bold'
                        : 'bg-surface/70 border border-border text-foreground-subtle'
                    }`}
                  >
                    {item.step}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>

        {/* Platform & Intake Header */}
        {!isCollapsed ? (
          <div className="px-4 pt-4 pb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-foreground-subtle">
            <span>Platform Tools</span>
          </div>
        ) : (
          <div className="my-3 border-b border-sidebar-border" />
        )}

        {/* Secondary Navigation */}
        <nav className="px-2 space-y-0.5 pb-4">
          {platformTools.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center justify-between px-2.5 py-1.5 rounded-control text-xs font-medium transition-all group ${
                    isActive
                      ? 'bg-primary/10 text-primary font-semibold border-l-2 border-primary pl-2'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border-l-2 border-transparent'
                  }`
                }
                title={isCollapsed ? item.name : undefined}
              >
                <div className="flex items-center space-x-2.5 min-w-0">
                  <Icon className="w-3.5 h-3.5 flex-shrink-0 group-hover:text-primary transition-colors" />
                  {!isCollapsed && <span className="truncate">{item.name}</span>}
                </div>

                {!isCollapsed && item.badge && (
                  <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-surface border border-border text-foreground-subtle">
                    {item.badge}
                  </span>
                )}
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
    </>
  );
};
