import React, { useState } from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  SearchCode,
  FolderLock,
  Globe2,
  FileText,
  Sliders,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  Radio,
  Zap,
  Palette,
  Network,
  GitMerge,
  BarChart3
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

  const navItems = [
    {
      name: 'Dashboard',
      path: '/',
      icon: LayoutDashboard,
      badge: undefined
    },
    {
      name: 'Analyze Email',
      path: '/analyze',
      icon: SearchCode,
      badge: 'UPLOAD'
    },
    {
      name: 'Forensic View',
      path: '/analysis/demo',
      icon: FileText,
      badge: 'EVIDENCE'
    },
    {
      name: 'Cross-Email Workspace',
      path: '/cross-investigation',
      icon: GitMerge,
      badge: '16 NEW'
    },
    {
      name: 'Investigations',
      path: '/cases',
      icon: FolderLock,
      badge: '3 Active'
    },
    {
      name: 'Campaign Intelligence',
      path: '/campaigns',
      icon: Network,
      badge: 'CLUSTERS'
    },
    {
      name: 'Threat Intelligence',
      path: '/intelligence',
      icon: Globe2,
      badge: undefined
    },
    {
      name: 'Reports',
      path: '/reports',
      icon: FileText,
      badge: undefined
    },
    {
      name: 'Benchmark & Evaluation',
      path: '/benchmarks',
      icon: BarChart3,
      badge: 'SIH-SAFE'
    },
    {
      name: 'Settings',
      path: '/settings',
      icon: Sliders,
      badge: undefined
    }
  ];

  return (
    <aside
      className={`fixed top-0 left-0 bottom-0 z-40 bg-sidebar-bg border-r border-sidebar-border transition-all duration-250 flex flex-col justify-between ${
        isCollapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Top Header Logo */}
      <div>
        <div className="h-16 px-4 flex items-center justify-between border-b border-sidebar-border">
          <div className="flex items-center space-x-3 overflow-hidden">
            <div className="relative flex-shrink-0">
              <div className="w-9 h-9 rounded-control bg-surface border border-border flex items-center justify-center text-primary shadow-xs">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full bg-success ring-2 ring-sidebar-bg" />
            </div>

            {!isCollapsed && (
              <div className="flex flex-col min-w-0">
                <span className="font-sans font-bold text-sm tracking-tight text-foreground truncate">
                  MailTrace AI
                </span>
                <span className="text-[10px] font-mono text-foreground-muted tracking-wider uppercase truncate">
                  Forensic Suite
                </span>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={toggleCollapse}
            className="p-1.5 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent hover:border-border transition-colors cursor-pointer"
            title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
            aria-label={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          >
            {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Live Status Indicator Pill */}
        {!isCollapsed && (
          <div className="mx-3 mt-3 mb-1 p-2.5 rounded-control bg-surface-secondary/70 border border-border flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Radio className="w-3.5 h-3.5 text-success animate-pulse" />
              <span className="text-xs font-mono text-foreground-muted">Sensor Telemetry</span>
            </div>
            <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-badge bg-surface border border-border text-foreground">
              ONLINE
            </span>
          </div>
        )}

        {/* Navigation Items */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2 rounded-control text-xs font-medium transition-all group ${
                    isActive
                      ? 'bg-primary-subtle text-primary border border-primary/25 font-semibold'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
                  }`
                }
                title={isCollapsed ? item.name : undefined}
              >
                <div className="flex items-center space-x-2.5 min-w-0">
                  <Icon className="w-4 h-4 flex-shrink-0 group-hover:text-primary transition-colors" />
                  {!isCollapsed && <span className="truncate">{item.name}</span>}
                </div>

                {!isCollapsed && item.badge && (
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded-badge bg-surface border border-border text-foreground-muted font-medium">
                    {item.badge}
                  </span>
                )}
              </NavLink>
            );
          })}
        </nav>
      </div>

      {/* Bottom Profile / Quick Action Card */}
      <div className="p-3 border-t border-sidebar-border space-y-2">
        {!isCollapsed ? (
          <div className="p-3 rounded-card bg-surface-secondary/50 border border-border space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2.5 min-w-0">
                <div className="w-7 h-7 rounded-control bg-surface border border-border flex items-center justify-center text-[11px] font-mono font-semibold text-primary">
                  AM
                </div>
                <div className="flex flex-col min-w-0">
                  <span className="text-xs font-medium text-foreground truncate">Alex Mercer</span>
                  <span className="text-[10px] font-mono text-foreground-muted truncate">SOC Analyst</span>
                </div>
              </div>

              {/* Theme Tag */}
              <div
                className="flex items-center space-x-1 px-1.5 py-0.5 rounded-badge text-[10px] font-mono text-foreground-muted bg-surface border border-border"
                title={`Active Theme: ${themeMeta.name}`}
              >
                <Palette className="w-3 h-3 text-primary" />
                <span className="capitalize">{themeMeta.id}</span>
              </div>
            </div>

            <NavLink
              to="/analyze"
              className="w-full flex items-center justify-center space-x-1.5 py-1.5 text-xs font-mono font-medium rounded-control bg-primary hover:bg-primary-hover text-primary-foreground transition-colors btn-press cursor-pointer"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>SCAN RAW EMAIL</span>
            </NavLink>
          </div>
        ) : (
          <div className="flex flex-col items-center space-y-2">
            <div className="w-8 h-8 rounded-control bg-surface border border-border flex items-center justify-center text-xs font-mono font-medium text-primary">
              AM
            </div>
          </div>
        )}
      </div>
    </aside>
  );
};
