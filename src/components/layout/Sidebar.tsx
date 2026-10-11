import React, { useState, useEffect } from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  FileText,
  Settings,
  ChevronLeft,
  ChevronRight,
  ShieldCheck,
  BellRing,
  Layers,
  Binary,
} from 'lucide-react';
import { Tooltip } from '../ui';
import { cn } from '../../utils/cn';

export interface SidebarProps {
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  mobileOpen?: boolean;
  onCloseMobile?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  collapsed: externalCollapsed,
  onToggleCollapse: externalToggle,
  mobileOpen = false,
  onCloseMobile,
}) => {
  const [internalCollapsed, setInternalCollapsed] = useState(() => {
    try {
      return localStorage.getItem('cyberguard_sidebar_collapsed') === 'true';
    } catch {
      return false;
    }
  });

  const isCollapsed = externalCollapsed !== undefined ? externalCollapsed : internalCollapsed;

  const toggleCollapse = () => {
    if (externalToggle) {
      externalToggle();
    } else {
      const next = !internalCollapsed;
      setInternalCollapsed(next);
      try {
        localStorage.setItem('cyberguard_sidebar_collapsed', String(next));
      } catch {
        // Ignore storage errors
      }
    }
  };

  const location = useLocation();

  // Query real agent and backend health status
  const [systemHealth, setSystemHealth] = useState<'OK' | 'DEGRADED' | 'STANDBY'>('STANDBY');
  const [agentCount, setAgentCount] = useState<number | null>(null);

  useEffect(() => {
    let isMounted = true;

    // Check system health
    fetch('/api/health')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!isMounted) return;
        if (data?.status === 'ok') setSystemHealth('OK');
        else if (data?.status === 'degraded') setSystemHealth('DEGRADED');
        else setSystemHealth('STANDBY');
      })
      .catch(() => {
        if (isMounted) setSystemHealth('STANDBY');
      });

    // Check fleet agent count
    fetch('/api/v1/endpoint/agents')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (!isMounted) return;
        if (Array.isArray(data)) setAgentCount(data.length);
        else if (data?.agents && Array.isArray(data.agents)) setAgentCount(data.agents.length);
      })
      .catch(() => {
        // Keep null if not enrolled
      });

    return () => {
      isMounted = false;
    };
  }, []);

  // Close mobile drawer on escape key
  useEffect(() => {
    if (!mobileOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onCloseMobile?.();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [mobileOpen, onCloseMobile]);

  // PRIMARY MINIMAL NAVIGATION SPECIFICATION (Section 1 & 5)
  // Dashboard, Investigations, Reports
  const mainNavItems = [
    {
      id: 'dashboard',
      name: 'Dashboard',
      path: '/dashboard',
      matchPrefixes: ['/dashboard', '/'],
      icon: LayoutDashboard,
      description: 'Security overview, universal ingestion & active threats',
    },
    {
      id: 'alerts',
      name: 'Alerts',
      path: '/alerts',
      matchPrefixes: ['/alerts', '/security-alerts'],
      icon: BellRing,
      description: 'Alert triage, correlation clusters & noise suppression',
    },
    {
      id: 'incidents',
      name: 'Incidents',
      path: '/incidents',
      matchPrefixes: ['/incidents', '/cases'],
      icon: Layers,
      description: 'Operational security cases, lifecycle & ownership',
    },
    {
      id: 'investigations',
      name: 'Investigations',
      path: '/investigations',
      matchPrefixes: [
        '/investigations',
        '/investigate',
        '/overview',
        '/email',
        '/analysis',
        '/intelligence',
        '/investigation',
      ],
      icon: ShieldAlert,
      description: 'Deep-dive forensic analysis, attack graphs & response workflows',
    },
    {
      id: 'reports',
      name: 'Reports',
      path: '/reports',
      matchPrefixes: ['/reports'],
      icon: FileText,
      description: 'Forensic dossiers, executive summaries & export logs',
    },
    {
      id: 'detections',
      name: 'Detection Rules',
      path: '/detections',
      matchPrefixes: ['/detections', '/rules', '/pipeline', '/detection-pipeline'],
      icon: Binary,
      description: 'Detection engineering, versioned rule lifecycles & backtesting',
    },
  ];

  const isItemActive = (item: (typeof mainNavItems)[0]) => {
    const current = location.pathname;
    if (item.path === '/dashboard' && (current === '/' || current === '/dashboard')) {
      return true;
    }
    return item.matchPrefixes.some((prefix) => {
      if (prefix === '/') return false;
      return current === prefix || current.startsWith(prefix + '/');
    });
  };

  const isSettingsActive = location.pathname.startsWith('/settings');

  return (
    <>
      {/* Mobile Drawer Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/60 backdrop-blur-xs md:hidden animate-in fade-in duration-150"
          onClick={onCloseMobile}
          aria-label="Close navigation backdrop"
        />
      )}

      {/* Main Sidebar Shell */}
      <aside
        aria-label="Primary Navigation"
        className={cn(
          'fixed top-0 bottom-0 z-50 md:z-40 bg-surface border-r border-border transition-all duration-200 flex flex-col justify-between select-none',
          mobileOpen ? 'left-0 w-64 shadow-2xl' : '-left-64 md:left-0',
          isCollapsed ? 'md:w-18' : 'md:w-64'
        )}
      >
        <div className="flex-1 flex flex-col min-h-0">
          {/* 1. BRANDING (Section 6: Restrained CyberGuard Identity) */}
          <div className="h-16 px-4 flex items-center justify-between border-b border-border shrink-0">
            <NavLink
              to="/dashboard"
              className="flex items-center space-x-3 overflow-hidden group cursor-pointer"
              title="CyberGuard AI Threat Defense"
            >
              <div className="w-8 h-8 rounded-control bg-surface-secondary border border-border flex items-center justify-center text-primary shrink-0 group-hover:border-primary/50 transition-colors">
                <ShieldCheck className="w-4 h-4" />
              </div>

              {!isCollapsed && (
                <div className="flex flex-col min-w-0">
                  <span className="font-sans font-extrabold text-xs tracking-tight text-foreground uppercase truncate">
                    CyberGuard
                  </span>
                  <span className="text-[10px] font-mono text-foreground-muted tracking-wider uppercase truncate">
                    AI Threat Defense
                  </span>
                </div>
              )}
            </NavLink>

            <button
              type="button"
              onClick={toggleCollapse}
              className="p-1 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent hover:border-border transition-colors cursor-pointer hidden md:flex"
              title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
              aria-label={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
            >
              {isCollapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Section Divider / Label */}
          {!isCollapsed ? (
            <div className="px-4 pt-4 pb-1 text-[10px] font-mono font-semibold uppercase tracking-wider text-foreground-muted">
              Navigation
            </div>
          ) : (
            <div className="my-2 border-b border-border-subtle" />
          )}

          {/* 2. PRIMARY NAVIGATION LINKS (Section 1 & 5) */}
          <nav className="px-2 space-y-1">
            {mainNavItems.map((item) => {
              const Icon = item.icon;
              const active = isItemActive(item);

              const navLink = (
                <NavLink
                  key={item.id}
                  to={item.path}
                  onClick={() => onCloseMobile?.()}
                  className={cn(
                    'flex items-center rounded-control text-xs font-medium transition-colors group cursor-pointer',
                    isCollapsed ? 'justify-center p-2.5' : 'justify-between px-3 py-2.5',
                    active
                      ? 'bg-primary-subtle text-primary font-semibold border-l-2 border-primary pl-2.5'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border-l-2 border-transparent'
                  )}
                  aria-current={active ? 'page' : undefined}
                >
                  <div className="flex items-center space-x-3 min-w-0">
                    <Icon
                      className={cn(
                        'w-4 h-4 shrink-0 transition-colors',
                        active ? 'text-primary' : 'text-foreground-muted group-hover:text-foreground'
                      )}
                    />
                    {!isCollapsed && <span className="truncate">{item.name}</span>}
                  </div>
                </NavLink>
              );

              if (isCollapsed) {
                return (
                  <Tooltip key={item.id} content={item.name} placement="right">
                    {navLink}
                  </Tooltip>
                );
              }

              return navLink;
            })}
          </nav>
        </div>

        {/* 3. FOOTER: SETTINGS & REAL SYSTEM / AGENT STATUS (Section 29, 30, 36) */}
        <div className="p-3 border-t border-border bg-surface shrink-0 space-y-2">
          {/* Settings Nav Item */}
          {(() => {
            const settingsLink = (
              <NavLink
                to="/settings"
                onClick={() => onCloseMobile?.()}
                className={cn(
                  'flex items-center rounded-control text-xs font-medium transition-colors group cursor-pointer',
                  isCollapsed ? 'justify-center p-2.5' : 'justify-between px-3 py-2',
                  isSettingsActive
                    ? 'bg-primary-subtle text-primary font-semibold border-l-2 border-primary pl-2.5'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border-l-2 border-transparent'
                )}
                aria-current={isSettingsActive ? 'page' : undefined}
              >
                <div className="flex items-center space-x-3 min-w-0">
                  <Settings
                    className={cn(
                      'w-4 h-4 shrink-0 transition-colors',
                      isSettingsActive ? 'text-primary' : 'text-foreground-muted group-hover:text-foreground'
                    )}
                  />
                  {!isCollapsed && <span className="truncate">Settings</span>}
                </div>
              </NavLink>
            );

            if (isCollapsed) {
              return (
                <Tooltip content="System & Platform Settings" placement="right">
                  {settingsLink}
                </Tooltip>
              );
            }

            return settingsLink;
          })()}

          {/* Real Backend Status / Agent Presence Strip */}
          {!isCollapsed ? (
            <div className="p-2.5 rounded-control bg-surface-secondary/70 border border-border text-[11px] font-mono space-y-1">
              <div className="flex items-center justify-between text-foreground">
                <span className="flex items-center gap-1.5 text-foreground-muted">
                  <span
                    className={cn(
                      'w-1.5 h-1.5 rounded-full',
                      systemHealth === 'OK'
                        ? 'bg-threat-safe'
                        : systemHealth === 'DEGRADED'
                        ? 'bg-threat-high'
                        : 'bg-foreground-muted'
                    )}
                  />
                  <span>System:</span>
                </span>
                <span className="font-semibold text-[10px]">
                  {systemHealth === 'OK' ? 'OPERATIONAL' : systemHealth === 'DEGRADED' ? 'DEGRADED' : 'STANDBY'}
                </span>
              </div>

              {agentCount !== null && (
                <div className="flex items-center justify-between text-[10px] text-foreground-muted pt-1 border-t border-border-subtle">
                  <span>Enrolled Agents:</span>
                  <span className="font-semibold text-foreground">{agentCount} online</span>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center py-1">
              <Tooltip
                content={`System: ${systemHealth === 'OK' ? 'Operational' : 'Standby'}${
                  agentCount !== null ? ` | Agents: ${agentCount}` : ''
                }`}
                placement="right"
              >
                <span
                  className={cn(
                    'w-2 h-2 rounded-full cursor-help',
                    systemHealth === 'OK' ? 'bg-threat-safe' : 'bg-foreground-muted'
                  )}
                />
              </Tooltip>
            </div>
          )}
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
