import React, { useState, useRef, useEffect, useMemo } from 'react';
import {
  Bell,
  ShieldAlert,
  ShieldCheck,
  Palette,
  Check,
  Sparkles,
  RotateCcw,
  Menu,
} from 'lucide-react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useTheme, THEME_OPTIONS, type AppTheme } from '../../context/ThemeContext';
import { useDemoTour } from '../../context/DemoTourContext';
import { useInvestigation } from '../../context/InvestigationContext';
import { SearchInput } from '../ui';
import { Breadcrumbs } from './Breadcrumbs';
import { cn } from '../../utils/cn';

export interface TopbarProps {
  onToggleMobileSidebar?: () => void;
  className?: string;
}

export const Topbar: React.FC<TopbarProps> = ({ onToggleMobileSidebar, className }) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showThemeMenu, setShowThemeMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();
  const location = useLocation();

  const { theme, setTheme, themeMeta } = useTheme();
  const { isTourActive, startTour, endTour, isResetting } = useDemoTour();
  const { activeEmail, activeEmailId, resetToCleanWorkspace } = useInvestigation();
  const [isResettingWorkspace, setIsResettingWorkspace] = useState(false);

  const themeMenuRef = useRef<HTMLDivElement>(null);
  const notifRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (themeMenuRef.current && !themeMenuRef.current.contains(event.target as Node)) {
        setShowThemeMenu(false);
      }
      if (notifRef.current && !notifRef.current.contains(event.target as Node)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleReset = async () => {
    setIsResettingWorkspace(true);
    try {
      if (isTourActive) endTour();
      await resetToCleanWorkspace();
    } finally {
      setIsResettingWorkspace(false);
    }
  };

  // Derive alerts from current active email telemetry
  const alerts = useMemo(() => {
    if (!activeEmail) return [];
    const list = [];
    if (activeEmail.threat_score && activeEmail.threat_score.score >= 50) {
      list.push({
        id: 'ALT-SCORE',
        title: `Threat Score: ${activeEmail.threat_score.score}/100 (${activeEmail.threat_score.severity?.toUpperCase() || 'HIGH'})`,
        time: 'Active Investigation',
        level: activeEmail.threat_score.score >= 80 ? 'CRITICAL' : 'HIGH',
        sender: activeEmail.from || activeEmail.subject || 'Threat detected',
      });
    }
    const spfResult = activeEmail.authentication?.spf?.result?.toLowerCase();
    const dkimResult = activeEmail.authentication?.dkim?.result?.toLowerCase();
    const dmarcResult = activeEmail.authentication?.dmarc?.result?.toLowerCase();
    if (spfResult === 'fail' || dkimResult === 'fail' || dmarcResult === 'fail') {
      list.push({
        id: 'ALT-AUTH',
        title: 'Cryptographic Authentication Verification Failure',
        time: 'Envelope Parsed',
        level: 'CRITICAL',
        sender: `SPF: ${spfResult || 'none'}, DKIM: ${dkimResult || 'none'}, DMARC: ${dmarcResult || 'none'}`,
      });
    }
    const urls = activeEmail.indicators?.urls || [];
    if (urls.length > 0 && activeEmail.threat_score && activeEmail.threat_score.score >= 50) {
      list.push({
        id: 'ALT-URL',
        title: `${urls.length} URL Indicator(s) Extracted from Email`,
        time: 'Payload Analysis',
        level: 'HIGH',
        sender: urls[0]?.value || 'Observed URL',
      });
    }
    return list;
  }, [activeEmail]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/history?search=${encodeURIComponent(searchQuery)}`);
    }
  };

  // Derive heading hierarchy based on current route (Section 13)
  const pageHeading = useMemo(() => {
    const path = location.pathname;
    if (path === '/' || path === '/dashboard') {
      return { title: 'Dashboard', subtitle: 'Security overview and active investigations' };
    }
    if (path.startsWith('/investigations') || path.startsWith('/investigate')) {
      if (activeEmailId) {
        return {
          title: `Investigation: ${activeEmail?.subject || activeEmailId}`,
          subtitle: 'Forensic telemetry and response lifecycle',
        };
      }
      return { title: 'Investigations', subtitle: 'Review and triage detected threats' };
    }
    if (path.startsWith('/reports')) {
      return { title: 'Reports', subtitle: 'Forensic dossiers and executive summaries' };
    }
    if (path.startsWith('/settings')) {
      return { title: 'Settings', subtitle: 'Platform configuration and security safeguards' };
    }
    if (path === '/cases') {
      return { title: 'Incident Cases', subtitle: 'Correlated incident case records' };
    }
    if (path === '/history') {
      return { title: 'Ingestion History', subtitle: 'Historical evidentiary records' };
    }
    if (path === '/analyze') {
      return { title: 'Universal Ingestion', subtitle: 'Intake and parsing of telemetry payloads' };
    }
    return { title: 'CyberGuard Console', subtitle: 'SOC Operations' };
  }, [location.pathname, activeEmailId, activeEmail]);

  return (
    <header
      className={cn(
        'sticky top-0 z-30 bg-surface/90 backdrop-blur-md border-b border-border px-3 sm:px-6 h-16 flex items-center justify-between transition-colors select-none',
        className
      )}
    >
      {/* Left: Mobile Toggle, Breadcrumb / Title, and Search Box */}
      <div className="flex items-center space-x-2 sm:space-x-3 min-w-0">
        {onToggleMobileSidebar && (
          <button
            type="button"
            onClick={onToggleMobileSidebar}
            className="p-1.5 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-border md:hidden cursor-pointer shrink-0"
            aria-label="Toggle navigation menu"
            title="Toggle Navigation Menu"
          >
            <Menu className="w-4 h-4 text-foreground" />
          </button>
        )}

        <div className="hidden lg:flex flex-col min-w-0 mr-2">
          <div className="flex items-center space-x-2">
            <Breadcrumbs />
          </div>
          {pageHeading.subtitle && (
            <span className="text-[10px] font-mono text-foreground-muted truncate">
              {pageHeading.subtitle}
            </span>
          )}
        </div>

        {/* Global Search Input */}
        <form onSubmit={handleSearchSubmit} className="relative w-36 sm:w-60 md:w-72">
          <SearchInput
            value={searchQuery}
            onChangeValue={setSearchQuery}
            placeholder="Search indicator, sender, hash..."
            size="sm"
          />
        </form>

        {/* Active Investigation Context Tag */}
        {activeEmail && (
          <button
            type="button"
            onClick={() => navigate(`/investigations/${activeEmailId}/overview`)}
            className="hidden xl:flex items-center space-x-2 px-2.5 py-1 rounded-control bg-surface-secondary/80 hover:bg-surface-secondary border border-border text-xs font-mono transition-colors cursor-pointer"
            title="Jump to active investigation workspace"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse" />
            <span className="text-foreground-muted">Target:</span>
            <span className="text-foreground font-semibold truncate max-w-[140px]">
              {activeEmail.subject || activeEmailId}
            </span>
          </button>
        )}
      </div>

      {/* Right: Real Threat State, SIH Walkthrough, Reset, Theme Menu, Notifications */}
      <div className="flex items-center space-x-2 sm:space-x-2.5">
        {/* Threat Ticker */}
        {activeEmail && activeEmail.threat_score ? (
          <div
            className={cn(
              'hidden md:flex items-center space-x-1.5 px-2.5 py-1 rounded-badge text-xs font-mono select-none',
              activeEmail.threat_score.score >= 50
                ? 'bg-danger-surface border border-danger-border text-danger'
                : 'bg-surface-secondary border border-border text-foreground'
            )}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>
              THREAT: <strong>{activeEmail.threat_score.score}/100</strong>
            </span>
          </div>
        ) : null}

        {/* SIH Demo Tour Trigger */}
        <button
          type="button"
          onClick={() => (isTourActive ? endTour() : startTour('scenario-3-campaign', 1))}
          className={cn(
            'flex items-center space-x-1.5 px-2.5 sm:px-3 py-1.5 rounded-control text-xs font-mono font-bold transition-all cursor-pointer',
            isTourActive
              ? 'bg-primary text-primary-foreground shadow-xs'
              : 'bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30'
          )}
          title="Launch Guided 10-Step SIH Demo Walkthrough"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">{isTourActive ? 'Demo Active' : 'SIH Demo'}</span>
        </button>

        {/* Reset Clean Workspace */}
        <button
          type="button"
          onClick={handleReset}
          disabled={isResettingWorkspace || isResetting}
          className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control text-xs font-mono bg-surface border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors cursor-pointer disabled:opacity-50"
          title="Reset workspace and return to clean standby state"
        >
          <RotateCcw className={cn('w-3.5 h-3.5', isResettingWorkspace && 'animate-spin text-primary')} />
          <span className="hidden sm:inline">{isResettingWorkspace ? 'Resetting...' : 'Reset'}</span>
        </button>

        {/* Theme Selector */}
        <div className="relative" ref={themeMenuRef}>
          <button
            type="button"
            onClick={() => setShowThemeMenu(!showThemeMenu)}
            className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control bg-surface border border-border hover:bg-surface-secondary text-foreground text-xs font-medium transition-colors btn-press cursor-pointer"
            title="Switch Theme"
            aria-label="Switch Theme"
          >
            <Palette className="w-3.5 h-3.5 text-primary" />
            <span className="hidden md:inline font-mono capitalize">{themeMeta.name}</span>
          </button>

          {showThemeMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-surface-elevated border border-border rounded-card shadow-popover p-1.5 z-50 animate-in fade-in slide-in-from-top-1 duration-150">
              <div className="px-2.5 py-1.5 text-[11px] font-mono font-semibold uppercase text-foreground-subtle border-b border-border-subtle mb-1">
                Select Theme
              </div>
              <div className="space-y-0.5">
                {THEME_OPTIONS.map((opt) => {
                  const isCurrent = theme === opt.id;
                  return (
                    <button
                      key={opt.id}
                      type="button"
                      onClick={() => {
                        setTheme(opt.id as AppTheme);
                        setShowThemeMenu(false);
                      }}
                      className={cn(
                        'w-full flex items-center justify-between px-2.5 py-2 rounded-control text-xs transition-colors cursor-pointer',
                        isCurrent
                          ? 'bg-primary-subtle text-primary font-semibold'
                          : 'text-foreground hover:bg-surface-secondary'
                      )}
                    >
                      <div className="flex items-center space-x-2.5">
                        <span
                          className="w-3.5 h-3.5 rounded-full border border-border flex-shrink-0"
                          style={{ backgroundColor: opt.previewAccent }}
                        />
                        <div className="flex flex-col text-left">
                          <span className="font-medium leading-tight">{opt.name}</span>
                          <span className="text-[10px] text-foreground-muted font-mono leading-tight">
                            {opt.accentLabel}
                          </span>
                        </div>
                      </div>
                      {isCurrent && <Check className="w-3.5 h-3.5 text-primary" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Notifications */}
        <div className="relative" ref={notifRef}>
          <button
            type="button"
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground transition-colors btn-press cursor-pointer"
            aria-label="View security notifications"
          >
            <Bell className="w-4 h-4" />
            {alerts.length > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-threat-critical text-[9px] font-bold text-white flex items-center justify-center animate-pulse">
                {alerts.length}
              </span>
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 md:w-96 bg-surface-elevated border border-border rounded-card shadow-popover p-3.5 z-50 animate-in fade-in slide-in-from-top-1 duration-150">
              <div className="flex items-center justify-between mb-2.5 pb-2 border-b border-border">
                <div className="flex items-center space-x-1.5">
                  <ShieldAlert className="w-4 h-4 text-threat-critical" />
                  <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
                    Active Security Alerts
                  </h4>
                </div>
                <button
                  type="button"
                  onClick={() => setShowNotifications(false)}
                  className="text-xs text-foreground-muted hover:text-foreground cursor-pointer"
                >
                  Close
                </button>
              </div>

              {alerts.length === 0 ? (
                <div className="py-6 text-center text-xs font-mono text-foreground-muted space-y-1">
                  <ShieldCheck className="w-6 h-6 text-threat-safe mx-auto mb-1.5" />
                  <p className="font-semibold text-foreground">No Active Security Alerts</p>
                  <p className="text-[11px] text-foreground-muted">System standby. Telemetry streams within baselines.</p>
                </div>
              ) : (
                <div className="space-y-1.5 max-h-80 overflow-y-auto">
                  {alerts.map((alt) => (
                    <div
                      key={alt.id}
                      onClick={() => {
                        setShowNotifications(false);
                        if (activeEmailId) {
                          navigate(`/investigations/${activeEmailId}/overview`);
                        } else {
                          navigate('/investigations');
                        }
                      }}
                      className="p-2.5 rounded-control bg-surface-secondary/70 border border-border hover:border-primary/60 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-badge bg-threat-critical-surface text-threat-critical border border-threat-critical-border">
                          {alt.level}
                        </span>
                        <span className="text-[10px] text-foreground-muted font-mono">{alt.time}</span>
                      </div>
                      <div className="text-xs font-medium text-foreground">{alt.title}</div>
                      <div className="text-[11px] font-mono text-foreground-muted mt-0.5 truncate">
                        {alt.sender}
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <button
                type="button"
                onClick={() => {
                  setShowNotifications(false);
                  navigate('/investigations');
                }}
                className="w-full mt-2.5 py-1 text-center text-xs font-mono text-primary hover:text-primary-hover font-medium cursor-pointer"
              >
                View All Investigations &rarr;
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};

export default Topbar;
