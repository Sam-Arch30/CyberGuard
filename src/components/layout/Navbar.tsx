import React, { useState, useRef, useEffect, useMemo } from 'react';
import { Search, Bell, ShieldAlert, ShieldCheck, Cpu, Palette, Check, Sparkles, RotateCcw, Menu } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTheme, THEME_OPTIONS, type AppTheme } from '../../context/ThemeContext';
import { useDemoTour } from '../../context/DemoTourContext';
import { useInvestigation } from '../../context/InvestigationContext';

export interface NavbarProps {
  onToggleMobileSidebar?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ onToggleMobileSidebar }) => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showThemeMenu, setShowThemeMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();
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
      if (isTourActive) {
        endTour();
      }
      await resetToCleanWorkspace();
    } finally {
      setIsResettingWorkspace(false);
    }
  };

  const alerts = useMemo(() => {
    if (!activeEmail) return [];
    const list = [];
    if (activeEmail.threat_score && activeEmail.threat_score.score >= 50) {
      list.push({
        id: 'ALT-SCORE',
        title: `Threat Score: ${activeEmail.threat_score.score}/100 (${activeEmail.threat_score.severity?.toUpperCase() || 'HIGH'})`,
        time: 'Active Investigation',
        level: activeEmail.threat_score.score >= 80 ? 'CRITICAL' : 'HIGH',
        sender: activeEmail.from || activeEmail.subject || 'Threat detected'
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
        sender: `SPF: ${spfResult || 'none'}, DKIM: ${dkimResult || 'none'}, DMARC: ${dmarcResult || 'none'}`
      });
    }
    const urls = activeEmail.indicators?.urls || [];
    if (urls.length > 0 && activeEmail.threat_score && activeEmail.threat_score.score >= 50) {
      list.push({
        id: 'ALT-URL',
        title: `${urls.length} URL Indicator(s) Extracted from Email`,
        time: 'Payload Analysis',
        level: 'HIGH',
        sender: urls[0]?.value || 'Observed URL'
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

  return (
    <header className="sticky top-0 z-30 bg-surface/85 backdrop-blur-md border-b border-border px-3 sm:px-6 h-16 flex items-center justify-between transition-colors">
      {/* Left: Hamburger (mobile), Global Search Box & Active Investigation Chip */}
      <div className="flex items-center space-x-2 sm:space-x-3 min-w-0">
        {onToggleMobileSidebar && (
          <button
            type="button"
            onClick={onToggleMobileSidebar}
            className="p-1.5 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-border md:hidden cursor-pointer shrink-0"
            aria-label="Toggle navigation menu"
            title="Toggle Navigation Sidebar"
          >
            <Menu className="w-4 h-4 text-foreground" />
          </button>
        )}

        <form onSubmit={handleSearchSubmit} className="relative w-36 sm:w-64 md:w-80">
          <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Subject, Sender, or Hash..."
            className="w-full pl-9 pr-3.5 py-1.5 bg-surface-secondary border border-border rounded-control text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
          />
        </form>

        {activeEmail && (
          <button
            type="button"
            onClick={() => navigate(`/investigate/${activeEmailId}/overview`)}
            className="hidden xl:flex items-center space-x-2 px-2.5 py-1 rounded-control bg-surface-secondary/80 hover:bg-surface-secondary border border-border text-xs font-mono transition-colors cursor-pointer"
            title="Jump to current active investigation"
          >
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
            <span className="text-foreground-muted">Target:</span>
            <span className="text-foreground font-semibold truncate max-w-[150px]">
              {activeEmail.subject || activeEmailId}
            </span>
          </button>
        )}
      </div>

      {/* Right Navbar Utility Controls */}
      <div className="flex items-center space-x-2.5">
        {/* Real-time Threat Ticker Banner */}
        {activeEmail ? (
          (() => {
            const score = activeEmail.threat_score?.score ?? 0;
            const defconLevel = score >= 80 ? 'DEFCON 1' : score >= 50 ? 'DEFCON 2' : score >= 20 ? 'DEFCON 3' : 'DEFCON 5';
            const isDanger = score >= 50;
            return (
              <div className={`hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-badge text-xs font-mono ${
                isDanger
                  ? 'bg-danger-surface border border-danger-border text-danger'
                  : 'bg-surface-secondary border border-border text-foreground'
              }`}>
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>THREAT: <strong className="font-semibold">{defconLevel}</strong></span>
              </div>
            );
          })()
        ) : (
          <div className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-badge bg-surface-secondary/80 border border-border text-foreground-muted text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span>SYSTEM: <strong className="font-semibold text-foreground">STANDBY</strong></span>
          </div>
        )}

        {/* AI Engine Status */}
        <div className="hidden sm:flex items-center space-x-1.5 px-2.5 py-1 rounded-badge bg-surface-secondary border border-border text-xs font-mono text-foreground-muted">
          <Cpu className="w-3.5 h-3.5 text-primary" />
          <span>AI Engine: <strong className="text-foreground">NLP v4.2</strong></span>
        </div>

        {/* SIH Demo Tour Trigger */}
        <button
          type="button"
          onClick={() => (isTourActive ? endTour() : startTour('scenario-3-campaign', 1))}
          className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-control text-xs font-mono font-bold transition-all cursor-pointer ${
            isTourActive
              ? 'bg-primary text-primary-foreground shadow-sm shadow-primary/30'
              : 'bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30'
          }`}
          title="Launch Guided 10-Step SIH Demo Walkthrough"
        >
          <Sparkles className="w-3.5 h-3.5" />
          <span className="hidden sm:inline">{isTourActive ? 'Demo Active' : 'SIH Demo'}</span>
        </button>

        {/* Reset Clean Workspace Button */}
        <button
          type="button"
          onClick={handleReset}
          disabled={isResettingWorkspace || isResetting}
          className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control text-xs font-mono bg-surface border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors cursor-pointer disabled:opacity-50"
          title="Reset workspace and purge all email data to return to clean state"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isResettingWorkspace ? 'animate-spin text-primary' : ''}`} />
          <span>{isResettingWorkspace ? 'Resetting...' : 'Reset'}</span>
        </button>

        {/* Theme Selector Dropdown */}
        <div className="relative" ref={themeMenuRef}>
          <button
            type="button"
            onClick={() => setShowThemeMenu(!showThemeMenu)}
            className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control bg-surface border border-border hover:bg-surface-secondary text-foreground text-xs font-medium transition-colors btn-press cursor-pointer"
            title="Switch Visual Theme"
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
                      className={`w-full flex items-center justify-between px-2.5 py-2 rounded-control text-xs transition-colors cursor-pointer ${
                        isCurrent
                          ? 'bg-primary-subtle text-primary font-semibold'
                          : 'text-foreground hover:bg-surface-secondary'
                      }`}
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

        {/* Notifications Dropdown Toggle */}
        <div className="relative" ref={notifRef}>
          <button
            type="button"
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-control bg-surface hover:bg-surface-secondary border border-border text-foreground-muted hover:text-foreground transition-colors btn-press cursor-pointer"
            aria-label="View notifications"
          >
            <Bell className="w-4 h-4" />
            {alerts.length > 0 && (
              <span className="absolute -top-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-danger text-[9px] font-bold text-white flex items-center justify-center animate-pulse">
                {alerts.length}
              </span>
            )}
          </button>

          {/* Notifications Modal Popup */}
          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 md:w-96 bg-surface-elevated border border-border rounded-card shadow-popover p-3.5 z-50 animate-in fade-in slide-in-from-top-1 duration-150">
              <div className="flex items-center justify-between mb-2.5 pb-2 border-b border-border">
                <div className="flex items-center space-x-1.5">
                  <ShieldAlert className="w-4 h-4 text-danger" />
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
                  <ShieldCheck className="w-6 h-6 text-success mx-auto mb-1.5" />
                  <p className="font-semibold text-foreground">No Active Security Alerts</p>
                  <p className="text-[11px] text-foreground-muted">System standby. Ingest an .eml file to initiate forensic analysis.</p>
                </div>
              ) : (
                <div className="space-y-1.5">
                  {alerts.map((alt) => (
                    <div
                      key={alt.id}
                      onClick={() => {
                        setShowNotifications(false);
                        if (activeEmailId) {
                          navigate(`/investigate/${activeEmailId}/overview`);
                        } else {
                          navigate('/analyze');
                        }
                      }}
                      className="p-2.5 rounded-control bg-surface-secondary/70 border border-border hover:border-primary/60 cursor-pointer transition-colors"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded-badge bg-danger-surface text-danger border border-danger-border">
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
                  navigate('/cases');
                }}
                className="w-full mt-2.5 py-1 text-center text-xs font-mono text-primary hover:text-primary-hover font-medium cursor-pointer"
              >
                View Incident Cases &rarr;
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
