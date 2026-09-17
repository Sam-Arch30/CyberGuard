import React, { useState, useRef, useEffect } from 'react';
import { Search, Bell, ShieldAlert, Cpu, Palette, Check, Sparkles, RotateCcw } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTheme, THEME_OPTIONS, type AppTheme } from '../../context/ThemeContext';
import { useDemoTour } from '../../context/DemoTourContext';

export const Navbar: React.FC = () => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showThemeMenu, setShowThemeMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const navigate = useNavigate();
  const { theme, setTheme, themeMeta } = useTheme();
  const { isTourActive, startTour, endTour, resetDemo, isResetting } = useDemoTour();

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

  const mockAlerts = [
    {
      id: 'ALT-1',
      title: 'High Risk BEC Wire Transfer Email Flagged',
      time: '2 mins ago',
      level: 'CRITICAL',
      sender: 'robert.vance@bank-corp-update.com'
    },
    {
      id: 'ALT-2',
      title: 'Microsoft 365 Impersonation Link Detected',
      time: '18 mins ago',
      level: 'HIGH',
      sender: 'no-reply@m365-security-portal-verify.net'
    },
    {
      id: 'ALT-3',
      title: 'Payroll Direct Deposit Change Attempt',
      time: '45 mins ago',
      level: 'HIGH',
      sender: 'payroll-servicedesk@bankcorp-hr-portal.com'
    }
  ];

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/analyze?search=${encodeURIComponent(searchQuery)}`);
    }
  };

  return (
    <header className="sticky top-0 z-30 bg-surface/85 backdrop-blur-md border-b border-border px-6 h-16 flex items-center justify-between transition-colors">
      {/* Global Search Box */}
      <form onSubmit={handleSearchSubmit} className="relative w-72 md:w-96">
        <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search IP, Domain, Message-ID or Hash..."
          className="w-full pl-9 pr-3.5 py-1.5 bg-surface-secondary border border-border rounded-control text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
        />
      </form>

      {/* Right Navbar Utility Controls */}
      <div className="flex items-center space-x-2.5">
        {/* Real-time Threat Ticker Banner */}
        <div className="hidden lg:flex items-center space-x-1.5 px-2.5 py-1 rounded-badge bg-danger-surface border border-danger-border text-danger text-xs font-mono">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>THREAT: <strong className="font-semibold">DEFCON 2</strong></span>
        </div>

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

        {/* Reset Demo Button */}
        <button
          type="button"
          onClick={resetDemo}
          disabled={isResetting}
          className="hidden md:flex items-center space-x-1 px-2.5 py-1.5 rounded-control text-xs font-mono bg-surface border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors cursor-pointer disabled:opacity-50"
          title="Restore synthetic demo state to baseline without affecting production"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-primary' : ''}`} />
          <span>{isResetting ? 'Resetting...' : 'Reset'}</span>
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
            <span className="absolute -top-0.5 -right-0.5 w-3.5 h-3.5 rounded-full bg-danger text-[9px] font-bold text-white flex items-center justify-center">
              3
            </span>
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

              <div className="space-y-1.5">
                {mockAlerts.map((alt) => (
                  <div
                    key={alt.id}
                    onClick={() => {
                      setShowNotifications(false);
                      navigate('/analyze');
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

              <button
                type="button"
                onClick={() => {
                  setShowNotifications(false);
                  navigate('/cases');
                }}
                className="w-full mt-2.5 py-1 text-center text-xs font-mono text-primary hover:text-primary-hover font-medium cursor-pointer"
              >
                View All Active Incidents &rarr;
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
