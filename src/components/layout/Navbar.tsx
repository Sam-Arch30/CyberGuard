import React, { useState, useRef, useEffect } from 'react';
<<<<<<< Updated upstream
import { Search, Bell, ShieldAlert, Cpu, Palette, Check } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTheme, THEME_OPTIONS, type AppTheme } from '../../context/ThemeContext';
=======
import { Search, Bell, Palette, Check, Sparkles, RotateCcw, Plus, ExternalLink } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTheme, THEME_OPTIONS, type AppTheme } from '../../context/ThemeContext';
import { useDemoTour } from '../../context/DemoTourContext';
import { api } from '../../services/api';
>>>>>>> Stashed changes

export const Navbar: React.FC = () => {
  const [showNotifications, setShowNotifications] = useState(false);
  const [showThemeMenu, setShowThemeMenu] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [recentThreats, setRecentThreats] = useState<any[]>([]);
  const navigate = useNavigate();
  const { theme, setTheme, themeMeta } = useTheme();

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

  // Fetch real recent threats for the notifications dropdown
  useEffect(() => {
    api.dashboard.getSummary(7, 5)
      .then(data => {
        if (data && Array.isArray(data.recent_emails)) {
          const highThreats = data.recent_emails.filter((e: any) => e.threat_score >= 50);
          setRecentThreats(highThreats);
        }
      })
      .catch(() => {
        setRecentThreats([]);
      });
  }, []);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      navigate(`/history?search=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  return (
    <header className="sticky top-0 z-30 bg-surface/85 backdrop-blur-md border-b border-border px-6 h-16 flex items-center justify-between transition-colors">
      {/* Global Search Box */}
      <form onSubmit={handleSearchSubmit} className="relative w-72 md:w-96">
        <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search Subject, Sender, Hash, or Domain..."
          className="w-full pl-8 pr-3 py-1.5 bg-surface-secondary border border-border rounded-control text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary transition-all"
        />
      </form>

      {/* Right Navbar Utility Controls */}
      <div className="flex items-center space-x-2">
        {/* Quick Ingest Button */}
        <button
          type="button"
          onClick={() => navigate('/analyze')}
          className="hidden sm:flex items-center space-x-1.5 px-3 py-1.5 rounded-control bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-medium transition-colors btn-press cursor-pointer"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Ingest EML</span>
        </button>

        {/* Real Alerts Notification Menu */}
        <div className="relative" ref={notifRef}>
          <button
            type="button"
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-1.5 rounded-control text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-border transition-colors cursor-pointer"
            title="Recent Threat Alerts"
            aria-label="Recent Threat Alerts"
          >
            <Bell className="w-4 h-4" />
            {recentThreats.length > 0 && (
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-danger animate-pulse" />
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-surface-elevated border border-border rounded-card shadow-popover p-2 z-50 animate-in fade-in slide-in-from-top-1 duration-150">
              <div className="flex items-center justify-between px-2.5 py-1.5 border-b border-border mb-1">
                <span className="text-[11px] font-mono font-semibold uppercase text-foreground">
                  Detected Threats ({recentThreats.length})
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setShowNotifications(false);
                    navigate('/history');
                  }}
                  className="text-[10px] font-mono text-primary hover:underline flex items-center space-x-1"
                >
                  <span>View All</span>
                  <ExternalLink className="w-2.5 h-2.5" />
                </button>
              </div>

              <div className="max-h-64 overflow-y-auto space-y-1">
                {recentThreats.length > 0 ? (
                  recentThreats.map((t) => (
                    <button
                      key={t.id}
                      type="button"
                      onClick={() => {
                        setShowNotifications(false);
                        navigate(`/analysis/${t.id}`);
                      }}
                      className="w-full text-left p-2 rounded-control hover:bg-surface-secondary transition-colors cursor-pointer space-y-1 border border-transparent hover:border-border"
                    >
                      <div className="flex items-center justify-between">
                        <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                          t.threat_score >= 80
                            ? 'bg-danger-surface text-danger'
                            : 'bg-warning-surface text-warning'
                        }`}>
                          Score: {t.threat_score}
                        </span>
                        <span className="text-[10px] font-mono text-foreground-muted">
                          {t.timestamp ? new Date(t.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}
                        </span>
                      </div>
                      <p className="text-xs text-foreground font-medium truncate">{t.subject || 'Untitled'}</p>
                      <p className="text-[10px] font-mono text-foreground-muted truncate">{t.sender || 'Unknown Sender'}</p>
                    </button>
                  ))
                ) : (
                  <div className="py-6 text-center text-xs font-mono text-foreground-muted">
                    No critical threats currently in queue
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

<<<<<<< Updated upstream
=======
        {/* SIH Demo Tour Trigger */}
        <button
          type="button"
          onClick={() => (isTourActive ? endTour() : startTour('scenario-3-campaign', 1))}
          className={`flex items-center space-x-1.5 px-2.5 py-1.5 rounded-control text-xs font-mono font-medium transition-all cursor-pointer ${
            isTourActive
              ? 'bg-primary text-primary-foreground shadow-xs'
              : 'bg-surface hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border'
          }`}
          title="Guided SIH Demo Walkthrough"
        >
          <Sparkles className="w-3.5 h-3.5 text-primary" />
          <span className="hidden md:inline">{isTourActive ? 'Tour Active' : 'SIH Demo'}</span>
        </button>

        {/* Reset Demo Button */}
        <button
          type="button"
          onClick={resetDemo}
          disabled={isResetting}
          className="hidden md:flex items-center space-x-1 px-2.5 py-1.5 rounded-control text-xs font-mono bg-surface border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors cursor-pointer disabled:opacity-50"
          title="Reset Synthetic Tour State"
        >
          <RotateCcw className={`w-3 h-3 ${isResetting ? 'animate-spin text-primary' : ''}`} />
          <span>Reset</span>
        </button>

>>>>>>> Stashed changes
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
            <span className="hidden lg:inline font-mono capitalize">{themeMeta.name}</span>
          </button>

          {showThemeMenu && (
            <div className="absolute right-0 mt-2 w-56 bg-surface-elevated border border-border rounded-card shadow-popover p-1.5 z-50 animate-in fade-in slide-in-from-top-1 duration-150">
              <div className="px-2.5 py-1.5 text-[10px] font-mono font-semibold uppercase text-foreground-subtle border-b border-border-subtle mb-1">
                Select Visual Palette
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
                      <div className="flex items-center space-x-2">
                        <span
                          className="w-2.5 h-2.5 rounded-full border border-border"
                          style={{ backgroundColor: opt.previewAccent }}
                        />
                        <span>{opt.name}</span>
                      </div>
                      {isCurrent && <Check className="w-3.5 h-3.5 text-primary" />}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
