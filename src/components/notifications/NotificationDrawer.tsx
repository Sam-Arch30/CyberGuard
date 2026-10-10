import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Bell,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Clock,
  ExternalLink,
  X,
  Check,
  Filter,
  AlertTriangle,
  Info,
  RefreshCw,
  ChevronRight,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { cn } from '../../utils/cn';
import { NotificationClientService } from '../../services/notificationService';
import type {
  NotificationItem,
  NotificationCategory,
  NotificationStatus,
  NotificationSeverity,
} from '../../types/notification';

interface NotificationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  onUnreadChange?: () => void;
}

export const NotificationDrawer: React.FC<NotificationDrawerProps> = ({
  isOpen,
  onClose,
  onUnreadChange,
}) => {
  const navigate = useNavigate();
  const drawerRef = useRef<HTMLDivElement>(null);

  // Filter states
  const [activeTab, setActiveTab] = useState<'ALL' | 'UNREAD' | 'ALERTS' | 'SYSTEM'>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');

  // Data states
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [unreadTotal, setUnreadTotal] = useState<number>(0);
  const [unreadAlerts, setUnreadAlerts] = useState<number>(0);
  const [unreadNotifs, setUnreadNotifs] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(false);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  // Load notifications from backend
  const loadNotifications = useCallback(async () => {
    setLoading(true);
    try {
      let categoryFilter: NotificationCategory | undefined = undefined;
      let statusFilter: NotificationStatus | undefined = undefined;

      if (activeTab === 'UNREAD') {
        statusFilter = 'UNREAD';
      } else if (activeTab === 'ALERTS') {
        categoryFilter = 'SECURITY_ALERT';
      } else if (activeTab === 'SYSTEM') {
        categoryFilter = 'NOTIFICATION';
      }

      const res = await NotificationClientService.getNotifications({
        category: categoryFilter,
        status: statusFilter,
        severity: selectedSeverity !== 'ALL' ? (selectedSeverity as NotificationSeverity) : undefined,
        limit: 50,
        offset: 0,
      });

      setItems(res.items);
      setTotal(res.total);
      setUnreadTotal(res.unread_total);
      setUnreadAlerts(res.unread_alerts);
      setUnreadNotifs(res.unread_notifications);
    } catch (err) {
      console.error('Failed to fetch notifications:', err);
    } finally {
      setLoading(false);
    }
  }, [activeTab, selectedSeverity]);

  // Load when open or filter changes
  useEffect(() => {
    if (isOpen) {
      loadNotifications();
    }
  }, [isOpen, loadNotifications]);

  // Keyboard navigation: Escape key closes the drawer
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Mark single as read
  const handleMarkAsRead = async (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setActionInProgress(id);
    try {
      await NotificationClientService.markAsRead(id);
      setItems((prev) =>
        prev.map((item) => (item.id === id ? { ...item, status: 'READ', read_at: new Date().toISOString() } : item))
      );
      setUnreadTotal((prev) => Math.max(0, prev - 1));
      if (onUnreadChange) onUnreadChange();
    } catch (err) {
      console.error('Failed to mark read:', err);
    } finally {
      setActionInProgress(null);
    }
  };

  // Mark all as read
  const handleMarkAllRead = async () => {
    setActionInProgress('ALL');
    try {
      const cat = activeTab === 'ALERTS' ? 'SECURITY_ALERT' : activeTab === 'SYSTEM' ? 'NOTIFICATION' : undefined;
      await NotificationClientService.markAllAsRead(cat);
      await loadNotifications();
      if (onUnreadChange) onUnreadChange();
    } catch (err) {
      console.error('Failed to mark all read:', err);
    } finally {
      setActionInProgress(null);
    }
  };

  // Acknowledge alert
  const handleAcknowledge = async (id: string, e?: React.MouseEvent) => {
    if (e) e.stopPropagation();
    setActionInProgress(id);
    try {
      const updated = await NotificationClientService.acknowledgeAlert(
        id,
        'SOC Analyst',
        'Analyst triaged and acknowledged threat.'
      );
      setItems((prev) => prev.map((item) => (item.id === id ? updated : item)));
      if (onUnreadChange) onUnreadChange();
    } catch (err) {
      console.error('Failed to acknowledge alert:', err);
    } finally {
      setActionInProgress(null);
    }
  };

  // Deep navigation
  const handleItemClick = (item: NotificationItem) => {
    if (item.status === 'UNREAD') {
      handleMarkAsRead(item.id);
    }
    if (item.navigation_target) {
      navigate(item.navigation_target);
      onClose();
    } else if (item.investigation_id) {
      navigate(`/investigations/${item.investigation_id}`);
      onClose();
    }
  };

  // Relative time helper
  const formatTimeAgo = (isoString: string) => {
    try {
      const diffSec = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
      if (diffSec < 60) return `${Math.max(1, diffSec)}s ago`;
      const diffMin = Math.floor(diffSec / 60);
      if (diffMin < 60) return `${diffMin}m ago`;
      const diffHours = Math.floor(diffMin / 60);
      if (diffHours < 24) return `${diffHours}h ago`;
      return `${Math.floor(diffHours / 24)}d ago`;
    } catch {
      return 'recently';
    }
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 overflow-hidden bg-black/40 backdrop-blur-xs transition-opacity animate-in fade-in duration-200"
      onClick={onClose}
    >
      <div className="fixed inset-y-0 right-0 max-w-full flex pl-10">
        <div
          ref={drawerRef}
          role="dialog"
          aria-label="Notifications and Security Alert Center"
          aria-modal="true"
          onClick={(e) => e.stopPropagation()}
          className="w-screen max-w-md bg-surface-elevated border-l border-border shadow-2xl flex flex-col transition-all duration-300 animate-in slide-in-from-right"
        >
          {/* Header */}
          <div className="px-5 py-4 border-b border-border flex items-center justify-between bg-surface/50">
            <div className="flex items-center space-x-2.5">
              <div className="p-1.5 rounded-md bg-primary/10 border border-primary/20 text-primary">
                <Bell className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <h3 className="text-sm font-mono font-bold text-foreground">
                    Notifications & Alert Center
                  </h3>
                  {unreadTotal > 0 && (
                    <span className="px-1.5 py-0.2 rounded-full text-[10px] font-mono font-bold bg-threat-critical/15 text-threat-critical border border-threat-critical/30">
                      {unreadTotal}
                    </span>
                  )}
                </div>
                <p className="text-[11px] font-mono text-foreground-muted">
                  Section 47: Authoritative Security Alerts & System Telemetry
                </p>
              </div>
            </div>

            <div className="flex items-center space-x-1">
              <button
                type="button"
                onClick={loadNotifications}
                disabled={loading}
                className="p-1.5 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer transition-colors"
                title="Refresh Notifications"
              >
                <RefreshCw className={cn('w-3.5 h-3.5', loading && 'animate-spin')} />
              </button>
              <button
                type="button"
                onClick={onClose}
                className="p-1.5 rounded-md text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer transition-colors"
                title="Close Drawer (Esc)"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          </div>

          {/* Action & Filter Toolbar */}
          <div className="px-4 py-2.5 border-b border-border bg-surface/30 space-y-2">
            {/* Category Tabs */}
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-1">
                <button
                  type="button"
                  onClick={() => setActiveTab('ALL')}
                  className={cn(
                    'px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer',
                    activeTab === 'ALL'
                      ? 'bg-primary text-primary-foreground'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
                  )}
                >
                  All ({total})
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('UNREAD')}
                  className={cn(
                    'px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer flex items-center space-x-1.5',
                    activeTab === 'UNREAD'
                      ? 'bg-primary text-primary-foreground'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
                  )}
                >
                  <span>Unread</span>
                  {unreadTotal > 0 && (
                    <span className="w-1.5 h-1.5 rounded-full bg-threat-critical animate-pulse" />
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('ALERTS')}
                  className={cn(
                    'px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer flex items-center space-x-1',
                    activeTab === 'ALERTS'
                      ? 'bg-threat-critical text-white'
                      : 'text-threat-critical hover:bg-threat-critical/10'
                  )}
                >
                  <ShieldAlert className="w-3 h-3" />
                  <span>Alerts</span>
                  {unreadAlerts > 0 && (
                    <span className="text-[10px] ml-0.5">({unreadAlerts})</span>
                  )}
                </button>
                <button
                  type="button"
                  onClick={() => setActiveTab('SYSTEM')}
                  className={cn(
                    'px-2.5 py-1 rounded text-xs font-mono font-semibold transition-colors cursor-pointer',
                    activeTab === 'SYSTEM'
                      ? 'bg-primary text-primary-foreground'
                      : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
                  )}
                >
                  System ({unreadNotifs})
                </button>
              </div>

              {unreadTotal > 0 && (
                <button
                  type="button"
                  onClick={handleMarkAllRead}
                  disabled={actionInProgress === 'ALL'}
                  className="text-[11px] font-mono text-primary hover:underline flex items-center space-x-1 cursor-pointer"
                >
                  <Check className="w-3 h-3" />
                  <span>Mark all read</span>
                </button>
              )}
            </div>

            {/* Severity Pill Selector */}
            <div className="flex items-center space-x-1 pt-1 overflow-x-auto text-[10px] font-mono">
              <span className="text-foreground-muted mr-1">Severity:</span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'INFO'].map((sev) => (
                <button
                  key={sev}
                  type="button"
                  onClick={() => setSelectedSeverity(sev)}
                  className={cn(
                    'px-2 py-0.5 rounded border transition-colors cursor-pointer',
                    selectedSeverity === sev
                      ? 'bg-surface-secondary border-primary text-foreground font-bold'
                      : 'border-border/60 text-foreground-muted hover:text-foreground hover:border-border'
                  )}
                >
                  {sev}
                </button>
              ))}
            </div>
          </div>

          {/* Notification List */}
          <div className="flex-1 overflow-y-auto divide-y divide-border p-2 space-y-1">
            {loading && items.length === 0 ? (
              <div className="py-16 text-center space-y-2">
                <RefreshCw className="w-6 h-6 text-primary animate-spin mx-auto" />
                <p className="text-xs font-mono text-foreground-muted">Loading notifications...</p>
              </div>
            ) : items.length === 0 ? (
              <div className="py-16 text-center space-y-2 px-6">
                <ShieldCheck className="w-10 h-10 text-threat-safe mx-auto opacity-70" />
                <h4 className="text-xs font-mono font-bold text-foreground">No Notifications Found</h4>
                <p className="text-[11px] font-mono text-foreground-muted leading-relaxed">
                  {activeTab === 'UNREAD'
                    ? 'All security alerts and operational notifications have been acknowledged or read.'
                    : 'System telemetry nominal. No notifications match current filters.'}
                </p>
              </div>
            ) : (
              items.map((item) => {
                const isAlert = item.category === 'SECURITY_ALERT';
                const isUnread = item.status === 'UNREAD';
                const isAcked = item.status === 'ACKNOWLEDGED';

                return (
                  <div
                    key={item.id}
                    onClick={() => handleItemClick(item)}
                    className={cn(
                      'p-3.5 rounded-lg border transition-all cursor-pointer group hover:bg-surface-secondary/70 relative',
                      isUnread
                        ? isAlert
                          ? 'bg-threat-critical/5 border-threat-critical/30 shadow-xs'
                          : 'bg-primary/5 border-primary/25 shadow-xs'
                        : 'bg-surface border-border/70 opacity-90'
                    )}
                  >
                    {/* Top Row: Category, Severity, Time, Status */}
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center space-x-1.5">
                        {isAlert ? (
                          <span
                            className={cn(
                              'px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase tracking-wider border flex items-center space-x-1',
                              item.severity === 'CRITICAL'
                                ? 'bg-threat-critical text-white border-threat-critical'
                                : 'bg-threat-high/20 text-threat-high border-threat-high/40'
                            )}
                          >
                            <ShieldAlert className="w-2.5 h-2.5" />
                            <span>{item.severity}</span>
                          </span>
                        ) : (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold uppercase bg-surface-secondary text-foreground-muted border border-border flex items-center space-x-1">
                            <Info className="w-2.5 h-2.5" />
                            <span>{item.severity}</span>
                          </span>
                        )}

                        <span className="text-[10px] font-mono text-foreground-subtle uppercase">
                          {isAlert ? 'Security Alert' : 'System'}
                        </span>
                      </div>

                      <div className="flex items-center space-x-1.5 text-[11px] font-mono text-foreground-muted">
                        <Clock className="w-3 h-3" />
                        <span>{formatTimeAgo(item.created_at)}</span>
                        {isUnread && (
                          <span className="w-2 h-2 rounded-full bg-threat-critical ml-1 animate-pulse" />
                        )}
                      </div>
                    </div>

                    {/* Title */}
                    <h4
                      className={cn(
                        'text-xs font-mono font-bold leading-snug',
                        isAlert ? 'text-threat-critical' : 'text-foreground'
                      )}
                    >
                      {item.title}
                    </h4>

                    {/* Message (Sanitized, normal escaped string) */}
                    <p className="text-[11px] font-mono text-foreground-muted mt-1 leading-relaxed line-clamp-2">
                      {item.message}
                    </p>

                    {/* Provenance & Actions Bar */}
                    <div className="mt-2.5 pt-2 border-t border-border/50 flex items-center justify-between text-[11px] font-mono">
                      <div className="flex items-center space-x-1 text-foreground-subtle truncate max-w-[200px]">
                        {item.investigation_id ? (
                          <span className="truncate">INV: {item.investigation_id}</span>
                        ) : item.source_type ? (
                          <span className="truncate">Source: {item.source_type}</span>
                        ) : null}
                      </div>

                      <div className="flex items-center space-x-2">
                        {isAlert && !isAcked && (
                          <button
                            type="button"
                            onClick={(e) => handleAcknowledge(item.id, e)}
                            disabled={actionInProgress === item.id}
                            className="px-2 py-0.5 rounded bg-threat-critical/10 hover:bg-threat-critical/20 text-threat-critical border border-threat-critical/30 text-[10px] font-bold cursor-pointer transition-colors"
                            title="Acknowledge this security alert as a SOC analyst"
                          >
                            Acknowledge
                          </button>
                        )}

                        {isAcked && (
                          <span className="text-[10px] text-threat-safe font-semibold flex items-center space-x-1">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Ack'd</span>
                          </span>
                        )}

                        {isUnread && (
                          <button
                            type="button"
                            onClick={(e) => handleMarkAsRead(item.id, e)}
                            disabled={actionInProgress === item.id}
                            className="p-1 rounded text-foreground-muted hover:text-foreground hover:bg-surface-secondary cursor-pointer transition-colors"
                            title="Mark as Read"
                          >
                            <Check className="w-3.5 h-3.5" />
                          </button>
                        )}

                        <span className="text-primary hover:underline flex items-center space-x-0.5 text-[10px] font-bold">
                          <span>Open</span>
                          <ChevronRight className="w-3 h-3" />
                        </span>
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="px-5 py-3 border-t border-border bg-surface/60 flex items-center justify-between text-[11px] font-mono text-foreground-muted">
            <span>Real-time transport: Section 46 SSE</span>
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1 rounded bg-surface hover:bg-surface-secondary border border-border text-foreground cursor-pointer"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
