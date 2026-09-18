import React, { useState } from 'react';
import {
  ChevronRight,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Info,
  ExternalLink
} from 'lucide-react';
import { DetailDrawer } from './DetailDrawer';

export interface StatusRowProps {
  title: string;
  status: 'PASS' | 'FAIL' | 'WARN' | 'NONE' | 'SOFTFAIL' | 'NEUTRAL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  statusLabel?: string;
  subtitle?: string;
  icon?: React.FC<{ className?: string }>;
  defaultExpanded?: boolean;
  isExpanded?: boolean;
  onToggle?: (expanded: boolean) => void;
  children?: React.ReactNode;
  rawEvidence?: any;
  rawEvidenceFormat?: 'json' | 'text' | 'headers';
  rawEvidenceTitle?: string;
  rawButtonLabel?: string;
  onViewRaw?: () => void;
  className?: string;
}

export const StatusRow: React.FC<StatusRowProps> = ({
  title,
  status,
  statusLabel,
  subtitle,
  icon: Icon,
  defaultExpanded = false,
  isExpanded: controlledExpanded,
  onToggle,
  children,
  rawEvidence,
  rawEvidenceFormat = 'json',
  rawEvidenceTitle,
  rawButtonLabel = 'View technical details',
  onViewRaw,
  className = ''
}) => {
  const [internalExpanded, setInternalExpanded] = useState(defaultExpanded);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const isExpanded = controlledExpanded !== undefined ? controlledExpanded : internalExpanded;

  const handleToggle = () => {
    const next = !isExpanded;
    if (controlledExpanded === undefined) {
      setInternalExpanded(next);
    }
    onToggle?.(next);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleToggle();
    }
  };

  const handleViewRaw = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (onViewRaw) {
      onViewRaw();
    } else if (rawEvidence !== undefined) {
      setDrawerOpen(true);
    }
  };

  const getStatusBadge = (st: string) => {
    const s = st.toUpperCase();
    switch (s) {
      case 'PASS':
      case 'LOW':
      case 'VERIFIED':
      case 'CLEAN':
        return {
          bg: 'bg-success-surface text-success border-success-border',
          icon: ShieldCheck,
          label: statusLabel || 'PASS'
        };
      case 'FAIL':
      case 'FAILED':
      case 'CRITICAL':
      case 'PERMERROR':
        return {
          bg: 'bg-danger-surface text-danger border-danger-border',
          icon: ShieldX,
          label: statusLabel || 'FAIL'
        };
      case 'WARN':
      case 'WARNING':
      case 'HIGH':
      case 'MEDIUM':
      case 'SOFTFAIL':
      case 'TEMPERROR':
        return {
          bg: 'bg-warning-surface text-warning border-warning-border',
          icon: ShieldAlert,
          label: statusLabel || 'WARN'
        };
      case 'NONE':
      case 'NEUTRAL':
      case 'INFO':
      default:
        return {
          bg: 'bg-surface-secondary text-foreground-muted border-border',
          icon: Info,
          label: statusLabel || s || 'NONE'
        };
    }
  };

  const badge = getStatusBadge(status);
  const StatusIcon = badge.icon;
  const hasLevel3 = Boolean(onViewRaw || rawEvidence !== undefined);

  return (
    <div className={`rounded-xl border border-border bg-surface transition-all duration-200 overflow-hidden shadow-2xs ${className}`}>
      {/* LEVEL 1: Result / State Only (Clickable Header) */}
      <button
        type="button"
        onClick={handleToggle}
        onKeyDown={handleKeyDown}
        aria-expanded={isExpanded}
        className="w-full flex items-center justify-between p-3.5 sm:p-4 text-left hover:bg-surface-secondary/50 focus:outline-none focus:ring-2 focus:ring-primary/40 transition-colors cursor-pointer"
      >
        <div className="flex items-center space-x-3 min-w-0 flex-1">
          {Icon ? (
            <div className="p-1.5 rounded-lg bg-surface-secondary text-primary shrink-0 border border-border">
              <Icon className="w-4 h-4" />
            </div>
          ) : (
            <div className={`p-1.5 rounded-lg border shrink-0 ${badge.bg}`}>
              <StatusIcon className="w-4 h-4" />
            </div>
          )}

          <div className="space-y-0.5 min-w-0 flex-1">
            <div className="flex items-center space-x-2">
              <span className="font-mono text-xs sm:text-sm font-bold text-foreground tracking-tight truncate">
                {title}
              </span>
            </div>
            {subtitle && (
              <p className="text-[11px] font-mono text-foreground-muted truncate">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        {/* Right: State Badge & Chevron Indicator */}
        <div className="flex items-center space-x-3 shrink-0 ml-3">
          <span
            className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold tracking-wider uppercase border flex items-center gap-1.5 ${badge.bg}`}
          >
            <span>{badge.label}</span>
          </span>

          <ChevronRight
            className={`w-4 h-4 text-foreground-muted transition-transform duration-200 ${
              isExpanded ? 'rotate-90 text-primary' : ''
            }`}
          />
        </div>
      </button>

      {/* LEVEL 2: Explanation (Visible When Expanded) */}
      {isExpanded && (
        <div className="border-t border-border bg-surface-secondary/25 p-4 space-y-3.5 accordion-expand">
          {/* Custom explanation content passed as children */}
          <div className="space-y-2 text-xs font-mono">
            {children}
          </div>

          {/* Level 3 Trigger Button */}
          {hasLevel3 && (
            <div className="pt-2 border-t border-border/60 flex justify-end">
              <button
                type="button"
                onClick={handleViewRaw}
                className="px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors cursor-pointer shadow-2xs hover:text-primary"
              >
                <span>{rawButtonLabel}</span>
                <ExternalLink className="w-3 h-3 text-primary" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* LEVEL 3 Drawer (if rawEvidence is passed and no custom onViewRaw) */}
      {rawEvidence !== undefined && (
        <DetailDrawer
          isOpen={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          title={rawEvidenceTitle || `${title} — Raw Technical Evidence`}
          subtitle={`Forensic examination for ${title}`}
          data={rawEvidence}
          format={rawEvidenceFormat}
        />
      )}
    </div>
  );
};
