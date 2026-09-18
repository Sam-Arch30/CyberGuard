import React, { useState } from 'react';
import {
  ChevronRight,
  AlertTriangle,
  ShieldAlert,
  Info,
  ExternalLink,
  ArrowRight
} from 'lucide-react';
import { DetailDrawer } from './DetailDrawer';

export interface FindingRowProps {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | string;
  title: string;
  subtitle?: string;
  defaultExpanded?: boolean;
  isExpanded?: boolean;
  onToggle?: (expanded: boolean) => void;
  children?: React.ReactNode;
  rawEvidence?: any;
  rawEvidenceFormat?: 'json' | 'text' | 'headers';
  rawEvidenceTitle?: string;
  rawButtonLabel?: string;
  onViewRaw?: () => void;
  actionLabel?: string;
  onAction?: () => void;
  className?: string;
}

export const FindingRow: React.FC<FindingRowProps> = ({
  severity,
  title,
  subtitle,
  defaultExpanded = false,
  isExpanded: controlledExpanded,
  onToggle,
  children,
  rawEvidence,
  rawEvidenceFormat = 'json',
  rawEvidenceTitle,
  rawButtonLabel = 'View technical details',
  onViewRaw,
  actionLabel,
  onAction,
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

  const getSeverityBadge = (sev: string) => {
    const s = sev.toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return {
          bg: 'bg-danger-surface text-danger border-danger-border',
          icon: ShieldAlert,
          label: 'CRITICAL'
        };
      case 'HIGH':
        return {
          bg: 'bg-warning-surface text-warning border-warning-border',
          icon: AlertTriangle,
          label: 'HIGH'
        };
      case 'MEDIUM':
        return {
          bg: 'bg-amber-500/15 text-amber-600 dark:text-amber-400 border-amber-500/30',
          icon: AlertTriangle,
          label: 'MEDIUM'
        };
      case 'LOW':
        return {
          bg: 'bg-success-surface text-success border-success-border',
          icon: Info,
          label: 'LOW'
        };
      case 'INFO':
      default:
        return {
          bg: 'bg-surface-secondary text-foreground-muted border-border',
          icon: Info,
          label: s || 'INFO'
        };
    }
  };

  const badge = getSeverityBadge(severity);
  const SevIcon = badge.icon;
  const hasLevel3 = Boolean(onViewRaw || rawEvidence !== undefined);

  return (
    <div className={`rounded-xl border border-border bg-surface transition-all duration-200 overflow-hidden shadow-2xs ${className}`}>
      {/* LEVEL 1: Result / State Only */}
      <button
        type="button"
        onClick={handleToggle}
        onKeyDown={handleKeyDown}
        aria-expanded={isExpanded}
        className="w-full flex items-center justify-between p-3.5 sm:p-4 text-left hover:bg-surface-secondary/50 focus:outline-none focus:ring-2 focus:ring-primary/40 transition-colors cursor-pointer"
      >
        <div className="flex items-start space-x-3 min-w-0 flex-1">
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase border shrink-0 mt-0.5 flex items-center gap-1 ${badge.bg}`}
          >
            <SevIcon className="w-3 h-3" />
            <span>{badge.label}</span>
          </span>

          <div className="space-y-0.5 min-w-0 flex-1">
            <span className="font-sans text-xs sm:text-sm font-semibold text-foreground tracking-tight block truncate">
              {title}
            </span>
            {subtitle && (
              <p className="text-[11px] font-mono text-foreground-muted line-clamp-1">
                {subtitle}
              </p>
            )}
          </div>
        </div>

        <div className="flex items-center space-x-2 shrink-0 ml-3">
          <ChevronRight
            className={`w-4 h-4 text-foreground-muted transition-transform duration-200 ${
              isExpanded ? 'rotate-90 text-primary' : ''
            }`}
          />
        </div>
      </button>

      {/* LEVEL 2: Explanation */}
      {isExpanded && (
        <div className="border-t border-border bg-surface-secondary/25 p-4 space-y-3.5 accordion-expand">
          <div className="space-y-2 text-xs font-mono">
            {children}
          </div>

          <div className="pt-2 border-t border-border/60 flex flex-wrap items-center justify-between gap-2">
            {onAction && actionLabel ? (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onAction();
                }}
                className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
              >
                <span>{actionLabel}</span>
                <ArrowRight className="w-3 h-3" />
              </button>
            ) : <div />}

            {hasLevel3 && (
              <button
                type="button"
                onClick={handleViewRaw}
                className="px-3 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-mono font-medium flex items-center space-x-1.5 transition-colors cursor-pointer shadow-2xs hover:text-primary"
              >
                <span>{rawButtonLabel}</span>
                <ExternalLink className="w-3 h-3 text-primary" />
              </button>
            )}
          </div>
        </div>
      )}

      {/* LEVEL 3 Drawer */}
      {rawEvidence !== undefined && (
        <DetailDrawer
          isOpen={drawerOpen}
          onClose={() => setDrawerOpen(false)}
          title={rawEvidenceTitle || `${title} — Raw Evidence`}
          subtitle={`Forensic examination for ${title}`}
          data={rawEvidence}
          format={rawEvidenceFormat}
        />
      )}
    </div>
  );
};
