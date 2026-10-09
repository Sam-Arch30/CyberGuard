import React from 'react';
import { ShieldAlert, Shield, AlertTriangle, AlertOctagon, HelpCircle } from 'lucide-react';
import { cn } from '../../utils/cn';
import type { ThreatSeverityTier } from './SeverityIndicator';

export interface RiskBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  score?: number; // 0 - 100
  severity?: ThreatSeverityTier | string;
  variant?: 'compact' | 'detailed' | 'minimal';
  size?: 'xs' | 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  pulse?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  score,
  severity,
  variant = 'compact',
  size = 'sm',
  showIcon = true,
  pulse = false,
  className,
  ...props
}) => {
  // Derive severity from score if not explicitly provided
  const resolvedSeverity: ThreatSeverityTier = React.useMemo(() => {
    if (severity) {
      const s = severity.toUpperCase().trim();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'INFO', 'UNKNOWN'].includes(s)) {
        return s as ThreatSeverityTier;
      }
    }
    if (score !== undefined) {
      if (score >= 85) return 'CRITICAL';
      if (score >= 65) return 'HIGH';
      if (score >= 40) return 'MEDIUM';
      if (score >= 15) return 'LOW';
      return 'SAFE';
    }
    return 'UNKNOWN';
  }, [severity, score]);

  const configs: Record<
    ThreatSeverityTier,
    { label: string; icon: React.ReactNode; bg: string; text: string; border: string; dot: string }
  > = {
    CRITICAL: {
      label: 'CRITICAL',
      icon: <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-critical-surface',
      text: 'text-threat-critical-foreground',
      border: 'border-threat-critical-border',
      dot: 'bg-threat-critical',
    },
    HIGH: {
      label: 'HIGH',
      icon: <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-high-surface',
      text: 'text-threat-high-foreground',
      border: 'border-threat-high-border',
      dot: 'bg-threat-high',
    },
    MEDIUM: {
      label: 'MEDIUM',
      icon: <AlertOctagon className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-medium-surface',
      text: 'text-threat-medium-foreground',
      border: 'border-threat-medium-border',
      dot: 'bg-threat-medium',
    },
    LOW: {
      label: 'LOW',
      icon: <Shield className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-low-surface',
      text: 'text-threat-low-foreground',
      border: 'border-threat-low-border',
      dot: 'bg-threat-low',
    },
    SAFE: {
      label: 'SAFE',
      icon: <Shield className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-safe-surface',
      text: 'text-threat-safe-foreground',
      border: 'border-threat-safe-border',
      dot: 'bg-threat-safe',
    },
    INFO: {
      label: 'INFO',
      icon: <Shield className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-info-surface',
      text: 'text-threat-info-foreground',
      border: 'border-threat-info-border',
      dot: 'bg-threat-info',
    },
    UNKNOWN: {
      label: 'UNKNOWN',
      icon: <HelpCircle className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-unknown-surface',
      text: 'text-threat-unknown-foreground',
      border: 'border-threat-unknown-border',
      dot: 'bg-threat-unknown',
    },
  };

  const conf = configs[resolvedSeverity];

  const sizeStyles = {
    xs: 'text-[10px] px-1.5 py-0.5 gap-1',
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-sm px-3 py-1.5 gap-2 font-semibold',
  }[size];

  const shouldPulse = pulse && (resolvedSeverity === 'CRITICAL' || resolvedSeverity === 'HIGH');

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-badge border font-mono font-medium select-none transition-colors',
        conf.bg,
        conf.text,
        conf.border,
        sizeStyles,
        className
      )}
      aria-label={`Risk: ${conf.label}${score !== undefined ? ` (Score: ${score}/100)` : ''}`}
      {...props}
    >
      {/* Pulse / indicator dot */}
      <span className="relative flex h-2 w-2 items-center justify-center flex-shrink-0">
        {shouldPulse && (
          <span className={cn('animate-ping absolute inline-flex h-full w-full rounded-full opacity-75', conf.dot)} />
        )}
        <span className={cn('relative inline-flex rounded-full h-1.5 w-1.5', conf.dot)} />
      </span>

      {showIcon && conf.icon}

      {/* Label and/or score */}
      {variant === 'minimal' ? (
        score !== undefined ? <span>{score}</span> : <span>{conf.label}</span>
      ) : variant === 'detailed' ? (
        <span className="flex items-center gap-1.5">
          <span>{conf.label}</span>
          {score !== undefined && (
            <span className="opacity-75 font-semibold border-l border-current/20 pl-1.5">
              {score}/100
            </span>
          )}
        </span>
      ) : (
        <span className="flex items-center gap-1">
          <span>{conf.label}</span>
          {score !== undefined && <span className="opacity-80">({score})</span>}
        </span>
      )}
    </span>
  );
};
