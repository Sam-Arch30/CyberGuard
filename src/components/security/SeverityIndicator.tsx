import React from 'react';
import { ShieldAlert, AlertTriangle, AlertOctagon, Info, ShieldCheck, HelpCircle } from 'lucide-react';
import { cn } from '../../utils/cn';

export type ThreatSeverityTier = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE' | 'INFO' | 'UNKNOWN';

export interface SeverityIndicatorProps extends React.HTMLAttributes<HTMLSpanElement> {
  severity: ThreatSeverityTier | string;
  size?: 'xs' | 'sm' | 'md' | 'lg';
  showIcon?: boolean;
  showText?: boolean;
  pulse?: boolean;
}

export const SeverityIndicator: React.FC<SeverityIndicatorProps> = ({
  severity,
  size = 'sm',
  showIcon = true,
  showText = true,
  pulse = false,
  className,
  ...props
}) => {
  const normalized = (severity || 'UNKNOWN').toUpperCase() as ThreatSeverityTier;

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
      icon: <Info className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-low-surface',
      text: 'text-threat-low-foreground',
      border: 'border-threat-low-border',
      dot: 'bg-threat-low',
    },
    SAFE: {
      label: 'SAFE',
      icon: <ShieldCheck className="w-3.5 h-3.5 flex-shrink-0" />,
      bg: 'bg-threat-safe-surface',
      text: 'text-threat-safe-foreground',
      border: 'border-threat-safe-border',
      dot: 'bg-threat-safe',
    },
    INFO: {
      label: 'INFO',
      icon: <Info className="w-3.5 h-3.5 flex-shrink-0" />,
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

  const conf = configs[normalized] || configs.UNKNOWN;

  const sizeStyles = {
    xs: 'text-[10px] px-1.5 py-0.5 gap-1',
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-xs px-3 py-1.5 gap-2 font-semibold',
  }[size];

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-badge border font-mono font-medium transition-colors select-none',
        conf.bg,
        conf.text,
        conf.border,
        sizeStyles,
        className
      )}
      {...props}
    >
      <span className="relative flex h-2 w-2 items-center justify-center flex-shrink-0">
        {pulse && (normalized === 'CRITICAL' || normalized === 'HIGH') && (
          <span className={cn('animate-ping absolute inline-flex h-full w-full rounded-full opacity-75', conf.dot)} />
        )}
        <span className={cn('relative inline-flex rounded-full h-1.5 w-1.5', conf.dot)} />
      </span>

      {showIcon && conf.icon}
      {showText && <span>{conf.label}</span>}
    </span>
  );
};
