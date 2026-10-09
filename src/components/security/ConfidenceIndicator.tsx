import React from 'react';
import { Target } from 'lucide-react';
import { cn } from '../../utils/cn';

export type ConfidenceTier = 'VERY_HIGH' | 'HIGH' | 'MEDIUM' | 'LOW' | 'UNCALIBRATED';

export interface ConfidenceIndicatorProps extends React.HTMLAttributes<HTMLSpanElement> {
  score?: number; // 0.0 - 1.0 or 0 - 100
  tier?: ConfidenceTier | string;
  size?: 'xs' | 'sm' | 'md';
  showPercentage?: boolean;
}

export const ConfidenceIndicator: React.FC<ConfidenceIndicatorProps> = ({
  score,
  tier,
  size = 'sm',
  showPercentage = true,
  className,
  ...props
}) => {
  // Normalize score between 0.0 and 1.0
  const normalizedScore = score !== undefined ? (score > 1 ? score / 100 : score) : undefined;

  const resolvedTier: ConfidenceTier = React.useMemo(() => {
    if (tier) {
      const t = tier.toUpperCase().replace(/\s+/g, '_');
      if (['VERY_HIGH', 'HIGH', 'MEDIUM', 'LOW', 'UNCALIBRATED'].includes(t)) {
        return t as ConfidenceTier;
      }
    }
    if (normalizedScore !== undefined) {
      if (normalizedScore >= 0.85) return 'VERY_HIGH';
      if (normalizedScore >= 0.70) return 'HIGH';
      if (normalizedScore >= 0.45) return 'MEDIUM';
      return 'LOW';
    }
    return 'UNCALIBRATED';
  }, [tier, normalizedScore]);

  const configs: Record<ConfidenceTier, { label: string; text: string; bg: string; border: string }> = {
    VERY_HIGH: {
      label: 'VERY HIGH CONFIDENCE',
      text: 'text-primary',
      bg: 'bg-primary-subtle',
      border: 'border-primary/25',
    },
    HIGH: {
      label: 'HIGH CONFIDENCE',
      text: 'text-info',
      bg: 'bg-info-surface',
      border: 'border-info-border',
    },
    MEDIUM: {
      label: 'MEDIUM CONFIDENCE',
      text: 'text-warning',
      bg: 'bg-warning-surface',
      border: 'border-warning-border',
    },
    LOW: {
      label: 'LOW CONFIDENCE',
      text: 'text-foreground-muted',
      bg: 'bg-surface-secondary',
      border: 'border-border',
    },
    UNCALIBRATED: {
      label: 'UNCALIBRATED',
      text: 'text-foreground-subtle',
      bg: 'bg-surface-secondary/50',
      border: 'border-border-subtle',
    },
  };

  const conf = configs[resolvedTier];

  const sizeStyles = {
    xs: 'text-[10px] px-1.5 py-0.5 gap-1',
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-1.5',
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
      title={`Evidence Confidence: ${conf.label}${normalizedScore !== undefined ? ` (${Math.round(normalizedScore * 100)}%)` : ''}`}
      {...props}
    >
      <Target className="w-3 h-3 flex-shrink-0 opacity-80" />
      <span>{conf.label}</span>
      {showPercentage && normalizedScore !== undefined && (
        <span className="opacity-75 font-semibold">({Math.round(normalizedScore * 100)}%)</span>
      )}
    </span>
  );
};
