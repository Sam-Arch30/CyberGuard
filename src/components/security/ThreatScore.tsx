import React from 'react';
import { Activity } from 'lucide-react';
import { cn } from '../../utils/cn';
import { SeverityIndicator, type ThreatSeverityTier } from './SeverityIndicator';
import { ConfidenceIndicator, type ConfidenceTier } from './ConfidenceIndicator';

export interface ThreatScoreProps extends React.HTMLAttributes<HTMLDivElement> {
  score?: number | null; // 0 - 100 or null if unknown
  severity?: ThreatSeverityTier | string;
  confidence?: ConfidenceTier | string;
  confidenceScore?: number; // 0.0 - 1.0
  variant?: 'compact' | 'card' | 'bar';
  showConfidence?: boolean;
}

export const ThreatScore: React.FC<ThreatScoreProps> = ({
  score,
  severity,
  confidence,
  confidenceScore,
  variant = 'compact',
  showConfidence = true,
  className,
  ...props
}) => {
  const isUnknown = score === null || score === undefined;

  const resolvedSeverity: ThreatSeverityTier = React.useMemo(() => {
    if (severity) {
      const s = severity.toUpperCase().trim();
      if (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE', 'INFO', 'UNKNOWN'].includes(s)) {
        return s as ThreatSeverityTier;
      }
    }
    if (score !== null && score !== undefined) {
      if (score >= 85) return 'CRITICAL';
      if (score >= 65) return 'HIGH';
      if (score >= 40) return 'MEDIUM';
      if (score >= 15) return 'LOW';
      return 'SAFE';
    }
    return 'UNKNOWN';
  }, [severity, score]);

  // Color tokens for gauge
  const getSeverityColor = () => {
    switch (resolvedSeverity) {
      case 'CRITICAL':
        return 'var(--color-threat-critical)';
      case 'HIGH':
        return 'var(--color-threat-high)';
      case 'MEDIUM':
        return 'var(--color-threat-medium)';
      case 'LOW':
        return 'var(--color-threat-low)';
      case 'SAFE':
        return 'var(--color-threat-safe)';
      default:
        return 'var(--color-threat-unknown)';
    }
  };

  if (variant === 'compact') {
    return (
      <div
        className={cn('inline-flex items-center gap-2 font-mono text-xs select-none', className)}
        {...props}
      >
        <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-border bg-surface-secondary/60">
          <span className="text-[10px] text-foreground-muted font-sans font-medium uppercase tracking-wider">
            Risk:
          </span>
          <span className="font-bold text-foreground">
            {isUnknown ? '—' : `${score}/100`}
          </span>
        </div>

        <SeverityIndicator severity={resolvedSeverity} size="xs" />

        {showConfidence && (
          <ConfidenceIndicator
            tier={confidence}
            score={confidenceScore}
            size="xs"
            showPercentage={false}
          />
        )}
      </div>
    );
  }

  // Detailed Card / Panel Presentation
  return (
    <div
      className={cn(
        'p-4 rounded-card border border-border bg-surface-card transition-colors',
        className
      )}
      {...props}
    >
      <div className="flex items-center justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4 text-primary" />
          <span className="text-xs font-semibold uppercase tracking-wider text-foreground-muted">
            Risk Assessment
          </span>
        </div>
        <SeverityIndicator severity={resolvedSeverity} size="sm" pulse />
      </div>

      {/* Main Score Display */}
      <div className="flex items-baseline justify-between mb-3">
        <div>
          <span className="text-3xl font-extrabold font-mono tracking-tight text-foreground">
            {isUnknown ? 'UNKNOWN' : score}
          </span>
          {!isUnknown && (
            <span className="text-sm font-mono text-foreground-muted ml-1">/ 100</span>
          )}
        </div>
        {showConfidence && (
          <div className="text-right">
            <span className="text-[10px] uppercase tracking-wider text-foreground-muted block mb-0.5">
              Confidence
            </span>
            <ConfidenceIndicator
              tier={confidence}
              score={confidenceScore}
              size="xs"
            />
          </div>
        )}
      </div>

      {/* Visual Risk Gauge Bar */}
      <div className="w-full bg-surface-secondary rounded-full h-1.5 overflow-hidden mb-2">
        <div
          className="h-full rounded-full transition-all duration-300"
          style={{
            width: isUnknown ? '100%' : `${Math.min(100, Math.max(0, score || 0))}%`,
            backgroundColor: getSeverityColor(),
            opacity: isUnknown ? 0.35 : 1,
            backgroundImage: isUnknown
              ? 'repeating-linear-gradient(45deg, transparent, transparent 4px, currentColor 4px, currentColor 8px)'
              : undefined,
          }}
        />
      </div>

      {/* Subtext info */}
      <div className="flex justify-between text-[10px] font-mono text-foreground-muted">
        <span>0 (No signals)</span>
        <span>50 (ELEVATED)</span>
        <span>100 (CRITICAL)</span>
      </div>
    </div>
  );
};
