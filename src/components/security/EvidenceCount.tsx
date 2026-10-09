import React from 'react';
import { Layers, CheckCircle2, XCircle, FileText } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface EvidenceCountProps extends React.HTMLAttributes<HTMLSpanElement> {
  total?: number;
  supporting?: number;
  refuting?: number;
  size?: 'xs' | 'sm' | 'md';
  variant?: 'compact' | 'split' | 'detailed';
}

export const EvidenceCount: React.FC<EvidenceCountProps> = ({
  total,
  supporting,
  refuting,
  size = 'sm',
  variant = 'compact',
  className,
  ...props
}) => {
  const calculatedTotal = total ?? ((supporting ?? 0) + (refuting ?? 0));

  const sizeStyles = {
    xs: 'text-[10px] px-1.5 py-0.5 gap-1',
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-2',
  }[size];

  if (variant === 'split' && (supporting !== undefined || refuting !== undefined)) {
    return (
      <span
        className={cn(
          'inline-flex items-center rounded-badge border border-border bg-surface-secondary/40 font-mono text-foreground-secondary select-none',
          sizeStyles,
          className
        )}
        title={`Evidence: ${supporting ?? 0} supporting, ${refuting ?? 0} refuting (${calculatedTotal} total)`}
        {...props}
      >
        <FileText className="w-3 h-3 text-foreground-muted flex-shrink-0" />
        <span className="flex items-center gap-1 text-threat-safe-foreground font-semibold">
          <CheckCircle2 className="w-2.5 h-2.5 text-threat-safe" />
          <span>+{supporting ?? 0}</span>
        </span>
        <span className="text-border-strong font-light">/</span>
        <span className="flex items-center gap-1 text-foreground-muted font-normal">
          <XCircle className="w-2.5 h-2.5 text-foreground-muted" />
          <span>-{refuting ?? 0}</span>
        </span>
      </span>
    );
  }

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-badge border border-border-subtle bg-surface-secondary/50 font-mono text-foreground-secondary select-none transition-colors hover:border-border',
        sizeStyles,
        className
      )}
      title={`${calculatedTotal} evidence artifacts recorded`}
      {...props}
    >
      <Layers className="w-3 h-3 text-primary flex-shrink-0" />
      <span className="font-semibold text-foreground">{calculatedTotal}</span>
      {variant === 'detailed' && <span className="text-foreground-muted">artifacts</span>}
    </span>
  );
};
