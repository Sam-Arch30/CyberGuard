import React from 'react';
import { cn } from '../../utils/cn';

export type StatusType =
  | 'pass'
  | 'safe'
  | 'warning'
  | 'critical'
  | 'danger'
  | 'neutral'
  | 'info';

export interface StatusIndicatorProps extends React.HTMLAttributes<HTMLSpanElement> {
  status: StatusType;
  variant?: 'dot' | 'badge' | 'subtle';
  size?: 'xs' | 'sm' | 'md';
  pulse?: boolean;
  label?: React.ReactNode;
}

export const StatusIndicator: React.FC<StatusIndicatorProps> = ({
  status,
  variant = 'badge',
  size = 'sm',
  pulse = false,
  label,
  className,
  ...props
}) => {
  const isPass = status === 'pass' || status === 'safe';
  const isWarning = status === 'warning';
  const isDanger = status === 'critical' || status === 'danger';
  const isInfo = status === 'info';

  const dotColors = isPass
    ? 'bg-success'
    : isWarning
    ? 'bg-warning'
    : isDanger
    ? 'bg-danger'
    : isInfo
    ? 'bg-info'
    : 'bg-foreground-muted';

  const badgeStyles = isPass
    ? 'bg-success-surface text-success border-success-border'
    : isWarning
    ? 'bg-warning-surface text-warning border-warning-border'
    : isDanger
    ? 'bg-danger-surface text-danger border-danger-border font-semibold'
    : isInfo
    ? 'bg-info-surface text-info border-info-border'
    : 'bg-surface-secondary text-foreground-muted border-border';

  const sizeStyles = {
    xs: 'text-[10px] px-1.5 py-0.2 gap-1',
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-1.5',
  };

  const dotSizes = {
    xs: 'w-1.5 h-1.5',
    sm: 'w-2 h-2',
    md: 'w-2.5 h-2.5',
  };

  if (variant === 'dot') {
    return (
      <span
        className={cn('inline-flex items-center gap-1.5 font-mono text-xs select-none', className)}
        {...props}
      >
        <span
          className={cn(
            'rounded-full shrink-0',
            dotSizes[size],
            dotColors,
            pulse && 'animate-pulse'
          )}
        />
        {label && <span className="text-foreground">{label}</span>}
      </span>
    );
  }

  return (
    <span
      className={cn(
        'inline-flex items-center font-mono font-medium border rounded-badge transition-colors select-none',
        badgeStyles,
        sizeStyles[size],
        className
      )}
      {...props}
    >
      <span
        className={cn(
          'rounded-full shrink-0',
          dotSizes[size === 'md' ? 'sm' : 'xs'],
          dotColors,
          pulse && 'animate-pulse'
        )}
      />
      {label && <span>{label}</span>}
    </span>
  );
};
