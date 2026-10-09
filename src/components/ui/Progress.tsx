import React from 'react';
import { cn } from '../../utils/cn';

export interface ProgressProps extends React.HTMLAttributes<HTMLDivElement> {
  value?: number;
  max?: number;
  indeterminate?: boolean;
  size?: 'xs' | 'sm' | 'md' | 'lg';
  variant?: 'primary' | 'success' | 'warning' | 'danger' | 'info';
  showLabel?: boolean;
}

export const Progress = React.forwardRef<HTMLDivElement, ProgressProps>(
  (
    {
      className,
      value = 0,
      max = 100,
      indeterminate = false,
      size = 'sm',
      variant = 'primary',
      showLabel = false,
      ...props
    },
    ref
  ) => {
    const percentage = Math.max(0, Math.min(100, (value / max) * 100));

    const heightClasses = {
      xs: 'h-1',
      sm: 'h-1.5',
      md: 'h-2.5',
      lg: 'h-4',
    }[size];

    const fillVariants = {
      primary: 'bg-primary',
      success: 'bg-success',
      warning: 'bg-warning',
      danger: 'bg-danger',
      info: 'bg-info',
    }[variant];

    return (
      <div ref={ref} className={cn('w-full flex flex-col space-y-1', className)} {...props}>
        <div
          role="progressbar"
          aria-valuenow={indeterminate ? undefined : Math.round(percentage)}
          aria-valuemin={0}
          aria-valuemax={100}
          className={cn('w-full bg-surface-secondary border border-border-subtle rounded-full overflow-hidden relative', heightClasses)}
        >
          {indeterminate ? (
            <div className={cn('h-full w-1/3 rounded-full animate-indeterminate', fillVariants)} />
          ) : (
            <div
              className={cn('h-full rounded-full transition-all duration-300 ease-out', fillVariants)}
              style={{ width: `${percentage}%` }}
            />
          )}
        </div>

        {showLabel && !indeterminate && (
          <div className="flex justify-between items-center text-[10px] font-mono text-foreground-muted">
            <span>{Math.round(percentage)}%</span>
            <span>{value} / {max}</span>
          </div>
        )}
      </div>
    );
  }
);

Progress.displayName = 'Progress';
