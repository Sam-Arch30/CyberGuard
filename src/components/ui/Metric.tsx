import React from 'react';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface MetricProps extends React.HTMLAttributes<HTMLDivElement> {
  label: React.ReactNode;
  value: React.ReactNode;
  sublabel?: React.ReactNode;
  change?: {
    value: string | number;
    trend?: 'up' | 'down' | 'neutral';
    label?: string;
  };
  icon?: React.ReactNode;
  dense?: boolean;
}

export const Metric = React.forwardRef<HTMLDivElement, MetricProps>(
  ({ className, label, value, sublabel, change, icon, dense = false, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'p-3.5 sm:p-4 rounded-card border border-border bg-surface flex flex-col justify-between transition-colors',
          dense ? 'p-3' : 'p-4',
          className
        )}
        {...props}
      >
        <div className="flex items-center justify-between text-foreground-muted mb-2">
          <span className="text-[11px] font-mono font-semibold uppercase tracking-wider">{label}</span>
          {icon && <span className="text-foreground-subtle flex-shrink-0">{icon}</span>}
        </div>

        <div className="flex items-baseline space-x-2">
          <span className={cn('font-bold font-mono text-foreground tracking-tight', dense ? 'text-xl' : 'text-2xl')}>
            {value}
          </span>
          {sublabel && <span className="text-xs text-foreground-muted font-mono">{sublabel}</span>}
        </div>

        {change && (
          <div className="mt-2.5 flex items-center space-x-1.5 text-xs font-mono">
            {change.trend === 'up' && <TrendingUp className="w-3.5 h-3.5 text-danger" />}
            {change.trend === 'down' && <TrendingDown className="w-3.5 h-3.5 text-success" />}
            {change.trend === 'neutral' && <Minus className="w-3.5 h-3.5 text-foreground-muted" />}

            <span
              className={cn(
                'font-semibold',
                change.trend === 'up' && 'text-danger',
                change.trend === 'down' && 'text-success',
                change.trend === 'neutral' && 'text-foreground-muted'
              )}
            >
              {change.value}
            </span>
            {change.label && <span className="text-foreground-subtle text-[11px]">{change.label}</span>}
          </div>
        )}
      </div>
    );
  }
);

Metric.displayName = 'Metric';
