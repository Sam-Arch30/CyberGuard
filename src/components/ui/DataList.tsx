import React from 'react';
import { cn } from '../../utils/cn';

export interface DataListItem {
  label: React.ReactNode;
  value: React.ReactNode;
  mono?: boolean;
  copyable?: boolean;
  badge?: React.ReactNode;
}

export interface DataListProps extends React.HTMLAttributes<HTMLDListElement> {
  items?: DataListItem[];
  dense?: boolean;
  orientation?: 'horizontal' | 'vertical';
}

export const DataList = React.forwardRef<HTMLDListElement, DataListProps>(
  ({ className, items = [], dense = false, orientation = 'horizontal', children, ...props }, ref) => {
    return (
      <dl
        ref={ref}
        className={cn(
          'divide-y divide-border-subtle text-xs',
          dense ? 'py-0.5' : 'py-1',
          className
        )}
        {...props}
      >
        {items.map((item, idx) => (
          <div
            key={idx}
            className={cn(
              'flex transition-colors hover:bg-surface-secondary/30',
              dense ? 'py-1.5' : 'py-2.5',
              orientation === 'horizontal'
                ? 'flex-col sm:flex-row sm:items-center sm:justify-between gap-1 sm:gap-4'
                : 'flex-col gap-1'
            )}
          >
            <dt className="text-foreground-muted font-mono text-[11px] uppercase tracking-wider flex-shrink-0">
              {item.label}
            </dt>
            <dd className={cn('text-foreground flex items-center space-x-1.5 min-w-0', item.mono && 'font-mono text-[11px]')}>
              <span className="truncate">{item.value}</span>
              {item.badge}
            </dd>
          </div>
        ))}
        {children}
      </dl>
    );
  }
);

DataList.displayName = 'DataList';
