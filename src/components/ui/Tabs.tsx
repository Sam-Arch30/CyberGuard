import React from 'react';
import { cn } from '../../utils/cn';

export interface TabItem {
  id: string;
  label: React.ReactNode;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  count?: number;
  disabled?: boolean;
}

export interface TabsProps {
  items: TabItem[];
  activeId: string;
  onChange: (id: string) => void;
  variant?: 'underline' | 'pills' | 'segmented';
  size?: 'sm' | 'md';
  className?: string;
  fullWidth?: boolean;
}

export const Tabs: React.FC<TabsProps> = ({
  items,
  activeId,
  onChange,
  variant = 'underline',
  size = 'md',
  className,
  fullWidth = false,
}) => {
  const sizeStyles = {
    sm: 'text-xs py-1.5 px-2.5 gap-1.5',
    md: 'text-xs py-2 px-3.5 gap-2',
  };

  if (variant === 'segmented') {
    return (
      <div
        role="tablist"
        className={cn(
          'inline-flex items-center p-1 bg-surface-secondary border border-border rounded-control select-none gap-0.5',
          fullWidth && 'w-full',
          className
        )}
      >
        {items.map((tab) => {
          const isActive = tab.id === activeId;
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              disabled={tab.disabled}
              onClick={() => onChange(tab.id)}
              className={cn(
                'inline-flex items-center justify-center font-mono font-medium rounded-control-sm transition-all cursor-pointer select-none',
                sizeStyles[size],
                fullWidth && 'flex-1',
                isActive
                  ? 'bg-surface text-primary font-bold shadow-xs border border-border'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface/50 border border-transparent',
                tab.disabled && 'opacity-40 cursor-not-allowed pointer-events-none'
              )}
            >
              {tab.icon && <span className="shrink-0">{tab.icon}</span>}
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span
                  className={cn(
                    'text-[10px] px-1.5 py-0.2 rounded-badge font-mono',
                    isActive ? 'bg-primary/10 text-primary' : 'bg-surface border border-border text-foreground-subtle'
                  )}
                >
                  {tab.count}
                </span>
              )}
              {tab.badge}
            </button>
          );
        })}
      </div>
    );
  }

  if (variant === 'pills') {
    return (
      <div
        role="tablist"
        className={cn('flex items-center gap-1.5 select-none overflow-x-auto', className)}
      >
        {items.map((tab) => {
          const isActive = tab.id === activeId;
          return (
            <button
              key={tab.id}
              role="tab"
              aria-selected={isActive}
              disabled={tab.disabled}
              onClick={() => onChange(tab.id)}
              className={cn(
                'inline-flex items-center justify-center font-mono font-medium rounded-control transition-all cursor-pointer shrink-0 border',
                sizeStyles[size],
                isActive
                  ? 'bg-primary/10 text-primary font-bold border-primary/30 shadow-xs'
                  : 'bg-surface text-foreground-muted hover:text-foreground hover:bg-surface-secondary border-border',
                tab.disabled && 'opacity-40 cursor-not-allowed pointer-events-none'
              )}
            >
              {tab.icon && <span className="shrink-0">{tab.icon}</span>}
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span
                  className={cn(
                    'text-[10px] px-1.5 py-0.2 rounded-badge font-mono',
                    isActive ? 'bg-primary/20 text-primary' : 'bg-surface-secondary text-foreground-subtle'
                  )}
                >
                  {tab.count}
                </span>
              )}
              {tab.badge}
            </button>
          );
        })}
      </div>
    );
  }

  // Default: Underline variant
  return (
    <div
      role="tablist"
      className={cn('flex items-center border-b border-border select-none overflow-x-auto', className)}
    >
      {items.map((tab) => {
        const isActive = tab.id === activeId;
        return (
          <button
            key={tab.id}
            role="tab"
            aria-selected={isActive}
            disabled={tab.disabled}
            onClick={() => onChange(tab.id)}
            className={cn(
              'relative inline-flex items-center justify-center font-mono font-medium transition-colors cursor-pointer shrink-0 border-b-2 -mb-px',
              sizeStyles[size],
              fullWidth && 'flex-1',
              isActive
                ? 'text-primary border-primary font-bold'
                : 'text-foreground-muted hover:text-foreground border-transparent hover:border-border',
              tab.disabled && 'opacity-40 cursor-not-allowed pointer-events-none'
            )}
          >
            {tab.icon && <span className="shrink-0">{tab.icon}</span>}
            <span>{tab.label}</span>
            {tab.count !== undefined && (
              <span
                className={cn(
                  'text-[10px] px-1.5 py-0.2 rounded-badge font-mono',
                  isActive ? 'bg-primary/10 text-primary font-semibold' : 'bg-surface-secondary text-foreground-subtle'
                )}
              >
                {tab.count}
              </span>
            )}
            {tab.badge}
          </button>
        );
      })}
    </div>
  );
};
