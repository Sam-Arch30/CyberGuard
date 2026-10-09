import React from 'react';
import { cn } from '../../utils/cn';

export interface PanelProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  badge?: React.ReactNode;
  actions?: React.ReactNode;
  footer?: React.ReactNode;
  dense?: boolean;
}

export const Panel = React.forwardRef<HTMLDivElement, PanelProps>(
  ({ className, title, subtitle, badge, actions, footer, dense = false, children, ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          'rounded-card border border-border bg-surface flex flex-col transition-colors',
          dense ? 'p-3 gap-2.5' : 'p-4 sm:p-5 gap-4',
          className
        )}
        {...props}
      >
        {(title || actions || badge) && (
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border-subtle gap-2">
            <div className="flex items-center space-x-2 min-w-0">
              {title && (
                <div className="flex flex-col min-w-0">
                  <div className="flex items-center space-x-2">
                    <h3 className={cn('font-sans font-bold text-foreground truncate', dense ? 'text-xs' : 'text-sm')}>
                      {title}
                    </h3>
                    {badge}
                  </div>
                  {subtitle && <p className="text-[11px] font-mono text-foreground-muted truncate mt-0.5">{subtitle}</p>}
                </div>
              )}
            </div>
            {actions && <div className="flex items-center space-x-2 flex-shrink-0">{actions}</div>}
          </div>
        )}

        <div className="flex-1 min-w-0">{children}</div>

        {footer && <div className="pt-3 border-t border-border-subtle text-xs text-foreground-muted">{footer}</div>}
      </div>
    );
  }
);

Panel.displayName = 'Panel';
