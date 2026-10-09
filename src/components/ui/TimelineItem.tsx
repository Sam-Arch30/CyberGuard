import React from 'react';
import { cn } from '../../utils/cn';

export interface TimelineItemProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  timestamp: React.ReactNode;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  isLast?: boolean;
}

export const TimelineItem = React.forwardRef<HTMLDivElement, TimelineItemProps>(
  ({ className, timestamp, title, subtitle, icon, badge, isLast = false, children, ...props }, ref) => {
    return (
      <div ref={ref} className={cn('relative flex items-start space-x-3 text-xs', className)} {...props}>
        {/* Left Column: Icon & Vertical Connector */}
        <div className="flex flex-col items-center flex-shrink-0 relative">
          <div className="w-7 h-7 rounded-full border border-border bg-surface-secondary flex items-center justify-center text-foreground-muted z-10 shadow-xs">
            {icon || <span className="w-2 h-2 rounded-full bg-primary" />}
          </div>
          {!isLast && <div className="w-px bg-border flex-1 absolute top-7 bottom-0 -mb-3" />}
        </div>

        {/* Right Column: Content */}
        <div className="flex-1 pb-4 min-w-0">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1 mb-1">
            <div className="flex items-center space-x-2">
              <span className="font-bold text-foreground font-sans truncate">{title}</span>
              {badge}
            </div>
            <span className="text-[11px] font-mono text-foreground-muted flex-shrink-0">{timestamp}</span>
          </div>

          {subtitle && <p className="text-[11px] font-mono text-foreground-muted mb-1.5">{subtitle}</p>}

          {children && <div className="mt-1 text-foreground leading-relaxed">{children}</div>}
        </div>
      </div>
    );
  }
);

TimelineItem.displayName = 'TimelineItem';
