import React, { useState } from 'react';
import { ChevronDown } from 'lucide-react';

export interface ExpandableSectionProps {
  title: React.ReactNode;
  subtitle?: string;
  icon?: React.FC<{ className?: string }>;
  badge?: React.ReactNode;
  defaultExpanded?: boolean;
  isExpanded?: boolean;
  onToggle?: (expanded: boolean) => void;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}

export const ExpandableSection: React.FC<ExpandableSectionProps> = ({
  title,
  subtitle,
  icon: Icon,
  badge,
  defaultExpanded = true,
  isExpanded: controlledExpanded,
  onToggle,
  actions,
  children,
  className = ''
}) => {
  const [internalExpanded, setInternalExpanded] = useState(defaultExpanded);

  const isExpanded = controlledExpanded !== undefined ? controlledExpanded : internalExpanded;

  const handleToggle = () => {
    const next = !isExpanded;
    if (controlledExpanded === undefined) {
      setInternalExpanded(next);
    }
    onToggle?.(next);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleToggle();
    }
  };

  return (
    <div className={`rounded-card border border-border bg-surface shadow-xs transition-all overflow-hidden ${className}`}>
      {/* Section Header (Clickable Accordion Trigger) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 sm:p-5 border-b border-border bg-surface select-none">
        <div
          role="button"
          tabIndex={0}
          onClick={handleToggle}
          onKeyDown={handleKeyDown}
          aria-expanded={isExpanded}
          className="flex items-center space-x-3 min-w-0 flex-1 cursor-pointer group focus:outline-none"
        >
          {Icon && (
            <div className="p-2 rounded-xl bg-primary/10 border border-primary/20 text-primary shrink-0 group-hover:scale-105 transition-transform">
              <Icon className="w-4 h-4" />
            </div>
          )}

          <div className="space-y-0.5 min-w-0 flex-1">
            <div className="flex items-center space-x-2.5 flex-wrap">
              <h3 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider group-hover:text-primary transition-colors truncate">
                {title}
              </h3>
              {badge}
            </div>
            {subtitle && (
              <p className="text-xs text-foreground-muted font-sans line-clamp-1">
                {subtitle}
              </p>
            )}
          </div>

          <div className="p-1 rounded-md text-foreground-muted group-hover:text-foreground transition-colors shrink-0">
            <ChevronDown
              className={`w-4 h-4 transition-transform duration-200 ${
                isExpanded ? 'rotate-180 text-primary' : ''
              }`}
            />
          </div>
        </div>

        {actions && (
          <div className="flex items-center space-x-2 shrink-0 self-start sm:self-auto pl-1 sm:pl-0">
            {actions}
          </div>
        )}
      </div>

      {/* Section Content (Animated Expansion) */}
      {isExpanded && (
        <div className="p-4 sm:p-5 space-y-4 animate-fadeIn">
          {children}
        </div>
      )}
    </div>
  );
};
