import React from 'react';
import { X } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface TagProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: 'neutral' | 'primary' | 'muted' | 'outline';
  size?: 'xs' | 'sm' | 'md';
  onRemove?: () => void;
  icon?: React.ReactNode;
}

export const Tag = React.forwardRef<HTMLSpanElement, TagProps>(
  ({ className, variant = 'neutral', size = 'sm', onRemove, icon, children, ...props }, ref) => {
    const variants = {
      neutral: 'bg-surface-secondary text-foreground border-border hover:border-border-strong',
      primary: 'bg-primary-subtle text-primary border-primary/30',
      muted: 'bg-surface text-foreground-muted border-border-subtle',
      outline: 'bg-transparent text-foreground border-border',
    }[variant];

    const sizes = {
      xs: 'text-[10px] px-1.5 py-0.5 gap-1',
      sm: 'text-[11px] px-2 py-0.5 gap-1.5',
      md: 'text-xs px-2.5 py-1 gap-1.5',
    }[size];

    return (
      <span
        ref={ref}
        className={cn(
          'inline-flex items-center font-mono font-medium rounded-badge border transition-colors select-none',
          variants,
          sizes,
          className
        )}
        {...props}
      >
        {icon && <span className="flex-shrink-0">{icon}</span>}
        <span>{children}</span>
        {onRemove && (
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onRemove();
            }}
            className="hover:bg-foreground/10 rounded-full p-0.5 text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
            aria-label="Remove tag"
          >
            <X className="w-2.5 h-2.5" />
          </button>
        )}
      </span>
    );
  }
);

Tag.displayName = 'Tag';
