import React from 'react';
import { Search, X } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface SearchInputProps
  extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'size'> {
  value: string;
  onChangeValue: (val: string) => void;
  onClear?: () => void;
  size?: 'sm' | 'md';
  placeholder?: string;
  shortcutBadge?: string;
}

export const SearchInput = React.forwardRef<HTMLInputElement, SearchInputProps>(
  (
    {
      value,
      onChangeValue,
      onClear,
      size = 'md',
      placeholder = 'Search indicators, hashes, entities...',
      shortcutBadge,
      className,
      disabled,
      ...props
    },
    ref
  ) => {
    const handleClear = () => {
      onChangeValue('');
      onClear?.();
    };

    const sizeStyles = {
      sm: 'h-8 text-xs pl-8 pr-7',
      md: 'h-8.5 text-xs pl-8.5 pr-8',
    };

    const iconSizes = {
      sm: 'w-3.5 h-3.5 left-2.5',
      md: 'w-4 h-4 left-2.5',
    };

    return (
      <div className="relative flex items-center w-full select-none">
        <Search
          className={cn(
            'absolute text-foreground-muted pointer-events-none -translate-y-1/2 top-1/2',
            iconSizes[size]
          )}
        />
        <input
          ref={ref}
          type="text"
          value={value}
          onChange={(e) => onChangeValue(e.target.value)}
          placeholder={placeholder}
          disabled={disabled}
          className={cn(
            'w-full bg-surface-secondary border border-border rounded-control font-mono text-foreground placeholder:text-foreground-subtle transition-colors',
            'focus:outline-none focus:ring-1 focus:ring-primary focus:border-primary',
            'disabled:opacity-50 disabled:cursor-not-allowed',
            sizeStyles[size],
            shortcutBadge && !value && 'pr-12',
            className
          )}
          {...props}
        />

        {value && !disabled && (
          <button
            type="button"
            onClick={handleClear}
            aria-label="Clear search"
            className="absolute right-2.5 p-0.5 rounded-full text-foreground-muted hover:text-foreground hover:bg-surface transition-colors cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}

        {shortcutBadge && !value && (
          <span className="absolute right-2.5 text-[9px] font-mono px-1.5 py-0.2 rounded bg-surface border border-border text-foreground-subtle pointer-events-none">
            {shortcutBadge}
          </span>
        )}
      </div>
    );
  }
);

SearchInput.displayName = 'SearchInput';
