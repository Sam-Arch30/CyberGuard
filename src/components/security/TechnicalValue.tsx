import React, { useState } from 'react';
import { Copy, Check, Eye, EyeOff } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface TechnicalValueProps extends React.HTMLAttributes<HTMLSpanElement> {
  value: string;
  type?: 'hash' | 'uuid' | 'id' | 'ip' | 'port' | 'command' | 'generic';
  truncate?: 'start' | 'middle' | 'end' | 'none';
  truncateLength?: number;
  copyable?: boolean;
  mask?: boolean;
  size?: 'xs' | 'sm' | 'md';
}

export const TechnicalValue: React.FC<TechnicalValueProps> = ({
  value,
  type = 'generic',
  truncate = 'middle',
  truncateLength = 20,
  copyable = true,
  mask = false,
  size = 'sm',
  className,
  ...props
}) => {
  const [copied, setCopied] = useState(false);
  const [revealed, setRevealed] = useState(!mask);

  const formattedValue = React.useMemo(() => {
    if (mask && !revealed) {
      return '••••••••••••••••';
    }

    if (truncate === 'none' || value.length <= truncateLength) {
      return value;
    }

    if (truncate === 'middle') {
      const start = Math.floor((truncateLength - 3) / 2);
      const end = Math.ceil((truncateLength - 3) / 2);
      return `${value.slice(0, start)}...${value.slice(value.length - end)}`;
    }

    if (truncate === 'start') {
      return `...${value.slice(value.length - truncateLength + 3)}`;
    }

    // truncate === 'end'
    return `${value.slice(0, truncateLength - 3)}...`;
  }, [value, truncate, truncateLength, mask, revealed]);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sizeStyles = {
    xs: 'text-[10px] px-1.5 py-0.5 gap-1',
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-2',
  }[size];

  return (
    <span
      className={cn(
        'inline-flex items-center rounded border border-border bg-surface-secondary/40 font-mono text-foreground font-medium select-none group max-w-full',
        sizeStyles,
        className
      )}
      title={mask && !revealed ? 'Masked technical identifier' : value}
      {...props}
    >
      <span className="truncate whitespace-nowrap select-text">{formattedValue}</span>

      {mask && (
        <button
          type="button"
          onClick={() => setRevealed(!revealed)}
          className="text-foreground-muted hover:text-foreground p-0.5 rounded focus:outline-none focus:ring-1 focus:ring-focus ml-0.5"
          title={revealed ? 'Hide value' : 'Show value'}
          aria-label={revealed ? 'Hide value' : 'Show value'}
        >
          {revealed ? <EyeOff className="w-2.5 h-2.5" /> : <Eye className="w-2.5 h-2.5" />}
        </button>
      )}

      {copyable && (!mask || revealed) && (
        <button
          type="button"
          onClick={handleCopy}
          className="text-foreground-muted hover:text-primary ml-0.5 p-0.5 rounded focus:outline-none focus:ring-1 focus:ring-focus"
          title={copied ? 'Copied full value to clipboard' : 'Copy technical identifier'}
          aria-label="Copy identifier"
        >
          {copied ? (
            <Check className="w-2.5 h-2.5 text-threat-safe" />
          ) : (
            <Copy className="w-2.5 h-2.5 opacity-60 hover:opacity-100" />
          )}
        </button>
      )}
    </span>
  );
};
