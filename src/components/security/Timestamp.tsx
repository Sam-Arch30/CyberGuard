import React, { useState } from 'react';
import { Clock, Copy, Check } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface TimestampProps extends React.HTMLAttributes<HTMLSpanElement> {
  date: string | number | Date;
  format?: 'utc' | 'local' | 'relative' | 'iso';
  showRelative?: boolean;
  showIcon?: boolean;
  copyable?: boolean;
  size?: 'xs' | 'sm' | 'md';
}

export const Timestamp: React.FC<TimestampProps> = ({
  date,
  format = 'utc',
  showRelative = true,
  showIcon = true,
  copyable = false,
  size = 'sm',
  className,
  ...props
}) => {
  const [copied, setCopied] = useState(false);

  const parsedDate = React.useMemo(() => {
    try {
      const d = new Date(date);
      return isNaN(d.getTime()) ? null : d;
    } catch {
      return null;
    }
  }, [date]);

  const isoString = parsedDate ? parsedDate.toISOString() : String(date);

  const formattedValue = React.useMemo(() => {
    if (!parsedDate) return String(date);

    switch (format) {
      case 'iso':
        return parsedDate.toISOString();
      case 'local':
        return parsedDate.toLocaleString();
      case 'relative':
        return getRelativeTime(parsedDate);
      case 'utc':
      default: {
        const pad = (n: number) => String(n).padStart(2, '0');
        const year = parsedDate.getUTCFullYear();
        const month = pad(parsedDate.getUTCMonth() + 1);
        const day = pad(parsedDate.getUTCDate());
        const hours = pad(parsedDate.getUTCHours());
        const mins = pad(parsedDate.getUTCMinutes());
        const secs = pad(parsedDate.getUTCSeconds());
        return `${year}-${month}-${day} ${hours}:${mins}:${secs} UTC`;
      }
    }
  }, [parsedDate, format, date]);

  const relativeText = parsedDate ? getRelativeTime(parsedDate) : '';

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(isoString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const sizeStyles = {
    xs: 'text-[10px] gap-1',
    sm: 'text-[11px] gap-1.5',
    md: 'text-xs gap-2',
  }[size];

  return (
    <span
      className={cn(
        'inline-flex items-center font-mono text-foreground-secondary select-none tracking-tight',
        sizeStyles,
        className
      )}
      title={`UTC: ${isoString}${parsedDate ? `\nLocal: ${parsedDate.toLocaleString()}` : ''}`}
      {...props}
    >
      {showIcon && <Clock className="w-3 h-3 text-foreground-muted flex-shrink-0" />}

      <span className="text-foreground">{formattedValue}</span>

      {showRelative && format !== 'relative' && relativeText && (
        <span className="text-[10px] text-foreground-muted">({relativeText})</span>
      )}

      {copyable && (
        <button
          type="button"
          onClick={handleCopy}
          className="text-foreground-muted hover:text-primary ml-0.5 p-0.5 rounded focus:outline-none focus:ring-1 focus:ring-focus"
          title={copied ? 'ISO timestamp copied' : 'Copy ISO timestamp'}
          aria-label={`Copy timestamp ${isoString}`}
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

function getRelativeTime(date: Date): string {
  const now = Date.now();
  const diffSecs = Math.floor((now - date.getTime()) / 1000);

  if (diffSecs < 10) return 'just now';
  if (diffSecs < 60) return `${diffSecs}s ago`;
  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 30) return `${diffDays}d ago`;
  return `${Math.floor(diffDays / 30)}mo ago`;
}
