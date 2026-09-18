import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import {
  defang,
  truncateMiddle,
  truncateUrl,
  truncateEmail,
  truncateDomain,
  formatIp,
  truncateSubject
} from '../../utils/forensicFormatters';
import { cn } from '../../utils/cn';

export type ForensicValueType = 'hash' | 'url' | 'domain' | 'email' | 'ip' | 'subject' | 'text' | 'attachment';

export interface TruncatedForensicValueProps {
  value: string;
  type?: ForensicValueType;
  maxWidth?: string;
  defanged?: boolean;
  copyable?: boolean;
  copyIconOnly?: boolean;
  codeStyle?: boolean;
  className?: string;
  onClick?: (e: React.MouseEvent) => void;
}

export const TruncatedForensicValue: React.FC<TruncatedForensicValueProps> = ({
  value,
  type = 'text',
  maxWidth = 'max-w-[200px] sm:max-w-[320px] md:max-w-[420px]',
  defanged: shouldDefang = false,
  copyable = true,
  copyIconOnly = true,
  codeStyle = true,
  className = '',
  onClick
}) => {
  const [copied, setCopied] = useState(false);

  if (!value) {
    return <span className="text-foreground-muted italic text-xs">None</span>;
  }

  // Determine truncated presentation
  let displayValue = value;
  switch (type) {
    case 'hash':
      displayValue = truncateMiddle(value, 8, 8);
      break;
    case 'url':
      displayValue = truncateUrl(value, 46, shouldDefang);
      break;
    case 'email':
      displayValue = truncateEmail(value, 36);
      break;
    case 'domain':
      displayValue = truncateDomain(value, 32, shouldDefang);
      break;
    case 'ip':
      displayValue = formatIp(value, 28);
      break;
    case 'subject':
      displayValue = truncateSubject(value, 60);
      break;
    case 'attachment':
      displayValue = truncateMiddle(value, 16, 8);
      break;
    case 'text':
    default:
      displayValue = shouldDefang ? defang(value) : value;
      break;
  }

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <span
      className={cn(
        'inline-flex items-center space-x-1.5 min-w-0 max-w-full align-middle select-none',
        className
      )}
      onClick={onClick}
    >
      <span
        title={value}
        className={cn(
          'truncate min-w-0 select-all cursor-help',
          codeStyle && 'font-mono text-xs text-foreground',
          maxWidth
        )}
      >
        {displayValue}
      </span>

      {copyable && (
        <button
          type="button"
          onClick={handleCopy}
          title={copied ? 'Copied to clipboard' : `Copy complete ${type.toUpperCase()}: ${value}`}
          className={cn(
            'shrink-0 p-1 rounded-control-sm border transition-colors cursor-pointer',
            copied
              ? 'bg-success/10 border-success/30 text-success'
              : 'bg-surface-secondary/70 hover:bg-surface border-border text-foreground-muted hover:text-primary'
          )}
        >
          {copied ? (
            <Check className="w-3 h-3 text-success" />
          ) : (
            <Copy className="w-3 h-3" />
          )}
          {!copyIconOnly && (
            <span className="text-[10px] font-mono ml-1">
              {copied ? 'Copied' : 'Copy'}
            </span>
          )}
        </button>
      )}
    </span>
  );
};
