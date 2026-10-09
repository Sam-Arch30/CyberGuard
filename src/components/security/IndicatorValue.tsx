import React, { useState } from 'react';
import { Copy, Check, ShieldAlert, AlertTriangle, ShieldCheck, HelpCircle } from 'lucide-react';
import { cn } from '../../utils/cn';

export type IndicatorReputation = 'malicious' | 'suspicious' | 'benign' | 'unknown';

export interface IndicatorValueProps extends React.HTMLAttributes<HTMLSpanElement> {
  value: string;
  type?: string;
  reputation?: IndicatorReputation;
  defang?: boolean;
  truncateLength?: number;
  copyable?: boolean;
  size?: 'xs' | 'sm' | 'md';
}

export const IndicatorValue: React.FC<IndicatorValueProps> = ({
  value,
  type,
  reputation,
  defang = false,
  truncateLength = 32,
  copyable = true,
  size = 'sm',
  className,
  ...props
}) => {
  const [copied, setCopied] = useState(false);

  // Defang helper
  const defangedValue = React.useMemo(() => {
    if (!defang) return value;
    return value
      .replace(/http:\/\//gi, 'hxxp://')
      .replace(/https:\/\//gi, 'hxxps://')
      .replace(/\./g, '[.]');
  }, [value, defang]);

  const displayValue = React.useMemo(() => {
    const val = defangedValue;
    if (val.length <= truncateLength) return val;
    const start = Math.floor((truncateLength - 3) / 2);
    const end = Math.ceil((truncateLength - 3) / 2);
    return `${val.slice(0, start)}...${val.slice(val.length - end)}`;
  }, [defangedValue, truncateLength]);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard?.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getReputationBadge = () => {
    if (!reputation) return null;
    switch (reputation) {
      case 'malicious':
        return (
          <span className="flex items-center gap-1 text-[10px] text-threat-critical-foreground bg-threat-critical-surface px-1.5 py-0.2 rounded border border-threat-critical-border">
            <ShieldAlert className="w-2.5 h-2.5" />
            MALICIOUS
          </span>
        );
      case 'suspicious':
        return (
          <span className="flex items-center gap-1 text-[10px] text-threat-high-foreground bg-threat-high-surface px-1.5 py-0.2 rounded border border-threat-high-border">
            <AlertTriangle className="w-2.5 h-2.5" />
            SUSPICIOUS
          </span>
        );
      case 'benign':
        return (
          <span className="flex items-center gap-1 text-[10px] text-threat-safe-foreground bg-threat-safe-surface px-1.5 py-0.2 rounded border border-threat-safe-border">
            <ShieldCheck className="w-2.5 h-2.5" />
            BENIGN
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 text-[10px] text-threat-unknown-foreground bg-threat-unknown-surface px-1.5 py-0.2 rounded border border-threat-unknown-border">
            <HelpCircle className="w-2.5 h-2.5" />
            UNKNOWN
          </span>
        );
    }
  };

  const sizeStyles = {
    xs: 'text-[10px] px-1.5 py-0.5 gap-1',
    sm: 'text-[11px] px-2 py-0.5 gap-1.5',
    md: 'text-xs px-2.5 py-1 gap-2',
  }[size];

  return (
    <span
      className={cn(
        'inline-flex items-center rounded border border-border bg-surface-secondary/60 font-mono text-foreground font-medium select-none group',
        sizeStyles,
        className
      )}
      title={`IOC: ${value}${type ? ` (${type})` : ''}`}
      {...props}
    >
      {type && (
        <span className="text-[10px] font-sans uppercase tracking-wider text-foreground-muted font-normal">
          {type}:
        </span>
      )}

      <span className="font-mono text-foreground select-text">{displayValue}</span>

      {getReputationBadge()}

      {copyable && (
        <button
          type="button"
          onClick={handleCopy}
          className="text-foreground-muted hover:text-primary ml-0.5 p-0.5 rounded focus:outline-none focus:ring-1 focus:ring-focus"
          title={copied ? 'Copied original value to clipboard' : 'Copy IOC value'}
          aria-label={`Copy IOC ${value}`}
        >
          {copied ? (
            <Check className="w-3 h-3 text-threat-safe" />
          ) : (
            <Copy className="w-3 h-3 opacity-60 hover:opacity-100" />
          )}
        </button>
      )}
    </span>
  );
};
