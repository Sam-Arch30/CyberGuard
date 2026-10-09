import React, { useState } from 'react';
import {
  User,
  Globe,
  Hash,
  Laptop,
  Mail,
  Cpu,
  Link2,
  FileCode,
  Radio,
  Crosshair,
  Copy,
  Check,
  Shield,
} from 'lucide-react';
import { cn } from '../../utils/cn';

export type EntityType =
  | 'user'
  | 'ip'
  | 'domain'
  | 'hash'
  | 'host'
  | 'device'
  | 'email'
  | 'process'
  | 'url'
  | 'file'
  | 'port'
  | 'mitre'
  | 'generic';

export interface EntityChipProps extends React.HTMLAttributes<HTMLSpanElement> {
  type: EntityType | string;
  value: string;
  label?: string;
  copyable?: boolean;
  truncateLength?: number;
  size?: 'xs' | 'sm' | 'md';
}

export const EntityChip: React.FC<EntityChipProps> = ({
  type,
  value,
  label,
  copyable = false,
  truncateLength,
  size = 'sm',
  className,
  onClick,
  ...props
}) => {
  const [copied, setCopied] = useState(false);

  const normalizedType = type.toLowerCase() as EntityType;

  const getIcon = () => {
    switch (normalizedType) {
      case 'user':
        return <User className="w-3 h-3 flex-shrink-0" />;
      case 'ip':
        return <Globe className="w-3 h-3 flex-shrink-0" />;
      case 'domain':
        return <Globe className="w-3 h-3 flex-shrink-0" />;
      case 'hash':
        return <Hash className="w-3 h-3 flex-shrink-0" />;
      case 'host':
      case 'device':
        return <Laptop className="w-3 h-3 flex-shrink-0" />;
      case 'email':
        return <Mail className="w-3 h-3 flex-shrink-0" />;
      case 'process':
        return <Cpu className="w-3 h-3 flex-shrink-0" />;
      case 'url':
        return <Link2 className="w-3 h-3 flex-shrink-0" />;
      case 'file':
        return <FileCode className="w-3 h-3 flex-shrink-0" />;
      case 'port':
        return <Radio className="w-3 h-3 flex-shrink-0" />;
      case 'mitre':
        return <Crosshair className="w-3 h-3 flex-shrink-0" />;
      default:
        return <Shield className="w-3 h-3 flex-shrink-0" />;
    }
  };

  const displayValue = React.useMemo(() => {
    if (!truncateLength || value.length <= truncateLength) return value;
    const start = Math.floor((truncateLength - 3) / 2);
    const end = Math.ceil((truncateLength - 3) / 2);
    return `${value.slice(0, start)}...${value.slice(value.length - end)}`;
  }, [value, truncateLength]);

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
        'inline-flex items-center rounded border border-border bg-surface-secondary/50 font-mono text-foreground hover:bg-surface-secondary transition-colors select-none group',
        sizeStyles,
        onClick && 'cursor-pointer hover:border-primary/40',
        className
      )}
      title={`${type.toUpperCase()}: ${value}`}
      onClick={onClick}
      {...props}
    >
      <span className="text-foreground-muted group-hover:text-primary transition-colors">
        {getIcon()}
      </span>

      {label && (
        <span className="text-[10px] font-sans font-medium uppercase text-foreground-muted tracking-wider">
          {label}:
        </span>
      )}

      <span className="truncate max-w-[240px]">{displayValue}</span>

      {copyable && (
        <button
          type="button"
          onClick={handleCopy}
          className="text-foreground-muted hover:text-primary ml-0.5 p-0.5 rounded focus:outline-none focus:ring-1 focus:ring-focus"
          title={copied ? 'Copied to clipboard' : 'Copy value'}
          aria-label={`Copy ${value}`}
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
