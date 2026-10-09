import React from 'react';
import { Terminal, Cloud, Radio, Mail, Database, Cpu } from 'lucide-react';
import { cn } from '../../utils/cn';

export type SourceType = 'agent' | 'cloud' | 'network' | 'email' | 'intel' | 'system' | 'custom';

export interface SourceBadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  source: string;
  type?: SourceType;
  version?: string;
  detector?: string;
  size?: 'xs' | 'sm' | 'md';
}

export const SourceBadge: React.FC<SourceBadgeProps> = ({
  source,
  type = 'system',
  version,
  detector,
  size = 'sm',
  className,
  ...props
}) => {
  const getSourceIcon = () => {
    switch (type) {
      case 'agent':
        return <Cpu className="w-3 h-3 flex-shrink-0" />;
      case 'cloud':
        return <Cloud className="w-3 h-3 flex-shrink-0" />;
      case 'network':
        return <Radio className="w-3 h-3 flex-shrink-0" />;
      case 'email':
        return <Mail className="w-3 h-3 flex-shrink-0" />;
      case 'intel':
        return <Database className="w-3 h-3 flex-shrink-0" />;
      case 'system':
      default:
        return <Terminal className="w-3 h-3 flex-shrink-0" />;
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
        'inline-flex items-center rounded-badge border border-border bg-surface-secondary/50 font-mono text-foreground-secondary select-none transition-colors hover:border-border-strong',
        sizeStyles,
        className
      )}
      title={`Telemetry Source: ${source}${detector ? ` | Detector: ${detector}` : ''}${version ? ` (v${version})` : ''}`}
      {...props}
    >
      <span className="text-foreground-muted">{getSourceIcon()}</span>
      <span className="font-medium text-foreground">{source}</span>

      {detector && (
        <span className="text-[10px] text-foreground-muted border-l border-border pl-1.5 font-sans">
          {detector}
        </span>
      )}

      {version && (
        <span className="text-[10px] text-foreground-muted font-mono opacity-80">
          v{version}
        </span>
      )}
    </span>
  );
};
