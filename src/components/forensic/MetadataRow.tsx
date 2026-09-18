import React from 'react';
import { CopyButton } from './CopyButton';

interface MetadataRowProps {
  label: string;
  value?: React.ReactNode;
  allowCopy?: boolean;
  isMonospace?: boolean;
}

export const MetadataRow: React.FC<MetadataRowProps> = ({
  label,
  value,
  allowCopy = false,
  isMonospace = true
}) => {
  const getDisplayValue = () => {
    if (value === null || value === undefined) return null;
    if (Array.isArray(value)) {
      return value.length > 0 ? value.join(', ') : null;
    }
    if (typeof value === 'string') {
      return value.trim() ? value : null;
    }
    return value;
  };

  const displayVal = getDisplayValue();
  const isAvailable = displayVal !== null && displayVal !== undefined;

  return (
    <div className="flex flex-col sm:flex-row sm:items-start justify-between py-2.5 px-3 rounded-control border border-border bg-surface-secondary/40 hover:bg-surface-secondary/70 transition-colors gap-2">
      <span className="text-xs font-mono font-semibold text-foreground-muted min-w-[120px] shrink-0 pt-0.5">
        {label}
      </span>

      <div className="flex-1 flex items-center justify-between min-w-0 gap-2">
        <span
          className={`text-xs break-all ${
            isAvailable
              ? isMonospace
                ? 'font-mono text-foreground'
                : 'text-foreground font-sans'
              : 'text-foreground-subtle italic font-mono'
          }`}
        >
          {isAvailable ? displayVal : 'Not available'}
        </span>

        {isAvailable && allowCopy && typeof displayVal === 'string' && (
          <CopyButton text={displayVal} iconOnly className="shrink-0" />
        )}
      </div>
    </div>
  );
};
