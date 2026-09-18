import React, { useState, useMemo } from 'react';
import { Copy, Check, WrapText } from 'lucide-react';

interface RawEvidenceViewerProps {
  data: any;
  format?: 'json' | 'text' | 'headers';
  title?: string;
  maxHeight?: string;
  className?: string;
}

export const RawEvidenceViewer: React.FC<RawEvidenceViewerProps> = ({
  data,
  format = 'json',
  title,
  maxHeight = '420px',
  className = ''
}) => {
  const [copied, setCopied] = useState(false);
  const [wrapLines, setWrapLines] = useState(true);

  const formattedContent = useMemo(() => {
    if (data === null || data === undefined) return 'No raw evidence data available.';
    if (typeof data === 'string') return data;
    try {
      return JSON.stringify(data, null, 2);
    } catch {
      return String(data);
    }
  }, [data]);

  const handleCopy = () => {
    navigator.clipboard.writeText(formattedContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const lineCount = formattedContent.split('\n').length;

  return (
    <div className={`rounded-xl border border-border bg-surface-secondary/80 overflow-hidden font-mono text-xs ${className}`}>
      {/* Header Bar */}
      <div className="flex items-center justify-between px-3 py-2 bg-surface border-b border-border text-[11px] text-foreground-muted">
        <div className="flex items-center space-x-2 truncate">
          <span className="font-bold text-foreground uppercase tracking-wider text-[10px]">
            {title || (format === 'json' ? 'Raw JSON Payload' : format === 'headers' ? 'Raw RFC-822 Headers' : 'Raw Text Evidence')}
          </span>
          <span className="text-[10px] text-foreground-subtle">
            ({lineCount} line{lineCount !== 1 ? 's' : ''}, {new Blob([formattedContent]).size} bytes)
          </span>
        </div>

        <div className="flex items-center space-x-1.5 shrink-0">
          <button
            type="button"
            onClick={() => setWrapLines(!wrapLines)}
            className={`p-1 rounded hover:bg-surface-secondary transition-colors cursor-pointer ${
              wrapLines ? 'text-primary' : 'text-foreground-muted'
            }`}
            title={wrapLines ? 'Disable line wrap' : 'Enable line wrap'}
          >
            <WrapText className="w-3.5 h-3.5" />
          </button>

          <button
            type="button"
            onClick={handleCopy}
            className="flex items-center space-x-1 px-2 py-0.5 rounded bg-surface hover:bg-surface-secondary border border-border text-foreground transition-colors cursor-pointer"
            title="Copy raw evidence to clipboard"
          >
            {copied ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
            <span className="text-[10px] font-semibold">{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>
      </div>

      {/* Code Display Area */}
      <div
        style={{ maxHeight }}
        className="overflow-auto p-3.5 bg-neutral-950 text-neutral-100 dark:bg-neutral-950 dark:text-neutral-200 select-all"
      >
        <pre
          className={`font-mono text-[11px] leading-relaxed ${
            wrapLines ? 'whitespace-pre-wrap break-all' : 'whitespace-pre'
          }`}
        >
          {formattedContent}
        </pre>
      </div>
    </div>
  );
};
