import React, { useEffect } from 'react';
import { X, FileCode, Shield } from 'lucide-react';
import { RawEvidenceViewer } from './RawEvidenceViewer';

interface DetailDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  data?: any;
  format?: 'json' | 'text' | 'headers';
  children?: React.ReactNode;
}

export const DetailDrawer: React.FC<DetailDrawerProps> = ({
  isOpen,
  onClose,
  title,
  subtitle,
  data,
  format = 'json',
  children
}) => {
  // Listen for Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end animate-fadeIn"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-neutral-950/60 xl:bg-neutral-950/20 xl:backdrop-blur-none backdrop-blur-xs transition-opacity cursor-pointer"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer Container */}
      <div className="relative w-full max-w-2xl bg-surface border-l border-border h-full shadow-2xl flex flex-col z-10 animate-slideLeft">
        {/* Header */}
        <div className="flex items-start justify-between p-5 border-b border-border bg-surface-secondary/50">
          <div className="space-y-1 min-w-0 pr-4">
            <div className="flex items-center space-x-2">
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold tracking-wider uppercase bg-primary/10 text-primary border border-primary/20 flex items-center gap-1">
                <FileCode className="w-3 h-3" />
                <span>Level 3 · Raw Evidence</span>
              </span>
            </div>
            <h3 className="text-base font-bold text-foreground truncate">
              {title}
            </h3>
            {subtitle && (
              <p className="text-xs text-foreground-muted font-mono">
                {subtitle}
              </p>
            )}
          </div>

          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-transparent hover:border-border transition-colors cursor-pointer shrink-0"
            title="Close drawer (Esc)"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-4 font-mono text-xs">
          {children}

          {data !== undefined && data !== null && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-[11px] text-foreground-muted">
                <span className="font-semibold text-foreground uppercase tracking-wider text-[10px] flex items-center gap-1.5">
                  <Shield className="w-3.5 h-3.5 text-primary" />
                  <span>Verbatim Forensic Trace</span>
                </span>
              </div>
              <RawEvidenceViewer
                data={data}
                format={format}
                maxHeight="520px"
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border bg-surface-secondary/40 flex items-center justify-between text-[11px] text-foreground-muted">
          <span>Press <kbd className="px-1.5 py-0.5 rounded bg-surface border border-border text-foreground font-mono text-[10px]">Esc</kbd> to exit</span>
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-1.5 rounded-lg bg-surface hover:bg-surface-secondary border border-border text-foreground text-xs font-semibold cursor-pointer transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
};
