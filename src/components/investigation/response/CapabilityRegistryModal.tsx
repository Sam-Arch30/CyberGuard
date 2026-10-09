import React, { useEffect } from 'react';
import {
  X,
  Server,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  HelpCircle,
} from 'lucide-react';
import type { ResponseCapability, CapabilityState } from '../../../types/response_recommendation';
import { Badge, Button } from '../../ui';


interface CapabilityRegistryModalProps {
  capabilities: ResponseCapability[];
  isOpen: boolean;
  onClose: () => void;
}

export const CapabilityRegistryModal: React.FC<CapabilityRegistryModalProps> = ({
  capabilities,
  isOpen,
  onClose,
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      window.addEventListener('keydown', handleKeyDown);
    }
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const getStateBadge = (state: CapabilityState) => {
    switch (state) {
      case 'AVAILABLE':
        return (
          <Badge variant="success" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <CheckCircle2 className="w-3 h-3" />
            <span>AVAILABLE</span>
          </Badge>
        );
      case 'REQUIRES_CONFIGURATION':
        return (
          <Badge variant="warning" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <AlertTriangle className="w-3 h-3" />
            <span>REQUIRES CONFIG</span>
          </Badge>
        );
      case 'UNAVAILABLE':
      case 'DISABLED':
        return (
          <Badge variant="danger" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <XCircle className="w-3 h-3" />
            <span>{state}</span>
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <HelpCircle className="w-3 h-3" />
            <span>UNKNOWN</span>
          </Badge>
        );
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 overflow-y-auto bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-150"
      role="dialog"
      aria-modal="true"
      aria-labelledby="capability-registry-title"
    >
      <div className="bg-surface border border-border rounded-xl shadow-2xl w-full max-w-3xl overflow-hidden flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="p-4 sm:p-5 border-b border-border bg-surface-secondary/40 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-primary/10 border border-primary/20 text-primary">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h2 id="capability-registry-title" className="text-sm font-semibold text-foreground font-sans">
                Defensive Capability Registry
              </h2>
              <p className="text-xs text-foreground-muted font-mono mt-0.5">
                Section 20 & 28 authoritative connector readiness & environment telemetry
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="p-1.5 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface-secondary transition-colors"
            aria-label="Close capability dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content list */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-3.5 divide-y divide-border/60">
          <p className="text-xs text-foreground-muted font-mono pb-2">
            Automated or analyst-approved execution is only permitted when the respective environment provider reports
            state <span className="text-success font-semibold">AVAILABLE</span>. Actions targeting unconfigured
            or offline connectors are safely suppressed to prevent silent failures.
          </p>

          {capabilities.map((cap) => (
            <div key={cap.id || cap.action_type} className="pt-3.5 first:pt-0 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-bold font-mono text-foreground">
                    {cap.action_type}
                  </span>
                  {getStateBadge(cap.capability_state)}
                  {cap.reversible && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-secondary border border-border text-foreground-muted">
                      Reversible
                    </span>
                  )}
                  {cap.approval_required && (
                    <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-warning/10 border border-warning/20 text-warning">
                      Approval Gated
                    </span>
                  )}
                </div>
                <div className="text-xs text-foreground-muted font-mono">
                  <span>Provider: </span>
                  <span className="text-foreground font-semibold">{cap.provider}</span>
                  <span className="mx-2">•</span>
                  <span>Env: {cap.environment}</span>
                </div>
                {cap.state_reason && (
                  <p className="text-xs text-foreground-muted font-sans italic">
                    {cap.state_reason}
                  </p>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-border bg-surface-secondary/30 flex justify-end">
          <Button variant="secondary" size="sm" onClick={onClose} className="font-mono text-xs">
            Dismiss
          </Button>
        </div>
      </div>
    </div>
  );
};
