import React, { createContext, useContext, useState, useCallback } from 'react';
import { AlertCircle, CheckCircle2, Info, AlertTriangle, X } from 'lucide-react';
import { cn } from '../../utils/cn';

export type ToastType = 'info' | 'success' | 'warning' | 'error';

export interface ToastItem {
  id: string;
  type: ToastType;
  title: string;
  message?: string;
  durationMs?: number;
}

interface ToastContextType {
  toast: (options: Omit<ToastItem, 'id'>) => void;
  removeToast: (id: string) => void;
}

const ToastContext = createContext<ToastContextType | undefined>(undefined);

export const ToastProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const toast = useCallback(({ type = 'info', title, message, durationMs = 4000 }: Omit<ToastItem, 'id'>) => {
    const id = `toast_${Date.now()}_${performance.now().toString(36).replace('.', '_')}`;
    setToasts((prev) => [...prev, { id, type, title, message, durationMs }]);

    if (durationMs > 0) {
      setTimeout(() => {
        removeToast(id);
      }, durationMs);
    }
  }, [removeToast]);

  const icons = {
    info: <Info className="w-4 h-4 text-info flex-shrink-0" />,
    success: <CheckCircle2 className="w-4 h-4 text-success flex-shrink-0" />,
    warning: <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0" />,
    error: <AlertCircle className="w-4 h-4 text-danger flex-shrink-0" />,
  };

  const borders = {
    info: 'border-info-border bg-surface-elevated',
    success: 'border-success-border bg-surface-elevated',
    warning: 'border-warning-border bg-surface-elevated',
    error: 'border-danger-border bg-surface-elevated',
  };

  return (
    <ToastContext.Provider value={{ toast, removeToast }}>
      {children}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col space-y-2 pointer-events-none max-w-sm w-full">
        {toasts.map((t) => (
          <div
            key={t.id}
            role="status"
            className={cn(
              'pointer-events-auto p-3.5 rounded-card border shadow-popover flex items-start space-x-3 text-xs transition-all animate-in slide-in-from-bottom-2 duration-200',
              borders[t.type]
            )}
          >
            <div className="pt-0.5">{icons[t.type]}</div>
            <div className="flex-1 min-w-0">
              <span className="font-bold font-sans text-foreground block leading-tight">{t.title}</span>
              {t.message && <span className="text-[11px] font-mono text-foreground-muted block mt-0.5">{t.message}</span>}
            </div>
            <button
              type="button"
              onClick={() => removeToast(t.id)}
              className="text-foreground-muted hover:text-foreground p-0.5 rounded cursor-pointer"
              aria-label="Dismiss toast"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
};

export const useToast = (): ToastContextType => {
  const context = useContext(ToastContext);
  if (!context) {
    throw new Error('useToast must be used within a ToastProvider');
  }
  return context;
};
