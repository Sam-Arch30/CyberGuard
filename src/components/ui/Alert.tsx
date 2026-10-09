import React from 'react';
import { AlertTriangle, AlertCircle, CheckCircle2, Info, X } from 'lucide-react';
import { cn } from '../../utils/cn';

export type AlertVariant = 'info' | 'warning' | 'danger' | 'success' | 'neutral';

export interface AlertProps extends Omit<React.HTMLAttributes<HTMLDivElement>, 'title'> {
  variant?: AlertVariant;
  title?: React.ReactNode;
  icon?: React.ReactNode;
  onDismiss?: () => void;
  action?: React.ReactNode;
}

export const Alert = React.forwardRef<HTMLDivElement, AlertProps>(
  ({ className, variant = 'info', title, icon, onDismiss, action, children, ...props }, ref) => {
    const defaultIcons = {
      info: <Info className="w-4 h-4 text-info flex-shrink-0" />,
      warning: <AlertTriangle className="w-4 h-4 text-warning flex-shrink-0" />,
      danger: <AlertCircle className="w-4 h-4 text-danger flex-shrink-0" />,
      success: <CheckCircle2 className="w-4 h-4 text-success flex-shrink-0" />,
      neutral: <Info className="w-4 h-4 text-foreground-muted flex-shrink-0" />,
    };

    const variants = {
      info: 'bg-info-surface border-info-border text-info-foreground',
      warning: 'bg-warning-surface border-warning-border text-warning-foreground',
      danger: 'bg-danger-surface border-danger-border text-danger-foreground',
      success: 'bg-success-surface border-success-border text-success-foreground',
      neutral: 'bg-surface-secondary border-border text-foreground',
    }[variant];

    return (
      <div
        ref={ref}
        role="alert"
        className={cn(
          'p-3 sm:p-3.5 rounded-card border flex items-start space-x-3 transition-colors text-xs',
          variants,
          className
        )}
        {...props}
      >
        <div className="pt-0.5">{icon || defaultIcons[variant]}</div>

        <div className="flex-1 min-w-0">
          {title && <h5 className="font-bold font-sans text-xs mb-0.5">{title}</h5>}
          <div className="text-[11px] leading-relaxed opacity-95">{children}</div>
          {action && <div className="mt-2">{action}</div>}
        </div>

        {onDismiss && (
          <button
            type="button"
            onClick={onDismiss}
            className="p-1 rounded-control hover:bg-foreground/10 text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
            aria-label="Dismiss alert"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    );
  }
);

Alert.displayName = 'Alert';
