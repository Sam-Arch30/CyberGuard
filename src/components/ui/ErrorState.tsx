import React from 'react';
import { AlertCircle, RotateCcw } from 'lucide-react';
import { cn } from '../../utils/cn';
import { Button } from './Button';

export interface ErrorStateProps extends React.HTMLAttributes<HTMLDivElement> {
  title?: string;
  message?: string;
  onRetry?: () => void;
  action?: React.ReactNode;
  variant?: 'card' | 'inline' | 'banner';
}

export const ErrorState: React.FC<ErrorStateProps> = ({
  title = 'Investigation Error',
  message = 'An unexpected error occurred while processing forensic telemetry.',
  onRetry,
  action,
  variant = 'card',
  className,
  ...props
}) => {
  if (variant === 'banner') {
    return (
      <div
        role="alert"
        className={cn(
          'p-3 rounded-control bg-danger-surface border border-danger-border flex items-center justify-between gap-3 text-xs',
          className
        )}
        {...props}
      >
        <div className="flex items-center space-x-2.5 min-w-0">
          <AlertCircle className="w-4 h-4 text-danger shrink-0" />
          <div className="min-w-0">
            <span className="font-semibold text-danger">{title}: </span>
            <span className="text-foreground-muted">{message}</span>
          </div>
        </div>
        {onRetry && (
          <Button
            size="xs"
            variant="secondary"
            onClick={onRetry}
            leftIcon={<RotateCcw className="w-3 h-3 text-danger" />}
          >
            Retry
          </Button>
        )}
      </div>
    );
  }

  if (variant === 'inline') {
    return (
      <div
        role="alert"
        className={cn('flex items-center space-x-2 text-xs font-mono text-danger py-2', className)}
        {...props}
      >
        <AlertCircle className="w-4 h-4 text-danger shrink-0" />
        <span className="truncate">{message}</span>
      </div>
    );
  }

  // Card Variant
  return (
    <div
      role="alert"
      className={cn(
        'max-w-md mx-auto my-8 p-6 bg-surface border border-danger-border rounded-card text-center space-y-3.5 shadow-xs select-none',
        className
      )}
      {...props}
    >
      <div className="w-10 h-10 rounded-control bg-danger-surface border border-danger-border flex items-center justify-center text-danger mx-auto">
        <AlertCircle className="w-5 h-5" />
      </div>

      <div className="space-y-1">
        <h4 className="text-sm font-bold font-sans text-foreground leading-snug">{title}</h4>
        <p className="text-xs font-mono text-foreground-muted max-w-sm mx-auto leading-relaxed">
          {message}
        </p>
      </div>

      {(onRetry || action) && (
        <div className="pt-2 flex items-center justify-center gap-2">
          {onRetry && (
            <Button
              size="sm"
              variant="secondary"
              onClick={onRetry}
              leftIcon={<RotateCcw className="w-3.5 h-3.5 text-danger" />}
            >
              Retry
            </Button>
          )}
          {action}
        </div>
      )}
    </div>
  );
};
