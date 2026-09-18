import React from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface LoadingStateProps extends React.HTMLAttributes<HTMLDivElement> {
  message?: string;
  subtext?: string;
  size?: 'sm' | 'md' | 'lg';
  fullHeight?: boolean;
}

export const LoadingState: React.FC<LoadingStateProps> = ({
  message = 'Loading telemetry...',
  subtext,
  size = 'md',
  fullHeight = false,
  className,
  ...props
}) => {
  const iconSizes = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8',
  };

  return (
    <div
      role="status"
      aria-live="polite"
      className={cn(
        'flex flex-col items-center justify-center text-center p-6 select-none space-y-2.5',
        fullHeight ? 'min-h-[50vh]' : 'py-12',
        className
      )}
      {...props}
    >
      <Loader2 className={cn('text-primary animate-spin', iconSizes[size])} />
      <div className="space-y-0.5">
        <p className="text-xs font-mono font-medium text-foreground tracking-tight">{message}</p>
        {subtext && <p className="text-[11px] font-sans text-foreground-muted">{subtext}</p>}
      </div>
    </div>
  );
};
