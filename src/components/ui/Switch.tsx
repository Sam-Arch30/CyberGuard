import React from 'react';
import { cn } from '../../utils/cn';

export interface SwitchProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type' | 'size'> {
  label?: React.ReactNode;
  description?: React.ReactNode;
  size?: 'sm' | 'md';
}

export const Switch = React.forwardRef<HTMLInputElement, SwitchProps>(
  ({ className, label, description, size = 'md', checked, disabled, id, onChange, ...props }, ref) => {
    const generatedId = React.useId();
    const inputId = id || generatedId;

    const dimensions = {
      sm: { track: 'w-7 h-4', thumb: 'w-3 h-3', translate: 'translate-x-3' },
      md: { track: 'w-9 h-5', thumb: 'w-3.5 h-3.5', translate: 'translate-x-4' },
    }[size];

    return (
      <div className={cn('flex items-start space-x-2.5 select-none', disabled && 'opacity-50 cursor-not-allowed', className)}>
        <div className="relative inline-flex items-center pt-0.5">
          <input
            ref={ref}
            type="checkbox"
            role="switch"
            id={inputId}
            checked={checked}
            disabled={disabled}
            onChange={onChange}
            className="peer sr-only"
            {...props}
          />
          <label
            htmlFor={inputId}
            className={cn(
              'inline-flex items-center rounded-full border border-border transition-colors cursor-pointer p-0.5',
              'bg-surface-secondary peer-focus-visible:ring-2 peer-focus-visible:ring-primary peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-background',
              'peer-checked:bg-primary peer-checked:border-primary',
              disabled && 'pointer-events-none cursor-not-allowed',
              dimensions.track
            )}
          >
            <span
              className={cn(
                'rounded-full bg-foreground transition-transform transform shadow-xs block',
                checked ? `${dimensions.translate} bg-primary-foreground` : 'translate-x-0 bg-foreground-muted',
                dimensions.thumb
              )}
            />
          </label>
        </div>

        {(label || description) && (
          <div className="flex flex-col text-xs leading-tight">
            {label && (
              <label htmlFor={inputId} className="font-medium text-foreground cursor-pointer">
                {label}
              </label>
            )}
            {description && <span className="text-[11px] text-foreground-muted font-mono mt-0.5">{description}</span>}
          </div>
        )}
      </div>
    );
  }
);

Switch.displayName = 'Switch';
