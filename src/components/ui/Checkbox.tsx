import React, { useEffect, useRef } from 'react';
import { Check, Minus } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface CheckboxProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: React.ReactNode;
  description?: React.ReactNode;
  error?: string;
  indeterminate?: boolean;
}

export const Checkbox = React.forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, label, description, error, indeterminate, checked, disabled, id, ...props }, forwardedRef) => {
    const innerRef = useRef<HTMLInputElement>(null);
    const resolvedRef = (forwardedRef as React.RefObject<HTMLInputElement>) || innerRef;
    const generatedId = React.useId();
    const inputId = id || generatedId;

    useEffect(() => {
      if (resolvedRef.current) {
        resolvedRef.current.indeterminate = Boolean(indeterminate);
      }
    }, [indeterminate, resolvedRef]);

    return (
      <div className={cn('flex items-start space-x-2.5 select-none', disabled && 'opacity-50 cursor-not-allowed', className)}>
        <div className="relative flex items-center justify-center pt-0.5">
          <input
            ref={resolvedRef}
            type="checkbox"
            id={inputId}
            checked={checked}
            disabled={disabled}
            className="peer sr-only"
            {...props}
          />
          <label
            htmlFor={inputId}
            className={cn(
              'w-4 h-4 rounded-control-sm border transition-colors flex items-center justify-center cursor-pointer',
              'bg-surface border-border peer-focus-visible:ring-2 peer-focus-visible:ring-primary peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-background',
              'peer-checked:bg-primary peer-checked:border-primary peer-checked:text-primary-foreground',
              indeterminate && 'bg-primary border-primary text-primary-foreground',
              error && 'border-danger peer-focus-visible:ring-danger',
              disabled && 'pointer-events-none cursor-not-allowed'
            )}
          >
            {checked && !indeterminate && <Check className="w-3 h-3 stroke-[3]" />}
            {indeterminate && <Minus className="w-3 h-3 stroke-[3]" />}
          </label>
        </div>

        {(label || description || error) && (
          <div className="flex flex-col text-xs leading-tight">
            {label && (
              <label htmlFor={inputId} className="font-medium text-foreground cursor-pointer">
                {label}
              </label>
            )}
            {description && <span className="text-[11px] text-foreground-muted font-mono mt-0.5">{description}</span>}
            {error && <span className="text-[11px] text-danger font-mono mt-0.5">{error}</span>}
          </div>
        )}
      </div>
    );
  }
);

Checkbox.displayName = 'Checkbox';
