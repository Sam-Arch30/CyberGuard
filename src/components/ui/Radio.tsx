import React from 'react';
import { cn } from '../../utils/cn';

export interface RadioProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, 'type'> {
  label?: React.ReactNode;
  description?: React.ReactNode;
}

export const Radio = React.forwardRef<HTMLInputElement, RadioProps>(
  ({ className, label, description, checked, disabled, id, ...props }, ref) => {
    const generatedId = React.useId();
    const inputId = id || generatedId;

    return (
      <div className={cn('flex items-start space-x-2.5 select-none', disabled && 'opacity-50 cursor-not-allowed', className)}>
        <div className="relative flex items-center justify-center pt-0.5">
          <input
            ref={ref}
            type="radio"
            id={inputId}
            checked={checked}
            disabled={disabled}
            className="peer sr-only"
            {...props}
          />
          <label
            htmlFor={inputId}
            className={cn(
              'w-4 h-4 rounded-full border border-border transition-colors flex items-center justify-center cursor-pointer bg-surface',
              'peer-focus-visible:ring-2 peer-focus-visible:ring-primary peer-focus-visible:ring-offset-2 peer-focus-visible:ring-offset-background',
              'peer-checked:border-primary',
              disabled && 'pointer-events-none cursor-not-allowed'
            )}
          >
            {checked && <span className="w-2 h-2 rounded-full bg-primary" />}
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

Radio.displayName = 'Radio';

export interface RadioGroupProps {
  label?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  orientation?: 'vertical' | 'horizontal';
}

export const RadioGroup: React.FC<RadioGroupProps> = ({ label, children, className, orientation = 'vertical' }) => {
  return (
    <div className={cn('space-y-1.5', className)} role="radiogroup">
      {label && <span className="text-xs font-mono font-semibold text-foreground uppercase tracking-wider block mb-1">{label}</span>}
      <div className={cn('flex', orientation === 'vertical' ? 'flex-col space-y-2' : 'flex-row space-x-4 flex-wrap')}>
        {children}
      </div>
    </div>
  );
};
