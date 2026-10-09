import React, { useState } from 'react';
import { ChevronDown } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface AccordionItemProps {
  id: string;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  badge?: React.ReactNode;
  icon?: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}

export const AccordionItem: React.FC<AccordionItemProps> = ({
  title,
  subtitle,
  badge,
  icon,
  children,
  defaultOpen = false,
}) => {
  const [isOpen, setIsOpen] = useState(defaultOpen);

  return (
    <div className="border border-border rounded-control bg-surface overflow-hidden transition-colors">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-full px-3.5 py-2.5 flex items-center justify-between text-left hover:bg-surface-secondary/60 transition-colors cursor-pointer select-none"
        aria-expanded={isOpen}
      >
        <div className="flex items-center space-x-2.5 min-w-0 pr-2">
          {icon && <span className="text-foreground-muted flex-shrink-0">{icon}</span>}
          <div className="flex flex-col min-w-0">
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-foreground font-sans truncate">{title}</span>
              {badge}
            </div>
            {subtitle && <span className="text-[11px] font-mono text-foreground-muted truncate">{subtitle}</span>}
          </div>
        </div>
        <ChevronDown
          className={cn(
            'w-4 h-4 text-foreground-muted transition-transform duration-200 flex-shrink-0',
            isOpen && 'rotate-180 text-foreground'
          )}
        />
      </button>

      {isOpen && (
        <div className="px-3.5 py-3 border-t border-border-subtle bg-surface-secondary/20 text-xs text-foreground">
          {children}
        </div>
      )}
    </div>
  );
};

export interface AccordionProps {
  children: React.ReactNode;
  className?: string;
}

export const Accordion: React.FC<AccordionProps> = ({ children, className }) => {
  return <div className={cn('space-y-2', className)}>{children}</div>;
};
