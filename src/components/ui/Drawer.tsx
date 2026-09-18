import React, { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { X } from 'lucide-react';
import { cn } from '../../utils/cn';
import { IconButton } from './IconButton';

export type DrawerSize = 'sm' | 'md' | 'lg' | 'xl' | 'full';

export interface DrawerProps {
  isOpen: boolean;
  onClose: () => void;
  title?: React.ReactNode;
  description?: React.ReactNode;
  headerActions?: React.ReactNode;
  footer?: React.ReactNode;
  size?: DrawerSize;
  closeOnOverlayClick?: boolean;
  closeOnEsc?: boolean;
  children: React.ReactNode;
  className?: string;
}

export const Drawer: React.FC<DrawerProps> = ({
  isOpen,
  onClose,
  title,
  description,
  headerActions,
  footer,
  size = 'md',
  closeOnOverlayClick = true,
  closeOnEsc = true,
  children,
  className,
}) => {
  const drawerRef = useRef<HTMLDivElement>(null);

  // Close on Escape key
  useEffect(() => {
    if (!isOpen || !closeOnEsc) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, closeOnEsc, onClose]);

  // Lock body scroll while drawer is open
  useEffect(() => {
    if (!isOpen || typeof document === 'undefined') return;

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    return () => {
      document.body.style.overflow = originalOverflow;
    };
  }, [isOpen]);

  if (!isOpen || typeof document === 'undefined') return null;

  const sizeClasses: Record<DrawerSize, string> = {
    sm: 'max-w-md w-full',
    md: 'max-w-lg w-full sm:w-[500px]',
    lg: 'max-w-2xl w-full sm:w-[600px]',
    xl: 'max-w-4xl w-full sm:w-[800px]',
    full: 'w-screen max-w-none',
  };

  const drawerContent = (
    <div className="fixed inset-0 z-50 flex justify-end animate-in fade-in duration-150">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-xs transition-opacity cursor-pointer"
        onClick={closeOnOverlayClick ? onClose : undefined}
        aria-label="Close drawer backdrop"
      />

      {/* Drawer Shell */}
      <div
        ref={drawerRef}
        role="dialog"
        aria-modal="true"
        className={cn(
          'relative h-full bg-surface border-l border-border shadow-2xl flex flex-col z-10',
          'drawer-enter',
          sizeClasses[size],
          className
        )}
      >
        {/* Drawer Header */}
        {(title || description || headerActions) && (
          <div className="px-4 py-3 sm:px-5 sm:py-3.5 border-b border-border bg-surface-secondary/60 flex items-center justify-between gap-3 shrink-0">
            <div className="min-w-0 flex-1 space-y-0.5">
              {title && (
                <div className="text-sm font-sans font-bold text-foreground leading-snug truncate">
                  {title}
                </div>
              )}
              {description && (
                <div className="text-xs font-sans text-foreground-muted line-clamp-1">
                  {description}
                </div>
              )}
            </div>

            <div className="flex items-center space-x-1.5 shrink-0">
              {headerActions}
              <IconButton
                aria-label="Close drawer (Esc)"
                variant="ghost"
                size="sm"
                icon={<X className="w-4 h-4" />}
                onClick={onClose}
              />
            </div>
          </div>
        )}

        {/* Drawer Body Content */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-5 space-y-4">
          {children}
        </div>

        {/* Optional Drawer Footer */}
        {footer && (
          <div className="px-4 py-3 sm:px-5 sm:py-3.5 border-t border-border bg-surface-secondary/40 shrink-0 flex items-center justify-end gap-2.5">
            {footer}
          </div>
        )}
      </div>
    </div>
  );

  return createPortal(drawerContent, document.body);
};
