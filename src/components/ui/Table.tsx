import React from 'react';
import { cn } from '../../utils/cn';

export interface TableProps extends React.TableHTMLAttributes<HTMLTableElement> {
  compact?: boolean;
}

export const Table = React.forwardRef<HTMLTableElement, TableProps>(
  ({ className, compact = false, ...props }, ref) => (
    <div className="relative w-full overflow-auto rounded-control border border-border bg-surface">
      <table
        ref={ref}
        className={cn('w-full caption-bottom text-xs border-collapse text-left', compact && 'text-[11px]', className)}
        {...props}
      />
    </div>
  )
);
Table.displayName = 'Table';

export const TableHeader = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <thead
    ref={ref}
    className={cn('border-b border-border bg-surface-secondary/80 select-none text-[10px] font-mono font-semibold uppercase tracking-wider text-foreground-subtle', className)}
    {...props}
  />
));
TableHeader.displayName = 'TableHeader';

export const TableBody = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tbody
    ref={ref}
    className={cn('divide-y divide-border/50 [&_tr:last-child]:border-0', className)}
    {...props}
  />
));
TableBody.displayName = 'TableBody';

export const TableFooter = React.forwardRef<
  HTMLTableSectionElement,
  React.HTMLAttributes<HTMLTableSectionElement>
>(({ className, ...props }, ref) => (
  <tfoot
    ref={ref}
    className={cn('border-t border-border bg-surface-secondary/50 font-medium text-foreground-muted', className)}
    {...props}
  />
));
TableFooter.displayName = 'TableFooter';

export const TableRow = React.forwardRef<
  HTMLTableRowElement,
  React.HTMLAttributes<HTMLTableRowElement>
>(({ className, ...props }, ref) => (
  <tr
    ref={ref}
    className={cn(
      'border-b border-border/40 transition-colors hover:bg-surface-secondary/40 data-[state=selected]:bg-surface-secondary',
      className
    )}
    {...props}
  />
));
TableRow.displayName = 'TableRow';

export const TableHead = React.forwardRef<
  HTMLTableCellElement,
  React.ThHTMLAttributes<HTMLTableCellElement>
>(({ className, ...props }, ref) => (
  <th
    ref={ref}
    className={cn(
      'h-8 px-3 text-left align-middle font-mono text-[10px] uppercase font-semibold text-foreground-subtle tracking-wider select-none [&:has([role=checkbox])]:pr-0',
      className
    )}
    {...props}
  />
));
TableHead.displayName = 'TableHead';

export const TableCell = React.forwardRef<
  HTMLTableCellElement,
  React.TdHTMLAttributes<HTMLTableCellElement> & { monospace?: boolean }
>(({ className, monospace = false, ...props }, ref) => (
  <td
    ref={ref}
    className={cn(
      'py-2 px-3 align-middle text-foreground [&:has([role=checkbox])]:pr-0',
      monospace && 'font-mono text-[11px] font-feature-settings-tnum',
      className
    )}
    {...props}
  />
));
TableCell.displayName = 'TableCell';

export const TableCaption = React.forwardRef<
  HTMLTableCaptionElement,
  React.HTMLAttributes<HTMLTableCaptionElement>
>(({ className, ...props }, ref) => (
  <caption
    ref={ref}
    className={cn('mt-3 text-xs font-mono text-foreground-muted', className)}
    {...props}
  />
));
TableCaption.displayName = 'TableCaption';
