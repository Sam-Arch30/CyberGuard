import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { ChevronRight, Home } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface BreadcrumbItem {
  label: string;
  path?: string;
  isIdentifier?: boolean;
}

export interface BreadcrumbsProps {
  items?: BreadcrumbItem[];
  className?: string;
}

export const Breadcrumbs: React.FC<BreadcrumbsProps> = ({ items, className }) => {
  const location = useLocation();

  // If items are not explicitly provided, auto-derive from current location pathname
  const derivedItems: BreadcrumbItem[] = React.useMemo(() => {
    if (items && items.length > 0) return items;

    const pathSegments = location.pathname.split('/').filter(Boolean);
    if (pathSegments.length <= 1 && (pathSegments[0] === 'dashboard' || pathSegments.length === 0)) {
      return [];
    }

    const breadcrumbs: BreadcrumbItem[] = [
      { label: 'CyberGuard', path: '/dashboard' }
    ];

    let currentPath = '';
    pathSegments.forEach((segment, idx) => {
      currentPath += `/${segment}`;
      const isLast = idx === pathSegments.length - 1;

      // Clean format label
      let label = segment.charAt(0).toUpperCase() + segment.slice(1);
      const isIdentifier = segment.includes('-') || segment.length >= 10 || !isNaN(Number(segment));

      if (segment.toLowerCase() === 'investigate' || segment.toLowerCase() === 'investigations') {
        label = 'Investigations';
      } else if (segment.toLowerCase() === 'attack-path') {
        label = 'Attack Path';
      } else if (segment.toLowerCase() === 'auth-security') {
        label = 'Auth Security';
      } else if (segment.toLowerCase() === 'file-security') {
        label = 'File Security';
      } else if (segment.toLowerCase() === 'network-security') {
        label = 'Network Security';
      } else if (segment.toLowerCase() === 'url-intelligence') {
        label = 'URL Intel';
      } else if (segment.toLowerCase() === 'cross-investigation') {
        label = 'Cross Investigation';
      }

      breadcrumbs.push({
        label,
        path: isLast ? undefined : currentPath,
        isIdentifier
      });
    });

    return breadcrumbs;
  }, [items, location.pathname]);

  if (derivedItems.length <= 1) {
    return null;
  }

  return (
    <nav aria-label="Breadcrumb" className={cn('flex items-center text-xs select-none', className)}>
      <ol className="flex items-center space-x-1.5 flex-wrap">
        {derivedItems.map((item, index) => {
          const isLast = index === derivedItems.length - 1;

          return (
            <li key={index} className="flex items-center space-x-1.5">
              {index > 0 && (
                <ChevronRight className="w-3 h-3 text-foreground-muted flex-shrink-0 opacity-60" />
              )}

              {isLast ? (
                <span
                  aria-current="page"
                  className={cn(
                    'font-medium text-foreground',
                    item.isIdentifier ? 'font-mono font-semibold' : 'font-sans'
                  )}
                >
                  {item.label}
                </span>
              ) : item.path ? (
                <Link
                  to={item.path}
                  className={cn(
                    'text-foreground-muted hover:text-foreground transition-colors',
                    item.isIdentifier ? 'font-mono' : 'font-sans'
                  )}
                >
                  {index === 0 ? (
                    <span className="flex items-center gap-1">
                      <Home className="w-3 h-3 opacity-80" />
                      <span>{item.label}</span>
                    </span>
                  ) : (
                    item.label
                  )}
                </Link>
              ) : (
                <span className="text-foreground-muted">{item.label}</span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
};

export default Breadcrumbs;
