import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Topbar } from './Topbar';
import { SIHGuidedTour } from '../demo/SIHGuidedTour';
import { ErrorState } from '../ui';
import { cn } from '../../utils/cn';

interface ErrorBoundaryProps {
  children: React.ReactNode;
}

interface ErrorBoundaryState {
  hasError: boolean;
  error: Error | null;
}

export class AppShellErrorBoundary extends React.Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('CyberGuard Route Error:', error, errorInfo);
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 max-w-xl mx-auto my-12">
          <ErrorState
            title="Application Error"
            message={this.state.error?.message || 'An unexpected error occurred while rendering this view.'}
            onRetry={this.handleReset}
          />
        </div>
      );
    }
    return this.props.children;
  }
}

export interface AppShellProps {
  children: React.ReactNode;
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem('cyberguard_sidebar_collapsed') === 'true';
    } catch {
      return false;
    }
  });

  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const location = useLocation();

  // Close mobile sidebar on route change
  useEffect(() => {
    setMobileSidebarOpen(false);
  }, [location.pathname]);

  const handleToggleCollapse = () => {
    const next = !sidebarCollapsed;
    setSidebarCollapsed(next);
    try {
      localStorage.setItem('cyberguard_sidebar_collapsed', String(next));
    } catch {
      // Ignore storage errors
    }
  };

  // Full-width mode for investigation workspaces (Section 43)
  const isInvestigationWorkspace =
    location.pathname.startsWith('/investigations/') ||
    location.pathname.startsWith('/investigate/');

  return (
    <div className="min-h-screen bg-background text-foreground flex transition-colors duration-200">
      {/* 1. Permanent Minimal Sidebar */}
      <Sidebar
        collapsed={sidebarCollapsed}
        onToggleCollapse={handleToggleCollapse}
        mobileOpen={mobileSidebarOpen}
        onCloseMobile={() => setMobileSidebarOpen(false)}
      />

      {/* 2. Main Content Workspace Region */}
      <div
        className={cn(
          'flex-1 flex flex-col min-w-0 transition-all duration-200 pl-0',
          sidebarCollapsed ? 'md:pl-18' : 'md:pl-64'
        )}
      >
        {/* Topbar */}
        <Topbar onToggleMobileSidebar={() => setMobileSidebarOpen(!mobileSidebarOpen)} />

        {/* Main Content Area with Contextual Width */}
        <main
          className={cn(
            'flex-1 w-full mx-auto p-3 sm:p-5 lg:p-6 transition-all',
            isInvestigationWorkspace ? 'max-w-none' : 'max-w-[1600px]'
          )}
        >
          <AppShellErrorBoundary key={location.pathname}>
            <div className="page-enter">{children}</div>
          </AppShellErrorBoundary>
        </main>

        {/* SIH Guided Tour HUD */}
        <SIHGuidedTour />
      </div>
    </div>
  );
};

export default AppShell;
