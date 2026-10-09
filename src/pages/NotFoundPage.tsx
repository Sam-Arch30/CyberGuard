import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, ArrowLeft, Home } from 'lucide-react';
import { Button } from '../components/ui';

export const NotFoundPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-[60vh] flex items-center justify-center p-6 select-none">
      <div className="max-w-md w-full p-8 rounded-card border border-border bg-surface text-center space-y-4 shadow-xs">
        <div className="w-12 h-12 rounded-control bg-surface-secondary border border-border flex items-center justify-center text-foreground-muted mx-auto">
          <ShieldAlert className="w-6 h-6 text-threat-unknown" />
        </div>

        <div className="space-y-1.5">
          <span className="text-[10px] font-mono uppercase tracking-widest text-primary font-semibold">
            ERROR 404
          </span>
          <h1 className="text-xl font-bold font-sans text-foreground">Page Not Found</h1>
          <p className="text-xs font-mono text-foreground-muted leading-relaxed">
            The requested CyberGuard route does not exist or has been relocated to another workspace.
          </p>
        </div>

        <div className="pt-2 flex items-center justify-center gap-3">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigate(-1)}
            leftIcon={<ArrowLeft className="w-3.5 h-3.5" />}
          >
            Go Back
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/dashboard')}
            leftIcon={<Home className="w-3.5 h-3.5" />}
          >
            Return to Dashboard
          </Button>
        </div>
      </div>
    </div>
  );
};

export default NotFoundPage;
