import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Compass,
  Cpu,
  Globe2,
  FolderLock,
  FileCheck,
  CheckCircle2,
  Clock,
  AlertCircle,
  FileText
} from 'lucide-react';
import { cn } from '../../utils/cn';
import { useInvestigation, type InvestigationSection } from '../../context/InvestigationContext';

export type WorkflowStageId = 'ingestion' | 'analysis' | 'investigation' | 'response' | 'report';

export type WorkflowStageStatus =
  | 'NOT_STARTED'
  | 'IN_PROGRESS'
  | 'COMPLETED'
  | 'BLOCKED'
  | 'FAILED'
  | 'UNAVAILABLE';

export interface WorkflowStage {
  id: WorkflowStageId;
  label: string;
  stepNumber: string;
  status: WorkflowStageStatus;
  subSections: InvestigationSection[];
}

export interface InvestigationWorkflowNavProps {
  className?: string;
  compact?: boolean;
}

export const InvestigationWorkflowNav: React.FC<InvestigationWorkflowNavProps> = ({
  className,
  compact = false,
}) => {
  const { activeEmail, activeEmailId, activeSection, setSection } = useInvestigation();

  // Compute status for the 5 workflow stages from actual telemetry data
  const stages: WorkflowStage[] = React.useMemo(() => {
    const hasEmail = Boolean(activeEmail);
    const hasAnalysis = Boolean(activeEmail?.threat_score);
    const hasGraph = Boolean(activeEmail?.investigation_graph || activeEmail?.indicators);
    const hasReport = Boolean(activeEmail?.threat_score);

    return [
      {
        id: 'ingestion',
        label: 'Ingestion',
        stepNumber: '01',
        status: hasEmail ? 'COMPLETED' : 'NOT_STARTED',
        subSections: ['email'],
      },
      {
        id: 'analysis',
        label: 'Analysis',
        stepNumber: '02',
        status: hasAnalysis ? 'COMPLETED' : hasEmail ? 'IN_PROGRESS' : 'UNAVAILABLE',
        subSections: ['overview', 'email', 'analysis'],
      },
      {
        id: 'investigation',
        label: 'Investigation',
        stepNumber: '03',
        status: hasGraph ? 'COMPLETED' : hasAnalysis ? 'IN_PROGRESS' : 'UNAVAILABLE',
        subSections: ['intelligence', 'investigation'],
      },
      {
        id: 'response',
        label: 'Response',
        stepNumber: '04',
        status: hasAnalysis ? 'COMPLETED' : 'UNAVAILABLE',
        subSections: ['investigation'],
      },
      {
        id: 'report',
        label: 'Report',
        stepNumber: '05',
        status: hasReport ? 'COMPLETED' : 'UNAVAILABLE',
        subSections: ['report'],
      },
    ];
  }, [activeEmail]);

  // Section tabs within investigation workspace
  const sectionTabs = [
    { id: 'overview', label: 'Overview', icon: Compass },
    { id: 'email', label: 'Email Envelope', icon: FileText },
    { id: 'analysis', label: 'Payload & IOCs', icon: Cpu },
    { id: 'intelligence', label: 'OSINT & Infrastructure', icon: Globe2 },
    { id: 'investigation', label: 'Attack Path & Graph', icon: FolderLock },
    { id: 'report', label: 'Executive Dossier', icon: FileCheck },
  ] as const;

  const getStatusIcon = (status: WorkflowStageStatus) => {
    switch (status) {
      case 'COMPLETED':
        return <CheckCircle2 className="w-3 h-3 text-threat-safe" />;
      case 'IN_PROGRESS':
        return <Clock className="w-3 h-3 text-threat-high animate-pulse" />;
      case 'BLOCKED':
      case 'FAILED':
        return <AlertCircle className="w-3 h-3 text-threat-critical" />;
      default:
        return <span className="w-1.5 h-1.5 rounded-full bg-foreground-muted/40" />;
    }
  };

  // Determine current active workflow stage based on activeSection
  const currentStageId = React.useMemo(() => {
    if (activeSection === 'email') return 'ingestion';
    if (activeSection === 'overview' || activeSection === 'analysis') return 'analysis';
    if (activeSection === 'intelligence' || activeSection === 'investigation') return 'investigation';
    if (activeSection === 'report') return 'report';
    return 'analysis';
  }, [activeSection]);

  return (
    <div className={cn('space-y-3 select-none', className)}>
      {/* 1. High-Level 5-Stage Workflow Pipeline Strip */}
      {!compact && (
        <div className="bg-surface-secondary/40 border border-border rounded-control p-2">
          <div className="flex items-center justify-between overflow-x-auto gap-2">
            {stages.map((stage, idx) => {
              const isCurrent = stage.id === currentStageId;
              const isLast = idx === stages.length - 1;

              return (
                <React.Fragment key={stage.id}>
                  <div
                    className={cn(
                      'flex items-center gap-2 px-2.5 py-1 rounded text-xs font-mono transition-colors shrink-0',
                      isCurrent
                        ? 'bg-surface border border-border-strong text-foreground font-semibold shadow-xs'
                        : 'text-foreground-muted hover:text-foreground'
                    )}
                  >
                    <span className="text-[10px] opacity-60 font-semibold">{stage.stepNumber}</span>
                    <span className="font-sans font-medium">{stage.label}</span>
                    {getStatusIcon(stage.status)}
                  </div>

                  {!isLast && (
                    <div className="w-4 h-px bg-border-strong shrink-0 hidden sm:block opacity-60" />
                  )}
                </React.Fragment>
              );
            })}
          </div>
        </div>
      )}

      {/* 2. Contextual Sub-Navigation Tabs */}
      <div className="flex items-center border-b border-border space-x-1 overflow-x-auto">
        {sectionTabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeSection === tab.id;
          const targetUrl = activeEmailId
            ? `/investigations/${activeEmailId}/${tab.id}`
            : `/investigations/${tab.id}`;

          return (
            <NavLink
              key={tab.id}
              to={targetUrl}
              onClick={() => setSection(tab.id as InvestigationSection)}
              className={cn(
                'inline-flex items-center gap-2 px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors shrink-0 cursor-pointer',
                isActive
                  ? 'border-primary text-primary font-semibold'
                  : 'border-transparent text-foreground-muted hover:text-foreground hover:border-border'
              )}
            >
              <Icon className={cn('w-3.5 h-3.5', isActive ? 'text-primary' : 'text-foreground-muted')} />
              <span>{tab.label}</span>
            </NavLink>
          );
        })}
      </div>
    </div>
  );
};

export default InvestigationWorkflowNav;
