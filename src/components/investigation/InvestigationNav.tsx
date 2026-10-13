import React from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Compass,
  Cpu,
  GitBranch,
  Network,
  Clock,
  FileText,
  Globe2,
  ShieldAlert,
  FileCheck,
  Bot,
} from 'lucide-react';
import type {
  InvestigationWorkspaceSection,
  InvestigationCountsModel,
} from '../../types/investigationWorkspace';

export interface WorkspaceTabConfig {
  id: InvestigationWorkspaceSection;
  label: string;
  icon: React.FC<{ className?: string }>;
  description: string;
  countKey?: keyof InvestigationCountsModel;
}

export const WORKSPACE_TABS: WorkspaceTabConfig[] = [
  {
    id: 'overview',
    label: 'Overview',
    icon: Compass,
    description: 'Executive threat summary, primary drivers, top findings and next steps',
  },
  {
    id: 'analysis',
    label: 'Analysis',
    icon: Cpu,
    description: 'Forensic inspection, live DAG pipeline, indicators and progressive disclosure',
    countKey: 'findings_count',
  },
  {
    id: 'attack-path',
    label: 'Attack Path',
    icon: GitBranch,
    description: 'Tactical attack reconstruction, stages, transitions and confidence gaps',
    countKey: 'attack_paths_count',
  },
  {
    id: 'graph',
    label: 'Graph',
    icon: Network,
    description: 'Security Knowledge Graph entities, relationships, and cross-incident connections',
  },
  {
    id: 'timeline',
    label: 'Timeline',
    icon: Clock,
    description: 'Forensic event sequence, timestamps, source provenance, and telemetry order',
    countKey: 'timeline_events_count',
  },
  {
    id: 'evidence',
    label: 'Evidence',
    icon: FileText,
    description: 'Immutable original artifacts, SHA-256 verification and derived evidence signals',
    countKey: 'evidence_count',
  },
  {
    id: 'intelligence',
    label: 'Intelligence',
    icon: Globe2,
    description: 'Threat memory, domain/IP telemetry, WHOIS, DNS and infrastructure attribution',
    countKey: 'indicators_count',
  },
  {
    id: 'response',
    label: 'Response',
    icon: ShieldAlert,
    description: 'Containment recommendations, defensive playbooks and approval workflows',
    countKey: 'response_actions_count',
  },
  {
    id: 'report',
    label: 'Report',
    icon: FileCheck,
    description: 'Forensic case dossier, findings summary and executive export',
  },
  {
    id: 'automation',
    label: 'Automation',
    icon: Bot,
    description: 'Automated workflow execution, gated approvals, telemetry audit & gaps',
  },
];

import type { InvestigationSection } from '../../context/InvestigationContext';

interface InvestigationNavProps {
  activeSection: InvestigationSection | string;
  investigationId: string;
  counts?: InvestigationCountsModel;
  onSelectSection?: (section: InvestigationSection) => void;
}

export const InvestigationNav: React.FC<InvestigationNavProps> = ({
  activeSection,
  investigationId,
  counts,
  onSelectSection,
}) => {
  const navigate = useNavigate();

  const handleTabClick = (sectionId: InvestigationWorkspaceSection) => {
    if (onSelectSection) {
      onSelectSection(sectionId);
    } else {
      const targetId = investigationId || 'current';
      if (sectionId === 'overview') {
        navigate(`/investigations/${encodeURIComponent(targetId)}`);
      } else {
        navigate(`/investigations/${encodeURIComponent(targetId)}/${sectionId}`);
      }
    }
  };

  return (
    <nav
      aria-label="Investigation Workspace Navigation"
      className="cg-workspace-tabs border-b border-border mb-6"
    >
      <div className="flex flex-wrap items-center gap-1">
        {WORKSPACE_TABS.map(tab => {
          const isActive = activeSection === tab.id;
          const Icon = tab.icon;
          const count = tab.countKey && counts ? counts[tab.countKey] : undefined;

          return (
            <button
              key={tab.id}
              type="button"
              aria-current={isActive ? "page" : undefined}
              
              onClick={() => handleTabClick(tab.id)}
              title={tab.description}
              className={`flex items-center space-x-2 px-3 py-2 rounded-control text-xs font-mono font-medium transition-all cursor-pointer select-none focus:outline-hidden focus:ring-1 focus:ring-primary ${
                isActive
                  ? 'cg-tab-active text-foreground font-semibold'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
              }`}
            >
              <Icon className={`w-3.5 h-3.5 shrink-0 ${isActive ? 'text-primary' : 'text-foreground-muted'}`} />
              <span className="whitespace-nowrap">{tab.label}</span>
              {count !== undefined && count > 0 && (
                <span
                  className={`px-1.5 py-0.2 rounded-full text-[10px] font-mono shrink-0 ${
                    isActive
                      ? 'bg-primary text-primary-foreground font-semibold'
                      : 'bg-surface-secondary text-foreground-muted border border-border'
                  }`}
                >
                  {count}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
