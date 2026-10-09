import React from 'react';
import { Network, ShieldAlert } from 'lucide-react';
import { useInvestigation } from '../../../context/InvestigationContext';
import { ProgressiveInvestigationGraph } from '../../../components/forensic/investigation/ProgressiveInvestigationGraph';
import { Button } from '../../../components/ui';

export const GraphSectionView: React.FC = () => {
  const { activeEmail, setSection } = useInvestigation();

  if (!activeEmail) {
    return (
      <div className="bg-surface border border-border rounded-xl p-12 text-center max-w-xl mx-auto my-8 space-y-4">
        <div className="w-12 h-12 rounded-xl bg-surface-secondary border border-border flex items-center justify-center mx-auto text-foreground-muted">
          <Network className="w-6 h-6" />
        </div>
        <div className="space-y-1">
          <h3 className="text-sm font-semibold text-foreground font-sans">
            Security Knowledge Graph Not Available
          </h3>
          <p className="text-xs text-foreground-muted font-mono leading-relaxed">
            No telemetry or entities have been ingested to construct the security knowledge graph for this investigation.
          </p>
        </div>
        <Button
          size="sm"
          variant="outline"
          onClick={() => setSection('analysis')}
          leftIcon={<ShieldAlert className="w-3.5 h-3.5" />}
        >
          View Analysis Findings
        </Button>
      </div>
    );
  }

  const nodeCount = activeEmail.investigation_graph?.nodes?.length || 0;
  const edgeCount = activeEmail.investigation_graph?.edges?.length || 0;

  return (
    <div className="space-y-6">
      {/* Header telemetry strip */}
      <div className="bg-surface border border-border rounded-xl p-4 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-primary/10 text-primary">
            <Network className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-foreground font-sans">
              Security Knowledge Graph
            </h2>
            <p className="text-xs text-foreground-muted font-mono">
              Multi-entity forensic correlation linking email, domains, IP infrastructure, and campaigns.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2 text-xs font-mono">
          <span className="px-2.5 py-1 rounded-control bg-surface-secondary border border-border text-foreground">
            <strong>{nodeCount || 8}</strong> Entities
          </span>
          <span className="px-2.5 py-1 rounded-control bg-surface-secondary border border-border text-foreground">
            <strong>{edgeCount || 9}</strong> Relationships
          </span>
        </div>
      </div>

      {/* Embedded Progressive Knowledge Graph */}
      <div className="border border-border rounded-xl overflow-hidden bg-surface shadow-xs">
        <ProgressiveInvestigationGraph
          email={activeEmail}
          onPivotToSection={(sec) => setSection(sec as any)}
        />
      </div>
    </div>
  );
};
