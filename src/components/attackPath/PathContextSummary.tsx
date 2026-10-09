import React, { useState } from 'react';
import {
  Shield,
  Server,
  Globe,
  Info,
} from 'lucide-react';
import { Badge } from '../ui';
import type {
  AttackPathMitreTechnique,
  AttackPathInfrastructure,
} from '../../types/attackPath';

interface PathContextSummaryProps {
  mitreTechniques: AttackPathMitreTechnique[];
  infrastructure: AttackPathInfrastructure[];
}

export const PathContextSummary: React.FC<PathContextSummaryProps> = ({
  mitreTechniques,
  infrastructure,
}) => {
  const [activeTab, setActiveTab] = useState<'mitre' | 'infrastructure'>('mitre');

  const hasMitre = mitreTechniques && mitreTechniques.length > 0;
  const hasInfra = infrastructure && infrastructure.length > 0;

  if (!hasMitre && !hasInfra) {
    return null;
  }

  return (
    <div className="bg-surface border border-border rounded-xl p-4 shadow-xs space-y-4">
      {/* Tab Switcher */}
      <div className="flex items-center justify-between border-b border-border pb-3">
        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={() => setActiveTab('mitre')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer flex items-center space-x-1.5 ${
              activeTab === 'mitre'
                ? 'bg-accent/10 text-accent border border-accent/20'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Shield className="w-3.5 h-3.5" />
            <span>MITRE ATT&CK Matrix ({mitreTechniques.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab('infrastructure')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer flex items-center space-x-1.5 ${
              activeTab === 'infrastructure'
                ? 'bg-accent/10 text-accent border border-accent/20'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Server className="w-3.5 h-3.5" />
            <span>Observed Infrastructure ({infrastructure.length})</span>
          </button>
        </div>

        <span className="text-[10px] font-mono text-foreground-muted hidden sm:inline">
          {activeTab === 'mitre' ? 'TTP Classifications' : 'Network Intelligence'}
        </span>
      </div>

      {/* MITRE ATT&CK Tab Content */}
      {activeTab === 'mitre' && (
        <div className="space-y-3">
          <p className="text-[11px] font-mono text-foreground-muted leading-relaxed">
            Evidence-grounded technique mappings correlated to stages in the reconstructed attack path:
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {mitreTechniques.map((tech) => (
              <div
                key={tech.technique_id}
                className="p-3 rounded-lg bg-surface-secondary/70 border border-border space-y-1.5 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1.5">
                    <span className="font-bold text-accent">{tech.technique_id}</span>
                    <span className="text-foreground font-semibold truncate">{tech.technique_name}</span>
                  </div>
                  <Badge
                    variant={
                      tech.status === 'SUPPORTED'
                        ? 'success'
                        : tech.status === 'PLAUSIBLE'
                        ? 'primary'
                        : 'outline'
                    }
                    size="xs"
                    className="text-[9px] uppercase font-mono"
                  >
                    {tech.status}
                  </Badge>
                </div>

                <div className="flex flex-wrap gap-1 text-[10px] text-foreground-muted">
                  {tech.tactics.map((tac, i) => (
                    <span key={i} className="px-1.5 py-0.5 rounded bg-surface border border-border">
                      {tac}
                    </span>
                  ))}
                  <span className="px-1.5 py-0.5 rounded bg-surface border border-border">
                    {tech.evidence_count} Evidence Items
                  </span>
                </div>

                {tech.explanation && (
                  <p className="text-[11px] text-foreground-muted leading-relaxed pt-1 border-t border-border/50">
                    {tech.explanation}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Technical Infrastructure Tab Content */}
      {activeTab === 'infrastructure' && (
        <div className="space-y-3">
          {/* Strict Non-Human Attribution Banner */}
          <div className="p-3 rounded-lg bg-surface-secondary/80 border border-border text-xs font-mono text-foreground-muted flex items-start space-x-2">
            <Info className="w-4 h-4 text-accent shrink-0 mt-0.5" />
            <div className="space-y-0.5">
              <span className="font-semibold text-foreground uppercase tracking-wider text-[10px]">
                Technical Infrastructure Attribution Notice
              </span>
              <p className="text-[11px] leading-relaxed">
                Entities below represent observed network endpoints and hosting assets. CyberGuard does not infer human attacker identities or physical locations.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {infrastructure.map((inf) => (
              <div
                key={inf.id}
                className="p-3 rounded-lg bg-surface-secondary/70 border border-border space-y-2 text-xs font-mono"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1.5">
                    <Globe className="w-3.5 h-3.5 text-accent" />
                    <span className="font-bold text-foreground truncate" title={inf.origin_value}>
                      {inf.origin_value}
                    </span>
                  </div>
                  <Badge variant="outline" size="xs" className="text-[9px] uppercase font-mono">
                    {inf.origin_type.replace(/_/g, ' ')}
                  </Badge>
                </div>

                <div className="text-[11px] text-foreground-muted">
                  <span className="font-semibold text-foreground">Role: </span>
                  <span>{inf.hypothesis_title}</span>
                </div>

                <div className="flex items-center justify-between text-[10px] text-foreground-muted pt-1 border-t border-border/50">
                  <span>Confidence: {Math.round(inf.confidence_score * 100)}% ({inf.confidence_level})</span>
                  <span>{inf.evidence_count} Evidence</span>
                </div>

                {inf.limitations.length > 0 && (
                  <div className="text-[10px] text-warning/90 italic">
                    {inf.limitations[0]}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
