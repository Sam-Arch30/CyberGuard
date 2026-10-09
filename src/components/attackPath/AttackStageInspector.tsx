import React from 'react';
import {
  HelpCircle,
  FileText,
  Share2,
  Bot,
  Clock,
  Layers,
  Key,
  Database,
} from 'lucide-react';
import { Badge, Button } from '../ui';
import type { AttackStageProjection } from '../../types/attackPath';

interface AttackStageInspectorProps {
  stage: AttackStageProjection;
  onViewInGraph: (nodeId?: string) => void;
  onViewEvidence: (evidenceId?: string) => void;
  onConsultCopilot: (prompt: string) => void;
}

export const AttackStageInspector: React.FC<AttackStageInspectorProps> = ({
  stage,
  onViewInGraph,
  onViewEvidence,
  onConsultCopilot,
}) => {
  const stageNum = String(stage.stage_order).padStart(2, '0');

  // Format timestamp
  let timeStr = 'Timestamp unrecorded';
  if (stage.start_time) {
    const d = new Date(stage.start_time);
    timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' }) + ' UTC';
    if (stage.time_uncertainty) {
      timeStr += ` (${stage.time_uncertainty})`;
    }
  }

  const primaryEntity = stage.entities_detail[0];

  return (
    <div className="bg-surface border border-border rounded-xl p-5 shadow-xs space-y-5 animate-in fade-in duration-150">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 pb-4 border-b border-border">
        <div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono font-bold text-accent uppercase">
              Stage {stageNum} · {stage.stage_type.replace(/_/g, ' ')}
            </span>
            <span className="text-xs font-mono text-foreground-muted">|</span>
            <Badge
              variant={stage.stage_status === 'OBSERVED' ? 'success' : stage.stage_status === 'DERIVED' ? 'primary' : 'warning'}
              size="sm"
              className="font-mono text-[9px] uppercase font-bold"
            >
              {stage.stage_status}
            </Badge>
          </div>
          <h2 className="text-base font-semibold text-foreground font-sans mt-1">
            {stage.title}
          </h2>
          <div className="flex items-center space-x-2 mt-1.5 text-xs font-mono text-foreground-muted">
            <Clock className="w-3.5 h-3.5 shrink-0" />
            <span>{timeStr}</span>
            {stage.tactic && (
              <>
                <span>•</span>
                <span>Tactic: {stage.tactic}</span>
              </>
            )}
            {stage.technique_id && (
              <>
                <span>•</span>
                <span className="text-accent font-semibold">{stage.technique_id}</span>
              </>
            )}
          </div>
        </div>

        {/* Confidence & Quick Actions */}
        <div className="flex flex-wrap items-center gap-2 shrink-0">
          <div className="px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-right">
            <div className="text-[10px] font-mono uppercase text-foreground-muted">Confidence</div>
            <div className="text-xs font-mono font-bold text-accent">
              {Math.round(stage.confidence * 100)}% ({stage.confidence_level})
            </div>
          </div>
        </div>
      </div>

      {/* Why This Stage Exists */}
      <div className="space-y-1.5">
        <h4 className="text-[11px] font-mono uppercase font-bold text-foreground-muted tracking-wider flex items-center space-x-1.5">
          <FileText className="w-3.5 h-3.5 text-accent" />
          <span>Analytical Justification & Rationale</span>
        </h4>
        <div className="p-3.5 rounded-lg bg-surface-secondary/50 border border-border text-xs font-mono text-foreground leading-relaxed">
          {stage.description || 'Stage established by deterministic correlation of observed findings and security events.'}
        </div>
      </div>

      {/* Grid: Entities & Findings Detail */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Involved Entities */}
        <div className="space-y-2">
          <h4 className="text-[11px] font-mono uppercase font-bold text-foreground-muted tracking-wider flex items-center justify-between">
            <span className="flex items-center space-x-1.5">
              <Key className="w-3.5 h-3.5 text-accent" />
              <span>Involved Entities ({stage.entities_detail.length})</span>
            </span>
          </h4>
          <div className="space-y-1.5">
            {stage.entities_detail.length > 0 ? (
              stage.entities_detail.map((ent) => (
                <div
                  key={ent.id}
                  className="p-2.5 rounded-lg bg-surface-secondary border border-border flex items-center justify-between gap-2 text-xs font-mono"
                >
                  <div className="min-w-0">
                    <div className="text-[10px] uppercase text-foreground-muted font-bold truncate">
                      {ent.type}
                    </div>
                    <div className="text-foreground font-semibold truncate" title={ent.value}>
                      {ent.value}
                    </div>
                  </div>
                  <Button
                    size="xs"
                    variant="ghost"
                    onClick={() => onViewInGraph(ent.id)}
                    className="shrink-0 text-[10px] font-mono"
                    rightIcon={<Share2 className="w-3 h-3" />}
                  >
                    Graph
                  </Button>
                </div>
              ))
            ) : (
              <div className="p-3 rounded-lg bg-surface-secondary/30 border border-border text-xs font-mono text-foreground-muted italic">
                No high-level entities bound directly to this stage.
              </div>
            )}
          </div>
        </div>

        {/* Associated Findings */}
        <div className="space-y-2">
          <h4 className="text-[11px] font-mono uppercase font-bold text-foreground-muted tracking-wider flex items-center justify-between">
            <span className="flex items-center space-x-1.5">
              <Layers className="w-3.5 h-3.5 text-accent" />
              <span>Correlated Findings ({stage.findings_detail.length})</span>
            </span>
          </h4>
          <div className="space-y-1.5">
            {stage.findings_detail.length > 0 ? (
              stage.findings_detail.map((fnd) => (
                <div
                  key={fnd.id}
                  className="p-2.5 rounded-lg bg-surface-secondary border border-border flex items-center justify-between gap-2 text-xs font-mono"
                >
                  <div className="min-w-0">
                    <div className="flex items-center space-x-1.5">
                      <span className="text-[9px] uppercase font-bold text-warning">
                        {fnd.severity}
                      </span>
                      <span className="text-foreground-muted text-[10px] truncate">· {fnd.analyzer}</span>
                    </div>
                    <div className="text-foreground font-medium truncate" title={fnd.title}>
                      {fnd.title}
                    </div>
                  </div>
                  <span className="text-[10px] text-accent font-semibold shrink-0">
                    {Math.round(fnd.confidence * 100)}%
                  </span>
                </div>
              ))
            ) : (
              <div className="p-3 rounded-lg bg-surface-secondary/30 border border-border text-xs font-mono text-foreground-muted italic">
                Derived from temporal sequence and gateway telemetry.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Supporting Evidence Items with Provenance */}
      {stage.supporting_evidence.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-[11px] font-mono uppercase font-bold text-foreground-muted tracking-wider flex items-center space-x-1.5">
            <Database className="w-3.5 h-3.5 text-accent" />
            <span>Structured Evidence Items & Provenance ({stage.supporting_evidence.length})</span>
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {stage.supporting_evidence.map((ev, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded-lg bg-surface-secondary/70 border border-border text-xs font-mono space-y-1"
              >
                <div className="flex items-center justify-between text-[10px] text-foreground-muted">
                  <span className="uppercase font-semibold text-accent">
                    Evidence Item #{idx + 1}
                  </span>
                  {ev.source && <span>Source: {ev.source}</span>}
                </div>
                <div className="text-foreground truncate">
                  {Object.entries(ev)
                    .filter(([k]) => k !== 'source')
                    .map(([k, v]) => `${k}: ${String(v)}`)
                    .join(' · ') || 'Verified evidence record.'}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Forensic Limitations & Caveats */}
      {stage.limitations.length > 0 && (
        <div className="p-3 rounded-lg bg-warning/5 border border-warning/20 text-xs font-mono text-foreground-muted space-y-1">
          <div className="text-[10px] font-bold uppercase tracking-wider text-warning flex items-center space-x-1">
            <HelpCircle className="w-3.5 h-3.5" />
            <span>Forensic Caveats & Telemetry Limitations</span>
          </div>
          <ul className="list-disc list-inside space-y-0.5 text-[11px]">
            {stage.limitations.map((limit, idx) => (
              <li key={idx}>{limit}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Action Footer Bar */}
      <div className="pt-3 border-t border-border flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => onViewEvidence(stage.evidence_ids[0])}
            leftIcon={<FileText className="w-3.5 h-3.5" />}
            className="text-xs font-mono"
          >
            Inspect Evidence Drawer
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={() => onViewInGraph(primaryEntity?.id)}
            leftIcon={<Share2 className="w-3.5 h-3.5" />}
            className="text-xs font-mono"
          >
            View in Knowledge Graph →
          </Button>
        </div>

        <Button
          size="sm"
          variant="primary"
          onClick={() =>
            onConsultCopilot(
              `Analyze stage 0${stage.stage_order} (${stage.title}) in the reconstructed attack path. What evidence supports this transition and what telemetry is missing?`
            )
          }
          leftIcon={<Bot className="w-3.5 h-3.5" />}
          className="text-xs font-mono"
        >
          Consult AI Copilot
        </Button>
      </div>
    </div>
  );
};
