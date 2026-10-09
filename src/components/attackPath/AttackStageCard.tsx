import React from 'react';
import {
  CheckCircle2,
  HelpCircle,
  Clock,
  FileText,
  Shield,
  Layers,
  ChevronRight,
  CircleDot,
  AlertCircle,
} from 'lucide-react';
import { Badge } from '../ui';
import type {
  AttackStageProjection,
  StageCertaintyStatus,
} from '../../types/attackPath';

interface AttackStageCardProps {
  stage: AttackStageProjection;
  isSelected: boolean;
  onSelect: () => void;
  index: number;
}

const CERTAINTY_CONFIG: Record<
  StageCertaintyStatus,
  { label: string; icon: React.ReactNode; borderClass: string; badgeVariant: 'success' | 'primary' | 'warning' | 'outline' }
> = {
  OBSERVED: {
    label: '● OBSERVED',
    icon: <CheckCircle2 className="w-3 h-3 text-success shrink-0" />,
    borderClass: 'border-success/40',
    badgeVariant: 'success',
  },
  DERIVED: {
    label: '⊙ DERIVED',
    icon: <CircleDot className="w-3 h-3 text-accent shrink-0" />,
    borderClass: 'border-accent/40',
    badgeVariant: 'primary',
  },
  INFERRED: {
    label: '◌ INFERRED',
    icon: <HelpCircle className="w-3 h-3 text-warning shrink-0" />,
    borderClass: 'border-warning/40 border-dashed',
    badgeVariant: 'warning',
  },
  UNRESOLVED: {
    label: '? UNRESOLVED',
    icon: <AlertCircle className="w-3 h-3 text-danger shrink-0" />,
    borderClass: 'border-danger/40 border-dashed',
    badgeVariant: 'outline',
  },
};

export const AttackStageCard: React.FC<AttackStageCardProps> = ({
  stage,
  isSelected,
  onSelect,
  index,
}) => {
  const certainty = CERTAINTY_CONFIG[stage.stage_status] || CERTAINTY_CONFIG.OBSERVED;
  const stageNum = String(stage.stage_order || index + 1).padStart(2, '0');

  // Format timestamp
  let timeStr = 'Timestamp unrecorded';
  if (stage.start_time) {
    const d = new Date(stage.start_time);
    timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' }) + ' UTC';
    if (stage.time_uncertainty) {
      timeStr += ` (${stage.time_uncertainty})`;
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      onSelect();
    }
  };

  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={handleKeyDown}
      aria-pressed={isSelected}
      aria-label={`Stage ${stageNum}: ${stage.title}. Certainty: ${stage.stage_status}.`}
      className={`relative p-4 rounded-xl border text-left transition-all cursor-pointer select-none outline-hidden ${
        isSelected
          ? 'bg-surface-secondary border-accent shadow-xs ring-2 ring-accent'
          : `bg-surface border-border hover:border-border-focus hover:bg-surface-secondary/40 ${certainty.borderClass}`
      }`}
    >
      {/* Header: Stage Number, Category, Certainty Badge */}
      <div className="flex items-center justify-between gap-2 mb-2">
        <div className="flex items-center space-x-1.5 min-w-0">
          <span className="text-[11px] font-mono font-bold uppercase tracking-wider text-accent shrink-0">
            {stageNum}
          </span>
          <span className="text-foreground-muted text-[10px] font-mono">/</span>
          <span className="text-[10px] font-mono uppercase tracking-wider text-foreground-muted truncate">
            {stage.stage_type.replace(/_/g, ' ')}
          </span>
        </div>

        <Badge
          variant={certainty.badgeVariant}
          size="sm"
          className="font-mono text-[9px] uppercase font-bold tracking-wider shrink-0 flex items-center space-x-1"
        >
          {certainty.icon}
          <span>{certainty.label}</span>
        </Badge>
      </div>

      {/* Title */}
      <h3 className="font-sans text-xs font-semibold text-foreground line-clamp-1 leading-snug">
        {stage.title}
      </h3>

      {/* MITRE Tactic / Technique */}
      <div className="flex flex-wrap items-center gap-1.5 mt-1.5">
        {stage.tactic && (
          <span className="text-[10px] font-mono font-medium text-foreground-muted bg-surface-secondary px-1.5 py-0.5 rounded border border-border">
            {stage.tactic}
          </span>
        )}
        {stage.technique_id && (
          <span className="text-[10px] font-mono font-semibold text-accent bg-accent/10 px-1.5 py-0.5 rounded border border-accent/20">
            {stage.technique_id}
          </span>
        )}
      </div>

      {/* Timestamp */}
      <div className="flex items-center space-x-1 mt-2 text-[10px] font-mono text-foreground-muted truncate">
        <Clock className="w-3 h-3 shrink-0" />
        <span className="truncate">{timeStr}</span>
      </div>

      {/* Bottom Summary Bar */}
      <div className="flex items-center justify-between border-t border-border mt-3 pt-2 text-[10px] font-mono text-foreground-muted">
        <span className="flex items-center space-x-1">
          <Shield className="w-3 h-3 text-accent shrink-0" />
          <span>{Math.round(stage.confidence * 100)}%</span>
        </span>
        <span className="flex items-center space-x-1">
          <FileText className="w-3 h-3 shrink-0" />
          <span>{stage.evidence_count} Evd</span>
        </span>
        {stage.finding_count > 0 && (
          <span className="flex items-center space-x-1">
            <Layers className="w-3 h-3 shrink-0" />
            <span>{stage.finding_count} Fnd</span>
          </span>
        )}
        <ChevronRight className={`w-3.5 h-3.5 transition-transform ${isSelected ? 'rotate-90 text-accent' : 'text-foreground-muted'}`} />
      </div>
    </div>
  );
};
