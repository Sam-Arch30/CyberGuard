import React from 'react';
import {
  AlertTriangle,
  Clock,
  CheckCircle2,
  Eye,
  Play,
  Ban,
  Check,
  Layers,
} from 'lucide-react';

import type {
  ResponseRecommendation,
  RecommendationPriority,
  RecommendationStatus,
} from '../../../types/response_recommendation';
import { Badge, Button } from '../../ui';

interface RecommendationCardProps {
  recommendation: ResponseRecommendation;
  onInspect: (rec: ResponseRecommendation) => void;
  onApprove: (rec: ResponseRecommendation) => void;
  onReject: (rec: ResponseRecommendation) => void;
  onDefer: (rec: ResponseRecommendation) => void;
  onOpenPlaybook?: (rec: ResponseRecommendation) => void;
}

export const RecommendationCard: React.FC<RecommendationCardProps> = ({
  recommendation,
  onInspect,
  onApprove,
  onReject,
  onDefer,
  onOpenPlaybook,
}) => {
  const getPriorityStyle = (p: RecommendationPriority) => {
    switch (p) {
      case 'P0':
        return 'bg-danger/15 text-danger border-danger/30 font-bold';
      case 'P1':
        return 'bg-warning/15 text-warning border-warning/30 font-bold';
      case 'P2':
        return 'bg-info/15 text-info border-info/30 font-semibold';
      case 'P3':
        return 'bg-surface-secondary text-foreground-muted border-border font-medium';
      default:
        return 'bg-surface-secondary text-foreground-muted border-border';
    }
  };

  const getStatusBadge = (status: RecommendationStatus) => {
    switch (status) {
      case 'APPROVED':
        return (
          <Badge variant="success" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <CheckCircle2 className="w-3 h-3" />
            <span>APPROVED</span>
          </Badge>
        );
      case 'REVIEW_REQUIRED':
      case 'GENERATED':
        return (
          <Badge variant="warning" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <Clock className="w-3 h-3" />
            <span>REVIEW REQUIRED</span>
          </Badge>
        );
      case 'REJECTED':
        return (
          <Badge variant="danger" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <Ban className="w-3 h-3" />
            <span>REJECTED</span>
          </Badge>
        );
      case 'DEFERRED':
        return (
          <Badge variant="outline" size="sm" className="font-mono text-[10px] flex items-center space-x-1">
            <Clock className="w-3 h-3" />
            <span>DEFERRED</span>
          </Badge>
        );
      case 'SUPERSEDED':
        return (
          <Badge variant="outline" size="sm" className="font-mono text-[10px] text-foreground-muted">
            SUPERSEDED
          </Badge>
        );
      default:
        return (
          <Badge variant="outline" size="sm" className="font-mono text-[10px]">
            {status}
          </Badge>
        );
    }
  };

  const isApplicable = recommendation.applicability !== 'NOT_APPLICABLE';
  const isApproved = recommendation.status === 'APPROVED';
  const isPending = recommendation.status === 'REVIEW_REQUIRED' || recommendation.status === 'GENERATED';

  // Primary affected target
  const targetEntity = recommendation.affected_entities && recommendation.affected_entities.length > 0
    ? recommendation.affected_entities[0]
    : null;

  return (
    <div
      className={`bg-surface border rounded-xl p-5 shadow-xs transition-all duration-200 hover:border-border-strong ${
        !isApplicable
          ? 'opacity-70 border-border/60 bg-surface-secondary/20'
          : recommendation.priority === 'P0'
          ? 'border-danger/30 hover:shadow-danger/5'
          : 'border-border'
      }`}
    >
      {/* Top Meta Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-3 border-b border-border/60">
        <div className="flex items-center space-x-2">
          <span className={`px-2 py-0.5 rounded text-[11px] font-mono border ${getPriorityStyle(recommendation.priority)}`}>
            {recommendation.priority}
          </span>
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-surface-secondary text-foreground-muted border border-border">
            {recommendation.category.replace(/_/g, ' ')}
          </span>
          {getStatusBadge(recommendation.status)}
        </div>

        <div className="flex items-center space-x-2 text-[11px] font-mono text-foreground-muted">
          <span>Confidence: </span>
          <span className="text-foreground font-semibold">
            {Math.round(recommendation.confidence * 100)}% ({recommendation.confidence_level})
          </span>
        </div>
      </div>

      {/* Main Body */}
      <div className="mt-3.5 space-y-2.5">
        <div>
          <h4 className="text-sm font-semibold text-foreground font-sans">
            {recommendation.title}
          </h4>
          <p className="text-xs text-foreground-muted font-sans mt-1 leading-relaxed">
            {recommendation.description}
          </p>
        </div>

        {/* Grounded Rationale ("WHY") */}
        <div className="p-3 rounded-lg bg-surface-secondary/50 border border-border/70 space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-primary font-bold block">
            Why Recommended
          </span>
          <p className="text-xs text-foreground font-sans leading-relaxed">
            {recommendation.rationale}
          </p>
        </div>

        {/* Affected Target & Operational Properties */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2 text-[11px] font-mono pt-1">
          <div className="p-2 rounded bg-surface-secondary/30 border border-border/60">
            <span className="text-foreground-muted text-[10px] block">Target Entity</span>
            <span className="font-semibold text-foreground truncate block" title={targetEntity?.identifier || 'Scoped Investigation'}>
              {targetEntity ? `${targetEntity.entity_type}: ${targetEntity.identifier}` : 'Investigation Scope'}
            </span>
          </div>

          <div className="p-2 rounded bg-surface-secondary/30 border border-border/60">
            <span className="text-foreground-muted text-[10px] block">Approval Policy</span>
            <span className="font-semibold text-foreground">
              {recommendation.approval_required ? 'Required (Gated)' : 'Pre-Authorized'}
            </span>
          </div>

          <div className="p-2 rounded bg-surface-secondary/30 border border-border/60">
            <span className="text-foreground-muted text-[10px] block">Reversibility</span>
            <span className="font-semibold text-foreground">
              {recommendation.reversibility === 'REVERSIBLE' ? 'Reversible' : 'Irreversible'}
            </span>
          </div>

          <div className="p-2 rounded bg-surface-secondary/30 border border-border/60">
            <span className="text-foreground-muted text-[10px] block">Impact Level</span>
            <span className="font-semibold text-foreground">
              {recommendation.impact} ({recommendation.safety_class})
            </span>
          </div>
        </div>

        {/* Conflicts & Dependencies Badges */}
        {recommendation.conflicts_with && recommendation.conflicts_with.length > 0 && (
          <div className="p-2.5 rounded-lg bg-danger/10 border border-danger/20 text-xs font-mono text-danger flex items-start space-x-2">
            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold block">Action Conflict Detected:</span>
              <span>{recommendation.conflicts_with[0].tradeoff_explanation}</span>
            </div>
          </div>
        )}

        {recommendation.depends_on && recommendation.depends_on.length > 0 && (
          <div className="text-[11px] font-mono text-foreground-muted flex items-center space-x-1.5">
            <Layers className="w-3.5 h-3.5 text-primary" />
            <span>Depends on prerequisite action: </span>
            <span className="text-foreground font-semibold">{recommendation.depends_on.join(', ')}</span>
          </div>
        )}

        {!isApplicable && (
          <div className="p-2.5 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground-muted">
            <span>Notice: </span>
            <span>{recommendation.applicability_reason}</span>
          </div>
        )}
      </div>

      {/* Action Footer */}
      <div className="mt-4 pt-3.5 border-t border-border/60 flex flex-wrap items-center justify-between gap-3">
        <button
          type="button"
          onClick={() => onInspect(recommendation)}
          className="inline-flex items-center space-x-1 text-xs font-mono text-primary hover:text-primary-hover font-semibold transition-colors cursor-pointer"
        >
          <Eye className="w-3.5 h-3.5" />
          <span>Inspect Provenance & Evidence ({recommendation.evidence_refs?.length || 0})</span>
        </button>

        <div className="flex items-center space-x-2">
          {isPending && isApplicable && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onDefer(recommendation)}
                className="font-mono text-xs text-foreground-muted"
              >
                Defer
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onReject(recommendation)}
                className="font-mono text-xs text-danger hover:bg-danger/10"
              >
                Reject
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={() => onApprove(recommendation)}
                leftIcon={<Check className="w-3.5 h-3.5" />}
                className="font-mono text-xs font-semibold"
              >
                Approve Action
              </Button>
            </>
          )}

          {isApproved && onOpenPlaybook && (
            <Button
              variant="primary"
              size="sm"
              onClick={() => onOpenPlaybook(recommendation)}
              leftIcon={<Play className="w-3.5 h-3.5" />}
              className="font-mono text-xs font-semibold"
            >
              Configure Playbook
            </Button>
          )}
        </div>
      </div>
    </div>
  );
};
