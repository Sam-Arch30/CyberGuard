import React, { useState } from 'react';
import { ShieldCheck, HelpCircle, AlertTriangle, Info, CheckCircle2 } from 'lucide-react';
import type { ForensicConclusion, ConfidenceLevel } from '../../types/confidence';
import { EvidenceConfidencePanel } from '../forensic/EvidenceConfidencePanel';

export interface ConfidenceBadgeProps {
  conclusion?: ForensicConclusion;
  allConclusions?: ForensicConclusion[];
  level?: ConfidenceLevel | string;
  score?: number;
  label?: string;
  size?: 'sm' | 'md' | 'lg';
  variant?: 'pill' | 'compact' | 'outline';
  showScore?: boolean;
  interactive?: boolean;
  onClick?: () => void;
  className?: string;
}

export const ConfidenceBadge: React.FC<ConfidenceBadgeProps> = ({
  conclusion,
  allConclusions = [],
  level: propLevel,
  score: propScore,
  label,
  size = 'md',
  variant = 'pill',
  showScore = true,
  interactive = true,
  onClick,
  className = ''
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);

  // Normalize level and score from conclusion or props
  const level: ConfidenceLevel = (
    conclusion?.confidence_level ||
    propLevel ||
    'MODERATE'
  ).toUpperCase() as ConfidenceLevel;

  const rawScore = conclusion ? conclusion.confidence_score : propScore;

  // Zero false precision: round to integer, no decimals like 63.482%
  const formattedScore = rawScore !== undefined ? Math.round(rawScore) : undefined;

  // Weak evidence / moderate wording without false precision
  const displayLabel = () => {
    if (label) return label;
    if (level === 'LOW') {
      return formattedScore !== undefined ? `${formattedScore}% LOW` : 'Low confidence';
    }
    if (level === 'MODERATE') {
      return formattedScore !== undefined ? `${formattedScore}% MODERATE` : 'Moderate confidence';
    }
    if (level === 'HIGH') {
      return formattedScore !== undefined ? `${formattedScore}% HIGH` : 'High confidence';
    }
    if (level === 'VERY HIGH') {
      return formattedScore !== undefined ? `${formattedScore}% VERY HIGH` : 'Very high confidence';
    }
    return `${level}`;
  };

  const getThemeStyles = () => {
    switch (level) {
      case 'VERY HIGH':
        return {
          pill: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/25',
          outline: 'border-emerald-500/50 text-emerald-400 hover:bg-emerald-500/10',
          icon: <CheckCircle2 className="shrink-0" />
        };
      case 'HIGH':
        return {
          pill: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30 hover:bg-cyan-500/25',
          outline: 'border-cyan-500/50 text-cyan-400 hover:bg-cyan-500/10',
          icon: <ShieldCheck className="shrink-0" />
        };
      case 'MODERATE':
        return {
          pill: 'bg-amber-500/15 text-amber-400 border-amber-500/30 hover:bg-amber-500/25',
          outline: 'border-amber-500/50 text-amber-400 hover:bg-amber-500/10',
          icon: <AlertTriangle className="shrink-0" />
        };
      case 'LOW':
      default:
        return {
          pill: 'bg-rose-500/15 text-rose-400 border-rose-500/30 hover:bg-rose-500/25',
          outline: 'border-rose-500/50 text-rose-400 hover:bg-rose-500/10',
          icon: <Info className="shrink-0" />
        };
    }
  };

  const theme = getThemeStyles();

  const sizeClasses = {
    sm: 'text-[10px] px-2 py-0.5 gap-1',
    md: 'text-xs px-2.5 py-1 gap-1.5',
    lg: 'text-xs px-3 py-1.5 gap-2 font-medium'
  }[size];

  const iconSizes = {
    sm: 'w-3 h-3',
    md: 'w-3.5 h-3.5',
    lg: 'w-4 h-4'
  }[size];

  const handleClick = (e: React.MouseEvent) => {
    if (!interactive) return;
    e.stopPropagation();
    if (onClick) {
      onClick();
    } else {
      setIsModalOpen(true);
    }
  };

  const resolvedConclusionsList =
    allConclusions.length > 0
      ? allConclusions
      : conclusion
      ? [conclusion]
      : [];

  return (
    <>
      <button
        type="button"
        onClick={handleClick}
        disabled={!interactive}
        title={
          interactive
            ? 'Click to inspect underlying evidence, conflicts, and confidence dimensions'
            : undefined
        }
        className={`inline-flex items-center rounded-full font-mono transition-all border ${
          variant === 'outline' ? theme.outline : theme.pill
        } ${sizeClasses} ${
          interactive
            ? 'cursor-pointer hover:shadow-xs focus:outline-hidden focus:ring-1 focus:ring-primary/50'
            : 'cursor-default'
        } ${className}`}
      >
        <span className={iconSizes}>{theme.icon}</span>
        <span className="font-semibold tracking-tight">{displayLabel()}</span>
        {showScore && formattedScore !== undefined && variant !== 'compact' && (
          <span className="ml-0.5 text-[10px] opacity-80 font-normal">
            ({formattedScore}%)
          </span>
        )}
        {interactive && (
          <HelpCircle className={`${iconSizes} opacity-60 hover:opacity-100 ml-0.5 shrink-0`} />
        )}
      </button>

      {/* Internal Evidence Confidence Panel modal */}
      {interactive && resolvedConclusionsList.length > 0 && (
        <EvidenceConfidencePanel
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
          conclusions={resolvedConclusionsList}
          selectedConclusionId={conclusion?.conclusion_id}
        />
      )}
    </>
  );
};
