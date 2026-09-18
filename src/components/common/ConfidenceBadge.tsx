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
          pill: 'bg-success-surface text-success border-success-border hover:bg-success-surface/80',
          outline: 'border-success-border text-success hover:bg-success-surface'
        };
      case 'HIGH':
        return {
          pill: 'bg-primary-subtle text-primary border-primary/30 hover:bg-primary/15',
          outline: 'border-primary/40 text-primary hover:bg-primary-subtle'
        };
      case 'MODERATE':
        return {
          pill: 'bg-warning-surface text-warning border-warning-border hover:bg-warning-surface/80',
          outline: 'border-warning-border text-warning hover:bg-warning-surface'
        };
      case 'LOW':
      default:
        return {
          pill: 'bg-danger-surface text-danger border-danger-border hover:bg-danger-surface/80',
          outline: 'border-danger-border text-danger hover:bg-danger-surface'
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

  const renderIcon = () => {
    const cls = `${iconSizes} shrink-0`;
    switch (level) {
      case 'VERY HIGH':
        return <CheckCircle2 className={cls} />;
      case 'HIGH':
        return <ShieldCheck className={cls} />;
      case 'MODERATE':
        return <AlertTriangle className={cls} />;
      case 'LOW':
      default:
        return <Info className={cls} />;
    }
  };

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
        className={`inline-flex items-center rounded-badge font-mono transition-all border ${
          variant === 'outline' ? theme.outline : theme.pill
        } ${sizeClasses} ${
          interactive
            ? 'cursor-pointer hover:shadow-xs focus:outline-hidden focus:ring-1 focus:ring-primary/50'
            : 'cursor-default'
        } ${className}`}
      >
        {renderIcon()}
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
