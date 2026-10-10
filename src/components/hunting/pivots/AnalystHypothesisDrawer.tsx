import React, { useState } from 'react';
import {
  FileQuestion,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Save,
  AlertCircle,
} from 'lucide-react';
import type {
  HypothesisRecordRequest,
  HypothesisResponse,
  HypothesisStatus,
} from '../../../types/pivots';
import { pivotService } from '../../../services/pivotService';

interface AnalystHypothesisDrawerProps {
  currentObservable: string;
  investigationId?: string;
  supportingItems: string[];
  contradictingItems: string[];
  neutralItems: string[];
  onRemoveItem: (item: string, classification: 'SUPPORTING' | 'CONTRADICTING' | 'NEUTRAL') => void;
  onSavedHypothesis?: (hypothesis: HypothesisResponse) => void;
}

export const AnalystHypothesisDrawer: React.FC<AnalystHypothesisDrawerProps> = ({
  currentObservable,
  investigationId,
  supportingItems,
  contradictingItems,
  neutralItems,
  onRemoveItem,
  onSavedHypothesis,
}) => {
  const [title, setTitle] = useState('');
  const [hypothesisText, setHypothesisText] = useState(
    `Discovered infrastructure overlaps around ${currentObservable} suggest linked campaign activity.`
  );
  const [status, setStatus] = useState<HypothesisStatus>('PROPOSED');
  const [notes, setNotes] = useState('');
  const [isSaving, setIsSaving] = useState(false);
  const [feedbackMessage, setFeedbackMessage] = useState<string | null>(null);

  const handleSave = async () => {
    if (!title.trim()) {
      setFeedbackMessage('Please provide a hypothesis title.');
      return;
    }

    setIsSaving(true);
    setFeedbackMessage(null);
    try {
      const payload: HypothesisRecordRequest = {
        title: title.trim(),
        hypothesis_text: hypothesisText.trim(),
        source_observable: currentObservable,
        investigation_id: investigationId,
        supporting_items: supportingItems,
        contradicting_items: contradictingItems,
        neutral_items: neutralItems,
        analyst_notes: notes.trim(),
        status,
      };

      const res = await pivotService.recordHypothesis(payload);
      setFeedbackMessage('Hypothesis recorded and attached to hunt workspace.');
      if (onSavedHypothesis) onSavedHypothesis(res);
    } catch (err: any) {
      setFeedbackMessage(err.message || 'Failed to record hypothesis');
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="bg-surface border border-border rounded-panel p-4 space-y-4 shadow-xs">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border pb-3">
        <div className="flex items-center space-x-2">
          <FileQuestion className="w-4 h-4 text-primary" />
          <h4 className="text-xs font-mono font-bold text-foreground uppercase tracking-wide">
            Analyst Investigation Hypothesis
          </h4>
        </div>

        <select
          value={status}
          onChange={(e) => setStatus(e.target.value as HypothesisStatus)}
          className="px-2.5 py-1 bg-surface-secondary border border-border rounded-control text-xs font-mono font-medium text-foreground"
        >
          <option value="PROPOSED">Proposed</option>
          <option value="INVESTIGATING">Under Investigation</option>
          <option value="CONFIRMED">Confirmed by Evidence</option>
          <option value="DISPROVED">Disproved</option>
          <option value="ABANDONED">Abandoned</option>
        </select>
      </div>

      {/* Form Fields */}
      <div className="space-y-3 text-xs">
        <div>
          <label className="block text-[11px] font-mono text-foreground-muted mb-1">
            Hypothesis Title *
          </label>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="e.g. Infrastructure shared across secondary spearphishing domains"
            className="w-full px-3 py-1.5 bg-surface-secondary border border-border rounded-control font-mono text-foreground focus:outline-hidden focus:border-primary"
          />
        </div>

        <div>
          <label className="block text-[11px] font-mono text-foreground-muted mb-1">
            Working Hypothesis Statement
          </label>
          <textarea
            rows={2}
            value={hypothesisText}
            onChange={(e) => setHypothesisText(e.target.value)}
            className="w-full px-3 py-1.5 bg-surface-secondary border border-border rounded-control font-sans text-foreground text-xs focus:outline-hidden focus:border-primary resize-none"
          />
        </div>

        {/* Evidence Classifications Breakdown */}
        <div className="grid grid-cols-3 gap-2 py-1">
          {/* Supporting */}
          <div className="p-2.5 bg-emerald-500/5 border border-emerald-500/20 rounded-panel">
            <div className="flex items-center space-x-1.5 text-emerald-500 font-mono text-[11px] font-semibold mb-1">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Supporting ({supportingItems.length})</span>
            </div>
            <div className="space-y-1 max-h-24 overflow-y-auto scrollbar-thin">
              {supportingItems.length === 0 ? (
                <span className="text-[10px] text-foreground-muted italic">None classified</span>
              ) : (
                supportingItems.map((val) => (
                  <div
                    key={val}
                    className="flex items-center justify-between text-[10px] font-mono bg-surface px-1.5 py-0.5 rounded-control border border-border"
                  >
                    <span className="truncate max-w-[120px]">{val}</span>
                    <button
                      onClick={() => onRemoveItem(val, 'SUPPORTING')}
                      className="text-foreground-muted hover:text-threat-critical cursor-pointer ml-1"
                    >
                      ×
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Contradicting */}
          <div className="p-2.5 bg-threat-critical/5 border border-threat-critical/20 rounded-panel">
            <div className="flex items-center space-x-1.5 text-threat-critical font-mono text-[11px] font-semibold mb-1">
              <XCircle className="w-3.5 h-3.5" />
              <span>Contradicting ({contradictingItems.length})</span>
            </div>
            <div className="space-y-1 max-h-24 overflow-y-auto scrollbar-thin">
              {contradictingItems.length === 0 ? (
                <span className="text-[10px] text-foreground-muted italic">None classified</span>
              ) : (
                contradictingItems.map((val) => (
                  <div
                    key={val}
                    className="flex items-center justify-between text-[10px] font-mono bg-surface px-1.5 py-0.5 rounded-control border border-border"
                  >
                    <span className="truncate max-w-[120px]">{val}</span>
                    <button
                      onClick={() => onRemoveItem(val, 'CONTRADICTING')}
                      className="text-foreground-muted hover:text-threat-critical cursor-pointer ml-1"
                    >
                      ×
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* Neutral */}
          <div className="p-2.5 bg-surface-secondary border border-border rounded-panel">
            <div className="flex items-center space-x-1.5 text-foreground-muted font-mono text-[11px] font-semibold mb-1">
              <HelpCircle className="w-3.5 h-3.5" />
              <span>Neutral ({neutralItems.length})</span>
            </div>
            <div className="space-y-1 max-h-24 overflow-y-auto scrollbar-thin">
              {neutralItems.length === 0 ? (
                <span className="text-[10px] text-foreground-muted italic">None classified</span>
              ) : (
                neutralItems.map((val) => (
                  <div
                    key={val}
                    className="flex items-center justify-between text-[10px] font-mono bg-surface px-1.5 py-0.5 rounded-control border border-border"
                  >
                    <span className="truncate max-w-[120px]">{val}</span>
                    <button
                      onClick={() => onRemoveItem(val, 'NEUTRAL')}
                      className="text-foreground-muted hover:text-threat-critical cursor-pointer ml-1"
                    >
                      ×
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div>
          <label className="block text-[11px] font-mono text-foreground-muted mb-1">
            Analyst Working Notes
          </label>
          <textarea
            rows={2}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Document observed overlaps, timing alignments, or open questions..."
            className="w-full px-3 py-1.5 bg-surface-secondary border border-border rounded-control font-sans text-foreground text-xs focus:outline-hidden focus:border-primary resize-none"
          />
        </div>
      </div>

      {feedbackMessage && (
        <div className="p-2 text-xs font-mono text-foreground bg-primary/10 border border-primary/20 rounded-control flex items-center space-x-1.5">
          <AlertCircle className="w-3.5 h-3.5 text-primary" />
          <span>{feedbackMessage}</span>
        </div>
      )}

      {/* Save Action */}
      <div className="flex justify-end pt-2 border-t border-border">
        <button
          onClick={handleSave}
          disabled={isSaving}
          className="px-3.5 py-1.5 text-xs font-mono font-medium text-white bg-primary hover:bg-primary/90 disabled:opacity-50 rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs transition-colors"
        >
          <Save className="w-3.5 h-3.5" />
          <span>{isSaving ? 'Saving...' : 'Record Hypothesis'}</span>
        </button>
      </div>
    </div>
  );
};
