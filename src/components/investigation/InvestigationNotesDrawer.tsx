import React, { useState } from 'react';
import {
  FileText,
  Send,
  User,
  Clock,
  ShieldAlert,
} from 'lucide-react';
import { Drawer, Button, Textarea, Badge } from '../ui';
import type { AnalystNoteModel } from '../../types/investigationWorkspace';

interface InvestigationNotesDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  notes: AnalystNoteModel[];
  onAddNote: (noteText: string) => Promise<void>;
  investigationId: string;
}

export const InvestigationNotesDrawer: React.FC<InvestigationNotesDrawerProps> = ({
  isOpen,
  onClose,
  notes,
  onAddNote,
  investigationId,
}) => {
  const [newNoteText, setNewNoteText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = newNoteText.trim();
    if (!trimmed) return;

    setSubmitting(true);
    setError(null);
    try {
      await onAddNote(trimmed);
      setNewNoteText('');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to record note.');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Drawer
      isOpen={isOpen}
      onClose={onClose}
      size="md"
      title={
        <div className="flex items-center space-x-2">
          <FileText className="w-4 h-4 text-primary" />
          <span className="font-mono text-sm font-bold text-foreground">Analyst Notes & Audit Trail</span>
          <Badge variant="outline" size="sm" className="font-mono text-[10px]">
            {notes.length}
          </Badge>
        </div>
      }
      description={
        <span className="font-mono text-xs text-foreground-muted">
          Immutable case annotations for {investigationId}
        </span>
      }
    >
      <div className="space-y-6 text-xs font-mono">
        {/* ADD NOTE FORM */}
        <form onSubmit={handleSubmit} className="p-3.5 rounded-xl bg-surface border border-border shadow-xs space-y-3">
          <span className="text-[11px] font-bold text-foreground uppercase tracking-wider block">
            Add Audited Note
          </span>

          <Textarea
            value={newNoteText}
            onChange={(e) => setNewNoteText(e.target.value)}
            placeholder="Record forensic observation, triage conclusion, or containment action..."
            rows={3}
            className="text-xs font-mono w-full"
            disabled={submitting}
          />

          {error && (
            <p className="text-[11px] text-danger font-sans">{error}</p>
          )}

          <div className="flex items-center justify-between pt-1">
            <span className="text-[10px] text-foreground-subtle flex items-center gap-1">
              <ShieldAlert className="w-3 h-3 text-primary" />
              Notes are permanently recorded with author attribution.
            </span>

            <Button
              type="submit"
              size="sm"
              variant="primary"
              disabled={!newNoteText.trim() || submitting}
              isLoading={submitting}
              leftIcon={<Send className="w-3 h-3" />}
            >
              Post Note
            </Button>
          </div>
        </form>

        {/* EXISTING NOTES LIST */}
        <div className="space-y-3">
          <span className="text-[11px] font-bold text-foreground-muted uppercase tracking-wider block">
            Investigation History ({notes.length})
          </span>

          {notes.length === 0 ? (
            <div className="p-6 rounded-xl bg-surface-secondary/40 border border-border text-center text-foreground-muted">
              No notes recorded for this investigation yet.
            </div>
          ) : (
            <div className="space-y-2.5">
              {notes.map((note) => (
                <div
                  key={note.id}
                  className="p-3 rounded-xl bg-surface border border-border shadow-xs space-y-1.5"
                >
                  <div className="flex items-center justify-between text-[10px] text-foreground-muted">
                    <span className="flex items-center gap-1 font-semibold text-foreground">
                      <User className="w-3 h-3 text-primary" />
                      {note.author}
                    </span>
                    <span className="flex items-center gap-1 text-foreground-subtle">
                      <Clock className="w-3 h-3" />
                      {new Date(note.created_at).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                  </div>

                  <p className="text-xs text-foreground font-sans leading-relaxed whitespace-pre-wrap">
                    {note.note_text}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Drawer>
  );
};
