import React, { useState, useEffect } from 'react';
import {
  History,
  Clock,
  User,
  CheckCircle2,
  AlertCircle,
  FileText,
  Link as LinkIcon,
  RefreshCw,
  GitMerge,
  ShieldAlert,
} from 'lucide-react';
import type { CaseTimelineEvent } from '../../types/case';
import { caseService } from '../../services/caseService';

interface CaseTimelineSectionProps {
  caseId: string;
}

const EVENT_ICON_MAP: Record<string, React.ReactNode> = {
  CASE_OPENED: <AlertCircle className="w-4 h-4 text-primary" />,
  STATUS_CHANGED: <RefreshCw className="w-4 h-4 text-warning" />,
  ASSIGNED: <User className="w-4 h-4 text-foreground" />,
  TASK_COMPLETED: <CheckCircle2 className="w-4 h-4 text-success" />,
  INCIDENT_LINKED: <LinkIcon className="w-4 h-4 text-primary" />,
  INVESTIGATION_LINKED: <LinkIcon className="w-4 h-4 text-primary" />,
  ALERT_LINKED: <ShieldAlert className="w-4 h-4 text-warning" />,
  NOTE_ADDED: <FileText className="w-4 h-4 text-foreground-muted" />,
  RESOLVED: <CheckCircle2 className="w-4 h-4 text-success" />,
  CLOSED: <CheckCircle2 className="w-4 h-4 text-foreground-muted" />,
  REOPENED: <AlertCircle className="w-4 h-4 text-danger" />,
  CASES_MERGED: <GitMerge className="w-4 h-4 text-warning" />,
};

export const CaseTimelineSection: React.FC<CaseTimelineSectionProps> = ({ caseId }) => {
  const [events, setEvents] = useState<CaseTimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchTimeline = async () => {
    setLoading(true);
    try {
      const data = await caseService.getCaseTimeline(caseId);
      setEvents(data);
    } catch (err) {
      console.warn('Failed to load case timeline', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimeline();
  }, [caseId]);

  return (
    <div className="bg-surface rounded-2xl border border-border p-5 space-y-4 shadow-xs">
      <div className="flex items-center justify-between pb-3 border-b border-border">
        <div className="flex items-center space-x-2">
          <History className="w-4 h-4 text-primary" />
          <h3 className="text-sm font-bold font-mono text-foreground">
            Authoritative Case Timeline ({events.length} Milestones)
          </h3>
        </div>
        <button
          type="button"
          onClick={fetchTimeline}
          className="p-1.5 rounded-lg border border-border hover:bg-surface-secondary text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
          title="Refresh Timeline"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-primary' : ''}`} />
        </button>
      </div>

      {loading ? (
        <div className="flex flex-col items-center justify-center py-10 space-y-2">
          <RefreshCw className="w-5 h-5 text-primary animate-spin" />
          <p className="text-xs font-mono text-foreground-muted">Reconstructing chronological milestones...</p>
        </div>
      ) : events.length === 0 ? (
        <div className="text-center py-8 text-xs font-mono text-foreground-muted">
          No chronological timeline events recorded yet.
        </div>
      ) : (
        <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-border">
          {events.map((evt, idx) => {
            const icon = EVENT_ICON_MAP[evt.event_type] || <Clock className="w-4 h-4 text-foreground-muted" />;

            return (
              <div key={evt.id || idx} className="relative group">
                {/* Node dot */}
                <div className="absolute -left-6 top-1 w-5 h-5 rounded-full bg-surface border border-border flex items-center justify-center shadow-xs">
                  {icon}
                </div>

                <div className="p-3.5 rounded-xl bg-surface-secondary/40 border border-border group-hover:border-primary/40 transition-colors space-y-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs font-mono font-bold text-foreground">
                      {evt.title}
                    </span>
                    <span className="text-[10px] font-mono text-foreground-muted">
                      {new Date(evt.timestamp).toLocaleString()}
                    </span>
                  </div>

                  <p className="text-xs font-mono text-foreground-muted leading-relaxed">
                    {evt.description}
                  </p>

                  <div className="flex items-center space-x-2 text-[10px] font-mono text-foreground-muted pt-1">
                    <span>Actor: {evt.actor}</span>
                    <span>·</span>
                    <span className="uppercase text-primary/80">{evt.source}</span>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
