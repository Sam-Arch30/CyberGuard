import React from 'react';
import { Clock } from 'lucide-react';
import { Badge } from '../ui';
import type { AttackPathTimelineEvent } from '../../types/attackPath';

interface AttackPathTimelineSyncProps {
  timelineEvents: AttackPathTimelineEvent[];
  selectedStageId?: string;
  onSelectEvent?: (event: AttackPathTimelineEvent) => void;
  onSelectStage?: (stageId: string) => void;
}

export const AttackPathTimelineSync: React.FC<AttackPathTimelineSyncProps> = ({
  timelineEvents,
  selectedStageId,
  onSelectEvent,
  onSelectStage,
}) => {
  if (!timelineEvents || timelineEvents.length === 0) {
    return null;
  }

  return (
    <div className="bg-surface border border-border rounded-xl p-4 shadow-xs space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="p-1 rounded-md bg-accent/10 text-accent">
            <Clock className="w-4 h-4" />
          </span>
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground">
            Synchronized Forensic Timeline ({timelineEvents.length} Events)
          </h3>
        </div>
        <Badge variant="outline" size="sm" className="font-mono text-[9px]">
          Event-Time Sequence (UTC)
        </Badge>
      </div>

      <p className="text-[11px] font-mono text-foreground-muted">
        Chronological telemetry ordered by normalized event timestamp. Highlighted events correspond to the active stage selection.
      </p>

      {/* Horizontal / Compact Timeline Scroller */}
      <div className="overflow-x-auto pb-2 pt-1">
        <div className="flex items-stretch space-x-2 min-w-max">
          {timelineEvents.map((evt) => {
            const isMatched = selectedStageId && evt.matched_stage_id === selectedStageId;
            const d = new Date(evt.timestamp);
            const timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'UTC' }) + ' UTC';

            return (
              <div
                key={evt.id}
                role="button"
                tabIndex={0}
                onClick={() => {
                  if (onSelectEvent) onSelectEvent(evt);
                  if (evt.matched_stage_id && onSelectStage) {
                    onSelectStage(evt.matched_stage_id);
                  }
                }}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' || e.key === ' ') {
                    if (onSelectEvent) onSelectEvent(evt);
                    if (evt.matched_stage_id && onSelectStage) {
                      onSelectStage(evt.matched_stage_id);
                    }
                  }
                }}
                className={`w-64 p-3 rounded-lg border text-left transition-all cursor-pointer flex flex-col justify-between select-none ${
                  isMatched
                    ? 'bg-accent/10 border-accent shadow-xs ring-1 ring-accent'
                    : 'bg-surface-secondary/70 border-border hover:border-border-focus hover:bg-surface-secondary'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between text-[10px] font-mono text-foreground-muted mb-1">
                    <span className="font-semibold text-accent">{timeStr}</span>
                    <Badge
                      variant={
                        evt.severity === 'CRITICAL' || evt.severity === 'HIGH'
                          ? 'danger'
                          : evt.severity === 'MEDIUM'
                          ? 'warning'
                          : 'outline'
                      }
                      size="xs"
                      className="text-[8px] font-mono uppercase"
                    >
                      {evt.severity}
                    </Badge>
                  </div>
                  <div className="text-xs font-semibold text-foreground truncate font-sans" title={evt.title}>
                    {evt.title}
                  </div>
                  <div className="text-[10px] font-mono text-foreground-muted line-clamp-2 mt-1 leading-relaxed" title={evt.description}>
                    {evt.description}
                  </div>
                </div>

                <div className="pt-2 mt-2 border-t border-border/50 flex items-center justify-between text-[9px] font-mono text-foreground-muted">
                  <span className="truncate">Source: {evt.source}</span>
                  {evt.matched_stage_id && (
                    <span className={`px-1 py-0.5 rounded font-bold ${isMatched ? 'text-accent bg-accent/10' : 'text-foreground-muted'}`}>
                      Stage Mapped
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
