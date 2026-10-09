import React, { useState } from 'react';
import {
  History,
  CheckCircle2,
  XCircle,
  Clock,
  Play,
  User,
  ChevronRight,
} from 'lucide-react';
import type { ResponsePlaybookExecution } from '../../../types/response_playbook';
import type { ResponseRecommendation } from '../../../types/response_recommendation';

export interface TimelineActionItem {
  id: string;
  type: 'EXECUTION' | 'REVIEW' | 'GENERATION';
  title: string;
  description: string;
  timestamp: string;
  actor: string;
  status: string;
  referenceId: string;
  rawExecution?: ResponsePlaybookExecution;
  rawRecommendation?: ResponseRecommendation;
}

interface ActionHistoryTimelineProps {
  executions: ResponsePlaybookExecution[];
  recommendations: ResponseRecommendation[];
  onSelectExecution?: (execution: ResponsePlaybookExecution) => void;
  onSelectRecommendation?: (rec: ResponseRecommendation) => void;
}

export const ActionHistoryTimeline: React.FC<ActionHistoryTimelineProps> = ({
  executions,
  recommendations,
  onSelectExecution,
  onSelectRecommendation
}) => {
  const [filter, setFilter] = useState<'ALL' | 'EXECUTIONS' | 'REVIEWS'>('ALL');


  // Compile unified timeline items
  const timelineItems: TimelineActionItem[] = React.useMemo(() => {
    const items: TimelineActionItem[] = [];

    // Executions
    executions.forEach((exec) => {
      items.push({
        id: `exec-${exec.id}`,
        type: 'EXECUTION',
        title: `Playbook ${exec.mode === 'LIVE' ? 'Execution' : 'Dry-Run'}: ${exec.playbook_id}`,
        description: exec.result_summary || `Execution in ${exec.mode} mode (${exec.step_executions?.length || 0} steps)`,
        timestamp: exec.started_at,
        actor: exec.requested_by,
        status: exec.status,
        referenceId: exec.id,
        rawExecution: exec
      });
    });

    // Reviews & Approvals
    recommendations.forEach((rec) => {
      const targetIdentifier = rec.affected_entities?.[0]?.identifier || (rec as any).target_entity || 'Investigation Target';
      const reviewTimestamp = rec.reviewed_at || (rec as any).last_reviewed_at;
      if (reviewTimestamp) {
        items.push({
          id: `rev-${rec.id}`,
          type: 'REVIEW',
          title: `Recommendation ${rec.status}: ${rec.title}`,
          description: rec.status_reason || (rec as any).reviewer_notes || rec.description,
          timestamp: reviewTimestamp,
          actor: rec.reviewed_by || 'SOC Analyst',
          status: rec.status,
          referenceId: rec.id,
          rawRecommendation: rec
        });
      } else if (rec.created_at) {
        items.push({
          id: `gen-${rec.id}`,
          type: 'GENERATION',
          title: `Recommendation Generated: ${rec.title}`,
          description: `Generated for target ${targetIdentifier} with priority ${rec.priority}`,
          timestamp: rec.created_at,
          actor: 'CyberGuard Engine',
          status: 'GENERATED',
          referenceId: rec.id,
          rawRecommendation: rec
        });
      }
    });


    // Sort descending by timestamp
    return items.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  }, [executions, recommendations]);

  const filteredItems = timelineItems.filter((item) => {
    if (filter === 'EXECUTIONS') return item.type === 'EXECUTION';
    if (filter === 'REVIEWS') return item.type === 'REVIEW';
    return true;
  });

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between pb-2 border-b border-border">
        <div className="flex items-center gap-2.5">
          <History className="w-5 h-5 text-primary" />
          <div>
            <h3 className="text-sm font-bold text-foreground tracking-tight">
              Action & Audit History
            </h3>
            <p className="text-xs text-muted-foreground">
              Immutable timeline of real state transitions, analyst authorizations, and execution telemetry.
            </p>
          </div>
        </div>

        {/* Filter buttons */}
        <div className="flex items-center gap-1 bg-muted/60 p-0.5 rounded-lg border border-border">
          <button
            onClick={() => setFilter('ALL')}
            className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors ${
              filter === 'ALL'
                ? 'bg-card text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            All ({timelineItems.length})
          </button>
          <button
            onClick={() => setFilter('EXECUTIONS')}
            className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors ${
              filter === 'EXECUTIONS'
                ? 'bg-card text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Executions ({executions.length})
          </button>
          <button
            onClick={() => setFilter('REVIEWS')}
            className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-colors ${
              filter === 'REVIEWS'
                ? 'bg-card text-foreground shadow-sm'
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Reviews
          </button>
        </div>
      </div>

      {/* Timeline List */}
      {filteredItems.length === 0 ? (
        <div className="p-8 border border-border/80 border-dashed rounded-xl text-center bg-card/40 space-y-1">
          <History className="w-7 h-7 text-muted-foreground mx-auto opacity-50" />
          <div className="text-xs font-semibold text-foreground">No Response Actions Logged Yet</div>
          <div className="text-[11px] text-muted-foreground">
            Review recommendations or execute staged playbooks to establish an audit trail.
          </div>
        </div>
      ) : (
        <div className="relative border-l-2 border-border/80 ml-3.5 space-y-4 py-1">
          {filteredItems.map((item) => {
            const isExecution = item.type === 'EXECUTION';
            const isSuccess =
              item.status === 'COMPLETED' || item.status === 'APPROVED';
            const isFailed =
              item.status === 'FAILED' || item.status === 'REJECTED';

            return (
              <div key={item.id} className="relative pl-6 group">
                {/* Timeline node icon */}
                <div
                  className={`absolute -left-[17px] top-1 p-1 rounded-full border bg-card transition-all ${
                    isSuccess
                      ? 'border-emerald-500 text-emerald-400'
                      : isFailed
                      ? 'border-rose-500 text-rose-400'
                      : isExecution
                      ? 'border-primary text-primary'
                      : 'border-muted-foreground text-muted-foreground'
                  }`}
                >
                  {isSuccess ? (
                    <CheckCircle2 className="w-3.5 h-3.5" />
                  ) : isFailed ? (
                    <XCircle className="w-3.5 h-3.5" />
                  ) : isExecution ? (
                    <Play className="w-3.5 h-3.5" />
                  ) : (
                    <Clock className="w-3.5 h-3.5" />
                  )}
                </div>

                {/* Timeline Card */}
                <div
                  className="p-3.5 rounded-lg border border-border bg-card hover:bg-muted/30 transition-all cursor-pointer space-y-1.5 shadow-sm"
                  onClick={() => {
                    if (item.rawExecution && onSelectExecution) {
                      onSelectExecution(item.rawExecution);
                    } else if (item.rawRecommendation && onSelectRecommendation) {
                      onSelectRecommendation(item.rawRecommendation);
                    }
                  }}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-foreground">{item.title}</span>
                      <span
                        className={`text-[10px] font-mono font-bold uppercase px-1.5 py-0.5 rounded border ${
                          isSuccess
                            ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                            : isFailed
                            ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                            : 'bg-muted text-muted-foreground border-border'
                        }`}
                      >
                        {item.status}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-muted-foreground">
                      {new Date(item.timestamp).toLocaleTimeString([], {
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit'
                      })}
                    </span>
                  </div>

                  <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">
                    {item.description}
                  </p>

                  <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1.5 border-t border-border/50">
                    <div className="flex items-center gap-2">
                      <span className="flex items-center gap-1">
                        <User className="w-3 h-3 text-muted-foreground/70" />
                        <span className="font-mono text-foreground">{item.actor}</span>
                      </span>
                      <span className="text-border">•</span>
                      <span className="font-mono text-[10px] text-muted-foreground">
                        Ref: {item.referenceId}
                      </span>
                    </div>

                    <div className="text-[10px] font-semibold text-primary flex items-center gap-0.5 group-hover:translate-x-0.5 transition-transform">
                      <span>Inspect Details</span>
                      <ChevronRight className="w-3 h-3" />
                    </div>
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
