import React, { useState } from 'react';
import {
  Mail,
  Globe,
  Server,
  Link as LinkIcon,
  Users,
  Clock,
  Copy,
  Check,
  Activity
} from 'lucide-react';
import type { CampaignTimelineEvent } from '../../types/campaign';

interface CampaignTimelineProps {
  events: CampaignTimelineEvent[];
  className?: string;
}

export const CampaignTimeline: React.FC<CampaignTimelineProps> = ({ events, className = '' }) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('all');
  const [copiedIndicator, setCopiedIndicator] = useState<string | null>(null);

  const handleCopy = (val: string, e: React.MouseEvent) => {
    e.stopPropagation();
    navigator.clipboard.writeText(val);
    setCopiedIndicator(val);
    setTimeout(() => setCopiedIndicator(null), 2000);
  };

  const getEventBadge = (type: string) => {
    switch (type.toLowerCase()) {
      case 'first_email':
        return {
          icon: Mail,
          label: 'First Email',
          color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30 ring-cyan-500/20'
        };
      case 'new_domain':
        return {
          icon: Globe,
          label: 'New Domain',
          color: 'text-purple-400 bg-purple-500/10 border-purple-500/30 ring-purple-500/20'
        };
      case 'infrastructure_change':
        return {
          icon: Server,
          label: 'Infrastructure Shift',
          color: 'text-amber-400 bg-amber-500/10 border-amber-500/30 ring-amber-500/20'
        };
      case 'new_url':
        return {
          icon: LinkIcon,
          label: 'New URL Lure',
          color: 'text-rose-400 bg-rose-500/10 border-rose-500/30 ring-rose-500/20'
        };
      case 'victim_expansion':
        return {
          icon: Users,
          label: 'Victim Expansion',
          color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30 ring-emerald-500/20'
        };
      default:
        return {
          icon: Activity,
          label: 'Activity',
          color: 'text-primary bg-primary/10 border-primary/30 ring-primary/20'
        };
    }
  };

  const filteredEvents = events.filter(evt => {
    if (selectedCategory === 'all') return true;
    return evt.event_type.toLowerCase() === selectedCategory.toLowerCase();
  });

  const categories = [
    { id: 'all', label: 'All Timeline Events', count: events.length },
    { id: 'first_email', label: 'First Email', count: events.filter(e => e.event_type === 'first_email').length },
    { id: 'new_domain', label: 'New Domains', count: events.filter(e => e.event_type === 'new_domain').length },
    { id: 'infrastructure_change', label: 'Infrastructure', count: events.filter(e => e.event_type === 'infrastructure_change').length },
    { id: 'new_url', label: 'New URLs', count: events.filter(e => e.event_type === 'new_url').length },
    { id: 'victim_expansion', label: 'Victim Expansion', count: events.filter(e => e.event_type === 'victim_expansion').length }
  ];

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Category Filter Pills */}
      <div className="flex flex-wrap items-center gap-2 p-1 bg-surface-secondary/50 rounded-xl border border-border">
        {categories.map(cat => (
          <button
            key={cat.id}
            type="button"
            onClick={() => setSelectedCategory(cat.id)}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              selectedCategory === cat.id
                ? 'bg-surface text-primary border border-primary/30 shadow-xs font-semibold'
                : 'text-foreground-muted hover:text-foreground hover:bg-surface/50 border border-transparent'
            }`}
          >
            <span>{cat.label}</span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded-full ${
              selectedCategory === cat.id ? 'bg-primary/20 text-primary font-bold' : 'bg-surface text-foreground-muted'
            }`}>
              {cat.count}
            </span>
          </button>
        ))}
      </div>

      {/* Timeline Vertical Stream */}
      {filteredEvents.length === 0 ? (
        <div className="p-8 text-center rounded-xl bg-surface-secondary/40 border border-border space-y-2">
          <p className="text-xs text-foreground-muted font-mono">No events recorded in this category.</p>
        </div>
      ) : (
        <div className="relative pl-6 sm:pl-8 space-y-6 before:absolute before:left-3 sm:before:left-4 before:top-3 before:bottom-3 before:w-0.5 before:bg-gradient-to-b before:from-primary before:via-warning before:to-surface-secondary">
          {filteredEvents.map((evt, idx) => {
            const badge = getEventBadge(evt.event_type);
            const Icon = badge.icon;

            return (
              <div key={evt.id || idx} className="relative group">
                {/* Node Ring Icon on the track */}
                <div
                  className={`absolute -left-6 sm:-left-8 top-1 w-6 h-6 sm:w-8 sm:h-8 rounded-full border-2 flex items-center justify-center transition-all group-hover:scale-110 shadow-xs ring-4 ${badge.color}`}
                >
                  <Icon className="w-3 h-3 sm:w-3.5 sm:h-3.5" />
                </div>

                {/* Event Card Content */}
                <div className="p-4 rounded-xl bg-surface border border-border hover:border-primary/40 transition-all shadow-xs space-y-2.5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center space-x-2.5">
                      <span className={`px-2.5 py-0.5 rounded-full border text-[11px] font-mono font-bold uppercase tracking-wider ${badge.color}`}>
                        {badge.label}
                      </span>
                      <h4 className="text-sm font-bold text-foreground font-sans">{evt.title}</h4>
                    </div>

                    <div className="flex items-center space-x-1.5 text-xs font-mono text-foreground-muted">
                      <Clock className="w-3.5 h-3.5" />
                      <span>{evt.timestamp}</span>
                    </div>
                  </div>

                  <p className="text-xs text-foreground-muted font-mono leading-relaxed">{evt.description}</p>

                  {/* Indicators list */}
                  {evt.indicators && evt.indicators.length > 0 && (
                    <div className="pt-2 border-t border-border flex flex-wrap items-center gap-1.5">
                      <span className="text-[10px] font-mono uppercase text-foreground-muted font-semibold mr-1">
                        IOCs:
                      </span>
                      {evt.indicators.map((ind, i) => (
                        <div
                          key={i}
                          className="inline-flex items-center space-x-1 px-2 py-0.5 rounded bg-surface-secondary border border-border text-xs font-mono text-foreground"
                        >
                          <span className="truncate max-w-[200px] sm:max-w-xs">{ind}</span>
                          <button
                            type="button"
                            onClick={(e) => handleCopy(ind, e)}
                            className="text-foreground-muted hover:text-foreground transition-colors p-0.5"
                            title="Copy indicator"
                          >
                            {copiedIndicator === ind ? (
                              <Check className="w-3 h-3 text-success" />
                            ) : (
                              <Copy className="w-3 h-3" />
                            )}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
