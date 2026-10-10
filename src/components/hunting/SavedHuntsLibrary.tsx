import React, { useState } from 'react';
import {
  Bookmark,
  Sparkles,
  Play,
  Trash2,
  Clock,
  Layers,
  Search,
} from 'lucide-react';
import type { SavedHuntResponse, HuntQueryDefinition } from '../../types/hunting';

interface SavedHuntsLibraryProps {
  items: SavedHuntResponse[];
  templates: SavedHuntResponse[];
  loading: boolean;
  onSelectAndRun: (queryDef: HuntQueryDefinition, savedId?: string) => void;
  onDelete: (id: string) => void;
}

export const SavedHuntsLibrary: React.FC<SavedHuntsLibraryProps> = ({
  items,
  templates,
  loading,
  onSelectAndRun,
  onDelete,
}) => {
  const [activeTab, setActiveTab] = useState<'custom' | 'templates'>('custom');
  const [searchTerm, setSearchTerm] = useState('');

  const displayedList = activeTab === 'custom' ? items : templates;
  const filteredList = displayedList.filter(
    (h) =>
      h.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (h.description && h.description.toLowerCase().includes(searchTerm.toLowerCase())) ||
      (h.hypothesis && h.hypothesis.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  return (
    <div className="space-y-4">
      {/* Tab Switcher & Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-surface border border-border rounded-panel">
        <div className="flex items-center space-x-1.5 p-1 bg-surface-secondary rounded-control border border-border shrink-0">
          <button
            onClick={() => setActiveTab('custom')}
            className={`px-3 py-1.5 rounded-control text-xs font-mono transition-colors cursor-pointer flex items-center space-x-1.5 ${
              activeTab === 'custom'
                ? 'bg-surface text-foreground font-bold shadow-xs'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Bookmark className="w-3.5 h-3.5" />
            <span>Saved Hunts ({items.length})</span>
          </button>
          <button
            onClick={() => setActiveTab('templates')}
            className={`px-3 py-1.5 rounded-control text-xs font-mono transition-colors cursor-pointer flex items-center space-x-1.5 ${
              activeTab === 'templates'
                ? 'bg-surface text-foreground font-bold shadow-xs'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5 text-primary" />
            <span>Built-in Templates ({templates.length})</span>
          </button>
        </div>

        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-2.5 w-3.5 h-3.5 text-foreground-muted" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search hunts by name, hypothesis, or tag..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary"
          />
        </div>
      </div>

      {/* Library Grid */}
      {loading ? (
        <div className="p-12 text-center text-foreground-muted text-xs">Loading hunt library...</div>
      ) : filteredList.length === 0 ? (
        <div className="p-12 text-center border border-dashed border-border rounded-panel bg-surface">
          <p className="text-xs text-foreground-muted mb-1">No hunts found matching criteria.</p>
          <p className="text-[11px] text-foreground-muted/70">
            {activeTab === 'custom'
              ? 'Execute a query in the workspace and click "Save Hunt" to add reusable queries here.'
              : 'Built-in templates will populate automatically.'}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredList.map((hunt) => (
            <div
              key={hunt.id}
              className="bg-surface border border-border rounded-panel p-4 hover:border-border/80 transition-all shadow-xs flex flex-col justify-between"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <div>
                    <div className="flex items-center space-x-2 mb-1">
                      <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono uppercase bg-primary/10 text-primary border border-primary/20">
                        {hunt.data_source}
                      </span>
                      {hunt.is_template && (
                        <span className="px-1.5 py-0.5 rounded-control text-[9px] font-mono uppercase bg-amber-500/10 text-amber-500 border border-amber-500/20">
                          Template
                        </span>
                      )}
                      <span className="text-[10px] font-mono text-foreground-muted uppercase">
                        {hunt.visibility}
                      </span>
                    </div>
                    <h4 className="text-sm font-sans font-bold text-foreground">{hunt.name}</h4>
                  </div>

                  {!hunt.is_template && (
                    <button
                      onClick={() => onDelete(hunt.id)}
                      className="p-1 text-foreground-muted hover:text-threat-critical rounded-control hover:bg-surface-secondary transition-colors cursor-pointer"
                      title="Delete Saved Hunt"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>

                {hunt.description && (
                  <p className="text-xs text-foreground-muted mb-3 line-clamp-2">{hunt.description}</p>
                )}

                {hunt.hypothesis && (
                  <div className="p-2.5 bg-surface-secondary/70 border border-border rounded-control mb-3 text-[11px]">
                    <span className="font-mono text-foreground-muted text-[10px] uppercase block mb-0.5">
                      Hypothesis:
                    </span>
                    <p className="text-foreground italic">{hunt.hypothesis}</p>
                  </div>
                )}

                {hunt.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1 mb-3">
                    {hunt.tags.map((t, idx) => (
                      <span
                        key={idx}
                        className="px-1.5 py-0.5 rounded-control text-[9px] font-mono bg-surface-secondary text-foreground-muted border border-border"
                      >
                        #{t}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div className="pt-3 border-t border-border flex items-center justify-between mt-2">
                <div className="text-[10px] font-mono text-foreground-muted flex items-center space-x-3">
                  {hunt.last_executed_at && (
                    <span className="flex items-center space-x-1" title="Last Executed">
                      <Clock className="w-3 h-3" />
                      <span>{new Date(hunt.last_executed_at).toLocaleDateString()}</span>
                    </span>
                  )}
                  {hunt.last_result_count !== undefined && (
                    <span className="flex items-center space-x-1" title="Last Match Count">
                      <Layers className="w-3 h-3" />
                      <span>{hunt.last_result_count} hits</span>
                    </span>
                  )}
                </div>

                <button
                  onClick={() => onSelectAndRun(hunt.query_definition, hunt.id)}
                  className="px-3 py-1.5 text-xs font-mono font-medium text-white bg-primary hover:bg-primary/90 rounded-control flex items-center space-x-1.5 shadow-xs cursor-pointer"
                >
                  <Play className="w-3 h-3 fill-white" />
                  <span>Load & Run</span>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
