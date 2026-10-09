import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  X,
  ShieldAlert,
  FileText,
  FileCode,
  Globe,
  Database,
  ArrowRight,
  Loader2,
  Clock,
  Sparkles,
  Command,
  Filter,
} from 'lucide-react';
import type { SearchResultItem, SearchResourceType } from '../../types/search';
import { searchService } from '../../services/searchService';
import { RiskBadge, SeverityIndicator } from '../security';

interface GlobalSearchModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectIndicator?: (indicatorValue: string) => void;
}

export const GlobalSearchModal: React.FC<GlobalSearchModalProps> = ({
  isOpen,
  onClose,
  onSelectIndicator,
}) => {
  const navigate = useNavigate();
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const [query, setQuery] = useState('');
  const [selectedTypes, setSelectedTypes] = useState<SearchResourceType[]>([]);
  const [results, setResults] = useState<SearchResultItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selectedIndex, setSelectedIndex] = useState(0);

  // Focus input on open
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => {
        inputRef.current?.focus();
        inputRef.current?.select();
      }, 50);
    } else {
      setQuery('');
      setResults([]);
      setError(null);
      setSelectedIndex(0);
    }
  }, [isOpen]);

  // Debounced search
  useEffect(() => {
    if (!isOpen) return;
    if (!query.trim()) {
      setResults([]);
      setLoading(false);
      setError(null);
      return;
    }

    const timer = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const resp = await searchService.search({
          q: query.trim(),
          types: selectedTypes.length > 0 ? selectedTypes : undefined,
          limit: 25,
        });
        setResults(resp.results || []);
        setSelectedIndex(0);
      } catch (err: any) {
        console.error('Global search failed:', err);
        setError(err.message || 'Search execution failed');
        setResults([]);
      } finally {
        setLoading(false);
      }
    }, 250);

    return () => clearTimeout(timer);
  }, [query, selectedTypes, isOpen]);

  // Group results
  const groupedResults = useMemo(() => {
    const groups: { [key: string]: SearchResultItem[] } = {
      'EXACT MATCHES': [],
      'INVESTIGATIONS': [],
      'INDICATORS': [],
      'REPORTS': [],
      'EVIDENCE': [],
      'FINDINGS': [],
      'THREAT MEMORY': [],
    };

    results.forEach((item) => {
      if (item.relevance >= 0.95 && (item.type === 'indicator' || item.id === query.trim())) {
        groups['EXACT MATCHES'].push(item);
      } else if (item.type === 'investigation') {
        groups['INVESTIGATIONS'].push(item);
      } else if (item.type === 'indicator') {
        groups['INDICATORS'].push(item);
      } else if (item.type === 'report') {
        groups['REPORTS'].push(item);
      } else if (item.type === 'evidence') {
        groups['EVIDENCE'].push(item);
      } else if (item.type === 'finding') {
        groups['FINDINGS'].push(item);
      } else if (item.type === 'threat_memory') {
        groups['THREAT MEMORY'].push(item);
      } else {
        if (!groups['OTHER']) groups['OTHER'] = [];
        groups['OTHER'].push(item);
      }
    });

    return Object.entries(groups).filter(([_, items]) => items.length > 0);
  }, [results, query]);

  // Flattened list for keyboard indexing
  const flatItems = useMemo(() => {
    return groupedResults.flatMap(([_, items]) => items);
  }, [groupedResults]);

  const handleSelectResult = (item: SearchResultItem) => {
    onClose();
    if (item.type === 'indicator' && onSelectIndicator) {
      onSelectIndicator(item.title);
      return;
    }
    if (item.navigation_target) {
      navigate(item.navigation_target);
      return;
    }
    // Fallback navigation targets
    if (item.type === 'investigation') {
      navigate(`/investigations/${encodeURIComponent(item.id)}/overview`);
    } else if (item.type === 'report') {
      navigate(`/reports/${encodeURIComponent(item.id)}`);
    } else if (item.type === 'indicator') {
      navigate(`/investigations?q=${encodeURIComponent(item.title)}`);
    }
  };

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (flatItems.length === 0 ? 0 : (prev + 1) % flatItems.length));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (flatItems.length === 0 ? 0 : (prev - 1 + flatItems.length) % flatItems.length));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (flatItems[selectedIndex]) {
        handleSelectResult(flatItems[selectedIndex]);
      }
    }
  };

  const getItemIcon = (type: string) => {
    switch (type) {
      case 'investigation':
        return <ShieldAlert className="w-4 h-4 text-primary" />;
      case 'indicator':
        return <Globe className="w-4 h-4 text-accent" />;
      case 'report':
        return <FileText className="w-4 h-4 text-success" />;
      case 'evidence':
        return <FileCode className="w-4 h-4 text-warning" />;
      case 'threat_memory':
        return <Database className="w-4 h-4 text-indigo-400" />;
      default:
        return <Sparkles className="w-4 h-4 text-foreground-muted" />;
    }
  };

  const toggleTypeFilter = (t: SearchResourceType) => {
    setSelectedTypes((prev) =>
      prev.includes(t) ? prev.filter((item) => item !== t) : [...prev, t]
    );
  };

  if (!isOpen) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-12 sm:pt-20 px-4 bg-black/60 backdrop-blur-xs animate-in fade-in duration-150"
      onClick={onClose}
    >
      <div
        className="w-full max-w-2xl bg-surface border border-border rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[82vh] animate-in zoom-in-95 duration-150"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
      >
        {/* Search Input Bar */}
        <div className="relative flex items-center px-4 py-3 border-b border-border bg-surface-secondary/40">
          <Search className="w-5 h-5 text-foreground-muted shrink-0 mr-3" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search CyberGuard investigations, indicators, SHA-256, domains, reports..."
            className="w-full bg-transparent border-0 text-foreground placeholder:text-foreground-muted text-sm font-sans focus:outline-none"
            aria-label="Global search query"
          />
          {loading && (
            <Loader2 className="w-4 h-4 text-primary animate-spin shrink-0 ml-2" />
          )}
          {query && !loading && (
            <button
              type="button"
              onClick={() => setQuery('')}
              className="p-1 text-foreground-muted hover:text-foreground rounded cursor-pointer"
              title="Clear input"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <button
            type="button"
            onClick={onClose}
            className="ml-2 px-1.5 py-0.5 rounded text-[11px] font-mono text-foreground-muted border border-border hover:bg-surface-secondary cursor-pointer"
            title="Close dialog (Escape)"
          >
            ESC
          </button>
        </div>

        {/* Filter Chips Bar */}
        <div className="px-4 py-2 border-b border-border/60 bg-surface flex items-center space-x-1.5 overflow-x-auto text-[11px] font-mono">
          <span className="text-foreground-muted flex items-center mr-1">
            <Filter className="w-3 h-3 mr-1" /> Scope:
          </span>
          {(['investigation', 'indicator', 'report', 'evidence', 'threat_memory'] as SearchResourceType[]).map((t) => {
            const isSelected = selectedTypes.includes(t);
            return (
              <button
                key={t}
                type="button"
                onClick={() => toggleTypeFilter(t)}
                className={`px-2 py-0.5 rounded-full border transition-colors cursor-pointer capitalize ${
                  isSelected
                    ? 'bg-primary/15 border-primary/40 text-primary font-bold'
                    : 'bg-surface-secondary/50 border-border text-foreground-muted hover:text-foreground'
                }`}
              >
                {t.replace('_', ' ')}
              </button>
            );
          })}
          {selectedTypes.length > 0 && (
            <button
              type="button"
              onClick={() => setSelectedTypes([])}
              className="text-[10px] text-danger hover:underline ml-auto pl-2"
            >
              Reset
            </button>
          )}
        </div>

        {/* Results Body */}
        <div ref={listRef} className="overflow-y-auto p-2 space-y-3 flex-1 min-h-[160px]">
          {error && (
            <div className="p-4 text-xs font-mono text-danger bg-danger-surface border border-danger-border rounded-lg m-2">
              <strong>Search Error:</strong> {error}
            </div>
          )}

          {!query.trim() && !loading && (
            <div className="py-10 px-6 text-center">
              <div className="inline-flex p-3 rounded-full bg-surface-secondary mb-3">
                <Command className="w-6 h-6 text-foreground-muted" />
              </div>
              <h4 className="text-sm font-semibold text-foreground mb-1">
                Unified Investigation & Evidence Discovery
              </h4>
              <p className="text-xs text-foreground-muted max-w-md mx-auto mb-4 font-mono">
                Type an exact indicator (domain, IP, SHA-256 hash), an investigation ID (e.g. INV-...), report title, or keywords to query persistent telemetry.
              </p>
              <div className="flex flex-wrap items-center justify-center gap-2 text-[11px] font-mono text-foreground-muted">
                <span className="bg-surface-secondary px-2 py-1 rounded border border-border">↑ / ↓ Navigate</span>
                <span className="bg-surface-secondary px-2 py-1 rounded border border-border">↵ Select</span>
                <span className="bg-surface-secondary px-2 py-1 rounded border border-border">ESC Close</span>
              </div>
            </div>
          )}

          {query.trim() && !loading && flatItems.length === 0 && !error && (
            <div className="py-10 px-6 text-center">
              <p className="text-sm font-medium text-foreground mb-1">
                No persistent records match &quot;{query}&quot;
              </p>
              <p className="text-xs text-foreground-muted font-mono max-w-sm mx-auto">
                Check spelling, remove scope filters, or verify whether this indicator has been ingested into CyberGuard.
              </p>
            </div>
          )}

          {groupedResults.map(([groupName, items]) => (
            <div key={groupName} className="space-y-1">
              <div className="px-3 py-1 text-[10px] font-mono font-bold text-foreground-muted tracking-wider uppercase">
                {groupName} ({items.length})
              </div>
              <div className="space-y-0.5">
                {items.map((item) => {
                  const itemIndex = flatItems.indexOf(item);
                  const isSelected = itemIndex === selectedIndex;

                  return (
                    <div
                      key={`${item.type}-${item.id}`}
                      onClick={() => handleSelectResult(item)}
                      onMouseEnter={() => setSelectedIndex(itemIndex)}
                      className={`px-3 py-2.5 rounded-lg flex items-center justify-between cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-primary/10 border border-primary/30'
                          : 'hover:bg-surface-secondary/70 border border-transparent'
                      }`}
                    >
                      <div className="flex items-center space-x-3 min-w-0 flex-1">
                        <div className="p-1.5 rounded-md bg-surface-secondary shrink-0 border border-border">
                          {getItemIcon(item.type)}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center space-x-2">
                            <span className="text-xs font-semibold text-foreground truncate">
                              {item.title}
                            </span>
                            {item.relevance >= 0.95 && (
                              <span className="text-[9px] font-mono px-1 py-0.2 rounded bg-accent/20 text-accent font-bold">
                                EXACT
                              </span>
                            )}
                            {item.status && (
                              <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-surface-secondary text-foreground-muted border border-border uppercase">
                                {item.status}
                              </span>
                            )}
                          </div>
                          <div className="flex items-center space-x-2 text-[10px] font-mono text-foreground-muted mt-0.5 truncate">
                            <span className="truncate">{item.subtitle || item.id}</span>
                            {item.source_type && (
                              <span>• {item.source_type}</span>
                            )}
                            {(item.matched_fields || (item.matched_field ? [item.matched_field] : [])) && (item.matched_fields || (item.matched_field ? [item.matched_field] : [])).length > 0 && (
                              <span className="text-primary font-bold">
                                • matched: {(item.matched_fields || (item.matched_field ? [item.matched_field] : [])).join(', ')}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0 ml-3">
                        {(item.risk_score !== undefined || item.risk !== undefined) && (
                          <RiskBadge score={item.risk_score ?? item.risk ?? 0} size="xs" variant="minimal" />
                        )}
                        {item.severity && item.risk_score === undefined && item.risk === undefined && (
                          <SeverityIndicator severity={item.severity} size="xs" />
                        )}
                        {item.timestamp && (
                          <span className="text-[10px] font-mono text-foreground-muted hidden sm:inline flex items-center">
                            <Clock className="w-2.5 h-2.5 mr-1" />
                            {new Date(item.timestamp).toLocaleDateString()}
                          </span>
                        )}
                        <ArrowRight className={`w-3.5 h-3.5 transition-transform ${isSelected ? 'text-primary translate-x-0.5' : 'text-foreground-muted'}`} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* Modal Footer */}
        <div className="px-4 py-2 border-t border-border bg-surface-secondary/40 flex items-center justify-between text-[11px] font-mono text-foreground-muted">
          <div className="flex items-center space-x-3">
            <span>CyberGuard Discovery Layer</span>
            {results.length > 0 && (
              <span>• {results.length} result(s)</span>
            )}
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="hidden sm:inline">Press</span>
            <kbd className="px-1.5 py-0.5 rounded bg-surface border border-border text-[10px]">↵</kbd>
            <span className="hidden sm:inline">to open</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default GlobalSearchModal;
