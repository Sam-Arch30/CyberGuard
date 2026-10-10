import React, { useState, useEffect } from 'react';
import {
  Compass,
  Bookmark,
  Database,
  AlertTriangle,
  CheckCircle,
  X,
} from 'lucide-react';
import type {
  DataSourceMetadata,
  HuntQueryDefinition,
  HuntSource,
  HuntQueryResultResponse,
  SavedHuntResponse,
  SavedHuntCreateRequest,
  HuntResultItem,
} from '../types/hunting';
import { huntingService } from '../services/huntingService';
import { QueryBuilder } from '../components/hunting/QueryBuilder';
import { HuntResultsTable } from '../components/hunting/HuntResultsTable';
import { SavedHuntsLibrary } from '../components/hunting/SavedHuntsLibrary';
import { InvestigationHandoffModal } from '../components/hunting/InvestigationHandoffModal';
import { WatchlistHandoffModal } from '../components/hunting/WatchlistHandoffModal';
import { PivotPanel } from '../components/hunting/pivots/PivotPanel';

export const ThreatHunting: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'workspace' | 'library'>('workspace');

  // Registry & State
  const [registry, setRegistry] = useState<DataSourceMetadata[]>([]);

  // Active Query
  const [query, setQuery] = useState<HuntQueryDefinition>({
    data_source: 'indicators' as HuntSource,
    filters: [],
    time_range: { preset: '7d' },
    limit: 50,
    offset: 0,
  });

  // Query Execution State
  const [executing, setExecuting] = useState(false);
  const [results, setResults] = useState<HuntQueryResultResponse | null>(null);
  const [executionError, setExecutionError] = useState<string | null>(null);

  // Saved Hunts Library State
  const [savedItems, setSavedItems] = useState<SavedHuntResponse[]>([]);
  const [templates, setTemplates] = useState<SavedHuntResponse[]>([]);
  const [loadingLibrary, setLoadingLibrary] = useState(false);

  // Save Modal State
  const [isSaveModalOpen, setIsSaveModalOpen] = useState(false);
  const [saveName, setSaveName] = useState('');
  const [saveDescription, setSaveDescription] = useState('');
  const [saveHypothesis, setSaveHypothesis] = useState('');
  const [saveTags, setSaveTags] = useState('hunting, suspicious');
  const [saveVisibility, setSaveVisibility] = useState<'TEAM' | 'PRIVATE' | 'TENANT'>('TEAM');

  // Handoff Modals
  const [handoffInvOpen, setHandoffInvOpen] = useState(false);
  const [handoffWlOpen, setHandoffWlOpen] = useState(false);
  const [selectedHandoffIds, setSelectedHandoffIds] = useState<string[]>([]);

  // Section 55: Advanced Pivots State
  const [pivotPanelOpen, setPivotPanelOpen] = useState(false);
  const [pivotSourceType, setPivotSourceType] = useState('DOMAIN');
  const [pivotSourceValue, setPivotSourceValue] = useState('');

  const inferSourceType = (item: HuntResultItem): string => {
    if (item.properties?.indicator_type) return String(item.properties.indicator_type).toUpperCase();
    if (item.properties?.type) return String(item.properties.type).toUpperCase();
    const val = item.primary_value.trim();
    if (val.includes('@')) return 'EMAIL';
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) return 'IP';
    if (/^[a-fA-F0-9]{32,64}$/.test(val)) return 'HASH';
    if (val.startsWith('http://') || val.startsWith('https://')) return 'URL';
    if (/^AS\d+$/i.test(val)) return 'ASN';
    return 'DOMAIN';
  };

  const handleOpenPivot = (item: HuntResultItem) => {
    setPivotSourceType(inferSourceType(item));
    setPivotSourceValue(item.primary_value);
    setPivotPanelOpen(true);
  };

  const handleHandoffToHunt = (queryDef: HuntQueryDefinition) => {
    setQuery(queryDef);
    setActiveTab('workspace');
    showToast('Applied iterative hunt query from pivot targets. Ready to execute.');
  };

  // Banner Feedback
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // Load Data Source Registry & Library
  useEffect(() => {
    loadRegistry();
    loadLibrary();
  }, []);

  const loadRegistry = async () => {
    try {
      const res = await huntingService.getRegistry();
      setRegistry(res.sources);
    } catch (err) {
      console.error('Failed to load registry', err);
    }
  };

  const loadLibrary = async () => {
    try {
      setLoadingLibrary(true);
      const res = await huntingService.listSavedHunts();
      setSavedItems(res.items);
      setTemplates(res.templates);
    } catch (err) {
      console.error('Failed to load saved hunts', err);
    } finally {
      setLoadingLibrary(false);
    }
  };

  // Execute Query
  const handleExecute = async () => {
    setExecuting(true);
    setExecutionError(null);
    try {
      const res = await huntingService.executeHunt({
        query_definition: query,
        execution_mode: 'FAST',
      });
      setResults(res);
      showToast(`Hunt executed successfully: ${res.total_matches} records matched.`);
    } catch (err: any) {
      setExecutionError(err.message || 'Execution failed');
    } finally {
      setExecuting(false);
    }
  };

  // Save Hunt Submission
  const handleSaveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!saveName.trim()) return;

    try {
      const payload: SavedHuntCreateRequest = {
        name: saveName.trim(),
        description: saveDescription.trim() || undefined,
        data_source: query.data_source,
        query_definition: query,
        hypothesis: saveHypothesis.trim() || undefined,
        tags: saveTags.split(',').map((t) => t.trim()).filter(Boolean),
        visibility: saveVisibility,
      };

      await huntingService.createSavedHunt(payload);
      setIsSaveModalOpen(false);
      setSaveName('');
      setSaveDescription('');
      setSaveHypothesis('');
      showToast('Hunt query successfully saved to Library.');
      loadLibrary();
    } catch (err: any) {
      alert(err.message || 'Failed to save hunt.');
    }
  };

  // Load from Library
  const handleSelectAndRun = (loadedQuery: HuntQueryDefinition, savedId?: string) => {
    setQuery(loadedQuery);
    setActiveTab('workspace');
    showToast('Loaded query into workspace. Executing threat hunt...');

    // Trigger execution
    setTimeout(async () => {
      setExecuting(true);
      setExecutionError(null);
      try {
        const res = await huntingService.executeHunt({
          query_definition: loadedQuery,
          saved_hunt_id: savedId,
          execution_mode: 'FAST',
        });
        setResults(res);
      } catch (err: any) {
        setExecutionError(err.message || 'Execution failed');
      } finally {
        setExecuting(false);
      }
    }, 100);
  };

  const handleDeleteSavedHunt = async (id: string) => {
    if (!confirm('Are you sure you want to delete this saved hunt?')) return;
    try {
      await huntingService.deleteSavedHunt(id);
      loadLibrary();
      showToast('Saved hunt deleted.');
    } catch (err: any) {
      alert(err.message || 'Failed to delete saved hunt.');
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 py-6 space-y-6 animate-in fade-in duration-200">
      {/* 1. Header & Context Ribbon */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border pb-5">
        <div>
          <div className="flex items-center space-x-2 text-xs font-mono text-primary uppercase tracking-wider mb-1">
            <Compass className="w-4 h-4" />
            <span>Section 54 • Proactive Cyber Defense</span>
          </div>
          <h1 className="text-2xl font-sans font-bold text-foreground tracking-tight">
            Threat Hunting Workspace
          </h1>
          <p className="text-xs text-foreground-muted mt-1 max-w-2xl">
            Proactively query existing CyberGuard forensic data, detect suspicious anomalies across IOCs and alerts, and pivot into investigations.
          </p>
        </div>

        {/* Telemetry Stat Cards */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="px-3 py-2 bg-surface border border-border rounded-panel text-center">
            <span className="block text-[10px] font-mono text-foreground-muted uppercase">Datasets</span>
            <span className="text-sm font-mono font-bold text-foreground">{registry.length}</span>
          </div>
          <div className="px-3 py-2 bg-surface border border-border rounded-panel text-center">
            <span className="block text-[10px] font-mono text-foreground-muted uppercase">Saved Hunts</span>
            <span className="text-sm font-mono font-bold text-primary">{savedItems.length}</span>
          </div>
          <div className="px-3 py-2 bg-surface border border-border rounded-panel text-center">
            <span className="block text-[10px] font-mono text-foreground-muted uppercase">Templates</span>
            <span className="text-sm font-mono font-bold text-amber-500">{templates.length}</span>
          </div>
        </div>
      </div>

      {/* Toast Feedback */}
      {toastMessage && (
        <div className="p-3 bg-primary/10 border border-primary/20 rounded-panel text-xs text-foreground flex items-center justify-between animate-in fade-in slide-in-from-top-1">
          <div className="flex items-center space-x-2">
            <CheckCircle className="w-4 h-4 text-primary shrink-0" />
            <span>{toastMessage}</span>
          </div>
          <button onClick={() => setToastMessage(null)} className="text-foreground-muted hover:text-foreground">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 2. Primary Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-border">
        <button
          onClick={() => setActiveTab('workspace')}
          className={`px-4 py-2 text-xs font-mono transition-colors border-b-2 cursor-pointer flex items-center space-x-2 ${
            activeTab === 'workspace'
              ? 'border-primary text-primary font-bold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <Database className="w-3.5 h-3.5" />
          <span>Query & Hunt Workspace</span>
        </button>
        <button
          onClick={() => setActiveTab('library')}
          className={`px-4 py-2 text-xs font-mono transition-colors border-b-2 cursor-pointer flex items-center space-x-2 ${
            activeTab === 'library'
              ? 'border-primary text-primary font-bold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <Bookmark className="w-3.5 h-3.5" />
          <span>Hunt Library & Templates ({savedItems.length + templates.length})</span>
        </button>
      </div>

      {/* 3. Main Workspace View */}
      {activeTab === 'workspace' && (
        <div className="space-y-6">
          <QueryBuilder
            registry={registry}
            query={query}
            onChangeQuery={setQuery}
            onExecute={handleExecute}
            onSave={() => setIsSaveModalOpen(true)}
            executing={executing}
          />

          {executionError && (
            <div className="p-4 bg-threat-critical/10 border border-threat-critical/20 rounded-panel text-xs text-threat-critical flex items-start space-x-2.5">
              <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold block mb-0.5">Threat Hunt Execution Error</span>
                <span>{executionError}</span>
              </div>
            </div>
          )}

          {results && (
            <HuntResultsTable
              results={results}
              onOpenInvestigationModal={(ids) => {
                setSelectedHandoffIds(ids);
                setHandoffInvOpen(true);
              }}
              onOpenWatchlistModal={(ids) => {
                setSelectedHandoffIds(ids);
                setHandoffWlOpen(true);
              }}
              onOpenPivotModal={handleOpenPivot}
            />
          )}
        </div>
      )}

      {/* 4. Hunt Library View */}
      {activeTab === 'library' && (
        <SavedHuntsLibrary
          items={savedItems}
          templates={templates}
          loading={loadingLibrary}
          onSelectAndRun={handleSelectAndRun}
          onDelete={handleDeleteSavedHunt}
        />
      )}

      {/* 5. Save Hunt Modal */}
      {isSaveModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-panel w-full max-w-lg shadow-2xl p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-sans font-bold text-foreground flex items-center space-x-2">
                <Bookmark className="w-4 h-4 text-primary" />
                <span>Save Threat Hunt Query</span>
              </h3>
              <button onClick={() => setIsSaveModalOpen(false)} className="text-foreground-muted hover:text-foreground">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveSubmit} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1">Hunt Name</label>
                <input
                  type="text"
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  placeholder="e.g. Unresolved Critical Infrastructure C2"
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary"
                  required
                />
              </div>

              <div>
                <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1">Description</label>
                <input
                  type="text"
                  value={saveDescription}
                  onChange={(e) => setSaveDescription(e.target.value)}
                  placeholder="Operational context for SOC peers..."
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1">Analytical Hypothesis</label>
                <textarea
                  value={saveHypothesis}
                  onChange={(e) => setSaveHypothesis(e.target.value)}
                  rows={2}
                  placeholder="What suspicious behavior or pattern does this hunt test?"
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary resize-none"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1">Tags (comma-separated)</label>
                  <input
                    type="text"
                    value={saveTags}
                    onChange={(e) => setSaveTags(e.target.value)}
                    className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary"
                  />
                </div>
                <div>
                  <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1">Visibility</label>
                  <select
                    value={saveVisibility}
                    onChange={(e) => setSaveVisibility(e.target.value as any)}
                    className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary"
                  >
                    <option value="TEAM">Team (Shared)</option>
                    <option value="PRIVATE">Private (Only Me)</option>
                    <option value="TENANT">Tenant (All Workspaces)</option>
                  </select>
                </div>
              </div>

              <div className="pt-3 border-t border-border flex items-center justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setIsSaveModalOpen(false)}
                  className="px-3 py-1.5 rounded-control border border-border text-foreground-muted hover:text-foreground"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-control bg-primary text-white font-medium hover:bg-primary/90"
                >
                  Save Hunt
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* 6. Handoff Modals */}
      {results && (
        <>
          <InvestigationHandoffModal
            isOpen={handoffInvOpen}
            onClose={() => setHandoffInvOpen(false)}
            executionId={results.execution_id}
            selectedIds={selectedHandoffIds}
            onSuccess={(invId) => {
              showToast(`Investigation created successfully (ID: ${invId.slice(0, 8)}).`);
            }}
          />

          <WatchlistHandoffModal
            isOpen={handoffWlOpen}
            onClose={() => setHandoffWlOpen(false)}
            executionId={results.execution_id}
            selectedIds={selectedHandoffIds}
            onSuccess={(wlId) => {
              showToast(`Indicators added to Watchlist (ID: ${wlId.slice(0, 8)}).`);
            }}
          />
        </>
      )}

      {/* 7. Section 55: Advanced Threat Hunting & Investigation Pivots Workspace */}
      <PivotPanel
        isOpen={pivotPanelOpen}
        onClose={() => setPivotPanelOpen(false)}
        initialSourceType={pivotSourceType}
        initialSourceValue={pivotSourceValue}
        onHandoffToHunt={handleHandoffToHunt}
      />
    </div>
  );
};

export default ThreatHunting;
