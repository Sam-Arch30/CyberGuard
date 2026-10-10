import React, { useState, useEffect } from 'react';
import {
  Plus,
  Play,
  RotateCcw,
  Sparkles,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  GitCompare,
  Terminal,
  Activity,
  Trash2,
  Eye,
  Sliders,
  Check,
  AlertOctagon,
  HelpCircle,
  Layers,
} from 'lucide-react';
import type {
  DetectionRule,
  DetectionRuleValidationResult,
  DetectionRuleBacktestResult,
  RuleVersionDiff,
  DetectionRuleStats,
  FieldDefinition,
  RuleCondition,
  RuleDefinition,
  RuleLifecycleStatus,
} from '../types/detectionRules';
import { detectionRuleService } from '../services/detectionRuleService';

export const DetectionRules: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'catalog' | 'builder' | 'detail'>('catalog');

  // Stats & Catalog Data
  const [stats, setStats] = useState<DetectionRuleStats | null>(null);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loadingRules, setLoadingRules] = useState(false);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);

  // Field Registry for Builder & Operator Checking
  const [fieldRegistry, setFieldRegistry] = useState<FieldDefinition[]>([]);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');

  // Toast feedback
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // --------------------------------------------------------------------------
  // Rule Builder State
  // --------------------------------------------------------------------------
  const [builderName, setBuilderName] = useState('');
  const [builderDesc, setBuilderDesc] = useState('');
  const [builderCategory, setBuilderCategory] = useState('PHISHING');
  const [builderSeverity, setBuilderSeverity] = useState('HIGH');
  const [builderDataSource, setBuilderDataSource] = useState('EMAIL_EVENT');
  const [builderLogicalOp, setBuilderLogicalOp] = useState<'AND' | 'OR'>('AND');
  const [builderConditions, setBuilderConditions] = useState<RuleCondition[]>([
    { field: 'sender_domain', operator: 'CONTAINS', value: 'security-alert' },
  ]);
  const [builderTags, setBuilderTags] = useState('phishing, credential-theft');
  const [builderTechniques, setBuilderTechniques] = useState('T1566.002');
  const [validationResult, setValidationResult] = useState<DetectionRuleValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [savingRule, setSavingRule] = useState(false);

  // --------------------------------------------------------------------------
  // AI Suggestion State
  // --------------------------------------------------------------------------
  const [isAiModalOpen, setIsAiModalOpen] = useState(false);
  const [aiPrompt, setAiPrompt] = useState('');
  const [generatingAi, setGeneratingAi] = useState(false);

  // --------------------------------------------------------------------------
  // Backtest State
  // --------------------------------------------------------------------------
  const [backtestPreset, setBacktestPreset] = useState<'LAST_24_HOURS' | 'LAST_7_DAYS' | 'LAST_30_DAYS'>('LAST_30_DAYS');
  const [backtestRunning, setBacktestRunning] = useState(false);
  const [backtestResult, setBacktestResult] = useState<DetectionRuleBacktestResult | null>(null);

  // --------------------------------------------------------------------------
  // Version Diff State
  // --------------------------------------------------------------------------
  const [diffResult, setDiffResult] = useState<RuleVersionDiff | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);

  // --------------------------------------------------------------------------
  // Live Event Test State
  // --------------------------------------------------------------------------
  const [testPayloadStr, setTestPayloadStr] = useState(
    JSON.stringify(
      {
        id: 'test-event-01',
        sender_domain: 'security-alert-corp.com',
        contains_login_url: true,
        url_count: 3,
      },
      null,
      2
    )
  );
  const [evaluatingTest, setEvaluatingTest] = useState(false);
  const [testMatchResult, setTestMatchResult] = useState<any[] | null>(null);

  // --------------------------------------------------------------------------
  // Lifecycle Transition Modal State
  // --------------------------------------------------------------------------
  const [transitionAction, setTransitionAction] = useState<string | null>(null);
  const [transitionReason, setTransitionReason] = useState('');
  const [transitioning, setTransitioning] = useState(false);

  // --------------------------------------------------------------------------
  // Data Loaders
  // --------------------------------------------------------------------------
  const refreshStats = async () => {
    try {
      const s = await detectionRuleService.getStats();
      setStats(s);
    } catch {
      // non-blocking
    }
  };

  const refreshRules = async () => {
    setLoadingRules(true);
    try {
      const res = await detectionRuleService.getRules({
        status: statusFilter === 'ALL' ? undefined : statusFilter,
        category: categoryFilter === 'ALL' ? undefined : categoryFilter,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        search: searchQuery.trim() || undefined,
        limit: 100,
      });
      setRules(res.items);
      refreshStats();
    } catch (e: any) {
      showToast(e.message || 'Failed to fetch rules');
    } finally {
      setLoadingRules(false);
    }
  };

  const loadFieldRegistry = async () => {
    try {
      const reg = await detectionRuleService.getFieldRegistry();
      setFieldRegistry(reg);
    } catch {
      // non-blocking
    }
  };

  useEffect(() => {
    loadFieldRegistry();
    refreshRules();
  }, [statusFilter, categoryFilter, severityFilter]);

  // Load single rule detail when selected
  useEffect(() => {
    if (!selectedRuleId) return;
    detectionRuleService
      .getRuleById(selectedRuleId)
      .then((r) => {
        setSelectedRule(r);
        setBacktestResult(null);
        setDiffResult(null);
        setTestMatchResult(null);
      })
      .catch((e) => showToast(e.message || 'Error loading rule details'));
  }, [selectedRuleId]);

  // Validate builder definition live
  useEffect(() => {
    if (activeTab !== 'builder') return;
    const def: RuleDefinition = {
      source: builderDataSource,
      logical_operator: builderLogicalOp,
      conditions: builderConditions,
    };
    setValidating(true);
    const timer = setTimeout(() => {
      detectionRuleService
        .validateRule(def)
        .then((v) => setValidationResult(v))
        .catch(() => {})
        .finally(() => setValidating(false));
    }, 250);
    return () => clearTimeout(timer);
  }, [builderConditions, builderLogicalOp, builderDataSource, activeTab]);

  // --------------------------------------------------------------------------
  // Condition Helpers for Builder
  // --------------------------------------------------------------------------
  const handleAddCondition = () => {
    setBuilderConditions([
      ...builderConditions,
      { field: 'sender_domain', operator: 'CONTAINS', value: '' },
    ]);
  };

  const handleRemoveCondition = (idx: number) => {
    setBuilderConditions(builderConditions.filter((_, i) => i !== idx));
  };

  const handleUpdateCondition = (idx: number, patch: Partial<RuleCondition>) => {
    const updated = [...builderConditions];
    updated[idx] = { ...updated[idx], ...patch };
    // If field changed, adapt operator if current is invalid
    if (patch.field) {
      const fDef = fieldRegistry.find((f) => f.field === patch.field);
      if (fDef && !fDef.allowed_operators.includes(updated[idx].operator)) {
        updated[idx].operator = fDef.allowed_operators[0] || 'EQUALS';
      }
    }
    setBuilderConditions(updated);
  };

  const handleSaveRule = async () => {
    if (!builderName.trim()) {
      showToast('Rule Name is required.');
      return;
    }
    if (builderConditions.length === 0) {
      showToast('At least one condition is required.');
      return;
    }
    setSavingRule(true);
    try {
      const newRule = await detectionRuleService.createRule({
        name: builderName,
        description: builderDesc,
        category: builderCategory,
        data_sources: [builderDataSource],
        severity: builderSeverity,
        definition: {
          source: builderDataSource,
          logical_operator: builderLogicalOp,
          conditions: builderConditions,
        },
        tags: builderTags.split(',').map((t) => t.trim()).filter(Boolean),
        attack_techniques: builderTechniques.split(',').map((t) => t.trim()).filter(Boolean),
      });
      showToast(`Rule '${newRule.name}' (${newRule.rule_identifier}) created successfully!`);
      setSelectedRuleId(newRule.id);
      setActiveTab('detail');
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Failed to create detection rule');
    } finally {
      setSavingRule(false);
    }
  };

  // --------------------------------------------------------------------------
  // AI Rule Generation
  // --------------------------------------------------------------------------
  const handleGenerateFromAi = async () => {
    if (!aiPrompt.trim()) return;
    setGeneratingAi(true);
    try {
      const res = await detectionRuleService.suggestRuleFromAI({
        prompt: aiPrompt,
        category: builderCategory,
        target_data_sources: [builderDataSource],
      });
      setBuilderName(res.name);
      setBuilderDesc(res.description);
      setBuilderCategory(res.category);
      setBuilderSeverity(res.severity);
      if (res.data_sources?.length) setBuilderDataSource(res.data_sources[0]);
      if (res.definition?.conditions) setBuilderConditions(res.definition.conditions);
      if (res.definition?.logical_operator) setBuilderLogicalOp(res.definition.logical_operator as any);
      setIsAiModalOpen(false);
      setActiveTab('builder');
      showToast('AI Rule proposal loaded into builder. Validate and review conditions.');
    } catch (e: any) {
      showToast(e.message || 'AI rule generation failed');
    } finally {
      setGeneratingAi(false);
    }
  };

  // --------------------------------------------------------------------------
  // Lifecycle Transition Handlers
  // --------------------------------------------------------------------------
  const handleExecuteTransition = async () => {
    if (!selectedRule || !transitionAction) return;
    setTransitioning(true);
    try {
      const updated = await detectionRuleService.transitionRule(
        selectedRule.id,
        transitionAction as any,
        transitionReason || 'Analyst lifecycle transition request'
      );
      setSelectedRule(updated);
      showToast(`Rule updated to status: ${updated.status}`);
      setTransitionAction(null);
      setTransitionReason('');
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Transition rejected');
    } finally {
      setTransitioning(false);
    }
  };

  // --------------------------------------------------------------------------
  // Historical Backtesting
  // --------------------------------------------------------------------------
  const handleRunBacktest = async () => {
    if (!selectedRule) return;
    setBacktestRunning(true);
    try {
      const res = await detectionRuleService.backtestRule(selectedRule.id, {
        time_range_preset: backtestPreset,
        max_records: 300,
        run_async: false,
      });
      setBacktestResult(res);
      showToast(`Backtest completed! Evaluated ${res.records_evaluated} records, found ${res.matches_count} matches.`);
    } catch (e: any) {
      showToast(e.message || 'Historical backtesting failed');
    } finally {
      setBacktestRunning(false);
    }
  };

  // --------------------------------------------------------------------------
  // Version Diff Viewer
  // --------------------------------------------------------------------------
  const handleComputeDiff = async () => {
    if (!selectedRule) return;
    setLoadingDiff(true);
    try {
      const diff = await detectionRuleService.getVersionDiff(selectedRule.id, '1', selectedRule.version);
      setDiffResult(diff);
    } catch (e: any) {
      showToast(e.message || 'Failed to compute version difference');
    } finally {
      setLoadingDiff(false);
    }
  };

  // --------------------------------------------------------------------------
  // Live Event Evaluation
  // --------------------------------------------------------------------------
  const handleTestEvent = async () => {
    if (!selectedRule) return;
    setEvaluatingTest(true);
    try {
      const parsed = JSON.parse(testPayloadStr);
      const matches = await detectionRuleService.evaluateLiveEvent(parsed, selectedRule.data_sources[0] || 'EMAIL_EVENT');
      setTestMatchResult(matches);
      if (matches.length > 0) {
        showToast(`Rule Matched incoming test event! (${matches.length} matches)`);
      } else {
        showToast('Rule did NOT trigger for test payload.');
      }
    } catch (e: any) {
      showToast(e.message || 'Failed to evaluate test event (check JSON format)');
    } finally {
      setEvaluatingTest(false);
    }
  };

  // Status Badge Helper
  const getStatusBadge = (status: RuleLifecycleStatus) => {
    switch (status) {
      case 'ACTIVE':
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">ACTIVE</span>;
      case 'STAGED':
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">STAGED</span>;
      case 'APPROVED':
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">APPROVED</span>;
      case 'PENDING_REVIEW':
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">PENDING REVIEW</span>;
      case 'CANDIDATE':
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">CANDIDATE</span>;
      case 'DRAFT':
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">DRAFT</span>;
      case 'DISABLED':
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-red-500/10 text-red-400 border border-red-500/20">DISABLED</span>;
      default:
        return <span className="px-2 py-0.5 text-[11px] font-mono rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20">{status}</span>;
    }
  };

  const getCostBadge = (cost: string) => {
    switch (cost) {
      case 'LOW':
        return <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400">COST: LOW</span>;
      case 'MEDIUM':
        return <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400">COST: MED</span>;
      case 'HIGH':
        return <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-red-500/10 text-red-400">COST: HIGH</span>;
      default:
        return <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400">COST: {cost}</span>;
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-background text-foreground">
      {/* Toast Banner */}
      {toastMessage && (
        <div className="fixed top-5 right-5 z-50 bg-surface-secondary border border-primary/50 text-foreground px-4 py-3 rounded-lg shadow-xl flex items-center space-x-2 text-xs font-mono animate-in fade-in duration-200">
          <Activity className="w-4 h-4 text-primary shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header & Stats Bar */}
      <header className="border-b border-border bg-surface px-6 py-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20">
              <Terminal className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-bold tracking-tight text-foreground">
                  Detection Engineering & Rule Lifecycle
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                  SEC-56
                </span>
              </div>
              <p className="text-xs text-foreground-muted">
                Turn validated threat observations into controlled, tested, versioned detection rules.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setIsAiModalOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground hover:border-primary/40 transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5 text-primary" />
              <span>AI Rule Assistant</span>
            </button>
            <button
              onClick={() => {
                setActiveTab('builder');
                setBuilderName('');
                setBuilderDesc('');
                setBuilderConditions([{ field: 'sender_domain', operator: 'CONTAINS', value: '' }]);
              }}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Rule</span>
            </button>
            <button
              onClick={refreshRules}
              className="p-1.5 rounded-md hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border transition-colors"
              title="Refresh Rule Catalog"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Global Statistics Tiles */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mt-4">
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-foreground-muted uppercase">Total Rules</span>
            <span className="text-base font-bold font-mono text-foreground">{stats?.total_rules ?? rules.length}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-emerald-400/80 uppercase">Active Rules</span>
            <span className="text-base font-bold font-mono text-emerald-400">{stats?.active_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-cyan-400/80 uppercase">Staged / Canary</span>
            <span className="text-base font-bold font-mono text-cyan-400">{stats?.staged_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-amber-400/80 uppercase">Pending Review</span>
            <span className="text-base font-bold font-mono text-amber-400">{stats?.pending_review_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-red-400/80 uppercase">Disabled</span>
            <span className="text-base font-bold font-mono text-red-400">{stats?.disabled_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-primary/80 uppercase">Avg Precision</span>
            <span className="text-base font-bold font-mono text-primary">
              {stats?.precision_rate !== undefined ? `${(stats.precision_rate * 100).toFixed(0)}%` : '96%'}
            </span>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex space-x-1 border-t border-border mt-4 pt-3">
          <button
            onClick={() => setActiveTab('catalog')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
              activeTab === 'catalog'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Rule Catalog</span>
          </button>
          <button
            onClick={() => setActiveTab('builder')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
              activeTab === 'builder'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>AST Rule Builder</span>
          </button>
          {selectedRule && (
            <button
              onClick={() => setActiveTab('detail')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
                activeTab === 'detail'
                  ? 'bg-primary/10 text-primary border border-primary/20'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Detail: {selectedRule.rule_identifier}</span>
            </button>
          )}
        </div>
      </header>

      {/* Main Tab Region */}
      <main className="flex-1 p-6">
        {/* ================================================================== */}
        {/* TAB 1: CATALOG                                                     */}
        {/* ================================================================== */}
        {activeTab === 'catalog' && (
          <div className="space-y-4">
            {/* Filter Bar */}
            <div className="flex flex-wrap items-center gap-3 p-3 rounded-lg bg-surface border border-border">
              <div className="relative flex-1 min-w-[220px]">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-foreground-muted" />
                <input
                  type="text"
                  placeholder="Search rules by name, ID, tags, ATT&CK..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && refreshRules()}
                  className="w-full pl-9 pr-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:outline-none focus:border-primary text-foreground"
                />
              </div>

              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-mono text-foreground-muted">Status:</span>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="ACTIVE">Active</option>
                  <option value="STAGED">Staged</option>
                  <option value="APPROVED">Approved</option>
                  <option value="PENDING_REVIEW">Pending Review</option>
                  <option value="CANDIDATE">Candidate</option>
                  <option value="DRAFT">Draft</option>
                  <option value="DISABLED">Disabled</option>
                </select>
              </div>

              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-mono text-foreground-muted">Severity:</span>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                </select>
              </div>

              <div className="flex items-center space-x-2">
                <span className="text-[11px] font-mono text-foreground-muted">Category:</span>
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">All Categories</option>
                  <option value="PHISHING">Phishing</option>
                  <option value="AUTHENTICATION">Authentication</option>
                  <option value="ENDPOINT">Endpoint</option>
                  <option value="NETWORK">Network</option>
                  <option value="ATTACHMENT">Attachment</option>
                  <option value="ANOMALY">Anomaly</option>
                </select>
              </div>
            </div>

            {/* Rules Table */}
            <div className="rounded-lg bg-surface border border-border overflow-hidden">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="border-b border-border bg-surface-secondary/50 text-[11px] font-mono uppercase text-foreground-muted">
                    <th className="py-2.5 px-4">Identifier</th>
                    <th className="py-2.5 px-4">Rule Name</th>
                    <th className="py-2.5 px-4">Category</th>
                    <th className="py-2.5 px-4">Severity</th>
                    <th className="py-2.5 px-4">Status</th>
                    <th className="py-2.5 px-4">Version</th>
                    <th className="py-2.5 px-4">Cost Class</th>
                    <th className="py-2.5 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border text-xs">
                  {loadingRules ? (
                    <tr>
                      <td colSpan={8} className="text-center py-8 text-foreground-muted font-mono">
                        Loading detection rules...
                      </td>
                    </tr>
                  ) : rules.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="text-center py-8 text-foreground-muted">
                        No detection rules match the specified filters.
                      </td>
                    </tr>
                  ) : (
                    rules.map((rule) => (
                      <tr
                        key={rule.id}
                        className="hover:bg-surface-secondary/40 transition-colors cursor-pointer group"
                        onClick={() => {
                          setSelectedRuleId(rule.id);
                          setActiveTab('detail');
                        }}
                      >
                        <td className="py-2.5 px-4 font-mono text-primary font-medium">
                          {rule.rule_identifier}
                        </td>
                        <td className="py-2.5 px-4 font-medium text-foreground max-w-xs truncate">
                          {rule.name}
                        </td>
                        <td className="py-2.5 px-4 font-mono text-[11px] text-foreground-muted">
                          {rule.category}
                        </td>
                        <td className="py-2.5 px-4">
                          <span
                            className={`px-2 py-0.5 text-[10px] font-mono rounded ${
                              rule.severity === 'CRITICAL'
                                ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                                : rule.severity === 'HIGH'
                                ? 'bg-orange-500/10 text-orange-400 border border-orange-500/20'
                                : rule.severity === 'MEDIUM'
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            }`}
                          >
                            {rule.severity}
                          </span>
                        </td>
                        <td className="py-2.5 px-4">{getStatusBadge(rule.status)}</td>
                        <td className="py-2.5 px-4 font-mono text-foreground-muted">
                          v{rule.version}
                        </td>
                        <td className="py-2.5 px-4">{getCostBadge(rule.cost_class)}</td>
                        <td className="py-2.5 px-4 text-right space-x-2" onClick={(e) => e.stopPropagation()}>
                          <button
                            onClick={() => {
                              setSelectedRuleId(rule.id);
                              setActiveTab('detail');
                            }}
                            className="px-2 py-1 text-[11px] rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ================================================================== */}
        {/* TAB 2: AST RULE BUILDER                                            */}
        {/* ================================================================== */}
        {activeTab === 'builder' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left 2 Cols: Form & Conditions */}
            <div className="lg:col-span-2 space-y-4">
              <div className="p-4 rounded-lg bg-surface border border-border space-y-4">
                <h2 className="text-sm font-semibold tracking-tight text-foreground flex items-center space-x-2">
                  <Sliders className="w-4 h-4 text-primary" />
                  <span>Rule Metadata & Governance</span>
                </h2>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                      Rule Name *
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. Lookalike Spear-Phishing Domain with Login URL"
                      value={builderName}
                      onChange={(e) => setBuilderName(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                      Category *
                    </label>
                    <select
                      value={builderCategory}
                      onChange={(e) => setBuilderCategory(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground"
                    >
                      <option value="PHISHING">PHISHING</option>
                      <option value="AUTHENTICATION">AUTHENTICATION</option>
                      <option value="ENDPOINT">ENDPOINT</option>
                      <option value="NETWORK">NETWORK</option>
                      <option value="ATTACHMENT">ATTACHMENT</option>
                      <option value="ANOMALY">ANOMALY</option>
                    </select>
                  </div>
                </div>

                <div>
                  <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                    Description & Hypothesis
                  </label>
                  <textarea
                    rows={2}
                    placeholder="Describe threat hypothesis, observed behavioral patterns, and intent..."
                    value={builderDesc}
                    onChange={(e) => setBuilderDesc(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                      Data Source Target
                    </label>
                    <select
                      value={builderDataSource}
                      onChange={(e) => setBuilderDataSource(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground"
                    >
                      <option value="EMAIL_EVENT">EMAIL_EVENT</option>
                      <option value="NETWORK_EVENT">NETWORK_EVENT</option>
                      <option value="ENDPOINT_EVENT">ENDPOINT_EVENT</option>
                      <option value="AUTH_EVENT">AUTH_EVENT</option>
                      <option value="API_EVENT">API_EVENT</option>
                      <option value="INDICATOR">INDICATOR</option>
                      <option value="THREAT_INTELLIGENCE">THREAT_INTELLIGENCE</option>
                      <option value="WATCHLIST">WATCHLIST</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                      Severity
                    </label>
                    <select
                      value={builderSeverity}
                      onChange={(e) => setBuilderSeverity(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                    </select>
                  </div>

                  <div>
                    <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                      Logical Combinator
                    </label>
                    <select
                      value={builderLogicalOp}
                      onChange={(e) => setBuilderLogicalOp(e.target.value as any)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground"
                    >
                      <option value="AND">ALL match (AND)</option>
                      <option value="OR">ANY match (OR)</option>
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                      MITRE ATT&CK Techniques
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. T1566.002, T1059.001"
                      value={builderTechniques}
                      onChange={(e) => setBuilderTechniques(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                      Tags (Comma-separated)
                    </label>
                    <input
                      type="text"
                      placeholder="e.g. phishing, spearphishing, lookalike"
                      value={builderTags}
                      onChange={(e) => setBuilderTags(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground font-mono"
                    />
                  </div>
                </div>
              </div>

              {/* Conditions Builder */}
              <div className="p-4 rounded-lg bg-surface border border-border space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                    AST Conditions ({builderConditions.length})
                  </h3>
                  <button
                    onClick={handleAddCondition}
                    className="flex items-center space-x-1 px-2.5 py-1 text-xs rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors"
                  >
                    <Plus className="w-3 h-3 text-primary" />
                    <span>Add Condition</span>
                  </button>
                </div>

                <div className="space-y-2">
                  {builderConditions.map((cond, idx) => {
                    const fDef = fieldRegistry.find((f) => f.field === cond.field);
                    const allowedOps = fDef ? fDef.allowed_operators : ['EQUALS', 'CONTAINS', 'GREATER_THAN', 'IN'];

                    return (
                      <div
                        key={idx}
                        className="flex flex-wrap items-center gap-2 p-2.5 rounded bg-surface-secondary/50 border border-border"
                      >
                        <span className="text-[10px] font-mono text-foreground-muted w-5">#{idx + 1}</span>

                        {/* Field Selector */}
                        <select
                          value={cond.field}
                          onChange={(e) => handleUpdateCondition(idx, { field: e.target.value })}
                          className="px-2 py-1 text-xs rounded bg-surface border border-border text-foreground font-mono focus:outline-none focus:border-primary min-w-[150px]"
                        >
                          {fieldRegistry.map((f) => (
                            <option key={f.field} value={f.field}>
                              {f.field} ({f.field_type})
                            </option>
                          ))}
                        </select>

                        {/* Operator Selector */}
                        <select
                          value={cond.operator}
                          onChange={(e) => handleUpdateCondition(idx, { operator: e.target.value })}
                          className="px-2 py-1 text-xs rounded bg-surface border border-border text-primary font-mono focus:outline-none focus:border-primary min-w-[120px]"
                        >
                          {allowedOps.map((op) => (
                            <option key={op} value={op}>
                              {op}
                            </option>
                          ))}
                        </select>

                        {/* Value Input */}
                        <input
                          type="text"
                          placeholder="Condition value..."
                          value={cond.value !== undefined ? String(cond.value) : ''}
                          onChange={(e) => {
                            let val: any = e.target.value;
                            if (val === 'true') val = true;
                            else if (val === 'false') val = false;
                            else if (!isNaN(Number(val)) && val.trim() !== '') val = Number(val);
                            handleUpdateCondition(idx, { value: val });
                          }}
                          className="flex-1 min-w-[140px] px-2 py-1 text-xs rounded bg-surface border border-border text-foreground font-mono focus:outline-none focus:border-primary"
                        />

                        {/* Remove */}
                        <button
                          onClick={() => handleRemoveCondition(idx)}
                          className="p-1 text-foreground-muted hover:text-red-400 rounded transition-colors"
                          title="Remove Condition"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex items-center justify-end space-x-3">
                <button
                  onClick={() => setActiveTab('catalog')}
                  className="px-4 py-2 text-xs rounded-md border border-border text-foreground-muted hover:text-foreground transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSaveRule}
                  disabled={savingRule || validationResult?.is_valid === false}
                  className="px-4 py-2 text-xs font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center space-x-2"
                >
                  {savingRule ? <span>Saving...</span> : <Check className="w-4 h-4" />}
                  <span>Save Candidate Rule</span>
                </button>
              </div>
            </div>

            {/* Right Col: Live Human-Readable Preview & Validation Box */}
            <div className="space-y-4">
              {/* Validation Status Card */}
              <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                    AST Validation Engine
                  </h3>
                  {validating ? (
                    <span className="text-[10px] font-mono text-primary animate-pulse">Compiling...</span>
                  ) : validationResult?.is_valid ? (
                    <span className="flex items-center space-x-1 text-[11px] font-mono text-emerald-400">
                      <CheckCircle2 className="w-3.5 h-3.5" />
                      <span>VALID</span>
                    </span>
                  ) : (
                    <span className="flex items-center space-x-1 text-[11px] font-mono text-red-400">
                      <XCircle className="w-3.5 h-3.5" />
                      <span>INVALID</span>
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                  <div className="p-2 rounded bg-surface-secondary border border-border">
                    <span className="text-foreground-muted block">Complexity</span>
                    <span className="font-bold text-foreground">
                      {validationResult?.complexity_score?.toFixed(1) ?? '1.0'}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-surface-secondary border border-border">
                    <span className="text-foreground-muted block">Estimated Cost</span>
                    <span className="font-bold text-foreground">{validationResult?.cost_class ?? 'LOW'}</span>
                  </div>
                </div>

                {validationResult?.errors && validationResult.errors.length > 0 && (
                  <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-xs space-y-1">
                    <span className="font-semibold block font-mono">Syntax / Validation Errors:</span>
                    {validationResult.errors.map((err, i) => (
                      <div key={i} className="flex items-start space-x-1.5 text-[11px]">
                        <AlertTriangle className="w-3 h-3 shrink-0 mt-0.5" />
                        <span>{err}</span>
                      </div>
                    ))}
                  </div>
                )}

                {validationResult?.warnings && validationResult.warnings.length > 0 && (
                  <div className="p-3 rounded bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs space-y-1">
                    <span className="font-semibold block font-mono">Performance Warnings:</span>
                    {validationResult.warnings.map((warn, i) => (
                      <div key={i} className="flex items-start space-x-1.5 text-[11px]">
                        <HelpCircle className="w-3 h-3 shrink-0 mt-0.5" />
                        <span>{warn}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Live Human-Readable Preview */}
              <div className="p-4 rounded-lg bg-surface border border-border space-y-2">
                <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center justify-between">
                  <span>Live Logic Preview</span>
                  <Terminal className="w-3.5 h-3.5 text-primary" />
                </h3>
                <pre className="p-3 rounded bg-black/60 border border-border text-emerald-400 font-mono text-[11px] whitespace-pre-wrap leading-relaxed overflow-x-auto">
                  {validationResult?.human_readable_logic || 'WHEN (empty) THEN generate detection match'}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================== */}
        {/* TAB 3: RULE DETAIL & LIFECYCLE WORKBENCH                           */}
        {/* ================================================================== */}
        {activeTab === 'detail' && selectedRule && (
          <div className="space-y-6">
            {/* Header Card */}
            <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center space-x-3">
                    <h2 className="text-base font-bold text-foreground font-mono">{selectedRule.name}</h2>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-surface-secondary text-primary border border-border">
                      {selectedRule.rule_identifier}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-surface-secondary text-foreground-muted border border-border">
                      v{selectedRule.version}
                    </span>
                  </div>
                  <p className="text-xs text-foreground-muted max-w-3xl">
                    {selectedRule.description || 'No description provided.'}
                  </p>
                </div>

                <div className="flex items-center space-x-2">
                  {getStatusBadge(selectedRule.status)}
                  {getCostBadge(selectedRule.cost_class)}
                </div>
              </div>

              {/* State Machine Action Bar */}
              <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-border">
                <span className="text-[11px] font-mono text-foreground-muted mr-1">LIFECYCLE TRANSITION:</span>

                {selectedRule.status === 'DRAFT' && (
                  <button
                    onClick={() => {
                      setTransitionAction('submit-review');
                      setTransitionReason('Draft ready for peer review.');
                    }}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 hover:bg-purple-500/20 transition-colors"
                  >
                    Submit for Review
                  </button>
                )}

                {(selectedRule.status === 'PENDING_REVIEW' || selectedRule.status === 'CANDIDATE') && (
                  <button
                    onClick={() => {
                      setTransitionAction('approve');
                      setTransitionReason('Peer review passed. Rule approved.');
                    }}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 hover:bg-blue-500/20 transition-colors"
                  >
                    Approve Rule (Lead)
                  </button>
                )}

                {selectedRule.status === 'APPROVED' && (
                  <button
                    onClick={() => {
                      setTransitionAction('stage');
                      setTransitionReason('Staging in canary mode for 48h observation.');
                    }}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 hover:bg-cyan-500/20 transition-colors"
                  >
                    Stage (Canary Mode)
                  </button>
                )}

                {(selectedRule.status === 'STAGED' || selectedRule.status === 'APPROVED') && (
                  <button
                    onClick={() => {
                      setTransitionAction('activate');
                      setTransitionReason('Telemetry validated; promoting to production active.');
                    }}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-emerald-500 text-black font-semibold hover:bg-emerald-400 transition-colors"
                  >
                    Activate in Production
                  </button>
                )}

                {selectedRule.status === 'ACTIVE' && (
                  <button
                    onClick={() => {
                      setTransitionAction('disable');
                      setTransitionReason('Emergency disable: Rule tuning required.');
                    }}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-red-500/10 text-red-400 border border-red-500/20 hover:bg-red-500/20 transition-colors"
                  >
                    Emergency Disable
                  </button>
                )}

                {selectedRule.status !== 'RETIRED' && (
                  <button
                    onClick={() => {
                      setTransitionAction('retire');
                      setTransitionReason('Rule retired or superseded by updated signature.');
                    }}
                    className="px-2.5 py-1 text-xs font-medium rounded bg-zinc-500/10 text-zinc-400 border border-zinc-500/20 hover:bg-zinc-500/20 transition-colors"
                  >
                    Retire Rule
                  </button>
                )}
              </div>
            </div>

            {/* Split Grid: Logic & Metadata vs Backtesting Workbench */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left Column: Human-Readable Logic, MITRE, Audit */}
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                  <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center justify-between">
                    <span>Compiled Detection Logic</span>
                    <Terminal className="w-3.5 h-3.5 text-primary" />
                  </h3>
                  <pre className="p-3 rounded bg-black/60 border border-border text-emerald-400 font-mono text-[11px] whitespace-pre-wrap leading-relaxed">
                    {selectedRule.human_readable_logic}
                  </pre>
                </div>

                <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                  <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                    Governance & ATT&CK Mapping
                  </h3>
                  <div className="space-y-2 text-xs">
                    <div className="flex justify-between py-1 border-b border-border">
                      <span className="text-foreground-muted font-mono">Created By:</span>
                      <span className="font-mono text-foreground">{selectedRule.created_by || 'analyst'}</span>
                    </div>
                    {selectedRule.reviewed_by && (
                      <div className="flex justify-between py-1 border-b border-border">
                        <span className="text-foreground-muted font-mono">Reviewed / Approved By:</span>
                        <span className="font-mono text-foreground">{selectedRule.reviewed_by}</span>
                      </div>
                    )}
                    <div className="flex justify-between py-1 border-b border-border">
                      <span className="text-foreground-muted font-mono">Provenance:</span>
                      <span className="font-mono text-primary">{selectedRule.provenance_type}</span>
                    </div>
                    <div className="flex items-center space-x-1.5 pt-1">
                      <span className="text-foreground-muted font-mono">ATT&CK:</span>
                      {selectedRule.attack_techniques?.map((t) => (
                        <span key={t} className="px-1.5 py-0.5 rounded bg-surface-secondary text-[10px] font-mono text-primary">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Version Diff Section */}
                <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                      Version Diff (v1 vs Current)
                    </h3>
                    <button
                      onClick={handleComputeDiff}
                      disabled={loadingDiff}
                      className="px-2 py-1 text-[11px] rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors flex items-center space-x-1"
                    >
                      <GitCompare className="w-3 h-3 text-primary" />
                      <span>{loadingDiff ? 'Diffing...' : 'Compare Versions'}</span>
                    </button>
                  </div>

                  {diffResult ? (
                    <div className="p-3 rounded bg-black/60 border border-border text-xs font-mono space-y-2">
                      <p className="text-foreground font-semibold">{diffResult.summary}</p>
                      {diffResult.added_conditions.length > 0 && (
                        <div className="text-emerald-400 text-[11px]">
                          + Added: {JSON.stringify(diffResult.added_conditions)}
                        </div>
                      )}
                      {diffResult.removed_conditions.length > 0 && (
                        <div className="text-red-400 text-[11px]">
                          - Removed: {JSON.stringify(diffResult.removed_conditions)}
                        </div>
                      )}
                      {diffResult.is_breaking_change && (
                        <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 text-[10px] font-bold">
                          BREAKING CHANGE DETECTED
                        </span>
                      )}
                    </div>
                  ) : (
                    <p className="text-xs text-foreground-muted">
                      Click Compare Versions to inspect AST condition mutations against v1.
                    </p>
                  )}
                </div>
              </div>

              {/* Right Column: Historical Backtesting Workbench & Live Event Testing */}
              <div className="space-y-4">
                {/* Backtesting Card */}
                <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center space-x-1.5">
                      <Activity className="w-4 h-4 text-primary" />
                      <span>Historical Backtest Workbench</span>
                    </h3>
                    <select
                      value={backtestPreset}
                      onChange={(e) => setBacktestPreset(e.target.value as any)}
                      className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none"
                    >
                      <option value="LAST_24_HOURS">Last 24 Hours</option>
                      <option value="LAST_7_DAYS">Last 7 Days</option>
                      <option value="LAST_30_DAYS">Last 30 Days</option>
                    </select>
                  </div>

                  <p className="text-xs text-foreground-muted">
                    Executes bounded, read-only evaluation against stored telemetry records. Never fires production alerts or automated response actions.
                  </p>

                  <button
                    onClick={handleRunBacktest}
                    disabled={backtestRunning}
                    className="w-full py-2 text-xs font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors disabled:opacity-50 flex items-center justify-center space-x-2"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>{backtestRunning ? 'Evaluating Telemetry...' : 'Run Historical Backtest'}</span>
                  </button>

                  {backtestResult && (
                    <div className="p-3 rounded bg-surface-secondary border border-border space-y-2 text-xs">
                      <div className="grid grid-cols-3 gap-2 text-center font-mono">
                        <div className="p-2 rounded bg-surface border border-border">
                          <span className="text-[10px] text-foreground-muted block">Records Scanned</span>
                          <span className="font-bold text-foreground">{backtestResult.records_evaluated}</span>
                        </div>
                        <div className="p-2 rounded bg-surface border border-border">
                          <span className="text-[10px] text-foreground-muted block">Matches</span>
                          <span className="font-bold text-primary">{backtestResult.matches_count}</span>
                        </div>
                        <div className="p-2 rounded bg-surface border border-border">
                          <span className="text-[10px] text-foreground-muted block">Duration</span>
                          <span className="font-bold text-foreground">{backtestResult.execution_duration_ms}ms</span>
                        </div>
                      </div>

                      {backtestResult.limitations && backtestResult.limitations.length > 0 && (
                        <div className="text-[11px] text-amber-400 space-y-0.5">
                          {backtestResult.limitations.map((lim, i) => (
                            <div key={i} className="flex items-center space-x-1">
                              <HelpCircle className="w-3 h-3 shrink-0" />
                              <span>{lim}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Live Event Test Panel */}
                <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                  <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center justify-between">
                    <span>Live Event Test Panel</span>
                    <Terminal className="w-3.5 h-3.5 text-primary" />
                  </h3>

                  <textarea
                    rows={5}
                    value={testPayloadStr}
                    onChange={(e) => setTestPayloadStr(e.target.value)}
                    className="w-full p-2.5 rounded bg-black/60 border border-border text-foreground font-mono text-xs focus:outline-none focus:border-primary"
                  />

                  <button
                    onClick={handleTestEvent}
                    disabled={evaluatingTest}
                    className="w-full py-1.5 text-xs font-medium rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors flex items-center justify-center space-x-2"
                  >
                    <Play className="w-3 h-3 text-primary" />
                    <span>{evaluatingTest ? 'Testing...' : 'Test Event Against Rule'}</span>
                  </button>

                  {testMatchResult !== null && (
                    <div
                      className={`p-3 rounded text-xs font-mono ${
                        testMatchResult.length > 0
                          ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                          : 'bg-zinc-500/10 border border-zinc-500/20 text-foreground-muted'
                      }`}
                    >
                      {testMatchResult.length > 0 ? (
                        <div>
                          <div className="font-bold flex items-center space-x-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>RULE MATCH TRIGGERED ({testMatchResult.length})</span>
                          </div>
                          <div className="text-[11px] mt-1 text-foreground">
                            {testMatchResult[0]?.explanation?.explanation || 'Matched all atomic conditions.'}
                          </div>
                        </div>
                      ) : (
                        <span>No match: incoming event conditions did not satisfy rule.</span>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ==================================================================== */}
      {/* MODAL: AI RULE GENERATOR ASSISTANT                                   */}
      {/* ==================================================================== */}
      {isAiModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-xl bg-surface border border-border p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2">
                <Sparkles className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground">AI Detection Rule Generator</h3>
              </div>
              <button
                onClick={() => setIsAiModalOpen(false)}
                className="text-foreground-muted hover:text-foreground text-xs font-mono"
              >
                ESC
              </button>
            </div>

            <p className="text-xs text-foreground-muted">
              Describe your threat investigation observation, hunt pattern, or adversary technique. CyberGuard compiles a constrained, allowlisted AST detection rule without arbitrary code execution.
            </p>

            <textarea
              rows={4}
              placeholder="e.g. Detect incoming external emails from lookalike or suspicious domains that contain urgent financial keywords and multiple URLs leading to credential phishing..."
              value={aiPrompt}
              onChange={(e) => setAiPrompt(e.target.value)}
              className="w-full p-3 text-xs rounded-lg bg-surface-secondary border border-border focus:border-primary focus:outline-none text-foreground"
            />

            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsAiModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground-muted hover:text-foreground"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerateFromAi}
                disabled={generatingAi || !aiPrompt.trim()}
                className="px-3 py-1.5 text-xs font-medium rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 flex items-center space-x-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{generatingAi ? 'Generating AST...' : 'Generate Rule'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: LIFECYCLE TRANSITION CONFIRMATION                             */}
      {/* ==================================================================== */}
      {transitionAction && selectedRule && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-xl bg-surface border border-border p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2">
                <AlertOctagon className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground">Confirm Lifecycle Transition</h3>
              </div>
              <button
                onClick={() => setTransitionAction(null)}
                className="text-foreground-muted hover:text-foreground text-xs font-mono"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-foreground-muted">
              Transitioning <span className="font-mono text-primary font-bold">{selectedRule.rule_identifier}</span> to status:{' '}
              <span className="font-bold font-mono text-foreground uppercase">{transitionAction}</span>.
            </p>

            <div>
              <label className="text-[11px] font-mono text-foreground-muted block mb-1">
                Reason / Justification *
              </label>
              <textarea
                rows={2}
                value={transitionReason}
                onChange={(e) => setTransitionReason(e.target.value)}
                placeholder="Document operational reason for audit trail..."
                className="w-full p-2.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
              />
            </div>

            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setTransitionAction(null)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground-muted hover:text-foreground"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteTransition}
                disabled={transitioning || !transitionReason.trim()}
                className="px-3 py-1.5 text-xs font-medium rounded bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
              >
                {transitioning ? 'Executing...' : 'Confirm Transition'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DetectionRules;
