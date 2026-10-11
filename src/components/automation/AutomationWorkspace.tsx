import React, { useState, useEffect } from 'react';
import {
  Cpu,
  Play,
  CheckCircle,
  Clock,
  Plus,
  RefreshCw,
  Search,
  Check,
  Sparkles,
  GitBranch,
  ShieldAlert,
  Sliders,
  Send,
  X,
  UserCheck,
} from 'lucide-react';
import type {
  AutomationWorkflow,
  AutomationRun,
  ApprovalRequest,
  RegisteredActionMeta,
  AutomationMetrics,
  WorkflowExecutionMode,
} from '../../types/automation';
import { automationService } from '../../services/automationService';

export const AutomationWorkspace: React.FC = () => {
  // Tabs: 'workflows' | 'runs' | 'approvals'
  const [activeTab, setActiveTab] = useState<'workflows' | 'runs' | 'approvals'>('workflows');

  // State
  const [workflows, setWorkflows] = useState<AutomationWorkflow[]>([]);
  const [runs, setRuns] = useState<AutomationRun[]>([]);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [registeredActions, setRegisteredActions] = useState<RegisteredActionMeta[]>([]);
  const [metrics, setMetrics] = useState<AutomationMetrics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Modals
  const [showCreateModal, setShowCreateModal] = useState<boolean>(false);
  const [showTraceModal, setShowTraceModal] = useState<boolean>(false);
  const [showTriggerModal, setShowTriggerModal] = useState<boolean>(false);
  const [selectedRun, setSelectedRun] = useState<AutomationRun | null>(null);
  const [selectedWorkflowId, setSelectedWorkflowId] = useState<string | null>(null);

  // Create Workflow Form State
  const [newWfName, setNewWfName] = useState<string>('');
  const [newWfDesc, setNewWfDesc] = useState<string>('');
  const [newWfType, setNewWfType] = useState<string>('ALERT_TRIAGE');
  const [newWfTrigger, setNewWfTrigger] = useState<string>('ALERT_CREATED');
  const [newWfCondField, setNewWfCondField] = useState<string>('severity');
  const [newWfCondOp, setNewWfCondOp] = useState<string>('eq');
  const [newWfCondVal, setNewWfCondVal] = useState<string>('CRITICAL');
  const [newWfActionId, setNewWfActionId] = useState<string>('CREATE_CASE');

  // Trigger Modal Form State
  const [triggerMode, setTriggerMode] = useState<WorkflowExecutionMode>('DRY_RUN');
  const [triggerResource, setTriggerResource] = useState<string>('ALT-2026-099');
  const [triggerPayload, setTriggerPayload] = useState<string>('{\n  "severity": "CRITICAL",\n  "risk_score": 92\n}');

  // Approval Decision Form State
  const [approvalReason, setApprovalReason] = useState<string>('');

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const loadData = async () => {
    setLoading(true);
    try {
      const [wData, rData, aData, actData, mData] = await Promise.all([
        automationService.listWorkflows(statusFilter),
        automationService.listRuns(),
        automationService.listPendingApprovals(),
        automationService.listRegisteredActions(),
        automationService.getMetrics(),
      ]);
      setWorkflows(wData.items);
      setRuns(rData.items);
      setApprovals(aData);
      setRegisteredActions(actData);
      setMetrics(mData);
    } catch (err: any) {
      console.error('Failed to load automation data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [statusFilter]);

  const handleActivate = async (wfId: string) => {
    try {
      await automationService.activateWorkflow(wfId);
      showToast('Workflow activated with immutable version lock.');
      loadData();
    } catch (err: any) {
      showToast(err.message || 'Activation failed');
    }
  };

  const handlePause = async (wfId: string) => {
    try {
      await automationService.pauseWorkflow(wfId);
      showToast('Workflow paused.');
      loadData();
    } catch (err: any) {
      showToast(err.message || 'Pause failed');
    }
  };

  const handleNewVersion = async (wfId: string) => {
    try {
      await automationService.createNewVersion(wfId);
      showToast('New draft version revision created.');
      loadData();
    } catch (err: any) {
      showToast(err.message || 'Failed to create new version');
    }
  };

  const handleOpenTriggerModal = (wfId: string) => {
    setSelectedWorkflowId(wfId);
    setShowTriggerModal(true);
  };

  const handleExecuteTrigger = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedWorkflowId) return;
    try {
      let parsedPayload = {};
      try {
        parsedPayload = JSON.parse(triggerPayload);
      } catch {
        showToast('Invalid JSON in payload');
        return;
      }
      const run = await automationService.triggerWorkflow(selectedWorkflowId, {
        resource_id: triggerResource,
        payload: parsedPayload,
        execution_mode: triggerMode,
      });
      showToast(`Run initiated: ${run.status} (${run.execution_mode})`);
      setShowTriggerModal(false);
      loadData();
      setSelectedRun(run);
      setShowTraceModal(true);
    } catch (err: any) {
      showToast(err.message || 'Trigger execution failed');
    }
  };

  const handleDecideApproval = async (approvalId: string, decision: 'APPROVED' | 'REJECTED') => {
    try {
      await automationService.decideApproval(approvalId, decision, approvalReason);
      showToast(`Approval decision submitted: ${decision}`);
      setApprovalReason('');
      loadData();
    } catch (err: any) {
      showToast(err.message || 'Approval decision error');
    }
  };

  const handleOpenTrace = async (runId: string) => {
    try {
      const fullRun = await automationService.getRun(runId);
      setSelectedRun(fullRun);
      setShowTraceModal(true);
    } catch (err: any) {
      showToast(err.message || 'Error loading run trace');
    }
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const selectedAct = registeredActions.find((a) => a.action_id === newWfActionId);
      await automationService.createWorkflow({
        name: newWfName,
        description: newWfDesc,
        workflow_type: newWfType as any,
        trigger_type: newWfTrigger as any,
        conditions: {
          logic: 'AND',
          rules: [{ field: newWfCondField, operator: newWfCondOp, value: newWfCondVal }],
        },
        actions: [
          {
            step_key: 'step_1',
            action_id: newWfActionId,
            name: selectedAct?.name || newWfActionId,
            risk_classification: selectedAct?.risk_classification || 'LOW_IMPACT',
            approval_level: selectedAct?.default_approval_level || 'AUTOMATIC',
            parameters: {},
          },
        ],
        execution_limits: {
          max_steps: 10,
          timeout_seconds: 300,
          max_retries: 2,
          max_recursion_depth: 3,
          deduplication_window_seconds: 300,
        },
      });
      showToast('Workflow created successfully in DRAFT mode.');
      setShowCreateModal(false);
      setNewWfName('');
      setNewWfDesc('');
      loadData();
    } catch (err: any) {
      showToast(err.message || 'Creation failed');
    }
  };

  const filteredWorkflows = workflows.filter((w) =>
    w.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    w.trigger_type.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6 pb-16 page-enter">
      {/* Toast Alert */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-slate-900 border border-sky-500/50 text-white px-5 py-3 rounded-lg shadow-xl flex items-center space-x-3 text-sm animate-in fade-in slide-in-from-bottom-2">
          <Sparkles className="w-4 h-4 text-sky-400" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Top Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-card border border-border shadow-xs">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Cpu className="w-3.5 h-3.5 text-primary" />
            <span>SECURITY OPERATIONS AUTOMATION (SOAR) & ORCHESTRATION</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-foreground font-sans tracking-tight">
            SOC Automation Workflows
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Authoritative, bounded, auditable security operations workflows with human-in-the-loop approval gates.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            type="button"
            onClick={loadData}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs font-mono font-medium transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-primary" />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            onClick={() => setShowCreateModal(true)}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-mono font-semibold text-xs transition-colors cursor-pointer shadow-xs"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>New Workflow</span>
          </button>
        </div>
      </div>

      {/* Real Metrics KPI Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-surface border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
          <div>
            <div className="text-xs font-semibold text-foreground-muted uppercase tracking-wider">Active Workflows</div>
            <div className="text-2xl font-bold text-foreground mt-1">{metrics?.active_workflows ?? 0}</div>
            <div className="text-[11px] text-foreground-muted mt-0.5">Of {metrics?.total_workflows ?? 0} Total</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <Cpu className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-surface border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
          <div>
            <div className="text-xs font-semibold text-foreground-muted uppercase tracking-wider">Total Runs</div>
            <div className="text-2xl font-bold text-primary mt-1">{metrics?.total_runs ?? 0}</div>
            <div className="text-[11px] text-foreground-muted mt-0.5">{metrics?.completed_runs ?? 0} Completed</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-success-surface border border-success-border flex items-center justify-center text-success">
            <CheckCircle className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-surface border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
          <div>
            <div className="text-xs font-semibold text-foreground-muted uppercase tracking-wider">Success Rate</div>
            <div className="text-2xl font-bold text-success mt-1">{metrics?.success_rate ?? 100}%</div>
            <div className="text-[11px] text-foreground-muted mt-0.5">Avg {Math.round(metrics?.average_duration_ms ?? 0)}ms</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center text-primary">
            <Sliders className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-surface border border-border rounded-xl p-4 flex items-center justify-between shadow-xs">
          <div>
            <div className="text-xs font-semibold text-foreground-muted uppercase tracking-wider">Pending Approvals</div>
            <div className="text-2xl font-bold text-warning mt-1">{approvals.length}</div>
            <div className="text-[11px] text-foreground-muted mt-0.5">Human Gate Required</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-warning-surface border border-warning-border flex items-center justify-center text-warning">
            <UserCheck className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Primary Sub-View Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-border pb-2">
        <button
          type="button"
          onClick={() => setActiveTab('workflows')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeTab === 'workflows'
              ? 'bg-primary text-primary-foreground shadow-xs'
              : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
          }`}
        >
          <Cpu className="w-3.5 h-3.5" />
          <span>Automation Workflows</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-white/20 ml-1">{workflows.length}</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('runs')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeTab === 'runs'
              ? 'bg-primary text-primary-foreground shadow-xs'
              : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
          }`}
        >
          <Play className="w-3.5 h-3.5" />
          <span>Execution Runs</span>
          <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-white/20 ml-1">{runs.length}</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('approvals')}
          className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-xs font-mono font-semibold transition-all cursor-pointer ${
            activeTab === 'approvals'
              ? 'bg-primary text-primary-foreground shadow-xs'
              : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
          }`}
        >
          <UserCheck className="w-3.5 h-3.5" />
          <span>Approval Queue</span>
          {approvals.length > 0 && (
            <span className="text-[10px] px-1.5 py-0.2 rounded-full bg-danger text-white ml-1">
              {approvals.length}
            </span>
          )}
        </button>
      </div>

      {/* --------------------------------------------------------------------- */}
      {/* TAB 1: WORKFLOWS CATALOG */}
      {/* --------------------------------------------------------------------- */}
      {activeTab === 'workflows' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-surface p-3.5 rounded-card border border-border">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search workflows by name or trigger..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground text-xs font-mono placeholder:text-foreground-muted focus:outline-none focus:border-primary"
              />
            </div>
            <div className="flex items-center space-x-2">
              {(['ALL', 'ACTIVE', 'DRAFT', 'PAUSED'] as const).map((st) => (
                <button
                  key={st}
                  type="button"
                  onClick={() => setStatusFilter(st)}
                  className={`px-2.5 py-1 rounded-md text-[10px] font-mono font-bold uppercase transition-all cursor-pointer ${
                    statusFilter === st
                      ? 'bg-primary/15 text-primary border border-primary/30'
                      : 'text-foreground-muted hover:text-foreground'
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          <div className="bg-surface rounded-card border border-border overflow-hidden">
            <table className="w-full text-xs font-mono text-left">
              <thead className="bg-surface-secondary text-foreground-muted border-b border-border uppercase text-[10px]">
                <tr>
                  <th className="px-4 py-3">Workflow Name</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Trigger</th>
                  <th className="px-4 py-3">Version</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Owner</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {loading ? (
                  <tr>
                    <td colSpan={7} className="text-center py-8 text-foreground-muted">
                      Loading workflows...
                    </td>
                  </tr>
                ) : filteredWorkflows.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="text-center py-8 text-foreground-muted">
                      No matching workflows found.
                    </td>
                  </tr>
                ) : (
                  filteredWorkflows.map((wf) => (
                    <tr key={wf.id} className="hover:bg-surface-secondary/50 transition-colors">
                      <td className="px-4 py-3 font-semibold text-foreground">
                        <div>{wf.name}</div>
                        <div className="text-[10px] text-foreground-muted font-normal mt-0.5 line-clamp-1">
                          {wf.description || 'No description provided'}
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="px-2 py-0.5 rounded bg-surface border border-border text-[10px]">
                          {wf.workflow_type}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-primary font-bold">{wf.trigger_type}</td>
                      <td className="px-4 py-3 text-foreground-muted">v{wf.version}</td>
                      <td className="px-4 py-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                            wf.status === 'ACTIVE'
                              ? 'bg-success-surface text-success border-success-border'
                              : wf.status === 'DRAFT'
                              ? 'bg-warning-surface text-warning border-warning-border'
                              : 'bg-surface text-foreground-muted border-border'
                          }`}
                        >
                          {wf.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-foreground-muted">{wf.owner_id}</td>
                      <td className="px-4 py-3 text-right space-x-1.5">
                        <button
                          type="button"
                          onClick={() => handleOpenTriggerModal(wf.id)}
                          className="px-2 py-1 rounded bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 text-[10px] font-bold cursor-pointer"
                          title="Execute Run or Dry-Run"
                        >
                          Trigger
                        </button>

                        {wf.status === 'DRAFT' && (
                          <button
                            type="button"
                            onClick={() => handleActivate(wf.id)}
                            className="px-2 py-1 rounded bg-success-surface hover:bg-success-surface/80 text-success border border-success-border text-[10px] font-bold cursor-pointer"
                          >
                            Activate
                          </button>
                        )}

                        {wf.status === 'ACTIVE' && (
                          <button
                            type="button"
                            onClick={() => handlePause(wf.id)}
                            className="px-2 py-1 rounded bg-surface-secondary hover:bg-surface border border-border text-foreground-muted text-[10px] font-bold cursor-pointer"
                          >
                            Pause
                          </button>
                        )}

                        <button
                          type="button"
                          onClick={() => handleNewVersion(wf.id)}
                          className="px-2 py-1 rounded bg-surface-secondary hover:bg-surface border border-border text-foreground-muted text-[10px] font-bold cursor-pointer"
                          title="Branch to next draft version"
                        >
                          <GitBranch className="w-3 h-3 inline" />
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

      {/* --------------------------------------------------------------------- */}
      {/* TAB 2: EXECUTION RUNS & AUDIT TRACE */}
      {/* --------------------------------------------------------------------- */}
      {activeTab === 'runs' && (
        <div className="bg-surface rounded-card border border-border overflow-hidden">
          <table className="w-full text-xs font-mono text-left">
            <thead className="bg-surface-secondary text-foreground-muted border-b border-border uppercase text-[10px]">
              <tr>
                <th className="px-4 py-3">Run ID</th>
                <th className="px-4 py-3">Trigger Event</th>
                <th className="px-4 py-3">Target Resource</th>
                <th className="px-4 py-3">Mode</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Steps</th>
                <th className="px-4 py-3">Started</th>
                <th className="px-4 py-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={8} className="text-center py-8 text-foreground-muted">
                    No automation runs recorded yet.
                  </td>
                </tr>
              ) : (
                runs.map((r) => (
                  <tr key={r.id} className="hover:bg-surface-secondary/50 transition-colors">
                    <td className="px-4 py-3 font-bold text-foreground truncate max-w-[120px]">
                      {r.id.slice(0, 8)}...
                    </td>
                    <td className="px-4 py-3 text-primary font-bold">{r.trigger_type}</td>
                    <td className="px-4 py-3 text-foreground-muted">
                      {r.trigger_resource_type}: {r.trigger_resource_id || 'N/A'}
                    </td>
                    <td className="px-4 py-3">
                      <span className="px-1.5 py-0.2 rounded bg-surface border border-border text-[9px] font-bold uppercase">
                        {r.execution_mode}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                          r.status === 'COMPLETED'
                            ? 'bg-success-surface text-success border-success-border'
                            : r.status === 'WAITING_FOR_APPROVAL'
                            ? 'bg-warning-surface text-warning border-warning-border'
                            : r.status === 'RUNNING'
                            ? 'bg-primary-subtle text-primary border-primary/30'
                            : 'bg-danger-surface text-danger border-danger-border'
                        }`}
                      >
                        {r.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-foreground">
                      {r.completed_steps}/{r.total_steps}
                    </td>
                    <td className="px-4 py-3 text-foreground-muted">
                      {new Date(r.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <button
                        type="button"
                        onClick={() => handleOpenTrace(r.id)}
                        className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface border border-border text-primary text-[10px] font-bold cursor-pointer"
                      >
                        Inspect Trace
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* TAB 3: HUMAN APPROVAL QUEUE */}
      {/* --------------------------------------------------------------------- */}
      {activeTab === 'approvals' && (
        <div className="space-y-4">
          {approvals.length === 0 ? (
            <div className="p-12 text-center bg-surface rounded-card border border-border space-y-2">
              <CheckCircle className="w-8 h-8 text-success mx-auto" />
              <h3 className="text-base font-bold text-foreground">No Pending Approvals</h3>
              <p className="text-xs text-foreground-muted font-mono">
                All consequential automation actions have been reviewed or executed.
              </p>
            </div>
          ) : (
            approvals.map((appr) => (
              <div
                key={appr.id}
                className="bg-surface border border-warning/40 rounded-card p-5 space-y-4 shadow-xs"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border pb-3">
                  <div className="flex items-center space-x-2">
                    <ShieldAlert className="w-4 h-4 text-warning" />
                    <span className="font-bold text-foreground font-sans text-sm">
                      Consequential Action Approval Required
                    </span>
                    <span className="px-2 py-0.2 rounded bg-warning-surface text-warning border border-warning-border text-[10px] font-bold uppercase">
                      Action: {appr.action_id}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2 text-xs font-mono text-foreground-muted">
                    <Clock className="w-3.5 h-3.5 text-warning" />
                    <span>Expires: {new Date(appr.expires_at).toLocaleTimeString()}</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
                  <div className="p-3 rounded-lg bg-surface-secondary border border-border">
                    <span className="text-[10px] uppercase text-foreground-muted block font-semibold">
                      Required Role:
                    </span>
                    <span className="text-warning font-bold block mt-0.5">{appr.required_role.toUpperCase()}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-surface-secondary border border-border">
                    <span className="text-[10px] uppercase text-foreground-muted block font-semibold">
                      Run Reference:
                    </span>
                    <span className="text-primary font-bold block mt-0.5">{appr.run_id.slice(0, 12)}...</span>
                  </div>
                  <div className="p-3 rounded-lg bg-surface-secondary border border-border">
                    <span className="text-[10px] uppercase text-foreground-muted block font-semibold">
                      Requested By:
                    </span>
                    <span className="text-foreground font-semibold block mt-0.5">{appr.requested_by}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="block text-xs font-mono text-foreground-muted">
                    Justification / Analyst Reason:
                  </label>
                  <input
                    type="text"
                    placeholder="Enter explicit approval rationale..."
                    value={approvalReason}
                    onChange={(e) => setApprovalReason(e.target.value)}
                    className="w-full bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-xs text-foreground font-mono focus:outline-none focus:border-primary"
                  />
                </div>

                <div className="flex items-center justify-end space-x-2 pt-2">
                  <button
                    type="button"
                    onClick={() => handleDecideApproval(appr.id, 'REJECTED')}
                    className="px-3.5 py-1.5 rounded-lg bg-danger-surface hover:bg-danger-surface/80 text-danger border border-danger-border text-xs font-mono font-bold cursor-pointer"
                  >
                    Reject Action
                  </button>
                  <button
                    type="button"
                    onClick={() => handleDecideApproval(appr.id, 'APPROVED')}
                    className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-success hover:bg-success/90 text-white text-xs font-mono font-bold cursor-pointer"
                  >
                    <Check className="w-3.5 h-3.5" />
                    <span>Authorize & Execute</span>
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* MODAL 1: CREATE WORKFLOW WIZARD */}
      {/* --------------------------------------------------------------------- */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold text-foreground font-sans flex items-center space-x-2">
                <Plus className="w-4 h-4 text-primary" />
                <span>Create Security Operations Workflow</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit} className="space-y-3.5 text-xs font-mono">
              <div>
                <label className="block text-foreground-muted mb-1">Workflow Name</label>
                <input
                  type="text"
                  placeholder="e.g. Critical Intrusion Triage & Containment"
                  value={newWfName}
                  onChange={(e) => setNewWfName(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-foreground focus:outline-none focus:border-primary"
                  required
                />
              </div>

              <div>
                <label className="block text-foreground-muted mb-1">Description</label>
                <textarea
                  rows={2}
                  placeholder="Operational purpose and scope..."
                  value={newWfDesc}
                  onChange={(e) => setNewWfDesc(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-foreground-muted mb-1">Workflow Type</label>
                  <select
                    value={newWfType}
                    onChange={(e) => setNewWfType(e.target.value)}
                    className="w-full bg-surface-secondary border border-border rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="ALERT_TRIAGE">Alert Triage</option>
                    <option value="INCIDENT_ESCALATION">Incident Escalation</option>
                    <option value="THREAT_HUNTING">Threat Hunting</option>
                    <option value="ACCOUNT_TAKEOVER_TRIAGE">ATO Triage</option>
                    <option value="MALICIOUS_ATTACHMENT_TRIAGE">Attachment Triage</option>
                  </select>
                </div>
                <div>
                  <label className="block text-foreground-muted mb-1">Trigger Event</label>
                  <select
                    value={newWfTrigger}
                    onChange={(e) => setNewWfTrigger(e.target.value)}
                    className="w-full bg-surface-secondary border border-border rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:border-primary"
                  >
                    <option value="ALERT_CREATED">ALERT_CREATED</option>
                    <option value="CRITICAL_FINDING_CREATED">CRITICAL_FINDING_CREATED</option>
                    <option value="INCIDENT_CREATED">INCIDENT_CREATED</option>
                    <option value="SLA_WARNING">SLA_WARNING</option>
                    <option value="MANUAL">MANUAL</option>
                  </select>
                </div>
              </div>

              {/* Structured Condition */}
              <div className="p-3 rounded-lg bg-surface-secondary border border-border space-y-2">
                <span className="text-[10px] uppercase text-primary font-bold block">
                  Structured Precondition Rule
                </span>
                <div className="grid grid-cols-3 gap-2">
                  <input
                    type="text"
                    placeholder="Field (severity)"
                    value={newWfCondField}
                    onChange={(e) => setNewWfCondField(e.target.value)}
                    className="bg-surface border border-border rounded px-2 py-1 text-[11px] text-foreground"
                  />
                  <select
                    value={newWfCondOp}
                    onChange={(e) => setNewWfCondOp(e.target.value)}
                    className="bg-surface border border-border rounded px-2 py-1 text-[11px] text-foreground"
                  >
                    <option value="eq">== (Equals)</option>
                    <option value="neq">!= (Not Equals)</option>
                    <option value="gte">&gt;= (Greater/Equal)</option>
                    <option value="in">in (Membership)</option>
                    <option value="contains">contains (Substring)</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Value (CRITICAL)"
                    value={newWfCondVal}
                    onChange={(e) => setNewWfCondVal(e.target.value)}
                    className="bg-surface border border-border rounded px-2 py-1 text-[11px] text-foreground"
                  />
                </div>
              </div>

              {/* Action Picker */}
              <div>
                <label className="block text-foreground-muted mb-1">Primary Action Step</label>
                <select
                  value={newWfActionId}
                  onChange={(e) => setNewWfActionId(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:border-primary"
                >
                  {registeredActions.map((act) => (
                    <option key={act.action_id} value={act.action_id}>
                      {act.name} ({act.risk_classification})
                    </option>
                  ))}
                </select>
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3.5 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-bold text-xs cursor-pointer shadow-xs"
                >
                  Save Draft Workflow
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* MODAL 2: EXECUTION TRACE INSPECTOR */}
      {/* --------------------------------------------------------------------- */}
      {showTraceModal && selectedRun && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div>
                <h3 className="text-base font-bold text-foreground font-sans">
                  Authoritative Execution Trace: {selectedRun.id.slice(0, 8)}
                </h3>
                <div className="flex items-center space-x-2 text-[11px] font-mono text-foreground-muted mt-1">
                  <span>Trigger: {selectedRun.trigger_type}</span>
                  <span>·</span>
                  <span>Mode: {selectedRun.execution_mode}</span>
                  <span>·</span>
                  <span>Status: <strong className="text-primary">{selectedRun.status}</strong></span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setShowTraceModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <h4 className="text-xs font-bold text-primary uppercase">
                Sequential Steps ({selectedRun.steps.length} Defined)
              </h4>

              {selectedRun.steps.map((st, i) => (
                <div key={st.id || i} className="p-3.5 rounded-xl bg-surface-secondary border border-border space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <span className="w-5 h-5 rounded bg-primary/15 text-primary flex items-center justify-center font-bold text-[10px]">
                        {st.step_index + 1}
                      </span>
                      <span className="font-bold text-foreground">{st.name}</span>
                      <span className="text-[9px] uppercase px-1.5 py-0.2 rounded bg-surface border border-border text-foreground-muted">
                        {st.risk_classification}
                      </span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                        st.status === 'COMPLETED'
                          ? 'bg-success-surface text-success border-success-border'
                          : st.status === 'WAITING_FOR_APPROVAL'
                          ? 'bg-warning-surface text-warning border-warning-border'
                          : 'bg-danger-surface text-danger border-danger-border'
                      }`}
                    >
                      {st.status}
                    </span>
                  </div>

                  {st.error_message && (
                    <div className="p-2 rounded bg-danger-surface border border-danger-border text-danger text-[11px]">
                      Error: {st.error_message}
                    </div>
                  )}

                  <div className="flex items-center justify-between text-[10px] text-foreground-muted pt-1">
                    <span>Duration: {st.execution_duration_ms}ms</span>
                    <span className={st.verified_state ? 'text-success font-bold' : 'text-foreground-muted'}>
                      {st.verified_state ? 'VERIFIED STATE SEALED' : 'UNVERIFIED'}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <div className="flex justify-end pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setShowTraceModal(false)}
                className="px-4 py-2 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground font-mono text-xs font-semibold cursor-pointer"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}

      {/* --------------------------------------------------------------------- */}
      {/* MODAL 3: RUN TRIGGER / TEST RUNNER */}
      {/* --------------------------------------------------------------------- */}
      {showTriggerModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold text-foreground font-sans flex items-center space-x-2">
                <Play className="w-4 h-4 text-primary" />
                <span>Trigger Automation Workflow</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowTriggerModal(false)}
                className="text-foreground-muted hover:text-foreground cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleExecuteTrigger} className="space-y-3.5 text-xs font-mono">
              <div>
                <label className="block text-foreground-muted mb-1">Execution Mode</label>
                <select
                  value={triggerMode}
                  onChange={(e) => setTriggerMode(e.target.value as any)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-2.5 py-1.5 text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="DRY_RUN">DRY_RUN (Simulate Preconditions & Actions)</option>
                  <option value="PRODUCTION">PRODUCTION (Authoritative Execution)</option>
                  <option value="TEST">TEST (Sandbox Scoped)</option>
                </select>
              </div>

              <div>
                <label className="block text-foreground-muted mb-1">Resource ID</label>
                <input
                  type="text"
                  placeholder="e.g. ALT-2026-099 or INC-2026-042"
                  value={triggerResource}
                  onChange={(e) => setTriggerResource(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-foreground focus:outline-none focus:border-primary"
                />
              </div>

              <div>
                <label className="block text-foreground-muted mb-1">Mock Payload JSON</label>
                <textarea
                  rows={4}
                  value={triggerPayload}
                  onChange={(e) => setTriggerPayload(e.target.value)}
                  className="w-full bg-surface-secondary border border-border rounded-lg px-3 py-1.5 text-foreground font-mono focus:outline-none focus:border-primary"
                />
              </div>

              <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
                <button
                  type="button"
                  onClick={() => setShowTriggerModal(false)}
                  className="px-3.5 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground text-xs cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground font-bold text-xs cursor-pointer shadow-xs"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Execute Run</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
