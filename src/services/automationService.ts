/**
 * Section 70: Security Operations Automation (SOAR) Client Service.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  AutomationWorkflow,
  AutomationRun,
  ApprovalRequest,
  RegisteredActionMeta,
  AutomationMetrics,
  WorkflowExecutionMode,
} from '../types/automation';

const API_BASE = '/api/automation';

export const automationService = {
  // Workflows
  async listWorkflows(
    status?: string,
    workflowType?: string,
    triggerType?: string,
    skip: number = 0,
    limit: number = 50
  ): Promise<{ items: AutomationWorkflow[]; total: number }> {
    const params = new URLSearchParams({ skip: String(skip), limit: String(limit) });
    if (status && status !== 'ALL') params.set('status', status);
    if (workflowType && workflowType !== 'ALL') params.set('workflow_type', workflowType);
    if (triggerType && triggerType !== 'ALL') params.set('trigger_type', triggerType);

    const res = await fetch(apiUrl(`${API_BASE}/workflows?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list workflows (${res.status})`);
    }
    return res.json();
  },

  async getWorkflow(workflowId: string): Promise<AutomationWorkflow> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch workflow '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  async createWorkflow(data: Partial<AutomationWorkflow>): Promise<AutomationWorkflow> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create workflow (${res.status})`);
    }
    return res.json();
  },

  async updateWorkflow(workflowId: string, data: Partial<AutomationWorkflow>): Promise<AutomationWorkflow> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}`), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update workflow '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  async validateWorkflow(workflowId: string): Promise<{ is_valid: boolean; errors: string[] }> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}/validate`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to validate workflow '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  async activateWorkflow(workflowId: string): Promise<AutomationWorkflow> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}/activate`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to activate workflow '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  async pauseWorkflow(workflowId: string): Promise<AutomationWorkflow> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}/pause`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to pause workflow '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  async disableWorkflow(workflowId: string): Promise<AutomationWorkflow> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}/disable`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to disable workflow '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  async createNewVersion(workflowId: string): Promise<AutomationWorkflow> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}/new-version`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create new version for '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  async triggerWorkflow(
    workflowId: string,
    data: {
      resource_type?: string;
      resource_id?: string;
      payload?: Record<string, any>;
      execution_mode?: WorkflowExecutionMode;
    }
  ): Promise<AutomationRun> {
    const res = await fetch(apiUrl(`${API_BASE}/workflows/${encodeURIComponent(workflowId)}/trigger`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to trigger workflow '${workflowId}' (${res.status})`);
    }
    return res.json();
  },

  // Runs
  async listRuns(
    workflowId?: string,
    status?: string,
    skip: number = 0,
    limit: number = 50
  ): Promise<{ items: AutomationRun[]; total: number }> {
    const params = new URLSearchParams({ skip: String(skip), limit: String(limit) });
    if (workflowId) params.set('workflow_id', workflowId);
    if (status && status !== 'ALL') params.set('status', status);

    const res = await fetch(apiUrl(`${API_BASE}/runs?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list runs (${res.status})`);
    }
    return res.json();
  },

  async getRun(runId: string): Promise<AutomationRun> {
    const res = await fetch(apiUrl(`${API_BASE}/runs/${encodeURIComponent(runId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch run '${runId}' (${res.status})`);
    }
    return res.json();
  },

  async cancelRun(runId: string): Promise<AutomationRun> {
    const res = await fetch(apiUrl(`${API_BASE}/runs/${encodeURIComponent(runId)}/cancel`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to cancel run '${runId}' (${res.status})`);
    }
    return res.json();
  },

  // Approvals
  async listPendingApprovals(): Promise<ApprovalRequest[]> {
    const res = await fetch(apiUrl(`${API_BASE}/approvals`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list approvals (${res.status})`);
    }
    return res.json();
  },

  async decideApproval(approvalId: string, decision: 'APPROVED' | 'REJECTED', reason?: string): Promise<ApprovalRequest> {
    const res = await fetch(apiUrl(`${API_BASE}/approvals/${encodeURIComponent(approvalId)}/decide`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reason }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to submit decision for approval '${approvalId}' (${res.status})`);
    }
    return res.json();
  },

  // Actions & Metrics
  async listRegisteredActions(): Promise<RegisteredActionMeta[]> {
    const res = await fetch(apiUrl(`${API_BASE}/actions`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch registered actions (${res.status})`);
    }
    return res.json();
  },

  async getMetrics(): Promise<AutomationMetrics> {
    const res = await fetch(apiUrl(`${API_BASE}/metrics`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch metrics (${res.status})`);
    }
    return res.json();
  },
};
