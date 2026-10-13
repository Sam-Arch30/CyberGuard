import { apiFetch } from '../utils/apiClient';
/**
 * Section 66: Advanced Investigation Automation Client Service.
 * Communicates with backend endpoints at /api/investigations/{id}/automation
 * and /api/v1/investigation-automation.
 */
import { apiUrl } from '../utils/apiClient';
import type {
  AutomationTemplateDefinition,
  InvestigationAutomationRunRead,
  InvestigationAutomationRunCreate,
  InvestigationGapRead,
  StepApprovalRequest,
  AutomationPolicyRead,
} from '../types/investigationAutomation';

const defaultHeaders = (workspaceId = 'default', role = 'analyst'): HeadersInit => ({
  'Content-Type': 'application/json',
  'X-Workspace-ID': workspaceId,
  'X-Role': role,
});

export const investigationAutomationService = {
  /**
   * Fetches the registered investigation templates.
   */
  async getTemplates(): Promise<AutomationTemplateDefinition[]> {
    const res = await apiFetch(apiUrl('/api/investigations/automation/templates'), {
      headers: defaultHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load investigation templates: ${res.statusText}`);
    return res.json();
  },

  /**
   * Lists historical automation runs for an investigation.
   */
  async listRuns(investigationId: string, limit = 20, workspaceId = 'default'): Promise<InvestigationAutomationRunRead[]> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/automation/runs?limit=${limit}`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to list automation runs: ${res.statusText}`);
    return res.json();
  },

  /**
   * Retrieves a specific automation run.
   */
  async getRun(runId: string, investigationId?: string, workspaceId = 'default'): Promise<InvestigationAutomationRunRead> {
    const endpoint = investigationId
      ? `/api/investigations/${encodeURIComponent(investigationId)}/automation/runs/${runId}`
      : `/api/v1/investigation-automation/runs/${runId}`;
    const res = await apiFetch(apiUrl(endpoint), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch automation run: ${res.statusText}`);
    return res.json();
  },

  /**
   * Plans and executes an automated investigation run.
   */
  async createAndExecuteRun(
    investigationId: string,
    req: InvestigationAutomationRunCreate,
    asyncExec = false,
    workspaceId = 'default',
    role = 'analyst',
  ): Promise<InvestigationAutomationRunRead> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/automation/runs?async_exec=${asyncExec}`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId, role),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to trigger automation run: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Approves or rejects a gated investigation step.
   */
  async approveStep(
    runId: string,
    stepIndex: number,
    approval: StepApprovalRequest,
    investigationId?: string,
    workspaceId = 'default',
    role = 'analyst',
  ): Promise<InvestigationAutomationRunRead> {
    const endpoint = investigationId
      ? `/api/investigations/${encodeURIComponent(investigationId)}/automation/runs/${runId}/steps/${stepIndex}/approve`
      : `/api/v1/investigation-automation/runs/${runId}/steps/${stepIndex}/approve`;
    const res = await apiFetch(apiUrl(endpoint), {
      method: 'POST',
      headers: defaultHeaders(workspaceId, role),
      body: JSON.stringify(approval),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to approve/reject step: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Cancels an ongoing or queued investigation run.
   */
  async cancelRun(runId: string, investigationId?: string, workspaceId = 'default', role = 'analyst'): Promise<InvestigationAutomationRunRead> {
    const endpoint = investigationId
      ? `/api/investigations/${encodeURIComponent(investigationId)}/automation/runs/${runId}/cancel`
      : `/api/v1/investigation-automation/runs/${runId}/cancel`;
    const res = await apiFetch(apiUrl(endpoint), {
      method: 'POST',
      headers: defaultHeaders(workspaceId, role),
    });
    if (!res.ok) throw new Error(`Failed to cancel automation run: ${res.statusText}`);
    return res.json();
  },

  /**
   * Resumes a paused investigation run.
   */
  async resumeRun(runId: string, investigationId?: string, workspaceId = 'default', role = 'analyst'): Promise<InvestigationAutomationRunRead> {
    const endpoint = investigationId
      ? `/api/investigations/${encodeURIComponent(investigationId)}/automation/runs/${runId}/resume`
      : `/api/v1/investigation-automation/runs/${runId}/resume`;
    const res = await apiFetch(apiUrl(endpoint), {
      method: 'POST',
      headers: defaultHeaders(workspaceId, role),
    });
    if (!res.ok) throw new Error(`Failed to resume automation run: ${res.statusText}`);
    return res.json();
  },

  /**
   * Retries failed steps in an investigation run.
   */
  async retryRun(runId: string, investigationId?: string, workspaceId = 'default', role = 'analyst'): Promise<InvestigationAutomationRunRead> {
    const endpoint = investigationId
      ? `/api/investigations/${encodeURIComponent(investigationId)}/automation/runs/${runId}/retry`
      : `/api/v1/investigation-automation/runs/${runId}/retry`;
    const res = await apiFetch(apiUrl(endpoint), {
      method: 'POST',
      headers: defaultHeaders(workspaceId, role),
    });
    if (!res.ok) throw new Error(`Failed to retry failed steps: ${res.statusText}`);
    return res.json();
  },

  /**
   * Fetches all detected investigation gaps for an investigation.
   */
  async getGaps(investigationId: string, workspaceId = 'default'): Promise<InvestigationGapRead[]> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(investigationId)}/automation/gaps`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch investigation gaps: ${res.statusText}`);
    return res.json();
  },

  /**
   * Lists automation policies.
   */
  async listPolicies(workspaceId = 'default'): Promise<AutomationPolicyRead[]> {
    const res = await apiFetch(apiUrl('/api/investigations/automation/policies'), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to list automation policies: ${res.statusText}`);
    return res.json();
  },
};
