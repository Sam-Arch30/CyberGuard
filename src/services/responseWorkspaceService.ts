/**
 * Response Workspace API Service for Section 41.
 * Authoritative integration with Section 28 recommendations, Section 29 playbooks,
 * capability registry, approvals, and immutable audit logs.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  ResponseRecommendation,
  ResponseCapability,
  ResponseWorkspaceOverview,
} from '../types/response_recommendation';
import type {
  ResponsePlaybook,
  ResponsePlaybookSummary,
  SimulationPlan,
  ResponsePlaybookExecution,
} from '../types/response_playbook';

export type {
  ResponseRecommendation,
  ResponseCapability,
  ResponseWorkspaceOverview,
} from '../types/response_recommendation';
export type {
  ResponsePlaybook,
  ResponsePlaybookSummary,
  SimulationPlan,
  ResponsePlaybookExecution,
} from '../types/response_playbook';

export type ReviewStatus = 'APPROVED' | 'REJECTED' | 'DEFERRED';

export interface RecommendationReviewRequest {
  recommendation_id: string;
  status: ReviewStatus;
  reviewer_id: string;
  reviewer_notes: string;
}

export type ResponseRecommendationResponse = ResponseRecommendation;

export interface ExecutionAuditLogEntry {
  id: string;
  action: string;
  user: string;
  timestamp: string;
  metadata: Record<string, any>;
}


export const responseWorkspaceService = {
  /**
   * Retrieves prioritized recommendations for a target scope (INVESTIGATION, EVENT, INCIDENT).
   */
  async getRecommendationsByScope(
    scopeType: string = 'INVESTIGATION',
    scopeId: string
  ): Promise<ResponseRecommendation[]> {
    const cleanScopeType = scopeType.trim().toUpperCase();
    const endpoint = cleanScopeType === 'INVESTIGATION'
      ? `/api/investigations/${encodeURIComponent(scopeId)}/response`
      : `/api/v1/recommendations/by-scope/${encodeURIComponent(cleanScopeType)}/${encodeURIComponent(scopeId)}`;

    const res = await fetch(apiUrl(endpoint));
    if (!res.ok) {
      // Fallback to by-scope route if investigations route is unavailable
      const fallbackRes = await fetch(
        apiUrl(`/api/v1/recommendations/by-scope/${encodeURIComponent(cleanScopeType)}/${encodeURIComponent(scopeId)}`)
      );
      if (!fallbackRes.ok) {
        const err = await extractErrorMessage(fallbackRes);
        throw new Error(err || `Failed to fetch response recommendations (${res.status})`);
      }
      const data = await fallbackRes.json();
      return Array.isArray(data) ? data : (data.recommendations || []);
    }
    const data = await res.json();
    return Array.isArray(data) ? data : (data.recommendations || []);
  },

  /**
   * Retrieves high-level response overview summary metrics and counts.
   */
  async getRecommendationsSummary(
    scopeType: string = 'INVESTIGATION',
    scopeId: string
  ): Promise<ResponseWorkspaceOverview> {
    const cleanScopeType = scopeType.trim().toUpperCase();
    const res = await fetch(
      apiUrl(`/api/v1/recommendations/summary/${encodeURIComponent(cleanScopeType)}/${encodeURIComponent(scopeId)}`)
    );
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch response overview (${res.status})`);
    }
    return res.json();
  },

  /**
   * Forces regeneration or evaluates fresh recommendations with updated telemetry.
   */
  async generateRecommendations(
    scopeType: string,
    scopeId: string,
    forceRegenerate: boolean = true
  ): Promise<ResponseRecommendation[]> {
    const res = await fetch(apiUrl('/api/v1/recommendations/generate'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        scope_type: scopeType.toUpperCase(),
        scope_id: scopeId,
        force_regenerate: forceRegenerate,
      }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to regenerate recommendations (${res.status})`);
    }
    const data = await res.json();
    return Array.isArray(data) ? data : (data.recommendations || []);
  },

  /**
   * Fetches the environment defensive capability registry.
   */
  async getCapabilities(): Promise<ResponseCapability[]> {
    const res = await fetch(apiUrl('/api/v1/recommendations/capabilities'));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch environment capability registry (${res.status})`);
    }
    return res.json();
  },

  /**
   * Analyst approves an advisory recommendation.
   * Does NOT trigger automatic execution; marks state as APPROVED.
   */
  async approveRecommendation(
    recommendationId: string,
    notes: string,
    reviewerId: string = 'SOC Analyst'
  ): Promise<ResponseRecommendation> {
    const res = await fetch(apiUrl(`/api/v1/recommendations/${encodeURIComponent(recommendationId)}/approve`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        reviewer_id: reviewerId,
        disposition: 'APPROVED',
        notes: notes.trim(),
      }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Approval failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Analyst rejects an advisory recommendation with documented reason.
   */
  async rejectRecommendation(
    recommendationId: string,
    notes: string,
    reviewerId: string = 'SOC Analyst'
  ): Promise<ResponseRecommendation> {
    const res = await fetch(apiUrl(`/api/v1/recommendations/${encodeURIComponent(recommendationId)}/reject`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        reviewer_id: reviewerId,
        disposition: 'REJECTED',
        notes: notes.trim(),
      }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Rejection failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Analyst defers an advisory recommendation for later investigation.
   */
  async deferRecommendation(
    recommendationId: string,
    notes: string,
    reviewerId: string = 'SOC Analyst'
  ): Promise<ResponseRecommendation> {
    const res = await fetch(apiUrl(`/api/v1/recommendations/${encodeURIComponent(recommendationId)}/defer`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        reviewer_id: reviewerId,
        disposition: 'DEFERRED',
        notes: notes.trim(),
      }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Deferral failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Lists available Playbooks in the workspace.
   */
  async getPlaybooks(status?: string, scopeType?: string): Promise<ResponsePlaybookSummary[]> {
    const params = new URLSearchParams();
    if (status) params.append('status', status);
    if (scopeType) params.append('scope_type', scopeType);
    const qs = params.toString() ? `?${params.toString()}` : '';

    const res = await fetch(apiUrl(`/api/v1/playbooks${qs}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list response playbooks (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves single playbook with all defined steps.
   */
  async getPlaybook(playbookId: string): Promise<ResponsePlaybook> {
    const res = await fetch(apiUrl(`/api/v1/playbooks/${encodeURIComponent(playbookId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Playbook '${playbookId}' not found (${res.status})`);
    }
    return res.json();
  },

  /**
   * Converts an approved recommendation into an executable playbook.
   */
  async createPlaybookFromRecommendation(
    recommendationId: string,
    requestedBy: string = 'SOC Analyst'
  ): Promise<ResponsePlaybook> {
    const res = await fetch(
      apiUrl(`/api/v1/playbooks/from-recommendation/${encodeURIComponent(recommendationId)}`),
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recommendation_id: recommendationId,
          requested_by: requestedBy,
          auto_stage: true,
        }),
      }
    );
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to generate playbook from recommendation (${res.status})`);
    }
    return res.json();
  },

  /**
   * Compiles and executes a dry-run simulation plan without live side-effects.
   */
  async simulatePlaybook(playbookId: string, targetOverride?: any): Promise<SimulationPlan> {
    const res = await fetch(apiUrl(`/api/v1/playbooks/${encodeURIComponent(playbookId)}/simulate`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target_override: targetOverride,
      }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Playbook simulation failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Executes a playbook in LIVE or DRY_RUN mode.
   */
  async executePlaybook(
    playbookId: string,
    mode: 'LIVE' | 'DRY_RUN' = 'DRY_RUN',
    requestedBy: string = 'SOC Analyst',
    investigationId?: string,
    targetOverride?: any
  ): Promise<ResponsePlaybookExecution> {
    const res = await fetch(apiUrl(`/api/v1/playbooks/${encodeURIComponent(playbookId)}/execute`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode,
        requested_by: requestedBy,
        target_override: targetOverride,
        execution_context: {
          investigation_id: investigationId,
          executed_from: 'Response Workspace',
        },
      }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Playbook execution request failed (${res.status})`);
    }
    return res.json();
  },

  /**
   * Lists executions, optionally filtered by investigation or playbook.
   */
  async listExecutions(
    investigationId?: string,
    playbookId?: string,
    status?: string
  ): Promise<ResponsePlaybookExecution[]> {
    const params = new URLSearchParams();
    if (investigationId) params.append('investigation_id', investigationId);
    if (playbookId) params.append('playbook_id', playbookId);
    if (status) params.append('status', status);
    const qs = params.toString() ? `?${params.toString()}` : '';

    const res = await fetch(apiUrl(`/api/v1/playbooks/executions${qs}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch execution history (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves single execution with step statuses and verifications.
   */
  async getExecution(executionId: string): Promise<ResponsePlaybookExecution> {
    const res = await fetch(apiUrl(`/api/v1/playbooks/executions/${encodeURIComponent(executionId)}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Execution record '${executionId}' not found (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves immutable audit log events for an execution.
   */
  async getExecutionAudit(executionId: string): Promise<ExecutionAuditLogEntry[]> {
    const res = await fetch(apiUrl(`/api/v1/playbooks/executions/${encodeURIComponent(executionId)}/audit`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch execution audit trail (${res.status})`);
    }
    return res.json();
  },
};
