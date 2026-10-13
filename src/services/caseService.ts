import { apiFetch } from '../utils/apiClient';
import { apiUrl } from '../utils/apiClient';
import type {
  CaseListItem,
  CaseDetail,
  CaseCreatePayload,
  CaseUpdatePayload,
  CaseAssignPayload,
  CaseResolvePayload,
  CaseClosePayload,
  CaseReopenPayload,
  CaseMergePayload,
  CaseLinkPayload,
  CaseTask,
  CaseTaskCreatePayload,
  CaseTaskUpdatePayload,
  CaseNote,
  CaseNoteCreateRequest,
  CaseNoteUpdateRequest,
  CaseFinding,
  CaseFindingCreateRequest,
  CaseEmail,
  CaseTimelineEvent,
  CaseMetricsSummary,
} from '../types/case';

export const caseService = {
  async listCases(params?: {
    status?: string;
    severity?: string;
    priority?: string;
    category?: string;
    owner_id?: string;
    team_id?: string;
    incident_id?: string;
    search?: string;
    skip?: number;
    limit?: number;
  }): Promise<{ cases: CaseListItem[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.status && params.status !== 'ALL') query.append('status', params.status);
    if (params?.severity && params.severity !== 'ALL') query.append('severity', params.severity);
    if (params?.priority && params.priority !== 'ALL') query.append('priority', params.priority);
    if (params?.category && params.category !== 'ALL') query.append('category', params.category);
    if (params?.owner_id) query.append('owner_id', params.owner_id);
    if (params?.team_id) query.append('team_id', params.team_id);
    if (params?.incident_id) query.append('incident_id', params.incident_id);
    if (params?.search) query.append('search', params.search);
    if (params?.skip !== undefined) query.append('skip', String(params.skip));
    if (params?.limit !== undefined) query.append('limit', String(params.limit));

    const res = await apiFetch(apiUrl(`/api/cases?${query.toString()}`));
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to list cases');
    }
    return res.json();
  },

  async getCaseMetrics(): Promise<CaseMetricsSummary> {
    const res = await apiFetch(apiUrl('/api/cases/metrics/overview'));
    if (!res.ok) {
      throw new Error('Failed to fetch case metrics');
    }
    return res.json();
  },

  async getCase(caseId: string): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}`));
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch case ${caseId}`);
    }
    return res.json();
  },

  async createCase(payload: CaseCreatePayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl('/api/cases'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to create case');
    }
    return res.json();
  },

  async updateCase(caseId: string, payload: CaseUpdatePayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to update case');
    }
    return res.json();
  },

  async assignCase(caseId: string, payload: CaseAssignPayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/assign`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to assign case');
    }
    return res.json();
  },

  async resolveCase(caseId: string, payload: CaseResolvePayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/resolve`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to resolve case');
    }
    return res.json();
  },

  async closeCase(caseId: string, payload: CaseClosePayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/close`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to close case');
    }
    return res.json();
  },

  async reopenCase(caseId: string, payload: CaseReopenPayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/reopen`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to reopen case');
    }
    return res.json();
  },

  async mergeCases(targetCaseId: string, payload: CaseMergePayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${targetCaseId}/merge`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to merge cases');
    }
    return res.json();
  },

  async linkEntity(caseId: string, payload: CaseLinkPayload): Promise<CaseDetail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/link`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to link entity to case');
    }
    return res.json();
  },

  async getCaseTimeline(caseId: string): Promise<CaseTimelineEvent[]> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/timeline`));
    if (!res.ok) {
      throw new Error('Failed to fetch case timeline');
    }
    return res.json();
  },

  async createTask(caseId: string, payload: CaseTaskCreatePayload): Promise<CaseTask> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/tasks`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to create task');
    }
    return res.json();
  },

  async updateTask(caseId: string, taskId: string, payload: CaseTaskUpdatePayload): Promise<CaseTask> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/tasks/${taskId}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to update task');
    }
    return res.json();
  },

  async deleteTask(caseId: string, taskId: string): Promise<void> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/tasks/${taskId}`), {
      method: 'DELETE',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to delete task');
    }
  },

  async addNote(caseId: string, payload: CaseNoteCreateRequest): Promise<CaseNote> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/notes`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to add note');
    }
    return res.json();
  },

  async updateNote(caseId: string, noteId: string, payload: CaseNoteUpdateRequest): Promise<CaseNote> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/notes/${noteId}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to edit note');
    }
    return res.json();
  },

  async addFinding(caseId: string, payload: CaseFindingCreateRequest): Promise<CaseFinding> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/findings`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to add finding');
    }
    return res.json();
  },

  async addEmail(caseId: string, payload: Record<string, any>): Promise<CaseEmail> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/emails`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to add email');
    }
    return res.json();
  },

  async removeEmail(caseId: string, emailId: string): Promise<void> {
    const res = await apiFetch(apiUrl(`/api/cases/${caseId}/emails/${emailId}`), {
      method: 'DELETE',
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to remove email');
    }
  },
};
