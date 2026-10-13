import { apiFetch } from '../utils/apiClient';
/**
 * Frontend client service for Section 39: Investigation Workspace.
 * Interacts with /api/investigations endpoints.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  InvestigationWorkspaceSummary,
  InvestigationStatusUpdate,
  InvestigationEvidenceItem,
  InvestigationTimelineEventItem,
  AnalystNoteModel,
} from '../types/investigationWorkspace';

export const investigationWorkspaceService = {
  /**
   * Retrieves the consolidated 9-part investigation workspace summary.
   */
  async getWorkspaceSummary(identifier: string): Promise<InvestigationWorkspaceSummary> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/summary`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Investigation '${identifier}' not found (${res.status})`);
    }
    return res.json();
  },

  /**
   * Updates investigation status with backend-validated lifecycle transitions.
   */
  async updateStatus(
    identifier: string,
    update: InvestigationStatusUpdate
  ): Promise<InvestigationWorkspaceSummary> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/status`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(update),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update status for investigation '${identifier}' (${res.status})`);
    }
    return res.json();
  },

  /**
   * Appends an attributed, timestamped analyst note to the investigation.
   */
  async addNote(
    identifier: string,
    noteText: string,
    author: string = 'SOC Analyst'
  ): Promise<AnalystNoteModel> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/notes`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ note_text: noteText, author }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to add analyst note (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves all analyst notes for an investigation.
   */
  async getNotes(identifier: string): Promise<AnalystNoteModel[]> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/notes`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch analyst notes (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves the evidence browser items distinguishing original files from derived signals.
   */
  async getEvidenceList(identifier: string): Promise<InvestigationEvidenceItem[]> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/evidence`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch investigation evidence (${res.status})`);
    }
    return res.json();
  },

  /**
   * Retrieves the chronological timeline events for the investigation.
   */
  async getTimelineEvents(identifier: string): Promise<InvestigationTimelineEventItem[]> {
    const res = await apiFetch(apiUrl(`/api/investigations/${encodeURIComponent(identifier)}/timeline`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch investigation timeline (${res.status})`);
    }
    return res.json();
  },
};
