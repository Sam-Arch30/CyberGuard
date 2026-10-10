/**
 * Section 50: Incident Management & Case Lifecycle Client Service.
 * Provides typed methods for incident queue listing, metrics, lifecycle state mutation,
 * alert/cluster promotion, assignment, timeline, notes, and resolution.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  IncidentDetail,
  IncidentItem,
  IncidentListResponse,
  IncidentMetrics,
  IncidentCreatePayload,
  IncidentPromoteAlertPayload,
  IncidentPromoteClusterPayload,
  IncidentStatusChangePayload,
  IncidentAssignPayload,
  IncidentNoteCreatePayload,
  IncidentTimelineEvent,
  IncidentNote,
  IncidentStatus,
  IncidentSeverity,
  IncidentPriority,
  IncidentCategory,
} from '../types/incident';

export interface IncidentListParams {
  status?: IncidentStatus;
  severity?: IncidentSeverity;
  priority?: IncidentPriority;
  category?: IncidentCategory;
  assigned_to?: string;
  search?: string;
  limit?: number;
  offset?: number;
  sort_by?: string;
}

export class IncidentService {
  /**
   * Retrieves paginated, filtered operational incident queue.
   */
  static async listIncidents(
    params?: IncidentListParams,
    workspaceId: string = 'default'
  ): Promise<IncidentListResponse> {
    const qp = new URLSearchParams();
    if (params?.status) qp.append('status', params.status);
    if (params?.severity) qp.append('severity', params.severity);
    if (params?.priority) qp.append('priority', params.priority);
    if (params?.category) qp.append('category', params.category);
    if (params?.assigned_to) qp.append('assigned_to', params.assigned_to);
    if (params?.search) qp.append('search', params.search);
    if (params?.limit) qp.append('limit', String(params.limit));
    if (params?.offset) qp.append('offset', String(params.offset));
    if (params?.sort_by) qp.append('sort_by', params.sort_by);

    const url = `${apiUrl('/api/incidents')}?${qp.toString()}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to list incidents: ${err}`);
    }

    return res.json();
  }

  /**
   * Retrieves full forensic and operational details for a specific incident.
   */
  static async getIncidentDetail(
    incidentId: string,
    workspaceId: string = 'default'
  ): Promise<IncidentDetail> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to get incident detail: ${err}`);
    }

    return res.json();
  }

  /**
   * Retrieves aggregated operational case management metrics.
   */
  static async getMetrics(workspaceId: string = 'default'): Promise<IncidentMetrics> {
    const url = apiUrl('/api/incidents/metrics');
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to get incident metrics: ${err}`);
    }

    return res.json();
  }

  /**
   * Manually creates an incident case.
   */
  static async createIncident(
    payload: IncidentCreatePayload,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl('/api/incidents');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to create incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Promotes a security alert directly to an operational Incident case.
   */
  static async promoteAlert(
    payload: IncidentPromoteAlertPayload,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl('/api/incidents/promote-alert');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to promote alert to incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Promotes an Alert Cluster directly to an operational Incident case.
   */
  static async promoteCluster(
    payload: IncidentPromoteClusterPayload,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl('/api/incidents/promote-cluster');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to promote cluster to incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Executes a validated lifecycle state transition.
   */
  static async updateStatus(
    incidentId: string,
    payload: IncidentStatusChangePayload,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/status`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to update incident status: ${err}`);
    }

    return res.json();
  }

  /**
   * Assigns or reassigns an analyst or team to the incident.
   */
  static async assignIncident(
    incidentId: string,
    payload: IncidentAssignPayload,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/assign`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to assign incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Resolves an incident with a mandatory structured reason.
   */
  static async resolveIncident(
    incidentId: string,
    resolutionReason: string,
    reason?: string,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/resolve`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify({
        resolution_reason: resolutionReason,
        reason: reason || `Resolved as ${resolutionReason}`,
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to resolve incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Closes an incident after resolution.
   */
  static async closeIncident(
    incidentId: string,
    reason?: string,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/close`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify({
        reason: reason || 'Incident case closed by analyst.',
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to close incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Reopens a resolved or closed incident.
   */
  static async reopenIncident(
    incidentId: string,
    reason: string,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentItem> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/reopen`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify({ reason }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to reopen incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Adds an analyst note to the case record.
   */
  static async addNote(
    incidentId: string,
    payload: IncidentNoteCreatePayload,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentNote> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/notes`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to add note: ${err}`);
    }

    return res.json();
  }

  /**
   * Retrieves timeline events for an incident.
   */
  static async getTimeline(
    incidentId: string,
    workspaceId: string = 'default'
  ): Promise<IncidentTimelineEvent[]> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/history`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to get incident timeline: ${err}`);
    }

    return res.json();
  }
}
