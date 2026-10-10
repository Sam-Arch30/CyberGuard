/**
 * Section 48: Alert Management & Triage Client Service.
 * Provides typed methods for alert retrieval, metrics posture, deep forensic detail,
 * and authenticated triage actions with workspace isolation.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  AlertItem,
  AlertDetail,
  AlertListResponse,
  AlertMetrics,
  AlertAcknowledgePayload,
  AlertAssignPayload,
  AlertResolvePayload,
  AlertFalsePositivePayload,
  AlertSuppressPayload,
  AlertAddNotePayload,
} from '../types/alert';

export interface AlertFilterOptions {
  status?: string;
  severity?: string;
  alert_type?: string;
  investigation_id?: string;
  assigned_to?: string;
  q?: string;
  limit?: number;
  offset?: number;
  sort_by?: string;
}

export class AlertService {
  /**
   * Retrieves filtered and paginated security alerts.
   */
  static async getAlerts(
    filters?: AlertFilterOptions,
    workspaceId: string = 'default'
  ): Promise<AlertListResponse> {
    const params = new URLSearchParams();
    if (filters?.status) params.append('status', filters.status);
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.alert_type) params.append('alert_type', filters.alert_type);
    if (filters?.investigation_id) params.append('investigation_id', filters.investigation_id);
    if (filters?.assigned_to) params.append('assigned_to', filters.assigned_to);
    if (filters?.q) params.append('q', filters.q);
    if (filters?.limit) params.append('limit', String(filters.limit));
    if (filters?.offset) params.append('offset', String(filters.offset));
    if (filters?.sort_by) params.append('sort_by', filters.sort_by);

    const url = `${apiUrl('/api/alerts')}?${params.toString()}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch alerts (${res.status})`);
    }

    return (await res.json()) as AlertListResponse;
  }

  /**
   * Retrieves operational alert triage metrics.
   */
  static async getAlertMetrics(workspaceId: string = 'default'): Promise<AlertMetrics> {
    const res = await fetch(apiUrl('/api/alerts/metrics'), {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch alert metrics (${res.status})`);
    }

    return (await res.json()) as AlertMetrics;
  }

  /**
   * Retrieves authoritative alert detail including provenance, evidence, and timeline.
   */
  static async getAlertDetail(
    alertId: string,
    workspaceId: string = 'default'
  ): Promise<AlertDetail> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}`), {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch alert detail (${res.status})`);
    }

    return (await res.json()) as AlertDetail;
  }

  /**
   * Transitions alert to ACKNOWLEDGED state.
   */
  static async acknowledgeAlert(
    alertId: string,
    payload?: AlertAcknowledgePayload,
    workspaceId: string = 'default'
  ): Promise<AlertItem> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/acknowledge`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload || {}),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to acknowledge alert (${res.status})`);
    }

    return (await res.json()) as AlertItem;
  }

  /**
   * Assigns alert to an analyst.
   */
  static async assignAlert(
    alertId: string,
    payload: AlertAssignPayload,
    workspaceId: string = 'default'
  ): Promise<AlertItem> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/assign`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to assign alert (${res.status})`);
    }

    return (await res.json()) as AlertItem;
  }

  /**
   * Transitions alert to INVESTIGATING status.
   */
  static async investigateAlert(
    alertId: string,
    analystName?: string,
    workspaceId: string = 'default'
  ): Promise<AlertItem> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/investigate`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        ...(analystName ? { 'X-User': analystName } : {}),
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to set alert investigating (${res.status})`);
    }

    return (await res.json()) as AlertItem;
  }

  /**
   * Resolves an alert with deterministic justification.
   */
  static async resolveAlert(
    alertId: string,
    payload: AlertResolvePayload,
    workspaceId: string = 'default'
  ): Promise<AlertItem> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/resolve`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to resolve alert (${res.status})`);
    }

    return (await res.json()) as AlertItem;
  }

  /**
   * Marks an alert as False Positive with reason.
   */
  static async markFalsePositive(
    alertId: string,
    payload: AlertFalsePositivePayload,
    workspaceId: string = 'default'
  ): Promise<AlertItem> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/false-positive`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to mark alert as false positive (${res.status})`);
    }

    return (await res.json()) as AlertItem;
  }

  /**
   * Suppresses an alert with reason and scope.
   */
  static async suppressAlert(
    alertId: string,
    payload: AlertSuppressPayload,
    workspaceId: string = 'default'
  ): Promise<AlertItem> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/suppress`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to suppress alert (${res.status})`);
    }

    return (await res.json()) as AlertItem;
  }

  /**
   * Appends a triage note to an alert.
   */
  static async addNote(
    alertId: string,
    payload: AlertAddNotePayload,
    workspaceId: string = 'default'
  ): Promise<AlertDetail> {
    const res = await fetch(apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/notes`), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to add triage note (${res.status})`);
    }

    return (await res.json()) as AlertDetail;
  }

  /**
   * Bulk acknowledges multiple alert IDs.
   */
  static async bulkAcknowledge(
    alertIds: string[],
    analystName?: string,
    workspaceId: string = 'default'
  ): Promise<{ status: string; acknowledged_count: number; acknowledged_ids: string[] }> {
    const res = await fetch(apiUrl('/api/alerts/bulk/acknowledge'), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({
        alert_ids: alertIds,
        analyst_name: analystName,
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to bulk acknowledge alerts (${res.status})`);
    }

    return await res.json();
  }
}
