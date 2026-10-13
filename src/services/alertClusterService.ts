import { apiFetch } from '../utils/apiClient';
/**
 * Section 49: Alert Correlation & Incident Clustering Client Service.
 * Provides typed methods for cluster listing, forensic detail, alert-to-cluster association,
 * lifecycle state mutation, cluster merging, and investigation handoff.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  AlertClusterDetail,
  AlertClusterItem,
  AlertClusterListParams,
  AlertClusterListResponse,
  ClusterStatus,
} from '../types/alertCluster';

export class AlertClusterService {
  /**
   * Retrieves filtered and paginated alert clusters.
   */
  static async listClusters(
    params?: AlertClusterListParams,
    workspaceId: string = 'default'
  ): Promise<AlertClusterListResponse> {
    const qp = new URLSearchParams();
    if (params?.status) qp.append('status', params.status);
    if (params?.severity) qp.append('severity', params.severity);
    if (params?.investigation_id) qp.append('investigation_id', params.investigation_id);
    if (params?.campaign_id) qp.append('campaign_id', params.campaign_id);
    if (params?.q) qp.append('q', params.q);
    if (params?.limit) qp.append('limit', String(params.limit));
    if (params?.offset) qp.append('offset', String(params.offset));
    if (params?.sort_by) qp.append('sort_by', params.sort_by);

    const url = `${apiUrl('/api/alerts/clusters')}?${qp.toString()}`;
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to list alert clusters: ${err}`);
    }

    return res.json();
  }

  /**
   * Retrieves full forensic detail for a specific alert cluster.
   */
  static async getClusterDetail(
    clusterId: string,
    workspaceId: string = 'default'
  ): Promise<AlertClusterDetail> {
    const url = apiUrl(`/api/alerts/clusters/${encodeURIComponent(clusterId)}`);
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to load alert cluster '${clusterId}': ${err}`);
    }

    return res.json();
  }

  /**
   * Retrieves the Alert Cluster associated with a specific alert, or null if unclustered.
   */
  static async getAlertCluster(
    alertId: string,
    workspaceId: string = 'default'
  ): Promise<AlertClusterDetail | null> {
    const url = apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/cluster`);
    const res = await apiFetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      if (res.status === 404) return null;
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to check cluster association for alert '${alertId}': ${err}`);
    }

    return res.json();
  }

  /**
   * Updates cluster lifecycle status.
   */
  static async updateClusterStatus(
    clusterId: string,
    status: ClusterStatus,
    reason?: string,
    analystName?: string,
    workspaceId: string = 'default'
  ): Promise<AlertClusterItem> {
    const url = apiUrl(`/api/alerts/clusters/${encodeURIComponent(clusterId)}/status`);
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({
        status,
        reason: reason || 'Analyst status change',
        analyst_name: analystName || 'SOC Analyst',
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to update cluster status: ${err}`);
    }

    return res.json();
  }

  /**
   * Links a cluster to an existing or newly created investigation workspace.
   */
  static async linkInvestigation(
    clusterId: string,
    payload: {
      investigation_id?: string;
      create_if_missing?: boolean;
      investigation_title?: string;
      analyst_name?: string;
    },
    workspaceId: string = 'default'
  ): Promise<AlertClusterItem> {
    const url = apiUrl(`/api/alerts/clusters/${encodeURIComponent(clusterId)}/investigate`);
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({
        investigation_id: payload.investigation_id,
        create_if_missing: payload.create_if_missing ?? true,
        investigation_title: payload.investigation_title,
        analyst_name: payload.analyst_name || 'SOC Analyst',
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to link cluster to investigation: ${err}`);
    }

    return res.json();
  }

  /**
   * Merges the current cluster into a target cluster.
   */
  static async mergeClusters(
    clusterId: string,
    targetClusterId: string,
    reason?: string,
    analystName?: string,
    workspaceId: string = 'default'
  ): Promise<AlertClusterItem> {
    const url = apiUrl(`/api/alerts/clusters/${encodeURIComponent(clusterId)}/merge`);
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({
        target_cluster_id: targetClusterId,
        reason: reason || 'Analyst incident consolidation',
        analyst_name: analystName || 'SOC Analyst',
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to merge clusters: ${err}`);
    }

    return res.json();
  }

  /**
   * Triggers correlation for an alert (synchronously or queued as a Background Job).
   */
  static async triggerAlertCorrelation(
    alertId: string,
    asyncJob: boolean = false,
    analystName?: string,
    workspaceId: string = 'default'
  ): Promise<{ status: string; cluster_id?: string; cluster_title?: string; clustered?: boolean }> {
    const url = apiUrl(`/api/alerts/${encodeURIComponent(alertId)}/correlate`);
    const res = await apiFetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify({
        async_job: asyncJob,
        analyst_name: analystName || 'SOC Analyst',
      }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to run alert correlation: ${err}`);
    }

    return res.json();
  }
}
