/**
 * Client service for Section 47: Notifications & Alert Center.
 * Handles listing, fast unread counts, marking as read, and acknowledging security alerts.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  NotificationItem,
  NotificationListResponse,
  NotificationUnreadCountResponse,
  NotificationFilterOptions,
  NotificationCategory,
} from '../types/notification';

export class NotificationClientService {
  /**
   * Retrieves paginated list of notifications and alerts.
   */
  static async getNotifications(
    filters?: NotificationFilterOptions,
    workspaceId: string = 'default'
  ): Promise<NotificationListResponse> {
    const params = new URLSearchParams();
    if (filters?.category) params.append('category', filters.category);
    if (filters?.status) params.append('status', filters.status);
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.investigation_id) params.append('investigation_id', filters.investigation_id);
    if (filters?.limit) params.append('limit', String(filters.limit));
    if (filters?.offset) params.append('offset', String(filters.offset));

    const url = `${apiUrl('/api/notifications')}?${params.toString()}`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch notifications (${res.status})`);
    }

    return (await res.json()) as NotificationListResponse;
  }

  /**
   * Retrieves quick unread counts for header badge and posture indicators.
   */
  static async getUnreadCount(
    workspaceId: string = 'default'
  ): Promise<NotificationUnreadCountResponse> {
    const res = await fetch(apiUrl('/api/notifications/unread-count'), {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to get unread count (${res.status})`);
    }

    return (await res.json()) as NotificationUnreadCountResponse;
  }

  /**
   * Marks a specific notification as READ.
   */
  static async markAsRead(
    notificationId: string,
    workspaceId: string = 'default'
  ): Promise<NotificationItem> {
    const res = await fetch(apiUrl(`/api/notifications/${encodeURIComponent(notificationId)}/read`), {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to mark notification as read (${res.status})`);
    }

    return (await res.json()) as NotificationItem;
  }

  /**
   * Marks all unread notifications in workspace as READ.
   */
  static async markAllAsRead(
    category?: NotificationCategory,
    workspaceId: string = 'default'
  ): Promise<{ success: boolean; count: number; message: string }> {
    const params = new URLSearchParams();
    if (category) params.append('category', category);

    const url = `${apiUrl('/api/notifications/read-all')}?${params.toString()}`;
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to mark all as read (${res.status})`);
    }

    return (await res.json()) as { success: boolean; count: number; message: string };
  }

  /**
   * Acknowledges a security alert by analyst with optional triage note.
   */
  static async acknowledgeAlert(
    notificationId: string,
    analystName?: string,
    note?: string,
    workspaceId: string = 'default'
  ): Promise<NotificationItem> {
    const res = await fetch(
      apiUrl(`/api/notifications/${encodeURIComponent(notificationId)}/acknowledge`),
      {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          'X-Workspace-ID': workspaceId,
        },
        body: JSON.stringify({
          analyst_name: analystName,
          note: note,
        }),
      }
    );

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to acknowledge alert (${res.status})`);
    }

    return (await res.json()) as NotificationItem;
  }
}
