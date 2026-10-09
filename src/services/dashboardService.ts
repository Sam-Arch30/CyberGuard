/**
 * Dashboard & Operational Telemetry Service.
 * Consumes real backend operational data:
 * - /api/dashboard/summary: Aggregated metrics & recent emails/cases
 * - /api/dashboard/emails: Paginated email analyses
 * - /api/health: Actual platform and database health
 * - /api/v1/endpoint/agents: Enrolled endpoint fleet agents
 */

import { apiUrl } from '../utils/apiClient';
import type { DashboardSummary, DashboardEmailItem } from '../types/dashboard';

export interface SystemHealthStatus {
  status: 'ok' | 'degraded' | 'unavailable' | 'unknown';
  service: string;
  database: string;
}

export interface EnrolledAgentSummary {
  agent_id: string;
  hostname: string;
  platform: string;
  status: string;
  last_heartbeat_at?: string;
  agent_version: string;
}

export class DashboardService {
  /**
   * Retrieves aggregated operational summary from real DB records.
   */
  static async getSummary(days: number = 30, recentLimit: number = 10): Promise<DashboardSummary | null> {
    try {
      const res = await fetch(apiUrl(`/api/dashboard/summary?days=${days}&recent_limit=${recentLimit}`));
      if (!res.ok) {
        return null;
      }
      return (await res.json()) as DashboardSummary;
    } catch {
      return null;
    }
  }

  /**
   * Retrieves paginated list of analyzed emails from real DB records.
   */
  static async listEmails(skip: number = 0, limit: number = 20): Promise<{ items: DashboardEmailItem[]; total: number }> {
    try {
      const res = await fetch(apiUrl(`/api/dashboard/emails?skip=${skip}&limit=${limit}`));
      if (!res.ok) {
        return { items: [], total: 0 };
      }
      const data = await res.json();
      return {
        items: data.items || [],
        total: data.total || 0,
      };
    } catch {
      return { items: [], total: 0 };
    }
  }

  /**
   * Checks authentic service & database health.
   */
  static async getHealth(): Promise<SystemHealthStatus> {
    try {
      const res = await fetch(apiUrl('/api/health'));
      if (!res.ok) {
        return {
          status: 'degraded',
          service: 'CyberGuard Core Engine',
          database: `HTTP ${res.status}`,
        };
      }
      const data = await res.json();
      return {
        status: data.status === 'ok' ? 'ok' : 'degraded',
        service: data.service || 'CyberGuard Core Engine',
        database: data.database || 'ok',
      };
    } catch {
      return {
        status: 'unavailable',
        service: 'CyberGuard Core Engine',
        database: 'Unreachable',
      };
    }
  }

  /**
   * Lists authentic enrolled endpoint agents from the fleet administration endpoint.
   */
  static async getEnrolledAgents(): Promise<EnrolledAgentSummary[]> {
    try {
      const res = await fetch(apiUrl('/api/v1/endpoint/agents'));
      if (!res.ok) {
        return [];
      }
      return (await res.json()) as EnrolledAgentSummary[];
    } catch {
      return [];
    }
  }
}
