/**
 * Section 71: Platform Administration & Governance Client Service
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  AdminUser,
  AdminTeam,
  AdminTenant,
  AdminSecurityPolicy,
  PolicyImpactPreview,
  AdminSystemSetting,
  AdminIntegration,
  AdminIntegrationTestResult,
  AdminFeatureControl,
  RoleDefinition,
  PermissionDefinition,
  PlatformOverview,
  SystemHealthData,
  AdminAuditLogItem,
  AdminRole,
  UserStatus,
} from '../types/admin';

const API_BASE = '/api/admin';

export const adminService = {
  // Overview & Health
  async getOverview(): Promise<PlatformOverview> {
    const res = await fetch(apiUrl(`${API_BASE}/overview`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch platform overview (${res.status})`);
    }
    return res.json();
  },

  async getHealth(): Promise<SystemHealthData> {
    const res = await fetch(apiUrl(`${API_BASE}/health`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to fetch system health (${res.status})`);
    }
    return res.json();
  },

  // Roles & Permissions
  async listRoles(): Promise<RoleDefinition[]> {
    const res = await fetch(apiUrl(`${API_BASE}/roles`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list roles (${res.status})`);
    }
    return res.json();
  },

  async listPermissions(): Promise<PermissionDefinition[]> {
    const res = await fetch(apiUrl(`${API_BASE}/permissions`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list permissions (${res.status})`);
    }
    return res.json();
  },

  // Users
  async listUsers(
    statusFilter?: string,
    roleFilter?: string,
    teamId?: string,
    search?: string,
    skip: number = 0,
    limit: number = 50
  ): Promise<{ items: AdminUser[]; total: number }> {
    const params = new URLSearchParams({ skip: String(skip), limit: String(limit) });
    if (statusFilter && statusFilter !== 'ALL') params.set('status_filter', statusFilter);
    if (roleFilter && roleFilter !== 'ALL') params.set('role_filter', roleFilter);
    if (teamId) params.set('team_id', teamId);
    if (search) params.set('search', search);

    const res = await fetch(apiUrl(`${API_BASE}/users?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list users (${res.status})`);
    }
    return res.json();
  },

  async createUser(data: Partial<AdminUser>): Promise<AdminUser> {
    const res = await fetch(apiUrl(`${API_BASE}/users`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create user (${res.status})`);
    }
    return res.json();
  },

  async updateUser(userId: string, data: Partial<AdminUser>): Promise<AdminUser> {
    const res = await fetch(apiUrl(`${API_BASE}/users/${encodeURIComponent(userId)}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update user (${res.status})`);
    }
    return res.json();
  },

  async changeUserRole(userId: string, newRole: AdminRole, reason: string): Promise<AdminUser> {
    const res = await fetch(apiUrl(`${API_BASE}/users/${encodeURIComponent(userId)}/role`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ new_role: newRole, reason }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to change role (${res.status})`);
    }
    return res.json();
  },

  async changeUserStatus(userId: string, newStatus: UserStatus, reason: string): Promise<AdminUser> {
    const res = await fetch(apiUrl(`${API_BASE}/users/${encodeURIComponent(userId)}/status?new_status=${encodeURIComponent(newStatus)}`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to change status (${res.status})`);
    }
    return res.json();
  },

  async revokeUserSessions(userId: string): Promise<{ user_id: string; status: string; message: string }> {
    const res = await fetch(apiUrl(`${API_BASE}/users/${encodeURIComponent(userId)}/revoke-sessions`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to revoke sessions (${res.status})`);
    }
    return res.json();
  },

  // Teams
  async listTeams(): Promise<AdminTeam[]> {
    const res = await fetch(apiUrl(`${API_BASE}/teams`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list teams (${res.status})`);
    }
    return res.json();
  },

  async createTeam(data: Partial<AdminTeam>): Promise<AdminTeam> {
    const res = await fetch(apiUrl(`${API_BASE}/teams`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create team (${res.status})`);
    }
    return res.json();
  },

  async updateTeam(teamId: string, data: Partial<AdminTeam>): Promise<AdminTeam> {
    const res = await fetch(apiUrl(`${API_BASE}/teams/${encodeURIComponent(teamId)}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update team (${res.status})`);
    }
    return res.json();
  },

  async deleteTeam(teamId: string): Promise<void> {
    const res = await fetch(apiUrl(`${API_BASE}/teams/${encodeURIComponent(teamId)}`), {
      method: 'DELETE',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to delete team (${res.status})`);
    }
  },

  // Tenants
  async listTenants(): Promise<AdminTenant[]> {
    const res = await fetch(apiUrl(`${API_BASE}/tenants`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list tenants (${res.status})`);
    }
    return res.json();
  },

  async createTenant(data: Partial<AdminTenant>): Promise<AdminTenant> {
    const res = await fetch(apiUrl(`${API_BASE}/tenants`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create tenant (${res.status})`);
    }
    return res.json();
  },

  async updateTenant(tenantId: string, data: Partial<AdminTenant>): Promise<AdminTenant> {
    const res = await fetch(apiUrl(`${API_BASE}/tenants/${encodeURIComponent(tenantId)}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update tenant (${res.status})`);
    }
    return res.json();
  },

  // System Settings
  async listSettings(category?: string): Promise<AdminSystemSetting[]> {
    const params = new URLSearchParams();
    if (category && category !== 'ALL') params.set('category', category);

    const res = await fetch(apiUrl(`${API_BASE}/settings?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list settings (${res.status})`);
    }
    return res.json();
  },

  async updateSetting(key: string, value: any, scope: string = 'GLOBAL', expectedVersion?: number): Promise<AdminSystemSetting> {
    const res = await fetch(apiUrl(`${API_BASE}/settings/${encodeURIComponent(key)}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ value, scope, expected_version: expectedVersion }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update setting '${key}' (${res.status})`);
    }
    return res.json();
  },

  // Security Policies
  async listPolicies(policyType?: string, statusFilter?: string): Promise<AdminSecurityPolicy[]> {
    const params = new URLSearchParams();
    if (policyType && policyType !== 'ALL') params.set('policy_type', policyType);
    if (statusFilter && statusFilter !== 'ALL') params.set('status_filter', statusFilter);

    const res = await fetch(apiUrl(`${API_BASE}/policies?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list security policies (${res.status})`);
    }
    return res.json();
  },

  async createPolicy(data: Partial<AdminSecurityPolicy>): Promise<AdminSecurityPolicy> {
    const res = await fetch(apiUrl(`${API_BASE}/policies`), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to create policy (${res.status})`);
    }
    return res.json();
  },

  async previewPolicyImpact(policyId: string): Promise<PolicyImpactPreview> {
    const res = await fetch(apiUrl(`${API_BASE}/policies/${encodeURIComponent(policyId)}/preview-impact`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to preview policy impact (${res.status})`);
    }
    return res.json();
  },

  async activatePolicy(policyId: string, reason: string): Promise<AdminSecurityPolicy> {
    const res = await fetch(apiUrl(`${API_BASE}/policies/${encodeURIComponent(policyId)}/activate?reason=${encodeURIComponent(reason)}`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to activate policy (${res.status})`);
    }
    return res.json();
  },

  // Integrations
  async listIntegrations(category?: string): Promise<AdminIntegration[]> {
    const params = new URLSearchParams();
    if (category && category !== 'ALL') params.set('category', category);

    const res = await fetch(apiUrl(`${API_BASE}/integrations?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list integrations (${res.status})`);
    }
    return res.json();
  },

  async updateIntegration(integrationId: string, data: { enabled?: boolean; endpoint_url?: string; api_key_replacement?: string }): Promise<AdminIntegration> {
    const res = await fetch(apiUrl(`${API_BASE}/integrations/${encodeURIComponent(integrationId)}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update integration (${res.status})`);
    }
    return res.json();
  },

  async testIntegration(integrationId: string): Promise<AdminIntegrationTestResult> {
    const res = await fetch(apiUrl(`${API_BASE}/integrations/${encodeURIComponent(integrationId)}/test`), {
      method: 'POST',
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to test integration (${res.status})`);
    }
    return res.json();
  },

  // Features
  async listFeatures(): Promise<AdminFeatureControl[]> {
    const res = await fetch(apiUrl(`${API_BASE}/features`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to list features (${res.status})`);
    }
    return res.json();
  },

  async updateFeature(featureId: string, enabled: boolean): Promise<AdminFeatureControl> {
    const res = await fetch(apiUrl(`${API_BASE}/features/${encodeURIComponent(featureId)}`), {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled }),
    });
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to update feature (${res.status})`);
    }
    return res.json();
  },

  // Audit
  async listAudit(resourceType?: string, action?: string, limit: number = 50): Promise<{ items: AdminAuditLogItem[]; total: number }> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (resourceType) params.set('resource_type', resourceType);
    if (action) params.set('action', action);

    const res = await fetch(apiUrl(`${API_BASE}/audit?${params.toString()}`));
    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(err || `Failed to query audit trail (${res.status})`);
    }
    return res.json();
  },
};
