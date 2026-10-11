import React, { useState, useEffect } from 'react';
import {
  Shield,
  Users,
  KeyRound,
  Building2,
  Sliders,
  Share2,
  Lock,
  Layers,
  FileCheck2,
  Activity,
  Search,
  Plus,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Save,
  X,
  Cpu,
} from 'lucide-react';
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
  PlatformOverview,
  SystemHealthData,
  AdminAuditLogItem,
  AdminRole,
  UserStatus,
} from '../../types/admin';
import { adminService } from '../../services/adminService';
import { cn } from '../../utils/cn';

export const PlatformAdminWorkspace: React.FC = () => {
  // Navigation sub-tab
  const [activeTab, setActiveTab] = useState<
    'overview' | 'users' | 'roles' | 'teams' | 'tenants' | 'policies' | 'integrations' | 'settings' | 'features' | 'audit'
  >('overview');

  // Overview & Health
  const [overview, setOverview] = useState<PlatformOverview | null>(null);
  const [health, setHealth] = useState<SystemHealthData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Users State
  const [users, setUsers] = useState<AdminUser[]>([]);
  const [userTotal, setUserTotal] = useState<number>(0);
  const [userSearch, setUserSearch] = useState<string>('');
  const [userRoleFilter, setUserRoleFilter] = useState<string>('ALL');
  const [userStatusFilter, setUserStatusFilter] = useState<string>('ALL');
  const [showCreateUserModal, setShowCreateUserModal] = useState<boolean>(false);
  const [newUsername, setNewUsername] = useState<string>('');
  const [newUserEmail, setNewUserEmail] = useState<string>('');
  const [newUserFullName, setNewUserFullName] = useState<string>('');
  const [newUserRole, setNewUserRole] = useState<AdminRole>('SOC_ANALYST');
  const [selectedUser, setSelectedUser] = useState<AdminUser | null>(null);
  const [showRoleModal, setShowRoleModal] = useState<boolean>(false);
  const [newRoleSelection, setNewRoleSelection] = useState<AdminRole>('SOC_ANALYST');
  const [roleChangeReason, setRoleChangeReason] = useState<string>('');
  const [showStatusModal, setShowStatusModal] = useState<boolean>(false);
  const [newStatusSelection, setNewStatusSelection] = useState<UserStatus>('DISABLED');
  const [statusChangeReason, setStatusChangeReason] = useState<string>('');

  // Roles & Permissions
  const [roles, setRoles] = useState<RoleDefinition[]>([]);

  // Teams
  const [teams, setTeams] = useState<AdminTeam[]>([]);
  const [showCreateTeamModal, setShowCreateTeamModal] = useState<boolean>(false);
  const [newTeamName, setNewTeamName] = useState<string>('');
  const [newTeamDesc, setNewTeamDesc] = useState<string>('');

  // Tenants
  const [tenants, setTenants] = useState<AdminTenant[]>([]);
  const [showCreateTenantModal, setShowCreateTenantModal] = useState<boolean>(false);
  const [newTenantId, setNewTenantId] = useState<string>('');
  const [newTenantName, setNewTenantName] = useState<string>('');

  // Policies
  const [policies, setPolicies] = useState<AdminSecurityPolicy[]>([]);
  const [selectedPolicy, setSelectedPolicy] = useState<AdminSecurityPolicy | null>(null);
  const [impactPreview, setImpactPreview] = useState<PolicyImpactPreview | null>(null);
  const [showImpactModal, setShowImpactModal] = useState<boolean>(false);
  const [showCreatePolicyModal, setShowCreatePolicyModal] = useState<boolean>(false);
  const [newPolicyName, setNewPolicyName] = useState<string>('');
  const [newPolicyType, setNewPolicyType] = useState<string>('AUTHENTICATION');
  const [newPolicyRulesJson, setNewPolicyRulesJson] = useState<string>('{"mfa_required": true, "session_timeout_minutes": 60}');

  // Integrations
  const [integrations, setIntegrations] = useState<AdminIntegration[]>([]);
  const [testingIntegId, setTestingIntegId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<AdminIntegrationTestResult | null>(null);
  const [editingInteg, setEditingInteg] = useState<AdminIntegration | null>(null);
  const [replacementKey, setReplacementKey] = useState<string>('');
  const [replacementUrl, setReplacementUrl] = useState<string>('');

  // System Settings
  const [settingsList, setSettingsList] = useState<AdminSystemSetting[]>([]);
  const [settingEditValues, setSettingEditValues] = useState<Record<string, any>>({});

  // Feature Controls
  const [features, setFeatures] = useState<AdminFeatureControl[]>([]);

  // Audit Logs
  const [auditLogs, setAuditLogs] = useState<AdminAuditLogItem[]>([]);
  const [auditTotal, setAuditTotal] = useState<number>(0);

  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  useEffect(() => {
    loadAllData();
  }, []);

  const loadAllData = async () => {
    setLoading(true);
    try {
      const [ov, hl, rl, usr, tm, tn, pol, integ, st, ft, ad] = await Promise.all([
        adminService.getOverview().catch(() => null),
        adminService.getHealth().catch(() => null),
        adminService.listRoles().catch(() => []),
        adminService.listUsers().catch(() => ({ items: [], total: 0 })),
        adminService.listTeams().catch(() => []),
        adminService.listTenants().catch(() => []),
        adminService.listPolicies().catch(() => []),
        adminService.listIntegrations().catch(() => []),
        adminService.listSettings().catch(() => []),
        adminService.listFeatures().catch(() => []),
        adminService.listAudit().catch(() => ({ items: [], total: 0 })),
      ]);

      if (ov) setOverview(ov);
      if (hl) setHealth(hl);
      setRoles(rl);
      setUsers(usr.items);
      setUserTotal(usr.total);
      setTeams(tm);
      setTenants(tn);
      setPolicies(pol);
      setIntegrations(integ);
      setSettingsList(st);
      setFeatures(ft);
      setAuditLogs(ad.items);
      setAuditTotal(ad.total);

      // Initialize setting edit dictionary
      const edits: Record<string, any> = {};
      st.forEach((s) => {
        edits[s.key] = s.value;
      });
      setSettingEditValues(edits);
    } catch (err: any) {
      console.error('Failed to load admin data:', err);
      showToast('Error loading platform administration records.');
    } finally {
      setLoading(false);
    }
  };

  // User Actions
  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await adminService.createUser({
        username: newUsername,
        email: newUserEmail,
        full_name: newUserFullName,
        role: newUserRole,
      });
      setShowCreateUserModal(false);
      setNewUsername('');
      setNewUserEmail('');
      setNewUserFullName('');
      showToast('User created successfully.');
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to create user');
    }
  };

  const handleRoleChange = async () => {
    if (!selectedUser || !roleChangeReason) return;
    try {
      await adminService.changeUserRole(selectedUser.id, newRoleSelection, roleChangeReason);
      setShowRoleModal(false);
      setSelectedUser(null);
      setRoleChangeReason('');
      showToast('User role updated successfully.');
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to update role');
    }
  };

  const handleStatusChange = async () => {
    if (!selectedUser || !statusChangeReason) return;
    try {
      await adminService.changeUserStatus(selectedUser.id, newStatusSelection, statusChangeReason);
      setShowStatusModal(false);
      setSelectedUser(null);
      setStatusChangeReason('');
      showToast(`User status transitioned to ${newStatusSelection}.`);
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to change status');
    }
  };

  const handleRevokeSessions = async (userId: string) => {
    if (!confirm('Are you sure you want to revoke all active sessions for this user?')) return;
    try {
      await adminService.revokeUserSessions(userId);
      showToast('User sessions invalidated.');
    } catch (err: any) {
      showToast(err.message || 'Failed to revoke sessions');
    }
  };

  // Team Actions
  const handleCreateTeam = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await adminService.createTeam({ name: newTeamName, description: newTeamDesc });
      setShowCreateTeamModal(false);
      setNewTeamName('');
      setNewTeamDesc('');
      showToast('Operational team created.');
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to create team');
    }
  };

  // Tenant Actions
  const handleCreateTenant = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await adminService.createTenant({ id: newTenantId, name: newTenantName });
      setShowCreateTenantModal(false);
      setNewTenantId('');
      setNewTenantName('');
      showToast('New tenant boundary provisioned.');
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to provision tenant');
    }
  };

  // Policy Creation
  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      let rules = {};
      try {
        rules = JSON.parse(newPolicyRulesJson);
      } catch {
        throw new Error('Rules must be valid JSON');
      }
      await adminService.createPolicy({
        name: newPolicyName,
        policy_type: newPolicyType as any,
        rules,
      });
      setShowCreatePolicyModal(false);
      setNewPolicyName('');
      showToast('Draft security policy created.');
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to create policy');
    }
  };

  // Policy Actions
  const handlePreviewImpact = async (pol: AdminSecurityPolicy) => {
    try {
      setSelectedPolicy(pol);
      const prev = await adminService.previewPolicyImpact(pol.id);
      setImpactPreview(prev);
      setShowImpactModal(true);
    } catch (err: any) {
      showToast(err.message || 'Failed to preview impact');
    }
  };

  const handleActivatePolicy = async (policyId: string) => {
    try {
      await adminService.activatePolicy(policyId, 'SOC Administrator direct rollout');
      setShowImpactModal(false);
      showToast('Security policy activated successfully.');
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to activate policy');
    }
  };

  // Integration Actions
  const handleTestIntegration = async (integId: string) => {
    setTestingIntegId(integId);
    try {
      const res = await adminService.testIntegration(integId);
      setTestResult(res);
      showToast(`Connection probe: ${res.health_status} (${res.latency_ms}ms)`);
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Connection test probe failed');
    } finally {
      setTestingIntegId(null);
    }
  };

  const handleSaveIntegration = async () => {
    if (!editingInteg) return;
    try {
      await adminService.updateIntegration(editingInteg.id, {
        enabled: editingInteg.enabled,
        endpoint_url: replacementUrl || undefined,
        api_key_replacement: replacementKey || undefined,
      });
      setEditingInteg(null);
      setReplacementKey('');
      setReplacementUrl('');
      showToast('Integration configuration updated.');
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to update integration');
    }
  };

  // Setting Save
  const handleSaveSetting = async (key: string, currentVer: number) => {
    try {
      const val = settingEditValues[key];
      await adminService.updateSetting(key, val, 'GLOBAL', currentVer);
      showToast(`Setting '${key}' saved.`);
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to save setting');
    }
  };

  // Feature Toggle
  const handleToggleFeature = async (feat: AdminFeatureControl) => {
    try {
      await adminService.updateFeature(feat.id, !feat.enabled);
      showToast(`Feature '${feat.display_name}' ${!feat.enabled ? 'enabled' : 'disabled'}.`);
      loadAllData();
    } catch (err: any) {
      showToast(err.message || 'Failed to toggle feature');
    }
  };

  return (
    <div className="space-y-6 pb-16">
      {/* 1. Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-surface p-6 rounded-xl border border-border shadow-xs">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <Shield className="w-3.5 h-3.5 text-primary" />
            <span>CYBERGUARD PLATFORM ADMINISTRATION & GOVERNANCE</span>
          </div>
          <h1 className="text-xl font-bold text-foreground font-sans tracking-tight">
            Governance, Access & Operations Center
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Authoritative administration: user lifecycle, RBAC matrices, multi-tenant boundaries, security policies, and verified integrations.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-xs font-mono">
            <span className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="text-foreground font-semibold">Platform v2.5-Enterprise</span>
          </div>
          <button
            type="button"
            onClick={loadAllData}
            disabled={loading}
            className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-xs font-mono text-foreground cursor-pointer transition-colors"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', loading && 'animate-spin')} />
            <span>REFRESH</span>
          </button>
        </div>
      </div>

      {toastMessage && (
        <div className="p-3.5 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-mono flex items-center space-x-2 animate-in fade-in">
          <CheckCircle2 className="w-4 h-4 text-primary flex-shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* 2. Primary Admin Navigation Tabs */}
      <div className="flex items-center gap-1.5 p-1 bg-surface-secondary/70 border border-border rounded-lg overflow-x-auto select-none">
        {[
          { id: 'overview', label: 'Overview & Health', icon: Activity },
          { id: 'users', label: 'Users & Access', icon: Users },
          { id: 'roles', label: 'Roles & RBAC', icon: KeyRound },
          { id: 'teams', label: 'Teams', icon: Building2 },
          { id: 'tenants', label: 'Tenants', icon: Layers },
          { id: 'policies', label: 'Security Policies', icon: FileCheck2 },
          { id: 'integrations', label: 'Integrations', icon: Share2 },
          { id: 'settings', label: 'System Settings', icon: Sliders },
          { id: 'features', label: 'Feature Controls', icon: Cpu },
          { id: 'audit', label: 'Governance Audit', icon: Lock },
        ].map((t) => {
          const Icon = t.icon;
          const isCurrent = activeTab === t.id;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id as any)}
              className={cn(
                'flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-mono font-medium transition-all cursor-pointer whitespace-nowrap',
                isCurrent
                  ? 'bg-surface text-primary shadow-xs font-semibold border border-border'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface/50'
              )}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{t.label}</span>
            </button>
          );
        })}
      </div>

      {/* 3. TAB CONTENT */}

      {/* OVERVIEW & HEALTH */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* KPI Ribbon */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-surface border border-border">
              <span className="text-[11px] font-mono text-foreground-muted uppercase">Active Tenants</span>
              <div className="text-2xl font-bold font-mono text-foreground mt-1">
                {overview?.active_tenants_count ?? 1}
              </div>
              <span className="text-[10px] font-mono text-foreground-muted">Strict isolated boundaries</span>
            </div>

            <div className="p-4 rounded-xl bg-surface border border-border">
              <span className="text-[11px] font-mono text-foreground-muted uppercase">Total Users</span>
              <div className="text-2xl font-bold font-mono text-foreground mt-1">
                {overview?.total_users_count ?? users.length}
              </div>
              <span className="text-[10px] font-mono text-success">
                {overview?.active_users_count ?? users.filter((u) => u.status === 'ACTIVE').length} Active
              </span>
            </div>

            <div className="p-4 rounded-xl bg-surface border border-border">
              <span className="text-[11px] font-mono text-foreground-muted uppercase">Active Security Policies</span>
              <div className="text-2xl font-bold font-mono text-primary mt-1">
                {overview?.active_policies_count ?? policies.filter((p) => p.status === 'ACTIVE').length}
              </div>
              <span className="text-[10px] font-mono text-foreground-muted">Versioned rule enforcement</span>
            </div>

            <div className="p-4 rounded-xl bg-surface border border-border">
              <span className="text-[11px] font-mono text-foreground-muted uppercase">Audit Events (24h)</span>
              <div className="text-2xl font-bold font-mono text-foreground mt-1">
                {overview?.pending_audit_events_24h ?? auditTotal}
              </div>
              <span className="text-[10px] font-mono text-foreground-muted">Append-only forensic ledger</span>
            </div>
          </div>

          {/* Component Diagnostics */}
          <div className="bg-surface rounded-xl border border-border p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-primary" />
                <h2 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
                  Authoritative Subsystem Diagnostics
                </h2>
              </div>
              <span
                className={cn(
                  'px-2.5 py-0.5 rounded-full text-[10px] font-mono font-semibold uppercase',
                  health?.overall_status === 'HEALTHY'
                    ? 'bg-success/15 text-success border border-success/30'
                    : 'bg-warning/15 text-warning border border-warning/30'
                )}
              >
                {health?.overall_status ?? 'HEALTHY'}
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {health?.components.map((comp, idx) => (
                <div key={idx} className="p-3.5 rounded-lg bg-surface-secondary/50 border border-border flex items-start justify-between">
                  <div>
                    <div className="text-xs font-bold font-mono text-foreground">{comp.name}</div>
                    {comp.details && <div className="text-[11px] font-mono text-foreground-muted mt-0.5">{comp.details}</div>}
                  </div>
                  <div className="flex items-center space-x-1.5 shrink-0">
                    {comp.status === 'HEALTHY' ? (
                      <CheckCircle2 className="w-4 h-4 text-success" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-warning" />
                    )}
                    <span className="text-[10px] font-mono font-bold">{comp.status}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* USERS & ACCESS */}
      {activeTab === 'users' && (
        <div className="space-y-4">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div className="flex items-center space-x-2 flex-1 max-w-md">
              <div className="relative w-full">
                <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
                <input
                  type="text"
                  placeholder="Search user, email, or full name..."
                  value={userSearch}
                  onChange={(e) => setUserSearch(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-surface border border-border text-xs font-mono text-foreground focus:outline-hidden focus:border-primary"
                />
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-[11px] font-mono text-foreground-muted hidden md:inline">
                Total: {userTotal}
              </span>
              <select
                value={userRoleFilter}
                onChange={(e) => setUserRoleFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface border border-border text-xs font-mono text-foreground"
              >
                <option value="ALL">All Roles</option>
                <option value="PLATFORM_ADMIN">Platform Admin</option>
                <option value="TENANT_ADMIN">Tenant Admin</option>
                <option value="SECURITY_ADMIN">Security Admin</option>
                <option value="SOC_ANALYST">SOC Analyst</option>
                <option value="READ_ONLY_AUDITOR">Auditor</option>
              </select>

              <select
                value={userStatusFilter}
                onChange={(e) => setUserStatusFilter(e.target.value)}
                className="px-2.5 py-1.5 rounded-lg bg-surface border border-border text-xs font-mono text-foreground"
              >
                <option value="ALL">All Statuses</option>
                <option value="ACTIVE">Active</option>
                <option value="DISABLED">Disabled</option>
                <option value="LOCKED">Locked</option>
              </select>

              <button
                type="button"
                onClick={() => setShowCreateUserModal(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold cursor-pointer transition-colors"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>NEW USER</span>
              </button>
            </div>
          </div>

          <div className="bg-surface rounded-xl border border-border overflow-hidden">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-surface-secondary/60 text-[11px] font-mono text-foreground-muted uppercase">
                  <th className="p-3">User</th>
                  <th className="p-3">Role</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Tenant</th>
                  <th className="p-3">Created</th>
                  <th className="p-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-xs font-mono">
                {users.map((u) => (
                  <tr key={u.id} className="hover:bg-surface-secondary/30 transition-colors">
                    <td className="p-3">
                      <div className="font-bold text-foreground">{u.full_name}</div>
                      <div className="text-[11px] text-foreground-muted">{u.email} ({u.username})</div>
                    </td>
                    <td className="p-3">
                      <span className={cn(
                        'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                        u.role === 'PLATFORM_ADMIN' ? 'bg-error/15 text-error border border-error/30' :
                        u.role === 'SECURITY_ADMIN' ? 'bg-primary/15 text-primary border border-primary/30' :
                        'bg-surface-secondary text-foreground'
                      )}>
                        {u.role}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className={cn(
                        'px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                        u.status === 'ACTIVE' ? 'bg-success/15 text-success' : 'bg-foreground-muted/15 text-foreground-muted'
                      )}>
                        {u.status}
                      </span>
                    </td>
                    <td className="p-3 text-foreground-muted">{u.tenant_id}</td>
                    <td className="p-3 text-foreground-muted">{new Date(u.created_at).toLocaleDateString()}</td>
                    <td className="p-3 text-right space-x-1.5">
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedUser(u);
                          setNewRoleSelection(u.role);
                          setShowRoleModal(true);
                        }}
                        className="px-2 py-1 rounded bg-surface-secondary hover:bg-surface border border-border text-[10px] text-foreground cursor-pointer"
                      >
                        ROLE
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setSelectedUser(u);
                          setNewStatusSelection(u.status === 'ACTIVE' ? 'DISABLED' : 'ACTIVE');
                          setShowStatusModal(true);
                        }}
                        className="px-2 py-1 rounded bg-surface-secondary hover:bg-surface border border-border text-[10px] text-foreground cursor-pointer"
                      >
                        STATUS
                      </button>
                      <button
                        type="button"
                        onClick={() => handleRevokeSessions(u.id)}
                        className="px-2 py-1 rounded bg-error/10 hover:bg-error/20 text-error border border-error/20 text-[10px] cursor-pointer"
                        title="Revoke active sessions"
                      >
                        REVOKE
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ROLES & RBAC MATRIX */}
      {activeTab === 'roles' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {roles.map((r) => (
              <div key={r.role} className="p-5 rounded-xl bg-surface border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <KeyRound className="w-4 h-4 text-primary" />
                    <h3 className="text-sm font-bold font-mono text-foreground">{r.display_name}</h3>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-secondary border border-border text-foreground-muted">
                    {r.assigned_users_count} Users
                  </span>
                </div>
                <p className="text-xs text-foreground-muted font-mono">{r.description}</p>
                <div className="pt-2 border-t border-border">
                  <span className="text-[10px] font-mono text-foreground-muted uppercase tracking-wider block mb-1.5">
                    Assigned Permissions ({r.permissions.length}):
                  </span>
                  <div className="flex flex-wrap gap-1">
                    {r.permissions.map((p) => (
                      <span key={p} className="px-1.5 py-0.5 rounded bg-surface-secondary text-[10px] font-mono text-foreground">
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TEAMS */}
      {activeTab === 'teams' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
              Operational SOC Units & Functional Groups
            </h2>
            <button
              type="button"
              onClick={() => setShowCreateTeamModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>NEW TEAM</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {teams.map((t) => (
              <div key={t.id} className="p-4 rounded-xl bg-surface border border-border space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-bold font-mono text-foreground">{t.name}</h3>
                  <span className="text-[10px] font-mono text-foreground-muted">{t.members_count} Members</span>
                </div>
                <p className="text-xs text-foreground-muted font-mono">{t.description || 'No description provided.'}</p>
                {t.team_lead_name && (
                  <div className="text-[11px] font-mono text-primary pt-1">Lead: {t.team_lead_name}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TENANTS */}
      {activeTab === 'tenants' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
              Multi-Tenant Governance Boundaries
            </h2>
            <button
              type="button"
              onClick={() => setShowCreateTenantModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>PROVISION TENANT</span>
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {tenants.map((tn) => (
              <div key={tn.id} className="p-5 rounded-xl bg-surface border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <Building2 className="w-4 h-4 text-primary" />
                    <h3 className="text-sm font-bold font-mono text-foreground">{tn.name}</h3>
                  </div>
                  <span className={cn(
                    'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase',
                    tn.status === 'ACTIVE' ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'
                  )}>
                    {tn.status}
                  </span>
                </div>
                <div className="grid grid-cols-3 gap-2 text-xs font-mono text-foreground-muted">
                  <div>
                    <span className="text-[10px] block">Slug:</span>
                    <span className="text-foreground">{tn.id}</span>
                  </div>
                  <div>
                    <span className="text-[10px] block">Plan:</span>
                    <span className="text-foreground">{tn.plan_tier}</span>
                  </div>
                  <div>
                    <span className="text-[10px] block">Retention:</span>
                    <span className="text-foreground">{tn.retention_days} Days</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SECURITY POLICIES */}
      {activeTab === 'policies' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
              Governance Policies & Lifecycles
            </h2>
            <button
              type="button"
              onClick={() => setShowCreatePolicyModal(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold cursor-pointer"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>NEW DRAFT POLICY</span>
            </button>
          </div>

          <div className="space-y-3">
            {policies.map((pol) => (
              <div key={pol.id} className="p-4 rounded-xl bg-surface border border-border flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs font-bold font-mono text-foreground">{pol.name}</span>
                    <span className={cn(
                      'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase',
                      pol.status === 'ACTIVE' ? 'bg-success/15 text-success border border-success/30' : 'bg-foreground-muted/15 text-foreground-muted'
                    )}>
                      {pol.status} v{pol.version}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-surface-secondary text-[10px] font-mono text-foreground-muted">
                      {pol.policy_type}
                    </span>
                  </div>
                  <p className="text-xs font-mono text-foreground-muted">{pol.description || 'Configured security policy.'}</p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    type="button"
                    onClick={() => handlePreviewImpact(pol)}
                    className="px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-xs font-mono text-foreground cursor-pointer flex items-center space-x-1.5"
                  >
                    <Sparkles className="w-3.5 h-3.5 text-primary" />
                    <span>PREVIEW IMPACT</span>
                  </button>
                  {pol.status !== 'ACTIVE' && (
                    <button
                      type="button"
                      onClick={() => handleActivatePolicy(pol.id)}
                      className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold cursor-pointer"
                    >
                      ACTIVATE
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* INTEGRATIONS */}
      {activeTab === 'integrations' && (
        <div className="space-y-4">
          {testResult && (
            <div className="p-3 rounded-lg bg-surface-secondary border border-border text-xs font-mono flex items-center justify-between animate-in fade-in">
              <div className="flex items-center space-x-2">
                <Activity className="w-4 h-4 text-primary" />
                <span>Probe: {testResult.provider_name} &bull; {testResult.message} ({testResult.latency_ms}ms)</span>
              </div>
              <button type="button" onClick={() => setTestResult(null)} className="text-foreground-muted hover:text-foreground">
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          )}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {integrations.map((integ) => (
              <div key={integ.id} className="p-5 rounded-xl bg-surface border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-xs font-bold font-mono text-foreground">{integ.display_name}</h3>
                    <span className="text-[10px] font-mono text-foreground-muted uppercase">{integ.category}</span>
                  </div>
                  <span className={cn(
                    'px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase',
                    integ.health_status === 'HEALTHY' ? 'bg-success/15 text-success' :
                    integ.health_status === 'DEGRADED' ? 'bg-warning/15 text-warning' : 'bg-foreground-muted/15 text-foreground-muted'
                  )}>
                    {integ.health_status}
                  </span>
                </div>

                <div className="flex items-center justify-between text-xs font-mono text-foreground-muted pt-2 border-t border-border">
                  <div className="flex items-center space-x-1.5">
                    <Lock className="w-3.5 h-3.5 text-primary" />
                    <span>Secret: {integ.credential_configured ? 'Configured (Redacted)' : 'Unset'}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      type="button"
                      onClick={() => {
                        setEditingInteg(integ);
                        setReplacementUrl(integ.endpoint_url || '');
                      }}
                      className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface border border-border text-[11px] text-foreground cursor-pointer"
                    >
                      CONFIGURE
                    </button>
                    <button
                      type="button"
                      disabled={testingIntegId === integ.id}
                      onClick={() => handleTestIntegration(integ.id)}
                      className="px-2.5 py-1 rounded bg-primary/10 hover:bg-primary/20 text-primary border border-primary/20 text-[11px] cursor-pointer flex items-center space-x-1"
                    >
                      <Activity className={cn('w-3 h-3', testingIntegId === integ.id && 'animate-spin')} />
                      <span>PROBE</span>
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SYSTEM SETTINGS */}
      {activeTab === 'settings' && (
        <div className="space-y-4">
          <div className="bg-surface rounded-xl border border-border overflow-hidden">
            <div className="p-4 border-b border-border bg-surface-secondary/40 flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-foreground uppercase tracking-wider">
                System Parameters with Deterministic Precedence
              </span>
              <span className="text-[11px] font-mono text-foreground-muted">Optimistic Concurrency v2</span>
            </div>
            <div className="divide-y divide-border">
              {settingsList.map((st) => (
                <div key={st.key} className="p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 hover:bg-surface-secondary/20">
                  <div className="space-y-0.5 max-w-lg">
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-bold font-mono text-foreground">{st.key}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-surface-secondary text-foreground-muted uppercase">
                        {st.category}
                      </span>
                      <span className="text-[10px] font-mono text-foreground-muted">v{st.version}</span>
                    </div>
                    <p className="text-[11px] font-mono text-foreground-muted">{st.description}</p>
                  </div>

                  <div className="flex items-center space-x-3">
                    {typeof st.default_value === 'boolean' ? (
                      <input
                        type="checkbox"
                        checked={Boolean(settingEditValues[st.key])}
                        onChange={(e) =>
                          setSettingEditValues((prev) => ({ ...prev, [st.key]: e.target.checked }))
                        }
                        className="rounded border-border text-primary focus:ring-0 cursor-pointer"
                      />
                    ) : (
                      <input
                        type="text"
                        value={String(settingEditValues[st.key] ?? '')}
                        onChange={(e) =>
                          setSettingEditValues((prev) => ({ ...prev, [st.key]: e.target.value }))
                        }
                        className="px-2.5 py-1 rounded bg-surface border border-border text-xs font-mono text-foreground w-40"
                      />
                    )}
                    <button
                      type="button"
                      onClick={() => handleSaveSetting(st.key, st.version)}
                      className="flex items-center space-x-1 px-3 py-1 rounded bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold cursor-pointer"
                    >
                      <Save className="w-3 h-3" />
                      <span>SAVE</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* FEATURE CONTROLS */}
      {activeTab === 'features' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {features.map((feat) => (
              <div key={feat.id} className="p-5 rounded-xl bg-surface border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <h3 className="text-xs font-bold font-mono text-foreground">{feat.display_name}</h3>
                    <span className="text-[10px] font-mono text-foreground-muted">Requires: {feat.requires_role}</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleToggleFeature(feat)}
                    className={cn(
                      'px-3 py-1 rounded-full text-xs font-mono font-bold transition-colors cursor-pointer',
                      feat.enabled ? 'bg-success/15 text-success border border-success/30' : 'bg-foreground-muted/15 text-foreground-muted border border-border'
                    )}
                  >
                    {feat.enabled ? 'ENABLED' : 'DISABLED'}
                  </button>
                </div>
                <p className="text-xs font-mono text-foreground-muted">{feat.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AUDIT LOG */}
      {activeTab === 'audit' && (
        <div className="space-y-4">
          <div className="bg-surface rounded-xl border border-border overflow-hidden">
            <div className="p-4 border-b border-border bg-surface-secondary/40 flex items-center justify-between">
              <span className="text-xs font-bold font-mono text-foreground uppercase tracking-wider">
                Forensic Administrative Ledger ({auditTotal} events recorded)
              </span>
              <span className="text-[11px] font-mono text-success">Append-only Immutable Trail</span>
            </div>
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-border bg-surface-secondary/20 text-[11px] font-mono text-foreground-muted uppercase">
                  <th className="p-3">Timestamp</th>
                  <th className="p-3">Actor</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Target</th>
                  <th className="p-3">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border text-xs font-mono">
                {auditLogs.map((log) => (
                  <tr key={log.id} className="hover:bg-surface-secondary/20 transition-colors">
                    <td className="p-3 text-foreground-muted">{new Date(log.timestamp).toLocaleString()}</td>
                    <td className="p-3 font-semibold text-foreground">{log.user}</td>
                    <td className="p-3">
                      <span className="px-1.5 py-0.5 rounded bg-surface-secondary text-[10px] font-bold text-primary">
                        {log.action}
                      </span>
                    </td>
                    <td className="p-3 text-foreground-muted">{log.resource_type}: {log.resource_id}</td>
                    <td className="p-3 text-foreground-muted max-w-xs truncate">{log.details || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 4. MODALS */}

      {/* Impact Preview Modal */}
      {showImpactModal && impactPreview && selectedPolicy && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <div className="flex items-center space-x-2 text-primary font-mono text-xs font-bold uppercase">
                <Sparkles className="w-4 h-4 text-primary" />
                <span>Truthful Policy Impact Preview</span>
              </div>
              <button type="button" onClick={() => setShowImpactModal(false)} className="text-foreground-muted hover:text-foreground">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div>
                <span className="text-foreground-muted block text-[10px] uppercase">Policy:</span>
                <span className="font-bold text-foreground">{impactPreview.policy_name} ({impactPreview.policy_type})</span>
              </div>
              <div>
                <span className="text-foreground-muted block text-[10px] uppercase">Summary:</span>
                <p className="text-foreground bg-surface-secondary p-2.5 rounded-lg border border-border">{impactPreview.summary}</p>
              </div>
              {impactPreview.warnings.length > 0 && (
                <div>
                  <span className="text-warning block text-[10px] uppercase font-bold mb-1">Operational Warnings:</span>
                  <ul className="list-disc list-inside space-y-1 text-warning/90 bg-warning/10 p-2.5 rounded-lg border border-warning/20">
                    {impactPreview.warnings.map((w, idx) => (
                      <li key={idx}>{w}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setShowImpactModal(false)}
                className="px-3 py-1.5 rounded-lg bg-surface-secondary text-xs font-mono text-foreground cursor-pointer"
              >
                CLOSE
              </button>
              <button
                type="button"
                onClick={() => handleActivatePolicy(selectedPolicy.id)}
                className="px-4 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-bold cursor-pointer"
              >
                CONFIRM & ACTIVATE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Role Change Modal */}
      {showRoleModal && selectedUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
              Change Role for {selectedUser.username}
            </h3>
            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-foreground-muted block mb-1">Select Authorized Role:</label>
                <select
                  value={newRoleSelection}
                  onChange={(e) => setNewRoleSelection(e.target.value as AdminRole)}
                  className="w-full px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground"
                >
                  <option value="PLATFORM_ADMIN">Platform Admin</option>
                  <option value="TENANT_ADMIN">Tenant Admin</option>
                  <option value="SECURITY_ADMIN">Security Admin</option>
                  <option value="SOC_ANALYST">SOC Analyst</option>
                  <option value="READ_ONLY_AUDITOR">Auditor</option>
                </select>
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Audited Justification (Mandatory):</label>
                <input
                  type="text"
                  placeholder="e.g. Promotion to Tier-2 SOC Lead"
                  value={roleChangeReason}
                  onChange={(e) => setRoleChangeReason(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground"
                />
              </div>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setShowRoleModal(false)}
                className="px-3 py-1.5 rounded-lg bg-surface-secondary text-xs font-mono"
              >
                CANCEL
              </button>
              <button
                type="button"
                disabled={!roleChangeReason}
                onClick={handleRoleChange}
                className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-bold"
              >
                APPLY ROLE
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Status Change Modal */}
      {showStatusModal && selectedUser && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
              Transition Status: {selectedUser.username}
            </h3>
            <div className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-foreground-muted block mb-1">Target Status:</label>
                <select
                  value={newStatusSelection}
                  onChange={(e) => setNewStatusSelection(e.target.value as UserStatus)}
                  className="w-full px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground"
                >
                  <option value="ACTIVE">ACTIVE</option>
                  <option value="DISABLED">DISABLED</option>
                  <option value="LOCKED">LOCKED</option>
                </select>
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Reason for Status Transition:</label>
                <input
                  type="text"
                  placeholder="e.g. Inactive employment status"
                  value={statusChangeReason}
                  onChange={(e) => setStatusChangeReason(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-foreground"
                />
              </div>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setShowStatusModal(false)}
                className="px-3 py-1.5 rounded-lg bg-surface-secondary text-xs font-mono"
              >
                CANCEL
              </button>
              <button
                type="button"
                disabled={!statusChangeReason}
                onClick={handleStatusChange}
                className="px-3 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-bold"
              >
                CONFIRM
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create User Modal */}
      {showCreateUserModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold font-mono text-foreground uppercase">Create User Account</h3>
              <button type="button" onClick={() => setShowCreateUserModal(false)}>
                <X className="w-4 h-4 text-foreground-muted" />
              </button>
            </div>
            <form onSubmit={handleCreateUser} className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-foreground-muted block mb-1">Username</label>
                <input
                  type="text"
                  required
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Email</label>
                <input
                  type="email"
                  required
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Full Name</label>
                <input
                  type="text"
                  required
                  value={newUserFullName}
                  onChange={(e) => setNewUserFullName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Role</label>
                <select
                  value={newUserRole}
                  onChange={(e) => setNewUserRole(e.target.value as AdminRole)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                >
                  <option value="SOC_ANALYST">SOC Analyst</option>
                  <option value="SECURITY_ADMIN">Security Admin</option>
                  <option value="TENANT_ADMIN">Tenant Admin</option>
                  <option value="PLATFORM_ADMIN">Platform Admin</option>
                  <option value="READ_ONLY_AUDITOR">Auditor</option>
                </select>
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreateUserModal(false)}
                  className="px-3 py-1.5 rounded bg-surface-secondary text-foreground"
                >
                  CANCEL
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 rounded bg-primary text-primary-foreground font-bold"
                >
                  CREATE USER
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Integration Edit Modal */}
      {editingInteg && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-sm font-bold font-mono text-foreground uppercase">
              Configure {editingInteg.display_name}
            </h3>
            <div className="space-y-3 text-xs font-mono">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="integ-enabled"
                  checked={editingInteg.enabled}
                  onChange={(e) => setEditingInteg({ ...editingInteg, enabled: e.target.checked })}
                  className="rounded border-border text-primary cursor-pointer"
                />
                <label htmlFor="integ-enabled" className="text-foreground font-bold">Enabled</label>
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Endpoint URL (SSRF Protected):</label>
                <input
                  type="text"
                  placeholder="https://api.provider.com/v1"
                  value={replacementUrl}
                  onChange={(e) => setReplacementUrl(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Write-Only Secret / API Key Replacement:</label>
                <input
                  type="password"
                  placeholder="Enter replacement key to update..."
                  value={replacementKey}
                  onChange={(e) => setReplacementKey(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
                <span className="text-[10px] text-foreground-muted block mt-1">Existing secrets are never displayed.</span>
              </div>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setEditingInteg(null)}
                className="px-3 py-1.5 rounded bg-surface-secondary text-foreground text-xs font-mono"
              >
                CANCEL
              </button>
              <button
                type="button"
                onClick={handleSaveIntegration}
                className="px-3 py-1.5 rounded bg-primary text-primary-foreground font-bold text-xs font-mono"
              >
                SAVE CONFIGURATION
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Team Modal */}
      {showCreateTeamModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold font-mono text-foreground uppercase">Create Operational Team</h3>
              <button type="button" onClick={() => setShowCreateTeamModal(false)}>
                <X className="w-4 h-4 text-foreground-muted" />
              </button>
            </div>
            <form onSubmit={handleCreateTeam} className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-foreground-muted block mb-1">Team Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Incident Response Red Team"
                  value={newTeamName}
                  onChange={(e) => setNewTeamName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Description</label>
                <textarea
                  placeholder="Team mandate and scope..."
                  value={newTeamDesc}
                  onChange={(e) => setNewTeamDesc(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground h-20"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button type="button" onClick={() => setShowCreateTeamModal(false)} className="px-3 py-1.5 rounded bg-surface-secondary text-foreground">
                  CANCEL
                </button>
                <button type="submit" className="px-3 py-1.5 rounded bg-primary text-primary-foreground font-bold">
                  CREATE TEAM
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Tenant Modal */}
      {showCreateTenantModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold font-mono text-foreground uppercase">Provision Tenant Boundary</h3>
              <button type="button" onClick={() => setShowCreateTenantModal(false)}>
                <X className="w-4 h-4 text-foreground-muted" />
              </button>
            </div>
            <form onSubmit={handleCreateTenant} className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-foreground-muted block mb-1">Tenant Slug / ID</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. acme-defense"
                  value={newTenantId}
                  onChange={(e) => setNewTenantId(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Organization Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Acme Corporation Security"
                  value={newTenantName}
                  onChange={(e) => setNewTenantName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button type="button" onClick={() => setShowCreateTenantModal(false)} className="px-3 py-1.5 rounded bg-surface-secondary text-foreground">
                  CANCEL
                </button>
                <button type="submit" className="px-3 py-1.5 rounded bg-primary text-primary-foreground font-bold">
                  PROVISION
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Policy Modal */}
      {showCreatePolicyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4 animate-in fade-in">
          <div className="bg-surface border border-border rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold font-mono text-foreground uppercase">Create Draft Security Policy</h3>
              <button type="button" onClick={() => setShowCreatePolicyModal(false)}>
                <X className="w-4 h-4 text-foreground-muted" />
              </button>
            </div>
            <form onSubmit={handleCreatePolicy} className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-foreground-muted block mb-1">Policy Title</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Identity Zero Trust Session Limits"
                  value={newPolicyName}
                  onChange={(e) => setNewPolicyName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Policy Category</label>
                <select
                  value={newPolicyType}
                  onChange={(e) => setNewPolicyType(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground"
                >
                  <option value="AUTHENTICATION">Authentication</option>
                  <option value="SESSION_MANAGEMENT">Session Management</option>
                  <option value="DATA_RETENTION">Data Retention</option>
                  <option value="ROLE_DELEGATION">Role Delegation</option>
                  <option value="EXTERNAL_SHARING">External Sharing</option>
                  <option value="API_ACCESS">API Access</option>
                </select>
              </div>
              <div>
                <label className="text-foreground-muted block mb-1">Rules Config (JSON)</label>
                <textarea
                  value={newPolicyRulesJson}
                  onChange={(e) => setNewPolicyRulesJson(e.target.value)}
                  className="w-full px-3 py-1.5 rounded bg-surface-secondary border border-border text-foreground h-24 font-mono text-[11px]"
                />
              </div>
              <div className="flex justify-end space-x-2 pt-2">
                <button type="button" onClick={() => setShowCreatePolicyModal(false)} className="px-3 py-1.5 rounded bg-surface-secondary text-foreground">
                  CANCEL
                </button>
                <button type="submit" className="px-3 py-1.5 rounded bg-primary text-primary-foreground font-bold">
                  CREATE DRAFT
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default PlatformAdminWorkspace;
