/**
 * Section 71: Platform Administration & Governance TypeScript Types
 */

export type AdminRole = 'PLATFORM_ADMIN' | 'TENANT_ADMIN' | 'SECURITY_ADMIN' | 'SOC_ANALYST' | 'READ_ONLY_AUDITOR';

export type UserStatus = 'ACTIVE' | 'DISABLED' | 'INVITED' | 'LOCKED' | 'PENDING_VERIFICATION';

export type TenantStatus = 'ACTIVE' | 'SUSPENDED' | 'PROVISIONING' | 'DISABLED';

export type TenantPlanTier = 'COMMUNITY' | 'STANDARD' | 'ENTERPRISE';

export type PolicyType = 'AUTHENTICATION' | 'SESSION_MANAGEMENT' | 'DATA_RETENTION' | 'ROLE_DELEGATION' | 'EXTERNAL_SHARING' | 'API_ACCESS';

export type PolicyStatus = 'DRAFT' | 'VALIDATING' | 'ACTIVE' | 'DISABLED' | 'ARCHIVED';

export type SettingCategory = 'GENERAL' | 'SECURITY' | 'AUTHENTICATION' | 'ANALYSIS' | 'THREAT_INTEL' | 'NOTIFICATIONS' | 'RETENTION' | 'PERFORMANCE';

export type SettingScope = 'GLOBAL' | 'TENANT';

export type IntegrationCategory = 'THREAT_INTEL' | 'SIEM' | 'EDR' | 'IDENTITY' | 'NOTIFICATION' | 'COMMUNICATION';

export type IntegrationHealthStatus = 'HEALTHY' | 'DEGRADED' | 'UNCONFIGURED' | 'ERROR';

export type FeatureScope = 'GLOBAL' | 'TENANT' | 'ENVIRONMENT';

export interface PermissionDefinition {
  key: string;
  resource: string;
  action: string;
  scope: string;
  description: string;
}

export interface RoleDefinition {
  role: AdminRole;
  display_name: string;
  description: string;
  is_system_managed: boolean;
  permissions: string[];
  assigned_users_count: number;
}

export interface AdminUser {
  id: string;
  tenant_id: string;
  workspace_id: string;
  username: string;
  email: string;
  full_name: string;
  role: AdminRole;
  status: UserStatus;
  team_id?: string | null;
  is_platform_admin: boolean;
  custom_permissions: string[];
  last_login_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AdminTeam {
  id: string;
  tenant_id: string;
  name: string;
  description?: string | null;
  team_lead_id?: string | null;
  team_lead_name?: string | null;
  members_count: number;
  created_at: string;
  updated_at: string;
}

export interface AdminTenant {
  id: string;
  name: string;
  status: TenantStatus;
  plan_tier: TenantPlanTier;
  retention_days: number;
  configuration: Record<string, any>;
  users_count: number;
  created_at: string;
  updated_at: string;
}

export interface AdminSecurityPolicy {
  id: string;
  tenant_id: string;
  policy_type: PolicyType;
  name: string;
  description?: string | null;
  status: PolicyStatus;
  version: number;
  rules: Record<string, any>;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface PolicyImpactPreview {
  policy_id: string;
  policy_name: string;
  policy_type: PolicyType;
  proposed_status: PolicyStatus;
  affected_users_count: number;
  affected_roles: string[];
  affected_integrations: string[];
  warnings: string[];
  is_safe_to_apply: boolean;
  summary: string;
}

export interface AdminSystemSetting {
  id: string;
  tenant_id: string;
  key: string;
  value: any;
  category: SettingCategory;
  scope: SettingScope;
  is_secret: boolean;
  version: number;
  updated_by: string;
  updated_at: string;
  default_value?: any;
  description?: string;
}

export interface AdminIntegration {
  id: string;
  tenant_id: string;
  provider_name: string;
  display_name: string;
  category: IntegrationCategory;
  enabled: boolean;
  health_status: IntegrationHealthStatus;
  endpoint_url?: string | null;
  credential_configured: boolean;
  settings: Record<string, any>;
  last_health_check_at?: string | null;
  last_error_message?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AdminIntegrationTestResult {
  provider_name: string;
  success: boolean;
  health_status: IntegrationHealthStatus;
  latency_ms: number;
  message: string;
  tested_at: string;
}

export interface AdminFeatureControl {
  id: string;
  tenant_id: string;
  feature_key: string;
  display_name: string;
  description?: string | null;
  enabled: boolean;
  scope: FeatureScope;
  requires_role: string;
  updated_by: string;
  updated_at: string;
}

export interface PlatformOverview {
  platform_name: string;
  version: string;
  active_tenants_count: number;
  total_users_count: number;
  active_users_count: number;
  total_teams_count: number;
  active_policies_count: number;
  configured_integrations_count: number;
  healthy_integrations_count: number;
  system_status: string;
  active_features_count: number;
  pending_audit_events_24h: number;
}

export interface ComponentHealthItem {
  name: string;
  status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY' | 'UNKNOWN';
  details?: string | null;
  latency_ms?: number | null;
}

export interface SystemHealthData {
  overall_status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY';
  checked_at: string;
  components: ComponentHealthItem[];
  warnings: string[];
}

export interface AdminAuditLogItem {
  id: string;
  timestamp: string;
  user: string;
  action: string;
  resource_type: string;
  resource_id: string;
  metadata?: Record<string, any>;
  details?: string;
}
