/**
 * Section 56: Detection Engineering & Rule Lifecycle Service Client
 */
import type {
  DetectionRule,
  DetectionRuleValidationResult,
  DetectionRuleBacktestResult,
  RuleVersionDiff,
  DetectionRuleStats,
  FieldDefinition,
  RuleDefinition,
} from '../types/detectionRules';

const getHeaders = (): Record<string, string> => {
  const ws = localStorage.getItem('cyberguard_active_workspace') || 'default';
  const usr = localStorage.getItem('cyberguard_user_id') || 'analyst-1';
  const role = localStorage.getItem('cyberguard_user_role') || 'analyst';
  return {
    'Content-Type': 'application/json',
    'X-Workspace-ID': ws,
    'X-User-ID': usr,
    'X-Role': role,
  };
};

export const detectionRuleService = {
  async getRules(params?: {
    status?: string;
    category?: string;
    severity?: string;
    data_source?: string;
    search?: string;
    offset?: number;
    limit?: number;
  }): Promise<{ items: DetectionRule[]; total: number; active_count: number; candidate_count: number; staged_count: number; disabled_count: number }> {
    const query = new URLSearchParams();
    if (params?.status) query.append('status', params.status);
    if (params?.category) query.append('category', params.category);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.data_source) query.append('data_source', params.data_source);
    if (params?.search) query.append('search', params.search);
    if (params?.offset !== undefined) query.append('offset', String(params.offset));
    if (params?.limit !== undefined) query.append('limit', String(params.limit));

    const res = await fetch(`/api/v1/rules?${query.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch detection rules: ${res.statusText}`);
    return res.json();
  },

  async getRuleById(id: string): Promise<DetectionRule> {
    const res = await fetch(`/api/v1/rules/${id}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load detection rule: ${res.statusText}`);
    return res.json();
  },

  async getStats(): Promise<DetectionRuleStats> {
    const res = await fetch('/api/v1/rules/stats', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch rule statistics: ${res.statusText}`);
    return res.json();
  },

  async getFieldRegistry(): Promise<FieldDefinition[]> {
    const res = await fetch('/api/v1/rules/registry/fields', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch field registry: ${res.statusText}`);
    return res.json();
  },

  async validateRule(definition: RuleDefinition): Promise<DetectionRuleValidationResult> {
    const res = await fetch('/api/v1/rules/validate', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(definition),
    });
    if (!res.ok) throw new Error(`Validation failed: ${res.statusText}`);
    return res.json();
  },

  async createRule(payload: {
    name: string;
    description?: string;
    category: string;
    data_sources: string[];
    severity?: string;
    confidence?: number;
    definition: RuleDefinition;
    tags?: string[];
    attack_techniques?: string[];
    scope?: string;
  }): Promise<DetectionRule> {
    const res = await fetch('/api/v1/rules', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to create detection rule: ${res.statusText}`);
    }
    return res.json();
  },

  async updateRule(
    id: string,
    payload: {
      name?: string;
      description?: string;
      category?: string;
      data_sources?: string[];
      severity?: string;
      confidence?: number;
      definition?: RuleDefinition;
      tags?: string[];
      attack_techniques?: string[];
      change_summary?: string;
    }
  ): Promise<DetectionRule> {
    const res = await fetch(`/api/v1/rules/${id}`, {
      method: 'PUT',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to update rule: ${res.statusText}`);
    }
    return res.json();
  },

  async transitionRule(id: string, action: 'submit-review' | 'approve' | 'stage' | 'activate' | 'disable' | 'retire' | 'reject', reason: string): Promise<DetectionRule> {
    const res = await fetch(`/api/v1/rules/${id}/${action}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to transition rule: ${res.statusText}`);
    }
    return res.json();
  },

  async backtestRule(
    id: string,
    params: { time_range_preset?: string; max_records?: number; run_async?: boolean }
  ): Promise<DetectionRuleBacktestResult> {
    const res = await fetch(`/api/v1/rules/${id}/backtest`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(params),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Backtest failed: ${res.statusText}`);
    }
    return res.json();
  },

  async getVersionDiff(id: string, v1: string, v2: string): Promise<RuleVersionDiff> {
    const res = await fetch(`/api/v1/rules/${id}/diff?v1=${v1}&v2=${v2}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to compute version diff: ${res.statusText}`);
    return res.json();
  },

  async suggestRuleFromAI(payload: { prompt: string; category?: string; target_data_sources?: string[] }): Promise<{
    name: string;
    description: string;
    category: string;
    data_sources: string[];
    severity: string;
    confidence: number;
    definition: RuleDefinition;
    human_readable_logic: string;
    reasoning: string;
    cost_class: string;
  }> {
    const res = await fetch('/api/v1/rules/suggest/ai', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `AI rule generation failed: ${res.statusText}`);
    }
    return res.json();
  },

  async createFromHunt(payload: { hunt_id: string; rule_name?: string; category?: string }): Promise<DetectionRule> {
    const res = await fetch('/api/v1/rules/from-hunt', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to create rule from hunt: ${res.statusText}`);
    }
    return res.json();
  },

  async evaluateLiveEvent(eventPayload: any, dataSource: string = 'EMAIL_EVENT'): Promise<any[]> {
    const res = await fetch(`/api/v1/rules/evaluate?data_source=${dataSource}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(eventPayload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Evaluation failed: ${res.statusText}`);
    }
    return res.json();
  },
};
