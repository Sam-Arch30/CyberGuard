import type {
  DetectionRule,
  DetectionRuleValidationResult,
  DetectionRuleBacktestResult,
  RuleVersionDiff,
  DetectionRuleStats,
  FieldDefinition,
  RuleDefinition,
  RuleOperationalHealth,
  DeploymentDryRunResult,
  RuleSimulationResult,
  RuleQualityMetrics,
  RuleSuppression,
  OperationalOverviewStats,
  BulkOperationResult,
  ValidationRun,
  ValidationOverview,
  DeploymentGateCheck,
  TestFixture,
  PipelineExecutionResult,
  PipelineMetrics,
  PipelineStatus,
  DetectionMatchItem,
  DeadLetterItem,
  EventIngestPayload,
  PipelineReplayRequestPayload,
  BehaviorProfile,
  BehaviorProfileDetail,
  BehavioralAnomalyDetail,
  LearningQuarantineItem,
  BehavioralOverviewStats,
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
    deployment_state?: string;
    operational_health?: string;
    owner_id?: string;
    team_id?: string;
    collection?: string;
    is_stale?: boolean;
    review_due?: boolean;
    sort_by?: string;
    sort_order?: string;
    offset?: number;
    limit?: number;
  }): Promise<{ items: DetectionRule[]; total: number; active_count: number; candidate_count: number; staged_count: number; disabled_count: number }> {
    const query = new URLSearchParams();
    if (params?.status) query.append('status', params.status);
    if (params?.category) query.append('category', params.category);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.data_source) query.append('data_source', params.data_source);
    if (params?.search) query.append('search', params.search);
    if (params?.deployment_state) query.append('deployment_state', params.deployment_state);
    if (params?.operational_health) query.append('operational_health', params.operational_health);
    if (params?.owner_id) query.append('owner_id', params.owner_id);
    if (params?.team_id) query.append('team_id', params.team_id);
    if (params?.collection) query.append('collection', params.collection);
    if (params?.is_stale !== undefined) query.append('is_stale', String(params.is_stale));
    if (params?.review_due !== undefined) query.append('review_due', String(params.review_due));
    if (params?.sort_by) query.append('sort_by', params.sort_by);
    if (params?.sort_order) query.append('sort_order', params.sort_order);
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

  // Section 57: Detection Management & Operational Control APIs

  async getOperationalOverview(): Promise<OperationalOverviewStats> {
    const res = await fetch('/api/v1/rules/overview', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load operational overview: ${res.statusText}`);
    return res.json();
  },

  async getRuleHealth(id: string): Promise<RuleOperationalHealth> {
    const res = await fetch(`/api/v1/rules/${id}/health`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load rule operational health: ${res.statusText}`);
    return res.json();
  },

  async dryRunDeployment(id: string, targetVersion?: string): Promise<DeploymentDryRunResult> {
    const query = targetVersion ? `?target_version=${encodeURIComponent(targetVersion)}` : '';
    const res = await fetch(`/api/v1/rules/${id}/dry-run${query}`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Dry-run failed: ${res.statusText}`);
    }
    return res.json();
  },

  async deployRule(
    id: string,
    targetState: 'DRAFT' | 'STAGING' | 'PRODUCTION' | 'DISABLED',
    targetVersion?: string,
    reason?: string
  ): Promise<DetectionRule> {
    const res = await fetch(`/api/v1/rules/${id}/deploy`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({
        target_state: targetState,
        target_version: targetVersion,
        reason: reason || `Deploying rule to ${targetState}`,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Deployment failed: ${res.statusText}`);
    }
    return res.json();
  },

  async rollbackRule(id: string, targetVersion: string, reason: string): Promise<DetectionRule> {
    const res = await fetch(`/api/v1/rules/${id}/rollback`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({
        target_version: targetVersion,
        reason,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Rollback failed: ${res.statusText}`);
    }
    return res.json();
  },

  async emergencyDisableRule(id: string, reason: string): Promise<DetectionRule> {
    const res = await fetch(`/api/v1/rules/${id}/emergency-disable`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Emergency disable failed: ${res.statusText}`);
    }
    return res.json();
  },

  async simulateRule(id: string, targetVersion?: string, eventCount: number = 25): Promise<RuleSimulationResult> {
    const res = await fetch(`/api/v1/rules/${id}/simulate`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({
        target_version: targetVersion,
        event_count: eventCount,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Rule simulation failed: ${res.statusText}`);
    }
    return res.json();
  },

  async updateOwnership(
    id: string,
    payload: { owner_id?: string; team_id?: string; collections?: string[]; review_interval_days?: number }
  ): Promise<DetectionRule> {
    const res = await fetch(`/api/v1/rules/${id}/ownership`, {
      method: 'PATCH',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to update rule ownership: ${res.statusText}`);
    }
    return res.json();
  },

  async getSuppressions(ruleId: string): Promise<RuleSuppression[]> {
    const res = await fetch(`/api/v1/rules/${ruleId}/suppressions`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load suppressions: ${res.statusText}`);
    return res.json();
  },

  async createSuppression(
    ruleId: string,
    payload: {
      name: string;
      reason: string;
      scope_type?: string;
      scope_target: string;
      match_operator?: string;
      match_value: string;
      expires_in_days?: number;
    }
  ): Promise<RuleSuppression> {
    const res = await fetch(`/api/v1/rules/${ruleId}/suppressions`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to create suppression: ${res.statusText}`);
    }
    return res.json();
  },

  async deleteSuppression(ruleId: string, suppressionId: string): Promise<boolean> {
    const res = await fetch(`/api/v1/rules/${ruleId}/suppressions/${suppressionId}`, {
      method: 'DELETE',
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to delete suppression: ${res.statusText}`);
    }
    return true;
  },

  async getQualityMetrics(ruleId: string): Promise<RuleQualityMetrics> {
    const res = await fetch(`/api/v1/rules/${ruleId}/quality`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load quality metrics: ${res.statusText}`);
    return res.json();
  },

  async recordMatchDisposition(
    matchId: string,
    payload: { disposition: string; notes?: string }
  ): Promise<any> {
    const res = await fetch(`/api/v1/rules/matches/${matchId}/disposition`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to record disposition: ${res.statusText}`);
    }
    return res.json();
  },

  async getRuleMatches(ruleId: string, limit: number = 50): Promise<any[]> {
    const res = await fetch(`/api/v1/rules/${ruleId}/matches?limit=${limit}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load matches: ${res.statusText}`);
    return res.json();
  },

  async getRuleDuplicates(ruleId: string): Promise<any> {
    const res = await fetch(`/api/v1/rules/${ruleId}/duplicates`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to check rule duplicates: ${res.statusText}`);
    return res.json();
  },

  async getRuleConflicts(ruleId: string): Promise<any> {
    const res = await fetch(`/api/v1/rules/${ruleId}/conflicts`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to check rule conflicts: ${res.statusText}`);
    return res.json();
  },

  async bulkOperation(payload: {
    rule_ids: string[];
    action: 'ENABLE' | 'DISABLE' | 'SET_OWNER' | 'SET_COLLECTION' | 'TAG';
    parameters?: Record<string, any>;
    reason?: string;
  }): Promise<BulkOperationResult> {
    const res = await fetch('/api/v1/rules/bulk', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Bulk operation failed: ${res.statusText}`);
    }
    return res.json();
  },

  async getHuntPattern(ruleId: string): Promise<any> {
    const res = await fetch(`/api/v1/rules/${ruleId}/hunt-pattern`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to export hunt pattern: ${res.statusText}`);
    return res.json();
  },

  // ==========================================================================
  // Section 58: Automated Detection Validation & Continuous Rule Quality API
  // ==========================================================================

  async getValidationOverview(): Promise<ValidationOverview> {
    const res = await fetch('/api/v1/rules/validation/overview', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch validation overview: ${res.statusText}`);
    return res.json();
  },

  async triggerValidation(ruleId: string, payload?: {
    validation_type?: string;
    trigger_type?: string;
    version?: string;
    baseline_version?: string;
    data_window_days?: number;
    run_async?: boolean;
    idempotency_key?: string;
  }): Promise<ValidationRun> {
    const res = await fetch(`/api/v1/rules/${ruleId}/validation`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload || {}),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to trigger validation: ${res.statusText}`);
    }
    return res.json();
  },

  async getLatestValidation(ruleId: string, version?: string): Promise<ValidationRun> {
    const query = version ? `?version=${encodeURIComponent(version)}` : '';
    const res = await fetch(`/api/v1/rules/${ruleId}/validation${query}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch latest validation: ${res.statusText}`);
    return res.json();
  },

  async getDeploymentGate(ruleId: string, version?: string): Promise<DeploymentGateCheck> {
    const query = version ? `?version=${encodeURIComponent(version)}` : '';
    const res = await fetch(`/api/v1/rules/${ruleId}/validation/gate${query}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to check deployment gate: ${res.statusText}`);
    return res.json();
  },

  async getValidationHistory(ruleId: string, limit = 20, offset = 0): Promise<ValidationRun[]> {
    const res = await fetch(`/api/v1/rules/${ruleId}/validation/history?limit=${limit}&offset=${offset}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch validation history: ${res.statusText}`);
    return res.json();
  },

  async getValidationRunDetails(runId: string): Promise<ValidationRun> {
    const res = await fetch(`/api/v1/rules/validation/runs/${runId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch validation run details: ${res.statusText}`);
    return res.json();
  },

  async cancelValidationRun(runId: string): Promise<ValidationRun> {
    const res = await fetch(`/api/v1/rules/validation/runs/${runId}/cancel`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to cancel validation run: ${res.statusText}`);
    return res.json();
  },

  async getFixtures(ruleId: string): Promise<TestFixture[]> {
    const res = await fetch(`/api/v1/rules/${ruleId}/fixtures`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to fetch test fixtures: ${res.statusText}`);
    return res.json();
  },

  async createFixture(ruleId: string, payload: {
    name: string;
    description?: string;
    fixture_type: 'POSITIVE' | 'NEGATIVE';
    payload: Record<string, any>;
    expected_match: boolean;
    is_active?: boolean;
  }): Promise<TestFixture> {
    const res = await fetch(`/api/v1/rules/${ruleId}/fixtures`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to create fixture: ${res.statusText}`);
    }
    return res.json();
  },

  async deleteFixture(ruleId: string, fixtureId: string): Promise<boolean> {
    const res = await fetch(`/api/v1/rules/${ruleId}/fixtures/${fixtureId}`, {
      method: 'DELETE',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to delete fixture: ${res.statusText}`);
    return true;
  },

  async runFixture(ruleId: string, fixtureId: string): Promise<TestFixture> {
    const res = await fetch(`/api/v1/rules/${ruleId}/fixtures/${fixtureId}/run`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to execute test fixture: ${res.statusText}`);
    return res.json();
  },

  // =========================================================================
  // Section 59: Unified Threat Detection Pipeline Client Methods
  // =========================================================================

  async ingestEvent(payload: EventIngestPayload): Promise<PipelineExecutionResult> {
    const res = await fetch('/api/v1/detection/events', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Event ingestion failed: ${res.statusText}`);
    }
    return res.json();
  },

  async ingestEventBatch(events: EventIngestPayload[], asyncMode: boolean = false): Promise<any> {
    const res = await fetch(`/api/v1/detection/events/batch?async_mode=${asyncMode}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ events, mode: 'PRODUCTION', stop_on_error: false }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Batch ingestion failed: ${res.statusText}`);
    }
    return res.json();
  },

  async getPipelineStatus(): Promise<PipelineStatus> {
    const res = await fetch('/api/v1/detection/pipeline/status', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load pipeline status: ${res.statusText}`);
    return res.json();
  },

  async getPipelineMetrics(): Promise<PipelineMetrics> {
    const res = await fetch('/api/v1/detection/pipeline/metrics', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load pipeline metrics: ${res.statusText}`);
    return res.json();
  },

  async getEventDetails(eventId: string): Promise<any> {
    const res = await fetch(`/api/v1/detection/events/${eventId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load event details: ${res.statusText}`);
    return res.json();
  },

  async getEventTrace(eventId: string): Promise<any> {
    const res = await fetch(`/api/v1/detection/events/${eventId}/trace`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load event trace: ${res.statusText}`);
    return res.json();
  },

  async replayPipeline(payload: PipelineReplayRequestPayload, asyncMode: boolean = false): Promise<any> {
    const res = await fetch(`/api/v1/detection/pipeline/replay?async_mode=${asyncMode}`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Replay failed: ${res.statusText}`);
    }
    return res.json();
  },

  async listDetectionMatches(params?: {
    ruleId?: string;
    severity?: string;
    mode?: string;
    status?: string;
    limit?: number;
    offset?: number;
  }): Promise<DetectionMatchItem[]> {
    const query = new URLSearchParams();
    if (params?.ruleId) query.set('rule_id', params.ruleId);
    if (params?.severity) query.set('severity', params.severity);
    if (params?.mode) query.set('mode', params.mode);
    if (params?.status) query.set('status', params.status);
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.offset) query.set('offset', params.offset.toString());

    const res = await fetch(`/api/v1/detection/matches?${query.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load detection matches: ${res.statusText}`);
    return res.json();
  },

  async getDetectionMatch(matchId: string): Promise<DetectionMatchItem> {
    const res = await fetch(`/api/v1/detection/matches/${matchId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load detection match: ${res.statusText}`);
    return res.json();
  },

  async listDeadLetters(limit: number = 50, offset: number = 0): Promise<DeadLetterItem[]> {
    const res = await fetch(`/api/v1/detection/dead-letters?limit=${limit}&offset=${offset}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load dead letters: ${res.statusText}`);
    return res.json();
  },

  async retryDeadLetter(deadLetterId: string): Promise<any> {
    const res = await fetch(`/api/v1/detection/dead-letters/${deadLetterId}/retry`, {
      method: 'POST',
      headers: getHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Dead letter retry failed: ${res.statusText}`);
    }
    return res.json();
  },

  // Section 60: Behavioral Detection & Anomaly Analytics
  async getBehavioralOverview(): Promise<BehavioralOverviewStats> {
    const res = await fetch('/api/v1/behavioral/overview', {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load behavioral overview: ${res.statusText}`);
    return res.json();
  },

  async listBehaviorProfiles(params?: {
    status?: string;
    quality?: string;
    entity_type?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ items: BehaviorProfile[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.status && params.status !== 'ALL') query.set('status', params.status);
    if (params?.quality && params.quality !== 'ALL') query.set('quality', params.quality);
    if (params?.entity_type && params.entity_type !== 'ALL') query.set('entity_type', params.entity_type);
    if (params?.search) query.set('search', params.search);
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.offset) query.set('offset', params.offset.toString());

    const res = await fetch(`/api/v1/behavioral/profiles?${query.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load behavior profiles: ${res.statusText}`);
    return res.json();
  },

  async getBehaviorProfileDetail(profileId: string): Promise<BehaviorProfileDetail> {
    const res = await fetch(`/api/v1/behavioral/profiles/${profileId}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load behavior profile detail: ${res.statusText}`);
    return res.json();
  },

  async listBehavioralDeviations(params?: {
    entity_type?: string;
    entity_id?: string;
    severity?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ items: BehavioralAnomalyDetail[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.entity_type && params.entity_type !== 'ALL') query.set('entity_type', params.entity_type);
    if (params?.entity_id) query.set('entity_id', params.entity_id);
    if (params?.severity && params.severity !== 'ALL') query.set('severity', params.severity);
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.offset) query.set('offset', params.offset.toString());

    const res = await fetch(`/api/v1/behavioral/deviations?${query.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load behavioral deviations: ${res.statusText}`);
    return res.json();
  },

  async listLearningQuarantine(params?: {
    disposition?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ items: LearningQuarantineItem[]; total: number }> {
    const query = new URLSearchParams();
    if (params?.disposition && params.disposition !== 'ALL') query.set('disposition', params.disposition);
    if (params?.limit) query.set('limit', params.limit.toString());
    if (params?.offset) query.set('offset', params.offset.toString());

    const res = await fetch(`/api/v1/behavioral/quarantine?${query.toString()}`, {
      headers: getHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to load learning quarantine: ${res.statusText}`);
    return res.json();
  },

  async reviewQuarantineItem(
    quarantineId: string,
    disposition: string,
    reviewNotes?: string
  ): Promise<LearningQuarantineItem> {
    const res = await fetch(`/api/v1/behavioral/quarantine/${quarantineId}/review`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ disposition, review_notes: reviewNotes }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Quarantine review failed: ${res.statusText}`);
    }
    return res.json();
  },

  async refreshBaselines(params?: { entity_type?: string; entity_id?: string }): Promise<any> {
    const res = await fetch('/api/v1/behavioral/baselines/refresh', {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({
        entity_type: params?.entity_type,
        entity_id: params?.entity_id,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Baseline refresh failed: ${res.statusText}`);
    }
    return res.json();
  },

  async rollbackBaseline(baselineId: string, reason: string): Promise<any> {
    const res = await fetch(`/api/v1/behavioral/baselines/${baselineId}/rollback`, {
      method: 'POST',
      headers: getHeaders(),
      body: JSON.stringify({ reason }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Baseline rollback failed: ${res.statusText}`);
    }
    return res.json();
  },
};
