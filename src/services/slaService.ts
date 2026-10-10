/**
 * Section 51: Incident SLA, Escalation & Analyst Workflow Client Service.
 * Provides typed methods for SLA clocks, pause/resume/exempt actions,
 * policy configuration, workflow history, routing, and policy simulations.
 */
import { apiUrl, extractErrorMessage } from '../utils/apiClient';
import type {
  IncidentSLADetail,
  SLAPolicy,
  EscalationPolicy,
  RoutingRule,
  WorkflowHistory,
  PolicySimulationRequest,
  PolicySimulationResponse,
} from '../types/sla';

export class SLAService {
  /**
   * Retrieves live operational SLA clocks, deadlines, and milestone statuses for an incident.
   */
  static async getIncidentSLA(
    incidentId: string,
    workspaceId: string = 'default'
  ): Promise<IncidentSLADetail> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/sla`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to get incident SLA: ${err}`);
    }

    return res.json();
  }

  /**
   * Pauses SLA clock with mandatory authorization reason.
   */
  static async pauseSLA(
    incidentId: string,
    reason: string,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentSLADetail> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/sla/pause`);
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
      throw new Error(`Failed to pause SLA: ${err}`);
    }

    return res.json();
  }

  /**
   * Resumes a paused SLA clock.
   */
  static async resumeSLA(
    incidentId: string,
    reason?: string,
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentSLADetail> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/sla/resume`);
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
      throw new Error(`Failed to resume SLA: ${err}`);
    }

    return res.json();
  }

  /**
   * Exempts an incident SLA (authorized lead/admin only).
   */
  static async exemptSLA(
    incidentId: string,
    reason: string,
    workspaceId: string = 'default',
    actor: string = 'SOC Lead'
  ): Promise<IncidentSLADetail> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/sla/exempt`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
        'X-Role': 'security_lead',
      },
      body: JSON.stringify({ reason }),
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to exempt SLA: ${err}`);
    }

    return res.json();
  }

  /**
   * Manually escalates an incident.
   */
  static async escalateIncident(
    incidentId: string,
    payload: {
      reason: string;
      target_level?: number;
      target_user?: string;
      target_team?: string;
    },
    workspaceId: string = 'default',
    actor: string = 'SOC Analyst'
  ): Promise<IncidentSLADetail> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/escalate`);
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
      throw new Error(`Failed to escalate incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Forces re-evaluation of SLA clocks.
   */
  static async evaluateSLA(
    incidentId: string,
    workspaceId: string = 'default'
  ): Promise<IncidentSLADetail> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/sla/evaluate`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to evaluate SLA: ${err}`);
    }

    return res.json();
  }

  /**
   * Dispatches automated routing rules on an incident.
   */
  static async routeIncident(
    incidentId: string,
    workspaceId: string = 'default'
  ): Promise<{ incident_id: string; assigned_to: string | null; team_id: string | null; routed: boolean }> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/route`);
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to route incident: ${err}`);
    }

    return res.json();
  }

  /**
   * Retrieves complete workflow execution and pause history.
   */
  static async getWorkflowHistory(
    incidentId: string,
    workspaceId: string = 'default'
  ): Promise<WorkflowHistory> {
    const url = apiUrl(`/api/incidents/${encodeURIComponent(incidentId)}/workflow-history`);
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
    });

    if (!res.ok) {
      const err = await extractErrorMessage(res);
      throw new Error(`Failed to get workflow history: ${err}`);
    }

    return res.json();
  }

  // =========================================================================
  // SETTINGS & POLICIES
  // =========================================================================

  static async listSLAPolicies(workspaceId: string = 'default'): Promise<{ items: SLAPolicy[]; total: number }> {
    const url = apiUrl('/api/settings/sla-policies');
    const res = await fetch(url, {
      headers: { 'X-Workspace-ID': workspaceId },
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async createSLAPolicy(
    payload: Partial<SLAPolicy>,
    workspaceId: string = 'default',
    actor: string = 'Admin'
  ): Promise<SLAPolicy> {
    const url = apiUrl('/api/settings/sla-policies');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
        'X-Role': 'admin',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async updateSLAPolicy(
    policyId: string,
    payload: Partial<SLAPolicy>,
    workspaceId: string = 'default',
    actor: string = 'Admin'
  ): Promise<SLAPolicy> {
    const url = apiUrl(`/api/settings/sla-policies/${encodeURIComponent(policyId)}`);
    const res = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
        'X-Role': 'admin',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async listEscalationPolicies(
    workspaceId: string = 'default'
  ): Promise<{ items: EscalationPolicy[]; total: number }> {
    const url = apiUrl('/api/settings/escalation-policies');
    const res = await fetch(url, {
      headers: { 'X-Workspace-ID': workspaceId },
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async createEscalationPolicy(
    payload: Partial<EscalationPolicy>,
    workspaceId: string = 'default',
    actor: string = 'Admin'
  ): Promise<EscalationPolicy> {
    const url = apiUrl('/api/settings/escalation-policies');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
        'X-Role': 'admin',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async updateEscalationPolicy(
    policyId: string,
    payload: Partial<EscalationPolicy>,
    workspaceId: string = 'default',
    actor: string = 'Admin'
  ): Promise<EscalationPolicy> {
    const url = apiUrl(`/api/settings/escalation-policies/${encodeURIComponent(policyId)}`);
    const res = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
        'X-Role': 'admin',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async listRoutingRules(
    workspaceId: string = 'default'
  ): Promise<{ items: RoutingRule[]; total: number }> {
    const url = apiUrl('/api/settings/routing-rules');
    const res = await fetch(url, {
      headers: { 'X-Workspace-ID': workspaceId },
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async createRoutingRule(
    payload: Partial<RoutingRule>,
    workspaceId: string = 'default',
    actor: string = 'Admin'
  ): Promise<RoutingRule> {
    const url = apiUrl('/api/settings/routing-rules');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
        'X-Role': 'admin',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async updateRoutingRule(
    ruleId: string,
    payload: Partial<RoutingRule>,
    workspaceId: string = 'default',
    actor: string = 'Admin'
  ): Promise<RoutingRule> {
    const url = apiUrl(`/api/settings/routing-rules/${encodeURIComponent(ruleId)}`);
    const res = await fetch(url, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
        'X-Analyst-Name': actor,
        'X-Role': 'admin',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }

  static async simulatePolicy(
    payload: PolicySimulationRequest,
    workspaceId: string = 'default'
  ): Promise<PolicySimulationResponse> {
    const url = apiUrl('/api/settings/sla-policies/simulate');
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Workspace-ID': workspaceId,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(await extractErrorMessage(res));
    return res.json();
  }
}

export class SlaClientService {
  static async getIncidentSLA(incidentId: string, workspaceId: string = 'default') {
    const raw = await SLAService.getIncidentSLA(incidentId, workspaceId);
    return {
      incident_id: raw.incident_id,
      incident_number: raw.incident_number,
      overall_sla_status: raw.overall_status === 'HEALTHY' ? 'ON_TRACK' : raw.overall_status,
      milestones: {
        acknowledgement: raw.acknowledgement,
        investigation: raw.investigation,
        containment: raw.containment,
        resolution: raw.resolution,
      },
      policy: {
        id: raw.policy_id || '',
        name: raw.policy_name || 'Operational SLA Policy',
        version: raw.policy_version,
        severity: 'ACTIVE',
        priority: 'ALL',
      },
      escalation: {
        current_level: raw.current_escalation_level,
        max_level: 3,
        current_level_name:
          raw.current_escalation_level === 1
            ? 'L1 Analyst'
            : raw.current_escalation_level === 2
            ? 'L2 SOC Lead'
            : 'L3 Security Manager',
        current_target_name: raw.last_escalated_at ? 'SOC Lead' : 'Primary Analyst',
      },
      is_paused: raw.is_paused,
      total_paused_minutes: Math.round((raw.total_paused_seconds || 0) / 60),
      is_exempt: raw.is_exempt,
      exemption_reason: raw.exempt_reason,
    };
  }

  static async pauseIncidentSLA(incidentId: string, payload: { reason: string }, workspaceId: string = 'default') {
    return SLAService.pauseSLA(incidentId, payload.reason, workspaceId);
  }

  static async resumeIncidentSLA(incidentId: string, workspaceId: string = 'default') {
    return SLAService.resumeSLA(incidentId, undefined, workspaceId);
  }

  static async exemptIncidentSLA(incidentId: string, payload: { reason: string }, workspaceId: string = 'default') {
    return SLAService.exemptSLA(incidentId, payload.reason, workspaceId);
  }

  static async escalateIncident(incidentId: string, payload: { reason: string; target_level?: number }, workspaceId: string = 'default') {
    return SLAService.escalateIncident(incidentId, payload, workspaceId);
  }

  static async evaluateIncidentSLA(incidentId: string, workspaceId: string = 'default') {
    return SLAService.evaluateSLA(incidentId, workspaceId);
  }

  static async getWorkflowHistory(incidentId: string, workspaceId: string = 'default') {
    const res = await SLAService.getWorkflowHistory(incidentId, workspaceId);
    return {
      executions: res.executions.map((e) => ({
        id: e.id,
        policy_name: e.policy_id || 'Operational Policy',
        rule_name: e.rule_id || '',
        action_type: e.action_type,
        condition_type: (e.details as Record<string, unknown>)?.condition_type ? String((e.details as Record<string, unknown>).condition_type) : 'SLA_TRIGGER',
        status: e.status,
        idempotency_key: e.execution_key,
        executed_at: e.executed_at,
        result: e.details,
        error: (e.details as Record<string, unknown>)?.error ? String((e.details as Record<string, unknown>).error) : null,
      })),
      pause_logs: res.pause_logs.map((p) => ({
        id: p.id,
        paused_at: p.timestamp,
        resumed_at: p.action === 'RESUMED' ? p.timestamp : null,
        duration_minutes: p.paused_duration_seconds ? Math.round(p.paused_duration_seconds / 60) : null,
        reason: p.reason,
        paused_by: p.actor,
        resumed_by: p.action === 'RESUMED' ? p.actor : null,
        active: p.action === 'PAUSED',
      })),
    };
  }

  static async listSLAPolicies(workspaceId: string = 'default') {
    const res = await SLAService.listSLAPolicies(workspaceId);
    return res.items;
  }

  static async createSLAPolicy(payload: any, workspaceId: string = 'default') {
    return SLAService.createSLAPolicy(payload, workspaceId);
  }

  static async listEscalationPolicies(workspaceId: string = 'default') {
    const res = await SLAService.listEscalationPolicies(workspaceId);
    return res.items;
  }

  static async listRoutingRules(workspaceId: string = 'default') {
    const res = await SLAService.listRoutingRules(workspaceId);
    return res.items.map((r) => ({
      id: r.id,
      name: r.name,
      strategy: r.routing_strategy,
      condition_category: r.category,
      condition_severity: r.severity,
      target_team: r.target_team_id,
      target_user: r.target_user_id,
    }));
  }

  static async simulateSLAPolicy(req: any, workspaceId: string = 'default') {
    const mapped: PolicySimulationRequest = {
      severity: req.severity,
      priority: req.priority,
      category: req.category,
      risk_score: 80,
      unacknowledged_minutes: req.is_acknowledged ? 0 : req.elapsed_minutes,
      uncontained_minutes: req.is_contained ? 0 : req.elapsed_minutes,
      status: req.is_resolved ? 'RESOLVED' : req.is_contained ? 'CONTAINED' : req.is_acknowledged ? 'INVESTIGATING' : 'NEW',
    };
    const res = await SLAService.simulatePolicy(mapped, workspaceId);
    return {
      matched_policy_name: res.matched_sla_policy || 'Default SLA Policy',
      evaluated_sla_status: Object.values(res.simulated_milestone_status).includes('BREACHED')
        ? 'BREACHED'
        : Object.values(res.simulated_milestone_status).includes('WARNING')
        ? 'WARNING'
        : 'MET',
      milestone_states: Object.entries(res.simulated_milestone_status).reduce((acc: Record<string, { status: string }>, [k, v]) => {
        acc[k] = { status: v };
        return acc;
      }, {}),
      escalations_triggered: res.triggered_escalation_rules.map((e) => ({
        target_tier: e.level,
        action: e.action_type,
        target_recipient: e.target || 'SOC Lead',
      })),
      target_assignee: res.simulated_routing_target || res.simulated_team_target || 'Identity Security Analyst',
    };
  }
}
