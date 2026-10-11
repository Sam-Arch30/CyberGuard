/**
 * Section 65: Threat Actor & Campaign Workspace Client Service.
 */
import { apiUrl } from '../utils/apiClient';
import type {
  ThreatActor,
  ThreatActorListResponse,
  CampaignWorkspaceDetail,
  CampaignListWorkspaceResponse,
  CandidateReviewRequest,
  CampaignMergePreviewResponse,
  AttributionAssessmentResponse,
  Hypothesis,
  CampaignTimelineEvent,
  ThreatHuntHandoff,
  DetectionHandoff,
} from '../types/threatWorkspace';

const BASE_PREFIX = '/api/v1/threat-workspace';

const defaultHeaders = (workspaceId = 'default', role = 'analyst'): HeadersInit => ({
  'Content-Type': 'application/json',
  'X-Workspace-Id': workspaceId,
  'X-Role': role,
});

export const threatWorkspaceService = {
  // Threat Actors
  async getActors(params?: {
    query?: string;
    status?: string;
    attribution_state?: string;
    actor_type?: string;
    page?: number;
    page_size?: number;
    workspaceId?: string;
  }): Promise<ThreatActorListResponse> {
    const sp = new URLSearchParams();
    if (params?.query) sp.set('query', params.query);
    if (params?.status) sp.set('status', params.status);
    if (params?.attribution_state) sp.set('attribution_state', params.attribution_state);
    if (params?.actor_type) sp.set('actor_type', params.actor_type);
    if (params?.page) sp.set('page', String(params.page));
    if (params?.page_size) sp.set('page_size', String(params.page_size));

    const res = await fetch(apiUrl(`${BASE_PREFIX}/actors?${sp.toString()}`), {
      headers: defaultHeaders(params?.workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to list threat actors: ${res.statusText}`);
    return res.json();
  },

  async getActor(actorId: string, workspaceId = 'default'): Promise<ThreatActor> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/actors/${actorId}`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch threat actor: ${res.statusText}`);
    return res.json();
  },

  async createActor(payload: Record<string, any>, workspaceId = 'default'): Promise<ThreatActor> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/actors`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to create threat actor: ${res.statusText}`);
    return res.json();
  },

  async updateActor(actorId: string, payload: Record<string, any>, workspaceId = 'default'): Promise<ThreatActor> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/actors/${actorId}`), {
      method: 'PATCH',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to update threat actor: ${res.statusText}`);
    return res.json();
  },

  async recordActorAssessment(
    actorId: string,
    payload: Record<string, any>,
    workspaceId = 'default'
  ): Promise<AttributionAssessmentResponse> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/actors/${actorId}/assessments`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to record attribution assessment: ${res.statusText}`);
    }
    return res.json();
  },

  async getActorAssessments(actorId: string, workspaceId = 'default'): Promise<AttributionAssessmentResponse[]> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/actors/${actorId}/assessments`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch actor assessments: ${res.statusText}`);
    return res.json();
  },

  // Campaigns
  async getCampaigns(params?: {
    query?: string;
    lifecycle_status?: string;
    attribution_state?: string;
    activity_state?: string;
    threat_actor_id?: string;
    page?: number;
    page_size?: number;
    workspaceId?: string;
  }): Promise<CampaignListWorkspaceResponse> {
    const sp = new URLSearchParams();
    if (params?.query) sp.set('query', params.query);
    if (params?.lifecycle_status) sp.set('lifecycle_status', params.lifecycle_status);
    if (params?.attribution_state) sp.set('attribution_state', params.attribution_state);
    if (params?.activity_state) sp.set('activity_state', params.activity_state);
    if (params?.threat_actor_id) sp.set('threat_actor_id', params.threat_actor_id);
    if (params?.page) sp.set('page', String(params.page));
    if (params?.page_size) sp.set('page_size', String(params.page_size));

    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns?${sp.toString()}`), {
      headers: defaultHeaders(params?.workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to list campaigns: ${res.statusText}`);
    return res.json();
  },

  async getCampaign(campaignId: string, workspaceId = 'default'): Promise<CampaignWorkspaceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch campaign: ${res.statusText}`);
    return res.json();
  },

  async createCampaign(payload: Record<string, any>, workspaceId = 'default'): Promise<CampaignWorkspaceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to create campaign: ${res.statusText}`);
    return res.json();
  },

  async updateCampaign(
    campaignId: string,
    payload: Record<string, any>,
    workspaceId = 'default'
  ): Promise<CampaignWorkspaceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}`), {
      method: 'PATCH',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to update campaign: ${res.statusText}`);
    return res.json();
  },

  async recordCampaignAssessment(
    campaignId: string,
    payload: Record<string, any>,
    workspaceId = 'default'
  ): Promise<AttributionAssessmentResponse> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}/assessments`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to record campaign assessment: ${res.statusText}`);
    }
    return res.json();
  },

  async getCampaignTimeline(
    campaignId: string,
    workspaceId = 'default'
  ): Promise<{ campaign_id: string; events: CampaignTimelineEvent[]; first_seen: string; last_seen: string; activity_state: string }> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}/timeline`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch campaign timeline: ${res.statusText}`);
    return res.json();
  },

  async getCampaignGraph(campaignId: string, maxNodes = 75, workspaceId = 'default'): Promise<any> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}/graph?max_nodes=${maxNodes}`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch campaign graph: ${res.statusText}`);
    return res.json();
  },

  // Candidate Workflows
  async getCandidates(workspaceId = 'default'): Promise<CampaignWorkspaceDetail[]> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/candidates`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch candidates: ${res.statusText}`);
    return res.json();
  },

  async reviewCandidate(
    candidateId: string,
    req: CandidateReviewRequest,
    workspaceId = 'default'
  ): Promise<CampaignWorkspaceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/candidates/${candidateId}/review`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(req),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to review candidate: ${res.statusText}`);
    }
    return res.json();
  },

  async previewMerge(sourceId: string, targetId: string, workspaceId = 'default'): Promise<CampaignMergePreviewResponse> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/merge-preview`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify({ source_campaign_id: sourceId, target_campaign_id: targetId }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to preview merge: ${res.statusText}`);
    }
    return res.json();
  },

  async mergeCampaigns(
    sourceId: string,
    targetId: string,
    reason: string,
    confirmConflicts = false,
    workspaceId = 'default'
  ): Promise<CampaignWorkspaceDetail> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/merge`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify({
        source_campaign_id: sourceId,
        target_campaign_id: targetId,
        reason,
        confirm_override_conflicts: confirmConflicts,
      }),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to merge campaigns: ${res.statusText}`);
    }
    return res.json();
  },

  async splitCampaign(
    campaignId: string,
    payload: { reason: string; new_campaign_name: string; incident_ids_to_move: string[] },
    workspaceId = 'default'
  ): Promise<any> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}/split`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to split campaign: ${res.statusText}`);
    }
    return res.json();
  },

  // Hypotheses
  async getHypotheses(subjectId: string, workspaceId = 'default'): Promise<Hypothesis[]> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/hypotheses?subject_id=${subjectId}`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to fetch hypotheses: ${res.statusText}`);
    return res.json();
  },

  async createHypothesis(payload: Record<string, any>, workspaceId = 'default'): Promise<Hypothesis> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/hypotheses`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to create hypothesis: ${res.statusText}`);
    return res.json();
  },

  async updateHypothesis(hypothesisId: string, payload: Record<string, any>, workspaceId = 'default'): Promise<Hypothesis> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/hypotheses/${hypothesisId}`), {
      method: 'PATCH',
      headers: defaultHeaders(workspaceId),
      body: JSON.stringify(payload),
    });
    if (!res.ok) throw new Error(`Failed to update hypothesis: ${res.statusText}`);
    return res.json();
  },

  // Handoffs
  async getHuntHandoff(campaignId: string, workspaceId = 'default'): Promise<ThreatHuntHandoff> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}/hunt-handoff`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to generate hunt handoff: ${res.statusText}`);
    return res.json();
  },

  async getDetectionHandoff(campaignId: string, workspaceId = 'default'): Promise<DetectionHandoff> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/campaigns/${campaignId}/detection-handoff`), {
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to generate detection handoff: ${res.statusText}`);
    return res.json();
  },

  async triggerSync(workspaceId = 'default'): Promise<any> {
    const res = await fetch(apiUrl(`${BASE_PREFIX}/sync`), {
      method: 'POST',
      headers: defaultHeaders(workspaceId),
    });
    if (!res.ok) throw new Error(`Failed to trigger sync: ${res.statusText}`);
    return res.json();
  },
};
