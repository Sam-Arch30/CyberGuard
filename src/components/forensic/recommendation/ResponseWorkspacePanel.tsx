import { apiFetch } from '../../../utils/apiClient';
import React, { useState, useEffect, useMemo } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Clock,
  Layers,
  XCircle,
  Lock,
  ArrowRight,
  RefreshCw,
  Cpu,
  Sparkles,
  Search,
  Eye,
  GitBranch,
  Play
} from 'lucide-react';
import type {
  ResponseRecommendation,
  ResponseCapability,
  ResponseWorkspaceOverview,
  RecommendationPriority,
  RecommendationStatus
} from '../../../types/response_recommendation';
import type { EmailAnalysis } from '../../../types/forensic';
import { ActionDetailModal } from './ActionDetailModal';
import { PlaybookExecutionModal } from './PlaybookExecutionModal';
import { apiUrl } from '../../../utils/apiClient';

interface ResponseWorkspacePanelProps {
  scopeType?: string;
  scopeId?: string;
  threatEventId?: string;
  incidentId?: string;
  riskAssessmentId?: string;
  explanationId?: string;
  email?: EmailAnalysis;
  className?: string;
}

export const ResponseWorkspacePanel: React.FC<ResponseWorkspacePanelProps> = ({
  scopeType = 'EVENT',
  scopeId,
  threatEventId,
  incidentId,
  riskAssessmentId,
  explanationId,
  email,
  className = ''
}) => {
  const effectiveScopeId = scopeId || email?.evidence_id || email?.id || 'EV-DEFAULT';
  const [recommendations, setRecommendations] = useState<ResponseRecommendation[]>([]);
  const [capabilities, setCapabilities] = useState<ResponseCapability[]>([]);
  const [overview, setOverview] = useState<ResponseWorkspaceOverview | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [generating, setGenerating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [selectedCategory, setSelectedCategory] = useState<string>('ALL');
  const [selectedPriority, setSelectedPriority] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Modals & Panels
  const [selectedRecommendation, setSelectedRecommendation] = useState<ResponseRecommendation | null>(null);
  const [showCapabilitiesModal, setShowCapabilitiesModal] = useState<boolean>(false);
  const [showPlaybookModal, setShowPlaybookModal] = useState<boolean>(false);
  const [playbookTargetRec, setPlaybookTargetRec] = useState<ResponseRecommendation | null>(null);

  // Load recommendations and capabilities
  const fetchRecommendations = async () => {
    setLoading(true);
    setError(null);
    try {
      const recsRes = await apiFetch(apiUrl(`/api/v1/recommendations/by-scope/${scopeType}/${effectiveScopeId}`));
      if (recsRes.ok) {
        const data = await recsRes.json();
        setRecommendations(data.recommendations || []);
      } else {
        setRecommendations([]);
      }

      const capsRes = await apiFetch(apiUrl('/api/v1/recommendations/capabilities'));
      if (capsRes.ok) {
        const caps = await capsRes.json();
        setCapabilities(caps || []);
      }

      const ovRes = await apiFetch(apiUrl(`/api/v1/recommendations/summary/${scopeType}/${effectiveScopeId}`));
      if (ovRes.ok) {
        const ov = await ovRes.json();
        setOverview(ov);
      }
    } catch (err: any) {
      console.warn('Failed to load recommendation data from backend:', err);
      // Fallback demo generation if local server is unreachable
      if (recommendations.length === 0 && email) {
        generateSyntheticFallback();
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (effectiveScopeId) {
      fetchRecommendations();
    }
  }, [effectiveScopeId, scopeType]);

  const handleGenerate = async () => {
    setGenerating(true);
    setError(null);
    try {
      const payload: Record<string, any> = {
        workspace_id: 'default',
        scope_type: scopeType,
        scope_id: effectiveScopeId,
        threat_event_id: threatEventId || email?.evidence_id || email?.id,
        incident_id: incidentId,
        risk_assessment_id: riskAssessmentId,
        explanation_id: explanationId
      };

      if (email) {
        payload.email_context = {
          subject: email.subject || 'Investigation Target',
          sender: email.from || 'unknown',
          recipient: email.to || 'unknown',
          threat_level: email.threat_score?.severity?.toUpperCase() || 'LOW',
          findings_count: email.threat_score?.reasons?.length || 0,
          urls: email.urls || [],
          has_attachments: (email.attachments?.length || 0) > 0
        };
      }

      const res = await apiFetch(apiUrl('/api/v1/recommendations/generate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (res.ok) {
        const data = await res.json();
        setRecommendations(data.recommendations || []);
        // Refresh overview
        const ovRes = await apiFetch(apiUrl(`/api/v1/recommendations/summary/${scopeType}/${effectiveScopeId}`));
        if (ovRes.ok) {
          const ov = await ovRes.json();
          setOverview(ov);
        }
      } else {
        const errJson = await res.json().catch(() => ({}));
        setError(errJson.detail || 'Failed to generate recommendations');
      }
    } catch (err: any) {
      setError(err.message || 'Network error triggering recommendation generation');
    } finally {
      setGenerating(false);
    }
  };

  const generateSyntheticFallback = () => {
    // Graceful fallback for offline demo view
    const isHighThreat = email?.threat_score?.severity === 'critical' || email?.threat_score?.severity === 'high';
    const fallbackList: ResponseRecommendation[] = [
      {
        id: `REC-FALLBACK-01`,
        workspace_id: 'default',
        scope_type: scopeType,
        scope_id: effectiveScopeId,
        action_type: 'PRESERVE_EMAIL',
        category: 'EVIDENCE_PRESERVATION',
        title: 'Preserve immutable original email raw artifact',
        description: 'Preserve raw RFC822 message payload and cryptographic headers in tamper-evident forensic vault.',
        rationale: 'High forensic value and active campaign attribution requirements mandate evidentiary preservation.',
        priority: 'P0',
        urgency: 'IMMEDIATE',
        expected_effect: 'Secures cryptographic chain of custody before message is modified or purged.',
        prerequisites: [{ name: 'RAW_MAIL_AVAILABLE', description: 'Original payload is present in ingest store', satisfied: true }],
        affected_entities: [{ entity_type: 'email', identifier: email?.subject || 'Target Email', role: 'evidence_source' }],
        evidence_refs: ['EV-RAW-001', 'EV-AUTH-002'],
        risk_refs: ['RISK-CRIT-01'],
        attack_path_refs: [],
        mitre_refs: ['T1566.001'],
        confidence: 0.98,
        confidence_level: 'VERY_HIGH',
        applicability: 'APPLICABLE',
        applicability_reason: 'Raw message exists in forensic pipeline.',
        reversibility: 'REVERSIBLE',
        impact: 'NONE',
        approval_required: false,
        safety_class: 'INFORMATIONAL',
        execution_mode: 'HUMAN_IN_THE_LOOP',
        status: 'REVIEW_REQUIRED',
        recommendation_version: 1,
        depends_on: [],
        conflicts_with: [],
        metadata: {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      },
      {
        id: `REC-FALLBACK-02`,
        workspace_id: 'default',
        scope_type: scopeType,
        scope_id: effectiveScopeId,
        action_type: isHighThreat ? 'BLOCK_DOMAIN' : 'REVIEW_AUTHENTICATION',
        category: isHighThreat ? 'CONTAINMENT' : 'INVESTIGATION',
        title: isHighThreat ? 'Consider DNS sinkhole or perimeter domain block' : 'Review sender authentication and cryptographic alignment',
        description: isHighThreat
          ? 'Add identified external command & control / harvesting domain to security perimeter blocklists.'
          : 'Inspect SPF, DKIM, and DMARC alignment records to detect spoofing.',
        rationale: isHighThreat
          ? 'Domain matches credential harvesting infrastructure with critical risk score.'
          : 'Authentication verification needed to validate sender legitimacy.',
        priority: isHighThreat ? 'P1' : 'P3',
        urgency: isHighThreat ? 'URGENT' : 'NORMAL',
        expected_effect: isHighThreat ? 'Prevents organizational endpoints from resolving malicious host.' : 'Validates sender identity.',
        prerequisites: [{ name: 'DOMAIN_RESOLVED', description: 'Destination domain identified in evidence', satisfied: true }],
        affected_entities: [{ entity_type: 'domain', identifier: email?.from?.split('@')[1] || 'malicious-domain.com', role: 'target' }],
        evidence_refs: ['EV-URL-001'],
        risk_refs: ['RISK-SCORE-92'],
        attack_path_refs: [],
        mitre_refs: ['T1071.001'],
        confidence: 0.89,
        confidence_level: 'HIGH',
        applicability: 'APPLICABLE',
        applicability_reason: 'Domain identified in extracted indicators.',
        reversibility: 'REVERSIBLE',
        impact: isHighThreat ? 'MEDIUM' : 'NONE',
        approval_required: isHighThreat,
        safety_class: isHighThreat ? 'CONTAINMENT' : 'INFORMATIONAL',
        execution_mode: 'HUMAN_IN_THE_LOOP',
        status: 'REVIEW_REQUIRED',
        recommendation_version: 1,
        depends_on: ['REC-FALLBACK-01'],
        conflicts_with: [],
        metadata: {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      }
    ];
    setRecommendations(fallbackList);
  };

  const handleRecommendationUpdated = (updated: ResponseRecommendation) => {
    setRecommendations(prev => prev.map(r => (r.id === updated.id ? updated : r)));
    if (selectedRecommendation?.id === updated.id) {
      setSelectedRecommendation(updated);
    }
  };

  // Filtered list
  const filteredRecommendations = useMemo(() => {
    return recommendations.filter(rec => {
      if (selectedCategory !== 'ALL' && rec.category !== selectedCategory) return false;
      if (selectedPriority !== 'ALL' && rec.priority !== selectedPriority) return false;
      if (selectedStatus !== 'ALL' && rec.status !== selectedStatus) return false;
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const inTitle = rec.title.toLowerCase().includes(query);
        const inDesc = rec.description.toLowerCase().includes(query);
        const inAction = rec.action_type.toLowerCase().includes(query);
        const inEntities = rec.affected_entities.some(e => e.identifier.toLowerCase().includes(query));
        if (!inTitle && !inDesc && !inAction && !inEntities) return false;
      }
      return true;
    });
  }, [recommendations, selectedCategory, selectedPriority, selectedStatus, searchQuery]);

  // Priority counts
  const p0Count = recommendations.filter(r => r.priority === 'P0').length;
  const p1Count = recommendations.filter(r => r.priority === 'P1').length;
  const approvalRequiredCount = recommendations.filter(r => r.approval_required).length;
  const pendingReviewCount = recommendations.filter(r => r.status === 'REVIEW_REQUIRED').length;

  const categories: { key: string; label: string }[] = [
    { key: 'ALL', label: 'All Categories' },
    { key: 'IMMEDIATE', label: 'Immediate Action' },
    { key: 'CONTAINMENT', label: 'Containment' },
    { key: 'EVIDENCE_PRESERVATION', label: 'Evidence Preservation' },
    { key: 'IDENTITY_SECURITY', label: 'Identity & Access' },
    { key: 'INVESTIGATION', label: 'Investigation' },
    { key: 'COMMUNICATION', label: 'Communication' },
    { key: 'RECOVERY', label: 'Recovery' }
  ];

  const getPriorityBadge = (p: RecommendationPriority) => {
    switch (p) {
      case 'P0':
        return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
      case 'P1':
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
      case 'P2':
        return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
      case 'P3':
        return 'bg-blue-500/15 text-blue-400 border-blue-500/30';
      case 'P4':
      default:
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
    }
  };

  const getStatusBadge = (status: RecommendationStatus) => {
    switch (status) {
      case 'APPROVED':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'REJECTED':
        return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
      case 'DEFERRED':
        return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
      case 'EXPIRED':
      case 'SUPERSEDED':
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
      case 'REVIEW_REQUIRED':
      case 'GENERATED':
      default:
        return 'bg-primary/15 text-primary border-primary/30';
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* 1. ADVISORY SAFETY BOUNDARY BANNER */}
      <div className="bg-gradient-to-r from-surface-secondary/80 via-surface to-surface-secondary/80 rounded-xl border border-border p-4.5 shadow-xs relative overflow-hidden">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-start space-x-3.5">
            <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/25 text-amber-400 shrink-0 mt-0.5">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-amber-400">
                  Defensive Response Recommendations
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface border border-border text-foreground-muted">
                  Advisory Layer · Section 28
                </span>
              </div>
              <h3 className="text-sm font-semibold font-sans text-foreground">
                Deterministic Defensive Proposals with Explicit Human Approval Boundary
              </h3>
              <p className="text-xs font-mono text-foreground-muted max-w-3xl leading-relaxed">
                CyberGuard recommends actionable next steps based on authoritative risk, XAI evidence, and attack paths.
                <span className="text-foreground font-semibold"> Consequential containment actions are strictly advisory </span>
                and require human analyst sign-off before being dispatched to future Section 29 Playbooks.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 shrink-0 self-end sm:self-center">
            <button
              type="button"
              onClick={() => setShowCapabilitiesModal(true)}
              className="px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-xs font-mono text-foreground flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <Cpu className="w-3.5 h-3.5 text-primary" />
              <span>Capabilities ({capabilities.length || 6})</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setPlaybookTargetRec(recommendations[0] || null);
                setShowPlaybookModal(true);
              }}
              className="px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-emerald-500/30 text-xs font-mono text-emerald-400 flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 text-emerald-400" />
              <span>Playbooks (Sec 29)</span>
            </button>
            <button
              type="button"
              onClick={handleGenerate}
              disabled={generating}
              className="px-3.5 py-1.5 rounded-lg bg-primary hover:bg-primary-hover text-primary-foreground text-xs font-mono font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer shadow-xs disabled:opacity-50"
            >
              <Sparkles className={`w-3.5 h-3.5 ${generating ? 'animate-spin' : ''}`} />
              <span>{generating ? 'Evaluating...' : 'Re-Evaluate Context'}</span>
            </button>
            <button
              type="button"
              onClick={fetchRecommendations}
              disabled={loading}
              className="p-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground-muted hover:text-foreground transition-colors cursor-pointer"
              title="Refresh"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            </button>
          </div>
        </div>
      </div>

      {/* ERROR ALERT BANNER */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-mono flex items-center justify-between">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)} className="text-rose-400 hover:text-white cursor-pointer">
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* 2. KPI / SUMMARY METRICS STRIP */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] text-foreground-muted block">Total Recommendations</span>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold text-foreground">{recommendations.length}</span>
              {overview && (
                <span className="text-[10px] text-foreground-muted">({overview.scope_type})</span>
              )}
            </div>
          </div>
          <div className="w-8 h-8 rounded-lg bg-primary/10 border border-primary/20 text-primary flex items-center justify-center">
            <Layers className="w-4 h-4" />
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] text-foreground-muted block">P0 / P1 Urgent Actions</span>
            <div className="flex items-center space-x-1.5">
              <span className="text-lg font-bold text-rose-400">{p0Count}</span>
              <span className="text-xs text-foreground-muted">/</span>
              <span className="text-lg font-bold text-amber-400">{p1Count}</span>
            </div>
          </div>
          <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-center justify-center">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] text-foreground-muted block">Approval Required</span>
            <span className="text-lg font-bold text-yellow-400">{approvalRequiredCount}</span>
          </div>
          <div className="w-8 h-8 rounded-lg bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 flex items-center justify-center">
            <Lock className="w-4 h-4" />
          </div>
        </div>

        <div className="p-3.5 rounded-xl bg-surface border border-border shadow-xs flex items-center justify-between">
          <div className="space-y-0.5">
            <span className="text-[11px] text-foreground-muted block">Awaiting Review</span>
            <span className="text-lg font-bold text-primary">{pendingReviewCount}</span>
          </div>
          <div className="w-8 h-8 rounded-lg bg-surface-secondary border border-border text-foreground-muted flex items-center justify-center">
            <Clock className="w-4 h-4" />
          </div>
        </div>
      </div>

      {/* 3. FILTER BAR */}
      <div className="bg-surface rounded-xl border border-border p-3 shadow-xs space-y-3 font-mono text-xs">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          {/* Category Tabs */}
          <div className="flex flex-wrap items-center gap-1.5">
            {categories.map(cat => (
              <button
                key={cat.key}
                type="button"
                onClick={() => setSelectedCategory(cat.key)}
                className={`px-2.5 py-1 rounded-lg text-[11px] transition-all cursor-pointer ${
                  selectedCategory === cat.key
                    ? 'bg-primary text-primary-foreground font-semibold shadow-xs'
                    : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary border border-transparent'
                }`}
              >
                {cat.label}
              </button>
            ))}
          </div>

          {/* Search box */}
          <div className="relative min-w-[200px]">
            <Search className="w-3.5 h-3.5 text-foreground-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search actions, entities..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-surface-secondary border border-border text-xs font-mono text-foreground placeholder:text-foreground-muted focus:outline-none focus:border-primary"
            />
          </div>
        </div>

        {/* Priority & Status Subfilters */}
        <div className="pt-2 border-t border-border/60 flex flex-wrap items-center justify-between gap-3 text-[11px]">
          <div className="flex items-center space-x-3">
            <span className="text-foreground-muted">Priority:</span>
            <div className="flex items-center space-x-1">
              {['ALL', 'P0', 'P1', 'P2', 'P3', 'P4'].map(p => (
                <button
                  key={p}
                  type="button"
                  onClick={() => setSelectedPriority(p)}
                  className={`px-2 py-0.5 rounded cursor-pointer ${
                    selectedPriority === p
                      ? 'bg-surface-secondary text-foreground font-bold border border-border'
                      : 'text-foreground-muted hover:text-foreground'
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center space-x-3">
            <span className="text-foreground-muted">Status:</span>
            <div className="flex items-center space-x-1">
              {['ALL', 'REVIEW_REQUIRED', 'APPROVED', 'REJECTED', 'DEFERRED'].map(s => (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSelectedStatus(s)}
                  className={`px-2 py-0.5 rounded cursor-pointer ${
                    selectedStatus === s
                      ? 'bg-surface-secondary text-foreground font-bold border border-border'
                      : 'text-foreground-muted hover:text-foreground'
                  }`}
                >
                  {s.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 4. RECOMMENDATIONS LIST */}
      {loading ? (
        <div className="p-12 text-center rounded-xl bg-surface border border-border space-y-3 font-mono text-xs">
          <RefreshCw className="w-6 h-6 text-primary animate-spin mx-auto" />
          <p className="text-foreground-muted">Analyzing forensic evidence & synthesizing defensive recommendations...</p>
        </div>
      ) : filteredRecommendations.length === 0 ? (
        <div className="p-12 text-center rounded-xl bg-surface border border-border space-y-3 font-mono text-xs">
          <Layers className="w-8 h-8 text-foreground-muted mx-auto" />
          <p className="text-foreground font-semibold">No recommendations match the current filter criteria.</p>
          <p className="text-foreground-muted text-[11px] max-w-md mx-auto">
            Try adjusting your category or priority filters, or click "Re-Evaluate Context" to generate fresh recommendations.
          </p>
          <button
            type="button"
            onClick={handleGenerate}
            className="px-4 py-2 rounded-xl bg-primary text-primary-foreground font-semibold cursor-pointer shadow-xs"
          >
            Generate Recommendations Now
          </button>
        </div>
      ) : (
        <div className="space-y-3">
          {filteredRecommendations.map(rec => (
            <div
              key={rec.id}
              className="bg-surface rounded-xl border border-border hover:border-primary/40 transition-all p-4.5 shadow-xs space-y-3.5 font-mono text-xs"
            >
              {/* Header row: Priority, Category, Status, Action Type */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${getPriorityBadge(
                      rec.priority
                    )}`}
                  >
                    {rec.priority} · {rec.urgency}
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] bg-surface-secondary text-foreground-muted border border-border uppercase">
                    {rec.category.replace('_', ' ')}
                  </span>
                  <span className="text-[11px] font-bold text-primary font-mono">{rec.action_type}</span>
                </div>

                <div className="flex items-center space-x-2">
                  {rec.approval_required ? (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-yellow-500/10 border border-yellow-500/30 text-yellow-400 font-semibold flex items-center space-x-1">
                      <Lock className="w-2.5 h-2.5" />
                      <span>Approval Required</span>
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded text-[10px] bg-surface-secondary text-foreground-muted border border-border">
                      Advisory
                    </span>
                  )}
                  <span className={`px-2 py-0.5 rounded text-[10px] border font-bold uppercase ${getStatusBadge(rec.status)}`}>
                    {rec.status.replace('_', ' ')}
                  </span>
                </div>
              </div>

              {/* Title & Description */}
              <div className="space-y-1">
                <h4 className="text-sm font-semibold font-sans text-foreground">{rec.title}</h4>
                <p className="text-xs text-foreground-muted leading-relaxed">{rec.description}</p>
              </div>

              {/* Affected Entities & Evidence Refs */}
              {(rec.affected_entities.length > 0 || rec.evidence_refs.length > 0) && (
                <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-border/40 text-[11px]">
                  {rec.affected_entities.length > 0 && (
                    <div className="flex items-center space-x-1.5">
                      <span className="text-foreground-muted">Targets:</span>
                      {rec.affected_entities.map((e, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.5 rounded bg-surface-secondary border border-border text-foreground font-mono"
                        >
                          {e.entity_type}: <span className="font-semibold text-primary">{e.identifier}</span>
                        </span>
                      ))}
                    </div>
                  )}

                  {rec.evidence_refs.length > 0 && (
                    <div className="flex items-center space-x-1.5 ml-auto">
                      <span className="text-foreground-muted">Evidence:</span>
                      {rec.evidence_refs.map((ev, idx) => (
                        <span
                          key={idx}
                          className="px-1.5 py-0.2 rounded bg-surface-secondary border border-border text-foreground-muted text-[10px]"
                        >
                          {ev}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Footer row: Reversibility, Impact, Action Buttons */}
              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-border/60 text-[11px]">
                <div className="flex flex-wrap items-center gap-3 text-foreground-muted">
                  <span>
                    Reversibility: <strong className="text-foreground">{rec.reversibility}</strong>
                  </span>
                  <span>·</span>
                  <span>
                    Impact: <strong className="text-foreground">{rec.impact}</strong>
                  </span>
                  <span>·</span>
                  <span>
                    Confidence: <strong className="text-foreground">{Math.round(rec.confidence * 100)}%</strong>
                  </span>
                  {rec.depends_on && rec.depends_on.length > 0 && (
                    <>
                      <span>·</span>
                      <span className="text-amber-400 font-semibold flex items-center space-x-1">
                        <GitBranch className="w-3 h-3" />
                        <span>Depends on {rec.depends_on.length} item(s)</span>
                      </span>
                    </>
                  )}
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    type="button"
                    onClick={() => {
                      setPlaybookTargetRec(rec);
                      setShowPlaybookModal(true);
                    }}
                    className="px-2.5 py-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 font-mono text-xs font-bold flex items-center space-x-1 transition-colors cursor-pointer"
                    title="Simulate or execute response playbook for this recommendation"
                  >
                    <Play className="w-3 h-3" />
                    <span>Run Playbook</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedRecommendation(rec)}
                    className="px-3 py-1.5 rounded-lg bg-surface-secondary hover:bg-surface border border-border text-foreground font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
                  >
                    <Eye className="w-3.5 h-3.5 text-primary" />
                    <span>Inspect Rationale & Review</span>
                    <ArrowRight className="w-3 h-3 text-foreground-muted" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* 5. CAPABILITY REGISTRY MODAL */}
      {showCapabilitiesModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs font-mono">
          <div className="bg-surface rounded-xl border border-border w-full max-w-2xl shadow-xl overflow-hidden flex flex-col max-h-[85vh]">
            <div className="p-4 border-b border-border flex items-center justify-between bg-surface-secondary/40">
              <div className="flex items-center space-x-2">
                <Cpu className="w-4 h-4 text-primary" />
                <h3 className="text-sm font-bold text-foreground">Defensive Capabilities Registry</h3>
              </div>
              <button
                type="button"
                onClick={() => setShowCapabilitiesModal(false)}
                className="p-1 rounded-lg text-foreground-muted hover:text-foreground hover:bg-surface transition-colors cursor-pointer"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <div className="p-5 overflow-y-auto space-y-4 text-xs">
              <p className="text-foreground-muted text-[11px] leading-relaxed">
                CyberGuard will not recommend execution-ready containment actions unless the environment provider is
                actively configured and available. The state of defensive capabilities determines whether an action is marked
                <span className="text-emerald-400 font-bold"> APPLICABLE</span>,
                <span className="text-yellow-400 font-bold"> REQUIRES_CONFIGURATION</span>, or
                <span className="text-rose-400 font-bold"> UNAVAILABLE</span>.
              </p>

              <div className="space-y-2">
                {capabilities.length === 0 ? (
                  <div className="p-6 text-center text-foreground-muted">Loading registered capabilities...</div>
                ) : (
                  capabilities.map(cap => (
                    <div
                      key={cap.id}
                      className="p-3 rounded-lg bg-surface-secondary/40 border border-border flex items-center justify-between gap-3"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center space-x-2">
                          <span className="font-bold text-foreground">{cap.action_type}</span>
                          <span className="text-[10px] text-foreground-muted">via {cap.provider}</span>
                        </div>
                        <span className="text-[10px] text-foreground-muted block">
                          Env: {cap.environment} · {cap.reversible ? 'Reversible' : 'Irreversible'}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2 shrink-0">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                            cap.capability_state === 'AVAILABLE'
                              ? 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30'
                              : cap.capability_state === 'REQUIRES_CONFIGURATION'
                              ? 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30'
                              : 'bg-rose-500/15 text-rose-400 border-rose-500/30'
                          }`}
                        >
                          {cap.capability_state.replace('_', ' ')}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

            <div className="p-4 border-t border-border flex justify-end bg-surface-secondary/20">
              <button
                type="button"
                onClick={() => setShowCapabilitiesModal(false)}
                className="px-4 py-2 rounded-lg bg-surface border border-border text-foreground text-xs font-semibold cursor-pointer"
              >
                Close Registry
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 6. ACTION DETAIL & REVIEW MODAL */}
      {selectedRecommendation && (
        <ActionDetailModal
          recommendation={selectedRecommendation}
          onClose={() => setSelectedRecommendation(null)}
          onStatusUpdated={handleRecommendationUpdated}
        />
      )}

      {/* 7. RESPONSE PLAYBOOK EXECUTION & SIMULATION MODAL */}
      {showPlaybookModal && (
        <PlaybookExecutionModal
          recommendation={playbookTargetRec}
          onClose={() => {
            setShowPlaybookModal(false);
            setPlaybookTargetRec(null);
          }}
          onExecutionCompleted={() => fetchRecommendations()}
        />
      )}
    </div>
  );
};
