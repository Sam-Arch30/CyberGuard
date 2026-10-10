import React, { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import {
  ShieldAlert,
  ArrowLeft,
  RefreshCw,
  Clock,
  User,
  AlertTriangle,
  CheckCircle2,
  Lock,
  ArrowUpRight,
  ShieldCheck,
  Send,
  FileText,
  Activity,
  Copy,
  Check,
  CheckCircle,
  ExternalLink,
  ChevronDown,
} from 'lucide-react';
import { IncidentService } from '../../services/incidentService';
import type {
  IncidentDetail,
  IncidentStatus,
  IncidentSeverity,
  IncidentPriority,
} from '../../types/incident';

const STATUS_CONFIG: Record<IncidentStatus, { label: string; badge: string }> = {
  NEW: { label: 'New', badge: 'bg-primary-subtle text-primary border-primary/30' },
  OPEN: { label: 'Open', badge: 'bg-surface-secondary text-foreground border-border' },
  ACKNOWLEDGED: { label: 'Acknowledged', badge: 'bg-info-surface text-info border-info-border' },
  INVESTIGATING: { label: 'Investigating', badge: 'bg-warning-surface text-warning border-warning-border' },
  CONTAINED: { label: 'Contained', badge: 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30' },
  RESOLVED: { label: 'Resolved', badge: 'bg-success-surface text-success border-success-border' },
  CLOSED: { label: 'Closed', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  FALSE_POSITIVE: { label: 'False Positive', badge: 'bg-surface-secondary text-foreground-muted border-border line-through' },
  DUPLICATE: { label: 'Duplicate', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  CANCELLED: { label: 'Cancelled', badge: 'bg-surface-secondary text-foreground-muted border-border' },
};

const SEVERITY_CONFIG: Record<IncidentSeverity, { label: string; badge: string }> = {
  CRITICAL: { label: 'Critical', badge: 'bg-danger-surface text-danger border-danger-border font-bold' },
  HIGH: { label: 'High', badge: 'bg-warning-surface text-warning border-warning-border font-semibold' },
  MEDIUM: { label: 'Medium', badge: 'bg-warning-surface/60 text-warning border-warning-border/60' },
  LOW: { label: 'Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
  INFO: { label: 'Info', badge: 'bg-surface-secondary text-foreground-muted border-border' },
};

const PRIORITY_CONFIG: Record<IncidentPriority, { label: string; badge: string }> = {
  P1_CRITICAL: { label: 'P1 - Critical', badge: 'bg-red-500/20 text-red-400 border-red-500/40 font-bold' },
  P2_HIGH: { label: 'P2 - High', badge: 'bg-amber-500/20 text-amber-400 border-amber-500/40 font-semibold' },
  P3_MEDIUM: { label: 'P3 - Medium', badge: 'bg-blue-500/20 text-blue-400 border-blue-500/40' },
  P4_LOW: { label: 'P4 - Low', badge: 'bg-surface-secondary text-foreground-muted border-border' },
};

export const IncidentDetailPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  // Active Tab
  const [activeTab, setActiveTab] = useState<'facts' | 'alerts' | 'timeline' | 'notes' | 'handoff'>('facts');

  // Modals / Inputs
  const [showResolveModal, setShowResolveModal] = useState<boolean>(false);
  const [resolveCategory, setResolveCategory] = useState<string>('THREAT_CONTAINED');
  const [resolveReason, setResolveReason] = useState<string>('');

  const [showContainModal, setShowContainModal] = useState<boolean>(false);
  const [containReason, setContainReason] = useState<string>('');

  const [showReopenModal, setShowReopenModal] = useState<boolean>(false);
  const [reopenReason, setReopenReason] = useState<string>('');

  const [showAssignModal, setShowAssignModal] = useState<boolean>(false);
  const [assigneeName, setAssigneeName] = useState<string>('');

  // Note submission
  const [newNoteText, setNewNoteText] = useState<string>('');
  const [submittingNote, setSubmittingNote] = useState<boolean>(false);

  const loadIncident = useCallback(async () => {
    if (!id) return;
    try {
      setLoading(true);
      setError(null);
      const res = await IncidentService.getIncidentDetail(id);
      setIncident(res);
      setAssigneeName(res.assigned_to || '');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load incident detail.');
    } finally {
      setLoading(false);
    }
  }, [id]);

  useEffect(() => {
    loadIncident();
  }, [loadIncident]);

  const handleCopyNumber = () => {
    if (!incident) return;
    navigator.clipboard.writeText(incident.incident_number);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Quick State Transitions
  const handleAcknowledge = async () => {
    if (!incident) return;
    try {
      setActionLoading(true);
      await IncidentService.updateStatus(incident.id, {
        status: 'ACKNOWLEDGED',
        reason: 'Analyst acknowledged incident via detail workspace.',
      });
      await loadIncident();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to acknowledge incident.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleInvestigate = async () => {
    if (!incident) return;
    try {
      setActionLoading(true);
      if (incident.status === 'NEW' || incident.status === 'OPEN' || incident.status === 'ACKNOWLEDGED') {
        await IncidentService.updateStatus(incident.id, {
          status: 'INVESTIGATING',
          reason: 'Analyst commenced forensic investigation.',
        });
      }
      if (incident.investigation_id) {
        navigate(`/investigations/${incident.investigation_id}`);
      } else {
        await loadIncident();
      }
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to update status.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleContainSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    try {
      setActionLoading(true);
      await IncidentService.updateStatus(incident.id, {
        status: 'CONTAINED',
        reason: containReason.trim() || 'Threat indicators contained and host isolated.',
      });
      setShowContainModal(false);
      setContainReason('');
      await loadIncident();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to mark contained.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleResolveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    try {
      setActionLoading(true);
      await IncidentService.resolveIncident(
        incident.id,
        resolveCategory,
        resolveReason.trim() || undefined
      );
      setShowResolveModal(false);
      setResolveReason('');
      await loadIncident();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to resolve incident.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleClose = async () => {
    if (!incident) return;
    if (!window.confirm('Are you sure you want to close this resolved incident?')) return;
    try {
      setActionLoading(true);
      await IncidentService.closeIncident(incident.id, 'Post-incident review complete.');
      await loadIncident();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to close incident.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleReopenSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !reopenReason.trim()) return;
    try {
      setActionLoading(true);
      await IncidentService.reopenIncident(incident.id, reopenReason.trim());
      setShowReopenModal(false);
      setReopenReason('');
      await loadIncident();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to reopen incident.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleAssignSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident) return;
    try {
      setActionLoading(true);
      await IncidentService.assignIncident(incident.id, {
        assigned_to: assigneeName.trim() || null,
        reason: 'Analyst assigned via incident header toolbar.',
      });
      setShowAssignModal(false);
      await loadIncident();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to update assignment.');
    } finally {
      setActionLoading(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incident || !newNoteText.trim()) return;
    try {
      setSubmittingNote(true);
      await IncidentService.addNote(incident.id, {
        note_text: newNoteText.trim(),
      });
      setNewNoteText('');
      await loadIncident();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to append note.');
    } finally {
      setSubmittingNote(false);
    }
  };

  if (loading && !incident) {
    return (
      <div className="py-24 text-center text-foreground-muted flex flex-col items-center justify-center space-y-3">
        <RefreshCw className="w-6 h-6 animate-spin text-primary" />
        <span className="text-sm font-medium">Loading operational case data...</span>
      </div>
    );
  }

  if (error || !incident) {
    return (
      <div className="p-8 max-w-xl mx-auto text-center space-y-4">
        <div className="p-3 bg-danger-surface border border-danger-border rounded-control text-danger inline-flex">
          <AlertTriangle className="w-8 h-8" />
        </div>
        <h2 className="text-lg font-bold text-foreground">Incident Case Not Found</h2>
        <p className="text-xs text-foreground-muted">{error || 'The requested incident could not be retrieved.'}</p>
        <button
          type="button"
          onClick={() => navigate('/incidents')}
          className="px-4 py-2 text-xs font-semibold bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface cursor-pointer"
        >
          Return to Incident Queue
        </button>
      </div>
    );
  }

  const statusCfg = STATUS_CONFIG[incident.status] || STATUS_CONFIG.OPEN;
  const sevCfg = SEVERITY_CONFIG[incident.severity] || SEVERITY_CONFIG.MEDIUM;
  const prioCfg = PRIORITY_CONFIG[incident.priority] || PRIORITY_CONFIG.P3_MEDIUM;

  const isTerminal =
    incident.status === 'RESOLVED' ||
    incident.status === 'CLOSED' ||
    incident.status === 'FALSE_POSITIVE' ||
    incident.status === 'DUPLICATE';

  return (
    <div className="space-y-6">
      {/* 1. Top Navigation Bar */}
      <div className="flex items-center justify-between">
        <button
          type="button"
          onClick={() => navigate('/incidents')}
          className="text-xs text-foreground-muted hover:text-foreground flex items-center space-x-1 cursor-pointer transition-colors"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Incident Queue</span>
        </button>

        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={loadIncident}
            disabled={actionLoading}
            className="p-1.5 text-foreground-muted hover:text-foreground hover:bg-surface-secondary rounded-control cursor-pointer"
            title="Refresh incident"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${actionLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* 2. Main Incident Header Card */}
      <div className="p-5 bg-surface border border-border rounded-control shadow-xs space-y-4">
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs font-bold text-foreground bg-surface-secondary px-2 py-0.5 rounded-xs border border-border flex items-center space-x-1">
                <span>{incident.incident_number}</span>
                <button
                  type="button"
                  onClick={handleCopyNumber}
                  className="hover:text-primary transition-colors cursor-pointer ml-1"
                  title="Copy incident ID"
                >
                  {copied ? <Check className="w-3 h-3 text-success" /> : <Copy className="w-3 h-3" />}
                </button>
              </span>

              <span className={`px-2 py-0.5 rounded-xs border text-[10px] ${sevCfg.badge}`}>
                {sevCfg.label}
              </span>

              <span className={`px-2 py-0.5 rounded-xs border text-[10px] ${prioCfg.badge}`}>
                {prioCfg.label}
              </span>

              <span className={`px-2 py-0.5 rounded-xs border text-[10px] ${statusCfg.badge}`}>
                {statusCfg.label}
              </span>

              <span className="text-[10px] font-mono text-foreground-muted uppercase">
                {incident.category.replace(/_/g, ' ')}
              </span>
            </div>

            <h1 className="text-xl font-bold text-foreground mt-2">{incident.title}</h1>

            {incident.description && (
              <p className="text-xs text-foreground-muted max-w-3xl pt-1">{incident.description}</p>
            )}
          </div>

          {/* Action Toolbar */}
          <div className="flex flex-wrap items-center gap-2 shrink-0">
            {/* Assignment Trigger */}
            <button
              type="button"
              onClick={() => setShowAssignModal(true)}
              className="px-2.5 py-1.5 text-xs bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface flex items-center space-x-1.5 cursor-pointer"
            >
              <User className="w-3.5 h-3.5 text-foreground-muted" />
              <span>{incident.assigned_to ? incident.assigned_to : 'Assign Analyst'}</span>
              <ChevronDown className="w-3 h-3 text-foreground-muted" />
            </button>

            {/* Acknowledge Button */}
            {(incident.status === 'NEW' || incident.status === 'OPEN') && (
              <button
                type="button"
                onClick={handleAcknowledge}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-medium bg-info-surface text-info border border-info-border hover:bg-info/20 rounded-control cursor-pointer flex items-center space-x-1.5"
              >
                <CheckCircle className="w-3.5 h-3.5" />
                <span>Acknowledge</span>
              </button>
            )}

            {/* Investigate Button */}
            {incident.status !== 'INVESTIGATING' && !isTerminal && (
              <button
                type="button"
                onClick={handleInvestigate}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-medium bg-warning-surface text-warning border border-warning-border hover:bg-warning/20 rounded-control cursor-pointer flex items-center space-x-1.5"
              >
                <Activity className="w-3.5 h-3.5" />
                <span>Investigate</span>
              </button>
            )}

            {/* Contain Button */}
            {incident.status !== 'CONTAINED' && !isTerminal && (
              <button
                type="button"
                onClick={() => setShowContainModal(true)}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-medium bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 hover:bg-indigo-500/20 rounded-control cursor-pointer flex items-center space-x-1.5"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Contain</span>
              </button>
            )}

            {/* Resolve Button */}
            {!isTerminal && (
              <button
                type="button"
                onClick={() => setShowResolveModal(true)}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-semibold bg-success-surface text-success border border-success-border hover:bg-success/20 rounded-control cursor-pointer flex items-center space-x-1.5"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Resolve</span>
              </button>
            )}

            {/* Close Button */}
            {incident.status === 'RESOLVED' && (
              <button
                type="button"
                onClick={handleClose}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-medium bg-surface-secondary border border-border text-foreground hover:bg-surface rounded-control cursor-pointer flex items-center space-x-1.5"
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Close Case</span>
              </button>
            )}

            {/* Reopen Button */}
            {isTerminal && (
              <button
                type="button"
                onClick={() => setShowReopenModal(true)}
                disabled={actionLoading}
                className="px-3 py-1.5 text-xs font-medium bg-primary-subtle text-primary border border-primary/30 hover:bg-primary/20 rounded-control cursor-pointer flex items-center space-x-1.5"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Reopen Case</span>
              </button>
            )}
          </div>
        </div>

        {/* Facts Summary Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-3 pt-3 border-t border-border text-xs">
          <div>
            <span className="text-[10px] font-mono uppercase text-foreground-muted block">Case Age</span>
            <span className="font-semibold text-foreground flex items-center space-x-1 mt-0.5">
              <Clock className="w-3 h-3 text-foreground-muted" />
              <span>{incident.age_display}</span>
            </span>
          </div>

          <div>
            <span className="text-[10px] font-mono uppercase text-foreground-muted block">Related Alerts</span>
            <span className="font-semibold text-foreground mt-0.5 block">
              {incident.related_alerts.length}
            </span>
          </div>

          <div>
            <span className="text-[10px] font-mono uppercase text-foreground-muted block">Alert Clusters</span>
            <span className="font-semibold text-foreground mt-0.5 block">
              {incident.related_clusters.length}
            </span>
          </div>

          <div>
            <span className="text-[10px] font-mono uppercase text-foreground-muted block">Findings</span>
            <span className="font-semibold text-foreground mt-0.5 block">
              {incident.findings_summary.length}
            </span>
          </div>

          <div>
            <span className="text-[10px] font-mono uppercase text-foreground-muted block">Evidence Records</span>
            <span className="font-semibold text-foreground mt-0.5 block">
              {incident.evidence_summary.length}
            </span>
          </div>

          <div>
            <span className="text-[10px] font-mono uppercase text-foreground-muted block">Risk Score</span>
            <span className="font-semibold text-foreground mt-0.5 block">
              {incident.risk_score} / 100
            </span>
          </div>
        </div>
      </div>

      {/* 3. Next Best Action (Section 37) */}
      {incident.next_best_action && (
        <div className="p-4 bg-primary-subtle/50 border border-primary/30 rounded-control flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex items-start space-x-3">
            <div className="p-2 bg-primary/20 text-primary rounded-control shrink-0 mt-0.5">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-primary font-bold">
                  Recommended Next Action
                </span>
                <span className="text-[10px] font-mono px-1.5 py-0.2 bg-primary/20 text-primary rounded-xs">
                  {incident.next_best_action.action_type}
                </span>
              </div>
              <p className="text-xs font-semibold text-foreground mt-0.5">
                {incident.next_best_action.action}: <span className="font-mono">{incident.next_best_action.target}</span>
              </p>
              <p className="text-[11px] text-foreground-muted mt-0.5">
                {incident.next_best_action.reason}
              </p>
            </div>
          </div>

          <div className="shrink-0 flex items-center space-x-2">
            <button
              type="button"
              onClick={() => {
                if (incident.investigation_id) {
                  navigate(`/investigations/${incident.investigation_id}/response`);
                } else {
                  navigate('/response');
                }
              }}
              className="px-3 py-1.5 text-xs font-semibold bg-primary hover:bg-primary-hover text-white rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
            >
              <span>Review Playbook</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* 4. Tab Navigation */}
      <div className="border-b border-border flex items-center space-x-4 text-xs font-medium">
        <button
          type="button"
          onClick={() => setActiveTab('facts')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 ${
            activeTab === 'facts'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          Facts & Entities
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('alerts')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 flex items-center space-x-1.5 ${
            activeTab === 'alerts'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <span>Related Alerts & Clusters</span>
          <span className="px-1.5 py-0.2 rounded-full bg-surface-secondary text-[10px]">
            {incident.related_alerts.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('timeline')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 flex items-center space-x-1.5 ${
            activeTab === 'timeline'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <span>Case Timeline</span>
          <span className="px-1.5 py-0.2 rounded-full bg-surface-secondary text-[10px]">
            {incident.timeline_events.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('notes')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 flex items-center space-x-1.5 ${
            activeTab === 'notes'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          <span>Case Notes</span>
          <span className="px-1.5 py-0.2 rounded-full bg-surface-secondary text-[10px]">
            {incident.notes.length}
          </span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('handoff')}
          className={`pb-2.5 cursor-pointer transition-colors border-b-2 ${
            activeTab === 'handoff'
              ? 'border-primary text-primary font-semibold'
              : 'border-transparent text-foreground-muted hover:text-foreground'
          }`}
        >
          Investigation & Response
        </button>
      </div>

      {/* 5. Tab Panels */}

      {/* Tab: Facts & Entities */}
      {activeTab === 'facts' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Affected Entities */}
          <div className="p-4 bg-surface border border-border rounded-control space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Affected Entities
            </h3>

            <div className="space-y-2 text-xs">
              <div>
                <span className="text-[11px] text-foreground-muted block font-mono">Affected Users</span>
                {incident.affected_entities.users.length === 0 ? (
                  <span className="text-[11px] text-foreground-muted italic">None identified</span>
                ) : (
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {incident.affected_entities.users.map((u) => (
                      <span key={u} className="px-2 py-0.5 bg-surface-secondary border border-border rounded-xs font-mono text-[11px]">
                        {u}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] text-foreground-muted block font-mono">Endpoints</span>
                {incident.affected_entities.endpoints.length === 0 ? (
                  <span className="text-[11px] text-foreground-muted italic">None identified</span>
                ) : (
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {incident.affected_entities.endpoints.map((ep) => (
                      <span key={ep} className="px-2 py-0.5 bg-surface-secondary border border-border rounded-xs font-mono text-[11px]">
                        {ep}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] text-foreground-muted block font-mono">Domains & Infrastructure</span>
                {incident.affected_entities.domains.length === 0 ? (
                  <span className="text-[11px] text-foreground-muted italic">None identified</span>
                ) : (
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {incident.affected_entities.domains.map((d) => (
                      <span key={d} className="px-2 py-0.5 bg-surface-secondary border border-border rounded-xs font-mono text-[11px] text-danger">
                        {d}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              <div>
                <span className="text-[11px] text-foreground-muted block font-mono">IP Addresses</span>
                {incident.affected_entities.ips.length === 0 ? (
                  <span className="text-[11px] text-foreground-muted italic">None identified</span>
                ) : (
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {incident.affected_entities.ips.map((ip) => (
                      <span key={ip} className="px-2 py-0.5 bg-surface-secondary border border-border rounded-xs font-mono text-[11px]">
                        {ip}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Findings & Evidence Summary */}
          <div className="p-4 bg-surface border border-border rounded-control space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Findings & Authoritative Evidence
            </h3>

            <div>
              <span className="text-[11px] text-foreground-muted block font-mono mb-1">Key Findings</span>
              {incident.findings_summary.length === 0 ? (
                <span className="text-[11px] text-foreground-muted italic">No linked findings</span>
              ) : (
                <div className="space-y-1.5">
                  {incident.findings_summary.map((f) => (
                    <div key={f.id} className="p-2 bg-surface-secondary border border-border rounded-control flex items-center justify-between text-xs">
                      <span className="font-medium text-foreground">{f.title}</span>
                      <span className="px-1.5 py-0.2 text-[10px] font-mono uppercase bg-surface border border-border rounded-xs">
                        {f.severity}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="pt-2">
              <span className="text-[11px] text-foreground-muted block font-mono mb-1">Evidence Records</span>
              {incident.evidence_summary.length === 0 ? (
                <span className="text-[11px] text-foreground-muted italic">No linked evidence artifacts</span>
              ) : (
                <div className="space-y-1.5">
                  {incident.evidence_summary.map((e) => (
                    <div key={e.id} className="p-2 bg-surface-secondary border border-border rounded-control flex items-center justify-between text-xs">
                      <div>
                        <span className="font-mono text-foreground">{e.name || e.id}</span>
                        <span className="text-[10px] text-foreground-muted block">{e.type}</span>
                      </div>
                      {e.hash && (
                        <span className="text-[10px] font-mono text-foreground-muted max-w-[120px] truncate" title={e.hash}>
                          {e.hash}
                        </span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Tab: Related Alerts & Clusters */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          <div className="bg-surface border border-border rounded-control overflow-hidden">
            <div className="p-3 bg-surface-secondary/50 border-b border-border flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
                Contributing Security Alerts ({incident.related_alerts.length})
              </h3>
              <Link
                to="/alerts"
                className="text-xs text-primary hover:underline flex items-center space-x-1"
              >
                <span>View in Alert Workspace</span>
                <ArrowUpRight className="w-3 h-3" />
              </Link>
            </div>

            {incident.related_alerts.length === 0 ? (
              <div className="p-8 text-center text-foreground-muted text-xs">
                No alerts associated with this incident.
              </div>
            ) : (
              <div className="divide-y divide-border text-xs">
                {incident.related_alerts.map((alt) => (
                  <div key={alt.id} className="p-3 flex items-center justify-between hover:bg-surface-secondary/40 transition-colors">
                    <div className="space-y-0.5">
                      <div className="flex items-center space-x-2">
                        <Link
                          to={`/alerts/${alt.id}`}
                          className="font-semibold text-foreground hover:text-primary transition-colors"
                        >
                          {alt.title}
                        </Link>
                        <span className="px-1.5 py-0.2 text-[10px] font-mono rounded-xs border border-border bg-surface">
                          {alt.severity}
                        </span>
                        <span className="px-1.5 py-0.2 text-[10px] font-mono rounded-xs border border-border bg-surface text-foreground-muted">
                          {alt.status}
                        </span>
                      </div>
                      <div className="text-[10px] text-foreground-muted font-mono">
                        ID: {alt.id} • Category: {alt.category} • Detected: {new Date(alt.created_at).toLocaleString()}
                      </div>
                    </div>

                    <Link
                      to={`/alerts/${alt.id}`}
                      className="p-1 text-foreground-muted hover:text-foreground rounded-control"
                      title="View Alert"
                    >
                      <ExternalLink className="w-4 h-4" />
                    </Link>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Related Clusters */}
          {incident.related_clusters.length > 0 && (
            <div className="bg-surface border border-border rounded-control overflow-hidden">
              <div className="p-3 bg-surface-secondary/50 border-b border-border">
                <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
                  Associated Alert Clusters ({incident.related_clusters.length})
                </h3>
              </div>
              <div className="divide-y divide-border text-xs">
                {incident.related_clusters.map((cl) => (
                  <div key={cl.id} className="p-3 flex items-center justify-between">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-semibold text-foreground">{cl.title}</span>
                        <span className="px-1.5 py-0.2 text-[10px] font-mono rounded-xs border border-border bg-surface text-indigo-400">
                          {cl.member_count} alerts
                        </span>
                      </div>
                      <div className="text-[10px] text-foreground-muted font-mono mt-0.5">
                        Cluster ID: {cl.id} • Status: {cl.status}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab: Timeline & History */}
      {activeTab === 'timeline' && (
        <div className="bg-surface border border-border rounded-control p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Immutable Case Timeline & Provenance
            </h3>
            <span className="text-[10px] font-mono text-foreground-muted">
              {incident.timeline_events.length} chronological audit events
            </span>
          </div>

          {incident.timeline_events.length === 0 ? (
            <div className="p-8 text-center text-foreground-muted text-xs">
              No timeline events recorded.
            </div>
          ) : (
            <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-border">
              {incident.timeline_events.map((evt) => (
                <div key={evt.id} className="relative group text-xs">
                  {/* Timeline dot */}
                  <div className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-primary border-2 border-surface" />

                  <div className="bg-surface-secondary/40 border border-border/80 rounded-control p-3 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-[11px] text-foreground">
                        {evt.event_type.replace(/_/g, ' ')}
                      </span>
                      <span className="text-[10px] font-mono text-foreground-muted">
                        {new Date(evt.timestamp).toLocaleString()}
                      </span>
                    </div>

                    <p className="text-xs text-foreground">{evt.summary}</p>

                    <div className="flex items-center space-x-3 text-[10px] text-foreground-muted font-mono pt-1">
                      <span>Actor: {evt.actor}</span>
                      <span>•</span>
                      <span>Source: {evt.source_type}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab: Case Notes */}
      {activeTab === 'notes' && (
        <div className="space-y-4">
          {/* Add Note Form */}
          <form onSubmit={handleAddNote} className="p-4 bg-surface border border-border rounded-control space-y-3">
            <h3 className="text-xs font-bold uppercase tracking-wider text-foreground">
              Append Analyst Note
            </h3>
            <textarea
              rows={3}
              required
              value={newNoteText}
              onChange={(e) => setNewNoteText(e.target.value)}
              placeholder="Record forensic observation, analyst findings, containment notes..."
              className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground placeholder:text-foreground-muted focus:outline-hidden focus:border-primary text-xs"
            />
            <div className="flex justify-end">
              <button
                type="submit"
                disabled={submittingNote || !newNoteText.trim()}
                className="px-3 py-1.5 bg-primary hover:bg-primary-hover text-white text-xs font-semibold rounded-control flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
              >
                {submittingNote ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                <span>Add Note</span>
              </button>
            </div>
          </form>

          {/* Notes Thread */}
          <div className="bg-surface border border-border rounded-control divide-y divide-border">
            {incident.notes.length === 0 ? (
              <div className="p-8 text-center text-foreground-muted text-xs">
                No notes have been logged for this incident yet.
              </div>
            ) : (
              incident.notes.map((note) => (
                <div key={note.id} className="p-4 space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <User className="w-3.5 h-3.5 text-foreground-muted" />
                      <span className="font-semibold text-foreground">{note.author}</span>
                    </div>
                    <span className="text-[10px] font-mono text-foreground-muted">
                      {new Date(note.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-foreground whitespace-pre-wrap">{note.note_text}</p>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Tab: Investigation & Response Handoff */}
      {activeTab === 'handoff' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 bg-surface border border-border rounded-control space-y-2 flex flex-col justify-between">
            <div>
              <div className="p-2 bg-warning-surface border border-warning-border rounded-control text-warning inline-flex mb-2">
                <Activity className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-bold text-foreground">Investigation Workspace</h4>
              <p className="text-[11px] text-foreground-muted mt-1">
                Deep forensic timeline, attack path reconstruction, graph relationships, and explainability.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                if (incident.investigation_id) {
                  navigate(`/investigations/${incident.investigation_id}`);
                } else {
                  navigate('/investigations');
                }
              }}
              className="mt-3 px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface text-xs font-medium flex items-center justify-between cursor-pointer"
            >
              <span>Launch Investigation</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="p-4 bg-surface border border-border rounded-control space-y-2 flex flex-col justify-between">
            <div>
              <div className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-control text-indigo-400 inline-flex mb-2">
                <Lock className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-bold text-foreground">Response Workspace</h4>
              <p className="text-[11px] text-foreground-muted mt-1">
                Execute approved containment playbooks, isolate hosts, block malicious infrastructure, reset accounts.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                if (incident.investigation_id) {
                  navigate(`/investigations/${incident.investigation_id}/response`);
                } else {
                  navigate('/response');
                }
              }}
              className="mt-3 px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface text-xs font-medium flex items-center justify-between cursor-pointer"
            >
              <span>Open Response Actions</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="p-4 bg-surface border border-border rounded-control space-y-2 flex flex-col justify-between">
            <div>
              <div className="p-2 bg-primary-subtle border border-primary/30 rounded-control text-primary inline-flex mb-2">
                <FileText className="w-4 h-4" />
              </div>
              <h4 className="text-xs font-bold text-foreground">Forensic Dossier Report</h4>
              <p className="text-[11px] text-foreground-muted mt-1">
                Generate an executive summary, MITRE ATT&CK coverage report, and forensic post-incident record.
              </p>
            </div>
            <button
              type="button"
              onClick={() => {
                if (incident.report_id) {
                  navigate(`/reports/${incident.report_id}`);
                } else {
                  navigate('/reports');
                }
              }}
              className="mt-3 px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface text-xs font-medium flex items-center justify-between cursor-pointer"
            >
              <span>View / Generate Report</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}

      {/* 6. Modals */}

      {/* Contain Modal */}
      {showContainModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-control w-full max-w-md shadow-2xl p-4 space-y-3">
            <h3 className="text-sm font-bold text-foreground flex items-center space-x-1.5">
              <Lock className="w-4 h-4 text-indigo-400" />
              <span>Confirm Incident Containment</span>
            </h3>
            <p className="text-xs text-foreground-muted">
              Record containment verification notes (e.g. host isolated, malicious traffic blocked):
            </p>
            <form onSubmit={handleContainSubmit} className="space-y-3 text-xs">
              <textarea
                rows={3}
                required
                value={containReason}
                onChange={(e) => setContainReason(e.target.value)}
                placeholder="Endpoint quarantined and malicious domain sinkholed..."
                className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground text-xs focus:outline-hidden focus:border-primary"
              />
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowContainModal(false)}
                  className="px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface cursor-pointer text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold rounded-control cursor-pointer text-xs"
                >
                  Mark Contained
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Resolve Modal */}
      {showResolveModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-control w-full max-w-md shadow-2xl p-4 space-y-3">
            <h3 className="text-sm font-bold text-foreground flex items-center space-x-1.5">
              <CheckCircle2 className="w-4 h-4 text-success" />
              <span>Resolve Incident Case</span>
            </h3>
            <p className="text-xs text-foreground-muted">
              Select the structured resolution reason and supply operational confirmation:
            </p>
            <form onSubmit={handleResolveSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block font-medium text-foreground mb-1">Resolution Category *</label>
                <select
                  value={resolveCategory}
                  onChange={(e) => setResolveCategory(e.target.value)}
                  className="w-full px-2.5 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground text-xs focus:outline-hidden focus:border-primary"
                >
                  <option value="THREAT_CONTAINED">Threat Contained</option>
                  <option value="THREAT_REMEDIATED">Threat Remediated</option>
                  <option value="FALSE_POSITIVE">False Positive</option>
                  <option value="DUPLICATE">Duplicate</option>
                  <option value="BENIGN_ACTIVITY">Benign Activity</option>
                  <option value="INSUFFICIENT_EVIDENCE">Insufficient Evidence</option>
                  <option value="OTHER">Other</option>
                </select>
              </div>

              <div>
                <label className="block font-medium text-foreground mb-1">Resolution Notes</label>
                <textarea
                  rows={3}
                  value={resolveReason}
                  onChange={(e) => setResolveReason(e.target.value)}
                  placeholder="Details regarding threat eradication and recovery verification..."
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground text-xs focus:outline-hidden focus:border-primary"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowResolveModal(false)}
                  className="px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface cursor-pointer text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-3 py-1.5 bg-success text-white font-semibold rounded-control cursor-pointer text-xs"
                >
                  Confirm Resolution
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Reopen Modal */}
      {showReopenModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-control w-full max-w-md shadow-2xl p-4 space-y-3">
            <h3 className="text-sm font-bold text-foreground flex items-center space-x-1.5">
              <RefreshCw className="w-4 h-4 text-primary" />
              <span>Reopen Incident Case</span>
            </h3>
            <p className="text-xs text-foreground-muted">
              State the reason for reopening this case (e.g. recurrence of threat activity or new forensic evidence):
            </p>
            <form onSubmit={handleReopenSubmit} className="space-y-3 text-xs">
              <textarea
                rows={3}
                required
                value={reopenReason}
                onChange={(e) => setReopenReason(e.target.value)}
                placeholder="New beaconing activity detected from the affected host..."
                className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground text-xs focus:outline-hidden focus:border-primary"
              />
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowReopenModal(false)}
                  className="px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface cursor-pointer text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-3 py-1.5 bg-primary hover:bg-primary-hover text-white font-semibold rounded-control cursor-pointer text-xs"
                >
                  Confirm Reopen
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Assign Modal */}
      {showAssignModal && (
        <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-control w-full max-w-md shadow-2xl p-4 space-y-3">
            <h3 className="text-sm font-bold text-foreground flex items-center space-x-1.5">
              <User className="w-4 h-4 text-primary" />
              <span>Assign Analyst Ownership</span>
            </h3>
            <form onSubmit={handleAssignSubmit} className="space-y-3 text-xs">
              <div>
                <label className="block font-medium text-foreground mb-1">Analyst Name / Email</label>
                <input
                  type="text"
                  value={assigneeName}
                  onChange={(e) => setAssigneeName(e.target.value)}
                  placeholder="e.g. Sarah Connor or leave blank to unassign"
                  className="w-full px-3 py-2 bg-surface-secondary border border-border rounded-control text-foreground text-xs focus:outline-hidden focus:border-primary"
                />
              </div>
              <div className="flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowAssignModal(false)}
                  className="px-3 py-1.5 bg-surface-secondary border border-border rounded-control text-foreground hover:bg-surface cursor-pointer text-xs"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={actionLoading}
                  className="px-3 py-1.5 bg-primary hover:bg-primary-hover text-white font-semibold rounded-control cursor-pointer text-xs"
                >
                  Update Assignment
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
