import { apiFetch } from '../../utils/apiClient';
import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { FolderPlus, Briefcase, CheckCircle2, AlertCircle, Loader2, ExternalLink, Plus } from 'lucide-react';
import type { EmailAnalysis } from '../../types/forensic';
import type { CaseListItem, CaseSeverity } from '../../types/case';
import { Modal, ModalHeader, ModalTitle, ModalDescription, ModalBody } from '../ui/Modal';
import { Button } from '../ui/Button';
import { Input } from '../ui/Input';
import { Textarea } from '../ui/Textarea';
import { Badge } from '../ui/Badge';
import { apiUrl } from '../../utils/apiClient';

interface AddToCaseModalProps {
  email: EmailAnalysis;
  isOpen: boolean;
  onClose: () => void;
}

export const AddToCaseModal: React.FC<AddToCaseModalProps> = ({ email, isOpen, onClose }) => {
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState<'existing' | 'new'>('existing');
  
  // Existing cases state
  const [cases, setCases] = useState<CaseListItem[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string>('');
  const [loadingCases, setLoadingCases] = useState<boolean>(false);
  const [filterQuery, setFilterQuery] = useState<string>('');

  // New case state
  const [newTitle, setNewTitle] = useState<string>(
    email.subject ? `Investigation: ${email.subject.slice(0, 60)}` : 'Suspicious Email Investigation'
  );
  const [newDescription, setNewDescription] = useState<string>(
    `Incident investigation for suspicious email from "${email.from || 'unknown'}" with Threat Score ${email.threat_score?.score ?? 'N/A'}/100.`
  );
  const [newSeverity, setNewSeverity] = useState<CaseSeverity>(
    (email.threat_score?.severity === 'critical' ? 'critical' :
     email.threat_score?.severity === 'high' ? 'high' :
     email.threat_score?.severity === 'suspicious' ? 'medium' : 'low') as CaseSeverity
  );

  // Submission state
  const [submitting, setSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successInfo, setSuccessInfo] = useState<{ caseId: string; caseNumber: string } | null>(null);

  const fetchCases = useCallback(async () => {
    setLoadingCases(true);
    try {
      const res = await apiFetch(apiUrl('/api/cases?limit=100'));
      if (res.ok) {
        const data = await res.json();
        const caseList = data.cases || [];
        setCases(caseList);
        if (caseList.length > 0 && !selectedCaseId) {
          setSelectedCaseId(caseList[0].id);
        }
      }
    } catch {
      // Fallback silently if backend offline
    } finally {
      setLoadingCases(false);
    }
  }, [selectedCaseId]);

  useEffect(() => {
    if (isOpen) {
      setError(null);
      setSuccessInfo(null);
      setFilterQuery('');
      fetchCases();
    }
  }, [isOpen, fetchCases]);

  // Extract clean indicators comprehensively
  const extractIndicators = () => {
    const rawDomains: string[] = [];
    if (email.indicators?.domains) {
      email.indicators.domains.forEach(d => rawDomains.push(typeof d === 'string' ? d : d.value));
    }
    if (email.domain_intelligence) {
      Object.keys(email.domain_intelligence).forEach(d => rawDomains.push(d));
    }

    const rawIps: string[] = [];
    if (email.indicators?.ips) {
      email.indicators.ips.forEach(i => rawIps.push(typeof i === 'string' ? i : i.value));
    }
    if (email.ip_intelligence) {
      Object.keys(email.ip_intelligence).forEach(ip => rawIps.push(ip));
    }
    if (email.relay_analysis?.transmission_order_hops) {
      email.relay_analysis.transmission_order_hops.forEach(hop => {
        if (hop.from_ip) rawIps.push(hop.from_ip);
        if (hop.by_ip) rawIps.push(hop.by_ip);
      });
    }

    const rawUrls: string[] = [];
    if (email.indicators?.urls) {
      email.indicators.urls.forEach(u => rawUrls.push(typeof u === 'string' ? u : u.value));
    }
    if (email.url_analysis) {
      email.url_analysis.forEach(u => rawUrls.push(u.url));
    }

    const rawAttachments: string[] = [];
    if (email.indicators?.attachments) {
      email.indicators.attachments.forEach(a => {
        if (a.sha256) rawAttachments.push(a.sha256);
        else if (a.filename) rawAttachments.push(a.filename);
      });
    }
    if (email.attachments) {
      email.attachments.forEach(a => {
        if (a.sha256) rawAttachments.push(a.sha256);
        else if (a.filename) rawAttachments.push(a.filename);
      });
    }

    return {
      domains: Array.from(new Set(rawDomains.filter(Boolean))),
      ips: Array.from(new Set(rawIps.filter(Boolean))),
      urls: Array.from(new Set(rawUrls.filter(Boolean))),
      attachments: Array.from(new Set(rawAttachments.filter(Boolean)))
    };
  };

  const getEmailPayload = () => {
    const emailId = email.id || (email.email_sha256 ? email.email_sha256.slice(0, 16) : `email-${Date.now()}`);
    return {
      email_id: emailId,
      email_sha256: email.email_sha256 || emailId,
      subject: email.subject || '(No Subject)',
      sender: email.from || 'unknown@domain.local',
      threat_score: email.threat_score?.score ?? 0,
      severity: email.threat_score?.severity ?? 'low',
      indicators: extractIndicators()
    };
  };

  const handleAttachExisting = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedCaseId) {
      setError('Please select a case to attach this email to.');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const payload = getEmailPayload();
      const res = await apiFetch(apiUrl(`/api/cases/${selectedCaseId}/emails`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to attach email to case');
      }

      const targetCase = cases.find(c => c.id === selectedCaseId);
      setSuccessInfo({
        caseId: selectedCaseId,
        caseNumber: targetCase?.case_number || 'Case'
      });
    } catch (err: any) {
      setError(err.message || 'Error attaching email to case.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleCreateAndAttach = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) {
      setError('Case title is required.');
      return;
    }

    setSubmitting(true);
    setError(null);

    try {
      const emailPayload = getEmailPayload();

      // Create Case with initial_email atomically
      const createRes = await apiFetch(apiUrl('/api/cases'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle.trim(),
          description: newDescription.trim() || undefined,
          severity: newSeverity,
          status: 'open',
          initial_email: emailPayload
        })
      });

      if (!createRes.ok) {
        const errData = await createRes.json().catch(() => ({}));
        throw new Error(errData.detail || 'Failed to create case');
      }

      const createdCase = await createRes.json();

      setSuccessInfo({
        caseId: createdCase.id,
        caseNumber: createdCase.case_number
      });
    } catch (err: any) {
      setError(err.message || 'Error creating case and attaching email.');
    } finally {
      setSubmitting(false);
    }
  };

  const filteredCases = cases.filter(c =>
    c.title.toLowerCase().includes(filterQuery.toLowerCase()) ||
    c.case_number.toLowerCase().includes(filterQuery.toLowerCase())
  );

  return (
    <Modal isOpen={isOpen} onClose={onClose} size="lg" className="max-h-[90vh]">
      <ModalHeader>
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 rounded-control bg-primary-subtle border border-primary/20 flex items-center justify-center text-primary flex-shrink-0">
            <Briefcase className="w-4 h-4" />
          </div>
          <div>
            <ModalTitle>Add Evidence to Investigation Case</ModalTitle>
            <ModalDescription className="font-mono">
              Link email indicators and findings to a SOC incident
            </ModalDescription>
          </div>
        </div>
      </ModalHeader>

      <ModalBody className="space-y-4">
        {/* Email Preview Snippet */}
        <div className="p-3 bg-surface-secondary/60 rounded-control border border-border flex items-center justify-between gap-4">
          <div className="min-w-0 flex-1">
            <span className="text-[10px] font-mono text-primary uppercase tracking-wider block">
              Email Subject
            </span>
            <p className="text-xs font-semibold text-foreground truncate mt-0.5">
              {email.subject || '(No Subject)'}
            </p>
            <p className="text-[11px] font-mono text-foreground-muted truncate">
              From: {email.from || 'unknown'}
            </p>
          </div>
          {email.threat_score && (
            <div className="shrink-0 text-right">
              <span className="text-[10px] font-mono text-foreground-subtle uppercase block">Threat Score</span>
              <span className={`text-xs font-mono font-bold ${
                email.threat_score.score >= 80 ? 'text-danger' :
                email.threat_score.score >= 60 ? 'text-warning' :
                email.threat_score.score >= 30 ? 'text-warning' : 'text-success'
              }`}>
                {email.threat_score.score}/100 ({email.threat_score.severity})
              </span>
            </div>
          )}
        </div>

        {/* Success View */}
        {successInfo ? (
          <div className="p-6 text-center space-y-4 bg-success-surface border border-success-border rounded-card">
            <div className="w-12 h-12 rounded-full bg-success/20 border border-success-border flex items-center justify-center mx-auto text-success">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <div className="space-y-1">
              <h3 className="text-base font-bold text-success font-sans">Email Linked Successfully</h3>
              <p className="text-xs text-foreground-muted">
                Forensic evidence and indicators have been added to{' '}
                <span className="font-mono font-bold text-foreground">{successInfo.caseNumber}</span>.
              </p>
            </div>
            <div className="flex items-center justify-center gap-2.5 pt-2">
              <Button variant="secondary" size="sm" onClick={onClose}>
                Close
              </Button>
              <Button
                variant="primary"
                size="sm"
                rightIcon={<ExternalLink className="w-3.5 h-3.5" />}
                onClick={() => {
                  onClose();
                  navigate(`/cases/${successInfo.caseId}`);
                }}
              >
                Open Case Workspace
              </Button>
            </div>
          </div>
        ) : (
          <>
            {/* Tab Selector */}
            <div className="flex rounded-control bg-surface-secondary/70 p-1 border border-border">
              <button
                type="button"
                onClick={() => { setActiveTab('existing'); setError(null); }}
                className={`flex-1 flex items-center justify-center space-x-2 py-1.5 text-xs font-medium rounded-control transition-all cursor-pointer ${
                  activeTab === 'existing'
                    ? 'bg-surface text-primary shadow-xs border border-border font-semibold'
                    : 'text-foreground-muted hover:text-foreground'
                }`}
              >
                <Briefcase className="w-3.5 h-3.5" />
                <span>Attach to Existing Case</span>
              </button>
              <button
                type="button"
                onClick={() => { setActiveTab('new'); setError(null); }}
                className={`flex-1 flex items-center justify-center space-x-2 py-1.5 text-xs font-medium rounded-control transition-all cursor-pointer ${
                  activeTab === 'new'
                    ? 'bg-surface text-primary shadow-xs border border-border font-semibold'
                    : 'text-foreground-muted hover:text-foreground'
                }`}
              >
                <FolderPlus className="w-3.5 h-3.5" />
                <span>Create New Case</span>
              </button>
            </div>

            {error && (
              <div className="p-3 bg-danger-surface border border-danger-border rounded-control flex items-start space-x-2 text-xs text-danger">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5 text-danger" />
                <span>{error}</span>
              </div>
            )}

            {/* Tab 1: Existing Case Form */}
            {activeTab === 'existing' && (
              <form onSubmit={handleAttachExisting} className="space-y-4">
                {loadingCases ? (
                  <div className="flex items-center justify-center py-8 text-foreground-muted space-x-2 text-xs font-mono">
                    <Loader2 className="w-4 h-4 animate-spin text-primary" />
                    <span>Loading investigation cases...</span>
                  </div>
                ) : cases.length === 0 ? (
                  <div className="p-6 text-center space-y-3 bg-surface-secondary/40 rounded-card border border-border">
                    <p className="text-xs text-foreground-muted">No active cases found.</p>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setActiveTab('new')}
                    >
                      Create your first case
                    </Button>
                  </div>
                ) : (
                  <>
                    {/* Search Filter */}
                    {cases.length > 3 && (
                      <Input
                        size="sm"
                        value={filterQuery}
                        onChange={e => setFilterQuery(e.target.value)}
                        placeholder="Filter cases by title or ID..."
                        className="font-mono"
                      />
                    )}

                    {/* Case Selection Cards */}
                    <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
                      {filteredCases.map(c => {
                        const isSelected = selectedCaseId === c.id;
                        return (
                          <div
                            key={c.id}
                            onClick={() => setSelectedCaseId(c.id)}
                            className={`p-3 rounded-control border cursor-pointer transition-all flex items-center justify-between gap-3 ${
                              isSelected
                                ? 'bg-surface border-primary text-foreground ring-1 ring-primary/40 shadow-xs'
                                : 'bg-surface-secondary/40 border-border hover:border-border-strong text-foreground'
                            }`}
                          >
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center space-x-2">
                                <span className="font-mono text-[11px] font-bold text-primary">{c.case_number}</span>
                                <Badge
                                  size="xs"
                                  variant={
                                    c.severity === 'critical' ? 'danger' :
                                    c.severity === 'high' ? 'warning' :
                                    c.severity === 'medium' ? 'warning' : 'neutral'
                                  }
                                >
                                  {c.severity}
                                </Badge>
                                <Badge size="xs" variant="outline">
                                  {c.status}
                                </Badge>
                              </div>
                              <p className="text-xs font-medium text-foreground truncate mt-1">{c.title}</p>
                            </div>
                            <div className="shrink-0 text-right text-[11px] font-mono text-foreground-subtle">
                              {c.email_count} email{c.email_count === 1 ? '' : 's'}
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="pt-2 flex justify-end gap-2.5">
                      <Button variant="secondary" size="sm" onClick={onClose}>
                        Cancel
                      </Button>
                      <Button
                        type="submit"
                        variant="primary"
                        size="sm"
                        isLoading={submitting}
                        disabled={submitting || !selectedCaseId}
                        leftIcon={<Briefcase className="w-3.5 h-3.5" />}
                      >
                        Attach Evidence
                      </Button>
                    </div>
                  </>
                )}
              </form>
            )}

            {/* Tab 2: Create New Case Form */}
            {activeTab === 'new' && (
              <form onSubmit={handleCreateAndAttach} className="space-y-3.5">
                <Input
                  label="Case Title *"
                  required
                  value={newTitle}
                  onChange={e => setNewTitle(e.target.value)}
                  placeholder="e.g. Credential Harvester Campaign Q3"
                  className="font-mono"
                />

                <div className="space-y-1.5">
                  <label className="text-xs font-mono text-foreground-muted uppercase tracking-wider block">
                    Initial Severity
                  </label>
                  <div className="grid grid-cols-4 gap-2">
                    {(['low', 'medium', 'high', 'critical'] as CaseSeverity[]).map(sev => (
                      <button
                        key={sev}
                        type="button"
                        onClick={() => setNewSeverity(sev)}
                        className={`py-1.5 px-2 rounded-control text-xs font-mono uppercase font-bold border transition-all cursor-pointer ${
                          newSeverity === sev
                            ? sev === 'critical' ? 'bg-danger-surface border-danger-border text-danger' :
                              sev === 'high' ? 'bg-warning-surface border-warning-border text-warning' :
                              sev === 'medium' ? 'bg-warning-surface/60 border-warning-border text-warning' :
                              'bg-surface text-foreground border-border ring-1 ring-primary'
                            : 'bg-surface-secondary/60 border-border text-foreground-muted hover:text-foreground'
                        }`}
                      >
                        {sev}
                      </button>
                    ))}
                  </div>
                </div>

                <Textarea
                  label="Description / Context"
                  rows={3}
                  value={newDescription}
                  onChange={e => setNewDescription(e.target.value)}
                  placeholder="Context on how this phishing campaign was discovered..."
                  className="font-mono"
                />

                <div className="pt-2 flex justify-end gap-2.5">
                  <Button variant="secondary" size="sm" onClick={onClose}>
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    variant="primary"
                    size="sm"
                    isLoading={submitting}
                    disabled={submitting}
                    leftIcon={<Plus className="w-3.5 h-3.5" />}
                  >
                    Create Case & Attach
                  </Button>
                </div>
              </form>
            )}
          </>
        )}
      </ModalBody>
    </Modal>
  );
};
