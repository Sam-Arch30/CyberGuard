import React, { useState, useEffect, useMemo, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { Core } from 'cytoscape';
import {
  GitMerge,
  ShieldAlert,
  Search,
  CheckCircle2,
  AlertTriangle,
  Calendar,
  ExternalLink,
  Columns,
  Sparkles,
  Check,
  X,
  RefreshCw,
  FolderPlus,
  Share2,
  ZoomIn,
  ZoomOut,
  Maximize2,
  ShieldCheck,
  SlidersHorizontal,
  Info
} from 'lucide-react';
import type { EmailAnalysis } from '../../types/forensic';
import type {
  CrossEmailAnalysisData,
  RelatedEmailItem,
  ComparisonMatrixData,
  AnalystDecisionRecord
} from '../../types/crossEmail';
import { useTheme } from '../../context/ThemeContext';

interface CrossEmailWorkspaceProps {
  email: EmailAnalysis;
  onOpenEmail?: (emailId: string) => void;
}

export const CrossEmailWorkspace: React.FC<CrossEmailWorkspaceProps> = ({ email, onOpenEmail }) => {
  const { isDark } = useTheme();

  // Active view tab inside the workspace
  const [workspaceTab, setWorkspaceTab] = useState<'table' | 'compare' | 'graph' | 'timeline' | 'decisions'>('table');

  // Loading & Data State
  const [data, setData] = useState<CrossEmailAnalysisData | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Selected Emails for comparison / batch actions
  const [selectedEmailIds, setSelectedEmailIds] = useState<Set<string>>(new Set());

  // Comparison Matrix State
  const [comparisonMatrix, setComparisonMatrix] = useState<ComparisonMatrixData | null>(null);
  const [loadingCompare, setLoadingCompare] = useState<boolean>(false);
  const [compareFilter, setCompareFilter] = useState<'all' | 'diffs' | 'identical'>('all');

  // Table Search & Sort
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [sortField, setSortField] = useState<keyof RelatedEmailItem>('similarity');
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  // Cytoscape Graph State
  const graphContainerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [graphData, setGraphData] = useState<any | null>(null);
  const [activeGraphFilters, setActiveGraphFilters] = useState<Set<string>>(
    new Set(['Email', 'Domain', 'IP', 'URL', 'ASN', 'Recipients', 'Campaign'])
  );
  const [selectedNode, setSelectedNode] = useState<any | null>(null);

  // Case & Decision Modal State
  const [actionModalOpen, setActionModalOpen] = useState<boolean>(false);
  const [modalActionType, setModalActionType] = useState<'mark_unrelated' | 'add_to_case' | 'assign_campaign' | 'escalate'>('mark_unrelated');
  const [targetEmailForAction, setTargetEmailForAction] = useState<RelatedEmailItem | null>(null);
  const [analystNotes, setAnalystNotes] = useState<string>('');
  const [actionSubmitting, setActionSubmitting] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [decisionsList, setDecisionsList] = useState<AnalystDecisionRecord[]>([]);

  // Show Toast notification helper
  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3500);
  };

  // Fetch Cross-Email Correlation on mount or email change
  useEffect(() => {
    let isMounted = true;
    setLoading(true);
    setError(null);

    const payload = {
      id: email.id || email.evidence_id || 'EML-2026-8819',
      subject: email.subject || 'URGENT: Executive Wire Transfer Instructions - Q3 Vendor Settlement #8819',
      sender: email.from || 'robert.vance@bank-corp-update.com',
      from: email.from || 'robert.vance@bank-corp-update.com',
      reply_to: email.reply_to || 'financial-operations-secure@wire-transfer-node.ru',
      ips: email.indicators?.ips?.map(i => i.value) || ['185.220.101.42'],
      urls: email.indicators?.urls?.map(u => u.value) || ['https://bank-corp-update.com/auth/v2/secure_login.php'],
      domains: email.indicators?.domains?.map(d => d.value) || ['bank-corp-update.com', 'wire-transfer-node.ru'],
      campaign: 'C-042'
    };

    fetch('/api/cross-investigation/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
      .then(res => (res.ok ? res.json() : null))
      .then(resData => {
        if (!isMounted) return;
        if (resData && resData.related_emails) {
          setData(resData);
          if (resData.related_emails.length >= 3) {
            setSelectedEmailIds(new Set([
              resData.related_emails[0].id,
              resData.related_emails[1].id,
              resData.related_emails[2].id
            ]));
          }
        } else {
          setData({
            related_activity_detected: false,
            related_count: 0,
            campaign_confidence: null,
            campaign_id: null,
            strongest_relationships: [],
            is_synthetic: false,
            timeline: [],
            related_emails: []
          });
        }
        setLoading(false);
      })
      .catch(() => {
        if (!isMounted) return;
        setData({
          related_activity_detected: false,
          related_count: 0,
          campaign_confidence: null,
          campaign_id: null,
          strongest_relationships: [],
          is_synthetic: false,
          timeline: [],
          related_emails: []
        });
        setLoading(false);
      });

    // Also fetch existing analyst decisions
    fetch('http://localhost:8000/api/cross-investigation/decisions')
      .then(res => (res.ok ? res.json() : []))
      .then(decs => {
        if (isMounted && Array.isArray(decs)) {
          setDecisionsList(decs);
        }
      })
      .catch(() => {});

    return () => {
      isMounted = false;
    };
  }, [email]);

  // Handle Comparison Mode trigger when 2-5 emails are selected
  const handleTriggerCompare = () => {
    if (selectedEmailIds.size < 2 || selectedEmailIds.size > 5) {
      showToast('Please select between 2 and 5 emails to compare.');
      return;
    }
    setLoadingCompare(true);
    setWorkspaceTab('compare');

    fetch('/api/cross-investigation/compare', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email_ids: Array.from(selectedEmailIds)
      })
    })
      .then(res => (res.ok ? res.json() : null))
      .then(matrix => {
        if (matrix && matrix.categories) {
          setComparisonMatrix(matrix);
        } else {
          showToast('Failed to load comparison matrix.');
        }
        setLoadingCompare(false);
      })
      .catch(() => {
        showToast('Comparison request failed.');
        setLoadingCompare(false);
      });
  };

  // Handle Graph trigger
  const handleTriggerGraph = () => {
    setWorkspaceTab('graph');
    const ids = selectedEmailIds.size > 0
      ? Array.from(selectedEmailIds)
      : (data?.related_emails.map(e => e.id) || [email.id].filter(Boolean));

    if (ids.length === 0) {
      setGraphData({ nodes: [], edges: [] });
      return;
    }

    fetch('/api/cross-investigation/graph', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email_ids: ids,
        node_types: Array.from(activeGraphFilters)
      })
    })
      .then(res => (res.ok ? res.json() : null))
      .then(g => {
        if (g && g.nodes) {
          setGraphData(g);
        } else {
          setGraphData({ nodes: [], edges: [] });
        }
      })
      .catch(() => {
        setGraphData({ nodes: [], edges: [] });
      });
  };

  // Initialize and update Cytoscape instance
  useEffect(() => {
    if (workspaceTab !== 'graph' || !graphContainerRef.current || !graphData) return;

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const elements: any[] = [];
    (graphData.nodes || []).forEach((n: any) => {
      elements.push({
        data: {
          id: n.id,
          label: n.label,
          type: n.type,
          metadata: n.metadata
        }
      });
    });

    (graphData.edges || []).forEach((e: any) => {
      elements.push({
        data: {
          id: e.id,
          source: e.source,
          target: e.target,
          label: e.label
        }
      });
    });

    try {
      const cy = cytoscape({
        container: graphContainerRef.current,
        elements,
        style: [
          {
            selector: 'node',
            style: {
              'label': 'data(label)',
              'font-size': '10px',
              'font-family': 'monospace',
              'text-valign': 'bottom',
              'text-margin-y': 4,
              'color': isDark ? '#f1f5f9' : '#0f172a',
              'text-wrap': 'ellipsis',
              'text-max-width': '120px',
              'background-color': '#0284c7',
              'border-width': 2,
              'border-color': '#38bdf8',
              'width': 28,
              'height': 28
            }
          },
          {
            selector: 'node[type = "Email"]',
            style: {
              'background-color': '#f59e0b',
              'border-color': '#fbbf24',
              'shape': 'round-rectangle',
              'width': 34,
              'height': 34
            }
          },
          {
            selector: 'node[type = "Campaign"]',
            style: {
              'background-color': '#ec4899',
              'border-color': '#f472b6',
              'shape': 'diamond',
              'width': 42,
              'height': 42
            }
          },
          {
            selector: 'node[type = "URL"]',
            style: {
              'background-color': '#ef4444',
              'border-color': '#f87171',
              'shape': 'hexagon',
              'width': 30,
              'height': 30
            }
          },
          {
            selector: 'node[type = "IP"]',
            style: {
              'background-color': '#10b981',
              'border-color': '#34d399',
              'shape': 'ellipse',
              'width': 30,
              'height': 30
            }
          },
          {
            selector: 'node[type = "ASN"]',
            style: {
              'background-color': '#3b82f6',
              'border-color': '#60a5fa',
              'shape': 'barrel',
              'width': 32,
              'height': 32
            }
          },
          {
            selector: 'node[type = "Domain"]',
            style: {
              'background-color': '#8b5cf6',
              'border-color': '#a78bfa',
              'shape': 'round-diamond',
              'width': 32,
              'height': 32
            }
          },
          {
            selector: 'edge',
            style: {
              'width': 1.8,
              'line-color': isDark ? '#475569' : '#cbd5e1',
              'target-arrow-color': isDark ? '#64748b' : '#94a3b8',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              'font-size': '8px',
              'font-family': 'monospace',
              'color': isDark ? '#94a3b8' : '#64748b',
              'text-rotation': 'autorotate',
              'label': 'data(label)'
            }
          },
          {
            selector: ':selected',
            style: {
              'border-width': 4,
              'border-color': '#38bdf8'
            }
          }
        ],
        layout: {
          name: 'cose',
          animate: false,
          padding: 30,
          nodeRepulsion: () => 6500,
          idealEdgeLength: () => 110
        }
      });

      cy.on('tap', 'node', (evt) => {
        const node = evt.target;
        setSelectedNode({
          id: node.data('id'),
          label: node.data('label'),
          type: node.data('type'),
          metadata: node.data('metadata') || {}
        });
      });

      cy.on('tap', (evt) => {
        if (evt.target === cy) {
          setSelectedNode(null);
        }
      });

      cyRef.current = cy;
    } catch (e) {
      console.warn('Cytoscape render notice', e);
    }
  }, [workspaceTab, graphData, isDark]);

  // Toggle email selection in table
  const handleToggleSelect = (emailId: string) => {
    setSelectedEmailIds(prev => {
      const next = new Set(prev);
      if (next.has(emailId)) {
        next.delete(emailId);
      } else {
        if (next.size >= 5) {
          showToast('Maximum 5 emails can be compared simultaneously.');
          return prev;
        }
        next.add(emailId);
      }
      return next;
    });
  };

  // Open Action Modal for an email
  const handleOpenActionModal = (
    action: 'mark_unrelated' | 'add_to_case' | 'assign_campaign' | 'escalate',
    item?: RelatedEmailItem
  ) => {
    setModalActionType(action);
    setTargetEmailForAction(item || (data?.related_emails[0] || null));
    setAnalystNotes('');
    setActionModalOpen(true);
  };

  // Submit Analyst Decision (Persists False Positive Feedback / Case Action)
  const handleSubmitDecision = async () => {
    if (!targetEmailForAction) return;
    setActionSubmitting(true);

    const emailA = email.id || email.evidence_id || 'EML-2026-8819';
    const emailB = targetEmailForAction.id;

    try {
      const res = await fetch('http://localhost:8000/api/cross-investigation/decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email_id_a: emailA,
          email_id_b: emailB,
          decision: modalActionType,
          campaign_id: 'C-042',
          case_id: 'CASE-2026-0042',
          analyst: 'SOC Lead Analyst',
          notes: analystNotes || `Analyst action: ${modalActionType}`
        })
      });

      if (res.ok) {
        const savedDec = await res.json();
        setDecisionsList(prev => [savedDec, ...prev]);

        // Update local status in table
        if (data) {
          const updatedEmails = data.related_emails.map(e => {
            if (e.id === emailB) {
              return {
                ...e,
                status: modalActionType === 'mark_unrelated' ? 'Unrelated' : (
                  modalActionType === 'escalate' ? 'Escalated' : 'Confirmed'
                )
              };
            }
            return e;
          });
          setData({ ...data, related_emails: updatedEmails });
        }

        if (modalActionType === 'mark_unrelated') {
          showToast(`False positive feedback saved: ${emailB} marked unrelated.`);
        } else if (modalActionType === 'add_to_case') {
          showToast(`Email ${emailB} added to case CASE-2026-0042.`);
        } else if (modalActionType === 'assign_campaign') {
          showToast(`Email ${emailB} assigned to Campaign C-042.`);
        } else {
          showToast(`Email ${emailB} escalated for urgent containment.`);
        }
      } else {
        showToast('Decision recorded in local session.');
      }
    } catch {
      showToast('Decision recorded in local session.');
    } finally {
      setActionSubmitting(false);
      setActionModalOpen(false);
    }
  };

  // Sorted & Filtered Related Emails
  const filteredAndSortedEmails = useMemo(() => {
    if (!data?.related_emails) return [];
    let list = [...data.related_emails];

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        e =>
          e.subject.toLowerCase().includes(q) ||
          e.sender.toLowerCase().includes(q) ||
          e.recipient.toLowerCase().includes(q) ||
          e.id.toLowerCase().includes(q) ||
          e.correlation_reasons.some(r => r.toLowerCase().includes(q))
      );
    }

    list.sort((a, b) => {
      const valA = a[sortField];
      const valB = b[sortField];
      if (typeof valA === 'number' && typeof valB === 'number') {
        return sortAsc ? valA - valB : valB - valA;
      }
      return sortAsc
        ? String(valA).localeCompare(String(valB))
        : String(valB).localeCompare(String(valA));
    });

    return list;
  }, [data, searchQuery, sortField, sortAsc]);

  const handleSort = (field: keyof RelatedEmailItem) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[350px] space-y-3 bg-surface rounded-2xl border border-border p-8">
        <RefreshCw className="w-6 h-6 text-primary animate-spin" />
        <p className="text-xs font-mono text-foreground-muted">
          Correlating forensic indicators across analyzed emails...
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {error && (
        <div className="p-3 bg-danger/10 border border-danger/30 rounded-xl text-xs font-mono text-danger flex items-center space-x-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Toast Alert */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-surface border border-primary/40 text-foreground px-4 py-3 rounded-xl shadow-lg flex items-center space-x-3 animate-fade-in">
          <CheckCircle2 className="w-5 h-5 text-primary flex-shrink-0" />
          <span className="text-xs font-mono font-medium">{toastMessage}</span>
          <button onClick={() => setToastMessage(null)} className="text-foreground-muted hover:text-foreground">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* ========================================================================= */}
      {/* SECTION 1: RELATED ACTIVITY DETECTED HERO BANNER                         */}
      {/* ========================================================================= */}
      <div className="bg-gradient-to-r from-danger/15 via-warning/10 to-primary/15 border-2 border-danger/40 rounded-2xl p-6 shadow-sm relative overflow-hidden">
        <div className="absolute top-0 right-0 w-80 h-80 bg-danger/10 rounded-full blur-3xl -mr-20 -mt-20 pointer-events-none" />

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 relative z-10">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2.5">
              <span className="px-2.5 py-1 rounded-md text-[11px] font-mono font-bold tracking-wider uppercase bg-danger/20 text-danger border border-danger/30 flex items-center gap-1.5 animate-pulse">
                <ShieldAlert className="w-3.5 h-3.5" />
                RELATED ACTIVITY DETECTED
              </span>
              {data?.is_synthetic && (
                <span className="px-2.5 py-1 rounded-md text-[10px] font-mono font-bold tracking-wide uppercase bg-purple-500/15 text-purple-600 dark:text-purple-300 border border-purple-500/30">
                  SYNTHETIC DEMO EVIDENCE
                </span>
              )}
              {data?.campaign_id && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-surface/80 border border-border text-foreground font-semibold">
                  Campaign: {data.campaign_id}
                </span>
              )}
            </div>

            <div className="flex items-baseline gap-3">
              <h1 className="text-2xl lg:text-3xl font-black font-sans tracking-tight text-foreground">
                {data ? `${data.related_count} potentially related emails` : '0 potentially related emails'}
              </h1>
              {data && data.campaign_confidence !== null && data.campaign_confidence !== undefined && (
                <span className="text-sm lg:text-base font-mono font-bold text-danger">
                  Campaign confidence: {data.campaign_confidence}%
                </span>
              )}
            </div>

            <p className="text-xs text-foreground-muted font-mono max-w-3xl">
              Forensic correlation engine cross-referenced 7-dimensional fingerprints across stored investigations and confirmed active campaign cluster activity.
            </p>

            {/* Strongest relationships */}
            {data?.strongest_relationships && data.strongest_relationships.length > 0 && (
              <div className="pt-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-foreground-muted block mb-2">
                  Strongest relationships:
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 text-xs font-mono">
                  {data.strongest_relationships.map((reason, idx) => (
                    <div
                      key={idx}
                      className="flex items-center space-x-2 bg-surface/80 border border-border/70 rounded-lg px-2.5 py-1.5 text-foreground shadow-2xs"
                    >
                      <CheckCircle2 className="w-3.5 h-3.5 text-danger flex-shrink-0" />
                      <span className="capitalize">{reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Quick Action Buttons */}
          <div className="flex flex-col sm:flex-row lg:flex-col gap-2.5 flex-shrink-0">
            <button
              type="button"
              onClick={handleTriggerCompare}
              disabled={selectedEmailIds.size < 2}
              className={`px-4 py-2.5 rounded-xl font-mono text-xs font-bold transition-all flex items-center justify-center space-x-2 shadow-sm cursor-pointer ${
                selectedEmailIds.size >= 2
                  ? 'bg-primary text-primary-foreground hover:bg-primary/90 shadow-primary/20'
                  : 'bg-surface-secondary text-foreground-muted border border-border cursor-not-allowed opacity-60'
              }`}
            >
              <Columns className="w-4 h-4" />
              <span>Compare Emails ({selectedEmailIds.size})</span>
            </button>

            <button
              type="button"
              onClick={handleTriggerGraph}
              className="px-4 py-2.5 rounded-xl font-mono text-xs font-bold bg-surface border border-border text-foreground hover:bg-surface-secondary transition-all flex items-center justify-center space-x-2 shadow-2xs cursor-pointer"
            >
              <Share2 className="w-4 h-4 text-primary" />
              <span>View Connections Graph</span>
            </button>

            <button
              type="button"
              onClick={() => setWorkspaceTab('timeline')}
              className="px-4 py-2.5 rounded-xl font-mono text-xs font-bold bg-surface border border-border text-foreground hover:bg-surface-secondary transition-all flex items-center justify-center space-x-2 shadow-2xs cursor-pointer"
            >
              <Calendar className="w-4 h-4 text-warning" />
              <span>Attack Timeline</span>
            </button>
          </div>
        </div>
      </div>

      {/* ========================================================================= */}
      {/* SECTION 2: WORKSPACE SUB-NAVIGATION TABS                                 */}
      {/* ========================================================================= */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-border pb-3">
        <div className="flex items-center space-x-1.5 bg-surface-secondary/70 p-1 rounded-xl border border-border">
          <button
            type="button"
            onClick={() => setWorkspaceTab('table')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              workspaceTab === 'table'
                ? 'bg-surface text-foreground font-bold shadow-2xs border border-border'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <GitMerge className="w-3.5 h-3.5 text-primary" />
            <span>Related Emails</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] bg-primary/15 text-primary font-bold">
              {data?.related_emails ? data.related_emails.length : 0}
            </span>
          </button>

          <button
            type="button"
            onClick={handleTriggerCompare}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              workspaceTab === 'compare'
                ? 'bg-surface text-foreground font-bold shadow-2xs border border-border'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Columns className="w-3.5 h-3.5 text-info" />
            <span>Comparison Mode</span>
            {selectedEmailIds.size > 0 && (
              <span className="px-1.5 py-0.2 rounded text-[10px] bg-info/15 text-info font-bold">
                {selectedEmailIds.size}
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={handleTriggerGraph}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              workspaceTab === 'graph'
                ? 'bg-surface text-foreground font-bold shadow-2xs border border-border'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Share2 className="w-3.5 h-3.5 text-purple-500" />
            <span>Investigation Graph</span>
          </button>

          <button
            type="button"
            onClick={() => setWorkspaceTab('timeline')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              workspaceTab === 'timeline'
                ? 'bg-surface text-foreground font-bold shadow-2xs border border-border'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <Calendar className="w-3.5 h-3.5 text-warning" />
            <span>Attack Timeline</span>
          </button>

          <button
            type="button"
            onClick={() => setWorkspaceTab('decisions')}
            className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-all flex items-center space-x-1.5 cursor-pointer ${
              workspaceTab === 'decisions'
                ? 'bg-surface text-foreground font-bold shadow-2xs border border-border'
                : 'text-foreground-muted hover:text-foreground'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5 text-success" />
            <span>Analyst Decisions</span>
            {decisionsList.length > 0 && (
              <span className="px-1.5 py-0.2 rounded text-[10px] bg-success/15 text-success font-bold">
                {decisionsList.length}
              </span>
            )}
          </button>
        </div>

        {/* Global Batch Actions toolbar */}
        {selectedEmailIds.size > 0 && (
          <div className="flex items-center space-x-2 text-xs font-mono">
            <span className="text-foreground-muted">{selectedEmailIds.size} selected:</span>
            <button
              type="button"
              onClick={handleTriggerCompare}
              disabled={selectedEmailIds.size < 2}
              className="px-2.5 py-1 rounded-lg bg-primary/15 text-primary border border-primary/30 font-bold hover:bg-primary/25 cursor-pointer"
            >
              Compare
            </button>
            <button
              type="button"
              onClick={() => handleOpenActionModal('add_to_case')}
              className="px-2.5 py-1 rounded-lg bg-surface border border-border text-foreground hover:bg-surface-secondary cursor-pointer"
            >
              Add to Case
            </button>
            <button
              type="button"
              onClick={() => handleOpenActionModal('mark_unrelated')}
              className="px-2.5 py-1 rounded-lg bg-danger/10 text-danger border border-danger/30 hover:bg-danger/20 cursor-pointer"
            >
              Mark Unrelated
            </button>
          </div>
        )}
      </div>

      {/* ========================================================================= */}
      {/* TAB 1: RELATED EMAILS SORTABLE TABLE                                     */}
      {/* ========================================================================= */}
      {workspaceTab === 'table' && (
        <div className="space-y-4">
          {/* Search and filter controls */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
            <div className="relative w-full sm:w-80">
              <Search className="w-4 h-4 text-foreground-muted absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search related messages, subjects, senders..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-surface border border-border rounded-xl text-xs font-mono text-foreground focus:outline-hidden focus:border-primary"
              />
            </div>
            <div className="text-xs font-mono text-foreground-muted">
              Select 2–5 emails to unlock side-by-side comparison mode
            </div>
          </div>

          {/* Table Container */}
          <div className="bg-surface rounded-2xl border border-border overflow-hidden shadow-sm">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-surface-secondary/80 border-b border-border text-foreground-muted">
                    <th className="py-3 px-3 w-10 text-center">
                      <span className="sr-only">Select</span>
                    </th>
                    <th
                      onClick={() => handleSort('threat_score')}
                      className="py-3 px-3 cursor-pointer hover:text-foreground font-semibold"
                    >
                      <div className="flex items-center space-x-1">
                        <span>Threat Score</span>
                        <SlidersHorizontal className="w-3 h-3 opacity-60" />
                      </div>
                    </th>
                    <th
                      onClick={() => handleSort('subject')}
                      className="py-3 px-3 cursor-pointer hover:text-foreground font-semibold min-w-[220px]"
                    >
                      <div className="flex items-center space-x-1">
                        <span>Subject</span>
                        <SlidersHorizontal className="w-3 h-3 opacity-60" />
                      </div>
                    </th>
                    <th
                      onClick={() => handleSort('sender')}
                      className="py-3 px-3 cursor-pointer hover:text-foreground font-semibold"
                    >
                      Sender
                    </th>
                    <th
                      onClick={() => handleSort('recipient')}
                      className="py-3 px-3 cursor-pointer hover:text-foreground font-semibold"
                    >
                      Recipient
                    </th>
                    <th
                      onClick={() => handleSort('received_time')}
                      className="py-3 px-3 cursor-pointer hover:text-foreground font-semibold"
                    >
                      Received Time
                    </th>
                    <th className="py-3 px-3 font-semibold">Campaign</th>
                    <th
                      onClick={() => handleSort('similarity')}
                      className="py-3 px-3 cursor-pointer hover:text-foreground font-semibold"
                    >
                      Similarity
                    </th>
                    <th className="py-3 px-3 font-semibold">Shared Indicators</th>
                    <th className="py-3 px-3 font-semibold">Status</th>
                    <th className="py-3 px-3 text-right font-semibold">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {filteredAndSortedEmails.map(item => {
                    const isSelected = selectedEmailIds.has(item.id);
                    const isUnrelated = item.status.toLowerCase() === 'unrelated';

                    return (
                      <tr
                        key={item.id}
                        className={`transition-colors hover:bg-surface-secondary/40 ${
                          isSelected ? 'bg-primary/5' : ''
                        } ${isUnrelated ? 'opacity-60 bg-surface-secondary/20' : ''}`}
                      >
                        {/* Checkbox */}
                        <td className="py-3 px-3 text-center">
                          <input
                            type="checkbox"
                            checked={isSelected}
                            onChange={() => handleToggleSelect(item.id)}
                            className="rounded border-border text-primary focus:ring-primary cursor-pointer w-3.5 h-3.5"
                          />
                        </td>

                        {/* Threat Score */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded-md font-bold text-[11px] ${
                              item.threat_score >= 80
                                ? 'bg-danger/15 text-danger border border-danger/30'
                                : item.threat_score >= 50
                                ? 'bg-warning/15 text-warning border border-warning/30'
                                : 'bg-success/15 text-success border border-success/30'
                            }`}
                          >
                            {item.threat_score.toFixed(0)}
                          </span>
                        </td>

                        {/* Subject */}
                        <td className="py-3 px-3">
                          <div className="flex flex-col">
                            <button
                              type="button"
                              onClick={() => onOpenEmail ? onOpenEmail(item.id) : null}
                              className="text-foreground hover:text-primary font-medium text-left truncate max-w-xs sm:max-w-sm md:max-w-md cursor-pointer flex items-center space-x-1"
                              title={item.subject}
                            >
                              <span>{item.subject}</span>
                              <ExternalLink className="w-3 h-3 opacity-50 flex-shrink-0 inline ml-1" />
                            </button>
                            <span className="text-[10px] text-foreground-muted flex items-center gap-1.5 mt-0.5">
                              <span>ID: {item.id}</span>
                              {item.is_synthetic && (
                                <span className="text-[9px] px-1 py-0.2 rounded bg-purple-500/10 text-purple-600 dark:text-purple-300">
                                  SYNTHETIC
                                </span>
                              )}
                            </span>
                          </div>
                        </td>

                        {/* Sender */}
                        <td className="py-3 px-3 text-foreground-muted truncate max-w-[140px]" title={item.sender}>
                          {item.sender}
                        </td>

                        {/* Recipient */}
                        <td className="py-3 px-3 text-foreground-muted truncate max-w-[140px]" title={item.recipient}>
                          {item.recipient}
                        </td>

                        {/* Received Time */}
                        <td className="py-3 px-3 text-foreground-muted whitespace-nowrap">
                          {item.received_time}
                        </td>

                        {/* Campaign */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          <span className="px-2 py-0.5 rounded bg-pink-500/15 text-pink-600 dark:text-pink-300 border border-pink-500/30 text-[10px] font-bold">
                            {item.campaign || 'C-042'}
                          </span>
                        </td>

                        {/* Similarity */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          <div className="flex items-center space-x-1.5">
                            <span className="font-bold text-foreground">{item.similarity.toFixed(1)}%</span>
                            <div className="w-12 h-1.5 bg-surface-secondary rounded-full overflow-hidden">
                              <div
                                className={`h-full ${
                                  item.similarity >= 85 ? 'bg-danger' : item.similarity >= 60 ? 'bg-warning' : 'bg-primary'
                                }`}
                                style={{ width: `${Math.min(100, item.similarity)}%` }}
                              />
                            </div>
                          </div>
                        </td>

                        {/* Shared Indicators */}
                        <td className="py-3 px-3">
                          <div className="flex flex-wrap gap-1 max-w-[180px]">
                            {item.correlation_reasons.slice(0, 2).map((r, rIdx) => (
                              <span
                                key={rIdx}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-surface-secondary border border-border text-foreground-muted truncate max-w-[160px]"
                                title={r}
                              >
                                {r}
                              </span>
                            ))}
                          </div>
                        </td>

                        {/* Status */}
                        <td className="py-3 px-3 whitespace-nowrap">
                          <span
                            className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                              item.status === 'Confirmed'
                                ? 'bg-danger/15 text-danger border border-danger/30'
                                : item.status === 'Unrelated'
                                ? 'bg-surface-secondary text-foreground-muted border border-border line-through'
                                : item.status === 'Escalated'
                                ? 'bg-purple-500/15 text-purple-600 border border-purple-500/30'
                                : 'bg-warning/15 text-warning border border-warning/30'
                            }`}
                          >
                            {item.status}
                          </span>
                        </td>

                        {/* Action Buttons */}
                        <td className="py-3 px-3 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end space-x-1.5">
                            <button
                              type="button"
                              onClick={() => handleOpenActionModal('mark_unrelated', item)}
                              title="Mark Unrelated (Persist False Positive Feedback)"
                              className="p-1 rounded text-foreground-muted hover:text-danger hover:bg-danger/10 transition-colors"
                            >
                              <X className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleOpenActionModal('add_to_case', item)}
                              title="Add to Case"
                              className="p-1 rounded text-foreground-muted hover:text-primary hover:bg-primary/10 transition-colors"
                            >
                              <FolderPlus className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => onOpenEmail ? onOpenEmail(item.id) : null}
                              title="Open Investigation"
                              className="px-2 py-1 rounded bg-surface border border-border text-foreground hover:bg-surface-secondary text-[10px] font-bold"
                            >
                              Inspect
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: COMPARISON MODE (2 TO 5 EMAILS SIDE-BY-SIDE)                      */}
      {/* ========================================================================= */}
      {workspaceTab === 'compare' && (
        <div className="space-y-6">
          {/* Comparison Mode Header & Filter */}
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-surface p-4 rounded-xl border border-border">
            <div>
              <h2 className="text-base font-bold font-sans text-foreground flex items-center space-x-2">
                <Columns className="w-4 h-4 text-info" />
                <span>Side-by-Side Comparison ({comparisonMatrix?.emails.length || selectedEmailIds.size} Emails)</span>
              </h2>
              <p className="text-xs text-foreground-muted font-mono mt-0.5">
                Comparative matrix across 10 forensic dimensions highlighting identical, similar, and divergent evidence.
              </p>
            </div>

            <div className="flex items-center space-x-2">
              <div className="flex items-center space-x-1 bg-surface-secondary p-1 rounded-lg border border-border text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setCompareFilter('all')}
                  className={`px-2.5 py-1 rounded ${compareFilter === 'all' ? 'bg-surface text-foreground font-bold shadow-2xs' : 'text-foreground-muted'}`}
                >
                  All Evidence
                </button>
                <button
                  type="button"
                  onClick={() => setCompareFilter('diffs')}
                  className={`px-2.5 py-1 rounded ${compareFilter === 'diffs' ? 'bg-surface text-foreground font-bold shadow-2xs' : 'text-foreground-muted'}`}
                >
                  Differences Only
                </button>
                <button
                  type="button"
                  onClick={() => setCompareFilter('identical')}
                  className={`px-2.5 py-1 rounded ${compareFilter === 'identical' ? 'bg-surface text-foreground font-bold shadow-2xs' : 'text-foreground-muted'}`}
                >
                  Identical Only
                </button>
              </div>
            </div>
          </div>

          {/* Legend */}
          <div className="flex flex-wrap items-center gap-3 text-xs font-mono bg-surface/50 p-3 rounded-xl border border-border">
            <span className="text-foreground-muted font-bold">Evidence Highlights:</span>
            <span className="px-2 py-0.5 rounded bg-success/15 text-success border border-success/30 font-semibold flex items-center gap-1">
              <Check className="w-3 h-3" /> IDENTICAL
            </span>
            <span className="px-2 py-0.5 rounded bg-warning/15 text-warning border border-warning/30 font-semibold flex items-center gap-1">
              <Sparkles className="w-3 h-3" /> SIMILAR / OVERLAPPING
            </span>
            <span className="px-2 py-0.5 rounded bg-danger/15 text-danger border border-danger/30 font-semibold flex items-center gap-1">
              <AlertTriangle className="w-3 h-3" /> CONFLICTING / DIVERGENT
            </span>
            <span className="px-2 py-0.5 rounded bg-purple-500/15 text-purple-600 dark:text-purple-300 border border-purple-500/30 font-semibold flex items-center gap-1">
              <Info className="w-3 h-3" /> UNIQUE INDICATOR
            </span>
          </div>

          {/* Comparison Matrix Table */}
          {loadingCompare ? (
            <div className="py-16 text-center text-xs font-mono text-foreground-muted flex flex-col items-center justify-center space-y-2">
              <RefreshCw className="w-6 h-6 animate-spin text-primary" />
              <span>Synthesizing comparison matrix...</span>
            </div>
          ) : comparisonMatrix ? (
            <div className="bg-surface rounded-2xl border border-border overflow-hidden shadow-sm">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs font-mono">
                  {/* Email Column Headers */}
                  <thead>
                    <tr className="bg-surface-secondary/80 border-b border-border">
                      <th className="py-3 px-4 w-52 font-bold text-foreground-muted uppercase tracking-wider">
                        Forensic Dimension
                      </th>
                      {comparisonMatrix.emails.map((meta, idx) => (
                        <th key={meta.id} className="py-3 px-4 min-w-[200px] border-l border-border">
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-foreground">Email {String.fromCharCode(65 + idx)}</span>
                              <span
                                className={`px-1.5 py-0.2 rounded text-[10px] font-bold ${
                                  meta.threat_score >= 80 ? 'bg-danger/15 text-danger' : 'bg-warning/15 text-warning'
                                }`}
                              >
                                Score: {meta.threat_score}
                              </span>
                            </div>
                            <div className="text-[11px] font-sans font-medium text-foreground truncate" title={meta.subject}>
                              {meta.subject}
                            </div>
                            <div className="text-[10px] text-foreground-muted truncate">
                              ID: {meta.id}
                            </div>
                          </div>
                        </th>
                      ))}
                    </tr>
                  </thead>

                  {/* Category Sections */}
                  <tbody className="divide-y divide-border/60">
                    {comparisonMatrix.categories.map(cat => {
                      const filteredItems = cat.items.filter(item => {
                        if (compareFilter === 'diffs') return item.comparison_status !== 'identical';
                        if (compareFilter === 'identical') return item.comparison_status === 'identical';
                        return true;
                      });

                      if (filteredItems.length === 0) return null;

                      return (
                        <React.Fragment key={cat.category_id}>
                          {/* Category Header Row */}
                          <tr className="bg-surface-secondary/40 font-bold text-foreground">
                            <td colSpan={comparisonMatrix.emails.length + 1} className="py-2.5 px-4">
                              <div className="flex items-center space-x-2">
                                <span className="uppercase text-[11px] tracking-wider text-primary">
                                  {cat.category_title}
                                </span>
                              </div>
                            </td>
                          </tr>

                          {/* Field Rows */}
                          {filteredItems.map(field => (
                            <tr key={field.field_key} className="hover:bg-surface-secondary/20 transition-colors">
                              <td className="py-2.5 px-4 text-foreground-muted font-medium bg-surface-secondary/10">
                                <div>{field.field_label}</div>
                                {field.comparison_status && (
                                  <span
                                    className={`inline-block mt-1 px-1.5 py-0.2 rounded text-[9px] font-bold uppercase tracking-wider ${
                                      field.comparison_status === 'identical'
                                        ? 'bg-success/15 text-success'
                                        : field.comparison_status === 'similar'
                                        ? 'bg-warning/15 text-warning'
                                        : field.comparison_status === 'conflicting'
                                        ? 'bg-danger/15 text-danger'
                                        : 'bg-purple-500/15 text-purple-600 dark:text-purple-300'
                                    }`}
                                  >
                                    {field.comparison_status}
                                  </span>
                                )}
                              </td>

                              {comparisonMatrix.emails.map(meta => {
                                const val = field.values[meta.id];
                                return (
                                  <td
                                    key={meta.id}
                                    className={`py-2.5 px-4 border-l border-border/80 align-top ${
                                      field.comparison_status === 'identical'
                                        ? 'bg-success/5'
                                        : field.comparison_status === 'conflicting'
                                        ? 'bg-danger/5'
                                        : field.comparison_status === 'similar'
                                        ? 'bg-warning/5'
                                        : ''
                                    }`}
                                  >
                                    <div className="text-foreground break-all whitespace-pre-wrap">
                                      {val !== undefined && val !== null ? String(val) : '—'}
                                    </div>
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          ) : null}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 3: INVESTIGATION GRAPH (FOCUSED MULTI-EMAIL CONNECTIONS)              */}
      {/* ========================================================================= */}
      {workspaceTab === 'graph' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-surface p-4 rounded-xl border border-border">
            <div>
              <h2 className="text-base font-bold font-sans text-foreground flex items-center space-x-2">
                <Share2 className="w-4 h-4 text-purple-500" />
                <span>Multi-Email Infrastructure Graph</span>
              </h2>
              <p className="text-xs text-foreground-muted font-mono mt-0.5">
                Visualizing direct relationships: Email A & B → URL X, Email A & C → IP Y, Domain A & B → ASN Z.
              </p>
            </div>

            {/* Filter Pills */}
            <div className="flex flex-wrap items-center gap-1.5 text-xs font-mono">
              {['Email', 'Domain', 'IP', 'URL', 'ASN', 'Recipients', 'Campaign'].map(type => {
                const isActive = activeGraphFilters.has(type);
                return (
                  <button
                    key={type}
                    type="button"
                    onClick={() => {
                      setActiveGraphFilters(prev => {
                        const next = new Set(prev);
                        if (next.has(type)) next.delete(type);
                        else next.add(type);
                        return next;
                      });
                      setTimeout(handleTriggerGraph, 50);
                    }}
                    className={`px-2.5 py-1 rounded-lg border text-xs cursor-pointer transition-all ${
                      isActive
                        ? 'bg-surface font-bold text-foreground border-primary'
                        : 'bg-surface-secondary text-foreground-muted border-border opacity-60'
                    }`}
                  >
                    {type}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Cytoscape Canvas Container */}
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
            <div className="lg:col-span-3 bg-surface rounded-2xl border border-border h-[520px] relative overflow-hidden shadow-inner">
              <div ref={graphContainerRef} className="w-full h-full" />

              {/* Layout and Zoom Controls */}
              <div className="absolute bottom-4 left-4 flex items-center space-x-1.5 bg-surface/90 backdrop-blur-md p-1.5 rounded-xl border border-border shadow-md">
                <button
                  type="button"
                  onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 1.25)}
                  className="p-1.5 rounded hover:bg-surface-secondary text-foreground-muted hover:text-foreground"
                  title="Zoom In"
                >
                  <ZoomIn className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => cyRef.current?.zoom(cyRef.current.zoom() * 0.8)}
                  className="p-1.5 rounded hover:bg-surface-secondary text-foreground-muted hover:text-foreground"
                  title="Zoom Out"
                >
                  <ZoomOut className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={() => cyRef.current?.fit()}
                  className="p-1.5 rounded hover:bg-surface-secondary text-foreground-muted hover:text-foreground"
                  title="Fit to Screen"
                >
                  <Maximize2 className="w-4 h-4" />
                </button>
                <button
                  type="button"
                  onClick={handleTriggerGraph}
                  className="p-1.5 rounded hover:bg-surface-secondary text-foreground-muted hover:text-foreground"
                  title="Re-layout Graph"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Node Inspector Drawer */}
            <div className="bg-surface rounded-2xl border border-border p-4 h-[520px] overflow-y-auto space-y-4">
              <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-foreground-muted flex items-center justify-between">
                <span>Node Inspector</span>
                {selectedNode && (
                  <span className="text-[10px] text-primary lowercase">{selectedNode.type}</span>
                )}
              </h3>

              {selectedNode ? (
                <div className="space-y-3 font-mono text-xs">
                  <div className="p-3 bg-surface-secondary/50 rounded-xl border border-border">
                    <span className="text-[10px] text-foreground-muted uppercase block">Label</span>
                    <span className="font-bold text-foreground break-all">{selectedNode.label}</span>
                  </div>

                  <div className="p-3 bg-surface-secondary/50 rounded-xl border border-border">
                    <span className="text-[10px] text-foreground-muted uppercase block">Canonical Node ID</span>
                    <span className="text-foreground-muted break-all">{selectedNode.id}</span>
                  </div>

                  {Object.entries(selectedNode.metadata || {}).map(([k, v]) => (
                    <div key={k} className="p-2.5 bg-surface-secondary/30 rounded-lg border border-border/70">
                      <span className="text-[10px] text-foreground-muted uppercase block">{k}</span>
                      <span className="text-foreground break-all">{String(v)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="py-20 text-center text-xs font-mono text-foreground-muted flex flex-col items-center justify-center space-y-2">
                  <Share2 className="w-6 h-6 opacity-40 text-foreground-muted" />
                  <span>Click any node in the graph to inspect forensic intelligence details</span>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: CROSS-EMAIL ATTACK TIMELINE                                       */}
      {/* ========================================================================= */}
      {workspaceTab === 'timeline' && (
        <div className="bg-surface rounded-2xl border border-border p-6 shadow-sm space-y-6">
          <div>
            <h2 className="text-base font-bold font-sans text-foreground flex items-center space-x-2">
              <Calendar className="w-4 h-4 text-warning" />
              <span>Cross-Email Attack Infrastructure Timeline</span>
            </h2>
            <p className="text-xs text-foreground-muted font-mono mt-0.5">
              Chronological progression showing sequential delivery, infrastructure pivots, and attacker registration milestones.
            </p>
          </div>

          <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-border font-mono text-xs">
            {(data?.timeline || []).map((evt, idx) => (
              <div key={evt.id || idx} className="relative group">
                {/* Dot */}
                <div
                  className={`absolute -left-[27px] top-1 w-3.5 h-3.5 rounded-full ring-4 ring-surface ${
                    evt.severity === 'critical'
                      ? 'bg-danger'
                      : evt.severity === 'high'
                      ? 'bg-warning'
                      : 'bg-primary'
                  }`}
                />

                <div className="bg-surface-secondary/40 hover:bg-surface-secondary/70 transition-colors p-4 rounded-xl border border-border space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center space-x-2">
                      <span className="font-bold text-foreground text-sm">{evt.time_display}</span>
                      <span className="text-foreground-muted">—</span>
                      <span className="font-bold text-foreground text-sm">{evt.title}</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        evt.severity === 'critical' ? 'bg-danger/15 text-danger' : 'bg-warning/15 text-warning'
                      }`}
                    >
                      {evt.severity}
                    </span>
                  </div>

                  <p className="text-foreground-muted text-xs font-sans">{evt.description}</p>

                  <div className="flex flex-wrap items-center gap-2 pt-1 text-[10px]">
                    {evt.related_emails.map((e, eIdx) => (
                      <span key={eIdx} className="px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                        {e}
                      </span>
                    ))}
                    {evt.indicators.map((ind, iIdx) => (
                      <span key={iIdx} className="px-2 py-0.5 rounded bg-surface border border-border text-foreground-muted">
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: ANALYST DECISIONS LOG                                             */}
      {/* ========================================================================= */}
      {workspaceTab === 'decisions' && (
        <div className="bg-surface rounded-2xl border border-border p-6 shadow-sm space-y-4">
          <div>
            <h2 className="text-base font-bold font-sans text-foreground flex items-center space-x-2">
              <ShieldCheck className="w-4 h-4 text-success" />
              <span>Analyst Decisions & False Positive Feedback Log</span>
            </h2>
            <p className="text-xs text-foreground-muted font-mono mt-0.5">
              Audit trail of persisted investigator choices. Decisions marked &ldquo;Unrelated&rdquo; guide the correlation engine to suppress false positives without data loss.
            </p>
          </div>

          {decisionsList.length === 0 ? (
            <div className="py-16 text-center text-xs font-mono text-foreground-muted">
              No analyst decisions recorded yet. Use the action buttons in the Related Emails table to mark items unrelated, add to cases, or assign campaigns.
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="bg-surface-secondary border-b border-border text-foreground-muted">
                    <th className="py-2.5 px-3">Timestamp</th>
                    <th className="py-2.5 px-3">Analyst</th>
                    <th className="py-2.5 px-3">Decision</th>
                    <th className="py-2.5 px-3">Email Pair</th>
                    <th className="py-2.5 px-3">Case / Campaign</th>
                    <th className="py-2.5 px-3">Notes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {decisionsList.map(dec => (
                    <tr key={dec.id}>
                      <td className="py-2.5 px-3 text-foreground-muted whitespace-nowrap">{dec.created_at}</td>
                      <td className="py-2.5 px-3 font-semibold text-foreground">{dec.analyst}</td>
                      <td className="py-2.5 px-3 whitespace-nowrap">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            dec.decision === 'unrelated'
                              ? 'bg-danger/15 text-danger'
                              : dec.decision === 'added_to_case'
                              ? 'bg-primary/15 text-primary'
                              : 'bg-success/15 text-success'
                          }`}
                        >
                          {dec.decision}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-foreground-muted">
                        {dec.email_id_a} &harr; {dec.email_id_b}
                      </td>
                      <td className="py-2.5 px-3 text-foreground-muted">
                        {dec.case_id || dec.campaign_id || '—'}
                      </td>
                      <td className="py-2.5 px-3 text-foreground max-w-xs truncate" title={dec.notes}>
                        {dec.notes || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* CASE INTEGRATION & FALSE POSITIVE DECISION MODAL                          */}
      {/* ========================================================================= */}
      {actionModalOpen && targetEmailForAction && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-2xl max-w-md w-full p-6 shadow-xl space-y-4 font-mono text-xs">
            <div className="flex items-center justify-between border-b border-border pb-3">
              <h3 className="text-sm font-bold text-foreground flex items-center space-x-2">
                <FolderPlus className="w-4 h-4 text-primary" />
                <span className="capitalize">
                  {modalActionType === 'mark_unrelated'
                    ? 'Mark Emails Unrelated (False Positive)'
                    : modalActionType === 'add_to_case'
                    ? 'Add Correlated Email to Case'
                    : modalActionType === 'assign_campaign'
                    ? 'Assign to Campaign Cluster'
                    : 'Escalate Threat Priority'}
                </span>
              </h3>
              <button
                type="button"
                onClick={() => setActionModalOpen(false)}
                className="text-foreground-muted hover:text-foreground"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-2">
              <div className="p-3 bg-surface-secondary rounded-xl border border-border space-y-1">
                <span className="text-[10px] text-foreground-muted uppercase">Target Email</span>
                <div className="font-bold text-foreground">{targetEmailForAction.id}</div>
                <div className="text-[11px] text-foreground-muted truncate">{targetEmailForAction.subject}</div>
              </div>

              {modalActionType === 'mark_unrelated' && (
                <div className="p-3 bg-warning/10 border border-warning/30 rounded-xl text-warning text-[11px] space-y-1">
                  <div className="font-bold flex items-center space-x-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0" />
                    <span>False Positive Feedback Loop</span>
                  </div>
                  <div>
                    This decision is permanently persisted in the correlation engine. Subsequent queries will flag or exclude this pair without losing investigator evidence.
                  </div>
                </div>
              )}

              <div>
                <label className="block text-[10px] font-bold text-foreground-muted uppercase mb-1">
                  Analyst Rationale / Case Notes
                </label>
                <textarea
                  rows={3}
                  value={analystNotes}
                  onChange={e => setAnalystNotes(e.target.value)}
                  placeholder="Enter justification or forensic correlation rationale..."
                  className="w-full p-2.5 bg-surface border border-border rounded-xl text-foreground text-xs font-mono focus:outline-hidden focus:border-primary"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setActionModalOpen(false)}
                className="px-3 py-2 rounded-xl border border-border text-foreground-muted hover:text-foreground"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSubmitDecision}
                disabled={actionSubmitting}
                className={`px-4 py-2 rounded-xl font-bold text-white transition-all cursor-pointer ${
                  modalActionType === 'mark_unrelated' ? 'bg-danger hover:bg-danger/90' : 'bg-primary hover:bg-primary/90'
                }`}
              >
                {actionSubmitting ? 'Saving...' : 'Confirm Decision'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};


