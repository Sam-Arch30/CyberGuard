import React, { useState, useEffect, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  Plus,
  Briefcase,
  Clock,
  ArrowRight,
  RefreshCw,
  FolderLock
} from 'lucide-react';
import { getAllAvailableAnalyses } from '../utils/forensicStore';
import type { EmailAnalysis } from '../types/forensic';
import {
  Button,
  SearchInput,
  Select,
  Panel,
  EmptyState,
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '../components/ui';
import {
  SeverityIndicator,
  ConfidenceIndicator,
  RiskBadge,
  EntityChip,
  Timestamp,
} from '../components/security';
import { useInvestigation } from '../context/InvestigationContext';

export const InvestigationsListPage: React.FC = () => {
  const navigate = useNavigate();
  const { setActiveEmailId, activeEmailId } = useInvestigation();

  const [analyses, setAnalyses] = useState<EmailAnalysis[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const loadData = () => {
    setLoading(true);
    try {
      const list = getAllAvailableAnalyses(true);
      setAnalyses(list);
    } catch {
      setAnalyses([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const filteredAnalyses = useMemo(() => {
    return analyses.filter((item) => {
      // Severity filter
      const sev = item.threat_score?.severity?.toUpperCase() || 'UNKNOWN';
      if (severityFilter !== 'ALL' && sev !== severityFilter) {
        return false;
      }

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const subject = (item.subject || '').toLowerCase();
        const sender = (item.from || '').toLowerCase();
        const id = (item.id || '').toLowerCase();
        return subject.includes(q) || sender.includes(q) || id.includes(q);
      }

      return true;
    });
  }, [analyses, severityFilter, searchQuery]);

  const handleOpenInvestigation = (id?: string) => {
    if (!id) return;
    setActiveEmailId(id);
    navigate(`/investigations/${id}/overview`);
  };

  return (
    <div className="space-y-6 pb-16">
      {/* 1. Header Banner */}
      <div className="bg-surface p-5 sm:p-6 rounded-card border border-border flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2 text-primary font-mono text-xs mb-1 font-semibold uppercase tracking-wider">
            <ShieldAlert className="w-3.5 h-3.5 text-primary" />
            <span>INCIDENT TRIAGE & FORENSIC DOSSIERS</span>
          </div>
          <h1 className="text-xl sm:text-2xl font-bold text-foreground font-sans tracking-tight">
            Investigations
          </h1>
          <p className="text-xs text-foreground-muted font-mono mt-1">
            Review active security threats, reconstruct attack chains, and coordinate containment responses.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center flex-wrap gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigate('/cases')}
            leftIcon={<Briefcase className="w-3.5 h-3.5" />}
          >
            Incident Cases
          </Button>

          <Button
            variant="secondary"
            size="sm"
            onClick={() => navigate('/history')}
            leftIcon={<Clock className="w-3.5 h-3.5" />}
          >
            Ingestion History
          </Button>

          <Button
            variant="primary"
            size="sm"
            onClick={() => navigate('/analyze')}
            leftIcon={<Plus className="w-3.5 h-3.5" />}
          >
            Ingest Telemetry
          </Button>
        </div>
      </div>

      {/* 2. Search & Filters Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-surface p-3 rounded-control border border-border">
        <div className="w-full sm:w-80">
          <SearchInput
            value={searchQuery}
            onChangeValue={setSearchQuery}
            placeholder="Search investigation subject, sender, ID..."
            size="sm"
          />
        </div>

        <div className="flex items-center space-x-2 w-full sm:w-auto justify-end">
          <span className="text-[11px] font-mono text-foreground-muted hidden sm:inline">Severity:</span>
          <Select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            options={[
              { value: 'ALL', label: 'All Severities' },
              { value: 'CRITICAL', label: 'Critical' },
              { value: 'HIGH', label: 'High' },
              { value: 'MEDIUM', label: 'Medium' },
              { value: 'LOW', label: 'Low' },
              { value: 'SAFE', label: 'Safe' },
            ]}
          />

          <Button
            variant="ghost"
            size="sm"
            onClick={loadData}
            title="Refresh List"
            aria-label="Refresh List"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </Button>
        </div>
      </div>

      {/* 3. Investigations Table / List */}
      <Panel
        title={`Investigation Records (${filteredAnalyses.length})`}
        subtitle="Active and archived threat incident dossiers"
      >
        {loading ? (
          <div className="p-8 text-center text-xs font-mono text-foreground-muted animate-pulse">
            Loading investigation records...
          </div>
        ) : filteredAnalyses.length === 0 ? (
          <EmptyState
            icon={<FolderLock className="w-8 h-8 text-foreground-muted" />}
            title="No Investigations Found"
            description={
              searchQuery || severityFilter !== 'ALL'
                ? 'No records match the current filter criteria.'
                : 'No telemetry has been ingested yet. Upload an .eml payload or ingest endpoint telemetry to begin.'
            }
            action={
              <Button
                variant="primary"
                size="sm"
                onClick={() => navigate('/analyze')}
                leftIcon={<Plus className="w-3.5 h-3.5" />}
              >
                Ingest New Telemetry
              </Button>
            }
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-28">Severity</TableHead>
                <TableHead>Target Incident & Subject</TableHead>
                <TableHead>Threat Origin / Sender</TableHead>
                <TableHead className="w-24">Risk Score</TableHead>
                <TableHead className="w-32">Confidence</TableHead>
                <TableHead className="w-40">Observed (UTC)</TableHead>
                <TableHead className="w-24 text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAnalyses.map((item) => {
                const sev = item.threat_score?.severity || 'UNKNOWN';
                const score = item.threat_score?.score;
                const isActive = item.id === activeEmailId;
                const itemDate = item.date || item.upload_timestamp || new Date();

                return (
                  <TableRow
                    key={item.id || item.evidence_id}
                    className={`cursor-pointer transition-colors ${
                      isActive ? 'bg-primary-subtle/40' : 'hover:bg-surface-secondary/60'
                    }`}
                    onClick={() => handleOpenInvestigation(item.id)}
                  >
                    <TableCell>
                      <SeverityIndicator severity={sev} size="xs" pulse={String(sev).toUpperCase() === 'CRITICAL'} />
                    </TableCell>

                    <TableCell>
                      <div className="flex flex-col min-w-0 max-w-md">
                        <div className="flex items-center space-x-2">
                          <span className="font-semibold text-foreground truncate">
                            {item.subject || 'Untitled Telemetry Artifact'}
                          </span>
                          {isActive && (
                            <span className="text-[9px] font-mono font-bold px-1 rounded bg-primary/20 text-primary">
                              ACTIVE
                            </span>
                          )}
                        </div>
                        <span className="text-[10px] font-mono text-foreground-muted truncate">
                          ID: {item.id}
                        </span>
                      </div>
                    </TableCell>

                    <TableCell>
                      {item.from ? (
                        <EntityChip type="email" value={item.from} size="xs" truncateLength={28} />
                      ) : (
                        <span className="text-foreground-muted font-mono text-xs">—</span>
                      )}
                    </TableCell>

                    <TableCell>
                      <RiskBadge score={score} severity={sev} size="xs" variant="minimal" />
                    </TableCell>

                    <TableCell>
                      <ConfidenceIndicator
                        tier={item.threat_score?.confidence || 'HIGH'}
                        size="xs"
                        showPercentage={false}
                      />
                    </TableCell>

                    <TableCell>
                      <Timestamp date={itemDate} size="xs" />
                    </TableCell>

                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenInvestigation(item.id);
                        }}
                        rightIcon={<ArrowRight className="w-3 h-3" />}
                      >
                        Open
                      </Button>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Panel>
    </div>
  );
};

export default InvestigationsListPage;
