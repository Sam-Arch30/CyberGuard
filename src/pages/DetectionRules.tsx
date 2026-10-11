import React, { useState, useEffect } from 'react';
import {
  Plus,
  Play,
  RotateCcw,
  Sparkles,
  Search,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  GitCompare,
  Terminal,
  Activity,
  Trash2,
  Eye,
  Sliders,
  AlertOctagon,
  HelpCircle,
  Layers,
  Shield,
  ShieldCheck,
  CheckSquare,
  Square,
  Flame,
  Ban,
  RefreshCw,
  Copy,
  Zap,
  FlaskConical,
  Lock,
  History,
  Cpu,
} from 'lucide-react';
import { UnifiedDetectionPipelineView } from '../components/detection/UnifiedDetectionPipelineView';
import type {
  DetectionRule,
  DetectionRuleValidationResult,
  DetectionRuleBacktestResult,
  RuleVersionDiff,
  FieldDefinition,
  RuleCondition,
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
} from '../types/detectionRules';
import { detectionRuleService } from '../services/detectionRuleService';

interface DetectionRulesProps {
  defaultTab?: 'catalog' | 'builder' | 'detail' | 'pipeline';
}

export const DetectionRules: React.FC<DetectionRulesProps> = ({ defaultTab = 'catalog' }) => {
  const [activeTab, setActiveTab] = useState<'catalog' | 'builder' | 'detail' | 'pipeline'>(defaultTab);
  const [detailSubTab, setDetailSubTab] = useState<
    'overview' | 'health' | 'validation' | 'deployment' | 'exceptions' | 'quality' | 'testing'
  >('overview');

  // Operational Overview Stats & Catalog Data
  const [overviewStats, setOverviewStats] = useState<OperationalOverviewStats | null>(null);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [loadingRules, setLoadingRules] = useState(false);
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [selectedRule, setSelectedRule] = useState<DetectionRule | null>(null);

  // Field Registry for Builder & Operator Checking
  const [fieldRegistry, setFieldRegistry] = useState<FieldDefinition[]>([]);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [deploymentFilter, setDeploymentFilter] = useState<string>('ALL');
  const [healthFilter, setHealthFilter] = useState<string>('ALL');
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [reviewDueOnly, setReviewDueOnly] = useState(false);
  const [staleOnly, setStaleOnly] = useState(false);

  // Multi-select & Bulk Operations
  const [selectedRuleIds, setSelectedRuleIds] = useState<string[]>([]);
  const [isBulkModalOpen, setIsBulkModalOpen] = useState(false);
  const [bulkAction, setBulkAction] = useState<'ENABLE' | 'DISABLE' | 'SET_OWNER' | 'SET_COLLECTION' | 'TAG'>('ENABLE');
  const [bulkParam, setBulkParam] = useState('');
  const [bulkReason, setBulkReason] = useState('');
  const [bulkRunning, setBulkRunning] = useState(false);
  const [bulkResult, setBulkResult] = useState<BulkOperationResult | null>(null);

  // Toast feedback
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const showToast = (msg: string) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 4000);
  };

  // --------------------------------------------------------------------------
  // Rule Detail Operational State
  // --------------------------------------------------------------------------
  const [ruleHealth, setRuleHealth] = useState<RuleOperationalHealth | null>(null);

  // Pre-flight Dry-Run State
  const [dryRunResult, setDryRunResult] = useState<DeploymentDryRunResult | null>(null);
  const [runningDryRun, setRunningDryRun] = useState(false);

  // Deploy & Promote Modal
  const [isDeployModalOpen, setIsDeployModalOpen] = useState(false);
  const [targetDeployState, setTargetDeployState] = useState<'STAGING' | 'PRODUCTION'>('PRODUCTION');
  const [deployReason, setDeployReason] = useState('');
  const [deploying, setDeploying] = useState(false);

  // Rollback Modal
  const [isRollbackModalOpen, setIsRollbackModalOpen] = useState(false);
  const [rollbackVersion, setRollbackVersion] = useState('1');
  const [rollbackReason, setRollbackReason] = useState('');
  const [rollingBack, setRollingBack] = useState(false);

  // Emergency Disable Modal
  const [isEmergencyModalOpen, setIsEmergencyModalOpen] = useState(false);
  const [emergencyReason, setEmergencyReason] = useState('');
  const [emergencyDisabling, setEmergencyDisabling] = useState(false);

  // Simulation Modal
  const [isSimulateModalOpen, setIsSimulateModalOpen] = useState(false);
  const [simulateCount, setSimulateCount] = useState(25);
  const [simulating, setSimulating] = useState(false);
  const [simulationResult, setSimulationResult] = useState<RuleSimulationResult | null>(null);

  // Suppressions State
  const [suppressions, setSuppressions] = useState<RuleSuppression[]>([]);
  const [isAddSuppModalOpen, setIsAddSuppModalOpen] = useState(false);
  const [newSuppName, setNewSuppName] = useState('');
  const [newSuppReason, setNewSuppReason] = useState('');
  const [newSuppTarget, setNewSuppTarget] = useState('ip_address');
  const [newSuppOp, setNewSuppOp] = useState('EQUALS');
  const [newSuppVal, setNewSuppVal] = useState('');
  const [newSuppExpires, setNewSuppExpires] = useState(30);
  const [savingSuppression, setSavingSuppression] = useState(false);

  // Quality & Matches State
  const [qualityMetrics, setQualityMetrics] = useState<RuleQualityMetrics | null>(null);
  const [matches, setMatches] = useState<any[]>([]);
  const [dispositionNotes, setDispositionNotes] = useState('');

  // Ownership Update Modal
  const [isOwnershipModalOpen, setIsOwnershipModalOpen] = useState(false);
  const [newOwner, setNewOwner] = useState('');
  const [newTeam, setNewTeam] = useState('');
  const [newCollections, setNewCollections] = useState('');
  const [newInterval, setNewInterval] = useState(90);
  const [savingOwnership, setSavingOwnership] = useState(false);

  // Hunt Pattern
  const [copiedHunt, setCopiedHunt] = useState(false);

  // Redundancy / Conflict Checks
  const [duplicatesInfo, setDuplicatesInfo] = useState<any | null>(null);

  // Section 58: Continuous Validation & Rule Quality State
  const [latestValidation, setLatestValidation] = useState<ValidationRun | null>(null);
  const [validationHistory, setValidationHistory] = useState<ValidationRun[]>([]);
  const [gateCheck, setGateCheck] = useState<DeploymentGateCheck | null>(null);
  const [fixtures, setFixtures] = useState<TestFixture[]>([]);
  const [validatingNow, setValidatingNow] = useState(false);
  const [checkingGate, setCheckingGate] = useState(false);
  const [isAddFixtureModalOpen, setIsAddFixtureModalOpen] = useState(false);
  const [newFixName, setNewFixName] = useState('');
  const [newFixDesc, setNewFixDesc] = useState('');
  const [newFixType, setNewFixType] = useState<'POSITIVE' | 'NEGATIVE'>('POSITIVE');
  const [newFixExpected, setNewFixExpected] = useState(true);
  const [newFixPayloadStr, setNewFixPayloadStr] = useState('{\n  "sender_domain": "suspicious-phish.net",\n  "has_attachments": true\n}');
  const [savingFixture, setSavingFixture] = useState(false);
  const [runningFixtureId, setRunningFixtureId] = useState<string | null>(null);
  const [expandedCheckId, setExpandedCheckId] = useState<string | null>(null);
  const [validationOverview, setValidationOverview] = useState<ValidationOverview | null>(null);

  // --------------------------------------------------------------------------
  // Builder State
  // --------------------------------------------------------------------------
  const [builderName, setBuilderName] = useState('');
  const [builderDesc, setBuilderDesc] = useState('');
  const [builderCategory, setBuilderCategory] = useState('PHISHING');
  const [builderSeverity, setBuilderSeverity] = useState('HIGH');
  const [builderDataSource, setBuilderDataSource] = useState('EMAIL_EVENT');
  const [builderLogicalOp, setBuilderLogicalOp] = useState<'AND' | 'OR'>('AND');
  const [builderConditions, setBuilderConditions] = useState<RuleCondition[]>([
    { field: 'sender_domain', operator: 'CONTAINS', value: 'security-alert' },
  ]);
  const [builderTags, setBuilderTags] = useState('phishing, credential-theft');
  const [builderTechniques, setBuilderTechniques] = useState('T1566.002');
  const [builderOwner, setBuilderOwner] = useState('lead-analyst');
  const [builderTeam, setBuilderTeam] = useState('SOC-Tier2');
  const [builderCollections, setBuilderCollections] = useState('Email Security');
  const [validationResult, setValidationResult] = useState<DetectionRuleValidationResult | null>(null);
  const [validating, setValidating] = useState(false);
  const [savingRule, setSavingRule] = useState(false);

  // AI Suggestion State
  const [isAiModalOpen, setIsAiModalOpen] = useState(false);
  const [aiPrompt, setAiPrompt] = useState('');
  const [generatingAi, setGeneratingAi] = useState(false);

  // Backtest State
  const [backtestPreset, setBacktestPreset] = useState<'LAST_24_HOURS' | 'LAST_7_DAYS' | 'LAST_30_DAYS'>('LAST_30_DAYS');
  const [backtestRunning, setBacktestRunning] = useState(false);
  const [backtestResult, setBacktestResult] = useState<DetectionRuleBacktestResult | null>(null);

  // Version Diff State
  const [diffResult, setDiffResult] = useState<RuleVersionDiff | null>(null);
  const [loadingDiff, setLoadingDiff] = useState(false);

  // Live Event Test State
  const [testPayloadStr, setTestPayloadStr] = useState(
    JSON.stringify(
      {
        id: 'test-event-01',
        sender_domain: 'security-alert-corp.com',
        contains_login_url: true,
        url_count: 3,
      },
      null,
      2
    )
  );
  const [evaluatingTest, setEvaluatingTest] = useState(false);
  const [testMatchResult, setTestMatchResult] = useState<any[] | null>(null);

  // --------------------------------------------------------------------------
  // Data Loaders
  // --------------------------------------------------------------------------
  const refreshOverview = async () => {
    try {
      const ov = await detectionRuleService.getOperationalOverview();
      setOverviewStats(ov);
    } catch {
      // non-blocking
    }
  };

  const refreshRules = async () => {
    setLoadingRules(true);
    try {
      const res = await detectionRuleService.getRules({
        status: statusFilter === 'ALL' ? undefined : statusFilter,
        deployment_state: deploymentFilter === 'ALL' ? undefined : deploymentFilter,
        operational_health: healthFilter === 'ALL' ? undefined : healthFilter,
        category: categoryFilter === 'ALL' ? undefined : categoryFilter,
        severity: severityFilter === 'ALL' ? undefined : severityFilter,
        is_stale: staleOnly ? true : undefined,
        review_due: reviewDueOnly ? true : undefined,
        search: searchQuery.trim() || undefined,
        limit: 100,
      });
      setRules(res.items);
      refreshOverview();
    } catch (e: any) {
      showToast(e.message || 'Failed to fetch rules');
    } finally {
      setLoadingRules(false);
    }
  };

  const loadFieldRegistry = async () => {
    try {
      const reg = await detectionRuleService.getFieldRegistry();
      setFieldRegistry(reg);
    } catch {
      // non-blocking
    }
  };

  useEffect(() => {
    loadFieldRegistry();
    refreshRules();
  }, [statusFilter, deploymentFilter, healthFilter, categoryFilter, severityFilter, reviewDueOnly, staleOnly]);

  // Load single rule detail when selected
  useEffect(() => {
    if (!selectedRuleId) return;
    detectionRuleService
      .getRuleById(selectedRuleId)
      .then((r) => {
        setSelectedRule(r);
        setBacktestResult(null);
        setDiffResult(null);
        setTestMatchResult(null);
        setDryRunResult(null);
        setSimulationResult(null);
        setDuplicatesInfo(null);
        loadRuleOperationalDetails(r.id);
      })
      .catch((e) => showToast(e.message || 'Error loading rule details'));
  }, [selectedRuleId]);

  const loadRuleOperationalDetails = async (ruleId: string) => {
    // 1. Health
    detectionRuleService
      .getRuleHealth(ruleId)
      .then((h) => setRuleHealth(h))
      .catch(() => {});

    // 2. Suppressions
    detectionRuleService
      .getSuppressions(ruleId)
      .then((s) => setSuppressions(s))
      .catch(() => {});

    // 3. Quality & Matches
    detectionRuleService
      .getQualityMetrics(ruleId)
      .then((q) => setQualityMetrics(q))
      .catch(() => {});

    detectionRuleService
      .getRuleMatches(ruleId, 25)
      .then((m) => setMatches(m))
      .catch(() => {});

    // 4. Duplicates
    detectionRuleService
      .getRuleDuplicates(ruleId)
      .then((d) => setDuplicatesInfo(d))
      .catch(() => {});

    // 5. Section 58 Continuous Validation & Fixtures
    loadRuleValidationDetails(ruleId);
  };

  // Validate builder definition live
  useEffect(() => {
    if (activeTab !== 'builder') return;
    const def: RuleDefinition = {
      source: builderDataSource,
      logical_operator: builderLogicalOp,
      conditions: builderConditions,
    };
    setValidating(true);
    const timer = setTimeout(() => {
      detectionRuleService
        .validateRule(def)
        .then((v) => setValidationResult(v))
        .catch(() => {})
        .finally(() => setValidating(false));
    }, 250);
    return () => clearTimeout(timer);
  }, [builderConditions, builderLogicalOp, builderDataSource, activeTab]);

  // --------------------------------------------------------------------------
  // Condition Helpers for Builder
  // --------------------------------------------------------------------------
  const handleAddCondition = () => {
    setBuilderConditions([
      ...builderConditions,
      { field: 'sender_domain', operator: 'CONTAINS', value: '' },
    ]);
  };

  const handleRemoveCondition = (idx: number) => {
    setBuilderConditions(builderConditions.filter((_, i) => i !== idx));
  };

  const handleUpdateCondition = (idx: number, patch: Partial<RuleCondition>) => {
    const updated = [...builderConditions];
    updated[idx] = { ...updated[idx], ...patch };
    if (patch.field) {
      const fDef = fieldRegistry.find((f) => f.field === patch.field);
      if (fDef && !fDef.allowed_operators.includes(updated[idx].operator)) {
        updated[idx].operator = fDef.allowed_operators[0] || 'EQUALS';
      }
    }
    setBuilderConditions(updated);
  };

  const handleSaveRule = async () => {
    if (!builderName.trim()) {
      showToast('Rule Name is required.');
      return;
    }
    if (builderConditions.length === 0) {
      showToast('At least one condition is required.');
      return;
    }
    setSavingRule(true);
    try {
      const newRule = await detectionRuleService.createRule({
        name: builderName,
        description: builderDesc,
        category: builderCategory,
        data_sources: [builderDataSource],
        severity: builderSeverity,
        definition: {
          source: builderDataSource,
          logical_operator: builderLogicalOp,
          conditions: builderConditions,
        },
        tags: builderTags.split(',').map((t) => t.trim()).filter(Boolean),
        attack_techniques: builderTechniques.split(',').map((t) => t.trim()).filter(Boolean),
      });
      showToast(`Rule '${newRule.name}' (${newRule.rule_identifier}) created successfully!`);
      setSelectedRuleId(newRule.id);
      setActiveTab('detail');
      setDetailSubTab('overview');
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Failed to create detection rule');
    } finally {
      setSavingRule(false);
    }
  };

  // --------------------------------------------------------------------------
  // AI Rule Generation
  // --------------------------------------------------------------------------
  const handleGenerateFromAi = async () => {
    if (!aiPrompt.trim()) return;
    setGeneratingAi(true);
    try {
      const res = await detectionRuleService.suggestRuleFromAI({
        prompt: aiPrompt,
        category: builderCategory,
        target_data_sources: [builderDataSource],
      });
      setBuilderName(res.name);
      setBuilderDesc(res.description);
      setBuilderCategory(res.category);
      setBuilderSeverity(res.severity);
      if (res.data_sources?.length) setBuilderDataSource(res.data_sources[0]);
      if (res.definition?.conditions) setBuilderConditions(res.definition.conditions);
      if (res.definition?.logical_operator) setBuilderLogicalOp(res.definition.logical_operator as any);
      setIsAiModalOpen(false);
      setActiveTab('builder');
      showToast('AI Rule proposal loaded into builder. Validate and review conditions.');
    } catch (e: any) {
      showToast(e.message || 'AI rule generation failed');
    } finally {
      setGeneratingAi(false);
    }
  };

  // --------------------------------------------------------------------------
  // Deployment & Control Actions
  // --------------------------------------------------------------------------
  const handleDryRun = async () => {
    if (!selectedRule) return;
    setRunningDryRun(true);
    try {
      const res = await detectionRuleService.dryRunDeployment(selectedRule.id);
      setDryRunResult(res);
      showToast(`Dry-run evaluation: Risk is ${res.operational_risk}`);
    } catch (e: any) {
      showToast(e.message || 'Pre-flight dry run failed');
    } finally {
      setRunningDryRun(false);
    }
  };

  const handleExecuteDeploy = async () => {
    if (!selectedRule) return;
    setDeploying(true);
    try {
      const res = await detectionRuleService.deployRule(
        selectedRule.id,
        targetDeployState,
        selectedRule.version,
        deployReason || `Promoted to ${targetDeployState} via SOC console`
      );
      setSelectedRule(res);
      setIsDeployModalOpen(false);
      setDeployReason('');
      showToast(`Rule successfully transitioned to ${targetDeployState}!`);
      loadRuleOperationalDetails(res.id);
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Deployment failed');
    } finally {
      setDeploying(false);
    }
  };

  const handleExecuteRollback = async () => {
    if (!selectedRule) return;
    if (!rollbackReason.trim()) {
      showToast('Mandatory rollback justification is required.');
      return;
    }
    setRollingBack(true);
    try {
      const res = await detectionRuleService.rollbackRule(
        selectedRule.id,
        rollbackVersion,
        rollbackReason
      );
      setSelectedRule(res);
      setIsRollbackModalOpen(false);
      setRollbackReason('');
      showToast(`Rule rolled back to v${rollbackVersion}!`);
      loadRuleOperationalDetails(res.id);
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Rollback failed');
    } finally {
      setRollingBack(false);
    }
  };

  const handleExecuteEmergencyDisable = async () => {
    if (!selectedRule) return;
    if (!emergencyReason.trim()) {
      showToast('Mandatory emergency justification reason is required.');
      return;
    }
    setEmergencyDisabling(true);
    try {
      const res = await detectionRuleService.emergencyDisableRule(selectedRule.id, emergencyReason);
      setSelectedRule(res);
      setIsEmergencyModalOpen(false);
      setEmergencyReason('');
      showToast('Rule EMERGENCY-DISABLED. Alert emitted to SOC.');
      loadRuleOperationalDetails(res.id);
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Emergency disable failed');
    } finally {
      setEmergencyDisabling(false);
    }
  };

  const handleSimulateRule = async () => {
    if (!selectedRule) return;
    setSimulating(true);
    try {
      const res = await detectionRuleService.simulateRule(selectedRule.id, selectedRule.version, simulateCount);
      setSimulationResult(res);
      showToast(`Simulation completed: ${res.simulated_matches_count} matches observed without production alerts.`);
    } catch (e: any) {
      showToast(e.message || 'Simulation failed');
    } finally {
      setSimulating(false);
    }
  };

  // --------------------------------------------------------------------------
  // Suppressions Actions
  // --------------------------------------------------------------------------
  const handleCreateSuppression = async () => {
    if (!selectedRule || !newSuppName.trim() || !newSuppVal.trim() || !newSuppReason.trim()) {
      showToast('Name, match value, and justification reason are required.');
      return;
    }
    setSavingSuppression(true);
    try {
      await detectionRuleService.createSuppression(selectedRule.id, {
        name: newSuppName,
        reason: newSuppReason,
        scope_target: newSuppTarget,
        match_operator: newSuppOp,
        match_value: newSuppVal,
        expires_in_days: newSuppExpires,
      });
      showToast('Suppression exception rule created successfully.');
      setIsAddSuppModalOpen(false);
      setNewSuppName('');
      setNewSuppReason('');
      setNewSuppVal('');
      loadRuleOperationalDetails(selectedRule.id);
    } catch (e: any) {
      showToast(e.message || 'Failed to create suppression');
    } finally {
      setSavingSuppression(false);
    }
  };

  const handleDeleteSuppression = async (suppId: string) => {
    if (!selectedRule) return;
    try {
      await detectionRuleService.deleteSuppression(selectedRule.id, suppId);
      showToast('Suppression exception removed.');
      loadRuleOperationalDetails(selectedRule.id);
    } catch (e: any) {
      showToast(e.message || 'Failed to remove suppression');
    }
  };

  // --------------------------------------------------------------------------
  // Ground-Truth Feedback Disposition
  // --------------------------------------------------------------------------
  const handleRecordDisposition = async (matchId: string, disp: string) => {
    if (!selectedRule) return;
    try {
      await detectionRuleService.recordMatchDisposition(matchId, {
        disposition: disp,
        notes: dispositionNotes || 'Analyst feedback',
      });
      showToast(`Feedback recorded: ${disp}`);
      setDispositionNotes('');
      loadRuleOperationalDetails(selectedRule.id);
    } catch (e: any) {
      showToast(e.message || 'Failed to record disposition');
    }
  };

  // --------------------------------------------------------------------------
  // Export Hunt Pattern
  // --------------------------------------------------------------------------
  const handleExportHunt = async () => {
    if (!selectedRule) return;
    try {
      const p = await detectionRuleService.getHuntPattern(selectedRule.id);
      navigator.clipboard.writeText(JSON.stringify(p, null, 2));
      setCopiedHunt(true);
      setTimeout(() => setCopiedHunt(false), 3000);
      showToast('Structured Hunt Pattern copied to clipboard (Ready for Section 54/55 Threat Hunt).');
    } catch (e: any) {
      showToast(e.message || 'Failed to export hunt pattern');
    }
  };

  // --------------------------------------------------------------------------
  // Update Ownership
  // --------------------------------------------------------------------------
  const handleSaveOwnership = async () => {
    if (!selectedRule) return;
    setSavingOwnership(true);
    try {
      const colls = newCollections
        .split(',')
        .map((c) => c.trim())
        .filter(Boolean);
      const res = await detectionRuleService.updateOwnership(selectedRule.id, {
        owner_id: newOwner || undefined,
        team_id: newTeam || undefined,
        collections: colls,
        review_interval_days: newInterval || 90,
      });
      setSelectedRule(res);
      setIsOwnershipModalOpen(false);
      showToast('Ownership and review interval updated.');
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Failed to update ownership');
    } finally {
      setSavingOwnership(false);
    }
  };

  // --------------------------------------------------------------------------
  // Section 58 Continuous Validation & Fixture Handlers
  // --------------------------------------------------------------------------
  const loadRuleValidationDetails = async (ruleId: string) => {
    try {
      detectionRuleService.getLatestValidation(ruleId).then((v) => setLatestValidation(v)).catch(() => {});
      detectionRuleService.getDeploymentGate(ruleId).then((g) => setGateCheck(g)).catch(() => {});
      detectionRuleService.getValidationHistory(ruleId).then((h) => setValidationHistory(h)).catch(() => {});
      detectionRuleService.getFixtures(ruleId).then((f) => setFixtures(f)).catch(() => {});
      detectionRuleService.getValidationOverview().then((ov) => setValidationOverview(ov)).catch(() => {});
    } catch {
      // non-blocking
    }
  };

  const handleTriggerValidation = async (runAsync: boolean = false) => {
    if (!selectedRule) return;
    setValidatingNow(true);
    try {
      const res = await detectionRuleService.triggerValidation(selectedRule.id, {
        validation_type: 'FULL',
        trigger_type: 'MANUAL',
        run_async: runAsync,
      });
      setLatestValidation(res);
      showToast(`Validation completed with status: ${res.status}. ${res.checks.length} checks performed.`);
      loadRuleValidationDetails(selectedRule.id);
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Validation failed');
    } finally {
      setValidatingNow(false);
    }
  };

  const handleCheckDeploymentGate = async () => {
    if (!selectedRule) return;
    setCheckingGate(true);
    try {
      const res = await detectionRuleService.getDeploymentGate(selectedRule.id, selectedRule.version);
      setGateCheck(res);
      if (res.can_promote) {
        showToast('Deployment Gate Passed! Rule is safe for production.');
      } else {
        showToast(`Deployment Gate Blocked: ${res.blocking_reasons.join('; ')}`);
      }
    } catch (e: any) {
      showToast(e.message || 'Gate check failed');
    } finally {
      setCheckingGate(false);
    }
  };

  const handleCreateFixture = async () => {
    if (!selectedRule || !newFixName.trim()) {
      showToast('Fixture name is required.');
      return;
    }
    let parsedPayload = {};
    try {
      parsedPayload = JSON.parse(newFixPayloadStr);
    } catch (e) {
      showToast('Invalid JSON in payload.');
      return;
    }
    setSavingFixture(true);
    try {
      await detectionRuleService.createFixture(selectedRule.id, {
        name: newFixName,
        description: newFixDesc,
        fixture_type: newFixType,
        payload: parsedPayload,
        expected_match: newFixExpected,
      });
      showToast('Test fixture created successfully.');
      setIsAddFixtureModalOpen(false);
      setNewFixName('');
      setNewFixDesc('');
      detectionRuleService.getFixtures(selectedRule.id).then((f) => setFixtures(f));
    } catch (e: any) {
      showToast(e.message || 'Failed to create fixture');
    } finally {
      setSavingFixture(false);
    }
  };

  const handleRunFixture = async (fixtureId: string) => {
    if (!selectedRule) return;
    setRunningFixtureId(fixtureId);
    try {
      const res = await detectionRuleService.runFixture(selectedRule.id, fixtureId);
      showToast(`Fixture executed: ${res.last_result}`);
      detectionRuleService.getFixtures(selectedRule.id).then((f) => setFixtures(f));
    } catch (e: any) {
      showToast(e.message || 'Failed to run fixture');
    } finally {
      setRunningFixtureId(null);
    }
  };

  const handleDeleteFixture = async (fixtureId: string) => {
    if (!selectedRule) return;
    try {
      await detectionRuleService.deleteFixture(selectedRule.id, fixtureId);
      showToast('Fixture deleted.');
      detectionRuleService.getFixtures(selectedRule.id).then((f) => setFixtures(f));
    } catch (e: any) {
      showToast(e.message || 'Failed to delete fixture');
    }
  };

  // --------------------------------------------------------------------------
  // Bulk Operations
  // --------------------------------------------------------------------------
  const handleExecuteBulk = async () => {
    if (selectedRuleIds.length === 0) return;
    setBulkRunning(true);
    try {
      const params: Record<string, any> = {};
      if (bulkAction === 'SET_OWNER') params.owner_id = bulkParam;
      if (bulkAction === 'SET_COLLECTION') params.collection = bulkParam;
      if (bulkAction === 'TAG') params.tag = bulkParam;

      const res = await detectionRuleService.bulkOperation({
        rule_ids: selectedRuleIds,
        action: bulkAction,
        parameters: params,
        reason: bulkReason || 'Bulk SOC operational action',
      });
      setBulkResult(res);
      showToast(`Bulk ${bulkAction} finished: ${res.successful} success, ${res.failed} failed.`);
      refreshRules();
    } catch (e: any) {
      showToast(e.message || 'Bulk operation failed');
    } finally {
      setBulkRunning(false);
    }
  };

  // Toggle selection
  const toggleSelectRule = (id: string) => {
    setSelectedRuleIds((prev) =>
      prev.includes(id) ? prev.filter((r) => r !== id) : [...prev, id]
    );
  };

  const toggleSelectAll = () => {
    if (selectedRuleIds.length === rules.length) {
      setSelectedRuleIds([]);
    } else {
      setSelectedRuleIds(rules.map((r) => r.id));
    }
  };

  // --------------------------------------------------------------------------
  // Historical Backtesting
  // --------------------------------------------------------------------------
  const handleRunBacktest = async () => {
    if (!selectedRule) return;
    setBacktestRunning(true);
    try {
      const res = await detectionRuleService.backtestRule(selectedRule.id, {
        time_range_preset: backtestPreset,
        max_records: 300,
        run_async: false,
      });
      setBacktestResult(res);
      showToast(`Backtest completed! Evaluated ${res.records_evaluated} records, found ${res.matches_count} matches.`);
    } catch (e: any) {
      showToast(e.message || 'Historical backtesting failed');
    } finally {
      setBacktestRunning(false);
    }
  };

  // Version Diff Viewer
  const handleComputeDiff = async () => {
    if (!selectedRule) return;
    setLoadingDiff(true);
    try {
      const diff = await detectionRuleService.getVersionDiff(selectedRule.id, '1', selectedRule.version);
      setDiffResult(diff);
    } catch (e: any) {
      showToast(e.message || 'Failed to compute version difference');
    } finally {
      setLoadingDiff(false);
    }
  };

  // Live Event Test
  const handleTestEvent = async () => {
    if (!selectedRule) return;
    setEvaluatingTest(true);
    try {
      const parsed = JSON.parse(testPayloadStr);
      const matchesResult = await detectionRuleService.evaluateLiveEvent(parsed, selectedRule.data_sources[0] || 'EMAIL_EVENT');
      setTestMatchResult(matchesResult);
      if (matchesResult.length > 0) {
        showToast(`Rule Matched incoming test event! (${matchesResult.length} matches)`);
      } else {
        showToast('Rule did NOT trigger for test payload.');
      }
    } catch (e: any) {
      showToast(e.message || 'Failed to evaluate test event (check JSON format)');
    } finally {
      setEvaluatingTest(false);
    }
  };

  // --------------------------------------------------------------------------
  // Badges
  // --------------------------------------------------------------------------
  const getDeploymentBadge = (state?: string) => {
    switch (state) {
      case 'PRODUCTION':
        return <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">PROD</span>;
      case 'STAGING':
        return <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30">STAGING</span>;
      case 'DRAFT':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">DRAFT</span>;
      case 'DISABLED':
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-red-500/15 text-red-400 border border-red-500/30">DISABLED</span>;
      default:
        return <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-zinc-500/15 text-zinc-400 border border-zinc-500/30">{state || 'NONE'}</span>;
    }
  };

  const getHealthBadge = (health?: string, reason?: string) => {
    switch (health) {
      case 'HEALTHY':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30" title={reason || 'Operational health nominal'}>
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>HEALTHY</span>
          </span>
        );
      case 'DEGRADED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-500/15 text-amber-400 border border-amber-500/30" title={reason || 'Operational health degraded'}>
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            <span>DEGRADED</span>
          </span>
        );
      case 'FAILING':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-red-500/15 text-red-400 border border-red-500/30" title={reason || 'Rule failing critical dependency or execution SLA'}>
            <XCircle className="w-3 h-3 text-red-400" />
            <span>FAILING</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono rounded bg-zinc-500/15 text-zinc-400 border border-zinc-500/30" title={reason || 'Telemetry unknown'}>
            <HelpCircle className="w-3 h-3 text-zinc-400" />
            <span>UNKNOWN</span>
          </span>
        );
    }
  };

  const getValidationBadge = (valStatus?: string) => {
    switch (valStatus) {
      case 'PASS':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            <span>PASS</span>
          </span>
        );
      case 'PASS_WITH_WARNINGS':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            <span>WARNING</span>
          </span>
        );
      case 'FAIL':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-red-500/15 text-red-400 border border-red-500/30">
            <XCircle className="w-3 h-3 text-red-400" />
            <span>FAIL</span>
          </span>
        );
      case 'BLOCKED':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-orange-500/15 text-orange-400 border border-orange-500/30">
            <Ban className="w-3 h-3 text-orange-400" />
            <span>BLOCKED</span>
          </span>
        );
      case 'TIMED_OUT':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-red-500/15 text-red-400 border border-red-500/30">
            <AlertOctagon className="w-3 h-3 text-red-400" />
            <span>TIMEOUT</span>
          </span>
        );
      case 'STALE':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono rounded bg-purple-500/15 text-purple-400 border border-purple-500/30">
            <RotateCcw className="w-3 h-3 text-purple-400" />
            <span>STALE</span>
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 animate-pulse">
            <RefreshCw className="w-3 h-3 text-cyan-400 animate-spin" />
            <span>RUNNING</span>
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center space-x-1 px-2 py-0.5 text-[10px] font-mono rounded bg-zinc-500/15 text-zinc-400 border border-zinc-500/30">
            <span>NOT RUN</span>
          </span>
        );
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">CRIT</span>;
      case 'HIGH':
        return <span className="text-[10px] font-mono font-bold px-1.5 py-0.5 rounded bg-orange-500/20 text-orange-400 border border-orange-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">MED</span>;
      case 'LOW':
        return <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 border border-blue-500/30">LOW</span>;
      default:
        return <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-500/20 text-zinc-400">INFO</span>;
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-background text-foreground">
      {/* Toast Banner */}
      {toastMessage && (
        <div className="fixed top-5 right-5 z-50 bg-surface-secondary border border-primary/50 text-foreground px-4 py-3 rounded-lg shadow-xl flex items-center space-x-2 text-xs font-mono animate-in fade-in duration-200">
          <Activity className="w-4 h-4 text-primary shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header & Operational Stats Bar */}
      <header className="border-b border-border bg-surface px-6 py-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-primary/10 text-primary border border-primary/20">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-lg font-bold tracking-tight text-foreground">
                  Detection Rule Management & Operational Control
                </h1>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-primary/10 text-primary border border-primary/20">
                  SEC-57
                </span>
              </div>
              <p className="text-xs text-foreground-muted">
                Enterprise SOC operational control layer: Health telemetry, staged promotion, safe rollback, and scoped suppressions.
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            <button
              onClick={() => setIsAiModalOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground hover:border-primary/40 transition-colors"
            >
              <Sparkles className="w-3.5 h-3.5 text-primary" />
              <span>AI Rule Assistant</span>
            </button>
            <button
              onClick={() => {
                setActiveTab('builder');
                setBuilderName('');
                setBuilderDesc('');
                setBuilderConditions([{ field: 'sender_domain', operator: 'CONTAINS', value: '' }]);
              }}
              className="flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Rule</span>
            </button>
            <button
              onClick={refreshRules}
              className="p-1.5 rounded-md hover:bg-surface-secondary text-foreground-muted hover:text-foreground border border-border transition-colors"
              title="Refresh Rule Catalog"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Global Operational Metrics Strip */}
        <div className="grid grid-cols-2 sm:grid-cols-5 lg:grid-cols-10 gap-2.5 mt-4">
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-foreground-muted uppercase">Total Rules</span>
            <span className="text-base font-bold font-mono text-foreground">{overviewStats?.total_rules ?? rules.length}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-emerald-400/80 uppercase">Active (Prod)</span>
            <span className="text-base font-bold font-mono text-emerald-400">{overviewStats?.active_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-cyan-400/80 uppercase">Staging</span>
            <span className="text-base font-bold font-mono text-cyan-400">{overviewStats?.staging_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-emerald-400/80 uppercase">Healthy</span>
            <span className="text-base font-bold font-mono text-emerald-400">{overviewStats?.healthy_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-emerald-400/80 uppercase">Validated (Pass)</span>
            <span className="text-base font-bold font-mono text-emerald-400">{validationOverview?.passed_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-amber-400/80 uppercase">Drift Warnings</span>
            <span className="text-base font-bold font-mono text-amber-400">
              {(validationOverview?.schema_drift_detected_count ?? 0) + (validationOverview?.performance_regression_count ?? 0)}
            </span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-amber-400/80 uppercase">Degraded</span>
            <span className="text-base font-bold font-mono text-amber-400">{overviewStats?.degraded_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-red-400/80 uppercase">Failing</span>
            <span className="text-base font-bold font-mono text-red-400">{overviewStats?.failing_rules ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-purple-400/80 uppercase">Review Due</span>
            <span className="text-base font-bold font-mono text-purple-400">{overviewStats?.review_due_count ?? 0}</span>
          </div>
          <div className="p-2.5 rounded-lg bg-surface-secondary/40 border border-border flex flex-col">
            <span className="text-[10px] font-mono text-primary/80 uppercase">24h Matches</span>
            <span className="text-base font-bold font-mono text-primary">{overviewStats?.total_matches_24h ?? 0}</span>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex space-x-1 border-t border-border mt-4 pt-3">
          <button
            onClick={() => setActiveTab('catalog')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
              activeTab === 'catalog'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Rule Library & SOC Grid</span>
          </button>
          <button
            onClick={() => setActiveTab('builder')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
              activeTab === 'builder'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            <span>Rule Compiler</span>
          </button>
          <button
            onClick={() => setActiveTab('pipeline')}
            className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
              activeTab === 'pipeline'
                ? 'bg-primary/10 text-primary border border-primary/20'
                : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Unified Detection Pipeline</span>
          </button>
          {selectedRule && (
            <button
              onClick={() => setActiveTab('detail')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
                activeTab === 'detail'
                  ? 'bg-primary/10 text-primary border border-primary/20'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Control: {selectedRule.rule_identifier}</span>
            </button>
          )}
        </div>
      </header>

      {/* Main Tab Region */}
      <main className="flex-1 p-6">
        {/* ================================================================== */}
        {/* TAB 1: CATALOG / SOC OPERATIONAL GRID                              */}
        {/* ================================================================== */}
        {activeTab === 'catalog' && (
          <div className="space-y-4">
            {/* Filter Bar */}
            <div className="flex flex-wrap items-center gap-3 p-3 rounded-lg bg-surface border border-border">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-foreground-muted" />
                <input
                  type="text"
                  placeholder="Search by name, identifier, owner, tags, ATT&CK..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && refreshRules()}
                  className="w-full pl-9 pr-3 py-1.5 text-xs rounded bg-surface-secondary border border-border focus:outline-none focus:border-primary text-foreground"
                />
              </div>

              {/* Status Filter */}
              <div className="flex items-center space-x-1.5">
                <span className="text-[11px] font-mono text-foreground-muted">Status:</span>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">ALL STATUSES</option>
                  <option value="ACTIVE">ACTIVE</option>
                  <option value="STAGED">STAGED</option>
                  <option value="APPROVED">APPROVED</option>
                  <option value="CANDIDATE">CANDIDATE</option>
                  <option value="DRAFT">DRAFT</option>
                  <option value="DISABLED">DISABLED</option>
                </select>
              </div>

              {/* Deployment Filter */}
              <div className="flex items-center space-x-1.5">
                <span className="text-[11px] font-mono text-foreground-muted">Deploy:</span>
                <select
                  value={deploymentFilter}
                  onChange={(e) => setDeploymentFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">ALL STAGES</option>
                  <option value="PRODUCTION">PRODUCTION</option>
                  <option value="STAGING">STAGING</option>
                  <option value="DRAFT">DRAFT</option>
                  <option value="DISABLED">DISABLED</option>
                </select>
              </div>

              {/* Health Filter */}
              <div className="flex items-center space-x-1.5">
                <span className="text-[11px] font-mono text-foreground-muted">Health:</span>
                <select
                  value={healthFilter}
                  onChange={(e) => setHealthFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">ALL HEALTH</option>
                  <option value="HEALTHY">HEALTHY</option>
                  <option value="DEGRADED">DEGRADED</option>
                  <option value="FAILING">FAILING</option>
                  <option value="UNKNOWN">UNKNOWN</option>
                </select>
              </div>

              {/* Severity Filter */}
              <div className="flex items-center space-x-1.5">
                <span className="text-[11px] font-mono text-foreground-muted">Severity:</span>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">ALL</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                </select>
              </div>

              {/* Category Filter */}
              <div className="flex items-center space-x-1.5">
                <span className="text-[11px] font-mono text-foreground-muted">Category:</span>
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                >
                  <option value="ALL">ALL</option>
                  <option value="PHISHING">PHISHING</option>
                  <option value="IMPERSONATION">IMPERSONATION</option>
                  <option value="CREDENTIAL_THEFT">CREDENTIAL THEFT</option>
                  <option value="MALWARE">MALWARE</option>
                  <option value="ENDPOINT">ENDPOINT</option>
                  <option value="NETWORK">NETWORK</option>
                  <option value="ACCOUNT_TAKEOVER">ACCOUNT TAKEOVER</option>
                </select>
              </div>

              {/* Review Due Checkbox */}
              <label className="flex items-center space-x-1.5 text-xs text-foreground-muted cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={reviewDueOnly}
                  onChange={(e) => setReviewDueOnly(e.target.checked)}
                  className="rounded border-border text-primary focus:ring-0"
                />
                <span className="font-mono text-[11px]">Review Due</span>
              </label>

              {/* Stale Only Checkbox */}
              <label className="flex items-center space-x-1.5 text-xs text-foreground-muted cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={staleOnly}
                  onChange={(e) => setStaleOnly(e.target.checked)}
                  className="rounded border-border text-primary focus:ring-0"
                />
                <span className="font-mono text-[11px]">Stale</span>
              </label>
            </div>

            {/* Bulk Action Toolbar (appears when 1+ rules selected) */}
            {selectedRuleIds.length > 0 && (
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-primary/10 border border-primary/30 text-xs animate-in fade-in">
                <div className="flex items-center space-x-2 font-mono">
                  <CheckSquare className="w-4 h-4 text-primary" />
                  <span className="font-semibold text-primary">{selectedRuleIds.length}</span>
                  <span className="text-foreground">rules selected</span>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => {
                      setBulkAction('ENABLE');
                      setIsBulkModalOpen(true);
                    }}
                    className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-emerald-400 font-mono text-[11px]"
                  >
                    Enable Selected
                  </button>
                  <button
                    onClick={() => {
                      setBulkAction('DISABLE');
                      setIsBulkModalOpen(true);
                    }}
                    className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-red-400 font-mono text-[11px]"
                  >
                    Disable Selected
                  </button>
                  <button
                    onClick={() => {
                      setBulkAction('SET_OWNER');
                      setIsBulkModalOpen(true);
                    }}
                    className="px-2.5 py-1 rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-cyan-400 font-mono text-[11px]"
                  >
                    Assign Owner
                  </button>
                  <button
                    onClick={() => setSelectedRuleIds([])}
                    className="px-2.5 py-1 rounded hover:bg-surface-secondary text-foreground-muted font-mono text-[11px]"
                  >
                    Clear Selection
                  </button>
                </div>
              </div>
            )}

            {/* SOC Rules Table */}
            <div className="rounded-lg border border-border bg-surface overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-surface-secondary/50 text-foreground-muted uppercase font-mono text-[10px] border-b border-border">
                    <tr>
                      <th className="p-3 w-8 text-center">
                        <button onClick={toggleSelectAll} className="p-0.5 hover:text-foreground">
                          {selectedRuleIds.length === rules.length && rules.length > 0 ? (
                            <CheckSquare className="w-3.5 h-3.5 text-primary" />
                          ) : (
                            <Square className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </th>
                      <th className="p-3 font-semibold">Rule Name & ID</th>
                      <th className="p-3 font-semibold">Deploy State</th>
                      <th className="p-3 font-semibold">Health</th>
                      <th className="p-3 font-semibold">Validation</th>
                      <th className="p-3 font-semibold">Ver</th>
                      <th className="p-3 font-semibold">Severity</th>
                      <th className="p-3 font-semibold">Owner / Team</th>
                      <th className="p-3 font-semibold">Data Sources</th>
                      <th className="p-3 font-semibold">24h Matches</th>
                      <th className="p-3 font-semibold">Next Review</th>
                      <th className="p-3 font-semibold text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border font-sans">
                    {loadingRules ? (
                      <tr>
                        <td colSpan={12} className="p-8 text-center text-foreground-muted font-mono">
                          <Activity className="w-5 h-5 animate-spin mx-auto mb-2 text-primary" />
                          Loading enterprise rule library...
                        </td>
                      </tr>
                    ) : rules.length === 0 ? (
                      <tr>
                        <td colSpan={12} className="p-8 text-center text-foreground-muted font-mono">
                          No detection rules matched the specified criteria.
                        </td>
                      </tr>
                    ) : (
                      rules.map((rule) => {
                        const isSelected = selectedRuleIds.includes(rule.id);
                        return (
                          <tr
                            key={rule.id}
                            className={`hover:bg-surface-secondary/30 transition-colors ${
                              selectedRuleId === rule.id ? 'bg-primary/5' : ''
                            }`}
                          >
                            <td className="p-3 text-center">
                              <input
                                type="checkbox"
                                checked={isSelected}
                                onChange={() => toggleSelectRule(rule.id)}
                                className="rounded border-border text-primary focus:ring-0"
                              />
                            </td>
                            <td className="p-3">
                              <div className="flex flex-col">
                                <span className="font-semibold text-foreground">{rule.name}</span>
                                <span className="font-mono text-[10px] text-primary">{rule.rule_identifier}</span>
                              </div>
                            </td>
                            <td className="p-3">{getDeploymentBadge(rule.deployment_state)}</td>
                            <td className="p-3">{getHealthBadge(rule.operational_health, rule.health_reason)}</td>
                            <td className="p-3">{getValidationBadge(rule.validation_status)}</td>
                            <td className="p-3 font-mono text-[11px] text-foreground-muted">v{rule.version}</td>
                            <td className="p-3">{getSeverityBadge(rule.severity)}</td>
                            <td className="p-3 font-mono text-[11px]">
                              <div className="flex flex-col">
                                <span className="text-foreground">{rule.owner_id || 'unassigned'}</span>
                                <span className="text-[10px] text-foreground-muted">{rule.team_id || 'SOC'}</span>
                              </div>
                            </td>
                            <td className="p-3 font-mono text-[10px] text-foreground-muted">
                              {rule.data_sources?.slice(0, 2).join(', ')}
                              {(rule.data_sources?.length || 0) > 2 && ' +more'}
                            </td>
                            <td className="p-3 font-mono text-[11px]">
                              <div className="flex items-center space-x-1.5">
                                <span className="font-semibold text-foreground">{rule.total_match_count ?? 0}</span>
                              </div>
                            </td>
                            <td className="p-3 font-mono text-[10px] text-foreground-muted">
                              {rule.review_due ? (
                                <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 font-bold">DUE NOW</span>
                              ) : rule.next_review_due ? (
                                new Date(rule.next_review_due).toLocaleDateString()
                              ) : (
                                '90d policy'
                              )}
                            </td>
                            <td className="p-3 text-right">
                              <button
                                onClick={() => {
                                  setSelectedRuleId(rule.id);
                                  setActiveTab('detail');
                                  setDetailSubTab('overview');
                                }}
                                className="px-2.5 py-1 text-xs font-medium rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground hover:border-primary/50 transition-colors inline-flex items-center space-x-1"
                              >
                                <Eye className="w-3 h-3 text-primary" />
                                <span>Control</span>
                              </button>
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================== */}
        {/* TAB 2: AST RULE COMPILER / BUILDER                                 */}
        {/* ================================================================== */}
        {activeTab === 'builder' && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-5">
              <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                <h2 className="text-sm font-semibold tracking-wide uppercase text-foreground-muted font-mono flex items-center justify-between">
                  <span>Rule Metadata & Governance</span>
                  <Sliders className="w-4 h-4 text-primary" />
                </h2>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Rule Name *</label>
                    <input
                      type="text"
                      placeholder="e.g. Lookalike Financial Phishing Domain"
                      value={builderName}
                      onChange={(e) => setBuilderName(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                    />
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Category *</label>
                    <select
                      value={builderCategory}
                      onChange={(e) => setBuilderCategory(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                    >
                      <option value="PHISHING">PHISHING</option>
                      <option value="IMPERSONATION">IMPERSONATION</option>
                      <option value="CREDENTIAL_THEFT">CREDENTIAL_THEFT</option>
                      <option value="MALWARE">MALWARE</option>
                      <option value="ENDPOINT">ENDPOINT</option>
                      <option value="NETWORK">NETWORK</option>
                      <option value="ACCOUNT_TAKEOVER">ACCOUNT_TAKEOVER</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Target Data Source *</label>
                    <select
                      value={builderDataSource}
                      onChange={(e) => setBuilderDataSource(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                    >
                      <option value="EMAIL_EVENT">EMAIL_EVENT</option>
                      <option value="ENDPOINT_EVENT">ENDPOINT_EVENT</option>
                      <option value="NETWORK_EVENT">NETWORK_EVENT</option>
                      <option value="AUTH_EVENT">AUTH_EVENT</option>
                      <option value="INDICATOR">INDICATOR</option>
                    </select>
                  </div>

                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Severity</label>
                    <select
                      value={builderSeverity}
                      onChange={(e) => setBuilderSeverity(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                    >
                      <option value="CRITICAL">CRITICAL</option>
                      <option value="HIGH">HIGH</option>
                      <option value="MEDIUM">MEDIUM</option>
                      <option value="LOW">LOW</option>
                      <option value="INFORMATIONAL">INFORMATIONAL</option>
                    </select>
                  </div>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-mono text-foreground-muted">Description / Rationale</label>
                  <textarea
                    rows={2}
                    placeholder="Describe threat vector, adversary intent, and intended detection objective..."
                    value={builderDesc}
                    onChange={(e) => setBuilderDesc(e.target.value)}
                    className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                  />
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Tags (csv)</label>
                    <input
                      type="text"
                      value={builderTags}
                      onChange={(e) => setBuilderTags(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">ATT&CK Techniques</label>
                    <input
                      type="text"
                      value={builderTechniques}
                      onChange={(e) => setBuilderTechniques(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Collections</label>
                    <input
                      type="text"
                      value={builderCollections}
                      onChange={(e) => setBuilderCollections(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary"
                    />
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Owner Analyst</label>
                    <input
                      type="text"
                      value={builderOwner}
                      onChange={(e) => setBuilderOwner(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                    />
                  </div>
                  <div className="space-y-1">
                    <label className="text-xs font-mono text-foreground-muted">Team</label>
                    <input
                      type="text"
                      value={builderTeam}
                      onChange={(e) => setBuilderTeam(e.target.value)}
                      className="w-full px-3 py-1.5 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary"
                    />
                  </div>
                </div>
              </div>

              {/* AST Condition Tree Editor */}
              <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <h2 className="text-sm font-semibold tracking-wide uppercase text-foreground-muted font-mono">
                      AST Condition Tree
                    </h2>
                    <div className="flex items-center rounded border border-border bg-surface-secondary p-0.5 font-mono text-[11px]">
                      <button
                        onClick={() => setBuilderLogicalOp('AND')}
                        className={`px-2 py-0.5 rounded ${
                          builderLogicalOp === 'AND' ? 'bg-primary text-black font-bold' : 'text-foreground-muted'
                        }`}
                      >
                        AND
                      </button>
                      <button
                        onClick={() => setBuilderLogicalOp('OR')}
                        className={`px-2 py-0.5 rounded ${
                          builderLogicalOp === 'OR' ? 'bg-primary text-black font-bold' : 'text-foreground-muted'
                        }`}
                      >
                        OR
                      </button>
                    </div>
                  </div>
                  <button
                    onClick={handleAddCondition}
                    className="flex items-center space-x-1 px-2.5 py-1 text-xs rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors"
                  >
                    <Plus className="w-3.5 h-3.5 text-primary" />
                    <span>Add Condition</span>
                  </button>
                </div>

                <div className="space-y-3">
                  {builderConditions.map((cond, idx) => {
                    const fDef = fieldRegistry.find((f) => f.field === cond.field);
                    const allowedOps = fDef?.allowed_operators || [
                      'EQUALS',
                      'CONTAINS',
                      'GREATER_THAN',
                      'LESS_THAN',
                      'REGEX',
                    ];
                    return (
                      <div
                        key={idx}
                        className="flex flex-wrap sm:flex-nowrap items-center gap-2 p-2.5 rounded bg-surface-secondary/40 border border-border"
                      >
                        <select
                          value={cond.field}
                          onChange={(e) => handleUpdateCondition(idx, { field: e.target.value })}
                          className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary flex-1 min-w-[140px]"
                        >
                          {fieldRegistry.map((f) => (
                            <option key={f.field} value={f.field}>
                              {f.field} ({f.field_type})
                            </option>
                          ))}
                        </select>

                        <select
                          value={cond.operator}
                          onChange={(e) => handleUpdateCondition(idx, { operator: e.target.value })}
                          className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary w-[120px]"
                        >
                          {allowedOps.map((op) => (
                            <option key={op} value={op}>
                              {op}
                            </option>
                          ))}
                        </select>

                        <input
                          type="text"
                          placeholder="value..."
                          value={String(cond.value ?? '')}
                          onChange={(e) => handleUpdateCondition(idx, { value: e.target.value })}
                          className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary flex-1 min-w-[120px]"
                        />

                        {builderConditions.length > 1 && (
                          <button
                            onClick={() => handleRemoveCondition(idx)}
                            className="p-1 hover:text-red-400 text-foreground-muted transition-colors"
                            title="Remove condition"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Validation & Compilation Preview Panel */}
            <div className="space-y-5">
              <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center justify-between">
                  <span>Static AST Validation</span>
                  {validating ? (
                    <RefreshCw className="w-3.5 h-3.5 text-primary animate-spin" />
                  ) : validationResult?.is_valid ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                  )}
                </h3>

                {validationResult ? (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-2 rounded bg-surface-secondary text-xs font-mono">
                      <span className="text-foreground-muted">Complexity Score:</span>
                      <span className="font-bold text-foreground">{validationResult.complexity_score} / 100</span>
                    </div>

                    <div className="flex items-center justify-between p-2 rounded bg-surface-secondary text-xs font-mono">
                      <span className="text-foreground-muted">Cost Class:</span>
                      <span className="font-bold text-primary">{validationResult.cost_class}</span>
                    </div>

                    {validationResult.errors.length > 0 && (
                      <div className="p-3 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-mono space-y-1">
                        <span className="font-bold">Errors:</span>
                        {validationResult.errors.map((err, i) => (
                          <div key={i}>• {err}</div>
                        ))}
                      </div>
                    )}

                    <div className="space-y-1">
                      <span className="text-[11px] font-mono text-foreground-muted uppercase">Compiled Logic:</span>
                      <pre className="p-3 rounded bg-black/60 border border-border text-emerald-400 font-mono text-[11px] whitespace-pre-wrap leading-relaxed">
                        {validationResult.human_readable_logic || 'Awaiting valid conditions...'}
                      </pre>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-foreground-muted">Compiling AST expression...</p>
                )}

                <button
                  onClick={handleSaveRule}
                  disabled={savingRule || !validationResult?.is_valid}
                  className="w-full py-2 text-xs font-semibold rounded bg-primary text-black hover:bg-primary/90 disabled:opacity-50 transition-colors shadow-sm font-mono uppercase"
                >
                  {savingRule ? 'Saving Rule...' : 'Save & Register Candidate Rule'}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* ================================================================== */}
        {/* TAB 3: RULE DETAIL & OPERATIONAL CONTROL WORKSPACE                 */}
        {/* ================================================================== */}
        {activeTab === 'detail' && selectedRule && (
          <div className="space-y-6">
            {/* Header Banner */}
            <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center space-x-3">
                    <h2 className="text-base font-bold text-foreground font-mono">{selectedRule.name}</h2>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-surface-secondary text-primary border border-border">
                      {selectedRule.rule_identifier}
                    </span>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-surface-secondary text-foreground-muted border border-border">
                      v{selectedRule.version}
                    </span>
                  </div>
                  <p className="text-xs text-foreground-muted max-w-3xl">
                    {selectedRule.description || 'No description provided.'}
                  </p>
                </div>

                <div className="flex items-center space-x-2">
                  {getDeploymentBadge(selectedRule.deployment_state)}
                  {getHealthBadge(selectedRule.operational_health, selectedRule.health_reason)}
                  {getValidationBadge(selectedRule.validation_status)}
                  {getSeverityBadge(selectedRule.severity)}
                </div>
              </div>

              {/* Operational Subtabs Navigation */}
              <div className="flex flex-wrap gap-1 border-t border-border pt-3">
                {[
                  { id: 'overview', label: 'Overview & Logic', icon: Terminal },
                  { id: 'health', label: 'Operational Health & Telemetry', icon: Activity },
                  { id: 'validation', label: 'Continuous Validation & Quality', icon: ShieldCheck },
                  { id: 'deployment', label: 'Deployment & Staging Control', icon: Sliders },
                  { id: 'exceptions', label: `Suppressions (${suppressions.length})`, icon: Ban },
                  { id: 'quality', label: 'Quality & Ground-Truth Matches', icon: CheckCircle2 },
                  { id: 'testing', label: 'Backtest & AST Diff', icon: GitCompare },
                ].map((st) => {
                  const Icon = st.icon;
                  return (
                    <button
                      key={st.id}
                      onClick={() => setDetailSubTab(st.id as any)}
                      className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors flex items-center space-x-1.5 ${
                        detailSubTab === st.id
                          ? 'bg-primary/10 text-primary border border-primary/20 font-semibold'
                          : 'text-foreground-muted hover:text-foreground hover:bg-surface-secondary'
                      }`}
                    >
                      <Icon className="w-3.5 h-3.5" />
                      <span>{st.label}</span>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* SUBTAB 1: OVERVIEW & LOGIC */}
            {detailSubTab === 'overview' && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-2 space-y-4">
                  <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                        Compiled Detection Logic
                      </h3>
                      <button
                        onClick={handleExportHunt}
                        className="px-2.5 py-1 text-[11px] rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors flex items-center space-x-1 font-mono"
                      >
                        <Copy className="w-3 h-3 text-primary" />
                        <span>{copiedHunt ? 'Copied!' : 'Hunt This Pattern'}</span>
                      </button>
                    </div>
                    <pre className="p-3 rounded bg-black/60 border border-border text-emerald-400 font-mono text-[11px] whitespace-pre-wrap leading-relaxed">
                      {selectedRule.human_readable_logic}
                    </pre>
                  </div>

                  {duplicatesInfo?.potential_duplicates?.length > 0 && (
                    <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono space-y-2">
                      <div className="flex items-center space-x-1.5 font-bold">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        <span>Potential Redundant / Duplicate Rules Detected</span>
                      </div>
                      {duplicatesInfo.potential_duplicates.map((dup: any) => (
                        <div key={dup.id} className="p-2 rounded bg-surface border border-border text-foreground">
                          {dup.name} ({dup.rule_identifier}) - Fingerprint match: {dup.similarity_type}
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div className="space-y-4">
                  <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                        Ownership & Collections
                      </h3>
                      <button
                        onClick={() => {
                          setNewOwner(selectedRule.owner_id || 'analyst-1');
                          setNewTeam(selectedRule.team_id || 'SOC');
                          setNewCollections(selectedRule.collections?.join(', ') || 'Email Security');
                          setNewInterval(selectedRule.review_interval_days || 90);
                          setIsOwnershipModalOpen(true);
                        }}
                        className="text-[11px] text-primary hover:underline font-mono"
                      >
                        Edit
                      </button>
                    </div>
                    <div className="space-y-2 text-xs font-mono">
                      <div className="flex justify-between py-1 border-b border-border">
                        <span className="text-foreground-muted">Owner:</span>
                        <span className="text-foreground">{selectedRule.owner_id || 'unassigned'}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-border">
                        <span className="text-foreground-muted">Team:</span>
                        <span className="text-foreground">{selectedRule.team_id || 'SOC'}</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-border">
                        <span className="text-foreground-muted">Review Interval:</span>
                        <span className="text-foreground">{selectedRule.review_interval_days || 90} days</span>
                      </div>
                      <div className="flex justify-between py-1 border-b border-border">
                        <span className="text-foreground-muted">Collections:</span>
                        <span className="text-primary">{selectedRule.collections?.join(', ') || 'None'}</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                    <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                      ATT&CK Techniques
                    </h3>
                    <div className="flex flex-wrap gap-1.5">
                      {selectedRule.attack_techniques?.map((t) => (
                        <span key={t} className="px-2 py-0.5 rounded bg-surface-secondary text-primary font-mono text-[10px] border border-border">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* SUBTAB 2: OPERATIONAL HEALTH & TELEMETRY */}
            {detailSubTab === 'health' && (
              <div className="space-y-5">
                {ruleHealth ? (
                  <div className="space-y-5">
                    {/* Health Status Box */}
                    <div className="p-4 rounded-lg bg-surface border border-border flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        {getHealthBadge(ruleHealth.operational_health)}
                        <span className="text-xs font-mono text-foreground">{ruleHealth.health_reason}</span>
                      </div>
                      <button
                        onClick={() => loadRuleOperationalDetails(selectedRule.id)}
                        className="px-2.5 py-1 text-xs rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground font-mono"
                      >
                        Re-evaluate Now
                      </button>
                    </div>

                    {/* Match Surge Alert if present */}
                    {ruleHealth.match_rate_anomaly && (
                      <div className="p-4 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-mono flex items-center space-x-2">
                        <Flame className="w-5 h-5 text-amber-400 shrink-0" />
                        <div>
                          <p className="font-bold">Match Rate Surge Detected</p>
                          <p>{ruleHealth.anomaly_details}</p>
                        </div>
                      </div>
                    )}

                    {/* Telemetry Metrics Grid */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="p-3 rounded-lg bg-surface border border-border">
                        <span className="text-[10px] font-mono text-foreground-muted uppercase">24h Executions</span>
                        <p className="text-lg font-bold font-mono text-foreground">{ruleHealth.execution_count_24h}</p>
                      </div>
                      <div className="p-3 rounded-lg bg-surface border border-border">
                        <span className="text-[10px] font-mono text-foreground-muted uppercase">Execution Error Rate</span>
                        <p className={`text-lg font-bold font-mono ${ruleHealth.error_rate > 0.05 ? 'text-red-400' : 'text-emerald-400'}`}>
                          {(ruleHealth.error_rate * 100).toFixed(1)}%
                        </p>
                      </div>
                      <div className="p-3 rounded-lg bg-surface border border-border">
                        <span className="text-[10px] font-mono text-foreground-muted uppercase">p95 Latency</span>
                        <p className="text-lg font-bold font-mono text-foreground">{ruleHealth.p95_duration_ms.toFixed(1)} ms</p>
                      </div>
                      <div className="p-3 rounded-lg bg-surface border border-border">
                        <span className="text-[10px] font-mono text-foreground-muted uppercase">24h Matches</span>
                        <p className="text-lg font-bold font-mono text-primary">{ruleHealth.matches_last_24h}</p>
                      </div>
                    </div>

                    {/* Dependencies Breakdown */}
                    <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                      <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                        Underlying Data Source & Analyzer Dependencies
                      </h3>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs font-mono">
                          <thead className="bg-surface-secondary/40 text-[10px] text-foreground-muted uppercase border-b border-border">
                            <tr>
                              <th className="p-2">Dependency Name</th>
                              <th className="p-2">Type</th>
                              <th className="p-2">Required / Optional</th>
                              <th className="p-2">Health</th>
                              <th className="p-2">Status Message</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {ruleHealth.dependencies.map((dep, idx) => (
                              <tr key={idx}>
                                <td className="p-2 text-foreground font-semibold">{dep.name}</td>
                                <td className="p-2 text-foreground-muted">{dep.dependency_type}</td>
                                <td className="p-2">
                                  {dep.required ? (
                                    <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 text-[10px]">REQUIRED</span>
                                  ) : (
                                    <span className="px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 text-[10px]">OPTIONAL</span>
                                  )}
                                </td>
                                <td className="p-2">{getHealthBadge(dep.health)}</td>
                                <td className="p-2 text-foreground-muted">{dep.status_message || 'Nominal'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs font-mono text-foreground-muted">Evaluating rule operational telemetry...</p>
                )}
              </div>
            )}

            {/* SUBTAB 3: DEPLOYMENT & STAGING CONTROL */}
            {detailSubTab === 'deployment' && (
              <div className="space-y-5">
                <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <h3 className="text-sm font-bold text-foreground font-mono">Controlled Deployment & Staging</h3>
                      <p className="text-xs text-foreground-muted">
                        Test in Staging Canary, promote with immutable version snapshots, or execute an emergency rollback.
                      </p>
                    </div>

                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={handleDryRun}
                        disabled={runningDryRun}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors font-mono"
                      >
                        {runningDryRun ? 'Running Dry-Run...' : 'Pre-flight Dry Run'}
                      </button>

                      <button
                        onClick={() => setIsSimulateModalOpen(true)}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors font-mono flex items-center space-x-1"
                      >
                        <Zap className="w-3.5 h-3.5 text-primary" />
                        <span>Simulate</span>
                      </button>

                      <button
                        onClick={() => {
                          setTargetDeployState('STAGING');
                          setIsDeployModalOpen(true);
                        }}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-cyan-500/15 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/25 transition-colors font-mono"
                      >
                        Deploy to Staging
                      </button>

                      <button
                        onClick={() => {
                          setTargetDeployState('PRODUCTION');
                          setIsDeployModalOpen(true);
                        }}
                        className="px-3 py-1.5 text-xs font-bold rounded bg-emerald-500 text-black hover:bg-emerald-400 transition-colors font-mono shadow-sm"
                      >
                        Promote to Production
                      </button>

                      <button
                        onClick={() => setIsRollbackModalOpen(true)}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-amber-500/15 text-amber-400 border border-amber-500/30 hover:bg-amber-500/25 transition-colors font-mono"
                      >
                        Rollback Version
                      </button>

                      <button
                        onClick={() => setIsEmergencyModalOpen(true)}
                        className="px-3 py-1.5 text-xs font-medium rounded bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 transition-colors font-mono"
                      >
                        Emergency Disable
                      </button>
                    </div>
                  </div>

                  {/* Dry Run Results Card */}
                  {dryRunResult && (
                    <div className="p-4 rounded-lg bg-surface-secondary/50 border border-border space-y-3 font-mono text-xs">
                      <div className="flex items-center justify-between border-b border-border pb-2">
                        <span className="font-bold text-foreground">Pre-flight Deployment Dry-Run Result:</span>
                        <span className={`px-2 py-0.5 rounded font-bold ${
                          dryRunResult.operational_risk === 'LOW' ? 'bg-emerald-500/20 text-emerald-400' :
                          dryRunResult.operational_risk === 'MEDIUM' ? 'bg-amber-500/20 text-amber-400' :
                          'bg-red-500/20 text-red-400'
                        }`}>
                          RISK: {dryRunResult.operational_risk}
                        </span>
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                        <div>Validation: <span className="text-emerald-400">{dryRunResult.validation_status}</span></div>
                        <div>Dependencies: <span className="text-emerald-400">{dryRunResult.dependencies_status}</span></div>
                        <div>Historical Matches: <span className="text-primary">{dryRunResult.historical_matches_observed}</span></div>
                      </div>
                      {dryRunResult.blocking_reasons.length > 0 && (
                        <div className="text-red-400">
                          Blocking: {dryRunResult.blocking_reasons.join(', ')}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Simulation Result */}
                  {simulationResult && (
                    <div className="p-4 rounded-lg bg-black/60 border border-border space-y-2 font-mono text-xs">
                      <span className="font-bold text-primary">Simulation Result ({simulationResult.label}):</span>
                      <p>Evaluated {simulationResult.events_evaluated} events in {simulationResult.duration_ms} ms.</p>
                      <p>Matches Observed: <span className="text-emerald-400 font-bold">{simulationResult.simulated_matches_count}</span> (Isolated from production pipeline).</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* SUBTAB 4: SUPPRESSIONS & EXCEPTIONS */}
            {detailSubTab === 'exceptions' && (
              <div className="space-y-4">
                <div className="p-4 rounded-lg bg-surface border border-border flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-foreground font-mono">Scoped Suppression Exceptions</h3>
                    <p className="text-xs text-foreground-muted">
                      Temporarily or scope-exclude known benign false-positive entities without disabling the entire detection rule.
                    </p>
                  </div>
                  <button
                    onClick={() => setIsAddSuppModalOpen(true)}
                    className="flex items-center space-x-1 px-3 py-1.5 text-xs font-semibold rounded bg-primary text-black hover:bg-primary/90 transition-colors font-mono"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Add Suppression Exception</span>
                  </button>
                </div>

                <div className="rounded-lg border border-border bg-surface overflow-hidden">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-surface-secondary/40 text-[10px] text-foreground-muted uppercase border-b border-border">
                      <tr>
                        <th className="p-3">Exception Name</th>
                        <th className="p-3">Scope Target</th>
                        <th className="p-3">Operator</th>
                        <th className="p-3">Value</th>
                        <th className="p-3">Status</th>
                        <th className="p-3">Expires</th>
                        <th className="p-3">Hits</th>
                        <th className="p-3 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {suppressions.length === 0 ? (
                        <tr>
                          <td colSpan={8} className="p-6 text-center text-foreground-muted">
                            No active suppression exceptions registered for this rule.
                          </td>
                        </tr>
                      ) : (
                        suppressions.map((s) => (
                          <tr key={s.id} className="hover:bg-surface-secondary/20">
                            <td className="p-3 font-semibold text-foreground">{s.name}</td>
                            <td className="p-3 text-foreground-muted">{s.scope_target}</td>
                            <td className="p-3 text-foreground-muted">{s.match_operator}</td>
                            <td className="p-3 text-primary">{s.match_value}</td>
                            <td className="p-3">
                              {s.is_active ? (
                                <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px]">ACTIVE</span>
                              ) : (
                                <span className="px-1.5 py-0.5 rounded bg-zinc-500/10 text-zinc-400 text-[10px]">EXPIRED</span>
                              )}
                            </td>
                            <td className="p-3 text-foreground-muted">
                              {s.expires_at ? new Date(s.expires_at).toLocaleDateString() : 'Permanent'}
                            </td>
                            <td className="p-3 text-foreground">{s.hit_count}</td>
                            <td className="p-3 text-right">
                              <button
                                onClick={() => handleDeleteSuppression(s.id)}
                                className="p-1 hover:text-red-400 text-foreground-muted transition-colors"
                                title="Delete exception"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* SUBTAB 5: QUALITY & MATCHES */}
            {detailSubTab === 'quality' && (
              <div className="space-y-5">
                {/* Metrics Summary Strip */}
                {qualityMetrics && (
                  <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                    <div className="p-3 rounded-lg bg-surface border border-border font-mono">
                      <span className="text-[10px] text-foreground-muted uppercase">Total Matches</span>
                      <p className="text-lg font-bold text-foreground">{qualityMetrics.total_matches}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-surface border border-border font-mono">
                      <span className="text-[10px] text-foreground-muted uppercase">Reviewed</span>
                      <p className="text-lg font-bold text-foreground">{qualityMetrics.reviewed_matches}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-surface border border-border font-mono">
                      <span className="text-[10px] text-emerald-400/80 uppercase">True Positives</span>
                      <p className="text-lg font-bold text-emerald-400">{qualityMetrics.true_positives}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-surface border border-border font-mono">
                      <span className="text-[10px] text-red-400/80 uppercase">False Positives</span>
                      <p className="text-lg font-bold text-red-400">{qualityMetrics.false_positives}</p>
                    </div>
                    <div className="p-3 rounded-lg bg-surface border border-border font-mono">
                      <span className="text-[10px] text-primary/80 uppercase">FP Rate</span>
                      <p className="text-lg font-bold text-primary">
                        {qualityMetrics.false_positive_rate !== undefined
                          ? `${(qualityMetrics.false_positive_rate * 100).toFixed(1)}%`
                          : 'N/A'}
                      </p>
                    </div>
                  </div>
                )}

                {/* Ground Truth Disposition Table */}
                <div className="rounded-lg border border-border bg-surface overflow-hidden">
                  <div className="p-3 bg-surface-secondary/40 border-b border-border flex items-center justify-between">
                    <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                      Recent Telemetry Matches & Analyst Feedback
                    </h3>
                    <input
                      type="text"
                      placeholder="Optional feedback notes..."
                      value={dispositionNotes}
                      onChange={(e) => setDispositionNotes(e.target.value)}
                      className="px-2 py-1 text-xs rounded bg-surface border border-border text-foreground font-mono w-64 focus:outline-none focus:border-primary"
                    />
                  </div>
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-surface-secondary/20 text-[10px] text-foreground-muted uppercase border-b border-border">
                      <tr>
                        <th className="p-3">Match ID / Event</th>
                        <th className="p-3">Observed At</th>
                        <th className="p-3">Mode</th>
                        <th className="p-3">Disposition</th>
                        <th className="p-3 text-right">Ground-Truth Feedback</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border">
                      {matches.length === 0 ? (
                        <tr>
                          <td colSpan={5} className="p-6 text-center text-foreground-muted">
                            No telemetry execution matches recorded for this rule yet.
                          </td>
                        </tr>
                      ) : (
                        matches.map((m) => (
                          <tr key={m.id} className="hover:bg-surface-secondary/20">
                            <td className="p-3 font-semibold text-foreground">
                              {m.detection_id || m.id.substring(0, 12)}
                            </td>
                            <td className="p-3 text-foreground-muted">
                              {new Date(m.executed_at).toLocaleString()}
                            </td>
                            <td className="p-3">
                              <span className="px-1.5 py-0.5 rounded bg-surface-secondary text-foreground text-[10px]">
                                {m.mode}
                              </span>
                            </td>
                            <td className="p-3">
                              {m.disposition ? (
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  m.disposition === 'TRUE_POSITIVE' ? 'bg-emerald-500/20 text-emerald-400' :
                                  m.disposition === 'FALSE_POSITIVE' ? 'bg-red-500/20 text-red-400' :
                                  'bg-zinc-500/20 text-zinc-400'
                                }`}>
                                  {m.disposition}
                                </span>
                              ) : (
                                <span className="text-foreground-muted text-[10px]">UNREVIEWED</span>
                              )}
                            </td>
                            <td className="p-3 text-right space-x-1">
                              <button
                                onClick={() => handleRecordDisposition(m.id, 'TRUE_POSITIVE')}
                                className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20 border border-emerald-500/30 text-[10px]"
                              >
                                True Pos
                              </button>
                              <button
                                onClick={() => handleRecordDisposition(m.id, 'FALSE_POSITIVE')}
                                className="px-2 py-0.5 rounded bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/30 text-[10px]"
                              >
                                False Pos
                              </button>
                              <button
                                onClick={() => handleRecordDisposition(m.id, 'BENIGN')}
                                className="px-2 py-0.5 rounded bg-zinc-500/10 text-zinc-400 hover:bg-zinc-500/20 border border-zinc-500/30 text-[10px]"
                              >
                                Benign
                              </button>
                            </td>
                          </tr>
                        ))
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* SUBTAB 6: TESTING & BACKTESTING */}
            {detailSubTab === 'testing' && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Backtesting Workbench */}
                <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                      Historical Telemetry Backtest
                    </h3>
                    <select
                      value={backtestPreset}
                      onChange={(e) => setBacktestPreset(e.target.value as any)}
                      className="px-2 py-1 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary"
                    >
                      <option value="LAST_24_HOURS">Past 24 Hours</option>
                      <option value="LAST_7_DAYS">Past 7 Days</option>
                      <option value="LAST_30_DAYS">Past 30 Days</option>
                    </select>
                  </div>

                  <button
                    onClick={handleRunBacktest}
                    disabled={backtestRunning}
                    className="w-full py-2 text-xs font-semibold rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors flex items-center justify-center space-x-1.5 font-mono"
                  >
                    <Play className="w-3.5 h-3.5 text-primary" />
                    <span>{backtestRunning ? 'Evaluating Telemetry...' : 'Run Historical Backtest'}</span>
                  </button>

                  {backtestResult && (
                    <div className="p-3 rounded bg-black/60 border border-border space-y-2 text-xs font-mono">
                      <div className="flex justify-between">
                        <span className="text-foreground-muted">Evaluated Records:</span>
                        <span className="text-foreground">{backtestResult.records_evaluated}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-foreground-muted">Matches Found:</span>
                        <span className="text-primary font-bold">{backtestResult.matches_count}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-foreground-muted">Execution Duration:</span>
                        <span className="text-foreground">{backtestResult.execution_duration_ms} ms</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Live Sandbox Test & Version Diff */}
                <div className="space-y-4">
                  <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                    <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                      Live Event Sandbox Evaluation
                    </h3>
                    <textarea
                      rows={5}
                      value={testPayloadStr}
                      onChange={(e) => setTestPayloadStr(e.target.value)}
                      className="w-full p-2.5 rounded bg-black/60 border border-border text-foreground font-mono text-xs focus:outline-none focus:border-primary"
                    />
                    <button
                      onClick={handleTestEvent}
                      disabled={evaluatingTest}
                      className="w-full py-2 text-xs font-semibold rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors font-mono"
                    >
                      {evaluatingTest ? 'Evaluating...' : 'Simulate Single Event'}
                    </button>
                    {testMatchResult && (
                      <div className="p-2.5 rounded bg-black/50 border border-border font-mono text-[11px] text-emerald-400">
                        {testMatchResult.length > 0 ? `Matched ${testMatchResult.length} rule condition(s).` : 'No conditions triggered.'}
                      </div>
                    )}
                  </div>

                  <div className="p-4 rounded-lg bg-surface border border-border space-y-3">
                    <div className="flex items-center justify-between">
                      <h3 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider">
                        Version Diff (v1 vs Current)
                      </h3>
                      <button
                        onClick={handleComputeDiff}
                        disabled={loadingDiff}
                        className="px-2 py-1 text-[11px] rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors flex items-center space-x-1 font-mono"
                      >
                        <GitCompare className="w-3 h-3 text-primary" />
                        <span>{loadingDiff ? 'Diffing...' : 'Compare Versions'}</span>
                      </button>
                    </div>
                    {diffResult && (
                      <div className="p-3 rounded bg-black/60 border border-border text-xs font-mono space-y-1">
                        <p className="text-foreground font-semibold">{diffResult.summary}</p>
                        {diffResult.added_conditions.length > 0 && (
                          <div className="text-emerald-400 text-[11px]">+ Added: {JSON.stringify(diffResult.added_conditions)}</div>
                        )}
                        {diffResult.removed_conditions.length > 0 && (
                          <div className="text-red-400 text-[11px]">- Removed: {JSON.stringify(diffResult.removed_conditions)}</div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* SUBTAB: CONTINUOUS VALIDATION & RULE QUALITY */}
            {detailSubTab === 'validation' && (
              <div className="space-y-6">
                {/* 1. Validation Status & Quality Gates Banner */}
                <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                    <div className="space-y-1">
                      <div className="flex items-center space-x-2">
                        <ShieldCheck className="w-5 h-5 text-primary" />
                        <h3 className="text-sm font-bold font-mono text-foreground uppercase tracking-wider">
                          Automated Detection Validation & Continuous Quality
                        </h3>
                      </div>
                      <p className="text-xs text-foreground-muted">
                        Continuous multi-dimensional evaluation: AST structure, dependencies, data compatibility, performance SLAs, regression, and test fixtures.
                      </p>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleTriggerValidation(false)}
                        disabled={validatingNow}
                        className="px-3 py-1.5 text-xs font-semibold rounded bg-primary text-black hover:bg-primary/90 transition-colors flex items-center space-x-1.5 font-mono shadow-sm"
                      >
                        <RefreshCw className={`w-3.5 h-3.5 ${validatingNow ? 'animate-spin' : ''}`} />
                        <span>{validatingNow ? 'Validating Rule...' : 'Validate Now'}</span>
                      </button>
                      <button
                        onClick={handleCheckDeploymentGate}
                        disabled={checkingGate}
                        className="px-3 py-1.5 text-xs font-semibold rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors flex items-center space-x-1.5 font-mono"
                      >
                        <Lock className="w-3.5 h-3.5 text-primary" />
                        <span>{checkingGate ? 'Checking Gate...' : 'Verify Promotion Gate'}</span>
                      </button>
                      <button
                        onClick={() => setIsAddFixtureModalOpen(true)}
                        className="px-3 py-1.5 text-xs font-semibold rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground transition-colors flex items-center space-x-1.5 font-mono"
                      >
                        <Plus className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Add Test Fixture</span>
                      </button>
                    </div>
                  </div>

                  {/* Summary Cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-2">
                    <div className="p-3 rounded bg-surface-secondary/60 border border-border space-y-1">
                      <span className="text-[10px] font-mono uppercase text-foreground-muted">Overall Validation</span>
                      <div className="flex items-center space-x-2">
                        {getValidationBadge(latestValidation?.status || selectedRule.validation_status)}
                        {latestValidation?.is_stale && (
                          <span className="px-1.5 py-0.5 text-[9px] rounded bg-purple-500/20 text-purple-400 font-bold">STALE</span>
                        )}
                      </div>
                    </div>
                    <div className="p-3 rounded bg-surface-secondary/60 border border-border space-y-1">
                      <span className="text-[10px] font-mono uppercase text-foreground-muted">Production Gate</span>
                      <div>
                        {gateCheck ? (
                          gateCheck.can_promote ? (
                            <span className="text-xs font-mono font-bold text-emerald-400 flex items-center space-x-1">
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>PROMOTION READY</span>
                            </span>
                          ) : (
                            <span className="text-xs font-mono font-bold text-red-400 flex items-center space-x-1">
                              <XCircle className="w-3.5 h-3.5" />
                              <span>GATE BLOCKED</span>
                            </span>
                          )
                        ) : (
                          <span className="text-xs font-mono text-foreground-muted">Not Checked</span>
                        )}
                      </div>
                    </div>
                    <div className="p-3 rounded bg-surface-secondary/60 border border-border space-y-1">
                      <span className="text-[10px] font-mono uppercase text-foreground-muted">Last Validated</span>
                      <p className="text-xs font-mono text-foreground font-semibold">
                        {latestValidation?.completed_at
                          ? new Date(latestValidation.completed_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
                          : 'Never'}
                      </p>
                    </div>
                    <div className="p-3 rounded bg-surface-secondary/60 border border-border space-y-1">
                      <span className="text-[10px] font-mono uppercase text-foreground-muted">Execution SLA</span>
                      <p className="text-xs font-mono text-foreground font-semibold">
                        {latestValidation?.duration_ms ? `${latestValidation.duration_ms} ms` : 'N/A'}
                      </p>
                    </div>
                  </div>

                  {/* Gate Blockers Alert if any */}
                  {gateCheck && !gateCheck.can_promote && gateCheck.blocking_reasons.length > 0 && (
                    <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-xs font-mono space-y-1.5">
                      <div className="flex items-center space-x-2 text-red-400 font-bold">
                        <AlertOctagon className="w-4 h-4" />
                        <span>Promotion to Production Blocked by Quality Gate:</span>
                      </div>
                      <ul className="list-disc list-inside space-y-0.5 text-red-300 text-[11px]">
                        {gateCheck.blocking_reasons.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* 2. Multi-Dimensional Validation Checks Grid */}
                <div className="space-y-3">
                  <h4 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center justify-between">
                    <span>Validation Dimensions & Evidence</span>
                    <span className="text-[10px] text-primary">{latestValidation?.checks.length || 0} checks recorded</span>
                  </h4>

                  {latestValidation && latestValidation.checks.length > 0 ? (
                    <div className="space-y-2">
                      {latestValidation.checks.map((chk) => {
                        const isExpanded = expandedCheckId === chk.id;
                        return (
                          <div
                            key={chk.id}
                            className="p-3.5 rounded-lg bg-surface border border-border hover:border-primary/30 transition-all space-y-2"
                          >
                            <div className="flex items-center justify-between cursor-pointer" onClick={() => setExpandedCheckId(isExpanded ? null : chk.id)}>
                              <div className="flex items-center space-x-2.5">
                                {chk.status === 'PASS' && <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />}
                                {chk.status === 'PASS_WITH_WARNINGS' && <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />}
                                {chk.status === 'FAIL' && <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />}
                                {chk.status === 'BLOCKED' && <Ban className="w-4 h-4 text-orange-400 flex-shrink-0" />}
                                {chk.status === 'TIMED_OUT' && <AlertOctagon className="w-4 h-4 text-red-400 flex-shrink-0" />}
                                <div>
                                  <div className="flex items-center space-x-2">
                                    <span className="font-mono font-bold text-xs text-foreground">{chk.category}</span>
                                    <span className="font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface-secondary text-foreground-muted border border-border">
                                      {chk.code}
                                    </span>
                                    <span className={`text-[9px] font-mono px-1 rounded font-bold ${chk.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-400' : chk.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-400' : 'bg-surface-secondary text-foreground-muted'}`}>
                                      {chk.severity}
                                    </span>
                                  </div>
                                  <p className="text-xs text-foreground-muted mt-0.5">{chk.message}</p>
                                </div>
                              </div>
                              <div className="flex items-center space-x-2">
                                {getValidationBadge(chk.status)}
                                <button className="p-1 text-foreground-muted hover:text-foreground">
                                  <Sliders className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </div>

                            {/* Expanded Technical Evidence & Observed Values */}
                            {isExpanded && (
                              <div className="pt-2.5 border-t border-border/60 text-xs font-mono space-y-2 bg-black/40 p-3 rounded">
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                                  <div>
                                    <span className="text-foreground-muted block mb-0.5">Observed Measurement:</span>
                                    <pre className="p-2 rounded bg-surface-secondary/70 overflow-x-auto text-primary text-[10px]">
                                      {JSON.stringify(chk.observed_value, null, 2)}
                                    </pre>
                                  </div>
                                  <div>
                                    <span className="text-foreground-muted block mb-0.5">Expected Baseline / Policy:</span>
                                    <pre className="p-2 rounded bg-surface-secondary/70 overflow-x-auto text-emerald-400 text-[10px]">
                                      {JSON.stringify(chk.expected_value, null, 2)}
                                    </pre>
                                  </div>
                                </div>
                                {chk.evidence && Object.keys(chk.evidence).length > 0 && (
                                  <div className="pt-1">
                                    <span className="text-foreground-muted block mb-0.5">Auditable Evidence Payload:</span>
                                    <pre className="p-2 rounded bg-surface-secondary/70 overflow-x-auto text-foreground-muted text-[10px]">
                                      {JSON.stringify(chk.evidence, null, 2)}
                                    </pre>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div className="p-8 text-center rounded-lg bg-surface border border-border text-foreground-muted font-mono text-xs">
                      No validation checks on record for this rule version. Click "Validate Now" to execute automated checks.
                    </div>
                  )}
                </div>

                {/* 3. Actionable Recommendations */}
                {latestValidation && latestValidation.recommendations && latestValidation.recommendations.length > 0 && (
                  <div className="p-4 rounded-lg bg-surface border border-border space-y-2">
                    <h4 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center space-x-2">
                      <Sparkles className="w-4 h-4 text-primary" />
                      <span>Operational Quality Recommendations</span>
                    </h4>
                    <div className="space-y-1.5 text-xs text-foreground font-mono">
                      {latestValidation.recommendations.map((rec, idx) => (
                        <div key={idx} className="flex items-start space-x-2">
                          <span className="text-primary font-bold">›</span>
                          <span>{rec}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* 4. Test Fixtures Section */}
                <div className="p-5 rounded-lg bg-surface border border-border space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center space-x-2">
                        <FlaskConical className="w-4 h-4 text-primary" />
                        <span>Deterministic Test Fixtures ({fixtures.length})</span>
                      </h4>
                      <p className="text-xs text-foreground-muted mt-0.5">
                        Positive (expected match) and Negative (expected non-match) regression test cases.
                      </p>
                    </div>
                    <button
                      onClick={() => setIsAddFixtureModalOpen(true)}
                      className="px-2.5 py-1 text-xs rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-foreground font-mono flex items-center space-x-1"
                    >
                      <Plus className="w-3 h-3 text-primary" />
                      <span>New Test Case</span>
                    </button>
                  </div>

                  {fixtures.length === 0 ? (
                    <div className="p-6 text-center text-foreground-muted font-mono text-xs border border-dashed border-border rounded">
                      No test fixtures configured. Create positive and negative test cases to guard against detection logic regression.
                    </div>
                  ) : (
                    <div className="divide-y divide-border border border-border rounded overflow-hidden">
                      {fixtures.map((fix) => (
                        <div key={fix.id} className="p-3 bg-surface-secondary/30 flex items-center justify-between text-xs">
                          <div className="space-y-0.5">
                            <div className="flex items-center space-x-2">
                              <span className="font-semibold text-foreground font-mono">{fix.name}</span>
                              <span className={`px-1.5 py-0.5 rounded font-mono text-[9px] font-bold ${fix.fixture_type === 'POSITIVE' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-blue-500/20 text-blue-400'}`}>
                                {fix.fixture_type} (Expected: {fix.expected_match ? 'MATCH' : 'NO MATCH'})
                              </span>
                              {fix.last_result && (
                                <span className={`px-1.5 py-0.5 rounded font-mono text-[9px] font-bold ${fix.last_result === 'PASS' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                                  LAST: {fix.last_result}
                                </span>
                              )}
                            </div>
                            {fix.description && <p className="text-foreground-muted text-[11px]">{fix.description}</p>}
                            {fix.last_error && <p className="text-red-400 text-[10px] font-mono">{fix.last_error}</p>}
                          </div>
                          <div className="flex items-center space-x-2">
                            <button
                              onClick={() => handleRunFixture(fix.id)}
                              disabled={runningFixtureId === fix.id}
                              className="px-2 py-1 rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border font-mono text-[10px] text-primary flex items-center space-x-1"
                            >
                              <Play className={`w-3 h-3 ${runningFixtureId === fix.id ? 'animate-spin' : ''}`} />
                              <span>{runningFixtureId === fix.id ? 'Testing...' : 'Run Test'}</span>
                            </button>
                            <button
                              onClick={() => handleDeleteFixture(fix.id)}
                              className="p-1 rounded text-foreground-muted hover:text-red-400 transition-colors"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* 5. Validation History Table */}
                <div className="p-5 rounded-lg bg-surface border border-border space-y-3">
                  <div className="flex items-center justify-between">
                    <h4 className="text-xs font-mono font-semibold uppercase text-foreground-muted tracking-wider flex items-center space-x-2">
                      <History className="w-4 h-4 text-primary" />
                      <span>Validation Run History</span>
                    </h4>
                    <span className="text-[10px] font-mono text-foreground-muted">{validationHistory.length} historical runs</span>
                  </div>

                  {validationHistory.length === 0 ? (
                    <p className="text-xs text-foreground-muted font-mono">No prior validation runs recorded.</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-left text-xs font-mono">
                        <thead className="bg-surface-secondary/60 text-foreground-muted uppercase text-[10px] border-b border-border">
                          <tr>
                            <th className="p-2 font-semibold">Run Timestamp</th>
                            <th className="p-2 font-semibold">Version</th>
                            <th className="p-2 font-semibold">Type</th>
                            <th className="p-2 font-semibold">Trigger</th>
                            <th className="p-2 font-semibold">Status</th>
                            <th className="p-2 font-semibold">Duration</th>
                            <th className="p-2 font-semibold">Checks</th>
                            <th className="p-2 font-semibold text-right">Actions</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-border">
                          {validationHistory.map((hrun) => (
                            <tr key={hrun.id} className="hover:bg-surface-secondary/30 transition-colors">
                              <td className="p-2 text-foreground-muted text-[11px]">
                                {new Date(hrun.created_at).toLocaleString()}
                              </td>
                              <td className="p-2 text-foreground font-bold">v{hrun.rule_version}</td>
                              <td className="p-2 text-foreground-muted">{hrun.validation_type}</td>
                              <td className="p-2 text-foreground-muted text-[10px]">{hrun.trigger_type}</td>
                              <td className="p-2">{getValidationBadge(hrun.status)}</td>
                              <td className="p-2 text-foreground-muted">{hrun.duration_ms ? `${hrun.duration_ms}ms` : '-'}</td>
                              <td className="p-2">
                                <span className="text-emerald-400 font-bold">{hrun.pass_count}P</span>
                                {hrun.warning_count > 0 && <span className="text-amber-400 ml-1 font-bold">{hrun.warning_count}W</span>}
                                {hrun.fail_count > 0 && <span className="text-red-400 ml-1 font-bold">{hrun.fail_count}F</span>}
                              </td>
                              <td className="p-2 text-right">
                                <button
                                  onClick={() => {
                                    setLatestValidation(hrun);
                                    showToast(`Loaded validation run from ${new Date(hrun.created_at).toLocaleTimeString()}`);
                                  }}
                                  className="px-2 py-0.5 rounded bg-surface-secondary hover:bg-surface-secondary/80 border border-border text-[10px] text-primary"
                                >
                                  Inspect
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ================================================================== */}
        {/* TAB 4: UNIFIED THREAT DETECTION PIPELINE (SECTION 59)             */}
        {/* ================================================================== */}
        {activeTab === 'pipeline' && (
          <UnifiedDetectionPipelineView />
        )}
      </main>

      {/* ==================================================================== */}
      {/* MODALS                                                               */}
      {/* ==================================================================== */}

      {/* Deploy Modal */}
      {isDeployModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-foreground font-mono">
              Deploy to {targetDeployState}
            </h3>
            <p className="text-xs text-foreground-muted">
              Promote rule snapshot to {targetDeployState}. State transition will be cryptographically audited.
            </p>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Justification Reason *</label>
              <textarea
                rows={3}
                placeholder="Operational purpose for promotion..."
                value={deployReason}
                onChange={(e) => setDeployReason(e.target.value)}
                className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary font-mono"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsDeployModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteDeploy}
                disabled={deploying}
                className="px-3 py-1.5 text-xs font-bold rounded bg-emerald-500 text-black hover:bg-emerald-400 font-mono"
              >
                {deploying ? 'Deploying...' : 'Confirm Deployment'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rollback Modal */}
      {isRollbackModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-foreground font-mono">
              Safe Version Rollback
            </h3>
            <p className="text-xs text-foreground-muted">
              Select an immutable prior version to restore. Complete version history is preserved.
            </p>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Target Version</label>
              <input
                type="text"
                placeholder="e.g. 1"
                value={rollbackVersion}
                onChange={(e) => setRollbackVersion(e.target.value)}
                className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Mandatory Rollback Reason *</label>
              <textarea
                rows={3}
                placeholder="Reason for reverting current version..."
                value={rollbackReason}
                onChange={(e) => setRollbackReason(e.target.value)}
                className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary font-mono"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsRollbackModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteRollback}
                disabled={rollingBack}
                className="px-3 py-1.5 text-xs font-bold rounded bg-amber-500 text-black hover:bg-amber-400 font-mono"
              >
                {rollingBack ? 'Reverting...' : 'Confirm Rollback'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Emergency Disable Modal */}
      {isEmergencyModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <div className="flex items-center space-x-2 text-red-400">
              <AlertOctagon className="w-5 h-5" />
              <h3 className="text-sm font-bold font-mono">EMERGENCY DISABLE</h3>
            </div>
            <p className="text-xs text-foreground-muted">
              Immediately ceases detection rule execution in live pipelines. Elevated authorization required.
            </p>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Mandatory Justification Reason *</label>
              <textarea
                rows={3}
                placeholder="e.g. Excessive false positives degrading SOC alert volume..."
                value={emergencyReason}
                onChange={(e) => setEmergencyReason(e.target.value)}
                className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary font-mono"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsEmergencyModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleExecuteEmergencyDisable}
                disabled={emergencyDisabling}
                className="px-3 py-1.5 text-xs font-bold rounded bg-red-500 text-white hover:bg-red-600 font-mono"
              >
                {emergencyDisabling ? 'Disabling...' : 'EMERGENCY DISABLE NOW'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Suppression Modal */}
      {isAddSuppModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-foreground font-mono">
              Add Scoped Suppression Exception
            </h3>
            <div className="space-y-3 font-mono text-xs">
              <div className="space-y-1">
                <label className="text-foreground-muted">Exception Name *</label>
                <input
                  type="text"
                  placeholder="e.g. Vulnerability Scanner Exclusion"
                  value={newSuppName}
                  onChange={(e) => setNewSuppName(e.target.value)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div className="space-y-1">
                  <label className="text-foreground-muted">Target Field</label>
                  <input
                    type="text"
                    value={newSuppTarget}
                    onChange={(e) => setNewSuppTarget(e.target.value)}
                    className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-foreground-muted">Operator</label>
                  <select
                    value={newSuppOp}
                    onChange={(e) => setNewSuppOp(e.target.value)}
                    className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                  >
                    <option value="EQUALS">EQUALS</option>
                    <option value="CONTAINS">CONTAINS</option>
                    <option value="ENDS_WITH">ENDS_WITH</option>
                  </select>
                </div>
              </div>
              <div className="space-y-1">
                <label className="text-foreground-muted">Match Value *</label>
                <input
                  type="text"
                  placeholder="e.g. 10.0.50.99"
                  value={newSuppVal}
                  onChange={(e) => setNewSuppVal(e.target.value)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div className="space-y-1">
                <label className="text-foreground-muted">Expires In (Days)</label>
                <input
                  type="number"
                  value={newSuppExpires}
                  onChange={(e) => setNewSuppExpires(Number(e.target.value))}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div className="space-y-1">
                <label className="text-foreground-muted">Justification Reason *</label>
                <textarea
                  rows={2}
                  placeholder="Authorized weekly maintenance or trusted partner IP..."
                  value={newSuppReason}
                  onChange={(e) => setNewSuppReason(e.target.value)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsAddSuppModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateSuppression}
                disabled={savingSuppression}
                className="px-3 py-1.5 text-xs font-bold rounded bg-primary text-black hover:bg-primary/90 font-mono"
              >
                {savingSuppression ? 'Creating...' : 'Register Exception'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Simulation Modal */}
      {isSimulateModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-foreground font-mono flex items-center space-x-2">
              <Zap className="w-4 h-4 text-primary" />
              <span>Simulate Detection Rule</span>
            </h3>
            <p className="text-xs text-foreground-muted">
              Evaluates incoming telemetry in shadow simulation without generating production alerts or incident tickets.
            </p>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Recent Events Count</label>
              <input
                type="number"
                value={simulateCount}
                onChange={(e) => setSimulateCount(Number(e.target.value))}
                className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsSimulateModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  setIsSimulateModalOpen(false);
                  handleSimulateRule();
                }}
                disabled={simulating}
                className="px-3 py-1.5 text-xs font-bold rounded bg-primary text-black hover:bg-primary/90 font-mono"
              >
                {simulating ? 'Simulating...' : 'Run Simulation'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Ownership Update Modal */}
      {isOwnershipModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-foreground font-mono">
              Update Rule Ownership & Governance
            </h3>
            <div className="space-y-3 font-mono text-xs">
              <div className="space-y-1">
                <label className="text-foreground-muted">Owner User ID</label>
                <input
                  type="text"
                  value={newOwner}
                  onChange={(e) => setNewOwner(e.target.value)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div className="space-y-1">
                <label className="text-foreground-muted">Team ID</label>
                <input
                  type="text"
                  value={newTeam}
                  onChange={(e) => setNewTeam(e.target.value)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div className="space-y-1">
                <label className="text-foreground-muted">Collections (csv)</label>
                <input
                  type="text"
                  value={newCollections}
                  onChange={(e) => setNewCollections(e.target.value)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
              <div className="space-y-1">
                <label className="text-foreground-muted">Review Interval (Days)</label>
                <input
                  type="number"
                  value={newInterval}
                  onChange={(e) => setNewInterval(Number(e.target.value))}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsOwnershipModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveOwnership}
                disabled={savingOwnership}
                className="px-3 py-1.5 text-xs font-bold rounded bg-primary text-black hover:bg-primary/90 font-mono"
              >
                {savingOwnership ? 'Saving...' : 'Save Ownership'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Operations Modal */}
      {isBulkModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-sm font-bold text-foreground font-mono">
              Bulk Operation ({selectedRuleIds.length} rules)
            </h3>
            <p className="text-xs text-foreground-muted">
              Execute batch operational command across all checked rules. Each rule is validated independently.
            </p>
            <div className="space-y-3 font-mono text-xs">
              <div className="space-y-1">
                <label className="text-foreground-muted">Action</label>
                <select
                  value={bulkAction}
                  onChange={(e) => setBulkAction(e.target.value as any)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                >
                  <option value="ENABLE">ENABLE (ACTIVE)</option>
                  <option value="DISABLE">DISABLE</option>
                  <option value="SET_OWNER">SET OWNER</option>
                  <option value="SET_COLLECTION">SET COLLECTION</option>
                  <option value="TAG">ADD TAG</option>
                </select>
              </div>

              {bulkAction !== 'ENABLE' && bulkAction !== 'DISABLE' && (
                <div className="space-y-1">
                  <label className="text-foreground-muted">Parameter Value</label>
                  <input
                    type="text"
                    placeholder="e.g. lead-analyst or Email Security..."
                    value={bulkParam}
                    onChange={(e) => setBulkParam(e.target.value)}
                    className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                  />
                </div>
              )}

              <div className="space-y-1">
                <label className="text-foreground-muted">Operational Reason</label>
                <textarea
                  rows={2}
                  placeholder="Audit reason for batch modification..."
                  value={bulkReason}
                  onChange={(e) => setBulkReason(e.target.value)}
                  className="w-full p-2 rounded bg-surface-secondary border border-border text-foreground"
                />
              </div>

              {bulkResult && (
                <div className="p-3 rounded bg-black/60 border border-border space-y-1">
                  <span className="font-bold text-primary">Result Summary:</span>
                  <p>Success: {bulkResult.successful} | Failed: {bulkResult.failed}</p>
                </div>
              )}
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => {
                  setIsBulkModalOpen(false);
                  setBulkResult(null);
                }}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Close
              </button>
              <button
                onClick={handleExecuteBulk}
                disabled={bulkRunning}
                className="px-3 py-1.5 text-xs font-bold rounded bg-primary text-black hover:bg-primary/90 font-mono"
              >
                {bulkRunning ? 'Executing...' : 'Execute Bulk Action'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* AI Assistant Modal */}
      {isAiModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-lg w-full space-y-4">
            <div className="flex items-center space-x-2 text-primary">
              <Sparkles className="w-5 h-5" />
              <h3 className="text-sm font-bold font-mono">AI Detection Rule Generator</h3>
            </div>
            <p className="text-xs text-foreground-muted">
              Describe the attacker tactic or phishing signature in plain text. AI synthesizes a compliant AST definition.
            </p>
            <div className="space-y-1">
              <textarea
                rows={4}
                placeholder="e.g. Detect emails originating from newly observed domains that contain login credentials forms..."
                value={aiPrompt}
                onChange={(e) => setAiPrompt(e.target.value)}
                className="w-full p-3 text-xs rounded bg-surface-secondary border border-border text-foreground focus:outline-none focus:border-primary font-mono"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsAiModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerateFromAi}
                disabled={generatingAi || !aiPrompt.trim()}
                className="px-3 py-1.5 text-xs font-bold rounded bg-primary text-black hover:bg-primary/90 font-mono"
              >
                {generatingAi ? 'Generating AST...' : 'Generate Rule Proposal'}
              </button>
            </div>
          </div>
        </div>
      )}
      {/* Add Test Fixture Modal */}
      {isAddFixtureModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-lg p-6 max-w-lg w-full space-y-4">
            <div className="flex items-center space-x-2 text-primary">
              <FlaskConical className="w-5 h-5" />
              <h3 className="text-sm font-bold font-mono">Create Detection Rule Test Fixture</h3>
            </div>
            <p className="text-xs text-foreground-muted">
              Define a deterministic test payload to verify positive (expected match) or negative (expected non-match) rule execution.
            </p>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Fixture Name *</label>
              <input
                type="text"
                placeholder="e.g. Known Phishing Domain in External Email"
                value={newFixName}
                onChange={(e) => setNewFixName(e.target.value)}
                className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Description</label>
              <input
                type="text"
                placeholder="e.g. Regression test for T1566 credential harvesting payload"
                value={newFixDesc}
                onChange={(e) => setNewFixDesc(e.target.value)}
                className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono focus:outline-none focus:border-primary"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground-muted">Fixture Type</label>
                <select
                  value={newFixType}
                  onChange={(e) => {
                    const val = e.target.value as 'POSITIVE' | 'NEGATIVE';
                    setNewFixType(val);
                    setNewFixExpected(val === 'POSITIVE');
                  }}
                  className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono"
                >
                  <option value="POSITIVE">Positive (Expected to Match)</option>
                  <option value="NEGATIVE">Negative (Expected to NOT Match)</option>
                </select>
              </div>
              <div className="space-y-1">
                <label className="text-xs font-mono text-foreground-muted">Expected Outcome</label>
                <select
                  value={newFixExpected ? 'TRUE' : 'FALSE'}
                  onChange={(e) => setNewFixExpected(e.target.value === 'TRUE')}
                  className="w-full p-2 text-xs rounded bg-surface-secondary border border-border text-foreground font-mono"
                >
                  <option value="TRUE">Matched: TRUE</option>
                  <option value="FALSE">Matched: FALSE</option>
                </select>
              </div>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-mono text-foreground-muted">Test Payload JSON *</label>
              <textarea
                rows={6}
                value={newFixPayloadStr}
                onChange={(e) => setNewFixPayloadStr(e.target.value)}
                className="w-full p-2 text-xs rounded bg-black/60 border border-border text-foreground font-mono focus:outline-none focus:border-primary"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setIsAddFixtureModalOpen(false)}
                className="px-3 py-1.5 text-xs rounded border border-border text-foreground hover:bg-surface-secondary font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateFixture}
                disabled={savingFixture}
                className="px-3 py-1.5 text-xs font-bold rounded bg-primary text-black hover:bg-primary/90 font-mono"
              >
                {savingFixture ? 'Saving...' : 'Save Fixture'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
