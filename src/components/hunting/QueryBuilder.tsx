import React, { useState } from 'react';
import {
  Sparkles,
  Plus,
  Trash2,
  Play,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Bookmark,
  ChevronDown,
  ChevronUp,
  SlidersHorizontal,
} from 'lucide-react';
import type {
  DataSourceMetadata,
  HuntQueryDefinition,
  QueryFilter,
  QueryOperator,
  TimePreset,
  HuntSource,
  HuntValidationResponse,
} from '../../types/hunting';
import { huntingService } from '../../services/huntingService';

interface QueryBuilderProps {
  registry: DataSourceMetadata[];
  query: HuntQueryDefinition;
  onChangeQuery: (newQuery: HuntQueryDefinition) => void;
  onExecute: () => void;
  onSave: () => void;
  executing: boolean;
}

export const QueryBuilder: React.FC<QueryBuilderProps> = ({
  registry,
  query,
  onChangeQuery,
  onExecute,
  onSave,
  executing,
}) => {
  const [naturalPrompt, setNaturalPrompt] = useState('');
  const [translating, setTranslating] = useState(false);
  const [assistantExplanation, setAssistantExplanation] = useState<string | null>(null);

  const [validationResult, setValidationResult] = useState<HuntValidationResponse | null>(null);
  const [validating, setValidating] = useState(false);
  const [showPlan, setShowPlan] = useState(false);

  const currentSourceMeta = registry.find((s) => s.key === query.data_source);
  const availableFields = currentSourceMeta?.fields || [];
  const groupableFields = availableFields.filter((f) => f.is_groupable);

  // Natural Language Translation
  const handleNaturalTranslate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!naturalPrompt.trim()) return;
    setTranslating(true);
    setAssistantExplanation(null);
    try {
      const res = await huntingService.queryAssistant(naturalPrompt, query.data_source);
      onChangeQuery(res.proposed_query);
      setAssistantExplanation(res.explanation);
    } catch (err) {
      console.error('Translation error', err);
    } finally {
      setTranslating(false);
    }
  };

  // Change Source
  const handleSourceChange = (newSource: HuntSource) => {
    onChangeQuery({
      ...query,
      data_source: newSource,
      filters: [],
      group_by: undefined,
    });
    setValidationResult(null);
  };

  // Add Filter
  const handleAddFilter = () => {
    if (availableFields.length === 0) return;
    const firstField = availableFields[0];
    const newFilter: QueryFilter = {
      field: firstField.name,
      operator: firstField.allowed_operators[0] || 'equals',
      value: firstField.options ? firstField.options[0] : '',
    };
    onChangeQuery({
      ...query,
      filters: [...query.filters, newFilter],
    });
  };

  // Update Filter
  const handleUpdateFilter = (index: number, updated: Partial<QueryFilter>) => {
    const nextFilters = [...query.filters];
    const target = { ...nextFilters[index], ...updated };

    // If field changed, update operator and reset value
    if (updated.field && updated.field !== nextFilters[index].field) {
      const fieldMeta = availableFields.find((f) => f.name === updated.field);
      if (fieldMeta) {
        target.operator = fieldMeta.allowed_operators[0] || 'equals';
        target.value = fieldMeta.options ? fieldMeta.options[0] : '';
      }
    }

    nextFilters[index] = target;
    onChangeQuery({ ...query, filters: nextFilters });
  };

  // Remove Filter
  const handleRemoveFilter = (index: number) => {
    const nextFilters = query.filters.filter((_, i) => i !== index);
    onChangeQuery({ ...query, filters: nextFilters });
  };

  // Time Preset
  const handleTimePreset = (preset: TimePreset) => {
    onChangeQuery({
      ...query,
      time_range: {
        ...query.time_range,
        preset,
      },
    });
  };

  // Validate Query
  const handleValidate = async () => {
    setValidating(true);
    try {
      const res = await huntingService.validateQuery(query);
      setValidationResult(res);
      setShowPlan(true);
    } catch (err: any) {
      setValidationResult({
        is_valid: false,
        errors: [err.message || 'Validation error'],
        warnings: [],
        estimated_cost: 'RESTRICTED',
        query_plan: [],
      });
    } finally {
      setValidating(false);
    }
  };

  return (
    <div className="bg-surface border border-border rounded-panel p-4 space-y-4 shadow-xs">
      {/* 1. Natural Language Translation Bar */}
      <form onSubmit={handleNaturalTranslate} className="relative">
        <div className="flex items-center space-x-2 p-1.5 bg-surface-secondary border border-border rounded-control focus-within:border-primary transition-colors">
          <Sparkles className="w-4 h-4 text-primary ml-2 shrink-0 animate-pulse" />
          <input
            type="text"
            value={naturalPrompt}
            onChange={(e) => setNaturalPrompt(e.target.value)}
            placeholder="Ask CyberGuard in plain language: e.g. Find malicious domains seen in the last 24 hours..."
            className="w-full text-xs bg-transparent border-none text-foreground placeholder:text-foreground-muted focus:outline-hidden"
          />
          <button
            type="submit"
            disabled={translating || !naturalPrompt.trim()}
            className="px-3 py-1.5 text-xs font-mono font-medium text-white bg-primary hover:bg-primary/90 rounded-control transition-colors cursor-pointer shrink-0 disabled:opacity-50"
          >
            {translating ? 'Interpreting...' : 'Generate Query'}
          </button>
        </div>
        {assistantExplanation && (
          <div className="mt-2 p-2 bg-primary/10 border border-primary/20 rounded-control text-xs text-foreground flex items-center justify-between">
            <span>{assistantExplanation}</span>
            <button
              onClick={() => setAssistantExplanation(null)}
              className="text-[10px] text-foreground-muted hover:text-foreground cursor-pointer"
            >
              Dismiss
            </button>
          </div>
        )}
      </form>

      {/* 2. Data Source Selector */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 p-3 bg-surface-secondary/40 border border-border rounded-control">
        <div>
          <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1">
            Data Source
          </label>
          <select
            value={query.data_source}
            onChange={(e) => handleSourceChange(e.target.value as HuntSource)}
            className="w-full px-2.5 py-1.5 text-xs font-mono bg-surface border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer"
          >
            {registry.map((s) => (
              <option key={s.key} value={s.key}>
                {s.display_name} {s.approximate_count ? `(${s.approximate_count.toLocaleString()})` : ''}
              </option>
            ))}
          </select>
        </div>

        <div className="md:col-span-2 flex flex-col justify-center text-xs">
          <span className="font-mono text-[10px] text-foreground-muted uppercase">Scope Description</span>
          <p className="text-foreground text-[11px] truncate">
            {currentSourceMeta?.description || 'Select an authoritative CyberGuard dataset to hunt.'}
          </p>
        </div>
      </div>

      {/* 3. Filter Predicates Section */}
      <div className="space-y-2.5">
        <div className="flex items-center justify-between">
          <label className="text-[10px] font-mono uppercase text-foreground-muted">
            Structured Filter Predicates ({query.filters.length})
          </label>
          <button
            type="button"
            onClick={handleAddFilter}
            className="px-2.5 py-1 text-xs font-mono text-primary bg-primary/10 hover:bg-primary/20 border border-primary/30 rounded-control flex items-center space-x-1 cursor-pointer transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Predicate</span>
          </button>
        </div>

        {query.filters.length === 0 ? (
          <div className="p-4 text-center border border-dashed border-border rounded-control bg-surface-secondary/20">
            <p className="text-xs text-foreground-muted">No filters applied. Query will match all records in time range.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {query.filters.map((flt, idx) => {
              const fieldMeta = availableFields.find((f) => f.name === flt.field);
              const allowedOps = fieldMeta?.allowed_operators || ['equals'];
              const options = fieldMeta?.options;

              return (
                <div
                  key={idx}
                  className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 p-2 bg-surface-secondary/50 border border-border rounded-control"
                >
                  {/* Field */}
                  <select
                    value={flt.field}
                    onChange={(e) => handleUpdateFilter(idx, { field: e.target.value })}
                    className="sm:w-1/3 px-2 py-1.5 text-xs bg-surface border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary font-mono"
                  >
                    {availableFields.map((f) => (
                      <option key={f.name} value={f.name}>
                        {f.display_name}
                      </option>
                    ))}
                  </select>

                  {/* Operator */}
                  <select
                    value={flt.operator}
                    onChange={(e) => handleUpdateFilter(idx, { operator: e.target.value as QueryOperator })}
                    className="sm:w-1/4 px-2 py-1.5 text-xs bg-surface border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary font-mono"
                  >
                    {allowedOps.map((op) => (
                      <option key={op} value={op}>
                        {op.replace('_', ' ')}
                      </option>
                    ))}
                  </select>

                  {/* Value Input */}
                  {options ? (
                    <select
                      value={flt.value}
                      onChange={(e) => handleUpdateFilter(idx, { value: e.target.value })}
                      className="flex-1 px-2 py-1.5 text-xs bg-surface border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary font-mono"
                    >
                      {options.map((opt) => (
                        <option key={opt} value={opt}>
                          {opt}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <input
                      type={fieldMeta?.field_type === 'number' ? 'number' : 'text'}
                      value={flt.value}
                      onChange={(e) => handleUpdateFilter(idx, { value: e.target.value })}
                      placeholder="Operand value..."
                      className="flex-1 px-2 py-1.5 text-xs bg-surface border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary font-mono"
                    />
                  )}

                  {/* Delete Button */}
                  <button
                    type="button"
                    onClick={() => handleRemoveFilter(idx)}
                    className="p-1.5 text-foreground-muted hover:text-threat-critical rounded-control hover:bg-surface border border-transparent hover:border-border transition-colors cursor-pointer shrink-0"
                    title="Remove Filter"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. Time Range & Group By */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-border">
        <div>
          <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1.5 flex items-center space-x-1">
            <Clock className="w-3 h-3" />
            <span>Time Window Preset</span>
          </label>
          <div className="flex flex-wrap gap-1">
            {(['15m', '1h', '6h', '24h', '7d', '30d', 'all'] as TimePreset[]).map((preset) => {
              const isActive = (query.time_range?.preset || '7d') === preset;
              return (
                <button
                  key={preset}
                  type="button"
                  onClick={() => handleTimePreset(preset)}
                  className={`px-2.5 py-1 text-xs font-mono rounded-control border transition-colors cursor-pointer ${
                    isActive
                      ? 'bg-primary text-white border-primary font-bold shadow-xs'
                      : 'bg-surface-secondary text-foreground-muted border-border hover:text-foreground'
                  }`}
                >
                  {preset}
                </button>
              );
            })}
          </div>
        </div>

        <div>
          <label className="block text-[10px] font-mono uppercase text-foreground-muted mb-1.5 flex items-center space-x-1">
            <SlidersHorizontal className="w-3 h-3" />
            <span>Server-side Grouping (Top-N)</span>
          </label>
          <select
            value={query.group_by || ''}
            onChange={(e) => onChangeQuery({ ...query, group_by: e.target.value || undefined })}
            className="w-full px-2.5 py-1.5 text-xs font-mono bg-surface border border-border rounded-control text-foreground focus:outline-hidden focus:border-primary cursor-pointer"
          >
            <option value="">No Grouping (Flat Records)</option>
            {groupableFields.map((f) => (
              <option key={f.name} value={f.name}>
                Group by {f.display_name}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* 5. Validation Result / Query Plan Accordion */}
      {validationResult && (
        <div className="pt-2 border-t border-border">
          <div
            onClick={() => setShowPlan(!showPlan)}
            className="flex items-center justify-between p-2.5 bg-surface-secondary/60 border border-border rounded-control cursor-pointer"
          >
            <div className="flex items-center space-x-2 text-xs">
              {validationResult.is_valid ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
              ) : (
                <AlertTriangle className="w-4 h-4 text-threat-critical" />
              )}
              <span className="font-mono font-medium text-foreground">
                {validationResult.is_valid
                  ? `Query Validated (${validationResult.estimated_cost} estimated cost)`
                  : 'Query Contains Validation Errors'}
              </span>
            </div>
            {showPlan ? <ChevronUp className="w-4 h-4 text-foreground-muted" /> : <ChevronDown className="w-4 h-4 text-foreground-muted" />}
          </div>

          {showPlan && (
            <div className="mt-2 p-3 bg-surface border border-border rounded-control text-xs space-y-2">
              {validationResult.errors.length > 0 && (
                <div className="p-2 bg-threat-critical/10 border border-threat-critical/20 rounded-control text-threat-critical text-xs space-y-1">
                  {validationResult.errors.map((e, idx) => (
                    <div key={idx}>• {e}</div>
                  ))}
                </div>
              )}
              {validationResult.query_plan.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[10px] font-mono text-foreground-muted uppercase">Query Execution Steps:</span>
                  {validationResult.query_plan.map((step, idx) => (
                    <div key={idx} className="flex items-start space-x-2 text-[11px] font-mono">
                      <span className="text-primary font-bold">[{idx + 1}]</span>
                      <span className="text-foreground-muted">{step.step}:</span>
                      <span className="text-foreground">{step.description}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* 6. Action Buttons Bar */}
      <div className="pt-3 border-t border-border flex items-center justify-between">
        <button
          type="button"
          onClick={handleValidate}
          disabled={validating}
          className="px-3 py-1.5 text-xs font-mono text-foreground-muted hover:text-foreground bg-surface-secondary border border-border rounded-control cursor-pointer transition-colors"
        >
          {validating ? 'Validating...' : 'Validate Query'}
        </button>

        <div className="flex items-center space-x-2">
          <button
            type="button"
            onClick={onSave}
            className="px-3 py-1.5 text-xs font-mono text-foreground hover:text-foreground bg-surface hover:bg-surface-secondary border border-border rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs"
          >
            <Bookmark className="w-3.5 h-3.5 text-primary" />
            <span>Save Hunt</span>
          </button>

          <button
            type="button"
            onClick={onExecute}
            disabled={executing}
            className="px-4 py-1.5 text-xs font-mono font-medium text-white bg-primary hover:bg-primary/90 rounded-control flex items-center space-x-1.5 cursor-pointer shadow-xs disabled:opacity-50"
          >
            <Play className="w-3.5 h-3.5 fill-white" />
            <span>{executing ? 'Executing...' : 'Run Threat Hunt'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
