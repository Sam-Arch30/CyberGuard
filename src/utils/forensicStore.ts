import type { EmailAnalysis } from '../types/forensic';
import { resolveEmailIndicators, resolveAttribution } from './indicatorHelper';
import { resolveConfidenceConclusions } from './confidenceResolver';
import { SCENARIO_1_LEGITIMATE, SCENARIO_2_PHISHING, SCENARIO_3_PRIMARY_EMAIL } from '../data/sihScenariosData';

const STORAGE_KEY_PREFIX = 'mailtrace_forensic_';
const memoryStore = new Map<string, EmailAnalysis>();

export const deriveFilename = (analysis: Partial<EmailAnalysis>): string => {
  if (analysis.original_filename) return analysis.original_filename;
  if (analysis.file_info?.filename) return analysis.file_info.filename;
  if (analysis.subject) {
    const slug = analysis.subject
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '_')
      .replace(/^_+|_+$/g, '')
      .slice(0, 32);
    if (slug) return `${slug}.eml`;
  }
  return `${analysis.id || 'email'}.eml`;
};

export const saveAnalysisResult = (id: string, data: EmailAnalysis): void => {
  const resolved = resolveEmailIndicators({ ...data, id });
  memoryStore.set(id, resolved);
  try {
    sessionStorage.setItem(STORAGE_KEY_PREFIX + id, JSON.stringify(resolved));
    sessionStorage.setItem(STORAGE_KEY_PREFIX + 'latest_id', id);
  } catch (e) {
    console.warn('Unable to persist analysis in sessionStorage', e);
  }
};

export const getAnalysisResult = (id: string): EmailAnalysis | null => {
  let targetId = id;
  if (targetId === 'latest') {
    const latestId = sessionStorage.getItem(STORAGE_KEY_PREFIX + 'latest_id');
    if (latestId && (memoryStore.has(latestId) || sessionStorage.getItem(STORAGE_KEY_PREFIX + latestId))) {
      targetId = latestId;
    } else {
      // Find the most recently added key in memoryStore or sessionStorage
      const allReal = getAllAvailableAnalyses(false);
      if (allReal.length > 0) {
        return allReal[0];
      }
      return null;
    }
  }

  if (memoryStore.has(targetId)) {
    const item = resolveEmailIndicators(memoryStore.get(targetId)!);
    if (!item.attribution || !item.attribution.probable_origin_ip) {
      item.attribution = resolveAttribution(item);
    }
    if (!item.forensic_conclusions || item.forensic_conclusions.length === 0) {
      item.forensic_conclusions = resolveConfidenceConclusions(item);
    }
    return item;
  }

  try {
    const raw = sessionStorage.getItem(STORAGE_KEY_PREFIX + targetId);
    if (raw) {
      const parsed = JSON.parse(raw);
      const resolved = resolveEmailIndicators(parsed);
      if (!resolved.attribution || !resolved.attribution.probable_origin_ip) {
        resolved.attribution = resolveAttribution(resolved);
      }
      if (!resolved.forensic_conclusions || resolved.forensic_conclusions.length === 0) {
        resolved.forensic_conclusions = resolveConfidenceConclusions(resolved);
      }
      memoryStore.set(targetId, resolved);
      return resolved;
    }
  } catch (e) {
    console.warn('Error reading analysis from sessionStorage', e);
  }

  // Explicit SIH Demo Benchmark Scenarios (only accessed when specifically requested by scenario ID)
  if (targetId === 'scenario-1-legit') {
    const item = resolveEmailIndicators({ ...SCENARIO_1_LEGITIMATE, is_demo: true });
    if (!item.attribution || !item.attribution.probable_origin_ip) item.attribution = resolveAttribution(item);
    if (!item.forensic_conclusions || item.forensic_conclusions.length === 0) item.forensic_conclusions = resolveConfidenceConclusions(item);
    return item;
  }
  if (targetId === 'scenario-2-phish') {
    const item = resolveEmailIndicators({ ...SCENARIO_2_PHISHING, is_demo: true });
    if (!item.attribution || !item.attribution.probable_origin_ip) item.attribution = resolveAttribution(item);
    if (!item.forensic_conclusions || item.forensic_conclusions.length === 0) item.forensic_conclusions = resolveConfidenceConclusions(item);
    return item;
  }
  if (targetId === 'scenario-3-campaign') {
    const item = resolveEmailIndicators({ ...SCENARIO_3_PRIMARY_EMAIL, is_demo: true });
    if (!item.attribution || !item.attribution.probable_origin_ip) item.attribution = resolveAttribution(item);
    if (!item.forensic_conclusions || item.forensic_conclusions.length === 0) item.forensic_conclusions = resolveConfidenceConclusions(item);
    return item;
  }

  return null;
};

export const getAllAvailableAnalyses = (includeDemo = false): EmailAnalysis[] => {
  const result: EmailAnalysis[] = [];
  const seenIds = new Set<string>();

  // 1. Memory store entries
  for (const [id, analysis] of memoryStore.entries()) {
    if (!seenIds.has(id)) {
      const resolved = resolveEmailIndicators(analysis);
      if (!resolved.original_filename) {
        resolved.original_filename = deriveFilename(resolved);
      }
      result.push(resolved);
      seenIds.add(id);
    }
  }

  // 2. SessionStorage entries
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key && key.startsWith(STORAGE_KEY_PREFIX) && key !== STORAGE_KEY_PREFIX + 'latest_id') {
        const id = key.substring(STORAGE_KEY_PREFIX.length);
        if (!seenIds.has(id)) {
          const raw = sessionStorage.getItem(key);
          if (raw) {
            const parsed = JSON.parse(raw);
            const resolved = resolveEmailIndicators(parsed);
            if (!resolved.original_filename) {
              resolved.original_filename = deriveFilename(resolved);
            }
            result.push(resolved);
            seenIds.add(id);
          }
        }
      }
    }
  } catch (e) {
    console.warn('Error reading sessionStorage for available analyses', e);
  }

  // Sort by upload timestamp descending if available
  result.sort((a, b) => {
    const tA = new Date(a.upload_timestamp || 0).getTime();
    const tB = new Date(b.upload_timestamp || 0).getTime();
    return tB - tA;
  });

  // 3. Isolated demo scenarios only if explicitly requested
  if (includeDemo) {
    const sihScenarios = [
      resolveEmailIndicators({ ...SCENARIO_1_LEGITIMATE, is_demo: true }),
      resolveEmailIndicators({ ...SCENARIO_2_PHISHING, is_demo: true }),
      resolveEmailIndicators({ ...SCENARIO_3_PRIMARY_EMAIL, is_demo: true })
    ];
    for (const scenario of sihScenarios) {
      if (scenario.id && !seenIds.has(scenario.id)) {
        result.push(scenario);
        seenIds.add(scenario.id);
      }
    }
  }

  return result;
};

export const resetDemoStore = async (): Promise<boolean> => {
  try {
    // 1. Remove synthetic demo keys from sessionStorage
    const toRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k && (k.includes('scenario-') || k.includes('DH-') || k.includes('sih_demo'))) {
        toRemove.push(k);
      }
    }
    toRemove.forEach(k => sessionStorage.removeItem(k));

    // 2. Remove from memoryStore
    ['scenario-1-legit', 'scenario-2-phish', 'scenario-3-campaign'].forEach(id => memoryStore.delete(id));

    // 3. Notify backend demo reset endpoint if reachable
    try {
      await fetch('http://127.0.0.1:8000/api/benchmark/demo-reset', { method: 'POST' });
    } catch {
      // Safe fallback
    }

    return true;
  } catch (e) {
    console.error('Failed to reset demo store:', e);
    return false;
  }
};

export const clearForensicStore = (): void => {
  memoryStore.clear();
  try {
    const toRemove: string[] = [];
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      if (k && (k.startsWith(STORAGE_KEY_PREFIX) || k.includes('mailtrace') || k.includes('scenario-') || k.includes('DH-') || k.includes('sih_demo'))) {
        toRemove.push(k);
      }
    }
    toRemove.forEach(k => sessionStorage.removeItem(k));

    const localToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k && (k.startsWith(STORAGE_KEY_PREFIX) || k.includes('mailtrace') || k.includes('scenario-'))) {
        localToRemove.push(k);
      }
    }
    localToRemove.forEach(k => localStorage.removeItem(k));
  } catch (e) {
    console.warn('Error clearing forensicStore', e);
  }
};
