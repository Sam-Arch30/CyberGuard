import type {
  ConfidenceLevel,
  EvaluatedEvidence,
  ForensicConclusion,
  EvidenceCategory
} from '../types/confidence';
import type { EmailAnalysis } from '../types/forensic';
import { resolveAttribution } from './indicatorHelper';

const ENGINE_VERSION = '1.0.0';

function scoreToLevel(score: number): ConfidenceLevel {
  if (score >= 85) return 'VERY HIGH';
  if (score >= 70) return 'HIGH';
  if (score >= 40) return 'MODERATE';
  return 'LOW';
}

function roundConfidence(score: number, level: ConfidenceLevel): number {
  const bounded = Math.max(0, Math.min(100, score));
  // Round to nearest whole integer to prevent false precision
  let rounded = Math.round(bounded);
  if (level === 'LOW' && rounded > 39) rounded = 39;
  if (level === 'MODERATE' && rounded > 69) rounded = 69;
  return rounded;
}

export function resolveConfidenceConclusions(email: EmailAnalysis): ForensicConclusion[] {
  if (email.forensic_conclusions && email.forensic_conclusions.length > 0) {
    return email.forensic_conclusions;
  }

  const conclusions: ForensicConclusion[] = [];
  const nowIso = new Date().toISOString();

  // 1. THREAT CLASSIFICATION
  const threatScore = email.threat_score;
  if (threatScore) {
    const isCriticalOrHigh = threatScore.severity === 'critical' || threatScore.severity === 'high';
    const supporting: EvaluatedEvidence[] = (threatScore.reasons || []).map((r, idx) => ({
      evidence_id: `ev-threat-${idx + 1}`,
      source_module: 'threat_scorer',
      statement: `${r.label}: ${r.evidence}`,
      is_supporting: true,
      reliability: 0.85,
      independence: 0.8,
      recency_days: 0,
      specificity: 0.85,
      consistency: 0.9,
      raw_score_contribution: r.points || 15,
      effective_weight: (r.points || 15) * 0.85,
      evidence_category: 'confirmed_evidence' as EvidenceCategory,
      independence_cluster: 'heuristic_rules'
    }));

    const conflicting: EvaluatedEvidence[] = (threatScore.positive_evidence || []).map((p, idx) => ({
      evidence_id: `ev-threat-conf-${idx + 1}`,
      source_module: 'threat_scorer',
      statement: `${p.label}: ${p.evidence}`,
      is_supporting: false,
      reliability: 0.8,
      independence: 0.85,
      recency_days: 0,
      specificity: 0.75,
      consistency: 0.8,
      raw_score_contribution: -15,
      effective_weight: -12,
      evidence_category: 'confirmed_evidence' as EvidenceCategory,
      independence_cluster: 'auth_positives'
    }));

    let score = threatScore.score || 50;
    let level = scoreToLevel(score);
    let finalScore = roundConfidence(score, level);

    conclusions.push({
      conclusion_id: 'conc-threat-001',
      type: 'threat_classification',
      statement: isCriticalOrHigh
        ? `High-risk email threat classified as ${threatScore.severity.toUpperCase()} severity with active malicious indicators.`
        : `Email threat evaluated as ${threatScore.severity.toUpperCase()} severity with standard risk signals.`,
      confidence_score: finalScore,
      confidence_level: level,
      supporting_evidence: supporting,
      conflicting_evidence: conflicting,
      limitations: [
        'Threat score is calculated from heuristic indicators and domain heuristics; does not guarantee runtime detonation.',
        'Zero-day evasion techniques may depress heuristic signal weights.'
      ],
      source_modules: ['threat_scorer', 'email_authenticator'],
      generated_at: nowIso,
      engine_version: ENGINE_VERSION
    });
  }

  // 2. INFRASTRUCTURE ATTRIBUTION
  const attribution = email.attribution || resolveAttribution(email);
  if (attribution && attribution.probable_origin_ip) {
    const supporting: EvaluatedEvidence[] = (attribution.supporting_evidence || []).map((s, idx) => ({
      evidence_id: `ev-attr-${idx + 1}`,
      source_module: 'attribution_engine',
      statement: s.observation,
      is_supporting: true,
      reliability: 0.8,
      independence: 0.75,
      recency_days: 1,
      specificity: 0.85,
      consistency: 0.9,
      raw_score_contribution: s.contribution || 15,
      effective_weight: (s.contribution || 15) * 0.8,
      evidence_category: 'probable_inference' as EvidenceCategory,
      independence_cluster: s.source?.toLowerCase().includes('maxmind') ? 'maxmind_derived_geo' : undefined
    }));

    const conflicting: EvaluatedEvidence[] = (attribution.conflicting_evidence || []).map((c, idx) => ({
      evidence_id: `ev-attr-conf-${idx + 1}`,
      source_module: 'attribution_engine',
      statement: c.observation,
      is_supporting: false,
      reliability: 0.85,
      independence: 0.9,
      recency_days: 1,
      specificity: 0.9,
      consistency: 0.85,
      raw_score_contribution: c.contribution || -20,
      effective_weight: (c.contribution || -20) * 0.9,
      evidence_category: 'probable_inference' as EvidenceCategory,
      independence_cluster: 'anonymization_network'
    }));

    const finalScore = roundConfidence(attribution.confidence_score, attribution.confidence_level as ConfidenceLevel);

    conclusions.push({
      conclusion_id: 'conc-attr-001',
      type: 'infrastructure_attribution',
      statement: `Probable sending infrastructure hosted on ${attribution.probable_origin_ip} (${attribution.probable_origin_asn || 'Unknown ASN'}) in ${attribution.probable_infrastructure_country || 'Unknown Region'}.`,
      confidence_score: finalScore,
      confidence_level: (attribution.confidence_level as ConfidenceLevel) || 'HIGH',
      supporting_evidence: supporting,
      conflicting_evidence: conflicting,
      limitations: [
        'Infrastructure location and ownership do not establish the physical identity or location of the human adversary.',
        'Shared cloud, VPS hosting, and bulletproof providers can be rented anonymously or hijacked via compromised credentials.'
      ],
      source_modules: ['attribution_engine', 'relay_reconstructor', 'ip_intelligence'],
      generated_at: nowIso,
      engine_version: ENGINE_VERSION
    });
  }

  // 3. GEOLOCATION & CONFLICT DETECTION
  const originIp = attribution?.probable_origin_ip;
  const ipIntel = originIp && email.ip_intelligence ? email.ip_intelligence[originIp] : undefined;
  if (originIp && ipIntel) {
    const geoCountry = ipIntel.country || 'United States';
    const supporting: EvaluatedEvidence[] = [
      {
        evidence_id: 'ev-geo-1',
        source_module: 'ip_intelligence',
        statement: `Earliest untrusted relay IP ${originIp} geolocates to ${geoCountry} (${ipIntel.city || 'Regional Node'}, ASN ${ipIntel.asn || 'AS-UNASSIGNED'}).`,
        is_supporting: true,
        reliability: 0.8,
        independence: 0.7,
        recency_days: 1,
        specificity: 0.75,
        consistency: 0.85,
        raw_score_contribution: 35,
        effective_weight: 28,
        evidence_category: 'probable_inference',
        independence_cluster: 'maxmind_derived_geo'
      }
    ];

    const conflicting: EvaluatedEvidence[] = [];

    // Check WHOIS country conflict
    const domains = email.domain_intelligence || {};
    let whoisConflictCountry: string | null = null;
    for (const d of Object.values(domains)) {
      const reg = d.registration as any;
      if (reg && reg.country && reg.country !== geoCountry) {
        whoisConflictCountry = reg.country;
        break;
      }
    }

    if (whoisConflictCountry) {
      conflicting.push({
        evidence_id: 'ev-geo-conf-whois',
        source_module: 'domain_intelligence',
        statement: `Associated domain WHOIS registration country (${whoisConflictCountry}) contradicts IP infrastructure country (${geoCountry}).`,
        is_supporting: false,
        reliability: 0.75,
        independence: 0.9,
        recency_days: 2,
        specificity: 0.85,
        consistency: 0.6,
        raw_score_contribution: -15,
        effective_weight: -13,
        evidence_category: 'probable_inference',
        independence_cluster: 'whois_registration'
      });
    }

    // Check timezone conflict
    if (email.date && (email.date.includes('+0530') || email.date.includes('+05:30') || email.date.includes('+0800')) && (geoCountry === 'United States' || geoCountry === 'Netherlands')) {
      conflicting.push({
        evidence_id: 'ev-geo-conf-tz',
        source_module: 'email_parser',
        statement: `Header Date timezone (+05:30 / Asia) contradicts geographic timezone of sending IP infrastructure (${geoCountry}).`,
        is_supporting: false,
        reliability: 0.85,
        independence: 0.95,
        recency_days: 0,
        specificity: 0.8,
        consistency: 0.65,
        raw_score_contribution: -15,
        effective_weight: -14,
        evidence_category: 'confirmed_evidence',
        independence_cluster: 'temporal_headers'
      });
    }

    // Proxy / VPN check
    if (ipIntel.is_proxy_vpn_tor) {
      conflicting.push({
        evidence_id: 'ev-geo-conf-proxy',
        source_module: 'ip_intelligence',
        statement: `Origin IP ${originIp} operates as a VPN, Tor exit, or proxy node; physical location obscured.`,
        is_supporting: false,
        reliability: 0.9,
        independence: 0.95,
        recency_days: 1,
        specificity: 0.95,
        consistency: 0.9,
        raw_score_contribution: -25,
        effective_weight: -24,
        evidence_category: 'confirmed_evidence',
        independence_cluster: 'anonymization_network'
      });
    }

    let geoScore = 75 - (conflicting.length * 15);
    geoScore = Math.max(25, Math.min(95, geoScore));
    const geoLevel = scoreToLevel(geoScore);
    const finalGeoScore = roundConfidence(geoScore, geoLevel);

    conclusions.push({
      conclusion_id: 'conc-geo-001',
      type: 'geolocation',
      statement: `Sending network infrastructure geolocates to ${geoCountry} (${ipIntel.city || 'Regional Center'}).`,
      confidence_score: finalGeoScore,
      confidence_level: geoLevel,
      supporting_evidence: supporting,
      conflicting_evidence: conflicting,
      limitations: [
        'IP geolocation reflects network egress routing point and can be masked via VPN, Tor, or intermediate relays.',
        'Does not identify physical location of the individual composer or operator.'
      ],
      source_modules: ['ip_intelligence', 'relay_reconstructor'],
      generated_at: nowIso,
      engine_version: ENGINE_VERSION
    });
  }

  // 4. LOOKALIKE DETERMINATION
  const lookalikes = email.lookalike_domains || [];
  if (lookalikes.length > 0) {
    const lk = lookalikes[0];
    const simPct = Math.round(lk.similarity * 100);
    const supporting: EvaluatedEvidence[] = [
      {
        evidence_id: 'ev-lk-1',
        source_module: 'lookalike_detector',
        statement: `Domain '${lk.domain}' exhibits ${simPct}% visual/lexical similarity to protected brand '${lk.suspected_brand || lk.brand_name}'.`,
        is_supporting: true,
        reliability: 0.95,
        independence: 0.9,
        recency_days: 0,
        specificity: 0.9,
        consistency: 0.95,
        raw_score_contribution: 55,
        effective_weight: 52,
        evidence_category: 'confirmed_evidence',
        independence_cluster: 'lexical_distance'
      }
    ];

    if (lk.techniques && lk.techniques.length > 0) {
      supporting.push({
        evidence_id: 'ev-lk-2',
        source_module: 'lookalike_detector',
        statement: `Typosquatting techniques identified: ${lk.techniques.join(', ')}.`,
        is_supporting: true,
        reliability: 0.9,
        independence: 0.8,
        recency_days: 0,
        specificity: 0.85,
        consistency: 0.9,
        raw_score_contribution: 25,
        effective_weight: 22,
        evidence_category: 'confirmed_evidence',
        independence_cluster: 'technique_fingerprint'
      });
    }

    const score = lk.similarity >= 0.90 ? 82 : 65;
    const level = scoreToLevel(score);
    const finalScore = roundConfidence(score, level);

    conclusions.push({
      conclusion_id: 'conc-lk-001',
      type: 'lookalike_determination',
      statement: `Domain '${lk.domain}' is classified as a brand impersonation / lookalike domain targeting '${lk.suspected_brand || lk.brand_name}'.`,
      confidence_score: finalScore,
      confidence_level: level,
      supporting_evidence: supporting,
      conflicting_evidence: [],
      limitations: [
        'Domain similarity algorithms measure lexical edit distance and homoglyphs; benign partner brands or typos can match.',
        'Ownership registry check is recommended before legal enforcement.'
      ],
      source_modules: ['lookalike_detector'],
      generated_at: nowIso,
      engine_version: ENGINE_VERSION
    });
  }

  // 5. MALICIOUS URL CONCLUSIONS
  const urls = email.url_analysis || [];
  const suspiciousUrls = urls.filter(u => u.suspicion_level === 'high' || u.suspicion_score >= 60);
  if (suspiciousUrls.length > 0) {
    const topUrl = suspiciousUrls[0];
    const supporting: EvaluatedEvidence[] = (topUrl.score_reasons || []).map((reason, idx) => ({
      evidence_id: `ev-url-${idx + 1}`,
      source_module: 'url_analyzer',
      statement: reason,
      is_supporting: true,
      reliability: 0.85,
      independence: 0.85,
      recency_days: 0,
      specificity: 0.85,
      consistency: 0.9,
      raw_score_contribution: 20,
      effective_weight: 18,
      evidence_category: 'confirmed_evidence',
      independence_cluster: 'url_static_features'
    }));

    const score = Math.min(95, Math.max(50, topUrl.suspicion_score || 75));
    const level = scoreToLevel(score);
    const finalScore = roundConfidence(score, level);

    conclusions.push({
      conclusion_id: 'conc-url-001',
      type: 'malicious_url',
      statement: `Target URL '${topUrl.domain}' is assessed as a high-risk phishing/credential harvesting destination.`,
      confidence_score: finalScore,
      confidence_level: level,
      supporting_evidence: supporting,
      conflicting_evidence: [],
      limitations: [
        'Static URL analysis cannot observe dynamic cloaking or geo-fenced redirect chains.',
        'Final payload delivery was not actively detonated in sandbox.'
      ],
      source_modules: ['url_analyzer'],
      generated_at: nowIso,
      engine_version: ENGINE_VERSION
    });
  }

  // 6. NLP CLASSIFICATION
  const mlAssessment = email.ml_assessment;
  if (mlAssessment && mlAssessment.available) {
    const isPhish = mlAssessment.classification === 'phishing';
    const probPct = mlAssessment.probability ? Math.round(mlAssessment.probability * 100) : 80;
    const supporting: EvaluatedEvidence[] = (mlAssessment.top_features || []).map((f, idx) => ({
      evidence_id: `ev-nlp-${idx + 1}`,
      source_module: 'ml_classifier',
      statement: `NLP linguistic feature identified: ${f}`,
      is_supporting: true,
      reliability: 0.8,
      independence: 0.75,
      recency_days: 0,
      specificity: 0.8,
      consistency: 0.85,
      raw_score_contribution: 15,
      effective_weight: 12,
      evidence_category: 'probable_inference',
      independence_cluster: 'nlp_embeddings'
    }));

    const score = isPhish ? probPct : 20;
    const level = scoreToLevel(score);
    const finalScore = roundConfidence(score, level);

    conclusions.push({
      conclusion_id: 'conc-nlp-001',
      type: 'nlp_classification',
      statement: isPhish
        ? `NLP behavioral and semantic analysis classifies body text as social engineering / phishing with ${probPct}% probability.`
        : `NLP semantic analysis classifies body text as legitimate correspondence.`,
      confidence_score: finalScore,
      confidence_level: level,
      supporting_evidence: supporting,
      conflicting_evidence: [],
      limitations: [
        'NLP models analyze linguistic structure and social engineering patterns; generative AI can produce evasion variants.',
        'High-context spear phishing with clean grammar may reduce classification sensitivity.'
      ],
      source_modules: ['ml_classifier'],
      generated_at: nowIso,
      engine_version: ENGINE_VERSION
    });
  }

  return conclusions;
}
