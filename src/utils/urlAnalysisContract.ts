type JsonObject = Record<string, unknown>;
const object = (value: unknown): JsonObject => value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : {};

export function adaptUrlAnalysis(payload: unknown) {
  const data = object(payload);
  const score = data.overall_score;
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 100 || !Array.isArray(data.findings)) {
    throw new Error('URL analysis returned an incomplete result. Retry and review the API logs.');
  }
  const metadata = object(data.analyzer_metadata);
  const components = object(object(metadata.passive_url_analyzer).parsed_components);
  const findings = data.findings.map(value => {
    const finding = object(value);
    if (typeof finding.title !== 'string' || typeof finding.finding_type !== 'string' || typeof finding.description !== 'string') {
      throw new Error('URL finding is missing required evidence fields.');
    }
    return {finding_type: finding.finding_type, title: finding.title, description: finding.description,
      severity: typeof finding.severity === 'string' ? finding.severity : 'LOW',
      confidence: typeof finding.confidence === 'number' ? finding.confidence : 0};
  });
  const domain = typeof components.hostname === 'string' ? components.hostname : '';
  return {url: String(data.target ?? ''), normalized_url: String(data.target ?? ''), domain,
    overall_risk_score: score, overall_severity: String(data.overall_severity ?? 'LOW'),
    is_lookalike: findings.some(f => /LOOKALIKE|HOMOGLYPH/.test(f.finding_type)),
    targeted_brand: undefined as string | undefined,
    is_punycode: domain.split('.').some(label => label.startsWith('xn--')),
    domain_age_days: undefined as number | undefined, is_newly_registered: false,
    redirect_hops_count: null as number | null, findings,
    confidence: typeof data.confidence === 'number' ? data.confidence : 0};
}
