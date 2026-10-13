"""Bounded, offline structural screening of URL lists; never claims website safety."""
import asyncio
import re
from urllib.parse import urlsplit
from backend.services.url_domain_analyzers import PassiveURLAnalyzer

MAX_URLS = 50
MAX_URL_LENGTH = 4096

def parse_url_lines(text):
    lines = [(n, line.strip()) for n, line in enumerate(text.splitlines(), 1) if line.strip()]
    if not lines:
        raise ValueError('Provide at least one URL, one per line.')
    if len(lines) > MAX_URLS:
        raise ValueError(f'At most {MAX_URLS} URLs can be assessed per batch.')
    result = []
    seen = set()
    for line_number, original in lines:
        value = re.sub(r'^hxxps?://', lambda m: 'https://' if m.group().lower().startswith('hxxps') else 'http://', original, flags=re.I).replace('[.]', '.')
        if len(value) > MAX_URL_LENGTH:
            raise ValueError(f'Line {line_number}: URL exceeds {MAX_URL_LENGTH} characters.')
        if '://' not in value:
            value = 'https://' + value
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname or any(c.isspace() for c in value):
                raise ValueError('Use an HTTP(S) URL with a valid hostname and no spaces.')
            parsed.port
        except ValueError as exc:
            raise ValueError(f'Line {line_number}: {exc}') from exc
        if value not in seen:
            seen.add(value)
            result.append({'line': line_number, 'original': original, 'url': value})
    return result

async def analyze_url_lines(text):
    inputs = parse_url_lines(text)
    analyzer = PassiveURLAnalyzer()
    results = []
    async with asyncio.timeout(15):
        for item in inputs:
            assessment = await analyzer.analyze(item['url'], {})
            findings = [{**finding, 'severity': getattr(finding['severity'], 'value', finding['severity']),
                         'method': getattr(finding.get('method'), 'value', finding.get('method'))}
                        for finding in assessment.findings]
            actionable = [f for f in findings if f['severity'] in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
            results.append({**item, 'status': 'STRUCTURAL_SIGNALS_FOUND' if actionable else 'NO_STRUCTURAL_SIGNALS',
                            'findings': findings, 'limitations': assessment.errors,
                            'parsed_components': assessment.metadata.get('parsed_components', {})})
    return {'mode': 'OFFLINE_STRUCTURAL_ANALYSIS', 'submitted_lines': len([l for l in text.splitlines() if l.strip()]),
            'urls_analyzed': len(results), 'results': results,
            'limitations': ['No DNS, registration, reputation feed or destination HTTP inspection was performed.',
                           'Structural signals are not confirmed phishing; no signals does not establish safety.']}
