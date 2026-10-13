"""Canonical sender contract shared by API validation and internal analysis."""
from email.utils import getaddresses
import re


def normalize_email_claim(data):
    data = dict(data)
    for legacy in ('from', 'reply_to'):
        if legacy in data:
            raise ValueError(f'Use {legacy}_address instead of {legacy}.')
    for prefix in ('from', 'reply_to'):
        raw = data.get(prefix + '_address') or ''
        if not isinstance(raw, str) or '\r' in raw or '\n' in raw:
            raise ValueError(f'{prefix}_address must be a single email address.')
        parsed = getaddresses([raw])
        if not raw and prefix == 'reply_to':
            if data.get(prefix + '_domain'):
                raise ValueError('reply_to_domain requires reply_to_address.')
            data[prefix + '_address'] = ''
            data[prefix + '_domain'] = ''
            continue
        if len(parsed) != 1 or not re.fullmatch(r'[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+', parsed[0][1]):
            raise ValueError(f'{prefix}_address must be a single valid email address.')
        display, address = parsed[0]
        address = address.lower()
        domain = address.rsplit('@', 1)[1].rstrip('.').encode('idna').decode('ascii')
        supplied = data.get(prefix + '_domain')
        if supplied and (not isinstance(supplied, str) or supplied.lower().rstrip('.') != domain):
            raise ValueError(f'{prefix}_domain contradicts {prefix}_address; omit domains to derive them automatically.')
        data[prefix + '_address'] = address.rsplit('@', 1)[0] + '@' + domain
        data[prefix + '_domain'] = domain
        if display and not data.get(prefix + '_display_name'):
            data[prefix + '_display_name'] = display
    return data
