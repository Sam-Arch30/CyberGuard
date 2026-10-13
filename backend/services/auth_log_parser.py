"""Explicit authentication log formats; malformed structured data never falls back."""
import json
from pathlib import Path
from fastapi import HTTPException
from backend.services.authentication_analyzers import global_adapter_registry


def parse_auth_log(content: bytes, filename: str, mime: str = '', provider_hint=None):
    try:
        text = content.decode('utf-8-sig')
    except UnicodeDecodeError:
        raise HTTPException(422, 'Authentication logs must be UTF-8 text.')
    suffix = Path(filename).suffix.lower()
    jsonl = suffix in ('.jsonl', '.ndjson') or mime in ('application/x-ndjson', 'application/jsonl')
    structured = jsonl or suffix == '.json' or mime == 'application/json'
    events = []
    if jsonl:
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise HTTPException(422, f'Invalid JSONL at line {number}, column {exc.colno}: {exc.msg}.')
            if not isinstance(event, dict) or not event:
                raise HTTPException(422, f'JSONL line {number} must contain a nonempty event object.')
            events.append(event)
    elif structured:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HTTPException(422, f'Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}.')
        events = parsed.get('events', [parsed]) if isinstance(parsed, dict) else parsed
        if not isinstance(events, list) or any(not isinstance(e, dict) or not e for e in events):
            raise HTTPException(422, 'JSON must contain event objects or an events array of objects.')
    elif suffix in ('.log', '.txt', '.syslog') or provider_hint == 'linux_auth':
        events = [line.strip() for line in text.splitlines() if line.strip()]
    else:
        raise HTTPException(422, 'Choose JSON (.json), JSONL (.jsonl), or plain text/syslog (.log/.txt).')
    if not events:
        raise HTTPException(422, 'No authentication events were supplied.')
    for number, event in enumerate(events, 1):
        try:
            normalized = global_adapter_registry.normalize(event, hint=provider_hint)
            usable = normalized.account_id not in ('', 'unknown')
        except Exception:
            usable = False
        if not usable:
            raise HTTPException(422, f'Event {number} has no usable authentication account; check the format and provider hint.')
    return events
