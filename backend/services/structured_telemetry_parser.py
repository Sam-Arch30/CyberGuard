"""Explicit JSON, JSONL and CSV event parsing; malformed formats never fall through."""
import csv
import io
import json

MAX_EVENTS = 10000

def validate_events(events):
    if not isinstance(events, list) or not events:
        raise ValueError('Provide a nonempty batch of structured events.')
    if len(events) > MAX_EVENTS:
        raise ValueError(f'At most {MAX_EVENTS} events can be processed per batch.')
    for number, event in enumerate(events, 1):
        if not isinstance(event, dict) or not event:
            raise ValueError(f'Event {number}: provide a nonempty event object.')
    return events

def parse_structured_telemetry(data, filename='', mime=''):
    try:
        text = data.decode('utf-8-sig')
    except UnicodeError as exc:
        raise ValueError('Telemetry must use UTF-8 text encoding.') from exc
    name = filename.lower()
    if name.endswith(('.jsonl', '.ndjson')) or 'ndjson' in mime:
        events = []
        for number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            try:
                events.append(json.loads(line))
            except (ValueError, RecursionError) as exc:
                raise ValueError(f'JSONL line {number}: malformed structured event.') from exc
        return validate_events(events)
    if name.endswith('.csv') or 'csv' in mime:
        reader = csv.DictReader(io.StringIO(text))
        events = []
        for number, row in enumerate(reader, 2):
            if None in row:
                raise ValueError(f'CSV line {number}: columns do not match the header.')
            events.append(row)
            if len(events) > MAX_EVENTS:
                raise ValueError(f'At most {MAX_EVENTS} events can be processed per batch.')
        return validate_events(events)
    if name.endswith('.json') or 'json' in mime or text.lstrip().startswith(('[', '{')):
        try:
            parsed = json.loads(text)
        except (ValueError, RecursionError) as exc:
            raise ValueError('Malformed JSON telemetry. Use a JSON array, event object, or declare JSONL for line-delimited events.') from exc
        events = parsed if isinstance(parsed, list) else parsed.get('events', [parsed]) if isinstance(parsed, dict) else None
        return validate_events(events)
    raise ValueError('Unsupported telemetry format. Use JSON, JSONL/NDJSON, or CSV.')
