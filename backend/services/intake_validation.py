"""Lightweight intake validation; accepting original evidence is not decoding it."""
import json
from pathlib import Path


def intake_limitations(data, filename, reported_mime):
    from backend.services.multimedia_service import MediaFormatIdentifier
    media_type, fmt, mime = MediaFormatIdentifier.identify(data)
    suffix = Path(filename).suffix.lower()
    warnings = []
    expected = {'.jpg': 'JPEG', '.jpeg': 'JPEG', '.png': 'PNG', '.gif': 'GIF', '.webp': 'WEBP', '.bmp': 'BMP',
                '.wav': 'WAV', '.mp3': 'MP3', '.ogg': 'OGG', '.flac': 'FLAC', '.mp4': 'MP4', '.mov': 'MOV', '.avi': 'AVI', '.webm': 'WEBM'}
    if suffix in expected or media_type.value != 'UNKNOWN_MEDIA':
        warnings.append('Original media retained; decoding and authenticity analysis have not run. Use focused media analysis.')
        if suffix in expected and expected[suffix] != fmt.value:
            warnings.append('Content signature does not match the declared extension; format is unverified.')
        if reported_mime and reported_mime != 'application/octet-stream' and mime != reported_mime:
            warnings.append('Reported MIME type differs from the detected content signature.')
    if suffix == '.pdf':
        if not data.startswith(b'%PDF-') or b'%%EOF' not in data[-2048:]:
            warnings.append('Invalid or truncated PDF structure, or extension/content mismatch. Original bytes retained; PDF decoding not verified.')
        else:
            warnings.append('PDF signature present; full document decoding has not been verified at intake.')
    if suffix in ('.json', '.jsonl', '.ndjson'):
        try:
            text = data.decode('utf-8-sig')
            if suffix == '.json':
                json.loads(text)
            else:
                lines = [(number, line) for number, line in enumerate(text.splitlines(), 1) if line.strip()]
                if not lines:
                    raise ValueError('No events')
                for number, line in lines:
                    try:
                        json.loads(line)
                    except json.JSONDecodeError:
                        warnings.append(f'Invalid JSONL at line {number}; retained as original evidence, not parsed events.')
                        break
        except (UnicodeDecodeError, ValueError):
            warnings.append('Invalid structured log content; retained as original evidence, not parsed events.')
    return warnings
