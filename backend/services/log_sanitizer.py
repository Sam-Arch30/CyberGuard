import os
import re
import logging
from typing import Any

# Sensitive regex patterns to redact in server logs
SENSITIVE_PATTERNS = [
    (re.compile(r'Authorization\s*:\s*Bearer\s+[^\r\n\s]+', re.IGNORECASE), 'Authorization: Bearer [REDACTED]'),
    (re.compile(r'Authorization\s*:\s*[^\r\n]+', re.IGNORECASE), 'Authorization: [REDACTED]'),
    (re.compile(r'Bearer\s+[a-zA-Z0-9_\-\.]{8,}', re.IGNORECASE), 'Bearer [REDACTED]'),
    (re.compile(r'(?:api_key|apikey|x-api-key|key)\s*[:=]\s*["\']?[a-zA-Z0-9_\-]{8,}["\']?', re.IGNORECASE), 'api_key=[REDACTED]'),
    (re.compile(r'(?:password|secret|token|passwd|pwd)\s*[:=]\s*["\']?[^"\'\s,]+["\']?', re.IGNORECASE), 'password=[REDACTED]'),
    (re.compile(r'[?&](?:key|api_key|token|password)=[^&\s]+', re.IGNORECASE), '?key=[REDACTED]'),
    (re.compile(r'(?:postgres(?:ql)?|sqlite|mysql|mongodb|redis):\/\/[^:\s\/]+:[^@\s]+@', re.IGNORECASE), 'postgresql://[REDACTED_USER]:[REDACTED_PASSWORD]@'),
]


def sanitize_log_text(text: str) -> str:
    """Sanitizes text string by redacting authorization tokens, API keys, passwords, and DB credentials."""
    if not isinstance(text, str):
        return str(text)

    clean = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        clean = pattern.sub(replacement, clean)
    return clean


class SensitiveLogFilter(logging.Filter):
    """
    Python logging filter that intercepts log records and redacts credentials,
    API keys, authorization headers, and raw secrets from log output.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_log_text(record.msg)

        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: (sanitize_log_text(v) if isinstance(v, str) else v) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_log_text(a) if isinstance(a, str) else a for a in record.args)
            elif isinstance(record.args, list):
                record.args = [sanitize_log_text(a) if isinstance(a, str) else a for a in record.args]

        return True


def install_log_sanitizer():
    """Attaches SensitiveLogFilter to the root logging handler."""
    root_logger = logging.getLogger()
    log_filter = SensitiveLogFilter()
    root_logger.addFilter(log_filter)
    for handler in root_logger.handlers:
        handler.addFilter(log_filter)


def configure_production_logging():
    """
    Configures production-safe logging with structured format, configurable
    LOG_LEVEL (default INFO), and automatic credential/key sanitization.
    """
    log_level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    numeric_level = getattr(logging, log_level_str, logging.INFO)

    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(
            level=numeric_level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
    else:
        root.setLevel(numeric_level)

    install_log_sanitizer()
