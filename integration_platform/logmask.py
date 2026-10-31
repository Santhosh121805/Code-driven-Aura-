"""Mask token-like strings in log lines and stored error messages."""
from __future__ import annotations

import logging
import re

_KNOWN: set[str] = set()  # actual secret values resolved at runtime (always masked, whatever their shape)
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\b(bearer|basic|ssws)\s+[A-Za-z0-9._~+/=-]{6,}"), r"\1 ****"),
    (re.compile(r'(?i)("?(?:access_token|refresh_token|id_token|client_secret|password|passwd|api[_-]?key|x-api-key|token|secret)"?\s*[:=]\s*"?)'
                r'([^"&\s,}]+)'), r"\1****"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "****(jwt)"),
    (re.compile(r"\bgAAAAA[A-Za-z0-9_=-]{20,}"), "****(fernet)"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "****(aws-key)"),
]


def remember(value: str) -> None:
    """Register a resolved secret value so it is masked wherever it appears."""
    if value and len(value) >= 6:
        _KNOWN.add(value)


def mask_text(text: str) -> str:
    for value in sorted(_KNOWN, key=len, reverse=True):
        text = text.replace(value, "****")
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text


class MaskingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()
        masked = mask_text(message)
        if masked != message:
            record.msg, record.args = masked, None
        if record.exc_info and not record.exc_text:
            record.exc_text = mask_text(logging.Formatter().formatException(record.exc_info))
        return True


# HTTP libraries log full request URLs (a Slack webhook URL is itself a secret): mask at the logger, whatever the handlers.
for _name in ("httpx", "httpcore"):
    logging.getLogger(_name).addFilter(MaskingFilter())


def install() -> None:
    """Attach the filter to every handler of the root and server loggers (handler filters see propagated records)."""
    masking = MaskingFilter()
    for name in ("", "uvicorn", "uvicorn.error", "uvicorn.access"):
        for handler in logging.getLogger(name).handlers:
            if not any(isinstance(f, MaskingFilter) for f in handler.filters):
                handler.addFilter(masking)
