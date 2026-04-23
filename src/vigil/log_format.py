"""Parse common Python logging format prefixes to extract the logger name."""
from __future__ import annotations
import re

__all__ = ["parse_logger_name"]

_LEVEL = r"(?:DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL)"
_NAME = r"([A-Za-z_][\w.\-]*)"

_PATTERNS: list[re.Pattern[str]] = [
    # Format 1: 2026-04-21 12:00:00,123 INFO vigil.auth.login - message
    re.compile(
        r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)? " + _LEVEL + r" " + _NAME + r" - ",
        re.IGNORECASE,
    ),
    # Format 2: 2026-04-21 12:00:00 INFO vigil.auth.login: message
    re.compile(
        r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:,\d+)? " + _LEVEL + r" " + _NAME + r":",
        re.IGNORECASE,
    ),
    # Format 3: INFO:vigil.auth.login:message  (basicConfig default)
    re.compile(
        r"^" + _LEVEL + r":" + _NAME + r":",
        re.IGNORECASE,
    ),
    # Format 4: [2026-04-21 12:00:00] [INFO] [vigil.auth.login] message
    re.compile(
        r"^\[\d{4}-\d{2}-\d{2}[^\]]*\] \[" + _LEVEL + r"\] \[" + _NAME + r"\]",
        re.IGNORECASE,
    ),
]


def parse_logger_name(line: str) -> str | None:
    """Return the logger name from a log line prefix, or None if not detected."""
    for pattern in _PATTERNS:
        m = pattern.match(line)
        if m:
            return m.group(1)
    return None
