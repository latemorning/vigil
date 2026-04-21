"""International PII detectors."""
from __future__ import annotations
import re
from typing import Iterator
from vigil.detectors.base import Match
from vigil.validators import luhn

__all__ = ["EmailDetector", "CreditCardDetector", "IPv4Detector"]


class EmailDetector:
    """Email address detector."""

    name = "email"
    _PATTERN = re.compile(r'[\w.+-]+@[\w-]+\.[\w.-]+')

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        for m in self._PATTERN.finditer(line):
            yield Match(
                detector=self.name,
                value=m.group(0),
                line_no=line_no,
                column=m.start(),
                confidence="high",
            )


class CreditCardDetector:
    """Credit card number detector."""

    name = "credit_card"
    # Matches 13-19 digit sequences with optional spaces or dashes between groups
    _PATTERN = re.compile(r'\b(?:\d[ -]?){12,18}\d\b')

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        for m in self._PATTERN.finditer(line):
            raw = m.group(0)
            digits = re.sub(r'[ -]', '', raw)
            if not luhn(digits):
                continue
            yield Match(
                detector=self.name,
                value=raw,
                line_no=line_no,
                column=m.start(),
                confidence="high",
            )


class IPv4Detector:
    """IPv4 address detector."""

    name = "ipv4"
    _PATTERN = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b'
    )

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        for m in self._PATTERN.finditer(line):
            yield Match(
                detector=self.name,
                value=m.group(0),
                line_no=line_no,
                column=m.start(),
                confidence="high",
            )
