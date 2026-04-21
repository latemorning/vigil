from __future__ import annotations
from dataclasses import dataclass
from typing import Literal, Protocol, Iterator

Confidence = Literal["high", "low"]


@dataclass(frozen=True)
class Match:
    """A match found by a detector within a single line."""
    detector: str       # e.g. "rrn", "email", "name_korean"
    value: str          # original matched text
    line_no: int        # 1-indexed line number
    column: int         # 0-indexed start column
    confidence: Confidence = "high"


@dataclass(frozen=True)
class FileMatch:
    """A match with associated file path."""
    file_path: str
    detector: str
    value: str
    line_no: int
    column: int
    confidence: Confidence = "high"


class Detector(Protocol):
    """Protocol for PII detectors."""
    name: str
    def find(self, line: str) -> Iterator[Match]:
        """Find all matches in a single line."""
        ...
