"""Log file scanner — discovers and scans files for PII matches."""
from __future__ import annotations
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence
from vigil.detectors.base import FileMatch, Detector

__all__ = ["ScanResult", "scan_file", "scan_path"]

DEFAULT_EXTENSIONS = frozenset({".log", ".txt", ""})


@dataclass
class ScanResult:
    root: str
    files_scanned: int
    bytes_scanned: int
    matches: list[FileMatch]

    @property
    def total_matches(self) -> int:
        return len(self.matches)

    @property
    def by_detector(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for m in self.matches:
            counts[m.detector] = counts.get(m.detector, 0) + 1
        return counts


def scan_file(path: Path, detectors: Sequence[Detector], min_confidence: str = "low") -> list[FileMatch]:
    matches: list[FileMatch] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.rstrip("\n")
            for detector in detectors:
                for match in detector.find(line, line_no=line_no):
                    if min_confidence == "high" and match.confidence == "low":
                        continue
                    matches.append(FileMatch(
                        file_path=str(path),
                        detector=match.detector,
                        value=match.value,
                        line_no=match.line_no,
                        column=match.column,
                        confidence=match.confidence,
                    ))
    return matches


def scan_path(root: Path, detectors: Sequence[Detector], extensions: frozenset[str] | None = None, min_confidence: str = "low") -> ScanResult:
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS

    all_matches: list[FileMatch] = []
    bytes_scanned = 0
    files_scanned = 0

    if root.is_file():
        candidates = [root]
    else:
        candidates = [p for p in root.rglob("*") if p.is_file()]

    for path in candidates:
        if path.suffix not in extensions:
            continue
        bytes_scanned += path.stat().st_size
        files_scanned += 1
        all_matches.extend(scan_file(path, detectors, min_confidence=min_confidence))

    return ScanResult(
        root=str(root),
        files_scanned=files_scanned,
        bytes_scanned=bytes_scanned,
        matches=all_matches,
    )
