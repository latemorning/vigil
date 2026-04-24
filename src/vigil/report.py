"""Terminal summary and JSON report writer for PII scan results."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from vigil.scanner import ScanResult

__all__ = ["print_summary", "write_json_report"]


def _fmt_bytes(n: int) -> str:
    """Format byte count as human-readable string."""
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MB"
    else:
        return f"{n / 1024 ** 3:.1f} GB"


def print_summary(result: ScanResult, output_path: str | None = None) -> None:
    """Print a formatted summary of scan results to stdout using rich."""
    from rich.console import Console
    from rich.table import Table

    console = Console()

    size_str = _fmt_bytes(result.bytes_scanned)
    console.print(f"Scanned {result.files_scanned} files ({size_str})")

    # Count high/low totals
    high_total = sum(1 for m in result.matches if m.confidence == "high")
    low_total = sum(1 for m in result.matches if m.confidence == "low")
    console.print(f"Found {result.total_matches} matches (high: {high_total}, low: {low_total}):")

    # Per-detector breakdown
    detector_table = Table(show_header=True, header_style="bold")
    detector_table.add_column("Detector")
    detector_table.add_column("Matches")
    detector_table.add_column("Confidence")

    # Gather per-detector stats
    detector_stats: dict[str, dict] = {}
    for m in result.matches:
        if m.detector not in detector_stats:
            detector_stats[m.detector] = {"count": 0, "high": 0, "low": 0}
        detector_stats[m.detector]["count"] += 1
        detector_stats[m.detector][m.confidence] += 1

    for det_name, stats in detector_stats.items():
        count = stats["count"]
        h = stats["high"]
        l = stats["low"]
        if l == 0:
            conf_str = "high"
        elif h == 0:
            conf_str = "low"
        else:
            conf_str = f"high: {h}, low: {l}"
        detector_table.add_row(det_name, str(count), conf_str)

    console.print(detector_table)

    # Top 5 files by match count
    file_counts: dict[str, int] = {}
    for m in result.matches:
        file_counts[m.file_path] = file_counts.get(m.file_path, 0) + 1

    top_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    if top_files:
        console.print("\nTop 5 files by matches:")
        file_table = Table(show_header=True, header_style="bold")
        file_table.add_column("File")
        file_table.add_column("Matches")
        for fp, cnt in top_files:
            file_table.add_row(fp, str(cnt))
        console.print(file_table)

    # Top 5 source modules by match count
    top_modules = sorted(result.by_source_module.items(), key=lambda x: x[1], reverse=True)[:5]

    if top_modules:
        console.print("\nTop 5 source modules:")
        module_table = Table(show_header=True, header_style="bold")
        module_table.add_column("Source module")
        module_table.add_column("Matches")
        for mod, cnt in top_modules:
            module_table.add_row(mod, str(cnt))
        console.print(module_table)

    if output_path is not None:
        console.print(f"\nDetails written to {output_path}")


def write_json_report(result: ScanResult, output_path: str | Path) -> None:
    """Write a JSON report of scan results to the specified path."""
    output_path = Path(output_path)

    matches_list = [
        {
            "file": m.file_path,
            "line": m.line_no,
            "column": m.column,
            "detector": m.detector,
            "value": m.value,
            "confidence": m.confidence,
            "source_module": m.source_module,
        }
        for m in result.matches
    ]

    report = {
        "scanned_at": datetime.now(timezone.utc).astimezone().isoformat(),
        "root": result.root,
        "files_scanned": result.files_scanned,
        "bytes_scanned": result.bytes_scanned,
        "total_matches": result.total_matches,
        "by_detector": result.by_detector,
        "matches": matches_list,
    }

    output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
