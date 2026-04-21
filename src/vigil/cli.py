"""vigil CLI — scan log files for PII."""
from __future__ import annotations
import sys
import argparse
from pathlib import Path
from vigil.detectors import BUILTIN_DETECTORS
from vigil.scanner import scan_path, DEFAULT_EXTENSIONS
from vigil.report import print_summary, write_json_report

__all__ = ["main"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description="Scan log files for personally identifiable information (PII).",
    )
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Scan a file or directory for PII")
    scan.add_argument("path", type=Path, help="File or directory to scan")
    scan.add_argument(
        "--output", "-o",
        default="vigil-report.json",
        metavar="FILE",
        help="Output JSON report path (default: vigil-report.json)",
    )
    scan.add_argument(
        "--ext",
        default=None,
        metavar="EXTS",
        help="Comma-separated extensions to scan, e.g. '.log,.txt' (default: .log .txt and no-ext)",
    )
    scan.add_argument(
        "--detector",
        default=None,
        metavar="NAMES",
        help="Comma-separated detector names to activate (default: all)",
    )
    scan.add_argument(
        "--min-confidence",
        choices=["high", "low"],
        default="low",
        dest="min_confidence",
        help="Minimum confidence level to report (default: low)",
    )
    scan.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress terminal summary output",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    # command == "scan"
    path = args.path.resolve()
    if not path.exists():
        print(f"Error: path does not exist: {path}", file=sys.stderr)
        sys.exit(2)

    # Build detector list
    detectors = BUILTIN_DETECTORS
    if args.detector:
        wanted = {name.strip() for name in args.detector.split(",")}
        detectors = [d for d in detectors if d.name in wanted]
        if not detectors:
            print(f"Error: no detectors matched: {args.detector}", file=sys.stderr)
            sys.exit(2)

    # Build extension set
    extensions = None
    if args.ext:
        extensions = frozenset(e.strip() for e in args.ext.split(","))

    result = scan_path(path, detectors, extensions=extensions, min_confidence=args.min_confidence)

    write_json_report(result, args.output)

    if not args.quiet:
        print_summary(result, output_path=args.output)

    sys.exit(1 if result.total_matches > 0 else 0)
