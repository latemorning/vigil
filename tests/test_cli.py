import json
import subprocess
import sys
from pathlib import Path
import pytest
from vigil.cli import build_parser


def run_vigil(*args, cwd="/Users/harry/projects/vigil"):
    return subprocess.run(
        [sys.executable, "-m", "vigil"] + list(args),
        capture_output=True, text=True, cwd=cwd
    )


def test_build_parser_scan_defaults():
    parser = build_parser()
    args = parser.parse_args(["scan", "/tmp"])
    assert args.output == "vigil-report.json"
    assert args.min_confidence == "low"
    assert args.quiet is False
    assert args.ext is None
    assert args.detector is None


def test_main_no_args_exits_0():
    result = run_vigil()
    assert result.returncode == 0


def test_main_scan_clean_log_exits_0():
    result = run_vigil(
        "scan", "tests/fixtures/logs/clean.log",
        "--detector", "email,rrn",
        "--quiet",
        "--output", "/tmp/vigil-test-clean.json",
    )
    assert result.returncode == 0


def test_main_scan_mixed_log_exits_1():
    result = run_vigil(
        "scan", "tests/fixtures/logs/mixed.log",
        "--quiet",
        "--output", "/tmp/vigil-test-mixed.json",
    )
    assert result.returncode == 1


def test_main_scan_creates_report():
    output = "/tmp/vigil-test-creates-report.json"
    result = run_vigil(
        "scan", "tests/fixtures/logs/mixed.log",
        "--quiet",
        "--output", output,
    )
    report_path = Path(output)
    assert report_path.exists()
    data = json.loads(report_path.read_text())
    assert data["total_matches"] > 0


def test_main_scan_nonexistent_path_exits_2():
    result = run_vigil(
        "scan", "/nonexistent/path",
        "--quiet",
        "--output", "/tmp/test.json",
    )
    assert result.returncode == 2


def test_main_scan_min_confidence_high():
    output = "/tmp/vigil-test-high.json"
    result = run_vigil(
        "scan", "tests/fixtures/logs/mixed.log",
        "--min-confidence", "high",
        "--quiet",
        "--output", output,
    )
    data = json.loads(Path(output).read_text())
    for match in data["matches"]:
        assert match["confidence"] != "low"


def test_main_scan_detector_filter():
    output = "/tmp/vigil-test-email.json"
    result = run_vigil(
        "scan", "tests/fixtures/logs/mixed.log",
        "--detector", "email",
        "--quiet",
        "--output", output,
    )
    data = json.loads(Path(output).read_text())
    for match in data["matches"]:
        assert match["detector"] == "email"
