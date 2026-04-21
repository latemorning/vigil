import json
import pytest
from pathlib import Path
from vigil.scanner import ScanResult
from vigil.detectors.base import FileMatch
from vigil.report import print_summary, write_json_report


def _make_result(matches=None):
    """Helper to build a ScanResult with given matches (or defaults)."""
    if matches is None:
        matches = [
            FileMatch(
                file_path="logs/app.log",
                detector="email",
                value="user@example.com",
                line_no=10,
                column=5,
                confidence="high",
            ),
            FileMatch(
                file_path="logs/app.log",
                detector="rrn",
                value="900101-1234568",
                line_no=20,
                column=3,
                confidence="high",
            ),
        ]
    return ScanResult(
        root="./logs",
        files_scanned=3,
        bytes_scanned=4096,
        matches=matches,
    )


def test_write_json_report_schema(tmp_path):
    result = _make_result()
    output = tmp_path / "report.json"
    write_json_report(result, output)

    data = json.loads(output.read_text(encoding="utf-8"))

    assert "scanned_at" in data
    assert "root" in data
    assert "files_scanned" in data
    assert "bytes_scanned" in data
    assert "total_matches" in data
    assert "by_detector" in data
    assert "matches" in data

    assert isinstance(data["scanned_at"], str)
    assert isinstance(data["root"], str)
    assert isinstance(data["files_scanned"], int)
    assert isinstance(data["bytes_scanned"], int)
    assert isinstance(data["total_matches"], int)
    assert isinstance(data["by_detector"], dict)
    assert isinstance(data["matches"], list)


def test_write_json_report_match_fields(tmp_path):
    result = _make_result()
    output = tmp_path / "report.json"
    write_json_report(result, output)

    data = json.loads(output.read_text(encoding="utf-8"))
    required_fields = {"file", "line", "column", "detector", "value", "confidence"}

    for match in data["matches"]:
        assert required_fields <= set(match.keys()), (
            f"Match missing fields: {required_fields - set(match.keys())}"
        )


def test_write_json_report_counts(tmp_path):
    result = _make_result()
    output = tmp_path / "report.json"
    write_json_report(result, output)

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["total_matches"] == len(data["matches"])

    # Verify by_detector counts match actual matches
    expected_counts: dict[str, int] = {}
    for m in data["matches"]:
        expected_counts[m["detector"]] = expected_counts.get(m["detector"], 0) + 1

    assert data["by_detector"] == expected_counts


def test_write_json_report_empty(tmp_path):
    result = ScanResult(
        root="./empty",
        files_scanned=0,
        bytes_scanned=0,
        matches=[],
    )
    output = tmp_path / "report.json"
    write_json_report(result, output)

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["total_matches"] == 0
    assert data["matches"] == []


def test_print_summary_runs_without_error(capsys):
    result = _make_result()
    # Should not raise
    print_summary(result)
    # Also test with output_path
    print_summary(result, output_path="/tmp/report.json")


def test_builtin_detectors_registry():
    from vigil.detectors import BUILTIN_DETECTORS

    assert len(BUILTIN_DETECTORS) == 9

    for detector in BUILTIN_DETECTORS:
        assert hasattr(detector, "name"), f"{detector} has no 'name' attribute"
        assert hasattr(detector, "find"), f"{detector} has no 'find' method"
        assert callable(detector.find), f"{detector}.find is not callable"
