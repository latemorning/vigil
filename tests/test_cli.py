import json
import subprocess
import sys
from pathlib import Path
import pytest
from vigil.cli import build_parser, _load_stopwords_file


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


def test_main_scan_uses_default_company_terms_file(tmp_path):
    log = tmp_path / "default-company-terms.log"
    output = tmp_path / "default-company-terms-report.json"
    log.write_text("고객이나 혜택 안내\nname=현대카드\n박수진 담당자 연락처\n", encoding="utf-8")
    result = run_vigil(
        "scan", str(log),
        "--detector", "name_korean",
        "--quiet",
        "--output", str(output),
    )
    assert result.returncode == 1
    data = json.loads(output.read_text())
    matched_values = [m["value"] for m in data["matches"]]
    assert "고객이나" not in matched_values
    assert "현대카드" not in matched_values
    assert "박수진" in matched_values


def test_main_scan_name_stopwords_filters():
    output = "/tmp/vigil-test-stopwords.json"
    result = run_vigil(
        "scan", "tests/fixtures/logs/name_stopwords_test.log",
        "--name-stopwords", "tests/fixtures/name_stopwords/company_terms.txt",
        "--quiet",
        "--output", output,
    )
    data = json.loads(Path(output).read_text())
    matched_values = [m["value"] for m in data["matches"]]
    assert "박하시럽" not in matched_values
    assert "이모티콘" not in matched_values
    assert "박수진" in matched_values


def test_main_scan_name_stopwords_missing_file_exits_2():
    result = run_vigil(
        "scan", "tests/fixtures/logs/mixed.log",
        "--name-stopwords", "/tmp/nonexistent-stopwords.txt",
        "--quiet",
        "--output", "/tmp/vigil-test-sw-missing.json",
    )
    assert result.returncode == 2
    assert "does not exist" in result.stderr


def test_main_scan_traces_source_module():
    output = "/tmp/vigil-test-source-tracing.json"
    result = run_vigil(
        "scan", "tests/fixtures/logs/with_logger_names.log",
        "--quiet",
        "--output", output,
    )
    data = json.loads(Path(output).read_text())
    # All matches must have the source_module key (D2)
    for match in data["matches"]:
        assert "source_module" in match
    # Matches from line 1 should carry vigil.auth.login
    line1 = [m for m in data["matches"] if m["line"] == 1]
    assert all(m["source_module"] == "vigil.auth.login" for m in line1)
    # Matches from line 4 (plain line) should have source_module=null
    line4 = [m for m in data["matches"] if m["line"] == 4]
    assert all(m["source_module"] is None for m in line4)


def test_load_stopwords_file_ignores_comments_and_blank_lines(tmp_path):
    f = tmp_path / "words.txt"
    f.write_text("# 주석\n박하시럽\n\n이모티콘\n# 또 주석\n강남점\n", encoding="utf-8")
    result = _load_stopwords_file(f)
    assert result == frozenset({"박하시럽", "이모티콘", "강남점"})
    assert "# 주석" not in result
