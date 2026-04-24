import pytest
from pathlib import Path
from vigil.scanner import scan_file, scan_path, ScanResult, DEFAULT_EXTENSIONS
from vigil.detectors.korean import RRNDetector, PhoneMobileDetector, BusinessNumberDetector, KoreanNameDetector
from vigil.detectors.international import EmailDetector, CreditCardDetector, IPv4Detector

FIXTURES = Path(__file__).parent / "fixtures" / "logs"


def all_detectors():
    return [
        RRNDetector(),
        PhoneMobileDetector(),
        BusinessNumberDetector(),
        KoreanNameDetector(),
        EmailDetector(),
        CreditCardDetector(),
        IPv4Detector(),
    ]


# 1. scan_file with clean.log — no PII when IPv4 excluded
def test_scan_file_clean_no_pii():
    detectors = [RRNDetector(), PhoneMobileDetector(), BusinessNumberDetector(),
                 KoreanNameDetector(), EmailDetector(), CreditCardDetector()]
    matches = scan_file(FIXTURES / "clean.log", detectors)
    assert matches == []


# 2. scan_file with mixed.log using all detectors
def test_scan_file_mixed_finds_expected_types():
    detectors = all_detectors()
    matches = scan_file(FIXTURES / "mixed.log", detectors)
    detectors_found = {m.detector for m in matches}
    assert "email" in detectors_found
    assert "rrn" in detectors_found
    assert "credit_card" in detectors_found


# 3. scan_path recursive scan on fixtures/logs/
def test_scan_path_recursive():
    result = scan_path(FIXTURES, all_detectors())
    # clean.log, mixed.log, nested/app.log all have .log extension;
    # .gitkeep has empty suffix "" which is also in DEFAULT_EXTENSIONS
    assert result.files_scanned >= 3
    # Should find matches in mixed.log and nested/app.log
    assert result.total_matches > 0


# 4. scan_path on single file
def test_scan_path_single_file():
    result = scan_path(FIXTURES / "mixed.log", all_detectors())
    assert result.files_scanned == 1


# 5. Extension filter — no .txt files in fixtures dir
def test_scan_path_extension_filter():
    result = scan_path(FIXTURES, all_detectors(), extensions=frozenset({".txt"}))
    assert result.files_scanned == 0


# 6. min_confidence="high" filters out low-confidence name_korean matches
# mixed.log line 5 "담당자 박수진 연락처" produces a low-confidence name match (surname heuristic)
# mixed.log line 3 "이름=홍길동" produces a high-confidence context match
def test_scan_file_min_confidence_high():
    detectors = [KoreanNameDetector()]
    matches_low = scan_file(FIXTURES / "mixed.log", detectors, min_confidence="low")
    matches_high = scan_file(FIXTURES / "mixed.log", detectors, min_confidence="high")
    # High mode must keep high-confidence matches
    assert any(m.confidence == "high" for m in matches_high)
    # High mode must have no low-confidence matches
    assert all(m.confidence == "high" for m in matches_high)
    # Low mode must produce more matches (박수진 is low-confidence via surname heuristic)
    low_conf_in_low_mode = [m for m in matches_low if m.confidence == "low"]
    assert len(low_conf_in_low_mode) >= 1, "mixed.log should produce at least one low-confidence name match"
    assert len(matches_high) < len(matches_low)


# 7. ScanResult.by_detector returns correct counts
def test_scan_result_by_detector():
    result = scan_path(FIXTURES / "mixed.log", all_detectors())
    bd = result.by_detector
    assert bd.get("email", 0) == 1
    assert bd.get("rrn", 0) == 1
    assert bd.get("credit_card", 0) == 1
    # All counts are positive integers
    for detector_name, count in bd.items():
        assert count > 0


# 8. ScanResult.total_matches == len(matches)
def test_scan_result_total_matches():
    result = scan_path(FIXTURES / "mixed.log", all_detectors())
    assert result.total_matches == len(result.matches)


# 9. source_module attached from log prefix
def test_scan_file_attaches_source_module():
    detectors = [EmailDetector(), RRNDetector(), CreditCardDetector(), KoreanNameDetector()]
    matches = scan_file(FIXTURES / "with_logger_names.log", detectors)
    by_line: dict[int, list] = {}
    for m in matches:
        by_line.setdefault(m.line_no, []).append(m)
    # Line 1: format 1 — vigil.auth.login
    for m in by_line.get(1, []):
        assert m.source_module == "vigil.auth.login", f"line 1 mismatch: {m.source_module}"
    # Line 2: format 3 — vigil.payment.processor
    for m in by_line.get(2, []):
        assert m.source_module == "vigil.payment.processor", f"line 2 mismatch: {m.source_module}"
    # Line 3: format 4 — app.user
    for m in by_line.get(3, []):
        assert m.source_module == "app.user", f"line 3 mismatch: {m.source_module}"


# 10. source_module is None for plain log lines without a logger prefix
def test_scan_file_none_when_no_logger():
    detectors = [EmailDetector()]
    matches = scan_file(FIXTURES / "mixed.log", detectors)
    assert all(m.source_module is None for m in matches)


# 11. by_source_module property aggregates correctly
def test_scan_result_by_source_module():
    detectors = [EmailDetector(), RRNDetector(), CreditCardDetector(), KoreanNameDetector()]
    result = scan_path(FIXTURES / "with_logger_names.log", detectors)
    bsm = result.by_source_module
    assert "vigil.auth.login" in bsm
    assert "vigil.payment.processor" in bsm
    assert "app.user" in bsm
    # Line 4 has no logger prefix — maps to <unknown>
    assert "<unknown>" in bsm
