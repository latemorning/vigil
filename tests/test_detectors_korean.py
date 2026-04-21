"""Tests for Korean PII detectors."""
import pytest
from vigil.detectors.korean import (
    RRNDetector,
    PhoneMobileDetector,
    PhoneLandlineDetector,
    BusinessNumberDetector,
    CIDetector,
    KoreanNameDetector,
)


# ---------------------------------------------------------------------------
# RRNDetector
# ---------------------------------------------------------------------------

class TestRRNDetector:
    def setup_method(self):
        self.det = RRNDetector()

    def test_valid_rrn_no_separator(self):
        matches = list(self.det.find("rrn=9001011234568"))
        assert len(matches) == 1
        assert "9001011234568" in matches[0].value

    def test_invalid_checksum(self):
        matches = list(self.det.find("rrn=9001011234561"))
        assert len(matches) == 0

    def test_valid_rrn_hyphen(self):
        matches = list(self.det.find("900101-1234568"))
        assert len(matches) == 1

    def test_valid_rrn_space(self):
        matches = list(self.det.find("900101 1234568"))
        assert len(matches) == 1

    def test_match_attributes(self):
        matches = list(self.det.find("900101-1234568", line_no=3))
        assert len(matches) == 1
        m = matches[0]
        assert m.detector == "rrn"
        assert m.confidence == "high"
        assert m.line_no == 3
        assert m.column == 0

    def test_no_match_for_random_digits(self):
        # 13 digits but invalid checksum
        matches = list(self.det.find("1234567890123"))
        assert len(matches) == 0

    def test_second_group_must_start_with_1_to_4(self):
        # Second group starts with 5 — outside [1-4], pattern won't match
        matches = list(self.det.find("900101-5234568"))
        assert len(matches) == 0

    def test_multiple_rrns_in_line(self):
        line = "a=900101-1234568 b=9001011234568"
        matches = list(self.det.find(line))
        assert len(matches) == 2


# ---------------------------------------------------------------------------
# PhoneMobileDetector
# ---------------------------------------------------------------------------

class TestPhoneMobileDetector:
    def setup_method(self):
        self.det = PhoneMobileDetector()

    def test_hyphen_separator(self):
        matches = list(self.det.find("phone=010-1234-5678"))
        assert len(matches) == 1
        assert matches[0].value == "010-1234-5678"

    def test_dot_separator(self):
        matches = list(self.det.find("010.1234.5678"))
        assert len(matches) == 1

    def test_space_separator(self):
        matches = list(self.det.find("0101234 5678"))
        assert len(matches) == 1

    def test_no_separator(self):
        matches = list(self.det.find("01012345678"))
        assert len(matches) == 1

    def test_011_prefix(self):
        matches = list(self.det.find("011-1234-5678"))
        assert len(matches) == 1

    def test_016_prefix(self):
        matches = list(self.det.find("016-1234-5678"))
        assert len(matches) == 1

    def test_019_prefix(self):
        matches = list(self.det.find("019-1234-5678"))
        assert len(matches) == 1

    def test_invalid_prefix_012(self):
        # 012 is not in [016789]
        matches = list(self.det.find("012-1234-5678"))
        assert len(matches) == 0

    def test_confidence_high(self):
        matches = list(self.det.find("010-1234-5678"))
        assert matches[0].confidence == "high"

    def test_detector_name(self):
        matches = list(self.det.find("010-1234-5678"))
        assert matches[0].detector == "phone_mobile"

    def test_column_position(self):
        matches = list(self.det.find("연락처: 010-1234-5678"))
        assert len(matches) == 1
        assert matches[0].column > 0


# ---------------------------------------------------------------------------
# PhoneLandlineDetector
# ---------------------------------------------------------------------------

class TestPhoneLandlineDetector:
    def setup_method(self):
        self.det = PhoneLandlineDetector()

    def test_seoul_02(self):
        matches = list(self.det.find("02-1234-5678"))
        assert len(matches) == 1

    def test_area_031(self):
        matches = list(self.det.find("031-123-4567"))
        assert len(matches) == 1

    def test_voip_070(self):
        matches = list(self.det.find("070-1234-5678"))
        assert len(matches) == 1

    def test_area_080(self):
        matches = list(self.det.find("080-1234-5678"))
        assert len(matches) == 1

    def test_dot_separator(self):
        matches = list(self.det.find("02.1234.5678"))
        assert len(matches) == 1

    def test_no_separator(self):
        matches = list(self.det.find("0212345678"))
        assert len(matches) == 1

    def test_confidence_high(self):
        matches = list(self.det.find("02-1234-5678"))
        assert matches[0].confidence == "high"

    def test_detector_name(self):
        matches = list(self.det.find("02-1234-5678"))
        assert matches[0].detector == "phone_landline"

    def test_invalid_area_code(self):
        # 090 is not a valid Korean area code
        matches = list(self.det.find("090-1234-5678"))
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# BusinessNumberDetector
# ---------------------------------------------------------------------------

class TestBusinessNumberDetector:
    def setup_method(self):
        self.det = BusinessNumberDetector()

    def test_valid_brn(self):
        matches = list(self.det.find("사업자: 123-45-67891"))
        assert len(matches) == 1
        assert matches[0].value == "123-45-67891"

    def test_invalid_checksum(self):
        matches = list(self.det.find("BRN=123-45-67890"))
        assert len(matches) == 0

    def test_too_short_last_group(self):
        # Last group only 3 digits (pattern requires 5)
        matches = list(self.det.find("123-45-678"))
        assert len(matches) == 0

    def test_confidence_high(self):
        matches = list(self.det.find("123-45-67891"))
        assert matches[0].confidence == "high"

    def test_detector_name(self):
        matches = list(self.det.find("123-45-67891"))
        assert matches[0].detector == "business_number"

    def test_no_match_plain_digits(self):
        # No dashes — pattern requires dashes
        matches = list(self.det.find("1234567891"))
        assert len(matches) == 0


# ---------------------------------------------------------------------------
# CIDetector
# ---------------------------------------------------------------------------

_CI_88 = "A" * 86 + "=="   # 88-char base64-like string
_CI_88_PLAIN = "B" * 88    # 88 plain base64 chars (no padding)


class TestCIDetector:
    def setup_method(self):
        self.det = CIDetector()

    def test_labeled_ci_equals(self):
        matches = list(self.det.find(f"CI={_CI_88}"))
        assert len(matches) == 1
        assert matches[0].confidence == "high"
        assert matches[0].value == _CI_88

    def test_labeled_ci_colon(self):
        matches = list(self.det.find(f"CI: {_CI_88}"))
        assert len(matches) == 1
        assert matches[0].confidence == "high"

    def test_labeled_ci_lowercase(self):
        matches = list(self.det.find(f"ci={_CI_88}"))
        assert len(matches) == 1
        assert matches[0].confidence == "high"

    def test_labeled_ci_json(self):
        matches = list(self.det.find(f'"ci": "{_CI_88}"'))
        assert len(matches) == 1
        assert matches[0].confidence == "high"

    def test_bare_ci_low_confidence(self):
        matches = list(self.det.find(_CI_88))
        assert len(matches) == 1
        assert matches[0].confidence == "low"

    def test_bare_ci_88_plain(self):
        matches = list(self.det.find(_CI_88_PLAIN))
        assert len(matches) == 1
        assert matches[0].confidence == "low"

    def test_no_duplicate_when_labeled(self):
        # labeled match should not produce an additional bare match
        matches = list(self.det.find(f"CI={_CI_88}"))
        assert len(matches) == 1

    def test_short_string_no_match(self):
        matches = list(self.det.find("CI=shortstring"))
        assert len(matches) == 0

    def test_confidence_high_for_labeled(self):
        matches = list(self.det.find(f"CI={_CI_88}"))
        assert matches[0].confidence == "high"

    def test_detector_name(self):
        matches = list(self.det.find(f"CI={_CI_88}"))
        assert matches[0].detector == "ci"


# ---------------------------------------------------------------------------
# KoreanNameDetector
# ---------------------------------------------------------------------------

class TestKoreanNameDetector:
    def setup_method(self):
        self.det = KoreanNameDetector()

    def test_context_keyword_이름(self):
        matches = list(self.det.find("이름=홍길동"))
        assert len(matches) >= 1
        high = [m for m in matches if m.confidence == "high"]
        assert len(high) == 1
        assert high[0].value == "홍길동"

    def test_context_keyword_name(self):
        matches = list(self.det.find("name=홍길동"))
        high = [m for m in matches if m.confidence == "high"]
        assert len(high) == 1
        assert high[0].value == "홍길동"

    def test_context_keyword_성명(self):
        matches = list(self.det.find("성명: 김영희"))
        high = [m for m in matches if m.confidence == "high"]
        assert len(high) == 1
        assert high[0].value == "김영희"

    def test_context_keyword_full_name(self):
        matches = list(self.det.find("full_name=이순신"))
        high = [m for m in matches if m.confidence == "high"]
        assert len(high) == 1

    def test_surname_heuristic_low_confidence(self):
        matches = list(self.det.find("담당자 박수진 연락처"))
        low = [m for m in matches if m.confidence == "low"]
        values = [m.value for m in low]
        assert "박수진" in values

    def test_stop_word_filtered(self):
        # 김치 is in stop list
        matches = list(self.det.find("김치 맛있다"))
        # 김치 should be filtered; 맛있다 doesn't start with a surname char
        values = [m.value for m in matches]
        assert "김치" not in values

    def test_no_duplicate_from_context_and_surname(self):
        # 홍길동 matched by context; strategy B should NOT duplicate it
        matches = list(self.det.find("이름=홍길동"))
        assert len(matches) == 1

    def test_detector_name(self):
        matches = list(self.det.find("이름=홍길동"))
        assert matches[0].detector == "name_korean"

    def test_no_match_for_non_surname_start(self):
        # 맛있는 doesn't start with a surname
        matches = list(self.det.find("맛있는 음식"))
        assert len(matches) == 0

    def test_line_no_passed_through(self):
        matches = list(self.det.find("이름=홍길동", line_no=7))
        assert matches[0].line_no == 7

    def test_column_accuracy(self):
        line = "사용자 이름=김철수 입니다"
        matches = list(self.det.find(line))
        high = [m for m in matches if m.confidence == "high"]
        assert len(high) == 1
        # value starts at the Korean name, not at "이름"
        assert line[high[0].column:high[0].column + len(high[0].value)] == high[0].value
