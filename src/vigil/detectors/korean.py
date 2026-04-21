"""Korean PII detectors."""
from __future__ import annotations
import re
from typing import Iterator
from vigil.detectors.base import Match, Confidence, Detector
from vigil.validators import validate_rrn, validate_brn


_KOREAN_SURNAMES = frozenset([
    "김", "이", "박", "최", "정", "강", "조", "윤", "장", "임", "한", "오", "서", "신", "권",
    "황", "안", "송", "전", "홍", "유", "고", "문", "양", "손", "배", "백", "허", "남", "심",
    "노", "하", "곽", "성", "차", "주", "우", "구", "민", "류", "나", "진", "엄", "채", "원",
    "천", "방", "공", "현", "함", "변", "염", "여", "추", "도", "석", "선", "설", "마", "길", "연",
])

_KOREAN_NAME_STOP = frozenset([
    "김치", "이것", "박수", "최고", "정말", "강아지", "조심", "윤리", "장난", "임시",
    "한국", "오늘", "서울", "신발", "권리", "황금", "안전", "송이", "전화", "홍수",
    "유리", "고양이", "문화", "양말", "손님", "배달", "백화", "허락", "남자", "심각",
    "노력", "하늘", "성공", "차이", "주의", "우리", "구름", "민족", "나라", "진심",
    "엄마", "채소", "원래", "천천", "방법", "공원", "현재", "함께", "변화", "도움",
    "석탄", "선택", "설명", "마음", "길이", "연락", "추천", "여행", "남녀", "여자",
    "조건", "류행", "지하", "강남", "장미", "강물", "정치", "권한", "안녕", "최근",
    "박물", "전통", "박자", "이야", "이미", "이상", "이후", "정도", "강도", "고기",
    # context-keyword words that start with surnames but are not names
    "이름", "성명", "성함", "성별", "이메일", "이용", "이전", "이번", "주소", "주민",
])


class RRNDetector:
    """주민등록번호 (Korean Resident Registration Number) detector."""

    name = "rrn"
    _PATTERN = re.compile(r'\b(\d{6})[-\s]?([1-4]\d{6})\b')

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        for m in self._PATTERN.finditer(line):
            raw = m.group(0)
            digits = re.sub(r'[-\s]', '', raw)
            if not validate_rrn(digits):
                continue
            yield Match(
                detector="rrn",
                value=raw,
                line_no=line_no,
                column=m.start(),
                confidence="high",
            )


class PhoneMobileDetector:
    """한국 휴대폰 (Korean mobile phone number) detector."""

    name = "phone_mobile"
    _PATTERN = re.compile(r'\b(01[016789])[-.\s]?(\d{3,4})[-.\s]?(\d{4})\b')

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        for m in self._PATTERN.finditer(line):
            yield Match(
                detector="phone_mobile",
                value=m.group(0),
                line_no=line_no,
                column=m.start(),
                confidence="high",
            )


class PhoneLandlineDetector:
    """한국 일반전화 (Korean landline phone number) detector."""

    name = "phone_landline"
    _PATTERN = re.compile(r'\b(0(?:2|[3-6][1-5]|70|80))[-.\s]?(\d{3,4})[-.\s]?(\d{4})\b')

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        for m in self._PATTERN.finditer(line):
            yield Match(
                detector="phone_landline",
                value=m.group(0),
                line_no=line_no,
                column=m.start(),
                confidence="high",
            )


class BusinessNumberDetector:
    """사업자등록번호 (Korean Business Registration Number) detector."""

    name = "business_number"
    _PATTERN = re.compile(r'\b(\d{3})-(\d{2})-(\d{5})\b')

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        for m in self._PATTERN.finditer(line):
            digits = m.group(1) + m.group(2) + m.group(3)
            if not validate_brn(digits):
                continue
            yield Match(
                detector="business_number",
                value=m.group(0),
                line_no=line_no,
                column=m.start(),
                confidence="high",
            )


class CIDetector:
    """Connecting Information (CI) detector — 88자 base64."""

    name = "ci"
    _PATTERN_LABELED = re.compile(
        r'(?:(?:CI|ci|Ci)\s*[:=]\s*|"ci"\s*:\s*")'
        r'([A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{88})'
    )
    _PATTERN_BARE = re.compile(
        r'(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{86}==|[A-Za-z0-9+/]{88})(?![A-Za-z0-9+/=])'
    )

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        labeled_spans: set[tuple[int, int]] = set()

        for m in self._PATTERN_LABELED.finditer(line):
            cap = m.group(1)
            cap_start = m.start(1)
            cap_end = m.end(1)
            labeled_spans.add((cap_start, cap_end))
            yield Match(
                detector="ci",
                value=cap,
                line_no=line_no,
                column=cap_start,
                confidence="high",
            )

        for m in self._PATTERN_BARE.finditer(line):
            span = (m.start(1), m.end(1))
            if span in labeled_spans:
                continue
            yield Match(
                detector="ci",
                value=m.group(1),
                line_no=line_no,
                column=m.start(1),
                confidence="low",
            )


class KoreanNameDetector:
    """한국식 이름 (Korean name) detector."""

    name = "name_korean"

    _PATTERN_CONTEXT = re.compile(
        r'(?:이름|성명|성함|name|user_name|full_name|username)\s*[:=]\s*([가-힣]{2,4})'
    )
    _PATTERN_SURNAME = re.compile(r'(?<![가-힣])([가-힣]{2,4})(?![가-힣])')

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        context_spans: set[tuple[int, int]] = set()

        # Strategy A: context keyword (high confidence)
        for m in self._PATTERN_CONTEXT.finditer(line):
            cap = m.group(1)
            cap_start = m.start(1)
            cap_end = m.end(1)
            context_spans.add((cap_start, cap_end))
            yield Match(
                detector="name_korean",
                value=cap,
                line_no=line_no,
                column=cap_start,
                confidence="high",
            )

        # Strategy B: surname dictionary + heuristic (low confidence)
        for m in self._PATTERN_SURNAME.finditer(line):
            candidate = m.group(1)
            span = (m.start(1), m.end(1))
            if span in context_spans:
                continue
            if candidate[0] not in _KOREAN_SURNAMES:
                continue
            if candidate in _KOREAN_NAME_STOP:
                continue
            yield Match(
                detector="name_korean",
                value=candidate,
                line_no=line_no,
                column=m.start(1),
                confidence="low",
            )
