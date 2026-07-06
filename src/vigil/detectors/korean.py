"""Korean PII detectors."""
from __future__ import annotations
import re
from typing import Iterable, Iterator
from vigil.detectors.base import Match
from vigil.validators import validate_rrn, validate_brn

__all__ = [
    "RRNDetector",
    "PhoneMobileDetector",
    "PhoneLandlineDetector",
    "BusinessNumberDetector",
    "CIDetector",
    "KoreanNameDetector",
]


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
    # 금융/업무 동사·명사 (운영 로그 고빈도 오탐)
    "조회", "전송", "차감", "차감요청", "차감완료", "차감을", "전달",
    "전환", "전환단위", "전환비율", "전환시", "전환한도",
    "추가인증", "전송성공", "유효성", "한도금액", "정책", "마스터",
    "주식회사", "구간", "정상",
    # 카드사명
    "신한카드", "하나카드", "우리카드", "현대카드",
    # 일반 서비스 용어
    "정보", "서비스", "고객", "이벤트", "이용약관", "마케팅", "안내", "공휴일", "주중", "노티",
    # 기업·브랜드
    "한화", "한화생명", "이글스",
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
                detector=self.name,
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
                detector=self.name,
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
                detector=self.name,
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
                detector=self.name,
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
                detector=self.name,
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
                detector=self.name,
                value=m.group(1),
                line_no=line_no,
                column=m.start(1),
                confidence="low",
            )


class KoreanNameDetector:
    """한국식 이름 (Korean name) detector."""

    name = "name_korean"

    _PATTERN_CONTEXT = re.compile(
        r'(?:(?<![A-Za-z_])(?:name|user_name|full_name|username)|이름|성명|성함)'
        r'\s*[:=]\s*([가-힣]{2,4})'
    )
    _PATTERN_SURNAME = re.compile(r'(?<![가-힣])([가-힣]{2,4})(?![가-힣])')

    def __init__(self, extra_stopwords: Iterable[str] | None = None) -> None:
        self._stopwords = _KOREAN_NAME_STOP | frozenset(extra_stopwords or ())

    def find(self, line: str, line_no: int = 0) -> Iterator[Match]:
        context_spans: set[tuple[int, int]] = set()

        # Strategy A: context keyword (high confidence)
        for m in self._PATTERN_CONTEXT.finditer(line):
            cap = m.group(1)
            cap_start = m.start(1)
            cap_end = m.end(1)
            context_spans.add((cap_start, cap_end))
            if cap in self._stopwords:
                continue
            yield Match(
                detector=self.name,
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
            if candidate in self._stopwords:
                continue
            yield Match(
                detector=self.name,
                value=candidate,
                line_no=line_no,
                column=m.start(1),
                confidence="low",
            )
