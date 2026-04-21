"""Detector registry — all built-in PII detectors."""
from vigil.detectors.base import Detector
from vigil.detectors.korean import (
    RRNDetector, PhoneMobileDetector, PhoneLandlineDetector,
    BusinessNumberDetector, CIDetector, KoreanNameDetector,
)
from vigil.detectors.international import EmailDetector, CreditCardDetector, IPv4Detector

BUILTIN_DETECTORS: list[Detector] = [
    RRNDetector(),
    PhoneMobileDetector(),
    PhoneLandlineDetector(),
    BusinessNumberDetector(),
    CIDetector(),
    KoreanNameDetector(),
    EmailDetector(),
    CreditCardDetector(),
    IPv4Detector(),
]
