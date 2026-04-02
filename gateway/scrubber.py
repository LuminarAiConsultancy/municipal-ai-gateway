"""PII scrubbing engine for Canadian municipalities.

Detects and replaces personally identifiable information before requests
leave the gateway and when responses come back. Combines regex-based
recognizers for Canadian-specific patterns with Presidio's NLP engine
for names and addresses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from presidio_analyzer import (
    AnalyzerEngine,
    PatternRecognizer,
    Pattern,
    RecognizerResult,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ── Detection log entry ───────────────────────────────────────────────────────


@dataclass
class PiiDetection:
    entity_type: str
    start: int
    end: int
    score: float
    original: str  # the matched text that was replaced


@dataclass
class ScrubResult:
    """Returned by scrub(). Contains the cleaned text and a log of removals."""

    text: str
    detections: list[PiiDetection] = field(default_factory=list)

    @property
    def pii_found(self) -> bool:
        return len(self.detections) > 0


# ── Luhn check for SIN validation ─────────────────────────────────────────────


def _luhn_valid(digits: str) -> bool:
    """Return True if *digits* passes the Luhn checksum (used by Canadian SINs)."""
    nums = [int(d) for d in digits]
    checksum = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


# ── Custom Canadian recognizers ───────────────────────────────────────────────


class SinRecognizer(PatternRecognizer):
    """Canadian Social Insurance Number: 123-456-789 or 123 456 789."""

    def __init__(self):
        patterns = [
            Pattern(
                "SIN_DASHES",
                r"\b\d{3}-\d{3}-\d{3}\b",
                0.6,
            ),
            Pattern(
                "SIN_SPACES",
                r"\b\d{3}\s\d{3}\s\d{3}\b",
                0.6,
            ),
        ]
        super().__init__(
            supported_entity="CA_SIN",
            supported_language="en",
            patterns=patterns,
            context=["sin", "social insurance", "social insurance number"],
        )

    def validate_result(self, pattern_text: str) -> bool:  # type: ignore[override]
        digits = re.sub(r"\D", "", pattern_text)
        if len(digits) != 9:
            return False
        # SINs starting with 0 or 8 are invalid.
        if digits[0] in ("0", "8"):
            return False
        return _luhn_valid(digits)


class BcPhnRecognizer(PatternRecognizer):
    """BC Personal Health Number: 10 digits starting with 9."""

    def __init__(self):
        patterns = [
            Pattern("BC_PHN", r"\b9\d{9}\b", 0.4),
            Pattern("BC_PHN_SPACED", r"\b9\d{3}[\s-]?\d{3}[\s-]?\d{3}\b", 0.4),
        ]
        super().__init__(
            supported_entity="CA_BC_PHN",
            supported_language="en",
            patterns=patterns,
            context=[
                "phn",
                "personal health number",
                "bc health",
                "british columbia",
                "carecard",
            ],
        )


class AlbertaPhnRecognizer(PatternRecognizer):
    """Alberta Personal Health Number (ULI): 9 digits."""

    def __init__(self):
        patterns = [
            Pattern("AB_PHN", r"\b\d{9}\b", 0.3),
        ]
        super().__init__(
            supported_entity="CA_AB_PHN",
            supported_language="en",
            patterns=patterns,
            context=[
                "uli",
                "alberta health",
                "ahcip",
                "personal health number",
                "alberta",
            ],
        )


class OntarioHealthRecognizer(PatternRecognizer):
    """Ontario Health Insurance Plan number: 10 digits + optional 2-letter version code."""

    def __init__(self):
        patterns = [
            Pattern("OHIP", r"\b\d{10}(?:\s?[A-Za-z]{2})?\b", 0.4),
        ]
        super().__init__(
            supported_entity="CA_ON_OHIP",
            supported_language="en",
            patterns=patterns,
            context=[
                "ohip",
                "ontario health",
                "health card",
                "health insurance",
                "ontario",
            ],
        )


class QuebecHealthRecognizer(PatternRecognizer):
    """Quebec RAMQ number: 4 letters + 8 digits (e.g. SMIT 7501 0312)."""

    def __init__(self):
        patterns = [
            Pattern(
                "RAMQ",
                r"\b[A-Za-z]{4}\s?\d{4}\s?\d{4}\b",
                0.4,
            ),
        ]
        super().__init__(
            supported_entity="CA_QC_RAMQ",
            supported_language="en",
            patterns=patterns,
            context=[
                "ramq",
                "régie de l'assurance maladie",
                "quebec health",
                "carte soleil",
                "health card",
                "québec",
            ],
        )


class CanadianPostalCodeRecognizer(PatternRecognizer):
    """Canadian postal code: A1A 1A1 or A1A1A1."""

    def __init__(self):
        patterns = [
            Pattern(
                "POSTAL_SPACE",
                r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\s\d[ABCEGHJ-NPRSTV-Z]\d\b",
                0.7,
            ),
            Pattern(
                "POSTAL_NOSPACE",
                r"\b[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z]\d[ABCEGHJ-NPRSTV-Z]\d\b",
                0.6,
            ),
        ]
        super().__init__(
            supported_entity="CA_POSTAL_CODE",
            supported_language="en",
            patterns=patterns,
            context=["postal code", "zip", "address", "mail"],
        )


_STREET_SUFFIXES = (
    r"Street|St|Avenue|Ave|Boulevard|Blvd|Drive|Dr|Road|Rd|"
    r"Crescent|Cres|Court|Ct|Lane|Ln|Way|Place|Pl|Trail"
)

# Canadian province abbreviations and full names for optional city+province tail.
_PROVINCES = (
    r"BC|AB|SK|MB|ON|QC|NB|NS|PE|NL|NT|YT|NU|"
    r"British\s+Columbia|Alberta|Saskatchewan|Manitoba|Ontario|"
    r"Quebec|Québec|New\s+Brunswick|Nova\s+Scotia|"
    r"Prince\s+Edward\s+Island|Newfoundland(?:\s+and\s+Labrador)?"
)


class CanadianAddressRecognizer(PatternRecognizer):
    """Canadian street addresses: 123 Main Street, optionally followed by city and province."""

    def __init__(self):
        # Full address with city + province: 456 Oak Street Vancouver BC
        full = (
            r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s+){1,3}"
            rf"(?:{_STREET_SUFFIXES})\.?"
            rf"(?:,?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*,?\s+(?:{_PROVINCES}))?"
            r"\b"
        )
        patterns = [
            Pattern("CA_ADDRESS_FULL", full, 0.7),
        ]
        super().__init__(
            supported_entity="CA_ADDRESS",
            supported_language="en",
            patterns=patterns,
            context=[
                "address", "live", "reside", "located", "mail",
                "ship", "deliver", "home", "office", "work",
            ],
        )


class CanadianPhoneRecognizer(PatternRecognizer):
    """Canadian phone numbers in common formats."""

    def __init__(self):
        patterns = [
            # +1 (604) 555-1234 or 1-604-555-1234
            Pattern(
                "PHONE_INTL",
                r"(?<!\d)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}(?!\d)",
                0.5,
            ),
        ]
        super().__init__(
            supported_entity="CA_PHONE_NUMBER",
            supported_language="en",
            patterns=patterns,
            context=[
                "phone",
                "telephone",
                "tel",
                "cell",
                "mobile",
                "fax",
                "call",
                "contact",
            ],
        )


# ── Placeholder labels ───────────────────────────────────────────────────────

PLACEHOLDER_MAP = {
    "CA_SIN": "[SIN REMOVED]",
    "CA_BC_PHN": "[BC PHN REMOVED]",
    "CA_AB_PHN": "[AB PHN REMOVED]",
    "CA_ON_OHIP": "[OHIP REMOVED]",
    "CA_QC_RAMQ": "[RAMQ REMOVED]",
    "CA_POSTAL_CODE": "[POSTAL CODE REMOVED]",
    "CA_PHONE_NUMBER": "[PHONE REMOVED]",
    "CA_ADDRESS": "[ADDRESS REMOVED]",
    "EMAIL_ADDRESS": "[EMAIL REMOVED]",
    "PERSON": "[NAME REMOVED]",
    "LOCATION": "[ADDRESS REMOVED]",
}

DEFAULT_PLACEHOLDER = "[PII REMOVED]"


# ── Scrubber singleton ───────────────────────────────────────────────────────

_scrubber: Scrubber | None = None


def get_scrubber() -> Scrubber:
    """Return the module-level Scrubber, creating it on first call."""
    global _scrubber
    if _scrubber is None:
        _scrubber = Scrubber()
    return _scrubber


class Scrubber:
    """Orchestrates PII detection (Presidio + custom Canadian recognizers) and replacement."""

    def __init__(self) -> None:
        nlp_config = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
        }
        nlp_engine = NlpEngineProvider(nlp_configuration=nlp_config).create_engine()

        self._analyzer = AnalyzerEngine(nlp_engine=nlp_engine)

        # Register Canadian-specific recognizers.
        self._analyzer.registry.add_recognizer(SinRecognizer())
        self._analyzer.registry.add_recognizer(BcPhnRecognizer())
        self._analyzer.registry.add_recognizer(AlbertaPhnRecognizer())
        self._analyzer.registry.add_recognizer(OntarioHealthRecognizer())
        self._analyzer.registry.add_recognizer(QuebecHealthRecognizer())
        self._analyzer.registry.add_recognizer(CanadianPostalCodeRecognizer())
        self._analyzer.registry.add_recognizer(CanadianAddressRecognizer())
        self._analyzer.registry.add_recognizer(CanadianPhoneRecognizer())

        self._anonymizer = AnonymizerEngine()

        # Entity types to scan for.
        self._entities = [
            # Canadian custom
            "CA_SIN",
            "CA_BC_PHN",
            "CA_AB_PHN",
            "CA_ON_OHIP",
            "CA_QC_RAMQ",
            "CA_POSTAL_CODE",
            "CA_PHONE_NUMBER",
            "CA_ADDRESS",
            # Presidio built-ins
            "EMAIL_ADDRESS",
            "PERSON",
            "LOCATION",
        ]

    # ── Public API ────────────────────────────────────────────────────────

    def scrub(self, text: str, *, score_threshold: float = 0.3) -> ScrubResult:
        """Detect and replace PII in *text*.

        Returns a ScrubResult with the cleaned text and a list of every
        detection that was replaced.
        """
        if not text:
            return ScrubResult(text=text)

        results: list[RecognizerResult] = self._analyzer.analyze(
            text=text,
            entities=self._entities,
            language="en",
            score_threshold=score_threshold,
        )

        if not results:
            return ScrubResult(text=text)

        # Build per-entity operator configs so each type gets its own placeholder.
        operators: dict[str, OperatorConfig] = {}
        for r in results:
            if r.entity_type not in operators:
                placeholder = PLACEHOLDER_MAP.get(r.entity_type, DEFAULT_PLACEHOLDER)
                operators[r.entity_type] = OperatorConfig(
                    "replace", {"new_value": placeholder}
                )

        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )

        detections = [
            PiiDetection(
                entity_type=r.entity_type,
                start=r.start,
                end=r.end,
                score=r.score,
                original=text[r.start : r.end],
            )
            for r in results
        ]

        return ScrubResult(text=anonymized.text, detections=detections)

    def scrub_request(self, text: str) -> ScrubResult:
        """Scrub an outbound AI request (convenience alias)."""
        return self.scrub(text)

    def scrub_response(self, text: str) -> ScrubResult:
        """Scrub an inbound AI response (same patterns, separate method for clarity)."""
        return self.scrub(text)
