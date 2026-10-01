"""Differential detection engine.

Every finding is gated by a baseline comparison. No finding is ever
emitted from a single response alone.
"""

from .analyzer import (
    DB_ERROR_PATTERNS,
    SLEEP_FLOOR,
    Baseline,
    DifferentialAnalyzer,
    ResponseSnapshot,
    body_fingerprint,
    check_pathtraver_oracle,
    check_securecookie_oracle,
    check_sqli_quote_oracle,
    check_trustbound_oracle,
    check_weakrand_oracle,
    normalize_body,
)

__all__ = [
    "DB_ERROR_PATTERNS",
    "SLEEP_FLOOR",
    "Baseline",
    "DifferentialAnalyzer",
    "ResponseSnapshot",
    "body_fingerprint",
    "check_pathtraver_oracle",
    "check_securecookie_oracle",
    "check_sqli_quote_oracle",
    "check_trustbound_oracle",
    "check_weakrand_oracle",
    "normalize_body",
]
