"""IDOR candidate detection (M42, ADR-024).

Cross-identity comparison: if URL U returns resource R to identity A,
and identity B (with different credentials) also returns R, that is an
IDOR candidate. Candidate-only; never verifies (ADR-024 D7).

This module is pure: it takes an Observation from Scanner._observations
plus B's status+body (already fetched by the caller). It makes no
network requests. The caller (Scanner.run_idor, M42-2b) does the
refetch under identity B.

v1 predicate is deliberately simple (ADR-024 D6): both 2xx and body
similarity via exact match or length-within-5%. Semantic diffing
(B sees A's PII replaced with B's PII) requires entity recognition
and is out of scope.
"""
from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from janissary.heuristic.types import Observation


#: Query parameter names that commonly carry object references (D5).
ID_PARAM_NAMES: frozenset[str] = frozenset({
    "id", "uid", "user_id", "account_id", "order_id", "resource_id",
    "object_id", "doc_id", "file_id", "invoice_id", "customer_id",
    "tenant_id",
})


_NUMERIC_SEG = re.compile(r"/\d+(?:/|$)")
_UUID_SEG = re.compile(
    r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?:/|$)"
)
_HEXISH_SEG = re.compile(r"/[0-9a-fA-F]{8,}(?:/|$)")


def is_idor_testable_url(url: str) -> bool:
    """True if the URL contains an object reference.

    Matches numeric path segments (/orders/42), UUID-shaped segments
    (/users/550e8400-...), long hex-shaped segments (/files/a1b2c3d4e5),
    or a query parameter whose name is in ID_PARAM_NAMES (case-insensitive).
    """
    if not url:
        return False
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    path = parsed.path or ""
    if _NUMERIC_SEG.search(path):
        return True
    if _UUID_SEG.search(path):
        return True
    if _HEXISH_SEG.search(path):
        return True
    try:
        qs = parse_qs(parsed.query, keep_blank_values=False)
    except ValueError:
        return False
    for name in qs:
        if name.lower() in ID_PARAM_NAMES:
            return True
    return False


def is_idor_candidate(
    a: Observation, b_status: int, b_body: str
) -> bool:
    """True if A and B both got 2xx and bodies look like the same resource.

    v1 predicate (ADR-024 D6):
      1. A status was 2xx (from the observation)
      2. B status is 2xx
      3. A body == B body (exact) OR length within 5%
    """
    a_status = a.response_status
    if a_status is None or not (200 <= a_status < 300):
        return False
    if not (200 <= b_status < 300):
        return False
    a_body = a.body or ""
    b_body_norm = b_body or ""
    if a_body == b_body_norm:
        return True
    if not a_body or not b_body_norm:
        return False
    a_len = len(a_body)
    b_len = len(b_body_norm)
    delta = abs(a_len - b_len)
    if delta / max(a_len, b_len) <= 0.05:
        return True
    return False
