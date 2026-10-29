"""Blind SQL injection oracle (Phase 4, FN-1).

Detects boolean-based blind SQLi via paired TRUE/FALSE payloads.

Detection logic:
  - Both responses must be coherent (status < 500, body >= MIN_BODY_BYTES)
  - No SQL error signature in either response
  - Status code delta alone -> emit (authoritative, unaffected by reflection)
  - Length delta only -> emit IF no payload reflection (a reflected
    payload trivially shifts body length and would be noisy)
  - Neither -> no emit

Pure. No I/O.
"""

from __future__ import annotations

import re

from janissary.detection.analyzer import ResponseSnapshot

LENGTH_DELTA_PCT = 10.0
MIN_BODY_BYTES = 100

_SQL_ERROR_SIGNATURES = re.compile(
    r"(SQL\s+syntax|mysql_fetch|ORA-\d{5}|PostgreSQL.*ERROR|"
    r"SQLite/JDBC|Unclosed\s+quotation\s+mark|"
    r"You\s+have\s+an\s+error\s+in\s+your\s+SQL\s+syntax|"
    r"Warning.*mysql_|supplied\s+argument\s+is\s+not\s+a\s+valid\s+MySQL\s+result)",
    re.I,
)


def _coherent(status: int, body: str) -> bool:
    if status >= 500:
        return False
    if len(body) < MIN_BODY_BYTES:
        return False
    return True


def check_blind_sqli_oracle(
    *,
    true_snapshot: ResponseSnapshot,
    true_status: int,
    true_payload: str,
    false_snapshot: ResponseSnapshot,
    false_status: int,
    false_payload: str,
    param: str,
) -> list[dict]:
    """Return zero or one finding dict."""
    true_body = true_snapshot.body or ""
    false_body = false_snapshot.body or ""

    if not _coherent(true_status, true_body):
        return []
    if not _coherent(false_status, false_body):
        return []

    if _SQL_ERROR_SIGNATURES.search(true_body):
        return []
    if _SQL_ERROR_SIGNATURES.search(false_body):
        return []

    true_reflected = bool(true_payload and true_payload in true_body)
    false_reflected = bool(false_payload and false_payload in false_body)

    status_differs = true_status != false_status

    tl = len(true_body)
    fl = len(false_body)
    max_len = max(tl, fl)
    length_delta_pct = abs(tl - fl) / max_len * 100.0 if max_len > 0 else 0.0
    length_differs = (
        length_delta_pct > LENGTH_DELTA_PCT
        and not (true_reflected or false_reflected)
    )

    if not (status_differs or length_differs):
        return []

    reasons = []
    if status_differs:
        reasons.append(f"status {true_status} vs {false_status}")
    if length_differs:
        reasons.append(f"length {tl} vs {fl} ({length_delta_pct:.1f}%)")

    return [
        {
            "type": "blind_sqli_oracle",
            "category": "sqli_blind",
            "severity": "high",
            "reason": "blind_sqli_paired_differential",
            "detail": (
                f"Blind SQLi: TRUE={true_payload!r} FALSE={false_payload!r} "
                f"distinguishable: {', '.join(reasons)}"
            ),
        }
    ]
