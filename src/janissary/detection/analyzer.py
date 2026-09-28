#!/usr/bin/env python3
"""
analyzer.py — Differential response analyzer.

Replaces the naive keyword-matching logic in janissary.py with a
gated differential analyzer. Every finding type requires multiple
independent gates to pass before a finding is emitted.

Design principle: it is better to miss a finding than to emit a
false positive. A missed finding costs a re-scan. A false positive
costs the customer's trust.
"""

from __future__ import annotations

import hashlib
import re
import statistics
from collections import Counter
from dataclasses import dataclass, field

# ===================================================================
# NORMALIZATION
# ===================================================================

_NORMALIZATION_PATTERNS = [
    # CSRF / anti-forgery tokens in HTML
    (
        re.compile(
            r'name=["\']?(csrf|_csrf|authenticity_token|__RequestVerificationToken|'
            r'_token|csrfmiddlewaretoken|nonce|_wpnonce|_csrf_token)["\']?'
            r'[^>]*?value=["\'][^"\']+["\']',
            re.I,
        ),
        r'name="\1" value="[CSRF]"',
    ),
    (
        re.compile(
            r'value=["\'][^"\']+["\'][^>]*?'
            r'name=["\']?(csrf|_csrf|authenticity_token|__RequestVerificationToken|'
            r'_token|csrfmiddlewaretoken|nonce|_wpnonce)["\']?',
            re.I,
        ),
        r'value="[CSRF]" name="\1"',
    ),
    (
        re.compile(r'<meta[^>]+csrf-token[^>]+content=["\'][^"\']+["\'][^>]*>', re.I),
        '<meta name="csrf-token" content="[CSRF]">',
    ),
    # Session IDs in URLs
    (re.compile(r";jsessionid=[A-Fa-f0-9]+", re.I), ";jsessionid=[SESSION]"),
    (
        re.compile(
            r"([?&])(sid|session|sessionid|PHPSESSID|JSESSIONID|ASP\.NET_SessionId)"
            r'=[^&\s"\']+',
            re.I,
        ),
        r"\1\2=[SESSION]",
    ),
    # Timestamps
    (
        re.compile(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})"
        ),
        "[TIMESTAMP]",
    ),
    (re.compile(r"\b1[5-9]\d{11}\b"), "[EPOCH_MS]"),
    (re.compile(r"\b1[5-9]\d{8}\b"), "[EPOCH_S]"),
    # UUIDs
    (
        re.compile(
            r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
        ),
        "[UUID]",
    ),
    # Long hex strings (nonces, hashes, trace IDs)
    (re.compile(r"\b[0-9a-f]{24,}\b", re.I), "[HEX]"),
    # ASP.NET ViewState
    (
        re.compile(r'__VIEWSTATE[^>]*value=["\'][^"\']+["\']', re.I),
        '__VIEWSTATE value="[VIEWSTATE]"',
    ),
    (
        re.compile(r'__EVENTVALIDATION[^>]*value=["\'][^"\']+["\']', re.I),
        '__EVENTVALIDATION value="[EVENTVALIDATION]"',
    ),
    # Request / trace IDs in text
    (
        re.compile(
            r'(request[_-]?id|trace[_-]?id|x-request-id)["\']?\s*[:=]\s*'
            r'["\']?[A-Za-z0-9\-]+',
            re.I,
        ),
        r"\1=[REQ_ID]",
    ),
]


def normalize_body(text: str) -> str:
    """
    Strip dynamic content from a response body so two identical pages
    produce identical fingerprints. This is the foundation of
    differential analysis.
    """
    if not text:
        return ""
    out = text
    for pattern, replacement in _NORMALIZATION_PATTERNS:
        out = pattern.sub(replacement, out)
    out = re.sub(r"\s+", " ", out)
    return out.strip()


def body_fingerprint(text: str) -> str:
    """SHA-256 of the normalized body."""
    return hashlib.sha256(
        normalize_body(text).encode("utf-8", errors="ignore")
    ).hexdigest()


# ===================================================================
# DB-SPECIFIC ERROR PATTERNS
# ===================================================================

DB_ERROR_PATTERNS = {
    "mysql": [
        re.compile(r"You have an error in your SQL syntax", re.I),
        re.compile(r"Warning:\s+mysql_", re.I),
        re.compile(r"MySqlException", re.I),
        re.compile(r"com\.mysql\.jdbc", re.I),
        re.compile(r"check the manual that corresponds to your MySQL", re.I),
        re.compile(r"#1064\b"),
        re.compile(r"#1054\b"),
        re.compile(r"Unknown column '[^']+' in", re.I),
    ],
    "postgresql": [
        re.compile(r"PostgreSQL.{0,40}(error|ERROR)"),
        re.compile(r"pg_query\(\)", re.I),
        re.compile(r"PG::SyntaxError"),
        re.compile(r"ERROR:\s+syntax error at or near", re.I),
        re.compile(r"org\.postgresql\.util\.PSQLException"),
        re.compile(r"unterminated quoted string", re.I),
    ],
    "mssql": [
        re.compile(r"Microsoft OLE DB Provider for SQL Server", re.I),
        re.compile(r"Unclosed quotation mark after the character string", re.I),
        re.compile(r"System\.Data\.SqlClient\.SqlException"),
        re.compile(r"Incorrect syntax near", re.I),
        re.compile(r"SQLServer JDBC Driver", re.I),
        re.compile(r"mssql_query\(\)", re.I),
    ],
    "oracle": [
        re.compile(r"ORA-\d{5}"),
        re.compile(r"oracle\.jdbc", re.I),
        re.compile(r"quoted string not properly terminated", re.I),
        re.compile(r"ORA-01756"),
        re.compile(r"ORA-00933"),
    ],
    "sqlite": [
        re.compile(r"SQLite3::"),
        re.compile(r"sqlite3\.OperationalError"),
        re.compile(r"unrecognized token:", re.I),
        re.compile(r"SQLite/JDBCDriver"),
        re.compile(r"\[SQLITE_ERROR\]"),
    ],
}


# ===================================================================
# OUTPUT-REGION MARKERS (OWASP Benchmark evidence shape)
# ===================================================================
# The scaffolding is static; the evidence is what sits between the
# header and the terminator. We do not emit on the header alone.

_CMD_OUTPUT_HEADER = re.compile(
    r"Here is the standard output of the command:\s*<br\s*/?>", re.I
)
_CMD_STDERR_HEADER = re.compile(r"Here is the std err of the command", re.I)

_SQL_RESULTS_HEADER = re.compile(r"Your results are:\s*<br\s*/?>", re.I)
_SQL_RESULTS_END = re.compile(r"</p>", re.I)


def _strip_tags(s: str) -> str:
    return re.sub(r"<[^>]+>", "", s or "")


def _region_after(body: str, header_match, stops) -> str:
    start = header_match.end()
    end = len(body)
    for pat in stops:
        m = pat.search(body, start)
        if m and m.start() < end:
            end = m.start()
    return body[start:end]


# ===================================================================
# SLEEP FLOOR
# ===================================================================

SLEEP_FLOOR = {
    "sql_sleep_mysql": 5.0,
    "sql_sleep_mssql": 5.0,
    "sql_sleep_pg": 5.0,
    "sql_sleep_oracle": 5.0,
    "sql_benchmark": 2.0,
    "sql_blind_sleep_true": 5.0,
    "sql_blind_sleep_false": 5.0,
    "nosql_where_sleep": 5.0,
    "cmd_semicolon_sleep": 5.0,
    "cmd_pipe_sleep": 5.0,
    "cmd_backtick_sleep": 5.0,
    "cmd_dollar_sleep": 5.0,
    "ssti_jinja_sleep": 5.0,
}


# ===================================================================
# RESPONSE SNAPSHOT
# ===================================================================


@dataclass
class ResponseSnapshot:
    """A normalized view of an HTTP response."""

    status: int
    body: str
    normalized: str
    fingerprint: str
    length: int
    normalized_length: int
    elapsed: float
    content_type: str

    @classmethod
    def from_response(cls, response) -> ResponseSnapshot:
        body = response.text or ""
        normalized = normalize_body(body)
        elapsed = 0.0
        if getattr(response, "elapsed", None) is not None:
            elapsed = response.elapsed.total_seconds()
        return cls(
            status=response.status_code,
            body=body,
            normalized=normalized,
            fingerprint=hashlib.sha256(
                normalized.encode("utf-8", errors="ignore")
            ).hexdigest(),
            length=len(body),
            normalized_length=len(normalized),
            elapsed=elapsed,
            content_type=(response.headers.get("content-type") or "").lower(),
        )


# ===================================================================
# BASELINE
# ===================================================================


@dataclass
class Baseline:
    """
    Built from N benign samples. The key properties are:
    - is_stable_body: all samples produced the same normalized fingerprint
    - is_stable_timing: timing variance is low enough to trust timing findings
    - is_static: page has no timing or body signal (timing attacks are invalid)
    - has_oracle: at least one sample has a non-empty body
    """

    snapshots: list[ResponseSnapshot] = field(default_factory=list)

    @property
    def mean_elapsed(self) -> float:
        if not self.snapshots:
            return 0.0
        return statistics.mean(s.elapsed for s in self.snapshots)

    @property
    def std_elapsed(self) -> float:
        if len(self.snapshots) < 2:
            return 0.0
        return statistics.pstdev(s.elapsed for s in self.snapshots)

    @property
    def modal_status(self) -> int:
        if not self.snapshots:
            return 0
        return Counter(s.status for s in self.snapshots).most_common(1)[0][0]

    @property
    def fingerprints(self) -> set:
        return {s.fingerprint for s in self.snapshots}

    @property
    def is_stable_body(self) -> bool:
        return len(self.fingerprints) == 1

    @property
    def is_stable_timing(self) -> bool:
        return self.std_elapsed < 0.05 and len(self.snapshots) >= 5

    @property
    def is_static(self) -> bool:
        return self.is_stable_body and self.std_elapsed < 0.02

    @property
    def has_oracle(self) -> bool:
        return any(s.length > 0 for s in self.snapshots)

    def add(self, snapshot: ResponseSnapshot) -> None:
        self.snapshots.append(snapshot)

    def body_length_band(self) -> tuple[int, int]:
        if not self.snapshots:
            return (0, 0)
        lengths = [s.normalized_length for s in self.snapshots]
        return (min(lengths), max(lengths))


# ===================================================================
# DIFFERENTIAL ANALYZER
# ===================================================================


class DifferentialAnalyzer:
    """
    Compares a payload response against a baseline. Every finding type
    has multiple independent gates. All gates must pass.
    """

    MIN_TIMING_DELTA = 1.5
    MIN_TIMING_Z = 4.0
    MIN_SLEEP_FLOOR = 3.0
    LENGTH_RATIO_HIGH = 3.0
    LENGTH_RATIO_LOW = 0.1
    MIN_REFLECTION_PAYLOAD_LEN = 3
    CONTEXT_WINDOW = 60
    BAND_SLACK = 500

    def __init__(
        self,
        baseline: Baseline,
        payload_name: str,
        payload_value: str,
        payload_category: str,
    ):
        self.baseline = baseline
        self.payload_name = payload_name
        self.payload_value = payload_value
        self.payload_category = payload_category

    def analyze(self, snapshot: ResponseSnapshot) -> list[dict]:
        findings: list[dict] = []
        findings.extend(self._check_db_error(snapshot))
        findings.extend(self._check_reflection(snapshot))
        findings.extend(self._check_timing(snapshot))
        findings.extend(self._check_status(snapshot))
        findings.extend(self._check_length(snapshot))
        findings.extend(self._check_output_region(snapshot))
        return findings

    # -- Gate 1: DB error ------------------------------------------

    def _check_db_error(self, snapshot: ResponseSnapshot) -> list[dict]:
        for dbms, patterns in DB_ERROR_PATTERNS.items():
            for pat in patterns:
                # Gate A: the payload itself must not contain the pattern.
                # Otherwise a reflection of the payload would match.
                if pat.search(self.payload_value):
                    continue
                m = pat.search(snapshot.body)
                if not m:
                    continue
                # Gate B: the pattern must not appear in any baseline sample.
                if any(pat.search(s.body) for s in self.baseline.snapshots):
                    continue
                ctx_start = max(0, m.start() - self.CONTEXT_WINDOW)
                ctx_end = min(len(snapshot.body), m.end() + self.CONTEXT_WINDOW)
                return [
                    {
                        "type": "db_error",
                        "severity": "critical",
                        "detail": f"{dbms.upper()} error signature matched",
                        "reflection_context": snapshot.body[ctx_start:ctx_end],
                        "dbms": dbms,
                        "evidence": m.group(0)[:200],
                    }
                ]
        return []

    # -- Gate 1b: Labelled output region ---------------------------

    def _check_output_region(self, snapshot: ResponseSnapshot) -> list[dict]:
        """Detect non-empty content between a static OWASP-Benchmark
        output header and its terminator.

        The header alone is boilerplate. The header PLUS non-empty
        region content, absent from every baseline sample, is evidence
        of command execution or SQL row disclosure.
        """
        regions = (
            (
                "command_output",
                "critical",
                _CMD_OUTPUT_HEADER,
                [_CMD_STDERR_HEADER],
                "Command output present in response body",
            ),
            (
                "sql_result_rows",
                "critical",
                _SQL_RESULTS_HEADER,
                [_SQL_RESULTS_END],
                "SQL result rows present in response body",
            ),
        )
        for ftype, sev, header, stops, detail in regions:
            if header.search(self.payload_value):
                continue
            m = header.search(snapshot.body)
            if not m:
                continue
            baseline_dirty = False
            for s in self.baseline.snapshots:
                bm = header.search(s.body)
                if not bm:
                    continue
                if _strip_tags(_region_after(s.body, bm, stops)).strip():
                    baseline_dirty = True
                    break
            if baseline_dirty:
                continue
            region = _region_after(snapshot.body, m, stops)
            stripped = _strip_tags(region).strip()
            if not stripped:
                continue
            return [
                {
                    "type": ftype,
                    "severity": sev,
                    "detail": detail,
                    "reflection_context": region[:300],
                    "evidence": stripped[:200],
                }
            ]
        return []


    # -- Gate 2: Reflection ----------------------------------------

    def _check_reflection(self, snapshot: ResponseSnapshot) -> list[dict]:
        if not self.payload_value or len(self.payload_value) > 200:
            return []
        payload = self.payload_value

        # Gate A: single-char payloads like `'`/`"` appear in every
        # HTML/JSON page; matching them is not evidence of reflection.
        if len(payload) < self.MIN_REFLECTION_PAYLOAD_LEN:
            return []

        # Gate B: the payload must not already appear in the baseline.
        # Otherwise the "reflection" is just the page's own content.
        escaped = (
            payload.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;")
        )
        for s in self.baseline.snapshots:
            if payload in s.body or escaped in s.body:
                return []

        body = snapshot.body

        idx_raw = body.find(payload)
        idx_escaped = body.find(escaped)

        if idx_raw < 0 and idx_escaped < 0:
            return []

        is_escaped = idx_raw < 0 and idx_escaped >= 0
        idx = idx_escaped if is_escaped else idx_raw

        if self.payload_category == "xss":
            if is_escaped:
                return [
                    {
                        "type": "reflected_xss_safe",
                        "severity": "info",
                        "detail": "XSS payload reflected but HTML-escaped",
                        "reflection_context": body[max(0, idx - 40) : idx + 120],
                    }
                ]
            ct = snapshot.content_type
            if "html" not in ct and "xml" not in ct:
                return [
                    {
                        "type": "payload_reflected",
                        "severity": "info",
                        "detail": f"Payload reflected in non-HTML content-type {ct!r}",
                        "reflection_context": body[max(0, idx - 40) : idx + 120],
                    }
                ]
            if self._is_inert_context(body, idx):
                return [
                    {
                        "type": "payload_reflected",
                        "severity": "info",
                        "detail": "XSS payload reflected in inert context",
                        "reflection_context": body[
                            max(0, idx - 60) : idx + len(payload) + 60
                        ],
                    }
                ]
            return [
                {
                    "type": "reflected_xss",
                    "severity": "high",
                    "detail": "XSS payload reflected UNESCAPED in HTML",
                    "reflection_context": body[
                        max(0, idx - 60) : idx + len(payload) + 60
                    ],
                }
            ]

        return [
            {
                "type": "payload_reflected",
                "severity": "low",
                "detail": f"Payload reflected ({'escaped' if is_escaped else 'raw'})",
                "reflection_context": body[max(0, idx - 40) : idx + 120],
            }
        ]

    @staticmethod
    def _is_inert_context(body: str, idx: int) -> bool:
        back = body[max(0, idx - 200) : idx]
        if back.rfind("<!--") > back.rfind("-->"):
            return True
        for tag in ("textarea", "title", "noscript"):
            open_tag = back.rfind(f"<{tag}")
            close_tag = back.rfind(f"</{tag}")
            if open_tag > close_tag and open_tag >= 0:
                return True
        return False

    # -- Gate 3: Timing --------------------------------------------

    def _check_timing(self, snapshot: ResponseSnapshot) -> list[dict]:
        declared = SLEEP_FLOOR.get(self.payload_name, 0.0)
        if declared < self.MIN_SLEEP_FLOOR:
            return []
        if not self.baseline.has_oracle:
            return []
        if self.baseline.std_elapsed < 0.05:
            return []
        if self.baseline.is_static:
            return []

        elapsed = snapshot.elapsed
        delta = elapsed - self.baseline.mean_elapsed
        z = (delta / self.baseline.std_elapsed) if self.baseline.std_elapsed else 0.0

        if elapsed < declared:
            return []

        lo, hi = self.baseline.body_length_band()
        if not (
            lo - self.BAND_SLACK <= snapshot.normalized_length <= hi + self.BAND_SLACK
        ):
            return []

        if delta < self.MIN_TIMING_DELTA and z < self.MIN_TIMING_Z:
            return []

        severity = "critical" if (z >= 6 and delta >= 3.0) else "high"
        return [
            {
                "type": "timing_anomaly",
                "severity": severity,
                "detail": (
                    f"Response {elapsed:.2f}s vs baseline "
                    f"{self.baseline.mean_elapsed:.2f}s "
                    f"(delta={delta:+.2f}s, z={z:.1f}, "
                    f"std={self.baseline.std_elapsed:.3f}s)"
                ),
                "reflection_context": None,
            }
        ]

    # -- Gate 4: Status --------------------------------------------

    def _check_status(self, snapshot: ResponseSnapshot) -> list[dict]:
        base = self.baseline.modal_status
        if base == 0 or base >= 400:
            return []
        if snapshot.status < 500:
            return []
        return [
            {
                "type": "status_change",
                "severity": "high",
                "detail": f"Baseline {base} -> Payload {snapshot.status}",
                "reflection_context": None,
            }
        ]

    # -- Gate 5: Length --------------------------------------------

    def _check_length(self, snapshot: ResponseSnapshot) -> list[dict]:
        if not self.baseline.is_stable_body:
            return []
        if not self.baseline.has_oracle:
            return []
        base_len = self.baseline.snapshots[0].normalized_length
        if base_len == 0:
            return []
        ratio = snapshot.normalized_length / base_len
        if ratio >= self.LENGTH_RATIO_HIGH:
            return [
                {
                    "type": "length_anomaly",
                    "severity": "medium",
                    "detail": (
                        f"Response {ratio:.1f}x baseline "
                        f"({base_len} -> {snapshot.normalized_length} bytes)"
                    ),
                    "reflection_context": None,
                }
            ]
        if ratio <= self.LENGTH_RATIO_LOW and snapshot.normalized_length > 0:
            return [
                {
                    "type": "length_shrink",
                    "severity": "medium",
                    "detail": (
                        f"Response {ratio:.3f}x baseline "
                        f"({base_len} -> {snapshot.normalized_length} bytes)"
                    ),
                    "reflection_context": None,
                }
            ]
        return []
